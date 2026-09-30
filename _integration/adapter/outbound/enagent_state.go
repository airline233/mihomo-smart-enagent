//go:build with_gvisor && !no_enagent

package outbound

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/airline233/mihomo-smart-enagent/cas"
	"github.com/airline233/mihomo-smart-enagent/passkey"
	"github.com/airline233/mihomo-smart-enagent/session"
	"github.com/airline233/mihomo-smart-enagent/stack"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
)

// 同进程、同控制器、同账号只有一条隧道。节点名和 UDP 开关不影响共享。
var enAgentStates = struct {
	sync.Mutex
	items map[string]*enAgentState
}{items: make(map[string]*enAgentState)}

type enAgentFlight struct {
	done  chan struct{}
	stack *stack.Stack
	err   error
}

type enAgentState struct {
	key        string
	profile    [32]byte
	refs       int // 由 enAgentStates 保护
	stopped    chan struct{}
	option     EnAgentOption
	baseDialer C.Dialer
	manager    *cas.Manager
	ctx        context.Context
	cancel     context.CancelFunc
	mu         sync.Mutex
	wg         sync.WaitGroup
	closing    bool
	stack      *stack.Stack
	session    *session.Session
	flight     *enAgentFlight
	retryAt    time.Time
	retryDelay time.Duration
	lastErr    error
}

func acquireEnAgentState(option EnAgentOption, bundle *passkey.Bundle, dialer C.Dialer) (*enAgentState, error) {
	controller := "https://" + net.JoinHostPort(option.Server, strconv.Itoa(option.Port))
	if option.Port == defaultEnAgentPort {
		controller = "https://" + option.Server
	}
	identity := sha256.Sum256([]byte(controller + "\x00" + option.Username))
	key := fmt.Sprintf("%x", identity)
	// 不允许同账号节点悄悄忽略不同的路由、凭据和 TLS 配置。
	encoded, err := json.Marshal([]any{option.Passkey, option.SPA, option.SkipCertVerify,
		option.StateDir, option.RenewInterval, option.HeartbeatTimeout, option.Interface,
		option.RoutingMark, option.IPVersion, option.DialerProxy, option.TFO, option.MPTCP,
		fmt.Sprintf("%T:%p", option.DialerForAPI, option.DialerForAPI),
		fmt.Sprintf("%T:%p", option.TunnelForAPI, option.TunnelForAPI)})
	if err != nil {
		return nil, err
	}
	profile := sha256.Sum256(encoded)
	for {
		enAgentStates.Lock()
		if old := enAgentStates.items[key]; old != nil {
			if old.refs == 0 {
				enAgentStates.Unlock()
				<-old.stopped
				continue
			}
			if old.profile != profile {
				enAgentStates.Unlock()
				return nil, errors.New("enagent: 同账号节点的凭据、路由、TLS 或会话配置不一致，无法共享隧道")
			}
			old.refs++
			enAgentStates.Unlock()
			return old, nil
		}
		opts := cas.ManagerOptions{Config: cas.Config{
			Bundle: bundle, Controller: controller, Timeout: defaultEnAgentTimeout,
			ControllerSkipVerify: option.SkipCertVerify, DialContext: dialer.DialContext,
			Logf: func(format string, args ...any) {
				log.Debugln("enagent[%s] "+format, append([]any{option.Name}, args...)...)
			},
		}}
		if option.StateDir != "" {
			opts.Cache = cas.FileCookieCache{Path: filepath.Join(option.StateDir, enAgentSessionCacheFileName, key, enAgentCookieCacheFile)}
		} else if dir, err := os.UserCacheDir(); err == nil {
			opts.Cache = cas.FileCookieCache{Path: filepath.Join(dir, "mihomo-enagent", key, enAgentCookieCacheFile)}
		}
		manager, err := cas.NewManager(opts)
		if err != nil {
			enAgentStates.Unlock()
			return nil, err
		}
		ctx, cancel := context.WithCancel(context.Background())
		state := &enAgentState{key: key, profile: profile, refs: 1, stopped: make(chan struct{}),
			option: option, baseDialer: dialer, manager: manager, ctx: ctx, cancel: cancel}
		enAgentStates.items[key] = state
		enAgentStates.Unlock()
		return state, nil
	}
}

func releaseEnAgentState(e *enAgentState) {
	enAgentStates.Lock()
	e.refs--
	last := e.refs == 0
	enAgentStates.Unlock()
	if !last {
		return
	}
	e.mu.Lock()
	e.closing = true
	e.cancel()
	sess := e.session
	e.mu.Unlock()
	if sess != nil {
		_ = sess.Close()
	}
	e.wg.Wait()
	e.manager.Close()
	enAgentStates.Lock()
	delete(enAgentStates.items, e.key)
	close(e.stopped)
	enAgentStates.Unlock()
}

func (e *enAgentState) ensureStack(ctx context.Context, nodeClosed <-chan struct{}) (*stack.Stack, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case <-nodeClosed:
		return nil, net.ErrClosed
	default:
	}
	e.mu.Lock()
	if e.closing {
		e.mu.Unlock()
		return nil, net.ErrClosed
	}
	if e.stack != nil && e.session.IsAlive() {
		st := e.stack
		e.mu.Unlock()
		return st, nil
	}
	flight := e.flight
	if flight == nil {
		if time.Now().Before(e.retryAt) {
			err := e.lastErr
			e.mu.Unlock()
			return nil, err
		}
		flight = &enAgentFlight{done: make(chan struct{})}
		e.flight = flight
		e.wg.Add(1)
		go e.connect(flight)
	}
	e.mu.Unlock()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-nodeClosed:
		return nil, net.ErrClosed
	case <-flight.done:
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		select {
		case <-nodeClosed:
			return nil, net.ErrClosed
		default:
		}
		return flight.stack, flight.err
	}
}

func (e *enAgentState) connect(flight *enAgentFlight) {
	defer e.wg.Done()
	// 建连属于共享会话；某个调用者取消不会中止其他调用者的请求。
	ctx, cancel := context.WithTimeout(e.ctx, 60*time.Second)
	defer cancel()
	st, sess, err := e.buildStack(ctx)
	e.mu.Lock()
	if e.closing && err == nil {
		_ = sess.Close()
		_ = st.Close()
		st, sess, err = nil, nil, net.ErrClosed
	}
	if err == nil {
		e.stack, e.session = st, sess
		e.retryAt, e.retryDelay, e.lastErr = time.Time{}, 0, nil
		e.wg.Add(1)
		go e.maintain(st, sess)
	} else {
		if e.retryDelay == 0 {
			e.retryDelay = time.Second
		} else {
			e.retryDelay *= 2
		}
		if e.retryDelay > 30*time.Second {
			e.retryDelay = 30 * time.Second
		}
		e.retryAt, e.lastErr = time.Now().Add(e.retryDelay), err
	}
	flight.stack, flight.err = st, err
	e.flight = nil
	close(flight.done)
	e.mu.Unlock()
}

func (e *enAgentState) maintain(st *stack.Stack, sess *session.Session) {
	defer e.wg.Done()
	ctx, cancel := context.WithCancel(e.ctx)
	bridgeDone := make(chan struct{})
	go func() {
		defer close(bridgeDone)
		select {
		case <-sess.Done():
			cancel()
		case <-ctx.Done():
		}
	}()
	defer func() {
		cancel()
		<-bridgeDone
		_ = sess.Close()
		_ = st.Close()
		e.mu.Lock()
		if e.session == sess {
			e.session, e.stack = nil, nil
		}
		e.mu.Unlock()
	}()
	interval := time.Duration(e.option.RenewInterval) * time.Second
	if interval < 0 {
		<-ctx.Done()
		return
	}
	timer := time.NewTimer(0) // 首次登记虚拟 IP，以后周期维护。
	defer timer.Stop()
	retry := interval
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			auth := sess.Auth()
			req := cas.SessionUpdate{VirtualIP: auth.VirtualIPv4.String(), Gateway: sess.GatewayHost()}
			renewCtx, stop := context.WithTimeout(ctx, defaultEnAgentTimeout)
			err := e.manager.Renew(renewCtx, req)
			stop()
			if ctx.Err() != nil {
				return
			}
			if errors.Is(err, cas.ErrSessionExpired) {
				log.Warnln("enagent[%s]: 控制器会话已失效，下一次连接将重新认证", e.option.Name)
				return
			}
			if errors.Is(err, cas.ErrRenewUnsupported) {
				log.Warnln("enagent[%s]: 控制器不支持会话维护接口，停止周期调用", e.option.Name)
				<-ctx.Done()
				return
			}
			if err != nil {
				log.Warnln("enagent[%s]: 会话维护失败，保留隧道: %v", e.option.Name, err)
				limit := 5 * time.Minute
				if interval > limit {
					limit = interval
				}
				if retry >= limit/2 {
					retry = limit
				} else {
					retry *= 2
				}
			} else {
				retry = interval
			}
			timer.Reset(retry)
		}
	}
}
