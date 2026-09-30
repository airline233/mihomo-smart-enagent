//go:build with_gvisor && !no_enagent

package outbound

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/airline233/mihomo-smart-enagent/cas"
	"github.com/airline233/mihomo-smart-enagent/stack"
)

type enAgentLocalDialer struct {
	allowed      map[string]bool
	blockGateway string
	started      chan struct{}
	once         sync.Once
	gateway      string
	gatewayCalls atomic.Int32
}

func (d *enAgentLocalDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if address == d.gateway {
		d.gatewayCalls.Add(1)
	}
	if address == d.blockGateway {
		d.once.Do(func() { close(d.started) })
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if !d.allowed[address] {
		return nil, fmt.Errorf("测试禁止访问非本地地址 %s", address)
	}
	return (&net.Dialer{}).DialContext(ctx, network, address)
}
func (d *enAgentLocalDialer) ListenPacket(context.Context, string, string, netip.AddrPort) (net.PacketConn, error) {
	return nil, errors.New("unused")
}

func enAgentFixture(t *testing.T, block bool, modes ...string) (EnAgentOption, *atomic.Int32, *atomic.Int32, *atomic.Int32) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	var connections, rules, renew atomic.Int32
	mode := ""
	if len(modes) != 0 {
		mode = modes[0]
	}
	var gateway string
	controller := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/enlink/api/client/user/terminal/rules/test-uid":
			rules.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{"code": "200", "data": map[string]any{"token": "test-token", "server": gateway}})
		case "/enlink/api/client/user/updateUserSession":
			renew.Add(1)
			if mode == "unsupported" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			if mode == "expired" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusServiceUnavailable) // 维护失败仍须保持当前隧道。
		default:
			t.Errorf("出现多余控制面请求 %s", r.URL.Path)
			w.WriteHeader(500)
		}
	}))
	t.Cleanup(controller.Close)
	listener, err := tls.Listen("tcp", "127.0.0.1:0", controller.TLS)
	if err != nil {
		t.Fatal(err)
	}
	gateway = listener.Addr().String()
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			connections.Add(1)
			go func() {
				defer conn.Close()
				for {
					hdr := make([]byte, 12)
					if _, err := io.ReadFull(conn, hdr); err != nil {
						return
					}
					n := int(binary.BigEndian.Uint16(hdr[2:4])) - 12
					if n < 0 {
						return
					}
					if _, err := io.CopyN(io.Discard, conn, int64(n)); err != nil {
						return
					}
					if hdr[8] == 1 {
						if mode == "reject" && connections.Load() == 1 {
							_, _ = conn.Write([]byte{1, 2, 0, 12, 0, 0, 0, 0, 1, 0, 0x80, 0})
							return
						}
						// 12 字节握手响应头 + IPv4 TLV + 结束符。
						_, err = conn.Write([]byte{1, 2, 0, 20, 0, 0, 0, 0, 1, 0, 0, 0, 0x0b, 0, 4, 1, 1, 8, 51, 0xff})
					} else {
						_, err = conn.Write([]byte{1, 2, 0, 8, 0, 0, 0, 0})
					}
					if err != nil {
						return
					}
				}
			}()
		}
	}()
	addr := controller.Listener.Addr().String()
	host, port, _ := net.SplitHostPort(addr)
	p, _ := strconv.Atoi(port)
	dialer := &enAgentLocalDialer{allowed: map[string]bool{addr: true, gateway: true}, started: make(chan struct{})}
	dialer.gateway = gateway
	if mode == "fail" {
		delete(dialer.allowed, gateway)
	}
	if block {
		dialer.blockGateway = gateway
	}
	option := EnAgentOption{BasicOption: BasicOption{DialerForAPI: dialer}, Name: "fixture", Server: host, Port: p,
		SkipCertVerify: true, StateDir: t.TempDir(), RenewInterval: 1, HeartbeatTimeout: 2,
		Passkey: map[string]any{"rpId": "authserver.nuist.edu.cn", "credentialId": "test-credential",
			"userId": base64.RawURLEncoding.EncodeToString([]byte("202500000000")), "anonbiometricsd": "test-start",
			"privateKeyPkcs8Pem": string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))}}
	return option, &connections, &rules, &renew
}

func enAgentWithCache(t *testing.T, option EnAgentOption) *EnAgent {
	t.Helper()
	e, err := NewEnAgent(option)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.Close() })
	identity, _ := json.Marshal(map[string]string{"userId": "test-uid", "username": "202500000000"})
	cache := cas.FileCookieCache{Path: filepath.Join(option.StateDir, "state", e.shared.key, enAgentCookieCacheFile)}
	if err := cache.Store(map[string]string{"ENSSESSIONID": "test-session", "clientInfo": base64.StdEncoding.EncodeToString(identity)}); err != nil {
		t.Fatal(err)
	}
	return e
}

func TestEnAgentSharesTunnelAndKeepsItOnRenewFailure(t *testing.T) {
	option, connections, rules, renew := enAgentFixture(t, false)
	first := enAgentWithCache(t, option)
	option.Name = "second"
	second, err := NewEnAgent(option)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = second.Close() })
	if first.shared != second.shared {
		t.Fatal("同账号未共享状态")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	stacks := make(chan *stack.Stack, 12)
	errs := make(chan error, 12)
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); st, err := second.ensureStack(ctx); stacks <- st; errs <- err }()
	}
	wg.Wait()
	close(stacks)
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	var expected *stack.Stack
	for st := range stacks {
		if expected == nil {
			expected = st
		}
		if expected != st {
			t.Fatal("并发请求建立了多个栈")
		}
	}
	deadline := time.Now().Add(time.Second)
	for renew.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if renew.Load() == 0 {
		t.Fatal("未调用会话维护")
	}
	_ = first.Close()
	st, err := second.ensureStack(ctx)
	if err != nil || st != expected {
		t.Fatalf("维护失败或关闭其他节点影响了共享隧道: %v", err)
	}
	if connections.Load() != 1 || rules.Load() != 1 {
		t.Fatalf("重复建连/取 token: %d/%d", connections.Load(), rules.Load())
	}
	if _, err := first.ensureStack(ctx); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("关闭节点仍能使用: %v", err)
	}
	_ = second.Close()
	select {
	case <-second.shared.stopped:
	default:
		t.Fatal("最后一个节点关闭后未回收")
	}
}

func TestEnAgentCanceledWaitAndCloseInterruptBuild(t *testing.T) {
	option, _, _, _ := enAgentFixture(t, true)
	e := enAgentWithCache(t, option)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := e.ensureStack(ctx); done <- err }()
	dialer := option.DialerForAPI.(*enAgentLocalDialer)
	select {
	case <-dialer.started:
	case <-time.After(3 * time.Second):
		t.Fatal("未进入网关拨号")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("等待者无法取消")
	}
	closed := make(chan struct{})
	go func() { _ = e.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("关闭未取消共享建连")
	}
}

func TestEnAgentRejectsConflictingSharedConfiguration(t *testing.T) {
	option, _, _, _ := enAgentFixture(t, false)
	first := enAgentWithCache(t, option)
	option.RoutingMark = 99
	if second, err := NewEnAgent(option); err == nil {
		_ = second.Close()
		t.Fatal("同账号不同路由被静默共享")
	}
	option.RoutingMark = 0
	option.Passkey = map[string]any{}
	for k, v := range first.option.Passkey {
		option.Passkey[k] = v
	}
	option.Passkey["userId"] = base64.RawURLEncoding.EncodeToString([]byte("202599999999"))
	second, err := NewEnAgent(option)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if first.shared.key == second.shared.key {
		t.Fatal("不同账号的会话/缓存未隔离")
	}
}

func TestEnAgentRefreshesRejectedTokenWithoutRelogin(t *testing.T) {
	option, connections, rules, _ := enAgentFixture(t, false, "reject")
	e := enAgentWithCache(t, option)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := e.ensureStack(ctx); err != nil {
		t.Fatal(err)
	}
	if connections.Load() != 2 || rules.Load() != 2 {
		t.Fatalf("拒绝后应只刷新一次 token: %d/%d", connections.Load(), rules.Load())
	}
}

func TestEnAgentFailedFlightUsesBackoff(t *testing.T) {
	option, _, _, _ := enAgentFixture(t, false, "fail")
	e := enAgentWithCache(t, option)
	if _, err := e.ensureStack(context.Background()); err == nil {
		t.Fatal("网关失败应返回错误")
	}
	for i := 0; i < 10; i++ {
		if _, err := e.ensureStack(context.Background()); err == nil {
			t.Fatal("退避期间应复用失败结果")
		}
	}
	if calls := option.DialerForAPI.(*enAgentLocalDialer).gatewayCalls.Load(); calls != 1 {
		t.Fatalf("发生重复拨号: %d", calls)
	}
}

func TestEnAgentRenewUnsupportedDisabledAndExpired(t *testing.T) {
	for _, mode := range []string{"unsupported", "disabled", "expired"} {
		t.Run(mode, func(t *testing.T) {
			option, _, _, renew := enAgentFixture(t, false, mode)
			if mode == "disabled" {
				option.RenewInterval = -1
			}
			e := enAgentWithCache(t, option)
			if _, err := e.ensureStack(context.Background()); err != nil {
				t.Fatal(err)
			}
			if mode == "expired" {
				deadline := time.Now().Add(time.Second)
				for time.Now().Before(deadline) {
					e.shared.mu.Lock()
					cleared := e.shared.session == nil
					e.shared.mu.Unlock()
					if cleared && renew.Load() != 0 {
						if e.shared.manager.Session() != nil {
							t.Fatal("明确过期后仍保留 Cookie 会话")
						}
						return
					}
					time.Sleep(time.Millisecond)
				}
				t.Fatal("明确过期未回收隧道")
			}
			time.Sleep(1200 * time.Millisecond)
			expected := int32(1)
			if mode == "disabled" {
				expected = 0
			}
			if n := renew.Load(); n != expected {
				t.Fatalf("维护调用次数=%d，期望=%d", n, expected)
			}
			if _, err := e.ensureStack(context.Background()); err != nil {
				t.Fatal(err)
			}
		})
	}
}
