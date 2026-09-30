//go:build with_gvisor && !no_enagent

// EnAgent（NUIST SDP/Enlink 零信任 VPN）outbound。
//
// 这个文件由 mihomo-smart-enagent 仓库以"新增文件"的形式拷进 mihomo 源码树，
// **不是** patch 的一部分 —— 我们自己新增的文件没有冲突风险，只有改动上游文件
// 的地方才需要 patch（见 integration/patches/）。
//
// 协议要点（详见仓库里的 PROTOCOL.md）：
//   - 控制面：CAS + Passkey(WebAuthn) 登录拿会话 Cookie，再取隧道 token 与网关列表
//   - SPA：可选的 UDP/62201 敲门（对数据面并非必需）
//   - 数据面：一条 TLS 连接承载裸 IP 包（12 字节头 + IP 包）
//
// 因为它是 L3 隧道，必须让用户态协议栈（stack 包）把"一条隧道"变成"每连接一个
// net.Conn"，并且 IsL3Protocol() 返回 true，否则 mihomo 的 DNS 模块会把域名
// 透传下来，而网关下发的 DNS 是 127.0.0.1（隧道内 DNS），会形成环路。
package outbound

import (
	"context"
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
	"github.com/airline233/mihomo-smart-enagent/spa"
	"github.com/airline233/mihomo-smart-enagent/stack"
	enagenttunnel "github.com/airline233/mihomo-smart-enagent/tunnel"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
)

const (
	defaultEnAgentPort          = 443
	defaultEnAgentTimeout       = 30 * time.Second
	enAgentCookieCacheFile      = "session-cookies.json"
	enAgentSPAKnockDelay        = 400 * time.Millisecond
	enAgentSessionCacheFileName = "state"
)

// EnAgentOption 是这个 outbound 的配置。
//
// 注意 passkey 声明成 map[string]any 而不是嵌套 struct：mihomo 的 structure
// 解码器会做键名规范化（rpId → rpid、privateKeyPkcs8Pem → privatekeypkcs8pem），
// 用 map 接住原始对象就能让 passkey.local.json 的字段名**原样粘贴**。
type EnAgentOption struct {
	BasicOption
	Name string `proxy:"name"`
	// Server 是控制器地址，例如 client.vpn.nuist.edu.cn。
	Server string `proxy:"server"`
	// Port 是控制器端口，默认 443。
	Port int `proxy:"port,omitempty"`
	// Username 可选。默认从 passkey bundle 的 userId 反解出学号。
	Username string `proxy:"username,omitempty"`
	// Passkey 是内联的 passkey bundle，字段名与 passkey.local.json 完全一致。
	Passkey map[string]any `proxy:"passkey"`
	// SPA 是否发送 SPA 敲门包。对数据面并非必需，默认关闭。
	SPA bool `proxy:"spa,omitempty"`
	// SkipCertVerify 关闭 TLS 证书校验。
	//
	// 参考实现（enuep.exe 的三处 tls.Config）只设了 InsecureSkipVerify=true 与
	// MinVersion=TLS1.2，且全库没有证书加载代码。默认跟随参考实现，可显式设 false
	// 开启校验。
	SkipCertVerify bool `proxy:"skip-cert-verify,omitempty"`
	// StateDir 可选：会话 Cookie 缓存目录，用于跨重启复用会话、避免每次重启都跑
	// CAS 登录。留空则只在内存里维持会话。
	StateDir string `proxy:"state-dir,omitempty"`
	// UDP 是否支持 UDP。IPv6/UDP 数据面尚未在真机上证伪，默认关闭。
	UDP bool `proxy:"udp,omitempty"`
}

// EnAgent 是 outbound 实现。
//
// 没有实现 MarshalJSON，因此继承 Base.MarshalJSON（只输出 {"type","id"}）。
// 这一点很重要：内联在配置里的 passkey 私钥**绝不能**经外部控制器 API 泄露出去。
type EnAgent struct {
	*Base
	option EnAgentOption

	baseDialer C.Dialer

	mu      sync.Mutex
	manager *cas.Manager
	stack   *stack.Stack
	session *session.Session
}

func NewEnAgent(option EnAgentOption) (*EnAgent, error) {
	bundle, err := passkey.Parse(option.Passkey)
	if err != nil {
		return nil, fmt.Errorf("enagent[%s]: %w", option.Name, err)
	}
	if option.Server == "" {
		return nil, fmt.Errorf("enagent[%s]: 缺少 server", option.Name)
	}
	if option.Port <= 0 {
		option.Port = defaultEnAgentPort
	}

	username := option.Username
	if username == "" {
		// 握手帧的 A 字段是明文学号，可以从 bundle 的 userId 反解。
		if username, err = bundle.Username(); err != nil {
			return nil, fmt.Errorf("enagent[%s]: 无法确定学号，请显式配置 username: %w", option.Name, err)
		}
	}

	addr := net.JoinHostPort(option.Server, strconv.Itoa(option.Port))
	outbound := &EnAgent{
		Base: NewBase(BaseOption{
			Name:         option.Name,
			Addr:         addr,
			Type:         C.EnAgent,
			ProviderName: option.ProviderName,
			UDP:          option.UDP,
			Interface:    option.Interface,
			RoutingMark:  option.RoutingMark,
			Prefer:       option.IPVersion,
		}),
		option: option,
	}
	outbound.baseDialer = option.NewDialer(outbound.DialOptions())

	managerOpts := cas.ManagerOptions{
		Config: cas.Config{
			Bundle:               bundle,
			Controller:           "https://" + addr,
			Timeout:              defaultEnAgentTimeout,
			ControllerSkipVerify: option.SkipCertVerify,
			// 控制面流量走 mihomo 的 dialer，才能吃到 interface-name /
			// routing-mark，也避免在 TUN auto-route 场景下绕回自己的隧道。
			DialContext: outbound.baseDialer.DialContext,
			Logf: func(format string, args ...any) {
				log.Debugln("enagent[%s] "+format, append([]any{option.Name}, args...)...)
			},
		},
	}
	if option.StateDir != "" {
		managerOpts.Cache = cas.FileCookieCache{
			Path: filepath.Join(option.StateDir, enAgentSessionCacheFileName, enAgentCookieCacheFile),
		}
	} else if cacheDir, cacheErr := os.UserCacheDir(); cacheErr == nil {
		managerOpts.Cache = cas.FileCookieCache{
			Path: filepath.Join(cacheDir, "mihomo-enagent", enAgentCookieCacheFile),
		}
	}
	manager, err := cas.NewManager(managerOpts)
	if err != nil {
		return nil, fmt.Errorf("enagent[%s]: %w", option.Name, err)
	}
	outbound.manager = manager
	return outbound, nil
}

// IsL3Protocol 必须返回 true：本 outbound 是 L3 隧道，网关下发的 DNS 是隧道内的
// 127.0.0.1，让 DNS 模块把域名透传下来会造成环路。
func (e *EnAgent) IsL3Protocol(*C.Metadata) bool { return true }

func (e *EnAgent) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	st, err := e.ensureStack(ctx)
	if err != nil {
		return nil, err
	}
	if err := e.ensureResolved(ctx, metadata); err != nil {
		return nil, err
	}

	address := net.JoinHostPort(metadata.DstIP.String(), strconv.Itoa(int(metadata.DstPort)))
	conn, err := st.DialContext(ctx, "tcp", address)
	if err != nil {
		// 隧道可能已经不可用：丢掉栈，下一次拨号会重建整条链路。
		e.invalidate(err)
		return nil, err
	}
	return NewConn(conn, e), nil
}

func (e *EnAgent) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	if err := e.ResolveUDP(ctx, metadata); err != nil {
		return nil, err
	}
	st, err := e.ensureStack(ctx)
	if err != nil {
		return nil, err
	}

	network := "udp4"
	if metadata.DstIP.Is6() {
		network = "udp6"
	}
	// 绑定本机虚拟地址上的随机端口；目的地由 WriteTo 决定。
	pc, err := st.ListenPacket(ctx, network, net.JoinHostPort("0.0.0.0", "0"))
	if err != nil {
		e.invalidate(err)
		return nil, err
	}
	return NewPacketConn(pc, e), nil
}

func (e *EnAgent) SupportUDP() bool { return e.option.UDP }

// ensureResolved 在 metadata 还没有目标 IP 时补一次解析（正常情况下 mihomo 已经
// 解析过了，因为 IsL3Protocol 会阻止域名被透传）。
func (e *EnAgent) ensureResolved(ctx context.Context, metadata *C.Metadata) error {
	if metadata.DstIP.IsValid() {
		return nil
	}
	if metadata.Host == "" {
		return errors.New("enagent: 目标既没有 IP 也没有域名")
	}
	return e.ResolveUDP(ctx, metadata)
}

// enAgentPacketHandler 在协议栈就绪之前丢弃入站包，避免 Connect 返回前的空指针。
type enAgentPacketHandler struct {
	mu  sync.Mutex
	ptr *stack.Stack
}

func (h *enAgentPacketHandler) set(st *stack.Stack) {
	h.mu.Lock()
	h.ptr = st
	h.mu.Unlock()
}

func (h *enAgentPacketHandler) Inject(packet []byte) error {
	h.mu.Lock()
	st := h.ptr
	h.mu.Unlock()
	if st == nil {
		return nil
	}
	return st.InjectIP(packet)
}

// ensureStack 保证"CAS 会话 + 隧道 + 用户态协议栈"这条链路可用。
//
// 整条链路必须单飞：同一账号同时只允许一条会话，并发建立会互相踢掉。
func (e *EnAgent) ensureStack(ctx context.Context) (*stack.Stack, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.stack != nil && e.session != nil && e.session.IsAlive() {
		return e.stack, nil
	}
	if e.stack != nil {
		_ = e.stack.Close()
		e.stack = nil
	}
	if e.session != nil {
		_ = e.session.Close()
		e.session = nil
	}

	rules, err := e.manager.EnsureRules(ctx, false)
	if err != nil {
		return nil, err
	}
	endpoint, err := rules.FirstEndpoint()
	if err != nil {
		return nil, err
	}

	if e.option.SPA {
		spaPort := rules.SPAPort
		if spaPort <= 0 {
			spaPort = spa.DefaultPort
		}
		if spaHost := rules.SPAHost(); spaHost != "" {
			knockCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			err := spa.Knock(knockCtx, spaHost, spaPort, spa.Options{User: e.username()})
			cancel()
			if err != nil {
				// SPA 不是必需步骤，失败不阻断。
				log.Warnln("enagent[%s]: SPA 敲门失败（忽略）: %v", e.option.Name, err)
			} else {
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-time.After(enAgentSPAKnockDelay):
				}
			}
		}
	}

	handler := &enAgentPacketHandler{}
	sess, err := session.Connect(ctx, session.Config{
		Host:              endpoint.Host,
		Port:              endpoint.Port,
		User:              e.username(),
		Token:             rules.Token,
		SkipCertVerify:    e.option.SkipCertVerify,
		OnPacket:          handler.Inject,
		DialContext:       e.baseDialer.DialContext,
		HeartbeatInterval: 500 * time.Millisecond,
		Logf: func(format string, args ...any) {
			log.Debugln("enagent[%s] "+format, append([]any{e.option.Name}, args...)...)
		},
	})
	if err != nil {
		// 握手失败常见原因是会话/token 过期，让下次重建时重新登录。
		e.manager.Invalidate(true)
		return nil, err
	}

	auth := sess.Auth()
	prefixLen := 32
	if auth.Netmask.IsValid() {
		if bits, err := enagenttunnel.IPv4MaskPrefix(auth.Netmask); err == nil {
			prefixLen = bits
		}
	}
	st, err := stack.New(stack.Options{
		VirtualIPv4: auth.VirtualIPv4,
		PrefixLen:   prefixLen,
		VirtualIPv6: auth.VirtualIPv6,
		Sender:      stack.SenderFunc(sess.WriteIP),
		Logf: func(format string, args ...any) {
			log.Debugln("enagent[%s] "+format, append([]any{e.option.Name}, args...)...)
		},
	})
	if err != nil {
		_ = sess.Close()
		return nil, err
	}
	handler.set(st)

	e.session = sess
	e.stack = st
	log.Infoln("enagent[%s]: 隧道就绪 虚拟IP=%s 网关=%s", e.option.Name, auth.VirtualIPv4, endpoint)
	return st, nil
}

// invalidate 在链路出错时丢弃缓存，让下一次拨号重建。
func (e *EnAgent) invalidate(cause error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.session != nil && !e.session.IsAlive() {
		_ = e.session.Close()
		e.session = nil
	}
	if e.stack != nil && e.session == nil {
		_ = e.stack.Close()
		e.stack = nil
	}
	if cause != nil {
		log.Debugln("enagent[%s]: 链路异常，等待重建: %v", e.option.Name, cause)
	}
}

func (e *EnAgent) username() string {
	if e.option.Username != "" {
		return e.option.Username
	}
	return e.manager.Username()
}

func (e *EnAgent) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.session != nil {
		_ = e.session.Close()
		e.session = nil
	}
	if e.stack != nil {
		_ = e.stack.Close()
		e.stack = nil
	}
	if e.manager != nil {
		e.manager.Close()
	}
	return nil
}
