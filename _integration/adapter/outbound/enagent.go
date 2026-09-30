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
	"strconv"
	"strings"
	"sync"
	"time"

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
	// CAS 登录。留空使用系统缓存目录；缓存按控制器和账号隔离。
	StateDir string `proxy:"state-dir,omitempty"`
	// UDP 是否支持 UDP，配置解析时默认开启；IPv6 强制关闭。
	UDP bool `proxy:"udp,omitempty"`
	// RenewInterval 为会话维护间隔（秒），0 使用默认 60，-1 禁用。
	RenewInterval int `proxy:"renew-interval,omitempty"`
	// HeartbeatTimeout 为等待入站帧的超时（秒），默认 30。
	HeartbeatTimeout int `proxy:"heartbeat-timeout,omitempty"`
}

// EnAgent 是 outbound 实现。
//
// 没有实现 MarshalJSON，因此继承 Base.MarshalJSON（只输出 {"type","id"}）。
// 这一点很重要：内联在配置里的 passkey 私钥**绝不能**经外部控制器 API 泄露出去。
type EnAgent struct {
	*Base
	option    EnAgentOption
	shared    *enAgentState
	closed    chan struct{}
	closeOnce sync.Once
}

func NewEnAgent(option EnAgentOption) (*EnAgent, error) {
	bundle, err := passkey.Parse(option.Passkey)
	if err != nil {
		return nil, fmt.Errorf("enagent[%s]: %w", option.Name, err)
	}
	if option.Server == "" {
		return nil, fmt.Errorf("enagent[%s]: 缺少 server", option.Name)
	}
	if option.Port == 0 {
		option.Port = defaultEnAgentPort
	}
	if option.Port < 1 || option.Port > 65535 {
		return nil, errors.New("enagent: port 必须在 1–65535 之间")
	}

	username := option.Username
	if username == "" {
		// 握手帧的 A 字段是明文学号，可以从 bundle 的 userId 反解。
		if username, err = bundle.Username(); err != nil {
			return nil, fmt.Errorf("enagent[%s]: 无法确定学号，请显式配置 username: %w", option.Name, err)
		}
	}

	expected, err := bundle.Username()
	if err != nil || username != expected {
		return nil, errors.New("enagent: username 与 Passkey 账号不一致")
	}
	option.Username = username
	option.Server = strings.ToLower(strings.TrimSuffix(option.Server, "."))
	option.IPVersion = C.IPv4Only
	maxSeconds := int64((1<<63 - 1) / int64(time.Second))
	if option.RenewInterval < -1 || option.HeartbeatTimeout < 0 || int64(option.RenewInterval) > maxSeconds || int64(option.HeartbeatTimeout) > maxSeconds {
		return nil, errors.New("enagent: 会话维护或心跳超时配置非法")
	}
	if option.RenewInterval == 0 {
		option.RenewInterval = 60
	}
	if option.HeartbeatTimeout == 0 {
		option.HeartbeatTimeout = 30
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
		closed: make(chan struct{}),
	}
	shared, err := acquireEnAgentState(option, bundle, option.NewDialer(outbound.DialOptions()))
	if err != nil {
		return nil, err
	}
	outbound.shared = shared
	return outbound, nil
}

// IsL3Protocol 必须返回 true：本 outbound 是 L3 隧道，网关下发的 DNS 是隧道内的
// 127.0.0.1，让 DNS 模块把域名透传下来会造成环路。
func (e *EnAgent) IsL3Protocol(*C.Metadata) bool { return true }

func (e *EnAgent) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	if err := e.ensureResolved(ctx, metadata); err != nil {
		return nil, err
	}
	st, err := e.ensureStack(ctx)
	if err != nil {
		return nil, err
	}

	address := net.JoinHostPort(metadata.DstIP.String(), strconv.Itoa(int(metadata.DstPort)))
	conn, err := st.DialContext(ctx, "tcp", address)
	if err != nil {
		// 隧道可能已经不可用：丢掉栈，下一次拨号会重建整条链路。
		e.shared.invalidate(err)
		return nil, err
	}
	return NewConn(conn, e), nil
}

func (e *EnAgent) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	if !e.option.UDP {
		return nil, errors.New("enagent: UDP 已禁用")
	}
	if err := e.ResolveUDP(ctx, metadata); err != nil {
		return nil, err
	}
	st, err := e.ensureStack(ctx)
	if err != nil {
		return nil, err
	}

	// 绑定本机虚拟地址上的随机端口；目的地由 WriteTo 决定。
	pc, err := st.ListenPacket(ctx, "udp4", "0.0.0.0:0")
	if err != nil {
		e.shared.invalidate(err)
		return nil, err
	}
	return NewPacketConn(pc, e), nil
}

func (e *EnAgent) SupportUDP() bool { return e.option.UDP }

func (e *EnAgent) ResolveUDP(ctx context.Context, metadata *C.Metadata) error {
	if metadata.DstIP.IsValid() && !metadata.DstIP.Unmap().Is4() {
		return errors.New("enagent: IPv6 已禁用")
	}
	if err := e.Base.ResolveUDP(ctx, metadata); err != nil {
		return err
	}
	metadata.DstIP = metadata.DstIP.Unmap()
	if !metadata.DstIP.Is4() {
		return errors.New("enagent: 目标必须是 IPv4 地址")
	}
	return nil
}

// ensureResolved 在 metadata 还没有目标 IP 时补一次解析（正常情况下 mihomo 已经
// 解析过了，因为 IsL3Protocol 会阻止域名被透传）。
func (e *EnAgent) ensureResolved(ctx context.Context, metadata *C.Metadata) error {
	if metadata.DstIP.IsValid() {
		return e.ResolveUDP(ctx, metadata)
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

func (e *EnAgent) ensureStack(ctx context.Context) (*stack.Stack, error) {
	return e.shared.ensureStack(ctx, e.closed)
}

// buildStack 仅在共享建连任务中运行，不持有状态锁。
func (e *enAgentState) buildStack(ctx context.Context) (*stack.Stack, *session.Session, error) {
	handler := &enAgentPacketHandler{}
	sess, err := e.connectTunnel(ctx, handler)
	if err != nil {
		return nil, nil, err
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
		Sender:      stack.SenderFunc(sess.WriteIP),
		Logf: func(format string, args ...any) {
			log.Debugln("enagent[%s] "+format, append([]any{e.option.Name}, args...)...)
		},
	})
	if err != nil {
		_ = sess.Close()
		return nil, nil, err
	}
	handler.set(st)

	log.Infoln("enagent[%s]: 隧道就绪 虚拟IP=%s 网关=%s", e.option.Name, auth.VirtualIPv4, sess.GatewayHost())
	return st, sess, nil
}

// invalidate 不因为单个目标连接失败而销毁共享隧道；死亡隧道由监控任务回收。
func (e *enAgentState) invalidate(cause error) {
	if cause != nil {
		log.Debugln("enagent[%s]: 目标连接失败: %v", e.option.Name, cause)
	}
}

func (e *EnAgent) Close() error {
	e.closeOnce.Do(func() { close(e.closed); releaseEnAgentState(e.shared) })
	return nil
}

// connectTunnel 先复用 token；明确拒绝时最多刷新一次，并在同一次建连中重试。
// 网络错误只尝试其他网关地址，不触发 CAS 登录。
func (e *enAgentState) connectTunnel(ctx context.Context, handler *enAgentPacketHandler) (*session.Session, error) {
	var lastErr error
	for refresh := 0; refresh < 2; refresh++ {
		rules, err := e.manager.EnsureRules(ctx, refresh != 0)
		if err != nil {
			return nil, err
		}
		rejected := false
		seen := make(map[string]bool)
		for _, endpoint := range rules.Servers {
			if seen[endpoint.String()] {
				continue
			}
			seen[endpoint.String()] = true
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if e.option.SPA {
				port := rules.SPAPort
				if port <= 0 {
					port = spa.DefaultPort
				}
				knockCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
				err := spa.Knock(knockCtx, endpoint.Host, port, spa.Options{
					User: e.option.Username, Access: "tcp/" + strconv.Itoa(endpoint.Port),
				})
				cancel()
				if err != nil {
					log.Warnln("enagent[%s]: SPA 敲门失败: %v", e.option.Name, err)
				} else {
					select {
					case <-ctx.Done():
						return nil, ctx.Err()
					case <-time.After(enAgentSPAKnockDelay):
					}
				}
			}
			sess, err := session.Connect(ctx, session.Config{
				Host: endpoint.Host, Port: endpoint.Port, User: e.option.Username, Token: rules.Token,
				SkipCertVerify: e.option.SkipCertVerify, OnPacket: handler.Inject,
				DialContext: e.baseDialer.DialContext, HandshakeRetries: 1,
				HeartbeatInterval: 500 * time.Millisecond,
				ReadTimeout:       time.Duration(e.option.HeartbeatTimeout) * time.Second,
				Logf: func(format string, args ...any) {
					log.Debugln("enagent[%s] "+format, append([]any{e.option.Name}, args...)...)
				},
			})
			if err == nil {
				return sess, nil
			}
			lastErr = err
			var rejection *session.RejectedError
			if errors.As(err, &rejection) {
				rejected = true
				break
			}
		}
		if !rejected {
			break
		}
		e.manager.Invalidate(false)
	}
	if lastErr == nil {
		lastErr = errors.New("enagent: 没有可用网关")
	}
	return nil, lastErr
}
