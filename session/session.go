// Package session 维护与网关的 TLS 隧道连接：建连、应用层握手、心跳、收发帧。
//
// 这一层只负责"一条隧道"，不管重连策略——连接断掉后 Done() 被关闭，由上层
// （mihomo 的 adapter）决定何时重建。重连必须由上层统一调度，因为同一账号
// 同时只允许一条会话。
package session

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/airline233/mihomo-smart-enagent/tunnel"
)

const (
	defaultDialTimeout       = 5 * time.Second
	defaultHandshakeRetries  = 5
	defaultHandshakeInterval = 1 * time.Second
	defaultHeartbeatInterval = 500 * time.Millisecond
	defaultHandshakeTimeout  = 5 * time.Second
)

// Config 是隧道连接配置。
type Config struct {
	// Host / Port 是网关地址（来自控制器下发的 server 列表）。
	Host string
	Port int
	// User 是明文学号，握手帧的 A 字段。
	//
	// 注意：这和 CAS 表单里的 username 不是一回事——那里是 base64url 的 userId。
	User string
	// Token 是隧道 token，握手帧的 B 字段。必须原样发送（裸 UUID）。
	Token string
	// SkipCertVerify 关闭服务端证书校验。
	//
	// 参考实现里 tls.Config 只写了两个字段：InsecureSkipVerify=true 与
	// MinVersion=TLS1.2，且全库没有证书加载代码（无 mTLS）。默认跟随参考实现，
	// 但移植到生产时建议开启校验或做证书 pin。
	SkipCertVerify bool
	// ServerName 覆盖 SNI。留空时按原客户端规则推断：
	// 网关地址是域名 → 带 SNI；是 IP 字面量 → 不带 SNI。
	ServerName string
	// DialTimeout 默认 5s（原客户端 net.Dialer.Timeout）。
	DialTimeout time.Duration
	// HandshakeRetries 默认 5；HandshakeInterval 默认 1s。
	HandshakeRetries  int
	HandshakeInterval time.Duration
	// HeartbeatInterval 默认 500ms（原客户端周期）。
	HeartbeatInterval time.Duration
	// OnPacket 收到数据帧时回调，参数是**裸 IP 包**。
	// 回调在读循环里同步执行，不要阻塞太久。
	OnPacket func(packet []byte) error
	// Logf 可选日志回调。
	Logf func(format string, args ...any)
	// DialContext 可选：底层拨号器。mihomo 侧注入 component/dialer 的实现，
	// 避免隧道自身流量又绕回自己的 TUN。
	DialContext func(ctx context.Context, network, address string) (net.Conn, error)
}

func (c Config) withDefaults() Config {
	if c.DialTimeout <= 0 {
		c.DialTimeout = defaultDialTimeout
	}
	if c.HandshakeRetries <= 0 {
		c.HandshakeRetries = defaultHandshakeRetries
	}
	if c.HandshakeInterval <= 0 {
		c.HandshakeInterval = defaultHandshakeInterval
	}
	if c.HeartbeatInterval <= 0 {
		c.HeartbeatInterval = defaultHeartbeatInterval
	}
	return c
}

func (c Config) logf(format string, args ...any) {
	if c.Logf != nil {
		c.Logf(format, args...)
	}
}

// Session 是一条已建立的隧道。
type Session struct {
	cfg  Config
	auth tunnel.AuthInfo

	conn net.Conn

	writeMu sync.Mutex
	hbSeq   uint32

	done      chan struct{}
	closeOnce sync.Once
	closeErr  error

	wg sync.WaitGroup
}

// Connect 建立 TLS 连接并完成应用层握手。
func Connect(ctx context.Context, cfg Config) (*Session, error) {
	cfg = cfg.withDefaults()
	if cfg.Host == "" || cfg.Port <= 0 {
		return nil, errors.New("session: 缺少网关地址")
	}
	if cfg.Token == "" {
		return nil, errors.New("session: 缺少隧道 token")
	}
	if cfg.OnPacket == nil {
		return nil, errors.New("session: 缺少 OnPacket 回调")
	}

	raw, err := dialTCP(ctx, cfg)
	if err != nil {
		return nil, err
	}

	tlsConn := tls.Client(raw, &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: cfg.SkipCertVerify, //nolint:gosec // 跟随参考实现，可由上层开启校验
		ServerName:         serverName(cfg),
	})
	handshakeCtx, cancel := context.WithTimeout(ctx, defaultHandshakeTimeout)
	defer cancel()
	if err := tlsConn.HandshakeContext(handshakeCtx); err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("session: TLS 握手失败: %w", err)
	}

	s := &Session{
		cfg:  cfg,
		conn: tlsConn,
		done: make(chan struct{}),
	}
	auth, err := s.authHandshake(ctx)
	if err != nil {
		_ = tlsConn.Close()
		return nil, err
	}
	s.auth = auth
	cfg.logf("session: 隧道就绪 %s", auth.String())

	// 原客户端在握手后立刻发一个心跳，并保持 0.5s 周期。
	s.wg.Add(2)
	go s.heartbeatLoop()
	go s.readLoop()
	return s, nil
}

func dialTCP(ctx context.Context, cfg Config) (net.Conn, error) {
	address := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))
	dial := cfg.DialContext
	if dial == nil {
		dialer := net.Dialer{Timeout: cfg.DialTimeout}
		dial = dialer.DialContext
	}
	conn, err := dial(ctx, "tcp", address)
	if err != nil {
		return nil, fmt.Errorf("session: 连接网关 %s 失败: %w", address, err)
	}
	return conn, nil
}

// serverName 实现原客户端的 SNI 规则：域名带 SNI，IP 字面量不带。
func serverName(cfg Config) string {
	if cfg.ServerName != "" {
		return cfg.ServerName
	}
	if net.ParseIP(cfg.Host) != nil {
		return ""
	}
	return cfg.Host
}

// authHandshake 发送握手帧并解析网关下发的 TLV。
// 失败时按原客户端策略重试：最多 5 次，每次间隔 1s，每次重新发送并重读 12 字节头。
func (s *Session) authHandshake(ctx context.Context) (tunnel.AuthInfo, error) {
	frame, err := tunnel.BuildHandshake(s.cfg.User, s.cfg.Token)
	if err != nil {
		return tunnel.AuthInfo{}, err
	}

	var lastCode string
	for attempt := 1; attempt <= s.cfg.HandshakeRetries; attempt++ {
		if err := ctx.Err(); err != nil {
			return tunnel.AuthInfo{}, err
		}
		s.writeMu.Lock()
		_, err := s.conn.Write(frame)
		s.writeMu.Unlock()
		if err != nil {
			return tunnel.AuthInfo{}, fmt.Errorf("session: 发送握手帧失败: %w", err)
		}

		resp, err := tunnel.ReadHandshakeResponseHeader(s.conn)
		if err != nil {
			return tunnel.AuthInfo{}, fmt.Errorf("session: 读取握手响应失败: %w", err)
		}
		if resp.OK {
			body := make([]byte, resp.BodyLen())
			if len(body) > 0 {
				if _, err := io.ReadFull(s.conn, body); err != nil {
					return tunnel.AuthInfo{}, fmt.Errorf("session: 读取握手响应体失败: %w", err)
				}
			}
			auth, err := tunnel.ParseAuthInfo(body)
			if err != nil {
				return tunnel.AuthInfo{}, err
			}
			return auth, nil
		}

		lastCode = resp.StatusCode()
		s.cfg.logf("session: 网关拒绝握手 code=%s（%s），第 %d/%d 次",
			lastCode, resp.FailureReason(), attempt, s.cfg.HandshakeRetries)
		if attempt == s.cfg.HandshakeRetries {
			break
		}
		select {
		case <-ctx.Done():
			return tunnel.AuthInfo{}, ctx.Err()
		case <-time.After(s.cfg.HandshakeInterval):
		}
	}
	return tunnel.AuthInfo{}, fmt.Errorf("session: 握手失败，最后一次 code=%s（%s）",
		lastCode, tunnel.FailureReasonFor(parseCode(lastCode)))
}

func parseCode(code string) uint16 {
	value, err := strconv.ParseUint(code, 16, 16)
	if err != nil {
		return 0
	}
	return uint16(value)
}

// Auth 返回握手时网关下发的参数（虚拟 IP / 掩码 / 网关 / DNS）。
func (s *Session) Auth() tunnel.AuthInfo { return s.auth }

// Done 在隧道断开时被关闭。
func (s *Session) Done() <-chan struct{} { return s.done }

// IsAlive 报告隧道是否仍然可用。
func (s *Session) IsAlive() bool {
	select {
	case <-s.done:
		return false
	default:
		return true
	}
}

// WriteIP 把一个裸 IP 包通过隧道发出去。
//
// 帧首字节由 tunnel.BuildData 保证是 0x01 —— 写成 0x00 会被网关静默丢弃。
// 写操作持锁串行化，避免心跳帧与数据帧交错。
func (s *Session) WriteIP(packet []byte) error {
	frame, err := tunnel.BuildData(packet)
	if err != nil {
		return err
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if _, err := s.conn.Write(frame); err != nil {
		return fmt.Errorf("session: 发送数据帧失败: %w", err)
	}
	return nil
}

// heartbeatLoop 周期发送心跳帧（+12..15 是 32 位递增计数器，小端）。
func (s *Session) heartbeatLoop() {
	defer s.wg.Done()
	ticker := time.NewTicker(s.cfg.HeartbeatInterval)
	defer ticker.Stop()

	s.sendHeartbeat()
	for {
		select {
		case <-s.done:
			return
		case <-ticker.C:
			s.sendHeartbeat()
		}
	}
}

func (s *Session) sendHeartbeat() {
	s.writeMu.Lock()
	seq := s.hbSeq
	s.hbSeq++
	_, err := s.conn.Write(tunnel.BuildHeartbeat(seq))
	s.writeMu.Unlock()
	if err != nil {
		s.cfg.logf("session: 心跳发送失败: %v", err)
		s.shutdown()
	}
}

// readLoop 读取网关下发的帧。
//
// 网关→客户端是 8 字节头 + **裸 IP 包**（没有 4 字节前缀，别再砍）。
// 控制帧（type=2）必须丢弃而不是注入协议栈。
// 网关会重传未 ACK 的数据、跨 TLS 重连还会重放排队的帧，所以这里不能假设
// 帧与请求一一对应。
func (s *Session) readLoop() {
	defer s.wg.Done()
	for {
		hdr, err := tunnel.ReadResponseHeader(s.conn)
		if err != nil {
			select {
			case <-s.done:
			default:
				s.cfg.logf("session: 读循环结束: %v", err)
				s.shutdown()
			}
			return
		}
		body := make([]byte, hdr.BodyLen())
		if len(body) > 0 {
			if _, err := io.ReadFull(s.conn, body); err != nil {
				s.cfg.logf("session: 读取帧体失败: %v", err)
				s.shutdown()
				return
			}
		}
		if hdr.Type == tunnel.TypeResponse {
			// 控制帧：不注入协议栈。
			continue
		}
		if len(body) == 0 {
			continue
		}
		if err := s.cfg.OnPacket(body); err != nil {
			s.cfg.logf("session: 注入 IP 包失败: %v", err)
		}
	}
}

// shutdown 关闭连接并通知所有内部 goroutine 退出。
//
// 内部 goroutine 只能调它，绝不能调 Close()：Close 会 wg.Wait()，而读循环自己
// 就是 wg 的成员，从读循环里调 Close 等于等自己 —— 直接死锁。
func (s *Session) shutdown() {
	s.closeOnce.Do(func() {
		close(s.done)
		if s.conn != nil {
			s.closeErr = s.conn.Close()
		}
	})
}

// Close 关闭隧道并等待内部 goroutine 退出。可重复调用。
func (s *Session) Close() error {
	s.shutdown()
	s.wg.Wait()
	return s.closeErr
}
