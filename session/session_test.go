package session

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/airline233/mihomo-smart-enagent/tunnel"
)

// 合成凭据与地址：测试里不使用任何真实账号或真实网络资源。
const (
	testUser  = "202500000000"
	testToken = "00000000-0000-0000-0000-000000000001"
)

func generateCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("生成密钥失败: %v", err)
	}
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "enagent-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("签发证书失败: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func appendTLV(dst []byte, typ byte, value []byte) []byte {
	dst = append(dst, typ, byte(len(value)>>8), byte(len(value)))
	return append(dst, value...)
}

// handshakeBody 复刻网关下发的 TLV 体。
func handshakeBody() []byte {
	var body []byte
	body = appendTLV(body, tunnel.TLVVirtualIPv4, []byte{1, 1, 8, 51})
	body = appendTLV(body, tunnel.TLVNetmask, []byte{255, 255, 0, 0})
	body = appendTLV(body, tunnel.TLVGateway, []byte{1, 1, 1, 1})
	body = appendTLV(body, tunnel.TLVDNSv4, []byte("127.0.0.1"))
	body = appendTLV(body, tunnel.TLVSessionFlag, []byte{0})
	body = appendTLV(body, tunnel.TLVVirtualIPv6, []byte{
		0x10, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x01, 0x08, 0x33,
	})
	body = appendTLV(body, tunnel.TLVDNSv6, []byte{
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
	})
	return append(body, tunnel.TLVEnd)
}

func handshakeResponse(code uint16) []byte {
	body := handshakeBody()
	if code != 0 {
		body = nil
	}
	hdr := make([]byte, tunnel.HeaderLen)
	hdr[0] = 1
	hdr[1] = 2
	binary.BigEndian.PutUint16(hdr[2:4], uint16(tunnel.HeaderLen+len(body)))
	if code == 0 {
		hdr[8] = 1
	}
	binary.BigEndian.PutUint16(hdr[10:12], code)
	return append(hdr, body...)
}

// dataFrame 构造网关→客户端方向的数据帧：8 字节头 + 裸 IP 包。
func dataFrame(typ byte, packet []byte) []byte {
	frame := make([]byte, tunnel.ResponseHeaderLen+len(packet))
	frame[0] = 1
	frame[1] = typ
	binary.BigEndian.PutUint16(frame[2:4], uint16(len(frame)))
	copy(frame[tunnel.ResponseHeaderLen:], packet)
	return frame
}

func minimalIPPacket() []byte {
	packet := make([]byte, 20)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], 20)
	packet[9] = 1
	return packet
}

// gateway 是本地假网关：接受一条 TLS 连接并跑最小可用的网关协议。
type gateway struct {
	listener net.Listener
	host     string
	port     int

	// handshakeCode 非 0 时握手一定失败。
	handshakeCode uint16

	// onDataFrame 收到客户端数据帧时调用（参数是**裸 IP 包**），返回值会作为
	// 一个数据帧回给客户端；返回 nil 表示不回。
	onDataFrame func(packet []byte) []byte
	// afterHandshake 握手成功后调用一次，用于主动下发帧。
	afterHandshake func(conn net.Conn)

	dataFrames chan []byte
	errs       chan error
}

func newGateway(t *testing.T, g *gateway) *gateway {
	t.Helper()
	if g == nil {
		g = &gateway{}
	}
	g.dataFrames = make(chan []byte, 16)
	g.errs = make(chan error, 4)

	cert := generateCert(t)
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatalf("监听失败: %v", err)
	}
	g.listener = listener
	host, portText, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatalf("解析监听地址失败: %v", err)
	}
	g.host = host
	g.port, err = strconv.Atoi(portText)
	if err != nil {
		t.Fatalf("解析端口失败: %v", err)
	}

	go g.serve()
	t.Cleanup(func() { _ = listener.Close() })
	return g
}

func (g *gateway) serve() {
	conn, err := g.listener.Accept()
	if err != nil {
		return
	}
	defer conn.Close()
	g.handle(conn)
}

func (g *gateway) handle(conn net.Conn) {
	// 1) 读握手帧并逐字节比对
	expect, err := tunnel.BuildHandshake(testUser, testToken)
	if err != nil {
		g.errs <- err
		return
	}
	frame := make([]byte, len(expect))
	if _, err := io.ReadFull(conn, frame); err != nil {
		g.errs <- fmt.Errorf("读取握手帧失败: %w", err)
		return
	}
	if !bytes.Equal(frame, expect) {
		g.errs <- fmt.Errorf("握手帧与预期不一致:\n got % x\nwant % x", frame, expect)
		return
	}

	// 2) 回握手响应
	if _, err := conn.Write(handshakeResponse(g.handshakeCode)); err != nil {
		g.errs <- err
		return
	}
	if g.handshakeCode != 0 {
		// 客户端每次重试都会重发握手帧并重读 12 字节头，所以这里必须逐次应答，
		// 否则双方互等。顺带让连接保持到客户端主动关闭，避免 RST 丢掉在途响应。
		for {
			frame := make([]byte, len(expect))
			if _, err := io.ReadFull(conn, frame); err != nil {
				return
			}
			if _, err := conn.Write(handshakeResponse(g.handshakeCode)); err != nil {
				return
			}
		}
	}

	if g.afterHandshake != nil {
		g.afterHandshake(conn)
	}

	// 3) 读后续帧（心跳 + 数据）
	for {
		hdr := make([]byte, tunnel.ResponseHeaderLen)
		if _, err := io.ReadFull(conn, hdr); err != nil {
			return
		}
		total := int(binary.BigEndian.Uint16(hdr[2:4]))
		if total < tunnel.ResponseHeaderLen {
			g.errs <- fmt.Errorf("帧总长非法: %d", total)
			return
		}
		rest := make([]byte, total-tunnel.ResponseHeaderLen)
		if _, err := io.ReadFull(conn, rest); err != nil {
			return
		}
		if hdr[1] != tunnel.TypeDataV4 && hdr[1] != tunnel.TypeDataV6 {
			continue // 心跳/控制帧
		}
		if len(rest) < 4 {
			g.errs <- fmt.Errorf("数据帧缺少 4 字节占位: % x", rest)
			return
		}
		// 客户端帧头 12 字节，而这里只读了 8 字节，所以 rest 前 4 字节是占位字段。
		packet := append([]byte(nil), rest[4:]...)
		g.dataFrames <- packet
		if g.onDataFrame != nil {
			if reply := g.onDataFrame(packet); reply != nil {
				if _, err := conn.Write(dataFrame(tunnel.TypeDataV4, reply)); err != nil {
					return
				}
			}
		}
	}
}

func TestConnectHandshakeHeartbeatAndData(t *testing.T) {
	packets := make(chan []byte, 16)
	gw := newGateway(t, &gateway{
		onDataFrame: func(packet []byte) []byte {
			// 回一个"echo reply"形状的包
			reply := append([]byte(nil), packet...)
			reply[9] = 1
			return reply
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	sess, err := Connect(ctx, Config{
		Host:  gw.host,
		Port:  gw.port,
		User:  testUser,
		Token: testToken,
		// 自签证书：验证确实会失败，所以这里跟随参考实现关闭校验。
		SkipCertVerify:    true,
		HeartbeatInterval: 50 * time.Millisecond,
		OnPacket: func(packet []byte) error {
			packets <- append([]byte(nil), packet...)
			return nil
		},
	})
	if err != nil {
		t.Fatalf("Connect 失败: %v", err)
	}
	defer sess.Close()

	auth := sess.Auth()
	if auth.VirtualIPv4 != netip.MustParseAddr("1.1.8.51") {
		t.Errorf("虚拟 IPv4 = %s，期望 1.1.8.51", auth.VirtualIPv4)
	}
	if auth.Gateway != netip.MustParseAddr("1.1.1.1") {
		t.Errorf("网关 = %s", auth.Gateway)
	}
	if auth.DNSv4 != "127.0.0.1" {
		t.Errorf("DNS = %q", auth.DNSv4)
	}
	if !sess.IsAlive() {
		t.Fatal("会话应为存活状态")
	}

	// 发一个 IP 包，假网关应原样收到（校验它拿到的是裸 IP 包）
	packet := minimalIPPacket()
	if err := sess.WriteIP(packet); err != nil {
		t.Fatalf("WriteIP 失败: %v", err)
	}

	select {
	case got := <-gw.dataFrames:
		if !bytes.Equal(got, packet) {
			t.Errorf("网关收到的载荷 = % x，期望 % x", got, packet)
		}
	case err := <-gw.errs:
		t.Fatalf("假网关报错: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("网关没有收到数据帧")
	}

	// 假网关的回包应经读循环交给 OnPacket
	select {
	case got := <-packets:
		if !bytes.Equal(got, packet) {
			t.Errorf("OnPacket 收到 % x，期望 % x", got, packet)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("OnPacket 没有收到回包")
	}

	// 心跳应当周期发出（假网关读循环会消费它们，不报错即证明帧格式可读）
	select {
	case err := <-gw.errs:
		t.Fatalf("假网关报错: %v", err)
	case <-time.After(200 * time.Millisecond):
	}

	if err := sess.Close(); err != nil {
		t.Logf("Close 返回: %v", err)
	}
	select {
	case <-sess.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("Close 之后 Done 应被关闭")
	}
	if sess.IsAlive() {
		t.Error("关闭后 IsAlive 应为 false")
	}
	// 重复 Close 不应 panic 或阻塞
	if err := sess.Close(); err != nil {
		t.Logf("重复 Close 返回: %v", err)
	}
}

// TestControlFramesAreDropped 网关下发的控制帧（type=2）不得注入协议栈。
func TestControlFramesAreDropped(t *testing.T) {
	packets := make(chan []byte, 4)
	gw := newGateway(t, &gateway{
		afterHandshake: func(conn net.Conn) {
			// 先发一个控制帧（不应被注入），再发一个数据帧（应被注入）
			_, _ = conn.Write(dataFrame(tunnel.TypeResponse, minimalIPPacket()))
			_, _ = conn.Write(dataFrame(tunnel.TypeDataV4, minimalIPPacket()))
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	sess, err := Connect(ctx, Config{
		Host:              gw.host,
		Port:              gw.port,
		User:              testUser,
		Token:             testToken,
		SkipCertVerify:    true,
		HeartbeatInterval: time.Hour, // 本用例不需要心跳干扰
		OnPacket: func(packet []byte) error {
			packets <- append([]byte(nil), packet...)
			return nil
		},
	})
	if err != nil {
		t.Fatalf("Connect 失败: %v", err)
	}
	defer sess.Close()

	select {
	case got := <-packets:
		if len(got) != 20 {
			t.Errorf("注入的包长度 = %d，期望 20", len(got))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("数据帧没有被注入")
	}

	// 控制帧不该产生第二次注入
	select {
	case extra := <-packets:
		t.Fatalf("控制帧也被注入了: % x", extra)
	case <-time.After(300 * time.Millisecond):
	}
}

func TestConnectReportsGatewayRejection(t *testing.T) {
	gw := newGateway(t, &gateway{handshakeCode: 0x8000})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := Connect(ctx, Config{
		Host:              gw.host,
		Port:              gw.port,
		User:              testUser,
		Token:             testToken,
		SkipCertVerify:    true,
		HandshakeRetries:  2,
		HandshakeInterval: time.Millisecond,
		OnPacket:          func([]byte) error { return nil },
	})
	if err == nil {
		t.Fatal("网关拒绝时 Connect 应返回错误")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("8000")) {
		t.Errorf("错误信息应包含状态码 8000: %v", err)
	}
	if !bytes.Contains([]byte(err.Error()), []byte("错误 13")) {
		t.Errorf("错误信息应包含原客户端的分类: %v", err)
	}
}

func TestConnectValidatesConfig(t *testing.T) {
	onPacket := func([]byte) error { return nil }
	cases := map[string]Config{
		"缺地址":     {Token: testToken, OnPacket: onPacket},
		"缺 token": {Host: "1.1.1.1", Port: 443, OnPacket: onPacket},
		"缺回调":     {Host: "1.1.1.1", Port: 443, Token: testToken},
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Connect(context.Background(), cfg); err == nil {
				t.Fatal("非法配置应报错")
			}
		})
	}
}

func TestServerNameFollowsSNIRule(t *testing.T) {
	// 域名带 SNI、IP 字面量不带 —— 与原客户端 tls.Dial 的行为一致。
	if got := serverName(Config{Host: "client.vpn.nuist.edu.cn"}); got != "client.vpn.nuist.edu.cn" {
		t.Errorf("域名 ServerName = %q", got)
	}
	if got := serverName(Config{Host: "202.195.225.220"}); got != "" {
		t.Errorf("IP 不应带 SNI，实际 %q", got)
	}
	if got := serverName(Config{Host: "202.195.225.220", ServerName: "override.example"}); got != "override.example" {
		t.Errorf("显式 ServerName 应生效，实际 %q", got)
	}
}

func TestWithDefaults(t *testing.T) {
	cfg := Config{}.withDefaults()
	if cfg.DialTimeout != defaultDialTimeout {
		t.Errorf("DialTimeout = %v", cfg.DialTimeout)
	}
	if cfg.HandshakeRetries != defaultHandshakeRetries {
		t.Errorf("HandshakeRetries = %d", cfg.HandshakeRetries)
	}
	if cfg.HeartbeatInterval != defaultHeartbeatInterval {
		t.Errorf("HeartbeatInterval = %v", cfg.HeartbeatInterval)
	}
	if cfg.HandshakeInterval != defaultHandshakeInterval {
		t.Errorf("HandshakeInterval = %v", cfg.HandshakeInterval)
	}
}
