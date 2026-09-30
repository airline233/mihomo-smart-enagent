package stack

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"
)

// 合成地址：测试里不使用任何真实网络资源的地址。
const (
	testVirtualIP = "1.1.8.51"
	testPeerIP    = "172.16.37.108"
	testPeerPort  = 53
	testDNSPort   = 443
)

// captureSender 把协议栈发出的 IP 包收集到 channel，供测试检查。
type captureSender struct {
	ch chan []byte
}

func newCaptureSender() *captureSender {
	return &captureSender{ch: make(chan []byte, 64)}
}

func (s *captureSender) WriteIP(packet []byte) error {
	select {
	case s.ch <- packet:
	default:
	}
	return nil
}

func (s *captureSender) next(t *testing.T) []byte {
	t.Helper()
	select {
	case p := <-s.ch:
		return p
	case <-time.After(5 * time.Second):
		t.Fatal("等待协议栈发出的 IP 包超时")
		return nil
	}
}

// newTestStack 建一个接到 captureSender 的协议栈。
// 不传 Logf：pump goroutine 可能在测试结束后仍打印，t.Logf 会 panic。
func newTestStack(t *testing.T) (*Stack, *captureSender) {
	t.Helper()
	sender := newCaptureSender()
	st, err := New(Options{
		VirtualIPv4: netip.MustParseAddr(testVirtualIP),
		PrefixLen:   16,
		Sender:      sender,
	})
	if err != nil {
		t.Fatalf("New 失败: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st, sender
}

// TestUDPRoundTripThroughStack 是这一层最有价值的验证：出站包真的带着虚拟源地址
// 走出协议栈，入站包真的能被注入并被已绑定的 UDP 端点收到。
func TestUDPRoundTripThroughStack(t *testing.T) {
	st, sender := newTestStack(t)
	ctx := context.Background()

	pc, err := st.ListenPacket(ctx, "udp4", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("ListenPacket 失败: %v", err)
	}
	defer pc.Close()

	virtualAddr := netip.MustParseAddr(testVirtualIP)
	peerAddr := netip.MustParseAddr(testPeerIP)
	peer := net.UDPAddrFromAddrPort(netip.AddrPortFrom(peerAddr, testPeerPort))

	if _, err := pc.WriteTo([]byte("ping-dns"), peer); err != nil {
		t.Fatalf("WriteTo 失败: %v", err)
	}

	out := sender.next(t)
	src, dst, proto, seg, err := parseIPv4(out)
	if err != nil {
		t.Fatalf("出站包不是合法 IPv4: %v", err)
	}
	if proto != 17 {
		t.Errorf("协议 = %d，期望 UDP(17)", proto)
	}
	if src != virtualAddr {
		t.Errorf("源地址 = %s，期望虚拟 IP %s（说明网卡地址没配上）", src, virtualAddr)
	}
	if dst != peerAddr {
		t.Errorf("目的地址 = %s，期望 %s", dst, peerAddr)
	}
	if len(seg) < 8 {
		t.Fatalf("UDP 段太短: %d", len(seg))
	}
	sport := binary.BigEndian.Uint16(seg[0:2])
	dport := binary.BigEndian.Uint16(seg[2:4])
	if dport != testPeerPort {
		t.Errorf("目的端口 = %d，期望 %d", dport, testPeerPort)
	}
	if got := string(seg[8:]); got != "ping-dns" {
		t.Errorf("载荷 = %q，期望 ping-dns", got)
	}

	// 构造"对端"的回包注入协议栈。
	reply := buildIPv4(peerAddr, virtualAddr, 17,
		buildUDP(testPeerPort, sport, []byte("pong-dns"), peerAddr, virtualAddr))
	if err := st.InjectIP(reply); err != nil {
		t.Fatalf("InjectIP 失败: %v", err)
	}

	if err := pc.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline 失败: %v", err)
	}
	buf := make([]byte, 1500)
	n, from, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom 失败: %v", err)
	}
	if got := string(buf[:n]); got != "pong-dns" {
		t.Errorf("收到载荷 %q，期望 pong-dns", got)
	}
	if from.String() != peer.String() {
		t.Errorf("from = %s，期望 %s", from, peer)
	}
}

// TestDialContextEmitsSYNAndFailsOnReset 验证 TCP 路径的两端：
// DialContext 会真的发出 SYN（源地址正确），注入 RST 后能及时报错。
func TestDialContextEmitsSYNAndFailsOnReset(t *testing.T) {
	st, sender := newTestStack(t)
	virtualAddr := netip.MustParseAddr(testVirtualIP)
	peerAddr := netip.MustParseAddr(testPeerIP)
	target := netip.AddrPortFrom(peerAddr, testDNSPort)

	dialErr := make(chan error, 1)
	go func() {
		conn, err := st.DialContext(context.Background(), "tcp", target.String())
		if err == nil {
			_ = conn.Close()
		}
		dialErr <- err
	}()

	out := sender.next(t)
	src, dst, proto, seg, err := parseIPv4(out)
	if err != nil {
		t.Fatalf("出站包不是合法 IPv4: %v", err)
	}
	if proto != 6 {
		t.Fatalf("协议 = %d，期望 TCP(6)", proto)
	}
	if src != virtualAddr {
		t.Errorf("源地址 = %s，期望虚拟 IP %s", src, virtualAddr)
	}
	if dst != peerAddr {
		t.Errorf("目的地址 = %s，期望 %s", dst, peerAddr)
	}
	if len(seg) < 20 {
		t.Fatalf("TCP 段太短: %d", len(seg))
	}
	sport := binary.BigEndian.Uint16(seg[0:2])
	dport := binary.BigEndian.Uint16(seg[2:4])
	seq := binary.BigEndian.Uint32(seg[4:8])
	if dport != testDNSPort {
		t.Errorf("目的端口 = %d，期望 %d", dport, testDNSPort)
	}
	if seg[13]&0x02 == 0 {
		t.Fatalf("不是 SYN（flags=%#02x）", seg[13])
	}

	// 注入 RST+ACK（ack = SYN.seq + 1）让这次连接被拒。
	rst := buildTCP(dport, sport, 0, seq+1, 0x14, nil, peerAddr, virtualAddr)
	if err := st.InjectIP(buildIPv4(peerAddr, virtualAddr, 6, rst)); err != nil {
		t.Fatalf("InjectIP 失败: %v", err)
	}

	select {
	case err := <-dialErr:
		if err == nil {
			t.Fatal("注入 RST 后 DialContext 应返回错误")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("DialContext 在 RST 之后没有返回")
	}
}

func TestNewValidatesOptions(t *testing.T) {
	valid := Options{
		VirtualIPv4: netip.MustParseAddr(testVirtualIP),
		PrefixLen:   16,
		Sender:      newCaptureSender(),
	}
	cases := map[string]Options{
		"缺虚拟 IP":      {PrefixLen: 16, Sender: valid.Sender},
		"缺 Sender":    {VirtualIPv4: valid.VirtualIPv4, PrefixLen: 16},
		"前缀越界":        {VirtualIPv4: valid.VirtualIPv4, PrefixLen: 33, Sender: valid.Sender},
		"IPv6 当 IPv4": {VirtualIPv4: netip.MustParseAddr("1001::101:833"), PrefixLen: 16, Sender: valid.Sender},
	}
	for name, opts := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := New(opts); err == nil {
				t.Fatal("非法配置应报错")
			}
		})
	}
}

func TestInjectIPRejectsGarbage(t *testing.T) {
	st, _ := newTestStack(t)
	if err := st.InjectIP(nil); err == nil {
		t.Error("空包应报错")
	}
	if err := st.InjectIP([]byte{0x00, 0x01, 0x02}); err == nil {
		t.Error("非 IP 包应报错")
	}
}

func TestDialContextRequiresNumericAddress(t *testing.T) {
	st, _ := newTestStack(t)
	if _, err := st.DialContext(context.Background(), "tcp", "example.com:443"); err == nil {
		t.Fatal("域名应被拒绝（本 outbound 是 L3 协议，域名不该透传到这里）")
	}
	if _, err := st.DialContext(context.Background(), "tcp", "172.16.37.108"); err == nil {
		t.Fatal("缺少端口应被拒绝")
	}
	if _, err := st.DialContext(context.Background(), "unix", "/tmp/x"); err == nil {
		t.Fatal("不支持的网络类型应被拒绝")
	}
}

func TestCloseIsIdempotent(t *testing.T) {
	st, _ := newTestStack(t)
	if err := st.Close(); err != nil {
		t.Fatalf("Close 失败: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("重复 Close 失败: %v", err)
	}
}

// TestChecksumMatchesReference 把测试侧的一补数校验和实现钉在外部参考值上。
// 参考值由独立的 Python 实现算出（见提交说明），这样 TestUDPRoundTripThroughStack
// 里"注入的包不合法"和"协议栈不工作"就能被区分开——这个坑真的踩过。
func TestChecksumMatchesReference(t *testing.T) {
	cases := []struct {
		name string
		data []byte
		want uint16
	}{
		{"普通数据", []byte("hello world checksum test"), 0xca7c},
		{"奇数长度", []byte{0x01, 0x02, 0x03}, 0xfbfd},
		{"全 0xff", []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, 0x0000},
		{"空", nil, 0xffff},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := checksum(c.data); got != c.want {
				t.Fatalf("checksum = %#04x，期望 %#04x", got, c.want)
			}
		})
	}
}

// TestStackAnswersICMPToVirtualIP 验证协议栈确实以网关分配的虚拟 IP 身份在工作：
// 往虚拟 IP 注入 ICMP echo，应当回一个源地址为虚拟 IP 的 echo reply。
func TestStackAnswersICMPToVirtualIP(t *testing.T) {
	st, sender := newTestStack(t)
	virtual := netip.MustParseAddr(testVirtualIP)
	prober := netip.MustParseAddr("202.195.225.220")

	echo := buildICMPEcho(0x1234, 1, []byte("probe"))
	if err := st.InjectIP(buildIPv4(prober, virtual, 1, echo)); err != nil {
		t.Fatalf("InjectIP 失败: %v", err)
	}

	out := sender.next(t)
	src, dst, proto, icmp, err := parseIPv4(out)
	if err != nil {
		t.Fatalf("回包不是合法 IPv4: %v", err)
	}
	if proto != 1 {
		t.Fatalf("协议 = %d，期望 ICMP(1)", proto)
	}
	if src != virtual {
		t.Errorf("回包源地址 = %s，期望虚拟 IP %s", src, virtual)
	}
	if dst != prober {
		t.Errorf("回包目的地址 = %s，期望 %s", dst, prober)
	}
	if len(icmp) < 8 || icmp[0] != 0 {
		t.Errorf("不是 ICMP echo reply: % x", icmp[:min8(len(icmp))])
	}
}

func min8(n int) int {
	if n < 8 {
		return n
	}
	return 8
}

func buildICMPEcho(ident uint16, seq uint16, payload []byte) []byte {
	icmp := make([]byte, 8+len(payload))
	icmp[0] = 8 // echo request
	binary.BigEndian.PutUint16(icmp[4:6], ident)
	binary.BigEndian.PutUint16(icmp[6:8], seq)
	copy(icmp[8:], payload)
	binary.BigEndian.PutUint16(icmp[2:4], checksum(icmp))
	return icmp
}

// ---------- 测试用的报文构造与解析 ----------

func checksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func l4Checksum(segment []byte, proto byte, src, dst netip.Addr) uint16 {
	pseudo := make([]byte, 0, 12+len(segment))
	pseudo = append(pseudo, src.AsSlice()...)
	pseudo = append(pseudo, dst.AsSlice()...)
	pseudo = append(pseudo, 0, proto)
	var length [2]byte
	binary.BigEndian.PutUint16(length[:], uint16(len(segment)))
	pseudo = append(pseudo, length[:]...)
	return checksum(append(pseudo, segment...))
}

func buildIPv4(src, dst netip.Addr, proto byte, payload []byte) []byte {
	// 只分配头部，再 append 载荷：如果先把载荷长度算进 make()，
	// append 会把载荷追加到数组末尾，中间留出一段未初始化的空洞。
	packet := make([]byte, 20)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(20+len(payload)))
	packet[8] = 64
	packet[9] = proto
	copy(packet[12:16], src.AsSlice())
	copy(packet[16:20], dst.AsSlice())
	binary.BigEndian.PutUint16(packet[10:12], checksum(packet[:20]))
	return append(packet, payload...)
}

func buildUDP(sport, dport uint16, payload []byte, src, dst netip.Addr) []byte {
	segment := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(segment[0:2], sport)
	binary.BigEndian.PutUint16(segment[2:4], dport)
	binary.BigEndian.PutUint16(segment[4:6], uint16(len(segment)))
	copy(segment[8:], payload)
	sum := l4Checksum(segment, 17, src, dst)
	if sum == 0 {
		sum = 0xffff
	}
	binary.BigEndian.PutUint16(segment[6:8], sum)
	return segment
}

func buildTCP(sport, dport uint16, seq, ack uint32, flags byte, payload []byte, src, dst netip.Addr) []byte {
	segment := make([]byte, 20+len(payload))
	binary.BigEndian.PutUint16(segment[0:2], sport)
	binary.BigEndian.PutUint16(segment[2:4], dport)
	binary.BigEndian.PutUint32(segment[4:8], seq)
	binary.BigEndian.PutUint32(segment[8:12], ack)
	segment[12] = 5 << 4 // 数据偏移 = 5 个 32 位字
	segment[13] = flags
	binary.BigEndian.PutUint16(segment[14:16], 64240)
	copy(segment[20:], payload)
	binary.BigEndian.PutUint16(segment[16:18], l4Checksum(segment, 6, src, dst))
	return segment
}

func parseIPv4(packet []byte) (src, dst netip.Addr, proto byte, payload []byte, err error) {
	if len(packet) < 20 {
		return netip.Addr{}, netip.Addr{}, 0, nil, fmt.Errorf("包太短: %d", len(packet))
	}
	if packet[0]>>4 != 4 {
		return netip.Addr{}, netip.Addr{}, 0, nil, fmt.Errorf("不是 IPv4（首字节 %#02x）", packet[0])
	}
	headerLen := int(packet[0]&0x0f) * 4
	if headerLen < 20 || len(packet) < headerLen {
		return netip.Addr{}, netip.Addr{}, 0, nil, fmt.Errorf("IPv4 头长度非法: %d", headerLen)
	}
	var srcBytes, dstBytes [4]byte
	copy(srcBytes[:], packet[12:16])
	copy(dstBytes[:], packet[16:20])
	return netip.AddrFrom4(srcBytes), netip.AddrFrom4(dstBytes), packet[9], packet[headerLen:], nil
}
