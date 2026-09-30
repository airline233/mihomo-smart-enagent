package tunnel

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"strings"
	"testing"
)

// 合成凭据：测试里绝不使用真实学号或真实 token。
const (
	testUser  = "202500000000"
	testToken = "00000000-0000-0000-0000-000000000000"
)

func appendTLV(dst []byte, typ byte, value []byte) []byte {
	dst = append(dst, typ, byte(len(value)>>8), byte(len(value)))
	return append(dst, value...)
}

// goldenResponseHeader 是现网 24 次采样完全一致的成功握手响应头。
var goldenResponseHeader = [HeaderLen]byte{1, 2, 0, 88, 0, 0, 0, 0, 1, 0, 0, 0}

// goldenAuthBody 按 PROTOCOL.md §4.2 逐项复刻的 76 字节 TLV 体。
// 逐字节钉死它是为了挡住"把 0x0B 读成 0x11""把 DNS 当 4 字节二进制"这类误读。
func goldenAuthBody() []byte {
	var body []byte
	body = appendTLV(body, TLVVirtualIPv4, []byte{1, 1, 8, 51}) // 1.1.8.51
	body = appendTLV(body, TLVNetmask, []byte{255, 255, 0, 0})  // 255.255.0.0
	body = appendTLV(body, TLVGateway, []byte{1, 1, 1, 1})      // 1.1.1.1
	body = appendTLV(body, TLVDNSv4, []byte("127.0.0.1"))       // 9 字节 ASCII
	body = appendTLV(body, TLVSessionFlag, []byte{0})
	// 1001::101:833
	body = appendTLV(body, TLVVirtualIPv6, []byte{
		0x10, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x08, 0x33,
	})
	// ::1
	body = appendTLV(body, TLVDNSv6, []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	})
	return append(body, TLVEnd)
}

func minimalIPv4() []byte {
	pkt := make([]byte, 20)
	pkt[0] = 0x45
	pkt[2] = 0x00
	pkt[3] = 0x14
	return pkt
}

func TestBuildHandshakeLayout(t *testing.T) {
	frame, err := BuildHandshake(testUser, testToken)
	if err != nil {
		t.Fatalf("BuildHandshake 失败: %v", err)
	}

	wantLen := HeaderLen + 3 + len(testUser) + 3 + len(testToken) + 1
	if len(frame) != wantLen {
		t.Fatalf("帧长 = %d，期望 %d", len(frame), wantLen)
	}
	if frame[0] != Magic {
		t.Errorf("+0 = %#02x，必须是 %#02x", frame[0], Magic)
	}
	if frame[1] != TypeRequest {
		t.Errorf("+1 = %#02x，期望 %#02x", frame[1], TypeRequest)
	}
	if got := binary.BigEndian.Uint16(frame[2:4]); int(got) != len(frame) {
		t.Errorf("+2..3 总长 = %d，期望 %d（必须回填）", got, len(frame))
	}
	if !bytes.Equal(frame[4:8], []byte{0, 0, 0, 0}) {
		t.Errorf("+4..7 = % x，期望全 0", frame[4:8])
	}
	if !bytes.Equal(frame[8:12], []byte{1, 0, 0, 0}) {
		t.Errorf("+8..11 = % x，期望 01 00 00 00", frame[8:12])
	}
	if frame[12] != 0x01 || frame[13] != 0x00 {
		t.Errorf("+12..13 = %#02x %#02x，期望 01 00", frame[12], frame[13])
	}
	if int(frame[14]) != len(testUser) {
		t.Errorf("+14 = %d，期望 len(A) = %d", frame[14], len(testUser))
	}
	aEnd := 15 + len(testUser)
	if !bytes.Equal(frame[15:aEnd], []byte(testUser)) {
		t.Errorf("A 字段 = %q，期望 %q", frame[15:aEnd], testUser)
	}
	if frame[aEnd] != 0x02 || frame[aEnd+1] != 0x00 {
		t.Errorf("B 的标签 = %#02x %#02x，期望 02 00", frame[aEnd], frame[aEnd+1])
	}
	if int(frame[aEnd+2]) != len(testToken) {
		t.Errorf("B 的长度字节 = %d，期望 %d", frame[aEnd+2], len(testToken))
	}
	bEnd := aEnd + 3 + len(testToken)
	if !bytes.Equal(frame[aEnd+3:bEnd], []byte(testToken)) {
		t.Errorf("B 字段 = %q，期望 %q", frame[aEnd+3:bEnd], testToken)
	}
	if frame[bEnd] != TLVEnd {
		t.Errorf("结束符 = %#02x，期望 %#02x", frame[bEnd], TLVEnd)
	}
}

func TestBuildHandshakeRejectsTooLongField(t *testing.T) {
	if _, err := BuildHandshake(strings.Repeat("x", MaxStringField+1), testToken); err == nil {
		t.Fatal("超长 A 字段应报错（单字节长度前缀装不下）")
	}
	if _, err := BuildHandshake(testUser, strings.Repeat("x", MaxStringField+1)); err == nil {
		t.Fatal("超长 B 字段应报错")
	}
}

func TestBuildDataLayout(t *testing.T) {
	packet := minimalIPv4()
	frame, err := BuildData(packet)
	if err != nil {
		t.Fatalf("BuildData 失败: %v", err)
	}
	if len(frame) != len(packet)+HeaderLen {
		t.Fatalf("帧长 = %d，期望 %d", len(frame), len(packet)+HeaderLen)
	}
	if frame[0] != Magic {
		t.Errorf("+0 = %#02x，必须是 %#02x（写成 0x00 会被静默丢弃）", frame[0], Magic)
	}
	if frame[1] != TypeDataV4 {
		t.Errorf("+1 = %#02x，期望 %#02x", frame[1], TypeDataV4)
	}
	if got := binary.BigEndian.Uint16(frame[2:4]); int(got) != len(packet)+HeaderLen {
		t.Errorf("+2..3 = %d，期望精确等于 len(IP)+12 = %d", got, len(packet)+HeaderLen)
	}
	if !bytes.Equal(frame[4:8], []byte{0, 0, 0, 0}) {
		t.Errorf("+4..7 = % x，期望全 0", frame[4:8])
	}
	if frame[8] != 0 || frame[9] != 0 || frame[10] != 0 || frame[11] != dataPlaceholder {
		t.Errorf("+8..11 = % x，期望 00 00 00 %02x", frame[8:12], dataPlaceholder)
	}
	if !bytes.Equal(frame[HeaderLen:], packet) {
		t.Errorf("载荷被改动: % x", frame[HeaderLen:])
	}
}

func TestBuildDataIPv6(t *testing.T) {
	packet := make([]byte, 40)
	packet[0] = 0x60
	frame, err := BuildData(packet)
	if err != nil {
		t.Fatalf("BuildData 失败: %v", err)
	}
	if frame[1] != TypeDataV6 {
		t.Errorf("+1 = %#02x，期望 %#02x", frame[1], TypeDataV6)
	}
}

func TestBuildDataRejectsNonIP(t *testing.T) {
	packet := make([]byte, 20)
	packet[0] = 0x00
	if _, err := BuildData(packet); err == nil {
		t.Fatal("首字节 0x00 不是 IP 包，应报错")
	}
	if _, err := BuildData(nil); err == nil {
		t.Fatal("空包应报错")
	}
}

func TestBuildHeartbeatLayout(t *testing.T) {
	frame := BuildHeartbeat(0x01020304)
	if len(frame) != 16 {
		t.Fatalf("帧长 = %d，期望 16", len(frame))
	}
	if frame[0] != Magic || frame[1] != TypeRequest {
		t.Errorf("+0..1 = %#02x %#02x，期望 %#02x %#02x", frame[0], frame[1], Magic, TypeRequest)
	}
	if got := binary.BigEndian.Uint16(frame[2:4]); got != 16 {
		t.Errorf("+2..3 = %d，期望 16", got)
	}
	if !bytes.Equal(frame[4:8], []byte{0, 0, 0, 0}) {
		t.Errorf("+4..7 = % x，期望全 0", frame[4:8])
	}
	if frame[8] != heartbeatFlag || frame[9] != 0 || frame[10] != 0 || frame[11] != 0 {
		t.Errorf("+8..11 = % x，期望 03 00 00 00", frame[8:12])
	}
	if got := binary.LittleEndian.Uint32(frame[12:16]); got != 0x01020304 {
		t.Errorf("计数器 = %#08x，期望 0x01020304（小端）", got)
	}
}

func TestHandshakeResponseGolden(t *testing.T) {
	body := goldenAuthBody()
	if len(body) != 76 {
		t.Fatalf("黄金 TLV 体长度 = %d，期望 76", len(body))
	}

	resp, err := ParseHandshakeResponseHeader(goldenResponseHeader)
	if err != nil {
		t.Fatalf("ParseHandshakeResponseHeader 失败: %v", err)
	}
	if !resp.OK {
		t.Errorf("OK = false，期望 true（+8=%d code=%04X）", resp.Flag, resp.Code)
	}
	if resp.StatusCode() != "0000" {
		t.Errorf("StatusCode = %s，期望 0000", resp.StatusCode())
	}
	if resp.FailureReason() != "成功" {
		t.Errorf("FailureReason = %s", resp.FailureReason())
	}
	if resp.BodyLen() != 76 {
		t.Errorf("BodyLen = %d，期望 76", resp.BodyLen())
	}
	if int(resp.Length) != HeaderLen+len(body) {
		t.Errorf("头里的总长 %d ≠ 12 + %d", resp.Length, len(body))
	}

	info, err := ParseAuthInfo(body)
	if err != nil {
		t.Fatalf("ParseAuthInfo 失败: %v", err)
	}
	if info.VirtualIPv4 != netip.MustParseAddr("1.1.8.51") {
		t.Errorf("虚拟IPv4 = %s，期望 1.1.8.51", info.VirtualIPv4)
	}
	if info.Netmask != netip.MustParseAddr("255.255.0.0") {
		t.Errorf("掩码 = %s，期望 255.255.0.0", info.Netmask)
	}
	if info.Gateway != netip.MustParseAddr("1.1.1.1") {
		t.Errorf("网关 = %s，期望 1.1.1.1", info.Gateway)
	}
	if info.DNSv4 != "127.0.0.1" {
		t.Errorf("DNS = %q，期望 127.0.0.1", info.DNSv4)
	}
	if len(info.SessionFlag) != 1 || info.SessionFlag[0] != 0 {
		t.Errorf("SessionFlag = % x，期望 00", info.SessionFlag)
	}
	if info.VirtualIPv6 != netip.MustParseAddr("1001::101:833") {
		t.Errorf("虚拟IPv6 = %s，期望 1001::101:833", info.VirtualIPv6)
	}
	if info.DNSv6 != netip.MustParseAddr("::1") {
		t.Errorf("DNSv6 = %s，期望 ::1", info.DNSv6)
	}
	if len(info.Unknown) != 0 {
		t.Errorf("出现未知 TLV: %v", info.Unknown)
	}

	prefix, err := IPv4MaskPrefix(info.Netmask)
	if err != nil {
		t.Fatalf("IPv4MaskPrefix 失败: %v", err)
	}
	if prefix != 16 {
		t.Errorf("掩码前缀 = %d，期望 16", prefix)
	}
}

func TestHandshakeResponseFailureCodes(t *testing.T) {
	cases := []struct {
		code   uint16
		want   string
		reason string
	}{
		{0x8000, "8000", "错误 13"},
		{0x8009, "8009", "错误 14"},
		{0x800B, "800B", "错误 12"},
		{0x1234, "1234", "错误 11"},
	}
	for _, c := range cases {
		hdr := [HeaderLen]byte{1, 2, 0, 12, 0, 0, 0, 0, 0, 0, byte(c.code >> 8), byte(c.code)}
		resp, err := ParseHandshakeResponseHeader(hdr)
		if err != nil {
			t.Fatalf("code %s: %v", c.want, err)
		}
		if resp.OK {
			t.Errorf("code %s: OK 应为 false", c.want)
		}
		if resp.StatusCode() != c.want {
			t.Errorf("StatusCode = %s，期望 %s", resp.StatusCode(), c.want)
		}
		if resp.FailureReason() != c.reason {
			t.Errorf("code %s: FailureReason = %s，期望 %s", c.want, resp.FailureReason(), c.reason)
		}
	}
}

func TestReadHelpers(t *testing.T) {
	stream := append(goldenResponseHeader[:], goldenAuthBody()...)
	r := bytes.NewReader(stream)

	resp, err := ReadHandshakeResponseHeader(r)
	if err != nil {
		t.Fatalf("ReadHandshakeResponseHeader 失败: %v", err)
	}
	if !resp.OK || resp.BodyLen() != 76 {
		t.Fatalf("响应头解析异常: OK=%v BodyLen=%d", resp.OK, resp.BodyLen())
	}
	body := make([]byte, resp.BodyLen())
	if _, err := r.Read(body); err != nil {
		t.Fatalf("读 body 失败: %v", err)
	}
	if _, err := ParseAuthInfo(body); err != nil {
		t.Fatalf("ParseAuthInfo 失败: %v", err)
	}
}

func TestReadResponseHeader(t *testing.T) {
	// 网关→客户端：8 字节头 + 裸 IP 包，body 不从 0x45 之前开始。
	packet := minimalIPv4()
	stream := make([]byte, 0, ResponseHeaderLen+len(packet))
	stream = append(stream, 1, TypeDataV4, 0, byte(ResponseHeaderLen+len(packet)))
	stream = append(stream, 0, 0, 0, 0)
	stream = append(stream, packet...)

	hdr, err := ReadResponseHeader(bytes.NewReader(stream))
	if err != nil {
		t.Fatalf("ReadResponseHeader 失败: %v", err)
	}
	if hdr.Type != TypeDataV4 {
		t.Errorf("Type = %#02x", hdr.Type)
	}
	if hdr.BodyLen() != len(packet) {
		t.Errorf("BodyLen = %d，期望 %d（body 就是裸 IP 包，没有 4 字节前缀）", hdr.BodyLen(), len(packet))
	}
}

func TestParseResponseHeaderRejectsShortLength(t *testing.T) {
	if _, err := ParseResponseHeader([ResponseHeaderLen]byte{1, 4, 0, 4}); err == nil {
		t.Fatal("总长小于 8 应报错")
	}
	if _, err := ParseHandshakeResponseHeader([HeaderLen]byte{1, 2, 0, 8}); err == nil {
		t.Fatal("握手响应总长小于 12 应报错")
	}
}

func TestParseTLVsTruncated(t *testing.T) {
	// 声明 4 字节但只给了 2 字节
	if _, err := ParseTLVs([]byte{TLVVirtualIPv4, 0x00, 0x04, 0x01, 0x01}); err == nil {
		t.Fatal("截断的 TLV 值应报错")
	}
	// 只有 2 字节，连头部都不够
	if _, err := ParseTLVs([]byte{TLVVirtualIPv4, 0x00}); err == nil {
		t.Fatal("截断的 TLV 头应报错")
	}
}

func TestParseAuthInfoMissingVirtualIP(t *testing.T) {
	body := appendTLV(nil, TLVGateway, []byte{1, 1, 1, 1})
	body = append(body, TLVEnd)
	if _, err := ParseAuthInfo(body); !errors.Is(err, ErrNoVirtualIP) {
		t.Fatalf("err = %v，期望 ErrNoVirtualIP", err)
	}
}

func TestIPv4MaskPrefixRejectsNonContiguous(t *testing.T) {
	if _, err := IPv4MaskPrefix(netip.MustParseAddr("255.0.255.0")); err == nil {
		t.Fatal("非连续掩码应报错")
	}
	cases := map[string]int{
		"255.255.255.0":   24,
		"255.255.0.0":     16,
		"255.255.255.255": 32,
		"0.0.0.0":         0,
	}
	for mask, want := range cases {
		got, err := IPv4MaskPrefix(netip.MustParseAddr(mask))
		if err != nil {
			t.Fatalf("%s: %v", mask, err)
		}
		if got != want {
			t.Errorf("%s → %d，期望 %d", mask, got, want)
		}
	}
}
