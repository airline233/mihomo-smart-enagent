// Package tunnel 实现 EnAgent/Enlink 网关隧道的报文层：握手帧、数据帧、心跳帧的
// 构造，以及响应帧头与 TLV 的解析。
//
// 所有字节布局均来自对 enuep.exe 的静态还原与实测确认（见 PROTOCOL.md §4）。
// 本包只做编解码，不持有连接、不发网络请求。
package tunnel

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	// HeaderLen 是客户端→网关方向的帧头长度。
	// 发送侧比接收侧多 4 字节占位字段，所以两个方向的头不对称（12 vs 8），
	// 这是实测结论，不是笔误。
	HeaderLen = 12
	// ResponseHeaderLen 是网关→客户端方向的帧头长度。
	ResponseHeaderLen = 8

	// Magic 是帧的第一个字节：握手帧、心跳帧、数据帧三者的 +0 都是它。
	//
	// ⚠️ 写成 0x00 的后果是：握手成功、心跳双向通、REST 全 200，但**每一个数据帧
	// 都被网关静默丢弃且连接不断开**，从客户端完全无法区分。这是本协议最大的坑。
	Magic = 0x01

	// TypeRequest 是客户端→网关的请求/心跳/控制帧类型。
	TypeRequest = 0x01
	// TypeResponse 是网关→客户端的控制帧类型，不应注入协议栈。
	TypeResponse = 0x02
	// TypeDataV4 / TypeDataV6 是数据帧的载荷类型，只有这两个值会被网关转发。
	TypeDataV4 = 0x04
	TypeDataV6 = 0x08

	// dataPlaceholder 是数据帧 +8..11 的低字节占位值。
	// 实测 +8..11 填任意值网关都接受（它只是随包透传的占位字段）；
	// 这里保留原客户端的常量仅为字节级一致性。
	dataPlaceholder = 0x29
	// heartbeatFlag 是心跳帧 +8..11 的常量 03 00 00 00。
	heartbeatFlag = 0x03
)

// MaxStringField 是握手帧里 A/B 字段的长度上限（单字节长度前缀）。
const MaxStringField = 0xFF

// BuildHandshake 构造握手请求帧。
//
//	+0      1   Magic
//	+1      1   TypeRequest
//	+2..3   2   整帧总长（大端，含 12 字节头）
//	+4..7   4   0
//	+8..11  4   01 00 00 00
//	+12..13 2   01 00              ← A 的标签
//	+14     1   len(A)
//	+15     n   A
//	+..     2   02 00              ← B 的标签
//	+..     1   len(B)
//	+..     m   B
//	+..     1   0xFF               ← 结束符
//
// A 是明文学号，B 是控制器下发的会话 token（裸 UUID，不要 base64、不要去横线——
// 两种变形都被网关以 8000 拒绝）。
func BuildHandshake(a, b string) ([]byte, error) {
	if len(a) > MaxStringField {
		return nil, fmt.Errorf("握手帧 A 字段过长: %d 字节", len(a))
	}
	if len(b) > MaxStringField {
		return nil, fmt.Errorf("握手帧 B 字段过长: %d 字节", len(b))
	}

	frame := make([]byte, 0, HeaderLen+len(a)+len(b)+8)
	frame = append(frame, Magic, TypeRequest, 0x00, 0x00)
	frame = append(frame, 0x00, 0x00, 0x00, 0x00)
	frame = append(frame, 0x01, 0x00, 0x00, 0x00)
	frame = append(frame, 0x01, 0x00, byte(len(a)))
	frame = append(frame, a...)
	frame = append(frame, 0x02, 0x00, byte(len(b)))
	frame = append(frame, b...)
	frame = append(frame, TLVEnd)

	binary.BigEndian.PutUint16(frame[2:4], uint16(len(frame)))
	return frame, nil
}

// BuildData 把裸 IP 包装进 12 字节隧道头。
//
//	+0      1   Magic
//	+1      1   TypeDataV4 / TypeDataV6
//	+2..3   2   整帧总长 = len(IP 包) + 12（必须精确相等，多 4 少 4 都被丢）
//	+4..7   4   0
//	+8..11  4   占位
//	+12     n   IP 包
func BuildData(packet []byte) ([]byte, error) {
	if len(packet) == 0 {
		return nil, errors.New("IP 包为空")
	}
	var frameType byte
	switch packet[0] >> 4 {
	case 4:
		frameType = TypeDataV4
	case 6:
		frameType = TypeDataV6
	default:
		return nil, fmt.Errorf("不是 IP 包（首字节 %#02x）", packet[0])
	}
	if len(packet)+HeaderLen > 0xFFFF {
		return nil, fmt.Errorf("IP 包过大: %d 字节", len(packet))
	}

	frame := make([]byte, HeaderLen+len(packet))
	frame[0] = Magic
	frame[1] = frameType
	binary.BigEndian.PutUint16(frame[2:4], uint16(len(packet)+HeaderLen))
	// +4..7 保持 0
	frame[11] = dataPlaceholder
	copy(frame[HeaderLen:], packet)
	return frame, nil
}

// BuildHeartbeat 构造心跳帧。原客户端周期 0.5s，计数器 32 位递增、**小端**。
//
//	+0      1   Magic
//	+1      1   TypeRequest
//	+2..3   2   16
//	+4..7   4   0
//	+8..11  4   03 00 00 00
//	+12..15 4   uint32 递增计数器（小端）
func BuildHeartbeat(counter uint32) []byte {
	frame := make([]byte, 4+HeaderLen)
	frame[0] = Magic
	frame[1] = TypeRequest
	binary.BigEndian.PutUint16(frame[2:4], uint16(len(frame)))
	frame[8] = heartbeatFlag
	binary.LittleEndian.PutUint32(frame[HeaderLen:], counter)
	return frame
}

// ResponseHeader 是网关→客户端方向的 8 字节帧头。
type ResponseHeader struct {
	Version byte
	// Type 为 TypeResponse(0x02) 时是控制帧，应丢弃而不是注入协议栈；
	// 0x04 / 0x08 分别对应 IPv4 / IPv6 载荷。
	Type byte
	// Length 是整帧总长（含 8 字节头）。
	Length uint16
}

// ParseResponseHeader 解析 8 字节响应头。
func ParseResponseHeader(h [ResponseHeaderLen]byte) (ResponseHeader, error) {
	hdr := ResponseHeader{
		Version: h[0],
		Type:    h[1],
		Length:  binary.BigEndian.Uint16(h[2:4]),
	}
	if int(hdr.Length) < ResponseHeaderLen {
		return hdr, fmt.Errorf("响应头总长非法: %d", hdr.Length)
	}
	return hdr, nil
}

// BodyLen 返回帧头之后还需要读多少字节。响应体就是**裸 IP 包**，
// 线上两个方向都没有驱动头前缀，不要再砍 4 字节。
func (h ResponseHeader) BodyLen() int { return int(h.Length) - ResponseHeaderLen }

// ReadResponseHeader 从 r 读满 8 字节响应头。
func ReadResponseHeader(r io.Reader) (ResponseHeader, error) {
	var buf [ResponseHeaderLen]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return ResponseHeader{}, err
	}
	return ParseResponseHeader(buf)
}

// HandshakeResponse 是握手响应：12 字节头 + 状态码 + TLV 体。
type HandshakeResponse struct {
	Version byte
	Type    byte
	// Length 是整帧总长（含 12 字节头）。现网成功样本是 88 = 12 + 76。
	Length uint16
	// Flag 是 +8 的成功标志，成功时必须为 1。
	Flag byte
	// Code 是 +10..11 大端状态码，0000 表示成功。
	Code uint16
	// OK 表示本次握手被接受。
	OK bool
}

// ParseHandshakeResponseHeader 解析 12 字节握手响应头。
func ParseHandshakeResponseHeader(h [HeaderLen]byte) (HandshakeResponse, error) {
	resp := HandshakeResponse{
		Version: h[0],
		Type:    h[1],
		Length:  binary.BigEndian.Uint16(h[2:4]),
		Flag:    h[8],
		Code:    binary.BigEndian.Uint16(h[10:12]),
	}
	if int(resp.Length) < HeaderLen {
		return resp, fmt.Errorf("握手响应总长非法: %d", resp.Length)
	}
	resp.OK = resp.Flag == 1 && resp.Code == 0
	return resp, nil
}

// BodyLen 返回 TLV 体的长度。
func (r HandshakeResponse) BodyLen() int { return int(r.Length) - HeaderLen }

// StatusCode 把状态码格式化成 4 位大写 hex，与原客户端日志一致。
func (r HandshakeResponse) StatusCode() string { return fmt.Sprintf("%04X", r.Code) }

// FailureReason 给出原客户端对失败码的分类（第 5 次重试时输出）。
func (r HandshakeResponse) FailureReason() string {
	switch r.StatusCode() {
	case "0000":
		return "成功"
	case "8000":
		return "错误 13"
	case "8009":
		return "错误 14"
	case "800B":
		return "错误 12"
	default:
		return "错误 11"
	}
}

// FailureReasonFor 是 FailureReason 的纯函数形式，供只有状态码的场合使用。
func FailureReasonFor(code uint16) string {
	return HandshakeResponse{Code: code}.FailureReason()
}

// ReadHandshakeResponseHeader 从 r 读满 12 字节握手响应头。
func ReadHandshakeResponseHeader(r io.Reader) (HandshakeResponse, error) {
	var buf [HeaderLen]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return HandshakeResponse{}, err
	}
	return ParseHandshakeResponseHeader(buf)
}
