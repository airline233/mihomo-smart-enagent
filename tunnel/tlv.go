package tunnel

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// 握手响应体（以及网关下发的其它控制体）是 TLV 列表：
// type(1) + len(2, 大端) + value(len)，以 0xFF 结束。
const (
	// TLVVirtualIPv4 是网关分配给本会话的虚拟 IPv4 地址（4 字节二进制）。
	TLVVirtualIPv4 = 0x0B
	// TLVNetmask 是子网掩码（4 字节二进制）。
	TLVNetmask = 0x0C
	// TLVGateway 是隧道内的网关地址（4 字节二进制）。
	TLVGateway = 0x23
	// TLVDNSv4 是 DNS 地址，**9 字节 ASCII 字符串**（例如 "127.0.0.1"），
	// 不是 4 字节二进制——这是本协议里另一处容易读错的地方。
	TLVDNSv4 = 0x24
	// TLVSessionFlag 恒为 1 字节 00。
	TLVSessionFlag = 0x2B
	// TLVVirtualIPv6 是虚拟 IPv6 地址（16 字节）。
	TLVVirtualIPv6 = 0x35
	// TLVDNSv6 是 DNS IPv6 地址（16 字节）。
	TLVDNSv6 = 0x36
	// TLVEnd 是 TLV 列表结束符。
	TLVEnd = 0xFF

	tlvHeaderLen = 3
)

// TLV 是原始的一个类型-长度-值项。
type TLV struct {
	Type  byte
	Value []byte
}

// ParseTLVs 解析 TLV 列表，遇到 0xFF 即停止。
// 截断的项会返回已解析的部分和错误，便于定位问题。
func ParseTLVs(body []byte) ([]TLV, error) {
	var out []TLV
	for i := 0; i < len(body); {
		t := body[i]
		if t == TLVEnd {
			break
		}
		if i+tlvHeaderLen > len(body) {
			return out, fmt.Errorf("TLV 头被截断: 偏移 %d", i)
		}
		n := int(binary.BigEndian.Uint16(body[i+1 : i+tlvHeaderLen]))
		if i+tlvHeaderLen+n > len(body) {
			return out, fmt.Errorf("TLV 值被截断: type %#02x 声明 %d 字节，剩余 %d", t, n, len(body)-i-tlvHeaderLen)
		}
		value := make([]byte, n)
		copy(value, body[i+tlvHeaderLen:i+tlvHeaderLen+n])
		out = append(out, TLV{Type: t, Value: value})
		i += tlvHeaderLen + n
	}
	return out, nil
}

// AuthInfo 是握手成功后网关下发的隧道参数。
type AuthInfo struct {
	// VirtualIPv4 是本会话的虚拟 IPv4 地址，隧道的源地址。
	VirtualIPv4 netip.Addr
	// Netmask 是点分掩码，例如 255.255.0.0。
	Netmask netip.Addr
	// Gateway 是隧道内的网关地址，例如 1.1.1.1。
	Gateway netip.Addr
	// DNSv4 是网关下发的 DNS 地址字符串。它通常是 127.0.0.1，
	// 表示"隧道内的 DNS"，因此这个 outbound 必须被标记为 L3 协议，
	// 否则 mihomo 的 DNS 模块会把域名透传下来造成环路。
	DNSv4 string
	// SessionFlag 是 0x2B 的原始值，恒为 {0x00}。
	SessionFlag []byte
	// VirtualIPv6 是虚拟 IPv6 地址（IPv6 数据面尚未证实可用）。
	VirtualIPv6 netip.Addr
	// DNSv6 是 DNS IPv6 地址。
	DNSv6 netip.Addr
	// Unknown 收集了未识别类型的 TLV，便于排查协议变化。
	Unknown []TLV
}

// ParseAuthInfo 解析握手响应体。
// 虚拟 IPv4 是必填项——没有它就说明网关没有真正接受本会话。
func ParseAuthInfo(body []byte) (AuthInfo, error) {
	tlvs, err := ParseTLVs(body)
	if err != nil {
		return AuthInfo{}, err
	}

	var info AuthInfo
	for _, tlv := range tlvs {
		switch tlv.Type {
		case TLVVirtualIPv4:
			addr, err := addrFrom(tlv.Value, 4)
			if err != nil {
				return info, fmt.Errorf("虚拟 IPv4: %w", err)
			}
			info.VirtualIPv4 = addr
		case TLVNetmask:
			addr, err := addrFrom(tlv.Value, 4)
			if err != nil {
				return info, fmt.Errorf("子网掩码: %w", err)
			}
			info.Netmask = addr
		case TLVGateway:
			addr, err := addrFrom(tlv.Value, 4)
			if err != nil {
				return info, fmt.Errorf("网关地址: %w", err)
			}
			info.Gateway = addr
		case TLVDNSv4:
			info.DNSv4 = string(tlv.Value)
		case TLVSessionFlag:
			info.SessionFlag = tlv.Value
		case TLVVirtualIPv6:
			addr, err := addrFrom(tlv.Value, 16)
			if err != nil {
				return info, fmt.Errorf("虚拟 IPv6: %w", err)
			}
			info.VirtualIPv6 = addr
		case TLVDNSv6:
			addr, err := addrFrom(tlv.Value, 16)
			if err != nil {
				return info, fmt.Errorf("DNS IPv6: %w", err)
			}
			info.DNSv6 = addr
		default:
			info.Unknown = append(info.Unknown, tlv)
		}
	}

	if !info.VirtualIPv4.IsValid() {
		return info, fmt.Errorf("%w（缺少 TLV %#02x）", ErrNoVirtualIP, TLVVirtualIPv4)
	}
	return info, nil
}

// addrFrom 把 4 或 16 字节的值转成 netip.Addr。
func addrFrom(value []byte, want int) (netip.Addr, error) {
	if len(value) != want {
		return netip.Addr{}, fmt.Errorf("期望 %d 字节，实际 %d 字节", want, len(value))
	}
	if want == 4 {
		var v4 [4]byte
		copy(v4[:], value)
		return netip.AddrFrom4(v4), nil
	}
	var v16 [16]byte
	copy(v16[:], value)
	return netip.AddrFrom16(v16), nil
}

// IPv4MaskPrefix 把点分掩码转成前缀长度（255.255.0.0 → 16）。
// netstack 需要用前缀长度来配置接口地址。
func IPv4MaskPrefix(mask netip.Addr) (int, error) {
	if !mask.Is4() {
		return 0, fmt.Errorf("不是 IPv4 掩码: %s", mask)
	}
	raw := mask.As4()
	bits := 0
	seenZero := false
	for _, b := range raw {
		for i := 7; i >= 0; i-- {
			if b&(1<<uint(i)) != 0 {
				if seenZero {
					return 0, fmt.Errorf("掩码不是连续的 1: %s", mask)
				}
				bits++
			} else {
				seenZero = true
			}
		}
	}
	return bits, nil
}

// String 便于日志输出。
func (a AuthInfo) String() string {
	parts := []string{fmt.Sprintf("虚拟IPv4=%s", a.VirtualIPv4)}
	if a.Netmask.IsValid() {
		parts = append(parts, "掩码="+a.Netmask.String())
	}
	if a.Gateway.IsValid() {
		parts = append(parts, "网关="+a.Gateway.String())
	}
	if a.DNSv4 != "" {
		parts = append(parts, "DNS="+a.DNSv4)
	}
	if a.VirtualIPv6.IsValid() {
		parts = append(parts, "虚拟IPv6="+a.VirtualIPv6.String())
	}
	if a.DNSv6.IsValid() {
		parts = append(parts, "DNSv6="+a.DNSv6.String())
	}
	if len(a.Unknown) > 0 {
		types := make([]string, 0, len(a.Unknown))
		for _, tlv := range a.Unknown {
			types = append(types, fmt.Sprintf("%#02x", tlv.Type))
		}
		parts = append(parts, "未知TLV="+strings.Join(types, ","))
	}
	return strings.Join(parts, " ")
}

// ErrNoVirtualIP 表示网关没有下发虚拟 IP。
var ErrNoVirtualIP = errors.New("tunnel: 网关未下发虚拟 IPv4")
