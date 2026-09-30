// Package stack 把一个 L3 隧道变成 userspace 的 net.Conn 工厂。
//
// EnAgent 隧道是"一条 TLS 连接承载原始 IP 包"，而 mihomo 的 ProxyAdapter 需要的是
// 每个连接一个 net.Conn。中间的转换在用户态跑一个 TCP/IP 协议栈（gVisor netstack）：
//
//	隧道入站 IP 包 → InjectIP()  → 协议栈 → DialContext 返回的 net.Conn
//	net.Conn 写出   → 协议栈 → Sender.WriteIP() → 隧道出站
//
// 依赖 github.com/metacubex/gvisor。它**已经在 mihomo 的 go.sum 里**（作为间接依赖），
// 因此打给 mihomo 的 patch 不需要改动 go.mod/go.sum —— 这对补丁的稳定性很关键。
package stack

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"github.com/metacubex/gvisor/pkg/buffer"
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/link/channel"
	"github.com/metacubex/gvisor/pkg/tcpip/network/ipv4"
	"github.com/metacubex/gvisor/pkg/tcpip/network/ipv6"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/tcp"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/udp"
)

const (
	// nicID 是这个用户态协议栈里唯一的网卡。
	nicID = tcpip.NICID(1)
	// channelDepth 是出入站队列深度。
	channelDepth = 1024
	// defaultMTU 与实测的网关 MSS=1460 相符。
	defaultMTU = 1500
)

// Sender 是协议栈出站 IP 包的出口，由隧道实现。
type Sender interface {
	// WriteIP 发送一个完整的裸 IP 包。
	WriteIP(packet []byte) error
}

// SenderFunc 把普通函数适配成 Sender。
type SenderFunc func(packet []byte) error

// WriteIP 实现 Sender。
func (f SenderFunc) WriteIP(packet []byte) error { return f(packet) }

// Options 是协议栈的配置。
type Options struct {
	// VirtualIPv4 是网关下发的本机虚拟地址，必填。
	VirtualIPv4 netip.Addr
	// PrefixLen 是子网前缀长度（由网关下发的掩码换算而来）。
	PrefixLen int
	// VirtualIPv6 可选。IPv6 数据面尚未证实可用，留空即不启用。
	VirtualIPv6 netip.Addr
	// MTU 默认 1500。
	MTU uint32
	// Sender 是出站 IP 包的出口，必填。
	Sender Sender
	// Logf 是可选日志回调。
	Logf func(format string, args ...any)
}

func (o Options) logf(format string, args ...any) {
	if o.Logf != nil {
		o.Logf(format, args...)
	}
}

// Stack 是用户态协议栈。
type Stack struct {
	opts  Options
	stack *stack.Stack
	link  *channel.Endpoint

	ctx    context.Context
	cancel context.CancelFunc

	closeOnce sync.Once
	closed    chan struct{}
}

// New 构造并启动协议栈。
func New(opts Options) (*Stack, error) {
	if !opts.VirtualIPv4.IsValid() {
		return nil, errors.New("stack: 缺少虚拟 IPv4 地址")
	}
	if !opts.VirtualIPv4.Is4() {
		return nil, fmt.Errorf("stack: 虚拟 IPv4 非法: %s", opts.VirtualIPv4)
	}
	if opts.PrefixLen < 0 || opts.PrefixLen > 32 {
		return nil, fmt.Errorf("stack: 前缀长度非法: %d", opts.PrefixLen)
	}
	if opts.Sender == nil {
		return nil, errors.New("stack: 缺少 Sender")
	}
	mtu := opts.MTU
	if mtu == 0 {
		mtu = defaultMTU
	}

	link := channel.New(channelDepth, mtu, "")
	netStack := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
		// 允许访问本机地址，否则某些回环场景会被内核直接拒绝。
		HandleLocal: true,
	})

	if err := netStack.CreateNIC(nicID, link); err != nil {
		return nil, fmt.Errorf("stack: 创建网卡失败: %v", err)
	}
	if err := netStack.AddProtocolAddress(nicID, tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFromSlice(opts.VirtualIPv4.AsSlice()),
			PrefixLen: opts.PrefixLen,
		},
	}, stack.AddressProperties{}); err != nil {
		return nil, fmt.Errorf("stack: 配置虚拟 IPv4 失败: %v", err)
	}
	if opts.VirtualIPv6.IsValid() && opts.VirtualIPv6.Is6() {
		if err := netStack.AddProtocolAddress(nicID, tcpip.ProtocolAddress{
			Protocol: ipv6.ProtocolNumber,
			AddressWithPrefix: tcpip.AddressWithPrefix{
				Address:   tcpip.AddrFromSlice(opts.VirtualIPv6.AsSlice()),
				PrefixLen: 128,
			},
		}, stack.AddressProperties{}); err != nil {
			// IPv6 配不上不算致命：数据面本来就还没证实。
			opts.logf("stack: 配置虚拟 IPv6 失败（忽略）: %v", err)
		}
	}
	// 默认路由全部指向隧道。
	netStack.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: nicID},
		{Destination: header.IPv6EmptySubnet, NIC: nicID},
	})

	ctx, cancel := context.WithCancel(context.Background())
	s := &Stack{
		opts:   opts,
		stack:  netStack,
		link:   link,
		ctx:    ctx,
		cancel: cancel,
		closed: make(chan struct{}),
	}
	go s.pump()
	return s, nil
}

// pump 把协议栈要发出去的 IP 包交给隧道。
func (s *Stack) pump() {
	defer close(s.closed)
	for {
		pkt := s.link.ReadContext(s.ctx)
		if pkt == nil {
			return
		}
		view := pkt.ToView()
		slice := view.AsSlice()
		packet := make([]byte, len(slice))
		copy(packet, slice)
		view.Release()
		pkt.DecRef()

		if err := s.opts.Sender.WriteIP(packet); err != nil {
			s.opts.logf("stack: 发送 IP 包失败: %v", err)
		}
	}
}

// InjectIP 把隧道收到的裸 IP 包注入协议栈。
func (s *Stack) InjectIP(packet []byte) error {
	if len(packet) == 0 {
		return errors.New("stack: 空 IP 包")
	}
	var networkProtocol tcpip.NetworkProtocolNumber
	switch packet[0] >> 4 {
	case 4:
		networkProtocol = ipv4.ProtocolNumber
	case 6:
		networkProtocol = ipv6.ProtocolNumber
	default:
		return fmt.Errorf("stack: 不是 IP 包（首字节 %#02x）", packet[0])
	}

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(packet),
	})
	defer pkt.DecRef()
	s.link.InjectInbound(networkProtocol, pkt)
	return nil
}

// DialContext 通过隧道建立一个 TCP 连接。
//
// address 必须是数字地址形式的 host:port —— 本 outbound 会被标记成 L3 协议，
// mihomo 的 DNS 模块不会把域名透传下来（透传会造成隧道内 DNS 环路）。
func (s *Stack) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	switch network {
	case "tcp", "tcp4", "tcp6", "":
	default:
		return nil, fmt.Errorf("stack: 不支持的网络类型 %q", network)
	}
	addrPort, err := netip.ParseAddrPort(address)
	if err != nil {
		return nil, fmt.Errorf("stack: 需要数字地址 host:port，收到 %q: %w", address, err)
	}
	networkProtocol := ipv4.ProtocolNumber
	if addrPort.Addr().Is6() {
		networkProtocol = ipv6.ProtocolNumber
	}
	conn, err := gonet.DialContextTCP(ctx, s.stack, tcpip.FullAddress{
		NIC:  nicID,
		Addr: tcpip.AddrFromSlice(addrPort.Addr().AsSlice()),
		Port: addrPort.Port(),
	}, networkProtocol)
	if err != nil {
		return nil, fmt.Errorf("stack: 建立 TCP 连接失败: %w", err)
	}
	return conn, nil
}

// ListenPacket 建立一个非连接的 UDP 端点，支持 WriteTo 任意目的地。
//
// 端点绑定在本机的虚拟地址上（端口取 address 里的端口，通常为 0 即自动分配），
// 这样出站包的源地址就是网关分配的那个虚拟 IP。
func (s *Stack) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	localAddr := tcpip.FullAddress{NIC: nicID}
	var networkProtocol tcpip.NetworkProtocolNumber
	switch network {
	case "udp", "udp4", "":
		networkProtocol = ipv4.ProtocolNumber
		localAddr.Addr = tcpip.AddrFromSlice(s.opts.VirtualIPv4.AsSlice())
	case "udp6":
		if !s.opts.VirtualIPv6.IsValid() {
			return nil, errors.New("stack: 未配置虚拟 IPv6")
		}
		networkProtocol = ipv6.ProtocolNumber
		localAddr.Addr = tcpip.AddrFromSlice(s.opts.VirtualIPv6.AsSlice())
	default:
		return nil, fmt.Errorf("stack: 不支持的 UDP 网络类型 %q", network)
	}
	if addrPort, err := netip.ParseAddrPort(address); err == nil {
		localAddr.Port = addrPort.Port()
	}

	// raddr 为 nil → 不 Connect，WriteTo 可指定任意目的地。
	conn, err := gonet.DialUDP(s.stack, &localAddr, nil, networkProtocol)
	if err != nil {
		return nil, fmt.Errorf("stack: 建立 UDP 端点失败: %w", err)
	}
	return conn, nil
}

// Close 关闭协议栈。可重复调用。
func (s *Stack) Close() error {
	s.closeOnce.Do(func() {
		s.cancel()
		<-s.closed
		s.stack.Destroy()
		s.link.Close()
	})
	return nil
}
