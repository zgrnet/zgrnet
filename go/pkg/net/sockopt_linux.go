//go:build linux

package net

import (
	"fmt"
	"net"
	"syscall"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const (
	sysSO_REUSEPORT = 15
	sysSO_BUSY_POLL = 46
	sysUDP_GRO      = 104
	sysUDP_SEGMENT  = 103
)

// SetReusePort sets SO_REUSEPORT on a raw fd before bind.
func SetReusePort(fd uintptr) error {
	return syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, sysSO_REUSEPORT, 1)
}

func applyPlatformOptions(conn *net.UDPConn, cfg SocketConfig, report *OptimizationReport) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return
	}

	if cfg.BusyPollUS > 0 {
		var setErr error
		raw.Control(func(fd uintptr) {
			setErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, sysSO_BUSY_POLL, cfg.BusyPollUS)
		})
		if setErr != nil {
			report.Entries = append(report.Entries, OptimizationEntry{
				Name: "SO_BUSY_POLL", Err: setErr,
			})
		} else {
			report.Entries = append(report.Entries, OptimizationEntry{
				Name: "SO_BUSY_POLL", Applied: true,
				Detail: fmt.Sprintf("SO_BUSY_POLL=%dμs", cfg.BusyPollUS),
			})
		}
	}

	if cfg.GRO {
		var setErr error
		raw.Control(func(fd uintptr) {
			setErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_UDP, sysUDP_GRO, 1)
		})
		if setErr != nil {
			report.Entries = append(report.Entries, OptimizationEntry{
				Name: "UDP_GRO", Err: setErr,
			})
		} else {
			report.Entries = append(report.Entries, OptimizationEntry{
				Name: "UDP_GRO", Applied: true,
				Detail: "UDP_GRO=1",
			})
		}
	}

	if cfg.GSO {
		var setErr error
		raw.Control(func(fd uintptr) {
			setErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_UDP, sysUDP_SEGMENT, DefaultGSOSegment)
		})
		if setErr != nil {
			report.Entries = append(report.Entries, OptimizationEntry{
				Name: "UDP_GSO", Err: setErr,
			})
		} else {
			report.Entries = append(report.Entries, OptimizationEntry{
				Name: "UDP_GSO", Applied: true,
				Detail: fmt.Sprintf("UDP_SEGMENT=%d", DefaultGSOSegment),
			})
		}
	}
}

// batchConn wraps a UDPConn for batch I/O using recvmmsg/sendmmsg.
// Supports both IPv4 and IPv6 sockets — detects the address family
// from the bound local address.
type batchConn struct {
	v4        *ipv4.PacketConn // non-nil for IPv4 sockets
	v6        *ipv6.PacketConn // non-nil for IPv6/dual-stack sockets
	msgs4     []ipv4.Message
	msgs6     []ipv6.Message
	batchSize int
}

func newBatchConn(conn *net.UDPConn, batchSize int) *batchConn {
	bc := &batchConn{batchSize: batchSize}

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	if localAddr.IP.To4() != nil {
		bc.v4 = ipv4.NewPacketConn(conn)
		bc.msgs4 = make([]ipv4.Message, batchSize)
	} else {
		bc.v6 = ipv6.NewPacketConn(conn)
		bc.msgs6 = make([]ipv6.Message, batchSize)
	}

	return bc
}

func (bc *batchConn) ReadBatch(buffers [][]byte) (n int, err error) {
	count := len(buffers)
	if count > bc.batchSize {
		count = bc.batchSize
	}

	if bc.v4 != nil {
		for i := 0; i < count; i++ {
			bc.msgs4[i].Buffers = [][]byte{buffers[i]}
			bc.msgs4[i].N = 0
			bc.msgs4[i].Addr = nil
		}
		return bc.v4.ReadBatch(bc.msgs4[:count], 0)
	}

	for i := 0; i < count; i++ {
		bc.msgs6[i].Buffers = [][]byte{buffers[i]}
		bc.msgs6[i].N = 0
		bc.msgs6[i].Addr = nil
	}
	return bc.v6.ReadBatch(bc.msgs6[:count], 0)
}

func (bc *batchConn) ReceivedN(i int) int {
	if bc.v4 != nil {
		return bc.msgs4[i].N
	}
	return bc.msgs6[i].N
}

func (bc *batchConn) ReceivedFrom(i int) *net.UDPAddr {
	if bc.v4 != nil {
		if bc.msgs4[i].Addr == nil {
			return nil
		}
		if addr, ok := bc.msgs4[i].Addr.(*net.UDPAddr); ok {
			return addr
		}
		return nil
	}

	if bc.msgs6[i].Addr == nil {
		return nil
	}
	if addr, ok := bc.msgs6[i].Addr.(*net.UDPAddr); ok {
		return addr
	}
	return nil
}

