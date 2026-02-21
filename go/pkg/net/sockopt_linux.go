//go:build linux

package net

import (
	"fmt"
	"net"
	"syscall"

	"golang.org/x/net/ipv4"
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
}

func newBatchConn(conn *net.UDPConn, batchSize int) *batchConn {
	pc := ipv4.NewPacketConn(conn)
	msgs := make([]ipv4.Message, batchSize)
	return &batchConn{pc: pc, msgs: msgs, batchSize: batchSize}
}

type batchConn struct {
	pc        *ipv4.PacketConn
	msgs      []ipv4.Message
	batchSize int
}

func (bc *batchConn) ReadBatch(buffers [][]byte) (n int, err error) {
	count := len(buffers)
	if count > bc.batchSize {
		count = bc.batchSize
	}
	for i := 0; i < count; i++ {
		bc.msgs[i].Buffers = [][]byte{buffers[i]}
		bc.msgs[i].N = 0
		bc.msgs[i].Addr = nil
	}
	return bc.pc.ReadBatch(bc.msgs[:count], 0)
}

func (bc *batchConn) ReceivedN(i int) int {
	return bc.msgs[i].N
}

func (bc *batchConn) ReceivedFrom(i int) *net.UDPAddr {
	if bc.msgs[i].Addr == nil {
		return nil
	}
	if addr, ok := bc.msgs[i].Addr.(*net.UDPAddr); ok {
		return addr
	}
	return nil
}

func (bc *batchConn) WriteBatch(buffers [][]byte, addrs []*net.UDPAddr) (int, error) {
	count := len(buffers)
	if count > bc.batchSize {
		count = bc.batchSize
	}
	for i := 0; i < count; i++ {
		bc.msgs[i].Buffers = [][]byte{buffers[i]}
		bc.msgs[i].Addr = addrs[i]
	}
	return bc.pc.WriteBatch(bc.msgs[:count], 0)
}

// GSOSupported returns true if UDP_SEGMENT (GSO) is available.
func GSOSupported(conn *net.UDPConn) bool {
	raw, err := conn.SyscallConn()
	if err != nil {
		return false
	}
	var supported bool
	raw.Control(func(fd uintptr) {
		err := syscall.SetsockoptInt(int(fd), syscall.IPPROTO_UDP, sysUDP_SEGMENT, 1400)
		supported = (err == nil)
	})
	return supported
}
