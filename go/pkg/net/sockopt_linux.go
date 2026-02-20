//go:build linux

package net

import (
	"fmt"
	"net"
	"syscall"

	"golang.org/x/net/ipv4"
)

const (
	sysUDP_GRO     = 104
	sysUDP_SEGMENT = 103
)

func applyPlatformOptions(conn *net.UDPConn, cfg SocketConfig, report *OptimizationReport) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return
	}

	// SO_BUSY_POLL
	if cfg.BusyPollUS > 0 {
		var setErr error
		raw.Control(func(fd uintptr) {
			setErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_BUSY_POLL, cfg.BusyPollUS)
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

	// UDP_GRO
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

// newBatchConn wraps a UDPConn for batch reading using recvmmsg on Linux.
// Returns nil if the connection cannot be used for batch I/O.
func newBatchConn(conn *net.UDPConn, batchSize int) *batchConn {
	pc := ipv4.NewPacketConn(conn)
	msgs := make([]ipv4.Message, batchSize)
	return &batchConn{pc: pc, msgs: msgs, batchSize: batchSize}
}

// batchConn wraps ipv4.PacketConn for batch read/write.
type batchConn struct {
	pc        *ipv4.PacketConn
	msgs      []ipv4.Message
	batchSize int
}

// ReadBatch reads up to batchSize packets into the provided buffers.
// On Linux this uses recvmmsg (one syscall for many packets).
// Returns number of packets read.
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

// ReceivedN returns the bytes received for batch index i.
func (bc *batchConn) ReceivedN(i int) int {
	return bc.msgs[i].N
}

// ReceivedFrom returns the sender address for batch index i.
func (bc *batchConn) ReceivedFrom(i int) *net.UDPAddr {
	if bc.msgs[i].Addr == nil {
		return nil
	}
	if addr, ok := bc.msgs[i].Addr.(*net.UDPAddr); ok {
		return addr
	}
	return nil
}

// WriteBatch sends multiple packets in one syscall using sendmmsg on Linux.
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
