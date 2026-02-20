package net

import (
	"context"
	"fmt"
	"net"
	"strings"
	"syscall"
)

const (
	DefaultRecvBufSize = 4 * 1024 * 1024 // 4MB
	DefaultSendBufSize = 4 * 1024 * 1024 // 4MB
	DefaultBusyPollUS  = 50              // 50μs busy-poll duration
	DefaultGSOSegment  = 1400            // MTU-sized GSO segments
	DefaultBatchSize   = 64              // recvmmsg/sendmmsg batch size
)

// SocketConfig holds configuration for UDP socket optimizations.
// All fields are optional; zero values trigger sensible defaults.
type SocketConfig struct {
	RecvBufSize int  // SO_RCVBUF in bytes (0 → DefaultRecvBufSize)
	SendBufSize int  // SO_SNDBUF in bytes (0 → DefaultSendBufSize)
	ReusePort   bool // SO_REUSEPORT (Linux + macOS)
	BusyPollUS  int  // SO_BUSY_POLL in μs (Linux, 0 = disabled)
	GRO         bool // UDP_GRO (Linux 4.18+)
	GSOSegment  int  // UDP_SEGMENT for GSO (Linux 4.18+, 0 = disabled)
	BatchSize   int  // recvmmsg/sendmmsg batch (Linux, 0 = disabled)
}

// DefaultSocketConfig returns recommended defaults for high-throughput use.
func DefaultSocketConfig() SocketConfig {
	return SocketConfig{
		RecvBufSize: DefaultRecvBufSize,
		SendBufSize: DefaultSendBufSize,
	}
}

// OptimizationEntry records the result of a single socket optimization attempt.
type OptimizationEntry struct {
	Name    string
	Applied bool
	Detail  string
	Err     error
}

// OptimizationReport collects the results of all optimization attempts.
type OptimizationReport struct {
	Entries []OptimizationEntry
}

func (r *OptimizationReport) String() string {
	var b strings.Builder
	b.WriteString("[udp] socket optimizations:")
	for _, e := range r.Entries {
		if e.Applied {
			fmt.Fprintf(&b, "\n  %-40s [ok]", e.Detail)
		} else {
			fmt.Fprintf(&b, "\n  %-40s [not available: %v]", e.Name, e.Err)
		}
	}
	return b.String()
}

// SetReusePort sets SO_REUSEPORT on a raw fd before bind.
// Must be called via net.ListenConfig.Control before the socket is bound.
func SetReusePort(fd uintptr) error {
	return syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEPORT, 1)
}

// ListenUDPReusePort creates a UDP socket with SO_REUSEPORT set.
// Multiple sockets can bind to the same address; the kernel load-balances
// incoming packets across them.
func ListenUDPReusePort(addr string) (*net.UDPConn, error) {
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var err error
			c.Control(func(fd uintptr) {
				err = SetReusePort(fd)
			})
			return err
		},
	}
	pc, err := lc.ListenPacket(context.Background(), "udp", addr)
	if err != nil {
		return nil, err
	}
	return pc.(*net.UDPConn), nil
}

// ApplySocketOptions applies all configured optimizations to a UDP connection.
// Each optimization is tried independently — failures don't block others.
func ApplySocketOptions(conn *net.UDPConn, cfg SocketConfig) *OptimizationReport {
	report := &OptimizationReport{}

	recvBuf := cfg.RecvBufSize
	if recvBuf <= 0 {
		recvBuf = DefaultRecvBufSize
	}
	if err := conn.SetReadBuffer(recvBuf); err != nil {
		report.Entries = append(report.Entries, OptimizationEntry{
			Name: "SO_RCVBUF", Err: err,
		})
	} else {
		actual := getSocketOptInt(conn, syscall.SOL_SOCKET, syscall.SO_RCVBUF)
		report.Entries = append(report.Entries, OptimizationEntry{
			Name: "SO_RCVBUF", Applied: true,
			Detail: fmt.Sprintf("SO_RCVBUF=%d (actual=%d)", recvBuf, actual),
		})
	}

	sendBuf := cfg.SendBufSize
	if sendBuf <= 0 {
		sendBuf = DefaultSendBufSize
	}
	if err := conn.SetWriteBuffer(sendBuf); err != nil {
		report.Entries = append(report.Entries, OptimizationEntry{
			Name: "SO_SNDBUF", Err: err,
		})
	} else {
		actual := getSocketOptInt(conn, syscall.SOL_SOCKET, syscall.SO_SNDBUF)
		report.Entries = append(report.Entries, OptimizationEntry{
			Name: "SO_SNDBUF", Applied: true,
			Detail: fmt.Sprintf("SO_SNDBUF=%d (actual=%d)", sendBuf, actual),
		})
	}

	applyPlatformOptions(conn, cfg, report)

	return report
}

// getSocketOptInt reads an integer socket option via SyscallConn.
func getSocketOptInt(conn *net.UDPConn, level, opt int) int {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0
	}
	var val int
	raw.Control(func(fd uintptr) {
		val, _ = syscall.GetsockoptInt(int(fd), level, opt)
	})
	return val
}
