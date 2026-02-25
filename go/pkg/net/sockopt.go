package net

import (
	"fmt"
	"net"
	"strings"
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
	BusyPollUS  int  // SO_BUSY_POLL in μs (Linux, 0 = disabled)
	GRO         bool // UDP_GRO receive coalescing (Linux 4.18+)
	GSO         bool // UDP_SEGMENT send segmentation (Linux 4.18+)
}

// DefaultSocketConfig returns recommended defaults for high-throughput use.
func DefaultSocketConfig() SocketConfig {
	return SocketConfig{
		RecvBufSize: DefaultRecvBufSize,
		SendBufSize: DefaultSendBufSize,
	}
}

// FullSocketConfig returns a config with all optimizations enabled.
func FullSocketConfig() SocketConfig {
	return SocketConfig{
		RecvBufSize: DefaultRecvBufSize,
		SendBufSize: DefaultSendBufSize,
		BusyPollUS:  DefaultBusyPollUS,
		GRO:         true,
		GSO:         true,
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
		} else if e.Err != nil {
			fmt.Fprintf(&b, "\n  %-40s [not available: %v]", e.Name, e.Err)
		} else if e.Detail != "" {
			fmt.Fprintf(&b, "\n  %-40s [%s]", e.Name, e.Detail)
		} else {
			fmt.Fprintf(&b, "\n  %-40s [skipped]", e.Name)
		}
	}
	return b.String()
}

// firstError returns the first non-nil error from the arguments.
func firstError(errs ...error) error {
	for _, e := range errs {
		if e != nil {
			return e
		}
	}
	return nil
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
		actual := getSocketBufSize(conn, true)
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
		actual := getSocketBufSize(conn, false)
		report.Entries = append(report.Entries, OptimizationEntry{
			Name: "SO_SNDBUF", Applied: true,
			Detail: fmt.Sprintf("SO_SNDBUF=%d (actual=%d)", sendBuf, actual),
		})
	}

	applyPlatformOptions(conn, cfg, report)

	return report
}
