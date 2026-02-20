//go:build linux

package net

import "net"

func applyPlatformOptions(conn *net.UDPConn, cfg SocketConfig, report *OptimizationReport) {
	// Linux-specific optimizations added in later phases:
	// Phase 2: recvmmsg/sendmmsg (BatchSize)
	// Phase 4: UDP_GRO / UDP_GSO (GRO, GSOSegment)
	// Phase 5: SO_BUSY_POLL (BusyPollUS)
	// Phase 3 (SO_REUSEPORT) is applied before bind, not here.
	_ = conn
	_ = cfg
}
