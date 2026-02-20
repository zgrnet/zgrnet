//go:build !linux

package net

import "net"

func applyPlatformOptions(_ *net.UDPConn, _ SocketConfig, _ *OptimizationReport) {}
