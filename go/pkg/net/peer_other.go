//go:build !linux

package net

import (
	"errors"
	"net"
)

// sendToGSO is a no-op stub for non-Linux platforms.
// GSO is only supported on Linux 4.18+ with supported NICs.
func (u *UDP) sendToGSO(_ []byte, _ *net.UDPAddr) (int, error) {
	return 0, errors.New("GSO is only supported on Linux")
}
