//go:build darwin || freebsd || netbsd || openbsd

package net

import "syscall"

// SetReusePort sets SO_REUSEPORT on a raw fd before bind.
func SetReusePort(fd uintptr) error {
	return syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEPORT, 1)
}
