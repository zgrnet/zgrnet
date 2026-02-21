//go:build unix

package net

import (
	"context"
	"net"
	"syscall"
)

// getSocketBufSize reads the actual socket buffer size via getsockopt.
// recv=true reads SO_RCVBUF, recv=false reads SO_SNDBUF.
func getSocketBufSize(conn *net.UDPConn, recv bool) int {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0
	}
	opt := syscall.SO_SNDBUF
	if recv {
		opt = syscall.SO_RCVBUF
	}
	var val int
	raw.Control(func(fd uintptr) {
		val, _ = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, opt)
	})
	return val
}

// SetReusePort sets SO_REUSEPORT on a raw fd before bind.
func SetReusePort(fd uintptr) error {
	return syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEPORT, 1)
}

// ListenUDPReusePort creates a UDP socket with SO_REUSEPORT set.
// Multiple sockets can bind to the same address; the kernel load-balances
// incoming packets across them.
func ListenUDPReusePort(addr string) (*net.UDPConn, error) {
	lc := net.ListenConfig{
		Control: func(_, _ string, c syscall.RawConn) error {
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
