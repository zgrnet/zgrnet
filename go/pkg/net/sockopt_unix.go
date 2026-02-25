//go:build unix

package net

import (
	"context"
	"net"
	"syscall"
)

// getSocketBufSize reads the actual socket buffer size via getsockopt.
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

// ListenUDPReusePort creates a UDP socket with SO_REUSEPORT set.
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
