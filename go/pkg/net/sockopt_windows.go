//go:build windows

package net

import (
	"errors"
	"net"
)

func getSocketBufSize(_ *net.UDPConn, _ bool) int { return 0 }

func SetReusePort(_ uintptr) error {
	return errors.New("SO_REUSEPORT not supported on Windows")
}

func ListenUDPReusePort(addr string) (*net.UDPConn, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	return net.ListenUDP("udp", udpAddr)
}
