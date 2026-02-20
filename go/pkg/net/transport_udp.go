package net

import (
	"net"
	"time"

	"github.com/vibing/zgrnet/pkg/noise"
)

// UDPAddr wraps net.UDPAddr to implement the noise.Addr interface.
type UDPAddr struct {
	addr *net.UDPAddr
}

// Network returns "udp".
func (a *UDPAddr) Network() string {
	return "udp"
}

// String returns the address string.
func (a *UDPAddr) String() string {
	return a.addr.String()
}

// UDPAddrFromNetAddr wraps a net.UDPAddr as a noise.Addr.
func UDPAddrFromNetAddr(addr *net.UDPAddr) *UDPAddr {
	return &UDPAddr{addr: addr}
}

// UDPTransport is a UDP-based transport implementation.
type UDPTransport struct {
	conn *net.UDPConn
}

// NewUDPTransport creates a new UDP transport bound to the specified address.
// Use "127.0.0.1:0" or ":0" to bind to a random available port.
func NewUDPTransport(addr string) (*UDPTransport, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, err
	}

	ApplySocketOptions(conn, DefaultSocketConfig())

	return &UDPTransport{conn: conn}, nil
}

// SendTo sends data to the specified address.
func (t *UDPTransport) SendTo(data []byte, addr noise.Addr) error {
	var udpAddr *net.UDPAddr

	switch a := addr.(type) {
	case *UDPAddr:
		udpAddr = a.addr
	default:
		// Try to resolve from string
		var err error
		udpAddr, err = net.ResolveUDPAddr("udp", addr.String())
		if err != nil {
			return err
		}
	}

	_, err := t.conn.WriteToUDP(data, udpAddr)
	return err
}

// RecvFrom receives data and returns the sender's address.
func (t *UDPTransport) RecvFrom(buf []byte) (int, noise.Addr, error) {
	n, addr, err := t.conn.ReadFromUDP(buf)
	if err != nil {
		return 0, nil, err
	}
	return n, &UDPAddr{addr: addr}, nil
}

// Close closes the transport.
func (t *UDPTransport) Close() error {
	return t.conn.Close()
}

// LocalAddr returns the local address.
func (t *UDPTransport) LocalAddr() noise.Addr {
	return &UDPAddr{addr: t.conn.LocalAddr().(*net.UDPAddr)}
}

// SetReadDeadline sets the read deadline.
func (t *UDPTransport) SetReadDeadline(tt time.Time) error {
	return t.conn.SetReadDeadline(tt)
}

// SetWriteDeadline sets the write deadline.
func (t *UDPTransport) SetWriteDeadline(tt time.Time) error {
	return t.conn.SetWriteDeadline(tt)
}
