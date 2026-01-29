// Package transport provides transport layer implementations for the noise package.
package transport

import (
	"net"

	"github.com/vibing/zgrnet/noise"
)

// UDPAddr wraps net.UDPAddr to implement the noise.Addr interface.
type UDPAddr struct {
	*net.UDPAddr
}

// Network returns "udp".
func (a *UDPAddr) Network() string {
	return "udp"
}

// String returns the string representation of the address.
func (a *UDPAddr) String() string {
	if a.UDPAddr == nil {
		return ""
	}
	return a.UDPAddr.String()
}

// UDP implements noise.Transport over a connected UDP socket.
// It is bound to a fixed remote address (no roaming support).
type UDP struct {
	conn       *net.UDPConn
	localAddr  *UDPAddr
	remoteAddr *UDPAddr
}

// NewUDP creates a UDP transport connected to the remote address.
//
// Parameters:
//   - localAddr: local bind address (e.g., ":0" for any available port, ":51820" for specific port)
//   - remoteAddr: remote peer address (e.g., "192.168.1.1:51820" or "example.com:51820")
//
// The transport uses a connected UDP socket, meaning all sends go to the
// fixed remote address and only packets from that address are received.
func NewUDP(localAddr, remoteAddr string) (*UDP, error) {
	// Resolve local address
	laddr, err := net.ResolveUDPAddr("udp", localAddr)
	if err != nil {
		return nil, err
	}

	// Resolve remote address
	raddr, err := net.ResolveUDPAddr("udp", remoteAddr)
	if err != nil {
		return nil, err
	}

	// Create connected UDP socket
	conn, err := net.DialUDP("udp", laddr, raddr)
	if err != nil {
		return nil, err
	}

	return &UDP{
		conn:       conn,
		localAddr:  &UDPAddr{conn.LocalAddr().(*net.UDPAddr)},
		remoteAddr: &UDPAddr{raddr},
	}, nil
}

// SendTo sends data to the remote peer.
// The addr parameter is ignored since this transport is connected to a fixed address.
func (t *UDP) SendTo(data []byte, addr noise.Addr) error {
	_, err := t.conn.Write(data)
	return err
}

// RecvFrom receives data from the remote peer.
// Returns the number of bytes read, the remote address, and any error.
// The returned address is always the fixed remote address.
func (t *UDP) RecvFrom(buf []byte) (int, noise.Addr, error) {
	n, err := t.conn.Read(buf)
	if err != nil {
		return 0, nil, err
	}
	return n, t.remoteAddr, nil
}

// Close closes the UDP connection.
func (t *UDP) Close() error {
	return t.conn.Close()
}

// LocalAddr returns the local address of the transport.
func (t *UDP) LocalAddr() noise.Addr {
	return t.localAddr
}

// RemoteAddr returns the fixed remote address of the transport.
func (t *UDP) RemoteAddr() noise.Addr {
	return t.remoteAddr
}

// SetReadBuffer sets the size of the operating system's receive buffer.
func (t *UDP) SetReadBuffer(bytes int) error {
	return t.conn.SetReadBuffer(bytes)
}

// SetWriteBuffer sets the size of the operating system's transmit buffer.
func (t *UDP) SetWriteBuffer(bytes int) error {
	return t.conn.SetWriteBuffer(bytes)
}
