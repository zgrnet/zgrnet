// Package transport provides transport layer implementations for the noise package.
package transport

import (
	"net"
	"sync"

	"github.com/vibing/zgrnet/noise"
)

// UDPListener implements noise.Transport over an unconnected UDP socket.
// It can send to and receive from multiple remote addresses.
// This is suitable for Host which manages multiple peers on a single port.
type UDPListener struct {
	mu        sync.RWMutex
	conn      *net.UDPConn
	localAddr *UDPAddr
	closed    bool
}

// NewUDPListener creates a UDP listener bound to the specified address.
// Use ":0" to let the OS assign an available port.
// Use ":51820" to bind to a specific port.
func NewUDPListener(bindAddr string) (*UDPListener, error) {
	laddr, err := net.ResolveUDPAddr("udp", bindAddr)
	if err != nil {
		return nil, err
	}

	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		return nil, err
	}

	return &UDPListener{
		conn:      conn,
		localAddr: &UDPAddr{conn.LocalAddr().(*net.UDPAddr)},
	}, nil
}

// SendTo sends data to the specified address.
func (t *UDPListener) SendTo(data []byte, addr noise.Addr) error {
	t.mu.RLock()
	if t.closed {
		t.mu.RUnlock()
		return noise.ErrTransportClosed
	}
	conn := t.conn
	t.mu.RUnlock()

	// Convert noise.Addr to *net.UDPAddr
	var udpAddr *net.UDPAddr
	switch a := addr.(type) {
	case *UDPAddr:
		udpAddr = a.UDPAddr
	default:
		// Try to resolve from string
		var err error
		udpAddr, err = net.ResolveUDPAddr("udp", addr.String())
		if err != nil {
			return err
		}
	}

	_, err := conn.WriteToUDP(data, udpAddr)
	return err
}

// RecvFrom receives data and returns the sender's address.
func (t *UDPListener) RecvFrom(buf []byte) (int, noise.Addr, error) {
	t.mu.RLock()
	if t.closed {
		t.mu.RUnlock()
		return 0, nil, noise.ErrTransportClosed
	}
	conn := t.conn
	t.mu.RUnlock()

	n, addr, err := conn.ReadFromUDP(buf)
	if err != nil {
		return 0, nil, err
	}

	return n, &UDPAddr{addr}, nil
}

// Close closes the UDP listener.
func (t *UDPListener) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return nil
	}

	t.closed = true
	return t.conn.Close()
}

// LocalAddr returns the local address of the listener.
func (t *UDPListener) LocalAddr() noise.Addr {
	return t.localAddr
}

// Port returns the local port number.
func (t *UDPListener) Port() int {
	return t.localAddr.UDPAddr.Port
}

// SetReadBuffer sets the size of the operating system's receive buffer.
func (t *UDPListener) SetReadBuffer(bytes int) error {
	return t.conn.SetReadBuffer(bytes)
}

// SetWriteBuffer sets the size of the operating system's transmit buffer.
func (t *UDPListener) SetWriteBuffer(bytes int) error {
	return t.conn.SetWriteBuffer(bytes)
}

// InjectPacket is not supported for UDPListener.
// This method exists to satisfy test interfaces but should not be used.
func (t *UDPListener) InjectPacket(data []byte, from noise.Addr) {
	// No-op for real UDP transport
}
