package noise

import (
	"net"
)

// Addr represents a transport-layer address.
// This abstraction allows the connection layer to work with different
// underlying transports (UDP, QUIC, etc.) without modification.
type Addr interface {
	// Network returns the name of the network (e.g., "udp", "quic").
	Network() string
	// String returns a string representation of the address.
	String() string
}

// Transport is an abstraction over datagram-based transports.
// It provides a unified interface for sending and receiving packets,
// regardless of the underlying protocol (UDP, QUIC, etc.).
type Transport interface {
	// SendTo sends data to the specified address.
	// Returns an error if the send fails.
	SendTo(data []byte, addr Addr) error

	// RecvFrom receives data into the provided buffer.
	// Returns the number of bytes read, the sender's address, and any error.
	// The buffer should be large enough to hold the maximum expected packet size.
	RecvFrom(buf []byte) (n int, addr Addr, err error)

	// Close closes the transport and releases any associated resources.
	Close() error

	// LocalAddr returns the local address of the transport.
	LocalAddr() Addr
}

// UDPAddr wraps net.UDPAddr to implement the Addr interface.
type UDPAddr struct {
	*net.UDPAddr
}

// Network returns "udp".
func (a *UDPAddr) Network() string {
	return "udp"
}

// String returns the string representation of the UDP address.
func (a *UDPAddr) String() string {
	if a.UDPAddr == nil {
		return "<nil>"
	}
	return a.UDPAddr.String()
}

// UDPTransport implements Transport over UDP.
type UDPTransport struct {
	conn *net.UDPConn
}

// NewUDPTransport creates a new UDP transport bound to the specified address.
// If addr is nil, the transport binds to a random available port.
func NewUDPTransport(addr *net.UDPAddr) (*UDPTransport, error) {
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, err
	}
	return &UDPTransport{conn: conn}, nil
}

// NewUDPTransportFromConn creates a UDP transport from an existing connection.
func NewUDPTransportFromConn(conn *net.UDPConn) *UDPTransport {
	return &UDPTransport{conn: conn}
}

// SendTo sends data to the specified address.
func (t *UDPTransport) SendTo(data []byte, addr Addr) error {
	udpAddr, ok := addr.(*UDPAddr)
	if !ok {
		return ErrInvalidAddress
	}
	_, err := t.conn.WriteToUDP(data, udpAddr.UDPAddr)
	return err
}

// RecvFrom receives data and returns the sender's address.
func (t *UDPTransport) RecvFrom(buf []byte) (int, Addr, error) {
	n, addr, err := t.conn.ReadFromUDP(buf)
	if err != nil {
		return 0, nil, err
	}
	return n, &UDPAddr{addr}, nil
}

// Close closes the UDP connection.
func (t *UDPTransport) Close() error {
	return t.conn.Close()
}

// LocalAddr returns the local UDP address.
func (t *UDPTransport) LocalAddr() Addr {
	return &UDPAddr{t.conn.LocalAddr().(*net.UDPAddr)}
}

// SetReadBuffer sets the size of the operating system's receive buffer.
func (t *UDPTransport) SetReadBuffer(size int) error {
	return t.conn.SetReadBuffer(size)
}

// SetWriteBuffer sets the size of the operating system's transmit buffer.
func (t *UDPTransport) SetWriteBuffer(size int) error {
	return t.conn.SetWriteBuffer(size)
}
