package noise

import "time"

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

	// SetReadDeadline sets the deadline for future RecvFrom calls.
	// A zero value means RecvFrom will not time out.
	// Returns an error if the transport does not support deadlines.
	SetReadDeadline(t time.Time) error
}
