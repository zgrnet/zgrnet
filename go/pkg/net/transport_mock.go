package net

import (
	"errors"
	"sync"
	"time"

	"github.com/vibing/zgrnet/pkg/noise"
)

// MockAddr is a simple address for testing.
type MockAddr struct {
	name string
}

// NewMockAddr creates a new mock address.
func NewMockAddr(name string) *MockAddr {
	return &MockAddr{name: name}
}

// Network returns "mock".
func (a *MockAddr) Network() string {
	return "mock"
}

// String returns the address name.
func (a *MockAddr) String() string {
	return a.name
}

// MockTransport is an in-memory transport for testing.
// It simulates a network by connecting to other MockTransports.
type MockTransport struct {
	mu        sync.Mutex
	localAddr *MockAddr
	peer      *MockTransport // Direct peer for simple testing
	inbox     chan mockPacket
	done      chan struct{} // Closed when transport is closed
	closed    bool
}

type mockPacket struct {
	data []byte
	from noise.Addr
}

// NewMockTransport creates a new mock transport.
func NewMockTransport(name string) *MockTransport {
	return &MockTransport{
		localAddr: NewMockAddr(name),
		inbox:     make(chan mockPacket, 100),
		done:      make(chan struct{}),
	}
}

// Connect connects two mock transports together.
func (t *MockTransport) Connect(peer *MockTransport) {
	t.mu.Lock()
	t.peer = peer
	t.mu.Unlock()

	peer.mu.Lock()
	peer.peer = t
	peer.mu.Unlock()
}

// SendTo sends data to the specified address.
// For MockTransport, this sends to the connected peer.
func (t *MockTransport) SendTo(data []byte, addr noise.Addr) error {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return ErrMockTransportClosed
	}
	peer := t.peer
	t.mu.Unlock()

	if peer == nil {
		return ErrMockNoPeer
	}

	// Copy data to prevent mutation
	dataCopy := make([]byte, len(data))
	copy(dataCopy, data)

	// Send to peer's inbox, using done channel to detect closure
	// This avoids a TOCTOU race between checking closed and sending
	select {
	case <-peer.done:
		return ErrMockTransportClosed
	case peer.inbox <- mockPacket{data: dataCopy, from: t.localAddr}:
		return nil
	default:
		return ErrMockInboxFull
	}
}

// RecvFrom receives data and returns the sender's address.
func (t *MockTransport) RecvFrom(buf []byte) (int, noise.Addr, error) {
	select {
	case <-t.done:
		return 0, nil, ErrMockTransportClosed
	case pkt, ok := <-t.inbox:
		if !ok {
			return 0, nil, ErrMockTransportClosed
		}
		n := copy(buf, pkt.data)
		return n, pkt.from, nil
	}
}

// Close closes the transport.
func (t *MockTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return nil
	}

	t.closed = true
	close(t.done)  // Signal closure to all goroutines
	close(t.inbox) // Close inbox to unblock RecvFrom
	return nil
}

// LocalAddr returns the local address.
func (t *MockTransport) LocalAddr() noise.Addr {
	return t.localAddr
}

// SetReadDeadline sets the read deadline (no-op for mock transport).
func (t *MockTransport) SetReadDeadline(_ time.Time) error {
	return nil
}

// SetWriteDeadline sets the write deadline (no-op for mock transport).
func (t *MockTransport) SetWriteDeadline(_ time.Time) error {
	return nil
}

// InjectPacket injects a packet into the transport's inbox.
// This is useful for testing without a connected peer.
func (t *MockTransport) InjectPacket(data []byte, from noise.Addr) error {
	dataCopy := make([]byte, len(data))
	copy(dataCopy, data)

	select {
	case <-t.done:
		return ErrMockTransportClosed
	case t.inbox <- mockPacket{data: dataCopy, from: from}:
		return nil
	default:
		return ErrMockInboxFull
	}
}

// MockTransport errors.
var (
	ErrMockTransportClosed = errors.New("net: mock transport closed")
	ErrMockNoPeer          = errors.New("net: mock no peer connected")
	ErrMockInboxFull       = errors.New("net: mock inbox full")
)
