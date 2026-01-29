package noise

import (
	"errors"
	"sync"
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
	closed    bool
}

type mockPacket struct {
	data []byte
	from Addr
}

// NewMockTransport creates a new mock transport.
func NewMockTransport(name string) *MockTransport {
	return &MockTransport{
		localAddr: NewMockAddr(name),
		inbox:     make(chan mockPacket, 100),
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
func (t *MockTransport) SendTo(data []byte, addr Addr) error {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return ErrTransportClosed
	}
	peer := t.peer
	t.mu.Unlock()

	if peer == nil {
		return ErrNoPeer
	}

	// Copy data to prevent mutation
	dataCopy := make([]byte, len(data))
	copy(dataCopy, data)

	// Send to peer's inbox
	peer.mu.Lock()
	if peer.closed {
		peer.mu.Unlock()
		return ErrTransportClosed
	}
	peer.mu.Unlock()

	select {
	case peer.inbox <- mockPacket{data: dataCopy, from: t.localAddr}:
		return nil
	default:
		return ErrInboxFull
	}
}

// RecvFrom receives data and returns the sender's address.
func (t *MockTransport) RecvFrom(buf []byte) (int, Addr, error) {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return 0, nil, ErrTransportClosed
	}
	t.mu.Unlock()

	pkt, ok := <-t.inbox
	if !ok {
		return 0, nil, ErrTransportClosed
	}

	n := copy(buf, pkt.data)
	return n, pkt.from, nil
}

// Close closes the transport.
func (t *MockTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return nil
	}

	t.closed = true
	close(t.inbox)
	return nil
}

// LocalAddr returns the local address.
func (t *MockTransport) LocalAddr() Addr {
	return t.localAddr
}

// InjectPacket injects a packet into the transport's inbox.
// This is useful for testing without a connected peer.
func (t *MockTransport) InjectPacket(data []byte, from Addr) error {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return ErrTransportClosed
	}
	t.mu.Unlock()

	dataCopy := make([]byte, len(data))
	copy(dataCopy, data)

	select {
	case t.inbox <- mockPacket{data: dataCopy, from: from}:
		return nil
	default:
		return ErrInboxFull
	}
}

// MockTransport errors.
var (
	ErrTransportClosed = errors.New("noise: transport closed")
	ErrNoPeer          = errors.New("noise: no peer connected")
	ErrInboxFull       = errors.New("noise: inbox full")
)
