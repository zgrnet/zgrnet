package net

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/vibing/zgrnet/pkg/noise"
)

// TestSetSession tests the Conn.SetSession method.
func TestSetSession(t *testing.T) {
	localKey, _ := noise.GenerateKeyPair()
	remoteKey, _ := noise.GenerateKeyPair()
	transport := NewMockTransport("test")
	defer transport.Close()

	conn, err := newConn(localKey, transport, NewMockAddr("remote"), remoteKey.Public)
	if err != nil {
		t.Fatalf("newConn() error = %v", err)
	}
	defer conn.Close()

	// Initially no session
	if conn.Session() != nil {
		t.Error("Session() should be nil initially")
	}

	// Create a test session
	idx, _ := noise.GenerateIndex()
	session, err := noise.NewSession(noise.SessionConfig{
		LocalIndex:  idx,
		RemoteIndex: idx + 1,
		SendKey:     [32]byte{1, 2, 3},
		RecvKey:     [32]byte{4, 5, 6},
		RemotePK:    remoteKey.Public,
	})
	if err != nil {
		t.Fatalf("NewSession() error = %v", err)
	}

	// Set the session
	conn.SetSession(session)

	// Verify session is set
	if conn.Session() == nil {
		t.Error("Session() should not be nil after SetSession")
	}

	// Verify state is established
	if conn.State() != ConnStateEstablished {
		t.Errorf("State() = %v, want %v", conn.State(), ConnStateEstablished)
	}

	// Verify local index is updated
	if conn.LocalIndex() != idx {
		t.Errorf("LocalIndex() = %d, want %d", conn.LocalIndex(), idx)
	}

	// Test setting nil session
	conn.SetSession(nil)
	if conn.Session() != nil {
		t.Error("Session() should be nil after SetSession(nil)")
	}
}

// TestIsTimeoutError tests the isTimeoutError helper function.
func TestIsTimeoutError(t *testing.T) {
	// Test with nil error
	if isTimeoutError(nil) {
		t.Error("isTimeoutError(nil) should be false")
	}

	// Test with regular error
	if isTimeoutError(errors.New("some error")) {
		t.Error("isTimeoutError(regular error) should be false")
	}

	// Test with timeout error
	timeoutErr := &timeoutTestError{timeout: true}
	if !isTimeoutError(timeoutErr) {
		t.Error("isTimeoutError(timeout error) should be true")
	}

	// Test with non-timeout error implementing the interface
	nonTimeoutErr := &timeoutTestError{timeout: false}
	if isTimeoutError(nonTimeoutErr) {
		t.Error("isTimeoutError(non-timeout error) should be false")
	}
}

// timeoutTestError is a test error that implements the Timeout() interface.
type timeoutTestError struct {
	timeout bool
}

func (e *timeoutTestError) Error() string {
	return "test timeout error"
}

func (e *timeoutTestError) Timeout() bool {
	return e.timeout
}

// TestRemoveConn tests the Listener.RemoveConn method.
func TestRemoveConn(t *testing.T) {
	localKey, _ := noise.GenerateKeyPair()
	transport := NewMockTransport("listener")
	defer transport.Close()

	cfg := ListenerConfig{
		LocalKey:  localKey,
		Transport: transport,
	}

	listener, err := NewListener(cfg)
	if err != nil {
		t.Fatalf("NewListener() error = %v", err)
	}
	defer listener.Close()

	// Create a connection manually and add it
	remoteKey, _ := noise.GenerateKeyPair()

	conn, err := newConn(localKey, transport, NewMockAddr("remote"), remoteKey.Public)
	if err != nil {
		t.Fatalf("newConn() error = %v", err)
	}

	localIdx := conn.LocalIndex()

	// Add connection to listener's internal map
	listener.mu.Lock()
	listener.conns[localIdx] = conn
	listener.mu.Unlock()

	// Verify connection exists
	listener.mu.Lock()
	_, exists := listener.conns[localIdx]
	listener.mu.Unlock()
	if !exists {
		t.Error("Connection should exist before RemoveConn")
	}

	// Remove the connection
	listener.RemoveConn(localIdx)

	// Verify connection is removed
	listener.mu.Lock()
	_, exists = listener.conns[localIdx]
	listener.mu.Unlock()
	if exists {
		t.Error("Connection should not exist after RemoveConn")
	}

	// Removing non-existent connection should not panic
	listener.RemoveConn(localIdx)
	listener.RemoveConn(99999)
}

// TestGetConn tests the UDP.GetConn method.
func TestGetConn(t *testing.T) {
	localKey, _ := noise.GenerateKeyPair()

	udp, err := NewUDP(localKey, WithBindAddr("127.0.0.1:0"))
	if err != nil {
		t.Fatalf("NewUDP() error = %v", err)
	}
	defer udp.Close()

	remoteKey, _ := noise.GenerateKeyPair()

	// GetConn should return nil in current implementation
	conn := udp.GetConn(remoteKey.Public)
	if conn != nil {
		t.Error("GetConn() should return nil in simplified implementation")
	}
}

// TestUDPConnect tests the UDP.Connect method.
func TestUDPConnect(t *testing.T) {
	localKey, _ := noise.GenerateKeyPair()

	udp, err := NewUDP(localKey, WithBindAddr("127.0.0.1:0"))
	if err != nil {
		t.Fatalf("NewUDP() error = %v", err)
	}
	defer udp.Close()

	// Test connect with non-existent peer
	remoteKey, _ := noise.GenerateKeyPair()
	err = udp.Connect(remoteKey.Public)
	if err != ErrPeerNotFound {
		t.Errorf("Connect() with no peer error = %v, want %v", err, ErrPeerNotFound)
	}

	// Add peer without endpoint
	remoteAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:12345")
	udp.SetPeerEndpoint(remoteKey.Public, remoteAddr)

	// Test connect after close
	udp.Close()
	err = udp.Connect(remoteKey.Public)
	if err != ErrClosed {
		t.Errorf("Connect() after close error = %v, want %v", err, ErrClosed)
	}
}

// TestUDPAddrMethods tests UDPAddr Network and String methods.
func TestUDPAddrMethods(t *testing.T) {
	netAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:8080")
	addr := UDPAddrFromNetAddr(netAddr)

	// Test Network()
	if addr.Network() != "udp" {
		t.Errorf("Network() = %s, want udp", addr.Network())
	}

	// Test String()
	expected := "127.0.0.1:8080"
	if addr.String() != expected {
		t.Errorf("String() = %s, want %s", addr.String(), expected)
	}
}

// TestUDPTransportSetWriteDeadline tests UDPTransport.SetWriteDeadline.
func TestUDPTransportSetWriteDeadline(t *testing.T) {
	transport, err := NewUDPTransport("127.0.0.1:0")
	if err != nil {
		t.Fatalf("NewUDPTransport() error = %v", err)
	}
	defer transport.Close()

	// Set a write deadline
	deadline := time.Now().Add(1 * time.Second)
	err = transport.SetWriteDeadline(deadline)
	if err != nil {
		t.Errorf("SetWriteDeadline() error = %v", err)
	}

	// Clear the deadline
	err = transport.SetWriteDeadline(time.Time{})
	if err != nil {
		t.Errorf("SetWriteDeadline(zero) error = %v", err)
	}
}

// TestMockTransportSetWriteDeadline tests MockTransport.SetWriteDeadline.
func TestMockTransportSetWriteDeadline(t *testing.T) {
	transport := NewMockTransport("test")
	defer transport.Close()

	// SetWriteDeadline should be a no-op for mock transport
	err := transport.SetWriteDeadline(time.Now())
	if err != nil {
		t.Errorf("SetWriteDeadline() error = %v", err)
	}
}

// TestPeerStateString tests PeerState.String method.
func TestPeerStateString(t *testing.T) {
	tests := []struct {
		state PeerState
		want  string
	}{
		{PeerStateNew, "new"},
		{PeerStateConnecting, "connecting"},
		{PeerStateEstablished, "established"},
		{PeerStateFailed, "failed"},
		{PeerState(99), "unknown"},
	}

	for _, tt := range tests {
		got := tt.state.String()
		if got != tt.want {
			t.Errorf("PeerState(%d).String() = %s, want %s", tt.state, got, tt.want)
		}
	}
}

// TestListenerHandleTransport tests Listener.handleTransport method.
func TestListenerHandleTransport(t *testing.T) {
	localKey, _ := noise.GenerateKeyPair()
	transport := NewMockTransport("listener")
	defer transport.Close()

	cfg := ListenerConfig{
		LocalKey:  localKey,
		Transport: transport,
	}

	listener, err := NewListener(cfg)
	if err != nil {
		t.Fatalf("NewListener() error = %v", err)
	}
	defer listener.Close()

	// Test with invalid data (too short)
	listener.handleTransport([]byte{1, 2, 3}, NewMockAddr("remote"))

	// Test with valid transport message but unknown connection
	validMsg := noise.BuildTransportMessage(12345, 0, []byte("test ciphertext"))
	listener.handleTransport(validMsg, NewMockAddr("remote"))

	// Create a connection and register it
	remoteKey, _ := noise.GenerateKeyPair()
	conn, _ := newConn(localKey, transport, NewMockAddr("remote"), remoteKey.Public)
	localIdx := conn.LocalIndex()

	listener.mu.Lock()
	listener.conns[localIdx] = conn
	listener.mu.Unlock()

	// Build a transport message for this connection
	msg := noise.BuildTransportMessage(localIdx, 0, []byte("test ciphertext"))

	// This should route to the connection (even if decryption fails)
	listener.handleTransport(msg, NewMockAddr("remote"))
}

// TestConnStateString tests ConnState.String method.
func TestConnStateString(t *testing.T) {
	tests := []struct {
		state ConnState
		want  string
	}{
		{ConnStateNew, "new"},
		{ConnStateHandshaking, "handshaking"},
		{ConnStateEstablished, "established"},
		{ConnStateClosed, "closed"},
		{ConnState(99), "unknown"},
	}

	for _, tt := range tests {
		got := tt.state.String()
		if got != tt.want {
			t.Errorf("ConnState(%d).String() = %s, want %s", tt.state, got, tt.want)
		}
	}
}

// TestUDPTransportSendToResolve tests UDPTransport.SendTo with address resolution.
func TestUDPTransportSendToResolve(t *testing.T) {
	transport, err := NewUDPTransport("127.0.0.1:0")
	if err != nil {
		t.Fatalf("NewUDPTransport() error = %v", err)
	}
	defer transport.Close()

	// Send to a mock address (will resolve from string)
	mockAddr := NewMockAddr("127.0.0.1:12345")
	err = transport.SendTo([]byte("test"), mockAddr)
	// This may or may not error depending on whether the address is reachable
	// but we're testing the code path
	_ = err
}

// TestNewUDPTransportError tests NewUDPTransport with invalid address.
func TestNewUDPTransportError(t *testing.T) {
	// Invalid address format
	_, err := NewUDPTransport("invalid:address:format")
	if err == nil {
		t.Error("NewUDPTransport(invalid) should return error")
	}
}

// TestUDPWriteToErrors tests various error conditions in UDP.WriteTo.
func TestUDPWriteToErrors(t *testing.T) {
	localKey, _ := noise.GenerateKeyPair()
	udp, err := NewUDP(localKey, WithBindAddr("127.0.0.1:0"))
	if err != nil {
		t.Fatalf("NewUDP() error = %v", err)
	}

	remoteKey, _ := noise.GenerateKeyPair()

	// Test write to non-existent peer
	err = udp.WriteTo(remoteKey.Public, []byte("test"))
	if err != ErrPeerNotFound {
		t.Errorf("WriteTo(non-existent) error = %v, want %v", err, ErrPeerNotFound)
	}

	// Add peer but without session
	remoteAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:12345")
	udp.SetPeerEndpoint(remoteKey.Public, remoteAddr)

	// Test write without session
	err = udp.WriteTo(remoteKey.Public, []byte("test"))
	if err != ErrNoSession {
		t.Errorf("WriteTo(no session) error = %v, want %v", err, ErrNoSession)
	}

	// Test write after close
	udp.Close()
	err = udp.WriteTo(remoteKey.Public, []byte("test"))
	if err != ErrClosed {
		t.Errorf("WriteTo(closed) error = %v, want %v", err, ErrClosed)
	}
}

// TestUDPReadFromClosed tests UDP.ReadFrom after close.
func TestUDPReadFromClosed(t *testing.T) {
	localKey, _ := noise.GenerateKeyPair()
	udp, err := NewUDP(localKey, WithBindAddr("127.0.0.1:0"))
	if err != nil {
		t.Fatalf("NewUDP() error = %v", err)
	}

	udp.Close()

	buf := make([]byte, 1024)
	_, _, err = udp.ReadFrom(buf)
	if err != ErrClosed {
		t.Errorf("ReadFrom(closed) error = %v, want %v", err, ErrClosed)
	}
}
