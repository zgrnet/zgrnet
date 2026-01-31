package conn

import (
	"testing"
	"time"

	"github.com/vibing/zgrnet/noise"
)

func TestTickActionString(t *testing.T) {
	tests := []struct {
		action TickAction
		str    string
	}{
		{TickActionNone, "none"},
		{TickActionSendKeepalive, "send_keepalive"},
		{TickActionRekey, "rekey"},
		{TickAction(99), "unknown"},
	}

	for _, tt := range tests {
		if tt.action.String() != tt.str {
			t.Errorf("TickAction(%d).String() = %s, want %s", tt.action, tt.action.String(), tt.str)
		}
	}
}

func TestTickNewConn(t *testing.T) {
	key, _ := noise.GenerateKeyPair()
	transport := noise.NewMockTransport("test")
	defer transport.Close()

	conn, _ := newConn(key, transport, nil, noise.PublicKey{})

	action, err := conn.Tick(time.Now())
	if err != nil {
		t.Errorf("Tick() error = %v", err)
	}
	if action != TickActionNone {
		t.Errorf("Tick() action = %v, want TickActionNone", action)
	}
}

func TestTickClosedConn(t *testing.T) {
	key, _ := noise.GenerateKeyPair()
	transport := noise.NewMockTransport("test")
	defer transport.Close()

	conn, _ := newConn(key, transport, nil, noise.PublicKey{})
	conn.Close()

	action, err := conn.Tick(time.Now())
	if err != ErrConnClosed {
		t.Errorf("Tick() error = %v, want ErrConnClosed", err)
	}
	if action != TickActionNone {
		t.Errorf("Tick() action = %v, want TickActionNone", action)
	}
}

func TestTickKeepalive(t *testing.T) {
	key, _ := noise.GenerateKeyPair()
	transport := noise.NewMockTransport("test")
	defer transport.Close()

	conn, _ := newConn(key, transport, nil, noise.PublicKey{})

	// Manually set connection to established state for testing
	conn.mu.Lock()
	conn.state = ConnStateEstablished
	conn.lastSent = time.Now().Add(-KeepaliveTimeout - time.Second)
	conn.lastReceived = time.Now()
	conn.createdAt = time.Now()
	conn.mu.Unlock()

	action, err := conn.Tick(time.Now())
	if err != nil {
		t.Errorf("Tick() error = %v", err)
	}
	if action != TickActionSendKeepalive {
		t.Errorf("Tick() action = %v, want TickActionSendKeepalive", action)
	}
}

func TestTickRekey(t *testing.T) {
	key, _ := noise.GenerateKeyPair()
	transport := noise.NewMockTransport("test")
	defer transport.Close()

	conn, _ := newConn(key, transport, nil, noise.PublicKey{})

	// Manually set connection to established state for testing
	conn.mu.Lock()
	conn.state = ConnStateEstablished
	conn.lastSent = time.Now()
	conn.lastReceived = time.Now()
	conn.createdAt = time.Now().Add(-RekeyAfterTime - time.Second)
	conn.mu.Unlock()

	action, err := conn.Tick(time.Now())
	if err != nil {
		t.Errorf("Tick() error = %v", err)
	}
	if action != TickActionRekey {
		t.Errorf("Tick() action = %v, want TickActionRekey", action)
	}
}

func TestTickTimeout(t *testing.T) {
	key, _ := noise.GenerateKeyPair()
	transport := noise.NewMockTransport("test")
	defer transport.Close()

	conn, _ := newConn(key, transport, nil, noise.PublicKey{})

	// Manually set connection to established state for testing
	conn.mu.Lock()
	conn.state = ConnStateEstablished
	conn.lastSent = time.Now()
	conn.lastReceived = time.Now().Add(-RejectAfterTime - time.Second)
	conn.createdAt = time.Now()
	conn.mu.Unlock()

	action, err := conn.Tick(time.Now())
	if err != ErrConnTimeout {
		t.Errorf("Tick() error = %v, want ErrConnTimeout", err)
	}
	if action != TickActionNone {
		t.Errorf("Tick() action = %v, want TickActionNone", action)
	}
}

func TestTickHandshakeTimeout(t *testing.T) {
	key, _ := noise.GenerateKeyPair()
	transport := noise.NewMockTransport("test")
	defer transport.Close()

	conn, _ := newConn(key, transport, nil, noise.PublicKey{})

	// Manually set connection to handshaking state for testing
	conn.mu.Lock()
	conn.state = ConnStateHandshaking
	conn.handshakeStarted = time.Now().Add(-HandshakeTimeout - time.Second)
	conn.mu.Unlock()

	action, err := conn.Tick(time.Now())
	if err != ErrHandshakeTimeout {
		t.Errorf("Tick() error = %v, want ErrHandshakeTimeout", err)
	}
	if action != TickActionNone {
		t.Errorf("Tick() action = %v, want TickActionNone", action)
	}
}

func TestTickNoAction(t *testing.T) {
	key, _ := noise.GenerateKeyPair()
	transport := noise.NewMockTransport("test")
	defer transport.Close()

	conn, _ := newConn(key, transport, nil, noise.PublicKey{})

	// Manually set connection to established state for testing
	now := time.Now()
	conn.mu.Lock()
	conn.state = ConnStateEstablished
	conn.lastSent = now
	conn.lastReceived = now
	conn.createdAt = now
	conn.mu.Unlock()

	action, err := conn.Tick(now)
	if err != nil {
		t.Errorf("Tick() error = %v", err)
	}
	if action != TickActionNone {
		t.Errorf("Tick() action = %v, want TickActionNone", action)
	}
}
