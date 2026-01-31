package net

import (
	"testing"
	"time"

	"github.com/vibing/zgrnet/noise"
)

func TestTickNewConn(t *testing.T) {
	key, _ := noise.GenerateKeyPair()
	transport := NewMockTransport("test")
	defer transport.Close()

	conn, _ := newConn(key, transport, nil, noise.PublicKey{})

	err := conn.Tick()
	if err != nil {
		t.Errorf("Tick() error = %v", err)
	}
}

func TestTickClosedConn(t *testing.T) {
	key, _ := noise.GenerateKeyPair()
	transport := NewMockTransport("test")
	defer transport.Close()

	conn, _ := newConn(key, transport, nil, noise.PublicKey{})
	conn.Close()

	err := conn.Tick()
	if err != ErrConnClosed {
		t.Errorf("Tick() error = %v, want ErrConnClosed", err)
	}
}

func TestTickKeepalive(t *testing.T) {
	// Create two connected transports
	clientTransport := NewMockTransport("client")
	serverTransport := NewMockTransport("server")
	clientTransport.Connect(serverTransport)
	defer clientTransport.Close()
	defer serverTransport.Close()

	clientKey, _ := noise.GenerateKeyPair()
	serverKey, _ := noise.GenerateKeyPair()

	// Create a mock session for the client
	sendKey := [32]byte{1, 2, 3}
	recvKey := [32]byte{4, 5, 6}

	session, err := noise.NewSession(noise.SessionConfig{
		LocalIndex:  1,
		RemoteIndex: 2,
		SendKey:     sendKey,
		RecvKey:     recvKey,
		RemotePK:    serverKey.Public,
	})
	if err != nil {
		t.Fatalf("NewSession() error = %v", err)
	}

	conn, _ := newConn(clientKey, clientTransport, serverTransport.LocalAddr(), serverKey.Public)

	// Manually set connection to established state with an old lastSent time
	conn.mu.Lock()
	conn.state = ConnStateEstablished
	conn.current = session
	conn.lastSent = time.Now().Add(-KeepaliveTimeout - time.Second)
	conn.lastReceived = time.Now() // Recent receive, so passive keepalive should trigger
	conn.sessionCreated = time.Now()
	conn.mu.Unlock()

	// Tick should send a keepalive
	err = conn.Tick()
	if err != nil {
		t.Errorf("Tick() error = %v", err)
	}

	// Verify lastSent was updated (keepalive was sent)
	conn.mu.RLock()
	lastSent := conn.lastSent
	conn.mu.RUnlock()

	if time.Since(lastSent) > time.Second {
		t.Error("Tick() did not update lastSent, keepalive may not have been sent")
	}
}

func TestTickNoKeepaliveWhenNoRecentReceive(t *testing.T) {
	key, _ := noise.GenerateKeyPair()
	transport := NewMockTransport("test")
	defer transport.Close()

	// Create a mock session
	sendKey := [32]byte{1, 2, 3}
	recvKey := [32]byte{4, 5, 6}
	remotePK := noise.PublicKey{}

	session, _ := noise.NewSession(noise.SessionConfig{
		LocalIndex:  1,
		RemoteIndex: 2,
		SendKey:     sendKey,
		RecvKey:     recvKey,
		RemotePK:    remotePK,
	})

	conn, _ := newConn(key, transport, nil, remotePK)

	// Set both lastSent and lastReceived to old times
	// Passive keepalive only triggers if we've received recently but not sent
	oldTime := time.Now().Add(-KeepaliveTimeout - time.Second)
	conn.mu.Lock()
	conn.state = ConnStateEstablished
	conn.current = session
	conn.lastSent = oldTime
	conn.lastReceived = oldTime // No recent receive, so no passive keepalive
	conn.sessionCreated = time.Now()
	conn.mu.Unlock()

	originalLastSent := oldTime
	err := conn.Tick()
	if err != nil {
		t.Errorf("Tick() error = %v", err)
	}

	// lastSent should NOT have been updated (no keepalive sent)
	conn.mu.RLock()
	lastSent := conn.lastSent
	conn.mu.RUnlock()

	if lastSent != originalLastSent {
		t.Error("Tick() sent keepalive when it shouldn't have (no recent receive)")
	}
}

func TestTickTimeout(t *testing.T) {
	key, _ := noise.GenerateKeyPair()
	transport := NewMockTransport("test")
	defer transport.Close()

	conn, _ := newConn(key, transport, nil, noise.PublicKey{})

	// Manually set connection to established state with old lastReceived
	conn.mu.Lock()
	conn.state = ConnStateEstablished
	conn.lastSent = time.Now()
	conn.lastReceived = time.Now().Add(-RejectAfterTime - time.Second)
	conn.sessionCreated = time.Now()
	conn.mu.Unlock()

	err := conn.Tick()
	if err != ErrConnTimeout {
		t.Errorf("Tick() error = %v, want ErrConnTimeout", err)
	}
}

func TestTickHandshakeTimeout(t *testing.T) {
	key, _ := noise.GenerateKeyPair()
	transport := NewMockTransport("test")
	defer transport.Close()

	conn, _ := newConn(key, transport, nil, noise.PublicKey{})

	// Manually set connection to handshaking state with expired attempt
	conn.mu.Lock()
	conn.state = ConnStateHandshaking
	conn.handshakeAttemptStart = time.Now().Add(-RekeyAttemptTime - time.Second)
	conn.mu.Unlock()

	err := conn.Tick()
	if err != ErrHandshakeTimeout {
		t.Errorf("Tick() error = %v, want ErrHandshakeTimeout", err)
	}
}

func TestTickNoAction(t *testing.T) {
	key, _ := noise.GenerateKeyPair()
	transport := NewMockTransport("test")
	defer transport.Close()

	// Create a mock session
	sendKey := [32]byte{1, 2, 3}
	recvKey := [32]byte{4, 5, 6}
	remotePK := noise.PublicKey{}

	session, _ := noise.NewSession(noise.SessionConfig{
		LocalIndex:  1,
		RemoteIndex: 2,
		SendKey:     sendKey,
		RecvKey:     recvKey,
		RemotePK:    remotePK,
	})

	conn, _ := newConn(key, transport, nil, remotePK)

	// Set all timestamps to recent
	now := time.Now()
	conn.mu.Lock()
	conn.state = ConnStateEstablished
	conn.current = session
	conn.lastSent = now
	conn.lastReceived = now
	conn.sessionCreated = now
	conn.mu.Unlock()

	err := conn.Tick()
	if err != nil {
		t.Errorf("Tick() error = %v", err)
	}
}

func TestTickRekeyTrigger(t *testing.T) {
	// Create two connected transports
	clientTransport := NewMockTransport("client")
	serverTransport := NewMockTransport("server")
	clientTransport.Connect(serverTransport)
	defer clientTransport.Close()
	defer serverTransport.Close()

	clientKey, _ := noise.GenerateKeyPair()
	serverKey, _ := noise.GenerateKeyPair()

	// Create a mock session for the client
	sendKey := [32]byte{1, 2, 3}
	recvKey := [32]byte{4, 5, 6}

	session, _ := noise.NewSession(noise.SessionConfig{
		LocalIndex:  1,
		RemoteIndex: 2,
		SendKey:     sendKey,
		RecvKey:     recvKey,
		RemotePK:    serverKey.Public,
	})

	conn, _ := newConn(clientKey, clientTransport, serverTransport.LocalAddr(), serverKey.Public)

	// Set as initiator with old session (past RekeyAfterTime)
	conn.mu.Lock()
	conn.state = ConnStateEstablished
	conn.current = session
	conn.isInitiator = true
	conn.lastSent = time.Now()
	conn.lastReceived = time.Now()
	conn.sessionCreated = time.Now().Add(-RekeyAfterTime - time.Second)
	conn.mu.Unlock()

	// Tick should trigger rekey (but won't error since it initiates in background)
	err := conn.Tick()
	if err != nil {
		t.Errorf("Tick() error = %v", err)
	}

	// Give the rekey goroutine a moment to start
	time.Sleep(50 * time.Millisecond)

	// Check that a handshake state was created
	conn.mu.RLock()
	hasHsState := conn.hsState != nil
	rekeyTriggered := conn.rekeyTriggered
	conn.mu.RUnlock()

	if !hasHsState {
		t.Error("Tick() did not trigger rekey (hsState is nil)")
	}
	if !rekeyTriggered {
		t.Error("Tick() did not set rekeyTriggered")
	}
}

func TestTickResponderNoRekey(t *testing.T) {
	key, _ := noise.GenerateKeyPair()
	transport := NewMockTransport("test")
	defer transport.Close()

	// Create a mock session
	sendKey := [32]byte{1, 2, 3}
	recvKey := [32]byte{4, 5, 6}
	remotePK := noise.PublicKey{}

	session, _ := noise.NewSession(noise.SessionConfig{
		LocalIndex:  1,
		RemoteIndex: 2,
		SendKey:     sendKey,
		RecvKey:     recvKey,
		RemotePK:    remotePK,
	})

	conn, _ := newConn(key, transport, nil, remotePK)

	// Set as responder (not initiator) with old session
	// Responders should NOT trigger rekey, only initiators
	conn.mu.Lock()
	conn.state = ConnStateEstablished
	conn.current = session
	conn.isInitiator = false // Responder
	conn.lastSent = time.Now()
	conn.lastReceived = time.Now()
	conn.sessionCreated = time.Now().Add(-RekeyAfterTime - time.Second)
	conn.mu.Unlock()

	err := conn.Tick()
	if err != nil {
		t.Errorf("Tick() error = %v", err)
	}

	// Responder should not have triggered rekey
	conn.mu.RLock()
	hasHsState := conn.hsState != nil
	conn.mu.RUnlock()

	if hasHsState {
		t.Error("Responder should not trigger rekey")
	}
}

// TestTickHandshakeRetransmit tests that Tick retransmits handshake after RekeyTimeout
func TestTickHandshakeRetransmit(t *testing.T) {
	// Create two connected transports
	clientTransport := NewMockTransport("client")
	serverTransport := NewMockTransport("server")
	clientTransport.Connect(serverTransport)
	defer clientTransport.Close()
	defer serverTransport.Close()

	clientKey, _ := noise.GenerateKeyPair()
	serverKey, _ := noise.GenerateKeyPair()

	conn, _ := newConn(clientKey, clientTransport, serverTransport.LocalAddr(), serverKey.Public)

	// Create initial handshake state
	hs, _ := noise.NewHandshakeState(noise.Config{
		Pattern:      noise.PatternIK,
		Initiator:    true,
		LocalStatic:  clientKey,
		RemoteStatic: &serverKey.Public,
	})

	// Set connection in handshaking state with old lastHandshakeSent
	conn.mu.Lock()
	conn.state = ConnStateHandshaking
	conn.hsState = hs
	conn.handshakeAttemptStart = time.Now()
	conn.lastHandshakeSent = time.Now().Add(-RekeyTimeout - time.Second) // Past retransmit time
	conn.mu.Unlock()

	// Tick should trigger retransmit
	err := conn.Tick()
	if err != nil {
		t.Errorf("Tick() error = %v", err)
	}

	// Verify lastHandshakeSent was updated (retransmit happened)
	conn.mu.RLock()
	lastHandshakeSent := conn.lastHandshakeSent
	conn.mu.RUnlock()

	if time.Since(lastHandshakeSent) > time.Second {
		t.Error("Tick() did not retransmit handshake")
	}
}

// TestTickEstablishedWithPendingRekey tests Tick behavior when established but rekey in progress
func TestTickEstablishedWithPendingRekey(t *testing.T) {
	clientTransport := NewMockTransport("client")
	serverTransport := NewMockTransport("server")
	clientTransport.Connect(serverTransport)
	defer clientTransport.Close()
	defer serverTransport.Close()

	clientKey, _ := noise.GenerateKeyPair()
	serverKey, _ := noise.GenerateKeyPair()

	// Create a mock session
	sendKey := [32]byte{1, 2, 3}
	recvKey := [32]byte{4, 5, 6}

	session, _ := noise.NewSession(noise.SessionConfig{
		LocalIndex:  1,
		RemoteIndex: 2,
		SendKey:     sendKey,
		RecvKey:     recvKey,
		RemotePK:    serverKey.Public,
	})

	conn, _ := newConn(clientKey, clientTransport, serverTransport.LocalAddr(), serverKey.Public)

	// Create handshake state for pending rekey
	hs, _ := noise.NewHandshakeState(noise.Config{
		Pattern:      noise.PatternIK,
		Initiator:    true,
		LocalStatic:  clientKey,
		RemoteStatic: &serverKey.Public,
	})

	// Set established state with pending rekey that needs retransmit
	conn.mu.Lock()
	conn.state = ConnStateEstablished
	conn.current = session
	conn.hsState = hs // Pending rekey
	conn.handshakeAttemptStart = time.Now()
	conn.lastHandshakeSent = time.Now().Add(-RekeyTimeout - time.Second)
	conn.lastReceived = time.Now()
	conn.sessionCreated = time.Now()
	conn.mu.Unlock()

	err := conn.Tick()
	if err != nil {
		t.Errorf("Tick() error = %v", err)
	}

	// Verify retransmit happened
	conn.mu.RLock()
	lastHandshakeSent := conn.lastHandshakeSent
	conn.mu.RUnlock()

	if time.Since(lastHandshakeSent) > time.Second {
		t.Error("Tick() did not retransmit during established rekey")
	}
}

// TestTickEstablishedRekeyTimeout tests that rekey timeout is detected in established state
func TestTickEstablishedRekeyTimeout(t *testing.T) {
	key, _ := noise.GenerateKeyPair()
	transport := NewMockTransport("test")
	defer transport.Close()

	serverKey, _ := noise.GenerateKeyPair()

	// Create a mock session
	sendKey := [32]byte{1, 2, 3}
	recvKey := [32]byte{4, 5, 6}

	session, _ := noise.NewSession(noise.SessionConfig{
		LocalIndex:  1,
		RemoteIndex: 2,
		SendKey:     sendKey,
		RecvKey:     recvKey,
		RemotePK:    serverKey.Public,
	})

	conn, _ := newConn(key, transport, nil, serverKey.Public)

	// Create handshake state for pending rekey
	hs, _ := noise.NewHandshakeState(noise.Config{
		Pattern:      noise.PatternIK,
		Initiator:    true,
		LocalStatic:  key,
		RemoteStatic: &serverKey.Public,
	})

	// Set established state with expired rekey attempt
	conn.mu.Lock()
	conn.state = ConnStateEstablished
	conn.current = session
	conn.hsState = hs
	conn.handshakeAttemptStart = time.Now().Add(-RekeyAttemptTime - time.Second) // Expired
	conn.lastReceived = time.Now()
	conn.sessionCreated = time.Now()
	conn.mu.Unlock()

	err := conn.Tick()
	if err != ErrHandshakeTimeout {
		t.Errorf("Tick() error = %v, want ErrHandshakeTimeout", err)
	}
}

// TestTickHandshakingRetransmit tests retransmit in handshaking state
func TestTickHandshakingRetransmit(t *testing.T) {
	clientTransport := NewMockTransport("client")
	serverTransport := NewMockTransport("server")
	clientTransport.Connect(serverTransport)
	defer clientTransport.Close()
	defer serverTransport.Close()

	clientKey, _ := noise.GenerateKeyPair()
	serverKey, _ := noise.GenerateKeyPair()

	conn, _ := newConn(clientKey, clientTransport, serverTransport.LocalAddr(), serverKey.Public)

	// Create handshake state
	hs, _ := noise.NewHandshakeState(noise.Config{
		Pattern:      noise.PatternIK,
		Initiator:    true,
		LocalStatic:  clientKey,
		RemoteStatic: &serverKey.Public,
	})

	// Set handshaking state needing retransmit
	conn.mu.Lock()
	conn.state = ConnStateHandshaking
	conn.hsState = hs
	conn.handshakeAttemptStart = time.Now()
	conn.lastHandshakeSent = time.Now().Add(-RekeyTimeout - time.Second)
	conn.mu.Unlock()

	err := conn.Tick()
	if err != nil {
		t.Errorf("Tick() error = %v", err)
	}

	// Verify retransmit
	conn.mu.RLock()
	lastSent := conn.lastHandshakeSent
	conn.mu.RUnlock()

	if time.Since(lastSent) > time.Second {
		t.Error("Tick() did not retransmit in handshaking state")
	}
}

// TestTickHandshakingNoRetransmitYet tests no retransmit before RekeyTimeout
func TestTickHandshakingNoRetransmitYet(t *testing.T) {
	key, _ := noise.GenerateKeyPair()
	transport := NewMockTransport("test")
	defer transport.Close()

	serverKey, _ := noise.GenerateKeyPair()

	conn, _ := newConn(key, transport, nil, serverKey.Public)

	// Create handshake state
	hs, _ := noise.NewHandshakeState(noise.Config{
		Pattern:      noise.PatternIK,
		Initiator:    true,
		LocalStatic:  key,
		RemoteStatic: &serverKey.Public,
	})

	originalTime := time.Now().Add(-time.Second) // Recent, not needing retransmit

	conn.mu.Lock()
	conn.state = ConnStateHandshaking
	conn.hsState = hs
	conn.handshakeAttemptStart = time.Now()
	conn.lastHandshakeSent = originalTime
	conn.mu.Unlock()

	err := conn.Tick()
	if err != nil {
		t.Errorf("Tick() error = %v", err)
	}

	// Should not have retransmitted
	conn.mu.RLock()
	lastSent := conn.lastHandshakeSent
	conn.mu.RUnlock()

	if lastSent != originalTime {
		t.Error("Tick() retransmitted too early")
	}
}

// TestTickInvalidState tests Tick with an invalid state
func TestTickInvalidState(t *testing.T) {
	key, _ := noise.GenerateKeyPair()
	transport := NewMockTransport("test")
	defer transport.Close()

	conn, _ := newConn(key, transport, nil, noise.PublicKey{})

	// Set invalid state
	conn.mu.Lock()
	conn.state = ConnState(99) // Invalid state
	conn.mu.Unlock()

	err := conn.Tick()
	if err != ErrInvalidConnState {
		t.Errorf("Tick() error = %v, want ErrInvalidConnState", err)
	}
}

// TestTickHandshakingWithoutHsState tests handshaking state but no hsState set
func TestTickHandshakingWithoutHsState(t *testing.T) {
	key, _ := noise.GenerateKeyPair()
	transport := NewMockTransport("test")
	defer transport.Close()

	conn, _ := newConn(key, transport, nil, noise.PublicKey{})

	// Set handshaking state but no hsState
	conn.mu.Lock()
	conn.state = ConnStateHandshaking
	conn.hsState = nil // No handshake state
	conn.handshakeAttemptStart = time.Now()
	conn.mu.Unlock()

	// Should not error, just nothing to retransmit
	err := conn.Tick()
	if err != nil {
		t.Errorf("Tick() error = %v", err)
	}
}

// TestTickHandshakingWithZeroTimestamps tests handshaking with zero timestamps
func TestTickHandshakingWithZeroTimestamps(t *testing.T) {
	key, _ := noise.GenerateKeyPair()
	transport := NewMockTransport("test")
	defer transport.Close()

	serverKey, _ := noise.GenerateKeyPair()

	conn, _ := newConn(key, transport, nil, serverKey.Public)

	hs, _ := noise.NewHandshakeState(noise.Config{
		Pattern:      noise.PatternIK,
		Initiator:    true,
		LocalStatic:  key,
		RemoteStatic: &serverKey.Public,
	})

	conn.mu.Lock()
	conn.state = ConnStateHandshaking
	conn.hsState = hs
	// Zero timestamps - should not trigger retransmit or timeout
	conn.handshakeAttemptStart = time.Time{}
	conn.lastHandshakeSent = time.Time{}
	conn.mu.Unlock()

	err := conn.Tick()
	if err != nil {
		t.Errorf("Tick() with zero timestamps error = %v", err)
	}
}

// TestTickRekeyNotDuplicate tests that rekey is not triggered twice
func TestTickRekeyNotDuplicate(t *testing.T) {
	clientTransport := NewMockTransport("client")
	serverTransport := NewMockTransport("server")
	clientTransport.Connect(serverTransport)
	defer clientTransport.Close()
	defer serverTransport.Close()

	clientKey, _ := noise.GenerateKeyPair()
	serverKey, _ := noise.GenerateKeyPair()

	sendKey := [32]byte{1, 2, 3}
	recvKey := [32]byte{4, 5, 6}

	session, _ := noise.NewSession(noise.SessionConfig{
		LocalIndex:  1,
		RemoteIndex: 2,
		SendKey:     sendKey,
		RecvKey:     recvKey,
		RemotePK:    serverKey.Public,
	})

	conn, _ := newConn(clientKey, clientTransport, serverTransport.LocalAddr(), serverKey.Public)

	conn.mu.Lock()
	conn.state = ConnStateEstablished
	conn.current = session
	conn.isInitiator = true
	conn.lastSent = time.Now()
	conn.lastReceived = time.Now()
	conn.sessionCreated = time.Now().Add(-RekeyAfterTime - time.Second)
	conn.rekeyTriggered = true // Already triggered
	conn.mu.Unlock()

	// Tick should NOT trigger rekey again
	err := conn.Tick()
	if err != nil {
		t.Errorf("Tick() error = %v", err)
	}

	conn.mu.RLock()
	hasHsState := conn.hsState != nil
	conn.mu.RUnlock()

	if hasHsState {
		t.Error("Should not trigger rekey when rekeyTriggered is already true")
	}
}

// TestTickEstablishedNoSessionNoPanic tests Tick doesn't panic with nil current session
func TestTickEstablishedNoSessionNoPanic(t *testing.T) {
	key, _ := noise.GenerateKeyPair()
	transport := NewMockTransport("test")
	defer transport.Close()

	conn, _ := newConn(key, transport, nil, noise.PublicKey{})

	conn.mu.Lock()
	conn.state = ConnStateEstablished
	conn.current = nil // No session
	conn.lastReceived = time.Now()
	conn.sessionCreated = time.Now()
	conn.mu.Unlock()

	// Should not panic
	err := conn.Tick()
	// May or may not error, but should not panic
	_ = err
}

// TestTickMessageBasedRekey tests rekey triggered by message count
func TestTickMessageBasedRekey(t *testing.T) {
	clientTransport := NewMockTransport("client")
	serverTransport := NewMockTransport("server")
	clientTransport.Connect(serverTransport)
	defer clientTransport.Close()
	defer serverTransport.Close()

	clientKey, _ := noise.GenerateKeyPair()
	serverKey, _ := noise.GenerateKeyPair()

	sendKey := [32]byte{1, 2, 3}
	recvKey := [32]byte{4, 5, 6}

	session, _ := noise.NewSession(noise.SessionConfig{
		LocalIndex:  1,
		RemoteIndex: 2,
		SendKey:     sendKey,
		RecvKey:     recvKey,
		RemotePK:    serverKey.Public,
	})

	conn, _ := newConn(clientKey, clientTransport, serverTransport.LocalAddr(), serverKey.Public)

	conn.mu.Lock()
	conn.state = ConnStateEstablished
	conn.current = session
	conn.isInitiator = true
	conn.lastSent = time.Now()
	conn.lastReceived = time.Now()
	conn.sessionCreated = time.Now() // Recent session (no time-based rekey)
	conn.mu.Unlock()

	// Tick should check session nonces but not trigger rekey for fresh session
	err := conn.Tick()
	if err != nil {
		t.Errorf("Tick() error = %v", err)
	}

	// Verify no rekey was triggered (nonces are low)
	conn.mu.RLock()
	hasHsState := conn.hsState != nil
	conn.mu.RUnlock()

	if hasHsState {
		t.Error("Should not trigger rekey for fresh session with low nonces")
	}
}
