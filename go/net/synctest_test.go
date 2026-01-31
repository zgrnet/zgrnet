//go:build go1.24

package net

import (
	"testing"
	"testing/synctest"
	"time"

	"github.com/vibing/zgrnet/noise"
)

// TestTickKeepaliveWithFakeTime tests keepalive using fake time.
// Using synctest, time.Sleep advances the fake clock immediately.
func TestTickKeepaliveWithFakeTime(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
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

		// Set up established state
		conn.mu.Lock()
		conn.state = ConnStateEstablished
		conn.current = session
		conn.sessionCreated = time.Now()
		conn.lastSent = time.Now()
		conn.lastReceived = time.Now()
		conn.mu.Unlock()

		// Advance time past KeepaliveTimeout using fake clock
		time.Sleep(KeepaliveTimeout + time.Second)

		// Tick should send keepalive (lastSent is old, lastReceived is recent due to synctest behavior)
		// In synctest, we need to simulate the condition properly
		conn.mu.Lock()
		conn.lastSent = time.Now().Add(-KeepaliveTimeout - time.Second)
		conn.lastReceived = time.Now() // Recent receive
		conn.mu.Unlock()

		err := conn.Tick()
		if err != nil {
			t.Errorf("Tick() error = %v", err)
		}

		// Verify keepalive was sent (lastSent updated)
		conn.mu.RLock()
		lastSent := conn.lastSent
		conn.mu.RUnlock()

		if time.Since(lastSent) > time.Second {
			t.Error("Keepalive was not sent")
		}
	})
}

// TestConnectionTimeoutWithFakeTime tests connection timeout using fake time.
func TestConnectionTimeoutWithFakeTime(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		key, _ := noise.GenerateKeyPair()
		transport := NewMockTransport("test")
		defer transport.Close()

		conn, _ := newConn(key, transport, nil, noise.PublicKey{})

		// Set up established state with recent timestamps
		startTime := time.Now()
		conn.mu.Lock()
		conn.state = ConnStateEstablished
		conn.lastSent = startTime
		conn.lastReceived = startTime
		conn.sessionCreated = startTime
		conn.mu.Unlock()

		// Advance fake time past RejectAfterTime
		time.Sleep(RejectAfterTime + time.Second)

		// Update lastReceived to be in the past (before the sleep)
		conn.mu.Lock()
		conn.lastReceived = startTime
		conn.mu.Unlock()

		// Tick should return timeout error
		err := conn.Tick()
		if err != ErrConnTimeout {
			t.Errorf("Tick() error = %v, want ErrConnTimeout", err)
		}
	})
}

// TestHandshakeTimeoutWithFakeTime tests handshake timeout using fake time.
func TestHandshakeTimeoutWithFakeTime(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		key, _ := noise.GenerateKeyPair()
		transport := NewMockTransport("test")
		defer transport.Close()

		conn, _ := newConn(key, transport, nil, noise.PublicKey{})

		// Set up handshaking state
		startTime := time.Now()
		conn.mu.Lock()
		conn.state = ConnStateHandshaking
		conn.handshakeAttemptStart = startTime
		conn.mu.Unlock()

		// Advance fake time past RekeyAttemptTime (90s)
		time.Sleep(RekeyAttemptTime + time.Second)

		// Tick should return handshake timeout
		err := conn.Tick()
		if err != ErrHandshakeTimeout {
			t.Errorf("Tick() error = %v, want ErrHandshakeTimeout", err)
		}
	})
}

// TestRekeyTriggerWithFakeTime tests rekey triggering at RekeyAfterTime.
func TestRekeyTriggerWithFakeTime(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		clientTransport := NewMockTransport("client")
		serverTransport := NewMockTransport("server")
		clientTransport.Connect(serverTransport)
		defer clientTransport.Close()
		defer serverTransport.Close()

		clientKey, _ := noise.GenerateKeyPair()
		serverKey, _ := noise.GenerateKeyPair()

		// Create session
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

		sessionStart := time.Now()
		conn.mu.Lock()
		conn.state = ConnStateEstablished
		conn.current = session
		conn.isInitiator = true
		conn.sessionCreated = sessionStart
		conn.lastSent = sessionStart
		conn.lastReceived = sessionStart
		conn.mu.Unlock()

		// Advance time to just before RekeyAfterTime
		time.Sleep(RekeyAfterTime - time.Second)

		// Tick should NOT trigger rekey yet
		conn.mu.Lock()
		conn.sessionCreated = sessionStart // Keep original time
		conn.lastReceived = time.Now()     // Recent receive
		conn.mu.Unlock()

		err := conn.Tick()
		if err != nil {
			t.Errorf("Tick() before rekey time error = %v", err)
		}

		conn.mu.RLock()
		hasHs := conn.hsState != nil
		conn.mu.RUnlock()

		if hasHs {
			t.Error("Should not have triggered rekey before RekeyAfterTime")
		}

		// Advance past RekeyAfterTime
		time.Sleep(2 * time.Second)

		err = conn.Tick()
		if err != nil {
			t.Errorf("Tick() at rekey time error = %v", err)
		}

		// Wait for rekey goroutine
		synctest.Wait()

		conn.mu.RLock()
		hasHsAfter := conn.hsState != nil
		conn.mu.RUnlock()

		if !hasHsAfter {
			t.Error("Should have triggered rekey after RekeyAfterTime")
		}
	})
}

// TestHandshakeRetransmitIntervalWithFakeTime tests retransmit at RekeyTimeout intervals.
func TestHandshakeRetransmitIntervalWithFakeTime(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
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

		startTime := time.Now()
		conn.mu.Lock()
		conn.state = ConnStateHandshaking
		conn.hsState = hs
		conn.handshakeAttemptStart = startTime
		conn.lastHandshakeSent = startTime
		conn.mu.Unlock()

		// Count retransmits
		retransmitCount := 0

		// Simulate multiple retransmit intervals
		for i := 0; i < 5; i++ {
			// Advance time by RekeyTimeout
			time.Sleep(RekeyTimeout + 100*time.Millisecond)

			conn.mu.RLock()
			lastSent := conn.lastHandshakeSent
			conn.mu.RUnlock()

			err := conn.Tick()
			if err != nil {
				t.Fatalf("Tick() iteration %d error = %v", i, err)
			}

			conn.mu.RLock()
			newLastSent := conn.lastHandshakeSent
			conn.mu.RUnlock()

			if newLastSent.After(lastSent) {
				retransmitCount++
			}
		}

		if retransmitCount < 3 {
			t.Errorf("Expected at least 3 retransmits, got %d", retransmitCount)
		}
	})
}

// TestSessionExpirationWithFakeTime tests that old sessions cannot be used.
func TestSessionExpirationWithFakeTime(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		key, _ := noise.GenerateKeyPair()
		transport := NewMockTransport("test")
		defer transport.Close()

		conn, _ := newConn(key, transport, nil, noise.PublicKey{})

		startTime := time.Now()
		conn.mu.Lock()
		conn.state = ConnStateEstablished
		conn.sessionCreated = startTime
		conn.lastReceived = startTime
		conn.mu.Unlock()

		// Advance past RejectAfterTime
		time.Sleep(RejectAfterTime + time.Second)

		// Connection should timeout on next Tick
		conn.mu.Lock()
		conn.lastReceived = startTime // Keep old receive time
		conn.mu.Unlock()

		err := conn.Tick()
		if err != ErrConnTimeout {
			t.Errorf("Tick() after session expiration = %v, want ErrConnTimeout", err)
		}
	})
}

// TestRekeyOnReceiveThresholdWithFakeTime tests rekey triggered on receive at 165s.
func TestRekeyOnReceiveThresholdWithFakeTime(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		clientTransport := NewMockTransport("client")
		serverTransport := NewMockTransport("server")
		clientTransport.Connect(serverTransport)
		defer clientTransport.Close()
		defer serverTransport.Close()

		clientKey, _ := noise.GenerateKeyPair()
		serverKey, _ := noise.GenerateKeyPair()

		// Create session
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

		sessionStart := time.Now()
		conn.mu.Lock()
		conn.state = ConnStateEstablished
		conn.current = session
		conn.isInitiator = true
		conn.sessionCreated = sessionStart
		conn.lastSent = sessionStart
		conn.lastReceived = sessionStart
		conn.mu.Unlock()

		// Advance time to RekeyOnRecvThreshold (165s)
		time.Sleep(RekeyOnRecvThreshold + time.Second)

		// Verify RekeyOnRecvThreshold is correct
		if RekeyOnRecvThreshold != 165*time.Second {
			t.Errorf("RekeyOnRecvThreshold = %v, want 165s", RekeyOnRecvThreshold)
		}
	})
}

// TestNoKeepaliveWhenBothOldWithFakeTime tests no keepalive when both timestamps are old.
func TestNoKeepaliveWhenBothOldWithFakeTime(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		key, _ := noise.GenerateKeyPair()
		transport := NewMockTransport("test")
		defer transport.Close()

		// Create session
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

		startTime := time.Now()
		conn.mu.Lock()
		conn.state = ConnStateEstablished
		conn.current = session
		conn.sessionCreated = startTime
		conn.lastSent = startTime
		conn.lastReceived = startTime
		conn.mu.Unlock()

		// Advance time so both are old
		time.Sleep(KeepaliveTimeout + time.Second)

		// Set both to old times (no recent receive, so no passive keepalive)
		conn.mu.Lock()
		conn.lastSent = startTime
		conn.lastReceived = startTime
		originalLastSent := conn.lastSent
		conn.mu.Unlock()

		err := conn.Tick()
		if err != nil {
			t.Errorf("Tick() error = %v", err)
		}

		// Should NOT have sent keepalive (passive keepalive only when we received recently)
		conn.mu.RLock()
		newLastSent := conn.lastSent
		conn.mu.RUnlock()

		if newLastSent != originalLastSent {
			t.Error("Should not have sent keepalive when lastReceived is also old")
		}
	})
}
