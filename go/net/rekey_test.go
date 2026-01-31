package net

import (
	"bytes"
	"context"
	"sync"
	"testing"
	"time"

	"github.com/vibing/zgrnet/noise"
)

// setupConnPair creates a pair of established connections for testing.
// Returns initiator, responder connections and a cleanup function.
func setupConnPair(t *testing.T) (initiator, responder *Conn, cleanup func()) {
	t.Helper()

	initiatorKey, _ := noise.GenerateKeyPair()
	responderKey, _ := noise.GenerateKeyPair()

	initiatorTransport := NewMockTransport("initiator")
	responderTransport := NewMockTransport("responder")
	initiatorTransport.Connect(responderTransport)

	var wg sync.WaitGroup
	var initiatorConn, responderConn *Conn
	var responderErr error

	// Start responder
	wg.Add(1)
	go func() {
		defer wg.Done()
		responderConn, _ = newConn(responderKey, responderTransport, initiatorTransport.LocalAddr(), noise.PublicKey{})
		buf := make([]byte, noise.MaxPacketSize)
		n, _, err := responderTransport.RecvFrom(buf)
		if err != nil {
			responderErr = err
			return
		}
		initMsg, err := noise.ParseHandshakeInit(buf[:n])
		if err != nil {
			responderErr = err
			return
		}
		resp, err := responderConn.accept(initMsg)
		if err != nil {
			responderErr = err
			return
		}
		if err := responderTransport.SendTo(resp, initiatorTransport.LocalAddr()); err != nil {
			responderErr = err
			return
		}
	}()

	time.Sleep(10 * time.Millisecond)

	// Dial from initiator
	initiatorConn, err := Dial(context.Background(), initiatorTransport, responderTransport.LocalAddr(), responderKey.Public, initiatorKey)
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	wg.Wait()

	if responderErr != nil {
		t.Fatalf("Responder error = %v", responderErr)
	}

	cleanup = func() {
		initiatorConn.Close()
		responderConn.Close()
		initiatorTransport.Close()
		responderTransport.Close()
	}

	return initiatorConn, responderConn, cleanup
}

// TestRekeyInitiatorFlow tests the complete rekey flow initiated by the initiator.
// 1. Establish initial connection
// 2. Trigger rekey by making session appear expired
// 3. Responder receives handshake init and sends response
// 4. Initiator processes response via Recv()
// 5. Verify session rotation: current -> previous
func TestRekeyInitiatorFlow(t *testing.T) {
	initiator, responder, cleanup := setupConnPair(t)
	defer cleanup()

	// Save old session info
	initiator.mu.RLock()
	oldSession := initiator.current
	oldLocalIdx := oldSession.LocalIndex()
	initiator.mu.RUnlock()

	// Make session appear expired to trigger rekey
	initiator.mu.Lock()
	initiator.sessionCreated = time.Now().Add(-RekeyAfterTime - time.Second)
	initiator.isInitiator = true
	initiator.mu.Unlock()

	// Tick should trigger rekey
	err := initiator.Tick()
	if err != nil {
		t.Fatalf("Tick() error = %v", err)
	}

	// Give time for rekey handshake to be sent
	time.Sleep(50 * time.Millisecond)

	// Verify initiator has started rekey (has hsState)
	initiator.mu.RLock()
	hasHsState := initiator.hsState != nil
	newLocalIdx := initiator.localIdx
	initiator.mu.RUnlock()

	if !hasHsState {
		t.Fatal("Initiator did not start rekey")
	}
	if newLocalIdx == oldLocalIdx {
		t.Error("Initiator should have new local index for rekey")
	}

	// Responder receives handshake init via Recv()
	// This should trigger handleHandshakeInit
	proto, payload, err := responder.Recv()
	if err != nil {
		t.Fatalf("Responder Recv() error = %v", err)
	}

	// Empty payload indicates handshake message was processed
	if proto != 0 || payload != nil {
		t.Errorf("Expected empty payload for handshake, got proto=%d, payload=%v", proto, payload)
	}

	// Verify responder has new session
	responder.mu.RLock()
	responderHasNew := responder.current != nil
	responderHasPrev := responder.previous != nil
	responder.mu.RUnlock()

	if !responderHasNew {
		t.Error("Responder should have new current session")
	}
	if !responderHasPrev {
		t.Error("Responder should have previous session after rekey")
	}

	// Initiator receives handshake response via Recv()
	proto, payload, err = initiator.Recv()
	if err != nil {
		t.Fatalf("Initiator Recv() error = %v", err)
	}

	// Empty payload indicates handshake response was processed
	if proto != 0 || payload != nil {
		t.Errorf("Expected empty payload for handshake response, got proto=%d, payload=%v", proto, payload)
	}

	// Verify initiator session rotation
	initiator.mu.RLock()
	initiatorCurrent := initiator.current
	initiatorPrev := initiator.previous
	initiatorHsState := initiator.hsState
	initiator.mu.RUnlock()

	if initiatorCurrent == nil {
		t.Fatal("Initiator current session is nil after rekey")
	}
	if initiatorPrev == nil {
		t.Error("Initiator should have previous session after rekey")
	}
	if initiatorPrev != oldSession {
		t.Error("Initiator previous should be old session")
	}
	if initiatorHsState != nil {
		t.Error("Initiator hsState should be nil after rekey completes")
	}

	// Test that communication still works with new session
	testData := []byte("message after rekey")
	if err := initiator.Send(noise.ProtocolChat, testData); err != nil {
		t.Fatalf("Send after rekey error = %v", err)
	}

	proto, payload, err = responder.Recv()
	if err != nil {
		t.Fatalf("Recv after rekey error = %v", err)
	}
	if proto != noise.ProtocolChat || !bytes.Equal(payload, testData) {
		t.Errorf("Message mismatch after rekey")
	}
}

// TestRekeyResponderFlow tests rekey when initiated by the peer.
// The responder should handle handshake init and complete the rekey.
func TestRekeyResponderFlow(t *testing.T) {
	// Setup connection where we're the responder
	clientKey, _ := noise.GenerateKeyPair()
	serverKey, _ := noise.GenerateKeyPair()

	clientTransport := NewMockTransport("client")
	serverTransport := NewMockTransport("server")
	clientTransport.Connect(serverTransport)
	defer clientTransport.Close()
	defer serverTransport.Close()

	// Establish initial connection
	var wg sync.WaitGroup
	var serverConn *Conn
	var serverErr error

	wg.Add(1)
	go func() {
		defer wg.Done()
		serverConn, _ = newConn(serverKey, serverTransport, clientTransport.LocalAddr(), noise.PublicKey{})
		buf := make([]byte, noise.MaxPacketSize)
		n, _, err := serverTransport.RecvFrom(buf)
		if err != nil {
			serverErr = err
			return
		}
		initMsg, _ := noise.ParseHandshakeInit(buf[:n])
		resp, _ := serverConn.accept(initMsg)
		serverTransport.SendTo(resp, clientTransport.LocalAddr())
	}()

	time.Sleep(10 * time.Millisecond)

	clientConn, err := Dial(context.Background(), clientTransport, serverTransport.LocalAddr(), serverKey.Public, clientKey)
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer clientConn.Close()
	wg.Wait()

	if serverErr != nil {
		t.Fatalf("Server error = %v", serverErr)
	}
	defer serverConn.Close()

	// Save server's old session
	serverConn.mu.RLock()
	oldServerSession := serverConn.current
	serverConn.mu.RUnlock()

	// Client initiates rekey by creating and sending new handshake init
	newClientIdx, _ := noise.GenerateIndex()
	hs, _ := noise.NewHandshakeState(noise.Config{
		Pattern:      noise.PatternIK,
		Initiator:    true,
		LocalStatic:  clientKey,
		RemoteStatic: &serverKey.Public,
	})
	msg1, _ := hs.WriteMessage(nil)
	wireInit := noise.BuildHandshakeInit(newClientIdx, hs.LocalEphemeral(), msg1[noise.KeySize:])

	// Inject handshake init to server
	serverTransport.InjectPacket(wireInit, clientTransport.LocalAddr())

	// Server calls Recv() which processes the handshake init
	proto, payload, err := serverConn.Recv()
	if err != nil {
		t.Fatalf("Server Recv() for rekey error = %v", err)
	}

	// Empty payload for handshake
	if proto != 0 || payload != nil {
		t.Errorf("Expected empty for handshake init processing")
	}

	// Verify server has rotated sessions
	serverConn.mu.RLock()
	newServerSession := serverConn.current
	prevServerSession := serverConn.previous
	serverIsInitiator := serverConn.isInitiator
	serverConn.mu.RUnlock()

	if newServerSession == oldServerSession {
		t.Error("Server should have new session after rekey")
	}
	if prevServerSession != oldServerSession {
		t.Error("Server previous should be old session")
	}
	if serverIsInitiator {
		t.Error("Server should be responder (isInitiator=false)")
	}
}

// TestRekeyResponseErrors tests error handling in handleHandshakeResponse
func TestRekeyResponseErrors(t *testing.T) {
	t.Run("NoHandshakeState", func(t *testing.T) {
		key, _ := noise.GenerateKeyPair()
		transport := NewMockTransport("test")
		defer transport.Close()

		conn, _ := newConn(key, transport, nil, noise.PublicKey{})
		conn.mu.Lock()
		conn.state = ConnStateEstablished
		conn.hsState = nil // No pending handshake
		conn.mu.Unlock()

		// Create a fake handshake response
		resp := &noise.HandshakeRespMessage{
			SenderIndex:   1,
			ReceiverIndex: 2,
		}

		_, _, err := conn.handleHandshakeResponse(resp, nil)
		if err != ErrInvalidConnState {
			t.Errorf("handleHandshakeResponse() error = %v, want ErrInvalidConnState", err)
		}
	})

	t.Run("WrongReceiverIndex", func(t *testing.T) {
		clientKey, _ := noise.GenerateKeyPair()
		serverKey, _ := noise.GenerateKeyPair()

		transport := NewMockTransport("test")
		defer transport.Close()

		conn, _ := newConn(clientKey, transport, nil, serverKey.Public)

		// Create handshake state
		hs, _ := noise.NewHandshakeState(noise.Config{
			Pattern:      noise.PatternIK,
			Initiator:    true,
			LocalStatic:  clientKey,
			RemoteStatic: &serverKey.Public,
		})
		hs.WriteMessage(nil)

		conn.mu.Lock()
		conn.state = ConnStateEstablished
		conn.hsState = hs
		conn.localIdx = 100
		conn.mu.Unlock()

		// Create response with wrong receiver index
		resp := &noise.HandshakeRespMessage{
			SenderIndex:   1,
			ReceiverIndex: 999, // Wrong index
		}

		_, _, err := conn.handleHandshakeResponse(resp, nil)
		if err != ErrInvalidReceiverIndex {
			t.Errorf("handleHandshakeResponse() error = %v, want ErrInvalidReceiverIndex", err)
		}
	})
}

// TestRekeyInitErrors tests error handling in handleHandshakeInit
func TestRekeyInitErrors(t *testing.T) {
	t.Run("InvalidRemotePK", func(t *testing.T) {
		serverKey, _ := noise.GenerateKeyPair()
		clientKey, _ := noise.GenerateKeyPair()
		wrongKey, _ := noise.GenerateKeyPair() // Different key

		serverTransport := NewMockTransport("server")
		clientTransport := NewMockTransport("client")
		serverTransport.Connect(clientTransport)
		defer serverTransport.Close()
		defer clientTransport.Close()

		// Create server conn expecting wrongKey, not clientKey
		serverConn, _ := newConn(serverKey, serverTransport, clientTransport.LocalAddr(), wrongKey.Public)
		serverConn.mu.Lock()
		serverConn.state = ConnStateEstablished
		serverConn.mu.Unlock()

		// Client sends handshake init with clientKey
		hs, _ := noise.NewHandshakeState(noise.Config{
			Pattern:      noise.PatternIK,
			Initiator:    true,
			LocalStatic:  clientKey,
			RemoteStatic: &serverKey.Public,
		})
		msg1, _ := hs.WriteMessage(nil)
		wireInit := noise.BuildHandshakeInit(1, hs.LocalEphemeral(), msg1[noise.KeySize:])

		// Parse and handle
		initMsg, _ := noise.ParseHandshakeInit(wireInit)
		_, _, err := serverConn.handleHandshakeInit(initMsg, nil)

		if err != ErrInvalidRemotePK {
			t.Errorf("handleHandshakeInit() error = %v, want ErrInvalidRemotePK", err)
		}
	})
}

// TestRekeyWithDataExchange tests that data can still be exchanged during and after rekey
func TestRekeyWithDataExchange(t *testing.T) {
	initiator, responder, cleanup := setupConnPair(t)
	defer cleanup()

	// Exchange data before rekey
	preRekeyData := []byte("before rekey")
	initiator.Send(noise.ProtocolChat, preRekeyData)
	proto, payload, _ := responder.Recv()
	if !bytes.Equal(payload, preRekeyData) {
		t.Error("Pre-rekey data mismatch")
	}
	_ = proto

	// Trigger rekey
	initiator.mu.Lock()
	initiator.sessionCreated = time.Now().Add(-RekeyAfterTime - time.Second)
	initiator.isInitiator = true
	initiator.mu.Unlock()

	initiator.Tick()
	time.Sleep(50 * time.Millisecond)

	// Process rekey on both sides
	responder.Recv() // Handles handshake init
	initiator.Recv() // Handles handshake response

	// Exchange data after rekey
	postRekeyData := []byte("after rekey")
	initiator.Send(noise.ProtocolChat, postRekeyData)
	proto, payload, err := responder.Recv()
	if err != nil {
		t.Fatalf("Recv after rekey error = %v", err)
	}
	if !bytes.Equal(payload, postRekeyData) {
		t.Error("Post-rekey data mismatch")
	}

	// Bidirectional
	responder.Send(noise.ProtocolRPC, postRekeyData)
	proto, payload, err = initiator.Recv()
	if err != nil {
		t.Fatalf("Initiator recv after rekey error = %v", err)
	}
	if proto != noise.ProtocolRPC || !bytes.Equal(payload, postRekeyData) {
		t.Error("Bidirectional data mismatch after rekey")
	}
}

// TestMultipleRekeys tests multiple consecutive rekeys
func TestMultipleRekeys(t *testing.T) {
	initiator, responder, cleanup := setupConnPair(t)
	defer cleanup()

	for i := 0; i < 3; i++ {
		// Trigger rekey
		initiator.mu.Lock()
		initiator.sessionCreated = time.Now().Add(-RekeyAfterTime - time.Second)
		initiator.isInitiator = true
		initiator.rekeyTriggered = false
		initiator.mu.Unlock()

		initiator.Tick()
		time.Sleep(50 * time.Millisecond)

		// Complete rekey
		responder.Recv()
		initiator.Recv()

		// Verify communication
		testData := []byte("test")
		initiator.Send(noise.ProtocolChat, testData)
		_, payload, err := responder.Recv()
		if err != nil {
			t.Fatalf("Rekey %d: Recv error = %v", i, err)
		}
		if !bytes.Equal(payload, testData) {
			t.Errorf("Rekey %d: data mismatch", i)
		}
	}
}
