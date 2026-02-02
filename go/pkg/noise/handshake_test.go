package noise

import (
	"bytes"
	"testing"
)

func TestHandshakeIK(t *testing.T) {
	// Generate key pairs
	initiatorStatic, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate initiator static key: %v", err)
	}

	responderStatic, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate responder static key: %v", err)
	}

	// Create handshake states
	// IK pattern: initiator knows responder's static key
	initiator, err := NewHandshakeState(Config{
		Pattern:      PatternIK,
		Initiator:    true,
		LocalStatic:  initiatorStatic,
		RemoteStatic: &responderStatic.Public,
	})
	if err != nil {
		t.Fatalf("failed to create initiator: %v", err)
	}

	responder, err := NewHandshakeState(Config{
		Pattern:     PatternIK,
		Initiator:   false,
		LocalStatic: responderStatic,
	})
	if err != nil {
		t.Fatalf("failed to create responder: %v", err)
	}

	// Message 1: Initiator -> Responder
	msg1, err := initiator.WriteMessage(nil)
	if err != nil {
		t.Fatalf("initiator.WriteMessage() error = %v", err)
	}
	t.Logf("Message 1 length: %d bytes", len(msg1))

	_, err = responder.ReadMessage(msg1)
	if err != nil {
		t.Fatalf("responder.ReadMessage() error = %v", err)
	}

	// Verify responder got initiator's static key
	if responder.RemoteStatic() != initiatorStatic.Public {
		t.Error("responder did not get initiator's static key")
	}

	// Message 2: Responder -> Initiator
	msg2, err := responder.WriteMessage(nil)
	if err != nil {
		t.Fatalf("responder.WriteMessage() error = %v", err)
	}
	t.Logf("Message 2 length: %d bytes", len(msg2))

	_, err = initiator.ReadMessage(msg2)
	if err != nil {
		t.Fatalf("initiator.ReadMessage() error = %v", err)
	}

	// Both should be finished
	if !initiator.IsFinished() {
		t.Error("initiator should be finished")
	}
	if !responder.IsFinished() {
		t.Error("responder should be finished")
	}

	// Split and test transport
	sendI, recvI, err := initiator.Split()
	if err != nil {
		t.Fatalf("initiator.Split() error = %v", err)
	}

	sendR, recvR, err := responder.Split()
	if err != nil {
		t.Fatalf("responder.Split() error = %v", err)
	}

	// Test bidirectional communication
	// Initiator -> Responder
	plaintext := []byte("Hello from initiator!")
	ciphertext := sendI.Encrypt(plaintext, nil)
	decrypted, err := recvR.Decrypt(ciphertext, nil)
	if err != nil {
		t.Fatalf("recvR.Decrypt() error = %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("decrypted = %q, want %q", decrypted, plaintext)
	}

	// Responder -> Initiator
	plaintext2 := []byte("Hello from responder!")
	ciphertext2 := sendR.Encrypt(plaintext2, nil)
	decrypted2, err := recvI.Decrypt(ciphertext2, nil)
	if err != nil {
		t.Fatalf("recvI.Decrypt() error = %v", err)
	}
	if !bytes.Equal(decrypted2, plaintext2) {
		t.Errorf("decrypted2 = %q, want %q", decrypted2, plaintext2)
	}
}

func TestHandshakeXX(t *testing.T) {
	// Generate key pairs
	initiatorStatic, _ := GenerateKeyPair()
	responderStatic, _ := GenerateKeyPair()

	// Create handshake states
	// XX pattern: no prior knowledge of keys
	initiator, err := NewHandshakeState(Config{
		Pattern:     PatternXX,
		Initiator:   true,
		LocalStatic: initiatorStatic,
	})
	if err != nil {
		t.Fatalf("failed to create initiator: %v", err)
	}

	responder, err := NewHandshakeState(Config{
		Pattern:     PatternXX,
		Initiator:   false,
		LocalStatic: responderStatic,
	})
	if err != nil {
		t.Fatalf("failed to create responder: %v", err)
	}

	// Message 1: Initiator -> Responder (-> e)
	msg1, err := initiator.WriteMessage(nil)
	if err != nil {
		t.Fatalf("msg1 write error: %v", err)
	}
	t.Logf("XX Message 1 length: %d bytes", len(msg1))

	_, err = responder.ReadMessage(msg1)
	if err != nil {
		t.Fatalf("msg1 read error: %v", err)
	}

	// Message 2: Responder -> Initiator (<- e, ee, s, es)
	msg2, err := responder.WriteMessage(nil)
	if err != nil {
		t.Fatalf("msg2 write error: %v", err)
	}
	t.Logf("XX Message 2 length: %d bytes", len(msg2))

	_, err = initiator.ReadMessage(msg2)
	if err != nil {
		t.Fatalf("msg2 read error: %v", err)
	}

	// Verify initiator got responder's static key
	if initiator.RemoteStatic() != responderStatic.Public {
		t.Error("initiator did not get responder's static key")
	}

	// Message 3: Initiator -> Responder (-> s, se)
	msg3, err := initiator.WriteMessage(nil)
	if err != nil {
		t.Fatalf("msg3 write error: %v", err)
	}
	t.Logf("XX Message 3 length: %d bytes", len(msg3))

	_, err = responder.ReadMessage(msg3)
	if err != nil {
		t.Fatalf("msg3 read error: %v", err)
	}

	// Verify responder got initiator's static key
	if responder.RemoteStatic() != initiatorStatic.Public {
		t.Error("responder did not get initiator's static key")
	}

	// Both should be finished
	if !initiator.IsFinished() || !responder.IsFinished() {
		t.Error("handshake should be finished")
	}

	// Test transport
	sendI, recvI, _ := initiator.Split()
	sendR, recvR, _ := responder.Split()

	ct := sendI.Encrypt([]byte("XX test"), nil)
	pt, err := recvR.Decrypt(ct, nil)
	if err != nil {
		t.Fatalf("decrypt error: %v", err)
	}
	if string(pt) != "XX test" {
		t.Errorf("got %q, want %q", pt, "XX test")
	}

	ct2 := sendR.Encrypt([]byte("XX reply"), nil)
	pt2, err := recvI.Decrypt(ct2, nil)
	if err != nil {
		t.Fatalf("decrypt error: %v", err)
	}
	if string(pt2) != "XX reply" {
		t.Errorf("got %q, want %q", pt2, "XX reply")
	}
}

func TestHandshakeNN(t *testing.T) {
	// NN pattern: no authentication
	initiator, err := NewHandshakeState(Config{
		Pattern:   PatternNN,
		Initiator: true,
	})
	if err != nil {
		t.Fatalf("failed to create initiator: %v", err)
	}

	responder, err := NewHandshakeState(Config{
		Pattern:   PatternNN,
		Initiator: false,
	})
	if err != nil {
		t.Fatalf("failed to create responder: %v", err)
	}

	// Message 1: -> e
	msg1, _ := initiator.WriteMessage(nil)
	t.Logf("NN Message 1 length: %d bytes", len(msg1))
	responder.ReadMessage(msg1)

	// Message 2: <- e, ee
	msg2, _ := responder.WriteMessage(nil)
	t.Logf("NN Message 2 length: %d bytes", len(msg2))
	initiator.ReadMessage(msg2)

	if !initiator.IsFinished() || !responder.IsFinished() {
		t.Error("handshake should be finished")
	}

	// Test transport
	sendI, recvI, _ := initiator.Split()
	sendR, recvR, _ := responder.Split()

	ct := sendI.Encrypt([]byte("NN test"), nil)
	pt, _ := recvR.Decrypt(ct, nil)
	if string(pt) != "NN test" {
		t.Errorf("got %q, want %q", pt, "NN test")
	}

	ct2 := sendR.Encrypt([]byte("NN reply"), nil)
	pt2, _ := recvI.Decrypt(ct2, nil)
	if string(pt2) != "NN reply" {
		t.Errorf("got %q, want %q", pt2, "NN reply")
	}
}

func TestHandshakeWithPayload(t *testing.T) {
	initiatorStatic, _ := GenerateKeyPair()
	responderStatic, _ := GenerateKeyPair()

	initiator, _ := NewHandshakeState(Config{
		Pattern:      PatternIK,
		Initiator:    true,
		LocalStatic:  initiatorStatic,
		RemoteStatic: &responderStatic.Public,
	})

	responder, _ := NewHandshakeState(Config{
		Pattern:     PatternIK,
		Initiator:   false,
		LocalStatic: responderStatic,
	})

	// Message 1 with payload
	payload1 := []byte("Hello in handshake msg 1")
	msg1, _ := initiator.WriteMessage(payload1)

	recvPayload1, err := responder.ReadMessage(msg1)
	if err != nil {
		t.Fatalf("ReadMessage error: %v", err)
	}
	if !bytes.Equal(recvPayload1, payload1) {
		t.Errorf("payload1 = %q, want %q", recvPayload1, payload1)
	}

	// Message 2 with payload
	payload2 := []byte("Hello in handshake msg 2")
	msg2, _ := responder.WriteMessage(payload2)

	recvPayload2, err := initiator.ReadMessage(msg2)
	if err != nil {
		t.Fatalf("ReadMessage error: %v", err)
	}
	if !bytes.Equal(recvPayload2, payload2) {
		t.Errorf("payload2 = %q, want %q", recvPayload2, payload2)
	}
}

func TestHandshakeWithPrologue(t *testing.T) {
	initiatorStatic, _ := GenerateKeyPair()
	responderStatic, _ := GenerateKeyPair()

	prologue := []byte("version:1.0")

	initiator, _ := NewHandshakeState(Config{
		Pattern:      PatternIK,
		Initiator:    true,
		LocalStatic:  initiatorStatic,
		RemoteStatic: &responderStatic.Public,
		Prologue:     prologue,
	})

	responder, _ := NewHandshakeState(Config{
		Pattern:     PatternIK,
		Initiator:   false,
		LocalStatic: responderStatic,
		Prologue:    prologue,
	})

	// Complete handshake
	msg1, _ := initiator.WriteMessage(nil)
	responder.ReadMessage(msg1)
	msg2, _ := responder.WriteMessage(nil)
	initiator.ReadMessage(msg2)

	// Should succeed with matching prologue
	sendI, recvI, _ := initiator.Split()
	sendR, recvR, _ := responder.Split()

	ct := sendI.Encrypt([]byte("test"), nil)
	pt, err := recvR.Decrypt(ct, nil)
	if err != nil {
		t.Fatalf("decrypt error: %v", err)
	}
	if string(pt) != "test" {
		t.Error("decryption failed")
	}

	// Test reverse direction
	ct2 := sendR.Encrypt([]byte("reply"), nil)
	pt2, _ := recvI.Decrypt(ct2, nil)
	if string(pt2) != "reply" {
		t.Error("reverse decryption failed")
	}
}

func TestHandshakePrologueMismatch(t *testing.T) {
	initiatorStatic, _ := GenerateKeyPair()
	responderStatic, _ := GenerateKeyPair()

	initiator, _ := NewHandshakeState(Config{
		Pattern:      PatternIK,
		Initiator:    true,
		LocalStatic:  initiatorStatic,
		RemoteStatic: &responderStatic.Public,
		Prologue:     []byte("version:1.0"),
	})

	responder, _ := NewHandshakeState(Config{
		Pattern:     PatternIK,
		Initiator:   false,
		LocalStatic: responderStatic,
		Prologue:    []byte("version:2.0"), // Different!
	})

	// Handshake will "succeed" but transport will fail
	msg1, _ := initiator.WriteMessage(nil)
	_, err := responder.ReadMessage(msg1)
	// The first message might succeed because prologue doesn't affect the
	// encrypted parts directly, but the hashes will diverge
	if err != nil {
		// Actually, with IK pattern, the first message contains encrypted
		// static key which will fail to decrypt
		t.Logf("Expected: handshake failed due to prologue mismatch: %v", err)
		return
	}

	// If msg1 succeeded (which shouldn't happen with proper auth),
	// msg2 decryption should fail
	msg2, _ := responder.WriteMessage(nil)
	_, err = initiator.ReadMessage(msg2)
	if err == nil {
		t.Error("handshake should fail with mismatched prologue")
	}
}

func TestHandshakeErrors(t *testing.T) {
	t.Run("missing local static for IK", func(t *testing.T) {
		remoteStatic, _ := GenerateKeyPair()
		_, err := NewHandshakeState(Config{
			Pattern:      PatternIK,
			Initiator:    true,
			RemoteStatic: &remoteStatic.Public,
			// Missing LocalStatic
		})
		if err != ErrMissingLocalStatic {
			t.Errorf("error = %v, want ErrMissingLocalStatic", err)
		}
	})

	t.Run("missing remote static for IK initiator", func(t *testing.T) {
		localStatic, _ := GenerateKeyPair()
		_, err := NewHandshakeState(Config{
			Pattern:     PatternIK,
			Initiator:   true,
			LocalStatic: localStatic,
			// Missing RemoteStatic
		})
		if err != ErrMissingRemoteStatic {
			t.Errorf("error = %v, want ErrMissingRemoteStatic", err)
		}
	})

	t.Run("write after finish", func(t *testing.T) {
		initiatorStatic, _ := GenerateKeyPair()
		responderStatic, _ := GenerateKeyPair()

		initiator, _ := NewHandshakeState(Config{
			Pattern:      PatternIK,
			Initiator:    true,
			LocalStatic:  initiatorStatic,
			RemoteStatic: &responderStatic.Public,
		})

		responder, _ := NewHandshakeState(Config{
			Pattern:     PatternIK,
			Initiator:   false,
			LocalStatic: responderStatic,
		})

		msg1, _ := initiator.WriteMessage(nil)
		responder.ReadMessage(msg1)
		msg2, _ := responder.WriteMessage(nil)
		initiator.ReadMessage(msg2)

		// Try to write after finish
		_, err := initiator.WriteMessage(nil)
		if err != ErrHandshakeFinished {
			t.Errorf("error = %v, want ErrHandshakeFinished", err)
		}
	})

	t.Run("split before finish", func(t *testing.T) {
		initiatorStatic, _ := GenerateKeyPair()
		responderStatic, _ := GenerateKeyPair()

		initiator, _ := NewHandshakeState(Config{
			Pattern:      PatternIK,
			Initiator:    true,
			LocalStatic:  initiatorStatic,
			RemoteStatic: &responderStatic.Public,
		})

		_, _, err := initiator.Split()
		if err != ErrHandshakeNotReady {
			t.Errorf("error = %v, want ErrHandshakeNotReady", err)
		}
	})
}

func TestHandshakeHash(t *testing.T) {
	initiatorStatic, _ := GenerateKeyPair()
	responderStatic, _ := GenerateKeyPair()

	initiator, _ := NewHandshakeState(Config{
		Pattern:      PatternIK,
		Initiator:    true,
		LocalStatic:  initiatorStatic,
		RemoteStatic: &responderStatic.Public,
	})

	responder, _ := NewHandshakeState(Config{
		Pattern:     PatternIK,
		Initiator:   false,
		LocalStatic: responderStatic,
	})

	// Complete handshake
	msg1, _ := initiator.WriteMessage(nil)
	responder.ReadMessage(msg1)
	msg2, _ := responder.WriteMessage(nil)
	initiator.ReadMessage(msg2)

	// Hashes should be equal (channel binding)
	if initiator.Hash() != responder.Hash() {
		t.Error("handshake hashes should be equal")
	}

	// Hash should not be zero
	var zero [HashSize]byte
	if initiator.Hash() == zero {
		t.Error("handshake hash should not be zero")
	}
}
