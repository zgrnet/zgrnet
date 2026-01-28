package noise

import (
	"bytes"
	"testing"
)

// Additional tests to improve coverage

func TestHMACTo(t *testing.T) {
	var key [HashSize]byte
	copy(key[:], []byte("test key"))

	var dst [HashSize]byte
	HMACTo(&dst, &key, []byte("data"))

	expected := HMAC(&key, []byte("data"))
	if dst != expected {
		t.Error("HMACTo should produce same result as HMAC")
	}
}

func TestKeyFromHexValid(t *testing.T) {
	// Valid 32-byte key
	hexStr := "0000000000000000000000000000000000000000000000000000000000000001"
	k, err := KeyFromHex(hexStr)
	if err != nil {
		t.Fatalf("KeyFromHex() error = %v", err)
	}
	if k[31] != 1 {
		t.Error("key value incorrect")
	}
}

func TestGenerateKeyPairFromError(t *testing.T) {
	// Reader that returns error
	errReader := &errorReader{}
	_, err := GenerateKeyPairFrom(errReader)
	if err == nil {
		t.Error("expected error from bad reader")
	}
}

type errorReader struct{}

func (e *errorReader) Read(p []byte) (n int, err error) {
	return 0, bytes.ErrTooLarge
}

func TestNewCipherStateError(t *testing.T) {
	// Invalid key size
	_, err := NewCipherState(Key{}) // zero key should still work
	if err != nil {
		t.Logf("zero key creates valid cipher: %v", err)
	}
}

func TestSplitError(t *testing.T) {
	ss := NewSymmetricState("Test")
	cs1, cs2, err := ss.Split()
	if err != nil {
		t.Fatalf("Split() error = %v", err)
	}
	if cs1 == nil || cs2 == nil {
		t.Error("cipher states should not be nil")
	}
}

func TestHKDFPanic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("HKDF should panic with invalid numOutputs")
		}
	}()

	var ck Key
	HKDF(&ck, nil, 0) // Should panic
}

func TestHKDFPanic4(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("HKDF should panic with numOutputs > 3")
		}
	}()

	var ck Key
	HKDF(&ck, nil, 4) // Should panic
}

func TestEncryptDecryptErrors(t *testing.T) {
	// Wrong key size for Encrypt
	_, err := Encrypt(make([]byte, 16), 0, []byte("test"), nil)
	if err == nil {
		t.Error("Encrypt should fail with wrong key size")
	}

	// Wrong key size for Decrypt
	_, err = Decrypt(make([]byte, 16), 0, []byte("test"), nil)
	if err == nil {
		t.Error("Decrypt should fail with wrong key size")
	}
}

func TestNewAEADError(t *testing.T) {
	// Wrong key size
	_, err := NewAEAD(make([]byte, 16))
	if err == nil {
		t.Error("NewAEAD should fail with wrong key size")
	}
}

func TestHandshakeWrongTurn(t *testing.T) {
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

	// Responder tries to write first (wrong turn)
	_, err := responder.WriteMessage(nil)
	if err == nil {
		t.Error("responder should not be able to write first")
	}

	// Initiator tries to read first (wrong turn)
	_, err = initiator.ReadMessage([]byte("fake"))
	if err == nil {
		t.Error("initiator should not be able to read first")
	}
}

func TestHandshakeInvalidMessage(t *testing.T) {
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

	// Send valid first message
	msg1, _ := initiator.WriteMessage(nil)
	responder.ReadMessage(msg1)

	// Create valid second message
	msg2, _ := responder.WriteMessage(nil)

	// Corrupt the message
	msg2[0] ^= 0xff

	// Try to read corrupted message
	_, err := initiator.ReadMessage(msg2)
	if err == nil {
		t.Error("should fail with corrupted message")
	}
}

func TestHandshakeTruncatedMessage(t *testing.T) {
	initiatorStatic, _ := GenerateKeyPair()
	responderStatic, _ := GenerateKeyPair()

	responder, _ := NewHandshakeState(Config{
		Pattern:     PatternIK,
		Initiator:   false,
		LocalStatic: responderStatic,
	})

	_ = initiatorStatic // unused

	// Send truncated message (too short for ephemeral key)
	_, err := responder.ReadMessage(make([]byte, 10))
	if err != ErrInvalidMessage {
		t.Errorf("error = %v, want ErrInvalidMessage", err)
	}
}

func TestHandshakeLocalEphemeral(t *testing.T) {
	initiatorStatic, _ := GenerateKeyPair()
	responderStatic, _ := GenerateKeyPair()

	initiator, _ := NewHandshakeState(Config{
		Pattern:      PatternIK,
		Initiator:    true,
		LocalStatic:  initiatorStatic,
		RemoteStatic: &responderStatic.Public,
	})

	// Before write, ephemeral should be zero
	eph := initiator.LocalEphemeral()
	if !eph.IsZero() {
		t.Error("ephemeral should be zero before write")
	}

	// After write, ephemeral should be set
	initiator.WriteMessage(nil)
	eph = initiator.LocalEphemeral()
	if eph.IsZero() {
		t.Error("ephemeral should be set after write")
	}
}

func TestDecryptWithADError(t *testing.T) {
	var key Key
	copy(key[:], []byte("test key 32 bytes long here!!!!"))

	// Encrypt with one AD
	ct := EncryptWithAD(&key, []byte("ad1"), []byte("test"))

	// Decrypt with different AD
	_, err := DecryptWithAD(&key, []byte("ad2"), ct)
	if err == nil {
		t.Error("DecryptWithAD should fail with wrong AD")
	}
}

func TestMultipleMessages(t *testing.T) {
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

	sendI, recvI, _ := initiator.Split()
	sendR, recvR, _ := responder.Split()

	// Send multiple messages
	for i := 0; i < 100; i++ {
		// I -> R
		ct := sendI.Encrypt([]byte("test"), nil)
		pt, err := recvR.Decrypt(ct, nil)
		if err != nil {
			t.Fatalf("message %d I->R decrypt error: %v", i, err)
		}
		if string(pt) != "test" {
			t.Fatalf("message %d I->R content mismatch", i)
		}

		// R -> I
		ct2 := sendR.Encrypt([]byte("reply"), nil)
		pt2, err := recvI.Decrypt(ct2, nil)
		if err != nil {
			t.Fatalf("message %d R->I decrypt error: %v", i, err)
		}
		if string(pt2) != "reply" {
			t.Fatalf("message %d R->I content mismatch", i)
		}
	}
}
