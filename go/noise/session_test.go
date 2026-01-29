package noise

import (
	"bytes"
	"sync"
	"testing"
	"time"
)

func createTestSession(t *testing.T) (*Session, *Session) {
	t.Helper()

	// Generate keys
	sendKey := Hash([]byte("send key"))
	recvKey := Hash([]byte("recv key"))

	// Create two sessions (Alice and Bob) with swapped keys
	alice, err := NewSession(SessionConfig{
		LocalIndex:  1,
		RemoteIndex: 2,
		SendKey:     sendKey,
		RecvKey:     recvKey,
		RemotePK:    PublicKey{},
	})
	if err != nil {
		t.Fatalf("failed to create alice session: %v", err)
	}

	bob, err := NewSession(SessionConfig{
		LocalIndex:  2,
		RemoteIndex: 1,
		SendKey:     recvKey, // Swapped
		RecvKey:     sendKey, // Swapped
		RemotePK:    PublicKey{},
	})
	if err != nil {
		t.Fatalf("failed to create bob session: %v", err)
	}

	return alice, bob
}

func TestSession_EncryptDecrypt(t *testing.T) {
	alice, bob := createTestSession(t)

	plaintext := []byte("Hello, World!")

	// Alice encrypts
	ciphertext, nonce, err := alice.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	// Bob decrypts
	decrypted, err := bob.Decrypt(ciphertext, nonce)
	if err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("decrypted != plaintext: got %q, want %q", decrypted, plaintext)
	}
}

func TestSession_BidirectionalCommunication(t *testing.T) {
	alice, bob := createTestSession(t)

	messages := []string{
		"Hello from Alice",
		"Hello from Bob",
		"Another message from Alice",
		"Response from Bob",
	}

	// Alice -> Bob
	ct1, n1, _ := alice.Encrypt([]byte(messages[0]))
	pt1, _ := bob.Decrypt(ct1, n1)
	if string(pt1) != messages[0] {
		t.Errorf("message 0 mismatch")
	}

	// Bob -> Alice
	ct2, n2, _ := bob.Encrypt([]byte(messages[1]))
	pt2, _ := alice.Decrypt(ct2, n2)
	if string(pt2) != messages[1] {
		t.Errorf("message 1 mismatch")
	}

	// Alice -> Bob
	ct3, n3, _ := alice.Encrypt([]byte(messages[2]))
	pt3, _ := bob.Decrypt(ct3, n3)
	if string(pt3) != messages[2] {
		t.Errorf("message 2 mismatch")
	}

	// Bob -> Alice
	ct4, n4, _ := bob.Encrypt([]byte(messages[3]))
	pt4, _ := alice.Decrypt(ct4, n4)
	if string(pt4) != messages[3] {
		t.Errorf("message 3 mismatch")
	}
}

func TestSession_NonceIncrement(t *testing.T) {
	alice, _ := createTestSession(t)

	for i := uint64(0); i < 10; i++ {
		if alice.SendNonce() != i {
			t.Errorf("send nonce should be %d, got %d", i, alice.SendNonce())
		}
		_, _, _ = alice.Encrypt([]byte("test"))
	}

	if alice.SendNonce() != 10 {
		t.Errorf("send nonce should be 10, got %d", alice.SendNonce())
	}
}

func TestSession_ReplayProtection(t *testing.T) {
	alice, bob := createTestSession(t)

	plaintext := []byte("test message")
	ciphertext, nonce, _ := alice.Encrypt(plaintext)

	// First decryption should succeed
	_, err := bob.Decrypt(ciphertext, nonce)
	if err != nil {
		t.Fatalf("first decrypt failed: %v", err)
	}

	// Replay should fail
	_, err = bob.Decrypt(ciphertext, nonce)
	if err != ErrReplayDetected {
		t.Errorf("replay should be detected, got: %v", err)
	}
}

func TestSession_OutOfOrderDecrypt(t *testing.T) {
	alice, bob := createTestSession(t)

	// Encrypt multiple messages
	var messages []struct {
		ct    []byte
		nonce uint64
	}
	for i := 0; i < 10; i++ {
		ct, n, _ := alice.Encrypt([]byte{byte(i)})
		messages = append(messages, struct {
			ct    []byte
			nonce uint64
		}{ct, n})
	}

	// Decrypt in reverse order
	for i := 9; i >= 0; i-- {
		pt, err := bob.Decrypt(messages[i].ct, messages[i].nonce)
		if err != nil {
			t.Errorf("decrypt message %d failed: %v", i, err)
			continue
		}
		if pt[0] != byte(i) {
			t.Errorf("message %d content mismatch", i)
		}
	}
}

func TestSession_WrongKey(t *testing.T) {
	alice, _ := createTestSession(t)

	// Create a third session with different keys
	wrongKey := Hash([]byte("wrong key"))
	eve, _ := NewSession(SessionConfig{
		LocalIndex:  3,
		RemoteIndex: 1,
		SendKey:     wrongKey,
		RecvKey:     wrongKey,
		RemotePK:    PublicKey{},
	})

	// Alice encrypts
	ciphertext, nonce, _ := alice.Encrypt([]byte("secret"))

	// Eve tries to decrypt with wrong key
	_, err := eve.Decrypt(ciphertext, nonce)
	if err != ErrDecryptionFailed {
		t.Errorf("decryption with wrong key should fail, got: %v", err)
	}
}

func TestSession_State(t *testing.T) {
	alice, _ := createTestSession(t)

	if alice.State() != SessionStateEstablished {
		t.Error("initial state should be established")
	}

	alice.SetState(SessionStateExpired)
	if alice.State() != SessionStateExpired {
		t.Error("state should be expired")
	}

	// Encrypt should fail when expired
	_, _, err := alice.Encrypt([]byte("test"))
	if err != ErrSessionNotEstablished {
		t.Errorf("encrypt should fail when expired, got: %v", err)
	}
}

func TestSession_Expiry(t *testing.T) {
	alice, _ := createTestSession(t)

	if alice.IsExpired() {
		t.Error("new session should not be expired")
	}

	alice.Expire()
	if !alice.IsExpired() {
		t.Error("expired session should be expired")
	}
}

func TestSession_Indices(t *testing.T) {
	alice, bob := createTestSession(t)

	if alice.LocalIndex() != 1 {
		t.Error("alice local index should be 1")
	}
	if alice.RemoteIndex() != 2 {
		t.Error("alice remote index should be 2")
	}
	if bob.LocalIndex() != 2 {
		t.Error("bob local index should be 2")
	}
	if bob.RemoteIndex() != 1 {
		t.Error("bob remote index should be 1")
	}
}

func TestSession_Timestamps(t *testing.T) {
	alice, bob := createTestSession(t)

	beforeSend := time.Now()
	ct, n, _ := alice.Encrypt([]byte("test"))
	afterSend := time.Now()

	if alice.LastSent().Before(beforeSend) || alice.LastSent().After(afterSend) {
		t.Error("last sent time incorrect")
	}

	beforeRecv := time.Now()
	_, _ = bob.Decrypt(ct, n)
	afterRecv := time.Now()

	if bob.LastReceived().Before(beforeRecv) || bob.LastReceived().After(afterRecv) {
		t.Error("last received time incorrect")
	}
}

func TestSession_Concurrent(t *testing.T) {
	alice, bob := createTestSession(t)

	var wg sync.WaitGroup
	numGoroutines := 10
	messagesPerGoroutine := 100

	// Concurrent sends from Alice
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < messagesPerGoroutine; j++ {
				_, _, err := alice.Encrypt([]byte{byte(id), byte(j)})
				if err != nil {
					t.Errorf("encrypt failed: %v", err)
				}
			}
		}(i)
	}

	wg.Wait()

	expectedNonce := uint64(numGoroutines * messagesPerGoroutine)
	if alice.SendNonce() != expectedNonce {
		t.Errorf("send nonce should be %d, got %d", expectedNonce, alice.SendNonce())
	}

	// Concurrent receives at Bob
	// First, generate all messages
	messages := make([]struct {
		ct    []byte
		nonce uint64
	}, 1000)
	for i := 0; i < 1000; i++ {
		ct, n, _ := alice.Encrypt([]byte{byte(i)})
		messages[i] = struct {
			ct    []byte
			nonce uint64
		}{ct, n}
	}

	// Decrypt concurrently
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(start int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				idx := start*100 + j
				_, _ = bob.Decrypt(messages[idx].ct, messages[idx].nonce)
			}
		}(i)
	}

	wg.Wait()
}

func TestGenerateIndex(t *testing.T) {
	indices := make(map[uint32]bool)
	for i := 0; i < 1000; i++ {
		idx, err := GenerateIndex()
		if err != nil {
			t.Fatalf("generate index failed: %v", err)
		}
		if indices[idx] {
			// This is possible but very unlikely
			t.Logf("duplicate index generated (possible but rare): %d", idx)
		}
		indices[idx] = true
	}
}

func TestSessionState_String(t *testing.T) {
	tests := []struct {
		state SessionState
		want  string
	}{
		{SessionStateHandshaking, "handshaking"},
		{SessionStateEstablished, "established"},
		{SessionStateExpired, "expired"},
		{SessionState(99), "unknown"},
	}

	for _, tt := range tests {
		if got := tt.state.String(); got != tt.want {
			t.Errorf("SessionState(%d).String() = %q, want %q", tt.state, got, tt.want)
		}
	}
}

func BenchmarkSession_Encrypt(b *testing.B) {
	alice, _ := createTestSession(&testing.T{})
	plaintext := make([]byte, 1024)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = alice.Encrypt(plaintext)
	}
}

func BenchmarkSession_Decrypt(b *testing.B) {
	alice, bob := createTestSession(&testing.T{})
	plaintext := make([]byte, 1024)

	// Pre-generate messages
	messages := make([]struct {
		ct    []byte
		nonce uint64
	}, b.N)
	for i := 0; i < b.N; i++ {
		ct, n, _ := alice.Encrypt(plaintext)
		messages[i].ct = ct
		messages[i].nonce = n
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = bob.Decrypt(messages[i].ct, messages[i].nonce)
	}
}
