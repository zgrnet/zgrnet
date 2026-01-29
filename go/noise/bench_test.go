package noise

import (
	"sync"
	"sync/atomic"
	"testing"
)

// Benchmark key generation
func BenchmarkKeyGeneration(b *testing.B) {
	for i := 0; i < b.N; i++ {
		GenerateKeyPair()
	}
}

// Benchmark DH exchange
func BenchmarkDH(b *testing.B) {
	alice, _ := GenerateKeyPair()
	bob, _ := GenerateKeyPair()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		alice.DH(bob.Public)
	}
}

// Benchmark BLAKE2s hash
func BenchmarkHash(b *testing.B) {
	data := make([]byte, 64)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Hash(data)
	}
}

// Benchmark HKDF
func BenchmarkHKDF(b *testing.B) {
	var ck Key
	input := make([]byte, 32)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		HKDF(&ck, input, 2)
	}
}

// Benchmark ChaCha20-Poly1305 encrypt (1KB)
func BenchmarkEncrypt1KB(b *testing.B) {
	key := make([]byte, 32)
	plaintext := make([]byte, 1024)
	b.SetBytes(1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Encrypt(key, uint64(i), plaintext, nil)
	}
}

// Benchmark ChaCha20-Poly1305 decrypt (1KB)
func BenchmarkDecrypt1KB(b *testing.B) {
	key := make([]byte, 32)
	plaintext := make([]byte, 1024)
	ciphertext, _ := Encrypt(key, 0, plaintext, nil)
	b.SetBytes(1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Decrypt(key, 0, ciphertext, nil)
	}
}

// Benchmark full IK handshake
func BenchmarkHandshakeIK(b *testing.B) {
	initiatorStatic, _ := GenerateKeyPair()
	responderStatic, _ := GenerateKeyPair()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
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

		initiator.Split()
		responder.Split()
	}
}

// Benchmark transport message (after handshake)
func BenchmarkTransport1KB(b *testing.B) {
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

	sendI, _, _ := initiator.Split()
	_, recvR, _ := responder.Split()

	plaintext := make([]byte, 1024)
	b.SetBytes(1024)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		ct := sendI.Encrypt(plaintext, nil)
		recvR.Decrypt(ct, nil)
	}
}

// =============================================================================
// Concurrent Session Benchmarks
// =============================================================================

// BenchmarkConcurrentSessionCreate benchmarks concurrent session creation
func BenchmarkConcurrentSessionCreate(b *testing.B) {
	manager := NewSessionManager()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			kp, _ := GenerateKeyPair()
			sendKey := Hash([]byte("send"))
			recvKey := Hash([]byte("recv"))
			session, _ := manager.CreateSession(kp.Public, sendKey, recvKey)
			if session != nil {
				manager.RemoveSession(session.LocalIndex())
			}
		}
	})
}

// BenchmarkConcurrentHandshake benchmarks concurrent IK handshakes
func BenchmarkConcurrentHandshake(b *testing.B) {
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
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

			initiator.Split()
			responder.Split()
		}
	})
}

// BenchmarkConcurrentSessionEncrypt benchmarks concurrent encryption on same session
func BenchmarkConcurrentSessionEncrypt(b *testing.B) {
	// Create a session pair
	sendKey := Hash([]byte("send"))
	recvKey := Hash([]byte("recv"))

	session, _ := NewSession(SessionConfig{
		LocalIndex:  1,
		RemoteIndex: 2,
		SendKey:     sendKey,
		RecvKey:     recvKey,
	})

	plaintext := make([]byte, 1024)
	b.SetBytes(1024)
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			session.Encrypt(plaintext)
		}
	})
}

// BenchmarkConcurrentSessionEncryptDecrypt benchmarks concurrent encrypt/decrypt
func BenchmarkConcurrentSessionEncryptDecrypt(b *testing.B) {
	sendKey := Hash([]byte("send"))
	recvKey := Hash([]byte("recv"))

	alice, _ := NewSession(SessionConfig{
		LocalIndex:  1,
		RemoteIndex: 2,
		SendKey:     sendKey,
		RecvKey:     recvKey,
	})

	bob, _ := NewSession(SessionConfig{
		LocalIndex:  2,
		RemoteIndex: 1,
		SendKey:     recvKey,
		RecvKey:     sendKey,
	})

	plaintext := make([]byte, 1024)
	b.SetBytes(1024)
	b.ResetTimer()

	var wg sync.WaitGroup
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			// Alice encrypts
			ct, nonce, err := alice.Encrypt(plaintext)
			if err != nil {
				continue
			}
			// Bob decrypts
			wg.Add(1)
			go func(ct []byte, n uint64) {
				defer wg.Done()
				bob.Decrypt(ct, n)
			}(ct, nonce)
		}
	})
	wg.Wait()
}

// BenchmarkConcurrentMultiSession benchmarks multiple concurrent sessions
func BenchmarkConcurrentMultiSession(b *testing.B) {
	const numSessions = 100
	sessions := make([]*Session, numSessions)

	for i := 0; i < numSessions; i++ {
		sendKey := Hash([]byte("send" + string(rune(i))))
		recvKey := Hash([]byte("recv" + string(rune(i))))
		sessions[i], _ = NewSession(SessionConfig{
			LocalIndex:  uint32(i + 1),
			RemoteIndex: uint32(i + 1001),
			SendKey:     sendKey,
			RecvKey:     recvKey,
		})
	}

	plaintext := make([]byte, 256)
	var counter atomic.Int64
	b.SetBytes(256)
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			idx := int(counter.Add(1)) % numSessions
			sessions[idx].Encrypt(plaintext)
		}
	})
}

// BenchmarkSessionManagerConcurrent benchmarks concurrent manager operations
func BenchmarkSessionManagerConcurrent(b *testing.B) {
	manager := NewSessionManager()

	// Pre-create some sessions
	for i := 0; i < 100; i++ {
		kp, _ := GenerateKeyPair()
		sendKey := Hash([]byte("send"))
		recvKey := Hash([]byte("recv"))
		manager.CreateSession(kp.Public, sendKey, recvKey)
	}

	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			// Mix of operations
			kp, _ := GenerateKeyPair()
			sendKey := Hash([]byte("send"))
			recvKey := Hash([]byte("recv"))

			// Create
			session, _ := manager.CreateSession(kp.Public, sendKey, recvKey)
			if session == nil {
				continue
			}

			// Lookup by index
			manager.GetByIndex(session.LocalIndex())

			// Lookup by pubkey
			manager.GetByPubkey(kp.Public)

			// Remove
			manager.RemoveSession(session.LocalIndex())
		}
	})
}
