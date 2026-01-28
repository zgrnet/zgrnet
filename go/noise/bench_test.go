package noise

import (
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

	sendI, _ , _ := initiator.Split()
	_, recvR, _ := responder.Split()

	plaintext := make([]byte, 1024)
	b.SetBytes(1024)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		ct := sendI.Encrypt(plaintext, nil)
		recvR.Decrypt(ct, nil)
	}
}
