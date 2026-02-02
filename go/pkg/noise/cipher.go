package noise

import (
	"crypto/cipher"
	"crypto/hmac"
	"encoding/binary"
	"fmt"
	"hash"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
)

// Hash sizes
const (
	HashSize = 32 // BLAKE2s-256 output size
	TagSize  = 16 // Poly1305 tag size
)

// Hash computes BLAKE2s-256 hash of the input data.
func Hash(data ...[]byte) [HashSize]byte {
	h, _ := blake2s.New256(nil)
	for _, d := range data {
		h.Write(d)
	}
	var out [HashSize]byte
	h.Sum(out[:0])
	return out
}

// HashTo computes BLAKE2s-256 hash and writes to dst.
func HashTo(dst *[HashSize]byte, data ...[]byte) {
	h, _ := blake2s.New256(nil)
	for _, d := range data {
		h.Write(d)
	}
	h.Sum(dst[:0])
}

// MAC computes BLAKE2s-128 MAC with the given key.
// Used for mac1/mac2 in message authentication.
func MAC(key []byte, data ...[]byte) [16]byte {
	h, _ := blake2s.New128(key)
	for _, d := range data {
		h.Write(d)
	}
	var out [16]byte
	h.Sum(out[:0])
	return out
}

// HMAC computes HMAC-BLAKE2s-256.
func HMAC(key *[HashSize]byte, data ...[]byte) [HashSize]byte {
	mac := hmac.New(func() hash.Hash {
		h, _ := blake2s.New256(nil)
		return h
	}, key[:])
	for _, d := range data {
		mac.Write(d)
	}
	var out [HashSize]byte
	mac.Sum(out[:0])
	return out
}

// HMACTo computes HMAC-BLAKE2s-256 and writes to dst.
func HMACTo(dst, key *[HashSize]byte, data ...[]byte) {
	mac := hmac.New(func() hash.Hash {
		h, _ := blake2s.New256(nil)
		return h
	}, key[:])
	for _, d := range data {
		mac.Write(d)
	}
	mac.Sum(dst[:0])
}

// HKDF derives keys using HKDF with BLAKE2s.
// This is Hugo Krawczyk's HKDF as used in Noise Protocol.
//
//	secret = HMAC(chainingKey, input)
//	output1 = HMAC(secret, 0x01)
//	output2 = HMAC(secret, output1 || 0x02)
//	output3 = HMAC(secret, output2 || 0x03)
func HKDF(chainingKey *Key, input []byte, numOutputs int) []Key {
	if numOutputs < 1 || numOutputs > 3 {
		panic("noise: HKDF numOutputs must be 1, 2, or 3")
	}

	// Extract: secret = HMAC(chainingKey, input)
	secret := HMAC((*[HashSize]byte)(chainingKey), input)

	outputs := make([]Key, numOutputs)

	// Expand: output1 = HMAC(secret, 0x01)
	outputs[0] = HMAC(&secret, []byte{0x01})

	if numOutputs >= 2 {
		// output2 = HMAC(secret, output1 || 0x02)
		outputs[1] = HMAC(&secret, outputs[0][:], []byte{0x02})
	}

	if numOutputs >= 3 {
		// output3 = HMAC(secret, output2 || 0x03)
		outputs[2] = HMAC(&secret, outputs[1][:], []byte{0x03})
	}

	return outputs
}

// KDF1 derives one key from chaining key and input.
// Returns the new chaining key.
func KDF1(chainingKey *Key, input []byte) Key {
	return HKDF(chainingKey, input, 1)[0]
}

// KDF2 derives two keys from chaining key and input.
// Returns (new chaining key, derived key).
func KDF2(chainingKey *Key, input []byte) (Key, Key) {
	keys := HKDF(chainingKey, input, 2)
	return keys[0], keys[1]
}

// KDF3 derives three keys from chaining key and input.
// Returns (new chaining key, temp key, derived key).
func KDF3(chainingKey *Key, input []byte) (Key, Key, Key) {
	keys := HKDF(chainingKey, input, 3)
	return keys[0], keys[1], keys[2]
}

// NewAEAD creates a ChaCha20-Poly1305 AEAD cipher.
func NewAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("noise: invalid AEAD key size: got %d, want %d", len(key), chacha20poly1305.KeySize)
	}
	return chacha20poly1305.New(key)
}

// Encrypt encrypts plaintext using ChaCha20-Poly1305.
// The nonce is a 64-bit counter encoded as little-endian, padded to 12 bytes.
func Encrypt(key []byte, nonce uint64, plaintext, additionalData []byte) ([]byte, error) {
	aead, err := NewAEAD(key)
	if err != nil {
		return nil, err
	}

	var nonceBytes [12]byte
	binary.LittleEndian.PutUint64(nonceBytes[:], nonce)

	return aead.Seal(nil, nonceBytes[:], plaintext, additionalData), nil
}

// Decrypt decrypts ciphertext using ChaCha20-Poly1305.
func Decrypt(key []byte, nonce uint64, ciphertext, additionalData []byte) ([]byte, error) {
	aead, err := NewAEAD(key)
	if err != nil {
		return nil, err
	}

	var nonceBytes [12]byte
	binary.LittleEndian.PutUint64(nonceBytes[:], nonce)

	return aead.Open(nil, nonceBytes[:], ciphertext, additionalData)
}

// EncryptWithAD encrypts plaintext with additional data using zero nonce.
// This is used during handshake where nonce is always 0.
func EncryptWithAD(key *Key, ad, plaintext []byte) []byte {
	aead, _ := chacha20poly1305.New(key[:])
	var nonce [12]byte // zero nonce for handshake
	return aead.Seal(nil, nonce[:], plaintext, ad)
}

// DecryptWithAD decrypts ciphertext with additional data using zero nonce.
func DecryptWithAD(key *Key, ad, ciphertext []byte) ([]byte, error) {
	aead, _ := chacha20poly1305.New(key[:])
	var nonce [12]byte // zero nonce for handshake
	return aead.Open(nil, nonce[:], ciphertext, ad)
}
