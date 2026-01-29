// Package noise implements the Noise Protocol Framework.
//
// This package provides a pure Noise Protocol implementation supporting
// various handshake patterns (IK, XX, NN) with configurable cipher suites.
//
// Reference: https://noiseprotocol.org/noise.html
package noise

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/curve25519"
)

// KeySize is the size of public/private keys in bytes.
const KeySize = 32

// Key represents a 32-byte cryptographic key.
type Key [KeySize]byte

// PublicKey is an alias for Key used to represent a peer's public key.
// Using a distinct type improves code readability and type safety.
type PublicKey = Key

// IsZero returns true if the key is all zeros.
func (k Key) IsZero() bool {
	var zero Key
	return k == zero
}

// String returns the hex-encoded key.
func (k Key) String() string {
	return hex.EncodeToString(k[:])
}

// ShortString returns the first 8 characters of the hex-encoded key.
func (k Key) ShortString() string {
	return hex.EncodeToString(k[:4])
}

// Equal returns true if the two keys are equal.
// Uses constant-time comparison to prevent timing attacks.
func (k Key) Equal(other Key) bool {
	var result byte
	for i := 0; i < KeySize; i++ {
		result |= k[i] ^ other[i]
	}
	return result == 0
}

// KeyFromHex creates a Key from a hex-encoded string.
func KeyFromHex(s string) (Key, error) {
	var k Key
	b, err := hex.DecodeString(s)
	if err != nil {
		return k, fmt.Errorf("noise: invalid hex string: %w", err)
	}
	if len(b) != KeySize {
		return k, fmt.Errorf("noise: invalid key length: got %d, want %d", len(b), KeySize)
	}
	copy(k[:], b)
	return k, nil
}

// KeyPair holds a Curve25519 private/public key pair.
type KeyPair struct {
	Private Key
	Public  Key
}

// GenerateKeyPair generates a new random Curve25519 key pair.
func GenerateKeyPair() (*KeyPair, error) {
	return GenerateKeyPairFrom(rand.Reader)
}

// GenerateKeyPairFrom generates a new Curve25519 key pair using the provided
// random source.
func GenerateKeyPairFrom(random io.Reader) (*KeyPair, error) {
	var priv Key
	if _, err := io.ReadFull(random, priv[:]); err != nil {
		return nil, fmt.Errorf("noise: failed to generate random key: %w", err)
	}
	return NewKeyPair(priv)
}

// NewKeyPair creates a KeyPair from a private key, deriving the public key.
// The private key is clamped according to Curve25519 requirements.
func NewKeyPair(privateKey Key) (*KeyPair, error) {
	// Clamp the private key for Curve25519
	// Reference: https://cr.yp.to/ecdh.html
	priv := privateKey
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64

	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("noise: failed to derive public key: %w", err)
	}

	kp := &KeyPair{Private: priv}
	copy(kp.Public[:], pub)
	return kp, nil
}

// ErrInvalidPublicKey is returned when a public key is invalid for DH.
var ErrInvalidPublicKey = errors.New("noise: invalid public key")

// DH performs a Curve25519 Diffie-Hellman exchange.
func (kp *KeyPair) DH(peerPublic Key) (Key, error) {
	shared, err := curve25519.X25519(kp.Private[:], peerPublic[:])
	if err != nil {
		return Key{}, fmt.Errorf("noise: DH failed: %w", err)
	}

	// Check for low-order points (all zeros result)
	var result Key
	copy(result[:], shared)
	if result.IsZero() {
		return Key{}, ErrInvalidPublicKey
	}
	return result, nil
}
