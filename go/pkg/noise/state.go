package noise

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// CipherState manages encryption for one direction of communication.
// It tracks the key and nonce (counter) for ChaCha20-Poly1305.
//
// WARNING: Uses auto-incrementing nonces. Only suitable for ordered,
// reliable transport (like TCP or within Noise handshake).
// For unreliable transport (UDP), use Session with explicit nonces.
type CipherState struct {
	key   Key
	nonce uint64
	aead  cipher.AEAD
}

// NewCipherState creates a new CipherState with the given key.
func NewCipherState(key Key) (*CipherState, error) {
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, fmt.Errorf("noise: failed to create AEAD: %w", err)
	}
	return &CipherState{
		key:  key,
		aead: aead,
	}, nil
}

// Encrypt encrypts plaintext and increments the nonce.
func (cs *CipherState) Encrypt(plaintext, ad []byte) []byte {
	var nonce [12]byte
	binary.LittleEndian.PutUint64(nonce[:], cs.nonce)
	cs.nonce++
	return cs.aead.Seal(nil, nonce[:], plaintext, ad)
}

// Decrypt decrypts ciphertext and increments the nonce.
func (cs *CipherState) Decrypt(ciphertext, ad []byte) ([]byte, error) {
	var nonce [12]byte
	binary.LittleEndian.PutUint64(nonce[:], cs.nonce)
	cs.nonce++
	return cs.aead.Open(nil, nonce[:], ciphertext, ad)
}

// Nonce returns the current nonce value.
func (cs *CipherState) Nonce() uint64 {
	return cs.nonce
}

// SetNonce sets the nonce value (used for replay protection testing).
func (cs *CipherState) SetNonce(n uint64) {
	cs.nonce = n
}

// Key returns a copy of the key.
func (cs *CipherState) Key() Key {
	return cs.key
}

// SymmetricState holds the evolving state during a Noise handshake.
// It tracks the chaining key (ck) and handshake hash (h).
type SymmetricState struct {
	chainingKey Key
	hash        [HashSize]byte
}

// NewSymmetricState initializes a SymmetricState with a protocol name.
// The protocol name is hashed to create the initial chaining key and hash.
//
// Example: "Noise_IK_25519_ChaChaPoly_BLAKE2s"
func NewSymmetricState(protocolName string) *SymmetricState {
	ss := &SymmetricState{}

	// If protocol name is <= 32 bytes, use it directly (padded with zeros)
	// Otherwise, hash it
	if len(protocolName) <= HashSize {
		copy(ss.chainingKey[:], protocolName)
	} else {
		ss.chainingKey = Hash([]byte(protocolName))
	}

	// h = ck initially
	ss.hash = ss.chainingKey

	return ss
}

// MixKey mixes input into the chaining key using HKDF.
// ck, k = HKDF(ck, input)
func (ss *SymmetricState) MixKey(input []byte) Key {
	newCK, k := KDF2(&ss.chainingKey, input)
	ss.chainingKey = newCK
	return k
}

// MixHash mixes data into the handshake hash.
// h = HASH(h || data)
func (ss *SymmetricState) MixHash(data []byte) {
	HashTo(&ss.hash, ss.hash[:], data)
}

// MixKeyAndHash mixes input into both chaining key and hash.
// Used for PSK mixing.
// ck, temp, k = HKDF(ck, input)
// h = HASH(h || temp)
func (ss *SymmetricState) MixKeyAndHash(input []byte) Key {
	ck, temp, k := KDF3(&ss.chainingKey, input)
	ss.chainingKey = ck
	ss.MixHash(temp[:])
	return k
}

// EncryptAndHash encrypts plaintext using a derived key.
// The hash is used as additional data, then updated with the ciphertext.
// Returns the ciphertext.
func (ss *SymmetricState) EncryptAndHash(key *Key, plaintext []byte) []byte {
	ciphertext := EncryptWithAD(key, ss.hash[:], plaintext)
	ss.MixHash(ciphertext)
	return ciphertext
}

// DecryptAndHash decrypts ciphertext using a derived key.
// The hash is used as additional data, then updated with the ciphertext.
// Returns the plaintext.
func (ss *SymmetricState) DecryptAndHash(key *Key, ciphertext []byte) ([]byte, error) {
	plaintext, err := DecryptWithAD(key, ss.hash[:], ciphertext)
	if err != nil {
		return nil, err
	}
	ss.MixHash(ciphertext)
	return plaintext, nil
}

// Split derives the final transport keys from the chaining key.
// Returns two CipherStates: one for sending, one for receiving.
// The caller determines which is which based on the handshake role.
func (ss *SymmetricState) Split() (*CipherState, *CipherState, error) {
	keys := HKDF(&ss.chainingKey, nil, 2)

	cs1, err := NewCipherState(keys[0])
	if err != nil {
		return nil, nil, err
	}

	cs2, err := NewCipherState(keys[1])
	if err != nil {
		return nil, nil, err
	}

	return cs1, cs2, nil
}

// ChainingKey returns the current chaining key.
func (ss *SymmetricState) ChainingKey() Key {
	return ss.chainingKey
}

// Hash returns the current handshake hash.
func (ss *SymmetricState) Hash() [HashSize]byte {
	return ss.hash
}

// Clone creates a deep copy of the SymmetricState.
// Useful for testing or parallel handshake attempts.
func (ss *SymmetricState) Clone() *SymmetricState {
	return &SymmetricState{
		chainingKey: ss.chainingKey,
		hash:        ss.hash,
	}
}

// ErrDecryptionFailed is returned when AEAD decryption fails.
var ErrDecryptionFailed = errors.New("noise: decryption failed")
