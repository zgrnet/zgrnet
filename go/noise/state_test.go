package noise

import (
	"bytes"
	"testing"
)

func TestCipherState(t *testing.T) {
	var key Key
	copy(key[:], []byte("test key 32 bytes long here!!!!"))

	cs, err := NewCipherState(key)
	if err != nil {
		t.Fatalf("NewCipherState() error = %v", err)
	}

	if cs.Nonce() != 0 {
		t.Errorf("initial nonce = %d, want 0", cs.Nonce())
	}

	if cs.Key() != key {
		t.Error("Key() should return the key")
	}
}

func TestCipherStateEncryptDecrypt(t *testing.T) {
	var key Key
	copy(key[:], []byte("test key 32 bytes long here!!!!"))

	cs1, _ := NewCipherState(key)
	cs2, _ := NewCipherState(key)

	plaintext := []byte("hello, world!")
	ad := []byte("additional data")

	// Encrypt
	ciphertext := cs1.Encrypt(plaintext, ad)
	if cs1.Nonce() != 1 {
		t.Errorf("nonce after encrypt = %d, want 1", cs1.Nonce())
	}

	// Decrypt with same nonce state
	decrypted, err := cs2.Decrypt(ciphertext, ad)
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}
	if cs2.Nonce() != 1 {
		t.Errorf("nonce after decrypt = %d, want 1", cs2.Nonce())
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("decrypted = %q, want %q", decrypted, plaintext)
	}
}

func TestCipherStateNonceIncrement(t *testing.T) {
	var key Key
	copy(key[:], []byte("test key 32 bytes long here!!!!"))

	cs, _ := NewCipherState(key)

	for i := 0; i < 10; i++ {
		if cs.Nonce() != uint64(i) {
			t.Errorf("nonce = %d, want %d", cs.Nonce(), i)
		}
		cs.Encrypt([]byte("test"), nil)
	}
}

func TestCipherStateSetNonce(t *testing.T) {
	var key Key
	copy(key[:], []byte("test key 32 bytes long here!!!!"))

	cs, _ := NewCipherState(key)
	cs.SetNonce(100)

	if cs.Nonce() != 100 {
		t.Errorf("nonce = %d, want 100", cs.Nonce())
	}
}

func TestCipherStateDecryptWrongNonce(t *testing.T) {
	var key Key
	copy(key[:], []byte("test key 32 bytes long here!!!!"))

	cs1, _ := NewCipherState(key)
	cs2, _ := NewCipherState(key)

	ciphertext := cs1.Encrypt([]byte("test"), nil)

	// Advance nonce on receiver
	cs2.SetNonce(5)

	_, err := cs2.Decrypt(ciphertext, nil)
	if err == nil {
		t.Error("Decrypt should fail with wrong nonce")
	}
}

func TestSymmetricStateNew(t *testing.T) {
	// Short protocol name (< 32 bytes)
	ss1 := NewSymmetricState("Noise_IK")
	if ss1.ChainingKey().IsZero() {
		t.Error("chaining key should not be zero")
	}

	// Long protocol name (> 32 bytes)
	longName := "Noise_IK_25519_ChaChaPoly_BLAKE2s"
	ss2 := NewSymmetricState(longName)
	if ss2.ChainingKey().IsZero() {
		t.Error("chaining key should not be zero for long name")
	}

	// Initial hash equals chaining key
	if ss1.Hash() != ss1.ChainingKey() {
		t.Error("initial hash should equal chaining key")
	}
}

func TestSymmetricStateMixHash(t *testing.T) {
	ss := NewSymmetricState("Test")
	initialHash := ss.Hash()

	ss.MixHash([]byte("data"))

	if ss.Hash() == initialHash {
		t.Error("hash should change after MixHash")
	}

	// Deterministic
	ss2 := NewSymmetricState("Test")
	ss2.MixHash([]byte("data"))

	if ss.Hash() != ss2.Hash() {
		t.Error("MixHash should be deterministic")
	}
}

func TestSymmetricStateMixKey(t *testing.T) {
	ss := NewSymmetricState("Test")
	initialCK := ss.ChainingKey()

	k := ss.MixKey([]byte("input"))

	if ss.ChainingKey() == initialCK {
		t.Error("chaining key should change after MixKey")
	}
	if k.IsZero() {
		t.Error("derived key should not be zero")
	}
	if k == ss.ChainingKey() {
		t.Error("derived key should differ from new chaining key")
	}
}

func TestSymmetricStateMixKeyAndHash(t *testing.T) {
	ss := NewSymmetricState("Test")
	initialCK := ss.ChainingKey()
	initialHash := ss.Hash()

	k := ss.MixKeyAndHash([]byte("input"))

	if ss.ChainingKey() == initialCK {
		t.Error("chaining key should change")
	}
	if ss.Hash() == initialHash {
		t.Error("hash should change")
	}
	if k.IsZero() {
		t.Error("derived key should not be zero")
	}
}

func TestSymmetricStateEncryptDecryptAndHash(t *testing.T) {
	ss1 := NewSymmetricState("Test")
	ss2 := NewSymmetricState("Test")

	// Get a key by mixing
	k1 := ss1.MixKey([]byte("keying material"))
	k2 := ss2.MixKey([]byte("keying material"))

	if k1 != k2 {
		t.Fatal("keys should be equal")
	}

	// Encrypt
	plaintext := []byte("secret message")
	ciphertext := ss1.EncryptAndHash(&k1, plaintext)

	if len(ciphertext) != len(plaintext)+TagSize {
		t.Errorf("ciphertext length = %d, want %d", len(ciphertext), len(plaintext)+TagSize)
	}

	// Decrypt
	decrypted, err := ss2.DecryptAndHash(&k2, ciphertext)
	if err != nil {
		t.Fatalf("DecryptAndHash() error = %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("decrypted = %q, want %q", decrypted, plaintext)
	}

	// Hashes should now be equal
	if ss1.Hash() != ss2.Hash() {
		t.Error("hashes should be equal after encrypt/decrypt")
	}
}

func TestSymmetricStateEncryptAndHashEmpty(t *testing.T) {
	ss := NewSymmetricState("Test")
	k := ss.MixKey([]byte("key"))

	// Encrypt empty plaintext (like in handshake response)
	ciphertext := ss.EncryptAndHash(&k, nil)

	if len(ciphertext) != TagSize {
		t.Errorf("empty ciphertext length = %d, want %d", len(ciphertext), TagSize)
	}
}

func TestSymmetricStateSplit(t *testing.T) {
	ss := NewSymmetricState("Test")
	ss.MixKey([]byte("some input"))

	cs1, cs2, err := ss.Split()
	if err != nil {
		t.Fatalf("Split() error = %v", err)
	}

	if cs1 == nil || cs2 == nil {
		t.Error("CipherStates should not be nil")
	}

	// Keys should be different
	if cs1.Key() == cs2.Key() {
		t.Error("split keys should be different")
	}

	// Both should work for encryption
	ct1 := cs1.Encrypt([]byte("test"), nil)
	ct2 := cs2.Encrypt([]byte("test"), nil)

	if bytes.Equal(ct1, ct2) {
		t.Error("encryptions with different keys should differ")
	}
}

func TestSymmetricStateClone(t *testing.T) {
	ss := NewSymmetricState("Test")
	ss.MixHash([]byte("data"))
	ss.MixKey([]byte("key"))

	clone := ss.Clone()

	if clone.ChainingKey() != ss.ChainingKey() {
		t.Error("clone chaining key should match")
	}
	if clone.Hash() != ss.Hash() {
		t.Error("clone hash should match")
	}

	// Modify original
	ss.MixHash([]byte("more"))

	// Clone should be unchanged
	if clone.Hash() == ss.Hash() {
		t.Error("clone should be independent")
	}
}

func TestSymmetricStateConsistency(t *testing.T) {
	// Test that two SymmetricStates evolve identically with same operations
	ss1 := NewSymmetricState("Noise_IK_25519_ChaChaPoly_BLAKE2s")
	ss2 := NewSymmetricState("Noise_IK_25519_ChaChaPoly_BLAKE2s")

	// Mix in same data
	remotePub := []byte("remote public key here!!")
	ss1.MixHash(remotePub)
	ss2.MixHash(remotePub)

	if ss1.Hash() != ss2.Hash() {
		t.Error("hashes should be equal")
	}

	// Mix key
	ephPub := []byte("ephemeral public key here")
	k1 := ss1.MixKey(ephPub)
	k2 := ss2.MixKey(ephPub)

	if k1 != k2 {
		t.Error("derived keys should be equal")
	}
	if ss1.ChainingKey() != ss2.ChainingKey() {
		t.Error("chaining keys should be equal")
	}
}


