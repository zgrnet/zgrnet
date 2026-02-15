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

func TestCipherStateDecryptWithNonce(t *testing.T) {
	var key Key
	copy(key[:], []byte("test key 32 bytes long here!!!!"))

	cs1, _ := NewCipherState(key)
	cs2, _ := NewCipherState(key)

	// Encrypt 3 messages (nonces 0, 1, 2)
	ct0 := cs1.Encrypt([]byte("message 0"), nil)
	ct1 := cs1.Encrypt([]byte("message 1"), nil)
	ct2 := cs1.Encrypt([]byte("message 2"), nil)

	// Simulate packet loss: receiver only gets ct0 and ct2 (ct1 lost).
	// Normal Decrypt works for ct0.
	pt0, err := cs2.Decrypt(ct0, nil)
	if err != nil {
		t.Fatalf("Decrypt ct0: %v", err)
	}
	if !bytes.Equal(pt0, []byte("message 0")) {
		t.Errorf("ct0 = %q, want %q", pt0, "message 0")
	}

	// Normal Decrypt of ct2 fails because receiver nonce is 1, but ct2 was encrypted with nonce 2.
	_, err = cs2.Decrypt(ct2, nil)
	if err == nil {
		t.Fatal("Decrypt ct2 with auto-nonce should fail (nonce desync)")
	}

	// DecryptWithNonce succeeds with the correct explicit nonce.
	// Note: cs2 auto-nonce is now 2 (incremented by the failed attempt), but that's irrelevant.
	pt2, err := cs2.DecryptWithNonce(ct2, nil, 2)
	if err != nil {
		t.Fatalf("DecryptWithNonce ct2: %v", err)
	}
	if !bytes.Equal(pt2, []byte("message 2")) {
		t.Errorf("ct2 = %q, want %q", pt2, "message 2")
	}

	// DecryptWithNonce can also recover the lost ct1.
	pt1, err := cs2.DecryptWithNonce(ct1, nil, 1)
	if err != nil {
		t.Fatalf("DecryptWithNonce ct1: %v", err)
	}
	if !bytes.Equal(pt1, []byte("message 1")) {
		t.Errorf("ct1 = %q, want %q", pt1, "message 1")
	}

	// Verify DecryptWithNonce does not modify the internal nonce.
	nonceBeforeCall := cs2.Nonce()
	_, _ = cs2.DecryptWithNonce(ct0, nil, 0)
	if cs2.Nonce() != nonceBeforeCall {
		t.Errorf("DecryptWithNonce modified nonce: got %d, want %d", cs2.Nonce(), nonceBeforeCall)
	}
}

func TestCipherStateDecryptWithNonceAD(t *testing.T) {
	var key Key
	copy(key[:], []byte("test key 32 bytes long here!!!!"))

	cs1, _ := NewCipherState(key)
	cs2, _ := NewCipherState(key)

	ad := []byte("additional data")
	ct := cs1.Encrypt([]byte("hello"), ad)

	// Wrong AD fails.
	_, err := cs2.DecryptWithNonce(ct, []byte("wrong ad"), 0)
	if err == nil {
		t.Fatal("DecryptWithNonce with wrong AD should fail")
	}

	// Correct AD + nonce succeeds.
	pt, err := cs2.DecryptWithNonce(ct, ad, 0)
	if err != nil {
		t.Fatalf("DecryptWithNonce: %v", err)
	}
	if !bytes.Equal(pt, []byte("hello")) {
		t.Errorf("plaintext = %q, want %q", pt, "hello")
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
