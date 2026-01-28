package noise

import (
	"bytes"
	"testing"
)

func TestHash(t *testing.T) {
	// Test empty input
	h1 := Hash()
	if len(h1) != HashSize {
		t.Errorf("Hash() size = %d, want %d", len(h1), HashSize)
	}

	// Test determinism
	h2 := Hash([]byte("hello"))
	h3 := Hash([]byte("hello"))
	if h2 != h3 {
		t.Error("Hash should be deterministic")
	}

	// Test different inputs produce different hashes
	h4 := Hash([]byte("world"))
	if h2 == h4 {
		t.Error("different inputs should produce different hashes")
	}

	// Test multiple inputs
	h5 := Hash([]byte("hello"), []byte("world"))
	h6 := Hash([]byte("helloworld"))
	if h5 != h6 {
		t.Error("concatenated inputs should produce same hash")
	}
}

func TestHashTo(t *testing.T) {
	var dst [HashSize]byte
	HashTo(&dst, []byte("test"))

	expected := Hash([]byte("test"))
	if dst != expected {
		t.Error("HashTo should produce same result as Hash")
	}
}

func TestMAC(t *testing.T) {
	key := []byte("0123456789abcdef") // 16 bytes

	mac1 := MAC(key, []byte("message"))
	mac2 := MAC(key, []byte("message"))
	if mac1 != mac2 {
		t.Error("MAC should be deterministic")
	}

	mac3 := MAC(key, []byte("different"))
	if mac1 == mac3 {
		t.Error("different messages should produce different MACs")
	}

	// Different key
	key2 := []byte("different_key___")
	mac4 := MAC(key2, []byte("message"))
	if mac1 == mac4 {
		t.Error("different keys should produce different MACs")
	}
}

func TestHMAC(t *testing.T) {
	var key [HashSize]byte
	copy(key[:], []byte("test key"))

	h1 := HMAC(&key, []byte("data"))
	h2 := HMAC(&key, []byte("data"))
	if h1 != h2 {
		t.Error("HMAC should be deterministic")
	}

	h3 := HMAC(&key, []byte("different"))
	if h1 == h3 {
		t.Error("different data should produce different HMACs")
	}
}

func TestHKDF(t *testing.T) {
	var ck Key
	copy(ck[:], []byte("chaining key"))
	input := []byte("input keying material")

	// Test 1 output
	keys1 := HKDF(&ck, input, 1)
	if len(keys1) != 1 {
		t.Errorf("HKDF(1) returned %d keys, want 1", len(keys1))
	}
	if keys1[0].IsZero() {
		t.Error("HKDF output should not be zero")
	}

	// Test 2 outputs
	keys2 := HKDF(&ck, input, 2)
	if len(keys2) != 2 {
		t.Errorf("HKDF(2) returned %d keys, want 2", len(keys2))
	}
	if keys2[0] != keys1[0] {
		t.Error("first output should be consistent")
	}
	if keys2[0] == keys2[1] {
		t.Error("outputs should be different")
	}

	// Test 3 outputs
	keys3 := HKDF(&ck, input, 3)
	if len(keys3) != 3 {
		t.Errorf("HKDF(3) returned %d keys, want 3", len(keys3))
	}
	if keys3[0] != keys2[0] || keys3[1] != keys2[1] {
		t.Error("first two outputs should be consistent")
	}
	if keys3[2] == keys3[0] || keys3[2] == keys3[1] {
		t.Error("third output should be different from others")
	}
}

func TestKDF1(t *testing.T) {
	var ck Key
	copy(ck[:], []byte("chaining key"))

	newCK := KDF1(&ck, []byte("input"))
	if newCK.IsZero() {
		t.Error("KDF1 output should not be zero")
	}
	if newCK == ck {
		t.Error("new chaining key should be different from input")
	}
}

func TestKDF2(t *testing.T) {
	var ck Key
	copy(ck[:], []byte("chaining key"))

	newCK, k := KDF2(&ck, []byte("input"))
	if newCK.IsZero() || k.IsZero() {
		t.Error("KDF2 outputs should not be zero")
	}
	if newCK == k {
		t.Error("outputs should be different")
	}
}

func TestKDF3(t *testing.T) {
	var ck Key
	copy(ck[:], []byte("chaining key"))

	newCK, t1, k := KDF3(&ck, []byte("input"))
	if newCK.IsZero() || t1.IsZero() || k.IsZero() {
		t.Error("KDF3 outputs should not be zero")
	}
	if newCK == t1 || newCK == k || t1 == k {
		t.Error("all outputs should be different")
	}
}

func TestNewAEAD(t *testing.T) {
	key := make([]byte, 32)

	aead, err := NewAEAD(key)
	if err != nil {
		t.Fatalf("NewAEAD() error = %v", err)
	}
	if aead == nil {
		t.Error("AEAD should not be nil")
	}

	// Wrong key size
	_, err = NewAEAD(make([]byte, 16))
	if err == nil {
		t.Error("NewAEAD should fail with wrong key size")
	}
}

func TestEncryptDecrypt(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	plaintext := []byte("hello, world!")
	ad := []byte("additional data")

	// Encrypt
	ciphertext, err := Encrypt(key, 0, plaintext, ad)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	// Ciphertext should be longer (includes tag)
	if len(ciphertext) != len(plaintext)+TagSize {
		t.Errorf("ciphertext length = %d, want %d", len(ciphertext), len(plaintext)+TagSize)
	}

	// Decrypt
	decrypted, err := Decrypt(key, 0, ciphertext, ad)
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("decrypted = %q, want %q", decrypted, plaintext)
	}
}

func TestEncryptDecryptWithDifferentNonces(t *testing.T) {
	key := make([]byte, 32)
	plaintext := []byte("hello")

	ct1, _ := Encrypt(key, 0, plaintext, nil)
	ct2, _ := Encrypt(key, 1, plaintext, nil)

	if bytes.Equal(ct1, ct2) {
		t.Error("different nonces should produce different ciphertexts")
	}
}

func TestDecryptWithWrongKey(t *testing.T) {
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	key2[0] = 1 // different key

	ciphertext, _ := Encrypt(key1, 0, []byte("secret"), nil)

	_, err := Decrypt(key2, 0, ciphertext, nil)
	if err == nil {
		t.Error("Decrypt should fail with wrong key")
	}
}

func TestDecryptWithWrongAD(t *testing.T) {
	key := make([]byte, 32)
	plaintext := []byte("secret")
	ad1 := []byte("correct ad")
	ad2 := []byte("wrong ad")

	ciphertext, _ := Encrypt(key, 0, plaintext, ad1)

	_, err := Decrypt(key, 0, ciphertext, ad2)
	if err == nil {
		t.Error("Decrypt should fail with wrong additional data")
	}
}

func TestEncryptWithAD(t *testing.T) {
	var key Key
	copy(key[:], []byte("test key 32 bytes long here!!!!"))

	plaintext := []byte("hello")
	ad := []byte("additional data")

	ciphertext := EncryptWithAD(&key, ad, plaintext)
	if len(ciphertext) != len(plaintext)+TagSize {
		t.Errorf("ciphertext length = %d, want %d", len(ciphertext), len(plaintext)+TagSize)
	}

	decrypted, err := DecryptWithAD(&key, ad, ciphertext)
	if err != nil {
		t.Fatalf("DecryptWithAD() error = %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("decrypted = %q, want %q", decrypted, plaintext)
	}
}

func TestEncryptWithADEmptyPlaintext(t *testing.T) {
	var key Key
	copy(key[:], []byte("test key 32 bytes long here!!!!"))

	ad := []byte("additional data")

	// Empty plaintext (used in handshake response)
	ciphertext := EncryptWithAD(&key, ad, nil)
	if len(ciphertext) != TagSize {
		t.Errorf("empty plaintext ciphertext length = %d, want %d", len(ciphertext), TagSize)
	}

	decrypted, err := DecryptWithAD(&key, ad, ciphertext)
	if err != nil {
		t.Fatalf("DecryptWithAD() error = %v", err)
	}

	if len(decrypted) != 0 {
		t.Errorf("decrypted should be empty, got %q", decrypted)
	}
}



