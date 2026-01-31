package noise

import (
	"encoding/hex"
	"fmt"
)

// TestVector holds intermediate state for cross-language testing
type TestVector struct {
	Step        string `json:"step"`
	ChainingKey string `json:"chaining_key"`
	Hash        string `json:"hash"`
	Key         string `json:"key,omitempty"`
	Output      string `json:"output,omitempty"`
}

// GenerateTestVectors creates test vectors for cross-language compatibility testing.
// Run this with: go test -v -run TestGenerateVectors
func GenerateTestVectors() []TestVector {
	var vectors []TestVector

	// Fixed test keys - use non-zero values to get distinct keys after clamping
	initiatorPriv := Key{}
	for i := range initiatorPriv {
		initiatorPriv[i] = byte(i + 1) // 01 02 03 ... 20
	}
	responderPriv := Key{}
	for i := range responderPriv {
		responderPriv[i] = byte(i + 33) // 21 22 23 ... 40
	}

	initiatorKP, _ := NewKeyPair(initiatorPriv)
	responderKP, _ := NewKeyPair(responderPriv)

	fmt.Printf("=== Test Vectors for Noise IK ===\n\n")
	fmt.Printf("Initiator private: %s\n", hex.EncodeToString(initiatorKP.Private[:]))
	fmt.Printf("Initiator public:  %s\n", hex.EncodeToString(initiatorKP.Public[:]))
	fmt.Printf("Responder private: %s\n", hex.EncodeToString(responderKP.Private[:]))
	fmt.Printf("Responder public:  %s\n", hex.EncodeToString(responderKP.Public[:]))
	fmt.Println()

	// Step 1: Protocol name initialization
	protocolName := "Noise_IK_25519_ChaChaPoly_BLAKE2s"
	fmt.Printf("Protocol name: %s (len=%d)\n", protocolName, len(protocolName))
	fmt.Printf("Protocol name hex: %s\n\n", hex.EncodeToString([]byte(protocolName)))

	ss := NewSymmetricState(protocolName)
	vectors = append(vectors, TestVector{
		Step:        "init",
		ChainingKey: hex.EncodeToString(ss.chainingKey[:]),
		Hash:        hex.EncodeToString(ss.hash[:]),
	})
	fmt.Printf("After init:\n")
	fmt.Printf("  ck: %s\n", hex.EncodeToString(ss.chainingKey[:]))
	fmt.Printf("  h:  %s\n\n", hex.EncodeToString(ss.hash[:]))

	// Step 2: MixHash with prologue (empty)
	ss.MixHash(nil)
	vectors = append(vectors, TestVector{
		Step:        "mixhash_prologue",
		ChainingKey: hex.EncodeToString(ss.chainingKey[:]),
		Hash:        hex.EncodeToString(ss.hash[:]),
	})
	fmt.Printf("After MixHash(prologue=[]):\n")
	fmt.Printf("  ck: %s\n", hex.EncodeToString(ss.chainingKey[:]))
	fmt.Printf("  h:  %s\n\n", hex.EncodeToString(ss.hash[:]))

	// Step 3: MixHash with responder's public key (pre-message)
	ss.MixHash(responderKP.Public[:])
	vectors = append(vectors, TestVector{
		Step:        "mixhash_rs",
		ChainingKey: hex.EncodeToString(ss.chainingKey[:]),
		Hash:        hex.EncodeToString(ss.hash[:]),
	})
	fmt.Printf("After MixHash(responder_public):\n")
	fmt.Printf("  ck: %s\n", hex.EncodeToString(ss.chainingKey[:]))
	fmt.Printf("  h:  %s\n\n", hex.EncodeToString(ss.hash[:]))

	// Step 4: Generate ephemeral key (use fixed for reproducibility)
	ephemeralPriv := Key{}
	for i := range ephemeralPriv {
		ephemeralPriv[i] = byte(i + 65) // 41 42 43 ... 60
	}
	ephemeralKP, _ := NewKeyPair(ephemeralPriv)
	fmt.Printf("Ephemeral private: %s\n", hex.EncodeToString(ephemeralKP.Private[:]))
	fmt.Printf("Ephemeral public:  %s\n\n", hex.EncodeToString(ephemeralKP.Public[:]))

	// Step 5: MixHash(e) - mix ephemeral public key
	ss.MixHash(ephemeralKP.Public[:])
	vectors = append(vectors, TestVector{
		Step:        "mixhash_e",
		ChainingKey: hex.EncodeToString(ss.chainingKey[:]),
		Hash:        hex.EncodeToString(ss.hash[:]),
	})
	fmt.Printf("After MixHash(ephemeral_public):\n")
	fmt.Printf("  ck: %s\n", hex.EncodeToString(ss.chainingKey[:]))
	fmt.Printf("  h:  %s\n\n", hex.EncodeToString(ss.hash[:]))

	// Step 6: DH(e, rs) and MixKey
	dhResult, _ := ephemeralKP.DH(responderKP.Public)
	fmt.Printf("DH(e, rs): %s\n", hex.EncodeToString(dhResult[:]))
	k1 := ss.MixKey(dhResult[:])
	vectors = append(vectors, TestVector{
		Step:        "mixkey_es",
		ChainingKey: hex.EncodeToString(ss.chainingKey[:]),
		Hash:        hex.EncodeToString(ss.hash[:]),
		Key:         hex.EncodeToString(k1[:]),
	})
	fmt.Printf("After MixKey(DH(e, rs)):\n")
	fmt.Printf("  ck: %s\n", hex.EncodeToString(ss.chainingKey[:]))
	fmt.Printf("  h:  %s\n", hex.EncodeToString(ss.hash[:]))
	fmt.Printf("  k:  %s\n\n", hex.EncodeToString(k1[:]))

	// Step 7: MixKey(nil) for encrypting static key
	k2 := ss.MixKey(nil)
	vectors = append(vectors, TestVector{
		Step:        "mixkey_before_s",
		ChainingKey: hex.EncodeToString(ss.chainingKey[:]),
		Hash:        hex.EncodeToString(ss.hash[:]),
		Key:         hex.EncodeToString(k2[:]),
	})
	fmt.Printf("After MixKey(nil) for encrypting s:\n")
	fmt.Printf("  ck: %s\n", hex.EncodeToString(ss.chainingKey[:]))
	fmt.Printf("  h:  %s\n", hex.EncodeToString(ss.hash[:]))
	fmt.Printf("  k:  %s\n\n", hex.EncodeToString(k2[:]))

	// Step 8: EncryptAndHash(initiator static public key)
	ciphertext := ss.EncryptAndHash(&k2, initiatorKP.Public[:])
	vectors = append(vectors, TestVector{
		Step:        "encrypt_s",
		ChainingKey: hex.EncodeToString(ss.chainingKey[:]),
		Hash:        hex.EncodeToString(ss.hash[:]),
		Output:      hex.EncodeToString(ciphertext),
	})
	fmt.Printf("After EncryptAndHash(initiator_public):\n")
	fmt.Printf("  ck: %s\n", hex.EncodeToString(ss.chainingKey[:]))
	fmt.Printf("  h:  %s\n", hex.EncodeToString(ss.hash[:]))
	fmt.Printf("  ciphertext: %s\n\n", hex.EncodeToString(ciphertext))

	// Step 9: DH(s, rs) and MixKey for ss token
	dhSS, _ := initiatorKP.DH(responderKP.Public)
	fmt.Printf("DH(s, rs): %s\n", hex.EncodeToString(dhSS[:]))
	k3 := ss.MixKey(dhSS[:])
	vectors = append(vectors, TestVector{
		Step:        "mixkey_ss",
		ChainingKey: hex.EncodeToString(ss.chainingKey[:]),
		Hash:        hex.EncodeToString(ss.hash[:]),
		Key:         hex.EncodeToString(k3[:]),
	})
	fmt.Printf("After MixKey(DH(s, rs)):\n")
	fmt.Printf("  ck: %s\n", hex.EncodeToString(ss.chainingKey[:]))
	fmt.Printf("  h:  %s\n", hex.EncodeToString(ss.hash[:]))
	fmt.Printf("  k:  %s\n\n", hex.EncodeToString(k3[:]))

	return vectors
}
