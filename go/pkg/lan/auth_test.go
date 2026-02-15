package lan

import (
	"encoding/json"
	"testing"

	"github.com/vibing/zgrnet/pkg/noise"
)

func TestOpenAuth(t *testing.T) {
	auth := NewOpenAuth()

	if auth.Method() != "open" {
		t.Fatalf("expected method 'open', got %q", auth.Method())
	}

	pk := genKey(t)
	if err := auth.Authenticate(pk, nil); err != nil {
		t.Fatalf("open auth should always succeed: %v", err)
	}
}

func TestPasswordAuth(t *testing.T) {
	auth, err := NewPasswordAuthFromPlaintext("secret123", 4) // low cost for test speed
	if err != nil {
		t.Fatal(err)
	}

	if auth.Method() != "password" {
		t.Fatalf("expected method 'password', got %q", auth.Method())
	}

	pk := genKey(t)

	// Correct password.
	cred := json.RawMessage(`{"password": "secret123"}`)
	if err := auth.Authenticate(pk, cred); err != nil {
		t.Fatalf("expected success with correct password: %v", err)
	}

	// Wrong password.
	cred = json.RawMessage(`{"password": "wrong"}`)
	if err := auth.Authenticate(pk, cred); err == nil {
		t.Fatal("expected error with wrong password")
	}

	// Empty password.
	cred = json.RawMessage(`{"password": ""}`)
	if err := auth.Authenticate(pk, cred); err == nil {
		t.Fatal("expected error with empty password")
	}

	// Invalid JSON.
	cred = json.RawMessage(`not json`)
	if err := auth.Authenticate(pk, cred); err == nil {
		t.Fatal("expected error with invalid JSON")
	}
}

func TestPasswordAuth_FromHash(t *testing.T) {
	// First create a hash.
	auth1, err := NewPasswordAuthFromPlaintext("mypass", 4)
	if err != nil {
		t.Fatal(err)
	}
	hashStr := string(auth1.hash)

	// Now create from hash.
	auth2, err := NewPasswordAuth(hashStr)
	if err != nil {
		t.Fatal(err)
	}

	pk := genKey(t)
	cred := json.RawMessage(`{"password": "mypass"}`)
	if err := auth2.Authenticate(pk, cred); err != nil {
		t.Fatalf("expected success with correct password from hash: %v", err)
	}

	// Invalid hash.
	if _, err := NewPasswordAuth("not-a-hash"); err == nil {
		t.Fatal("expected error with invalid hash")
	}
}

func TestInviteCodeAuth(t *testing.T) {
	auth := NewInviteCodeAuth()

	if auth.Method() != "invite_code" {
		t.Fatalf("expected method 'invite_code', got %q", auth.Method())
	}

	// Generate a single-use code.
	code, err := auth.GenerateCode(1)
	if err != nil {
		t.Fatal(err)
	}

	pk := genKey(t)

	// First use succeeds.
	cred := json.RawMessage(`{"code": "` + code + `"}`)
	if err := auth.Authenticate(pk, cred); err != nil {
		t.Fatalf("expected success with valid invite code: %v", err)
	}

	// Second use fails (single-use).
	if err := auth.Authenticate(pk, cred); err == nil {
		t.Fatal("expected error on second use of single-use code")
	}

	// Invalid code.
	cred = json.RawMessage(`{"code": "nonexistent"}`)
	if err := auth.Authenticate(pk, cred); err == nil {
		t.Fatal("expected error with invalid code")
	}

	// Empty code.
	cred = json.RawMessage(`{"code": ""}`)
	if err := auth.Authenticate(pk, cred); err == nil {
		t.Fatal("expected error with empty code")
	}
}

func TestInviteCodeAuth_Unlimited(t *testing.T) {
	auth := NewInviteCodeAuth()

	code, err := auth.GenerateCode(0) // unlimited
	if err != nil {
		t.Fatal(err)
	}

	pk := genKey(t)
	cred := json.RawMessage(`{"code": "` + code + `"}`)

	// Should succeed many times.
	for i := 0; i < 10; i++ {
		if err := auth.Authenticate(pk, cred); err != nil {
			t.Fatalf("use %d: expected success with unlimited code: %v", i, err)
		}
	}
}

func TestInviteCodeAuth_RevokeAndList(t *testing.T) {
	auth := NewInviteCodeAuth()

	code1, _ := auth.GenerateCode(0)
	code2, _ := auth.GenerateCode(5)

	codes := auth.ListCodes()
	if len(codes) != 2 {
		t.Fatalf("expected 2 codes, got %d", len(codes))
	}

	// Revoke one.
	if !auth.RevokeCode(code1) {
		t.Fatal("expected revoke to return true")
	}
	if auth.RevokeCode(code1) {
		t.Fatal("expected revoke of already-revoked code to return false")
	}

	codes = auth.ListCodes()
	if len(codes) != 1 {
		t.Fatalf("expected 1 code after revoke, got %d", len(codes))
	}
	if codes[0].Code != code2 {
		t.Fatalf("expected remaining code to be %s, got %s", code2, codes[0].Code)
	}
}

func TestPubkeyWhitelistAuth(t *testing.T) {
	pk1 := genKey(t)
	pk2 := genKey(t)
	pkUnknown := genKey(t)

	auth := NewPubkeyWhitelistAuth([]noise.PublicKey{pk1, pk2})

	if auth.Method() != "pubkey_whitelist" {
		t.Fatalf("expected method 'pubkey_whitelist', got %q", auth.Method())
	}

	// Allowed keys.
	if err := auth.Authenticate(pk1, nil); err != nil {
		t.Fatalf("expected pk1 to be allowed: %v", err)
	}
	if err := auth.Authenticate(pk2, nil); err != nil {
		t.Fatalf("expected pk2 to be allowed: %v", err)
	}

	// Unknown key.
	if err := auth.Authenticate(pkUnknown, nil); err == nil {
		t.Fatal("expected unknown key to be rejected")
	}

	// Dynamic add/remove.
	auth.AddKey(pkUnknown)
	if err := auth.Authenticate(pkUnknown, nil); err != nil {
		t.Fatalf("expected newly added key to be allowed: %v", err)
	}

	auth.RemoveKey(pk1)
	if err := auth.Authenticate(pk1, nil); err == nil {
		t.Fatal("expected removed key to be rejected")
	}
}
