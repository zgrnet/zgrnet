package config

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func hexKey(hexStr string) [32]byte {
	var key [32]byte
	b, _ := hex.DecodeString(hexStr)
	copy(key[:], b)
	return key
}

func TestPolicyEngine_AnyMatch(t *testing.T) {
	policy := &InboundPolicy{
		Default: "deny",
		Rules: []InboundRule{
			{
				Name:     "allow-all",
				Match:    MatchConfig{Pubkey: PubkeyMatch{Type: "any"}},
				Services: []ServiceConfig{{Proto: "*", Port: "*"}},
				Action:   "allow",
			},
		},
	}

	pe, err := NewPolicyEngine(policy)
	if err != nil {
		t.Fatal(err)
	}

	result := pe.Check(hexKey("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"))
	if result.Action != "allow" {
		t.Errorf("action = %q, want allow", result.Action)
	}
	if result.RuleName != "allow-all" {
		t.Errorf("rule = %q, want allow-all", result.RuleName)
	}
}

func TestPolicyEngine_Whitelist(t *testing.T) {
	dir := t.TempDir()
	listPath := filepath.Join(dir, "trusted.txt")

	trustedKey := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	content := "# Trusted keys\n" + trustedKey + "\n"
	if err := os.WriteFile(listPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	policy := &InboundPolicy{
		Default: "deny",
		Rules: []InboundRule{
			{
				Name:     "trusted",
				Match:    MatchConfig{Pubkey: PubkeyMatch{Type: "whitelist", Path: listPath}},
				Services: []ServiceConfig{{Proto: "tcp", Port: "80,443"}},
				Action:   "allow",
			},
		},
	}

	pe, err := NewPolicyEngine(policy)
	if err != nil {
		t.Fatal(err)
	}

	// Trusted key should be allowed
	result := pe.Check(hexKey(trustedKey))
	if result.Action != "allow" {
		t.Errorf("trusted key: action = %q, want allow", result.Action)
	}
	if len(result.Services) != 1 || result.Services[0].Proto != "tcp" {
		t.Errorf("services = %v", result.Services)
	}

	// Unknown key should be denied (default)
	result = pe.Check(hexKey("0000000000000000000000000000000000000000000000000000000000000001"))
	if result.Action != "deny" {
		t.Errorf("unknown key: action = %q, want deny", result.Action)
	}
	if result.RuleName != "default" {
		t.Errorf("rule = %q, want default", result.RuleName)
	}
}

func TestPolicyEngine_Zgrlan(t *testing.T) {
	policy := &InboundPolicy{
		Default: "deny",
		Rules: []InboundRule{
			{
				Name:     "company",
				Match:    MatchConfig{Pubkey: PubkeyMatch{Type: "zgrlan", Peer: "company.zigor.net"}},
				Services: []ServiceConfig{{Proto: "tcp", Port: "80,443"}},
				Action:   "allow",
			},
		},
	}

	pe, err := NewPolicyEngine(policy)
	if err != nil {
		t.Fatal(err)
	}

	result := pe.Check(hexKey("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"))
	if result.Action != "allow" {
		t.Errorf("action = %q, want allow", result.Action)
	}
	if !result.NeedsZgrlanVerify {
		t.Error("expected NeedsZgrlanVerify = true")
	}
	if result.ZgrlanPeer != "company.zigor.net" {
		t.Errorf("zgrlan peer = %q, want company.zigor.net", result.ZgrlanPeer)
	}
}

func TestPolicyEngine_DefaultAllow(t *testing.T) {
	policy := &InboundPolicy{
		Default: "allow",
	}

	pe, err := NewPolicyEngine(policy)
	if err != nil {
		t.Fatal(err)
	}

	result := pe.Check(hexKey("0000000000000000000000000000000000000000000000000000000000000001"))
	if result.Action != "allow" {
		t.Errorf("action = %q, want allow", result.Action)
	}
}

func TestPolicyEngine_DefaultDeny(t *testing.T) {
	policy := &InboundPolicy{
		Default: "deny",
	}

	pe, err := NewPolicyEngine(policy)
	if err != nil {
		t.Fatal(err)
	}

	result := pe.Check(hexKey("0000000000000000000000000000000000000000000000000000000000000001"))
	if result.Action != "deny" {
		t.Errorf("action = %q, want deny", result.Action)
	}
}

func TestPolicyEngine_RulePriority(t *testing.T) {
	dir := t.TempDir()
	listPath := filepath.Join(dir, "trusted.txt")
	trustedKey := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	if err := os.WriteFile(listPath, []byte(trustedKey+"\n"), 0644); err != nil {
		t.Fatal(err)
	}

	policy := &InboundPolicy{
		Default: "deny",
		Rules: []InboundRule{
			{
				Name:     "trusted-full",
				Match:    MatchConfig{Pubkey: PubkeyMatch{Type: "whitelist", Path: listPath}},
				Services: []ServiceConfig{{Proto: "*", Port: "*"}},
				Action:   "allow",
			},
			{
				Name:     "any-limited",
				Match:    MatchConfig{Pubkey: PubkeyMatch{Type: "any"}},
				Services: []ServiceConfig{{Proto: "tcp", Port: "80"}},
				Action:   "allow",
			},
		},
	}

	pe, err := NewPolicyEngine(policy)
	if err != nil {
		t.Fatal(err)
	}

	// Trusted key hits first rule (full access)
	result := pe.Check(hexKey(trustedKey))
	if result.RuleName != "trusted-full" {
		t.Errorf("trusted key rule = %q, want trusted-full", result.RuleName)
	}
	if len(result.Services) != 1 || result.Services[0].Proto != "*" {
		t.Errorf("services = %v, want wildcard", result.Services)
	}

	// Unknown key hits second rule (limited access)
	result = pe.Check(hexKey("0000000000000000000000000000000000000000000000000000000000000001"))
	if result.RuleName != "any-limited" {
		t.Errorf("unknown key rule = %q, want any-limited", result.RuleName)
	}
	if len(result.Services) != 1 || result.Services[0].Port != "80" {
		t.Errorf("services = %v, want port 80 only", result.Services)
	}
}

func TestPolicyEngine_Reload(t *testing.T) {
	dir := t.TempDir()
	listPath := filepath.Join(dir, "trusted.txt")

	key1 := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	key2 := "0000000000000000000000000000000000000000000000000000000000000001"

	// Initially only key1
	if err := os.WriteFile(listPath, []byte(key1+"\n"), 0644); err != nil {
		t.Fatal(err)
	}

	policy := &InboundPolicy{
		Default: "deny",
		Rules: []InboundRule{
			{
				Name:     "trusted",
				Match:    MatchConfig{Pubkey: PubkeyMatch{Type: "whitelist", Path: listPath}},
				Services: []ServiceConfig{{Proto: "*", Port: "*"}},
				Action:   "allow",
			},
		},
	}

	pe, err := NewPolicyEngine(policy)
	if err != nil {
		t.Fatal(err)
	}

	// key2 should be denied
	if result := pe.Check(hexKey(key2)); result.Action != "deny" {
		t.Error("key2 should be denied initially")
	}

	// Add key2 to whitelist
	if err := os.WriteFile(listPath, []byte(key1+"\n"+key2+"\n"), 0644); err != nil {
		t.Fatal(err)
	}

	if err := pe.Reload(); err != nil {
		t.Fatal(err)
	}

	// key2 should now be allowed
	if result := pe.Check(hexKey(key2)); result.Action != "allow" {
		t.Error("key2 should be allowed after reload")
	}
}

func TestPolicyEngine_WhitelistFileNotFound(t *testing.T) {
	policy := &InboundPolicy{
		Rules: []InboundRule{
			{
				Name:     "bad",
				Match:    MatchConfig{Pubkey: PubkeyMatch{Type: "whitelist", Path: "/nonexistent/trusted.txt"}},
				Services: []ServiceConfig{{Proto: "*", Port: "*"}},
				Action:   "allow",
			},
		},
	}

	_, err := NewPolicyEngine(policy)
	if err == nil {
		t.Fatal("expected error for nonexistent whitelist file")
	}
}

func TestPolicyEngine_LabelMatch(t *testing.T) {
	store := NewLabelStore()
	trustedKey := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	unknownKey := "0000000000000000000000000000000000000000000000000000000000000001"

	store.SetLabels(trustedKey, []string{"host.zigor.net/trusted", "host.zigor.net/exit-node"})

	policy := &InboundPolicy{
		Default: "deny",
		Rules: []InboundRule{
			{
				Name: "label-trusted",
				Match: MatchConfig{
					Pubkey: PubkeyMatch{Type: "any"},
					Labels: []string{"host.zigor.net/trusted"},
				},
				Services: []ServiceConfig{{Proto: "tcp", Port: "80,443"}},
				Action:   "allow",
			},
		},
	}

	pe, err := NewPolicyEngine(policy, store)
	if err != nil {
		t.Fatal(err)
	}

	// Trusted key has the label -> allow
	result := pe.Check(hexKey(trustedKey))
	if result.Action != "allow" {
		t.Errorf("trusted key: action = %q, want allow", result.Action)
	}
	if result.RuleName != "label-trusted" {
		t.Errorf("trusted key: rule = %q, want label-trusted", result.RuleName)
	}

	// Unknown key has no labels -> deny (falls through to default)
	result = pe.Check(hexKey(unknownKey))
	if result.Action != "deny" {
		t.Errorf("unknown key: action = %q, want deny", result.Action)
	}
}

func TestPolicyEngine_LabelWildcard(t *testing.T) {
	store := NewLabelStore()
	companyKey := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	store.SetLabels(companyKey, []string{"company.zigor.net/employee", "company.zigor.net/dev-team"})

	policy := &InboundPolicy{
		Default: "deny",
		Rules: []InboundRule{
			{
				Name: "company-all",
				Match: MatchConfig{
					Pubkey: PubkeyMatch{Type: "any"},
					Labels: []string{"company.zigor.net/*"},
				},
				Services: []ServiceConfig{{Proto: "*", Port: "*"}},
				Action:   "allow",
			},
		},
	}

	pe, err := NewPolicyEngine(policy, store)
	if err != nil {
		t.Fatal(err)
	}

	result := pe.Check(hexKey(companyKey))
	if result.Action != "allow" {
		t.Errorf("company key: action = %q, want allow", result.Action)
	}
}

func TestPolicyEngine_LabelAndPubkey(t *testing.T) {
	// Test that both pubkey AND label must match when both are specified
	dir := t.TempDir()
	listPath := filepath.Join(dir, "trusted.txt")
	trustedKey := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	otherKey := "0000000000000000000000000000000000000000000000000000000000000001"
	if err := os.WriteFile(listPath, []byte(trustedKey+"\n"), 0644); err != nil {
		t.Fatal(err)
	}

	store := NewLabelStore()
	// Both keys have the label, but only trustedKey is in the whitelist
	store.SetLabels(trustedKey, []string{"host.zigor.net/admin"})
	store.SetLabels(otherKey, []string{"host.zigor.net/admin"})

	policy := &InboundPolicy{
		Default: "deny",
		Rules: []InboundRule{
			{
				Name: "whitelist-plus-label",
				Match: MatchConfig{
					Pubkey: PubkeyMatch{Type: "whitelist", Path: listPath},
					Labels: []string{"host.zigor.net/admin"},
				},
				Services: []ServiceConfig{{Proto: "*", Port: "*"}},
				Action:   "allow",
			},
		},
	}

	pe, err := NewPolicyEngine(policy, store)
	if err != nil {
		t.Fatal(err)
	}

	// trustedKey: in whitelist + has label -> allow
	result := pe.Check(hexKey(trustedKey))
	if result.Action != "allow" {
		t.Errorf("trusted key: action = %q, want allow", result.Action)
	}

	// otherKey: NOT in whitelist (pubkey match fails) -> deny
	result = pe.Check(hexKey(otherKey))
	if result.Action != "deny" {
		t.Errorf("other key: action = %q, want deny (not in whitelist)", result.Action)
	}
}

func TestPolicyEngine_NoLabelStore(t *testing.T) {
	// Without a LabelStore, label rules skip (no labels to match against)
	policy := &InboundPolicy{
		Default: "deny",
		Rules: []InboundRule{
			{
				Name: "label-only",
				Match: MatchConfig{
					Pubkey: PubkeyMatch{Type: "any"},
					Labels: []string{"host.zigor.net/trusted"},
				},
				Services: []ServiceConfig{{Proto: "*", Port: "*"}},
				Action:   "allow",
			},
		},
	}

	pe, err := NewPolicyEngine(policy) // no label store
	if err != nil {
		t.Fatal(err)
	}

	result := pe.Check(hexKey("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"))
	if result.Action != "deny" {
		t.Errorf("action = %q, want deny (no label store)", result.Action)
	}
}

func TestPolicyEngine_WhitelistInvalidFormat(t *testing.T) {
	dir := t.TempDir()
	listPath := filepath.Join(dir, "bad.txt")
	// Not valid hex
	if err := os.WriteFile(listPath, []byte("not-a-hex-key\n"), 0644); err != nil {
		t.Fatal(err)
	}

	policy := &InboundPolicy{
		Rules: []InboundRule{
			{
				Name:     "bad",
				Match:    MatchConfig{Pubkey: PubkeyMatch{Type: "whitelist", Path: listPath}},
				Services: []ServiceConfig{{Proto: "*", Port: "*"}},
				Action:   "allow",
			},
		},
	}

	_, err := NewPolicyEngine(policy)
	if err == nil {
		t.Fatal("expected error for invalid whitelist format")
	}
}
