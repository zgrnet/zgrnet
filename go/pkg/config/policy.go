package config

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"sync"
)

// PolicyResult is returned when checking inbound access for a peer.
type PolicyResult struct {
	// Action is "allow" or "deny".
	Action string

	// Services lists the allowed services (only meaningful when Action == "allow").
	Services []ServiceConfig

	// RuleName is the name of the matching rule, or "default" if no rule matched.
	RuleName string

	// NeedsZgrlanVerify is true when the matching rule requires zgrlan RPC verification.
	// The actual RPC is performed by the caller, not the config manager.
	NeedsZgrlanVerify bool

	// ZgrlanPeer is the zgrlan peer domain to query (when NeedsZgrlanVerify is true).
	ZgrlanPeer string
}

// PolicyEngine evaluates inbound policy rules against peer public keys and labels.
// Thread-safe for concurrent reads after Build().
type PolicyEngine struct {
	mu      sync.RWMutex
	policy  *InboundPolicy
	entries []compiledPolicyEntry

	// labelStore is optional. When set, label-based matching is enabled.
	labelStore *LabelStore
}

type compiledPolicyEntry struct {
	rule *InboundRule

	// For whitelist type: loaded pubkeys (hex -> true)
	whitelist map[string]bool
	listPath  string
}

// NewPolicyEngine creates a PolicyEngine from an InboundPolicy.
// Whitelist files are loaded eagerly. LabelStore is optional (nil = no label matching).
func NewPolicyEngine(policy *InboundPolicy, labelStore ...*LabelStore) (*PolicyEngine, error) {
	pe := &PolicyEngine{policy: policy}
	if len(labelStore) > 0 {
		pe.labelStore = labelStore[0]
	}
	if err := pe.build(); err != nil {
		return nil, err
	}
	return pe, nil
}

func (pe *PolicyEngine) build() error {
	entries := make([]compiledPolicyEntry, 0, len(pe.policy.Rules))
	for i := range pe.policy.Rules {
		rule := &pe.policy.Rules[i]
		entry := compiledPolicyEntry{rule: rule}

		if rule.Match.Pubkey.Type == "whitelist" {
			keys, err := loadPubkeyList(rule.Match.Pubkey.Path)
			if err != nil {
				return fmt.Errorf("policy: load whitelist %q: %w", rule.Match.Pubkey.Path, err)
			}
			entry.whitelist = keys
			entry.listPath = rule.Match.Pubkey.Path
		}

		entries = append(entries, entry)
	}

	pe.mu.Lock()
	pe.entries = entries
	pe.mu.Unlock()
	return nil
}

// Check evaluates the inbound policy for the given peer public key.
// The pubkey is the raw 32-byte Curve25519 public key.
func (pe *PolicyEngine) Check(pubkey [32]byte) *PolicyResult {
	pubkeyHex := hex.EncodeToString(pubkey[:])

	pe.mu.RLock()
	defer pe.mu.RUnlock()

	// Look up labels once (only if any rule uses label matching)
	var peerLabels []string
	if pe.labelStore != nil {
		peerLabels = pe.labelStore.Labels(pubkeyHex)
	}

	for i := range pe.entries {
		entry := &pe.entries[i]
		rule := entry.rule

		pubkeyMatched := false
		needsZgrlan := false
		zgrlanPeer := ""

		switch rule.Match.Pubkey.Type {
		case "any":
			pubkeyMatched = true

		case "whitelist":
			pubkeyMatched = entry.whitelist[pubkeyHex]

		case "zgrlan":
			// Can't verify locally — tell caller to do RPC
			pubkeyMatched = true
			needsZgrlan = true
			zgrlanPeer = rule.Match.Pubkey.Peer

		case "solana", "database", "http":
			// Future: external verification. For now, skip.
			continue
		}

		if !pubkeyMatched {
			continue
		}

		// If the rule has label patterns, the peer must also match at least one
		if len(rule.Match.Labels) > 0 {
			if !MatchLabels(peerLabels, rule.Match.Labels) {
				continue
			}
		}

		result := &PolicyResult{
			Action:   rule.Action,
			Services: rule.Services,
			RuleName: rule.Name,
		}
		if needsZgrlan {
			result.NeedsZgrlanVerify = true
			result.ZgrlanPeer = zgrlanPeer
		}
		return result
	}

	// No rule matched — use default
	return &PolicyResult{
		Action:   pe.defaultAction(),
		RuleName: "default",
	}
}

// Reload reloads whitelist files from disk.
func (pe *PolicyEngine) Reload() error {
	pe.mu.Lock()
	defer pe.mu.Unlock()

	for i := range pe.entries {
		entry := &pe.entries[i]
		if entry.listPath != "" {
			keys, err := loadPubkeyList(entry.listPath)
			if err != nil {
				return fmt.Errorf("policy: reload whitelist %q: %w", entry.listPath, err)
			}
			entry.whitelist = keys
		}
	}
	return nil
}

func (pe *PolicyEngine) defaultAction() string {
	if pe.policy.Default == "" {
		return "deny"
	}
	return pe.policy.Default
}

// loadPubkeyList reads a pubkey list file. Each line is a hex-encoded 32-byte key.
// Empty lines and lines starting with '#' are ignored.
func loadPubkeyList(path string) (map[string]bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	keys := make(map[string]bool)
	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.ToLower(line)
		if len(line) != 64 {
			return nil, fmt.Errorf("line %d: expected 64 hex chars, got %d", lineNum, len(line))
		}
		if _, err := hex.DecodeString(line); err != nil {
			return nil, fmt.Errorf("line %d: invalid hex: %w", lineNum, err)
		}
		keys[line] = true
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return keys, nil
}
