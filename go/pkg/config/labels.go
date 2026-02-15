package config

import (
	"strings"
	"sync"
)

// LabelStore manages the mapping from public keys (hex-encoded) to labels.
// Labels come from two sources:
//   - Host LAN labels: from config peers (e.g., "host.zigor.net/trusted")
//   - Remote LAN labels: from zgrlan API (e.g., "company.zigor.net/employee")
//
// Thread-safe for concurrent reads and writes.
type LabelStore struct {
	mu     sync.RWMutex
	labels map[string][]string // pubkey hex -> sorted labels
}

// NewLabelStore creates an empty LabelStore.
func NewLabelStore() *LabelStore {
	return &LabelStore{
		labels: make(map[string][]string),
	}
}

// Labels returns all labels for the given pubkey (hex-encoded, lowercase).
// Returns nil if the pubkey has no labels.
// The returned slice is a copy — safe to use after the lock is released.
func (s *LabelStore) Labels(pubkeyHex string) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	src := s.labels[pubkeyHex]
	if len(src) == 0 {
		return nil
	}
	dst := make([]string, len(src))
	copy(dst, src)
	return dst
}

// AddLabels adds labels to the given pubkey. Duplicates are ignored.
func (s *LabelStore) AddLabels(pubkeyHex string, labels []string) {
	if len(labels) == 0 {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	existing := s.labels[pubkeyHex]
	set := make(map[string]bool, len(existing))
	for _, l := range existing {
		set[l] = true
	}
	for _, l := range labels {
		if !set[l] {
			existing = append(existing, l)
			set[l] = true
		}
	}
	s.labels[pubkeyHex] = existing
}

// SetLabels replaces all labels for the given pubkey.
func (s *LabelStore) SetLabels(pubkeyHex string, labels []string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(labels) == 0 {
		delete(s.labels, pubkeyHex)
		return
	}
	dst := make([]string, len(labels))
	copy(dst, labels)
	s.labels[pubkeyHex] = dst
}

// RemoveLabels removes all labels for the given pubkey that belong to the
// specified LAN domain prefix. For example, RemoveLabels(pk, "company.zigor.net")
// removes all labels starting with "company.zigor.net/".
func (s *LabelStore) RemoveLabels(pubkeyHex string, lanDomain string) {
	prefix := lanDomain + "/"

	s.mu.Lock()
	defer s.mu.Unlock()

	existing := s.labels[pubkeyHex]
	if len(existing) == 0 {
		return
	}

	filtered := existing[:0]
	for _, l := range existing {
		if !strings.HasPrefix(l, prefix) {
			filtered = append(filtered, l)
		}
	}

	if len(filtered) == 0 {
		delete(s.labels, pubkeyHex)
	} else {
		s.labels[pubkeyHex] = filtered
	}
}

// RemovePeer removes all labels for the given pubkey.
func (s *LabelStore) RemovePeer(pubkeyHex string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.labels, pubkeyHex)
}

// LoadFromConfig populates the store with labels from config peers.
// Each peer domain is mapped to its configured labels.
// Existing labels from other sources (e.g., remote LANs) are preserved.
func (s *LabelStore) LoadFromConfig(peers map[string]PeerConfig) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Extract pubkey hex from each peer domain and set labels
	for domain, peer := range peers {
		pubkeyHex := pubkeyHexFromDomain(domain)
		if pubkeyHex == "" {
			continue
		}
		// Remove existing host lan labels, keep remote lan labels
		existing := s.labels[pubkeyHex]
		var kept []string
		for _, l := range existing {
			if !strings.HasPrefix(l, "host.zigor.net/") {
				kept = append(kept, l)
			}
		}
		// Add config labels (with dedup against kept remote labels)
		set := make(map[string]bool, len(kept))
		for _, l := range kept {
			set[l] = true
		}
		for _, l := range peer.Labels {
			if !set[l] {
				kept = append(kept, l)
				set[l] = true
			}
		}
		if len(kept) == 0 {
			delete(s.labels, pubkeyHex)
		} else {
			s.labels[pubkeyHex] = kept
		}
	}
}

// Count returns the number of pubkeys with labels.
func (s *LabelStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.labels)
}

// MatchLabel checks if any of the peer's labels match a label pattern.
// Supports:
//   - Exact match: "host.zigor.net/trusted"
//   - Wildcard match: "company.zigor.net/*" (matches any label under that domain)
func MatchLabel(peerLabels []string, pattern string) bool {
	if strings.HasSuffix(pattern, "/*") && len(pattern) > 2 {
		prefix := pattern[:len(pattern)-1] // "company.zigor.net/" from "company.zigor.net/*"
		for _, l := range peerLabels {
			if strings.HasPrefix(l, prefix) {
				return true
			}
		}
		return false
	}

	// Exact match
	for _, l := range peerLabels {
		if l == pattern {
			return true
		}
	}
	return false
}

// MatchLabels checks if any of the peer's labels match any of the patterns.
// Returns true if at least one pattern matches.
func MatchLabels(peerLabels []string, patterns []string) bool {
	for _, p := range patterns {
		if MatchLabel(peerLabels, p) {
			return true
		}
	}
	return false
}

// pubkeyHexFromDomain extracts the hex pubkey from a peer domain.
// Format: "{hex}.zigor.net" -> lowercase hex string.
// Returns empty string if the domain is not a valid peer domain.
func pubkeyHexFromDomain(domain string) string {
	if !strings.HasSuffix(domain, ".zigor.net") {
		return ""
	}
	prefix := strings.TrimSuffix(domain, ".zigor.net")
	prefix = strings.ToLower(prefix)
	// Validate hex
	for _, c := range prefix {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return ""
		}
	}
	if len(prefix) == 0 || len(prefix) > 64 {
		return ""
	}
	return prefix
}
