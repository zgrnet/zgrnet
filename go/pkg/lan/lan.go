// Package lan provides a composable LAN service for zgrnet.
//
// A LAN is a group of peers that share membership, labels, and events.
// The lan package exposes an HTTP handler that implements the zgrlan API:
//
//	GET    /api/lan/peers           — list online members + labels
//	POST   /api/lan/join            — join the LAN (requires authentication)
//	POST   /api/lan/leave           — leave the LAN
//	GET    /api/lan/query/:pubkey   — query a specific member
//	POST   /api/lan/labels/:pubkey  — set labels (admin only)
//	DELETE /api/lan/labels/:pubkey  — remove labels (admin only)
//	GET    /api/lan/events          — WebSocket event stream
//
// Authentication is pluggable: callers register [Authenticator] implementations
// for each supported join method (open, invite code, password, OAuth, etc.).
// The package includes built-in authenticators for common methods.
//
// Identity resolution (IP → pubkey) is injected via [IdentityFunc], so the
// package has no dependency on the host or transport layer.
package lan

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/vibing/zgrnet/pkg/noise"
)

// IdentityFunc resolves a remote IP address to its cryptographic identity.
// This is typically backed by the host's IP allocator (IP → pubkey).
// Returns the peer's public key and accumulated labels from all LANs.
type IdentityFunc func(ip net.IP) (pubkey noise.PublicKey, labels []string, err error)

// Member represents a peer that has joined the LAN.
type Member struct {
	// Pubkey is the member's Curve25519 public key (hex-encoded in JSON).
	Pubkey noise.PublicKey `json:"-"`

	// PubkeyHex is the hex-encoded public key for JSON serialization.
	PubkeyHex string `json:"pubkey"`

	// Labels are tags assigned to this member (e.g., "admin", "dev-team").
	Labels []string `json:"labels"`

	// JoinedAt is when the member joined.
	JoinedAt time.Time `json:"joined_at"`
}

// Event is a change notification pushed to WebSocket subscribers.
type Event struct {
	// Type is the event kind: "join", "leave", "labels".
	Type string `json:"type"`

	// Pubkey is the affected member (hex-encoded).
	Pubkey string `json:"pubkey"`

	// Labels is set for "labels" events (new label set).
	Labels []string `json:"labels,omitempty"`

	// Timestamp is when the event occurred.
	Timestamp time.Time `json:"timestamp"`
}

// Config holds the configuration for creating a LAN server.
type Config struct {
	// Domain is the LAN's domain (e.g., "company.zigor.net").
	Domain string

	// Description is a human-readable description of the LAN.
	Description string

	// DataDir is the directory for persistent storage (members.json, etc.).
	// If empty, the store operates in memory only.
	DataDir string

	// IdentityFn resolves IP → (pubkey, labels). Required.
	IdentityFn IdentityFunc
}

// Store persists LAN membership data to disk.
// Thread-safe for concurrent use.
type Store struct {
	mu      sync.RWMutex
	members map[noise.PublicKey]*Member
	path    string // empty = in-memory only
}

// storeFile is the JSON structure persisted to disk.
type storeFile struct {
	Members []memberJSON `json:"members"`
}

type memberJSON struct {
	Pubkey   string   `json:"pubkey"`
	Labels   []string `json:"labels"`
	JoinedAt string   `json:"joined_at"`
}

// NewStore creates a new store. If dataDir is non-empty, it loads existing
// data from dataDir/members.json and persists changes there.
func NewStore(dataDir string) (*Store, error) {
	s := &Store{
		members: make(map[noise.PublicKey]*Member),
	}

	if dataDir != "" {
		s.path = filepath.Join(dataDir, "members.json")
		if err := s.load(); err != nil && !os.IsNotExist(err) {
			return nil, fmt.Errorf("lan: load store %s: %w", s.path, err)
		}
	}

	return s, nil
}

// Add adds a member to the store. If the member already exists, this is a no-op.
// Returns true if the member was newly added.
func (s *Store) Add(pk noise.PublicKey) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.members[pk]; exists {
		return false, nil
	}

	s.members[pk] = &Member{
		Pubkey:    pk,
		PubkeyHex: pk.String(),
		Labels:    []string{},
		JoinedAt:  time.Now().UTC(),
	}

	if err := s.saveLocked(); err != nil {
		delete(s.members, pk)
		return false, err
	}

	return true, nil
}

// Remove removes a member from the store. Returns true if the member existed.
func (s *Store) Remove(pk noise.PublicKey) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	m, exists := s.members[pk]
	if !exists {
		return false, nil
	}

	delete(s.members, pk)

	if err := s.saveLocked(); err != nil {
		s.members[pk] = m // restore on save failure
		return false, err
	}

	return true, nil
}

// Get returns a member by public key. Returns nil if not found.
func (s *Store) Get(pk noise.PublicKey) *Member {
	s.mu.RLock()
	defer s.mu.RUnlock()

	m, ok := s.members[pk]
	if !ok {
		return nil
	}

	// Return a copy to avoid races.
	cp := *m
	cp.Labels = append([]string(nil), m.Labels...)
	return &cp
}

// IsMember returns true if the public key is a member.
func (s *Store) IsMember(pk noise.PublicKey) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.members[pk]
	return ok
}

// List returns all members as a slice. The returned slice is a snapshot;
// mutations to it do not affect the store.
func (s *Store) List() []*Member {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*Member, 0, len(s.members))
	for _, m := range s.members {
		cp := *m
		cp.Labels = append([]string(nil), m.Labels...)
		result = append(result, &cp)
	}
	return result
}

// SetLabels replaces the labels for the given member.
// Returns error if the pubkey is not a member.
func (s *Store) SetLabels(pk noise.PublicKey, labels []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	m, ok := s.members[pk]
	if !ok {
		return fmt.Errorf("lan: pubkey %s is not a member", pk.ShortString())
	}

	old := m.Labels
	m.Labels = append([]string(nil), labels...)

	if err := s.saveLocked(); err != nil {
		m.Labels = old // restore on save failure
		return err
	}

	return nil
}

// RemoveLabels removes specific labels from the given member.
// Returns error if the pubkey is not a member.
func (s *Store) RemoveLabels(pk noise.PublicKey, toRemove []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	m, ok := s.members[pk]
	if !ok {
		return fmt.Errorf("lan: pubkey %s is not a member", pk.ShortString())
	}

	removeSet := make(map[string]bool, len(toRemove))
	for _, l := range toRemove {
		removeSet[l] = true
	}

	old := m.Labels
	filtered := make([]string, 0, len(m.Labels))
	for _, l := range m.Labels {
		if !removeSet[l] {
			filtered = append(filtered, l)
		}
	}
	m.Labels = filtered

	if err := s.saveLocked(); err != nil {
		m.Labels = old
		return err
	}

	return nil
}

// Count returns the number of members.
func (s *Store) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.members)
}

// load reads the store from disk. Must be called before concurrent access.
func (s *Store) load() error {
	if s.path == "" {
		return nil
	}

	data, err := os.ReadFile(s.path)
	if err != nil {
		return err
	}

	var sf storeFile
	if err := json.Unmarshal(data, &sf); err != nil {
		return fmt.Errorf("lan: parse %s: %w", s.path, err)
	}

	for _, mj := range sf.Members {
		pk, err := noise.KeyFromHex(mj.Pubkey)
		if err != nil {
			continue // skip invalid entries
		}

		joinedAt, _ := time.Parse(time.RFC3339, mj.JoinedAt)
		if joinedAt.IsZero() {
			joinedAt = time.Now().UTC()
		}

		labels := mj.Labels
		if labels == nil {
			labels = []string{}
		}

		s.members[pk] = &Member{
			Pubkey:    pk,
			PubkeyHex: pk.String(),
			Labels:    labels,
			JoinedAt:  joinedAt,
		}
	}

	return nil
}

// saveLocked writes the store to disk. Caller must hold s.mu.
func (s *Store) saveLocked() error {
	if s.path == "" {
		return nil
	}

	sf := storeFile{
		Members: make([]memberJSON, 0, len(s.members)),
	}
	for _, m := range s.members {
		sf.Members = append(sf.Members, memberJSON{
			Pubkey:   m.PubkeyHex,
			Labels:   m.Labels,
			JoinedAt: m.JoinedAt.Format(time.RFC3339),
		})
	}

	data, err := json.MarshalIndent(sf, "", "  ")
	if err != nil {
		return fmt.Errorf("lan: marshal: %w", err)
	}

	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("lan: mkdir %s: %w", dir, err)
	}

	// Atomic write: write to temp file, then rename.
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return fmt.Errorf("lan: write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("lan: rename %s → %s: %w", tmp, s.path, err)
	}

	return nil
}
