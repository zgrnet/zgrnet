package lan

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/vibing/zgrnet/pkg/noise"
)

// ── MemStore ────────────────────────────────────────────────────────────────

// MemStore is an in-memory Store implementation. Fast, no I/O, but data is
// lost when the process exits. Good for testing and ephemeral LANs.
type MemStore struct {
	mu      sync.RWMutex
	members map[noise.PublicKey]*Member
}

// NewMemStore creates an empty in-memory store.
func NewMemStore() *MemStore {
	return &MemStore{
		members: make(map[noise.PublicKey]*Member),
	}
}

func (s *MemStore) Add(pk noise.PublicKey) (bool, error) {
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
	return true, nil
}

func (s *MemStore) Remove(pk noise.PublicKey) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.members[pk]; !exists {
		return false, nil
	}
	delete(s.members, pk)
	return true, nil
}

func (s *MemStore) Get(pk noise.PublicKey) *Member {
	s.mu.RLock()
	defer s.mu.RUnlock()

	m, ok := s.members[pk]
	if !ok {
		return nil
	}
	cp := *m
	cp.Labels = append([]string(nil), m.Labels...)
	return &cp
}

func (s *MemStore) IsMember(pk noise.PublicKey) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.members[pk]
	return ok
}

func (s *MemStore) List() []*Member {
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

func (s *MemStore) SetLabels(pk noise.PublicKey, labels []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	m, ok := s.members[pk]
	if !ok {
		return fmt.Errorf("lan: pubkey %s is not a member", pk.ShortString())
	}
	m.Labels = append([]string(nil), labels...)
	return nil
}

func (s *MemStore) RemoveLabels(pk noise.PublicKey, toRemove []string) error {
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

	filtered := make([]string, 0, len(m.Labels))
	for _, l := range m.Labels {
		if !removeSet[l] {
			filtered = append(filtered, l)
		}
	}
	m.Labels = filtered
	return nil
}

func (s *MemStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.members)
}

// ── FileStore ───────────────────────────────────────────────────────────────

// FileStore wraps a MemStore and persists every mutation to a JSON file.
// Atomic writes (tmp + rename) prevent corruption on crash.
type FileStore struct {
	mem  *MemStore
	path string
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

// NewFileStore creates a file-backed store. Loads existing data from
// dataDir/members.json if it exists.
func NewFileStore(dataDir string) (*FileStore, error) {
	mem := NewMemStore()
	path := filepath.Join(dataDir, "members.json")

	fs := &FileStore{mem: mem, path: path}
	if err := fs.load(); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("lan: load store %s: %w", path, err)
	}
	return fs, nil
}

func (fs *FileStore) Add(pk noise.PublicKey) (bool, error) {
	added, err := fs.mem.Add(pk)
	if err != nil || !added {
		return added, err
	}
	if err := fs.save(); err != nil {
		fs.mem.Remove(pk) // rollback
		return false, err
	}
	return true, nil
}

func (fs *FileStore) Remove(pk noise.PublicKey) (bool, error) {
	m := fs.mem.Get(pk) // snapshot before remove
	removed, err := fs.mem.Remove(pk)
	if err != nil || !removed {
		return removed, err
	}
	if err := fs.save(); err != nil {
		if m != nil {
			fs.mem.Add(pk) // rollback
			fs.mem.SetLabels(pk, m.Labels)
		}
		return false, err
	}
	return true, nil
}

func (fs *FileStore) Get(pk noise.PublicKey) *Member        { return fs.mem.Get(pk) }
func (fs *FileStore) IsMember(pk noise.PublicKey) bool       { return fs.mem.IsMember(pk) }
func (fs *FileStore) List() []*Member                        { return fs.mem.List() }
func (fs *FileStore) Count() int                             { return fs.mem.Count() }

func (fs *FileStore) SetLabels(pk noise.PublicKey, labels []string) error {
	old := fs.mem.Get(pk)
	if err := fs.mem.SetLabels(pk, labels); err != nil {
		return err
	}
	if err := fs.save(); err != nil {
		if old != nil {
			fs.mem.SetLabels(pk, old.Labels) // rollback
		}
		return err
	}
	return nil
}

func (fs *FileStore) RemoveLabels(pk noise.PublicKey, toRemove []string) error {
	old := fs.mem.Get(pk)
	if err := fs.mem.RemoveLabels(pk, toRemove); err != nil {
		return err
	}
	if err := fs.save(); err != nil {
		if old != nil {
			fs.mem.SetLabels(pk, old.Labels) // rollback
		}
		return err
	}
	return nil
}

func (fs *FileStore) load() error {
	data, err := os.ReadFile(fs.path)
	if err != nil {
		return err
	}

	var sf storeFile
	if err := json.Unmarshal(data, &sf); err != nil {
		return fmt.Errorf("lan: parse %s: %w", fs.path, err)
	}

	for _, mj := range sf.Members {
		pk, err := noise.KeyFromHex(mj.Pubkey)
		if err != nil {
			continue
		}
		fs.mem.Add(pk)

		joinedAt, _ := time.Parse(time.RFC3339, mj.JoinedAt)
		if joinedAt.IsZero() {
			joinedAt = time.Now().UTC()
		}

		labels := mj.Labels
		if labels == nil {
			labels = []string{}
		}
		fs.mem.SetLabels(pk, labels)

		// Set joined_at directly (needs lock).
		fs.mem.mu.Lock()
		if m, ok := fs.mem.members[pk]; ok {
			m.JoinedAt = joinedAt
		}
		fs.mem.mu.Unlock()
	}

	return nil
}

func (fs *FileStore) save() error {
	fs.mem.mu.RLock()
	sf := storeFile{
		Members: make([]memberJSON, 0, len(fs.mem.members)),
	}
	for _, m := range fs.mem.members {
		sf.Members = append(sf.Members, memberJSON{
			Pubkey:   m.PubkeyHex,
			Labels:   m.Labels,
			JoinedAt: m.JoinedAt.Format(time.RFC3339),
		})
	}
	fs.mem.mu.RUnlock()

	data, err := json.MarshalIndent(sf, "", "  ")
	if err != nil {
		return fmt.Errorf("lan: marshal: %w", err)
	}

	dir := filepath.Dir(fs.path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("lan: mkdir %s: %w", dir, err)
	}

	tmp := fs.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return fmt.Errorf("lan: write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, fs.path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("lan: rename %s → %s: %w", tmp, fs.path, err)
	}

	return nil
}
