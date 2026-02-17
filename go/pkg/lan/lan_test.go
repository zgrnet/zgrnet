package lan

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vibing/zgrnet/pkg/noise"
)

func genKey(t *testing.T) noise.PublicKey {
	t.Helper()
	kp, err := noise.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	return kp.Public
}

// ── MemStore tests ──────────────────────────────────────────────────────────

func TestMemStore_AddAndGet(t *testing.T) {
	s := NewMemStore()
	pk := genKey(t)

	added, err := s.Add(pk)
	if err != nil {
		t.Fatal(err)
	}
	if !added {
		t.Fatal("expected member to be added")
	}

	added, err = s.Add(pk)
	if err != nil {
		t.Fatal(err)
	}
	if added {
		t.Fatal("expected no-op on duplicate add")
	}

	m := s.Get(pk)
	if m == nil {
		t.Fatal("expected member, got nil")
	}
	if m.PubkeyHex != pk.String() {
		t.Fatalf("pubkey mismatch: got %s, want %s", m.PubkeyHex, pk.String())
	}
	if len(m.Labels) != 0 {
		t.Fatalf("expected empty labels, got %v", m.Labels)
	}
	if s.Count() != 1 {
		t.Fatalf("expected count 1, got %d", s.Count())
	}
}

func TestMemStore_Remove(t *testing.T) {
	s := NewMemStore()
	pk := genKey(t)

	s.Add(pk)

	removed, err := s.Remove(pk)
	if err != nil {
		t.Fatal(err)
	}
	if !removed {
		t.Fatal("expected member to be removed")
	}

	removed, err = s.Remove(pk)
	if err != nil {
		t.Fatal(err)
	}
	if removed {
		t.Fatal("expected false on double remove")
	}
	if s.Count() != 0 {
		t.Fatalf("expected count 0, got %d", s.Count())
	}
}

func TestMemStore_Labels(t *testing.T) {
	s := NewMemStore()
	pk := genKey(t)

	s.Add(pk)

	if err := s.SetLabels(pk, []string{"admin", "dev"}); err != nil {
		t.Fatal(err)
	}

	m := s.Get(pk)
	if len(m.Labels) != 2 || m.Labels[0] != "admin" || m.Labels[1] != "dev" {
		t.Fatalf("expected [admin dev], got %v", m.Labels)
	}

	if err := s.RemoveLabels(pk, []string{"admin"}); err != nil {
		t.Fatal(err)
	}

	m = s.Get(pk)
	if len(m.Labels) != 1 || m.Labels[0] != "dev" {
		t.Fatalf("expected [dev], got %v", m.Labels)
	}

	unknown := genKey(t)
	if err := s.SetLabels(unknown, []string{"x"}); err == nil {
		t.Fatal("expected error setting labels on non-member")
	}
}

func TestMemStore_List(t *testing.T) {
	s := NewMemStore()
	pk1, pk2, pk3 := genKey(t), genKey(t), genKey(t)

	s.Add(pk1)
	s.Add(pk2)
	s.Add(pk3)

	list := s.List()
	if len(list) != 3 {
		t.Fatalf("expected 3 members, got %d", len(list))
	}
}

func TestMemStore_IsMember(t *testing.T) {
	s := NewMemStore()
	pk := genKey(t)

	if s.IsMember(pk) {
		t.Fatal("expected not a member before add")
	}
	s.Add(pk)
	if !s.IsMember(pk) {
		t.Fatal("expected member after add")
	}
	s.Remove(pk)
	if s.IsMember(pk) {
		t.Fatal("expected not a member after remove")
	}
}

// ── FileStore tests ─────────────────────────────────────────────────────────

func TestFileStore_Persistence(t *testing.T) {
	dir := t.TempDir()

	s1, err := NewFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	pk := genKey(t)
	s1.Add(pk)
	s1.SetLabels(pk, []string{"admin", "dev"})

	path := filepath.Join(dir, "members.json")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected members.json to exist: %v", err)
	}

	s2, err := NewFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	if s2.Count() != 1 {
		t.Fatalf("expected 1 member after reload, got %d", s2.Count())
	}

	m := s2.Get(pk)
	if m == nil {
		t.Fatal("expected member after reload")
	}
	if len(m.Labels) != 2 || m.Labels[0] != "admin" {
		t.Fatalf("expected labels [admin dev] after reload, got %v", m.Labels)
	}
}

// ── Store interface compliance ──────────────────────────────────────────────

// Compile-time check that both implementations satisfy the Store interface.
var (
	_ Store = (*MemStore)(nil)
	_ Store = (*FileStore)(nil)
)
