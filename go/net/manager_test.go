package net

import (
	"sync"
	"testing"
	"time"

	"github.com/vibing/zgrnet/noise"
)

func TestSessionManager_CreateSession(t *testing.T) {
	m := NewSessionManager()

	pk := noise.PublicKey{1, 2, 3}
	sendKey := noise.Hash([]byte("send"))
	recvKey := noise.Hash([]byte("recv"))

	session, err := m.CreateSession(pk, sendKey, recvKey)
	if err != nil {
		t.Fatalf("create session failed: %v", err)
	}

	if session == nil {
		t.Fatal("session should not be nil")
	}

	if session.LocalIndex() == 0 {
		t.Error("local index should not be 0")
	}

	if m.Count() != 1 {
		t.Errorf("count should be 1, got %d", m.Count())
	}
}

func TestSessionManager_GetByIndex(t *testing.T) {
	m := NewSessionManager()

	pk := noise.PublicKey{1, 2, 3}
	session, _ := m.CreateSession(pk, noise.Key{}, noise.Key{})

	// Should find by index
	found := m.GetByIndex(session.LocalIndex())
	if found != session {
		t.Error("should find session by index")
	}

	// Should not find unknown index
	notFound := m.GetByIndex(99999)
	if notFound != nil {
		t.Error("should not find unknown index")
	}
}

func TestSessionManager_GetByPubkey(t *testing.T) {
	m := NewSessionManager()

	pk := noise.PublicKey{1, 2, 3}
	session, _ := m.CreateSession(pk, noise.Key{}, noise.Key{})

	// Should find by pubkey
	found := m.GetByPubkey(pk)
	if found != session {
		t.Error("should find session by pubkey")
	}

	// Should not find unknown pubkey
	notFound := m.GetByPubkey(noise.PublicKey{9, 9, 9})
	if notFound != nil {
		t.Error("should not find unknown pubkey")
	}
}

func TestSessionManager_RemoveSession(t *testing.T) {
	m := NewSessionManager()

	pk := noise.PublicKey{1, 2, 3}
	session, _ := m.CreateSession(pk, noise.Key{}, noise.Key{})
	index := session.LocalIndex()

	m.RemoveSession(index)

	if m.GetByIndex(index) != nil {
		t.Error("session should be removed by index")
	}
	if m.GetByPubkey(pk) != nil {
		t.Error("session should be removed by pubkey")
	}
	if m.Count() != 0 {
		t.Error("count should be 0")
	}
}

func TestSessionManager_RemoveByPubkey(t *testing.T) {
	m := NewSessionManager()

	pk := noise.PublicKey{1, 2, 3}
	session, _ := m.CreateSession(pk, noise.Key{}, noise.Key{})
	index := session.LocalIndex()

	m.RemoveByPubkey(pk)

	if m.GetByIndex(index) != nil {
		t.Error("session should be removed by index")
	}
	if m.GetByPubkey(pk) != nil {
		t.Error("session should be removed by pubkey")
	}
}

func TestSessionManager_ReplaceExisting(t *testing.T) {
	m := NewSessionManager()

	pk := noise.PublicKey{1, 2, 3}

	// Create first session
	session1, _ := m.CreateSession(pk, noise.Key{}, noise.Key{})
	index1 := session1.LocalIndex()

	// Create second session for same peer
	session2, _ := m.CreateSession(pk, noise.Key{1}, noise.Key{1})
	index2 := session2.LocalIndex()

	// First session should be gone
	if m.GetByIndex(index1) != nil {
		t.Error("first session should be removed")
	}

	// Second session should exist
	if m.GetByIndex(index2) != session2 {
		t.Error("second session should exist")
	}

	// Pubkey should point to new session
	if m.GetByPubkey(pk) != session2 {
		t.Error("pubkey should point to new session")
	}

	if m.Count() != 1 {
		t.Error("count should be 1")
	}
}

func TestSessionManager_MultiplePeers(t *testing.T) {
	m := NewSessionManager()

	peers := []noise.PublicKey{
		{1},
		{2},
		{3},
		{4},
		{5},
	}

	sessions := make([]*noise.Session, len(peers))
	for i, pk := range peers {
		s, _ := m.CreateSession(pk, noise.Key{byte(i)}, noise.Key{byte(i)})
		sessions[i] = s
	}

	if m.Count() != len(peers) {
		t.Errorf("count should be %d, got %d", len(peers), m.Count())
	}

	// All should be findable
	for i, pk := range peers {
		if m.GetByPubkey(pk) != sessions[i] {
			t.Errorf("peer %d not found by pubkey", i)
		}
		if m.GetByIndex(sessions[i].LocalIndex()) != sessions[i] {
			t.Errorf("peer %d not found by index", i)
		}
	}
}

func TestSessionManager_ExpireSessions(t *testing.T) {
	m := NewSessionManager()

	pk1 := noise.PublicKey{1}
	pk2 := noise.PublicKey{2}

	session1, _ := m.CreateSession(pk1, noise.Key{}, noise.Key{})
	session2, _ := m.CreateSession(pk2, noise.Key{}, noise.Key{})

	// Expire session1
	session1.Expire()

	removed := m.ExpireSessions()
	if removed != 1 {
		t.Errorf("should remove 1 session, removed %d", removed)
	}

	if m.GetByPubkey(pk1) != nil {
		t.Error("expired session should be removed")
	}
	if m.GetByPubkey(pk2) != session2 {
		t.Error("active session should still exist")
	}
}

func TestSessionManager_Sessions(t *testing.T) {
	m := NewSessionManager()

	for i := 0; i < 5; i++ {
		pk := noise.PublicKey{byte(i)}
		m.CreateSession(pk, noise.Key{}, noise.Key{})
	}

	sessions := m.Sessions()
	if len(sessions) != 5 {
		t.Errorf("should have 5 sessions, got %d", len(sessions))
	}
}

func TestSessionManager_ForEach(t *testing.T) {
	m := NewSessionManager()

	for i := 0; i < 5; i++ {
		pk := noise.PublicKey{byte(i)}
		m.CreateSession(pk, noise.Key{}, noise.Key{})
	}

	count := 0
	m.ForEach(func(s *noise.Session) {
		count++
	})

	if count != 5 {
		t.Errorf("should iterate 5 sessions, got %d", count)
	}
}

func TestSessionManager_Clear(t *testing.T) {
	m := NewSessionManager()

	for i := 0; i < 5; i++ {
		pk := noise.PublicKey{byte(i)}
		m.CreateSession(pk, noise.Key{}, noise.Key{})
	}

	m.Clear()

	if m.Count() != 0 {
		t.Errorf("count should be 0 after clear, got %d", m.Count())
	}
}

func TestSessionManager_RegisterSession(t *testing.T) {
	m := NewSessionManager()

	// Create a session externally
	session, _ := noise.NewSession(noise.SessionConfig{
		LocalIndex: 12345,
		SendKey:    noise.Key{},
		RecvKey:    noise.Key{},
		RemotePK:   noise.PublicKey{1, 2, 3},
	})

	err := m.RegisterSession(session)
	if err != nil {
		t.Fatalf("register failed: %v", err)
	}

	// Should be findable
	if m.GetByIndex(12345) != session {
		t.Error("session not found by index")
	}
	if m.GetByPubkey(noise.PublicKey{1, 2, 3}) != session {
		t.Error("session not found by pubkey")
	}
}

func TestSessionManager_RegisterSession_IndexCollision(t *testing.T) {
	m := NewSessionManager()

	// Create first session
	pk1 := noise.PublicKey{1}
	session1, _ := m.CreateSession(pk1, noise.Key{}, noise.Key{})

	// Try to register a session with same index
	session2, _ := noise.NewSession(noise.SessionConfig{
		LocalIndex: session1.LocalIndex(), // Collision!
		SendKey:    noise.Key{},
		RecvKey:    noise.Key{},
		RemotePK:   noise.PublicKey{2},
	})

	err := m.RegisterSession(session2)
	if err != ErrIndexInUse {
		t.Errorf("should get index collision error, got: %v", err)
	}
}

func TestSessionManager_Concurrent(t *testing.T) {
	m := NewSessionManager()
	var wg sync.WaitGroup

	// Concurrent creates
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			pk := noise.PublicKey{byte(id)}
			m.CreateSession(pk, noise.Key{}, noise.Key{})
		}(i)
	}

	wg.Wait()

	if m.Count() != 100 {
		t.Errorf("should have 100 sessions, got %d", m.Count())
	}

	// Concurrent reads
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			pk := noise.PublicKey{byte(id)}
			m.GetByPubkey(pk)
		}(i)
	}

	wg.Wait()

	// Concurrent removes
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			pk := noise.PublicKey{byte(id)}
			m.RemoveByPubkey(pk)
		}(i)
	}

	wg.Wait()

	if m.Count() != 50 {
		t.Errorf("should have 50 sessions after removals, got %d", m.Count())
	}
}

func TestSessionManager_ExpiryWorker(t *testing.T) {
	m := NewSessionManager()

	pk := noise.PublicKey{1}
	session, _ := m.CreateSession(pk, noise.Key{}, noise.Key{})
	session.Expire()

	// Start expiry worker
	stop := m.StartExpiryWorker(10 * time.Millisecond)
	defer stop()

	// Wait for expiry
	time.Sleep(50 * time.Millisecond)

	if m.Count() != 0 {
		t.Error("expired session should be removed by worker")
	}
}

func TestSessionManager_IndexWrap(t *testing.T) {
	m := NewSessionManager()
	m.nextIndex = ^uint32(0) - 5 // Near max

	// Create several sessions to trigger wrap
	for i := 0; i < 10; i++ {
		pk := noise.PublicKey{byte(i)}
		_, err := m.CreateSession(pk, noise.Key{}, noise.Key{})
		if err != nil {
			t.Fatalf("create session %d failed: %v", i, err)
		}
	}

	if m.Count() != 10 {
		t.Errorf("should have 10 sessions, got %d", m.Count())
	}
}

func BenchmarkSessionManager_CreateSession(b *testing.B) {
	m := NewSessionManager()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		pk := noise.PublicKey{byte(i >> 24), byte(i >> 16), byte(i >> 8), byte(i)}
		m.CreateSession(pk, noise.Key{}, noise.Key{})
	}
}

func BenchmarkSessionManager_GetByIndex(b *testing.B) {
	m := NewSessionManager()
	var indices []uint32

	// Pre-populate
	for i := 0; i < 1000; i++ {
		pk := noise.PublicKey{byte(i >> 8), byte(i)}
		s, _ := m.CreateSession(pk, noise.Key{}, noise.Key{})
		indices = append(indices, s.LocalIndex())
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.GetByIndex(indices[i%len(indices)])
	}
}

func BenchmarkSessionManager_GetByPubkey(b *testing.B) {
	m := NewSessionManager()
	var pks []noise.PublicKey

	// Pre-populate
	for i := 0; i < 1000; i++ {
		pk := noise.PublicKey{byte(i >> 8), byte(i)}
		m.CreateSession(pk, noise.Key{}, noise.Key{})
		pks = append(pks, pk)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.GetByPubkey(pks[i%len(pks)])
	}
}
