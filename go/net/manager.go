package net

import (
	"errors"
	"sync"
	"time"

	"github.com/vibing/zgrnet/noise"
)

// SessionManager manages multiple sessions with different peers.
// It provides lookup by local index and by remote public key.
type SessionManager struct {
	mu sync.RWMutex

	// Sessions indexed by local index
	byIndex map[uint32]*noise.Session

	// Sessions indexed by remote public key
	byPubkey map[noise.PublicKey]*noise.Session

	// Index allocator
	nextIndex uint32
}

// NewSessionManager creates a new session manager.
func NewSessionManager() *SessionManager {
	return &SessionManager{
		byIndex:   make(map[uint32]*noise.Session),
		byPubkey:  make(map[noise.PublicKey]*noise.Session),
		nextIndex: 1, // Start from 1, 0 is reserved
	}
}

// CreateSession creates and registers a new session.
// If a session already exists for the given public key, it is replaced.
func (m *SessionManager) CreateSession(remotePK noise.PublicKey, sendKey, recvKey noise.Key) (*noise.Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Generate a unique local index
	localIndex := m.allocateIndex()
	if localIndex == 0 {
		return nil, ErrNoFreeIndex
	}

	// Create the session
	session, err := noise.NewSession(noise.SessionConfig{
		LocalIndex: localIndex,
		SendKey:    sendKey,
		RecvKey:    recvKey,
		RemotePK:   remotePK,
	})
	if err != nil {
		return nil, err
	}

	// Remove any existing session for this peer
	if existing, ok := m.byPubkey[remotePK]; ok {
		delete(m.byIndex, existing.LocalIndex())
	}

	// Register the new session
	m.byIndex[localIndex] = session
	m.byPubkey[remotePK] = session

	return session, nil
}

// RegisterSession registers an externally created session.
// This is useful when the handshake is performed separately.
func (m *SessionManager) RegisterSession(session *noise.Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	localIndex := session.LocalIndex()
	remotePK := session.RemotePublicKey()

	// Check for index collision
	if _, exists := m.byIndex[localIndex]; exists {
		return ErrIndexInUse
	}

	// Remove any existing session for this peer
	if existing, ok := m.byPubkey[remotePK]; ok {
		delete(m.byIndex, existing.LocalIndex())
	}

	// Register
	m.byIndex[localIndex] = session
	m.byPubkey[remotePK] = session

	return nil
}

// GetByIndex retrieves a session by its local index.
// Returns nil if not found.
func (m *SessionManager) GetByIndex(index uint32) *noise.Session {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.byIndex[index]
}

// GetByPubkey retrieves a session by the remote peer's public key.
// Returns nil if not found.
func (m *SessionManager) GetByPubkey(pk noise.PublicKey) *noise.Session {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.byPubkey[pk]
}

// RemoveSession removes a session by its local index.
func (m *SessionManager) RemoveSession(index uint32) {
	m.mu.Lock()
	defer m.mu.Unlock()

	session, ok := m.byIndex[index]
	if !ok {
		return
	}

	delete(m.byIndex, index)
	delete(m.byPubkey, session.RemotePublicKey())
}

// RemoveByPubkey removes a session by the remote peer's public key.
func (m *SessionManager) RemoveByPubkey(pk noise.PublicKey) {
	m.mu.Lock()
	defer m.mu.Unlock()

	session, ok := m.byPubkey[pk]
	if !ok {
		return
	}

	delete(m.byIndex, session.LocalIndex())
	delete(m.byPubkey, pk)
}

// ExpireSessions removes all expired sessions.
// Returns the number of sessions removed.
func (m *SessionManager) ExpireSessions() int {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Store session pointers directly to avoid second lookup
	var expired []*noise.Session
	for _, session := range m.byIndex {
		if session.IsExpired() {
			expired = append(expired, session)
		}
	}

	for _, session := range expired {
		delete(m.byIndex, session.LocalIndex())
		delete(m.byPubkey, session.RemotePublicKey())
	}

	return len(expired)
}

// Count returns the number of active sessions.
func (m *SessionManager) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.byIndex)
}

// Sessions returns a snapshot of all sessions.
// The returned slice is safe to iterate while the manager is modified.
func (m *SessionManager) Sessions() []*noise.Session {
	m.mu.RLock()
	defer m.mu.RUnlock()

	sessions := make([]*noise.Session, 0, len(m.byIndex))
	for _, session := range m.byIndex {
		sessions = append(sessions, session)
	}
	return sessions
}

// ForEach iterates over all sessions with a callback.
// The callback should not modify the manager.
func (m *SessionManager) ForEach(fn func(*noise.Session)) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, session := range m.byIndex {
		fn(session)
	}
}

// Clear removes all sessions.
func (m *SessionManager) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.byIndex = make(map[uint32]*noise.Session)
	m.byPubkey = make(map[noise.PublicKey]*noise.Session)
}

// allocateIndex generates a unique session index.
// Must be called with mu held.
// Returns 0 if no free index is available (extremely unlikely).
func (m *SessionManager) allocateIndex() uint32 {
	startIndex := m.nextIndex
	for {
		index := m.nextIndex
		m.nextIndex++
		if m.nextIndex == 0 {
			m.nextIndex = 1 // Wrap around, skip 0
		}

		// Check if index is in use
		if _, exists := m.byIndex[index]; !exists {
			return index
		}

		// Check if we've wrapped around completely
		if m.nextIndex == startIndex {
			return 0 // No free index available
		}
	}
}

// StartExpiryWorker starts a background goroutine that periodically
// removes expired sessions. Returns a stop function.
func (m *SessionManager) StartExpiryWorker(interval time.Duration) func() {
	stop := make(chan struct{})
	done := make(chan struct{})

	go func() {
		defer close(done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				m.ExpireSessions()
			case <-stop:
				return
			}
		}
	}()

	return func() {
		close(stop)
		<-done
	}
}

// Errors for SessionManager
var (
	ErrIndexInUse  = errors.New("net: session index already in use")
	ErrNoFreeIndex = errors.New("net: no free session index available")
)
