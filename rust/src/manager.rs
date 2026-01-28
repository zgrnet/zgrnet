//! Session manager for multiple peers.

use crate::keypair::Key;
use crate::session::{Session, SessionConfig};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;

/// Manages multiple sessions with different peers.
pub struct SessionManager {
    inner: RwLock<SessionManagerInner>,
}

struct SessionManagerInner {
    by_index: HashMap<u32, Arc<Session>>,
    by_pubkey: HashMap<Key, Arc<Session>>,
    next_index: u32,
}

impl SessionManager {
    /// Creates a new session manager.
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(SessionManagerInner {
                by_index: HashMap::new(),
                by_pubkey: HashMap::new(),
                next_index: 1,
            }),
        }
    }

    /// Creates and registers a new session.
    pub fn create_session(
        &self,
        remote_pk: Key,
        send_key: Key,
        recv_key: Key,
    ) -> Arc<Session> {
        let mut inner = self.inner.write().unwrap();

        let local_index = Self::allocate_index(&mut inner);

        let session = Arc::new(Session::new(SessionConfig {
            local_index,
            remote_index: 0,
            send_key,
            recv_key,
            remote_pk: remote_pk.clone(),
        }));

        // Remove existing session for this peer
        if let Some(existing) = inner.by_pubkey.remove(&remote_pk) {
            inner.by_index.remove(&existing.local_index());
        }

        inner.by_index.insert(local_index, session.clone());
        inner.by_pubkey.insert(remote_pk, session.clone());

        session
    }

    /// Registers an externally created session.
    pub fn register_session(&self, session: Arc<Session>) -> Result<(), ManagerError> {
        let mut inner = self.inner.write().unwrap();

        let local_index = session.local_index();
        let remote_pk = session.remote_pk().clone();

        if inner.by_index.contains_key(&local_index) {
            return Err(ManagerError::IndexInUse);
        }

        // Remove existing session for this peer
        if let Some(existing) = inner.by_pubkey.remove(&remote_pk) {
            inner.by_index.remove(&existing.local_index());
        }

        inner.by_index.insert(local_index, session.clone());
        inner.by_pubkey.insert(remote_pk, session);

        Ok(())
    }

    /// Gets a session by local index.
    pub fn get_by_index(&self, index: u32) -> Option<Arc<Session>> {
        self.inner.read().unwrap().by_index.get(&index).cloned()
    }

    /// Gets a session by remote public key.
    pub fn get_by_pubkey(&self, pk: &Key) -> Option<Arc<Session>> {
        self.inner.read().unwrap().by_pubkey.get(pk).cloned()
    }

    /// Removes a session by local index.
    pub fn remove_session(&self, index: u32) {
        let mut inner = self.inner.write().unwrap();
        if let Some(session) = inner.by_index.remove(&index) {
            inner.by_pubkey.remove(session.remote_pk());
        }
    }

    /// Removes a session by remote public key.
    pub fn remove_by_pubkey(&self, pk: &Key) {
        let mut inner = self.inner.write().unwrap();
        if let Some(session) = inner.by_pubkey.remove(pk) {
            inner.by_index.remove(&session.local_index());
        }
    }

    /// Removes all expired sessions.
    /// Returns the number of sessions removed.
    pub fn expire_sessions(&self) -> usize {
        let mut inner = self.inner.write().unwrap();
        
        let expired: Vec<u32> = inner
            .by_index
            .iter()
            .filter(|(_, s)| s.is_expired())
            .map(|(idx, _)| *idx)
            .collect();

        for index in &expired {
            if let Some(session) = inner.by_index.remove(index) {
                inner.by_pubkey.remove(session.remote_pk());
            }
        }

        expired.len()
    }

    /// Returns the number of sessions.
    pub fn count(&self) -> usize {
        self.inner.read().unwrap().by_index.len()
    }

    /// Returns all sessions.
    pub fn sessions(&self) -> Vec<Arc<Session>> {
        self.inner.read().unwrap().by_index.values().cloned().collect()
    }

    /// Iterates over all sessions.
    pub fn for_each<F>(&self, f: F)
    where
        F: FnMut(&Arc<Session>),
    {
        self.inner.read().unwrap().by_index.values().for_each(f);
    }

    /// Clears all sessions.
    pub fn clear(&self) {
        let mut inner = self.inner.write().unwrap();
        inner.by_index.clear();
        inner.by_pubkey.clear();
    }

    fn allocate_index(inner: &mut SessionManagerInner) -> u32 {
        loop {
            let index = inner.next_index;
            inner.next_index = inner.next_index.wrapping_add(1);
            if inner.next_index == 0 {
                inner.next_index = 1;
            }

            if !inner.by_index.contains_key(&index) {
                return index;
            }
        }
    }

    /// Starts a background task to expire sessions.
    /// Returns a handle that stops the task when dropped.
    #[cfg(feature = "tokio")]
    pub fn start_expiry_task(self: &Arc<Self>, interval: Duration) -> ExpiryTaskHandle {
        use std::sync::atomic::{AtomicBool, Ordering};
        
        let running = Arc::new(AtomicBool::new(true));
        let running_clone = running.clone();
        let manager = self.clone();

        std::thread::spawn(move || {
            while running_clone.load(Ordering::SeqCst) {
                std::thread::sleep(interval);
                if running_clone.load(Ordering::SeqCst) {
                    manager.expire_sessions();
                }
            }
        });

        ExpiryTaskHandle { running }
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Handle for the expiry background task.
#[cfg(feature = "tokio")]
pub struct ExpiryTaskHandle {
    running: Arc<std::sync::atomic::AtomicBool>,
}

#[cfg(feature = "tokio")]
impl Drop for ExpiryTaskHandle {
    fn drop(&mut self) {
        self.running.store(false, std::sync::atomic::Ordering::SeqCst);
    }
}

/// Manager errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagerError {
    /// Session index already in use.
    IndexInUse,
}

impl std::fmt::Display for ManagerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IndexInUse => write!(f, "session index already in use"),
        }
    }
}

impl std::error::Error for ManagerError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keypair::KEY_SIZE;

    #[test]
    fn test_create_session() {
        let m = SessionManager::new();
        
        let pk = Key::new([1u8; KEY_SIZE]);
        let session = m.create_session(pk, Key::default(), Key::default());
        
        assert!(session.local_index() > 0);
        assert_eq!(m.count(), 1);
    }

    #[test]
    fn test_get_by_index() {
        let m = SessionManager::new();
        
        let pk = Key::new([1u8; KEY_SIZE]);
        let session = m.create_session(pk, Key::default(), Key::default());
        let index = session.local_index();
        
        assert!(m.get_by_index(index).is_some());
        assert!(m.get_by_index(99999).is_none());
    }

    #[test]
    fn test_get_by_pubkey() {
        let m = SessionManager::new();
        
        let pk = Key::new([1u8; KEY_SIZE]);
        let session = m.create_session(pk.clone(), Key::default(), Key::default());
        
        assert!(m.get_by_pubkey(&pk).is_some());
        assert!(m.get_by_pubkey(&Key::new([9u8; KEY_SIZE])).is_none());
    }

    #[test]
    fn test_remove_session() {
        let m = SessionManager::new();
        
        let pk = Key::new([1u8; KEY_SIZE]);
        let session = m.create_session(pk.clone(), Key::default(), Key::default());
        let index = session.local_index();
        
        m.remove_session(index);
        
        assert!(m.get_by_index(index).is_none());
        assert!(m.get_by_pubkey(&pk).is_none());
        assert_eq!(m.count(), 0);
    }

    #[test]
    fn test_remove_by_pubkey() {
        let m = SessionManager::new();
        
        let pk = Key::new([1u8; KEY_SIZE]);
        let session = m.create_session(pk.clone(), Key::default(), Key::default());
        let index = session.local_index();
        
        m.remove_by_pubkey(&pk);
        
        assert!(m.get_by_index(index).is_none());
        assert!(m.get_by_pubkey(&pk).is_none());
    }

    #[test]
    fn test_replace_existing() {
        let m = SessionManager::new();
        
        let pk = Key::new([1u8; KEY_SIZE]);
        
        let s1 = m.create_session(pk.clone(), Key::default(), Key::default());
        let i1 = s1.local_index();
        
        let s2 = m.create_session(pk.clone(), Key::new([1u8; KEY_SIZE]), Key::default());
        let i2 = s2.local_index();
        
        assert!(m.get_by_index(i1).is_none());
        assert!(m.get_by_index(i2).is_some());
        assert_eq!(m.count(), 1);
    }

    #[test]
    fn test_multiple_peers() {
        let m = SessionManager::new();
        
        let peers: Vec<Key> = (0..5).map(|i| Key::new([i; KEY_SIZE])).collect();
        let sessions: Vec<_> = peers
            .iter()
            .map(|pk| m.create_session(pk.clone(), Key::default(), Key::default()))
            .collect();
        
        assert_eq!(m.count(), 5);
        
        for (pk, session) in peers.iter().zip(sessions.iter()) {
            assert!(m.get_by_pubkey(pk).is_some());
            assert!(m.get_by_index(session.local_index()).is_some());
        }
    }

    #[test]
    fn test_expire_sessions() {
        let m = SessionManager::new();
        
        let pk1 = Key::new([1u8; KEY_SIZE]);
        let pk2 = Key::new([2u8; KEY_SIZE]);
        
        let s1 = m.create_session(pk1.clone(), Key::default(), Key::default());
        let s2 = m.create_session(pk2.clone(), Key::default(), Key::default());
        
        s1.expire();
        
        let removed = m.expire_sessions();
        assert_eq!(removed, 1);
        
        assert!(m.get_by_pubkey(&pk1).is_none());
        assert!(m.get_by_pubkey(&pk2).is_some());
    }

    #[test]
    fn test_sessions() {
        let m = SessionManager::new();
        
        for i in 0..5 {
            let pk = Key::new([i; KEY_SIZE]);
            m.create_session(pk, Key::default(), Key::default());
        }
        
        assert_eq!(m.sessions().len(), 5);
    }

    #[test]
    fn test_for_each() {
        let m = SessionManager::new();
        
        for i in 0..5 {
            let pk = Key::new([i; KEY_SIZE]);
            m.create_session(pk, Key::default(), Key::default());
        }
        
        let mut count = 0;
        m.for_each(|_| count += 1);
        assert_eq!(count, 5);
    }

    #[test]
    fn test_clear() {
        let m = SessionManager::new();
        
        for i in 0..5 {
            let pk = Key::new([i; KEY_SIZE]);
            m.create_session(pk, Key::default(), Key::default());
        }
        
        m.clear();
        assert_eq!(m.count(), 0);
    }

    #[test]
    fn test_register_session() {
        let m = SessionManager::new();
        
        let session = Arc::new(Session::new(SessionConfig {
            local_index: 12345,
            remote_index: 0,
            send_key: Key::default(),
            recv_key: Key::default(),
            remote_pk: Key::new([1u8; KEY_SIZE]),
        }));
        
        m.register_session(session.clone()).unwrap();
        
        assert!(m.get_by_index(12345).is_some());
    }

    #[test]
    fn test_register_session_index_collision() {
        let m = SessionManager::new();
        
        let pk1 = Key::new([1u8; KEY_SIZE]);
        let s1 = m.create_session(pk1, Key::default(), Key::default());
        
        let s2 = Arc::new(Session::new(SessionConfig {
            local_index: s1.local_index(),
            remote_index: 0,
            send_key: Key::default(),
            recv_key: Key::default(),
            remote_pk: Key::new([2u8; KEY_SIZE]),
        }));
        
        assert_eq!(m.register_session(s2), Err(ManagerError::IndexInUse));
    }

    #[test]
    fn test_index_wrap() {
        let m = SessionManager::new();
        
        // Set next_index near max
        {
            let mut inner = m.inner.write().unwrap();
            inner.next_index = u32::MAX - 5;
        }
        
        for i in 0..10 {
            let pk = Key::new([i; KEY_SIZE]);
            m.create_session(pk, Key::default(), Key::default());
        }
        
        assert_eq!(m.count(), 10);
    }
}
