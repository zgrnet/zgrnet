//! Session management for transport phase.

use crate::cipher::{DecryptError, TAG_SIZE};
use crate::keypair::{Key, KEY_SIZE};
use crate::replay::ReplayFilter;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;
use std::time::{Duration, Instant};

/// Session state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// Handshake in progress.
    Handshaking,
    /// Session established, ready for transport.
    Established,
    /// Session expired.
    Expired,
}

impl std::fmt::Display for SessionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Handshaking => write!(f, "handshaking"),
            Self::Established => write!(f, "established"),
            Self::Expired => write!(f, "expired"),
        }
    }
}

/// Session timeout duration.
pub const SESSION_TIMEOUT: Duration = Duration::from_secs(180);

/// Maximum nonce value.
pub const MAX_NONCE: u64 = u64::MAX - 1;

/// Configuration for creating a session.
pub struct SessionConfig {
    pub local_index: u32,
    pub remote_index: u32,
    pub send_key: Key,
    pub recv_key: Key,
    pub remote_pk: Key,
}

/// An established Noise session with a peer.
pub struct Session {
    local_index: u32,
    remote_index: RwLock<u32>,
    
    send_key: Key,
    recv_key: Key,
    send_cipher: LessSafeKey,
    recv_cipher: LessSafeKey,
    
    send_nonce: AtomicU64,
    recv_filter: ReplayFilter,
    
    state: RwLock<SessionState>,
    remote_pk: Key,
    
    created_at: Instant,
    last_received: RwLock<Instant>,
    last_sent: RwLock<Instant>,
}

impl Session {
    /// Creates a new session.
    pub fn new(cfg: SessionConfig) -> Self {
        let send_cipher = LessSafeKey::new(
            UnboundKey::new(&CHACHA20_POLY1305, cfg.send_key.as_bytes())
                .expect("valid key size"),
        );
        let recv_cipher = LessSafeKey::new(
            UnboundKey::new(&CHACHA20_POLY1305, cfg.recv_key.as_bytes())
                .expect("valid key size"),
        );
        
        let now = Instant::now();
        Self {
            local_index: cfg.local_index,
            remote_index: RwLock::new(cfg.remote_index),
            send_key: cfg.send_key,
            recv_key: cfg.recv_key,
            send_cipher,
            recv_cipher,
            send_nonce: AtomicU64::new(0),
            recv_filter: ReplayFilter::new(),
            state: RwLock::new(SessionState::Established),
            remote_pk: cfg.remote_pk,
            created_at: now,
            last_received: RwLock::new(now),
            last_sent: RwLock::new(now),
        }
    }

    /// Returns the local index.
    pub fn local_index(&self) -> u32 {
        self.local_index
    }

    /// Returns the remote index.
    pub fn remote_index(&self) -> u32 {
        *self.remote_index.read().unwrap()
    }

    /// Sets the remote index.
    pub fn set_remote_index(&self, idx: u32) {
        *self.remote_index.write().unwrap() = idx;
    }

    /// Returns the remote public key.
    pub fn remote_pk(&self) -> &Key {
        &self.remote_pk
    }

    /// Returns the current state.
    pub fn state(&self) -> SessionState {
        *self.state.read().unwrap()
    }

    /// Sets the state.
    pub fn set_state(&self, state: SessionState) {
        *self.state.write().unwrap() = state;
    }

    /// Encrypts a message.
    /// Returns (ciphertext, nonce).
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<(Vec<u8>, u64), SessionError> {
        if self.state() != SessionState::Established {
            return Err(SessionError::NotEstablished);
        }

        let nonce = self.send_nonce.fetch_add(1, Ordering::SeqCst);
        if nonce >= MAX_NONCE {
            return Err(SessionError::NonceExhausted);
        }

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[..8].copy_from_slice(&nonce.to_le_bytes());
        let ring_nonce = Nonce::assume_unique_for_key(nonce_bytes);

        let mut buffer = Vec::with_capacity(plaintext.len() + TAG_SIZE);
        buffer.extend_from_slice(plaintext);
        
        self.send_cipher
            .seal_in_place_append_tag(ring_nonce, Aad::empty(), &mut buffer)
            .map_err(|_| SessionError::EncryptFailed)?;

        *self.last_sent.write().unwrap() = Instant::now();

        Ok((buffer, nonce))
    }

    /// Encrypts to a pre-allocated buffer.
    pub fn encrypt_to(&self, plaintext: &[u8], out: &mut [u8]) -> Result<u64, SessionError> {
        if self.state() != SessionState::Established {
            return Err(SessionError::NotEstablished);
        }

        let nonce = self.send_nonce.fetch_add(1, Ordering::SeqCst);
        if nonce >= MAX_NONCE {
            return Err(SessionError::NonceExhausted);
        }

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[..8].copy_from_slice(&nonce.to_le_bytes());
        let ring_nonce = Nonce::assume_unique_for_key(nonce_bytes);

        let pt_len = plaintext.len();
        out[..pt_len].copy_from_slice(plaintext);

        let tag = self.send_cipher
            .seal_in_place_separate_tag(ring_nonce, Aad::empty(), &mut out[..pt_len])
            .map_err(|_| SessionError::EncryptFailed)?;
        out[pt_len..pt_len + TAG_SIZE].copy_from_slice(tag.as_ref());

        *self.last_sent.write().unwrap() = Instant::now();

        Ok(nonce)
    }

    /// Decrypts a message.
    pub fn decrypt(&self, ciphertext: &[u8], nonce: u64) -> Result<Vec<u8>, SessionError> {
        if self.state() != SessionState::Established {
            return Err(SessionError::NotEstablished);
        }

        if !self.recv_filter.check(nonce) {
            return Err(SessionError::ReplayDetected);
        }

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[..8].copy_from_slice(&nonce.to_le_bytes());
        let ring_nonce = Nonce::assume_unique_for_key(nonce_bytes);

        let mut buffer = ciphertext.to_vec();
        let plaintext = self.recv_cipher
            .open_in_place(ring_nonce, Aad::empty(), &mut buffer)
            .map_err(|_| SessionError::DecryptFailed)?;
        
        let len = plaintext.len();
        buffer.truncate(len);

        self.recv_filter.update(nonce);
        *self.last_received.write().unwrap() = Instant::now();

        Ok(buffer)
    }

    /// Decrypts to a pre-allocated buffer.
    pub fn decrypt_to(&self, ciphertext: &[u8], nonce: u64, out: &mut [u8]) -> Result<usize, SessionError> {
        if self.state() != SessionState::Established {
            return Err(SessionError::NotEstablished);
        }

        if !self.recv_filter.check(nonce) {
            return Err(SessionError::ReplayDetected);
        }

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[..8].copy_from_slice(&nonce.to_le_bytes());
        let ring_nonce = Nonce::assume_unique_for_key(nonce_bytes);

        let ct_len = ciphertext.len();
        out[..ct_len].copy_from_slice(ciphertext);

        let plaintext = self.recv_cipher
            .open_in_place(ring_nonce, Aad::empty(), &mut out[..ct_len])
            .map_err(|_| SessionError::DecryptFailed)?;
        
        let len = plaintext.len();
        self.recv_filter.update(nonce);
        *self.last_received.write().unwrap() = Instant::now();

        Ok(len)
    }

    /// Checks if the session has expired.
    pub fn is_expired(&self) -> bool {
        if self.state() == SessionState::Expired {
            return true;
        }
        self.last_received.read().unwrap().elapsed() > SESSION_TIMEOUT
    }

    /// Marks the session as expired.
    pub fn expire(&self) {
        self.set_state(SessionState::Expired);
    }

    /// Returns when the session was created.
    pub fn created_at(&self) -> Instant {
        self.created_at
    }

    /// Returns when last message was received.
    pub fn last_received(&self) -> Instant {
        *self.last_received.read().unwrap()
    }

    /// Returns when last message was sent.
    pub fn last_sent(&self) -> Instant {
        *self.last_sent.read().unwrap()
    }

    /// Returns current send nonce.
    pub fn send_nonce(&self) -> u64 {
        self.send_nonce.load(Ordering::SeqCst)
    }

    /// Returns max received nonce.
    pub fn recv_max_nonce(&self) -> u64 {
        self.recv_filter.max_nonce()
    }
}

/// Session errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionError {
    /// Session not established.
    NotEstablished,
    /// Replay detected.
    ReplayDetected,
    /// Nonce exhausted.
    NonceExhausted,
    /// Encryption failed.
    EncryptFailed,
    /// Decryption failed.
    DecryptFailed,
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotEstablished => write!(f, "session not established"),
            Self::ReplayDetected => write!(f, "replay detected"),
            Self::NonceExhausted => write!(f, "nonce exhausted"),
            Self::EncryptFailed => write!(f, "encryption failed"),
            Self::DecryptFailed => write!(f, "decryption failed"),
        }
    }
}

impl std::error::Error for SessionError {}

/// Generates a random session index.
pub fn generate_index() -> u32 {
    use rand::Rng;
    rand::thread_rng().gen()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cipher;

    fn create_test_sessions() -> (Session, Session) {
        let send_key = Key::new(cipher::hash(&[b"send key"]));
        let recv_key = Key::new(cipher::hash(&[b"recv key"]));

        let alice = Session::new(SessionConfig {
            local_index: 1,
            remote_index: 2,
            send_key: send_key.clone(),
            recv_key: recv_key.clone(),
            remote_pk: Key::default(),
        });

        let bob = Session::new(SessionConfig {
            local_index: 2,
            remote_index: 1,
            send_key: recv_key,
            recv_key: send_key,
            remote_pk: Key::default(),
        });

        (alice, bob)
    }

    #[test]
    fn test_encrypt_decrypt() {
        let (alice, bob) = create_test_sessions();
        
        let plaintext = b"Hello, World!";
        let (ciphertext, nonce) = alice.encrypt(plaintext).unwrap();
        let decrypted = bob.decrypt(&ciphertext, nonce).unwrap();
        
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_bidirectional() {
        let (alice, bob) = create_test_sessions();
        
        // Alice -> Bob
        let (ct1, n1) = alice.encrypt(b"from alice").unwrap();
        let pt1 = bob.decrypt(&ct1, n1).unwrap();
        assert_eq!(pt1, b"from alice");
        
        // Bob -> Alice
        let (ct2, n2) = bob.encrypt(b"from bob").unwrap();
        let pt2 = alice.decrypt(&ct2, n2).unwrap();
        assert_eq!(pt2, b"from bob");
    }

    #[test]
    fn test_nonce_increment() {
        let (alice, _) = create_test_sessions();
        
        for i in 0..10 {
            assert_eq!(alice.send_nonce(), i);
            alice.encrypt(b"test").unwrap();
        }
        assert_eq!(alice.send_nonce(), 10);
    }

    #[test]
    fn test_replay_protection() {
        let (alice, bob) = create_test_sessions();
        
        let (ciphertext, nonce) = alice.encrypt(b"test").unwrap();
        
        // First decrypt succeeds
        bob.decrypt(&ciphertext, nonce).unwrap();
        
        // Replay fails
        assert_eq!(bob.decrypt(&ciphertext, nonce), Err(SessionError::ReplayDetected));
    }

    #[test]
    fn test_out_of_order() {
        let (alice, bob) = create_test_sessions();
        
        let mut messages = Vec::new();
        for i in 0..10u8 {
            let (ct, n) = alice.encrypt(&[i]).unwrap();
            messages.push((ct, n, i));
        }
        
        // Decrypt in reverse
        for (ct, n, expected) in messages.into_iter().rev() {
            let pt = bob.decrypt(&ct, n).unwrap();
            assert_eq!(pt, [expected]);
        }
    }

    #[test]
    fn test_wrong_key() {
        let (alice, _) = create_test_sessions();
        
        let eve = Session::new(SessionConfig {
            local_index: 3,
            remote_index: 1,
            send_key: Key::new([99u8; KEY_SIZE]),
            recv_key: Key::new([99u8; KEY_SIZE]),
            remote_pk: Key::default(),
        });
        
        let (ciphertext, nonce) = alice.encrypt(b"secret").unwrap();
        assert_eq!(eve.decrypt(&ciphertext, nonce), Err(SessionError::DecryptFailed));
    }

    #[test]
    fn test_state() {
        let (alice, _) = create_test_sessions();
        
        assert_eq!(alice.state(), SessionState::Established);
        
        alice.set_state(SessionState::Expired);
        assert_eq!(alice.state(), SessionState::Expired);
        
        assert_eq!(alice.encrypt(b"test"), Err(SessionError::NotEstablished));
    }

    #[test]
    fn test_indices() {
        let (alice, bob) = create_test_sessions();
        
        assert_eq!(alice.local_index(), 1);
        assert_eq!(alice.remote_index(), 2);
        assert_eq!(bob.local_index(), 2);
        assert_eq!(bob.remote_index(), 1);
    }

    #[test]
    fn test_encrypt_to_decrypt_to() {
        let (alice, bob) = create_test_sessions();
        
        let plaintext = b"Hello, World!";
        let mut ct_buf = [0u8; 13 + 16];
        let mut pt_buf = [0u8; 13 + 16];
        
        let nonce = alice.encrypt_to(plaintext, &mut ct_buf).unwrap();
        let pt_len = bob.decrypt_to(&ct_buf, nonce, &mut pt_buf).unwrap();
        
        assert_eq!(&pt_buf[..pt_len], plaintext);
    }

    #[test]
    fn test_generate_index() {
        let mut indices = std::collections::HashSet::new();
        for _ in 0..1000 {
            indices.insert(generate_index());
        }
        // Should have many unique values
        assert!(indices.len() > 900);
    }

    #[test]
    fn test_session_state_display() {
        assert_eq!(format!("{}", SessionState::Handshaking), "handshaking");
        assert_eq!(format!("{}", SessionState::Established), "established");
        assert_eq!(format!("{}", SessionState::Expired), "expired");
    }
}
