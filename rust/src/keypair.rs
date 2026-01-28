//! Key and KeyPair types for Curve25519.

use std::fmt;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

/// Size of keys in bytes.
pub const KEY_SIZE: usize = 32;

/// A 32-byte cryptographic key.
#[derive(Clone, Copy, PartialEq, Eq, Zeroize)]
pub struct Key(pub [u8; KEY_SIZE]);

impl Key {
    /// Creates a new key from bytes.
    pub fn new(bytes: [u8; KEY_SIZE]) -> Self {
        Self(bytes)
    }

    /// Returns true if the key is all zeros.
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|&b| b == 0)
    }

    /// Returns the key as a byte slice.
    pub fn as_bytes(&self) -> &[u8; KEY_SIZE] {
        &self.0
    }

    /// Creates a Key from a hex string.
    pub fn from_hex(s: &str) -> Result<Self, hex::FromHexError> {
        let bytes = hex::decode(s)?;
        if bytes.len() != KEY_SIZE {
            return Err(hex::FromHexError::InvalidStringLength);
        }
        let mut arr = [0u8; KEY_SIZE];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }

    /// Returns the key as a hex string.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Returns first 8 hex characters.
    pub fn short_hex(&self) -> String {
        hex::encode(&self.0[..4])
    }
}

impl Default for Key {
    fn default() -> Self {
        Self([0u8; KEY_SIZE])
    }
}

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Key({}...)", self.short_hex())
    }
}

impl fmt::Display for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl From<[u8; KEY_SIZE]> for Key {
    fn from(bytes: [u8; KEY_SIZE]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for Key {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// A Curve25519 key pair.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct KeyPair {
    /// Private key (secret).
    pub private: Key,
    /// Public key.
    pub public: Key,
}

impl KeyPair {
    /// Generates a new random key pair.
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(rand_core::OsRng);
        let public = PublicKey::from(&secret);
        
        Self {
            private: Key(secret.to_bytes()),
            public: Key(public.to_bytes()),
        }
    }

    /// Creates a key pair from a private key.
    pub fn from_private(private: Key) -> Self {
        let secret = StaticSecret::from(private.0);
        let public = PublicKey::from(&secret);
        
        Self {
            private,
            public: Key(public.to_bytes()),
        }
    }

    /// Performs Diffie-Hellman key exchange.
    pub fn dh(&self, peer_public: &Key) -> Result<Key, DhError> {
        let secret = StaticSecret::from(self.private.0);
        let peer = PublicKey::from(peer_public.0);
        let shared = secret.diffie_hellman(&peer);
        
        let result = Key(shared.to_bytes());
        if result.is_zero() {
            return Err(DhError::LowOrderPoint);
        }
        Ok(result)
    }
}

impl fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyPair")
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}

/// Error during DH operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DhError {
    /// The peer's public key is a low-order point.
    LowOrderPoint,
}

impl std::fmt::Display for DhError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LowOrderPoint => write!(f, "low-order point in DH"),
        }
    }
}

impl std::error::Error for DhError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_is_zero() {
        let zero = Key::default();
        assert!(zero.is_zero());

        let non_zero = Key([1; KEY_SIZE]);
        assert!(!non_zero.is_zero());
    }

    #[test]
    fn test_key_from_hex() {
        let hex_str = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
        let key = Key::from_hex(hex_str).unwrap();
        assert_eq!(key.0[0], 0x01);
        assert_eq!(key.0[31], 0x20);

        // Invalid hex
        assert!(Key::from_hex("xyz").is_err());
        // Wrong length
        assert!(Key::from_hex("0102").is_err());
    }

    #[test]
    fn test_key_to_hex() {
        let key = Key([0x01, 0x02, 0x03, 0x04, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                       0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert!(key.to_hex().starts_with("01020304"));
        assert_eq!(key.short_hex(), "01020304");
    }

    #[test]
    fn test_generate_keypair() {
        let kp = KeyPair::generate();
        assert!(!kp.private.is_zero());
        assert!(!kp.public.is_zero());
    }

    #[test]
    fn test_keypair_from_private() {
        let kp1 = KeyPair::generate();
        let kp2 = KeyPair::from_private(kp1.private.clone());
        assert_eq!(kp1.public, kp2.public);
    }

    #[test]
    fn test_dh() {
        let alice = KeyPair::generate();
        let bob = KeyPair::generate();

        let shared_alice = alice.dh(&bob.public).unwrap();
        let shared_bob = bob.dh(&alice.public).unwrap();

        assert_eq!(shared_alice, shared_bob);
        assert!(!shared_alice.is_zero());
    }

    #[test]
    fn test_dh_deterministic() {
        // Same private key should produce same results
        let priv_bytes = [42u8; KEY_SIZE];
        let kp1 = KeyPair::from_private(Key(priv_bytes));
        let kp2 = KeyPair::from_private(Key(priv_bytes));
        
        assert_eq!(kp1.public, kp2.public);
    }
}
