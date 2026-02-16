//! Pluggable authentication for LAN join requests.
//!
//! The [`Authenticator`] trait defines how join requests are validated.
//! Built-in implementations: [`OpenAuth`], [`PasswordAuth`], [`InviteCodeAuth`],
//! [`PubkeyWhitelistAuth`].

use crate::noise::Key;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

/// Authentication request from a join body.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthRequest {
    pub method: String,
    #[serde(default)]
    pub credential: String,
}

/// Trait for authenticating join requests.
///
/// Implementations must be Send + Sync for use in multi-threaded HTTP servers.
pub trait Authenticator: Send + Sync {
    /// Returns the method name (e.g., "open", "password").
    fn method(&self) -> &str;

    /// Validates the join request. `credential` is the raw credential string
    /// from the request body. Returns Ok(()) on success.
    fn authenticate(&self, pubkey: Key, credential: &str) -> Result<(), String>;
}

// ── OpenAuth ────────────────────────────────────────────────────────────────

/// Allows any peer to join without credentials.
pub struct OpenAuth;

impl Authenticator for OpenAuth {
    fn method(&self) -> &str {
        "open"
    }

    fn authenticate(&self, _pubkey: Key, _credential: &str) -> Result<(), String> {
        Ok(())
    }
}

// ── PasswordAuth ────────────────────────────────────────────────────────────

/// Validates join requests against a bcrypt-hashed password.
pub struct PasswordAuth {
    hash: String,
}

impl PasswordAuth {
    /// Creates from an existing bcrypt hash string.
    pub fn from_hash(hash: String) -> Result<Self, String> {
        if !hash.starts_with("$2a$") && !hash.starts_with("$2b$") && !hash.starts_with("$2y$") {
            return Err("lan: invalid bcrypt hash".to_string());
        }
        Ok(PasswordAuth { hash })
    }

    /// Creates by hashing a plaintext password with bcrypt.
    pub fn from_plaintext(password: &str, cost: u32) -> Result<Self, String> {
        let hash = bcrypt::hash(password, cost)
            .map_err(|e| format!("lan: hash password: {}", e))?;
        Ok(PasswordAuth { hash })
    }
}

impl Authenticator for PasswordAuth {
    fn method(&self) -> &str {
        "password"
    }

    fn authenticate(&self, _pubkey: Key, credential: &str) -> Result<(), String> {
        if credential.is_empty() {
            return Err("password is required".to_string());
        }
        let valid = bcrypt::verify(credential, &self.hash)
            .map_err(|e| format!("bcrypt error: {}", e))?;
        if !valid {
            return Err("invalid password".to_string());
        }
        Ok(())
    }
}

// ── InviteCodeAuth ──────────────────────────────────────────────────────────

/// An invite code with optional usage limit.
#[derive(Clone, Debug)]
pub struct InviteCode {
    pub code: String,
    pub max_uses: usize, // 0 = unlimited
    pub use_count: usize,
}

/// Validates join requests against admin-generated invite codes.
pub struct InviteCodeAuth {
    codes: Mutex<HashMap<String, InviteCode>>,
}

impl Default for InviteCodeAuth {
    fn default() -> Self {
        Self::new()
    }
}

impl InviteCodeAuth {
    pub fn new() -> Self {
        InviteCodeAuth {
            codes: Mutex::new(HashMap::new()),
        }
    }

    /// Generates a new invite code. Returns the code string.
    pub fn generate_code(&self, max_uses: usize) -> String {
        let mut buf = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut buf);
        let code = hex::encode(buf);

        self.codes.lock().unwrap().insert(
            code.clone(),
            InviteCode {
                code: code.clone(),
                max_uses,
                use_count: 0,
            },
        );

        code
    }

    /// Revokes an invite code.
    pub fn revoke_code(&self, code: &str) -> bool {
        self.codes.lock().unwrap().remove(code).is_some()
    }

    /// Lists all active invite codes.
    pub fn list_codes(&self) -> Vec<InviteCode> {
        self.codes.lock().unwrap().values().cloned().collect()
    }
}

impl Authenticator for InviteCodeAuth {
    fn method(&self) -> &str {
        "invite_code"
    }

    fn authenticate(&self, _pubkey: Key, credential: &str) -> Result<(), String> {
        if credential.is_empty() {
            return Err("invite code is required".to_string());
        }

        let mut codes = self.codes.lock().unwrap();
        let ic = codes
            .get_mut(credential)
            .ok_or_else(|| "invalid invite code".to_string())?;

        if ic.max_uses > 0 && ic.use_count >= ic.max_uses {
            return Err("invite code has been fully used".to_string());
        }

        ic.use_count += 1;
        Ok(())
    }
}

// ── PubkeyWhitelistAuth ────────────────────────────────────────────────────

/// Allows only pre-approved public keys to join.
pub struct PubkeyWhitelistAuth {
    allowed: Mutex<HashSet<Key>>,
}

impl PubkeyWhitelistAuth {
    pub fn new(keys: &[Key]) -> Self {
        PubkeyWhitelistAuth {
            allowed: Mutex::new(keys.iter().copied().collect()),
        }
    }

    pub fn add_key(&self, pk: Key) {
        self.allowed.lock().unwrap().insert(pk);
    }

    pub fn remove_key(&self, pk: Key) {
        self.allowed.lock().unwrap().remove(&pk);
    }
}

impl Authenticator for PubkeyWhitelistAuth {
    fn method(&self) -> &str {
        "pubkey_whitelist"
    }

    fn authenticate(&self, pubkey: Key, _credential: &str) -> Result<(), String> {
        if self.allowed.lock().unwrap().contains(&pubkey) {
            Ok(())
        } else {
            Err("pubkey not in whitelist".to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::noise::KeyPair;

    fn test_key() -> Key {
        KeyPair::generate().public
    }

    #[test]
    fn test_open_auth() {
        let auth = OpenAuth;
        assert_eq!(auth.method(), "open");
        assert!(auth.authenticate(test_key(), "").is_ok());
    }

    #[test]
    fn test_password_auth() {
        let auth = PasswordAuth::from_plaintext("secret123", 4).unwrap();
        assert_eq!(auth.method(), "password");

        let pk = test_key();
        assert!(auth.authenticate(pk, "secret123").is_ok());
        assert!(auth.authenticate(pk, "wrong").is_err());
        assert!(auth.authenticate(pk, "").is_err());
    }

    #[test]
    fn test_password_auth_from_hash() {
        let auth1 = PasswordAuth::from_plaintext("mypass", 4).unwrap();
        let auth2 = PasswordAuth::from_hash(auth1.hash.clone()).unwrap();

        let pk = test_key();
        assert!(auth2.authenticate(pk, "mypass").is_ok());
        assert!(auth2.authenticate(pk, "wrong").is_err());

        assert!(PasswordAuth::from_hash("not-a-hash".into()).is_err());
    }

    #[test]
    fn test_invite_code_auth() {
        let auth = InviteCodeAuth::new();
        assert_eq!(auth.method(), "invite_code");

        let code = auth.generate_code(1); // single use
        let pk = test_key();

        assert!(auth.authenticate(pk, &code).is_ok());
        assert!(auth.authenticate(pk, &code).is_err()); // exhausted

        assert!(auth.authenticate(pk, "nonexistent").is_err());
        assert!(auth.authenticate(pk, "").is_err());
    }

    #[test]
    fn test_invite_code_unlimited() {
        let auth = InviteCodeAuth::new();
        let code = auth.generate_code(0);
        let pk = test_key();

        for _ in 0..10 {
            assert!(auth.authenticate(pk, &code).is_ok());
        }
    }

    #[test]
    fn test_invite_code_revoke() {
        let auth = InviteCodeAuth::new();
        let code1 = auth.generate_code(0);
        let _code2 = auth.generate_code(5);

        assert_eq!(auth.list_codes().len(), 2);
        assert!(auth.revoke_code(&code1));
        assert!(!auth.revoke_code(&code1)); // already revoked
        assert_eq!(auth.list_codes().len(), 1);
    }

    #[test]
    fn test_pubkey_whitelist() {
        let pk1 = test_key();
        let pk2 = test_key();
        let pk_unknown = test_key();

        let auth = PubkeyWhitelistAuth::new(&[pk1, pk2]);
        assert_eq!(auth.method(), "pubkey_whitelist");

        assert!(auth.authenticate(pk1, "").is_ok());
        assert!(auth.authenticate(pk2, "").is_ok());
        assert!(auth.authenticate(pk_unknown, "").is_err());

        auth.add_key(pk_unknown);
        assert!(auth.authenticate(pk_unknown, "").is_ok());

        auth.remove_key(pk1);
        assert!(auth.authenticate(pk1, "").is_err());
    }
}
