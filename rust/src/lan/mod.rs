//! LAN service for zgrnet.
//!
//! A composable library that provides membership management, authentication,
//! and event notification for zgrnet LANs.
//!
//! # Architecture
//!
//! The LAN service is a library — not a standalone binary. Callers create a
//! [`Server`], register [`Authenticator`] trait objects for supported join
//! methods, and mount the [`Server::handler`] on their HTTP infrastructure.
//!
//! Identity resolution (IP → pubkey) is injected via [`IdentityFn`], so the
//! package has no dependency on the host or transport layer.

pub mod auth;
pub mod store;

pub use auth::{
    Authenticator, AuthRequest, InviteCodeAuth, OpenAuth, PasswordAuth, PubkeyWhitelistAuth,
};
pub use store::{Member, Store, MemStore, FileStore};

use crate::noise::Key;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, RwLock};

/// Identity resolution function: IP → (pubkey, labels).
pub type IdentityFn = Box<dyn Fn(IpAddr) -> Result<(Key, Vec<String>), String> + Send + Sync>;

/// Configuration for creating a LAN server.
pub struct Config {
    /// LAN domain (e.g., "company.zigor.net").
    pub domain: String,

    /// Human-readable description.
    pub description: String,

    /// Directory for persistent storage. Empty = in-memory only.
    pub data_dir: String,

    /// Identity resolution function.
    pub identity_fn: IdentityFn,
}

/// Event pushed to subscribers on LAN changes.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Event {
    /// Event kind: "join", "leave", "labels".
    #[serde(rename = "type")]
    pub event_type: String,

    /// Affected member (hex-encoded pubkey).
    pub pubkey: String,

    /// New label set (for "labels" events).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub labels: Option<Vec<String>>,

    /// When the event occurred (RFC 3339).
    pub timestamp: String,
}

/// LAN server. Holds store, authenticators, and event subscribers.
///
/// Thread-safe — all methods can be called from any thread.
pub struct Server {
    pub(crate) config: Config,
    pub(crate) store: Arc<dyn Store>,
    pub(crate) auths: RwLock<HashMap<String, Box<dyn Authenticator>>>,
    pub(crate) subs: Mutex<Subscribers>,
}

pub(crate) struct Subscribers {
    next_id: u64,
    channels: HashMap<u64, std::sync::mpsc::Sender<Event>>,
}

impl Server {
    /// Creates a new LAN server with the given config and store.
    pub fn new(config: Config, store: Arc<dyn Store>) -> Self {
        Server {
            config,
            store,
            auths: RwLock::new(HashMap::new()),
            subs: Mutex::new(Subscribers {
                next_id: 0,
                channels: HashMap::new(),
            }),
        }
    }

    /// Registers an authenticator. Replaces any existing one with the same method.
    pub fn register_auth(&self, auth: Box<dyn Authenticator>) {
        let method = auth.method().to_string();
        self.auths.write().unwrap().insert(method, auth);
    }

    /// Returns the underlying store.
    pub fn store(&self) -> &Arc<dyn Store> {
        &self.store
    }

    /// Returns the LAN domain.
    pub fn domain(&self) -> &str {
        &self.config.domain
    }

    /// Returns registered authentication method names.
    pub fn auth_methods(&self) -> Vec<String> {
        self.auths.read().unwrap().keys().cloned().collect()
    }

    /// Resolves a remote IP to a pubkey using the configured identity function.
    pub fn identify(&self, ip: IpAddr) -> Result<Key, String> {
        let (pk, _) = (self.config.identity_fn)(ip)?;
        Ok(pk)
    }

    /// Authenticates a join request.
    pub fn authenticate(
        &self,
        pubkey: Key,
        req: &AuthRequest,
    ) -> Result<(), String> {
        let auths = self.auths.read().unwrap();
        let auth = auths
            .get(&req.method)
            .ok_or_else(|| format!("unsupported auth method: {:?}", req.method))?;
        auth.authenticate(pubkey, &req.credential)
    }

    /// Joins a peer to the LAN after authentication.
    /// Returns true if the peer was newly added.
    pub fn join(&self, pubkey: Key, req: &AuthRequest) -> Result<bool, String> {
        self.authenticate(pubkey, req)?;

        let added = self.store.add(pubkey)?;
        if added {
            self.broadcast(Event {
                event_type: "join".to_string(),
                pubkey: pubkey.to_hex(),
                labels: None,
                timestamp: now_rfc3339(),
            });
        }
        Ok(added)
    }

    /// Removes a peer from the LAN.
    /// Returns true if the peer was a member.
    pub fn leave(&self, pubkey: Key) -> Result<bool, String> {
        let removed = self.store.remove(pubkey)?;
        if removed {
            self.broadcast(Event {
                event_type: "leave".to_string(),
                pubkey: pubkey.to_hex(),
                labels: None,
                timestamp: now_rfc3339(),
            });
        }
        Ok(removed)
    }

    /// Sets labels for a member.
    pub fn set_labels(&self, pubkey: Key, labels: Vec<String>) -> Result<(), String> {
        self.store.set_labels(pubkey, labels.clone())?;
        self.broadcast(Event {
            event_type: "labels".to_string(),
            pubkey: pubkey.to_hex(),
            labels: Some(labels),
            timestamp: now_rfc3339(),
        });
        Ok(())
    }

    /// Removes specific labels from a member.
    pub fn remove_labels(&self, pubkey: Key, to_remove: &[String]) -> Result<(), String> {
        self.store.remove_labels(pubkey, to_remove)?;
        let member = self.store.get(pubkey);
        let new_labels = member.map(|m| m.labels.clone()).unwrap_or_default();
        self.broadcast(Event {
            event_type: "labels".to_string(),
            pubkey: pubkey.to_hex(),
            labels: Some(new_labels),
            timestamp: now_rfc3339(),
        });
        Ok(())
    }

    /// Subscribes to LAN events. Returns a receiver channel.
    pub fn subscribe(&self) -> (u64, std::sync::mpsc::Receiver<Event>) {
        let (tx, rx) = std::sync::mpsc::channel();
        let mut subs = self.subs.lock().unwrap();
        subs.next_id += 1;
        let id = subs.next_id;
        subs.channels.insert(id, tx);
        (id, rx)
    }

    /// Unsubscribes from LAN events.
    pub fn unsubscribe(&self, id: u64) {
        self.subs.lock().unwrap().channels.remove(&id);
    }

    /// Broadcasts an event to all subscribers.
    pub(crate) fn broadcast(&self, event: Event) {
        let subs = self.subs.lock().unwrap();
        for tx in subs.channels.values() {
            let _ = tx.send(event.clone());
        }
    }
}

fn now_rfc3339() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = dur.as_secs();
    // Simple ISO 8601 format without external crate.
    format!("1970-01-01T00:00:00Z+{}s", secs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::noise::KeyPair;

    fn test_key() -> Key {
        KeyPair::generate().public
    }

    fn test_identity(pk: Key) -> IdentityFn {
        Box::new(move |_ip| Ok((pk, vec![])))
    }

    fn test_server(pk: Key) -> Server {
        let store: Arc<dyn Store> = Arc::new(MemStore::new());
        let srv = Server::new(
            Config {
                domain: "test.zigor.net".to_string(),
                description: "Test LAN".to_string(),
                data_dir: String::new(),
                identity_fn: test_identity(pk),
            },
            store,
        );
        srv.register_auth(Box::new(OpenAuth));
        srv
    }

    #[test]
    fn test_join_and_leave() {
        let pk = test_key();
        let srv = test_server(pk);

        let req = AuthRequest {
            method: "open".to_string(),
            credential: String::new(),
        };

        // Join.
        let added = srv.join(pk, &req).unwrap();
        assert!(added, "expected member to be added");

        // Join again — no-op.
        let added = srv.join(pk, &req).unwrap();
        assert!(!added, "expected no-op on duplicate");

        assert_eq!(srv.store().count(), 1);

        // Leave.
        let removed = srv.leave(pk).unwrap();
        assert!(removed, "expected member to be removed");

        assert_eq!(srv.store().count(), 0);
    }

    #[test]
    fn test_labels() {
        let pk = test_key();
        let srv = test_server(pk);

        let req = AuthRequest {
            method: "open".to_string(),
            credential: String::new(),
        };
        srv.join(pk, &req).unwrap();

        srv.set_labels(pk, vec!["admin".into(), "dev".into()])
            .unwrap();

        let m = srv.store().get(pk).unwrap();
        assert_eq!(m.labels, vec!["admin", "dev"]);

        srv.remove_labels(pk, &["admin".into()]).unwrap();
        let m = srv.store().get(pk).unwrap();
        assert_eq!(m.labels, vec!["dev"]);
    }

    #[test]
    fn test_auth_methods() {
        let pk = test_key();
        let srv = test_server(pk);

        let methods = srv.auth_methods();
        assert_eq!(methods.len(), 1);
        assert!(methods.contains(&"open".to_string()));
    }

    #[test]
    fn test_unsupported_auth() {
        let pk = test_key();
        let srv = test_server(pk);

        let req = AuthRequest {
            method: "oauth".to_string(),
            credential: String::new(),
        };
        assert!(srv.join(pk, &req).is_err());
    }

    #[test]
    fn test_events() {
        let pk = test_key();
        let srv = test_server(pk);

        let (_id, rx) = srv.subscribe();

        let req = AuthRequest {
            method: "open".to_string(),
            credential: String::new(),
        };
        srv.join(pk, &req).unwrap();

        let evt = rx.try_recv().unwrap();
        assert_eq!(evt.event_type, "join");
        assert_eq!(evt.pubkey, pk.to_hex());
    }
}
