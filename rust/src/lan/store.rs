//! LAN membership store with optional JSON persistence.

use crate::noise::Key;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::RwLock;

/// A LAN member.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Member {
    /// Hex-encoded public key.
    pub pubkey: String,

    /// Assigned labels.
    pub labels: Vec<String>,

    /// When the member joined (RFC 3339).
    pub joined_at: String,
}

/// JSON structure for persistence.
#[derive(Serialize, Deserialize)]
struct StoreFile {
    members: Vec<Member>,
}

/// Thread-safe membership store.
pub struct Store {
    inner: RwLock<StoreInner>,
}

struct StoreInner {
    members: HashMap<Key, Member>,
    path: Option<PathBuf>,
}

impl Store {
    /// Creates an in-memory store (no persistence).
    pub fn new_memory() -> Self {
        Store {
            inner: RwLock::new(StoreInner {
                members: HashMap::new(),
                path: None,
            }),
        }
    }

    /// Creates a store backed by a JSON file in `data_dir`.
    /// Loads existing data if the file exists.
    pub fn new(data_dir: &str) -> Result<Self, String> {
        let path = PathBuf::from(data_dir).join("members.json");
        let mut members = HashMap::new();

        if path.exists() {
            let data = std::fs::read_to_string(&path)
                .map_err(|e| format!("lan: read {:?}: {}", path, e))?;
            let sf: StoreFile = serde_json::from_str(&data)
                .map_err(|e| format!("lan: parse {:?}: {}", path, e))?;
            for m in sf.members {
                if let Ok(pk) = Key::from_hex(&m.pubkey) {
                    members.insert(pk, m);
                }
            }
        }

        Ok(Store {
            inner: RwLock::new(StoreInner {
                members,
                path: Some(path),
            }),
        })
    }

    /// Adds a member. Returns true if newly added.
    pub fn add(&self, pk: Key) -> Result<bool, String> {
        let mut inner = self.inner.write().unwrap();

        if inner.members.contains_key(&pk) {
            return Ok(false);
        }

        inner.members.insert(
            pk,
            Member {
                pubkey: pk.to_hex(),
                labels: vec![],
                joined_at: now_rfc3339(),
            },
        );

        self.save_locked(&inner)?;
        Ok(true)
    }

    /// Removes a member. Returns true if the member existed.
    pub fn remove(&self, pk: Key) -> Result<bool, String> {
        let mut inner = self.inner.write().unwrap();

        if inner.members.remove(&pk).is_none() {
            return Ok(false);
        }

        self.save_locked(&inner)?;
        Ok(true)
    }

    /// Gets a member by pubkey.
    pub fn get(&self, pk: Key) -> Option<Member> {
        self.inner.read().unwrap().members.get(&pk).cloned()
    }

    /// Checks if a pubkey is a member.
    pub fn is_member(&self, pk: Key) -> bool {
        self.inner.read().unwrap().members.contains_key(&pk)
    }

    /// Lists all members.
    pub fn list(&self) -> Vec<Member> {
        self.inner.read().unwrap().members.values().cloned().collect()
    }

    /// Returns member count.
    pub fn count(&self) -> usize {
        self.inner.read().unwrap().members.len()
    }

    /// Replaces labels for a member.
    pub fn set_labels(&self, pk: Key, labels: Vec<String>) -> Result<(), String> {
        let mut inner = self.inner.write().unwrap();
        let m = inner
            .members
            .get_mut(&pk)
            .ok_or_else(|| format!("lan: pubkey {} is not a member", pk.short_hex()))?;
        m.labels = labels;
        self.save_locked(&inner)?;
        Ok(())
    }

    /// Removes specific labels from a member.
    pub fn remove_labels(&self, pk: Key, to_remove: &[String]) -> Result<(), String> {
        let mut inner = self.inner.write().unwrap();
        let m = inner
            .members
            .get_mut(&pk)
            .ok_or_else(|| format!("lan: pubkey {} is not a member", pk.short_hex()))?;
        m.labels.retain(|l| !to_remove.contains(l));
        self.save_locked(&inner)?;
        Ok(())
    }

    /// Persists to disk. Caller must hold the write lock via inner.
    fn save_locked(&self, inner: &StoreInner) -> Result<(), String> {
        let path = match &inner.path {
            Some(p) => p,
            None => return Ok(()),
        };

        let sf = StoreFile {
            members: inner.members.values().cloned().collect(),
        };

        let data = serde_json::to_string_pretty(&sf)
            .map_err(|e| format!("lan: marshal: {}", e))?;

        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)
                .map_err(|e| format!("lan: mkdir {:?}: {}", dir, e))?;
        }

        // Atomic write: temp file → rename.
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, &data)
            .map_err(|e| format!("lan: write {:?}: {}", tmp, e))?;
        std::fs::rename(&tmp, path)
            .map_err(|e| format!("lan: rename {:?} → {:?}: {}", tmp, path, e))?;

        Ok(())
    }
}

fn now_rfc3339() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = dur.as_secs();
    // Days since epoch for date calculation.
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let mins = (time_of_day % 3600) / 60;
    let s = time_of_day % 60;

    // Gregorian calendar from days since epoch.
    let (y, m, d) = days_to_date(days);
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", y, m, d, hours, mins, s)
}

fn days_to_date(days: u64) -> (u64, u64, u64) {
    // Algorithm from http://howardhinnant.github.io/date_algorithms.html
    let z = days + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::noise::KeyPair;

    fn test_key() -> Key {
        KeyPair::generate().public
    }

    #[test]
    fn test_add_and_get() {
        let store = Store::new_memory();
        let pk = test_key();

        assert!(store.add(pk).unwrap());
        assert!(!store.add(pk).unwrap()); // duplicate

        let m = store.get(pk).unwrap();
        assert_eq!(m.pubkey, pk.to_hex());
        assert!(m.labels.is_empty());

        assert_eq!(store.count(), 1);
    }

    #[test]
    fn test_remove() {
        let store = Store::new_memory();
        let pk = test_key();

        store.add(pk).unwrap();
        assert!(store.remove(pk).unwrap());
        assert!(!store.remove(pk).unwrap()); // already removed
        assert_eq!(store.count(), 0);
    }

    #[test]
    fn test_labels() {
        let store = Store::new_memory();
        let pk = test_key();

        store.add(pk).unwrap();
        store
            .set_labels(pk, vec!["admin".into(), "dev".into()])
            .unwrap();

        let m = store.get(pk).unwrap();
        assert_eq!(m.labels, vec!["admin", "dev"]);

        store.remove_labels(pk, &["admin".into()]).unwrap();
        let m = store.get(pk).unwrap();
        assert_eq!(m.labels, vec!["dev"]);
    }

    #[test]
    fn test_list() {
        let store = Store::new_memory();
        let pk1 = test_key();
        let pk2 = test_key();

        store.add(pk1).unwrap();
        store.add(pk2).unwrap();

        assert_eq!(store.list().len(), 2);
    }

    #[test]
    fn test_is_member() {
        let store = Store::new_memory();
        let pk = test_key();

        assert!(!store.is_member(pk));
        store.add(pk).unwrap();
        assert!(store.is_member(pk));
        store.remove(pk).unwrap();
        assert!(!store.is_member(pk));
    }

    #[test]
    fn test_persistence() {
        let dir = tempfile::tempdir().unwrap();
        let dir_str = dir.path().to_str().unwrap();

        let pk = test_key();

        // Create, add, save.
        {
            let store = Store::new(dir_str).unwrap();
            store.add(pk).unwrap();
            store
                .set_labels(pk, vec!["admin".into()])
                .unwrap();
        }

        // Reload.
        {
            let store = Store::new(dir_str).unwrap();
            assert_eq!(store.count(), 1);
            let m = store.get(pk).unwrap();
            assert_eq!(m.labels, vec!["admin"]);
        }
    }
}
