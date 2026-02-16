//! LAN membership storage — trait + built-in implementations.
//!
//! [`Store`] is the abstract interface. Two implementations:
//! - [`MemStore`]: in-memory, no persistence (good for testing)
//! - [`FileStore`]: wraps MemStore + JSON file persistence

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

/// Abstract store interface for LAN membership.
/// Implementations must be Send + Sync for multi-threaded HTTP servers.
pub trait Store: Send + Sync {
    fn add(&self, pk: Key) -> Result<bool, String>;
    fn remove(&self, pk: Key) -> Result<bool, String>;
    fn get(&self, pk: Key) -> Option<Member>;
    fn is_member(&self, pk: Key) -> bool;
    fn list(&self) -> Vec<Member>;
    fn count(&self) -> usize;
    fn set_labels(&self, pk: Key, labels: Vec<String>) -> Result<(), String>;
    fn remove_labels(&self, pk: Key, to_remove: &[String]) -> Result<(), String>;
}

// ── MemStore ────────────────────────────────────────────────────────────────

/// In-memory store. Fast, no I/O, data lost on process exit.
pub struct MemStore {
    inner: RwLock<HashMap<Key, Member>>,
}

impl Default for MemStore {
    fn default() -> Self {
        Self::new()
    }
}

impl MemStore {
    pub fn new() -> Self {
        MemStore {
            inner: RwLock::new(HashMap::new()),
        }
    }
}

impl Store for MemStore {
    fn add(&self, pk: Key) -> Result<bool, String> {
        let mut inner = self.inner.write().unwrap();
        if inner.contains_key(&pk) {
            return Ok(false);
        }
        inner.insert(
            pk,
            Member {
                pubkey: pk.to_hex(),
                labels: vec![],
                joined_at: now_rfc3339(),
            },
        );
        Ok(true)
    }

    fn remove(&self, pk: Key) -> Result<bool, String> {
        let mut inner = self.inner.write().unwrap();
        Ok(inner.remove(&pk).is_some())
    }

    fn get(&self, pk: Key) -> Option<Member> {
        self.inner.read().unwrap().get(&pk).cloned()
    }

    fn is_member(&self, pk: Key) -> bool {
        self.inner.read().unwrap().contains_key(&pk)
    }

    fn list(&self) -> Vec<Member> {
        self.inner.read().unwrap().values().cloned().collect()
    }

    fn count(&self) -> usize {
        self.inner.read().unwrap().len()
    }

    fn set_labels(&self, pk: Key, labels: Vec<String>) -> Result<(), String> {
        let mut inner = self.inner.write().unwrap();
        let m = inner
            .get_mut(&pk)
            .ok_or_else(|| format!("lan: pubkey {} is not a member", pk.short_hex()))?;
        m.labels = labels;
        Ok(())
    }

    fn remove_labels(&self, pk: Key, to_remove: &[String]) -> Result<(), String> {
        let mut inner = self.inner.write().unwrap();
        let m = inner
            .get_mut(&pk)
            .ok_or_else(|| format!("lan: pubkey {} is not a member", pk.short_hex()))?;
        m.labels.retain(|l| !to_remove.contains(l));
        Ok(())
    }
}

// ── FileStore ───────────────────────────────────────────────────────────────

/// JSON structure for persistence.
#[derive(Serialize, Deserialize)]
struct StoreFile {
    members: Vec<Member>,
}

/// File-backed store. Wraps MemStore and persists every mutation to JSON.
pub struct FileStore {
    mem: MemStore,
    path: PathBuf,
}

impl FileStore {
    /// Creates a file-backed store. Loads existing data if the file exists.
    pub fn new(data_dir: &str) -> Result<Self, String> {
        let path = PathBuf::from(data_dir).join("members.json");
        let mem = MemStore::new();

        if path.exists() {
            let data = std::fs::read_to_string(&path)
                .map_err(|e| format!("lan: read {:?}: {}", path, e))?;
            let sf: StoreFile = serde_json::from_str(&data)
                .map_err(|e| format!("lan: parse {:?}: {}", path, e))?;
            let mut inner = mem.inner.write().unwrap();
            for m in sf.members {
                if let Ok(pk) = Key::from_hex(&m.pubkey) {
                    inner.insert(pk, m);
                }
            }
        }

        Ok(FileStore { mem, path })
    }

    fn save(&self) -> Result<(), String> {
        let inner = self.mem.inner.read().unwrap();
        let sf = StoreFile {
            members: inner.values().cloned().collect(),
        };
        drop(inner);

        let data = serde_json::to_string_pretty(&sf)
            .map_err(|e| format!("lan: marshal: {}", e))?;

        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir)
                .map_err(|e| format!("lan: mkdir {:?}: {}", dir, e))?;
        }

        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, &data)
            .map_err(|e| format!("lan: write {:?}: {}", tmp, e))?;
        std::fs::rename(&tmp, &self.path)
            .map_err(|e| format!("lan: rename {:?} → {:?}: {}", tmp, self.path, e))?;

        Ok(())
    }
}

impl Store for FileStore {
    fn add(&self, pk: Key) -> Result<bool, String> {
        let added = self.mem.add(pk)?;
        if added {
            if let Err(e) = self.save() {
                self.mem.remove(pk).ok();
                return Err(e);
            }
        }
        Ok(added)
    }

    fn remove(&self, pk: Key) -> Result<bool, String> {
        let snapshot = self.mem.get(pk);
        let removed = self.mem.remove(pk)?;
        if removed {
            if let Err(e) = self.save() {
                // Rollback: re-add member with original data.
                if let Some(m) = snapshot {
                    self.mem.add(pk).ok();
                    self.mem.set_labels(pk, m.labels).ok();
                }
                return Err(e);
            }
        }
        Ok(removed)
    }

    fn get(&self, pk: Key) -> Option<Member> { self.mem.get(pk) }
    fn is_member(&self, pk: Key) -> bool { self.mem.is_member(pk) }
    fn list(&self) -> Vec<Member> { self.mem.list() }
    fn count(&self) -> usize { self.mem.count() }

    fn set_labels(&self, pk: Key, labels: Vec<String>) -> Result<(), String> {
        let old = self.mem.get(pk).map(|m| m.labels);
        self.mem.set_labels(pk, labels)?;
        if let Err(e) = self.save() {
            // Rollback to old labels.
            if let Some(old_labels) = old {
                self.mem.set_labels(pk, old_labels).ok();
            }
            return Err(e);
        }
        Ok(())
    }

    fn remove_labels(&self, pk: Key, to_remove: &[String]) -> Result<(), String> {
        let old = self.mem.get(pk).map(|m| m.labels);
        self.mem.remove_labels(pk, to_remove)?;
        if let Err(e) = self.save() {
            if let Some(old_labels) = old {
                self.mem.set_labels(pk, old_labels).ok();
            }
            return Err(e);
        }
        Ok(())
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────────

pub(crate) fn now_rfc3339() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = dur.as_secs();
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let mins = (time_of_day % 3600) / 60;
    let s = time_of_day % 60;
    let (y, m, d) = days_to_date(days);
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", y, m, d, hours, mins, s)
}

pub(crate) fn days_to_date(days: u64) -> (u64, u64, u64) {
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

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::noise::KeyPair;

    fn test_key() -> Key {
        KeyPair::generate().public
    }

    #[test]
    fn test_mem_add_and_get() {
        let store = MemStore::new();
        let pk = test_key();

        assert!(store.add(pk).unwrap());
        assert!(!store.add(pk).unwrap());

        let m = store.get(pk).unwrap();
        assert_eq!(m.pubkey, pk.to_hex());
        assert!(m.labels.is_empty());
        assert_eq!(store.count(), 1);
    }

    #[test]
    fn test_mem_remove() {
        let store = MemStore::new();
        let pk = test_key();

        store.add(pk).unwrap();
        assert!(store.remove(pk).unwrap());
        assert!(!store.remove(pk).unwrap());
        assert_eq!(store.count(), 0);
    }

    #[test]
    fn test_mem_labels() {
        let store = MemStore::new();
        let pk = test_key();

        store.add(pk).unwrap();
        store.set_labels(pk, vec!["admin".into(), "dev".into()]).unwrap();

        let m = store.get(pk).unwrap();
        assert_eq!(m.labels, vec!["admin", "dev"]);

        store.remove_labels(pk, &["admin".into()]).unwrap();
        let m = store.get(pk).unwrap();
        assert_eq!(m.labels, vec!["dev"]);
    }

    #[test]
    fn test_mem_list() {
        let store = MemStore::new();
        store.add(test_key()).unwrap();
        store.add(test_key()).unwrap();
        assert_eq!(store.list().len(), 2);
    }

    #[test]
    fn test_mem_is_member() {
        let store = MemStore::new();
        let pk = test_key();

        assert!(!store.is_member(pk));
        store.add(pk).unwrap();
        assert!(store.is_member(pk));
        store.remove(pk).unwrap();
        assert!(!store.is_member(pk));
    }

    #[test]
    fn test_file_persistence() {
        let dir = tempfile::tempdir().unwrap();
        let dir_str = dir.path().to_str().unwrap();

        let pk = test_key();

        {
            let store = FileStore::new(dir_str).unwrap();
            store.add(pk).unwrap();
            store.set_labels(pk, vec!["admin".into()]).unwrap();
        }

        {
            let store = FileStore::new(dir_str).unwrap();
            assert_eq!(store.count(), 1);
            let m = store.get(pk).unwrap();
            assert_eq!(m.labels, vec!["admin"]);
        }
    }
}
