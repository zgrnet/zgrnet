//! Label store: manages pubkey → labels mapping from multiple sources.
//!
//! Labels come from:
//! - Host LAN labels: config peers (e.g., "host.zigor.net/trusted")
//! - Remote LAN labels: zgrlan API (e.g., "company.zigor.net/employee")

use std::collections::HashMap;
use std::sync::RwLock;

/// Thread-safe store mapping pubkey hex strings to labels.
pub struct LabelStore {
    inner: RwLock<HashMap<String, Vec<String>>>,
}

impl Default for LabelStore {
    fn default() -> Self {
        Self::new()
    }
}

impl LabelStore {
    /// Create an empty LabelStore.
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
        }
    }

    /// Returns all labels for the given pubkey (hex-encoded, lowercase).
    pub fn labels(&self, pubkey_hex: &str) -> Vec<String> {
        let inner = self.inner.read().unwrap();
        inner.get(pubkey_hex).cloned().unwrap_or_default()
    }

    /// Add labels to the given pubkey. Duplicates are ignored.
    pub fn add_labels(&self, pubkey_hex: &str, labels: &[String]) {
        if labels.is_empty() {
            return;
        }

        let mut inner = self.inner.write().unwrap();
        let existing = inner.entry(pubkey_hex.to_string()).or_default();
        for label in labels {
            if !existing.contains(label) {
                existing.push(label.clone());
            }
        }
    }

    /// Replace all labels for the given pubkey.
    pub fn set_labels(&self, pubkey_hex: &str, labels: &[String]) {
        let mut inner = self.inner.write().unwrap();
        if labels.is_empty() {
            inner.remove(pubkey_hex);
        } else {
            inner.insert(pubkey_hex.to_string(), labels.to_vec());
        }
    }

    /// Remove all labels for the given pubkey that belong to the
    /// specified LAN domain prefix. For example, `remove_labels(pk, "company.zigor.net")`
    /// removes all labels starting with "company.zigor.net/".
    pub fn remove_labels(&self, pubkey_hex: &str, lan_domain: &str) {
        let prefix = format!("{}/", lan_domain);

        let mut inner = self.inner.write().unwrap();
        if let Some(existing) = inner.get_mut(pubkey_hex) {
            existing.retain(|l| !l.starts_with(&prefix));
            if existing.is_empty() {
                inner.remove(pubkey_hex);
            }
        }
    }

    /// Remove all labels for the given pubkey.
    pub fn remove_peer(&self, pubkey_hex: &str) {
        let mut inner = self.inner.write().unwrap();
        inner.remove(pubkey_hex);
    }

    /// Populate the store with labels from config peers.
    /// Preserves existing labels from other sources (e.g., remote LANs).
    pub fn load_from_config(&self, peers: &std::collections::HashMap<String, super::PeerConfig>) {
        let mut inner = self.inner.write().unwrap();

        for (domain, peer) in peers {
            let pubkey_hex = match pubkey_hex_from_domain(domain) {
                Some(pk) => pk,
                None => continue,
            };
            if peer.labels.is_empty() {
                continue;
            }

            // Remove existing host lan labels, keep remote lan labels
            let existing = inner.entry(pubkey_hex.clone()).or_default();
            existing.retain(|l| !l.starts_with("host.zigor.net/"));

            // Add config labels
            for label in &peer.labels {
                if !existing.contains(label) {
                    existing.push(label.clone());
                }
            }
        }
    }

    /// Returns the number of pubkeys with labels.
    pub fn count(&self) -> usize {
        let inner = self.inner.read().unwrap();
        inner.len()
    }
}

/// Check if any of the peer's labels match a label pattern.
///
/// Supports:
/// - Exact match: "host.zigor.net/trusted"
/// - Wildcard match: "company.zigor.net/*" (matches any label under that domain)
pub fn match_label(peer_labels: &[String], pattern: &str) -> bool {
    if let Some(prefix) = pattern.strip_suffix("/*") {
        let prefix_with_slash = format!("{}/", prefix);
        peer_labels.iter().any(|l| l.starts_with(&prefix_with_slash))
    } else {
        peer_labels.iter().any(|l| l == pattern)
    }
}

/// Check if any of the peer's labels match any of the patterns.
/// Returns true if at least one pattern matches.
pub fn match_labels(peer_labels: &[String], patterns: &[String]) -> bool {
    patterns.iter().any(|p| match_label(peer_labels, p))
}

/// Extract the hex pubkey from a peer domain.
/// Format: "{hex}.zigor.net" -> lowercase hex string.
fn pubkey_hex_from_domain(domain: &str) -> Option<String> {
    let prefix = domain.strip_suffix(".zigor.net")?;
    if prefix.is_empty() || prefix.len() > 64 {
        return None;
    }
    let lower = prefix.to_lowercase();
    if lower.chars().all(|c| c.is_ascii_hexdigit()) {
        Some(lower)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_operations() {
        let store = LabelStore::new();
        let pk = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

        // Initially empty
        assert!(store.labels(pk).is_empty());
        assert_eq!(store.count(), 0);

        // Add labels
        store.add_labels(pk, &[
            "host.zigor.net/trusted".into(),
            "host.zigor.net/friend".into(),
        ]);
        let labels = store.labels(pk);
        assert_eq!(labels.len(), 2);
        assert_eq!(labels[0], "host.zigor.net/trusted");
        assert_eq!(labels[1], "host.zigor.net/friend");
        assert_eq!(store.count(), 1);
    }

    #[test]
    fn test_add_duplicates() {
        let store = LabelStore::new();
        let pk = "0000000000000000000000000000000000000000000000000000000000000001";

        store.add_labels(pk, &["host.zigor.net/trusted".into()]);
        store.add_labels(pk, &[
            "host.zigor.net/trusted".into(),
            "host.zigor.net/friend".into(),
        ]);

        let labels = store.labels(pk);
        assert_eq!(labels.len(), 2);
    }

    #[test]
    fn test_set_labels() {
        let store = LabelStore::new();
        let pk = "0000000000000000000000000000000000000000000000000000000000000001";

        store.add_labels(pk, &["host.zigor.net/old".into()]);
        store.set_labels(pk, &["host.zigor.net/new".into()]);

        let labels = store.labels(pk);
        assert_eq!(labels, vec!["host.zigor.net/new"]);

        // Empty set removes peer
        store.set_labels(pk, &[]);
        assert!(store.labels(pk).is_empty());
        assert_eq!(store.count(), 0);
    }

    #[test]
    fn test_remove_by_lan_domain() {
        let store = LabelStore::new();
        let pk = "0000000000000000000000000000000000000000000000000000000000000001";

        store.add_labels(pk, &[
            "host.zigor.net/trusted".into(),
            "company.zigor.net/employee".into(),
            "company.zigor.net/dev-team".into(),
        ]);

        store.remove_labels(pk, "company.zigor.net");

        let labels = store.labels(pk);
        assert_eq!(labels, vec!["host.zigor.net/trusted"]);
    }

    #[test]
    fn test_remove_peer() {
        let store = LabelStore::new();
        let pk = "0000000000000000000000000000000000000000000000000000000000000001";

        store.add_labels(pk, &["host.zigor.net/trusted".into()]);
        store.remove_peer(pk);

        assert!(store.labels(pk).is_empty());
    }

    #[test]
    fn test_load_from_config() {
        let store = LabelStore::new();
        let pk = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234567aa";
        let domain = format!("{}.zigor.net", pk);

        // Pre-populate with remote lan labels
        store.add_labels(pk, &["company.zigor.net/employee".into()]);

        let mut peers = HashMap::new();
        peers.insert(domain, super::super::PeerConfig {
            alias: "peer_us".into(),
            direct: vec!["1.2.3.4:51820".into()],
            relay: vec![],
            labels: vec!["host.zigor.net/trusted".into(), "host.zigor.net/exit-node".into()],
        });

        store.load_from_config(&peers);

        let labels = store.labels(pk);
        assert_eq!(labels.len(), 3);
        assert!(labels.contains(&"company.zigor.net/employee".to_string()));
        assert!(labels.contains(&"host.zigor.net/trusted".to_string()));
        assert!(labels.contains(&"host.zigor.net/exit-node".to_string()));
    }

    #[test]
    fn test_match_label_exact() {
        let labels: Vec<String> = vec![
            "host.zigor.net/trusted".into(),
            "company.zigor.net/employee".into(),
        ];

        assert!(match_label(&labels, "host.zigor.net/trusted"));
        assert!(!match_label(&labels, "host.zigor.net/friend"));
    }

    #[test]
    fn test_match_label_wildcard() {
        let labels: Vec<String> = vec![
            "company.zigor.net/employee".into(),
            "company.zigor.net/dev-team".into(),
        ];

        assert!(match_label(&labels, "company.zigor.net/*"));
        assert!(!match_label(&labels, "other.zigor.net/*"));
    }

    #[test]
    fn test_match_labels() {
        let labels: Vec<String> = vec!["host.zigor.net/trusted".into()];

        assert!(match_labels(&labels, &[
            "company.zigor.net/*".into(),
            "host.zigor.net/trusted".into(),
        ]));

        assert!(!match_labels(&labels, &[
            "company.zigor.net/*".into(),
            "other.zigor.net/admin".into(),
        ]));
    }

    #[test]
    fn test_match_labels_empty() {
        assert!(!match_labels(&[], &["host.zigor.net/trusted".into()]));
        assert!(!match_labels(&["host.zigor.net/trusted".into()], &[]));
    }

    #[test]
    fn test_pubkey_hex_from_domain() {
        assert_eq!(
            pubkey_hex_from_domain("abcdef01.zigor.net"),
            Some("abcdef01".into())
        );
        assert_eq!(
            pubkey_hex_from_domain("ABCDEF01.zigor.net"),
            Some("abcdef01".into())
        );
        assert_eq!(pubkey_hex_from_domain("not-hex.zigor.net"), None);
        assert_eq!(pubkey_hex_from_domain("example.com"), None);
        assert_eq!(pubkey_hex_from_domain(".zigor.net"), None);
    }
}
