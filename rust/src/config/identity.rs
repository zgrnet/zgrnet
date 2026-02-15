//! Identity API: query peer identity by IP address.
//!
//! Provides a function that resolves an IP address to a peer's public key
//! and labels. This is used by HTTP services running on the TUN IP to
//! determine who is making a request.
//!
//! ```text
//! GET /internal/identity?ip=100.64.0.5
//! → { "pubkey": "abc123...", "labels": ["host.zigor.net/trusted", ...] }
//! ```

use std::net::Ipv4Addr;

use super::LabelStore;

/// Result of an identity lookup.
#[derive(Debug, Clone, serde::Serialize)]
pub struct IdentityResponse {
    pub pubkey: String,
    pub labels: Vec<String>,
}

/// Trait for IP-to-pubkey lookups, decoupling config from host.
pub trait IPAllocator: Send + Sync {
    /// Returns the 32-byte public key for the given IPv4 address.
    fn lookup_by_ip(&self, ip: Ipv4Addr) -> Option<[u8; 32]>;
}

/// Resolve an IP address to a peer's identity (pubkey + labels).
///
/// Returns None if the IP is not assigned to any peer.
pub fn lookup_identity(
    ip: Ipv4Addr,
    ip_alloc: &dyn IPAllocator,
    label_store: &LabelStore,
) -> Option<IdentityResponse> {
    let pubkey = ip_alloc.lookup_by_ip(ip)?;
    let pubkey_hex = hex::encode(pubkey);
    let labels = label_store.labels(&pubkey_hex);

    Some(IdentityResponse {
        pubkey: pubkey_hex,
        labels,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    struct MockAllocator {
        by_ip: HashMap<Ipv4Addr, [u8; 32]>,
    }

    impl IPAllocator for MockAllocator {
        fn lookup_by_ip(&self, ip: Ipv4Addr) -> Option<[u8; 32]> {
            self.by_ip.get(&ip).copied()
        }
    }

    fn hex_key(hex_str: &str) -> [u8; 32] {
        let mut key = [0u8; 32];
        let bytes = hex::decode(hex_str).unwrap();
        key[..bytes.len()].copy_from_slice(&bytes);
        key
    }

    #[test]
    fn test_lookup_identity() {
        let pk = hex_key("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789");
        let mut by_ip = HashMap::new();
        by_ip.insert(Ipv4Addr::new(100, 64, 0, 5), pk);
        let alloc = MockAllocator { by_ip };

        let store = LabelStore::new();
        store.set_labels(
            "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
            &["host.zigor.net/trusted".into(), "company.zigor.net/employee".into()],
        );

        let result = lookup_identity(Ipv4Addr::new(100, 64, 0, 5), &alloc, &store);
        assert!(result.is_some());
        let resp = result.unwrap();
        assert_eq!(resp.pubkey, "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789");
        assert_eq!(resp.labels.len(), 2);
        assert_eq!(resp.labels[0], "host.zigor.net/trusted");
    }

    #[test]
    fn test_lookup_identity_unknown_ip() {
        let alloc = MockAllocator { by_ip: HashMap::new() };
        let store = LabelStore::new();

        let result = lookup_identity(Ipv4Addr::new(100, 64, 0, 99), &alloc, &store);
        assert!(result.is_none());
    }

    #[test]
    fn test_lookup_identity_no_labels() {
        let pk = hex_key("0000000000000000000000000000000000000000000000000000000000000001");
        let mut by_ip = HashMap::new();
        by_ip.insert(Ipv4Addr::new(100, 64, 0, 2), pk);
        let alloc = MockAllocator { by_ip };
        let store = LabelStore::new();

        let result = lookup_identity(Ipv4Addr::new(100, 64, 0, 2), &alloc, &store);
        assert!(result.is_some());
        let resp = result.unwrap();
        assert!(resp.labels.is_empty());
    }
}
