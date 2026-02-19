//! BindTable for RELAY BIND/ALIAS short mode.
//!
//! Each relay node maintains a BindTable. When forwarding a RELAY_0/1/2,
//! the relay allocates a relay_id, stores the routing info, and sends
//! BIND back to the sender. Subsequent messages use ALIAS mode.

use std::collections::HashMap;
use std::sync::{RwLock, atomic::{AtomicU32, Ordering}};
use std::time::Instant;
use super::message::*;

/// Entry in the BindTable mapping relay_id to routing info.
pub struct BindEntry {
    pub src_key: [u8; 32],
    pub dst_key: [u8; 32],
    pub next_hop: [u8; 32],
    pub created: Instant,
}

/// BindTable manages relay_id allocations for BIND/ALIAS short mode.
///
/// Thread-safe via RwLock.
pub struct BindTable {
    entries: RwLock<HashMap<u32, BindEntry>>,
    next_id: AtomicU32,
}

impl BindTable {
    pub fn new() -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            next_id: AtomicU32::new(1), // 0 is reserved
        }
    }

    pub fn allocate(&self, src: [u8; 32], dst: [u8; 32], next_hop: [u8; 32]) -> u32 {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let entry = BindEntry {
            src_key: src,
            dst_key: dst,
            next_hop,
            created: Instant::now(),
        };
        self.entries.write().unwrap().insert(id, entry);
        id
    }

    pub fn lookup(&self, relay_id: u32) -> Option<([u8; 32], [u8; 32], [u8; 32])> {
        let entries = self.entries.read().unwrap();
        entries.get(&relay_id).map(|e| (e.src_key, e.dst_key, e.next_hop))
    }

    pub fn remove(&self, relay_id: u32) {
        self.entries.write().unwrap().remove(&relay_id);
    }

    pub fn len(&self) -> usize {
        self.entries.read().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.read().unwrap().is_empty()
    }

    pub fn expire(&self, max_age: std::time::Duration) -> usize {
        let cutoff = Instant::now() - max_age;
        let mut entries = self.entries.write().unwrap();
        let before = entries.len();
        entries.retain(|_, e| e.created >= cutoff);
        before - entries.len()
    }
}

impl Default for BindTable {
    fn default() -> Self {
        Self::new()
    }
}

/// Process RELAY_0 with BIND: forward + optional BIND action back to sender.
pub fn handle_relay0_with_bind(
    router: &dyn super::engine::Router,
    bt: &BindTable,
    from: &[u8; 32],
    data: &[u8],
) -> Result<(/*forward*/ super::engine::Action, /*bind*/ Option<super::engine::Action>), RelayError> {
    let r0 = decode_relay0(data)?;
    if r0.ttl == 0 {
        return Err(RelayError::TtlExpired);
    }

    let next_hop = router.next_hop(&r0.dst_key, r0.strategy)?;

    let forward = if next_hop == r0.dst_key {
        let r2 = Relay2 { src_key: *from, payload: r0.payload.clone() };
        super::engine::Action { dst: next_hop, protocol: 68, data: encode_relay2(&r2) }
    } else {
        let r1 = Relay1 {
            ttl: r0.ttl - 1, strategy: r0.strategy,
            src_key: *from, dst_key: r0.dst_key, payload: r0.payload,
        };
        super::engine::Action { dst: next_hop, protocol: 67, data: encode_relay1(&r1) }
    };

    let relay_id = bt.allocate(*from, r0.dst_key, next_hop);
    let bind_msg = encode_relay0_bind(&Relay0Bind { relay_id, dst_key: r0.dst_key });
    let bind_action = super::engine::Action { dst: *from, protocol: 72, data: bind_msg };

    Ok((forward, Some(bind_action)))
}

/// Process RELAY_0_ALIAS: lookup relay_id, reconstitute routing, forward.
pub fn handle_relay0_alias(
    bt: &BindTable,
    from: &[u8; 32],
    data: &[u8],
) -> Result<super::engine::Action, RelayError> {
    let alias = decode_relay0_alias(data)?;

    let (src, dst, next_hop) = bt.lookup(alias.relay_id).ok_or(RelayError::NoRoute)?;

    if src != *from {
        return Err(RelayError::NoRoute);
    }

    if next_hop == dst {
        let r2 = Relay2 { src_key: *from, payload: alias.payload };
        Ok(super::engine::Action { dst: next_hop, protocol: 68, data: encode_relay2(&r2) })
    } else {
        let r1 = Relay1 {
            ttl: DEFAULT_TTL, strategy: Strategy::Auto,
            src_key: *from, dst_key: dst, payload: alias.payload,
        };
        Ok(super::engine::Action { dst: next_hop, protocol: 67, data: encode_relay1(&r1) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap as StdMap;

    struct StaticRouter {
        routes: StdMap<[u8; 32], [u8; 32]>,
    }

    impl super::super::engine::Router for StaticRouter {
        fn next_hop(&self, dst: &[u8; 32], _: Strategy) -> Result<[u8; 32], RelayError> {
            self.routes.get(dst).copied().ok_or(RelayError::NoRoute)
        }
    }

    fn pk(b: u8) -> [u8; 32] {
        let mut k = [0u8; 32];
        k[0] = b;
        k
    }

    #[test]
    fn test_allocate_and_lookup() {
        let bt = BindTable::new();
        let src = pk(0x0A);
        let dst = pk(0x0D);
        let nh = pk(0x0C);

        let id = bt.allocate(src, dst, nh);
        assert!(id > 0);

        let (s, d, n) = bt.lookup(id).unwrap();
        assert_eq!(s, src);
        assert_eq!(d, dst);
        assert_eq!(n, nh);
    }

    #[test]
    fn test_lookup_missing() {
        let bt = BindTable::new();
        assert!(bt.lookup(999).is_none());
    }

    #[test]
    fn test_unique_ids() {
        let bt = BindTable::new();
        let mut ids = std::collections::HashSet::new();
        for i in 0..100u8 {
            let id = bt.allocate(pk(i), pk(0xFF), pk(0xFE));
            assert!(ids.insert(id), "duplicate relay_id: {}", id);
        }
        assert_eq!(bt.len(), 100);
    }

    #[test]
    fn test_remove() {
        let bt = BindTable::new();
        let id = bt.allocate(pk(1), pk(2), pk(3));
        assert_eq!(bt.len(), 1);
        bt.remove(id);
        assert_eq!(bt.len(), 0);
        assert!(bt.lookup(id).is_none());
    }

    #[test]
    fn test_handle_relay0_with_bind() {
        let key_a = pk(0x0A);
        let key_b = pk(0x0B);
        let payload = b"test payload".to_vec();

        let mut routes = StdMap::new();
        routes.insert(key_b, key_b);
        let router = StaticRouter { routes };
        let bt = BindTable::new();

        let r0_data = encode_relay0(&Relay0 {
            ttl: 8, strategy: Strategy::Auto, dst_key: key_b, payload: payload.clone(),
        });

        let (fwd, bind) = handle_relay0_with_bind(&router, &bt, &key_a, &r0_data).unwrap();

        assert_eq!(fwd.dst, key_b);
        assert_eq!(fwd.protocol, 68);

        let bind = bind.unwrap();
        assert_eq!(bind.dst, key_a);
        assert_eq!(bind.protocol, 72);
        assert_eq!(bt.len(), 1);
    }

    #[test]
    fn test_handle_relay0_alias() {
        let key_a = pk(0x0A);
        let key_b = pk(0x0B);
        let key_c = pk(0x0C);
        let payload = b"alias data".to_vec();

        let bt = BindTable::new();
        let relay_id = bt.allocate(key_a, key_b, key_c);

        let alias_data = encode_relay0_alias(&Relay0Alias {
            relay_id, payload: payload.clone(),
        });

        let action = handle_relay0_alias(&bt, &key_a, &alias_data).unwrap();
        assert_eq!(action.dst, key_c);
        assert_eq!(action.protocol, 67); // RELAY_1

        let r1 = decode_relay1(&action.data).unwrap();
        assert_eq!(r1.src_key, key_a);
        assert_eq!(r1.dst_key, key_b);
        assert_eq!(r1.payload, payload);
    }

    #[test]
    fn test_alias_wrong_sender() {
        let bt = BindTable::new();
        let relay_id = bt.allocate(pk(0x0A), pk(0x0B), pk(0x0C));
        let alias_data = encode_relay0_alias(&Relay0Alias { relay_id, payload: vec![] });
        assert_eq!(
            handle_relay0_alias(&bt, &pk(0xFF), &alias_data).unwrap_err(),
            RelayError::NoRoute
        );
    }

    #[test]
    fn test_alias_unknown_id() {
        let bt = BindTable::new();
        let alias_data = encode_relay0_alias(&Relay0Alias { relay_id: 999, payload: vec![] });
        assert_eq!(
            handle_relay0_alias(&bt, &pk(0x0A), &alias_data).unwrap_err(),
            RelayError::NoRoute
        );
    }
}
