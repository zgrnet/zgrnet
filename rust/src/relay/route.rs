//! RouteTable for relay routing decisions.
//!
//! Provides next-hop routing for both relay engine forwarding (Router trait)
//! and outbound relay wrapping (relay_for).

use std::collections::HashMap;
use std::sync::RwLock;
use super::message::{Strategy, RelayError};
use super::engine::Router;

/// RouteTable provides next-hop routing decisions for relay forwarding and
/// outbound relay wrapping. Implements the Router trait.
///
/// Thread-safe: all methods acquire the internal RwLock.
pub struct RouteTable {
    routes: RwLock<HashMap<[u8; 32], [u8; 32]>>,
}

impl RouteTable {
    /// Create an empty route table.
    pub fn new() -> Self {
        Self {
            routes: RwLock::new(HashMap::new()),
        }
    }

    /// Set the next-hop for reaching dst.
    pub fn add_route(&self, dst: [u8; 32], next_hop: [u8; 32]) {
        self.routes.write().unwrap().insert(dst, next_hop);
    }

    /// Remove the route for dst.
    pub fn remove_route(&self, dst: &[u8; 32]) {
        self.routes.write().unwrap().remove(dst);
    }

    /// Returns the relay peer's key if dst should be sent through a relay,
    /// or None if dst is directly reachable.
    ///
    /// A destination is relayed when a route exists AND next_hop != dst.
    pub fn relay_for(&self, dst: &[u8; 32]) -> Option<[u8; 32]> {
        let routes = self.routes.read().unwrap();
        match routes.get(dst) {
            Some(nh) if nh != dst => Some(*nh),
            _ => None,
        }
    }

    /// Returns whether an explicit route exists for dst.
    pub fn has_route(&self, dst: &[u8; 32]) -> bool {
        self.routes.read().unwrap().contains_key(dst)
    }

    /// Returns the number of routes.
    pub fn len(&self) -> usize {
        self.routes.read().unwrap().len()
    }

    /// Returns whether the route table is empty.
    pub fn is_empty(&self) -> bool {
        self.routes.read().unwrap().is_empty()
    }

    /// Returns a snapshot copy of all routes.
    pub fn routes(&self) -> HashMap<[u8; 32], [u8; 32]> {
        self.routes.read().unwrap().clone()
    }
}

impl Default for RouteTable {
    fn default() -> Self {
        Self::new()
    }
}

impl Router for RouteTable {
    fn next_hop(&self, dst: &[u8; 32], _strategy: Strategy) -> Result<[u8; 32], RelayError> {
        let routes = self.routes.read().unwrap();
        match routes.get(dst) {
            Some(nh) => Ok(*nh),
            None => Ok(*dst), // No route: treat as direct
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pk(b: u8) -> [u8; 32] {
        let mut k = [0u8; 32];
        k[0] = b;
        k
    }

    #[test]
    fn test_add_and_lookup() {
        let rt = RouteTable::new();
        let dst = pk(0x0D);
        let relay = pk(0x0C);

        rt.add_route(dst, relay);

        let nh = rt.next_hop(&dst, Strategy::Auto).unwrap();
        assert_eq!(nh, relay);

        let r = rt.relay_for(&dst);
        assert_eq!(r, Some(relay));
    }

    #[test]
    fn test_direct_route() {
        let rt = RouteTable::new();
        let dst = pk(0x0D);
        rt.add_route(dst, dst); // next_hop == dst

        let nh = rt.next_hop(&dst, Strategy::Auto).unwrap();
        assert_eq!(nh, dst);

        assert_eq!(rt.relay_for(&dst), None);
    }

    #[test]
    fn test_no_route() {
        let rt = RouteTable::new();
        let dst = pk(0x0D);

        let nh = rt.next_hop(&dst, Strategy::Auto).unwrap();
        assert_eq!(nh, dst); // returns dst itself

        assert_eq!(rt.relay_for(&dst), None);
    }

    #[test]
    fn test_remove() {
        let rt = RouteTable::new();
        let dst = pk(0x0D);
        let relay = pk(0x0C);

        rt.add_route(dst, relay);
        assert_eq!(rt.len(), 1);

        rt.remove_route(&dst);
        assert_eq!(rt.len(), 0);
        assert_eq!(rt.relay_for(&dst), None);
    }

    #[test]
    fn test_overwrite() {
        let rt = RouteTable::new();
        let dst = pk(0x0D);
        let relay1 = pk(0x0C);
        let relay2 = pk(0x0B);

        rt.add_route(dst, relay1);
        rt.add_route(dst, relay2);

        assert_eq!(rt.relay_for(&dst), Some(relay2));
        assert_eq!(rt.len(), 1);
    }

    #[test]
    fn test_has_route() {
        let rt = RouteTable::new();
        let dst = pk(0x0D);
        let relay = pk(0x0C);

        assert!(!rt.has_route(&dst));
        rt.add_route(dst, relay);
        assert!(rt.has_route(&dst));
        rt.remove_route(&dst);
        assert!(!rt.has_route(&dst));
    }

    #[test]
    fn test_routes_snapshot() {
        let rt = RouteTable::new();
        let a = pk(0x0A);
        let b = pk(0x0B);
        let c = pk(0x0C);

        rt.add_route(a, c);
        rt.add_route(b, c);

        let snap = rt.routes();
        assert_eq!(snap.len(), 2);
        assert_eq!(snap[&a], c);
        assert_eq!(snap[&b], c);
    }

    #[test]
    fn test_implements_router() {
        let rt = RouteTable::new();
        let dst = pk(0x0D);
        let relay = pk(0x0C);
        rt.add_route(dst, relay);

        let router: &dyn Router = &rt;
        let nh = router.next_hop(&dst, Strategy::Fastest).unwrap();
        assert_eq!(nh, relay);
    }

    #[test]
    fn test_multiple_destinations() {
        let rt = RouteTable::new();
        let relay1 = pk(0x01);
        let relay2 = pk(0x02);

        for i in 10u8..20 {
            let dst = pk(i);
            if i % 2 == 0 {
                rt.add_route(dst, relay1);
            } else {
                rt.add_route(dst, relay2);
            }
        }

        assert_eq!(rt.len(), 10);

        for i in 10u8..20 {
            let dst = pk(i);
            let r = rt.relay_for(&dst).unwrap();
            if i % 2 == 0 {
                assert_eq!(r, relay1);
            } else {
                assert_eq!(r, relay2);
            }
        }
    }

    #[test]
    fn test_concurrent_access() {
        use std::sync::Arc;
        use std::thread;

        let rt = Arc::new(RouteTable::new());
        let mut handles = vec![];

        for i in 0u8..100 {
            let rt = Arc::clone(&rt);
            handles.push(thread::spawn(move || {
                let dst = pk(i);
                let relay = pk(i.wrapping_add(100));
                rt.add_route(dst, relay);
                rt.relay_for(&dst);
                rt.next_hop(&dst, Strategy::Auto).unwrap();
                rt.has_route(&dst);
                rt.routes();
                rt.len();
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        assert_eq!(rt.len(), 100);
    }
}
