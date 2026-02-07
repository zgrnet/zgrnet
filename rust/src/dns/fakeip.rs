//! Fake IP pool for route-matched domains.
//!
//! Range: 198.18.0.0/15 (RFC 5737 benchmarking).
//! Bidirectional domain <-> IP mapping with LRU eviction.

use std::collections::HashMap;
use std::net::Ipv4Addr;

/// Fake IP pool with bidirectional mapping and LRU eviction.
pub struct FakeIPPool {
    domain_to_ip: HashMap<String, Ipv4Addr>,
    ip_to_domain: HashMap<u32, String>,
    lru_order: Vec<String>,
    max_size: usize,
    base_ip: u32,   // 198.18.0.0 = 0xC6120000
    next_off: u32,
    max_off: u32,
}

impl FakeIPPool {
    /// Create a new Fake IP pool.
    /// If max_size <= 0, defaults to 65536.
    pub fn new(max_size: usize) -> Self {
        let max_size = if max_size == 0 { 65536 } else { max_size };
        FakeIPPool {
            domain_to_ip: HashMap::new(),
            ip_to_domain: HashMap::new(),
            lru_order: Vec::new(),
            max_size,
            base_ip: 0xC612_0000, // 198.18.0.0
            next_off: 1,          // Skip .0.0
            max_off: 131072 - 1,  // 198.19.255.255
        }
    }

    /// Assign a Fake IP for the given domain.
    /// Returns the same IP for the same domain (idempotent).
    pub fn assign(&mut self, domain: &str) -> Ipv4Addr {
        if let Some(&ip) = self.domain_to_ip.get(domain) {
            self.touch_lru(domain);
            return ip;
        }

        if self.domain_to_ip.len() >= self.max_size {
            self.evict_lru();
        }

        let ip = self.alloc_ip();
        let ip_key = u32::from(ip);

        self.domain_to_ip.insert(domain.to_string(), ip);
        self.ip_to_domain.insert(ip_key, domain.to_string());
        self.lru_order.push(domain.to_string());

        ip
    }

    /// Lookup the domain for a given Fake IP.
    pub fn lookup(&self, ip: Ipv4Addr) -> Option<&str> {
        self.ip_to_domain.get(&u32::from(ip)).map(|s| s.as_str())
    }

    /// Lookup the Fake IP for a given domain without allocating.
    pub fn lookup_domain(&self, domain: &str) -> Option<Ipv4Addr> {
        self.domain_to_ip.get(domain).copied()
    }

    /// Number of entries in the pool.
    pub fn size(&self) -> usize {
        self.domain_to_ip.len()
    }

    fn alloc_ip(&mut self) -> Ipv4Addr {
        let ip_val = self.base_ip + self.next_off;
        self.next_off += 1;
        if self.next_off > self.max_off {
            self.next_off = 1;
        }
        Ipv4Addr::from(ip_val)
    }

    fn touch_lru(&mut self, domain: &str) {
        if let Some(pos) = self.lru_order.iter().position(|d| d == domain) {
            self.lru_order.remove(pos);
            self.lru_order.push(domain.to_string());
        }
    }

    fn evict_lru(&mut self) {
        if self.lru_order.is_empty() {
            return;
        }
        let victim = self.lru_order.remove(0);
        if let Some(ip) = self.domain_to_ip.remove(&victim) {
            self.ip_to_domain.remove(&u32::from(ip));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_assign() {
        let mut pool = FakeIPPool::new(100);
        let ip1 = pool.assign("example.com");

        // In range 198.18.x.x
        let octets = ip1.octets();
        assert_eq!(octets[0], 198);
        assert_eq!(octets[1], 18);

        // Same domain, same IP
        let ip2 = pool.assign("example.com");
        assert_eq!(ip1, ip2);

        // Different domain, different IP
        let ip3 = pool.assign("other.com");
        assert_ne!(ip1, ip3);
    }

    #[test]
    fn test_lookup() {
        let mut pool = FakeIPPool::new(100);
        let ip = pool.assign("test.example.com");

        assert_eq!(pool.lookup(ip), Some("test.example.com"));
        assert_eq!(pool.lookup(Ipv4Addr::new(1, 2, 3, 4)), None);
    }

    #[test]
    fn test_lookup_domain() {
        let mut pool = FakeIPPool::new(100);
        assert_eq!(pool.lookup_domain("notassigned.com"), None);

        let expected = pool.assign("test.com");
        assert_eq!(pool.lookup_domain("test.com"), Some(expected));
    }

    #[test]
    fn test_lru_eviction() {
        let mut pool = FakeIPPool::new(3);
        pool.assign("a.com");
        pool.assign("b.com");
        pool.assign("c.com");
        assert_eq!(pool.size(), 3);

        // Adding 4th evicts a.com
        pool.assign("d.com");
        assert_eq!(pool.size(), 3);
        assert_eq!(pool.lookup_domain("a.com"), None);
        assert!(pool.lookup_domain("b.com").is_some());
        assert!(pool.lookup_domain("d.com").is_some());
    }

    #[test]
    fn test_lru_touch() {
        let mut pool = FakeIPPool::new(3);
        pool.assign("a.com");
        pool.assign("b.com");
        pool.assign("c.com");

        // Touch a.com
        pool.assign("a.com");

        // Add d.com -> evicts b.com (now LRU)
        pool.assign("d.com");
        assert!(pool.lookup_domain("a.com").is_some());
        assert_eq!(pool.lookup_domain("b.com"), None);
    }

    #[test]
    fn test_ip_range() {
        let mut pool = FakeIPPool::new(1000);
        for i in 0..100 {
            let domain = format!("test{}.example.com", i);
            let ip = pool.assign(&domain);
            let octets = ip.octets();
            assert_eq!(octets[0], 198);
            assert!(octets[1] == 18 || octets[1] == 19);
        }
    }
}
