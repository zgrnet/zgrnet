//! Fake IP pool for route-matched domains.
//!
//! Range: 198.18.0.0/15 (RFC 5737 benchmarking).
//! Bidirectional domain <-> IP mapping with O(1) amortized LRU eviction.
//!
//! Uses a generation-counter approach: each domain has a generation number.
//! The LRU queue stores (domain, gen) pairs. On touch, we increment the
//! generation and push a new entry. On eviction, we skip stale entries
//! whose generation doesn't match. This gives O(1) touch and O(1) amortized
//! eviction without needing a linked list.

use std::collections::{HashMap, VecDeque};
use std::net::Ipv4Addr;

/// Entry holding domain and associated peer for a Fake IP.
#[derive(Debug, Clone)]
pub struct FakeIPEntry {
    pub domain: String,
    pub peer: String,
}

/// Fake IP pool with bidirectional mapping and O(1) amortized LRU eviction.
pub struct FakeIPPool {
    domain_to_ip: HashMap<String, Ipv4Addr>,
    ip_to_entry: HashMap<u32, FakeIPEntry>,
    /// Generation counter per domain (incremented on each touch).
    domain_gen: HashMap<String, u64>,
    /// LRU queue: (domain, generation_at_insert). Stale entries are skipped.
    lru_queue: VecDeque<(String, u64)>,
    max_size: usize,
    base_ip: u32,   // 198.18.0.0 = 0xC6120000
    next_off: u32,
    max_off: u32,
}

impl FakeIPPool {
    /// Create a new Fake IP pool.
    pub fn new(max_size: usize) -> Self {
        let max_size = if max_size == 0 { 65536 } else { max_size };
        FakeIPPool {
            domain_to_ip: HashMap::new(),
            ip_to_entry: HashMap::new(),
            domain_gen: HashMap::new(),
            lru_queue: VecDeque::new(),
            max_size,
            base_ip: 0xC612_0000, // 198.18.0.0
            next_off: 1,          // Skip .0.0
            max_off: 131072 - 1,  // 198.19.255.255
        }
    }

    /// Assign a Fake IP for the given domain. O(1) amortized.
    pub fn assign(&mut self, domain: &str) -> Ipv4Addr {
        self.assign_with_peer(domain, "")
    }

    /// Assign a Fake IP for the given domain and store the associated peer.
    pub fn assign_with_peer(&mut self, domain: &str, peer: &str) -> Ipv4Addr {
        if let Some(&ip) = self.domain_to_ip.get(domain) {
            if !peer.is_empty() {
                let ip_key = u32::from(ip);
                self.ip_to_entry.insert(ip_key, FakeIPEntry {
                    domain: domain.to_string(), peer: peer.to_string(),
                });
            }
            self.touch_lru(domain);
            return ip;
        }

        if self.domain_to_ip.len() >= self.max_size {
            self.evict_lru();
        }

        let ip = self.alloc_ip();
        let ip_key = u32::from(ip);

        self.domain_to_ip.insert(domain.to_string(), ip);
        self.ip_to_entry.insert(ip_key, FakeIPEntry {
            domain: domain.to_string(), peer: peer.to_string(),
        });
        // Insert into LRU queue with generation 0
        self.domain_gen.insert(domain.to_string(), 0);
        self.lru_queue.push_back((domain.to_string(), 0));

        ip
    }

    /// Lookup the domain for a given Fake IP.
    pub fn lookup(&self, ip: Ipv4Addr) -> Option<&str> {
        self.ip_to_entry.get(&u32::from(ip)).map(|e| e.domain.as_str())
    }

    /// Lookup the full entry (domain + peer) for a given Fake IP.
    pub fn lookup_entry(&self, ip: Ipv4Addr) -> Option<&FakeIPEntry> {
        self.ip_to_entry.get(&u32::from(ip))
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

        // Check for IP collision from wrap-around: if this IP is still held
        // by an active domain, evict it first.
        if let Some(old_entry) = self.ip_to_entry.remove(&ip_val) {
            self.domain_to_ip.remove(&old_entry.domain);
            self.domain_gen.remove(&old_entry.domain);
        }

        Ipv4Addr::from(ip_val)
    }

    /// Touch: increment generation and push new entry. O(1).
    fn touch_lru(&mut self, domain: &str) {
        let gen = self.domain_gen.get_mut(domain).unwrap();
        *gen += 1;
        self.lru_queue.push_back((domain.to_string(), *gen));
    }

    /// Evict: pop front entries, skipping stale ones. O(1) amortized.
    fn evict_lru(&mut self) {
        while let Some((domain, gen)) = self.lru_queue.pop_front() {
            // Check if this entry is still current (not superseded by a touch)
            match self.domain_gen.get(&domain) {
                Some(&current_gen) if current_gen == gen => {
                    // This is the current entry — evict it
                    self.domain_gen.remove(&domain);
                    if let Some(ip) = self.domain_to_ip.remove(&domain) {
                        self.ip_to_entry.remove(&u32::from(ip));
                    }
                    return;
                }
                _ => {
                    // Stale entry (domain was touched since), skip it
                    continue;
                }
            }
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

    #[test]
    fn test_wrap_around() {
        let mut pool = FakeIPPool::new(200000);
        pool.next_off = pool.max_off;

        pool.assign("last.com");
        let ip = pool.assign("wrap.com");
        assert_eq!(ip, Ipv4Addr::new(198, 18, 0, 1));
    }

    #[test]
    fn test_default_size() {
        let pool = FakeIPPool::new(0);
        assert_eq!(pool.max_size, 65536);
    }

    #[test]
    fn test_evict_empty() {
        let mut pool = FakeIPPool::new(1);
        pool.evict_lru(); // should not panic
        assert_eq!(pool.size(), 0);
    }

    #[test]
    fn test_lookup_unknown_ip() {
        let pool = FakeIPPool::new(10);
        assert_eq!(pool.lookup(Ipv4Addr::new(1, 2, 3, 4)), None);
    }
}
