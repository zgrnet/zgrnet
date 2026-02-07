//! IP Allocator: bidirectional mapping between Noise public keys and IPv4 addresses.
//!
//! Allocates addresses from the CGNAT range (100.64.0.0/10) which won't conflict
//! with public IPs.

use crate::noise::Key;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::RwLock;

/// CGNAT IPv4 range: 100.64.0.0/10 (100.64.0.0 - 100.127.255.255)
const CGNAT_BASE: u32 = 0x6440_0000; // 100.64.0.0
const CGNAT_SIZE: u32 = 0x003F_FFFF; // 4,194,303 usable addresses

/// Thread-safe bidirectional mapping between public keys and IPv4 addresses.
pub struct IPAllocator {
    inner: RwLock<AllocatorInner>,
}

struct AllocatorInner {
    next_ipv4: u32, // offset from CGNAT_BASE for next allocation
    by_pubkey: HashMap<Key, Ipv4Addr>,
    by_ipv4: HashMap<Ipv4Addr, Key>,
}

impl Default for IPAllocator {
    fn default() -> Self {
        Self::new()
    }
}

impl IPAllocator {
    /// Creates a new IP allocator.
    /// Addresses are allocated starting from 100.64.0.2 (skipping .0 network and .1 reserved).
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(AllocatorInner {
                next_ipv4: 2, // start from 100.64.0.2
                by_pubkey: HashMap::new(),
                by_ipv4: HashMap::new(),
            }),
        }
    }

    /// Allocates an IPv4 address for the given public key.
    /// If the key already has an allocation, returns the existing IP.
    pub fn assign(&self, pk: Key) -> Result<Ipv4Addr, String> {
        let mut inner = self.inner.write().unwrap();

        // Return existing allocation
        if let Some(&ip) = inner.by_pubkey.get(&pk) {
            return Ok(ip);
        }

        // Check pool exhaustion
        if inner.next_ipv4 > CGNAT_SIZE {
            return Err("host: IP address pool exhausted".to_string());
        }

        // Allocate next address
        let ip = u32_to_ipv4(CGNAT_BASE + inner.next_ipv4);
        inner.next_ipv4 += 1;

        inner.by_pubkey.insert(pk, ip);
        inner.by_ipv4.insert(ip, pk);

        Ok(ip)
    }

    /// Assigns a specific IPv4 address to the given public key.
    /// Returns error if the IP is already assigned to a different key.
    pub fn assign_static(&self, pk: Key, ipv4: Ipv4Addr) -> Result<(), String> {
        let mut inner = self.inner.write().unwrap();

        // Check for conflict
        if let Some(&existing) = inner.by_ipv4.get(&ipv4) {
            if existing != pk {
                return Err(format!(
                    "host: IP {} already assigned to different peer",
                    ipv4
                ));
            }
        }

        inner.by_pubkey.insert(pk, ipv4);
        inner.by_ipv4.insert(ipv4, pk);

        Ok(())
    }

    /// Returns the public key associated with the given IP address.
    pub fn lookup_by_ip(&self, ip: Ipv4Addr) -> Option<Key> {
        let inner = self.inner.read().unwrap();
        inner.by_ipv4.get(&ip).copied()
    }

    /// Returns the IPv4 address associated with the given public key.
    pub fn lookup_by_pubkey(&self, pk: &Key) -> Option<Ipv4Addr> {
        let inner = self.inner.read().unwrap();
        inner.by_pubkey.get(pk).copied()
    }

    /// Removes the allocation for the given public key.
    pub fn remove(&self, pk: &Key) {
        let mut inner = self.inner.write().unwrap();

        if let Some(ip) = inner.by_pubkey.remove(pk) {
            inner.by_ipv4.remove(&ip);
        }
    }

    /// Returns the number of allocated addresses.
    pub fn count(&self) -> usize {
        let inner = self.inner.read().unwrap();
        inner.by_pubkey.len()
    }
}

/// Converts a u32 to an Ipv4Addr.
fn u32_to_ipv4(n: u32) -> Ipv4Addr {
    Ipv4Addr::new(
        (n >> 24) as u8,
        (n >> 16) as u8,
        (n >> 8) as u8,
        n as u8,
    )
}
