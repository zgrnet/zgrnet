//! Policy engine for proxy target address validation.
//!
//! Controls which addresses are allowed for proxying.
//! Used on exit nodes to prevent SSRF attacks.

use crate::noise::address::Address;
use std::net::{Ipv4Addr, Ipv6Addr};

/// Policy trait for target address validation.
/// A `None` policy means allow all (for tests and trusted environments).
pub trait Policy: Send + Sync {
    /// Check if a connection to the given address is permitted.
    fn allow(&self, addr: &Address) -> bool;
}

/// Permits all addresses. Use for testing only.
pub struct AllowAllPolicy;

impl Policy for AllowAllPolicy {
    fn allow(&self, _addr: &Address) -> bool {
        true
    }
}

/// Blocks connections to private, loopback, and link-local IP addresses.
/// Prevents SSRF attacks through the exit node.
/// Domain names are allowed (resolved on exit node).
pub struct DenyPrivatePolicy;

impl Policy for DenyPrivatePolicy {
    fn allow(&self, addr: &Address) -> bool {
        use crate::noise::address::{ATYP_DOMAIN, ATYP_IPV4, ATYP_IPV6};

        if addr.atyp == ATYP_DOMAIN {
            return true;
        }

        if addr.atyp == ATYP_IPV4 {
            if let Ok(ip) = addr.host.parse::<Ipv4Addr>() {
                return !ip.is_loopback()
                    && !ip.is_private()
                    && !ip.is_link_local()
                    && !ip.is_unspecified()
                    && !is_shared_nat(ip);
            }
            return false;
        }

        if addr.atyp == ATYP_IPV6 {
            if let Ok(ip) = addr.host.parse::<Ipv6Addr>() {
                return !ip.is_loopback() && !ip.is_unspecified();
            }
            return false;
        }

        false
    }
}

/// Check if IPv4 is in Shared Address Space (100.64.0.0/10, RFC 6598).
fn is_shared_nat(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 100 && (octets[1] & 0xC0) == 64
}

/// Helper: check policy, treating None as allow-all.
pub fn check_policy(policy: Option<&dyn Policy>, addr: &Address) -> bool {
    match policy {
        Some(p) => p.allow(addr),
        None => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::noise::address::Address;

    #[test]
    fn test_allow_all() {
        let p = AllowAllPolicy;
        assert!(p.allow(&Address::ipv4("127.0.0.1", 80)));
        assert!(p.allow(&Address::domain("example.com", 443)));
    }

    #[test]
    fn test_deny_private() {
        let p = DenyPrivatePolicy;

        // Allowed
        assert!(p.allow(&Address::ipv4("8.8.8.8", 53)));
        assert!(p.allow(&Address::domain("example.com", 443)));

        // Denied
        assert!(!p.allow(&Address::ipv4("127.0.0.1", 80)));
        assert!(!p.allow(&Address::ipv4("10.0.0.1", 80)));
        assert!(!p.allow(&Address::ipv4("192.168.1.1", 80)));
        assert!(!p.allow(&Address::ipv4("169.254.169.254", 80)));
        assert!(!p.allow(&Address::ipv4("0.0.0.0", 80)));
        assert!(!p.allow(&Address::ipv6("::1", 80)));
    }

    #[test]
    fn test_check_policy_none() {
        // None policy = allow all
        assert!(check_policy(None, &Address::ipv4("127.0.0.1", 80)));
    }

    #[test]
    fn test_check_policy_deny() {
        let p = DenyPrivatePolicy;
        assert!(!check_policy(Some(&p), &Address::ipv4("127.0.0.1", 80)));
        assert!(check_policy(Some(&p), &Address::ipv4("8.8.8.8", 53)));
    }
}
