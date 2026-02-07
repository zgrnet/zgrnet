//! Network address encoding/decoding (SOCKS5 compatible).
//!
//! Wire format: atyp(1B) | addr(var) | port(2B BE)
//!   atyp=0x01: IPv4, addr=4 bytes
//!   atyp=0x03: Domain, addr=1 byte len + string
//!   atyp=0x04: IPv6, addr=16 bytes

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

/// Address type constants (SOCKS5 compatible).
pub const ATYP_IPV4: u8 = 0x01;
pub const ATYP_DOMAIN: u8 = 0x03;
pub const ATYP_IPV6: u8 = 0x04;

/// A network address with type, host, and port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Address {
    pub atyp: u8,
    pub host: String,
    pub port: u16,
}

/// Address errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddressError {
    /// Data too short.
    TooShort,
    /// Invalid address type.
    InvalidType(u8),
    /// Invalid IPv4 address.
    InvalidIPv4,
    /// Invalid IPv6 address.
    InvalidIPv6,
    /// Invalid domain (empty).
    InvalidDomain,
}

impl fmt::Display for AddressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AddressError::TooShort => write!(f, "address data too short"),
            AddressError::InvalidType(t) => write!(f, "unknown address type 0x{:02x}", t),
            AddressError::InvalidIPv4 => write!(f, "invalid IPv4 address"),
            AddressError::InvalidIPv6 => write!(f, "invalid IPv6 address"),
            AddressError::InvalidDomain => write!(f, "invalid domain"),
        }
    }
}

impl std::error::Error for AddressError {}

impl Address {
    /// Create a new IPv4 address.
    pub fn ipv4(host: &str, port: u16) -> Self {
        Address {
            atyp: ATYP_IPV4,
            host: host.to_string(),
            port,
        }
    }

    /// Create a new IPv6 address.
    pub fn ipv6(host: &str, port: u16) -> Self {
        Address {
            atyp: ATYP_IPV6,
            host: host.to_string(),
            port,
        }
    }

    /// Create a new domain address.
    pub fn domain(host: &str, port: u16) -> Self {
        Address {
            atyp: ATYP_DOMAIN,
            host: host.to_string(),
            port,
        }
    }

    /// Encode the address to bytes.
    pub fn encode(&self) -> Result<Vec<u8>, AddressError> {
        match self.atyp {
            ATYP_IPV4 => {
                let ip: Ipv4Addr = self.host.parse().map_err(|_| AddressError::InvalidIPv4)?;
                let octets = ip.octets();
                let mut buf = Vec::with_capacity(7);
                buf.push(ATYP_IPV4);
                buf.extend_from_slice(&octets);
                buf.extend_from_slice(&self.port.to_be_bytes());
                Ok(buf)
            }
            ATYP_DOMAIN => {
                if self.host.is_empty() || self.host.len() > 255 {
                    return Err(AddressError::InvalidDomain);
                }
                let mut buf = Vec::with_capacity(1 + 1 + self.host.len() + 2);
                buf.push(ATYP_DOMAIN);
                buf.push(self.host.len() as u8);
                buf.extend_from_slice(self.host.as_bytes());
                buf.extend_from_slice(&self.port.to_be_bytes());
                Ok(buf)
            }
            ATYP_IPV6 => {
                let ip: Ipv6Addr = self.host.parse().map_err(|_| AddressError::InvalidIPv6)?;
                let octets = ip.octets();
                let mut buf = Vec::with_capacity(19);
                buf.push(ATYP_IPV6);
                buf.extend_from_slice(&octets);
                buf.extend_from_slice(&self.port.to_be_bytes());
                Ok(buf)
            }
            t => Err(AddressError::InvalidType(t)),
        }
    }

    /// Decode an address from bytes.
    /// Returns the address and the number of bytes consumed.
    pub fn decode(data: &[u8]) -> Result<(Address, usize), AddressError> {
        if data.is_empty() {
            return Err(AddressError::TooShort);
        }

        match data[0] {
            ATYP_IPV4 => {
                if data.len() < 7 {
                    return Err(AddressError::TooShort);
                }
                let ip = Ipv4Addr::new(data[1], data[2], data[3], data[4]);
                let port = u16::from_be_bytes([data[5], data[6]]);
                Ok((
                    Address {
                        atyp: ATYP_IPV4,
                        host: ip.to_string(),
                        port,
                    },
                    7,
                ))
            }
            ATYP_DOMAIN => {
                if data.len() < 2 {
                    return Err(AddressError::TooShort);
                }
                let domain_len = data[1] as usize;
                if domain_len == 0 {
                    return Err(AddressError::InvalidDomain);
                }
                if data.len() < 2 + domain_len + 2 {
                    return Err(AddressError::TooShort);
                }
                let host = String::from_utf8_lossy(&data[2..2 + domain_len]).into_owned();
                let port = u16::from_be_bytes([data[2 + domain_len], data[3 + domain_len]]);
                let consumed = 2 + domain_len + 2;
                Ok((
                    Address {
                        atyp: ATYP_DOMAIN,
                        host,
                        port,
                    },
                    consumed,
                ))
            }
            ATYP_IPV6 => {
                if data.len() < 19 {
                    return Err(AddressError::TooShort);
                }
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&data[1..17]);
                let ip = Ipv6Addr::from(octets);
                let port = u16::from_be_bytes([data[17], data[18]]);
                Ok((
                    Address {
                        atyp: ATYP_IPV6,
                        host: ip.to_string(),
                        port,
                    },
                    19,
                ))
            }
            t => Err(AddressError::InvalidType(t)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4_roundtrip() {
        let addr = Address::ipv4("192.168.1.1", 8080);
        let encoded = addr.encode().unwrap();
        assert_eq!(encoded.len(), 7);
        assert_eq!(encoded[0], ATYP_IPV4);

        let (decoded, consumed) = Address::decode(&encoded).unwrap();
        assert_eq!(consumed, 7);
        assert_eq!(decoded.atyp, ATYP_IPV4);
        assert_eq!(decoded.host, "192.168.1.1");
        assert_eq!(decoded.port, 8080);
    }

    #[test]
    fn test_ipv6_roundtrip() {
        let addr = Address::ipv6("2001:db8::1", 443);
        let encoded = addr.encode().unwrap();
        assert_eq!(encoded.len(), 19);
        assert_eq!(encoded[0], ATYP_IPV6);

        let (decoded, consumed) = Address::decode(&encoded).unwrap();
        assert_eq!(consumed, 19);
        assert_eq!(decoded.atyp, ATYP_IPV6);
        assert_eq!(decoded.host, "2001:db8::1");
        assert_eq!(decoded.port, 443);
    }

    #[test]
    fn test_domain_roundtrip() {
        let addr = Address::domain("example.com", 80);
        let encoded = addr.encode().unwrap();
        assert_eq!(encoded.len(), 15); // 1 + 1 + 11 + 2
        assert_eq!(encoded[0], ATYP_DOMAIN);

        let (decoded, consumed) = Address::decode(&encoded).unwrap();
        assert_eq!(consumed, 15);
        assert_eq!(decoded.atyp, ATYP_DOMAIN);
        assert_eq!(decoded.host, "example.com");
        assert_eq!(decoded.port, 80);
    }

    #[test]
    fn test_decode_errors() {
        // Empty data
        assert_eq!(Address::decode(&[]).unwrap_err(), AddressError::TooShort);

        // Too short for IPv4
        assert_eq!(
            Address::decode(&[0x01, 1, 2]).unwrap_err(),
            AddressError::TooShort
        );

        // Too short for IPv6
        assert_eq!(
            Address::decode(&[0x04, 1, 2, 3]).unwrap_err(),
            AddressError::TooShort
        );

        // Domain with zero length
        assert_eq!(
            Address::decode(&[0x03, 0]).unwrap_err(),
            AddressError::InvalidDomain
        );

        // Unknown type
        assert_eq!(
            Address::decode(&[0xFF, 1, 2, 3]).unwrap_err(),
            AddressError::InvalidType(0xFF)
        );
    }

    #[test]
    fn test_encode_errors() {
        // Invalid IPv4
        assert!(Address::ipv4("not-an-ip", 80).encode().is_err());

        // Empty domain
        assert!(Address::domain("", 80).encode().is_err());

        // Unknown type
        let addr = Address {
            atyp: 0xFF,
            host: "test".to_string(),
            port: 80,
        };
        assert!(addr.encode().is_err());
    }
}
