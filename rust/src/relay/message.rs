//! Relay and PING/PONG message encoding/decoding.
//!
//! All encode/decode functions handle the message body AFTER the protocol
//! byte has been stripped by `decode_payload()`.

use std::fmt;

/// Relay message header sizes (excluding protocol byte).
pub const RELAY0_HEADER_SIZE: usize = 1 + 1 + 32; // ttl + strategy + dst_key = 34
pub const RELAY1_HEADER_SIZE: usize = 1 + 1 + 32 + 32; // ttl + strategy + src_key + dst_key = 66
pub const RELAY2_HEADER_SIZE: usize = 32; // src_key = 32

/// Ping message size: ping_id(4) + timestamp(8) = 12
pub const PING_SIZE: usize = 4 + 8;

/// Pong message size: ping_id(4) + timestamp(8) + load(1) + relay_count(2) + bw_avail(2) + price(4) = 21
pub const PONG_SIZE: usize = 4 + 8 + 1 + 2 + 2 + 4;

/// Default TTL for relay messages.
pub const DEFAULT_TTL: u8 = 8;

/// Relay error type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayError {
    /// Message is too short.
    TooShort,
    /// TTL has expired (reached 0).
    TtlExpired,
    /// No route to destination.
    NoRoute,
}

impl fmt::Display for RelayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort => write!(f, "relay: message too short"),
            Self::TtlExpired => write!(f, "relay: TTL expired"),
            Self::NoRoute => write!(f, "relay: no route to destination"),
        }
    }
}

impl std::error::Error for RelayError {}

/// Routing strategy preference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Strategy {
    /// Relay node decides (default).
    Auto = 0,
    /// Prefer lowest latency.
    Fastest = 1,
    /// Prefer lowest cost.
    Cheapest = 2,
}

impl From<u8> for Strategy {
    fn from(v: u8) -> Self {
        match v {
            1 => Strategy::Fastest,
            2 => Strategy::Cheapest,
            _ => Strategy::Auto,
        }
    }
}

/// RELAY_0 - first-hop relay message (protocol 66).
#[derive(Debug, Clone)]
pub struct Relay0 {
    pub ttl: u8,
    pub strategy: Strategy,
    pub dst_key: [u8; 32],
    pub payload: Vec<u8>,
}

/// RELAY_1 - middle-hop relay message (protocol 67).
#[derive(Debug, Clone)]
pub struct Relay1 {
    pub ttl: u8,
    pub strategy: Strategy,
    pub src_key: [u8; 32],
    pub dst_key: [u8; 32],
    pub payload: Vec<u8>,
}

/// RELAY_2 - last-hop relay message (protocol 68).
#[derive(Debug, Clone)]
pub struct Relay2 {
    pub src_key: [u8; 32],
    pub payload: Vec<u8>,
}

/// PING probe request (protocol 70).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ping {
    pub ping_id: u32,
    pub timestamp: u64,
}

/// PONG probe response (protocol 71).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pong {
    pub ping_id: u32,
    pub timestamp: u64,
    pub load: u8,
    pub relay_count: u16,
    pub bw_avail: u16,
    pub price: u32,
}

// ============================================================================
// Relay0
// ============================================================================

pub fn encode_relay0(r: &Relay0) -> Vec<u8> {
    let mut buf = Vec::with_capacity(RELAY0_HEADER_SIZE + r.payload.len());
    buf.push(r.ttl);
    buf.push(r.strategy as u8);
    buf.extend_from_slice(&r.dst_key);
    buf.extend_from_slice(&r.payload);
    buf
}

pub fn decode_relay0(data: &[u8]) -> Result<Relay0, RelayError> {
    if data.len() < RELAY0_HEADER_SIZE {
        return Err(RelayError::TooShort);
    }
    let mut dst_key = [0u8; 32];
    dst_key.copy_from_slice(&data[2..34]);
    Ok(Relay0 {
        ttl: data[0],
        strategy: Strategy::from(data[1]),
        dst_key,
        payload: data[34..].to_vec(),
    })
}

// ============================================================================
// Relay1
// ============================================================================

pub fn encode_relay1(r: &Relay1) -> Vec<u8> {
    let mut buf = Vec::with_capacity(RELAY1_HEADER_SIZE + r.payload.len());
    buf.push(r.ttl);
    buf.push(r.strategy as u8);
    buf.extend_from_slice(&r.src_key);
    buf.extend_from_slice(&r.dst_key);
    buf.extend_from_slice(&r.payload);
    buf
}

pub fn decode_relay1(data: &[u8]) -> Result<Relay1, RelayError> {
    if data.len() < RELAY1_HEADER_SIZE {
        return Err(RelayError::TooShort);
    }
    let mut src_key = [0u8; 32];
    let mut dst_key = [0u8; 32];
    src_key.copy_from_slice(&data[2..34]);
    dst_key.copy_from_slice(&data[34..66]);
    Ok(Relay1 {
        ttl: data[0],
        strategy: Strategy::from(data[1]),
        src_key,
        dst_key,
        payload: data[66..].to_vec(),
    })
}

// ============================================================================
// Relay2
// ============================================================================

pub fn encode_relay2(r: &Relay2) -> Vec<u8> {
    let mut buf = Vec::with_capacity(RELAY2_HEADER_SIZE + r.payload.len());
    buf.extend_from_slice(&r.src_key);
    buf.extend_from_slice(&r.payload);
    buf
}

pub fn decode_relay2(data: &[u8]) -> Result<Relay2, RelayError> {
    if data.len() < RELAY2_HEADER_SIZE {
        return Err(RelayError::TooShort);
    }
    let mut src_key = [0u8; 32];
    src_key.copy_from_slice(&data[0..32]);
    Ok(Relay2 {
        src_key,
        payload: data[32..].to_vec(),
    })
}

// ============================================================================
// Ping
// ============================================================================

pub fn encode_ping(p: &Ping) -> Vec<u8> {
    let mut buf = vec![0u8; PING_SIZE];
    buf[0..4].copy_from_slice(&p.ping_id.to_le_bytes());
    buf[4..12].copy_from_slice(&p.timestamp.to_le_bytes());
    buf
}

pub fn decode_ping(data: &[u8]) -> Result<Ping, RelayError> {
    if data.len() < PING_SIZE {
        return Err(RelayError::TooShort);
    }
    Ok(Ping {
        ping_id: u32::from_le_bytes([data[0], data[1], data[2], data[3]]),
        timestamp: u64::from_le_bytes([
            data[4], data[5], data[6], data[7],
            data[8], data[9], data[10], data[11],
        ]),
    })
}

// ============================================================================
// Pong
// ============================================================================

pub fn encode_pong(p: &Pong) -> Vec<u8> {
    let mut buf = vec![0u8; PONG_SIZE];
    buf[0..4].copy_from_slice(&p.ping_id.to_le_bytes());
    buf[4..12].copy_from_slice(&p.timestamp.to_le_bytes());
    buf[12] = p.load;
    buf[13..15].copy_from_slice(&p.relay_count.to_le_bytes());
    buf[15..17].copy_from_slice(&p.bw_avail.to_le_bytes());
    buf[17..21].copy_from_slice(&p.price.to_le_bytes());
    buf
}

pub fn decode_pong(data: &[u8]) -> Result<Pong, RelayError> {
    if data.len() < PONG_SIZE {
        return Err(RelayError::TooShort);
    }
    Ok(Pong {
        ping_id: u32::from_le_bytes([data[0], data[1], data[2], data[3]]),
        timestamp: u64::from_le_bytes([
            data[4], data[5], data[6], data[7],
            data[8], data[9], data[10], data[11],
        ]),
        load: data[12],
        relay_count: u16::from_le_bytes([data[13], data[14]]),
        bw_avail: u16::from_le_bytes([data[15], data[16]]),
        price: u32::from_le_bytes([data[17], data[18], data[19], data[20]]),
    })
}

// ============================================================================
// BIND/ALIAS messages
// ============================================================================

/// BIND/ALIAS header sizes (excluding protocol byte).
pub const RELAY0_BIND_SIZE: usize = 4 + 32;      // relay_id + dst_key
pub const RELAY0_ALIAS_MIN: usize = 4;            // relay_id (+ var payload)
pub const RELAY1_BIND_SIZE: usize = 4 + 32 + 32;  // relay_id + src_key + dst_key
pub const RELAY1_ALIAS_MIN: usize = 4;
pub const RELAY2_BIND_SIZE: usize = 4 + 32;       // relay_id + src_key
pub const RELAY2_ALIAS_MIN: usize = 4;

#[derive(Debug, Clone)]
pub struct Relay0Bind { pub relay_id: u32, pub dst_key: [u8; 32] }

#[derive(Debug, Clone)]
pub struct Relay0Alias { pub relay_id: u32, pub payload: Vec<u8> }

#[derive(Debug, Clone)]
pub struct Relay1Bind { pub relay_id: u32, pub src_key: [u8; 32], pub dst_key: [u8; 32] }

#[derive(Debug, Clone)]
pub struct Relay1Alias { pub relay_id: u32, pub payload: Vec<u8> }

#[derive(Debug, Clone)]
pub struct Relay2Bind { pub relay_id: u32, pub src_key: [u8; 32] }

#[derive(Debug, Clone)]
pub struct Relay2Alias { pub relay_id: u32, pub payload: Vec<u8> }

pub fn encode_relay0_bind(r: &Relay0Bind) -> Vec<u8> {
    let mut buf = vec![0u8; RELAY0_BIND_SIZE];
    buf[0..4].copy_from_slice(&r.relay_id.to_le_bytes());
    buf[4..36].copy_from_slice(&r.dst_key);
    buf
}

pub fn decode_relay0_bind(data: &[u8]) -> Result<Relay0Bind, RelayError> {
    if data.len() < RELAY0_BIND_SIZE { return Err(RelayError::TooShort); }
    let mut dst_key = [0u8; 32];
    dst_key.copy_from_slice(&data[4..36]);
    Ok(Relay0Bind {
        relay_id: u32::from_le_bytes([data[0], data[1], data[2], data[3]]),
        dst_key,
    })
}

pub fn encode_relay0_alias(r: &Relay0Alias) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4 + r.payload.len());
    buf.extend_from_slice(&r.relay_id.to_le_bytes());
    buf.extend_from_slice(&r.payload);
    buf
}

pub fn decode_relay0_alias(data: &[u8]) -> Result<Relay0Alias, RelayError> {
    if data.len() < RELAY0_ALIAS_MIN { return Err(RelayError::TooShort); }
    Ok(Relay0Alias {
        relay_id: u32::from_le_bytes([data[0], data[1], data[2], data[3]]),
        payload: data[4..].to_vec(),
    })
}

pub fn encode_relay1_bind(r: &Relay1Bind) -> Vec<u8> {
    let mut buf = vec![0u8; RELAY1_BIND_SIZE];
    buf[0..4].copy_from_slice(&r.relay_id.to_le_bytes());
    buf[4..36].copy_from_slice(&r.src_key);
    buf[36..68].copy_from_slice(&r.dst_key);
    buf
}

pub fn decode_relay1_bind(data: &[u8]) -> Result<Relay1Bind, RelayError> {
    if data.len() < RELAY1_BIND_SIZE { return Err(RelayError::TooShort); }
    let mut src_key = [0u8; 32];
    let mut dst_key = [0u8; 32];
    src_key.copy_from_slice(&data[4..36]);
    dst_key.copy_from_slice(&data[36..68]);
    Ok(Relay1Bind {
        relay_id: u32::from_le_bytes([data[0], data[1], data[2], data[3]]),
        src_key, dst_key,
    })
}

pub fn encode_relay1_alias(r: &Relay1Alias) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4 + r.payload.len());
    buf.extend_from_slice(&r.relay_id.to_le_bytes());
    buf.extend_from_slice(&r.payload);
    buf
}

pub fn decode_relay1_alias(data: &[u8]) -> Result<Relay1Alias, RelayError> {
    if data.len() < RELAY1_ALIAS_MIN { return Err(RelayError::TooShort); }
    Ok(Relay1Alias {
        relay_id: u32::from_le_bytes([data[0], data[1], data[2], data[3]]),
        payload: data[4..].to_vec(),
    })
}

pub fn encode_relay2_bind(r: &Relay2Bind) -> Vec<u8> {
    let mut buf = vec![0u8; RELAY2_BIND_SIZE];
    buf[0..4].copy_from_slice(&r.relay_id.to_le_bytes());
    buf[4..36].copy_from_slice(&r.src_key);
    buf
}

pub fn decode_relay2_bind(data: &[u8]) -> Result<Relay2Bind, RelayError> {
    if data.len() < RELAY2_BIND_SIZE { return Err(RelayError::TooShort); }
    let mut src_key = [0u8; 32];
    src_key.copy_from_slice(&data[4..36]);
    Ok(Relay2Bind {
        relay_id: u32::from_le_bytes([data[0], data[1], data[2], data[3]]),
        src_key,
    })
}

pub fn encode_relay2_alias(r: &Relay2Alias) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4 + r.payload.len());
    buf.extend_from_slice(&r.relay_id.to_le_bytes());
    buf.extend_from_slice(&r.payload);
    buf
}

pub fn decode_relay2_alias(data: &[u8]) -> Result<Relay2Alias, RelayError> {
    if data.len() < RELAY2_ALIAS_MIN { return Err(RelayError::TooShort); }
    Ok(Relay2Alias {
        relay_id: u32::from_le_bytes([data[0], data[1], data[2], data[3]]),
        payload: data[4..].to_vec(),
    })
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_relay0_roundtrip() {
        let mut dst_key = [0u8; 32];
        for i in 0..32 { dst_key[i] = i as u8; }
        let payload = b"hello relay world".to_vec();

        let orig = Relay0 { ttl: 8, strategy: Strategy::Fastest, dst_key, payload: payload.clone() };
        let encoded = encode_relay0(&orig);
        assert_eq!(encoded.len(), RELAY0_HEADER_SIZE + payload.len());

        let decoded = decode_relay0(&encoded).unwrap();
        assert_eq!(decoded.ttl, 8);
        assert_eq!(decoded.strategy, Strategy::Fastest);
        assert_eq!(decoded.dst_key, dst_key);
        assert_eq!(decoded.payload, payload);
    }

    #[test]
    fn test_relay0_too_short() {
        assert_eq!(decode_relay0(&[0u8; RELAY0_HEADER_SIZE - 1]).unwrap_err(), RelayError::TooShort);
    }

    #[test]
    fn test_relay1_roundtrip() {
        let mut src_key = [0u8; 32];
        let mut dst_key = [0u8; 32];
        for i in 0..32 { src_key[i] = i as u8; dst_key[i] = (i + 100) as u8; }
        let payload = b"relay1 payload".to_vec();

        let orig = Relay1 { ttl: 7, strategy: Strategy::Cheapest, src_key, dst_key, payload: payload.clone() };
        let encoded = encode_relay1(&orig);
        assert_eq!(encoded.len(), RELAY1_HEADER_SIZE + payload.len());

        let decoded = decode_relay1(&encoded).unwrap();
        assert_eq!(decoded.ttl, 7);
        assert_eq!(decoded.strategy, Strategy::Cheapest);
        assert_eq!(decoded.src_key, src_key);
        assert_eq!(decoded.dst_key, dst_key);
        assert_eq!(decoded.payload, payload);
    }

    #[test]
    fn test_relay1_too_short() {
        assert_eq!(decode_relay1(&[0u8; RELAY1_HEADER_SIZE - 1]).unwrap_err(), RelayError::TooShort);
    }

    #[test]
    fn test_relay2_roundtrip() {
        let mut src_key = [0u8; 32];
        for i in 0..32 { src_key[i] = (i + 50) as u8; }
        let payload = b"final hop payload".to_vec();

        let orig = Relay2 { src_key, payload: payload.clone() };
        let encoded = encode_relay2(&orig);
        assert_eq!(encoded.len(), RELAY2_HEADER_SIZE + payload.len());

        let decoded = decode_relay2(&encoded).unwrap();
        assert_eq!(decoded.src_key, src_key);
        assert_eq!(decoded.payload, payload);
    }

    #[test]
    fn test_relay2_too_short() {
        assert_eq!(decode_relay2(&[0u8; RELAY2_HEADER_SIZE - 1]).unwrap_err(), RelayError::TooShort);
    }

    #[test]
    fn test_ping_roundtrip() {
        let orig = Ping { ping_id: 12345, timestamp: 9876543210 };
        let encoded = encode_ping(&orig);
        assert_eq!(encoded.len(), PING_SIZE);

        let decoded = decode_ping(&encoded).unwrap();
        assert_eq!(decoded, orig);
    }

    #[test]
    fn test_ping_too_short() {
        assert_eq!(decode_ping(&[0u8; PING_SIZE - 1]).unwrap_err(), RelayError::TooShort);
    }

    #[test]
    fn test_pong_roundtrip() {
        let orig = Pong {
            ping_id: 12345, timestamp: 9876543210,
            load: 128, relay_count: 42, bw_avail: 1024, price: 500,
        };
        let encoded = encode_pong(&orig);
        assert_eq!(encoded.len(), PONG_SIZE);

        let decoded = decode_pong(&encoded).unwrap();
        assert_eq!(decoded, orig);
    }

    #[test]
    fn test_pong_too_short() {
        assert_eq!(decode_pong(&[0u8; PONG_SIZE - 1]).unwrap_err(), RelayError::TooShort);
    }

    #[test]
    fn test_strategy_from_u8() {
        assert_eq!(Strategy::from(0), Strategy::Auto);
        assert_eq!(Strategy::from(1), Strategy::Fastest);
        assert_eq!(Strategy::from(2), Strategy::Cheapest);
        assert_eq!(Strategy::from(255), Strategy::Auto);
    }

    #[test]
    fn test_relay0_bind_roundtrip() {
        let mut dst_key = [0u8; 32];
        for i in 0..32 { dst_key[i] = i as u8; }
        let orig = Relay0Bind { relay_id: 0x1234, dst_key };
        let encoded = encode_relay0_bind(&orig);
        assert_eq!(encoded.len(), RELAY0_BIND_SIZE);
        let decoded = decode_relay0_bind(&encoded).unwrap();
        assert_eq!(decoded.relay_id, 0x1234);
        assert_eq!(decoded.dst_key, dst_key);
    }

    #[test]
    fn test_relay0_bind_too_short() {
        assert_eq!(decode_relay0_bind(&[0u8; RELAY0_BIND_SIZE - 1]).unwrap_err(), RelayError::TooShort);
    }

    #[test]
    fn test_relay0_alias_roundtrip() {
        let payload = b"alias payload".to_vec();
        let orig = Relay0Alias { relay_id: 0xABCD, payload: payload.clone() };
        let encoded = encode_relay0_alias(&orig);
        assert_eq!(encoded.len(), 4 + payload.len());
        let decoded = decode_relay0_alias(&encoded).unwrap();
        assert_eq!(decoded.relay_id, 0xABCD);
        assert_eq!(decoded.payload, payload);
    }

    #[test]
    fn test_relay1_bind_roundtrip() {
        let mut src_key = [0u8; 32];
        let mut dst_key = [0u8; 32];
        for i in 0..32 { src_key[i] = i as u8; dst_key[i] = (i + 100) as u8; }
        let orig = Relay1Bind { relay_id: 0x5678, src_key, dst_key };
        let encoded = encode_relay1_bind(&orig);
        assert_eq!(encoded.len(), RELAY1_BIND_SIZE);
        let decoded = decode_relay1_bind(&encoded).unwrap();
        assert_eq!(decoded.relay_id, 0x5678);
        assert_eq!(decoded.src_key, src_key);
        assert_eq!(decoded.dst_key, dst_key);
    }

    #[test]
    fn test_relay1_alias_roundtrip() {
        let payload = b"relay1 alias".to_vec();
        let orig = Relay1Alias { relay_id: 0xFF00, payload: payload.clone() };
        let encoded = encode_relay1_alias(&orig);
        let decoded = decode_relay1_alias(&encoded).unwrap();
        assert_eq!(decoded.relay_id, 0xFF00);
        assert_eq!(decoded.payload, payload);
    }

    #[test]
    fn test_relay2_bind_roundtrip() {
        let mut src_key = [0u8; 32];
        for i in 0..32 { src_key[i] = (i + 50) as u8; }
        let orig = Relay2Bind { relay_id: 0x9ABC, src_key };
        let encoded = encode_relay2_bind(&orig);
        assert_eq!(encoded.len(), RELAY2_BIND_SIZE);
        let decoded = decode_relay2_bind(&encoded).unwrap();
        assert_eq!(decoded.relay_id, 0x9ABC);
        assert_eq!(decoded.src_key, src_key);
    }

    #[test]
    fn test_relay2_alias_roundtrip() {
        let payload = b"relay2 alias final".to_vec();
        let orig = Relay2Alias { relay_id: 0xDEAD, payload: payload.clone() };
        let encoded = encode_relay2_alias(&orig);
        let decoded = decode_relay2_alias(&encoded).unwrap();
        assert_eq!(decoded.relay_id, 0xDEAD);
        assert_eq!(decoded.payload, payload);
    }

    #[test]
    fn test_alias_empty_payload() {
        let orig = Relay0Alias { relay_id: 42, payload: vec![] };
        let encoded = encode_relay0_alias(&orig);
        assert_eq!(encoded.len(), 4);
        let decoded = decode_relay0_alias(&encoded).unwrap();
        assert_eq!(decoded.relay_id, 42);
        assert!(decoded.payload.is_empty());
    }
}
