//! Relay forwarding engine - pure functions with no I/O.
//!
//! The engine processes relay messages and returns `Action`s for the
//! caller to execute. The `Router` trait provides routing decisions.

use crate::noise::message::protocol;
use super::message::*;

/// Router trait provides next-hop routing decisions.
///
/// Implementations range from simple static maps (for testing) to
/// dynamic routing based on PONG metrics (Host layer).
pub trait Router {
    /// Returns the next peer to forward to for reaching `dst`.
    ///
    /// - If `next_hop == dst`, the destination is directly reachable (send RELAY_2).
    /// - If `next_hop != dst`, forward via intermediate relay (send RELAY_1).
    fn next_hop(&self, dst: &[u8; 32], strategy: Strategy) -> Result<[u8; 32], RelayError>;
}

/// An action returned by the relay engine for the caller to execute.
#[derive(Debug, Clone)]
pub struct Action {
    /// Next-hop peer public key to send to.
    pub dst: [u8; 32],
    /// Protocol byte (RELAY_1, RELAY_2, or PONG).
    pub protocol: u8,
    /// Encoded message body.
    pub data: Vec<u8>,
}

/// Local node metrics for PONG responses.
#[derive(Debug, Clone, Copy, Default)]
pub struct NodeMetrics {
    pub load: u8,
    pub relay_count: u16,
    pub bw_avail: u16,
    pub price: u32,
}

/// Process a RELAY_0 (first-hop) message.
///
/// `from` is the sender's public key (from the Noise session).
/// `data` is the message body after protocol byte.
pub fn handle_relay0(router: &dyn Router, from: &[u8; 32], data: &[u8]) -> Result<Action, RelayError> {
    let r0 = decode_relay0(data)?;
    if r0.ttl == 0 {
        return Err(RelayError::TtlExpired);
    }

    let next_hop = router.next_hop(&r0.dst_key, r0.strategy)?;

    if next_hop == r0.dst_key {
        // Direct: send RELAY_2 to destination
        let r2 = Relay2 { src_key: *from, payload: r0.payload };
        Ok(Action {
            dst: next_hop,
            protocol: protocol::RELAY_2,
            data: encode_relay2(&r2),
        })
    } else {
        // Forward: send RELAY_1 to next hop
        let r1 = Relay1 {
            ttl: r0.ttl - 1,
            strategy: r0.strategy,
            src_key: *from,
            dst_key: r0.dst_key,
            payload: r0.payload,
        };
        Ok(Action {
            dst: next_hop,
            protocol: protocol::RELAY_1,
            data: encode_relay1(&r1),
        })
    }
}

/// Process a RELAY_1 (middle-hop) message.
///
/// `data` is the message body after protocol byte.
pub fn handle_relay1(router: &dyn Router, data: &[u8]) -> Result<Action, RelayError> {
    let r1 = decode_relay1(data)?;
    if r1.ttl == 0 {
        return Err(RelayError::TtlExpired);
    }

    let next_hop = router.next_hop(&r1.dst_key, r1.strategy)?;

    if next_hop == r1.dst_key {
        // Direct: send RELAY_2 to destination
        let r2 = Relay2 { src_key: r1.src_key, payload: r1.payload };
        Ok(Action {
            dst: next_hop,
            protocol: protocol::RELAY_2,
            data: encode_relay2(&r2),
        })
    } else {
        // Forward: send RELAY_1 to next hop (TTL-1)
        let fwd = Relay1 {
            ttl: r1.ttl - 1,
            strategy: r1.strategy,
            src_key: r1.src_key,
            dst_key: r1.dst_key,
            payload: r1.payload,
        };
        Ok(Action {
            dst: next_hop,
            protocol: protocol::RELAY_1,
            data: encode_relay1(&fwd),
        })
    }
}

/// Process a RELAY_2 (last-hop) message.
///
/// Returns the source public key and inner payload.
/// The caller should feed the payload back through the decrypt pipeline.
pub fn handle_relay2(data: &[u8]) -> Result<(/*src*/ [u8; 32], /*payload*/ Vec<u8>), RelayError> {
    let r2 = decode_relay2(data)?;
    Ok((r2.src_key, r2.payload))
}

/// Process a PING message and return a PONG action.
///
/// `from` is the sender's public key. `data` is the body after protocol byte.
pub fn handle_ping(from: &[u8; 32], data: &[u8], metrics: &NodeMetrics) -> Result<Action, RelayError> {
    let ping = decode_ping(data)?;
    let pong = Pong {
        ping_id: ping.ping_id,
        timestamp: ping.timestamp,
        load: metrics.load,
        relay_count: metrics.relay_count,
        bw_avail: metrics.bw_avail,
        price: metrics.price,
    };
    Ok(Action {
        dst: *from,
            protocol: protocol::PONG,
        data: encode_pong(&pong),
    })
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// Simple static router for testing.
    struct StaticRouter {
        routes: HashMap<[u8; 32], [u8; 32]>,
    }

    impl Router for StaticRouter {
        fn next_hop(&self, dst: &[u8; 32], _strategy: Strategy) -> Result<[u8; 32], RelayError> {
            self.routes.get(dst).copied().ok_or(RelayError::NoRoute)
        }
    }

    fn key_from_byte(b: u8) -> [u8; 32] {
        let mut k = [0u8; 32];
        k[0] = b;
        k
    }

    #[test]
    fn test_handle_relay0_direct() {
        let key_a = key_from_byte(0x0A);
        let key_b = key_from_byte(0x0B);
        let payload = b"secret payload A->B".to_vec();

        let mut routes = HashMap::new();
        routes.insert(key_b, key_b); // B is direct
        let router = StaticRouter { routes };

        let r0_data = encode_relay0(&Relay0 {
            ttl: 8, strategy: Strategy::Auto, dst_key: key_b, payload: payload.clone(),
        });

        let action = handle_relay0(&router, &key_a, &r0_data).unwrap();
        assert_eq!(action.dst, key_b);
        assert_eq!(action.protocol, protocol::RELAY_2);

        let r2 = decode_relay2(&action.data).unwrap();
        assert_eq!(r2.src_key, key_a);
        assert_eq!(r2.payload, payload);
    }

    #[test]
    fn test_handle_relay0_forward() {
        let key_a = key_from_byte(0x0A);
        let key_b = key_from_byte(0x0B);
        let key_c = key_from_byte(0x0C);
        let payload = b"secret payload A->B".to_vec();

        let mut routes = HashMap::new();
        routes.insert(key_b, key_c); // B via C
        let router = StaticRouter { routes };

        let r0_data = encode_relay0(&Relay0 {
            ttl: 8, strategy: Strategy::Fastest, dst_key: key_b, payload: payload.clone(),
        });

        let action = handle_relay0(&router, &key_a, &r0_data).unwrap();
        assert_eq!(action.dst, key_c);
        assert_eq!(action.protocol, protocol::RELAY_1);

        let r1 = decode_relay1(&action.data).unwrap();
        assert_eq!(r1.ttl, 7);
        assert_eq!(r1.strategy, Strategy::Fastest);
        assert_eq!(r1.src_key, key_a);
        assert_eq!(r1.dst_key, key_b);
        assert_eq!(r1.payload, payload);
    }

    #[test]
    fn test_handle_relay0_ttl_expired() {
        let key_a = key_from_byte(0x0A);
        let key_b = key_from_byte(0x0B);
        let mut routes = HashMap::new();
        routes.insert(key_b, key_b);
        let router = StaticRouter { routes };

        let r0_data = encode_relay0(&Relay0 {
            ttl: 0, strategy: Strategy::Auto, dst_key: key_b, payload: vec![],
        });

        assert_eq!(handle_relay0(&router, &key_a, &r0_data).unwrap_err(), RelayError::TtlExpired);
    }

    #[test]
    fn test_handle_relay0_no_route() {
        let key_a = key_from_byte(0x0A);
        let key_b = key_from_byte(0x0B);
        let router = StaticRouter { routes: HashMap::new() };

        let r0_data = encode_relay0(&Relay0 {
            ttl: 8, strategy: Strategy::Auto, dst_key: key_b, payload: vec![],
        });

        assert_eq!(handle_relay0(&router, &key_a, &r0_data).unwrap_err(), RelayError::NoRoute);
    }

    #[test]
    fn test_handle_relay1_direct() {
        let key_a = key_from_byte(0x0A);
        let key_b = key_from_byte(0x0B);
        let payload = b"relay1 payload".to_vec();

        let mut routes = HashMap::new();
        routes.insert(key_b, key_b);
        let router = StaticRouter { routes };

        let r1_data = encode_relay1(&Relay1 {
            ttl: 5, strategy: Strategy::Cheapest, src_key: key_a, dst_key: key_b, payload: payload.clone(),
        });

        let action = handle_relay1(&router, &r1_data).unwrap();
        assert_eq!(action.dst, key_b);
        assert_eq!(action.protocol, protocol::RELAY_2);

        let r2 = decode_relay2(&action.data).unwrap();
        assert_eq!(r2.src_key, key_a);
        assert_eq!(r2.payload, payload);
    }

    #[test]
    fn test_handle_relay1_forward() {
        let key_a = key_from_byte(0x0A);
        let key_b = key_from_byte(0x0B);
        let key_d = key_from_byte(0x0D);

        let mut routes = HashMap::new();
        routes.insert(key_b, key_d); // B via D
        let router = StaticRouter { routes };

        let r1_data = encode_relay1(&Relay1 {
            ttl: 5, strategy: Strategy::Auto, src_key: key_a, dst_key: key_b, payload: b"data".to_vec(),
        });

        let action = handle_relay1(&router, &r1_data).unwrap();
        assert_eq!(action.dst, key_d);
        assert_eq!(action.protocol, protocol::RELAY_1);

        let fwd = decode_relay1(&action.data).unwrap();
        assert_eq!(fwd.ttl, 4);
        assert_eq!(fwd.src_key, key_a);
        assert_eq!(fwd.dst_key, key_b);
    }

    #[test]
    fn test_handle_relay1_ttl_expired() {
        let router = StaticRouter { routes: HashMap::new() };
        let r1_data = encode_relay1(&Relay1 {
            ttl: 0, strategy: Strategy::Auto, src_key: [0; 32], dst_key: [1; 32], payload: vec![],
        });
        assert_eq!(handle_relay1(&router, &r1_data).unwrap_err(), RelayError::TtlExpired);
    }

    #[test]
    fn test_handle_relay2() {
        let key_a = key_from_byte(0x0A);
        let payload = b"final payload".to_vec();

        let r2_data = encode_relay2(&Relay2 { src_key: key_a, payload: payload.clone() });
        let (src, inner) = handle_relay2(&r2_data).unwrap();
        assert_eq!(src, key_a);
        assert_eq!(inner, payload);
    }

    #[test]
    fn test_handle_relay2_too_short() {
        assert_eq!(handle_relay2(&[0u8; 31]).unwrap_err(), RelayError::TooShort);
    }

    #[test]
    fn test_handle_ping() {
        let from = key_from_byte(0x0A);
        let ping_data = encode_ping(&Ping { ping_id: 42, timestamp: 1234567890 });
        let metrics = NodeMetrics { load: 50, relay_count: 10, bw_avail: 2048, price: 100 };

        let action = handle_ping(&from, &ping_data, &metrics).unwrap();
        assert_eq!(action.dst, from);
        assert_eq!(action.protocol, protocol::PONG);

        let pong = decode_pong(&action.data).unwrap();
        assert_eq!(pong.ping_id, 42);
        assert_eq!(pong.timestamp, 1234567890);
        assert_eq!(pong.load, 50);
        assert_eq!(pong.relay_count, 10);
        assert_eq!(pong.bw_avail, 2048);
        assert_eq!(pong.price, 100);
    }

    #[test]
    fn test_multi_hop_relay() {
        let key_a = key_from_byte(0x0A);
        let key_b = key_from_byte(0x0B);
        let key_d = key_from_byte(0x0D);
        let payload = b"e2e encrypted".to_vec();

        // C routes B via D
        let mut routes_c = HashMap::new();
        routes_c.insert(key_b, key_d);
        let router_c = StaticRouter { routes: routes_c };

        // D routes B direct
        let mut routes_d = HashMap::new();
        routes_d.insert(key_b, key_b);
        let router_d = StaticRouter { routes: routes_d };

        // Step 1: A sends RELAY_0
        let r0_data = encode_relay0(&Relay0 {
            ttl: 8, strategy: Strategy::Auto, dst_key: key_b, payload: payload.clone(),
        });

        // Step 2: C -> RELAY_1 to D
        let a1 = handle_relay0(&router_c, &key_a, &r0_data).unwrap();
        assert_eq!(a1.protocol, protocol::RELAY_1);
        assert_eq!(a1.dst, key_d);

        // Step 3: D -> RELAY_2 to B
        let a2 = handle_relay1(&router_d, &a1.data).unwrap();
        assert_eq!(a2.protocol, protocol::RELAY_2);
        assert_eq!(a2.dst, key_b);

        // Step 4: B extracts src + payload
        let (src, inner) = handle_relay2(&a2.data).unwrap();
        assert_eq!(src, key_a);
        assert_eq!(inner, payload);
    }
}
