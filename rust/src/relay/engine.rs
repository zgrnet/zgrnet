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
    use crate::noise::cipher;
    use crate::noise::{Key, Session, SessionConfig};
    use crate::noise::message::{build_transport_message, parse_transport_message, encode_payload, decode_payload};

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

    /// Test full relay chain A -> B(relay) -> C with real Noise session encryption.
    /// Verifies that the encrypted payload survives the relay chain and can be
    /// decrypted by the final destination.
    #[test]
    fn test_relay_chain_with_noise_session() {
        // Create A-C end-to-end session (symmetric keys, swapped between sides)
        let send_key = Key(cipher::hash(&[b"A-to-C send key"]));
        let recv_key = Key(cipher::hash(&[b"A-to-C recv key"]));

        let session_a = Session::new(SessionConfig {
            local_index: 1,
            remote_index: 2,
            send_key: send_key.clone(),
            recv_key: recv_key.clone(),
            remote_pk: Key([0u8; 32]),
        });

        let session_c = Session::new(SessionConfig {
            local_index: 2,
            remote_index: 1,
            send_key: recv_key, // swapped
            recv_key: send_key, // swapped
            remote_pk: Key([0u8; 32]),
        });

        let key_a = key_from_byte(0x0A);
        let key_c = key_from_byte(0x0C);

        // Step 1: A encrypts data with A-C session
        let original_data = b"hello through relay!";
        let payload = encode_payload(protocol::CHAT, 0, original_data);
        let (ciphertext, nonce) = session_a.encrypt(&payload).unwrap();

        // Build Type 4 transport message
        let type4msg = build_transport_message(session_a.remote_index(), nonce, &ciphertext);

        // Step 2: Wrap in RELAY_0(dst=C)
        let r0_data = encode_relay0(&Relay0 {
            ttl: 8, strategy: Strategy::Auto, dst_key: key_c, payload: type4msg,
        });

        // Step 3: B (relay) processes RELAY_0 → RELAY_2 to C
        let mut routes = HashMap::new();
        routes.insert(key_c, key_c); // C is direct
        let router = StaticRouter { routes };
        let action = handle_relay0(&router, &key_a, &r0_data).unwrap();
        assert_eq!(action.protocol, protocol::RELAY_2);
        assert_eq!(action.dst, key_c);

        // Step 4: C processes RELAY_2
        let (src, inner_payload) = handle_relay2(&action.data).unwrap();
        assert_eq!(src, key_a);

        // Step 5: C decrypts the inner Type 4 message
        let msg = parse_transport_message(&inner_payload).unwrap();
        assert_eq!(msg.receiver_index, session_c.local_index());

        let plaintext = session_c.decrypt(msg.ciphertext, msg.counter).unwrap();
        let (proto, _svc, data) = decode_payload(&plaintext).unwrap();
        assert_eq!(proto, protocol::CHAT);
        assert_eq!(data, original_data);
    }

    /// Test multi-hop relay A -> B -> C -> D with real Noise encryption.
    /// B and C are relay nodes that cannot see the payload.
    #[test]
    fn test_relay_multi_hop_with_noise_session() {
        let send_key = Key(cipher::hash(&[b"A-to-D send key"]));
        let recv_key = Key(cipher::hash(&[b"A-to-D recv key"]));

        let session_a = Session::new(SessionConfig {
            local_index: 10,
            remote_index: 20,
            send_key: send_key.clone(),
            recv_key: recv_key.clone(),
            remote_pk: Key([0u8; 32]),
        });

        let session_d = Session::new(SessionConfig {
            local_index: 20,
            remote_index: 10,
            send_key: recv_key,
            recv_key: send_key,
            remote_pk: Key([0u8; 32]),
        });

        let key_a = key_from_byte(0x0A);
        let key_c = key_from_byte(0x0C);
        let key_d = key_from_byte(0x0D);

        // Step 1: A encrypts
        let original_data = b"multi-hop relay with real encryption!";
        let payload = encode_payload(0, 0, original_data); // protocol=RAW, service=0
        let (ciphertext, nonce) = session_a.encrypt(&payload).unwrap();
        let type4msg = build_transport_message(session_a.remote_index(), nonce, &ciphertext);

        // Step 2: RELAY_0(dst=D)
        let r0_data = encode_relay0(&Relay0 {
            ttl: 8, strategy: Strategy::Fastest, dst_key: key_d, payload: type4msg,
        });

        // Step 3: B → RELAY_1 to C (D is via C)
        let mut routes_b = HashMap::new();
        routes_b.insert(key_d, key_c);
        let router_b = StaticRouter { routes: routes_b };
        let action1 = handle_relay0(&router_b, &key_a, &r0_data).unwrap();
        assert_eq!(action1.protocol, protocol::RELAY_1);

        // Step 4: C → RELAY_2 to D (D is direct)
        let mut routes_c = HashMap::new();
        routes_c.insert(key_d, key_d);
        let router_c = StaticRouter { routes: routes_c };
        let action2 = handle_relay1(&router_c, &action1.data).unwrap();
        assert_eq!(action2.protocol, protocol::RELAY_2);

        // Step 5: D processes RELAY_2
        let (src, inner_payload) = handle_relay2(&action2.data).unwrap();
        assert_eq!(src, key_a);

        // Step 6: D decrypts
        let msg = parse_transport_message(&inner_payload).unwrap();
        assert_eq!(msg.receiver_index, session_d.local_index());

        let plaintext = session_d.decrypt(msg.ciphertext, msg.counter).unwrap();
        let (proto, _svc, data) = decode_payload(&plaintext).unwrap();
        assert_eq!(proto, 0); // 0 = RAW
        assert_eq!(data, original_data);
    }
}
