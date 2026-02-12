//! Noise Protocol implementation with UDP network layer.
//!
//! This module provides:
//! 1. Pure Noise Protocol Framework (IK, XX, NN handshake patterns)
//! 2. UDP-based network layer with WireGuard-style connection management
//!
//! The implementation is parameterized by a Crypto type that must provide:
//! - `Blake2s256`: BLAKE2s-256 hash (trait.crypto validated)
//! - `ChaCha20Poly1305`: ChaCha20-Poly1305 AEAD (trait.crypto validated)
//! - `X25519`: Curve25519 DH (trait.crypto validated)
//!
//! Usage:
//!   const noise = @import("noise/mod.zig").Protocol(MyCrypto);
//!   var hs = try noise.HandshakeState.init(.{ ... });

const std = @import("std");

// Core Noise Protocol modules (no crypto dependency)
pub const keypair_mod = @import("keypair.zig");
pub const replay = @import("replay.zig");
pub const message = @import("message.zig");
pub const address = @import("address.zig");

// UDP Network layer modules
pub const conn_impl = @import("conn.zig");
pub const consts = @import("consts.zig");
pub const dial_mod = @import("dial.zig");
pub const listener_mod = @import("listener.zig");
pub const manager = @import("manager.zig");
pub const transport_udp = @import("transport_udp.zig");
pub const udp = @import("udp.zig");

// Non-generic re-exports
pub const Key = keypair_mod.Key;
pub const key_size = keypair_mod.key_size;

pub const ReplayFilter = replay.ReplayFilter;

pub const MessageType = message.MessageType;
pub const Protocol_msg = message.Protocol;
pub const HandshakeInit = message.HandshakeInit;
pub const HandshakeResp = message.HandshakeResp;
pub const TransportMessage = message.TransportMessage;

pub const Address = address.Address;
pub const AddressError = address.AddressError;

// Crypto constants
pub const crypto_mod = @import("crypto.zig");
pub const tag_size = crypto_mod.tag_size;
pub const hash_size = crypto_mod.hash_size;
pub const CipherSuite = crypto_mod.CipherSuite;

// Generic module references (for advanced usage)
pub const cipher_mod = @import("cipher.zig");
pub const state_mod = @import("state.zig");
pub const handshake_mod = @import("handshake.zig");
pub const session_mod = @import("session.zig");

/// Instantiate the full Noise Protocol for a given Crypto implementation.
///
/// Default cipher suite is ChaChaPoly_BLAKE2s. Use ProtocolWithSuite for
/// alternative suites (e.g., AESGCM_SHA256 for ESP32 hardware acceleration).
pub fn Protocol(comptime Crypto: type) type {
    return ProtocolWithSuite(Crypto, .ChaChaPoly_BLAKE2s);
}

/// Instantiate the Noise Protocol with a specific cipher suite.
pub fn ProtocolWithSuite(comptime Crypto: type, comptime suite: CipherSuite) type {
    const hs = handshake_mod.Handshake(Crypto, suite);
    const st = state_mod.State(Crypto, suite);
    const sess = session_mod.SessionMod(Crypto, suite);

    return struct {
        // Crypto-dependent types
        pub const KeyPair = keypair_mod.KeyPair(Crypto);
        pub const CipherState = st.CipherState;
        pub const SymmetricState = st.SymmetricState;
        pub const HandshakeState = hs.HandshakeState;
        pub const Config = hs.Config;
        pub const Session = sess.Session;

        // Re-export non-generic types for convenience
        pub const Key = keypair_mod.Key;
        pub const key_size = keypair_mod.key_size;
        pub const Pattern = handshake_mod.Pattern;
        pub const Error = handshake_mod.Error;
        pub const SessionConfig = session_mod.SessionConfig;
        pub const SessionState = session_mod.SessionState;
        pub const SessionError = session_mod.SessionError;
        pub const ReplayFilter = replay.ReplayFilter;
    };
}

// Handshake pattern (non-generic)
pub const Pattern = handshake_mod.Pattern;
pub const Error = handshake_mod.Error;

// Re-export UDP network layer types
pub const Conn = conn_impl.Conn;
pub const ConnConfig = conn_impl.ConnConfig;
pub const ConnState = conn_impl.ConnState;
pub const ConnError = conn_impl.ConnError;
pub const RecvResult = conn_impl.RecvResult;

pub const dial = dial_mod.dial;
pub const DialOptions = dial_mod.DialOptions;
pub const DialError = dial_mod.DialError;

pub const Listener = listener_mod.Listener;
pub const ListenerConfig = listener_mod.ListenerConfig;
pub const ListenerError = listener_mod.ListenerError;

pub const SessionManager = manager.SessionManager;
pub const ManagerError = manager.ManagerError;

pub const UdpTransport = transport_udp.UdpTransport;
pub const UdpAddr = transport_udp.UdpAddr;

pub const UDP = udp.UDP;
pub const UdpError = udp.UdpError;
pub const UdpOptions = udp.UdpOptions;
pub const Packet = udp.Packet;
pub const PacketPool = udp.PacketPool;
pub const ReadResult = udp.ReadResult;
pub const ReadPacketResult = udp.ReadPacketResult;

pub const KcpMux = udp.KcpMux;
pub const KcpStream = udp.KcpStream;

pub const DecryptChanSize = udp.DecryptChanSize;
pub const OutputChanSize = udp.OutputChanSize;
pub const MaxPacketSize = udp.MaxPacketSize;

// Re-export network constants
pub const rekey_after_time_ns = consts.rekey_after_time_ns;
pub const reject_after_time_ns = consts.reject_after_time_ns;
pub const rekey_attempt_time_ns = consts.rekey_attempt_time_ns;
pub const rekey_timeout_ns = consts.rekey_timeout_ns;
pub const keepalive_timeout_ns = consts.keepalive_timeout_ns;
pub const rekey_on_recv_threshold_ns = consts.rekey_on_recv_threshold_ns;
pub const session_cleanup_time_ns = consts.session_cleanup_time_ns;
pub const rekey_after_messages = consts.rekey_after_messages;
pub const reject_after_messages = consts.reject_after_messages;

test {
    // Don't use refAllDecls — it forces analysis of generate()/generateIndex()
    // which use std.crypto.random (unavailable on freestanding).
    _ = keypair_mod;
    _ = cipher_mod;
    _ = crypto_mod;
    _ = state_mod;
    _ = handshake_mod;
    _ = replay;
    _ = session_mod;
    _ = message;
    _ = address;
    _ = conn_impl;
    _ = consts;
    _ = dial_mod;
    _ = listener_mod;
    _ = manager;
    _ = transport_udp;
    _ = udp;
}
