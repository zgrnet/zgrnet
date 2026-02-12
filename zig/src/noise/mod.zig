//! Noise Protocol implementation.
//!
//! This module provides the pure Noise Protocol Framework (IK, XX, NN handshake patterns),
//! parameterized by a Crypto type that must provide:
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
pub const transport = @import("transport.zig");

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

pub const Transport = transport.Transport;
pub const Addr = transport.Addr;
pub const MockTransport = transport.MockTransport;
pub const MockAddr = transport.MockAddr;

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

// Test/std crypto implementation (std.crypto wrappers for trait.crypto interface)
pub const test_crypto = @import("test_crypto.zig");

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

// Session config/state (non-generic)
pub const SessionConfig = session_mod.SessionConfig;
pub const SessionState = session_mod.SessionState;
pub const SessionError = session_mod.SessionError;

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
    _ = transport;
}
