//! Noise Protocol implementation for zgrnet.
//!
//! This module provides a pure Noise Protocol Framework implementation
//! supporting IK, XX, and NN handshake patterns.
//!
//! ## Architecture Support
//! - ARM64 (aarch64): Uses BoringSSL assembly (~13 Gbps)
//! - ESP32/ARM32/x86: Uses pure Zig implementation (~7 Gbps)

const std = @import("std");

pub const keypair = @import("keypair.zig");
pub const cipher = @import("cipher.zig");
pub const crypto = @import("crypto.zig");
pub const state = @import("state.zig");
pub const handshake = @import("handshake.zig");

// Re-export main types
pub const Key = keypair.Key;
pub const KeyPair = keypair.KeyPair;
pub const CipherState = state.CipherState;
pub const SymmetricState = state.SymmetricState;
pub const HandshakeState = handshake.HandshakeState;
pub const Config = handshake.Config;
pub const Pattern = handshake.Pattern;
pub const Error = handshake.Error;

// Re-export constants
pub const key_size = keypair.key_size;
pub const tag_size = crypto.tag_size;
pub const hash_size = crypto.hash_size;

/// Returns the name of the active cipher backend.
pub fn backendName() []const u8 {
    return cipher.backendName();
}

test {
    std.testing.refAllDecls(@This());
    _ = keypair;
    _ = cipher;
    _ = crypto;
    _ = state;
    _ = handshake;
}
