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
pub const replay = @import("replay.zig");
pub const session = @import("session.zig");
pub const manager = @import("manager.zig");

// Re-export main types
pub const Key = keypair.Key;
pub const KeyPair = keypair.KeyPair;
pub const CipherState = state.CipherState;
pub const SymmetricState = state.SymmetricState;
pub const HandshakeState = handshake.HandshakeState;
pub const Config = handshake.Config;
pub const Pattern = handshake.Pattern;
pub const Error = handshake.Error;

// Session management types
pub const ReplayFilter = replay.ReplayFilter;
pub const Session = session.Session;
pub const SessionConfig = session.SessionConfig;
pub const SessionState = session.SessionState;
pub const SessionError = session.SessionError;
pub const SessionManager = manager.SessionManager;
pub const ManagerError = manager.ManagerError;

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
    _ = replay;
    _ = session;
    _ = manager;
}
