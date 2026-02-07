//! Relay protocol implementation for multi-hop forwarding.
//!
//! This module implements RELAY_0/1/2 (protocol 66/67/68) and
//! PING/PONG (protocol 70/71) message encoding/decoding and
//! forwarding logic.

const std = @import("std");

pub const message = @import("message.zig");
pub const engine = @import("relay.zig");

// Re-export message types
pub const Relay0 = message.Relay0;
pub const Relay1 = message.Relay1;
pub const Relay2 = message.Relay2;
pub const Ping = message.Ping;
pub const Pong = message.Pong;
pub const Strategy = message.Strategy;
pub const RelayError = message.RelayError;

// Re-export sizes
pub const relay0_header_size = message.relay0_header_size;
pub const relay1_header_size = message.relay1_header_size;
pub const relay2_header_size = message.relay2_header_size;
pub const ping_size = message.ping_size;
pub const pong_size = message.pong_size;
pub const default_ttl = message.default_ttl;

// Re-export encode/decode
pub const encodeRelay0 = message.encodeRelay0;
pub const decodeRelay0 = message.decodeRelay0;
pub const encodeRelay1 = message.encodeRelay1;
pub const decodeRelay1 = message.decodeRelay1;
pub const encodeRelay2 = message.encodeRelay2;
pub const decodeRelay2 = message.decodeRelay2;
pub const encodePing = message.encodePing;
pub const decodePing = message.decodePing;
pub const encodePong = message.encodePong;
pub const decodePong = message.decodePong;

// Re-export engine types and functions
pub const Router = engine.Router;
pub const Action = engine.Action;
pub const NodeMetrics = engine.NodeMetrics;
pub const Relay2Result = engine.Relay2Result;
pub const handleRelay0 = engine.handleRelay0;
pub const handleRelay1 = engine.handleRelay1;
pub const handleRelay2 = engine.handleRelay2;
pub const handlePing = engine.handlePing;

test {
    std.testing.refAllDecls(@This());
    _ = message;
    _ = engine;
}
