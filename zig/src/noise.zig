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

// Conn layer
pub const message = @import("message.zig");
pub const transport = @import("transport.zig");
pub const conn = @import("conn.zig");
pub const udp = @import("udp.zig");
pub const udp_listener = @import("udp_listener.zig");

// Host layer
pub const peer = @import("peer.zig");
pub const peer_manager = @import("peer_manager.zig");
pub const host = @import("host.zig");

// KCP multiplexing
pub const kcp = @import("kcp.zig");
pub const stream = @import("stream.zig");

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

// Conn layer types
pub const MessageType = message.MessageType;
pub const Protocol = message.Protocol;
pub const HandshakeInit = message.HandshakeInit;
pub const HandshakeResp = message.HandshakeResp;
pub const TransportMessage = message.TransportMessage;
pub const Transport = transport.Transport;
pub const Addr = transport.Addr;
pub const MockTransport = transport.MockTransport;
pub const MockAddr = transport.MockAddr;
pub const Udp = udp.Udp;
pub const UdpAddr = udp.UdpAddr;
pub const UdpListener = udp_listener.UdpListener;
pub const Conn = conn.Conn;
pub const ConnConfig = conn.ConnConfig;
pub const ConnState = conn.ConnState;
pub const ConnError = conn.ConnError;

// KCP types
pub const Kcp = kcp.Kcp;
pub const Frame = kcp.Frame;
pub const Cmd = kcp.Cmd;

// Stream/Mux types
pub const Stream = stream.Stream;
pub const StreamState = stream.StreamState;
pub const StreamError = stream.StreamError;
pub const Mux = stream.Mux;
pub const MuxConfig = stream.MuxConfig;

// Host layer types
pub const Peer = peer.Peer;
pub const PeerConfig = peer.PeerConfig;
pub const PeerState = peer.PeerState;
pub const PeerInfo = peer.PeerInfo;
pub const PeerManager = peer_manager.PeerManager;
pub const PeerManagerError = peer_manager.PeerManagerError;
pub const Host = host.Host;
pub const HostConfig = host.HostConfig;
pub const HostError = host.HostError;
pub const Message = host.Message;

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
    _ = message;
    _ = transport;
    _ = conn;
    _ = udp;
    _ = udp_listener;
    _ = peer;
    _ = peer_manager;
    _ = host;
    _ = kcp;
    _ = stream;
}
