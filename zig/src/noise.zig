//! zgrnet - Noise Protocol based networking library.
//!
//! This module provides:
//! - `noise`: Pure Noise Protocol Framework implementation
//! - `conn`: WireGuard-style connection management

const std = @import("std");

// Submodules
pub const noise = @import("noise/root.zig");
pub const conn = @import("conn/root.zig");
pub const udp = @import("udp.zig");
// Net layer (unified UDP)
pub const net = @import("net.zig");

// KCP multiplexing
pub const kcp = @import("kcp.zig");
pub const stream = @import("stream.zig");

// Re-export noise types for convenience
pub const Key = noise.Key;
pub const KeyPair = noise.KeyPair;
pub const key_size = noise.key_size;
pub const CipherState = noise.CipherState;
pub const SymmetricState = noise.SymmetricState;
pub const HandshakeState = noise.HandshakeState;
pub const Config = noise.Config;
pub const Pattern = noise.Pattern;
pub const Error = noise.Error;
pub const ReplayFilter = noise.ReplayFilter;
pub const Session = noise.Session;
pub const SessionConfig = noise.SessionConfig;
pub const SessionState = noise.SessionState;
pub const SessionError = noise.SessionError;
pub const MessageType = noise.MessageType;
pub const Protocol = noise.Protocol;
pub const HandshakeInit = noise.HandshakeInit;
pub const HandshakeResp = noise.HandshakeResp;
pub const TransportMessage = noise.TransportMessage;
pub const Transport = noise.Transport;
pub const Addr = noise.Addr;
pub const MockTransport = noise.MockTransport;
pub const MockAddr = noise.MockAddr;
pub const tag_size = noise.tag_size;
pub const hash_size = noise.hash_size;

// Re-export conn types for convenience
pub const Conn = conn.Conn;
pub const ConnConfig = conn.ConnConfig;
pub const ConnState = conn.ConnState;
pub const ConnError = conn.ConnError;
pub const RecvResult = conn.RecvResult;
pub const SessionManager = conn.SessionManager;
pub const ManagerError = conn.ManagerError;

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

// Net layer types
pub const UDP = net.UDP;
pub const UdpOptions = net.UdpOptions;
pub const UdpError = net.UdpError;
pub const PeerInfo = net.PeerInfo;
pub const NetPeerState = net.PeerState;
pub const NetPeer = net.Peer;

// Re-export UDP types
pub const Udp = udp.Udp;
pub const UdpAddr = udp.UdpAddr;

/// Returns the name of the active cipher backend.
pub fn backendName() []const u8 {
    return noise.backendName();
}

test {
    std.testing.refAllDecls(@This());
    _ = noise;
    _ = conn;
    _ = udp;
    _ = kcp;
    _ = stream;
    _ = net;
}
