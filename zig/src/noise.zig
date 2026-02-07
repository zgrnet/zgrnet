//! zgrnet - Noise Protocol based networking library.
//!
//! This module provides:
//! - `noise`: Pure Noise Protocol Framework implementation
//! - `net`: Network layer with WireGuard-style connection management

const std = @import("std");

// Submodules
pub const noise = @import("noise/mod.zig");
pub const net = @import("net/mod.zig");
pub const async_mod = @import("async/mod.zig");
pub const kcp_mod = @import("kcp/mod.zig");
pub const relay_mod = @import("relay/mod.zig");
pub const host = @import("host/mod.zig");
pub const proxy_mod = @import("proxy/mod.zig");
pub const dns_mod = @import("dns/mod.zig");
pub const dnsmgr_mod = @import("dnsmgr/mod.zig");

// KCP multiplexing (re-export submodules)
pub const kcp = kcp_mod.kcp;
pub const stream = kcp_mod.stream;

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
pub const Address = noise.Address;
pub const AddressError = noise.AddressError;
pub const address = noise.address;
pub const tag_size = noise.tag_size;
pub const hash_size = noise.hash_size;

// Re-export net types for convenience
pub const Conn = net.Conn;
pub const ConnConfig = net.ConnConfig;
pub const ConnState = net.ConnState;
pub const ConnError = net.ConnError;
pub const RecvResult = net.RecvResult;
pub const SessionManager = net.SessionManager;
pub const ManagerError = net.ManagerError;
pub const dial = net.dial;
pub const DialOptions = net.DialOptions;
pub const DialError = net.DialError;
pub const Listener = net.Listener;
pub const ListenerConfig = net.ListenerConfig;
pub const ListenerError = net.ListenerError;

// Transport types
pub const UdpTransport = net.UdpTransport;
pub const UdpAddr = net.UdpAddr;

// High-level UDP API types (double-queue architecture)
pub const UDP = net.UDP;
pub const UdpError = net.UdpError;
pub const UdpOptions = net.UdpOptions;
pub const ReadResult = net.ReadResult;
pub const ReadPacketResult = net.ReadPacketResult;
pub const Packet = net.Packet;
pub const PacketPool = net.PacketPool;

// IO backend types (for UDP generic parameter)
pub const IOService = async_mod.IOService;
pub const KqueueIO = async_mod.KqueueIO;

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

// Relay types
pub const relay = relay_mod;

// Host types
pub const Host = host.Host;
pub const TunDevice = host.TunDevice;
pub const IPAllocator = host.IPAllocator;
pub const HostError = host.HostError;
pub const HostConfig = host.Config;
pub const PeerConfig = host.PeerConfig;

/// Returns the name of the active cipher backend.
pub fn backendName() []const u8 {
    return noise.backendName();
}

test {
    std.testing.refAllDecls(@This());
    _ = noise;
    _ = net;
    _ = kcp_mod;
    _ = relay_mod;
    _ = host;
    _ = proxy_mod;
    _ = dns_mod;
    _ = dnsmgr_mod;
}
