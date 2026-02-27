//! zgrnet - Noise Protocol based networking library.
//!
//! This module provides:
//! - `noise`: Pure Noise Protocol Framework (generic over Crypto)
//! - `net`: Network layer with WireGuard-style connection management (generic over Crypto + Rt)
//!
//! The noise protocol is parameterized by a Crypto type. For desktop platforms,
//! we use StdCrypto (std.crypto wrappers conforming to trait.crypto interface).
//! For ESP32, a hardware-accelerated Crypto implementation can be substituted.

const std = @import("std");

// Core modules
pub const noise = @import("noise/mod.zig");
pub const net = @import("net/mod.zig");
pub const kcp_mod = @import("kcp/mod.zig");
pub const relay_mod = @import("relay/mod.zig");
pub const host = @import("host/mod.zig");
pub const node_mod = @import("node.zig");
pub const proxy_mod = @import("proxy/mod.zig");
pub const dns_mod = @import("dns/mod.zig");
pub const dnsmgr_mod = @import("dnsmgr/mod.zig");
pub const config_mod = @import("config/mod.zig");
pub const json_config = @import("config.zig");
pub const lan_mod = @import("lan/mod.zig");

// ============================================================================
// Concrete Crypto + Runtime instantiation for desktop platforms
// ============================================================================

/// StdCrypto — std.crypto wrappers conforming to trait.crypto interface.
/// Provides Blake2s256, ChaCha20Poly1305, X25519 for Noise Protocol.
pub const StdCrypto = noise.test_crypto;

/// StdRt — embed-zig's std runtime + timedWait/sleepMs shim.
/// Once embed-zig adds these to std_impl.runtime, this can be
/// changed to `@import("std_impl").runtime` directly.
pub const StdRt = @import("runtime.zig");

/// Concrete Noise Protocol instantiation for desktop platforms.
pub const N = noise.Protocol(StdCrypto);

// ============================================================================
// Non-generic noise types (no Crypto dependency)
// ============================================================================

pub const Key = noise.Key;
pub const key_size = noise.key_size;
pub const Pattern = noise.Pattern;
pub const Error = noise.Error;
pub const ReplayFilter = noise.ReplayFilter;
pub const MessageType = noise.MessageType;
pub const Protocol = noise.Protocol_msg;
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
pub const SessionConfig = noise.SessionConfig;
pub const SessionState = noise.SessionState;
pub const SessionError = noise.SessionError;

// ============================================================================
// Concrete generic types (instantiated with StdCrypto)
// ============================================================================

pub const KeyPair = N.KeyPair;
pub const CipherState = N.CipherState;
pub const SymmetricState = N.SymmetricState;
pub const HandshakeState = N.HandshakeState;
pub const Config = N.Config;
pub const Session = N.Session;

// ============================================================================
// IO backends (for UDP)
// ============================================================================

const std_impl = @import("std_impl");
pub const IOService = std_impl.IOService;
// Backward-compatible alias (now resolves to kqueue on macOS, epoll on Linux).
pub const KqueueIO = IOService;

// ============================================================================
// Socket abstraction
// ============================================================================

pub const Endpoint = net.Endpoint;
pub const StdUdpSocket = net.StdUdpSocket;

// ============================================================================
// Concrete Net layer types (instantiated with StdCrypto + StdRt)
// ============================================================================

pub const Conn = net.Conn(StdCrypto, StdRt);
pub const ConnConfig = Conn.ConnConfig;
pub const ConnState = net.ConnState;
pub const ConnError = net.ConnError;
pub const RecvResult = net.RecvResult;
pub const SessionManager = net.SessionManager(StdCrypto, StdRt);
pub const ManagerError = net.ManagerError;
pub const DialOptions = net.DialOptions(StdCrypto);
pub const DialError = net.DialError;
pub const Listener = net.Listener(StdCrypto, StdRt);
pub const ListenerConfig = Listener.Config;
pub const ListenerError = net.ListenerError;
pub const UdpTransport = net.UdpTransport;
pub const UdpAddr = net.UdpAddr;
pub const UDP = net.UDP(StdCrypto, StdRt, IOService, StdUdpSocket);
pub const UdpError = net.UdpError;
pub const UdpOptions = net.UdpOptions;
pub const ReadResult = net.ReadResult;
pub const ReadPacketResult = net.ReadPacketResult;
pub const Packet = net.Packet(StdRt);
pub const PacketPool = net.PacketPool(StdRt);

/// Dial function instantiated with StdCrypto + StdRt.
pub fn dial(opts: DialOptions) DialError!*Conn {
    return net.dial(StdCrypto, StdRt, opts);
}

// ============================================================================
// KCP types
// ============================================================================

pub const kcp = kcp_mod.kcp;
pub const Kcp = kcp_mod.Kcp;
pub const Frame = kcp_mod.Frame;
pub const Cmd = kcp_mod.Cmd;
pub const KcpConn = kcp_mod.KcpConn;
pub const KcpSelector = kcp_mod.KcpSelector;
pub const Yamux = kcp_mod.Yamux;
pub const YamuxStream = kcp_mod.YamuxStream;
pub const ServiceMux = kcp_mod.ServiceMux;

// ============================================================================
// Relay types
// ============================================================================

pub const relay = relay_mod;

// ============================================================================
// Host types
// ============================================================================

pub const Host = host.Host;
pub const TunDevice = host.TunDevice;
pub const IPAllocator = host.IPAllocator;
pub const HostError = host.HostError;
pub const HostConfig = host.Config(KeyPair);
pub const PeerConfig = host.PeerConfig;
pub const HostEndpoint = host.Endpoint;

// ============================================================================
// Node types (embeddable network node, no TUN)
// ============================================================================

pub const NodeType = node_mod.Node(StdCrypto, StdRt, IOService, StdUdpSocket);
pub const NodeConfig = NodeType.Config;
pub const NodePeerConfig = NodeType.PeerConfig;
pub const NodeStream = NodeType.NodeStream;

// ============================================================================
// Config types
// ============================================================================

pub const config = config_mod;

// ============================================================================
// LAN types
// ============================================================================

pub const lan = lan_mod;
pub const LanStore = lan_mod.Store;
pub const LanServer = lan_mod.Server(StdRt);
pub const LanEvent = lan_mod.Event;

test {
    // Don't use refAllDecls — it forces analysis of generate()/generateIndex()
    // which use std.crypto.random (unavailable on freestanding).
    _ = noise;
    _ = net;
    _ = kcp_mod;
    _ = kcp_mod.conn_mod;
    _ = kcp_mod.yamux_mod;
    _ = kcp_mod.service_mod;
    _ = relay_mod;
    _ = host;
    _ = node_mod;
    _ = proxy_mod;
    _ = dns_mod;
    _ = dnsmgr_mod;
    _ = config_mod;
    _ = lan_mod;
}
