//! Network layer for zgrnet.
//!
//! This module provides WireGuard-style connection management including:
//! - `Conn`: A connection to a remote peer (generic over Crypto + Rt)
//! - `Listener`: Server-side connection acceptor (generic over Crypto + Rt)
//! - `dial`: Client-side connection initiator (generic over Crypto + Rt)
//! - `SessionManager`: Multi-peer session management (generic over Crypto + Rt)
//! - `UdpTransport`: UDP-based transport implementation
//! - `UDP`: High-level peer management layer with double-queue architecture (generic over Crypto + Rt + IOBackend + SocketImpl)
//! - `Endpoint`: Portable IPv4 endpoint (replaces posix.sockaddr)
//! - `StdUdpSocket`: POSIX-based UDP socket implementation

const std = @import("std");

// Connection management modules
pub const conn_impl = @import("conn.zig");
pub const consts = @import("consts.zig");
pub const dial_mod = @import("dial.zig");
pub const listener_mod = @import("listener.zig");
pub const manager = @import("manager.zig");

// Transport modules
pub const transport_udp = @import("transport_udp.zig");
pub const udp = @import("udp.zig");

// Socket abstraction
pub const endpoint_mod = @import("endpoint.zig");
pub const socket_mod = @import("socket.zig");
pub const std_socket = @import("std_socket.zig");

// Re-export generic type constructors
pub const Conn = conn_impl.Conn;
pub const ConnState = conn_impl.ConnState;
pub const ConnError = conn_impl.ConnError;
pub const RecvResult = conn_impl.RecvResult;
pub const InboundPacket = conn_impl.InboundPacket;

// Re-export dial function and options
pub const dial = dial_mod.dial;
pub const DialOptions = dial_mod.DialOptions;
pub const DialError = dial_mod.DialError;

// Re-export listener types
pub const Listener = listener_mod.Listener;
pub const ListenerError = listener_mod.ListenerError;

// Re-export session manager
pub const SessionManager = manager.SessionManager;
pub const ManagerError = manager.ManagerError;

// Re-export transport types
pub const UdpTransport = transport_udp.UdpTransport;
pub const UdpAddr = transport_udp.UdpAddr;

// Re-export high-level UDP API (double-queue architecture)
pub const UDP = udp.UDP;
pub const UdpError = udp.UdpError;
pub const UdpOptions = udp.UdpOptions;
pub const Packet = udp.Packet;
pub const PacketPool = udp.PacketPool;
pub const ReadResult = udp.ReadResult;
pub const ReadPacketResult = udp.ReadPacketResult;

// Re-export portable endpoint and socket types
pub const Endpoint = endpoint_mod.Endpoint;
pub const SocketError = socket_mod.SocketError;
pub const RecvFromResult = socket_mod.RecvFromResult;
pub const StdUdpSocket = std_socket.StdUdpSocket;

// KCP types (convenience re-exports from udp module, for backward compat)
pub const KcpMux = udp.StdKcpMux;
pub const KcpStream = udp.StdKcpStream;

// Channel sizes
pub const DecryptChanSize = udp.DecryptChanSize;
pub const OutputChanSize = udp.OutputChanSize;
pub const MaxPacketSize = udp.MaxPacketSize;

// Re-export constants
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
    _ = conn_impl;
    _ = consts;
    _ = dial_mod;
    _ = listener_mod;
    _ = manager;
    _ = transport_udp;
    _ = udp;
    _ = endpoint_mod;
    _ = socket_mod;
    _ = std_socket;
}
