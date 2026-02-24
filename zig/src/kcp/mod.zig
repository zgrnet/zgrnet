//! KCP reliable transport and stream multiplexing.
//!
//! New architecture (Phase 6):
//! - `KcpConn(Rt)`: Event-driven KCP connection with write coalescing
//! - `Yamux(Rt)`: yamux stream multiplexer (from spec)
//! - `ServiceMux(Rt)`: Per-service KCP + yamux routing
//! - `Kcp`: Low-level C KCP bindings

pub const kcp = @import("kcp.zig");
pub const fec = @import("fec.zig");
pub const ring_buffer = @import("ring_buffer.zig");
pub const conn_mod = @import("conn.zig");
pub const yamux_mod = @import("yamux.zig");
pub const service_mod = @import("service.zig");

pub const Kcp = kcp.Kcp;
pub const Frame = kcp.Frame;
pub const Cmd = kcp.Cmd;
pub const FrameError = kcp.FrameError;
pub const FrameHeaderSize = kcp.FrameHeaderSize;

pub const FecEncoder = fec.Encoder;
pub const FecDecoder = fec.Decoder;
pub const FecHeaderSize = fec.HeaderSize;

pub const RingBuffer = ring_buffer.RingBuffer;

pub const KcpConn = conn_mod.KcpConn;
pub const KcpSelector = conn_mod.KcpSelector;
pub const Yamux = yamux_mod.Yamux;
pub const YamuxStream = yamux_mod.YamuxStream;
pub const YamuxFrame = yamux_mod.Frame;
pub const ServiceMux = service_mod.ServiceMux;
