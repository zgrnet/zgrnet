//! KCP reliable transport and stream multiplexing.
//!
//! This module provides:
//! - `Kcp`: KCP reliable transport protocol bindings
//! - `Frame`: Multiplexing frame encoding/decoding
//! - `Stream`: Multiplexed reliable stream
//! - `Mux`: Stream multiplexer

pub const kcp = @import("kcp.zig");
pub const stream = @import("stream.zig");
pub const ring_buffer = @import("ring_buffer.zig");

// Re-export commonly used types
pub const Kcp = kcp.Kcp;
pub const Frame = kcp.Frame;
pub const Cmd = kcp.Cmd;
pub const FrameError = kcp.FrameError;
pub const FRAME_HEADER_SIZE = kcp.FRAME_HEADER_SIZE;

pub const Stream = stream.Stream;
pub const StreamState = stream.StreamState;
pub const StreamError = stream.StreamError;
pub const Mux = stream.Mux;
pub const MuxConfig = stream.MuxConfig;
pub const MuxError = stream.MuxError;

pub const RingBuffer = ring_buffer.RingBuffer;
