//! KCP reliable transport and stream multiplexing.
//!
//! This module provides:
//! - `Kcp`: KCP reliable transport protocol bindings
//! - `Frame`: Multiplexing frame encoding/decoding
//! - `Stream`: Multiplexed reliable stream
//! - `Mux`: Stream multiplexer (comptime generic for zero-cost async)
//!
//! ## Usage
//!
//! ```zig
//! const MuxType = kcp.Mux(MyTimerService);
//! const mux = try MuxType.init(allocator, timer_service, ...);
//! defer mux.deinit();
//!
//! const stream = try mux.openStream(0, &.{});
//! defer stream.close();
//! ```

pub const kcp = @import("kcp.zig");
pub const stream = @import("stream.zig");
pub const ring_buffer = @import("ring_buffer.zig");

// Re-export commonly used types
pub const Kcp = kcp.Kcp;
pub const Frame = kcp.Frame;
pub const Cmd = kcp.Cmd;
pub const FrameError = kcp.FrameError;
pub const FrameHeaderSize = kcp.FrameHeaderSize;

// Stream types
pub const Stream = stream.Stream;
pub const StreamState = stream.StreamState;
pub const StreamError = stream.StreamError;

// Mux - comptime generic
pub const Mux = stream.Mux;
pub const MuxConfig = stream.MuxConfig;
pub const MuxError = stream.MuxError;
pub const SimpleMux = stream.SimpleMux;

// Callbacks
pub const OutputFn = stream.OutputFn;
pub const OnNewStreamFn = stream.OnNewStreamFn;

pub const RingBuffer = ring_buffer.RingBuffer;
