//! KCP reliable transport and stream multiplexing.
//!
//! This module provides:
//! - `Kcp`: KCP reliable transport protocol bindings
//! - `Frame`: Multiplexing frame encoding/decoding
//! - `Stream(Rt)`: Multiplexed reliable stream (generic over Runtime)
//! - `Mux(Rt)`: Stream multiplexer (generic over Runtime)
//!
//! ## Usage
//!
//! ```zig
//! const MyMux = kcp.Mux(MyRuntime);
//! const mux = try MyMux.init(allocator, ...);
//! defer mux.deinit();
//!
//! const stream = try mux.openStream(0, &.{});
//! defer stream.close();
//!
//! const n = try stream.readBlocking(&buf, 5_000_000_000); // 5s timeout
//! ```

pub const kcp = @import("kcp.zig");
pub const stream_mod = @import("stream.zig");
pub const ring_buffer = @import("ring_buffer.zig");

// Re-export commonly used types
pub const Kcp = kcp.Kcp;
pub const Frame = kcp.Frame;
pub const Cmd = kcp.Cmd;
pub const FrameError = kcp.FrameError;
pub const FrameHeaderSize = kcp.FrameHeaderSize;

// Stream/Mux - generic over Runtime
pub const Stream = stream_mod.Stream;
pub const Mux = stream_mod.Mux;
pub const StreamState = stream_mod.StreamState;
pub const StreamError = stream_mod.StreamError;
pub const MuxConfig = stream_mod.MuxConfig;
pub const MuxError = stream_mod.MuxError;

// Callbacks
pub const OutputFn = stream_mod.OutputFn;
pub const OnNewStreamFn = stream_mod.OnNewStreamFn;

pub const RingBuffer = ring_buffer.RingBuffer;
