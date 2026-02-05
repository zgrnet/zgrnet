//! KCP reliable transport and stream multiplexing.
//!
//! This module provides:
//! - `Kcp`: KCP reliable transport protocol bindings
//! - `Frame`: Multiplexing frame encoding/decoding
//! - `Stream`: Multiplexed reliable stream
//! - `Mux`: Stream multiplexer

#[allow(clippy::module_inception)]
mod kcp;
mod stream;

// Re-export from kcp module
pub use kcp::{Kcp, Frame, Cmd, FrameError, FRAME_HEADER_SIZE, MAX_PAYLOAD_SIZE};

// Re-export from stream module
pub use stream::{Stream, StreamState, StreamError, Mux, MuxConfig, MuxError, OutputFn, OnStreamDataFn, OnNewStreamFn};
