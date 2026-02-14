//! KCP reliable transport and stream multiplexing.
//!
//! This module provides:
//! - `Kcp`: KCP reliable transport protocol bindings
//! - `Frame`: Multiplexing frame encoding/decoding
//! - `Stream`: Multiplexed reliable stream
//! - `Mux`: Stream multiplexer

#[allow(clippy::module_inception)]
mod kcp;
pub mod fec;
mod stream;

// Re-export from kcp module
pub use kcp::{Kcp, Frame, Cmd, FrameError, FRAME_HEADER_SIZE, MAX_PAYLOAD_SIZE};

// Re-export from fec module
pub use fec::{Encoder as FecEncoder, Decoder as FecDecoder};

// Re-export from stream module
pub use stream::{Stream, StreamIo, StreamState, StreamError, Mux, MuxConfig, MuxError, OutputFn, OnStreamDataFn, OnNewStreamFn};
