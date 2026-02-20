//! KCP reliable transport and stream multiplexing.
//!
//! This module provides:
//! - `Kcp`: KCP reliable transport protocol bindings
//! - `KcpConn`: Event-driven KCP connection with dedicated thread
//! - `AsyncKcpConn`: Async adapter (AsyncRead + AsyncWrite) for yamux
//! - Legacy: `Stream`, `Mux` (to be removed in Step 5.4)

#[allow(clippy::module_inception)]
mod kcp;
pub mod fec;
mod stream;
pub mod conn;
pub mod service;

// Re-export from kcp module
pub use kcp::{Kcp, Frame, Cmd, FrameError, FRAME_HEADER_SIZE, MAX_PAYLOAD_SIZE};

// Re-export from fec module
pub use fec::{Encoder as FecEncoder, Decoder as FecDecoder};

// Re-export new conn types
pub use conn::KcpConn;
pub use service::{ServiceMux, ServiceMuxConfig, ServiceOutputFn};

// Legacy re-exports (to be removed in Step 5.4)
pub use stream::{Stream, StreamIo, StreamState, StreamError, Mux, MuxConfig, MuxError, OutputFn, OnStreamDataFn, OnNewStreamFn};
