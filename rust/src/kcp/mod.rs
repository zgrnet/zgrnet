//! KCP reliable transport and stream multiplexing.
//!
//! Architecture:
//! - `KcpConn`: Async KCP connection with write coalescing and greedy run loop
//! - `ServiceMux`: Per-service KCP + yamux stream multiplexing
//! - `SyncStream`: Sync compatibility wrapper for yamux::Stream
//! - `Kcp`: Low-level KCP frame codec (used by old C-based tests)

#[allow(clippy::module_inception)]
mod kcp;
pub mod fec;
pub mod conn;
pub mod service;
pub mod compat;

pub use kcp::{Kcp, Frame, Cmd, FrameError, FRAME_HEADER_SIZE, MAX_PAYLOAD_SIZE};
pub use fec::{Encoder as FecEncoder, Decoder as FecDecoder};
pub use conn::{KcpConn, KcpInput};
pub use service::{ServiceMux, ServiceMuxConfig, ServiceOutputFn};
pub use compat::SyncStream;
