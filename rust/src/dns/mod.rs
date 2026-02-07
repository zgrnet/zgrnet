//! Magic DNS server implementation.
//!
//! This module provides:
//! - `protocol`: Minimal DNS message encode/decode (A/AAAA)
//! - `server`: Magic DNS server with zigor.net resolution
//! - `fakeip`: Fake IP pool for route-matched domains

pub mod protocol;
pub mod server;
pub mod fakeip;

pub use protocol::*;
pub use server::Server;
pub use fakeip::FakeIPPool;
