//! SOCKS5 and HTTP CONNECT proxy protocol implementation.
//!
//! Provides protocol parsing and formatting for:
//! - SOCKS5 TCP CONNECT and UDP ASSOCIATE
//! - HTTP CONNECT (auto-detected by first byte)
//! - Remote TCP_PROXY and UDP_PROXY handlers

pub const socks5 = @import("socks5.zig");

// Re-export commonly used types
pub const Address = @import("../noise/address.zig").Address;
pub const VERSION5 = socks5.VERSION5;
pub const Request = socks5.Request;
pub const Error = socks5.Error;

test {
    _ = socks5;
}
