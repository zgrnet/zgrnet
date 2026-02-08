//! Magic DNS server implementation.
//!
//! This module provides:
//! - `protocol`: Minimal DNS message encode/decode (A/AAAA)
//! - `server`: Magic DNS server with zigor.net resolution
//! - `fakeip`: Fake IP pool for route-matched domains

const std = @import("std");

pub const protocol = @import("protocol.zig");
pub const server = @import("server.zig");
pub const fakeip = @import("fakeip.zig");

// Re-export main types
pub const Message = protocol.Message;
pub const Header = protocol.Header;
pub const Question = protocol.Question;
pub const ResourceRecord = protocol.ResourceRecord;
pub const DnsError = protocol.DnsError;

pub const Server = server.Server;
pub const ServerConfig = server.ServerConfig;
pub const FakeIPPool = fakeip.FakeIPPool;

test {
    std.testing.refAllDecls(@This());
    _ = protocol;
    _ = server;
    _ = fakeip;
}
