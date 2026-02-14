//! Configuration file parsing and validation for zgrnetd.
//!
//! Zig uses JSON (no YAML library). The config format is identical to
//! Go/Rust except for JSON syntax.
//!
//! Example:
//! ```json
//! {
//!   "net": {
//!     "private_key": "private.key",
//!     "tun_ipv4": "100.64.0.1",
//!     "tun_mtu": 1400,
//!     "listen_port": 51820,
//!     "data_dir": "./data"
//!   },
//!   "peers": {
//!     "aaa...zigor.net": { "alias": "peer_us", "direct": ["1.2.3.4:51820"] }
//!   }
//! }
//! ```

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

/// Top-level configuration.
pub const Config = struct {
    net: NetConfig,
    peers: std.json.ArrayHashMap(PeerConfig) = .{},
    inbound_policy: InboundPolicy = .{},
    route: RouteConfig = .{},
};

/// Global network settings.
pub const NetConfig = struct {
    private_key: []const u8 = "private.key",
    tun_ipv4: []const u8 = "",
    tun_mtu: u16 = 1400,
    listen_port: u16 = 51820,
    data_dir: []const u8 = "./data",
};

/// Peer configuration.
pub const PeerConfig = struct {
    alias: []const u8 = "",
    direct: []const []const u8 = &.{},
    relay: []const []const u8 = &.{},
};

/// Inbound access control policy.
pub const InboundPolicy = struct {
    default: []const u8 = "deny",
    rules: []const InboundRule = &.{},
};

/// Single inbound rule.
pub const InboundRule = struct {
    name: []const u8 = "",
    action: []const u8 = "",
};

/// Outbound routing rules.
pub const RouteConfig = struct {
    rules: []const RouteRule = &.{},
};

/// Single route rule. All domain matching is suffix-based.
pub const RouteRule = struct {
    domain: []const u8 = "",
    peer: []const u8 = "",
};

/// Parse a JSON config from a byte slice.
pub fn parse(allocator: Allocator, data: []const u8) !std.json.Parsed(Config) {
    return std.json.parseFromSlice(Config, allocator, data, .{
        .allocate = .alloc_always,
        .ignore_unknown_fields = true,
    });
}

/// Load and parse a JSON config file.
pub fn load(allocator: Allocator, path: []const u8) !std.json.Parsed(Config) {
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();

    const data = try file.readToEndAlloc(allocator, 1024 * 1024); // 1MB max
    defer allocator.free(data);

    return parse(allocator, data);
}

/// Validate the configuration.
pub fn validate(cfg: *const Config) !void {
    // net.tun_ipv4 required
    if (cfg.net.tun_ipv4.len == 0) {
        return error.MissingTunIpv4;
    }

    // Validate CGNAT range
    try validateCgnat(cfg.net.tun_ipv4);

    // MTU range
    if (cfg.net.tun_mtu < 576) {
        return error.InvalidMtu;
    }

    // Validate inbound policy default
    if (!mem.eql(u8, cfg.inbound_policy.default, "allow") and
        !mem.eql(u8, cfg.inbound_policy.default, "deny"))
    {
        return error.InvalidPolicyDefault;
    }
}

/// Check that the IP string is in the CGNAT range (100.64.0.0/10).
fn validateCgnat(addr: []const u8) !void {
    const parsed = parseIpv4(addr) orelse return error.InvalidIpAddress;
    if (parsed[0] != 100 or parsed[1] < 64 or parsed[1] > 127) {
        return error.NotCgnatRange;
    }
}

/// Parse "a.b.c.d" into [4]u8.
pub fn parseIpv4(s: []const u8) ?[4]u8 {
    var result: [4]u8 = undefined;
    var idx: usize = 0;
    var start: usize = 0;

    for (s, 0..) |c, i| {
        if (c == '.') {
            if (idx >= 3) return null;
            result[idx] = std.fmt.parseInt(u8, s[start..i], 10) catch return null;
            idx += 1;
            start = i + 1;
        }
    }
    if (idx != 3) return null;
    result[3] = std.fmt.parseInt(u8, s[start..], 10) catch return null;
    return result;
}

/// Extract hex pubkey from a peer domain.
/// Format: "{first32hex}.{last32hex}.zigor.net" or plain 64-char hex.
pub fn pubkeyFromDomain(domain: []const u8, out: *[32]u8) bool {
    // Strip .zigor.net suffix if present
    const suffix = ".zigor.net";
    var subdomain = domain;
    if (mem.endsWith(u8, domain, suffix)) {
        subdomain = domain[0 .. domain.len - suffix.len];
    }

    // Try "first32.last32" format
    if (mem.indexOf(u8, subdomain, ".")) |dot_pos| {
        const first = subdomain[0..dot_pos];
        const last = subdomain[dot_pos + 1 ..];
        if (first.len + last.len == 64) {
            var combined: [64]u8 = undefined;
            @memcpy(combined[0..first.len], first);
            @memcpy(combined[first.len..64], last);
            if (hexDecode(&combined, out)) return true;
        }
    }

    // Try plain 64-char hex
    if (subdomain.len == 64) {
        if (hexDecode(subdomain, out)) return true;
    }

    return false;
}

fn hexDecode(hex: []const u8, out: *[32]u8) bool {
    if (hex.len != 64) return false;
    const result = std.fmt.hexToBytes(out, hex) catch return false;
    _ = result;
    return true;
}

pub const ConfigError = error{
    MissingTunIpv4,
    InvalidIpAddress,
    NotCgnatRange,
    InvalidMtu,
    InvalidPolicyDefault,
};

test "parse minimal config" {
    const json =
        \\{"net": {"tun_ipv4": "100.64.0.1"}}
    ;
    const parsed = try parse(std.testing.allocator, json);
    defer parsed.deinit();

    try std.testing.expectEqualStrings("100.64.0.1", parsed.value.net.tun_ipv4);
    try std.testing.expectEqual(@as(u16, 1400), parsed.value.net.tun_mtu);
    try std.testing.expectEqual(@as(u16, 51820), parsed.value.net.listen_port);
}

test "validate cgnat" {
    try validateCgnat("100.64.0.1");
    try validateCgnat("100.127.255.254");
    try std.testing.expectError(error.NotCgnatRange, validateCgnat("192.168.1.1"));
    try std.testing.expectError(error.InvalidIpAddress, validateCgnat("invalid"));
}

test "parse ipv4" {
    const ip = parseIpv4("100.64.0.1").?;
    try std.testing.expectEqual([4]u8{ 100, 64, 0, 1 }, ip);
    try std.testing.expectEqual(@as(?[4]u8, null), parseIpv4("invalid"));
}

test "pubkey from domain" {
    var out: [32]u8 = undefined;
    const hex64 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const domain = hex64[0..32] ++ "." ++ hex64[32..64] ++ ".zigor.net";
    try std.testing.expect(pubkeyFromDomain(domain, &out));
    try std.testing.expect(!pubkeyFromDomain("bad.zigor.net", &out));
}
