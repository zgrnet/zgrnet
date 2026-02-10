//! Configuration data types and JSON parsing with validation.

const std = @import("std");
const mem = std.mem;
const Allocator = std.mem.Allocator;

/// Top-level configuration structure.
pub const Config = struct {
    net: NetConfig = .{},
    lans: []const LanConfig = &.{},
    peers: std.json.ArrayHashMap(PeerConfig) = .{},
    inbound_policy: InboundPolicy = .{},
    route: RouteConfig = .{},
};

/// Global network settings. Changes require a restart.
pub const NetConfig = struct {
    private_key: []const u8 = "",
    tun_ipv4: []const u8 = "",
    tun_mtu: u16 = 0,
    listen_port: u16 = 0,
};

/// Configuration for a zgrlan node.
pub const LanConfig = struct {
    domain: []const u8 = "",
    pubkey: []const u8 = "",
    endpoint: []const u8 = "",
};

/// Configuration for a manually configured peer.
pub const PeerConfig = struct {
    alias: []const u8 = "",
    direct: []const []const u8 = &.{},
    relay: []const []const u8 = &.{},
};

/// Controls who can connect and what services they can access.
pub const InboundPolicy = struct {
    default: []const u8 = "",
    revalidate_interval: []const u8 = "",
    rules: []const InboundRule = &.{},
};

/// A single inbound policy rule.
/// JSON key "match" maps to Zig field @"match" (escaped keyword).
pub const InboundRule = struct {
    name: []const u8 = "",
    @"match": MatchConfig = .{},
    services: []const ServiceConfig = &.{},
    action: []const u8 = "",
};

/// Defines how to match a peer's identity.
pub const MatchConfig = struct {
    pubkey: PubkeyMatch = .{},
};

/// Defines the pubkey matching strategy.
/// JSON key "type" maps to Zig field @"type" (escaped keyword).
pub const PubkeyMatch = struct {
    @"type": []const u8 = "",
    path: []const u8 = "",
    peer: []const u8 = "",
};

/// Defines which network services are accessible.
pub const ServiceConfig = struct {
    proto: []const u8 = "",
    port: []const u8 = "",
};

/// Outbound routing rules.
pub const RouteConfig = struct {
    rules: []const RouteRule = &.{},
};

/// Defines how traffic for specific domains is routed.
pub const RouteRule = struct {
    domain: []const u8 = "",
    domain_list: []const u8 = "",
    peer: []const u8 = "",
};

pub const ConfigError = error{
    ValidationFailed,
    ParseFailed,
    IoError,
    UnexpectedToken,
    Overflow,
    InvalidNumber,
    InvalidEnumTag,
    DuplicateField,
    UnknownField,
    MissingField,
    LengthMismatch,
    OutOfMemory,
    BufferUnderrun,
    EndOfStream,
};

/// Load and parse a JSON config file from the given path.
pub fn load(allocator: Allocator, path: []const u8) ConfigError!std.json.Parsed(Config) {
    const file = std.fs.cwd().openFile(path, .{}) catch return error.IoError;
    defer file.close();
    const data = file.readToEndAlloc(allocator, 1024 * 1024) catch return error.IoError;
    defer allocator.free(data);
    return loadFromBytes(allocator, data);
}

/// Parse a JSON config from raw bytes.
pub fn loadFromBytes(allocator: Allocator, data: []const u8) ConfigError!std.json.Parsed(Config) {
    const parsed = std.json.parseFromSlice(Config, allocator, data, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    }) catch return error.ParseFailed;

    validate(&parsed.value) catch {
        parsed.deinit();
        return error.ValidationFailed;
    };

    return parsed;
}

/// Validate a Config for correctness.
pub fn validate(cfg: *const Config) error{ValidationFailed}!void {
    try validateNet(&cfg.net);
    for (cfg.lans) |lan| {
        try validateLan(&lan);
    }
    for (cfg.peers.map.keys()) |domain| {
        try validatePeerDomain(domain);
    }
    for (cfg.peers.map.values()) |*peer_cfg| {
        try validatePeer(peer_cfg);
    }
    try validateInbound(&cfg.inbound_policy);
    try validateRoute(&cfg.route);
}

fn validateNet(net: *const NetConfig) error{ValidationFailed}!void {
    if (net.private_key.len == 0) return error.ValidationFailed;
    if (net.tun_ipv4.len == 0) return error.ValidationFailed;
    const ip = parseIPv4(net.tun_ipv4) orelse return error.ValidationFailed;
    if (!isCGNAT(ip)) return error.ValidationFailed;
}

fn validateLan(lan: *const LanConfig) error{ValidationFailed}!void {
    if (lan.domain.len == 0) return error.ValidationFailed;
    if (lan.pubkey.len == 0) return error.ValidationFailed;
    if (lan.pubkey.len != 64) return error.ValidationFailed;
    if (!isValidHex(lan.pubkey)) return error.ValidationFailed;
    if (lan.endpoint.len == 0) return error.ValidationFailed;
}

fn validatePeerDomain(domain: []const u8) error{ValidationFailed}!void {
    const suffix = ".zigor.net";
    if (domain.len <= suffix.len) return error.ValidationFailed;
    if (!mem.endsWith(u8, domain, suffix)) return error.ValidationFailed;
    const prefix = domain[0 .. domain.len - suffix.len];
    if (prefix.len == 0 or prefix.len > 64) return error.ValidationFailed;
    if (!isValidHex(prefix)) return error.ValidationFailed;
}

fn validatePeer(peer_cfg: *const PeerConfig) error{ValidationFailed}!void {
    if (peer_cfg.direct.len == 0 and peer_cfg.relay.len == 0) return error.ValidationFailed;
}

fn validateInbound(policy: *const InboundPolicy) error{ValidationFailed}!void {
    if (policy.default.len > 0) {
        if (!mem.eql(u8, policy.default, "allow") and !mem.eql(u8, policy.default, "deny")) {
            return error.ValidationFailed;
        }
    }
    for (policy.rules) |*rule| {
        try validateInboundRule(rule);
    }
}

fn validateInboundRule(rule: *const InboundRule) error{ValidationFailed}!void {
    if (rule.name.len == 0) return error.ValidationFailed;
    const match_type = rule.@"match".pubkey.@"type";
    if (match_type.len == 0) return error.ValidationFailed;
    const valid_types = [_][]const u8{ "whitelist", "zgrlan", "any", "solana", "database", "http" };
    var found = false;
    for (&valid_types) |t| {
        if (mem.eql(u8, match_type, t)) {
            found = true;
            break;
        }
    }
    if (!found) return error.ValidationFailed;
    // Type-specific validation (must match Go and Rust)
    if (mem.eql(u8, match_type, "whitelist")) {
        if (rule.@"match".pubkey.path.len == 0) return error.ValidationFailed;
    }
    if (mem.eql(u8, match_type, "zgrlan")) {
        if (rule.@"match".pubkey.peer.len == 0) return error.ValidationFailed;
    }
    if (!mem.eql(u8, rule.action, "allow") and !mem.eql(u8, rule.action, "deny")) {
        return error.ValidationFailed;
    }
    for (rule.services) |*svc| {
        try validateService(svc);
    }
}

fn validateService(svc: *const ServiceConfig) error{ValidationFailed}!void {
    const valid_protos = [_][]const u8{ "*", "tcp", "udp", "icmp" };
    var found = false;
    for (&valid_protos) |p| {
        if (mem.eql(u8, svc.proto, p)) {
            found = true;
            break;
        }
    }
    if (!found) return error.ValidationFailed;
    if (svc.port.len == 0) return error.ValidationFailed;
}

fn validateRoute(route: *const RouteConfig) error{ValidationFailed}!void {
    for (route.rules) |*rule| {
        if (rule.domain.len == 0 and rule.domain_list.len == 0) return error.ValidationFailed;
        if (rule.peer.len == 0) return error.ValidationFailed;
    }
}

/// Parse an IPv4 address string into 4 octets.
fn parseIPv4(s: []const u8) ?[4]u8 {
    var octets: [4]u8 = .{ 0, 0, 0, 0 };
    var idx: usize = 0;
    var num: u16 = 0;
    var has_digit = false;

    for (s) |c| {
        if (c == '.') {
            if (!has_digit or idx >= 3) return null;
            octets[idx] = @intCast(num);
            idx += 1;
            num = 0;
            has_digit = false;
        } else if (c >= '0' and c <= '9') {
            num = num * 10 + (c - '0');
            if (num > 255) return null;
            has_digit = true;
        } else {
            return null;
        }
    }

    if (!has_digit or idx != 3) return null;
    octets[3] = @intCast(num);
    return octets;
}

/// Check if an IPv4 address is in the CGNAT range (100.64.0.0/10).
fn isCGNAT(ip: [4]u8) bool {
    return ip[0] == 100 and (ip[1] & 0xC0) == 64;
}

/// Check if a string is valid hexadecimal.
fn isValidHex(s: []const u8) bool {
    if (s.len % 2 != 0) return false;
    for (s) |c| {
        if (!((c >= '0' and c <= '9') or (c >= 'a' and c <= 'f') or (c >= 'A' and c <= 'F'))) {
            return false;
        }
    }
    return true;
}

// =========================================================================
// Tests
// =========================================================================

test "parseIPv4" {
    const ip = parseIPv4("100.64.0.1") orelse unreachable;
    try std.testing.expectEqual([4]u8{ 100, 64, 0, 1 }, ip);
    try std.testing.expect(parseIPv4("not-an-ip") == null);
    try std.testing.expect(parseIPv4("999.0.0.1") == null);
}

test "isCGNAT" {
    try std.testing.expect(isCGNAT(.{ 100, 64, 0, 1 }));
    try std.testing.expect(isCGNAT(.{ 100, 127, 255, 255 }));
    try std.testing.expect(!isCGNAT(.{ 192, 168, 1, 1 }));
    try std.testing.expect(!isCGNAT(.{ 100, 128, 0, 0 }));
}

test "isValidHex" {
    try std.testing.expect(isValidHex("abcdef0123456789"));
    try std.testing.expect(!isValidHex("xyz"));
    try std.testing.expect(!isValidHex("abc")); // odd length
}

test "load valid JSON config" {
    const json =
        \\{
        \\  "net": {
        \\    "private_key": "/tmp/test.key",
        \\    "tun_ipv4": "100.64.0.1",
        \\    "tun_mtu": 1400,
        \\    "listen_port": 51820
        \\  },
        \\  "peers": {
        \\    "abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234567aa.zigor.net": {
        \\      "alias": "peer_us",
        \\      "direct": ["us.example.com:51820"]
        \\    }
        \\  },
        \\  "inbound_policy": {
        \\    "default": "deny",
        \\    "rules": [
        \\      {
        \\        "name": "trusted",
        \\        "match": {
        \\          "pubkey": { "type": "any" }
        \\        },
        \\        "services": [{ "proto": "*", "port": "*" }],
        \\        "action": "allow"
        \\      }
        \\    ]
        \\  },
        \\  "route": {
        \\    "rules": [
        \\      { "domain": "*.google.com", "peer": "peer_us" }
        \\    ]
        \\  }
        \\}
    ;

    const parsed = try loadFromBytes(std.testing.allocator, json);
    defer parsed.deinit();

    const cfg = &parsed.value;
    try std.testing.expectEqualStrings("/tmp/test.key", cfg.net.private_key);
    try std.testing.expectEqualStrings("100.64.0.1", cfg.net.tun_ipv4);
    try std.testing.expectEqual(@as(u16, 1400), cfg.net.tun_mtu);
    try std.testing.expectEqual(@as(u16, 51820), cfg.net.listen_port);
    try std.testing.expectEqual(@as(usize, 1), cfg.peers.map.count());
    try std.testing.expectEqual(@as(usize, 1), cfg.inbound_policy.rules.len);
    try std.testing.expectEqual(@as(usize, 1), cfg.route.rules.len);
}

test "validation: missing private_key" {
    const json =
        \\{"net": {"tun_ipv4": "100.64.0.1"}}
    ;
    const result = loadFromBytes(std.testing.allocator, json);
    try std.testing.expectError(error.ValidationFailed, result);
}

test "validation: invalid IP" {
    const json =
        \\{"net": {"private_key": "/tmp/k", "tun_ipv4": "not-an-ip"}}
    ;
    const result = loadFromBytes(std.testing.allocator, json);
    try std.testing.expectError(error.ValidationFailed, result);
}

test "validation: not CGNAT" {
    const json =
        \\{"net": {"private_key": "/tmp/k", "tun_ipv4": "192.168.1.1"}}
    ;
    const result = loadFromBytes(std.testing.allocator, json);
    try std.testing.expectError(error.ValidationFailed, result);
}

test "validation: peer domain format" {
    try validatePeerDomain("abcd.zigor.net");
    try std.testing.expectError(error.ValidationFailed, validatePeerDomain("abc.example.com"));
    try std.testing.expectError(error.ValidationFailed, validatePeerDomain(".zigor.net"));
    try std.testing.expectError(error.ValidationFailed, validatePeerDomain("xyz.zigor.net")); // odd hex
}

test "validation: inbound policy invalid default" {
    const json =
        \\{"net": {"private_key": "/tmp/k", "tun_ipv4": "100.64.0.1"}, "inbound_policy": {"default": "maybe"}}
    ;
    const result = loadFromBytes(std.testing.allocator, json);
    try std.testing.expectError(error.ValidationFailed, result);
}

test "validation: route missing peer" {
    const json =
        \\{"net": {"private_key": "/tmp/k", "tun_ipv4": "100.64.0.1"}, "route": {"rules": [{"domain": "*.google.com"}]}}
    ;
    const result = loadFromBytes(std.testing.allocator, json);
    try std.testing.expectError(error.ValidationFailed, result);
}
