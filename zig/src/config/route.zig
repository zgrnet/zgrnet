//! Route matching engine: matches domains to peers via longest suffix match.
//!
//! All rules are suffix-based: "google.com" matches google.com and all
//! subdomains. When multiple rules match, the longest suffix wins.

const std = @import("std");
const mem = std.mem;
const Allocator = std.mem.Allocator;
const types = @import("types.zig");
const RouteConfig = types.RouteConfig;

pub const RouteResult = struct {
    peer: []const u8,
    rule_name: []const u8,
};

const CompiledRule = struct {
    peer: []const u8,
    suffix: []const u8, // lowercase, allocator-owned
};

/// Provides domain-to-peer route matching using longest suffix match.
pub const RouteMatcher = struct {
    rules: std.ArrayListUnmanaged(CompiledRule) = .{},
    allocator: Allocator,

    pub fn init(allocator: Allocator, cfg: *const RouteConfig) !RouteMatcher {
        var rm = RouteMatcher{ .allocator = allocator };
        errdefer rm.deinit();

        for (cfg.rules) |rule| {
            if (rule.domain.len == 0) continue;

            var domain = rule.domain;
            // Strip "*." prefix — all matches are suffix-based
            if (domain.len >= 2 and domain[0] == '*' and domain[1] == '.') {
                domain = domain[2..];
            }
            if (domain.len == 0) continue; // skip bare "*." without a domain component

            const lower = try allocator.alloc(u8, domain.len);
            for (domain, 0..) |c, i| {
                lower[i] = if (c >= 'A' and c <= 'Z') c + 32 else c;
            }

            try rm.rules.append(allocator, .{
                .peer = rule.peer,
                .suffix = lower,
            });
        }

        return rm;
    }

    pub fn deinit(self: *RouteMatcher) void {
        for (self.rules.items) |*r| {
            self.allocator.free(r.suffix);
        }
        self.rules.deinit(self.allocator);
    }

    /// Check if a domain matches any route rule.
    /// Returns the result with the longest matching suffix.
    pub fn match_(self: *const RouteMatcher, domain_raw: []const u8) ?RouteResult {
        var buf: [256]u8 = undefined;
        const domain_trimmed = if (domain_raw.len > 0 and domain_raw[domain_raw.len - 1] == '.')
            domain_raw[0 .. domain_raw.len - 1]
        else
            domain_raw;
        if (domain_trimmed.len > buf.len) return null;

        const domain = buf[0..domain_trimmed.len];
        for (domain_trimmed, 0..) |c, i| {
            domain[i] = if (c >= 'A' and c <= 'Z') c + 32 else c;
        }

        var best: ?*const CompiledRule = null;
        for (self.rules.items) |*r| {
            if (matchSuffix(domain, r.suffix)) {
                if (best == null or r.suffix.len > best.?.suffix.len) {
                    best = r;
                }
            }
        }

        if (best) |b| {
            return .{ .peer = b.peer, .rule_name = b.suffix };
        }
        return null;
    }
};

/// Check if domain equals suffix or is a subdomain of suffix.
fn matchSuffix(domain: []const u8, suffix: []const u8) bool {
    if (mem.eql(u8, domain, suffix)) return true;
    // domain must be longer and end with ".suffix"
    if (domain.len > suffix.len + 1) {
        const prefix_end = domain.len - suffix.len - 1;
        if (domain[prefix_end] == '.' and mem.eql(u8, domain[prefix_end + 1 ..], suffix)) {
            return true;
        }
    }
    return false;
}

test "suffix match" {
    const rules = [_]types.RouteRule{.{ .domain = "google.com", .peer = "peer_us" }};
    const cfg = RouteConfig{ .rules = &rules };
    var rm = try RouteMatcher.init(std.testing.allocator, &cfg);
    defer rm.deinit();

    try std.testing.expect(rm.match_("google.com") != null);
    try std.testing.expect(rm.match_("www.google.com") != null);
    try std.testing.expect(rm.match_("mail.google.com") != null);
    try std.testing.expect(rm.match_("notgoogle.com") == null);
    try std.testing.expect(rm.match_("example.com") == null);
}

test "wildcard prefix stripped" {
    const rules = [_]types.RouteRule{.{ .domain = "*.google.com", .peer = "peer_us" }};
    const cfg = RouteConfig{ .rules = &rules };
    var rm = try RouteMatcher.init(std.testing.allocator, &cfg);
    defer rm.deinit();

    try std.testing.expect(rm.match_("google.com") != null);
    try std.testing.expect(rm.match_("www.google.com") != null);
    try std.testing.expect(rm.match_("notgoogle.com") == null);
}

test "longest suffix wins" {
    const rules = [_]types.RouteRule{
        .{ .domain = "google.com", .peer = "peer_us" },
        .{ .domain = "cn.google.com", .peer = "peer_cn" },
    };
    const cfg = RouteConfig{ .rules = &rules };
    var rm = try RouteMatcher.init(std.testing.allocator, &cfg);
    defer rm.deinit();

    const r1 = rm.match_("www.google.com") orelse unreachable;
    try std.testing.expectEqualStrings("peer_us", r1.peer);

    const r2 = rm.match_("cn.google.com") orelse unreachable;
    try std.testing.expectEqualStrings("peer_cn", r2.peer);

    const r3 = rm.match_("www.cn.google.com") orelse unreachable;
    try std.testing.expectEqualStrings("peer_cn", r3.peer);
}

test "case insensitive" {
    const rules = [_]types.RouteRule{.{ .domain = "Google.COM", .peer = "p" }};
    const cfg = RouteConfig{ .rules = &rules };
    var rm = try RouteMatcher.init(std.testing.allocator, &cfg);
    defer rm.deinit();
    try std.testing.expect(rm.match_("WWW.GOOGLE.COM") != null);
}

test "trailing dot" {
    const rules = [_]types.RouteRule{.{ .domain = "google.com", .peer = "p" }};
    const cfg = RouteConfig{ .rules = &rules };
    var rm = try RouteMatcher.init(std.testing.allocator, &cfg);
    defer rm.deinit();
    try std.testing.expect(rm.match_("www.google.com.") != null);
}

test "no match" {
    const rules = [_]types.RouteRule{.{ .domain = "google.com", .peer = "p" }};
    const cfg = RouteConfig{ .rules = &rules };
    var rm = try RouteMatcher.init(std.testing.allocator, &cfg);
    defer rm.deinit();
    try std.testing.expect(rm.match_("example.com") == null);
}

test "empty rules" {
    const cfg = RouteConfig{};
    var rm = try RouteMatcher.init(std.testing.allocator, &cfg);
    defer rm.deinit();
    try std.testing.expect(rm.match_("google.com") == null);
}
