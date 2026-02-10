//! Route matching engine: matches domains to peers via exact, wildcard, or list rules.

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
    pattern: []const u8, // lowercased, allocated
    is_suffix: bool,
    list_path: []const u8,
    domains: ?std.StringHashMapUnmanaged(void),
};

/// Provides domain-to-peer route matching.
pub const RouteMatcher = struct {
    rules: std.ArrayListUnmanaged(CompiledRule) = .{},
    allocator: Allocator,

    pub fn init(allocator: Allocator, cfg: *const RouteConfig) !RouteMatcher {
        var rm = RouteMatcher{ .allocator = allocator };
        errdefer rm.deinit();

        for (cfg.rules) |rule| {
            var cr = CompiledRule{
                .peer = rule.peer,
                .pattern = "",
                .is_suffix = false,
                .list_path = rule.domain_list,
                .domains = null,
            };

            if (rule.domain.len > 0) {
                const lower = try allocator.alloc(u8, rule.domain.len);
                for (rule.domain, 0..) |c, i| {
                    lower[i] = if (c >= 'A' and c <= 'Z') c + 32 else c;
                }
                if (mem.startsWith(u8, lower, "*.")) {
                    cr.is_suffix = true;
                    cr.pattern = lower[1..]; // ".google.com"
                } else {
                    cr.pattern = lower;
                }
            }

            if (rule.domain_list.len > 0) {
                cr.domains = try loadDomainList(allocator, rule.domain_list);
            }

            try rm.rules.append(allocator, cr);
        }

        return rm;
    }

    pub fn deinit(self: *RouteMatcher) void {
        for (self.rules.items) |*r| {
            if (r.pattern.len > 0) {
                if (r.is_suffix) {
                    const full = (r.pattern.ptr - 1)[0 .. r.pattern.len + 1];
                    self.allocator.free(full);
                } else {
                    self.allocator.free(r.pattern);
                }
            }
            if (r.domains) |*d| {
                freeStringKeys(self.allocator, d);
                d.deinit(self.allocator);
            }
        }
        self.rules.deinit(self.allocator);
    }

    /// Check if a domain matches any route rule.
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

        for (self.rules.items) |*r| {
            if (r.pattern.len > 0) {
                if (r.is_suffix) {
                    const base = r.pattern[1..];
                    if (mem.eql(u8, domain, base) or
                        (domain.len > r.pattern.len and mem.endsWith(u8, domain, r.pattern)))
                    {
                        return .{ .peer = r.peer, .rule_name = r.pattern };
                    }
                } else {
                    if (mem.eql(u8, domain, r.pattern)) {
                        return .{ .peer = r.peer, .rule_name = r.pattern };
                    }
                }
            }

            if (r.domains) |domains| {
                if (matchDomainList(domain, &domains)) {
                    return .{ .peer = r.peer, .rule_name = r.list_path };
                }
            }
        }
        return null;
    }

    pub fn reload(self: *RouteMatcher) !void {
        for (self.rules.items) |*r| {
            if (r.list_path.len > 0) {
                if (r.domains) |*d| {
                    freeStringKeys(self.allocator, d);
                    d.deinit(self.allocator);
                }
                r.domains = try loadDomainList(self.allocator, r.list_path);
            }
        }
    }
};

/// Free all allocated key strings in a StringHashMap before deiniting it.
fn freeStringKeys(allocator: Allocator, map: *std.StringHashMapUnmanaged(void)) void {
    var it = map.iterator();
    while (it.next()) |entry| {
        allocator.free(entry.key_ptr.*);
    }
}

fn matchDomainList(domain: []const u8, domains: *const std.StringHashMapUnmanaged(void)) bool {
    if (domains.get(domain) != null) return true;
    var d = domain;
    while (true) {
        const idx = mem.indexOfScalar(u8, d, '.') orelse break;
        d = d[idx + 1 ..];
        if (domains.get(d) != null) return true;
    }
    return false;
}

fn loadDomainList(allocator: Allocator, path: []const u8) !std.StringHashMapUnmanaged(void) {
    var domains = std.StringHashMapUnmanaged(void){};
    errdefer domains.deinit(allocator);

    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();
    const data = try file.readToEndAlloc(allocator, 1024 * 1024);
    defer allocator.free(data);

    var it = mem.splitScalar(u8, data, '\n');
    while (it.next()) |line| {
        const trimmed = mem.trim(u8, line, " \t\r");
        if (trimmed.len == 0 or trimmed[0] == '#') continue;
        const lower = try allocator.alloc(u8, trimmed.len);
        for (trimmed, 0..) |c, i| {
            lower[i] = if (c >= 'A' and c <= 'Z') c + 32 else c;
        }
        try domains.put(allocator, lower, {});
    }
    return domains;
}

test "exact match" {
    const rules = [_]types.RouteRule{.{ .domain = "google.com", .peer = "peer_us" }};
    const cfg = RouteConfig{ .rules = &rules };
    var rm = try RouteMatcher.init(std.testing.allocator, &cfg);
    defer rm.deinit();
    try std.testing.expect(rm.match_("google.com") != null);
    try std.testing.expect(rm.match_("www.google.com") == null);
}

test "wildcard match" {
    const rules = [_]types.RouteRule{.{ .domain = "*.google.com", .peer = "peer_us" }};
    const cfg = RouteConfig{ .rules = &rules };
    var rm = try RouteMatcher.init(std.testing.allocator, &cfg);
    defer rm.deinit();
    try std.testing.expect(rm.match_("www.google.com") != null);
    try std.testing.expect(rm.match_("mail.google.com") != null);
    try std.testing.expect(rm.match_("google.com") != null);
    try std.testing.expect(rm.match_("notgoogle.com") == null);
}

test "case insensitive" {
    const rules = [_]types.RouteRule{.{ .domain = "*.Google.COM", .peer = "p" }};
    const cfg = RouteConfig{ .rules = &rules };
    var rm = try RouteMatcher.init(std.testing.allocator, &cfg);
    defer rm.deinit();
    try std.testing.expect(rm.match_("WWW.GOOGLE.COM") != null);
}

test "trailing dot" {
    const rules = [_]types.RouteRule{.{ .domain = "*.google.com", .peer = "p" }};
    const cfg = RouteConfig{ .rules = &rules };
    var rm = try RouteMatcher.init(std.testing.allocator, &cfg);
    defer rm.deinit();
    try std.testing.expect(rm.match_("www.google.com.") != null);
}

test "priority" {
    const rules = [_]types.RouteRule{
        .{ .domain = "*.google.com", .peer = "peer_us" },
        .{ .domain = "*.google.com", .peer = "peer_jp" },
    };
    const cfg = RouteConfig{ .rules = &rules };
    var rm = try RouteMatcher.init(std.testing.allocator, &cfg);
    defer rm.deinit();
    const result = rm.match_("www.google.com") orelse unreachable;
    try std.testing.expectEqualStrings("peer_us", result.peer);
}

test "no match" {
    const rules = [_]types.RouteRule{.{ .domain = "*.google.com", .peer = "p" }};
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
