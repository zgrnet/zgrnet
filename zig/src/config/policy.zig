//! Inbound policy engine: evaluates rules against peer public keys.

const std = @import("std");
const mem = std.mem;
const Allocator = std.mem.Allocator;
const types = @import("types.zig");
const InboundPolicy = types.InboundPolicy;
const InboundRule = types.InboundRule;
const ServiceConfig = types.ServiceConfig;

pub const PolicyResult = struct {
    action: []const u8,
    services: []const ServiceConfig,
    rule_name: []const u8,
    needs_zgrlan_verify: bool,
    zgrlan_peer: []const u8,
};

const CompiledEntry = struct {
    rule: *const InboundRule,
    whitelist: ?std.StringHashMapUnmanaged(void),
    list_path: []const u8,
};

/// Evaluates inbound policy rules against peer public keys.
pub const PolicyEngine = struct {
    default_action: []const u8,
    entries: std.ArrayListUnmanaged(CompiledEntry) = .{},
    allocator: Allocator,

    pub fn init(allocator: Allocator, policy: *const InboundPolicy) !PolicyEngine {
        var pe = PolicyEngine{
            .default_action = if (policy.default.len == 0) "deny" else policy.default,
            .allocator = allocator,
        };
        errdefer pe.deinit();

        for (policy.rules) |*rule| {
            var entry = CompiledEntry{
                .rule = rule,
                .whitelist = null,
                .list_path = "",
            };

            if (mem.eql(u8, rule.@"match".pubkey.@"type", "whitelist")) {
                entry.list_path = rule.@"match".pubkey.path;
                entry.whitelist = try loadPubkeyList(allocator, rule.@"match".pubkey.path);
            }

            try pe.entries.append(allocator, entry);
        }

        return pe;
    }

    pub fn deinit(self: *PolicyEngine) void {
        for (self.entries.items) |*e| {
            if (e.whitelist) |*w| {
                freeStringKeys(self.allocator, w);
                w.deinit(self.allocator);
            }
        }
        self.entries.deinit(self.allocator);
    }

    /// Check a peer's public key against the policy rules.
    pub fn check(self: *const PolicyEngine, pubkey: *const [32]u8) PolicyResult {
        var hex_buf: [64]u8 = undefined;
        const hex_chars = "0123456789abcdef";
        for (pubkey, 0..) |b, i| {
            hex_buf[i * 2] = hex_chars[b >> 4];
            hex_buf[i * 2 + 1] = hex_chars[b & 0x0f];
        }
        const pubkey_hex: []const u8 = &hex_buf;

        for (self.entries.items) |*entry| {
            const rule = entry.rule;
            const match_type = rule.@"match".pubkey.@"type";

            if (mem.eql(u8, match_type, "any")) {
                return .{
                    .action = rule.action,
                    .services = rule.services,
                    .rule_name = rule.name,
                    .needs_zgrlan_verify = false,
                    .zgrlan_peer = "",
                };
            } else if (mem.eql(u8, match_type, "whitelist")) {
                if (entry.whitelist) |wl| {
                    if (wl.get(pubkey_hex) != null) {
                        return .{
                            .action = rule.action,
                            .services = rule.services,
                            .rule_name = rule.name,
                            .needs_zgrlan_verify = false,
                            .zgrlan_peer = "",
                        };
                    }
                }
            } else if (mem.eql(u8, match_type, "zgrlan")) {
                return .{
                    .action = rule.action,
                    .services = rule.services,
                    .rule_name = rule.name,
                    .needs_zgrlan_verify = true,
                    .zgrlan_peer = rule.@"match".pubkey.peer,
                };
            }
        }

        return .{
            .action = self.default_action,
            .services = &.{},
            .rule_name = "default",
            .needs_zgrlan_verify = false,
            .zgrlan_peer = "",
        };
    }

    pub fn reload(self: *PolicyEngine) !void {
        for (self.entries.items) |*entry| {
            if (entry.list_path.len > 0) {
                if (entry.whitelist) |*w| {
                    freeStringKeys(self.allocator, w);
                    w.deinit(self.allocator);
                }
                entry.whitelist = try loadPubkeyList(self.allocator, entry.list_path);
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

fn loadPubkeyList(allocator: Allocator, path: []const u8) !std.StringHashMapUnmanaged(void) {
    var keys = std.StringHashMapUnmanaged(void){};
    errdefer keys.deinit(allocator);

    const file = std.fs.cwd().openFile(path, .{}) catch |err| return err;
    defer file.close();
    const data = file.readToEndAlloc(allocator, 1024 * 1024) catch return error.IoError;
    defer allocator.free(data);

    var it = mem.splitScalar(u8, data, '\n');
    while (it.next()) |line| {
        const trimmed = mem.trim(u8, line, " \t\r");
        if (trimmed.len == 0 or trimmed[0] == '#') continue;
        if (trimmed.len != 64) return error.InvalidInput;
        for (trimmed) |c| {
            if (!((c >= '0' and c <= '9') or (c >= 'a' and c <= 'f') or (c >= 'A' and c <= 'F'))) {
                return error.InvalidInput;
            }
        }
        const lower = try allocator.alloc(u8, 64);
        for (trimmed, 0..) |c, i| {
            lower[i] = if (c >= 'A' and c <= 'Z') c + 32 else c;
        }
        try keys.put(allocator, lower, {});
    }
    return keys;
}

test "any match" {
    const rules = [_]InboundRule{.{
        .name = "allow-all",
        .@"match" = .{ .pubkey = .{ .@"type" = "any" } },
        .services = &.{.{ .proto = "*", .port = "*" }},
        .action = "allow",
    }};
    const policy = InboundPolicy{ .default = "deny", .rules = &rules };
    var pe = try PolicyEngine.init(std.testing.allocator, &policy);
    defer pe.deinit();

    const key = [_]u8{0xab} ** 32;
    const result = pe.check(&key);
    try std.testing.expectEqualStrings("allow", result.action);
    try std.testing.expectEqualStrings("allow-all", result.rule_name);
}

test "zgrlan match" {
    const rules = [_]InboundRule{.{
        .name = "company",
        .@"match" = .{ .pubkey = .{ .@"type" = "zgrlan", .peer = "company.zigor.net" } },
        .services = &.{.{ .proto = "tcp", .port = "80,443" }},
        .action = "allow",
    }};
    const policy = InboundPolicy{ .default = "deny", .rules = &rules };
    var pe = try PolicyEngine.init(std.testing.allocator, &policy);
    defer pe.deinit();

    const key = [_]u8{0xab} ** 32;
    const result = pe.check(&key);
    try std.testing.expectEqualStrings("allow", result.action);
    try std.testing.expect(result.needs_zgrlan_verify);
    try std.testing.expectEqualStrings("company.zigor.net", result.zgrlan_peer);
}

test "default deny" {
    const policy = InboundPolicy{ .default = "deny" };
    var pe = try PolicyEngine.init(std.testing.allocator, &policy);
    defer pe.deinit();

    const key = [_]u8{0} ** 32;
    const result = pe.check(&key);
    try std.testing.expectEqualStrings("deny", result.action);
    try std.testing.expectEqualStrings("default", result.rule_name);
}

test "default allow" {
    const policy = InboundPolicy{ .default = "allow" };
    var pe = try PolicyEngine.init(std.testing.allocator, &policy);
    defer pe.deinit();

    const key = [_]u8{0} ** 32;
    const result = pe.check(&key);
    try std.testing.expectEqualStrings("allow", result.action);
}
