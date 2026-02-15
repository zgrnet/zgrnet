//! Config diff engine: computes incremental changes between two configurations.

const std = @import("std");
const mem = std.mem;
const Allocator = std.mem.Allocator;
const types = @import("types.zig");
const Config = types.Config;
const PeerConfig = types.PeerConfig;
const LanConfig = types.LanConfig;

/// Represents the differences between two configurations.
pub const ConfigDiff = struct {
    peers_added: std.StringArrayHashMapUnmanaged(PeerConfig) = .{},
    peers_removed: std.ArrayListUnmanaged([]const u8) = .{},
    peers_changed: std.StringArrayHashMapUnmanaged(PeerConfig) = .{},
    lans_added: std.ArrayListUnmanaged(LanConfig) = .{},
    lans_removed: std.ArrayListUnmanaged(LanConfig) = .{},
    inbound_changed: bool = false,
    route_changed: bool = false,

    pub fn deinit(self: *ConfigDiff, allocator: Allocator) void {
        self.peers_added.deinit(allocator);
        self.peers_removed.deinit(allocator);
        self.peers_changed.deinit(allocator);
        self.lans_added.deinit(allocator);
        self.lans_removed.deinit(allocator);
    }

    pub fn isEmpty(self: *const ConfigDiff) bool {
        return self.peers_added.count() == 0 and
            self.peers_removed.items.len == 0 and
            self.peers_changed.count() == 0 and
            self.lans_added.items.len == 0 and
            self.lans_removed.items.len == 0 and
            !self.inbound_changed and
            !self.route_changed;
    }
};

/// Compute the differences between two configurations.
pub fn diff(allocator: Allocator, old: *const Config, new: *const Config) !ConfigDiff {
    var d = ConfigDiff{};
    errdefer d.deinit(allocator);

    // Diff peers: find added and changed
    for (new.peers.map.keys(), new.peers.map.values()) |domain, *new_peer| {
        if (old.peers.map.get(domain)) |old_peer| {
            if (!peerEqual(&old_peer, new_peer)) {
                try d.peers_changed.put(allocator, domain, new_peer.*);
            }
        } else {
            try d.peers_added.put(allocator, domain, new_peer.*);
        }
    }
    // Find removed
    for (old.peers.map.keys()) |domain| {
        if (new.peers.map.get(domain) == null) {
            try d.peers_removed.append(allocator, domain);
        }
    }

    // Diff lans
    for (new.lans) |new_lan| {
        var found = false;
        for (old.lans) |old_lan| {
            if (mem.eql(u8, old_lan.domain, new_lan.domain)) {
                found = true;
                break;
            }
        }
        if (!found) try d.lans_added.append(allocator, new_lan);
    }
    for (old.lans) |old_lan| {
        var found = false;
        for (new.lans) |new_lan| {
            if (mem.eql(u8, old_lan.domain, new_lan.domain)) {
                found = true;
                break;
            }
        }
        if (!found) try d.lans_removed.append(allocator, old_lan);
    }

    d.inbound_changed = !inboundEqual(&old.inbound_policy, &new.inbound_policy);
    d.route_changed = !routeEqual(&old.route, &new.route);

    return d;
}

fn peerEqual(a: *const PeerConfig, b: *const PeerConfig) bool {
    if (!mem.eql(u8, a.alias, b.alias)) return false;
    if (a.direct.len != b.direct.len) return false;
    for (a.direct, b.direct) |ad, bd| {
        if (!mem.eql(u8, ad, bd)) return false;
    }
    if (a.relay.len != b.relay.len) return false;
    for (a.relay, b.relay) |ar, br| {
        if (!mem.eql(u8, ar, br)) return false;
    }
    if (a.labels.len != b.labels.len) return false;
    for (a.labels, b.labels) |al, bl| {
        if (!mem.eql(u8, al, bl)) return false;
    }
    return true;
}

fn inboundEqual(a: *const types.InboundPolicy, b: *const types.InboundPolicy) bool {
    if (!mem.eql(u8, a.default, b.default)) return false;
    if (!mem.eql(u8, a.revalidate_interval, b.revalidate_interval)) return false;
    if (a.rules.len != b.rules.len) return false;
    for (a.rules, b.rules) |ar, br| {
        if (!mem.eql(u8, ar.name, br.name)) return false;
        if (!mem.eql(u8, ar.action, br.action)) return false;
        if (!mem.eql(u8, ar.@"match".pubkey.@"type", br.@"match".pubkey.@"type")) return false;
        if (!mem.eql(u8, ar.@"match".pubkey.path, br.@"match".pubkey.path)) return false;
        if (!mem.eql(u8, ar.@"match".pubkey.peer, br.@"match".pubkey.peer)) return false;
        if (ar.@"match".labels.len != br.@"match".labels.len) return false;
        for (ar.@"match".labels, br.@"match".labels) |al, bl| {
            if (!mem.eql(u8, al, bl)) return false;
        }
    }
    return true;
}

fn routeEqual(a: *const types.RouteConfig, b: *const types.RouteConfig) bool {
    if (a.rules.len != b.rules.len) return false;
    for (a.rules, b.rules) |ar, br| {
        if (!mem.eql(u8, ar.domain, br.domain)) return false;
        if (!mem.eql(u8, ar.peer, br.peer)) return false;
    }
    return true;
}

test "diff: empty configs are equal" {
    var d = try diff(std.testing.allocator, &Config{}, &Config{});
    defer d.deinit(std.testing.allocator);
    try std.testing.expect(d.isEmpty());
}

test "diff: inbound changed" {
    const old = Config{ .inbound_policy = .{ .default = "deny" } };
    const new = Config{ .inbound_policy = .{ .default = "allow" } };
    var d = try diff(std.testing.allocator, &old, &new);
    defer d.deinit(std.testing.allocator);
    try std.testing.expect(d.inbound_changed);
}

test "diff: route changed" {
    const old = Config{};
    const rules = [_]types.RouteRule{.{ .domain = "google.com", .peer = "p" }};
    const new = Config{ .route = .{ .rules = &rules } };
    var d = try diff(std.testing.allocator, &old, &new);
    defer d.deinit(std.testing.allocator);
    try std.testing.expect(d.route_changed);
}
