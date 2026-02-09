//! Configuration manager with hot-reload and change notification.

const std = @import("std");
const Allocator = std.mem.Allocator;
const types = @import("types.zig");
const diff_mod = @import("diff.zig");
const route_mod = @import("route.zig");
const policy_mod = @import("policy.zig");

const Config = types.Config;
const ConfigDiff = diff_mod.ConfigDiff;
const RouteMatcher = route_mod.RouteMatcher;
const RouteResult = route_mod.RouteResult;
const PolicyEngine = policy_mod.PolicyEngine;
const PolicyResult = policy_mod.PolicyResult;

/// Receives notifications when configuration changes.
pub const Watcher = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        onPeersChanged: *const fn (*anyopaque) void,
        onLansChanged: *const fn (*anyopaque) void,
        onInboundPolicyChanged: *const fn (*anyopaque) void,
        onRouteChanged: *const fn (*anyopaque) void,
    };

    pub fn onPeersChanged(self: Watcher) void {
        self.vtable.onPeersChanged(self.ptr);
    }
    pub fn onLansChanged(self: Watcher) void {
        self.vtable.onLansChanged(self.ptr);
    }
    pub fn onInboundPolicyChanged(self: Watcher) void {
        self.vtable.onInboundPolicyChanged(self.ptr);
    }
    pub fn onRouteChanged(self: Watcher) void {
        self.vtable.onRouteChanged(self.ptr);
    }
};

/// Manages the lifecycle of a configuration file.
pub const Manager = struct {
    allocator: Allocator,
    path: []const u8,
    current: std.json.Parsed(Config),
    route: RouteMatcher,
    policy: PolicyEngine,
    watchers: std.ArrayListUnmanaged(Watcher) = .{},
    config_mtime: i128,

    pub fn init(allocator: Allocator, path: []const u8) !Manager {
        const parsed = try types.load(allocator, path);
        errdefer parsed.deinit();

        var route = try RouteMatcher.init(allocator, &parsed.value.route);
        errdefer route.deinit();

        var policy = try PolicyEngine.init(allocator, &parsed.value.inbound_policy);
        errdefer policy.deinit();

        return .{
            .allocator = allocator,
            .path = path,
            .current = parsed,
            .route = route,
            .policy = policy,
            .config_mtime = fileMtime(path),
        };
    }

    pub fn deinit(self: *Manager) void {
        self.policy.deinit();
        self.route.deinit();
        self.current.deinit();
        self.watchers.deinit(self.allocator);
    }

    /// Get the current configuration.
    pub fn getCurrent(self: *const Manager) *const Config {
        return &self.current.value;
    }

    /// Check if a domain matches any outbound route rule.
    pub fn matchRoute(self: *const Manager, domain: []const u8) ?RouteResult {
        return self.route.match_(domain);
    }

    /// Evaluate inbound policy for a peer's public key.
    pub fn checkInbound(self: *const Manager, pubkey: *const [32]u8) PolicyResult {
        return self.policy.check(pubkey);
    }

    /// Register a watcher to receive change notifications.
    pub fn watch(self: *Manager, w: Watcher) !void {
        try self.watchers.append(self.allocator, w);
    }

    /// Manually reload the configuration from disk.
    pub fn reload(self: *Manager) !?ConfigDiff {
        const new_parsed = try types.load(self.allocator, self.path);

        var d = try diff_mod.diff(self.allocator, &self.current.value, &new_parsed.value);

        if (d.isEmpty()) {
            d.deinit(self.allocator);
            new_parsed.deinit();
            return null;
        }

        // Rebuild route/policy if changed
        if (d.route_changed) {
            self.route.deinit();
            self.route = try RouteMatcher.init(self.allocator, &new_parsed.value.route);
        }
        if (d.inbound_changed) {
            self.policy.deinit();
            self.policy = try PolicyEngine.init(self.allocator, &new_parsed.value.inbound_policy);
        }

        // Replace current config
        self.current.deinit();
        self.current = new_parsed;
        self.config_mtime = fileMtime(self.path);

        // Notify watchers
        for (self.watchers.items) |w| {
            if (d.peers_added.count() > 0 or d.peers_removed.items.len > 0 or d.peers_changed.count() > 0) {
                w.onPeersChanged();
            }
            if (d.lans_added.items.len > 0 or d.lans_removed.items.len > 0) {
                w.onLansChanged();
            }
            if (d.inbound_changed) w.onInboundPolicyChanged();
            if (d.route_changed) w.onRouteChanged();
        }

        return d;
    }

    /// Check if the config file has been modified since last load.
    pub fn configFileChanged(self: *const Manager) bool {
        return fileMtime(self.path) != self.config_mtime;
    }
};

fn fileMtime(path: []const u8) i128 {
    const file = std.fs.cwd().openFile(path, .{}) catch return 0;
    defer file.close();
    const stat = file.stat() catch return 0;
    return stat.mtime;
}

test "manager: init and getCurrent" {
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();

    const json =
        \\{"net": {"private_key": "/tmp/k", "tun_ipv4": "100.64.0.1", "tun_mtu": 1400}}
    ;
    dir.dir.writeFile(.{ .sub_path = "config.json", .data = json }) catch unreachable;

    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const full_path = dir.dir.realpath("config.json", &path_buf) catch unreachable;

    var m = try Manager.init(std.testing.allocator, full_path);
    defer m.deinit();

    try std.testing.expectEqualStrings("100.64.0.1", m.getCurrent().net.tun_ipv4);
}

test "manager: route match" {
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();

    const json =
        \\{"net": {"private_key": "/tmp/k", "tun_ipv4": "100.64.0.1"},
        \\ "route": {"rules": [{"domain": "*.google.com", "peer": "peer_us"}]}}
    ;
    dir.dir.writeFile(.{ .sub_path = "config.json", .data = json }) catch unreachable;

    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const full_path = dir.dir.realpath("config.json", &path_buf) catch unreachable;

    var m = try Manager.init(std.testing.allocator, full_path);
    defer m.deinit();

    try std.testing.expect(m.matchRoute("www.google.com") != null);
    try std.testing.expect(m.matchRoute("example.com") == null);
}

test "manager: policy check" {
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();

    const json =
        \\{"net": {"private_key": "/tmp/k", "tun_ipv4": "100.64.0.1"},
        \\ "inbound_policy": {"default": "deny", "rules": [
        \\   {"name": "open", "match": {"pubkey": {"type": "any"}},
        \\    "services": [{"proto": "*", "port": "*"}], "action": "allow"}
        \\ ]}}
    ;
    dir.dir.writeFile(.{ .sub_path = "config.json", .data = json }) catch unreachable;

    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const full_path = dir.dir.realpath("config.json", &path_buf) catch unreachable;

    var m = try Manager.init(std.testing.allocator, full_path);
    defer m.deinit();

    const key = [_]u8{1} ** 32;
    const result = m.checkInbound(&key);
    try std.testing.expectEqualStrings("allow", result.action);
}

test "manager: reload with changes" {
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();

    dir.dir.writeFile(.{
        .sub_path = "config.json",
        .data = \\{"net": {"private_key": "/tmp/k", "tun_ipv4": "100.64.0.1"}}
        ,
    }) catch unreachable;

    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const full_path = dir.dir.realpath("config.json", &path_buf) catch unreachable;

    var m = try Manager.init(std.testing.allocator, full_path);
    defer m.deinit();

    // Update config with a route
    dir.dir.writeFile(.{
        .sub_path = "config.json",
        .data =
        \\{"net": {"private_key": "/tmp/k", "tun_ipv4": "100.64.0.1"},
        \\ "route": {"rules": [{"domain": "*.google.com", "peer": "peer_us"}]}}
        ,
    }) catch unreachable;

    var d = (try m.reload()) orelse return error.ValidationFailed;
    defer d.deinit(std.testing.allocator);
    try std.testing.expect(d.route_changed);

    try std.testing.expect(m.matchRoute("www.google.com") != null);
}
