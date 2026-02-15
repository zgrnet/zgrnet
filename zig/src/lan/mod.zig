//! LAN service for zgrnet.
//!
//! Provides membership management, pluggable authentication, and event
//! notification for zgrnet LANs. This is a library — callers create a
//! Server, register Authenticator implementations, and handle HTTP
//! requests through the provided dispatch function.
//!
//! Identity resolution (IP → pubkey) is injected via IdentityFn callback,
//! so this module has no dependency on the host or transport layer.

const std = @import("std");
const noise = @import("../noise/mod.zig");
const Key = noise.Key;

pub const store = @import("store.zig");
pub const auth = @import("auth.zig");

pub const Store = store.Store;
pub const Member = store.Member;
pub const Authenticator = auth.Authenticator;
pub const AuthError = auth.AuthError;
pub const OpenAuth = auth.OpenAuth;
pub const PasswordAuth = auth.PasswordAuth;
pub const InviteCodeAuth = auth.InviteCodeAuth;
pub const PubkeyWhitelistAuth = auth.PubkeyWhitelistAuth;

/// Identity resolution: IP bytes → (pubkey, labels).
pub const IdentityFn = *const fn (ip: [4]u8) IdentityError!IdentityResult;

pub const IdentityResult = struct {
    pubkey: Key,
    labels: []const []const u8,
};

pub const IdentityError = error{
    UnknownIP,
    NotConfigured,
};

/// Event pushed to subscribers on LAN changes.
pub const Event = struct {
    /// Event kind.
    type: EventType,
    /// Affected member pubkey.
    pubkey: Key,
    /// New labels (for .labels events).
    labels: ?[]const []const u8,

    pub const EventType = enum {
        join,
        leave,
        labels,
    };
};

/// Server configuration.
pub const Config = struct {
    domain: []const u8,
    description: []const u8,
    data_dir: []const u8,
    identity_fn: ?IdentityFn,
};

/// LAN server. Holds store, authenticators, and event subscribers.
///
/// Thread-safe: all methods can be called from any thread.
pub const Server = struct {
    config: Config,
    st: *Store,
    allocator: std.mem.Allocator,

    mutex: std.Thread.Mutex,
    auths: std.StringHashMap(*const Authenticator),

    sub_mutex: std.Thread.Mutex,
    next_sub_id: u64,
    subs: std.AutoHashMap(u64, *EventCallback),

    pub const EventCallback = struct {
        callback: *const fn (ctx: *anyopaque, event: Event) void,
        ctx: *anyopaque,
    };

    pub fn init(allocator: std.mem.Allocator, config: Config, st: *Store) Server {
        return .{
            .config = config,
            .st = st,
            .allocator = allocator,
            .mutex = .{},
            .auths = std.StringHashMap(*const Authenticator).init(allocator),
            .sub_mutex = .{},
            .next_sub_id = 0,
            .subs = std.AutoHashMap(u64, *EventCallback).init(allocator),
        };
    }

    pub fn deinit(self: *Server) void {
        self.auths.deinit();
        self.subs.deinit();
    }

    /// Registers an authenticator for the given method.
    pub fn registerAuth(self: *Server, a: *const Authenticator) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.auths.put(a.method(), a) catch {};
    }

    /// Returns registered auth method names.
    pub fn authMethods(self: *Server, buf: [][]const u8) usize {
        self.mutex.lock();
        defer self.mutex.unlock();

        var i: usize = 0;
        var it = self.auths.keyIterator();
        while (it.next()) |key| {
            if (i >= buf.len) break;
            buf[i] = key.*;
            i += 1;
        }
        return i;
    }

    /// Resolves IP to pubkey using configured identity function.
    pub fn identify(self: *Server, ip: [4]u8) IdentityError!Key {
        const id_fn = self.config.identity_fn orelse return IdentityError.NotConfigured;
        const result = try id_fn(ip);
        return result.pubkey;
    }

    /// Authenticates a join request.
    pub fn authenticate(self: *Server, pubkey: Key, method: []const u8, credential: []const u8) ServerAuthError!void {
        self.mutex.lock();
        const a = self.auths.get(method);
        self.mutex.unlock();

        if (a == null) return ServerAuthError.UnsupportedMethod;
        try a.?.authenticate(pubkey, credential);
    }

    pub const ServerAuthError = error{
        UnsupportedMethod,
    } || auth.AuthError;

    /// Joins a peer after authentication. Returns true if newly added.
    pub fn join(self: *Server, pubkey: Key, method: []const u8, credential: []const u8) (ServerAuthError || Store.StoreError)!bool {
        try self.authenticate(pubkey, method, credential);

        const added = try self.st.add(pubkey);
        if (added) {
            self.broadcast(.{
                .type = .join,
                .pubkey = pubkey,
                .labels = null,
            });
        }
        return added;
    }

    /// Removes a peer. Returns true if the peer was a member.
    pub fn leave(self: *Server, pubkey: Key) Store.StoreError!bool {
        const removed = try self.st.remove(pubkey);
        if (removed) {
            self.broadcast(.{
                .type = .leave,
                .pubkey = pubkey,
                .labels = null,
            });
        }
        return removed;
    }

    /// Sets labels for a member.
    pub fn setLabels(self: *Server, pubkey: Key, labels: []const []const u8) Store.StoreError!void {
        try self.st.setLabels(pubkey, labels);
        self.broadcast(.{
            .type = .labels,
            .pubkey = pubkey,
            .labels = labels,
        });
    }

    /// Removes specific labels from a member.
    pub fn removeLabels(self: *Server, pubkey: Key, to_remove: []const []const u8) Store.StoreError!void {
        try self.st.removeLabels(pubkey, to_remove);
        self.broadcast(.{
            .type = .labels,
            .pubkey = pubkey,
            .labels = null, // caller can re-fetch if needed
        });
    }

    /// Subscribes to events. Returns a subscription ID.
    pub fn subscribe(self: *Server, cb: *EventCallback) u64 {
        self.sub_mutex.lock();
        defer self.sub_mutex.unlock();
        self.next_sub_id += 1;
        const id = self.next_sub_id;
        self.subs.put(id, cb) catch {};
        return id;
    }

    /// Unsubscribes from events.
    pub fn unsubscribe(self: *Server, id: u64) void {
        self.sub_mutex.lock();
        defer self.sub_mutex.unlock();
        _ = self.subs.remove(id);
    }

    /// Broadcasts an event to all subscribers.
    fn broadcast(self: *Server, event: Event) void {
        self.sub_mutex.lock();
        defer self.sub_mutex.unlock();

        var it = self.subs.valueIterator();
        while (it.next()) |cb_ptr| {
            cb_ptr.*.callback(cb_ptr.*.ctx, event);
        }
    }
};

// ============================================================================
// Tests
// ============================================================================

test "server join and leave" {
    const allocator = std.testing.allocator;

    var st = Store.init(allocator, null);
    defer st.deinit();

    var srv = Server.init(allocator, .{
        .domain = "test.zigor.net",
        .description = "Test",
        .data_dir = "",
        .identity_fn = null,
    }, &st);
    defer srv.deinit();

    var open = OpenAuth.init();
    const open_iface = open.authenticator();
    srv.registerAuth(&open_iface);

    // Generate a test key.
    var seed: [32]u8 = undefined;
    std.crypto.random.bytes(&seed);
    const pk = Key.fromBytes(seed);

    // Join.
    const added = try srv.join(pk, "open", "");
    try std.testing.expect(added);

    // Join again — no-op.
    const added2 = try srv.join(pk, "open", "");
    try std.testing.expect(!added2);

    try std.testing.expectEqual(@as(usize, 1), srv.st.count());

    // Leave.
    const removed = try srv.leave(pk);
    try std.testing.expect(removed);
    try std.testing.expectEqual(@as(usize, 0), srv.st.count());
}

test "server auth methods" {
    const allocator = std.testing.allocator;

    var st = Store.init(allocator, null);
    defer st.deinit();

    var srv = Server.init(allocator, .{
        .domain = "test.zigor.net",
        .description = "Test",
        .data_dir = "",
        .identity_fn = null,
    }, &st);
    defer srv.deinit();

    var open = OpenAuth.init();
    const open_iface = open.authenticator();
    srv.registerAuth(&open_iface);

    var buf: [8][]const u8 = undefined;
    const n = srv.authMethods(&buf);
    try std.testing.expectEqual(@as(usize, 1), n);
    try std.testing.expectEqualStrings("open", buf[0]);
}

test "server unsupported auth" {
    const allocator = std.testing.allocator;

    var st = Store.init(allocator, null);
    defer st.deinit();

    var srv = Server.init(allocator, .{
        .domain = "test.zigor.net",
        .description = "Test",
        .data_dir = "",
        .identity_fn = null,
    }, &st);
    defer srv.deinit();

    var seed: [32]u8 = undefined;
    std.crypto.random.bytes(&seed);
    const pk = Key.fromBytes(seed);

    const result = srv.join(pk, "oauth", "");
    try std.testing.expectError(Server.ServerAuthError.UnsupportedMethod, result);
}

test "server labels" {
    const allocator = std.testing.allocator;

    var st = Store.init(allocator, null);
    defer st.deinit();

    var srv = Server.init(allocator, .{
        .domain = "test.zigor.net",
        .description = "Test",
        .data_dir = "",
        .identity_fn = null,
    }, &st);
    defer srv.deinit();

    var open = OpenAuth.init();
    const open_iface = open.authenticator();
    srv.registerAuth(&open_iface);

    var seed: [32]u8 = undefined;
    std.crypto.random.bytes(&seed);
    const pk = Key.fromBytes(seed);

    _ = try srv.join(pk, "open", "");

    const labels = [_][]const u8{ "admin", "dev" };
    try srv.setLabels(pk, &labels);

    const m = srv.st.get(pk) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(usize, 2), m.labels.items.len);

    const to_remove = [_][]const u8{"admin"};
    try srv.removeLabels(pk, &to_remove);

    const m2 = srv.st.get(pk) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(usize, 1), m2.labels.items.len);
}

test "server events" {
    const allocator = std.testing.allocator;

    var st = Store.init(allocator, null);
    defer st.deinit();

    var srv = Server.init(allocator, .{
        .domain = "test.zigor.net",
        .description = "Test",
        .data_dir = "",
        .identity_fn = null,
    }, &st);
    defer srv.deinit();

    var open = OpenAuth.init();
    const open_iface = open.authenticator();
    srv.registerAuth(&open_iface);

    // Subscribe.
    var received_event: ?Event = null;
    var cb = Server.EventCallback{
        .callback = struct {
            fn f(ctx: *anyopaque, event: Event) void {
                const ptr: *?Event = @ptrCast(@alignCast(ctx));
                ptr.* = event;
            }
        }.f,
        .ctx = @ptrCast(&received_event),
    };
    const sub_id = srv.subscribe(&cb);

    var seed: [32]u8 = undefined;
    std.crypto.random.bytes(&seed);
    const pk = Key.fromBytes(seed);

    _ = try srv.join(pk, "open", "");

    // Check event was received.
    try std.testing.expect(received_event != null);
    try std.testing.expectEqual(Event.EventType.join, received_event.?.type);
    try std.testing.expect(received_event.?.pubkey.eql(pk));

    srv.unsubscribe(sub_id);
}
