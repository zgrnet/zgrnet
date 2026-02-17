//! LAN service for zgrnet.
//!
//! Provides membership management, pluggable authentication, and event
//! notification for zgrnet LANs. This is a library — callers create a
//! Server, register Authenticator implementations, and mount handlers
//! on their HTTP infrastructure.
//!
//! ## embed-zig integration
//!
//! - **Authenticator**: Runtime vtable dispatch (auth methods are registered
//!   dynamically, so comptime traits don't apply).
//! - **Events**: Uses embed-zig `Channel(Event, N, Rt)` for Go-style event
//!   subscription. Subscribers receive events via blocking `recv()`.
//! - **Identity**: Injected via `IdentityFn` callback — no host dependency.

const std = @import("std");
const channel_mod = @import("channel");
const noise = @import("../noise/mod.zig");
const Key = noise.Key;

pub const store = @import("store.zig");
pub const auth = @import("auth.zig");

pub const Store = store.Store;
pub const StoreError = store.StoreError;
pub const MemStore = store.MemStore;
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
    kind: EventKind,
    /// Affected member pubkey.
    pubkey: Key,
    /// New labels (for .labels events).
    labels: ?[]const []const u8,

    pub const EventKind = enum {
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

/// Event channel capacity per subscriber.
const event_channel_capacity = 64;

/// LAN server, parameterized by Runtime (for Channel sync primitives).
///
/// Thread-safe: all methods can be called from any thread.
///
/// Usage:
/// ```zig
/// const Rt = @import("runtime.zig");
/// const LanServer = lan.Server(Rt);
/// var srv = LanServer.init(allocator, config, &store);
/// srv.registerAuth(&open_auth.iface);
///
/// // Subscribe to events (in another thread):
/// var ch = srv.subscribe();
/// defer srv.unsubscribe(ch);
/// while (ch.recv()) |event| { ... }
/// ```
pub fn Server(comptime Rt: type) type {
    const EventChannel = channel_mod.Channel(Event, event_channel_capacity, Rt);

    return struct {
        config: Config,
        st: Store,
        allocator: std.mem.Allocator,

        mutex: std.Thread.Mutex,
        auths: std.StringHashMap(*const Authenticator),

        sub_mutex: std.Thread.Mutex,
        next_sub_id: u64,
        subs: std.AutoHashMap(u64, *EventChannel),

        const Self = @This();

        pub fn init(allocator: std.mem.Allocator, config: Config, st: Store) Self {
            return .{
                .config = config,
                .st = st,
                .allocator = allocator,
                .mutex = .{},
                .auths = std.StringHashMap(*const Authenticator).init(allocator),
                .sub_mutex = .{},
                .next_sub_id = 0,
                .subs = std.AutoHashMap(u64, *EventChannel).init(allocator),
            };
        }

        pub fn deinit(self: *Self) void {
            // Close and free all subscriber channels.
            var it = self.subs.valueIterator();
            while (it.next()) |ch_ptr| {
                ch_ptr.*.close();
                self.allocator.destroy(ch_ptr.*);
            }
            self.subs.deinit();
            self.auths.deinit();
        }

        /// Registers an authenticator for the given method.
        pub fn registerAuth(self: *Self, a: *const Authenticator) void {
            self.mutex.lock();
            defer self.mutex.unlock();
            self.auths.put(a.method(), a) catch {};
        }

        /// Returns registered auth method names.
        pub fn authMethods(self: *Self, buf: [][]const u8) usize {
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
        pub fn identify(self: *Self, ip: [4]u8) IdentityError!Key {
            const id_fn = self.config.identity_fn orelse return IdentityError.NotConfigured;
            const result = try id_fn(ip);
            return result.pubkey;
        }

        /// Authenticates a join request.
        pub fn authenticate(self: *Self, pubkey: Key, method: []const u8, credential: []const u8) ServerAuthError!void {
            self.mutex.lock();
            const a = self.auths.get(method);
            self.mutex.unlock();

            if (a == null) return ServerAuthError.UnsupportedMethod;
            try a.?.authenticate(pubkey, credential);
        }

        pub const ServerAuthError = error{
            UnsupportedMethod,
        } || auth.AuthError;

        pub const JoinError = ServerAuthError || StoreError;

        /// Joins a peer after authentication. Returns true if newly added.
        pub fn join(self: *Self, pubkey: Key, method: []const u8, credential: []const u8) JoinError!bool {
            try self.authenticate(pubkey, method, credential);

            const added = try self.st.add(pubkey);
            if (added) {
                self.broadcast(.{
                    .kind = .join,
                    .pubkey = pubkey,
                    .labels = null,
                });
            }
            return added;
        }

        /// Removes a peer. Returns true if the peer was a member.
        pub fn leave(self: *Self, pubkey: Key) StoreError!bool {
            const removed = try self.st.remove(pubkey);
            if (removed) {
                self.broadcast(.{
                    .kind = .leave,
                    .pubkey = pubkey,
                    .labels = null,
                });
            }
            return removed;
        }

        /// Sets labels for a member.
        pub fn setLabels(self: *Self, pubkey: Key, labels_val: []const []const u8) StoreError!void {
            try self.st.setLabels(pubkey, labels_val);
            self.broadcast(.{
                .kind = .labels,
                .pubkey = pubkey,
                .labels = labels_val,
            });
        }

        /// Removes specific labels from a member.
        pub fn removeLabels(self: *Self, pubkey: Key, to_remove: []const []const u8) StoreError!void {
            try self.st.removeLabels(pubkey, to_remove);
            self.broadcast(.{
                .kind = .labels,
                .pubkey = pubkey,
                .labels = null, // caller can re-fetch if needed
            });
        }

        /// Subscribes to events. Returns a Channel that the caller can
        /// recv() from. Call unsubscribe() when done.
        pub fn subscribe(self: *Self) !*EventChannel {
            const ch = try self.allocator.create(EventChannel);
            ch.* = EventChannel.init();

            self.sub_mutex.lock();
            defer self.sub_mutex.unlock();
            self.next_sub_id += 1;
            try self.subs.put(self.next_sub_id, ch);
            return ch;
        }

        /// Unsubscribes and closes the event channel.
        /// Only frees the channel if it was actually registered.
        pub fn unsubscribe(self: *Self, ch: *EventChannel) void {
            self.sub_mutex.lock();
            defer self.sub_mutex.unlock();

            var found = false;
            var it = self.subs.iterator();
            while (it.next()) |entry| {
                if (entry.value_ptr.* == ch) {
                    _ = self.subs.remove(entry.key_ptr.*);
                    found = true;
                    break;
                }
            }

            if (found) {
                ch.close();
                self.allocator.destroy(ch);
            }
        }

        /// Broadcasts an event to all subscribers via trySend (non-blocking).
        fn broadcast(self: *Self, event: Event) void {
            self.sub_mutex.lock();
            defer self.sub_mutex.unlock();

            var it = self.subs.valueIterator();
            while (it.next()) |ch_ptr| {
                // Non-blocking: drop if subscriber is slow.
                ch_ptr.*.trySend(event) catch {};
            }
        }
    };
}

// ============================================================================
// Tests — use std runtime shim
// ============================================================================

const TestRt = @import("../runtime.zig");
const TestServer = Server(TestRt);

test "server join and leave" {
    const allocator = std.testing.allocator;

    var ms = MemStore.init(allocator);
    defer ms.deinit();

    var srv = TestServer.init(allocator, .{
        .domain = "test.zigor.net",
        .description = "Test",
        .data_dir = "",
        .identity_fn = null,
    }, ms.store());
    defer srv.deinit();

    var open = OpenAuth.init();
    srv.registerAuth(&open.iface);

    var seed: [32]u8 = undefined;
    std.crypto.random.bytes(&seed);
    const pk = Key.fromBytes(seed);

    const added = try srv.join(pk, "open", "");
    try std.testing.expect(added);

    const added2 = try srv.join(pk, "open", "");
    try std.testing.expect(!added2);

    try std.testing.expectEqual(@as(usize, 1), srv.st.count());

    const removed = try srv.leave(pk);
    try std.testing.expect(removed);
    try std.testing.expectEqual(@as(usize, 0), srv.st.count());
}

test "server auth methods" {
    const allocator = std.testing.allocator;

    var ms = MemStore.init(allocator);
    defer ms.deinit();

    var srv = TestServer.init(allocator, .{
        .domain = "test.zigor.net",
        .description = "Test",
        .data_dir = "",
        .identity_fn = null,
    }, ms.store());
    defer srv.deinit();

    var open = OpenAuth.init();
    srv.registerAuth(&open.iface);

    var buf: [8][]const u8 = undefined;
    const n = srv.authMethods(&buf);
    try std.testing.expectEqual(@as(usize, 1), n);
    try std.testing.expectEqualStrings("open", buf[0]);
}

test "server unsupported auth" {
    const allocator = std.testing.allocator;

    var ms = MemStore.init(allocator);
    defer ms.deinit();

    var srv = TestServer.init(allocator, .{
        .domain = "test.zigor.net",
        .description = "Test",
        .data_dir = "",
        .identity_fn = null,
    }, ms.store());
    defer srv.deinit();

    var seed: [32]u8 = undefined;
    std.crypto.random.bytes(&seed);
    const pk = Key.fromBytes(seed);

    const result = srv.join(pk, "oauth", "");
    try std.testing.expectError(TestServer.ServerAuthError.UnsupportedMethod, result);
}

test "server labels" {
    const allocator = std.testing.allocator;

    var ms = MemStore.init(allocator);
    defer ms.deinit();

    var srv = TestServer.init(allocator, .{
        .domain = "test.zigor.net",
        .description = "Test",
        .data_dir = "",
        .identity_fn = null,
    }, ms.store());
    defer srv.deinit();

    var open = OpenAuth.init();
    srv.registerAuth(&open.iface);

    var seed: [32]u8 = undefined;
    std.crypto.random.bytes(&seed);
    const pk = Key.fromBytes(seed);

    _ = try srv.join(pk, "open", "");

    const set_labels = [_][]const u8{ "admin", "dev" };
    try srv.setLabels(pk, &set_labels);

    const m = srv.st.get(pk) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(usize, 2), m.labels.items.len);

    const to_remove = [_][]const u8{"admin"};
    try srv.removeLabels(pk, &to_remove);

    const m2 = srv.st.get(pk) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(usize, 1), m2.labels.items.len);
}

test "server events via channel" {
    const allocator = std.testing.allocator;

    var ms = MemStore.init(allocator);
    defer ms.deinit();

    var srv = TestServer.init(allocator, .{
        .domain = "test.zigor.net",
        .description = "Test",
        .data_dir = "",
        .identity_fn = null,
    }, ms.store());
    defer srv.deinit();

    var open = OpenAuth.init();
    srv.registerAuth(&open.iface);

    // Subscribe — get a Channel.
    const ch = try srv.subscribe();

    var seed: [32]u8 = undefined;
    std.crypto.random.bytes(&seed);
    const pk = Key.fromBytes(seed);

    _ = try srv.join(pk, "open", "");

    // Non-blocking receive — event should be there.
    const event = ch.tryRecv() orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(Event.EventKind.join, event.kind);
    try std.testing.expect(event.pubkey.eql(pk));

    srv.unsubscribe(ch);
}
