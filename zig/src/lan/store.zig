//! LAN membership storage — vtable interface + built-in implementations.
//!
//! [`Store`] is the abstract vtable. Two implementations:
//! - [`MemStore`]: in-memory, no persistence (good for testing)
//! - The concrete struct holds state; Store vtable delegates to it.

const std = @import("std");
const noise = @import("../noise/mod.zig");
const Key = noise.Key;

/// A LAN member.
pub const Member = struct {
    pubkey: Key,
    labels: std.ArrayList([]const u8),
    joined_at_secs: i64,

    const Self = @This();

    pub fn initMember(allocator: std.mem.Allocator, pk: Key) Self {
        return .{
            .pubkey = pk,
            .labels = std.ArrayList([]const u8).init(allocator),
            .joined_at_secs = std.time.timestamp(),
        };
    }

    pub fn deinit(self: *Self) void {
        for (self.labels.items) |label| {
            self.labels.allocator.free(label);
        }
        self.labels.deinit();
    }
};

/// Store errors.
pub const StoreError = error{
    NotMember,
    OutOfMemory,
    SaveFailed,
};

/// Abstract store vtable — runtime dispatch for pluggable backends.
pub const Store = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        add: *const fn (ptr: *anyopaque, pk: Key) StoreError!bool,
        remove: *const fn (ptr: *anyopaque, pk: Key) StoreError!bool,
        get: *const fn (ptr: *anyopaque, pk: Key) ?*const Member,
        isMember: *const fn (ptr: *anyopaque, pk: Key) bool,
        count: *const fn (ptr: *anyopaque) usize,
        setLabels: *const fn (ptr: *anyopaque, pk: Key, labels: []const []const u8) StoreError!void,
        removeLabels: *const fn (ptr: *anyopaque, pk: Key, to_remove: []const []const u8) StoreError!void,
    };

    pub fn add(self: Store, pk: Key) StoreError!bool {
        return self.vtable.add(self.ptr, pk);
    }

    pub fn remove(self: Store, pk: Key) StoreError!bool {
        return self.vtable.remove(self.ptr, pk);
    }

    pub fn get(self: Store, pk: Key) ?*const Member {
        return self.vtable.get(self.ptr, pk);
    }

    pub fn isMember(self: Store, pk: Key) bool {
        return self.vtable.isMember(self.ptr, pk);
    }

    pub fn count(self: Store) usize {
        return self.vtable.count(self.ptr);
    }

    pub fn setLabels(self: Store, pk: Key, labels: []const []const u8) StoreError!void {
        return self.vtable.setLabels(self.ptr, pk, labels);
    }

    pub fn removeLabels(self: Store, pk: Key, to_remove: []const []const u8) StoreError!void {
        return self.vtable.removeLabels(self.ptr, pk, to_remove);
    }
};

// ── MemStore ────────────────────────────────────────────────────────────────

/// In-memory store. Thread-safe, no persistence.
pub const MemStore = struct {
    allocator: std.mem.Allocator,
    mutex: std.Thread.Mutex,
    members: std.AutoHashMap([32]u8, Member),

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return .{
            .allocator = allocator,
            .mutex = .{},
            .members = std.AutoHashMap([32]u8, Member).init(allocator),
        };
    }

    pub fn deinit(self: *Self) void {
        var it = self.members.valueIterator();
        while (it.next()) |m| {
            @constCast(m).deinit();
        }
        self.members.deinit();
    }

    /// Returns a Store vtable pointing to this MemStore.
    pub fn store(self: *Self) Store {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    const vtable = Store.VTable{
        .add = addImpl,
        .remove = removeImpl,
        .get = getImpl,
        .isMember = isMemberImpl,
        .count = countImpl,
        .setLabels = setLabelsImpl,
        .removeLabels = removeLabelsImpl,
    };

    fn addImpl(ptr: *anyopaque, pk: Key) StoreError!bool {
        const self: *Self = @ptrCast(@alignCast(ptr));
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.members.contains(pk.data)) return false;
        self.members.put(pk.data, Member.initMember(self.allocator, pk)) catch return StoreError.OutOfMemory;
        return true;
    }

    fn removeImpl(ptr: *anyopaque, pk: Key) StoreError!bool {
        const self: *Self = @ptrCast(@alignCast(ptr));
        self.mutex.lock();
        defer self.mutex.unlock();

        const entry = self.members.fetchRemove(pk.data);
        if (entry == null) return false;
        var m = entry.?.value;
        m.deinit();
        return true;
    }

    fn getImpl(ptr: *anyopaque, pk: Key) ?*const Member {
        const self: *Self = @ptrCast(@alignCast(ptr));
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.members.getPtr(pk.data);
    }

    fn isMemberImpl(ptr: *anyopaque, pk: Key) bool {
        const self: *Self = @ptrCast(@alignCast(ptr));
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.members.contains(pk.data);
    }

    fn countImpl(ptr: *anyopaque) usize {
        const self: *Self = @ptrCast(@alignCast(ptr));
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.members.count();
    }

    fn setLabelsImpl(ptr: *anyopaque, pk: Key, labels: []const []const u8) StoreError!void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        self.mutex.lock();
        defer self.mutex.unlock();

        const m = self.members.getPtr(pk.data) orelse return StoreError.NotMember;

        for (m.labels.items) |old| {
            self.allocator.free(old);
        }
        m.labels.clearRetainingCapacity();

        for (labels) |label| {
            const duped = self.allocator.dupe(u8, label) catch return StoreError.OutOfMemory;
            m.labels.append(duped) catch {
                self.allocator.free(duped);
                return StoreError.OutOfMemory;
            };
        }
    }

    fn removeLabelsImpl(ptr: *anyopaque, pk: Key, to_remove: []const []const u8) StoreError!void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        self.mutex.lock();
        defer self.mutex.unlock();

        const m = self.members.getPtr(pk.data) orelse return StoreError.NotMember;

        var i: usize = 0;
        while (i < m.labels.items.len) {
            var found = false;
            for (to_remove) |rm| {
                if (std.mem.eql(u8, m.labels.items[i], rm)) {
                    found = true;
                    break;
                }
            }
            if (found) {
                self.allocator.free(m.labels.items[i]);
                _ = m.labels.swapRemove(i);
            } else {
                i += 1;
            }
        }
    }
};

// ============================================================================
// Tests
// ============================================================================

test "memstore add and get" {
    const allocator = std.testing.allocator;
    var ms = MemStore.init(allocator);
    defer ms.deinit();
    const s = ms.store();

    var seed: [32]u8 = undefined;
    std.crypto.random.bytes(&seed);
    const pk = Key.fromBytes(seed);

    try std.testing.expect(try s.add(pk));
    try std.testing.expect(!try s.add(pk));

    const m = s.get(pk);
    try std.testing.expect(m != null);
    try std.testing.expect(m.?.pubkey.eql(pk));
    try std.testing.expectEqual(@as(usize, 0), m.?.labels.items.len);
    try std.testing.expectEqual(@as(usize, 1), s.count());
}

test "memstore remove" {
    const allocator = std.testing.allocator;
    var ms = MemStore.init(allocator);
    defer ms.deinit();
    const s = ms.store();

    var seed: [32]u8 = undefined;
    std.crypto.random.bytes(&seed);
    const pk = Key.fromBytes(seed);

    _ = try s.add(pk);
    try std.testing.expect(try s.remove(pk));
    try std.testing.expect(!try s.remove(pk));
    try std.testing.expectEqual(@as(usize, 0), s.count());
}

test "memstore labels" {
    const allocator = std.testing.allocator;
    var ms = MemStore.init(allocator);
    defer ms.deinit();
    const s = ms.store();

    var seed: [32]u8 = undefined;
    std.crypto.random.bytes(&seed);
    const pk = Key.fromBytes(seed);

    _ = try s.add(pk);

    const labels = [_][]const u8{ "admin", "dev" };
    try s.setLabels(pk, &labels);

    const m = s.get(pk).?;
    try std.testing.expectEqual(@as(usize, 2), m.labels.items.len);

    const to_remove = [_][]const u8{"admin"};
    try s.removeLabels(pk, &to_remove);

    const m2 = s.get(pk).?;
    try std.testing.expectEqual(@as(usize, 1), m2.labels.items.len);
}

test "memstore is_member" {
    const allocator = std.testing.allocator;
    var ms = MemStore.init(allocator);
    defer ms.deinit();
    const s = ms.store();

    var seed: [32]u8 = undefined;
    std.crypto.random.bytes(&seed);
    const pk = Key.fromBytes(seed);

    try std.testing.expect(!s.isMember(pk));
    _ = try s.add(pk);
    try std.testing.expect(s.isMember(pk));
    _ = try s.remove(pk);
    try std.testing.expect(!s.isMember(pk));
}

test "memstore labels on non-member" {
    const allocator = std.testing.allocator;
    var ms = MemStore.init(allocator);
    defer ms.deinit();
    const s = ms.store();

    var seed: [32]u8 = undefined;
    std.crypto.random.bytes(&seed);
    const pk = Key.fromBytes(seed);

    const labels = [_][]const u8{"admin"};
    try std.testing.expectError(StoreError.NotMember, s.setLabels(pk, &labels));
}
