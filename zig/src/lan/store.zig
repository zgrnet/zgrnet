//! LAN membership store.
//!
//! Thread-safe in-memory store with optional JSON persistence.

const std = @import("std");
const noise = @import("../noise/mod.zig");
const Key = noise.Key;

/// A LAN member.
pub const Member = struct {
    pubkey: Key,
    labels: std.ArrayList([]const u8),
    joined_at_secs: i64, // seconds since epoch

    const Self = @This();

    fn init(allocator: std.mem.Allocator, pk: Key) Self {
        return .{
            .pubkey = pk,
            .labels = std.ArrayList([]const u8).init(allocator),
            .joined_at_secs = std.time.timestamp(),
        };
    }

    fn deinit(self: *Self) void {
        // Free duplicated label strings.
        for (self.labels.items) |label| {
            self.labels.allocator.free(label);
        }
        self.labels.deinit();
    }

    fn clone(self: *const Self, allocator: std.mem.Allocator) !Self {
        var new_labels = std.ArrayList([]const u8).init(allocator);
        for (self.labels.items) |label| {
            try new_labels.append(try allocator.dupe(u8, label));
        }
        return .{
            .pubkey = self.pubkey,
            .labels = new_labels,
            .joined_at_secs = self.joined_at_secs,
        };
    }
};

/// Thread-safe membership store.
pub const Store = struct {
    allocator: std.mem.Allocator,
    mutex: std.Thread.Mutex,
    members: std.AutoHashMap([32]u8, Member),
    path: ?[]const u8,

    pub const StoreError = error{
        NotMember,
        OutOfMemory,
        SaveFailed,
    };

    pub fn init(allocator: std.mem.Allocator, data_dir: ?[]const u8) Store {
        var self = Store{
            .allocator = allocator,
            .mutex = .{},
            .members = std.AutoHashMap([32]u8, Member).init(allocator),
            .path = null,
        };

        if (data_dir) |dir| {
            // Build path: data_dir/members.json
            const path = std.fmt.allocPrint(allocator, "{s}/members.json", .{dir}) catch null;
            self.path = path;
            self.load() catch {};
        }

        return self;
    }

    pub fn deinit(self: *Store) void {
        var it = self.members.valueIterator();
        while (it.next()) |m| {
            @constCast(m).deinit();
        }
        self.members.deinit();
        if (self.path) |p| {
            self.allocator.free(p);
        }
    }

    /// Adds a member. Returns true if newly added.
    pub fn add(self: *Store, pk: Key) StoreError!bool {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.members.contains(pk.data)) return false;

        self.members.put(pk.data, Member.init(self.allocator, pk)) catch return StoreError.OutOfMemory;
        self.saveLocked() catch return StoreError.SaveFailed;
        return true;
    }

    /// Removes a member. Returns true if removed.
    pub fn remove(self: *Store, pk: Key) StoreError!bool {
        self.mutex.lock();
        defer self.mutex.unlock();

        const entry = self.members.fetchRemove(pk.data);
        if (entry == null) return false;

        var m = entry.?.value;
        m.deinit();

        self.saveLocked() catch return StoreError.SaveFailed;
        return true;
    }

    /// Gets a member (returns pointer, caller must not hold across mutations).
    pub fn get(self: *Store, pk: Key) ?*const Member {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.members.getPtr(pk.data);
    }

    /// Returns true if the pubkey is a member.
    pub fn isMember(self: *Store, pk: Key) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.members.contains(pk.data);
    }

    /// Returns the number of members.
    pub fn count(self: *Store) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.members.count();
    }

    /// Sets labels for a member (replaces existing).
    pub fn setLabels(self: *Store, pk: Key, labels: []const []const u8) StoreError!void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const m = self.members.getPtr(pk.data) orelse return StoreError.NotMember;

        // Free old labels.
        for (m.labels.items) |old| {
            self.allocator.free(old);
        }
        m.labels.clearRetainingCapacity();

        // Add new labels (duped).
        for (labels) |label| {
            const duped = self.allocator.dupe(u8, label) catch return StoreError.OutOfMemory;
            m.labels.append(duped) catch {
                self.allocator.free(duped);
                return StoreError.OutOfMemory;
            };
        }

        self.saveLocked() catch return StoreError.SaveFailed;
    }

    /// Removes specific labels from a member.
    pub fn removeLabels(self: *Store, pk: Key, to_remove: []const []const u8) StoreError!void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const m = self.members.getPtr(pk.data) orelse return StoreError.NotMember;

        // Filter out labels that are in the removal set.
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

        self.saveLocked() catch return StoreError.SaveFailed;
    }

    // ── Persistence ─────────────────────────────────────────────────────

    fn load(self: *Store) !void {
        const path = self.path orelse return;
        const data = std.fs.cwd().readFileAlloc(self.allocator, path, 1 << 20) catch return;
        defer self.allocator.free(data);

        const parsed = std.json.parseFromSlice(StoreFile, self.allocator, data, .{
            .allocate = .alloc_always,
        }) catch return;
        defer parsed.deinit();

        for (parsed.value.members) |mj| {
            const pk = Key.fromHex(mj.pubkey) catch continue;
            var m = Member.init(self.allocator, pk);
            for (mj.labels) |label| {
                m.labels.append(self.allocator.dupe(u8, label) catch continue) catch continue;
            }
            self.members.put(pk.data, m) catch continue;
        }
    }

    fn saveLocked(self: *Store) !void {
        _ = self.path orelse return;
        // Persistence not implemented in Zig yet — store is in-memory only.
        // TODO: implement JSON write when std.json.stringify is stable.
    }

    const StoreFile = struct {
        members: []const MemberJSON,
    };

    const MemberJSON = struct {
        pubkey: []const u8,
        labels: []const []const u8,
        joined_at: []const u8,
    };
};

// ============================================================================
// Tests
// ============================================================================

test "store add and get" {
    const allocator = std.testing.allocator;

    var st = Store.init(allocator, null);
    defer st.deinit();

    var seed: [32]u8 = undefined;
    std.crypto.random.bytes(&seed);
    const pk = Key.fromBytes(seed);

    const added = try st.add(pk);
    try std.testing.expect(added);

    const added2 = try st.add(pk);
    try std.testing.expect(!added2);

    const m = st.get(pk);
    try std.testing.expect(m != null);
    try std.testing.expect(m.?.pubkey.eql(pk));
    try std.testing.expectEqual(@as(usize, 0), m.?.labels.items.len);

    try std.testing.expectEqual(@as(usize, 1), st.count());
}

test "store remove" {
    const allocator = std.testing.allocator;

    var st = Store.init(allocator, null);
    defer st.deinit();

    var seed: [32]u8 = undefined;
    std.crypto.random.bytes(&seed);
    const pk = Key.fromBytes(seed);

    _ = try st.add(pk);

    const removed = try st.remove(pk);
    try std.testing.expect(removed);

    const removed2 = try st.remove(pk);
    try std.testing.expect(!removed2);

    try std.testing.expectEqual(@as(usize, 0), st.count());
}

test "store labels" {
    const allocator = std.testing.allocator;

    var st = Store.init(allocator, null);
    defer st.deinit();

    var seed: [32]u8 = undefined;
    std.crypto.random.bytes(&seed);
    const pk = Key.fromBytes(seed);

    _ = try st.add(pk);

    const labels = [_][]const u8{ "admin", "dev" };
    try st.setLabels(pk, &labels);

    const m = st.get(pk).?;
    try std.testing.expectEqual(@as(usize, 2), m.labels.items.len);
    try std.testing.expectEqualStrings("admin", m.labels.items[0]);
    try std.testing.expectEqualStrings("dev", m.labels.items[1]);

    const to_remove = [_][]const u8{"admin"};
    try st.removeLabels(pk, &to_remove);

    const m2 = st.get(pk).?;
    try std.testing.expectEqual(@as(usize, 1), m2.labels.items.len);
}

test "store is_member" {
    const allocator = std.testing.allocator;

    var st = Store.init(allocator, null);
    defer st.deinit();

    var seed: [32]u8 = undefined;
    std.crypto.random.bytes(&seed);
    const pk = Key.fromBytes(seed);

    try std.testing.expect(!st.isMember(pk));
    _ = try st.add(pk);
    try std.testing.expect(st.isMember(pk));
    _ = try st.remove(pk);
    try std.testing.expect(!st.isMember(pk));
}

test "store labels on non-member" {
    const allocator = std.testing.allocator;

    var st = Store.init(allocator, null);
    defer st.deinit();

    var seed: [32]u8 = undefined;
    std.crypto.random.bytes(&seed);
    const pk = Key.fromBytes(seed);

    const labels = [_][]const u8{"admin"};
    const result = st.setLabels(pk, &labels);
    try std.testing.expectError(Store.StoreError.NotMember, result);
}
