//! BindTable for RELAY BIND/ALIAS short mode.
//!
//! Each relay node maintains a BindTable. When forwarding RELAY_0/1/2,
//! the relay allocates a relay_id and sends BIND back. Subsequent messages
//! use ALIAS mode with just the relay_id.

const std = @import("std");
const message = @import("message.zig");
const engine = @import("relay.zig");

pub const Strategy = message.Strategy;
pub const Relay0 = message.Relay0;
pub const Relay1 = message.Relay1;
pub const Relay2 = message.Relay2;
pub const Relay0Alias = message.Relay0Alias;
pub const Relay0Bind = message.Relay0Bind;

pub const BindEntry = struct {
    src_key: [32]u8,
    dst_key: [32]u8,
    next_hop: [32]u8,
};

pub const BindTable = struct {
    entries: std.AutoHashMap(u32, BindEntry),
    next_id: std.atomic.Value(u32),
    mutex: std.Thread.Mutex,

    pub fn init(allocator: std.mem.Allocator) BindTable {
        return .{
            .entries = std.AutoHashMap(u32, BindEntry).init(allocator),
            .next_id = std.atomic.Value(u32).init(1),
            .mutex = .{},
        };
    }

    pub fn deinit(self: *BindTable) void {
        self.entries.deinit();
    }

    pub fn allocate(self: *BindTable, src: [32]u8, dst: [32]u8, next_hop: [32]u8) u32 {
        const id = self.next_id.fetchAdd(1, .monotonic);
        self.mutex.lock();
        defer self.mutex.unlock();
        self.entries.put(id, BindEntry{
            .src_key = src,
            .dst_key = dst,
            .next_hop = next_hop,
        }) catch {};
        return id;
    }

    pub fn lookup(self: *BindTable, relay_id: u32) ?BindEntry {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.entries.get(relay_id);
    }

    pub fn remove(self: *BindTable, relay_id: u32) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        _ = self.entries.remove(relay_id);
    }

    pub fn len(self: *BindTable) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.entries.count();
    }
};

/// Process RELAY_0_ALIAS: lookup relay_id, reconstitute routing, forward.
pub fn handleRelay0Alias(bt: *BindTable, from: *const [32]u8, data: []const u8) !engine.Action {
    const alias = try message.decodeRelay0Alias(data);

    const entry = bt.lookup(alias.relay_id) orelse return error.NoRoute;

    if (!std.mem.eql(u8, &entry.src_key, from)) {
        return error.NoRoute;
    }

    if (std.mem.eql(u8, &entry.next_hop, &entry.dst_key)) {
        const r2 = Relay2{ .src_key = from.*, .payload = alias.payload };
        var action = engine.Action{
            .dst = entry.next_hop,
            .protocol = 68, // RELAY_2
            .len = 0,
            .buf = undefined,
        };
        action.len = try message.encodeRelay2(&r2, &action.buf);
        return action;
    } else {
        const r1 = Relay1{
            .ttl = message.default_ttl,
            .strategy = .auto,
            .src_key = from.*,
            .dst_key = entry.dst_key,
            .payload = alias.payload,
        };
        var action = engine.Action{
            .dst = entry.next_hop,
            .protocol = 67, // RELAY_1
            .len = 0,
            .buf = undefined,
        };
        action.len = try message.encodeRelay1(&r1, &action.buf);
        return action;
    }
}

// ============================================================================
// Tests
// ============================================================================

fn keyFromByte(b: u8) [32]u8 {
    var k = [_]u8{0} ** 32;
    k[0] = b;
    return k;
}

test "bind table allocate and lookup" {
    var bt = BindTable.init(std.testing.allocator);
    defer bt.deinit();

    const src = keyFromByte(0x0A);
    const dst = keyFromByte(0x0D);
    const nh = keyFromByte(0x0C);

    const id = bt.allocate(src, dst, nh);
    try std.testing.expect(id > 0);

    const entry = bt.lookup(id);
    try std.testing.expect(entry != null);
    try std.testing.expectEqualSlices(u8, &src, &entry.?.src_key);
    try std.testing.expectEqualSlices(u8, &dst, &entry.?.dst_key);
    try std.testing.expectEqualSlices(u8, &nh, &entry.?.next_hop);
}

test "bind table lookup missing" {
    var bt = BindTable.init(std.testing.allocator);
    defer bt.deinit();
    try std.testing.expect(bt.lookup(999) == null);
}

test "bind table unique ids" {
    var bt = BindTable.init(std.testing.allocator);
    defer bt.deinit();

    var ids = std.AutoHashMap(u32, void).init(std.testing.allocator);
    defer ids.deinit();

    for (0..100) |i| {
        const id = bt.allocate(keyFromByte(@intCast(i)), keyFromByte(0xFF), keyFromByte(0xFE));
        try ids.put(id, {});
    }
    try std.testing.expectEqual(@as(usize, 100), bt.len());
    try std.testing.expectEqual(@as(usize, 100), ids.count());
}

test "bind table remove" {
    var bt = BindTable.init(std.testing.allocator);
    defer bt.deinit();

    const id = bt.allocate(keyFromByte(1), keyFromByte(2), keyFromByte(3));
    try std.testing.expectEqual(@as(usize, 1), bt.len());

    bt.remove(id);
    try std.testing.expectEqual(@as(usize, 0), bt.len());
    try std.testing.expect(bt.lookup(id) == null);
}

test "handle relay0 alias" {
    var bt = BindTable.init(std.testing.allocator);
    defer bt.deinit();

    const key_a = keyFromByte(0x0A);
    const key_b = keyFromByte(0x0B);
    const key_c = keyFromByte(0x0C);
    const payload = "alias data";

    const relay_id = bt.allocate(key_a, key_b, key_c);

    var alias_buf: [256]u8 = undefined;
    const alias_msg = Relay0Alias{ .relay_id = relay_id, .payload = payload };
    const n = try message.encodeRelay0Alias(&alias_msg, &alias_buf);

    const action = try handleRelay0Alias(&bt, &key_a, alias_buf[0..n]);
    try std.testing.expectEqualSlices(u8, &key_c, &action.dst);
    try std.testing.expectEqual(@as(u8, 67), action.protocol);

    const r1 = try message.decodeRelay1(action.data());
    try std.testing.expectEqualSlices(u8, &key_a, &r1.src_key);
    try std.testing.expectEqualSlices(u8, &key_b, &r1.dst_key);
    try std.testing.expectEqualStrings(payload, r1.payload);
}

test "handle relay0 alias wrong sender" {
    var bt = BindTable.init(std.testing.allocator);
    defer bt.deinit();

    const relay_id = bt.allocate(keyFromByte(0x0A), keyFromByte(0x0B), keyFromByte(0x0C));
    var alias_buf: [256]u8 = undefined;
    const alias_msg = Relay0Alias{ .relay_id = relay_id, .payload = "" };
    const n = try message.encodeRelay0Alias(&alias_msg, &alias_buf);

    const wrong = keyFromByte(0xFF);
    try std.testing.expectError(error.NoRoute, handleRelay0Alias(&bt, &wrong, alias_buf[0..n]));
}

test "handle relay0 alias unknown id" {
    var bt = BindTable.init(std.testing.allocator);
    defer bt.deinit();

    var alias_buf: [256]u8 = undefined;
    const alias_msg = Relay0Alias{ .relay_id = 999, .payload = "" };
    const n = try message.encodeRelay0Alias(&alias_msg, &alias_buf);

    const key_a = keyFromByte(0x0A);
    try std.testing.expectError(error.NoRoute, handleRelay0Alias(&bt, &key_a, alias_buf[0..n]));
}
