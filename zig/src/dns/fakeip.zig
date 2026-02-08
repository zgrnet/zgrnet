//! Fake IP pool for route-matched domains.
//!
//! Range: 198.18.0.0/15 (RFC 5737 benchmarking).
//! Bidirectional domain <-> IP mapping with O(1) LRU eviction.
//!
//! Uses a generation-counter approach with a ring buffer queue:
//! - Touch: O(1) — increment gen, push_back to ring buffer
//! - Evict: O(1) amortized — pop_front from ring buffer, skip stale entries
//! - All operations are truly O(1), no memmove.

const std = @import("std");

/// Ring buffer for O(1) push_back and pop_front.
fn RingBuffer(comptime T: type) type {
    return struct {
        items: []T,
        head: usize, // index of first element
        len: usize, // number of elements
        allocator: std.mem.Allocator,

        const Self = @This();

        pub fn init(allocator: std.mem.Allocator) Self {
            return .{ .items = &.{}, .head = 0, .len = 0, .allocator = allocator };
        }

        pub fn deinit(self: *Self) void {
            if (self.items.len > 0) {
                self.allocator.free(self.items);
            }
        }

        pub fn pushBack(self: *Self, item: T) !void {
            if (self.len == self.items.len) {
                try self.grow();
            }
            const idx = (self.head + self.len) % self.items.len;
            self.items[idx] = item;
            self.len += 1;
        }

        pub fn popFront(self: *Self) ?T {
            if (self.len == 0) return null;
            const item = self.items[self.head];
            self.head = (self.head + 1) % self.items.len;
            self.len -= 1;
            return item;
        }

        pub fn count(self: *const Self) usize {
            return self.len;
        }

        fn grow(self: *Self) !void {
            const new_cap = if (self.items.len == 0) 16 else self.items.len * 2;
            const new_items = try self.allocator.alloc(T, new_cap);
            // Copy elements in order
            if (self.len > 0) {
                const tail_space = self.items.len - self.head;
                if (tail_space >= self.len) {
                    // Contiguous
                    @memcpy(new_items[0..self.len], self.items[self.head .. self.head + self.len]);
                } else {
                    // Wrapped: copy tail then head
                    @memcpy(new_items[0..tail_space], self.items[self.head..]);
                    @memcpy(new_items[tail_space .. tail_space + self.len - tail_space], self.items[0 .. self.len - tail_space]);
                }
            }
            if (self.items.len > 0) {
                self.allocator.free(self.items);
            }
            self.items = new_items;
            self.head = 0;
        }
    };
}

const LruEntry = struct {
    domain: []const u8,
    gen: u64,
};

pub const FakeIPPool = struct {
    allocator: std.mem.Allocator,
    domain_to_ip: std.StringHashMap(u32),
    ip_to_domain: std.AutoHashMap(u32, []const u8),
    /// Generation counter per domain.
    domain_gen: std.StringHashMap(u64),
    /// LRU ring buffer with (domain, gen) pairs. O(1) push_back + pop_front.
    lru_queue: RingBuffer(LruEntry),
    max_size: usize,
    base_ip: u32,
    next_off: u32,
    max_off: u32,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, max_size: usize) Self {
        const effective_size = if (max_size == 0) 65536 else max_size;
        return .{
            .allocator = allocator,
            .domain_to_ip = std.StringHashMap(u32).init(allocator),
            .ip_to_domain = std.AutoHashMap(u32, []const u8).init(allocator),
            .domain_gen = std.StringHashMap(u64).init(allocator),
            .lru_queue = RingBuffer(LruEntry).init(allocator),
            .max_size = effective_size,
            .base_ip = 0xC612_0000,
            .next_off = 1,
            .max_off = 131072 - 1,
        };
    }

    pub fn deinit(self: *Self) void {
        var it = self.domain_to_ip.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.domain_to_ip.deinit();
        self.ip_to_domain.deinit();
        self.domain_gen.deinit();
        self.lru_queue.deinit();
    }

    pub const AssignError = error{OutOfMemory};

    /// Assign a Fake IP for the given domain. O(1) amortized.
    pub fn assign(self: *Self, domain: []const u8) [4]u8 {
        return self.assignInner(domain) catch {
            return ipFromU32(self.base_ip + 1);
        };
    }

    fn assignInner(self: *Self, domain: []const u8) AssignError![4]u8 {
        if (self.domain_to_ip.get(domain)) |ip_val| {
            self.touchLRU(domain);
            return ipFromU32(ip_val);
        }

        if (self.domain_to_ip.count() >= self.max_size) {
            self.evictLRU();
        }

        const ip_val = self.base_ip + self.next_off;
        self.next_off += 1;
        if (self.next_off > self.max_off) {
            self.next_off = 1;
        }

        // Check for IP collision from wrap-around
        if (self.ip_to_domain.get(ip_val)) |old_domain| {
            const key = self.domain_to_ip.getKey(old_domain) orelse old_domain;
            _ = self.domain_to_ip.remove(old_domain);
            _ = self.domain_gen.remove(old_domain);
            _ = self.ip_to_domain.remove(ip_val);
            self.allocator.free(key);
        }

        const owned = try self.allocator.dupe(u8, domain);
        errdefer self.allocator.free(owned);

        self.domain_to_ip.put(owned, ip_val) catch return error.OutOfMemory;
        errdefer _ = self.domain_to_ip.remove(owned);

        self.ip_to_domain.put(ip_val, owned) catch return error.OutOfMemory;
        errdefer _ = self.ip_to_domain.remove(ip_val);

        self.domain_gen.put(owned, 0) catch return error.OutOfMemory;
        errdefer _ = self.domain_gen.remove(owned);

        self.lru_queue.pushBack(.{ .domain = owned, .gen = 0 }) catch return error.OutOfMemory;

        return ipFromU32(ip_val);
    }

    /// Lookup domain by Fake IP.
    pub fn lookup(self: *const Self, ip: [4]u8) ?[]const u8 {
        const ip_val = u32FromIp(ip);
        return self.ip_to_domain.get(ip_val);
    }

    /// Lookup Fake IP by domain.
    pub fn lookupDomain(self: *const Self, domain: []const u8) ?[4]u8 {
        if (self.domain_to_ip.get(domain)) |ip_val| {
            return ipFromU32(ip_val);
        }
        return null;
    }

    /// Number of entries.
    pub fn size(self: *const Self) usize {
        return self.domain_to_ip.count();
    }

    /// Touch: increment generation and push new entry. O(1).
    fn touchLRU(self: *Self, domain: []const u8) void {
        if (self.domain_gen.getPtr(domain)) |gen_ptr| {
            gen_ptr.* += 1;
            self.lru_queue.pushBack(.{ .domain = domain, .gen = gen_ptr.* }) catch {
                // Rollback gen increment on OOM. Without the queue entry,
                // all existing entries become stale and evictLRU would skip
                // this domain forever, causing pool to exceed max_size.
                gen_ptr.* -= 1;
            };
        }
    }

    /// Evict: pop front entries, skipping stale ones. O(1) amortized.
    fn evictLRU(self: *Self) void {
        while (self.lru_queue.count() > 0) {
            const entry = self.lru_queue.popFront() orelse return;
            if (self.domain_gen.get(entry.domain)) |current_gen| {
                if (current_gen == entry.gen) {
                    // Current entry — evict it
                    if (self.domain_to_ip.get(entry.domain)) |ip_val| {
                        _ = self.ip_to_domain.remove(ip_val);
                    }
                    const key = self.domain_to_ip.getKey(entry.domain) orelse continue;
                    _ = self.domain_to_ip.remove(entry.domain);
                    _ = self.domain_gen.remove(entry.domain);
                    self.allocator.free(key);
                    return;
                }
            }
            // Stale — skip
        }
    }
};

fn ipFromU32(val: u32) [4]u8 {
    return .{
        @intCast((val >> 24) & 0xFF),
        @intCast((val >> 16) & 0xFF),
        @intCast((val >> 8) & 0xFF),
        @intCast(val & 0xFF),
    };
}

fn u32FromIp(ip: [4]u8) u32 {
    return (@as(u32, ip[0]) << 24) | (@as(u32, ip[1]) << 16) | (@as(u32, ip[2]) << 8) | @as(u32, ip[3]);
}

// =============================================================================
// Tests
// =============================================================================

test "RingBuffer basic" {
    var rb = RingBuffer(u32).init(std.testing.allocator);
    defer rb.deinit();

    try rb.pushBack(1);
    try rb.pushBack(2);
    try rb.pushBack(3);
    try std.testing.expectEqual(@as(usize, 3), rb.count());

    try std.testing.expectEqual(@as(?u32, 1), rb.popFront());
    try std.testing.expectEqual(@as(?u32, 2), rb.popFront());
    try std.testing.expectEqual(@as(?u32, 3), rb.popFront());
    try std.testing.expectEqual(@as(?u32, null), rb.popFront());
}

test "RingBuffer wrap-around" {
    var rb = RingBuffer(u32).init(std.testing.allocator);
    defer rb.deinit();

    // Fill and drain to advance head
    for (0..10) |i| try rb.pushBack(@intCast(i));
    for (0..10) |_| _ = rb.popFront();

    // Now push more — should wrap around in the buffer
    for (100..110) |i| try rb.pushBack(@intCast(i));
    for (100..110) |i| {
        try std.testing.expectEqual(@as(?u32, @intCast(i)), rb.popFront());
    }
}

test "FakeIPPool assign" {
    var pool = FakeIPPool.init(std.testing.allocator, 100);
    defer pool.deinit();

    const ip1 = pool.assign("example.com");
    try std.testing.expectEqual(@as(u8, 198), ip1[0]);
    try std.testing.expectEqual(@as(u8, 18), ip1[1]);

    const ip2 = pool.assign("example.com");
    try std.testing.expectEqualSlices(u8, &ip1, &ip2);

    const ip3 = pool.assign("other.com");
    try std.testing.expect(!std.mem.eql(u8, &ip1, &ip3));
}

test "FakeIPPool lookup" {
    var pool = FakeIPPool.init(std.testing.allocator, 100);
    defer pool.deinit();

    const ip = pool.assign("test.example.com");
    const domain = pool.lookup(ip);
    try std.testing.expect(domain != null);
    try std.testing.expectEqualStrings("test.example.com", domain.?);

    try std.testing.expect(pool.lookup(.{ 1, 2, 3, 4 }) == null);
}

test "FakeIPPool LRU eviction" {
    var pool = FakeIPPool.init(std.testing.allocator, 3);
    defer pool.deinit();

    _ = pool.assign("a.com");
    _ = pool.assign("b.com");
    _ = pool.assign("c.com");
    try std.testing.expectEqual(@as(usize, 3), pool.size());

    _ = pool.assign("d.com");
    try std.testing.expectEqual(@as(usize, 3), pool.size());
    try std.testing.expect(pool.lookupDomain("a.com") == null);
    try std.testing.expect(pool.lookupDomain("b.com") != null);
    try std.testing.expect(pool.lookupDomain("d.com") != null);
}

test "FakeIPPool LRU touch" {
    var pool = FakeIPPool.init(std.testing.allocator, 3);
    defer pool.deinit();

    _ = pool.assign("a.com");
    _ = pool.assign("b.com");
    _ = pool.assign("c.com");

    _ = pool.assign("a.com"); // touch

    _ = pool.assign("d.com"); // evicts b.com
    try std.testing.expect(pool.lookupDomain("a.com") != null);
    try std.testing.expect(pool.lookupDomain("b.com") == null);
}

test "FakeIPPool wrap around" {
    var pool = FakeIPPool.init(std.testing.allocator, 200000);
    defer pool.deinit();

    pool.next_off = pool.max_off;
    _ = pool.assign("last.com");

    const ip = pool.assign("wrap.com");
    try std.testing.expectEqual(@as(u8, 198), ip[0]);
    try std.testing.expectEqual(@as(u8, 18), ip[1]);
    try std.testing.expectEqual(@as(u8, 0), ip[2]);
    try std.testing.expectEqual(@as(u8, 1), ip[3]);
}

test "FakeIPPool default size" {
    var pool = FakeIPPool.init(std.testing.allocator, 0);
    defer pool.deinit();
    try std.testing.expectEqual(@as(usize, 65536), pool.max_size);
}

test "FakeIPPool evict empty" {
    var pool = FakeIPPool.init(std.testing.allocator, 1);
    defer pool.deinit();
    pool.evictLRU();
    try std.testing.expectEqual(@as(usize, 0), pool.size());
}

test "FakeIPPool lookup unknown" {
    var pool = FakeIPPool.init(std.testing.allocator, 10);
    defer pool.deinit();
    try std.testing.expect(pool.lookup(.{ 1, 2, 3, 4 }) == null);
    try std.testing.expect(pool.lookupDomain("nothere.com") == null);
}

test "ipFromU32 and u32FromIp roundtrip" {
    const ip = [4]u8{ 198, 18, 0, 1 };
    const val = u32FromIp(ip);
    const back = ipFromU32(val);
    try std.testing.expectEqualSlices(u8, &ip, &back);
}

test "ipFromU32 edge cases" {
    const zero = ipFromU32(0);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0, 0, 0, 0 }, &zero);

    const max = ipFromU32(0xFFFFFFFF);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 255, 255, 255, 255 }, &max);
}
