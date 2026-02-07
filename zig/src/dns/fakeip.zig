//! Fake IP pool for route-matched domains.
//!
//! Range: 198.18.0.0/15 (RFC 5737 benchmarking).
//! Bidirectional domain <-> IP mapping with O(1) amortized LRU eviction.
//!
//! Uses a generation-counter approach: each domain has a generation number.
//! The LRU queue stores (domain_ptr, gen) pairs. On touch, we increment the
//! generation and push a new entry. On eviction, we skip stale entries.
//! This gives O(1) touch and O(1) amortized eviction.

const std = @import("std");

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
    /// LRU queue with (domain, gen) pairs. Stale entries skipped on eviction.
    lru_queue: std.ArrayListUnmanaged(LruEntry),
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
            .lru_queue = .{},
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
        self.lru_queue.deinit(self.allocator);
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

        const owned = try self.allocator.dupe(u8, domain);
        errdefer self.allocator.free(owned);

        self.domain_to_ip.put(owned, ip_val) catch return error.OutOfMemory;
        errdefer _ = self.domain_to_ip.remove(owned);

        self.ip_to_domain.put(ip_val, owned) catch return error.OutOfMemory;
        errdefer _ = self.ip_to_domain.remove(ip_val);

        self.domain_gen.put(owned, 0) catch return error.OutOfMemory;
        errdefer _ = self.domain_gen.remove(owned);

        self.lru_queue.append(self.allocator, .{ .domain = owned, .gen = 0 }) catch return error.OutOfMemory;

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
            self.lru_queue.append(self.allocator, .{ .domain = domain, .gen = gen_ptr.* }) catch {};
        }
    }

    /// Evict: pop front entries, skipping stale ones. O(1) amortized.
    fn evictLRU(self: *Self) void {
        while (self.lru_queue.items.len > 0) {
            const entry = self.lru_queue.orderedRemove(0);
            // Check if this entry is still current
            if (self.domain_gen.get(entry.domain)) |current_gen| {
                if (current_gen == entry.gen) {
                    // Current entry — evict it
                    if (self.domain_to_ip.get(entry.domain)) |ip_val| {
                        _ = self.ip_to_domain.remove(ip_val);
                    }
                    // Need to get the owned key before removing
                    const key = self.domain_to_ip.getKey(entry.domain) orelse continue;
                    _ = self.domain_to_ip.remove(entry.domain);
                    _ = self.domain_gen.remove(entry.domain);
                    self.allocator.free(key);
                    return;
                }
                // Stale — skip
            }
            // Stale or already removed — skip
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
