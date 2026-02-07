//! IP Allocator: bidirectional mapping between Noise public keys and IPv4 addresses.
//!
//! Allocates addresses from the CGNAT range (100.64.0.0/10) which won't conflict
//! with public IPs. Thread-safe with Mutex.

const std = @import("std");
const noise = @import("../noise/mod.zig");
const Key = noise.Key;

/// CGNAT IPv4 range: 100.64.0.0/10 (100.64.0.0 - 100.127.255.255)
const cgnat_base: u32 = 0x64400000; // 100.64.0.0
const cgnat_size: u32 = 0x003FFFFF; // 4,194,303 usable addresses

pub const AllocError = error{
    PoolExhausted,
    IpConflict,
};

/// Thread-safe bidirectional mapping between public keys and IPv4 addresses.
pub const IPAllocator = struct {
    mutex: std.Thread.Mutex,
    next_ipv4: u32, // offset from cgnat_base for next allocation
    by_pubkey: std.AutoHashMap([32]u8, [4]u8),
    by_ipv4: std.AutoHashMap([4]u8, [32]u8),

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .mutex = .{},
            .next_ipv4 = 2, // start from 100.64.0.2 (skip .0 network, .1 reserved)
            .by_pubkey = std.AutoHashMap([32]u8, [4]u8).init(allocator),
            .by_ipv4 = std.AutoHashMap([4]u8, [32]u8).init(allocator),
        };
    }

    pub fn deinit(self: *Self) void {
        self.by_pubkey.deinit();
        self.by_ipv4.deinit();
    }

    /// Allocates an IPv4 address for the given public key.
    /// If the key already has an allocation, returns the existing IP.
    pub fn assign(self: *Self, pk: Key) AllocError![4]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Return existing allocation
        if (self.by_pubkey.get(pk.data)) |ip| {
            return ip;
        }

        // Check pool exhaustion
        if (self.next_ipv4 > cgnat_size) {
            return AllocError.PoolExhausted;
        }

        // Allocate next address
        const ip = uint32ToIpv4(cgnat_base + self.next_ipv4);
        self.next_ipv4 += 1;

        self.by_pubkey.put(pk.data, ip) catch return AllocError.PoolExhausted;
        self.by_ipv4.put(ip, pk.data) catch return AllocError.PoolExhausted;

        return ip;
    }

    /// Assigns a specific IPv4 address to the given public key.
    /// Returns error if the IP is already assigned to a different key.
    pub fn assignStatic(self: *Self, pk: Key, ip: [4]u8) AllocError!void {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Check for conflict
        if (self.by_ipv4.get(ip)) |existing| {
            if (!std.mem.eql(u8, &existing, &pk.data)) {
                return AllocError.IpConflict;
            }
        }

        self.by_pubkey.put(pk.data, ip) catch return AllocError.PoolExhausted;
        self.by_ipv4.put(ip, pk.data) catch return AllocError.PoolExhausted;
    }

    /// Returns the public key associated with the given IP address.
    pub fn lookupByIp(self: *Self, ip: [4]u8) ?Key {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.by_ipv4.get(ip)) |pk_data| {
            return Key.fromBytes(pk_data);
        }
        return null;
    }

    /// Returns the IPv4 address associated with the given public key.
    pub fn lookupByPubkey(self: *Self, pk: Key) ?[4]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();

        return self.by_pubkey.get(pk.data);
    }

    /// Removes the allocation for the given public key.
    pub fn remove(self: *Self, pk: Key) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.by_pubkey.get(pk.data)) |ip| {
            _ = self.by_ipv4.remove(ip);
            _ = self.by_pubkey.remove(pk.data);
        }
    }

    /// Returns the number of allocated addresses.
    pub fn count(self: *Self) usize {
        self.mutex.lock();
        defer self.mutex.unlock();

        return self.by_pubkey.count();
    }
};

/// Converts a u32 to a [4]u8 IPv4 address (big-endian).
fn uint32ToIpv4(n: u32) [4]u8 {
    return .{
        @intCast((n >> 24) & 0xFF),
        @intCast((n >> 16) & 0xFF),
        @intCast((n >> 8) & 0xFF),
        @intCast(n & 0xFF),
    };
}

// ============================================================================
// Tests
// ============================================================================

test "IPAllocator: assign auto" {
    var alloc = IPAllocator.init(std.testing.allocator);
    defer alloc.deinit();

    var key1_bytes: [32]u8 = undefined;
    @memset(&key1_bytes, 0);
    key1_bytes[0] = 1;
    const key1 = Key.fromBytes(key1_bytes);

    var key2_bytes: [32]u8 = undefined;
    @memset(&key2_bytes, 0);
    key2_bytes[0] = 2;
    const key2 = Key.fromBytes(key2_bytes);

    const ip1 = try alloc.assign(key1);
    try std.testing.expectEqualSlices(u8, &.{ 100, 64, 0, 2 }, &ip1);

    const ip2 = try alloc.assign(key2);
    try std.testing.expectEqualSlices(u8, &.{ 100, 64, 0, 3 }, &ip2);

    // Re-assigning should return existing
    const ip1_again = try alloc.assign(key1);
    try std.testing.expectEqualSlices(u8, &ip1, &ip1_again);

    try std.testing.expectEqual(@as(usize, 2), alloc.count());
}

test "IPAllocator: assign static" {
    var alloc = IPAllocator.init(std.testing.allocator);
    defer alloc.deinit();

    var key1_bytes: [32]u8 = undefined;
    @memset(&key1_bytes, 0);
    key1_bytes[0] = 1;
    const key1 = Key.fromBytes(key1_bytes);

    var key2_bytes: [32]u8 = undefined;
    @memset(&key2_bytes, 0);
    key2_bytes[0] = 2;
    const key2 = Key.fromBytes(key2_bytes);

    const ip = [4]u8{ 100, 64, 1, 1 };
    try alloc.assignStatic(key1, ip);

    // Same key, same IP — should succeed
    try alloc.assignStatic(key1, ip);

    // Different key, same IP — should fail
    try std.testing.expectError(AllocError.IpConflict, alloc.assignStatic(key2, ip));
}

test "IPAllocator: lookup" {
    var alloc = IPAllocator.init(std.testing.allocator);
    defer alloc.deinit();

    var key_bytes: [32]u8 = undefined;
    @memset(&key_bytes, 0);
    key_bytes[0] = 42;
    const key = Key.fromBytes(key_bytes);

    const ip = try alloc.assign(key);

    // Lookup by IP
    const found_key = alloc.lookupByIp(ip);
    try std.testing.expect(found_key != null);
    try std.testing.expectEqualSlices(u8, &key.data, &found_key.?.data);

    // Lookup by pubkey
    const found_ip = alloc.lookupByPubkey(key);
    try std.testing.expect(found_ip != null);
    try std.testing.expectEqualSlices(u8, &ip, &found_ip.?);

    // Lookup unknown
    var unknown_bytes: [32]u8 = undefined;
    @memset(&unknown_bytes, 0xFF);
    try std.testing.expect(alloc.lookupByPubkey(Key.fromBytes(unknown_bytes)) == null);
}

test "IPAllocator: remove" {
    var alloc = IPAllocator.init(std.testing.allocator);
    defer alloc.deinit();

    var key_bytes: [32]u8 = undefined;
    @memset(&key_bytes, 0);
    key_bytes[0] = 1;
    const key = Key.fromBytes(key_bytes);

    const ip = try alloc.assign(key);
    try std.testing.expectEqual(@as(usize, 1), alloc.count());

    alloc.remove(key);
    try std.testing.expectEqual(@as(usize, 0), alloc.count());
    try std.testing.expect(alloc.lookupByIp(ip) == null);
    try std.testing.expect(alloc.lookupByPubkey(key) == null);
}
