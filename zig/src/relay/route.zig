//! RouteTable for relay routing decisions.
//!
//! Provides next-hop routing for both relay engine forwarding (Router vtable)
//! and outbound relay wrapping (relayFor).

const std = @import("std");
const message = @import("message.zig");
const engine = @import("relay.zig");

pub const Strategy = message.Strategy;
pub const RelayError = message.RelayError;
pub const Router = engine.Router;

/// RouteTable provides next-hop routing decisions for relay forwarding and
/// outbound relay wrapping. Can be used as a Router via the router() method.
///
/// Thread-safe when accessed through the Mutex-protected methods.
/// The caller must use the provided lock/unlock or the convenience methods.
pub const RouteTable = struct {
    routes: std.AutoHashMap([32]u8, [32]u8),
    mutex: std.Thread.Mutex,

    pub fn init(allocator: std.mem.Allocator) RouteTable {
        return .{
            .routes = std.AutoHashMap([32]u8, [32]u8).init(allocator),
            .mutex = .{},
        };
    }

    pub fn deinit(self: *RouteTable) void {
        self.routes.deinit();
    }

    /// Set the next-hop for reaching dst.
    pub fn addRoute(self: *RouteTable, dst: [32]u8, next_hop: [32]u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.routes.put(dst, next_hop) catch {};
    }

    /// Remove the route for dst.
    pub fn removeRoute(self: *RouteTable, dst: [32]u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        _ = self.routes.remove(dst);
    }

    /// Returns the relay peer's key if dst should be sent through a relay,
    /// or null if dst is directly reachable.
    ///
    /// A destination is relayed when a route exists AND next_hop != dst.
    pub fn relayFor(self: *RouteTable, dst: *const [32]u8) ?[32]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.routes.get(dst.*)) |nh| {
            if (!std.mem.eql(u8, &nh, dst)) {
                return nh;
            }
        }
        return null;
    }

    /// Returns whether an explicit route exists for dst.
    pub fn hasRoute(self: *RouteTable, dst: *const [32]u8) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.routes.contains(dst.*);
    }

    /// Returns the number of routes.
    pub fn len(self: *RouteTable) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.routes.count();
    }

    /// NextHop for Router vtable compatibility.
    /// Returns next_hop if route exists, or dst itself if no route (direct).
    fn nextHopImpl(ptr: *anyopaque, dst: *const [32]u8, _: Strategy) RelayError![32]u8 {
        const self: *RouteTable = @ptrCast(@alignCast(ptr));
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.routes.get(dst.*)) |nh| {
            return nh;
        }
        return dst.*;
    }

    /// Returns a Router vtable backed by this RouteTable.
    pub fn router(self: *RouteTable) Router {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &.{
                .next_hop = @ptrCast(&nextHopImpl),
            },
        };
    }
};

// ============================================================================
// Tests
// ============================================================================

test "route table add and lookup" {
    var rt = RouteTable.init(std.testing.allocator);
    defer rt.deinit();

    const dst = keyFromByte(0x0D);
    const relay_key = keyFromByte(0x0C);

    rt.addRoute(dst, relay_key);

    // relayFor should return the relay
    const r = rt.relayFor(&dst);
    try std.testing.expect(r != null);
    try std.testing.expectEqualSlices(u8, &relay_key, &r.?);
}

test "route table direct route" {
    var rt = RouteTable.init(std.testing.allocator);
    defer rt.deinit();

    const dst = keyFromByte(0x0D);
    rt.addRoute(dst, dst); // next_hop == dst

    // relayFor should return null for direct route
    try std.testing.expect(rt.relayFor(&dst) == null);
}

test "route table no route" {
    var rt = RouteTable.init(std.testing.allocator);
    defer rt.deinit();

    const dst = keyFromByte(0x0D);

    try std.testing.expect(rt.relayFor(&dst) == null);
}

test "route table remove" {
    var rt = RouteTable.init(std.testing.allocator);
    defer rt.deinit();

    const dst = keyFromByte(0x0D);
    const relay_key = keyFromByte(0x0C);

    rt.addRoute(dst, relay_key);
    try std.testing.expectEqual(@as(usize, 1), rt.len());

    rt.removeRoute(dst);
    try std.testing.expectEqual(@as(usize, 0), rt.len());
    try std.testing.expect(rt.relayFor(&dst) == null);
}

test "route table overwrite" {
    var rt = RouteTable.init(std.testing.allocator);
    defer rt.deinit();

    const dst = keyFromByte(0x0D);
    const relay1 = keyFromByte(0x0C);
    const relay2 = keyFromByte(0x0B);

    rt.addRoute(dst, relay1);
    rt.addRoute(dst, relay2);

    const r = rt.relayFor(&dst);
    try std.testing.expect(r != null);
    try std.testing.expectEqualSlices(u8, &relay2, &r.?);
    try std.testing.expectEqual(@as(usize, 1), rt.len());
}

test "route table has route" {
    var rt = RouteTable.init(std.testing.allocator);
    defer rt.deinit();

    const dst = keyFromByte(0x0D);
    const relay_key = keyFromByte(0x0C);

    try std.testing.expect(!rt.hasRoute(&dst));
    rt.addRoute(dst, relay_key);
    try std.testing.expect(rt.hasRoute(&dst));
    rt.removeRoute(dst);
    try std.testing.expect(!rt.hasRoute(&dst));
}

test "route table router vtable" {
    var rt = RouteTable.init(std.testing.allocator);
    defer rt.deinit();

    const dst = keyFromByte(0x0D);
    const relay_key = keyFromByte(0x0C);
    rt.addRoute(dst, relay_key);

    var r = rt.router();
    const nh = try r.nextHop(&dst, .fastest);
    try std.testing.expectEqualSlices(u8, &relay_key, &nh);
}

test "route table router vtable no route returns dst" {
    var rt = RouteTable.init(std.testing.allocator);
    defer rt.deinit();

    const dst = keyFromByte(0x0D);
    var r = rt.router();
    const nh = try r.nextHop(&dst, .auto);
    try std.testing.expectEqualSlices(u8, &dst, &nh);
}

test "route table multiple destinations" {
    var rt = RouteTable.init(std.testing.allocator);
    defer rt.deinit();

    const relay1 = keyFromByte(0x01);
    const relay2 = keyFromByte(0x02);

    for (10..20) |i| {
        const b: u8 = @intCast(i);
        const dst = keyFromByte(b);
        if (b % 2 == 0) {
            rt.addRoute(dst, relay1);
        } else {
            rt.addRoute(dst, relay2);
        }
    }

    try std.testing.expectEqual(@as(usize, 10), rt.len());

    for (10..20) |i| {
        const b: u8 = @intCast(i);
        const dst = keyFromByte(b);
        const r = rt.relayFor(&dst);
        try std.testing.expect(r != null);
        if (b % 2 == 0) {
            try std.testing.expectEqualSlices(u8, &relay1, &r.?);
        } else {
            try std.testing.expectEqualSlices(u8, &relay2, &r.?);
        }
    }
}

fn keyFromByte(b: u8) [32]u8 {
    var k = [_]u8{0} ** 32;
    k[0] = b;
    return k;
}
