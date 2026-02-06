//! C ABI exports for the TUN module.
//!
//! This file provides C-compatible function exports that can be called
//! from Rust, Go, or any other language that supports C FFI.

const std = @import("std");
const mod = @import("mod.zig");
const Tun = mod.Tun;
const TunError = mod.TunError;

// Error code mapping
const TUN_OK: c_int = 0;
const TUN_ERR_CREATE_FAILED: c_int = -1;
const TUN_ERR_OPEN_FAILED: c_int = -2;
const TUN_ERR_INVALID_NAME: c_int = -3;
const TUN_ERR_PERMISSION_DENIED: c_int = -4;
const TUN_ERR_DEVICE_NOT_FOUND: c_int = -5;
const TUN_ERR_NOT_SUPPORTED: c_int = -6;
const TUN_ERR_DEVICE_BUSY: c_int = -7;
const TUN_ERR_INVALID_ARGUMENT: c_int = -8;
const TUN_ERR_SYSTEM_RESOURCES: c_int = -9;
const TUN_ERR_WOULD_BLOCK: c_int = -10;
const TUN_ERR_IO_ERROR: c_int = -11;
const TUN_ERR_SET_MTU_FAILED: c_int = -12;
const TUN_ERR_SET_ADDRESS_FAILED: c_int = -13;
const TUN_ERR_SET_STATE_FAILED: c_int = -14;
const TUN_ERR_ALREADY_CLOSED: c_int = -15;
const TUN_ERR_WINTUN_NOT_FOUND: c_int = -16;
const TUN_ERR_WINTUN_INIT_FAILED: c_int = -17;

fn errorToCode(err: TunError) c_int {
    return switch (err) {
        TunError.CreateFailed => TUN_ERR_CREATE_FAILED,
        TunError.OpenFailed => TUN_ERR_OPEN_FAILED,
        TunError.InvalidName => TUN_ERR_INVALID_NAME,
        TunError.PermissionDenied => TUN_ERR_PERMISSION_DENIED,
        TunError.DeviceNotFound => TUN_ERR_DEVICE_NOT_FOUND,
        TunError.NotSupported => TUN_ERR_NOT_SUPPORTED,
        TunError.DeviceBusy => TUN_ERR_DEVICE_BUSY,
        TunError.InvalidArgument => TUN_ERR_INVALID_ARGUMENT,
        TunError.SystemResources => TUN_ERR_SYSTEM_RESOURCES,
        TunError.WouldBlock => TUN_ERR_WOULD_BLOCK,
        TunError.IoError => TUN_ERR_IO_ERROR,
        TunError.SetMtuFailed => TUN_ERR_SET_MTU_FAILED,
        TunError.SetAddressFailed => TUN_ERR_SET_ADDRESS_FAILED,
        TunError.SetStateFailed => TUN_ERR_SET_STATE_FAILED,
        TunError.AlreadyClosed => TUN_ERR_ALREADY_CLOSED,
        TunError.WintunNotFound => TUN_ERR_WINTUN_NOT_FOUND,
        TunError.WintunInitFailed => TUN_ERR_WINTUN_INIT_FAILED,
    };
}

// Allocator for TUN objects
var gpa = std.heap.GeneralPurposeAllocator(.{}){};
const allocator = gpa.allocator();

// ============================================================================
// Initialization
// ============================================================================

/// Initialize TUN subsystem
export fn tun_init() c_int {
    mod.init() catch |err| {
        return errorToCode(err);
    };
    return TUN_OK;
}

/// Cleanup TUN subsystem
export fn tun_deinit() void {
    mod.deinit();
}

// ============================================================================
// Lifecycle
// ============================================================================

/// Create a new TUN device
export fn tun_create(name: ?[*:0]const u8) ?*Tun {
    const name_slice: ?[]const u8 = if (name) |n| blk: {
        const len = std.mem.len(n);
        break :blk n[0..len];
    } else null;

    const tun = allocator.create(Tun) catch {
        return null;
    };

    tun.* = Tun.create(name_slice) catch {
        allocator.destroy(tun);
        return null;
    };

    return tun;
}

/// Close a TUN device
export fn tun_close(tun: ?*Tun) void {
    if (tun) |t| {
        t.close();
        allocator.destroy(t);
    }
}

// ============================================================================
// Read/Write
// ============================================================================

/// Read a packet from the TUN device
export fn tun_read(tun: ?*Tun, buf: ?[*]u8, len: usize) isize {
    const t = tun orelse return TUN_ERR_INVALID_ARGUMENT;
    const b = buf orelse return TUN_ERR_INVALID_ARGUMENT;

    const n = t.read(b[0..len]) catch |err| {
        return errorToCode(err);
    };

    return @intCast(n);
}

/// Write a packet to the TUN device
export fn tun_write(tun: ?*Tun, buf: ?[*]const u8, len: usize) isize {
    const t = tun orelse return TUN_ERR_INVALID_ARGUMENT;
    const b = buf orelse return TUN_ERR_INVALID_ARGUMENT;

    const n = t.write(b[0..len]) catch |err| {
        return errorToCode(err);
    };

    return @intCast(n);
}

// ============================================================================
// Properties
// ============================================================================

/// Get the device name
export fn tun_get_name(tun: ?*Tun) ?[*:0]const u8 {
    const t = tun orelse return null;
    _ = t.getName(); // Validate the tun is valid

    // Return pointer to internal name buffer (null-terminated)
    if (t.name_len < 16 and t.name_buf[t.name_len] == 0) {
        return @ptrCast(&t.name_buf);
    }
    return null;
}

/// Get the underlying handle
export fn tun_get_handle(tun: ?*Tun) c_int {
    const t = tun orelse return -1;
    return @intCast(t.getHandle());
}

// ============================================================================
// MTU
// ============================================================================

/// Get the MTU
export fn tun_get_mtu(tun: ?*Tun) c_int {
    const t = tun orelse return TUN_ERR_INVALID_ARGUMENT;

    const mtu = t.getMtu() catch |err| {
        return errorToCode(err);
    };

    return @intCast(mtu);
}

/// Set the MTU
export fn tun_set_mtu(tun: ?*Tun, mtu: c_int) c_int {
    const t = tun orelse return TUN_ERR_INVALID_ARGUMENT;

    if (mtu <= 0) return TUN_ERR_INVALID_ARGUMENT;

    t.setMtu(@intCast(mtu)) catch |err| {
        return errorToCode(err);
    };

    return TUN_OK;
}

// ============================================================================
// Non-blocking Mode
// ============================================================================

/// Set non-blocking mode
export fn tun_set_nonblocking(tun: ?*Tun, enabled: c_int) c_int {
    const t = tun orelse return TUN_ERR_INVALID_ARGUMENT;

    t.setNonBlocking(enabled != 0) catch |err| {
        return errorToCode(err);
    };

    return TUN_OK;
}

// ============================================================================
// Interface State
// ============================================================================

/// Bring the interface up
export fn tun_set_up(tun: ?*Tun) c_int {
    const t = tun orelse return TUN_ERR_INVALID_ARGUMENT;

    t.setUp() catch |err| {
        return errorToCode(err);
    };

    return TUN_OK;
}

/// Bring the interface down
export fn tun_set_down(tun: ?*Tun) c_int {
    const t = tun orelse return TUN_ERR_INVALID_ARGUMENT;

    t.setDown() catch |err| {
        return errorToCode(err);
    };

    return TUN_OK;
}

// ============================================================================
// IP Configuration
// ============================================================================

/// Parse IPv4 address string to bytes using std.net.Ip4Address
fn parseIPv4(addr_str: []const u8) ?[4]u8 {
    const a = std.net.Ip4Address.parse(addr_str, 0) catch return null;
    return @bitCast(a.sa.addr);
}

/// Set IPv4 address and netmask
export fn tun_set_ipv4(tun: ?*Tun, addr: ?[*:0]const u8, netmask: ?[*:0]const u8) c_int {
    const t = tun orelse return TUN_ERR_INVALID_ARGUMENT;
    const a = addr orelse return TUN_ERR_INVALID_ARGUMENT;
    const m = netmask orelse return TUN_ERR_INVALID_ARGUMENT;

    const addr_len = std.mem.len(a);
    const mask_len = std.mem.len(m);

    const addr_bytes = parseIPv4(a[0..addr_len]) orelse return TUN_ERR_INVALID_ARGUMENT;
    const mask_bytes = parseIPv4(m[0..mask_len]) orelse return TUN_ERR_INVALID_ARGUMENT;

    t.setIPv4(addr_bytes, mask_bytes) catch |err| {
        return errorToCode(err);
    };

    return TUN_OK;
}

/// Parse IPv6 address string to bytes using std.net.Ip6Address
fn parseIPv6(addr_str: []const u8) ?[16]u8 {
    const a = std.net.Ip6Address.parse(addr_str, 0) catch return null;
    return a.sa.addr;
}

/// Set IPv6 address with prefix length
export fn tun_set_ipv6(tun: ?*Tun, addr: ?[*:0]const u8, prefix_len: c_int) c_int {
    const t = tun orelse return TUN_ERR_INVALID_ARGUMENT;
    const a = addr orelse return TUN_ERR_INVALID_ARGUMENT;

    if (prefix_len < 0 or prefix_len > 128) return TUN_ERR_INVALID_ARGUMENT;

    const addr_len = std.mem.len(a);
    const addr_bytes = parseIPv6(a[0..addr_len]) orelse return TUN_ERR_INVALID_ARGUMENT;

    t.setIPv6(addr_bytes, @intCast(prefix_len)) catch |err| {
        return errorToCode(err);
    };

    return TUN_OK;
}

// ============================================================================
// Unit Tests
// ============================================================================

test "parseIPv4" {
    const testing = std.testing;

    // Standard addresses
    try testing.expectEqual([4]u8{ 192, 168, 1, 1 }, parseIPv4("192.168.1.1").?);
    try testing.expectEqual([4]u8{ 0, 0, 0, 0 }, parseIPv4("0.0.0.0").?);
    try testing.expectEqual([4]u8{ 255, 255, 255, 255 }, parseIPv4("255.255.255.255").?);
    try testing.expectEqual([4]u8{ 10, 0, 0, 1 }, parseIPv4("10.0.0.1").?);
    try testing.expectEqual([4]u8{ 127, 0, 0, 1 }, parseIPv4("127.0.0.1").?);

    // Edge cases - single digit octets
    try testing.expectEqual([4]u8{ 1, 2, 3, 4 }, parseIPv4("1.2.3.4").?);
    try testing.expectEqual([4]u8{ 0, 0, 0, 1 }, parseIPv4("0.0.0.1").?);

    // Leading zeros - rejected by std.net.Ip4Address per RFC (avoids octal ambiguity)
    try testing.expect(parseIPv4("01.02.03.04") == null);

    // Invalid addresses
    try testing.expect(parseIPv4("") == null);
    try testing.expect(parseIPv4("192.168.1") == null); // Too few octets
    try testing.expect(parseIPv4("192.168.1.1.1") == null); // Too many octets
    try testing.expect(parseIPv4("256.0.0.1") == null); // Out of range
    try testing.expect(parseIPv4("abc.def.ghi.jkl") == null); // Non-numeric
    try testing.expect(parseIPv4("192.168.1.") == null); // Trailing dot
    try testing.expect(parseIPv4(".192.168.1.1") == null); // Leading dot
    try testing.expect(parseIPv4("192..168.1") == null); // Double dot
    try testing.expect(parseIPv4(" 192.168.1.1") == null); // Leading space
    try testing.expect(parseIPv4("192.168.1.1 ") == null); // Trailing space
    try testing.expect(parseIPv4("-1.0.0.1") == null); // Negative
    try testing.expect(parseIPv4("192.168.1.1a") == null); // Trailing char
}

test "errorToCode" {
    const testing = std.testing;

    // Verify all error codes are correctly mapped
    try testing.expectEqual(TUN_ERR_CREATE_FAILED, errorToCode(TunError.CreateFailed));
    try testing.expectEqual(TUN_ERR_OPEN_FAILED, errorToCode(TunError.OpenFailed));
    try testing.expectEqual(TUN_ERR_INVALID_NAME, errorToCode(TunError.InvalidName));
    try testing.expectEqual(TUN_ERR_PERMISSION_DENIED, errorToCode(TunError.PermissionDenied));
    try testing.expectEqual(TUN_ERR_DEVICE_NOT_FOUND, errorToCode(TunError.DeviceNotFound));
    try testing.expectEqual(TUN_ERR_NOT_SUPPORTED, errorToCode(TunError.NotSupported));
    try testing.expectEqual(TUN_ERR_DEVICE_BUSY, errorToCode(TunError.DeviceBusy));
    try testing.expectEqual(TUN_ERR_INVALID_ARGUMENT, errorToCode(TunError.InvalidArgument));
    try testing.expectEqual(TUN_ERR_SYSTEM_RESOURCES, errorToCode(TunError.SystemResources));
    try testing.expectEqual(TUN_ERR_WOULD_BLOCK, errorToCode(TunError.WouldBlock));
    try testing.expectEqual(TUN_ERR_IO_ERROR, errorToCode(TunError.IoError));
    try testing.expectEqual(TUN_ERR_SET_MTU_FAILED, errorToCode(TunError.SetMtuFailed));
    try testing.expectEqual(TUN_ERR_SET_ADDRESS_FAILED, errorToCode(TunError.SetAddressFailed));
    try testing.expectEqual(TUN_ERR_SET_STATE_FAILED, errorToCode(TunError.SetStateFailed));
    try testing.expectEqual(TUN_ERR_ALREADY_CLOSED, errorToCode(TunError.AlreadyClosed));
    try testing.expectEqual(TUN_ERR_WINTUN_NOT_FOUND, errorToCode(TunError.WintunNotFound));
    try testing.expectEqual(TUN_ERR_WINTUN_INIT_FAILED, errorToCode(TunError.WintunInitFailed));

    // Verify all error codes are negative
    try testing.expect(TUN_ERR_CREATE_FAILED < 0);
    try testing.expect(TUN_ERR_WINTUN_INIT_FAILED < 0);
}

test "parseIPv6" {
    const testing = std.testing;

    // Full addresses (no ::)
    try testing.expectEqual(
        [16]u8{ 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 },
        parseIPv6("2001:db8:0:0:0:0:0:1").?,
    );
    try testing.expectEqual(
        [16]u8{ 0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x34, 0x00, 0x01 },
        parseIPv6("2001:db8:85a3:0:8a2e:370:7334:1").?,
    );

    // Addresses with :: (zero compression)
    try testing.expectEqual(
        [16]u8{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 },
        parseIPv6("::1").?,
    );
    try testing.expectEqual(
        [16]u8{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
        parseIPv6("::").?,
    );
    try testing.expectEqual(
        [16]u8{ 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 },
        parseIPv6("fd00::1").?,
    );
    try testing.expectEqual(
        [16]u8{ 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 },
        parseIPv6("2001:db8::1").?,
    );
    try testing.expectEqual(
        [16]u8{ 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 },
        parseIPv6("fe80::1").?,
    );

    // :: in the middle
    try testing.expectEqual(
        [16]u8{ 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02 },
        parseIPv6("2001:db8::1:2").?,
    );

    // :: at the end
    try testing.expectEqual(
        [16]u8{ 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
        parseIPv6("2001:db8::").?,
    );

    // Loopback and all-zeros
    try testing.expectEqual(
        [16]u8{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 },
        parseIPv6("0:0:0:0:0:0:0:1").?,
    );

    // Link-local addresses
    try testing.expectEqual(
        [16]u8{ 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
        parseIPv6("fe80::").?,
    );

    // Max value groups
    try testing.expectEqual(
        [16]u8{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
        parseIPv6("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff").?,
    );

    // Case insensitive
    try testing.expectEqual(
        [16]u8{ 0xAB, 0xCD, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x34 },
        parseIPv6("ABCD::1234").?,
    );
    try testing.expectEqual(
        [16]u8{ 0xab, 0xcd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x34 },
        parseIPv6("abcd::1234").?,
    );

    // Invalid addresses
    try testing.expect(parseIPv6("") == null);
    try testing.expect(parseIPv6("2001:db8:85a3:0:8a2e:370:7334:1:extra") == null); // Too many groups
    try testing.expect(parseIPv6("gggg::1") == null); // Invalid hex
    try testing.expect(parseIPv6("12345::1") == null); // Group too large (>4 hex digits)
    // std.net.Ip6Address properly rejects malformed addresses
    try testing.expect(parseIPv6(":::1") == null);
    try testing.expect(parseIPv6("2001:db8:::1") == null);
    try testing.expect(parseIPv6("2001:db8::1::2") == null);
}
