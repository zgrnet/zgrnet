//! Linux TUN implementation using /dev/net/tun.
//!
//! Linux provides the standard TUN/TAP interface through the /dev/net/tun device.
//! This implementation uses IFF_TUN | IFF_NO_PI for raw IP packet access.

const std = @import("std");
const posix = std.posix;
const mod = @import("mod.zig");
const Tun = mod.Tun;
const TunError = mod.TunError;

// Linux-specific constants
const TUNSETIFF = 0x400454ca;
const TUNSETPERSIST = 0x400454cb;

// TUN flags
const IFF_TUN: c_short = 0x0001;
const IFF_NO_PI: c_short = 0x1000;

// ioctl commands
const SIOCGIFMTU = 0x8921;
const SIOCSIFMTU = 0x8922;
const SIOCGIFFLAGS = 0x8913;
const SIOCSIFFLAGS = 0x8914;
const SIOCSIFADDR = 0x8916;
const SIOCSIFDSTADDR = 0x8918;
const SIOCSIFNETMASK = 0x891c;

// Interface flags
const IFF_UP: c_short = 0x1;
const IFF_RUNNING: c_short = 0x40;

// Interface request structure
const Ifreq = extern struct {
    ifr_name: [16]u8,
    ifr_ifru: extern union {
        ifru_flags: c_short,
        ifru_mtu: c_int,
        ifru_addr: posix.sockaddr,
        ifru_data: [14]u8,
    },
};

/// Create a new TUN device
pub fn create(name: ?[]const u8) TunError!Tun {
    // Open /dev/net/tun
    const fd = posix.open("/dev/net/tun", .{ .ACCMODE = .RDWR }, 0) catch |err| {
        return switch (err) {
            error.AccessDenied => TunError.PermissionDenied,
            error.FileNotFound, error.NoDevice => TunError.DeviceNotFound,
            else => TunError.OpenFailed,
        };
    };
    errdefer posix.close(fd);

    // Set up interface request
    var ifr = Ifreq{
        .ifr_name = undefined,
        .ifr_ifru = .{ .ifru_flags = IFF_TUN | IFF_NO_PI },
    };

    // Set name if provided
    if (name) |n| {
        if (n.len >= 16) {
            return TunError.InvalidName;
        }
        @memcpy(ifr.ifr_name[0..n.len], n);
        @memset(ifr.ifr_name[n.len..], 0);
    } else {
        @memset(&ifr.ifr_name, 0);
    }

    // Create TUN device
    if (posix.system.ioctl(fd, TUNSETIFF, @intFromPtr(&ifr)) != 0) {
        const err = std.posix.errno(posix.system.ioctl(fd, TUNSETIFF, @intFromPtr(&ifr)));
        return switch (err) {
            .PERM, .ACCES => TunError.PermissionDenied,
            .BUSY => TunError.DeviceBusy,
            .INVAL => TunError.InvalidName,
            else => TunError.CreateFailed,
        };
    }

    // Get assigned name length
    var name_len: u8 = 0;
    for (ifr.ifr_name, 0..) |c, i| {
        if (c == 0) {
            name_len = @intCast(i);
            break;
        }
    }

    return Tun{
        .handle = fd,
        .name_buf = ifr.ifr_name,
        .name_len = name_len,
        .closed = false,
    };
}

/// Read a packet from the TUN device
///
/// Linux with IFF_NO_PI returns raw IP packets without any header.
pub fn read(tun: *Tun, buf: []u8) TunError!usize {
    const n = posix.read(tun.handle, buf) catch |err| {
        return switch (err) {
            error.WouldBlock => TunError.WouldBlock,
            else => TunError.IoError,
        };
    };

    return n;
}

/// Write a packet to the TUN device
///
/// Linux with IFF_NO_PI accepts raw IP packets without any header.
pub fn write(tun: *Tun, data: []const u8) TunError!usize {
    if (data.len == 0) {
        return TunError.InvalidArgument;
    }

    const written = posix.write(tun.handle, data) catch |err| {
        return switch (err) {
            error.WouldBlock => TunError.WouldBlock,
            else => TunError.IoError,
        };
    };

    return written;
}

/// Close the TUN device
pub fn close(tun: *Tun) void {
    posix.close(tun.handle);
}

/// Get MTU
pub fn getMtu(tun: *Tun) TunError!u32 {
    const sock = posix.socket(posix.AF.INET, posix.SOCK.DGRAM, 0) catch {
        return TunError.IoError;
    };
    defer posix.close(sock);

    var ifr = Ifreq{
        .ifr_name = tun.name_buf,
        .ifr_ifru = .{ .ifru_mtu = 0 },
    };

    if (posix.system.ioctl(sock, SIOCGIFMTU, @intFromPtr(&ifr)) != 0) {
        return TunError.IoError;
    }

    return @intCast(ifr.ifr_ifru.ifru_mtu);
}

/// Set MTU
pub fn setMtu(tun: *Tun, mtu: u32) TunError!void {
    const sock = posix.socket(posix.AF.INET, posix.SOCK.DGRAM, 0) catch {
        return TunError.IoError;
    };
    defer posix.close(sock);

    var ifr = Ifreq{
        .ifr_name = tun.name_buf,
        .ifr_ifru = .{ .ifru_mtu = @intCast(mtu) },
    };

    if (posix.system.ioctl(sock, SIOCSIFMTU, @intFromPtr(&ifr)) != 0) {
        return TunError.SetMtuFailed;
    }
}

/// Set non-blocking mode
pub fn setNonBlocking(tun: *Tun, enabled: bool) TunError!void {
    const flags = posix.fcntl(tun.handle, posix.F.GETFL, 0) catch {
        return TunError.IoError;
    };

    const new_flags = if (enabled)
        flags | @as(u32, @bitCast(posix.O{ .NONBLOCK = true }))
    else
        flags & ~@as(u32, @bitCast(posix.O{ .NONBLOCK = true }));

    _ = posix.fcntl(tun.handle, posix.F.SETFL, new_flags) catch {
        return TunError.IoError;
    };
}

/// Bring interface up
pub fn setUp(tun: *Tun) TunError!void {
    const sock = posix.socket(posix.AF.INET, posix.SOCK.DGRAM, 0) catch {
        return TunError.IoError;
    };
    defer posix.close(sock);

    var ifr = Ifreq{
        .ifr_name = tun.name_buf,
        .ifr_ifru = .{ .ifru_flags = 0 },
    };

    // Get current flags
    if (posix.system.ioctl(sock, SIOCGIFFLAGS, @intFromPtr(&ifr)) != 0) {
        return TunError.IoError;
    }

    // Set UP flag
    ifr.ifr_ifru.ifru_flags |= IFF_UP | IFF_RUNNING;

    if (posix.system.ioctl(sock, SIOCSIFFLAGS, @intFromPtr(&ifr)) != 0) {
        return TunError.SetStateFailed;
    }
}

/// Bring interface down
pub fn setDown(tun: *Tun) TunError!void {
    const sock = posix.socket(posix.AF.INET, posix.SOCK.DGRAM, 0) catch {
        return TunError.IoError;
    };
    defer posix.close(sock);

    var ifr = Ifreq{
        .ifr_name = tun.name_buf,
        .ifr_ifru = .{ .ifru_flags = 0 },
    };

    // Get current flags
    if (posix.system.ioctl(sock, SIOCGIFFLAGS, @intFromPtr(&ifr)) != 0) {
        return TunError.IoError;
    }

    // Clear UP flag
    ifr.ifr_ifru.ifru_flags &= ~(IFF_UP | IFF_RUNNING);

    if (posix.system.ioctl(sock, SIOCSIFFLAGS, @intFromPtr(&ifr)) != 0) {
        return TunError.SetStateFailed;
    }
}

/// Set IPv4 address and netmask
pub fn setIPv4(tun: *Tun, addr: [4]u8, netmask: [4]u8) TunError!void {
    const sock = posix.socket(posix.AF.INET, posix.SOCK.DGRAM, 0) catch {
        return TunError.IoError;
    };
    defer posix.close(sock);

    // Set address
    var ifr_addr = Ifreq{
        .ifr_name = tun.name_buf,
        .ifr_ifru = .{
            .ifru_addr = posix.sockaddr{
                .family = posix.AF.INET,
                .data = undefined,
            },
        },
    };

    // Set up sockaddr_in for address
    var sin_addr: *posix.sockaddr.in = @ptrCast(@alignCast(&ifr_addr.ifr_ifru.ifru_addr));
    sin_addr.family = posix.AF.INET;
    sin_addr.port = 0;
    sin_addr.addr = @bitCast(addr);

    if (posix.system.ioctl(sock, SIOCSIFADDR, @intFromPtr(&ifr_addr)) != 0) {
        return TunError.SetAddressFailed;
    }

    // Set netmask
    var ifr_mask = ifr_addr;
    var sin_mask: *posix.sockaddr.in = @ptrCast(@alignCast(&ifr_mask.ifr_ifru.ifru_addr));
    sin_mask.addr = @bitCast(netmask);

    if (posix.system.ioctl(sock, SIOCSIFNETMASK, @intFromPtr(&ifr_mask)) != 0) {
        return TunError.SetAddressFailed;
    }
}

/// Set IPv6 address with prefix length
pub fn setIPv6(tun: *Tun, addr: [16]u8, prefix_len: u8) TunError!void {
    // Use ip command for IPv6 as ioctl is more complex
    const name = tun.name_buf[0..tun.name_len];

    // Format IPv6 as standard notation: xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx/prefix
    // Each group is a 16-bit value formatted as 4 hex digits
    var addr_str_buf: [64]u8 = undefined;
    const addr_str = std.fmt.bufPrint(&addr_str_buf, "{x:0>4}:{x:0>4}:{x:0>4}:{x:0>4}:{x:0>4}:{x:0>4}:{x:0>4}:{x:0>4}/{d}", .{
        @as(u16, addr[0]) << 8 | addr[1],
        @as(u16, addr[2]) << 8 | addr[3],
        @as(u16, addr[4]) << 8 | addr[5],
        @as(u16, addr[6]) << 8 | addr[7],
        @as(u16, addr[8]) << 8 | addr[9],
        @as(u16, addr[10]) << 8 | addr[11],
        @as(u16, addr[12]) << 8 | addr[13],
        @as(u16, addr[14]) << 8 | addr[15],
        prefix_len,
    }) catch {
        return TunError.InvalidArgument;
    };

    // Use absolute path to prevent PATH hijacking
    // Try /sbin/ip first (common on most distros), fallback to /usr/sbin/ip
    // Use explicit empty environment to avoid FFI issues with env inheritance
    var env_map = std.process.EnvMap.init(std.heap.page_allocator);
    defer env_map.deinit();

    const result = std.process.Child.run(.{
        .allocator = std.heap.page_allocator,
        .argv = &.{ "/sbin/ip", "-6", "addr", "add", addr_str, "dev", name },
        .env_map = &env_map,
    }) catch {
        // Fallback to /usr/sbin/ip
        const result2 = std.process.Child.run(.{
            .allocator = std.heap.page_allocator,
            .argv = &.{ "/usr/sbin/ip", "-6", "addr", "add", addr_str, "dev", name },
            .env_map = &env_map,
        }) catch {
            return TunError.SetAddressFailed;
        };
        defer {
            std.heap.page_allocator.free(result2.stdout);
            std.heap.page_allocator.free(result2.stderr);
        }
        if (result2.term.Exited != 0) {
            return TunError.SetAddressFailed;
        }
        return;
    };
    defer {
        std.heap.page_allocator.free(result.stdout);
        std.heap.page_allocator.free(result.stderr);
    }

    if (result.term.Exited != 0) {
        return TunError.SetAddressFailed;
    }
}
