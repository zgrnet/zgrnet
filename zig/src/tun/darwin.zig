//! macOS TUN implementation using utun via AF_SYSTEM socket.
//!
//! macOS provides the utun interface for user-space tunneling.
//! Unlike Linux's /dev/net/tun, macOS uses a socket-based approach.

const std = @import("std");
const posix = std.posix;
const mod = @import("mod.zig");
const Tun = mod.Tun;
const TunError = mod.TunError;

// macOS-specific constants
const AF_SYSTEM = 32;
const SYSPROTO_CONTROL = 2;
const AF_SYS_CONTROL = 2;
const UTUN_CONTROL_NAME = "com.apple.net.utun_control";

// ioctl commands (use c_ulong for macOS to handle large values)
const CTLIOCGINFO: c_ulong = 0xc0644e03; // _IOWR('N', 3, struct ctl_info)
const SIOCGIFMTU: c_ulong = 0xc0206933;
const SIOCSIFMTU: c_ulong = 0x80206934;
const SIOCGIFFLAGS: c_ulong = 0xc0206911;
const SIOCSIFFLAGS: c_ulong = 0x80206910;
const SIOCAIFADDR: c_ulong = 0x8040691a; // _IOW('i', 26, struct ifaliasreq)
const SIOCAIFADDR_IN6: c_ulong = 0x8080691a;

// macOS ioctl with correct signature (unsigned long request)
extern "c" fn ioctl(fd: c_int, request: c_ulong, ...) c_int;

// Interface flags
const IFF_UP: c_short = 0x1;
const IFF_RUNNING: c_short = 0x40;

// Control info structure for ioctl
const CtlInfo = extern struct {
    ctl_id: u32,
    ctl_name: [96]u8,
};

// Socket address for control
const SockaddrCtl = extern struct {
    sc_len: u8,
    sc_family: u8,
    ss_sysaddr: u16,
    sc_id: u32,
    sc_unit: u32,
    sc_reserved: [5]u32,
};

// Interface request structure
// Note: On macOS, the union is typically 16 bytes to accommodate sockaddr
const Ifreq = extern struct {
    ifr_name: [16]u8,
    ifr_ifru: extern union {
        ifru_flags: c_short,
        ifru_mtu: c_int,
        ifru_data: [16]u8, // Large enough for sockaddr_in
    },
};

// IPv4 interface alias request
const IfaliasReq = extern struct {
    ifra_name: [16]u8,
    ifra_addr: posix.sockaddr.in,
    ifra_broadaddr: posix.sockaddr.in,
    ifra_mask: posix.sockaddr.in,
};

// IPv6 interface alias request
const In6IfaliasReq = extern struct {
    ifra_name: [16]u8,
    ifra_addr: posix.sockaddr.in6,
    ifra_dstaddr: posix.sockaddr.in6,
    ifra_prefixmask: posix.sockaddr.in6,
    ifra_flags: i32,
    ifra_lifetime: In6AddrLifetime,
};

// IPv6 address lifetime (time_t is i64 on arm64 macOS)
const In6AddrLifetime = extern struct {
    ia6t_expire: i64, // time_t - valid lifetime expiration
    ia6t_preferred: i64, // time_t - preferred lifetime expiration
    ia6t_vltime: u32, // valid lifetime
    ia6t_pltime: u32, // prefix lifetime
};

/// Create a new utun device
pub fn create(name: ?[]const u8) TunError!Tun {
    // Parse unit number from name if provided (e.g., "utun5" -> 6)
    var unit: u32 = 0; // 0 means auto-assign

    if (name) |n| {
        if (n.len >= 4 and std.mem.eql(u8, n[0..4], "utun")) {
            if (n.len > 4) {
                unit = std.fmt.parseInt(u32, n[4..], 10) catch return TunError.InvalidName;
                unit += 1; // utun0 = unit 1, utun1 = unit 2, etc.
            }
        } else {
            return TunError.InvalidName;
        }
    }

    // Create AF_SYSTEM socket
    const fd = posix.socket(AF_SYSTEM, posix.SOCK.DGRAM, SYSPROTO_CONTROL) catch {
        return TunError.CreateFailed;
    };
    errdefer posix.close(fd);

    // Get control ID
    var ctl_info = CtlInfo{
        .ctl_id = 0,
        .ctl_name = undefined,
    };
    @memcpy(ctl_info.ctl_name[0..UTUN_CONTROL_NAME.len], UTUN_CONTROL_NAME);
    @memset(ctl_info.ctl_name[UTUN_CONTROL_NAME.len..], 0);

    if (ioctl(@intCast(fd), CTLIOCGINFO, @intFromPtr(&ctl_info)) != 0) {
        return TunError.CreateFailed;
    }

    // Connect to control
    var sc = SockaddrCtl{
        .sc_len = @sizeOf(SockaddrCtl),
        .sc_family = AF_SYSTEM,
        .ss_sysaddr = AF_SYS_CONTROL,
        .sc_id = ctl_info.ctl_id,
        .sc_unit = unit,
        .sc_reserved = .{ 0, 0, 0, 0, 0 },
    };

    posix.connect(fd, @ptrCast(&sc), @sizeOf(SockaddrCtl)) catch |err| {
        return switch (err) {
            error.PermissionDenied => TunError.PermissionDenied,
            error.AddressInUse => TunError.DeviceBusy,
            else => TunError.CreateFailed,
        };
    };

    // Get assigned interface name via getsockopt
    // UTUN_OPT_IFNAME = 2 returns the interface name as a string
    var name_buf: [16]u8 = undefined;
    var opt_len: posix.socklen_t = @sizeOf([16]u8);

    const result = std.c.getsockopt(fd, SYSPROTO_CONTROL, 2, &name_buf, &opt_len);
    if (result != 0) {
        // Fallback: try to get unit from sockaddr and build name
        var sc_out: SockaddrCtl = undefined;
        var sc_len: posix.socklen_t = @sizeOf(SockaddrCtl);
        const gn_result = std.c.getpeername(fd, @ptrCast(&sc_out), &sc_len);
        if (gn_result == 0 and sc_out.sc_unit > 0) {
            const name_slice = std.fmt.bufPrint(&name_buf, "utun{d}", .{sc_out.sc_unit - 1}) catch {
                return TunError.CreateFailed;
            };
            @memset(name_buf[name_slice.len..], 0);
        } else {
            // Last resort: use the unit we requested
            if (unit > 0) {
                const name_slice = std.fmt.bufPrint(&name_buf, "utun{d}", .{unit - 1}) catch {
                    return TunError.CreateFailed;
                };
                @memset(name_buf[name_slice.len..], 0);
            } else {
                return TunError.CreateFailed;
            }
        }
    }

    // Calculate name length (find null terminator)
    var name_len: u8 = 0;
    for (name_buf, 0..) |c, i| {
        if (c == 0) {
            name_len = @intCast(i);
            break;
        }
    }

    return Tun{
        .handle = fd,
        .name_buf = name_buf,
        .name_len = name_len,
        .closed = false,
    };
}

/// Maximum buffer size for TUN devices
/// 2KB is sufficient for standard MTU (1500) + header (4), with room for slightly larger frames.
/// For jumbo frames, consider using heap allocation or increasing this value.
const MAX_BUFFER = 2048;

/// Read a packet from the TUN device
///
/// On macOS, the first 4 bytes are the address family (AF_INET or AF_INET6).
/// We strip this header and return only the IP packet.
pub fn read(tun: *Tun, buf: []u8) TunError!usize {
    // Need extra 4 bytes for address family header
    // Use 2KB stack buffer to avoid stack overflow in multi-threaded apps
    const header_size = 4;
    const read_size = @min(buf.len + header_size, MAX_BUFFER);
    var read_buf: [MAX_BUFFER]u8 = undefined;

    const n = posix.read(tun.handle, read_buf[0..read_size]) catch |err| {
        return switch (err) {
            error.WouldBlock => TunError.WouldBlock,
            else => TunError.IoError,
        };
    };

    if (n <= header_size) {
        return TunError.IoError;
    }

    // Skip the 4-byte address family header
    const payload_len = n - header_size;
    const copy_len = @min(payload_len, buf.len);
    @memcpy(buf[0..copy_len], read_buf[header_size..][0..copy_len]);

    return copy_len;
}

/// Write a packet to the TUN device
///
/// On macOS, we need to prepend a 4-byte address family header.
pub fn write(tun: *Tun, data: []const u8) TunError!usize {
    if (data.len == 0) {
        return TunError.InvalidArgument;
    }

    // Prepend address family header
    // Use 2KB stack buffer to avoid stack overflow in multi-threaded apps
    const header_size = 4;
    var write_buf: [MAX_BUFFER]u8 = undefined;
    const total_len = data.len + header_size;

    if (total_len > write_buf.len) {
        return TunError.InvalidArgument;
    }

    // Determine address family from IP version
    const ip_version = data[0] >> 4;
    const af: u32 = switch (ip_version) {
        4 => posix.AF.INET,
        6 => posix.AF.INET6,
        else => return TunError.InvalidArgument,
    };

    // Write in network byte order (big-endian)
    write_buf[0] = 0;
    write_buf[1] = 0;
    write_buf[2] = @truncate(af >> 8);
    write_buf[3] = @truncate(af);
    @memcpy(write_buf[header_size..total_len], data);

    const written = posix.write(tun.handle, write_buf[0..total_len]) catch |err| {
        return switch (err) {
            error.WouldBlock => TunError.WouldBlock,
            else => TunError.IoError,
        };
    };

    if (written <= header_size) {
        return TunError.IoError;
    }

    return written - header_size;
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
        .ifr_name = undefined,
        .ifr_ifru = .{ .ifru_mtu = 0 },
    };
    @memcpy(ifr.ifr_name[0..tun.name_len], tun.name_buf[0..tun.name_len]);
    @memset(ifr.ifr_name[tun.name_len..], 0);

    if (ioctl(@intCast(sock), SIOCGIFMTU, @intFromPtr(&ifr)) != 0) {
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
        .ifr_name = undefined,
        .ifr_ifru = .{ .ifru_mtu = @intCast(mtu) },
    };
    @memcpy(ifr.ifr_name[0..tun.name_len], tun.name_buf[0..tun.name_len]);
    @memset(ifr.ifr_name[tun.name_len..], 0);

    if (ioctl(@intCast(sock), SIOCSIFMTU, @intFromPtr(&ifr)) != 0) {
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
        .ifr_name = undefined,
        .ifr_ifru = .{ .ifru_flags = 0 },
    };
    @memcpy(ifr.ifr_name[0..tun.name_len], tun.name_buf[0..tun.name_len]);
    @memset(ifr.ifr_name[tun.name_len..], 0);

    // Get current flags
    if (ioctl(@intCast(sock), SIOCGIFFLAGS, @intFromPtr(&ifr)) != 0) {
        return TunError.IoError;
    }

    // Set UP flag
    ifr.ifr_ifru.ifru_flags |= IFF_UP | IFF_RUNNING;

    if (ioctl(@intCast(sock), SIOCSIFFLAGS, @intFromPtr(&ifr)) != 0) {
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
        .ifr_name = undefined,
        .ifr_ifru = .{ .ifru_flags = 0 },
    };
    @memcpy(ifr.ifr_name[0..tun.name_len], tun.name_buf[0..tun.name_len]);
    @memset(ifr.ifr_name[tun.name_len..], 0);

    // Get current flags
    if (ioctl(@intCast(sock), SIOCGIFFLAGS, @intFromPtr(&ifr)) != 0) {
        return TunError.IoError;
    }

    // Clear UP flag
    ifr.ifr_ifru.ifru_flags &= ~(IFF_UP | IFF_RUNNING);

    if (ioctl(@intCast(sock), SIOCSIFFLAGS, @intFromPtr(&ifr)) != 0) {
        return TunError.SetStateFailed;
    }
}

/// Set IPv4 address and netmask using SIOCAIFADDR (atomic operation)
pub fn setIPv4(tun: *Tun, addr: [4]u8, netmask: [4]u8) TunError!void {
    const sock = posix.socket(posix.AF.INET, posix.SOCK.DGRAM, 0) catch {
        return TunError.IoError;
    };
    defer posix.close(sock);

    // For point-to-point, set dst to next address in subnet
    var dst_addr = addr;
    dst_addr[3] +|= 1;

    // Use SIOCAIFADDR to set addr, dst, and mask atomically
    // This is required on macOS - separate ioctls ignore the netmask
    var req = IfaliasReq{
        .ifra_name = undefined,
        .ifra_addr = posix.sockaddr.in{
            .len = @sizeOf(posix.sockaddr.in),
            .family = posix.AF.INET,
            .port = 0,
            .addr = @bitCast(addr),
        },
        .ifra_broadaddr = posix.sockaddr.in{
            .len = @sizeOf(posix.sockaddr.in),
            .family = posix.AF.INET,
            .port = 0,
            .addr = @bitCast(dst_addr),
        },
        .ifra_mask = posix.sockaddr.in{
            .len = @sizeOf(posix.sockaddr.in),
            .family = posix.AF.INET,
            .port = 0,
            .addr = @bitCast(netmask),
        },
    };
    @memcpy(req.ifra_name[0..tun.name_len], tun.name_buf[0..tun.name_len]);
    @memset(req.ifra_name[tun.name_len..], 0);

    if (ioctl(@intCast(sock), SIOCAIFADDR, @intFromPtr(&req)) != 0) {
        return TunError.SetAddressFailed;
    }
}

/// Set IPv6 address with prefix length
pub fn setIPv6(tun: *Tun, addr: [16]u8, prefix_len: u8) TunError!void {
    const sock = posix.socket(posix.AF.INET6, posix.SOCK.DGRAM, 0) catch {
        return TunError.IoError;
    };
    defer posix.close(sock);

    var req = In6IfaliasReq{
        .ifra_name = undefined,
        .ifra_addr = posix.sockaddr.in6{
            .len = @sizeOf(posix.sockaddr.in6),
            .family = posix.AF.INET6,
            .port = 0,
            .flowinfo = 0,
            .addr = addr,
            .scope_id = 0,
        },
        .ifra_dstaddr = posix.sockaddr.in6{
            .len = @sizeOf(posix.sockaddr.in6),
            .family = 0, // Must be 0 when address is zero
            .port = 0,
            .flowinfo = 0,
            .addr = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
            .scope_id = 0,
        },
        .ifra_prefixmask = posix.sockaddr.in6{
            .len = @sizeOf(posix.sockaddr.in6),
            .family = 0, // Must be 0 for prefix mask
            .port = 0,
            .flowinfo = 0,
            .addr = prefixToMask(prefix_len),
            .scope_id = 0,
        },
        .ifra_flags = 0,
        .ifra_lifetime = In6AddrLifetime{
            .ia6t_expire = 0,
            .ia6t_preferred = 0,
            .ia6t_vltime = 0xffffffff, // infinite
            .ia6t_pltime = 0xffffffff, // infinite
        },
    };
    @memcpy(req.ifra_name[0..tun.name_len], tun.name_buf[0..tun.name_len]);
    @memset(req.ifra_name[tun.name_len..], 0);

    if (ioctl(@intCast(sock), SIOCAIFADDR_IN6, @intFromPtr(&req)) != 0) {
        return TunError.SetAddressFailed;
    }
}

/// Convert prefix length to IPv6 mask
fn prefixToMask(prefix_len: u8) [16]u8 {
    var mask: [16]u8 = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    var remaining = prefix_len;
    var i: usize = 0;

    while (remaining >= 8 and i < 16) {
        mask[i] = 0xff;
        remaining -= 8;
        i += 1;
    }

    if (remaining > 0 and i < 16) {
        mask[i] = @as(u8, 0xff) << @intCast(8 - remaining);
    }

    return mask;
}
