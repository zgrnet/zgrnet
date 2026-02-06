//! TUN device abstraction for cross-platform virtual network interface management.
//!
//! This module provides a unified API for creating and managing TUN devices
//! across macOS, Linux, and Windows platforms.
//!
//! ## Example
//!
//! ```zig
//! const tun = @import("tun");
//!
//! pub fn main() !void {
//!     try tun.init();
//!     defer tun.deinit();
//!
//!     var device = try tun.Tun.create(null);
//!     defer device.close();
//!
//!     try device.setIPv4(.{10, 0, 0, 1}, .{255, 255, 255, 0});
//!     try device.setUp();
//!
//!     var buf: [1500]u8 = undefined;
//!     const n = try device.read(&buf);
//!     // Process packet...
//! }
//! ```

const std = @import("std");
const builtin = @import("builtin");

// Platform-specific implementations
pub const darwin = if (builtin.os.tag == .macos) @import("darwin.zig") else struct {};
pub const linux = if (builtin.os.tag == .linux) @import("linux.zig") else struct {};
pub const windows = if (builtin.os.tag == .windows) @import("windows.zig") else struct {};

/// Platform-specific handle type
pub const Handle = switch (builtin.os.tag) {
    .macos, .linux => std.posix.fd_t,
    .windows => std.os.windows.HANDLE,
    else => i32,
};

/// Error type for TUN operations
pub const TunError = error{
    /// Failed to create TUN device
    CreateFailed,
    /// Failed to open TUN device
    OpenFailed,
    /// Invalid device name
    InvalidName,
    /// Permission denied (need root/admin)
    PermissionDenied,
    /// Device not found
    DeviceNotFound,
    /// Operation not supported on this platform
    NotSupported,
    /// Device is busy
    DeviceBusy,
    /// Invalid argument
    InvalidArgument,
    /// System resources exhausted
    SystemResources,
    /// Operation would block (non-blocking mode)
    WouldBlock,
    /// I/O error
    IoError,
    /// Failed to set MTU
    SetMtuFailed,
    /// Failed to set IP address
    SetAddressFailed,
    /// Failed to set interface up/down
    SetStateFailed,
    /// Device already closed
    AlreadyClosed,
    /// Wintun DLL not found (Windows only)
    WintunNotFound,
    /// Wintun initialization failed (Windows only)
    WintunInitFailed,
};

/// TUN device configuration
pub const TunConfig = struct {
    /// Device name (null for auto-assign)
    name: ?[]const u8 = null,
    /// MTU size (default: 1400)
    mtu: u32 = 1400,
    /// Enable non-blocking mode
    non_blocking: bool = false,
};

/// TUN device interface
///
/// Provides read/write access to a virtual network interface.
/// Packets written to the TUN device appear as if they came from the network.
/// Packets destined for the TUN's network appear in read().
pub const Tun = struct {
    /// Platform-specific handle (fd on Unix, HANDLE on Windows)
    handle: Handle,
    /// Device name (e.g., "utun0", "tun0")
    name_buf: [16]u8,
    /// Length of device name
    name_len: u8,
    /// Whether the device is closed
    closed: bool,

    const Self = @This();

    /// Create a new TUN device
    ///
    /// On macOS, uses utun via AF_SYSTEM socket.
    /// On Linux, uses /dev/net/tun with IFF_TUN.
    /// On Windows, uses Wintun driver.
    ///
    /// - `name`: Device name (null for auto-assign)
    /// Returns the created TUN device or an error.
    pub fn create(name: ?[]const u8) TunError!Self {
        return switch (builtin.os.tag) {
            .macos => darwin.create(name),
            .linux => linux.create(name),
            .windows => windows.create(name),
            else => TunError.NotSupported,
        };
    }

    /// Create a TUN device with configuration
    pub fn createWithConfig(config: TunConfig) TunError!Self {
        var tun = try create(config.name);
        errdefer tun.close();

        if (config.mtu != 1400) {
            try tun.setMtu(config.mtu);
        }
        if (config.non_blocking) {
            try tun.setNonBlocking(true);
        }
        return tun;
    }

    /// Read a packet from the TUN device
    ///
    /// Blocks until a packet is available (unless in non-blocking mode).
    /// Returns the number of bytes read, or an error.
    pub fn read(self: *Self, buf: []u8) TunError!usize {
        if (self.closed) return TunError.AlreadyClosed;
        return switch (builtin.os.tag) {
            .macos => darwin.read(self, buf),
            .linux => linux.read(self, buf),
            .windows => windows.read(self, buf),
            else => TunError.NotSupported,
        };
    }

    /// Write a packet to the TUN device
    ///
    /// The packet should be a valid IP packet.
    /// Returns the number of bytes written, or an error.
    pub fn write(self: *Self, data: []const u8) TunError!usize {
        if (self.closed) return TunError.AlreadyClosed;
        return switch (builtin.os.tag) {
            .macos => darwin.write(self, data),
            .linux => linux.write(self, data),
            .windows => windows.write(self, data),
            else => TunError.NotSupported,
        };
    }

    /// Close the TUN device
    ///
    /// Releases all resources associated with the device.
    /// After close(), the device cannot be used.
    pub fn close(self: *Self) void {
        if (self.closed) return;
        switch (builtin.os.tag) {
            .macos => darwin.close(self),
            .linux => linux.close(self),
            .windows => windows.close(self),
            else => {},
        }
        self.closed = true;
    }

    /// Get the device name
    pub fn getName(self: *const Self) []const u8 {
        return self.name_buf[0..self.name_len];
    }

    /// Get the underlying handle (fd on Unix, HANDLE on Windows)
    ///
    /// Useful for integrating with event loops (poll/epoll/kqueue/IOCP).
    pub fn getHandle(self: *const Self) Handle {
        return self.handle;
    }

    /// Get the MTU (Maximum Transmission Unit)
    pub fn getMtu(self: *Self) TunError!u32 {
        if (self.closed) return TunError.AlreadyClosed;
        return switch (builtin.os.tag) {
            .macos => darwin.getMtu(self),
            .linux => linux.getMtu(self),
            .windows => windows.getMtu(self),
            else => TunError.NotSupported,
        };
    }

    /// Set the MTU (Maximum Transmission Unit)
    ///
    /// Requires root/admin privileges.
    pub fn setMtu(self: *Self, mtu: u32) TunError!void {
        if (self.closed) return TunError.AlreadyClosed;
        return switch (builtin.os.tag) {
            .macos => darwin.setMtu(self, mtu),
            .linux => linux.setMtu(self, mtu),
            .windows => windows.setMtu(self, mtu),
            else => TunError.NotSupported,
        };
    }

    /// Set non-blocking mode
    pub fn setNonBlocking(self: *Self, enabled: bool) TunError!void {
        if (self.closed) return TunError.AlreadyClosed;
        return switch (builtin.os.tag) {
            .macos => darwin.setNonBlocking(self, enabled),
            .linux => linux.setNonBlocking(self, enabled),
            .windows => windows.setNonBlocking(self, enabled),
            else => TunError.NotSupported,
        };
    }

    /// Bring the interface up
    ///
    /// Requires root/admin privileges.
    pub fn setUp(self: *Self) TunError!void {
        if (self.closed) return TunError.AlreadyClosed;
        return switch (builtin.os.tag) {
            .macos => darwin.setUp(self),
            .linux => linux.setUp(self),
            .windows => windows.setUp(self),
            else => TunError.NotSupported,
        };
    }

    /// Bring the interface down
    ///
    /// Requires root/admin privileges.
    pub fn setDown(self: *Self) TunError!void {
        if (self.closed) return TunError.AlreadyClosed;
        return switch (builtin.os.tag) {
            .macos => darwin.setDown(self),
            .linux => linux.setDown(self),
            .windows => windows.setDown(self),
            else => TunError.NotSupported,
        };
    }

    /// Set IPv4 address and netmask
    ///
    /// Requires root/admin privileges.
    pub fn setIPv4(self: *Self, addr: [4]u8, netmask: [4]u8) TunError!void {
        if (self.closed) return TunError.AlreadyClosed;
        return switch (builtin.os.tag) {
            .macos => darwin.setIPv4(self, addr, netmask),
            .linux => linux.setIPv4(self, addr, netmask),
            .windows => windows.setIPv4(self, addr, netmask),
            else => TunError.NotSupported,
        };
    }

    /// Set IPv6 address with prefix length
    ///
    /// Requires root/admin privileges.
    pub fn setIPv6(self: *Self, addr: [16]u8, prefix_len: u8) TunError!void {
        if (self.closed) return TunError.AlreadyClosed;
        return switch (builtin.os.tag) {
            .macos => darwin.setIPv6(self, addr, prefix_len),
            .linux => linux.setIPv6(self, addr, prefix_len),
            .windows => windows.setIPv6(self, addr, prefix_len),
            else => TunError.NotSupported,
        };
    }
};

/// Global initialization (required on Windows for Wintun)
///
/// On Unix systems, this is a no-op.
/// On Windows, this extracts and loads the embedded wintun.dll.
pub fn init() TunError!void {
    return switch (builtin.os.tag) {
        .windows => windows.init(),
        else => {},
    };
}

/// Global cleanup
///
/// On Unix systems, this is a no-op.
/// On Windows, this unloads wintun.dll.
pub fn deinit() void {
    switch (builtin.os.tag) {
        .windows => windows.deinit(),
        else => {},
    }
}

// Re-export test utilities
pub const testing = @import("testing.zig");

// C ABI exports (for building static library)
pub const cabi = @import("cabi.zig");

test {
    std.testing.refAllDecls(@This());
}
