//! OS DNS Configuration Manager.
//!
//! Configures the operating system to route DNS queries for specific domains
//! to a specified nameserver. Uses platform-specific mechanisms:
//! - macOS: /etc/resolver/ files (native split DNS)
//! - Linux: systemd-resolved or /etc/resolv.conf
//! - Windows: NRPT (Name Resolution Policy Table) registry rules

const std = @import("std");
const builtin = @import("builtin");

pub const darwin = if (builtin.os.tag == .macos) @import("darwin.zig") else struct {};
pub const linux = if (builtin.os.tag == .linux) @import("linux.zig") else struct {};
pub const windows = if (builtin.os.tag == .windows) @import("windows.zig") else struct {};

/// Error type for DNS manager operations.
pub const DnsMgrError = error{
    /// Failed to set DNS configuration.
    SetFailed,
    /// Failed to create resolver file/registry key.
    CreateFailed,
    /// Failed to remove resolver file/registry key.
    RemoveFailed,
    /// Permission denied (need root/admin).
    PermissionDenied,
    /// Operation not supported on this platform.
    NotSupported,
    /// Invalid argument.
    InvalidArgument,
    /// Failed to flush DNS cache.
    FlushFailed,
    /// Failed to detect DNS mode.
    DetectFailed,
    /// Upstream operation failed.
    UpstreamFailed,
};

/// DNS manager configuration.
pub const DnsMgrConfig = struct {
    /// TUN interface name (e.g., "utun3", "tun0").
    iface_name: ?[]const u8 = null,
};

/// OS DNS Configuration Manager.
///
/// Manages split DNS configuration so that queries for specific domains
/// are routed to a specified nameserver (typically the Magic DNS server).
pub const DnsMgr = struct {
    config: DnsMgrConfig,
    /// Whether DNS configuration has been applied.
    active: bool,
    /// Platform-specific state.
    platform: PlatformState,

    const PlatformState = switch (builtin.os.tag) {
        .macos => darwin.DarwinState,
        .linux => linux.LinuxState,
        .windows => windows.WindowsState,
        else => struct {},
    };

    const Self = @This();

    /// Create a new DNS manager.
    pub fn init(config: DnsMgrConfig) Self {
        return .{
            .config = config,
            .active = false,
            .platform = switch (builtin.os.tag) {
                .macos => darwin.DarwinState.init(),
                .linux => linux.LinuxState.init(),
                .windows => windows.WindowsState.init(),
                else => .{},
            },
        };
    }

    /// Set DNS configuration: route queries for `domains` to `nameserver`.
    /// `nameserver` is an IP address string (e.g., "100.64.0.1").
    /// `domains` is a slice of domain suffixes (e.g., ["zigor.net"]).
    pub fn setDNS(self: *Self, nameserver: []const u8, domains: []const []const u8) DnsMgrError!void {
        switch (builtin.os.tag) {
            .macos => try darwin.setDNS(&self.platform, nameserver, domains),
            .linux => try linux.setDNS(&self.platform, nameserver, domains, self.config.iface_name),
            .windows => try windows.setDNS(&self.platform, nameserver, domains),
            else => return DnsMgrError.NotSupported,
        }
        self.active = true;
    }

    /// Check if the platform supports split DNS natively.
    pub fn supportsSplitDNS(_: *const Self) bool {
        return switch (builtin.os.tag) {
            .macos => true, // /etc/resolver/ is native split DNS
            .linux => linux.supportsSplitDNS(),
            .windows => true, // NRPT is split DNS
            else => false,
        };
    }

    /// Flush the OS DNS cache.
    pub fn flushCache(_: *Self) DnsMgrError!void {
        switch (builtin.os.tag) {
            .macos => try darwin.flushCache(),
            .linux => try linux.flushCache(),
            .windows => try windows.flushCache(),
            else => return DnsMgrError.NotSupported,
        }
    }

    /// Remove all DNS configuration and restore original state.
    pub fn close(self: *Self) void {
        if (!self.active) return;
        switch (builtin.os.tag) {
            .macos => darwin.close(&self.platform),
            .linux => linux.close(&self.platform),
            .windows => windows.close(&self.platform),
            else => {},
        }
        self.active = false;
    }
};

// C ABI exports
pub const cabi = @import("cabi.zig");

test {
    std.testing.refAllDecls(@This());
    _ = cabi;
}
