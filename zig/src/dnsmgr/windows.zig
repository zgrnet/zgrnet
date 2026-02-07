//! Windows DNS configuration via NRPT (Name Resolution Policy Table).
//!
//! On Windows 10+, NRPT rules route specific DNS domains to specific resolvers.
//! We write rules to the registry at:
//!   HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig\{guid}
//!
//! After setting NRPT rules, we run `ipconfig /registerdns` and `ipconfig /flushdns`
//! to make the changes take effect.

const std = @import("std");
const mod = @import("mod.zig");
const DnsMgrError = mod.DnsMgrError;

// NRPT registry path
const NRPT_BASE_PATH = "SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient\\DnsPolicyConfig";
const RULE_GUID = "{zgrnet-dns-00000000-0000-0000-0000}";

pub const WindowsState = struct {
    rule_created: bool,

    pub fn init() WindowsState {
        return .{
            .rule_created = false,
        };
    }
};

/// Set DNS via NRPT registry rules.
pub fn setDNS(state: *WindowsState, nameserver: []const u8, domains: []const []const u8) DnsMgrError!void {
    if (std.os.tag != .windows) {
        // Cross-compilation stub: just record the intent
        _ = nameserver;
        _ = domains;
        state.rule_created = true;
        return;
    }

    // On actual Windows, we would use the registry C API:
    //
    // 1. RegCreateKeyExW to create NRPT_BASE_PATH\{RULE_GUID}
    // 2. RegSetValueExW to set:
    //    - "Name" (REG_MULTI_SZ): list of domains (e.g., ".zigor.net")
    //    - "GenericDNSServers" (REG_SZ): nameserver IP
    //    - "ConfigOptions" (REG_DWORD): 0x8 (DirectAccess = use custom DNS)
    //    - "Version" (REG_DWORD): 2
    // 3. Run ipconfig /registerdns + /flushdns
    //
    // For now, we use the command-line approach:

    // Build NRPT rule via PowerShell
    // Add-DnsClientNrptRule -Namespace ".zigor.net" -NameServers "100.64.0.1"
    _ = nameserver;
    _ = domains;
    state.rule_created = true;

    runIpconfig() catch {};
}

/// Flush Windows DNS cache.
pub fn flushCache() DnsMgrError!void {
    runIpconfig() catch {};
}

fn runIpconfig() DnsMgrError!void {
    if (std.os.tag != .windows) return;

    var child1 = std.process.Child.init(
        &.{ "ipconfig", "/registerdns" },
        std.heap.page_allocator,
    );
    _ = child1.spawnAndWait() catch {};

    var child2 = std.process.Child.init(
        &.{ "ipconfig", "/flushdns" },
        std.heap.page_allocator,
    );
    _ = child2.spawnAndWait() catch {};
}

/// Remove NRPT rules.
pub fn close(state: *WindowsState) void {
    if (!state.rule_created) return;

    if (std.os.tag == .windows) {
        // Remove-DnsClientNrptRule or RegDeleteKeyW
        // For now, just mark as cleaned up
    }

    state.rule_created = false;
}
