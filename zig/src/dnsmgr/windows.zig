//! Windows DNS configuration via NRPT (Name Resolution Policy Table).
//!
//! On Windows 10+, NRPT rules route specific DNS domains to specific resolvers.
//! We use PowerShell cmdlets to manage NRPT rules:
//!   Add-DnsClientNrptRule -Namespace ".zigor.net" -NameServers "100.64.0.1" -Comment "zgrnet"
//!
//! After setting NRPT rules, we run `ipconfig /registerdns` and `ipconfig /flushdns`
//! to make the changes take effect.
//!
//! Alternative approach (not yet implemented): direct registry manipulation at
//! HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig\{guid}
//! via RegCreateKeyExW/RegSetValueExW from advapi32.dll.

const std = @import("std");
const mod = @import("mod.zig");
const DnsMgrError = mod.DnsMgrError;

const NRPT_COMMENT = "zgrnet";
const MAX_DOMAINS = 16;

pub const WindowsState = struct {
    /// Whether we've created NRPT rules.
    rule_created: bool,
    /// Number of domains configured.
    domain_count: usize,
    /// Domain names for cleanup.
    domains: [MAX_DOMAINS][128]u8,
    domain_lens: [MAX_DOMAINS]usize,

    pub fn init() WindowsState {
        return .{
            .rule_created = false,
            .domain_count = 0,
            .domains = undefined,
            .domain_lens = [_]usize{0} ** MAX_DOMAINS,
        };
    }
};

/// Validate that a string contains only safe DNS/IP characters.
/// Allowed: a-z, A-Z, 0-9, '.', '-', ':' (for IPv6)
/// Rejects anything that could be used for command injection.
fn validateSafeString(s: []const u8) bool {
    for (s) |c| {
        if (!std.ascii.isAlphanumeric(c) and c != '.' and c != '-' and c != ':') {
            return false;
        }
    }
    return s.len > 0;
}

/// Set DNS via NRPT rules using PowerShell.
pub fn setDNS(state: *WindowsState, nameserver: []const u8, domains: []const []const u8) DnsMgrError!void {
    // Validate inputs to prevent command injection.
    // Since we embed these in a PowerShell -Command string, any metacharacters
    // (quotes, semicolons, pipes, etc.) could execute arbitrary code.
    if (!validateSafeString(nameserver)) return DnsMgrError.InvalidArgument;
    for (domains) |domain| {
        if (!validateSafeString(domain)) return DnsMgrError.InvalidArgument;
    }

    // First, remove any existing zgrnet NRPT rules
    removeExistingRules() catch {};

    // Add NRPT rule for each domain
    for (domains) |domain| {
        if (state.domain_count >= MAX_DOMAINS) break;

        // Build the namespace: ".zigor.net" (leading dot for suffix matching)
        var ns_buf: [256]u8 = undefined;
        const namespace = std.fmt.bufPrint(&ns_buf, ".{s}", .{domain}) catch continue;

        // PowerShell: Add-DnsClientNrptRule -Namespace ".zigor.net" -NameServers "100.64.0.1" -Comment "zgrnet"
        var cmd_buf: [512]u8 = undefined;
        const cmd = std.fmt.bufPrint(&cmd_buf, "Add-DnsClientNrptRule -Namespace \"{s}\" -NameServers \"{s}\" -Comment \"{s}\"", .{ namespace, nameserver, NRPT_COMMENT }) catch continue;

        var child = std.process.Child.init(
            &.{ "powershell", "-NoProfile", "-NonInteractive", "-Command", cmd },
            std.heap.page_allocator,
        );
        const term = child.spawnAndWait() catch return DnsMgrError.SetFailed;
        switch (term) {
            .Exited => |code| {
                if (code != 0) return DnsMgrError.SetFailed;
            },
            else => return DnsMgrError.SetFailed,
        }

        // Store domain for cleanup
        const copy_len = @min(domain.len, 128);
        @memcpy(state.domains[state.domain_count][0..copy_len], domain[0..copy_len]);
        state.domain_lens[state.domain_count] = copy_len;
        state.domain_count += 1;
    }

    state.rule_created = true;

    // Force DNS re-registration and flush cache
    flushCache() catch {};
}

/// Flush Windows DNS cache.
pub fn flushCache() DnsMgrError!void {
    // ipconfig /registerdns - forces Windows to notice adapter changes
    var child1 = std.process.Child.init(
        &.{ "ipconfig", "/registerdns" },
        std.heap.page_allocator,
    );
    _ = child1.spawnAndWait() catch {};

    // ipconfig /flushdns - clear DNS cache
    var child2 = std.process.Child.init(
        &.{ "ipconfig", "/flushdns" },
        std.heap.page_allocator,
    );
    _ = child2.spawnAndWait() catch {};

    // Also clear via PowerShell for newer Windows
    var child3 = std.process.Child.init(
        &.{ "powershell", "-NoProfile", "-NonInteractive", "-Command", "Clear-DnsClientCache" },
        std.heap.page_allocator,
    );
    _ = child3.spawnAndWait() catch {};
}

/// Remove NRPT rules created by zgrnet.
pub fn close(state: *WindowsState) void {
    if (!state.rule_created) return;

    removeExistingRules() catch {};
    flushCache() catch {};

    state.rule_created = false;
    state.domain_count = 0;
}

/// Remove all NRPT rules with our comment tag.
fn removeExistingRules() DnsMgrError!void {
    // PowerShell: Get-DnsClientNrptRule | Where-Object { $_.Comment -eq "zgrnet" } | Remove-DnsClientNrptRule -Force
    const cmd = "Get-DnsClientNrptRule | Where-Object { $_.Comment -eq '" ++ NRPT_COMMENT ++ "' } | Remove-DnsClientNrptRule -Force";

    var child = std.process.Child.init(
        &.{ "powershell", "-NoProfile", "-NonInteractive", "-Command", cmd },
        std.heap.page_allocator,
    );
    const term = child.spawnAndWait() catch return DnsMgrError.RemoveFailed;
    switch (term) {
        .Exited => |code| {
            // Exit code 0 = success, non-zero may mean no rules found (OK)
            _ = code;
        },
        else => return DnsMgrError.RemoveFailed,
    }
}
