//! C ABI exports for the DNS Manager module.
//!
//! Provides C-compatible function exports that can be called
//! from Rust, Go, or any other language that supports C FFI.

const std = @import("std");
const mod = @import("mod.zig");
const DnsMgr = mod.DnsMgr;
const DnsMgrConfig = mod.DnsMgrConfig;
const DnsMgrError = mod.DnsMgrError;

// Error code mapping
const DNSMGR_OK: c_int = 0;
const DNSMGR_ERR_SET_FAILED: c_int = -1;
const DNSMGR_ERR_CREATE_FAILED: c_int = -2;
const DNSMGR_ERR_REMOVE_FAILED: c_int = -3;
const DNSMGR_ERR_PERMISSION_DENIED: c_int = -4;
const DNSMGR_ERR_NOT_SUPPORTED: c_int = -5;
const DNSMGR_ERR_INVALID_ARGUMENT: c_int = -6;
const DNSMGR_ERR_FLUSH_FAILED: c_int = -7;
const DNSMGR_ERR_DETECT_FAILED: c_int = -8;
const DNSMGR_ERR_UPSTREAM_FAILED: c_int = -9;

fn errorToCode(err: DnsMgrError) c_int {
    return switch (err) {
        DnsMgrError.SetFailed => DNSMGR_ERR_SET_FAILED,
        DnsMgrError.CreateFailed => DNSMGR_ERR_CREATE_FAILED,
        DnsMgrError.RemoveFailed => DNSMGR_ERR_REMOVE_FAILED,
        DnsMgrError.PermissionDenied => DNSMGR_ERR_PERMISSION_DENIED,
        DnsMgrError.NotSupported => DNSMGR_ERR_NOT_SUPPORTED,
        DnsMgrError.InvalidArgument => DNSMGR_ERR_INVALID_ARGUMENT,
        DnsMgrError.FlushFailed => DNSMGR_ERR_FLUSH_FAILED,
        DnsMgrError.DetectFailed => DNSMGR_ERR_DETECT_FAILED,
        DnsMgrError.UpstreamFailed => DNSMGR_ERR_UPSTREAM_FAILED,
    };
}

var gpa = std.heap.GeneralPurposeAllocator(.{}){};
const allocator = gpa.allocator();

// ============================================================================
// Lifecycle
// ============================================================================

/// Create a new DNS manager.
export fn dnsmgr_create(iface_name: ?[*:0]const u8) ?*DnsMgr {
    // Duplicate the iface_name string to avoid Use-After-Free.
    // The caller (Go/Rust) frees the original C string after this call returns,
    // so we must own the memory.
    const owned_name: ?[]const u8 = if (iface_name) |n| blk: {
        const len = std.mem.len(n);
        break :blk allocator.dupe(u8, n[0..len]) catch return null;
    } else null;

    const mgr = allocator.create(DnsMgr) catch {
        if (owned_name) |name| allocator.free(name);
        return null;
    };
    mgr.* = DnsMgr.init(.{
        .iface_name = owned_name,
    });
    return mgr;
}

/// Close and destroy a DNS manager.
/// Restores original DNS configuration.
export fn dnsmgr_close(mgr: ?*DnsMgr) void {
    if (mgr) |m| {
        m.close();
        // Free the owned iface_name copy.
        if (m.config.iface_name) |name| {
            allocator.free(name);
        }
        allocator.destroy(m);
    }
}

// ============================================================================
// Configuration
// ============================================================================

/// Set DNS configuration.
/// `nameserver`: IP address string (e.g., "100.64.0.1")
/// `domains`: comma-separated domain suffixes (e.g., "zigor.net,example.com")
export fn dnsmgr_set(mgr: ?*DnsMgr, nameserver: ?[*:0]const u8, domains_csv: ?[*:0]const u8) c_int {
    const m = mgr orelse return DNSMGR_ERR_INVALID_ARGUMENT;
    const ns = if (nameserver) |n| n[0..std.mem.len(n)] else return DNSMGR_ERR_INVALID_ARGUMENT;
    const csv = if (domains_csv) |d| d[0..std.mem.len(d)] else return DNSMGR_ERR_INVALID_ARGUMENT;

    // Count commas to determine number of domains
    var num_domains: usize = 1;
    for (csv) |c| {
        if (c == ',') num_domains += 1;
    }

    // Dynamically allocate domain slice array
    const domain_ptrs = allocator.alloc([]const u8, num_domains) catch return DNSMGR_ERR_SET_FAILED;
    defer allocator.free(domain_ptrs);

    var count: usize = 0;
    var start: usize = 0;
    for (csv, 0..) |c, i| {
        if (c == ',') {
            if (i > start) {
                domain_ptrs[count] = csv[start..i];
                count += 1;
            }
            start = i + 1;
        }
    }
    if (start < csv.len) {
        domain_ptrs[count] = csv[start..];
        count += 1;
    }

    m.setDNS(ns, domain_ptrs[0..count]) catch |err| {
        return errorToCode(err);
    };
    return DNSMGR_OK;
}

/// Check if platform supports split DNS.
export fn dnsmgr_supports_split_dns(mgr: ?*DnsMgr) c_int {
    const m = mgr orelse return 0;
    return if (m.supportsSplitDNS()) 1 else 0;
}

/// Flush OS DNS cache (standalone, no DnsMgr instance needed).
export fn dnsmgr_flush_cache() c_int {
    const builtin = @import("builtin");
    switch (builtin.os.tag) {
        .macos => mod.darwin.flushCache() catch |err| return errorToCode(err),
        .linux => mod.linux.flushCache() catch |err| return errorToCode(err),
        .windows => mod.windows.flushCache() catch |err| return errorToCode(err),
        else => return DNSMGR_ERR_NOT_SUPPORTED,
    }
    return DNSMGR_OK;
}

// ============================================================================
// Tests
// ============================================================================

test "errorToCode mapping" {
    try std.testing.expectEqual(DNSMGR_ERR_SET_FAILED, errorToCode(DnsMgrError.SetFailed));
    try std.testing.expectEqual(DNSMGR_ERR_PERMISSION_DENIED, errorToCode(DnsMgrError.PermissionDenied));
    try std.testing.expectEqual(DNSMGR_ERR_NOT_SUPPORTED, errorToCode(DnsMgrError.NotSupported));
    try std.testing.expect(DNSMGR_ERR_SET_FAILED < 0);
}
