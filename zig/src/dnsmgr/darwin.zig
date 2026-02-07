//! macOS DNS configuration via /etc/resolver/ files.
//!
//! macOS natively supports split DNS through the /etc/resolver/ directory.
//! For each domain, we create a file like /etc/resolver/zigor.net containing:
//!   nameserver 100.64.0.1
//!
//! This tells the macOS resolver to use our DNS server for that domain.

const std = @import("std");
const mod = @import("mod.zig");
const DnsMgrError = mod.DnsMgrError;

const RESOLVER_DIR = "/etc/resolver";
const FILE_HEADER = "# Added by zgrnet\n";
const MAX_DOMAINS = 16;

pub const DarwinState = struct {
    /// Domain files we've created (to clean up on close).
    created_files: [MAX_DOMAINS]?[]const u8,
    created_count: usize,

    pub fn init() DarwinState {
        return .{
            .created_files = [_]?[]const u8{null} ** MAX_DOMAINS,
            .created_count = 0,
        };
    }
};

/// Validate domain name: only alphanumeric, dots, hyphens allowed.
/// Rejects path traversal sequences (..) and path separators (/).
fn validateDomain(domain: []const u8) bool {
    if (domain.len == 0) return false;
    // Reject path separators and traversal
    for (domain) |c| {
        if (!std.ascii.isAlphanumeric(c) and c != '.' and c != '-') {
            return false;
        }
    }
    // Reject ".." sequences (path traversal)
    if (std.mem.indexOf(u8, domain, "..") != null) return false;
    return true;
}

/// Set DNS configuration by writing /etc/resolver/ files.
pub fn setDNS(state: *DarwinState, nameserver: []const u8, domains: []const []const u8) DnsMgrError!void {
    // Validate all domains to prevent path traversal attacks.
    // Since we use domain as a filename under /etc/resolver/, a domain like
    // "../crontab" would write to /etc/crontab with root privileges.
    for (domains) |domain| {
        if (!validateDomain(domain)) return DnsMgrError.InvalidArgument;
    }

    // Ensure /etc/resolver/ directory exists
    std.fs.makeDirAbsolute(RESOLVER_DIR) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        error.AccessDenied => return DnsMgrError.PermissionDenied,
        else => return DnsMgrError.CreateFailed,
    };

    // Write a resolver file for each domain
    for (domains) |domain| {
        if (state.created_count >= MAX_DOMAINS) break;

        // Build file content: "# Added by zgrnet\nnameserver 100.64.0.1\n"
        var content_buf: [256]u8 = undefined;
        const content = std.fmt.bufPrint(&content_buf, "{s}nameserver {s}\n", .{ FILE_HEADER, nameserver }) catch continue;

        // Build path: "/etc/resolver/zigor.net"
        var path_buf: [256]u8 = undefined;
        const path = std.fmt.bufPrint(&path_buf, "{s}/{s}", .{ RESOLVER_DIR, domain }) catch continue;

        // Write the file
        const file = std.fs.createFileAbsolute(path, .{}) catch |err| switch (err) {
            error.AccessDenied => return DnsMgrError.PermissionDenied,
            else => return DnsMgrError.CreateFailed,
        };
        defer file.close();
        file.writeAll(content) catch return DnsMgrError.SetFailed;

        // Track for cleanup
        // We store a static copy of the domain for cleanup
        state.created_files[state.created_count] = domain;
        state.created_count += 1;
    }
}

/// Flush macOS DNS cache.
pub fn flushCache() DnsMgrError!void {
    // macOS uses dscacheutil -flushcache and killall -HUP mDNSResponder
    var child1 = std.process.Child.init(
        &.{ "dscacheutil", "-flushcache" },
        std.heap.page_allocator,
    );
    _ = child1.spawnAndWait() catch {};

    var child2 = std.process.Child.init(
        &.{ "killall", "-HUP", "mDNSResponder" },
        std.heap.page_allocator,
    );
    _ = child2.spawnAndWait() catch {};
}

/// Remove all resolver files created by us.
pub fn close(state: *DarwinState) void {
    for (state.created_files[0..state.created_count]) |maybe_domain| {
        if (maybe_domain) |domain| {
            var path_buf: [256]u8 = undefined;
            const path = std.fmt.bufPrint(&path_buf, "{s}/{s}", .{ RESOLVER_DIR, domain }) catch continue;

            // Only remove if it's our file (check header)
            if (std.fs.openFileAbsolute(path, .{})) |file| {
                var header_buf: [FILE_HEADER.len]u8 = undefined;
                const n = file.read(&header_buf) catch 0;
                file.close();
                if (n == FILE_HEADER.len and std.mem.eql(u8, &header_buf, FILE_HEADER)) {
                    std.fs.deleteFileAbsolute(path) catch {};
                }
            } else |_| {}
        }
    }
    state.created_count = 0;
}
