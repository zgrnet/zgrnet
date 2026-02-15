//! Label store: manages pubkey → labels mapping from multiple sources.
//!
//! Labels come from:
//! - Host LAN labels: config peers (e.g., "host.zigor.net/trusted")
//! - Remote LAN labels: zgrlan API (e.g., "company.zigor.net/employee")

const std = @import("std");
const mem = std.mem;
const Allocator = std.mem.Allocator;

/// Thread-safe store mapping pubkey hex strings to labels.
pub const LabelStore = struct {
    allocator: Allocator,
    /// pubkey hex -> list of labels (all allocator-owned strings)
    labels: std.StringHashMapUnmanaged(std.ArrayListUnmanaged([]const u8)),

    pub fn init(allocator: Allocator) LabelStore {
        return .{
            .allocator = allocator,
            .labels = .{},
        };
    }

    pub fn deinit(self: *LabelStore) void {
        var it = self.labels.iterator();
        while (it.next()) |entry| {
            for (entry.value_ptr.items) |label| {
                self.allocator.free(label);
            }
            entry.value_ptr.deinit(self.allocator);
            self.allocator.free(entry.key_ptr.*);
        }
        self.labels.deinit(self.allocator);
    }

    /// Returns all labels for the given pubkey hex.
    pub fn getLabels(self: *const LabelStore, pubkey_hex: []const u8) []const []const u8 {
        if (self.labels.get(pubkey_hex)) |list| {
            return list.items;
        }
        return &.{};
    }

    /// Add labels to the given pubkey. Duplicates are ignored.
    pub fn addLabels(self: *LabelStore, pubkey_hex: []const u8, new_labels: []const []const u8) !void {
        if (new_labels.len == 0) return;

        const gop = try self.labels.getOrPut(self.allocator, pubkey_hex);
        if (!gop.found_existing) {
            gop.key_ptr.* = try self.allocator.dupe(u8, pubkey_hex);
            gop.value_ptr.* = .{};
        }
        var list = gop.value_ptr;

        for (new_labels) |label| {
            var found = false;
            for (list.items) |existing| {
                if (mem.eql(u8, existing, label)) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                const owned = try self.allocator.dupe(u8, label);
                try list.append(self.allocator, owned);
            }
        }
    }

    /// Replace all labels for the given pubkey.
    pub fn setLabels(self: *LabelStore, pubkey_hex: []const u8, new_labels: []const []const u8) !void {
        if (self.labels.getPtr(pubkey_hex)) |list| {
            for (list.items) |label| {
                self.allocator.free(label);
            }
            list.clearRetainingCapacity();

            if (new_labels.len == 0) {
                list.deinit(self.allocator);
                const key = self.labels.getKey(pubkey_hex).?;
                _ = self.labels.remove(pubkey_hex);
                self.allocator.free(key);
                return;
            }

            for (new_labels) |label| {
                const owned = try self.allocator.dupe(u8, label);
                try list.append(self.allocator, owned);
            }
        } else if (new_labels.len > 0) {
            try self.addLabels(pubkey_hex, new_labels);
        }
    }

    /// Remove all labels matching a LAN domain prefix (e.g., "company.zigor.net").
    pub fn removeLabels(self: *LabelStore, pubkey_hex: []const u8, lan_domain: []const u8) !void {
        const list = self.labels.getPtr(pubkey_hex) orelse return;

        // Build prefix: "company.zigor.net/"
        const prefix = try std.fmt.allocPrint(self.allocator, "{s}/", .{lan_domain});
        defer self.allocator.free(prefix);

        var i: usize = 0;
        while (i < list.items.len) {
            if (mem.startsWith(u8, list.items[i], prefix)) {
                self.allocator.free(list.items[i]);
                _ = list.swapRemove(i);
            } else {
                i += 1;
            }
        }

        if (list.items.len == 0) {
            list.deinit(self.allocator);
            const key = self.labels.getKey(pubkey_hex).?;
            _ = self.labels.remove(pubkey_hex);
            self.allocator.free(key);
        }
    }

    /// Remove all labels for the given pubkey.
    pub fn removePeer(self: *LabelStore, pubkey_hex: []const u8) void {
        if (self.labels.getPtr(pubkey_hex)) |list| {
            for (list.items) |label| {
                self.allocator.free(label);
            }
            list.deinit(self.allocator);
            const key = self.labels.getKey(pubkey_hex).?;
            _ = self.labels.remove(pubkey_hex);
            self.allocator.free(key);
        }
    }

    /// Returns the number of pubkeys with labels.
    pub fn count(self: *const LabelStore) usize {
        return self.labels.count();
    }
};

/// Check if any of the peer's labels match a label pattern.
/// Supports exact match and wildcard ("company.zigor.net/*").
pub fn matchLabel(peer_labels: []const []const u8, pattern: []const u8) bool {
    // Check for wildcard: ends with "/*"
    if (pattern.len >= 2 and mem.endsWith(u8, pattern, "/*")) {
        const domain_prefix = pattern[0 .. pattern.len - 1]; // "company.zigor.net/"
        for (peer_labels) |label| {
            if (mem.startsWith(u8, label, domain_prefix)) {
                return true;
            }
        }
        return false;
    }

    // Exact match
    for (peer_labels) |label| {
        if (mem.eql(u8, label, pattern)) {
            return true;
        }
    }
    return false;
}

/// Check if any of the peer's labels match any of the patterns.
pub fn matchLabels(peer_labels: []const []const u8, patterns: []const []const u8) bool {
    for (patterns) |pattern| {
        if (matchLabel(peer_labels, pattern)) {
            return true;
        }
    }
    return false;
}

// =========================================================================
// Tests
// =========================================================================

test "LabelStore basic operations" {
    var store = LabelStore.init(std.testing.allocator);
    defer store.deinit();

    const pk = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

    // Initially empty
    try std.testing.expectEqual(@as(usize, 0), store.getLabels(pk).len);
    try std.testing.expectEqual(@as(usize, 0), store.count());

    // Add labels
    try store.addLabels(pk, &.{ "host.zigor.net/trusted", "host.zigor.net/friend" });
    const labels = store.getLabels(pk);
    try std.testing.expectEqual(@as(usize, 2), labels.len);
    try std.testing.expectEqualStrings("host.zigor.net/trusted", labels[0]);
    try std.testing.expectEqualStrings("host.zigor.net/friend", labels[1]);
    try std.testing.expectEqual(@as(usize, 1), store.count());
}

test "LabelStore add duplicates" {
    var store = LabelStore.init(std.testing.allocator);
    defer store.deinit();

    const pk = "0000000000000000000000000000000000000000000000000000000000000001";
    try store.addLabels(pk, &.{"host.zigor.net/trusted"});
    try store.addLabels(pk, &.{ "host.zigor.net/trusted", "host.zigor.net/friend" });

    try std.testing.expectEqual(@as(usize, 2), store.getLabels(pk).len);
}

test "LabelStore remove peer" {
    var store = LabelStore.init(std.testing.allocator);
    defer store.deinit();

    const pk = "0000000000000000000000000000000000000000000000000000000000000001";
    try store.addLabels(pk, &.{"host.zigor.net/trusted"});
    store.removePeer(pk);

    try std.testing.expectEqual(@as(usize, 0), store.getLabels(pk).len);
    try std.testing.expectEqual(@as(usize, 0), store.count());
}

test "matchLabel exact" {
    const labels = [_][]const u8{ "host.zigor.net/trusted", "company.zigor.net/employee" };
    try std.testing.expect(matchLabel(&labels, "host.zigor.net/trusted"));
    try std.testing.expect(!matchLabel(&labels, "host.zigor.net/friend"));
}

test "matchLabel wildcard" {
    const labels = [_][]const u8{ "company.zigor.net/employee", "company.zigor.net/dev-team" };
    try std.testing.expect(matchLabel(&labels, "company.zigor.net/*"));
    try std.testing.expect(!matchLabel(&labels, "other.zigor.net/*"));
}

test "matchLabels" {
    const labels = [_][]const u8{"host.zigor.net/trusted"};
    const patterns = [_][]const u8{ "company.zigor.net/*", "host.zigor.net/trusted" };
    try std.testing.expect(matchLabels(&labels, &patterns));

    const patterns2 = [_][]const u8{ "company.zigor.net/*", "other.zigor.net/admin" };
    try std.testing.expect(!matchLabels(&labels, &patterns2));
}

test "matchLabels empty" {
    const empty = [_][]const u8{};
    const patterns = [_][]const u8{"host.zigor.net/trusted"};
    try std.testing.expect(!matchLabels(&empty, &patterns));
    const labels = [_][]const u8{"host.zigor.net/trusted"};
    try std.testing.expect(!matchLabels(&labels, &empty));
}
