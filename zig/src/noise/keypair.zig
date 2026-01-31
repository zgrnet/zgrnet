//! Key and KeyPair types for Curve25519.

const std = @import("std");
const crypto = std.crypto;
const fmt = std.fmt;
const mem = std.mem;

/// Size of keys in bytes.
pub const key_size: usize = 32;

/// A 32-byte cryptographic key.
pub const Key = struct {
    data: [key_size]u8,

    pub const zero = Key{ .data = [_]u8{0} ** key_size };

    /// Creates a key from bytes.
    pub fn fromBytes(bytes: [key_size]u8) Key {
        return .{ .data = bytes };
    }

    /// Creates a key from a slice.
    pub fn fromSlice(slice: []const u8) !Key {
        if (slice.len != key_size) return error.InvalidLength;
        var key: Key = undefined;
        @memcpy(&key.data, slice);
        return key;
    }

    /// Creates a key from hex string.
    pub fn fromHex(hex: []const u8) !Key {
        if (hex.len != key_size * 2) return error.InvalidLength;
        var key: Key = undefined;
        _ = fmt.hexToBytes(&key.data, hex) catch return error.InvalidHex;
        return key;
    }

    /// Returns true if the key is all zeros.
    pub fn isZero(self: Key) bool {
        return mem.eql(u8, &self.data, &zero.data);
    }

    /// Returns the key as a byte slice.
    pub fn asBytes(self: *const Key) *const [key_size]u8 {
        return &self.data;
    }

    /// Formats key as hex string.
    pub fn format(
        self: Key,
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        try writer.print("{s}", .{fmt.fmtSliceHexLower(&self.data)});
    }

    /// Returns short hex representation (first 8 chars).
    pub fn shortHex(self: Key) [8]u8 {
        var buf: [8]u8 = undefined;
        _ = fmt.bufPrint(&buf, "{s}", .{fmt.fmtSliceHexLower(self.data[0..4])}) catch unreachable;
        return buf;
    }

    /// Constant-time equality check.
    pub fn eql(self: Key, other: Key) bool {
        return crypto.timing_safe.eql([key_size]u8, self.data, other.data);
    }
};

/// A Curve25519 key pair.
pub const KeyPair = struct {
    private: Key,
    public: Key,

    /// Generates a new random key pair.
    pub fn generate() KeyPair {
        const kp = crypto.dh.X25519.KeyPair.generate();
        return .{
            .private = Key.fromBytes(kp.secret_key),
            .public = Key.fromBytes(kp.public_key),
        };
    }

    /// Creates a key pair from a private key.
    pub fn fromPrivate(private: Key) KeyPair {
        const public_key = crypto.dh.X25519.recoverPublicKey(private.data) catch {
            // This shouldn't happen with valid private keys
            return .{ .private = private, .public = Key.zero };
        };
        return .{
            .private = private,
            .public = Key.fromBytes(public_key),
        };
    }

    /// Performs Diffie-Hellman key exchange.
    pub fn dh(self: KeyPair, peer_public: Key) !Key {
        const shared = crypto.dh.X25519.scalarmult(self.private.data, peer_public.data) catch {
            return error.DhFailed;
        };
        // Check for low-order points
        if (mem.eql(u8, &shared, &Key.zero.data)) {
            return error.LowOrderPoint;
        }
        return Key.fromBytes(shared);
    }
};

// Tests
test "key is zero" {
    const zero = Key.zero;
    try std.testing.expect(zero.isZero());

    var non_zero = Key.zero;
    non_zero.data[0] = 1;
    try std.testing.expect(!non_zero.isZero());
}

test "key from hex" {
    const hex = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
    const key = try Key.fromHex(hex);
    try std.testing.expectEqual(@as(u8, 0x01), key.data[0]);
    try std.testing.expectEqual(@as(u8, 0x20), key.data[31]);

    // Invalid hex
    try std.testing.expectError(error.InvalidLength, Key.fromHex("xyz"));
    try std.testing.expectError(error.InvalidLength, Key.fromHex("0102"));
}

test "key equality" {
    const k1 = Key.fromBytes([_]u8{1} ** key_size);
    const k2 = Key.fromBytes([_]u8{1} ** key_size);
    const k3 = Key.fromBytes([_]u8{2} ** key_size);

    try std.testing.expect(k1.eql(k2));
    try std.testing.expect(!k1.eql(k3));
}

test "generate keypair" {
    const kp = KeyPair.generate();
    try std.testing.expect(!kp.private.isZero());
    try std.testing.expect(!kp.public.isZero());
}

test "keypair from private" {
    const kp1 = KeyPair.generate();
    const kp2 = KeyPair.fromPrivate(kp1.private);
    try std.testing.expect(kp1.public.eql(kp2.public));
}

test "dh exchange" {
    const alice = KeyPair.generate();
    const bob = KeyPair.generate();

    const shared_alice = try alice.dh(bob.public);
    const shared_bob = try bob.dh(alice.public);

    try std.testing.expect(shared_alice.eql(shared_bob));
    try std.testing.expect(!shared_alice.isZero());
}

test "dh deterministic" {
    const priv = Key.fromBytes([_]u8{42} ** key_size);
    const kp1 = KeyPair.fromPrivate(priv);
    const kp2 = KeyPair.fromPrivate(priv);
    try std.testing.expect(kp1.public.eql(kp2.public));
}
