//! Key and KeyPair types for Curve25519.
//!
//! Key is a standalone 32-byte wrapper (no crypto dependency).
//! KeyPair uses trait.crypto X25519 for DH operations.

const std = @import("std");
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
        for (self.data) |byte| {
            try writer.print("{x:0>2}", .{byte});
        }
    }

    /// Returns short hex representation (first 8 chars).
    pub fn shortHex(self: Key) [8]u8 {
        var buf: [8]u8 = undefined;
        const hex_chars = "0123456789abcdef";
        for (self.data[0..4], 0..) |byte, i| {
            buf[i * 2] = hex_chars[byte >> 4];
            buf[i * 2 + 1] = hex_chars[byte & 0x0f];
        }
        return buf;
    }

    /// Constant-time equality check.
    pub fn eql(self: Key, other: Key) bool {
        // Constant-time comparison without std.crypto dependency
        var diff: u8 = 0;
        for (self.data, other.data) |a, b| {
            diff |= a ^ b;
        }
        return diff == 0;
    }
};

/// A Curve25519 key pair, parameterized by Crypto implementation.
pub fn KeyPair(comptime Crypto: type) type {
    const X = Crypto.X25519;

    return struct {
        private: Key,
        public: Key,

        const Self = @This();

        /// Creates a key pair from a 32-byte seed (deterministic).
        /// Use platform RNG to generate the seed.
        pub fn fromSeed(seed: [32]u8) Self {
            const kp = X.KeyPair.generateDeterministic(seed) catch {
                return Self{ .private = Key.zero, .public = Key.zero };
            };
            return .{
                .private = Key.fromBytes(kp.secret_key),
                .public = Key.fromBytes(kp.public_key),
            };
        }

        /// Creates a key pair from a private key.
        pub fn fromPrivate(private: Key) Self {
            // X25519 base point (u = 9)
            var base: [32]u8 = [_]u8{0} ** 32;
            base[0] = 9;
            const public_key = X.scalarmult(private.data, base) catch {
                return Self{ .private = private, .public = Key.zero };
            };
            return .{
                .private = private,
                .public = Key.fromBytes(public_key),
            };
        }

        /// Performs Diffie-Hellman key exchange.
        pub fn dh(self: Self, peer_public: Key) !Key {
            const shared = X.scalarmult(self.private.data, peer_public.data) catch {
                return error.DhFailed;
            };
            // Check for low-order points
            if (mem.eql(u8, &shared, &Key.zero.data)) {
                return error.LowOrderPoint;
            }
            return Key.fromBytes(shared);
        }
    };
}

// Tests
const TestCrypto = @import("test_crypto.zig");
const TestKeyPair = KeyPair(TestCrypto);

test "key is zero" {
    const zero_key = Key.zero;
    try std.testing.expect(zero_key.isZero());

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

test "keypair from seed" {
    const kp = TestKeyPair.fromSeed([_]u8{42} ** 32);
    try std.testing.expect(!kp.private.isZero());
    try std.testing.expect(!kp.public.isZero());
}

test "keypair from private" {
    const kp1 = TestKeyPair.fromSeed([_]u8{99} ** 32);
    const kp2 = TestKeyPair.fromPrivate(kp1.private);
    try std.testing.expect(kp1.public.eql(kp2.public));
}

test "dh exchange" {
    const alice = TestKeyPair.fromSeed([_]u8{1} ** 32);
    const bob = TestKeyPair.fromSeed([_]u8{2} ** 32);

    const shared_alice = try alice.dh(bob.public);
    const shared_bob = try bob.dh(alice.public);

    try std.testing.expect(shared_alice.eql(shared_bob));
    try std.testing.expect(!shared_alice.isZero());
}

test "dh deterministic" {
    const priv = Key.fromBytes([_]u8{42} ** key_size);
    const kp1 = TestKeyPair.fromPrivate(priv);
    const kp2 = TestKeyPair.fromPrivate(priv);
    try std.testing.expect(kp1.public.eql(kp2.public));
}
