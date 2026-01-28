//! Common cryptographic primitives for Noise Protocol.
//! Provides BLAKE2s hash, HMAC, and HKDF functions.

const std = @import("std");
const crypto = std.crypto;

const keypair = @import("keypair.zig");
pub const Key = keypair.Key;
pub const key_size = keypair.key_size;

/// Hash output size (BLAKE2s-256).
pub const hash_size: usize = 32;

/// AEAD tag size (Poly1305).
pub const tag_size: usize = 16;

/// Computes BLAKE2s-256 hash of concatenated data slices.
pub fn hash(data: []const []const u8) [hash_size]u8 {
    var h = crypto.hash.blake2.Blake2s256.init(.{});
    for (data) |d| {
        h.update(d);
    }
    var out: [hash_size]u8 = undefined;
    h.final(&out);
    return out;
}

/// Computes HMAC-BLAKE2s-256.
pub fn hmac(key: *const [hash_size]u8, data: []const []const u8) [hash_size]u8 {
    const Hmac = crypto.auth.hmac.Hmac(crypto.hash.blake2.Blake2s256);
    var mac = Hmac.init(key);
    for (data) |d| {
        mac.update(d);
    }
    var out: [hash_size]u8 = undefined;
    mac.final(&out);
    return out;
}

/// HKDF with BLAKE2s - derives 1-3 keys from chaining key and input.
pub fn hkdf(chaining_key: *const Key, input: []const u8, comptime num_outputs: usize) [num_outputs]Key {
    comptime {
        if (num_outputs < 1 or num_outputs > 3) {
            @compileError("num_outputs must be 1-3");
        }
    }

    const secret = hmac(chaining_key.asBytes(), &.{input});
    var outputs: [num_outputs]Key = undefined;

    outputs[0] = Key.fromBytes(hmac(&secret, &.{&[_]u8{0x01}}));

    if (num_outputs >= 2) {
        outputs[1] = Key.fromBytes(hmac(&secret, &.{ outputs[0].asBytes(), &[_]u8{0x02} }));
    }

    if (num_outputs >= 3) {
        outputs[2] = Key.fromBytes(hmac(&secret, &.{ outputs[1].asBytes(), &[_]u8{0x03} }));
    }

    return outputs;
}

/// Derives two keys from chaining key and input.
pub fn kdf2(chaining_key: *const Key, input: []const u8) struct { Key, Key } {
    const keys = hkdf(chaining_key, input, 2);
    return .{ keys[0], keys[1] };
}

/// Derives three keys from chaining key and input.
pub fn kdf3(chaining_key: *const Key, input: []const u8) struct { Key, Key, Key } {
    const keys = hkdf(chaining_key, input, 3);
    return .{ keys[0], keys[1], keys[2] };
}

// =============================================================================
// Tests
// =============================================================================

test "hash consistency" {
    const h1 = hash(&.{"hello"});
    const h2 = hash(&.{"hello"});
    try std.testing.expectEqualSlices(u8, &h1, &h2);
}

test "hash concatenation" {
    const h1 = hash(&.{ "hello", "world" });
    const h2 = hash(&.{"helloworld"});
    try std.testing.expectEqualSlices(u8, &h1, &h2);
}

test "hkdf derives different keys" {
    const ck = Key.zero;
    const keys = hkdf(&ck, "input", 3);

    try std.testing.expect(!keys[0].isZero());
    try std.testing.expect(!keys[0].eql(keys[1]));
    try std.testing.expect(!keys[1].eql(keys[2]));
}
