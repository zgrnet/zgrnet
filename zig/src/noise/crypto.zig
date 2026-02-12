//! Common cryptographic primitives for Noise Protocol.
//! Provides hash, HMAC, and HKDF functions via trait.crypto.
//!
//! Supports two cipher suites:
//! - ChaChaPoly_BLAKE2s: ChaCha20-Poly1305 + BLAKE2s (default)
//! - AESGCM_SHA256: AES-128-GCM + SHA-256 (for hardware acceleration)

const std = @import("std");

const keypair = @import("keypair.zig");
pub const Key = keypair.Key;
pub const key_size = keypair.key_size;

/// Hash output size (both BLAKE2s-256 and SHA-256 produce 32 bytes).
pub const hash_size: usize = 32;

/// AEAD tag size (both Poly1305 and GCM use 16-byte tags).
pub const tag_size: usize = 16;

/// Noise cipher suite selection.
pub const CipherSuite = enum {
    /// Noise_XX_25519_ChaChaPoly_BLAKE2s (default)
    ChaChaPoly_BLAKE2s,
    /// Noise_XX_25519_AESGCM_SHA256 (uses AES-256-GCM for 32-byte keys)
    AESGCM_SHA256,
};

/// Instantiate crypto operations for a given Crypto implementation.
pub fn CryptoMod(comptime Crypto: type, comptime suite: CipherSuite) type {
    const Hash = switch (suite) {
        .ChaChaPoly_BLAKE2s => Crypto.Blake2s256,
        .AESGCM_SHA256 => Crypto.Sha256,
    };

    return struct {
        pub const cipher_suite = suite;

        /// The cipher suite name suffix for the Noise protocol name.
        pub const suite_name: []const u8 = switch (suite) {
            .ChaChaPoly_BLAKE2s => "ChaChaPoly_BLAKE2s",
            .AESGCM_SHA256 => "AESGCM_SHA256",
        };

        /// Computes hash of concatenated data slices.
        pub fn hash(data: []const []const u8) [hash_size]u8 {
            var h = Hash.init();
            for (data) |d| {
                h.update(d);
            }
            return h.final();
        }

        /// Computes HMAC.
        pub fn hmac(key_data: *const [hash_size]u8, data: []const []const u8) [hash_size]u8 {
            const block_len = Hash.block_length;

            // Build padded keys (hash_size=32 <= block_length=64, no pre-hashing needed)
            var k_ipad: [block_len]u8 = [_]u8{0x36} ** block_len;
            var k_opad: [block_len]u8 = [_]u8{0x5c} ** block_len;
            for (0..hash_size) |i| {
                k_ipad[i] = key_data[i] ^ 0x36;
                k_opad[i] = key_data[i] ^ 0x5c;
            }

            // Inner hash: H(k_ipad || data)
            var inner = Hash.init();
            inner.update(&k_ipad);
            for (data) |d| {
                inner.update(d);
            }
            const inner_hash = inner.final();

            // Outer hash: H(k_opad || inner_hash)
            var outer = Hash.init();
            outer.update(&k_opad);
            outer.update(&inner_hash);
            return outer.final();
        }

        /// HKDF - derives 1-3 keys from chaining key and input.
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
    };
}

// =============================================================================
// Tests
// =============================================================================

const TestCrypto = @import("test_crypto.zig");

test "hash consistency (BLAKE2s)" {
    const c = CryptoMod(TestCrypto, .ChaChaPoly_BLAKE2s);
    const h1 = c.hash(&.{"hello"});
    const h2 = c.hash(&.{"hello"});
    try std.testing.expectEqualSlices(u8, &h1, &h2);
}

test "hash concatenation (BLAKE2s)" {
    const c = CryptoMod(TestCrypto, .ChaChaPoly_BLAKE2s);
    const h1 = c.hash(&.{ "hello", "world" });
    const h2 = c.hash(&.{"helloworld"});
    try std.testing.expectEqualSlices(u8, &h1, &h2);
}

test "hkdf derives different keys (BLAKE2s)" {
    const c = CryptoMod(TestCrypto, .ChaChaPoly_BLAKE2s);
    const ck = Key.zero;
    const keys = c.hkdf(&ck, "input", 3);

    try std.testing.expect(!keys[0].isZero());
    try std.testing.expect(!keys[0].eql(keys[1]));
    try std.testing.expect(!keys[1].eql(keys[2]));
}

test "hash consistency (SHA256)" {
    const c = CryptoMod(TestCrypto, .AESGCM_SHA256);
    const h1 = c.hash(&.{"hello"});
    const h2 = c.hash(&.{"hello"});
    try std.testing.expectEqualSlices(u8, &h1, &h2);
}

test "hkdf derives different keys (SHA256)" {
    const c = CryptoMod(TestCrypto, .AESGCM_SHA256);
    const ck = Key.zero;
    const keys = c.hkdf(&ck, "input", 3);

    try std.testing.expect(!keys[0].isZero());
    try std.testing.expect(!keys[0].eql(keys[1]));
    try std.testing.expect(!keys[1].eql(keys[2]));
}
