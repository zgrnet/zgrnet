//! ChaCha20-Poly1305 AEAD cipher adapter for Noise Protocol.
//!
//! Adapts the trait.crypto ChaCha20Poly1305 interface to Noise's
//! u64 nonce convention (little-endian in first 8 bytes of 12-byte nonce).
//!
//! The Crypto type must provide ChaCha20Poly1305 with the standard AEAD
//! trait interface (encryptStatic/decryptStatic).

const std = @import("std");
const mem = std.mem;

const keypair = @import("keypair.zig");
pub const Key = keypair.Key;
pub const key_size = keypair.key_size;

const crypto_mod = @import("crypto.zig");
const CipherSuite = crypto_mod.CipherSuite;

/// Instantiate cipher operations for a given Crypto implementation.
pub fn Cipher(comptime Crypto: type, comptime suite: CipherSuite) type {
    const Aead = switch (suite) {
        .ChaChaPoly_BLAKE2s => Crypto.ChaCha20Poly1305,
        .AESGCM_SHA256 => Crypto.Aes256Gcm,
    };

    return struct {
        /// AEAD tag size (Poly1305).
        pub const tag_size: usize = Aead.tag_length;

        /// Encrypts plaintext with ChaCha20-Poly1305.
        /// Output buffer must have space for plaintext + 16-byte tag.
        pub fn encrypt(
            key: *const [key_size]u8,
            nonce: u64,
            plaintext: []const u8,
            ad: []const u8,
            out: []u8,
        ) void {
            std.debug.assert(out.len >= plaintext.len + tag_size);

            var nonce_bytes: [Aead.nonce_length]u8 = [_]u8{0} ** Aead.nonce_length;
            mem.writeInt(u64, nonce_bytes[0..8], nonce, .little);

            var tag: [tag_size]u8 = undefined;
            Aead.encryptStatic(
                out[0..plaintext.len],
                &tag,
                plaintext,
                ad,
                nonce_bytes,
                key.*,
            );
            @memcpy(out[plaintext.len..][0..tag_size], &tag);
        }

        /// Decrypts ciphertext with ChaCha20-Poly1305.
        /// Returns error if authentication fails.
        pub fn decrypt(
            key: *const [key_size]u8,
            nonce: u64,
            ciphertext: []const u8,
            ad: []const u8,
            out: []u8,
        ) !void {
            if (ciphertext.len < tag_size) return error.InvalidCiphertext;
            const pt_len = ciphertext.len - tag_size;
            std.debug.assert(out.len >= pt_len);

            var nonce_bytes: [Aead.nonce_length]u8 = [_]u8{0} ** Aead.nonce_length;
            mem.writeInt(u64, nonce_bytes[0..8], nonce, .little);

            const tag = ciphertext[pt_len..][0..tag_size].*;
            Aead.decryptStatic(
                out[0..pt_len],
                ciphertext[0..pt_len],
                tag,
                ad,
                nonce_bytes,
                key.*,
            ) catch {
                return error.DecryptionFailed;
            };
        }

        /// Encrypts with zero nonce (for Noise handshake).
        pub fn encryptWithAd(key: *const Key, ad: []const u8, plaintext: []const u8, out: []u8) void {
            encrypt(key.asBytes(), 0, plaintext, ad, out);
        }

        /// Decrypts with zero nonce (for Noise handshake).
        pub fn decryptWithAd(key: *const Key, ad: []const u8, ciphertext: []const u8, out: []u8) !void {
            try decrypt(key.asBytes(), 0, ciphertext, ad, out);
        }
    };
}

// =============================================================================
// Tests
// =============================================================================

const TestCrypto = @import("test_crypto.zig");
const TestCipher = Cipher(TestCrypto, .ChaChaPoly_BLAKE2s);

test "encrypt decrypt roundtrip" {
    const key = [_]u8{0} ** key_size;
    const plaintext = "Hello, ChaCha20-Poly1305!";
    const ad = "additional data";

    var ciphertext: [plaintext.len + TestCipher.tag_size]u8 = undefined;
    TestCipher.encrypt(&key, 0, plaintext, ad, &ciphertext);

    var decrypted: [plaintext.len]u8 = undefined;
    try TestCipher.decrypt(&key, 0, &ciphertext, ad, &decrypted);
    try std.testing.expectEqualSlices(u8, plaintext, &decrypted);
}

test "wrong key fails" {
    const key1 = [_]u8{0} ** key_size;
    var key2 = [_]u8{0} ** key_size;
    key2[0] = 1;

    const plaintext = "secret";
    var ciphertext: [plaintext.len + TestCipher.tag_size]u8 = undefined;
    TestCipher.encrypt(&key1, 0, plaintext, "", &ciphertext);

    var decrypted: [plaintext.len]u8 = undefined;
    try std.testing.expectError(error.DecryptionFailed, TestCipher.decrypt(&key2, 0, &ciphertext, "", &decrypted));
}

test "different nonces produce different ciphertext" {
    const key = [_]u8{0} ** key_size;
    const plaintext = "hello";

    var ct1: [plaintext.len + TestCipher.tag_size]u8 = undefined;
    var ct2: [plaintext.len + TestCipher.tag_size]u8 = undefined;
    TestCipher.encrypt(&key, 0, plaintext, "", &ct1);
    TestCipher.encrypt(&key, 1, plaintext, "", &ct2);

    try std.testing.expect(!mem.eql(u8, &ct1, &ct2));
}

test "large data" {
    const key = [_]u8{0} ** key_size;
    const plaintext = [_]u8{0xAB} ** 4096;

    var ciphertext: [plaintext.len + TestCipher.tag_size]u8 = undefined;
    TestCipher.encrypt(&key, 42, &plaintext, "", &ciphertext);

    var decrypted: [plaintext.len]u8 = undefined;
    try TestCipher.decrypt(&key, 42, &ciphertext, "", &decrypted);
    try std.testing.expectEqualSlices(u8, &plaintext, &decrypted);
}
