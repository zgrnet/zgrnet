//! ChaCha20-Poly1305 AEAD cipher.
//!
//! Backend auto-selection based on architecture:
//! - ARM64: BoringSSL assembly (~13 Gbps)
//! - x86_64: SIMD-optimized Zig (~10 Gbps)
//! - Other: Pure Zig std.crypto (~6 Gbps)
//!
//! Override via `-Dbackend=asm|simd|zig`

const std = @import("std");
const build_options = @import("build_options");
const builtin = @import("builtin");
const crypto = std.crypto;
const mem = std.mem;

const keypair = @import("keypair.zig");
pub const Key = keypair.Key;
pub const key_size = keypair.key_size;

/// AEAD tag size (Poly1305).
pub const tag_size: usize = 16;

/// Backend selection.
pub const Backend = enum {
    /// ARM64 assembly - fastest on ARM64 (~13 Gbps)
    aarch64_asm,
    /// x86_64 AVX2/SSE4.1 assembly - fastest on x86_64 (~12 Gbps)
    x86_64_asm,
    /// SIMD-optimized Zig (~10 Gbps, experimental)
    simd_zig,
    /// Pure Zig using std.crypto - portable (~6 Gbps)
    native_zig,
};

/// Backend selection from build options
pub const backend: Backend = @enumFromInt(@intFromEnum(build_options.backend));

// =============================================================================
// ASM Backends (ARM64 and x86_64 share same C interface)
// =============================================================================

const asm_backend = struct {
    // C functions from wrapper (same interface for ARM64 and x86_64)
    extern fn aead_seal_with_ad(out: [*]u8, key: [*]const u8, nonce: u64, plaintext: [*]const u8, plaintext_len: usize, ad: [*]const u8, ad_len: usize) void;
    extern fn aead_open_with_ad(out: [*]u8, key: [*]const u8, nonce: u64, ciphertext: [*]const u8, ciphertext_len: usize, ad: [*]const u8, ad_len: usize) c_int;

    fn encrypt(key: *const [key_size]u8, nonce: u64, plaintext: []const u8, ad: []const u8, out: []u8) void {
        aead_seal_with_ad(out.ptr, key, nonce, plaintext.ptr, plaintext.len, ad.ptr, ad.len);
    }

    fn decrypt(key: *const [key_size]u8, nonce: u64, ciphertext: []const u8, ad: []const u8, out: []u8) !void {
        if (ciphertext.len < tag_size) return error.InvalidCiphertext;
        const ret = aead_open_with_ad(out.ptr, key, nonce, ciphertext.ptr, ciphertext.len, ad.ptr, ad.len);
        if (ret != 0) return error.DecryptionFailed;
    }
};

// =============================================================================
// SIMD-optimized Zig Backend (for x86_64)
// =============================================================================

const simd = @import("chacha20_poly1305/simd.zig");

const simd_backend = struct {
    fn encrypt(key: *const [key_size]u8, nonce: u64, plaintext: []const u8, ad: []const u8, out: []u8) void {
        simd.encrypt(key, nonce, plaintext, ad, out);
    }

    fn decrypt(key: *const [key_size]u8, nonce: u64, ciphertext: []const u8, ad: []const u8, out: []u8) !void {
        try simd.decrypt(key, nonce, ciphertext, ad, out);
    }
};

// =============================================================================
// Pure Zig Backend (portable)
// =============================================================================

const native = struct {
    fn encrypt(key: *const [key_size]u8, nonce: u64, plaintext: []const u8, ad: []const u8, out: []u8) void {
        std.debug.assert(out.len >= plaintext.len + tag_size);

        var nonce_bytes: [12]u8 = [_]u8{0} ** 12;
        mem.writeInt(u64, nonce_bytes[0..8], nonce, .little);

        // Use std.crypto ChaCha20-Poly1305
        const aead = crypto.aead.chacha_poly.ChaCha20Poly1305;
        var tag: [tag_size]u8 = undefined;
        aead.encrypt(out[0..plaintext.len], &tag, plaintext, ad, nonce_bytes, key.*);
        @memcpy(out[plaintext.len..][0..tag_size], &tag);
    }

    fn decrypt(key: *const [key_size]u8, nonce: u64, ciphertext: []const u8, ad: []const u8, out: []u8) !void {
        if (ciphertext.len < tag_size) return error.InvalidCiphertext;
        const pt_len = ciphertext.len - tag_size;
        std.debug.assert(out.len >= pt_len);

        var nonce_bytes: [12]u8 = [_]u8{0} ** 12;
        mem.writeInt(u64, nonce_bytes[0..8], nonce, .little);

        const aead = crypto.aead.chacha_poly.ChaCha20Poly1305;
        const tag = ciphertext[pt_len..][0..tag_size];
        aead.decrypt(out[0..pt_len], ciphertext[0..pt_len], tag.*, ad, nonce_bytes, key.*) catch {
            return error.DecryptionFailed;
        };
    }
};

// =============================================================================
// Public API
// =============================================================================

/// Encrypts plaintext with ChaCha20-Poly1305.
/// Output buffer must have space for plaintext + 16-byte tag.
pub fn encrypt(
    key: *const [key_size]u8,
    nonce: u64,
    plaintext: []const u8,
    ad: []const u8,
    out: []u8,
) void {
    switch (backend) {
        .aarch64_asm, .x86_64_asm => asm_backend.encrypt(key, nonce, plaintext, ad, out),
        .simd_zig => simd_backend.encrypt(key, nonce, plaintext, ad, out),
        .native_zig => native.encrypt(key, nonce, plaintext, ad, out),
    }
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
    switch (backend) {
        .aarch64_asm, .x86_64_asm => try asm_backend.decrypt(key, nonce, ciphertext, ad, out),
        .simd_zig => try simd_backend.decrypt(key, nonce, ciphertext, ad, out),
        .native_zig => try native.decrypt(key, nonce, ciphertext, ad, out),
    }
}

/// Encrypts with zero nonce (for Noise handshake).
pub fn encryptWithAd(key: *const Key, ad: []const u8, plaintext: []const u8, out: []u8) void {
    encrypt(key.asBytes(), 0, plaintext, ad, out);
}

/// Decrypts with zero nonce (for Noise handshake).
pub fn decryptWithAd(key: *const Key, ad: []const u8, ciphertext: []const u8, out: []u8) !void {
    try decrypt(key.asBytes(), 0, ciphertext, ad, out);
}

/// Returns the name of the active backend for debugging.
pub fn backendName() []const u8 {
    return switch (backend) {
        .aarch64_asm => "ARM64 ASM",
        .x86_64_asm => "x86_64 AVX2/SSE4.1 ASM",
        .simd_zig => "SIMD Zig (experimental)",
        .native_zig => "Native Zig (std.crypto)",
    };
}

// =============================================================================
// Tests
// =============================================================================

test "encrypt decrypt roundtrip" {
    const key = [_]u8{0} ** key_size;
    const plaintext = "Hello, ChaCha20-Poly1305!";
    const ad = "additional data";

    var ciphertext: [plaintext.len + tag_size]u8 = undefined;
    encrypt(&key, 0, plaintext, ad, &ciphertext);

    var decrypted: [plaintext.len]u8 = undefined;
    try decrypt(&key, 0, &ciphertext, ad, &decrypted);
    try std.testing.expectEqualSlices(u8, plaintext, &decrypted);
}

test "wrong key fails" {
    const key1 = [_]u8{0} ** key_size;
    var key2 = [_]u8{0} ** key_size;
    key2[0] = 1;

    const plaintext = "secret";
    var ciphertext: [plaintext.len + tag_size]u8 = undefined;
    encrypt(&key1, 0, plaintext, "", &ciphertext);

    var decrypted: [plaintext.len]u8 = undefined;
    try std.testing.expectError(error.DecryptionFailed, decrypt(&key2, 0, &ciphertext, "", &decrypted));
}

test "different nonces produce different ciphertext" {
    const key = [_]u8{0} ** key_size;
    const plaintext = "hello";

    var ct1: [plaintext.len + tag_size]u8 = undefined;
    var ct2: [plaintext.len + tag_size]u8 = undefined;
    encrypt(&key, 0, plaintext, "", &ct1);
    encrypt(&key, 1, plaintext, "", &ct2);

    try std.testing.expect(!mem.eql(u8, &ct1, &ct2));
}

test "large data" {
    const key = [_]u8{0} ** key_size;
    const plaintext = [_]u8{0xAB} ** 4096;

    var ciphertext: [plaintext.len + tag_size]u8 = undefined;
    encrypt(&key, 42, &plaintext, "", &ciphertext);

    var decrypted: [plaintext.len]u8 = undefined;
    try decrypt(&key, 42, &ciphertext, "", &decrypted);
    try std.testing.expectEqualSlices(u8, &plaintext, &decrypted);
}
