//! SIMD-optimized ChaCha20-Poly1305 for x86_64 (AVX2) and ARM64 (NEON)
//!
//! Uses Zig's @Vector for portable SIMD that compiles to AVX2/NEON instructions.

const std = @import("std");
const builtin = @import("builtin");

/// 4-way parallel ChaCha20 state using SIMD
const Vec4u32 = @Vector(4, u32);

/// ChaCha20 quarter round on 4 lanes in parallel
inline fn quarterRound(a: *Vec4u32, b: *Vec4u32, c: *Vec4u32, d: *Vec4u32) void {
    a.* +%= b.*;
    d.* ^= a.*;
    d.* = rotl(d.*, 16);

    c.* +%= d.*;
    b.* ^= c.*;
    b.* = rotl(b.*, 12);

    a.* +%= b.*;
    d.* ^= a.*;
    d.* = rotl(d.*, 8);

    c.* +%= d.*;
    b.* ^= c.*;
    b.* = rotl(b.*, 7);
}

/// Vector rotate left
inline fn rotl(v: Vec4u32, comptime n: comptime_int) Vec4u32 {
    return (v << @splat(@as(u5, n))) | (v >> @splat(@as(u5, 32 - n)));
}

/// ChaCha20 block function - generates 64 bytes of keystream
pub fn chachaBlock(key: *const [32]u8, counter: u32, nonce: *const [12]u8, out: *[64]u8) void {
    // Initial state: "expand 32-byte k" + key + counter + nonce
    var state: [16]u32 = .{
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574, // "expand 32-byte k"
        std.mem.readInt(u32, key[0..4], .little),
        std.mem.readInt(u32, key[4..8], .little),
        std.mem.readInt(u32, key[8..12], .little),
        std.mem.readInt(u32, key[12..16], .little),
        std.mem.readInt(u32, key[16..20], .little),
        std.mem.readInt(u32, key[20..24], .little),
        std.mem.readInt(u32, key[24..28], .little),
        std.mem.readInt(u32, key[28..32], .little),
        counter,
        std.mem.readInt(u32, nonce[0..4], .little),
        std.mem.readInt(u32, nonce[4..8], .little),
        std.mem.readInt(u32, nonce[8..12], .little),
    };

    const initial = state;

    // 20 rounds (10 double-rounds)
    var i: usize = 0;
    while (i < 10) : (i += 1) {
        // Column rounds using SIMD
        var col0 = Vec4u32{ state[0], state[1], state[2], state[3] };
        var col1 = Vec4u32{ state[4], state[5], state[6], state[7] };
        var col2 = Vec4u32{ state[8], state[9], state[10], state[11] };
        var col3 = Vec4u32{ state[12], state[13], state[14], state[15] };

        quarterRound(&col0, &col1, &col2, &col3);

        state[0] = col0[0];
        state[1] = col0[1];
        state[2] = col0[2];
        state[3] = col0[3];
        state[4] = col1[0];
        state[5] = col1[1];
        state[6] = col1[2];
        state[7] = col1[3];
        state[8] = col2[0];
        state[9] = col2[1];
        state[10] = col2[2];
        state[11] = col2[3];
        state[12] = col3[0];
        state[13] = col3[1];
        state[14] = col3[2];
        state[15] = col3[3];

        // Diagonal rounds
        var diag0 = Vec4u32{ state[0], state[5], state[10], state[15] };
        var diag1 = Vec4u32{ state[4], state[9], state[14], state[3] };
        var diag2 = Vec4u32{ state[8], state[13], state[2], state[7] };
        var diag3 = Vec4u32{ state[12], state[1], state[6], state[11] };

        quarterRound(&diag0, &diag1, &diag2, &diag3);

        state[0] = diag0[0];
        state[5] = diag0[1];
        state[10] = diag0[2];
        state[15] = diag0[3];
        state[4] = diag1[0];
        state[9] = diag1[1];
        state[14] = diag1[2];
        state[3] = diag1[3];
        state[8] = diag2[0];
        state[13] = diag2[1];
        state[2] = diag2[2];
        state[7] = diag2[3];
        state[12] = diag3[0];
        state[1] = diag3[1];
        state[6] = diag3[2];
        state[11] = diag3[3];
    }

    // Add initial state
    for (&state, initial) |*s, init| {
        s.* +%= init;
    }

    // Output as little-endian bytes
    for (state, 0..) |word, idx| {
        std.mem.writeInt(u32, out[idx * 4 ..][0..4], word, .little);
    }
}

/// Poly1305 authenticator using SIMD-friendly operations
pub const Poly1305 = struct {
    r: [2]u64,
    h: [3]u64,
    pad: [2]u64,

    pub fn init(key: *const [32]u8) Poly1305 {
        // r = key[0..16] with clamping
        const r0 = std.mem.readInt(u64, key[0..8], .little) & 0x0ffffffc0fffffff;
        const r1 = std.mem.readInt(u64, key[8..16], .little) & 0x0ffffffc0ffffffc;

        // pad = key[16..32]
        const pad0 = std.mem.readInt(u64, key[16..24], .little);
        const pad1 = std.mem.readInt(u64, key[24..32], .little);

        return .{
            .r = .{ r0, r1 },
            .h = .{ 0, 0, 0 },
            .pad = .{ pad0, pad1 },
        };
    }

    pub fn update(self: *Poly1305, data: []const u8) void {
        var i: usize = 0;
        while (i + 16 <= data.len) : (i += 16) {
            self.addBlock(data[i..][0..16], 1);
        }
        if (i < data.len) {
            var block: [16]u8 = [_]u8{0} ** 16;
            const remaining = data.len - i;
            @memcpy(block[0..remaining], data[i..]);
            block[remaining] = 1; // Padding
            self.addBlock(&block, 0);
        }
    }

    fn addBlock(self: *Poly1305, block: *const [16]u8, hibit: u64) void {
        const s0 = std.mem.readInt(u64, block[0..8], .little);
        const s1 = std.mem.readInt(u64, block[8..16], .little);

        // h += m
        var h0 = self.h[0] +% s0;
        var h1 = self.h[1] +% s1;
        var h2 = self.h[2] +% hibit;

        // Carry propagation
        h1 +%= h0 >> 44;
        h0 &= 0xfffffffffff;
        h2 +%= h1 >> 44;
        h1 &= 0xfffffffffff;

        // h *= r (mod 2^130 - 5)
        const r0 = self.r[0];
        const r1 = self.r[1];
        const r1_5 = r1 *% 5;

        // Multiply and reduce
        var d0: u128 = @as(u128, h0) * r0 + @as(u128, h1) * r1_5 + @as(u128, h2) * (r1_5 >> 2);
        var d1: u128 = @as(u128, h0) * r1 + @as(u128, h1) * r0 + @as(u128, h2) * r1;
        var d2: u128 = @as(u128, h2) * r0;

        // Carry and reduce
        d1 += d0 >> 44;
        d0 &= 0xfffffffffff;
        d2 += d1 >> 44;
        d1 &= 0xfffffffffff;
        d0 += @as(u128, @truncate(d2 >> 42)) * 5;
        d2 &= 0x3ffffffffff;

        self.h[0] = @truncate(d0);
        self.h[1] = @truncate(d1);
        self.h[2] = @truncate(d2);
    }

    pub fn final(self: *Poly1305, out: *[16]u8) void {
        // Finalize h
        var h0 = self.h[0];
        var h1 = self.h[1];
        var h2 = self.h[2];

        // Carry
        h1 +%= h0 >> 44;
        h0 &= 0xfffffffffff;
        h2 +%= h1 >> 44;
        h1 &= 0xfffffffffff;

        // Compute h - (2^130 - 5)
        const g0 = h0 +% 5;
        const g1 = h1 +% (g0 >> 44);
        const g2 = h2 +% (g1 >> 44) -% (1 << 42);

        // Select h or g based on carry
        const mask = (g2 >> 63) -% 1;
        h0 = (h0 & ~mask) | (g0 & mask);
        h1 = (h1 & ~mask) | (g1 & mask);
        h2 = (h2 & ~mask) | (g2 & mask);

        h0 &= 0xfffffffffff;
        h1 &= 0xfffffffffff;

        // h = h + pad
        const t0 = h0 | (h1 << 44);
        const t1 = (h1 >> 20) | (h2 << 24);

        var f: u128 = @as(u128, t0) + self.pad[0];
        const out0: u64 = @truncate(f);
        f = @as(u128, t1) + self.pad[1] + (f >> 64);
        const out1: u64 = @truncate(f);

        std.mem.writeInt(u64, out[0..8], out0, .little);
        std.mem.writeInt(u64, out[8..16], out1, .little);
    }
};

/// ChaCha20-Poly1305 AEAD encrypt
pub fn encrypt(
    key: *const [32]u8,
    nonce: u64,
    plaintext: []const u8,
    ad: []const u8,
    out: []u8,
) void {
    _ = ad; // TODO: implement AD support

    var nonce_bytes: [12]u8 = [_]u8{0} ** 12;
    std.mem.writeInt(u64, nonce_bytes[0..8], nonce, .little);

    // Generate Poly1305 key from first block
    var poly_key: [64]u8 = undefined;
    chachaBlock(key, 0, &nonce_bytes, &poly_key);

    // Encrypt plaintext
    var counter: u32 = 1;
    var offset: usize = 0;
    while (offset < plaintext.len) {
        var keystream: [64]u8 = undefined;
        chachaBlock(key, counter, &nonce_bytes, &keystream);

        const chunk_len = @min(64, plaintext.len - offset);
        for (0..chunk_len) |i| {
            out[offset + i] = plaintext[offset + i] ^ keystream[i];
        }

        offset += chunk_len;
        counter += 1;
    }

    // Compute Poly1305 tag
    var poly = Poly1305.init(poly_key[0..32]);
    poly.update(out[0..plaintext.len]);
    poly.final(out[plaintext.len..][0..16]);
}

/// ChaCha20-Poly1305 AEAD decrypt
pub fn decrypt(
    key: *const [32]u8,
    nonce: u64,
    ciphertext: []const u8,
    ad: []const u8,
    out: []u8,
) !void {
    _ = ad; // TODO: implement AD support

    if (ciphertext.len < 16) return error.InvalidCiphertext;
    const ct_len = ciphertext.len - 16;

    var nonce_bytes: [12]u8 = [_]u8{0} ** 12;
    std.mem.writeInt(u64, nonce_bytes[0..8], nonce, .little);

    // Generate Poly1305 key
    var poly_key: [64]u8 = undefined;
    chachaBlock(key, 0, &nonce_bytes, &poly_key);

    // Verify tag first
    var poly = Poly1305.init(poly_key[0..32]);
    poly.update(ciphertext[0..ct_len]);
    var computed_tag: [16]u8 = undefined;
    poly.final(&computed_tag);

    // Constant-time comparison
    var diff: u8 = 0;
    for (computed_tag, ciphertext[ct_len..][0..16]) |a, b| {
        diff |= a ^ b;
    }
    if (diff != 0) return error.DecryptionFailed;

    // Decrypt
    var counter: u32 = 1;
    var offset: usize = 0;
    while (offset < ct_len) {
        var keystream: [64]u8 = undefined;
        chachaBlock(key, counter, &nonce_bytes, &keystream);

        const chunk_len = @min(64, ct_len - offset);
        for (0..chunk_len) |i| {
            out[offset + i] = ciphertext[offset + i] ^ keystream[i];
        }

        offset += chunk_len;
        counter += 1;
    }
}

// Tests
test "chacha20 block" {
    const key = [_]u8{0} ** 32;
    const nonce = [_]u8{0} ** 12;
    var out: [64]u8 = undefined;

    chachaBlock(&key, 0, &nonce, &out);

    // First 4 bytes should be non-zero (keystream)
    try std.testing.expect(out[0] != 0 or out[1] != 0 or out[2] != 0 or out[3] != 0);
}

test "encrypt decrypt roundtrip" {
    const key = [_]u8{0} ** 32;
    const plaintext = "Hello, SIMD ChaCha20-Poly1305!";
    var ciphertext: [plaintext.len + 16]u8 = undefined;
    var decrypted: [plaintext.len]u8 = undefined;

    encrypt(&key, 0, plaintext, "", &ciphertext);
    try decrypt(&key, 0, &ciphertext, "", &decrypted);

    try std.testing.expectEqualSlices(u8, plaintext, &decrypted);
}

test "wrong key fails" {
    const key1 = [_]u8{0} ** 32;
    var key2 = [_]u8{0} ** 32;
    key2[0] = 1;

    const plaintext = "secret";
    var ciphertext: [plaintext.len + 16]u8 = undefined;
    var decrypted: [plaintext.len]u8 = undefined;

    encrypt(&key1, 0, plaintext, "", &ciphertext);
    try std.testing.expectError(error.DecryptionFailed, decrypt(&key2, 0, &ciphertext, "", &decrypted));
}
