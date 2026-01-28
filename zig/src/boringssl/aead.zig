//! ChaCha20-Poly1305 AEAD using BoringSSL ARM64 assembly
const std = @import("std");

pub const KEY_LEN = 32;
pub const TAG_LEN = 16;

// C functions
extern fn aead_seal(out: [*]u8, key: [*]const u8, nonce: u64, plaintext: [*]const u8, plaintext_len: usize) void;
extern fn aead_open(out: [*]u8, key: [*]const u8, nonce: u64, ciphertext: [*]const u8, ciphertext_len: usize) c_int;

pub fn encrypt(key: *const [KEY_LEN]u8, nonce: u64, plaintext: []const u8, out: []u8) void {
    aead_seal(out.ptr, key, nonce, plaintext.ptr, plaintext.len);
}

pub fn decrypt(key: *const [KEY_LEN]u8, nonce: u64, ciphertext: []const u8, out: []u8) !void {
    if (ciphertext.len < TAG_LEN) return error.InvalidInput;
    const ret = aead_open(out.ptr, key, nonce, ciphertext.ptr, ciphertext.len);
    if (ret != 0) return error.AuthenticationFailed;
}
