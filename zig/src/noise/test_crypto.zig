//! Test crypto implementation using std.crypto.
//! Conforms to trait.crypto interface. Only used in tests.

const std = @import("std");

pub const Blake2s256 = struct {
    pub const digest_length = 32;
    pub const block_length = 64;

    inner: std.crypto.hash.blake2.Blake2s256,

    pub fn init() @This() {
        return .{ .inner = std.crypto.hash.blake2.Blake2s256.init(.{}) };
    }
    pub fn update(self: *@This(), data: []const u8) void {
        self.inner.update(data);
    }
    pub fn final(self: *@This()) [32]u8 {
        var out: [32]u8 = undefined;
        self.inner.final(&out);
        return out;
    }
    pub fn hash(data: []const u8, out: *[32]u8, opts: anytype) void {
        _ = opts;
        std.crypto.hash.blake2.Blake2s256.hash(data, out, .{});
    }
};

pub const ChaCha20Poly1305 = struct {
    pub const key_length = 32;
    pub const nonce_length = 12;
    pub const tag_length = 16;

    const Aead = std.crypto.aead.chacha_poly.ChaCha20Poly1305;

    pub fn encryptStatic(ct: []u8, tag: *[16]u8, pt: []const u8, aad: []const u8, nonce: [12]u8, key: [32]u8) void {
        Aead.encrypt(ct[0..pt.len], tag, pt, aad, nonce, key);
    }
    pub fn decryptStatic(pt: []u8, ct: []const u8, tag: [16]u8, aad: []const u8, nonce: [12]u8, key: [32]u8) error{AuthenticationFailed}!void {
        Aead.decrypt(pt[0..ct.len], ct, tag, aad, nonce, key) catch return error.AuthenticationFailed;
    }
};

pub const Sha256 = struct {
    pub const digest_length = 32;
    pub const block_length = 64;

    inner: std.crypto.hash.sha2.Sha256,

    pub fn init() @This() {
        return .{ .inner = std.crypto.hash.sha2.Sha256.init(.{}) };
    }
    pub fn update(self: *@This(), data: []const u8) void {
        self.inner.update(data);
    }
    pub fn final(self: *@This()) [32]u8 {
        var out: [32]u8 = undefined;
        self.inner.final(&out);
        return out;
    }
    pub fn hash(data: []const u8, out: *[32]u8, opts: anytype) void {
        _ = opts;
        std.crypto.hash.sha2.Sha256.hash(data, out, .{});
    }
};

pub const Aes128Gcm = struct {
    pub const key_length = 16;
    pub const nonce_length = 12;
    pub const tag_length = 16;

    const Aead = std.crypto.aead.aes_gcm.Aes128Gcm;

    pub fn encryptStatic(ct: []u8, tag: *[16]u8, pt: []const u8, aad: []const u8, nonce: [12]u8, key: [16]u8) void {
        Aead.encrypt(ct[0..pt.len], tag, pt, aad, nonce, key);
    }
    pub fn decryptStatic(pt: []u8, ct: []const u8, tag: [16]u8, aad: []const u8, nonce: [12]u8, key: [16]u8) error{AuthenticationFailed}!void {
        Aead.decrypt(pt[0..ct.len], ct, tag, aad, nonce, key) catch return error.AuthenticationFailed;
    }
};

pub const Rng = struct {
    pub fn fill(buf: []u8) void {
        std.crypto.random.bytes(buf);
    }
};

pub const X25519 = struct {
    pub const secret_length = 32;
    pub const public_length = 32;

    pub const KeyPair = struct {
        secret_key: [32]u8,
        public_key: [32]u8,

        pub fn generateDeterministic(seed: [32]u8) !@This() {
            const kp = std.crypto.dh.X25519.KeyPair.generateDeterministic(seed) catch
                return error.IdentityElement;
            return .{ .secret_key = kp.secret_key, .public_key = kp.public_key };
        }
    };

    pub fn scalarmult(sk: [32]u8, pk: [32]u8) ![32]u8 {
        return std.crypto.dh.X25519.scalarmult(sk, pk) catch
            return error.WeakPublicKey;
    }
};
