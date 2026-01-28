//! CipherState and SymmetricState for Noise Protocol.

const std = @import("std");
const mem = std.mem;

const keypair = @import("keypair.zig");
const cipher = @import("cipher.zig");
const c = @import("crypto.zig");

const Key = keypair.Key;
const key_size = keypair.key_size;
const hash_size = c.hash_size;
const tag_size = c.tag_size;

/// Manages encryption for one direction of communication.
pub const CipherState = struct {
    key: Key,
    nonce: u64,

    pub fn init(key: Key) CipherState {
        return .{ .key = key, .nonce = 0 };
    }

    /// Encrypts plaintext and increments nonce.
    pub fn encrypt(self: *CipherState, plaintext: []const u8, ad: []const u8, out: []u8) void {
        cipher.encrypt(self.key.asBytes(), self.nonce, plaintext, ad, out);
        self.nonce += 1;
    }

    /// Decrypts ciphertext and increments nonce.
    pub fn decrypt(self: *CipherState, ciphertext: []const u8, ad: []const u8, out: []u8) !void {
        try cipher.decrypt(self.key.asBytes(), self.nonce, ciphertext, ad, out);
        self.nonce += 1;
    }

    /// Returns current nonce.
    pub fn getNonce(self: CipherState) u64 {
        return self.nonce;
    }

    /// Sets nonce (for testing).
    pub fn setNonce(self: *CipherState, n: u64) void {
        self.nonce = n;
    }

    /// Returns the key.
    pub fn getKey(self: CipherState) Key {
        return self.key;
    }
};

/// Holds the evolving state during a Noise handshake.
pub const SymmetricState = struct {
    chaining_key: Key,
    hash: [hash_size]u8,

    /// Creates a new SymmetricState with the protocol name.
    pub fn init(protocol_name: []const u8) SymmetricState {
        var chaining_key: [key_size]u8 = [_]u8{0} ** key_size;

        if (protocol_name.len <= hash_size) {
            @memcpy(chaining_key[0..protocol_name.len], protocol_name);
        } else {
            chaining_key = c.hash(&.{protocol_name});
        }

        return .{
            .chaining_key = Key.fromBytes(chaining_key),
            .hash = chaining_key,
        };
    }

    /// Mixes input into the chaining key.
    pub fn mixKey(self: *SymmetricState, input: []const u8) Key {
        const new_ck, const k = c.kdf2(&self.chaining_key, input);
        self.chaining_key = new_ck;
        return k;
    }

    /// Mixes data into the hash.
    pub fn mixHash(self: *SymmetricState, data: []const u8) void {
        self.hash = c.hash(&.{ &self.hash, data });
    }

    /// Mixes input into both chaining key and hash (for PSK).
    pub fn mixKeyAndHash(self: *SymmetricState, input: []const u8) Key {
        const ck, const temp, const k = c.kdf3(&self.chaining_key, input);
        self.chaining_key = ck;
        self.mixHash(temp.asBytes());
        return k;
    }

    /// Encrypts plaintext and updates hash.
    pub fn encryptAndHash(self: *SymmetricState, key: *const Key, plaintext: []const u8, out: []u8) void {
        cipher.encryptWithAd(key, &self.hash, plaintext, out);
        self.mixHash(out[0 .. plaintext.len + tag_size]);
    }

    /// Decrypts ciphertext and updates hash.
    pub fn decryptAndHash(self: *SymmetricState, key: *const Key, ciphertext: []const u8, out: []u8) !void {
        try cipher.decryptWithAd(key, &self.hash, ciphertext, out);
        self.mixHash(ciphertext);
    }

    /// Splits into two CipherStates for transport.
    pub fn split(self: *const SymmetricState) struct { CipherState, CipherState } {
        const keys = c.hkdf(&self.chaining_key, "", 2);
        return .{ CipherState.init(keys[0]), CipherState.init(keys[1]) };
    }

    /// Returns the current chaining key.
    pub fn getChainingKey(self: SymmetricState) Key {
        return self.chaining_key;
    }

    /// Returns the current hash.
    pub fn getHash(self: *const SymmetricState) *const [hash_size]u8 {
        return &self.hash;
    }

    /// Creates a copy of the state.
    pub fn clone(self: SymmetricState) SymmetricState {
        return self;
    }
};

// Tests
test "cipher state" {
    const key = Key.fromBytes([_]u8{42} ** key_size);
    var cs = CipherState.init(key);
    try std.testing.expectEqual(@as(u64, 0), cs.getNonce());
    try std.testing.expect(cs.getKey().eql(key));
}

test "cipher state encrypt decrypt" {
    const key = Key.fromBytes([_]u8{42} ** key_size);
    var cs1 = CipherState.init(key);
    var cs2 = CipherState.init(key);

    const plaintext = "hello, world!";
    var ciphertext: [plaintext.len + tag_size]u8 = undefined;
    cs1.encrypt(plaintext, "", &ciphertext);
    try std.testing.expectEqual(@as(u64, 1), cs1.getNonce());

    var decrypted: [plaintext.len]u8 = undefined;
    try cs2.decrypt(&ciphertext, "", &decrypted);
    try std.testing.expectEqual(@as(u64, 1), cs2.getNonce());
    try std.testing.expectEqualSlices(u8, plaintext, &decrypted);
}

test "cipher state nonce increment" {
    const key = Key.fromBytes([_]u8{0} ** key_size);
    var cs = CipherState.init(key);

    var i: u64 = 0;
    while (i < 10) : (i += 1) {
        try std.testing.expectEqual(i, cs.getNonce());
        var buf: [4 + tag_size]u8 = undefined;
        cs.encrypt("test", "", &buf);
    }
}

test "cipher state set nonce" {
    const key = Key.fromBytes([_]u8{0} ** key_size);
    var cs = CipherState.init(key);
    cs.setNonce(100);
    try std.testing.expectEqual(@as(u64, 100), cs.getNonce());
}

test "symmetric state new" {
    // Short name
    const ss1 = SymmetricState.init("Noise_IK");
    try std.testing.expect(!ss1.chaining_key.isZero());

    // Long name
    const ss2 = SymmetricState.init("Noise_IK_25519_ChaChaPoly_BLAKE2s");
    try std.testing.expect(!ss2.chaining_key.isZero());
}

test "symmetric state mix hash" {
    var ss = SymmetricState.init("Test");
    const initial = ss.hash;
    ss.mixHash("data");
    try std.testing.expect(!mem.eql(u8, &ss.hash, &initial));
}

test "symmetric state mix key" {
    var ss = SymmetricState.init("Test");
    const initial = ss.chaining_key;
    const k = ss.mixKey("input");
    try std.testing.expect(!ss.chaining_key.eql(initial));
    try std.testing.expect(!k.isZero());
}

test "symmetric state mix key and hash" {
    var ss = SymmetricState.init("Test");
    const initial_ck = ss.chaining_key;
    const initial_h = ss.hash;

    const k = ss.mixKeyAndHash("input");

    try std.testing.expect(!ss.chaining_key.eql(initial_ck));
    try std.testing.expect(!mem.eql(u8, &ss.hash, &initial_h));
    try std.testing.expect(!k.isZero());
}

test "symmetric state encrypt decrypt and hash" {
    var ss1 = SymmetricState.init("Test");
    var ss2 = SymmetricState.init("Test");

    const k1 = ss1.mixKey("key");
    const k2 = ss2.mixKey("key");
    try std.testing.expect(k1.eql(k2));

    const plaintext = "secret message";
    var ciphertext: [plaintext.len + tag_size]u8 = undefined;
    ss1.encryptAndHash(&k1, plaintext, &ciphertext);

    var decrypted: [plaintext.len]u8 = undefined;
    try ss2.decryptAndHash(&k2, &ciphertext, &decrypted);

    try std.testing.expectEqualSlices(u8, plaintext, &decrypted);
    try std.testing.expectEqualSlices(u8, &ss1.hash, &ss2.hash);
}

test "symmetric state split" {
    var ss = SymmetricState.init("Test");
    _ = ss.mixKey("input");

    const cs1, const cs2 = ss.split();
    try std.testing.expect(!cs1.key.eql(cs2.key));
}

test "symmetric state clone" {
    var ss = SymmetricState.init("Test");
    ss.mixHash("data");

    const cloned = ss.clone();
    try std.testing.expect(ss.chaining_key.eql(cloned.chaining_key));
    try std.testing.expectEqualSlices(u8, &ss.hash, &cloned.hash);
}
