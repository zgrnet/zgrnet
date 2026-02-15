//! CipherState and SymmetricState for Noise Protocol.

const std = @import("std");
const mem = std.mem;

const keypair = @import("keypair.zig");
const crypto_mod = @import("crypto.zig");

const Key = keypair.Key;
const key_size = keypair.key_size;
const hash_size = crypto_mod.hash_size;
const tag_size = crypto_mod.tag_size;

/// Instantiate state types for a given Crypto implementation and cipher suite.
pub fn State(comptime Crypto: type, comptime suite: crypto_mod.CipherSuite) type {
    const cipher = @import("cipher.zig").Cipher(Crypto, suite);
    const c = crypto_mod.CryptoMod(Crypto, suite);

    return struct {
        /// Manages encryption for one direction of communication.
        ///
        /// WARNING: Uses auto-incrementing nonces. Only suitable for ordered,
        /// reliable transport (like TCP or within Noise handshake).
        /// For unreliable transport (UDP), use Session with explicit nonces.
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

            /// Decrypts ciphertext using an explicit nonce.
            /// The internal nonce counter is NOT modified.
            ///
            /// Use this for unreliable transport (UDP) where packets may arrive
            /// out of order or be lost, causing the auto-incrementing nonce to desync.
            /// The caller is responsible for obtaining the nonce from the packet header.
            pub fn decryptWithNonce(self: *const CipherState, nonce: u64, ciphertext: []const u8, ad: []const u8, out: []u8) !void {
                try cipher.decrypt(self.key.asBytes(), nonce, ciphertext, ad, out);
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
    };
}

// Tests
const TestCrypto = @import("test_crypto.zig");
const TestState = State(TestCrypto, .ChaChaPoly_BLAKE2s);
const TestCipherState = TestState.CipherState;
const TestSymmetricState = TestState.SymmetricState;

test "cipher state" {
    const key = Key.fromBytes([_]u8{42} ** key_size);
    var cs = TestCipherState.init(key);
    try std.testing.expectEqual(@as(u64, 0), cs.getNonce());
    try std.testing.expect(cs.getKey().eql(key));
}

test "cipher state encrypt decrypt" {
    const key = Key.fromBytes([_]u8{42} ** key_size);
    var cs1 = TestCipherState.init(key);
    var cs2 = TestCipherState.init(key);

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
    var cs = TestCipherState.init(key);

    var i: u64 = 0;
    while (i < 10) : (i += 1) {
        try std.testing.expectEqual(i, cs.getNonce());
        var buf: [4 + tag_size]u8 = undefined;
        cs.encrypt("test", "", &buf);
    }
}

test "cipher state set nonce" {
    const key = Key.fromBytes([_]u8{0} ** key_size);
    var cs = TestCipherState.init(key);
    cs.setNonce(100);
    try std.testing.expectEqual(@as(u64, 100), cs.getNonce());
}

test "decrypt with nonce packet loss" {
    const key = Key.fromBytes([_]u8{42} ** key_size);
    var cs1 = TestCipherState.init(key);
    var cs2 = TestCipherState.init(key);

    // Encrypt 3 messages (nonces 0, 1, 2)
    const msg0 = "message 0";
    const msg1 = "message 1";
    const msg2 = "message 2";
    var ct0: [msg0.len + tag_size]u8 = undefined;
    var ct1: [msg1.len + tag_size]u8 = undefined;
    var ct2: [msg2.len + tag_size]u8 = undefined;
    cs1.encrypt(msg0, "", &ct0);
    cs1.encrypt(msg1, "", &ct1);
    cs1.encrypt(msg2, "", &ct2);

    // Receiver gets ct0 normally.
    var pt0: [msg0.len]u8 = undefined;
    try cs2.decrypt(&ct0, "", &pt0);
    try std.testing.expectEqualSlices(u8, msg0, &pt0);

    // ct1 lost — receiver tries ct2 with auto-nonce (1), fails.
    var pt_fail: [msg2.len]u8 = undefined;
    try std.testing.expectError(error.DecryptionFailed, cs2.decrypt(&ct2, "", &pt_fail));

    // decryptWithNonce recovers ct2 with explicit nonce 2.
    var pt2: [msg2.len]u8 = undefined;
    try cs2.decryptWithNonce(2, &ct2, "", &pt2);
    try std.testing.expectEqualSlices(u8, msg2, &pt2);

    // Also recover lost ct1.
    var pt1: [msg1.len]u8 = undefined;
    try cs2.decryptWithNonce(1, &ct1, "", &pt1);
    try std.testing.expectEqualSlices(u8, msg1, &pt1);
}

test "decrypt with nonce does not modify counter" {
    const key = Key.fromBytes([_]u8{42} ** key_size);
    var cs1 = TestCipherState.init(key);
    const cs2 = TestCipherState.init(key);

    var ct: [4 + tag_size]u8 = undefined;
    cs1.encrypt("test", "", &ct);

    const nonce_before = cs2.getNonce();
    var pt: [4]u8 = undefined;
    try cs2.decryptWithNonce(0, &ct, "", &pt);
    try std.testing.expectEqual(nonce_before, cs2.getNonce());
}

test "decrypt with nonce wrong ad" {
    const key = Key.fromBytes([_]u8{42} ** key_size);
    var cs1 = TestCipherState.init(key);
    const cs2 = TestCipherState.init(key);

    var ct: [5 + tag_size]u8 = undefined;
    cs1.encrypt("hello", "correct ad", &ct);

    var pt: [5]u8 = undefined;
    try std.testing.expectError(error.DecryptionFailed, cs2.decryptWithNonce(0, &ct, "wrong ad", &pt));
    try cs2.decryptWithNonce(0, &ct, "correct ad", &pt);
    try std.testing.expectEqualSlices(u8, "hello", &pt);
}

test "symmetric state new" {
    // Short name
    const ss1 = TestSymmetricState.init("Noise_IK");
    try std.testing.expect(!ss1.chaining_key.isZero());

    // Long name
    const ss2 = TestSymmetricState.init("Noise_IK_25519_ChaChaPoly_BLAKE2s");
    try std.testing.expect(!ss2.chaining_key.isZero());
}

test "symmetric state mix hash" {
    var ss = TestSymmetricState.init("Test");
    const initial = ss.hash;
    ss.mixHash("data");
    try std.testing.expect(!mem.eql(u8, &ss.hash, &initial));
}

test "symmetric state mix key" {
    var ss = TestSymmetricState.init("Test");
    const initial = ss.chaining_key;
    const k = ss.mixKey("input");
    try std.testing.expect(!ss.chaining_key.eql(initial));
    try std.testing.expect(!k.isZero());
}

test "symmetric state mix key and hash" {
    var ss = TestSymmetricState.init("Test");
    const initial_ck = ss.chaining_key;
    const initial_h = ss.hash;

    const k = ss.mixKeyAndHash("input");

    try std.testing.expect(!ss.chaining_key.eql(initial_ck));
    try std.testing.expect(!mem.eql(u8, &ss.hash, &initial_h));
    try std.testing.expect(!k.isZero());
}

test "symmetric state encrypt decrypt and hash" {
    var ss1 = TestSymmetricState.init("Test");
    var ss2 = TestSymmetricState.init("Test");

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
    var ss = TestSymmetricState.init("Test");
    _ = ss.mixKey("input");

    const cs1, const cs2 = ss.split();
    try std.testing.expect(!cs1.key.eql(cs2.key));
}

test "symmetric state clone" {
    var ss = TestSymmetricState.init("Test");
    ss.mixHash("data");

    const cloned = ss.clone();
    try std.testing.expect(ss.chaining_key.eql(cloned.chaining_key));
    try std.testing.expectEqualSlices(u8, &ss.hash, &cloned.hash);
}
