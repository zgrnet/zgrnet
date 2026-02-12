//! Session management for transport phase.
//!
//! NOT thread-safe. Caller must provide external synchronization
//! and pass timestamps explicitly. No std.Thread or std.time dependencies.

const std = @import("std");
const mem = std.mem;

const keypair = @import("keypair.zig");
const replay_mod = @import("replay.zig");
const crypto_mod = @import("crypto.zig");

pub const Key = keypair.Key;
pub const key_size = keypair.key_size;
pub const ReplayFilter = replay_mod.ReplayFilter;
pub const tag_size = crypto_mod.tag_size;

/// Session state.
pub const SessionState = enum {
    handshaking,
    established,
    expired,
};

/// Session timeout in nanoseconds (180 seconds).
pub const session_timeout_ns: u64 = 180 * std.time.ns_per_s;

/// Maximum nonce value.
pub const max_nonce: u64 = std.math.maxInt(u64) - 1;

/// Session errors.
pub const SessionError = error{
    NotEstablished,
    ReplayDetected,
    NonceExhausted,
    EncryptFailed,
    DecryptFailed,
    AuthenticationFailed,
};

/// Configuration for creating a session.
pub const SessionConfig = struct {
    local_index: u32,
    remote_index: u32 = 0,
    send_key: Key,
    recv_key: Key,
    remote_pk: Key = Key.zero,
    /// Current timestamp in nanoseconds (caller-provided).
    now_ns: u64 = 0,
};

/// Instantiate session for a given Crypto implementation and cipher suite.
pub fn SessionMod(comptime Crypto: type, comptime suite: crypto_mod.CipherSuite) type {
    const cipher = @import("cipher.zig").Cipher(Crypto, suite);

    return struct {
        /// An established Noise session with a peer.
        ///
        /// NOT thread-safe. Caller must synchronize access and provide
        /// timestamps via method parameters.
        pub const Session = struct {
            local_index: u32,
            remote_index: u32,

            send_key: Key,
            recv_key: Key,

            send_nonce: u64 = 0,
            recv_filter: ReplayFilter = ReplayFilter.init(),

            state: SessionState = .established,
            remote_pk: Key,

            created_ns: u64,
            last_received_ns: u64 = 0,
            last_sent_ns: u64 = 0,

            /// Creates a new session.
            pub fn init(cfg: SessionConfig) Session {
                return .{
                    .local_index = cfg.local_index,
                    .remote_index = cfg.remote_index,
                    .send_key = cfg.send_key,
                    .recv_key = cfg.recv_key,
                    .remote_pk = cfg.remote_pk,
                    .created_ns = cfg.now_ns,
                    .last_received_ns = cfg.now_ns,
                    .last_sent_ns = cfg.now_ns,
                };
            }

            pub fn localIndex(self: *const Session) u32 {
                return self.local_index;
            }

            pub fn remoteIndex(self: *const Session) u32 {
                return self.remote_index;
            }

            pub fn setRemoteIndex(self: *Session, idx: u32) void {
                self.remote_index = idx;
            }

            pub fn remotePk(self: *const Session) Key {
                return self.remote_pk;
            }

            pub fn getState(self: *const Session) SessionState {
                return self.state;
            }

            pub fn setState(self: *Session, new_state: SessionState) void {
                self.state = new_state;
            }

            /// Encrypts a message. Returns the nonce used.
            /// `now_ns` is the current timestamp in nanoseconds (caller-provided).
            pub fn encrypt(self: *Session, plaintext: []const u8, out: []u8, now_ns: u64) SessionError!u64 {
                if (self.state != .established) {
                    return SessionError.NotEstablished;
                }

                const nonce = self.send_nonce;
                if (nonce >= max_nonce) {
                    return SessionError.NonceExhausted;
                }
                self.send_nonce += 1;

                cipher.encrypt(&self.send_key.data, nonce, plaintext, "", out);
                self.last_sent_ns = now_ns;

                return nonce;
            }

            /// Decrypts a message.
            /// `now_ns` is the current timestamp in nanoseconds (caller-provided).
            pub fn decrypt(self: *Session, ciphertext: []const u8, nonce: u64, out: []u8, now_ns: u64) SessionError!usize {
                if (self.state != .established) {
                    return SessionError.NotEstablished;
                }

                if (!self.recv_filter.checkAndUpdate(nonce)) {
                    return SessionError.ReplayDetected;
                }

                if (ciphertext.len < tag_size) {
                    return SessionError.DecryptFailed;
                }

                cipher.decrypt(&self.recv_key.data, nonce, ciphertext, "", out) catch {
                    return SessionError.AuthenticationFailed;
                };

                self.last_received_ns = now_ns;

                return ciphertext.len - tag_size;
            }

            pub fn isExpired(self: *const Session, now_ns: u64) bool {
                if (self.state == .expired) return true;
                if (now_ns < self.last_received_ns) return false;
                return (now_ns - self.last_received_ns) > session_timeout_ns;
            }

            pub fn expire(self: *Session) void {
                self.state = .expired;
            }

            pub fn sendNonce(self: *const Session) u64 {
                return self.send_nonce;
            }

            pub fn recvMaxNonce(self: *const Session) u64 {
                return self.recv_filter.maxNonce();
            }

            pub fn createdNs(self: *const Session) u64 {
                return self.created_ns;
            }

            pub fn lastReceivedNs(self: *const Session) u64 {
                return self.last_received_ns;
            }

            pub fn lastSentNs(self: *const Session) u64 {
                return self.last_sent_ns;
            }
        };
    };
}

/// Creates a session index from 4 random bytes.
/// The caller is responsible for providing cryptographic random bytes.
pub fn generateIndexFromBytes(random_bytes: [4]u8) u32 {
    return mem.readInt(u32, &random_bytes, .little);
}

// Tests
const testing = std.testing;
const TestCrypto = @import("test_crypto.zig");
const TestSession = SessionMod(TestCrypto, .ChaChaPoly_BLAKE2s).Session;
const c = crypto_mod.CryptoMod(TestCrypto, .ChaChaPoly_BLAKE2s);

fn createTestSessions() struct { alice: TestSession, bob: TestSession } {
    const send_key = Key.fromBytes(c.hash(&.{"send key"}));
    const recv_key = Key.fromBytes(c.hash(&.{"recv key"}));

    const alice = TestSession.init(.{
        .local_index = 1,
        .remote_index = 2,
        .send_key = send_key,
        .recv_key = recv_key,
    });

    const bob = TestSession.init(.{
        .local_index = 2,
        .remote_index = 1,
        .send_key = recv_key,
        .recv_key = send_key,
    });

    return .{ .alice = alice, .bob = bob };
}

test "encrypt decrypt" {
    var sessions = createTestSessions();

    const plaintext = "Hello, World!";
    var ciphertext: [plaintext.len + tag_size]u8 = undefined;
    var decrypted: [plaintext.len]u8 = undefined;

    const nonce = try sessions.alice.encrypt(plaintext, &ciphertext, 0);
    const pt_len = try sessions.bob.decrypt(&ciphertext, nonce, &decrypted, 0);

    try testing.expectEqualSlices(u8, plaintext, decrypted[0..pt_len]);
}

test "nonce increment" {
    var sessions = createTestSessions();
    var ct: [4 + tag_size]u8 = undefined;

    for (0..10) |i| {
        try testing.expectEqual(@as(u64, i), sessions.alice.sendNonce());
        _ = try sessions.alice.encrypt("test", &ct, 0);
    }
    try testing.expectEqual(@as(u64, 10), sessions.alice.sendNonce());
}

test "replay protection" {
    var sessions = createTestSessions();

    const plaintext = "test";
    var ciphertext: [plaintext.len + tag_size]u8 = undefined;
    var decrypted: [plaintext.len]u8 = undefined;

    const nonce = try sessions.alice.encrypt(plaintext, &ciphertext, 0);
    _ = try sessions.bob.decrypt(&ciphertext, nonce, &decrypted, 0);
    try testing.expectError(SessionError.ReplayDetected, sessions.bob.decrypt(&ciphertext, nonce, &decrypted, 0));
}

test "state" {
    var sessions = createTestSessions();

    try testing.expectEqual(SessionState.established, sessions.alice.getState());
    sessions.alice.setState(.expired);
    try testing.expectEqual(SessionState.expired, sessions.alice.getState());

    var ct: [4 + tag_size]u8 = undefined;
    try testing.expectError(SessionError.NotEstablished, sessions.alice.encrypt("test", &ct, 0));
}

test "generate index from bytes" {
    const bytes1 = [4]u8{ 1, 0, 0, 0 };
    const bytes2 = [4]u8{ 2, 0, 0, 0 };
    try testing.expect(generateIndexFromBytes(bytes1) != generateIndexFromBytes(bytes2));
}
