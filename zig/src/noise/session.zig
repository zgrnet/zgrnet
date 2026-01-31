//! Session management for transport phase.

const std = @import("std");
const crypto = std.crypto;
const mem = std.mem;
const time = std.time;
const Mutex = std.Thread.Mutex;
const Atomic = std.atomic.Value;

const keypair = @import("keypair.zig");
const replay_mod = @import("replay.zig");
const cipher_mod = @import("cipher.zig");

pub const Key = keypair.Key;
pub const key_size = keypair.key_size;
pub const ReplayFilter = replay_mod.ReplayFilter;
pub const tag_size = 16;

/// Session state.
pub const SessionState = enum {
    handshaking,
    established,
    expired,

    pub fn format(
        self: SessionState,
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        try writer.writeAll(switch (self) {
            .handshaking => "handshaking",
            .established => "established",
            .expired => "expired",
        });
    }
};

/// Session timeout in nanoseconds (180 seconds).
pub const session_timeout_ns: i128 = 180 * std.time.ns_per_s;

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
};

/// An established Noise session with a peer.
pub const Session = struct {
    mutex: Mutex = .{},

    local_index: u32,
    remote_index: u32,

    send_key: Key,
    recv_key: Key,

    send_nonce: Atomic(u64) = Atomic(u64).init(0),
    recv_filter: ReplayFilter = ReplayFilter.init(),

    // Use atomic for state to allow lock-free reads
    state_atomic: Atomic(u8) = Atomic(u8).init(@intFromEnum(SessionState.established)),
    remote_pk: Key,

    created_at: i128,
    // Use atomic timestamps to avoid lock contention
    last_received_nanos: Atomic(i64) = Atomic(i64).init(0),
    last_sent_nanos: Atomic(i64) = Atomic(i64).init(0),

    /// Creates a new session.
    pub fn init(cfg: SessionConfig) Session {
        const now = time.nanoTimestamp();
        const now_i64: i64 = @intCast(@mod(now, std.math.maxInt(i64)));
        return .{
            .local_index = cfg.local_index,
            .remote_index = cfg.remote_index,
            .send_key = cfg.send_key,
            .recv_key = cfg.recv_key,
            .remote_pk = cfg.remote_pk,
            .created_at = now,
            .last_received_nanos = Atomic(i64).init(now_i64),
            .last_sent_nanos = Atomic(i64).init(now_i64),
        };
    }

    /// Returns the local index.
    pub fn localIndex(self: *const Session) u32 {
        return self.local_index;
    }

    /// Returns the remote index.
    pub fn remoteIndex(self: *Session) u32 {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.remote_index;
    }

    /// Sets the remote index.
    pub fn setRemoteIndex(self: *Session, idx: u32) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.remote_index = idx;
    }

    /// Returns the remote public key.
    pub fn remotePk(self: *const Session) Key {
        return self.remote_pk;
    }

    /// Returns the current state (lock-free).
    pub fn getState(self: *const Session) SessionState {
        return @enumFromInt(self.state_atomic.load(.acquire));
    }

    /// Sets the state (lock-free).
    pub fn setState(self: *Session, new_state: SessionState) void {
        self.state_atomic.store(@intFromEnum(new_state), .release);
    }

    /// Encrypts a message.
    /// Returns the nonce used. Output buffer must be at least plaintext.len + tag_size.
    /// Lock-free for concurrent encryption.
    pub fn encrypt(self: *Session, plaintext: []const u8, out: []u8) SessionError!u64 {
        // Lock-free state check
        if (self.getState() != .established) {
            return SessionError.NotEstablished;
        }

        // Atomic nonce increment
        const nonce = self.send_nonce.fetchAdd(1, .seq_cst);
        if (nonce >= max_nonce) {
            return SessionError.NonceExhausted;
        }

        // Encryption is thread-safe (read-only key)
        cipher_mod.encrypt(&self.send_key.data, nonce, plaintext, "", out);

        // Atomic timestamp update
        const now: i64 = @intCast(@mod(time.nanoTimestamp(), std.math.maxInt(i64)));
        self.last_sent_nanos.store(now, .release);

        return nonce;
    }

    /// Decrypts a message.
    /// Output buffer must be at least ciphertext.len - tag_size.
    /// Lock-free for concurrent decryption.
    pub fn decrypt(self: *Session, ciphertext: []const u8, nonce: u64, out: []u8) SessionError!usize {
        // Lock-free state check
        if (self.getState() != .established) {
            return SessionError.NotEstablished;
        }

        // Atomically check and update replay filter (has its own lock)
        if (!self.recv_filter.checkAndUpdate(nonce)) {
            return SessionError.ReplayDetected;
        }

        if (ciphertext.len < tag_size) {
            return SessionError.DecryptFailed;
        }

        // Decryption is thread-safe (read-only key)
        cipher_mod.decrypt(&self.recv_key.data, nonce, ciphertext, "", out) catch {
            return SessionError.AuthenticationFailed;
        };

        // Atomic timestamp update
        const now: i64 = @intCast(@mod(time.nanoTimestamp(), std.math.maxInt(i64)));
        self.last_received_nanos.store(now, .release);

        return ciphertext.len - tag_size;
    }

    /// Checks if the session has expired (lock-free).
    pub fn isExpired(self: *const Session) bool {
        if (self.getState() == .expired) {
            return true;
        }

        const last = self.last_received_nanos.load(.acquire);
        const now: i64 = @intCast(@mod(time.nanoTimestamp(), std.math.maxInt(i64)));
        const elapsed = now - last;
        return elapsed > @as(i64, @intCast(@mod(session_timeout_ns, std.math.maxInt(i64))));
    }

    /// Marks the session as expired.
    pub fn expire(self: *Session) void {
        self.setState(.expired);
    }

    /// Returns current send nonce (lock-free).
    pub fn sendNonce(self: *const Session) u64 {
        return self.send_nonce.load(.seq_cst);
    }

    /// Returns max received nonce.
    pub fn recvMaxNonce(self: *Session) u64 {
        return self.recv_filter.maxNonce();
    }

    /// Returns when session was created.
    pub fn createdAt(self: *const Session) i128 {
        return self.created_at;
    }

    /// Returns when last message was received (as nanos, lock-free).
    pub fn lastReceivedNanos(self: *const Session) i64 {
        return self.last_received_nanos.load(.acquire);
    }

    /// Returns when last message was sent (as nanos, lock-free).
    pub fn lastSentNanos(self: *const Session) i64 {
        return self.last_sent_nanos.load(.acquire);
    }
};

/// Generates a random session index.
pub fn generateIndex() u32 {
    var buf: [4]u8 = undefined;
    crypto.random.bytes(&buf);
    return mem.readInt(u32, &buf, .little);
}

// Tests
const testing = std.testing;
const c = @import("crypto.zig");

fn createTestSessions() struct { alice: Session, bob: Session } {
    const send_key = Key.fromBytes(c.hash(&.{"send key"}));
    const recv_key = Key.fromBytes(c.hash(&.{"recv key"}));

    const alice = Session.init(.{
        .local_index = 1,
        .remote_index = 2,
        .send_key = send_key,
        .recv_key = recv_key,
    });

    const bob = Session.init(.{
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

    const nonce = try sessions.alice.encrypt(plaintext, &ciphertext);
    const pt_len = try sessions.bob.decrypt(&ciphertext, nonce, &decrypted);

    try testing.expectEqualSlices(u8, plaintext, decrypted[0..pt_len]);
}

test "bidirectional" {
    var sessions = createTestSessions();

    // Alice -> Bob
    const msg1 = "from alice";
    var ct1: [msg1.len + tag_size]u8 = undefined;
    var pt1: [msg1.len]u8 = undefined;
    const n1 = try sessions.alice.encrypt(msg1, &ct1);
    const len1 = try sessions.bob.decrypt(&ct1, n1, &pt1);
    try testing.expectEqualSlices(u8, msg1, pt1[0..len1]);

    // Bob -> Alice
    const msg2 = "from bob";
    var ct2: [msg2.len + tag_size]u8 = undefined;
    var pt2: [msg2.len]u8 = undefined;
    const n2 = try sessions.bob.encrypt(msg2, &ct2);
    const len2 = try sessions.alice.decrypt(&ct2, n2, &pt2);
    try testing.expectEqualSlices(u8, msg2, pt2[0..len2]);
}

test "nonce increment" {
    var sessions = createTestSessions();
    var ct: [4 + tag_size]u8 = undefined;

    for (0..10) |i| {
        try testing.expectEqual(@as(u64, i), sessions.alice.sendNonce());
        _ = try sessions.alice.encrypt("test", &ct);
    }
    try testing.expectEqual(@as(u64, 10), sessions.alice.sendNonce());
}

test "replay protection" {
    var sessions = createTestSessions();

    const plaintext = "test";
    var ciphertext: [plaintext.len + tag_size]u8 = undefined;
    var decrypted: [plaintext.len]u8 = undefined;

    const nonce = try sessions.alice.encrypt(plaintext, &ciphertext);

    // First decrypt succeeds
    _ = try sessions.bob.decrypt(&ciphertext, nonce, &decrypted);

    // Replay fails
    try testing.expectError(SessionError.ReplayDetected, sessions.bob.decrypt(&ciphertext, nonce, &decrypted));
}

test "out of order" {
    var sessions = createTestSessions();

    const Messages = struct {
        ct: [5 + tag_size]u8,
        nonce: u64,
        expected: u8,
    };

    var messages: [10]Messages = undefined;
    for (0..10) |i| {
        const msg = [_]u8{@intCast(i)} ++ [_]u8{0} ** 4;
        const nonce = try sessions.alice.encrypt(&msg, &messages[i].ct);
        messages[i].nonce = nonce;
        messages[i].expected = @intCast(i);
    }

    // Decrypt in reverse
    var i: usize = 9;
    while (true) {
        var pt: [5]u8 = undefined;
        const len = try sessions.bob.decrypt(&messages[i].ct, messages[i].nonce, &pt);
        try testing.expectEqual(messages[i].expected, pt[0]);
        _ = len;
        if (i == 0) break;
        i -= 1;
    }
}

test "state" {
    var sessions = createTestSessions();

    try testing.expectEqual(SessionState.established, sessions.alice.getState());

    sessions.alice.setState(.expired);
    try testing.expectEqual(SessionState.expired, sessions.alice.getState());

    var ct: [4 + tag_size]u8 = undefined;
    try testing.expectError(SessionError.NotEstablished, sessions.alice.encrypt("test", &ct));
}

test "indices" {
    const sessions = createTestSessions();

    try testing.expectEqual(@as(u32, 1), sessions.alice.localIndex());
    try testing.expectEqual(@as(u32, 2), sessions.bob.localIndex());
}

test "generate index" {
    var indices = std.AutoHashMap(u32, void).init(testing.allocator);
    defer indices.deinit();

    for (0..1000) |_| {
        try indices.put(generateIndex(), {});
    }

    // Should have many unique values
    try testing.expect(indices.count() > 900);
}

test "session state enum" {
    // Just verify the enum values work correctly
    try testing.expectEqual(SessionState.handshaking, SessionState.handshaking);
    try testing.expectEqual(SessionState.established, SessionState.established);
    try testing.expectEqual(SessionState.expired, SessionState.expired);

    // Verify they are distinct
    try testing.expect(SessionState.handshaking != SessionState.established);
    try testing.expect(SessionState.established != SessionState.expired);
}
