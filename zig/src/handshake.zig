//! Noise handshake patterns (IK, XX, NN).

const std = @import("std");
const mem = std.mem;

const keypair = @import("keypair.zig");
const cipher = @import("cipher.zig");
const state = @import("state.zig");
const c = @import("crypto.zig");

const Key = keypair.Key;
const KeyPair = keypair.KeyPair;
const CipherState = state.CipherState;
const SymmetricState = state.SymmetricState;
const key_size = keypair.key_size;
const tag_size = c.tag_size;
const hash_size = c.hash_size;

/// Handshake pattern.
pub const Pattern = enum {
    /// IK: Initiator knows responder's static key.
    IK,
    /// XX: Mutual authentication, no prior knowledge.
    XX,
    /// NN: No authentication.
    NN,

    fn name(self: Pattern) []const u8 {
        return switch (self) {
            .IK => "IK",
            .XX => "XX",
            .NN => "NN",
        };
    }

    fn responderPreMessage(self: Pattern) []const Token {
        return switch (self) {
            .IK => &[_]Token{.s},
            .XX, .NN => &[_]Token{},
        };
    }

    fn messagePatterns(self: Pattern) []const []const Token {
        return switch (self) {
            .IK => &[_][]const Token{
                &[_]Token{ .e, .es, .s, .ss },
                &[_]Token{ .e, .ee, .se },
            },
            .XX => &[_][]const Token{
                &[_]Token{.e},
                &[_]Token{ .e, .ee, .s, .es },
                &[_]Token{ .s, .se },
            },
            .NN => &[_][]const Token{
                &[_]Token{.e},
                &[_]Token{ .e, .ee },
            },
        };
    }
};

const Token = enum { e, s, ee, es, se, ss };

/// Handshake errors.
pub const Error = error{
    Finished,
    NotReady,
    InvalidMessage,
    MissingLocalStatic,
    MissingRemoteStatic,
    NotOurTurn,
    DecryptionFailed,
    DhFailed,
    LowOrderPoint,
};

/// Handshake configuration.
pub const Config = struct {
    pattern: Pattern,
    initiator: bool,
    local_static: ?KeyPair = null,
    remote_static: ?Key = null,
    prologue: []const u8 = "",
    preshared_key: ?Key = null,
};

/// Manages the state of a Noise handshake.
pub const HandshakeState = struct {
    pattern: Pattern,
    initiator: bool,
    local_static: ?KeyPair,
    remote_static: Key,
    preshared_key: ?Key,
    ss: SymmetricState,
    local_ephemeral: ?KeyPair,
    remote_ephemeral: Key,
    msg_index: usize,
    finished: bool,

    /// Creates a new handshake state.
    pub fn init(config: Config) Error!HandshakeState {
        // Validate config
        try validateConfig(config);

        // Build protocol name
        var protocol_buf: [64]u8 = undefined;
        const protocol_name = std.fmt.bufPrint(&protocol_buf, "Noise_{s}_25519_ChaChaPoly_BLAKE2s", .{config.pattern.name()}) catch unreachable;

        var ss = SymmetricState.init(protocol_name);

        // Mix prologue
        ss.mixHash(config.prologue);

        var remote_static = Key.zero;

        // Process pre-messages
        if (config.initiator) {
            for (config.pattern.responderPreMessage()) |token| {
                if (token == .s) {
                    const rs = config.remote_static orelse return Error.MissingRemoteStatic;
                    ss.mixHash(rs.asBytes());
                    remote_static = rs;
                }
            }
        } else {
            for (config.pattern.responderPreMessage()) |token| {
                if (token == .s) {
                    const ls = config.local_static orelse return Error.MissingLocalStatic;
                    ss.mixHash(ls.public.asBytes());
                }
            }
        }

        return .{
            .pattern = config.pattern,
            .initiator = config.initiator,
            .local_static = config.local_static,
            .remote_static = remote_static,
            .preshared_key = config.preshared_key,
            .ss = ss,
            .local_ephemeral = null,
            .remote_ephemeral = Key.zero,
            .msg_index = 0,
            .finished = false,
        };
    }

    fn validateConfig(config: Config) Error!void {
        const needs_local_static = config.pattern == .IK or config.pattern == .XX;
        if (needs_local_static and config.local_static == null) {
            return Error.MissingLocalStatic;
        }
        if (config.pattern == .IK and config.initiator and config.remote_static == null) {
            return Error.MissingRemoteStatic;
        }
    }

    /// Generates the next handshake message.
    pub fn writeMessage(self: *HandshakeState, payload: []const u8, out: []u8) Error!usize {
        if (self.finished) return Error.Finished;

        const my_turn = (self.initiator and self.msg_index % 2 == 0) or
            (!self.initiator and self.msg_index % 2 == 1);
        if (!my_turn) return Error.NotOurTurn;

        const patterns = self.pattern.messagePatterns();
        if (self.msg_index >= patterns.len) return Error.Finished;

        const tokens = patterns[self.msg_index];
        var offset: usize = 0;

        for (tokens) |token| {
            switch (token) {
                .e => {
                    const ephemeral = KeyPair.generate();
                    @memcpy(out[offset..][0..key_size], ephemeral.public.asBytes());
                    offset += key_size;
                    self.ss.mixHash(ephemeral.public.asBytes());
                    if (self.preshared_key != null) {
                        _ = self.ss.mixKey(ephemeral.public.asBytes());
                    }
                    self.local_ephemeral = ephemeral;
                },
                .s => {
                    const ls = self.local_static orelse return Error.MissingLocalStatic;
                    const k = self.ss.mixKey("");
                    self.ss.encryptAndHash(&k, ls.public.asBytes(), out[offset..][0 .. key_size + tag_size]);
                    offset += key_size + tag_size;
                },
                .ee => {
                    const le = self.local_ephemeral orelse return Error.InvalidMessage;
                    const shared = le.dh(self.remote_ephemeral) catch return Error.DhFailed;
                    _ = self.ss.mixKey(shared.asBytes());
                },
                .es => {
                    const shared = if (self.initiator) blk: {
                        const le = self.local_ephemeral orelse return Error.InvalidMessage;
                        break :blk le.dh(self.remote_static) catch return Error.DhFailed;
                    } else blk: {
                        const ls = self.local_static orelse return Error.MissingLocalStatic;
                        break :blk ls.dh(self.remote_ephemeral) catch return Error.DhFailed;
                    };
                    _ = self.ss.mixKey(shared.asBytes());
                },
                .se => {
                    const shared = if (self.initiator) blk: {
                        const ls = self.local_static orelse return Error.MissingLocalStatic;
                        break :blk ls.dh(self.remote_ephemeral) catch return Error.DhFailed;
                    } else blk: {
                        const le = self.local_ephemeral orelse return Error.InvalidMessage;
                        break :blk le.dh(self.remote_static) catch return Error.DhFailed;
                    };
                    _ = self.ss.mixKey(shared.asBytes());
                },
                .ss => {
                    const ls = self.local_static orelse return Error.MissingLocalStatic;
                    const shared = ls.dh(self.remote_static) catch return Error.DhFailed;
                    _ = self.ss.mixKey(shared.asBytes());
                },
            }
        }

        // Encrypt payload
        if (payload.len > 0 or self.msg_index == patterns.len - 1) {
            const k = self.ss.mixKey("");
            self.ss.encryptAndHash(&k, payload, out[offset..][0 .. payload.len + tag_size]);
            offset += payload.len + tag_size;
        }

        self.msg_index += 1;
        if (self.msg_index >= patterns.len) {
            self.finished = true;
        }

        return offset;
    }

    /// Processes a received handshake message.
    pub fn readMessage(self: *HandshakeState, msg: []const u8, payload_out: []u8) Error!usize {
        if (self.finished) return Error.Finished;

        const my_turn = (self.initiator and self.msg_index % 2 == 0) or
            (!self.initiator and self.msg_index % 2 == 1);
        if (my_turn) return Error.NotOurTurn;

        const patterns = self.pattern.messagePatterns();
        if (self.msg_index >= patterns.len) return Error.Finished;

        const tokens = patterns[self.msg_index];
        var offset: usize = 0;

        for (tokens) |token| {
            switch (token) {
                .e => {
                    if (offset + key_size > msg.len) return Error.InvalidMessage;
                    self.remote_ephemeral = Key.fromSlice(msg[offset..][0..key_size]) catch return Error.InvalidMessage;
                    offset += key_size;
                    self.ss.mixHash(self.remote_ephemeral.asBytes());
                    if (self.preshared_key != null) {
                        _ = self.ss.mixKey(self.remote_ephemeral.asBytes());
                    }
                },
                .s => {
                    const encrypted_len = key_size + tag_size;
                    if (offset + encrypted_len > msg.len) return Error.InvalidMessage;
                    const k = self.ss.mixKey("");
                    var rs_bytes: [key_size]u8 = undefined;
                    self.ss.decryptAndHash(&k, msg[offset..][0..encrypted_len], &rs_bytes) catch return Error.DecryptionFailed;
                    self.remote_static = Key.fromBytes(rs_bytes);
                    offset += encrypted_len;
                },
                .ee => {
                    const le = self.local_ephemeral orelse return Error.InvalidMessage;
                    const shared = le.dh(self.remote_ephemeral) catch return Error.DhFailed;
                    _ = self.ss.mixKey(shared.asBytes());
                },
                .es => {
                    const shared = if (self.initiator) blk: {
                        const le = self.local_ephemeral orelse return Error.InvalidMessage;
                        break :blk le.dh(self.remote_static) catch return Error.DhFailed;
                    } else blk: {
                        const ls = self.local_static orelse return Error.MissingLocalStatic;
                        break :blk ls.dh(self.remote_ephemeral) catch return Error.DhFailed;
                    };
                    _ = self.ss.mixKey(shared.asBytes());
                },
                .se => {
                    const shared = if (self.initiator) blk: {
                        const ls = self.local_static orelse return Error.MissingLocalStatic;
                        break :blk ls.dh(self.remote_ephemeral) catch return Error.DhFailed;
                    } else blk: {
                        const le = self.local_ephemeral orelse return Error.InvalidMessage;
                        break :blk le.dh(self.remote_static) catch return Error.DhFailed;
                    };
                    _ = self.ss.mixKey(shared.asBytes());
                },
                .ss => {
                    const ls = self.local_static orelse return Error.MissingLocalStatic;
                    const shared = ls.dh(self.remote_static) catch return Error.DhFailed;
                    _ = self.ss.mixKey(shared.asBytes());
                },
            }
        }

        // Decrypt payload
        var payload_len: usize = 0;
        if (offset < msg.len) {
            const k = self.ss.mixKey("");
            payload_len = msg.len - offset - tag_size;
            self.ss.decryptAndHash(&k, msg[offset..], payload_out[0..payload_len]) catch return Error.DecryptionFailed;
        }

        self.msg_index += 1;
        if (self.msg_index >= self.pattern.messagePatterns().len) {
            self.finished = true;
        }

        return payload_len;
    }

    /// Returns true if handshake is complete.
    pub fn isFinished(self: HandshakeState) bool {
        return self.finished;
    }

    /// Splits into transport CipherStates.
    pub fn split(self: *const HandshakeState) Error!struct { CipherState, CipherState } {
        if (!self.finished) return Error.NotReady;

        const cs1, const cs2 = self.ss.split();
        if (self.initiator) {
            return .{ cs1, cs2 };
        } else {
            return .{ cs2, cs1 };
        }
    }

    /// Returns the remote static public key.
    pub fn getRemoteStatic(self: HandshakeState) Key {
        return self.remote_static;
    }

    /// Returns the handshake hash.
    pub fn getHash(self: *const HandshakeState) *const [hash_size]u8 {
        return self.ss.getHash();
    }
};

// Tests
test "handshake IK" {
    const initiator_static = KeyPair.generate();
    const responder_static = KeyPair.generate();

    var initiator = try HandshakeState.init(.{
        .pattern = .IK,
        .initiator = true,
        .local_static = initiator_static,
        .remote_static = responder_static.public,
    });

    var responder = try HandshakeState.init(.{
        .pattern = .IK,
        .initiator = false,
        .local_static = responder_static,
    });

    // Message 1
    var msg1: [256]u8 = undefined;
    const msg1_len = try initiator.writeMessage("", &msg1);

    var payload1: [64]u8 = undefined;
    _ = try responder.readMessage(msg1[0..msg1_len], &payload1);
    try std.testing.expect(responder.getRemoteStatic().eql(initiator_static.public));

    // Message 2
    var msg2: [256]u8 = undefined;
    const msg2_len = try responder.writeMessage("", &msg2);

    var payload2: [64]u8 = undefined;
    _ = try initiator.readMessage(msg2[0..msg2_len], &payload2);

    try std.testing.expect(initiator.isFinished());
    try std.testing.expect(responder.isFinished());

    // Test transport
    var send_i, var recv_i = try initiator.split();
    var send_r, var recv_r = try responder.split();

    const plaintext = "hello from initiator";
    var ct: [plaintext.len + tag_size]u8 = undefined;
    send_i.encrypt(plaintext, "", &ct);

    var pt: [plaintext.len]u8 = undefined;
    try recv_r.decrypt(&ct, "", &pt);
    try std.testing.expectEqualSlices(u8, plaintext, &pt);

    const reply = "hello from responder";
    var ct2: [reply.len + tag_size]u8 = undefined;
    send_r.encrypt(reply, "", &ct2);

    var pt2: [reply.len]u8 = undefined;
    try recv_i.decrypt(&ct2, "", &pt2);
    try std.testing.expectEqualSlices(u8, reply, &pt2);
}

test "handshake XX" {
    const initiator_static = KeyPair.generate();
    const responder_static = KeyPair.generate();

    var initiator = try HandshakeState.init(.{
        .pattern = .XX,
        .initiator = true,
        .local_static = initiator_static,
    });

    var responder = try HandshakeState.init(.{
        .pattern = .XX,
        .initiator = false,
        .local_static = responder_static,
    });

    // Message 1: -> e
    var msg1: [256]u8 = undefined;
    const msg1_len = try initiator.writeMessage("", &msg1);
    var p1: [64]u8 = undefined;
    _ = try responder.readMessage(msg1[0..msg1_len], &p1);

    // Message 2: <- e, ee, s, es
    var msg2: [256]u8 = undefined;
    const msg2_len = try responder.writeMessage("", &msg2);
    var p2: [64]u8 = undefined;
    _ = try initiator.readMessage(msg2[0..msg2_len], &p2);
    try std.testing.expect(initiator.getRemoteStatic().eql(responder_static.public));

    // Message 3: -> s, se
    var msg3: [256]u8 = undefined;
    const msg3_len = try initiator.writeMessage("", &msg3);
    var p3: [64]u8 = undefined;
    _ = try responder.readMessage(msg3[0..msg3_len], &p3);
    try std.testing.expect(responder.getRemoteStatic().eql(initiator_static.public));

    try std.testing.expect(initiator.isFinished());
    try std.testing.expect(responder.isFinished());
}

test "handshake NN" {
    var initiator = try HandshakeState.init(.{
        .pattern = .NN,
        .initiator = true,
    });

    var responder = try HandshakeState.init(.{
        .pattern = .NN,
        .initiator = false,
    });

    // Message 1: -> e
    var msg1: [256]u8 = undefined;
    const msg1_len = try initiator.writeMessage("", &msg1);
    var p1: [64]u8 = undefined;
    _ = try responder.readMessage(msg1[0..msg1_len], &p1);

    // Message 2: <- e, ee
    var msg2: [256]u8 = undefined;
    const msg2_len = try responder.writeMessage("", &msg2);
    var p2: [64]u8 = undefined;
    _ = try initiator.readMessage(msg2[0..msg2_len], &p2);

    try std.testing.expect(initiator.isFinished());
    try std.testing.expect(responder.isFinished());

    var send_i, _ = try initiator.split();
    _, var recv_r = try responder.split();

    const plaintext = "NN test";
    var ct: [plaintext.len + tag_size]u8 = undefined;
    send_i.encrypt(plaintext, "", &ct);

    var pt: [plaintext.len]u8 = undefined;
    try recv_r.decrypt(&ct, "", &pt);
    try std.testing.expectEqualSlices(u8, plaintext, &pt);
}

test "handshake hash" {
    const initiator_static = KeyPair.generate();
    const responder_static = KeyPair.generate();

    var initiator = try HandshakeState.init(.{
        .pattern = .IK,
        .initiator = true,
        .local_static = initiator_static,
        .remote_static = responder_static.public,
    });

    var responder = try HandshakeState.init(.{
        .pattern = .IK,
        .initiator = false,
        .local_static = responder_static,
    });

    var msg1: [256]u8 = undefined;
    const msg1_len = try initiator.writeMessage("", &msg1);
    var p1: [64]u8 = undefined;
    _ = try responder.readMessage(msg1[0..msg1_len], &p1);

    var msg2: [256]u8 = undefined;
    const msg2_len = try responder.writeMessage("", &msg2);
    var p2: [64]u8 = undefined;
    _ = try initiator.readMessage(msg2[0..msg2_len], &p2);

    try std.testing.expectEqualSlices(u8, initiator.getHash(), responder.getHash());
}

test "handshake errors" {
    // Missing local static for IK
    const rs = KeyPair.generate();
    try std.testing.expectError(Error.MissingLocalStatic, HandshakeState.init(.{
        .pattern = .IK,
        .initiator = true,
        .remote_static = rs.public,
    }));

    // Missing remote static for IK initiator
    const ls = KeyPair.generate();
    try std.testing.expectError(Error.MissingRemoteStatic, HandshakeState.init(.{
        .pattern = .IK,
        .initiator = true,
        .local_static = ls,
    }));
}

test "handshake wrong turn" {
    var initiator = try HandshakeState.init(.{
        .pattern = .NN,
        .initiator = true,
    });

    var responder = try HandshakeState.init(.{
        .pattern = .NN,
        .initiator = false,
    });

    // Responder tries to write first
    var buf: [256]u8 = undefined;
    try std.testing.expectError(Error.NotOurTurn, responder.writeMessage("", &buf));

    // Initiator tries to read first
    var p: [64]u8 = undefined;
    try std.testing.expectError(Error.NotOurTurn, initiator.readMessage("", &p));
}

test "split before finish" {
    const initiator = try HandshakeState.init(.{
        .pattern = .NN,
        .initiator = true,
    });

    try std.testing.expectError(Error.NotReady, initiator.split());
}
