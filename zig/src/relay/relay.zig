//! Relay forwarding engine - pure functions with no I/O.
//!
//! The engine processes relay messages and returns `Action`s for the
//! caller to execute. The `Router` provides routing decisions.

const std = @import("std");
const message = @import("message.zig");
const noise_message = @import("../noise/message.zig");
const session_mod = @import("../noise/session.zig");
const keypair_mod = @import("../noise/keypair.zig");
const crypto_mod = @import("../noise/crypto.zig");

pub const Strategy = message.Strategy;
pub const RelayError = message.RelayError;
pub const Relay0 = message.Relay0;
pub const Relay1 = message.Relay1;
pub const Relay2 = message.Relay2;
pub const Ping = message.Ping;
pub const Pong = message.Pong;

/// Router provides next-hop routing decisions for relay forwarding.
///
/// Implementations range from simple static maps (for testing) to
/// dynamic routing based on PONG metrics (Host layer).
pub const Router = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// Returns the next peer to forward to for reaching `dst`.
        ///
        /// - If `next_hop == dst`, the destination is directly reachable (send RELAY_2).
        /// - If `next_hop != dst`, forward via intermediate relay (send RELAY_1).
        next_hop: *const fn (ptr: *anyopaque, dst: *const [32]u8, strategy: Strategy) RelayError![32]u8,
    };

    pub fn nextHop(self: Router, dst: *const [32]u8, strategy: Strategy) RelayError![32]u8 {
        return self.vtable.next_hop(self.ptr, dst, strategy);
    }
};

/// An action returned by the relay engine for the caller to execute.
pub const Action = struct {
    /// Next-hop peer public key.
    dst: [32]u8,
    /// Protocol byte (relay_1, relay_2, or pong).
    protocol: u8,
    /// Encoded data length in the buffer.
    len: usize,
    /// Buffer holding the encoded message.
    buf: [max_action_buf]u8,

    pub const max_action_buf = 2048;

    pub fn data(self: *const Action) []const u8 {
        return self.buf[0..self.len];
    }
};

/// Local node metrics for PONG responses.
pub const NodeMetrics = struct {
    load: u8 = 0,
    relay_count: u16 = 0,
    bw_avail: u16 = 0,
    price: u32 = 0,
};

/// Process a RELAY_0 (first-hop) message.
/// `from` is the sender's public key.
/// `data_buf` is the message body after protocol byte.
pub fn handleRelay0(router: Router, from: *const [32]u8, data_buf: []const u8) !Action {
    const r0 = try message.decodeRelay0(data_buf);
    if (r0.ttl == 0) return error.TtlExpired;

    const next_hop = try router.nextHop(&r0.dst_key, r0.strategy);

    if (std.mem.eql(u8, &next_hop, &r0.dst_key)) {
        // Direct: send RELAY_2
        const r2 = Relay2{ .src_key = from.*, .payload = r0.payload };
        var action = Action{
            .dst = next_hop,
            .protocol = @intFromEnum(noise_message.Protocol.relay_2),
            .len = 0,
            .buf = undefined,
        };
        action.len = try message.encodeRelay2(&r2, &action.buf);
        return action;
    } else {
        // Forward: send RELAY_1
        const r1 = Relay1{
            .ttl = r0.ttl - 1,
            .strategy = r0.strategy,
            .src_key = from.*,
            .dst_key = r0.dst_key,
            .payload = r0.payload,
        };
        var action = Action{
            .dst = next_hop,
            .protocol = @intFromEnum(noise_message.Protocol.relay_1),
            .len = 0,
            .buf = undefined,
        };
        action.len = try message.encodeRelay1(&r1, &action.buf);
        return action;
    }
}

/// Process a RELAY_1 (middle-hop) message.
pub fn handleRelay1(router: Router, data_buf: []const u8) !Action {
    const r1 = try message.decodeRelay1(data_buf);
    if (r1.ttl == 0) return error.TtlExpired;

    const next_hop = try router.nextHop(&r1.dst_key, r1.strategy);

    if (std.mem.eql(u8, &next_hop, &r1.dst_key)) {
        // Direct: send RELAY_2
        const r2 = Relay2{ .src_key = r1.src_key, .payload = r1.payload };
        var action = Action{
            .dst = next_hop,
            .protocol = @intFromEnum(noise_message.Protocol.relay_2),
            .len = 0,
            .buf = undefined,
        };
        action.len = try message.encodeRelay2(&r2, &action.buf);
        return action;
    } else {
        // Forward: send RELAY_1 (TTL-1)
        const fwd = Relay1{
            .ttl = r1.ttl - 1,
            .strategy = r1.strategy,
            .src_key = r1.src_key,
            .dst_key = r1.dst_key,
            .payload = r1.payload,
        };
        var action = Action{
            .dst = next_hop,
            .protocol = @intFromEnum(noise_message.Protocol.relay_1),
            .len = 0,
            .buf = undefined,
        };
        action.len = try message.encodeRelay1(&fwd, &action.buf);
        return action;
    }
}

/// Process a RELAY_2 (last-hop) message.
/// Returns the source public key and a slice pointing to the payload in the input data.
pub const Relay2Result = struct {
    src_key: [32]u8,
    payload: []const u8,
};

pub fn handleRelay2(data_buf: []const u8) error{TooShort}!Relay2Result {
    const r2 = try message.decodeRelay2(data_buf);
    return Relay2Result{
        .src_key = r2.src_key,
        .payload = r2.payload,
    };
}

/// Process a PING message and return a PONG action.
pub fn handlePing(from: *const [32]u8, data_buf: []const u8, metrics: *const NodeMetrics) !Action {
    const ping = try message.decodePing(data_buf);
    const pong_msg = Pong{
        .ping_id = ping.ping_id,
        .timestamp = ping.timestamp,
        .load = metrics.load,
        .relay_count = metrics.relay_count,
        .bw_avail = metrics.bw_avail,
        .price = metrics.price,
    };
    var action = Action{
        .dst = from.*,
        .protocol = @intFromEnum(noise_message.Protocol.pong),
        .len = 0,
        .buf = undefined,
    };
    action.len = try message.encodePong(&pong_msg, &action.buf);
    return action;
}

// ============================================================================
// Tests
// ============================================================================

/// Simple static router for testing.
const StaticRouter = struct {
    routes: std.AutoHashMap([32]u8, [32]u8),

    fn init(allocator: std.mem.Allocator) StaticRouter {
        return .{ .routes = std.AutoHashMap([32]u8, [32]u8).init(allocator) };
    }

    fn deinit(self: *StaticRouter) void {
        self.routes.deinit();
    }

    fn addRoute(self: *StaticRouter, dst: [32]u8, next_hop: [32]u8) !void {
        try self.routes.put(dst, next_hop);
    }

    fn router(self: *StaticRouter) Router {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &.{
                .next_hop = @ptrCast(&nextHopImpl),
            },
        };
    }

    fn nextHopImpl(self: *StaticRouter, dst: *const [32]u8, _: Strategy) RelayError![32]u8 {
        return self.routes.get(dst.*) orelse return error.NoRoute;
    }
};

fn keyFromByte(b: u8) [32]u8 {
    var k = [_]u8{0} ** 32;
    k[0] = b;
    return k;
}

test "handle_relay0 direct" {
    const allocator = std.testing.allocator;
    var sr = StaticRouter.init(allocator);
    defer sr.deinit();

    const key_a = keyFromByte(0x0A);
    const key_b = keyFromByte(0x0B);
    try sr.addRoute(key_b, key_b); // B is direct

    const payload = "secret payload A->B";
    var r0_buf: [256]u8 = undefined;
    const r0 = Relay0{ .ttl = 8, .strategy = .auto, .dst_key = key_b, .payload = payload };
    const r0_n = try message.encodeRelay0(&r0, &r0_buf);

    const action = try handleRelay0(sr.router(), &key_a, r0_buf[0..r0_n]);
    try std.testing.expectEqualSlices(u8, &key_b, &action.dst);
    try std.testing.expectEqual(@intFromEnum(noise_message.Protocol.relay_2), action.protocol);

    const r2 = try message.decodeRelay2(action.data());
    try std.testing.expectEqualSlices(u8, &key_a, &r2.src_key);
    try std.testing.expectEqualStrings(payload, r2.payload);
}

test "handle_relay0 forward" {
    const allocator = std.testing.allocator;
    var sr = StaticRouter.init(allocator);
    defer sr.deinit();

    const key_a = keyFromByte(0x0A);
    const key_b = keyFromByte(0x0B);
    const key_c = keyFromByte(0x0C);
    try sr.addRoute(key_b, key_c); // B via C

    const payload = "secret";
    var r0_buf: [256]u8 = undefined;
    const r0 = Relay0{ .ttl = 8, .strategy = .fastest, .dst_key = key_b, .payload = payload };
    const r0_n = try message.encodeRelay0(&r0, &r0_buf);

    const action = try handleRelay0(sr.router(), &key_a, r0_buf[0..r0_n]);
    try std.testing.expectEqualSlices(u8, &key_c, &action.dst);
    try std.testing.expectEqual(@intFromEnum(noise_message.Protocol.relay_1), action.protocol);

    const r1 = try message.decodeRelay1(action.data());
    try std.testing.expectEqual(@as(u8, 7), r1.ttl);
    try std.testing.expectEqual(Strategy.fastest, r1.strategy);
    try std.testing.expectEqualSlices(u8, &key_a, &r1.src_key);
    try std.testing.expectEqualSlices(u8, &key_b, &r1.dst_key);
}

test "handle_relay0 TTL expired" {
    const allocator = std.testing.allocator;
    var sr = StaticRouter.init(allocator);
    defer sr.deinit();

    const key_a = keyFromByte(0x0A);
    const key_b = keyFromByte(0x0B);
    try sr.addRoute(key_b, key_b);

    var r0_buf: [256]u8 = undefined;
    const r0 = Relay0{ .ttl = 0, .strategy = .auto, .dst_key = key_b, .payload = "" };
    const r0_n = try message.encodeRelay0(&r0, &r0_buf);

    try std.testing.expectError(error.TtlExpired, handleRelay0(sr.router(), &key_a, r0_buf[0..r0_n]));
}

test "handle_relay0 no route" {
    const allocator = std.testing.allocator;
    var sr = StaticRouter.init(allocator);
    defer sr.deinit();
    // Empty routes

    const key_a = keyFromByte(0x0A);
    const key_b = keyFromByte(0x0B);
    var r0_buf: [256]u8 = undefined;
    const r0 = Relay0{ .ttl = 8, .strategy = .auto, .dst_key = key_b, .payload = "" };
    const r0_n = try message.encodeRelay0(&r0, &r0_buf);

    try std.testing.expectError(error.NoRoute, handleRelay0(sr.router(), &key_a, r0_buf[0..r0_n]));
}

test "handle_relay1 direct" {
    const allocator = std.testing.allocator;
    var sr = StaticRouter.init(allocator);
    defer sr.deinit();

    const key_a = keyFromByte(0x0A);
    const key_b = keyFromByte(0x0B);
    try sr.addRoute(key_b, key_b);

    const payload = "relay1 data";
    var r1_buf: [256]u8 = undefined;
    const r1 = Relay1{ .ttl = 5, .strategy = .cheapest, .src_key = key_a, .dst_key = key_b, .payload = payload };
    const r1_n = try message.encodeRelay1(&r1, &r1_buf);

    const action = try handleRelay1(sr.router(), r1_buf[0..r1_n]);
    try std.testing.expectEqualSlices(u8, &key_b, &action.dst);
    try std.testing.expectEqual(@intFromEnum(noise_message.Protocol.relay_2), action.protocol);

    const r2 = try message.decodeRelay2(action.data());
    try std.testing.expectEqualSlices(u8, &key_a, &r2.src_key);
    try std.testing.expectEqualStrings(payload, r2.payload);
}

test "handle_relay1 forward" {
    const allocator = std.testing.allocator;
    var sr = StaticRouter.init(allocator);
    defer sr.deinit();

    const key_a = keyFromByte(0x0A);
    const key_b = keyFromByte(0x0B);
    const key_d = keyFromByte(0x0D);
    try sr.addRoute(key_b, key_d);

    var r1_buf: [256]u8 = undefined;
    const r1 = Relay1{ .ttl = 5, .strategy = .auto, .src_key = key_a, .dst_key = key_b, .payload = "data" };
    const r1_n = try message.encodeRelay1(&r1, &r1_buf);

    const action = try handleRelay1(sr.router(), r1_buf[0..r1_n]);
    try std.testing.expectEqualSlices(u8, &key_d, &action.dst);
    try std.testing.expectEqual(@intFromEnum(noise_message.Protocol.relay_1), action.protocol);

    const fwd = try message.decodeRelay1(action.data());
    try std.testing.expectEqual(@as(u8, 4), fwd.ttl);
    try std.testing.expectEqualSlices(u8, &key_a, &fwd.src_key);
    try std.testing.expectEqualSlices(u8, &key_b, &fwd.dst_key);
}

test "handle_relay1 TTL expired" {
    const allocator = std.testing.allocator;
    var sr = StaticRouter.init(allocator);
    defer sr.deinit();

    var r1_buf: [256]u8 = undefined;
    const r1 = Relay1{ .ttl = 0, .strategy = .auto, .src_key = [_]u8{0} ** 32, .dst_key = [_]u8{1} ** 32, .payload = "" };
    const r1_n = try message.encodeRelay1(&r1, &r1_buf);

    try std.testing.expectError(error.TtlExpired, handleRelay1(sr.router(), r1_buf[0..r1_n]));
}

test "handle_relay2" {
    const key_a = keyFromByte(0x0A);
    const payload = "final payload";
    var r2_buf: [256]u8 = undefined;
    const r2 = Relay2{ .src_key = key_a, .payload = payload };
    const r2_n = try message.encodeRelay2(&r2, &r2_buf);

    const result = try handleRelay2(r2_buf[0..r2_n]);
    try std.testing.expectEqualSlices(u8, &key_a, &result.src_key);
    try std.testing.expectEqualStrings(payload, result.payload);
}

test "handle_relay2 too short" {
    var short: [31]u8 = undefined;
    try std.testing.expectError(error.TooShort, handleRelay2(&short));
}

test "handle_ping" {
    const from = keyFromByte(0x0A);
    var ping_buf: [message.ping_size]u8 = undefined;
    const ping = Ping{ .ping_id = 42, .timestamp = 1234567890 };
    _ = try message.encodePing(&ping, &ping_buf);

    const metrics = NodeMetrics{ .load = 50, .relay_count = 10, .bw_avail = 2048, .price = 100 };
    const action = try handlePing(&from, &ping_buf, &metrics);
    try std.testing.expectEqualSlices(u8, &from, &action.dst);
    try std.testing.expectEqual(@intFromEnum(noise_message.Protocol.pong), action.protocol);

    const pong = try message.decodePong(action.data());
    try std.testing.expectEqual(@as(u32, 42), pong.ping_id);
    try std.testing.expectEqual(@as(u64, 1234567890), pong.timestamp);
    try std.testing.expectEqual(@as(u8, 50), pong.load);
    try std.testing.expectEqual(@as(u16, 10), pong.relay_count);
    try std.testing.expectEqual(@as(u16, 2048), pong.bw_avail);
    try std.testing.expectEqual(@as(u32, 100), pong.price);
}

test "multi-hop relay A->C->D->B" {
    const allocator = std.testing.allocator;

    const key_a = keyFromByte(0x0A);
    const key_b = keyFromByte(0x0B);
    const key_d = keyFromByte(0x0D);
    const payload = "e2e encrypted data";

    // Router C: B via D
    var sr_c = StaticRouter.init(allocator);
    defer sr_c.deinit();
    try sr_c.addRoute(key_b, key_d);

    // Router D: B direct
    var sr_d = StaticRouter.init(allocator);
    defer sr_d.deinit();
    try sr_d.addRoute(key_b, key_b);

    // Step 1: Encode RELAY_0 (A sends)
    var r0_buf: [256]u8 = undefined;
    const r0 = Relay0{ .ttl = 8, .strategy = .auto, .dst_key = key_b, .payload = payload };
    const r0_n = try message.encodeRelay0(&r0, &r0_buf);

    // Step 2: C handles RELAY_0 -> RELAY_1 to D
    const a1 = try handleRelay0(sr_c.router(), &key_a, r0_buf[0..r0_n]);
    try std.testing.expectEqual(@intFromEnum(noise_message.Protocol.relay_1), a1.protocol);
    try std.testing.expectEqualSlices(u8, &key_d, &a1.dst);

    // Step 3: D handles RELAY_1 -> RELAY_2 to B
    const a2 = try handleRelay1(sr_d.router(), a1.data());
    try std.testing.expectEqual(@intFromEnum(noise_message.Protocol.relay_2), a2.protocol);
    try std.testing.expectEqualSlices(u8, &key_b, &a2.dst);

    // Step 4: B handles RELAY_2 -> extract src + payload
    const result = try handleRelay2(a2.data());
    try std.testing.expectEqualSlices(u8, &key_a, &result.src_key);
    try std.testing.expectEqualStrings(payload, result.payload);
}

test "relay chain with noise session A->B->C" {
    const allocator = std.testing.allocator;

    // Generate keys via BLAKE2s hash (same approach as Go/Rust tests)
    const send_key_data = crypto_mod.hash(&.{"A-to-C send key"});
    const recv_key_data = crypto_mod.hash(&.{"A-to-C recv key"});
    const send_key = keypair_mod.Key{ .data = send_key_data };
    const recv_key = keypair_mod.Key{ .data = recv_key_data };

    // Create A-C end-to-end sessions (keys swapped between sides)
    var session_a = session_mod.Session.init(.{
        .local_index = 1,
        .remote_index = 2,
        .send_key = send_key,
        .recv_key = recv_key,
    });
    var session_c = session_mod.Session.init(.{
        .local_index = 2,
        .remote_index = 1,
        .send_key = recv_key, // swapped
        .recv_key = send_key, // swapped
    });

    const key_a = keyFromByte(0x0A);
    const key_c = keyFromByte(0x0C);

    // Step 1: A encrypts data with A-C session
    const original_data = "hello through relay!";
    const payload_enc = try noise_message.encodePayload(allocator, .chat, original_data);
    defer allocator.free(payload_enc);

    var cipher_buf: [1024]u8 = undefined;
    const nonce = try session_a.encrypt(payload_enc, &cipher_buf);
    const ciphertext_len = payload_enc.len + session_mod.tag_size;

    // Build Type 4 transport message
    const type4msg = try noise_message.buildTransportMessage(
        allocator,
        session_a.remote_index,
        nonce,
        cipher_buf[0..ciphertext_len],
    );
    defer allocator.free(type4msg);

    // Step 2: Wrap in RELAY_0(dst=C)
    var r0_buf: [2048]u8 = undefined;
    const r0 = Relay0{ .ttl = 8, .strategy = .auto, .dst_key = key_c, .payload = type4msg };
    const r0_n = try message.encodeRelay0(&r0, &r0_buf);

    // Step 3: B (relay) processes RELAY_0 → RELAY_2 to C
    var sr = StaticRouter.init(allocator);
    defer sr.deinit();
    try sr.addRoute(key_c, key_c); // C is direct

    const action = try handleRelay0(sr.router(), &key_a, r0_buf[0..r0_n]);
    try std.testing.expectEqual(@intFromEnum(noise_message.Protocol.relay_2), action.protocol);
    try std.testing.expectEqualSlices(u8, &key_c, &action.dst);

    // Step 4: C processes RELAY_2
    const result = try handleRelay2(action.data());
    try std.testing.expectEqualSlices(u8, &key_a, &result.src_key);

    // Step 5: C decrypts the inner Type 4 message using A-C session
    const inner_msg = try noise_message.parseTransportMessage(result.payload);
    try std.testing.expectEqual(@as(u32, 2), inner_msg.receiver_index);

    var decrypt_buf: [1024]u8 = undefined;
    const pt_len = try session_c.decrypt(inner_msg.ciphertext, inner_msg.counter, &decrypt_buf);
    const plaintext = decrypt_buf[0..pt_len];

    const decoded = try noise_message.decodePayload(plaintext);
    try std.testing.expectEqual(noise_message.Protocol.chat, decoded.protocol);
    try std.testing.expectEqualStrings(original_data, decoded.payload);
}

test "relay multi-hop with noise session A->B->C->D" {
    const allocator = std.testing.allocator;

    // A-D end-to-end session
    const send_key_data = crypto_mod.hash(&.{"A-to-D send key"});
    const recv_key_data = crypto_mod.hash(&.{"A-to-D recv key"});
    const send_key = keypair_mod.Key{ .data = send_key_data };
    const recv_key = keypair_mod.Key{ .data = recv_key_data };

    var session_a = session_mod.Session.init(.{
        .local_index = 10,
        .remote_index = 20,
        .send_key = send_key,
        .recv_key = recv_key,
    });
    var session_d = session_mod.Session.init(.{
        .local_index = 20,
        .remote_index = 10,
        .send_key = recv_key,
        .recv_key = send_key,
    });

    const key_a = keyFromByte(0x0A);
    const key_c = keyFromByte(0x0C);
    const key_d = keyFromByte(0x0D);

    // Step 1: A encrypts
    const original_data = "multi-hop relay with real encryption!";
    const payload_enc = try noise_message.encodePayload(allocator, .icmp, original_data);
    defer allocator.free(payload_enc);

    var cipher_buf: [1024]u8 = undefined;
    const nonce = try session_a.encrypt(payload_enc, &cipher_buf);
    const ct_len = payload_enc.len + session_mod.tag_size;
    const type4msg = try noise_message.buildTransportMessage(
        allocator,
        session_a.remote_index,
        nonce,
        cipher_buf[0..ct_len],
    );
    defer allocator.free(type4msg);

    // Step 2: RELAY_0(dst=D)
    var r0_buf: [2048]u8 = undefined;
    const r0 = Relay0{ .ttl = 8, .strategy = .fastest, .dst_key = key_d, .payload = type4msg };
    const r0_n = try message.encodeRelay0(&r0, &r0_buf);

    // Step 3: B → RELAY_1 to C (D is via C)
    var sr_b = StaticRouter.init(allocator);
    defer sr_b.deinit();
    try sr_b.addRoute(key_d, key_c);
    const action1 = try handleRelay0(sr_b.router(), &key_a, r0_buf[0..r0_n]);
    try std.testing.expectEqual(@intFromEnum(noise_message.Protocol.relay_1), action1.protocol);

    // Step 4: C → RELAY_2 to D (D is direct)
    var sr_c = StaticRouter.init(allocator);
    defer sr_c.deinit();
    try sr_c.addRoute(key_d, key_d);
    const action2 = try handleRelay1(sr_c.router(), action1.data());
    try std.testing.expectEqual(@intFromEnum(noise_message.Protocol.relay_2), action2.protocol);

    // Step 5: D processes RELAY_2
    const result = try handleRelay2(action2.data());
    try std.testing.expectEqualSlices(u8, &key_a, &result.src_key);

    // Step 6: D decrypts
    const inner_msg = try noise_message.parseTransportMessage(result.payload);
    try std.testing.expectEqual(@as(u32, 20), inner_msg.receiver_index);

    var decrypt_buf: [1024]u8 = undefined;
    const pt_len = try session_d.decrypt(inner_msg.ciphertext, inner_msg.counter, &decrypt_buf);
    const plaintext = decrypt_buf[0..pt_len];

    const decoded = try noise_message.decodePayload(plaintext);
    try std.testing.expectEqual(noise_message.Protocol.icmp, decoded.protocol);
    try std.testing.expectEqualStrings(original_data, decoded.payload);
}
