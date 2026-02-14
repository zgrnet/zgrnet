//! FEC - Forward Error Correction for KCP packet loss resilience.
//!
//! XOR-based parity encoding that adds redundancy to KCP output packets.
//! For a group of N data packets, produces 1 parity packet (XOR of all N).
//! If any single packet in the group is lost, it can be reconstructed from
//! the remaining N-1 data packets and the parity.
//!
//! Overhead: 1/N (e.g., N=3 → 33% overhead for single-loss recovery per group).
//!
//! ## Wire format
//!
//! Each FEC-wrapped packet has a 6-byte header:
//!
//!     [group_id: u16 LE][index: u8][count: u8][payload_len: u16 LE][payload...]
//!
//! - group_id: Monotonically increasing group counter (wraps at u16 max)
//! - index: Packet index within the group (0..count-1 for data, count for parity)
//! - count: Number of data packets in the group (N)
//! - payload_len: Actual data length (before padding, for parity reconstruction)
//!
//! The parity packet's payload is the XOR of all data packets' payloads,
//! zero-padded to the maximum packet length in the group.

const std = @import("std");

/// FEC packet header size: group_id(2) + index(1) + count(1) + payload_len(2) = 6 bytes.
pub const HeaderSize: usize = 6;

/// Maximum supported MTU for FEC packets.
pub const MaxMtu: usize = 1500;

/// Encode a FEC header into the buffer.
pub fn encodeHeader(buf: []u8, group_id: u16, index: u8, count: u8, payload_len: u16) void {
    std.mem.writeInt(u16, buf[0..2], group_id, .little);
    buf[2] = index;
    buf[3] = count;
    std.mem.writeInt(u16, buf[4..6], payload_len, .little);
}

/// Decode a FEC header from a buffer.
pub fn decodeHeader(buf: []const u8) !struct { group_id: u16, index: u8, count: u8, payload_len: u16 } {
    if (buf.len < HeaderSize) return error.FecPacketTooShort;
    return .{
        .group_id = std.mem.readInt(u16, buf[0..2], .little),
        .index = buf[2],
        .count = buf[3],
        .payload_len = std.mem.readInt(u16, buf[4..6], .little),
    };
}

/// XOR src into dst (dst ^= src). Operates on min(dst.len, src.len) bytes.
pub fn xorBytes(dst: []u8, src: []const u8) void {
    const len = @min(dst.len, src.len);
    for (0..len) |i| {
        dst[i] ^= src[i];
    }
}

// =============================================================================
// FEC Encoder
// =============================================================================

/// FEC Encoder — buffers output packets and emits groups with parity.
///
/// Usage:
///   1. Call `addPacket()` for each KCP output packet
///   2. When group_size packets accumulate, the encoder emits N+1 packets
///      (N data + 1 parity) via the output callback
///   3. Call `flushPartial()` to emit a partial group (e.g., on timer)
pub const Encoder = struct {
    group_size: u8,
    group_id: u16 = 0,
    buffered: u8 = 0,

    /// Buffered packet data: [group_size][MaxMtu]
    packet_buf: [max_group_size][MaxMtu]u8 = undefined,
    packet_lens: [max_group_size]u16 = .{0} ** max_group_size,

    /// Parity accumulator (running XOR).
    parity_buf: [MaxMtu]u8 = .{0} ** MaxMtu,
    max_payload_len: u16 = 0,

    /// Output callback: called with each FEC-wrapped packet.
    output_fn: *const fn (data: []const u8, user_data: ?*anyopaque) void,
    user_data: ?*anyopaque,

    const max_group_size: usize = 16;

    pub fn init(
        group_size: u8,
        output_fn: *const fn (data: []const u8, user_data: ?*anyopaque) void,
        user_data: ?*anyopaque,
    ) Encoder {
        return .{
            .group_size = if (group_size > max_group_size) max_group_size else group_size,
            .output_fn = output_fn,
            .user_data = user_data,
        };
    }

    /// Add a packet to the current group. Emits the group when full.
    pub fn addPacket(self: *Encoder, data: []const u8) void {
        if (data.len > MaxMtu) return; // Drop oversized packets
        if (self.buffered >= self.group_size) {
            self.emitGroup();
        }

        const idx = self.buffered;

        // Store packet data
        @memcpy(self.packet_buf[idx][0..data.len], data);
        // Zero-pad remainder for XOR
        if (data.len < MaxMtu) {
            @memset(self.packet_buf[idx][data.len..MaxMtu], 0);
        }
        self.packet_lens[idx] = @intCast(data.len);

        // Update parity (running XOR)
        xorBytes(&self.parity_buf, &self.packet_buf[idx]);
        if (data.len > self.max_payload_len) {
            self.max_payload_len = @intCast(data.len);
        }

        self.buffered += 1;

        if (self.buffered >= self.group_size) {
            self.emitGroup();
        }
    }

    /// Flush a partial group (fewer than group_size packets).
    /// Call this on a timer to avoid indefinite buffering.
    pub fn flushPartial(self: *Encoder) void {
        if (self.buffered > 0) {
            self.emitGroup();
        }
    }

    fn emitGroup(self: *Encoder) void {
        const count = self.buffered;
        if (count == 0) return;

        var emit_buf: [HeaderSize + MaxMtu]u8 = undefined;

        // Emit data packets with FEC header
        for (0..count) |i| {
            const plen = self.packet_lens[i];
            const total = HeaderSize + plen;
            encodeHeader(&emit_buf, self.group_id, @intCast(i), count, plen);
            @memcpy(emit_buf[HeaderSize..][0..plen], self.packet_buf[i][0..plen]);
            self.output_fn(emit_buf[0..total], self.user_data);
        }

        // Emit parity packet
        const parity_len = self.max_payload_len;
        const parity_total = HeaderSize + parity_len;
        encodeHeader(&emit_buf, self.group_id, count, count, parity_len);
        @memcpy(emit_buf[HeaderSize..][0..parity_len], self.parity_buf[0..parity_len]);
        self.output_fn(emit_buf[0..parity_total], self.user_data);

        // Reset for next group
        self.group_id +%= 1;
        self.buffered = 0;
        self.max_payload_len = 0;
        @memset(&self.parity_buf, 0);
    }
};

// =============================================================================
// FEC Decoder
// =============================================================================

/// FEC Decoder — receives FEC-wrapped packets and reconstructs lost data.
///
/// Tracks packet groups and attempts reconstruction when a single packet
/// is missing from a group (using XOR parity).
pub const Decoder = struct {
    /// Per-group tracking state.
    const Group = struct {
        received: u32 = 0, // Bitmask of received packet indices
        parity_received: bool = false,
        count: u8 = 0,
        packets: [Encoder.max_group_size + 1][MaxMtu]u8 = undefined,
        packet_lens: [Encoder.max_group_size + 1]u16 = .{0} ** (Encoder.max_group_size + 1),

        fn reset(self: *Group) void {
            self.received = 0;
            self.parity_received = false;
            self.count = 0;
        }
    };

    /// Circular buffer of groups, indexed by group_id % window_size.
    const window_size: usize = 64;
    groups: [window_size]Group = [_]Group{.{}} ** window_size,
    group_ids: [window_size]u16 = .{0} ** window_size,
    group_active: [window_size]bool = .{false} ** window_size,

    /// Output callback: called with each recovered data packet.
    output_fn: *const fn (data: []const u8, user_data: ?*anyopaque) void,
    user_data: ?*anyopaque,

    pub fn init(
        output_fn: *const fn (data: []const u8, user_data: ?*anyopaque) void,
        user_data: ?*anyopaque,
    ) Decoder {
        return .{
            .output_fn = output_fn,
            .user_data = user_data,
        };
    }

    /// Process a received FEC packet. Emits recovered data packets via output callback.
    pub fn addPacket(self: *Decoder, data: []const u8) void {
        const hdr = decodeHeader(data) catch return;
        if (data.len < HeaderSize + hdr.payload_len) return;

        // Validate untrusted wire values against array bounds.
        // count must be in [1, max_group_size], index in [0, count].
        if (hdr.count == 0 or hdr.count > Encoder.max_group_size) return;
        if (hdr.index > hdr.count) return;

        const payload = data[HeaderSize..][0..hdr.payload_len];
        const slot = hdr.group_id % window_size;

        // Initialize or validate group slot
        if (!self.group_active[slot] or self.group_ids[slot] != hdr.group_id) {
            // New group — reset slot
            self.groups[slot].reset();
            self.group_ids[slot] = hdr.group_id;
            self.group_active[slot] = true;
        }

        var group = &self.groups[slot];
        group.count = hdr.count;

        const is_parity = hdr.index == hdr.count;

        if (is_parity) {
            if (group.parity_received) return; // Duplicate
            group.parity_received = true;
            @memcpy(group.packets[hdr.count][0..hdr.payload_len], payload);
            if (hdr.payload_len < MaxMtu) {
                @memset(group.packets[hdr.count][hdr.payload_len..MaxMtu], 0);
            }
            group.packet_lens[hdr.count] = hdr.payload_len;
        } else {
            if (hdr.index >= hdr.count) return; // Invalid index
            const bit: u32 = @as(u32, 1) << @intCast(hdr.index);
            if (group.received & bit != 0) return; // Duplicate
            group.received |= bit;
            @memcpy(group.packets[hdr.index][0..hdr.payload_len], payload);
            if (hdr.payload_len < MaxMtu) {
                @memset(group.packets[hdr.index][hdr.payload_len..MaxMtu], 0);
            }
            group.packet_lens[hdr.index] = hdr.payload_len;

            // Emit this data packet immediately (don't wait for group completion)
            self.output_fn(payload, self.user_data);
        }

        // Check if we can recover a missing packet
        self.tryRecover(group);
    }

    fn tryRecover(self: *Decoder, group: *Group) void {
        if (!group.parity_received) return;

        const count = group.count;
        const all_received: u32 = (@as(u32, 1) << @intCast(count)) - 1;
        const received = group.received & all_received;
        const missing = all_received ^ received;

        // Can only recover exactly 1 missing packet
        if (missing == 0 or @popCount(missing) != 1) return;

        // Find the missing index
        const missing_idx: u5 = @intCast(@ctz(missing));

        // Reconstruct: XOR parity with all other received data packets
        var recovered: [MaxMtu]u8 = undefined;
        const parity_len = group.packet_lens[count];
        @memcpy(recovered[0..parity_len], group.packets[count][0..parity_len]);
        if (parity_len < MaxMtu) {
            @memset(recovered[parity_len..MaxMtu], 0);
        }

        for (0..count) |i| {
            if (i == missing_idx) continue;
            const plen = group.packet_lens[i];
            xorBytes(recovered[0..@max(plen, parity_len)], group.packets[i][0..@max(plen, parity_len)]);
        }

        group.received |= @as(u32, 1) << missing_idx;

        // Emit recovered packet
        self.output_fn(recovered[0..parity_len], self.user_data);
    }
};

// =============================================================================
// Tests
// =============================================================================

test "FEC header encode/decode roundtrip" {
    var buf: [HeaderSize]u8 = undefined;
    encodeHeader(&buf, 42, 2, 3, 1400);
    const hdr = try decodeHeader(&buf);
    try std.testing.expectEqual(@as(u16, 42), hdr.group_id);
    try std.testing.expectEqual(@as(u8, 2), hdr.index);
    try std.testing.expectEqual(@as(u8, 3), hdr.count);
    try std.testing.expectEqual(@as(u16, 1400), hdr.payload_len);
}

test "FEC xorBytes" {
    var a = [_]u8{ 0xAA, 0xBB, 0xCC };
    const b = [_]u8{ 0x55, 0x44, 0x33 };
    xorBytes(&a, &b);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xFF, 0xFF, 0xFF }, &a);
}

test "FEC encoder produces N+1 packets" {
    const TestCtx = struct {
        var count: usize = 0;
        fn output(_: []const u8, _: ?*anyopaque) void {
            count += 1;
        }
    };

    TestCtx.count = 0;
    var enc = Encoder.init(3, TestCtx.output, null);

    // Add 3 packets → should emit 4 (3 data + 1 parity)
    enc.addPacket("packet1");
    enc.addPacket("packet2");
    enc.addPacket("packet3");

    try std.testing.expectEqual(@as(usize, 4), TestCtx.count);
}

test "FEC encoder/decoder roundtrip with no loss" {
    const TestCtx = struct {
        var received_count: usize = 0;
        var packet_store: [16][MaxMtu]u8 = undefined;
        var packet_lens: [16]usize = .{0} ** 16;

        fn decoderOutput(data: []const u8, _: ?*anyopaque) void {
            if (received_count < 16) {
                @memcpy(packet_store[received_count][0..data.len], data);
                packet_lens[received_count] = data.len;
                received_count += 1;
            }
        }

        var fec_packets: [16][HeaderSize + MaxMtu]u8 = undefined;
        var fec_lens: [16]usize = .{0} ** 16;
        var fec_count: usize = 0;

        fn encoderOutput(data: []const u8, _: ?*anyopaque) void {
            if (fec_count < 16) {
                @memcpy(fec_packets[fec_count][0..data.len], data);
                fec_lens[fec_count] = data.len;
                fec_count += 1;
            }
        }
    };

    // Encoder: 3 packets per group
    TestCtx.fec_count = 0;
    TestCtx.received_count = 0;
    var enc = Encoder.init(3, TestCtx.encoderOutput, null);

    enc.addPacket("hello");
    enc.addPacket("world");
    enc.addPacket("test!");

    try std.testing.expectEqual(@as(usize, 4), TestCtx.fec_count);

    // Decoder: feed all 4 FEC packets
    var dec = Decoder.init(TestCtx.decoderOutput, null);
    for (0..TestCtx.fec_count) |i| {
        dec.addPacket(TestCtx.fec_packets[i][0..TestCtx.fec_lens[i]]);
    }

    // Should receive 3 data packets
    try std.testing.expectEqual(@as(usize, 3), TestCtx.received_count);
    try std.testing.expectEqualStrings("hello", TestCtx.packet_store[0][0..TestCtx.packet_lens[0]]);
    try std.testing.expectEqualStrings("world", TestCtx.packet_store[1][0..TestCtx.packet_lens[1]]);
    try std.testing.expectEqualStrings("test!", TestCtx.packet_store[2][0..TestCtx.packet_lens[2]]);
}

test "FEC recover single lost data packet" {
    const TestCtx = struct {
        var received_count: usize = 0;
        var packet_store: [16][MaxMtu]u8 = undefined;
        var packet_lens: [16]usize = .{0} ** 16;

        fn decoderOutput(data: []const u8, _: ?*anyopaque) void {
            if (received_count < 16) {
                @memcpy(packet_store[received_count][0..data.len], data);
                packet_lens[received_count] = data.len;
                received_count += 1;
            }
        }

        var fec_packets: [16][HeaderSize + MaxMtu]u8 = undefined;
        var fec_lens: [16]usize = .{0} ** 16;
        var fec_count: usize = 0;

        fn encoderOutput(data: []const u8, _: ?*anyopaque) void {
            if (fec_count < 16) {
                @memcpy(fec_packets[fec_count][0..data.len], data);
                fec_lens[fec_count] = data.len;
                fec_count += 1;
            }
        }
    };

    TestCtx.fec_count = 0;
    TestCtx.received_count = 0;

    var enc = Encoder.init(3, TestCtx.encoderOutput, null);
    // All packets same length for clean XOR recovery
    enc.addPacket("AAA");
    enc.addPacket("BBB");
    enc.addPacket("CCC");

    try std.testing.expectEqual(@as(usize, 4), TestCtx.fec_count);

    // Feed to decoder, SKIP packet index 1 ("BBB")
    var dec = Decoder.init(TestCtx.decoderOutput, null);
    dec.addPacket(TestCtx.fec_packets[0][0..TestCtx.fec_lens[0]]); // "AAA"
    // skip [1] "BBB"
    dec.addPacket(TestCtx.fec_packets[2][0..TestCtx.fec_lens[2]]); // "CCC"
    dec.addPacket(TestCtx.fec_packets[3][0..TestCtx.fec_lens[3]]); // parity

    // Should receive 3 packets: "AAA", "CCC" (immediate), and "BBB" (recovered)
    try std.testing.expectEqual(@as(usize, 3), TestCtx.received_count);

    // First two are immediate emissions: "AAA" and "CCC"
    try std.testing.expectEqualStrings("AAA", TestCtx.packet_store[0][0..TestCtx.packet_lens[0]]);
    try std.testing.expectEqualStrings("CCC", TestCtx.packet_store[1][0..TestCtx.packet_lens[1]]);

    // Third is recovered "BBB"
    try std.testing.expectEqualStrings("BBB", TestCtx.packet_store[2][0..TestCtx.packet_lens[2]]);
}

test "FEC decoder rejects out-of-bounds count and index" {
    const NullCtx = struct {
        fn output(_: []const u8, _: ?*anyopaque) void {}
    };
    var dec = Decoder.init(NullCtx.output, null);

    // count=255 (> max_group_size=16) — must be silently dropped, not OOB
    var bad1: [HeaderSize + 4]u8 = undefined;
    encodeHeader(&bad1, 0, 0, 255, 4);
    @memcpy(bad1[HeaderSize..][0..4], "XXXX");
    dec.addPacket(&bad1); // should not panic

    // count=0 — invalid, must be dropped
    var bad2: [HeaderSize + 4]u8 = undefined;
    encodeHeader(&bad2, 0, 0, 0, 4);
    @memcpy(bad2[HeaderSize..][0..4], "XXXX");
    dec.addPacket(&bad2); // should not panic

    // index > count — must be dropped
    var bad3: [HeaderSize + 4]u8 = undefined;
    encodeHeader(&bad3, 0, 5, 3, 4);
    @memcpy(bad3[HeaderSize..][0..4], "XXXX");
    dec.addPacket(&bad3); // should not panic
}
