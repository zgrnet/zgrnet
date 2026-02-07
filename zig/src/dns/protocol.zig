//! Minimal DNS protocol parser (encode/decode).
//!
//! Supports A (1) and AAAA (28) query/response types.
//! Handles DNS name compression for decoding.

const std = @import("std");

/// DNS record types.
pub const TYPE_A: u16 = 1;
pub const TYPE_AAAA: u16 = 28;
pub const CLASS_IN: u16 = 1;

/// DNS header flag bits.
pub const FLAG_QR: u16 = 1 << 15;
pub const FLAG_AA: u16 = 1 << 10;
pub const FLAG_RD: u16 = 1 << 8;
pub const FLAG_RA: u16 = 1 << 7;
pub const MASK_RCODE: u16 = 0x000F;

/// DNS response codes.
pub const RCODE_NOERROR: u16 = 0;
pub const RCODE_FORMERR: u16 = 1;
pub const RCODE_SERVFAIL: u16 = 2;
pub const RCODE_NXDOMAIN: u16 = 3;

/// DNS errors.
pub const DnsError = error{
    Truncated,
    InvalidHeader,
    InvalidName,
    NameTooLong,
    LabelTooLong,
    PointerLoop,
    BufferTooSmall,
};

/// DNS message header (12 bytes).
pub const Header = struct {
    id: u16,
    flags: u16,
    qd_count: u16,
    an_count: u16,
    ns_count: u16,
    ar_count: u16,

    pub fn isResponse(self: *const Header) bool {
        return self.flags & FLAG_QR != 0;
    }

    pub fn rcode(self: *const Header) u16 {
        return self.flags & MASK_RCODE;
    }
};

/// DNS question entry.
pub const Question = struct {
    name: []const u8,
    qtype: u16,
    qclass: u16,
};

/// DNS resource record.
pub const ResourceRecord = struct {
    name: []const u8,
    rtype: u16,
    rclass: u16,
    ttl: u32,
    rdata: []const u8,
};

/// Complete DNS message.
pub const Message = struct {
    header: Header,
    questions: []Question,
    answers: []ResourceRecord,
    authorities: []ResourceRecord,
    additionals: []ResourceRecord,

    /// Decode a DNS message from wire format.
    pub fn decode(allocator: std.mem.Allocator, data: []const u8) DnsError!Message {
        if (data.len < 12) return DnsError.InvalidHeader;

        const header = Header{
            .id = std.mem.readInt(u16, data[0..2], .big),
            .flags = std.mem.readInt(u16, data[2..4], .big),
            .qd_count = std.mem.readInt(u16, data[4..6], .big),
            .an_count = std.mem.readInt(u16, data[6..8], .big),
            .ns_count = std.mem.readInt(u16, data[8..10], .big),
            .ar_count = std.mem.readInt(u16, data[10..12], .big),
        };

        var offset: usize = 12;

        // Decode questions
        const questions = allocator.alloc(Question, header.qd_count) catch return DnsError.BufferTooSmall;
        for (0..header.qd_count) |i| {
            const name_result = try decodeName(allocator, data, offset);
            offset += name_result.consumed;
            if (offset + 4 > data.len) return DnsError.Truncated;
            questions[i] = .{
                .name = name_result.name,
                .qtype = std.mem.readInt(u16, data[offset..][0..2], .big),
                .qclass = std.mem.readInt(u16, data[offset + 2 ..][0..2], .big),
            };
            offset += 4;
        }

        // Decode RR sections
        const ans_result = try decodeRRs(allocator, data, offset, header.an_count);
        offset = ans_result.offset;
        const auth_result = try decodeRRs(allocator, data, offset, header.ns_count);
        offset = auth_result.offset;
        const add_result = try decodeRRs(allocator, data, offset, header.ar_count);

        return .{
            .header = header,
            .questions = questions,
            .answers = ans_result.rrs,
            .authorities = auth_result.rrs,
            .additionals = add_result.rrs,
        };
    }

    /// Encode a DNS message to wire format.
    pub fn encode(self: *const Message, buf: []u8) DnsError![]u8 {
        if (buf.len < 12) return DnsError.BufferTooSmall;

        // Header
        std.mem.writeInt(u16, buf[0..2], self.header.id, .big);
        std.mem.writeInt(u16, buf[2..4], self.header.flags, .big);
        std.mem.writeInt(u16, buf[4..6], @intCast(self.questions.len), .big);
        std.mem.writeInt(u16, buf[6..8], @intCast(self.answers.len), .big);
        std.mem.writeInt(u16, buf[8..10], @intCast(self.authorities.len), .big);
        std.mem.writeInt(u16, buf[10..12], @intCast(self.additionals.len), .big);

        var offset: usize = 12;

        // Questions
        for (self.questions) |q| {
            const n = try encodeName(q.name, buf[offset..]);
            offset += n;
            if (offset + 4 > buf.len) return DnsError.BufferTooSmall;
            std.mem.writeInt(u16, buf[offset..][0..2], q.qtype, .big);
            std.mem.writeInt(u16, buf[offset + 2 ..][0..2], q.qclass, .big);
            offset += 4;
        }

        // Resource records
        for (self.answers) |rr| {
            offset += try encodeRR(rr, buf[offset..]);
        }
        for (self.authorities) |rr| {
            offset += try encodeRR(rr, buf[offset..]);
        }
        for (self.additionals) |rr| {
            offset += try encodeRR(rr, buf[offset..]);
        }

        return buf[0..offset];
    }

    /// Create a response message for the given query.
    pub fn newResponse(query: *const Message, rcode: u16, allocator: std.mem.Allocator) DnsError!Message {
        // Copy questions
        const questions = allocator.alloc(Question, query.questions.len) catch return DnsError.BufferTooSmall;
        @memcpy(questions, query.questions);

        return .{
            .header = .{
                .id = query.header.id,
                .flags = FLAG_QR | FLAG_AA | (query.header.flags & FLAG_RD) | rcode,
                .qd_count = @intCast(query.questions.len),
                .an_count = 0,
                .ns_count = 0,
                .ar_count = 0,
            },
            .questions = questions,
            .answers = &.{},
            .authorities = &.{},
            .additionals = &.{},
        };
    }
};

/// Create an A resource record.
/// Note: rdata points to the ip parameter which must outlive the ResourceRecord.
/// For heap-allocated rdata, use newARecordAlloc.
pub fn newARecord(name: []const u8, ttl: u32, ip: *const [4]u8) ResourceRecord {
    return .{
        .name = name,
        .rtype = TYPE_A,
        .rclass = CLASS_IN,
        .ttl = ttl,
        .rdata = ip,
    };
}

/// Create an A resource record with heap-allocated rdata.
pub fn newARecordAlloc(allocator: std.mem.Allocator, name: []const u8, ttl: u32, ip: [4]u8) !ResourceRecord {
    const rdata = try allocator.alloc(u8, 4);
    @memcpy(rdata, &ip);
    return .{
        .name = name,
        .rtype = TYPE_A,
        .rclass = CLASS_IN,
        .ttl = ttl,
        .rdata = rdata,
    };
}

/// Encode a domain name to wire format.
/// Returns the number of bytes written.
pub fn encodeName(name: []const u8, buf: []u8) DnsError!usize {
    if (name.len == 0 or (name.len == 1 and name[0] == '.')) {
        if (buf.len < 1) return DnsError.BufferTooSmall;
        buf[0] = 0;
        return 1;
    }

    // Trim trailing dot
    var input = name;
    if (input.len > 0 and input[input.len - 1] == '.') {
        input = input[0 .. input.len - 1];
    }

    var offset: usize = 0;
    var start: usize = 0;

    for (input, 0..) |c, i| {
        if (c == '.') {
            const label_len = i - start;
            if (label_len == 0) return DnsError.InvalidName;
            if (label_len > 63) return DnsError.LabelTooLong;
            if (offset + 1 + label_len > buf.len) return DnsError.BufferTooSmall;
            buf[offset] = @intCast(label_len);
            offset += 1;
            @memcpy(buf[offset .. offset + label_len], input[start..i]);
            offset += label_len;
            start = i + 1;
        }
    }

    // Last label
    const label_len = input.len - start;
    if (label_len == 0) return DnsError.InvalidName;
    if (label_len > 63) return DnsError.LabelTooLong;
    if (offset + 1 + label_len + 1 > buf.len) return DnsError.BufferTooSmall;
    buf[offset] = @intCast(label_len);
    offset += 1;
    @memcpy(buf[offset .. offset + label_len], input[start..]);
    offset += label_len;
    buf[offset] = 0; // Root
    offset += 1;

    return offset;
}

const DecodeNameResult = struct {
    name: []const u8,
    consumed: usize,
};

/// Decode a domain name from wire format with compression pointer support.
/// Maximum number of compression pointer jumps allowed during name decoding.
/// A DNS message is max 65535 bytes, but practically 512 without EDNS.
/// 128 jumps is far more than any legitimate message needs, and prevents
/// infinite loops from malicious pointer chains.
const MAX_POINTER_JUMPS: usize = 128;

pub fn decodeName(allocator: std.mem.Allocator, data: []const u8, offset: usize) DnsError!DecodeNameResult {
    var name_buf: [256]u8 = undefined;
    var name_len: usize = 0;
    var consumed: usize = 0;
    var jumped = false;
    var pos = offset;
    var jump_count: usize = 0;

    while (true) {
        if (pos >= data.len) return DnsError.Truncated;

        const length: usize = data[pos];

        if (length == 0) {
            if (!jumped) {
                consumed = pos - offset + 1;
            }
            break;
        }

        // Compression pointer
        if (length & 0xC0 == 0xC0) {
            if (pos + 1 >= data.len) return DnsError.Truncated;
            if (!jumped) {
                consumed = pos - offset + 2;
            }
            const ptr = (@as(usize, data[pos] & 0x3F) << 8) | @as(usize, data[pos + 1]);
            jump_count += 1;
            if (jump_count > MAX_POINTER_JUMPS) return DnsError.PointerLoop;
            pos = ptr;
            jumped = true;
            continue;
        }

        // Regular label
        pos += 1;
        if (pos + length > data.len) return DnsError.Truncated;
        if (name_len > 0) {
            if (name_len >= name_buf.len) return DnsError.NameTooLong;
            name_buf[name_len] = '.';
            name_len += 1;
        }
        if (name_len + length > name_buf.len) return DnsError.NameTooLong;
        @memcpy(name_buf[name_len .. name_len + length], data[pos .. pos + length]);
        name_len += length;
        pos += length;
    }

    if (name_len == 0) {
        const dot = allocator.alloc(u8, 1) catch return DnsError.BufferTooSmall;
        dot[0] = '.';
        return .{ .name = dot, .consumed = consumed };
    }

    const name = allocator.alloc(u8, name_len) catch return DnsError.BufferTooSmall;
    @memcpy(name, name_buf[0..name_len]);
    return .{ .name = name, .consumed = consumed };
}

const DecodeRRsResult = struct {
    rrs: []ResourceRecord,
    offset: usize,
};

fn decodeRRs(allocator: std.mem.Allocator, data: []const u8, start_offset: usize, count: u16) DnsError!DecodeRRsResult {
    const rrs = allocator.alloc(ResourceRecord, count) catch return DnsError.BufferTooSmall;
    var offset = start_offset;

    for (0..count) |i| {
        const name_result = try decodeName(allocator, data, offset);
        offset += name_result.consumed;

        if (offset + 10 > data.len) return DnsError.Truncated;

        const rtype = std.mem.readInt(u16, data[offset..][0..2], .big);
        const rclass = std.mem.readInt(u16, data[offset + 2 ..][0..2], .big);
        const ttl = std.mem.readInt(u32, data[offset + 4 ..][0..4], .big);
        const rd_len: usize = std.mem.readInt(u16, data[offset + 8 ..][0..2], .big);
        offset += 10;

        if (offset + rd_len > data.len) return DnsError.Truncated;

        const rdata = allocator.alloc(u8, rd_len) catch return DnsError.BufferTooSmall;
        @memcpy(rdata, data[offset .. offset + rd_len]);
        offset += rd_len;

        rrs[i] = .{
            .name = name_result.name,
            .rtype = rtype,
            .rclass = rclass,
            .ttl = ttl,
            .rdata = rdata,
        };
    }

    return .{ .rrs = rrs, .offset = offset };
}

fn encodeRR(rr: ResourceRecord, buf: []u8) DnsError!usize {
    var offset: usize = 0;
    const n = try encodeName(rr.name, buf[offset..]);
    offset += n;
    if (offset + 10 + rr.rdata.len > buf.len) return DnsError.BufferTooSmall;
    std.mem.writeInt(u16, buf[offset..][0..2], rr.rtype, .big);
    std.mem.writeInt(u16, buf[offset + 2 ..][0..2], rr.rclass, .big);
    std.mem.writeInt(u32, buf[offset + 4 ..][0..4], rr.ttl, .big);
    std.mem.writeInt(u16, buf[offset + 8 ..][0..2], @intCast(rr.rdata.len), .big);
    offset += 10;
    @memcpy(buf[offset .. offset + rr.rdata.len], rr.rdata);
    offset += rr.rdata.len;
    return offset;
}

// =============================================================================
// Tests
// =============================================================================

test "encodeName" {
    var buf: [256]u8 = undefined;

    const n1 = try encodeName("example.com", &buf);
    try std.testing.expectEqual(@as(usize, 13), n1);
    try std.testing.expectEqual(@as(u8, 7), buf[0]);
    try std.testing.expectEqualStrings("example", buf[1..8]);
    try std.testing.expectEqual(@as(u8, 3), buf[8]);
    try std.testing.expectEqualStrings("com", buf[9..12]);
    try std.testing.expectEqual(@as(u8, 0), buf[12]);

    // Root
    const n2 = try encodeName(".", &buf);
    try std.testing.expectEqual(@as(usize, 1), n2);
    try std.testing.expectEqual(@as(u8, 0), buf[0]);

    // Empty
    const n3 = try encodeName("", &buf);
    try std.testing.expectEqual(@as(usize, 1), n3);
}

test "encodeName errors" {
    var buf: [256]u8 = undefined;

    // Double dot
    try std.testing.expectError(DnsError.InvalidName, encodeName("example..com", &buf));
}

test "decodeName" {
    const data = [_]u8{ 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0 };
    const result = try decodeName(std.testing.allocator, &data, 0);
    defer std.testing.allocator.free(result.name);
    try std.testing.expectEqualStrings("example.com", result.name);
    try std.testing.expectEqual(@as(usize, 13), result.consumed);
}

test "decodeName compression" {
    var data: [15]u8 = undefined;
    // "example.com" at offset 0
    @memcpy(data[0..13], &[_]u8{ 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0 });
    // Pointer to offset 0
    data[13] = 0xC0;
    data[14] = 0x00;

    const result = try decodeName(std.testing.allocator, &data, 13);
    defer std.testing.allocator.free(result.name);
    try std.testing.expectEqualStrings("example.com", result.name);
    try std.testing.expectEqual(@as(usize, 2), result.consumed);
}

test "decodeName pointer loop" {
    const data = [_]u8{ 0xC0, 0x00 };
    try std.testing.expectError(DnsError.PointerLoop, decodeName(std.testing.allocator, &data, 0));
}

test "message roundtrip" {
    const allocator = std.testing.allocator;

    // Build a query
    var questions = [_]Question{.{
        .name = "example.com",
        .qtype = TYPE_A,
        .qclass = CLASS_IN,
    }};
    const query = Message{
        .header = .{
            .id = 0x1234,
            .flags = FLAG_RD,
            .qd_count = 1,
            .an_count = 0,
            .ns_count = 0,
            .ar_count = 0,
        },
        .questions = &questions,
        .answers = &.{},
        .authorities = &.{},
        .additionals = &.{},
    };

    var buf: [512]u8 = undefined;
    const encoded = try query.encode(&buf);

    const decoded = try Message.decode(allocator, encoded);
    defer {
        for (decoded.questions) |q| allocator.free(q.name);
        allocator.free(decoded.questions);
        allocator.free(decoded.answers);
        allocator.free(decoded.authorities);
        allocator.free(decoded.additionals);
    }

    try std.testing.expectEqual(@as(u16, 0x1234), decoded.header.id);
    try std.testing.expectEqual(FLAG_RD, decoded.header.flags);
    try std.testing.expectEqual(@as(usize, 1), decoded.questions.len);
    try std.testing.expectEqualStrings("example.com", decoded.questions[0].name);
    try std.testing.expectEqual(TYPE_A, decoded.questions[0].qtype);
}

test "response roundtrip" {
    const allocator = std.testing.allocator;

    var questions = [_]Question{.{
        .name = "localhost.zigor.net",
        .qtype = TYPE_A,
        .qclass = CLASS_IN,
    }};
    const query = Message{
        .header = .{ .id = 0xABCD, .flags = FLAG_RD, .qd_count = 1, .an_count = 0, .ns_count = 0, .ar_count = 0 },
        .questions = &questions,
        .answers = &.{},
        .authorities = &.{},
        .additionals = &.{},
    };

    var resp = try Message.newResponse(&query, RCODE_NOERROR, allocator);
    defer allocator.free(resp.questions);

    const rdata: [4]u8 = .{ 100, 64, 0, 1 };
    var answers = [_]ResourceRecord{.{
        .name = "localhost.zigor.net",
        .rtype = TYPE_A,
        .rclass = CLASS_IN,
        .ttl = 60,
        .rdata = &rdata,
    }};
    resp.answers = &answers;

    var buf: [512]u8 = undefined;
    const encoded = try resp.encode(&buf);

    const decoded = try Message.decode(allocator, encoded);
    defer {
        for (decoded.questions) |q| allocator.free(q.name);
        allocator.free(decoded.questions);
        for (decoded.answers) |a| {
            allocator.free(a.name);
            allocator.free(a.rdata);
        }
        allocator.free(decoded.answers);
        allocator.free(decoded.authorities);
        allocator.free(decoded.additionals);
    }

    try std.testing.expect(decoded.header.isResponse());
    try std.testing.expectEqual(@as(u16, 0xABCD), decoded.header.id);
    try std.testing.expectEqual(RCODE_NOERROR, decoded.header.rcode());
    try std.testing.expectEqual(@as(usize, 1), decoded.answers.len);
    try std.testing.expectEqualStrings("localhost.zigor.net", decoded.answers[0].name);
    try std.testing.expectEqual(TYPE_A, decoded.answers[0].rtype);
    try std.testing.expectEqual(@as(u32, 60), decoded.answers[0].ttl);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 100, 64, 0, 1 }, decoded.answers[0].rdata);
}

test "decode truncated" {
    try std.testing.expectError(DnsError.InvalidHeader, Message.decode(std.testing.allocator, &[_]u8{ 0, 1, 2 }));

    // Header says 1 question but no data — use arena to avoid leak detection
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var data = [_]u8{0} ** 12;
    data[5] = 1; // qd_count = 1
    try std.testing.expectError(DnsError.Truncated, Message.decode(arena.allocator(), &data));
}
