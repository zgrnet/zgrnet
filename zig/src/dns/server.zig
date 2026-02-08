//! Magic DNS server with zigor.net resolution and upstream forwarding.

const std = @import("std");
const protocol = @import("protocol.zig");
const fakeip_mod = @import("fakeip.zig");

const Message = protocol.Message;
const Header = protocol.Header;
const Question = protocol.Question;
const ResourceRecord = protocol.ResourceRecord;
const DnsError = protocol.DnsError;
const FakeIPPool = fakeip_mod.FakeIPPool;

pub const DEFAULT_TTL: u32 = 60;
pub const ZIGOR_NET_SUFFIX = ".zigor.net";

/// IPAllocator interface for pubkey -> IP mapping.
pub const IPAllocator = struct {
    ptr: *anyopaque,
    lookupByPubkeyFn: *const fn (ptr: *anyopaque, pubkey: *const [32]u8) ?[4]u8,

    pub fn lookupByPubkey(self: *const IPAllocator, pubkey: *const [32]u8) ?[4]u8 {
        return self.lookupByPubkeyFn(self.ptr, pubkey);
    }
};

/// Server configuration.
pub const ServerConfig = struct {
    tun_ipv4: [4]u8 = .{ 100, 64, 0, 1 },
    tun_ipv6: ?[16]u8 = null,
    upstream: []const u8 = "8.8.8.8",
    upstream_port: u16 = 53,
    ip_alloc: ?IPAllocator = null,
    fake_pool: ?*FakeIPPool = null,
    match_domains: []const []const u8 = &.{},
};

/// Magic DNS server.
pub const Server = struct {
    config: ServerConfig,
    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, config: ServerConfig) Self {
        return .{ .config = config, .allocator = allocator };
    }

    /// Handle a DNS query and return response bytes written to buf.
    pub fn handleQuery(self: *const Self, query_data: []const u8, buf: []u8) ![]u8 {
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const alloc = arena.allocator();

        const msg = Message.decode(alloc, query_data) catch {
            return error.InvalidQuery;
        };

        if (msg.questions.len == 0) {
            var resp = Message.newResponse(&msg, protocol.RCODE_FORMERR, alloc) catch return error.EncodeFailed;
            return resp.encode(buf) catch return error.EncodeFailed;
        }

        const q = msg.questions[0];

        // Lowercase the name for comparison
        var name_lower: [256]u8 = undefined;
        const name_len = @min(q.name.len, 255);
        for (0..name_len) |i| {
            name_lower[i] = std.ascii.toLower(q.name[i]);
        }
        const name = name_lower[0..name_len];

        // zigor.net resolution
        if (endsWith(name, ZIGOR_NET_SUFFIX) or std.mem.eql(u8, name, "zigor.net")) {
            return self.resolveZigorNet(alloc, &msg, name, q.qtype, buf);
        }

        // Fake IP matching
        if (self.config.fake_pool != null and self.matchesDomain(name)) {
            return self.resolveFakeIP(alloc, &msg, name, q.qtype, buf);
        }

        // Forward upstream
        return self.forwardUpstream(query_data, buf);
    }

    fn resolveZigorNet(self: *const Self, alloc: std.mem.Allocator, query: *const Message, name: []const u8, qtype: u16, buf: []u8) ![]u8 {
        const subdomain = if (std.mem.eql(u8, name, "zigor.net"))
            ""
        else if (name.len > ZIGOR_NET_SUFFIX.len)
            name[0 .. name.len - ZIGOR_NET_SUFFIX.len]
        else
            "";

        // localhost.zigor.net
        if (std.mem.eql(u8, subdomain, "localhost")) {
            return self.respondWithTunIP(alloc, query, name, qtype, buf);
        }

        // Split pubkey: {first32hex}.{last32hex}.zigor.net
        // Pubkey is split into two 32-char labels to comply with RFC 1035 (max 63 chars/label).
        if (std.mem.indexOfScalar(u8, subdomain, '.')) |dot_pos| {
            const first = subdomain[0..dot_pos];
            const rest = subdomain[dot_pos + 1 ..];
            if (first.len + rest.len == 64 and isHexString(first) and isHexString(rest)) {
                var combined: [64]u8 = undefined;
                @memcpy(combined[0..first.len], first);
                @memcpy(combined[first.len..64], rest);
                return self.respondWithPeerIP(alloc, query, name, &combined, qtype, buf);
            }
        }

        // Unknown -> NXDOMAIN
        var resp = Message.newResponse(query, protocol.RCODE_NXDOMAIN, alloc) catch return error.EncodeFailed;
        return resp.encode(buf) catch return error.EncodeFailed;
    }

    fn respondWithTunIP(self: *const Self, alloc: std.mem.Allocator, query: *const Message, name: []const u8, qtype: u16, buf: []u8) ![]u8 {
        var resp = Message.newResponse(query, protocol.RCODE_NOERROR, alloc) catch return error.EncodeFailed;

        if (qtype == protocol.TYPE_A) {
            var answers = alloc.alloc(ResourceRecord, 1) catch return error.EncodeFailed;
            answers[0] = protocol.newARecordAlloc(alloc, name, DEFAULT_TTL, self.config.tun_ipv4) catch return error.EncodeFailed;
            resp.answers = answers;
        }

        return resp.encode(buf) catch return error.EncodeFailed;
    }

    fn respondWithPeerIP(self: *const Self, alloc: std.mem.Allocator, query: *const Message, name: []const u8, hex_pubkey: []const u8, qtype: u16, buf: []u8) ![]u8 {
        const ip_alloc = self.config.ip_alloc orelse {
            var resp = Message.newResponse(query, protocol.RCODE_SERVFAIL, alloc) catch return error.EncodeFailed;
            return resp.encode(buf) catch return error.EncodeFailed;
        };

        // Decode hex pubkey using std library
        var pubkey: [32]u8 = undefined;
        _ = std.fmt.hexToBytes(&pubkey, hex_pubkey) catch {
            var resp = Message.newResponse(query, protocol.RCODE_NXDOMAIN, alloc) catch return error.EncodeFailed;
            return resp.encode(buf) catch return error.EncodeFailed;
        };

        const ip = ip_alloc.lookupByPubkey(&pubkey) orelse {
            var resp = Message.newResponse(query, protocol.RCODE_NXDOMAIN, alloc) catch return error.EncodeFailed;
            return resp.encode(buf) catch return error.EncodeFailed;
        };

        var resp = Message.newResponse(query, protocol.RCODE_NOERROR, alloc) catch return error.EncodeFailed;
        if (qtype == protocol.TYPE_A) {
            var answers = alloc.alloc(ResourceRecord, 1) catch return error.EncodeFailed;
            answers[0] = protocol.newARecordAlloc(alloc, name, DEFAULT_TTL, ip) catch return error.EncodeFailed;
            resp.answers = answers;
        }
        return resp.encode(buf) catch return error.EncodeFailed;
    }

    fn resolveFakeIP(self: *const Self, alloc: std.mem.Allocator, query: *const Message, name: []const u8, qtype: u16, buf: []u8) ![]u8 {
        if (qtype != protocol.TYPE_A) {
            var resp = Message.newResponse(query, protocol.RCODE_NOERROR, alloc) catch return error.EncodeFailed;
            return resp.encode(buf) catch return error.EncodeFailed;
        }

        const pool = self.config.fake_pool.?;
        const ip = pool.assign(name);

        var resp = Message.newResponse(query, protocol.RCODE_NOERROR, alloc) catch return error.EncodeFailed;
        var answers = alloc.alloc(ResourceRecord, 1) catch return error.EncodeFailed;
        answers[0] = protocol.newARecordAlloc(alloc, name, DEFAULT_TTL, ip) catch return error.EncodeFailed;
        resp.answers = answers;
        return resp.encode(buf) catch return error.EncodeFailed;
    }

    // TODO: Implement upstream DNS forwarding for Zig.
    // Zig's std networking is async (io_uring/kqueue based), so a synchronous
    // UDP sendto/recvfrom needs posix syscalls directly. Deferring to when
    // the Zig DNS server is integrated with the async event loop.
    fn forwardUpstream(self: *const Self, query_data: []const u8, buf: []u8) ![]u8 {
        _ = self;
        _ = query_data;
        _ = buf;
        return error.UpstreamUnavailable;
    }

    fn matchesDomain(self: *const Self, name: []const u8) bool {
        for (self.config.match_domains) |suffix| {
            if (endsWith(name, suffix)) return true;
        }
        return false;
    }
};

fn endsWith(haystack: []const u8, needle: []const u8) bool {
    if (needle.len > haystack.len) return false;
    return std.mem.eql(u8, haystack[haystack.len - needle.len ..], needle);
}

fn isHexString(s: []const u8) bool {
    if (s.len == 0) return false;
    for (s) |c| {
        if (!std.ascii.isHex(c)) return false;
    }
    return true;
}


// =============================================================================
// Tests
// =============================================================================

const testing = std.testing;

fn buildQuery(alloc: std.mem.Allocator, name: []const u8, qtype: u16) ![]u8 {
    var questions = try alloc.alloc(Question, 1);
    questions[0] = .{ .name = name, .qtype = qtype, .qclass = protocol.CLASS_IN };

    const msg = Message{
        .header = .{ .id = 0x1234, .flags = protocol.FLAG_RD, .qd_count = 1, .an_count = 0, .ns_count = 0, .ar_count = 0 },
        .questions = questions,
        .answers = &.{},
        .authorities = &.{},
        .additionals = &.{},
    };
    var buf: [512]u8 = undefined;
    const encoded = try msg.encode(&buf);
    const result = try alloc.dupe(u8, encoded);
    return result;
}

test "server: localhost.zigor.net" {
    const alloc = testing.allocator;
    const srv = Server.init(alloc, .{ .tun_ipv4 = .{ 100, 64, 0, 1 } });

    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();

    const query = try buildQuery(arena.allocator(), "localhost.zigor.net", protocol.TYPE_A);
    var resp_buf: [512]u8 = undefined;
    const resp_data = try srv.handleQuery(query, &resp_buf);

    const resp = try Message.decode(arena.allocator(), resp_data);
    try testing.expectEqual(protocol.RCODE_NOERROR, resp.header.rcode());
    try testing.expectEqual(@as(usize, 1), resp.answers.len);
    try testing.expectEqualSlices(u8, &[_]u8{ 100, 64, 0, 1 }, resp.answers[0].rdata);
}

test "server: case insensitive" {
    const alloc = testing.allocator;
    const srv = Server.init(alloc, .{ .tun_ipv4 = .{ 100, 64, 0, 1 } });

    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();

    const query = try buildQuery(arena.allocator(), "LOCALHOST.ZIGOR.NET", protocol.TYPE_A);
    var resp_buf: [512]u8 = undefined;
    const resp_data = try srv.handleQuery(query, &resp_buf);

    const resp = try Message.decode(arena.allocator(), resp_data);
    try testing.expectEqual(protocol.RCODE_NOERROR, resp.header.rcode());
    try testing.expectEqual(@as(usize, 1), resp.answers.len);
}

test "server: unknown subdomain -> NXDOMAIN" {
    const alloc = testing.allocator;
    const srv = Server.init(alloc, .{});

    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();

    const query = try buildQuery(arena.allocator(), "unknown.zigor.net", protocol.TYPE_A);
    var resp_buf: [512]u8 = undefined;
    const resp_data = try srv.handleQuery(query, &resp_buf);

    const resp = try Message.decode(arena.allocator(), resp_data);
    try testing.expectEqual(protocol.RCODE_NXDOMAIN, resp.header.rcode());
}

test "server: no allocator -> SERVFAIL" {
    const alloc = testing.allocator;
    const srv = Server.init(alloc, .{});

    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();

    // Split pubkey format
    const query = try buildQuery(arena.allocator(), "00000000000000000000000000000000.00000000000000000000000000000000.zigor.net", protocol.TYPE_A);
    var resp_buf: [512]u8 = undefined;
    const resp_data = try srv.handleQuery(query, &resp_buf);

    const resp = try Message.decode(arena.allocator(), resp_data);
    try testing.expectEqual(protocol.RCODE_SERVFAIL, resp.header.rcode());
}

test "server: empty query -> FORMERR" {
    const alloc = testing.allocator;
    const srv = Server.init(alloc, .{});

    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();

    const msg = Message{
        .header = .{ .id = 0x1234, .flags = protocol.FLAG_RD, .qd_count = 0, .an_count = 0, .ns_count = 0, .ar_count = 0 },
        .questions = &.{},
        .answers = &.{},
        .authorities = &.{},
        .additionals = &.{},
    };
    var enc_buf: [512]u8 = undefined;
    const query = try msg.encode(&enc_buf);
    const query_copy = try arena.allocator().dupe(u8, query);

    var resp_buf: [512]u8 = undefined;
    const resp_data = try srv.handleQuery(query_copy, &resp_buf);

    const resp = try Message.decode(arena.allocator(), resp_data);
    try testing.expectEqual(protocol.RCODE_FORMERR, resp.header.rcode());
}

test "server: fake IP" {
    const alloc = testing.allocator;
    var pool = FakeIPPool.init(alloc, 100);
    defer pool.deinit();

    const match_domains = [_][]const u8{".example.com"};
    const srv = Server.init(alloc, .{
        .fake_pool = &pool,
        .match_domains = &match_domains,
    });

    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();

    const query = try buildQuery(arena.allocator(), "test.example.com", protocol.TYPE_A);
    var resp_buf: [512]u8 = undefined;
    const resp_data = try srv.handleQuery(query, &resp_buf);

    const resp = try Message.decode(arena.allocator(), resp_data);
    try testing.expectEqual(protocol.RCODE_NOERROR, resp.header.rcode());
    try testing.expectEqual(@as(usize, 1), resp.answers.len);
    try testing.expectEqual(@as(u8, 198), resp.answers[0].rdata[0]);
    try testing.expectEqual(@as(u8, 18), resp.answers[0].rdata[1]);
}

test "isHexString" {
    try testing.expect(isHexString("0123456789abcdef"));
    try testing.expect(isHexString("ABCDEF"));
    try testing.expect(!isHexString(""));
    try testing.expect(!isHexString("0123g"));
}

test "server: bare zigor.net -> NXDOMAIN" {
    const alloc = testing.allocator;
    const srv = Server.init(alloc, .{ .tun_ipv4 = .{ 100, 64, 0, 1 } });

    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();

    const query = try buildQuery(arena.allocator(), "zigor.net", protocol.TYPE_A);
    var resp_buf: [512]u8 = undefined;
    const resp_data = try srv.handleQuery(query, &resp_buf);

    const resp = try Message.decode(arena.allocator(), resp_data);
    try testing.expectEqual(protocol.RCODE_NXDOMAIN, resp.header.rcode());
}

test "server: fake IP AAAA -> empty" {
    const alloc = testing.allocator;
    var pool = FakeIPPool.init(alloc, 100);
    defer pool.deinit();

    const match_domains = [_][]const u8{".example.com"};
    const srv = Server.init(alloc, .{
        .fake_pool = &pool,
        .match_domains = &match_domains,
    });

    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();

    const query = try buildQuery(arena.allocator(), "test.example.com", protocol.TYPE_AAAA);
    var resp_buf: [512]u8 = undefined;
    const resp_data = try srv.handleQuery(query, &resp_buf);

    const resp = try Message.decode(arena.allocator(), resp_data);
    try testing.expectEqual(protocol.RCODE_NOERROR, resp.header.rcode());
    try testing.expectEqual(@as(usize, 0), resp.answers.len);
}

test "server: malformed query" {
    const alloc = testing.allocator;
    const srv = Server.init(alloc, .{});
    var resp_buf: [512]u8 = undefined;
    const result = srv.handleQuery(&[_]u8{ 0x00, 0x01 }, &resp_buf);
    try testing.expectError(error.InvalidQuery, result);
}

test "endsWith" {
    try testing.expect(endsWith("localhost.zigor.net", ".zigor.net"));
    try testing.expect(endsWith(".zigor.net", ".zigor.net"));
    try testing.expect(!endsWith("google.com", ".zigor.net"));
    try testing.expect(!endsWith("net", ".zigor.net"));
}

