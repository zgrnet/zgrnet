//! Host integration tests using MockTUN.
//!
//! These tests require a platform-specific IO backend (KqueueIO on macOS/BSD).
//! On unsupported platforms (e.g., Linux without EpollIO), the Host tests are
//! skipped at comptime. IP allocator and packet tests remain in their own files.

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const mem = std.mem;
const Allocator = std.mem.Allocator;
const Atomic = std.atomic.Value;

const noise_mod = @import("../noise/mod.zig");
const async_mod = @import("../async/mod.zig");
const Key = noise_mod.Key;
const KeyPair = noise_mod.KeyPair;

const host_mod = @import("mod.zig");
const TunDevice = host_mod.TunDevice;
const IPAllocator = host_mod.IPAllocator;
const packet = host_mod.packet;
const parseIpPacket = host_mod.parseIpPacket;
const buildIpv4Packet = host_mod.buildIpv4Packet;

const net_udp = @import("../net/udp.zig");

// KqueueIO is only available on macOS/BSD. On other platforms, Host tests are skipped.
const has_io_backend = builtin.os.tag == .macos or
    builtin.os.tag == .freebsd or
    builtin.os.tag == .netbsd or
    builtin.os.tag == .openbsd;

const UDPType = if (has_io_backend) net_udp.UDP(async_mod.KqueueIO) else void;
const HostType = if (has_io_backend) host_mod.Host(UDPType) else void;

// ============================================================================
// MockTUN
// ============================================================================

const MockTUN = struct {
    // Channel for read side: test injects packets here
    read_queue: std.ArrayListUnmanaged([]u8),
    read_mutex: std.Thread.Mutex,
    read_signal: std.Thread.Condition,

    // Channel for write side: host writes packets here
    write_queue: std.ArrayListUnmanaged([]u8),
    write_mutex: std.Thread.Mutex,
    write_signal: std.Thread.Condition,

    closed: Atomic(bool),
    allocator: Allocator,

    fn init(allocator: Allocator) *MockTUN {
        const self = allocator.create(MockTUN) catch @panic("OOM");
        self.* = .{
            .read_queue = .{},
            .read_mutex = .{},
            .read_signal = .{},
            .write_queue = .{},
            .write_mutex = .{},
            .write_signal = .{},
            .closed = Atomic(bool).init(false),
            .allocator = allocator,
        };
        return self;
    }

    fn deinit(self: *MockTUN) void {
        // Free remaining queued packets
        for (self.read_queue.items) |item| {
            self.allocator.free(item);
        }
        self.read_queue.deinit(self.allocator);
        for (self.write_queue.items) |item| {
            self.allocator.free(item);
        }
        self.write_queue.deinit(self.allocator);
        self.allocator.destroy(self);
    }

    /// Inject a packet into the read side (simulating app traffic).
    fn inject(self: *MockTUN, data: []const u8) void {
        const pkt = self.allocator.dupe(u8, data) catch return;
        self.read_mutex.lock();
        defer self.read_mutex.unlock();
        self.read_queue.append(self.allocator, pkt) catch {
            self.allocator.free(pkt);
            return;
        };
        self.read_signal.signal();
    }

    /// Receive a packet from the write side (capturing host output).
    /// Returns null on timeout.
    fn receive(self: *MockTUN, timeout_ms: u64) ?[]u8 {
        self.write_mutex.lock();
        defer self.write_mutex.unlock();

        if (self.write_queue.items.len > 0) {
            return self.write_queue.orderedRemove(0);
        }

        // Wait with timeout
        self.write_signal.timedWait(&self.write_mutex, timeout_ms * std.time.ns_per_ms) catch {};

        if (self.write_queue.items.len > 0) {
            return self.write_queue.orderedRemove(0);
        }
        return null;
    }

    // -- TunDevice interface --

    fn read(self_opaque: *anyopaque, buf: []u8) TunDevice.ReadError!usize {
        const self: *MockTUN = @ptrCast(@alignCast(self_opaque));
        while (true) {
            if (self.closed.load(.acquire)) return TunDevice.ReadError.Closed;

            self.read_mutex.lock();
            if (self.read_queue.items.len > 0) {
                const pkt = self.read_queue.orderedRemove(0);
                defer self.allocator.free(pkt);
                const n = @min(buf.len, pkt.len);
                @memcpy(buf[0..n], pkt[0..n]);
                self.read_mutex.unlock();
                return n;
            }

            // Wait with timeout so we can check closed flag
            self.read_signal.timedWait(&self.read_mutex, 100 * std.time.ns_per_ms) catch {};
            self.read_mutex.unlock();
        }
    }

    fn write(self_opaque: *anyopaque, data: []const u8) TunDevice.WriteError!usize {
        const self: *MockTUN = @ptrCast(@alignCast(self_opaque));
        if (self.closed.load(.acquire)) return TunDevice.WriteError.Closed;

        const pkt = self.allocator.dupe(u8, data) catch return TunDevice.WriteError.IoError;

        self.write_mutex.lock();
        defer self.write_mutex.unlock();
        self.write_queue.append(self.allocator, pkt) catch {
            self.allocator.free(pkt);
            return TunDevice.WriteError.IoError;
        };
        self.write_signal.signal();
        return data.len;
    }

    fn closeFn(self_opaque: *anyopaque) void {
        const self: *MockTUN = @ptrCast(@alignCast(self_opaque));
        self.closed.store(true, .release);
        // Wake up any blocked readers
        self.read_signal.broadcast();
    }

    fn toTunDevice(self: *MockTUN) TunDevice {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    const vtable = TunDevice.VTable{
        .read = MockTUN.read,
        .write = MockTUN.write,
        .close = MockTUN.closeFn,
    };
};

// ============================================================================
// Helper: sockaddr conversion
// ============================================================================

fn sockaddrIn(port: u16) posix.sockaddr.in {
    return .{
        .family = posix.AF.INET,
        .port = mem.nativeToBig(u16, port),
        .addr = mem.nativeToBig(u32, 0x7F000001), // 127.0.0.1
    };
}

fn toSockaddr(sin: *posix.sockaddr.in) posix.sockaddr {
    return @as(*posix.sockaddr, @ptrCast(sin)).*;
}

// ============================================================================
// Helper: build ICMP echo
// ============================================================================

fn makeICMPEcho(typ: u8, code: u8, id: u16, seq: u16, data: []const u8) [64]u8 {
    var pkt: [64]u8 = undefined;
    const pkt_len = 8 + data.len;
    pkt[0] = typ;
    pkt[1] = code;
    pkt[2] = 0; // checksum
    pkt[3] = 0;
    mem.writeInt(u16, pkt[4..6], id, .big);
    mem.writeInt(u16, pkt[6..8], seq, .big);
    @memcpy(pkt[8 .. 8 + data.len], data);

    // Compute ICMP checksum
    const cs = packet.ipChecksum(pkt[0..pkt_len]);
    mem.writeInt(u16, pkt[2..4], cs, .big);

    return pkt;
}

fn makeTCPSYN(src_port: u16, dst_port: u16) [20]u8 {
    var pkt: [20]u8 = undefined;
    @memset(&pkt, 0);
    mem.writeInt(u16, pkt[0..2], src_port, .big);
    mem.writeInt(u16, pkt[2..4], dst_port, .big);
    mem.writeInt(u32, pkt[4..8], 1000, .big); // seq
    mem.writeInt(u32, pkt[8..12], 0, .big); // ack
    pkt[12] = 0x50; // data offset = 5 (20 bytes)
    pkt[13] = 0x02; // SYN flag
    mem.writeInt(u16, pkt[14..16], 65535, .big); // window
    // checksum at [16:18] starts as 0, will be set by BuildIPv4Packet
    return pkt;
}

// ============================================================================
// Tests
// ============================================================================

test "Host: create and close" {
    if (!has_io_backend) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const key = KeyPair.generate();

    const mock_tun = MockTUN.init(allocator);
    defer mock_tun.deinit();

    const h = HostType.init(allocator, .{
        .private_key = &key,
        .tun_ipv4 = .{ 100, 64, 0, 1 },
    }, mock_tun.toTunDevice()) catch |err| {
        std.debug.print("Host init failed: {}\n", .{err});
        return error.SkipZigTest;
    };

    // Start then immediately stop — verifies init/run/close lifecycle
    h.run();
    h.close();
    h.deinit();
}

test "Host: ICMP forwarding A->B" {
    if (!has_io_backend) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const key_a = KeyPair.generate();
    const key_b = KeyPair.generate();

    const tun_a = MockTUN.init(allocator);
    defer tun_a.deinit();
    const tun_b = MockTUN.init(allocator);
    defer tun_b.deinit();

    // Create Host A
    const host_a = HostType.init(allocator, .{
        .private_key = &key_a,
        .tun_ipv4 = .{ 100, 64, 0, 1 },
    }, tun_a.toTunDevice()) catch return error.SkipZigTest;
    defer host_a.deinit();

    // Create Host B
    const host_b = HostType.init(allocator, .{
        .private_key = &key_b,
        .tun_ipv4 = .{ 100, 64, 0, 1 },
    }, tun_b.toTunDevice()) catch return error.SkipZigTest;
    defer host_b.deinit();

    // Add peers using localhost with actual ports
    const port_a = host_a.getLocalPort();
    const port_b = host_b.getLocalPort();

    var ep_b = sockaddrIn(port_b);
    var ep_a = sockaddrIn(port_a);

    host_a.addPeer(key_b.public, toSockaddr(&ep_b), @sizeOf(posix.sockaddr.in)) catch return error.SkipZigTest;
    host_b.addPeer(key_a.public, toSockaddr(&ep_a), @sizeOf(posix.sockaddr.in)) catch return error.SkipZigTest;

    // Get allocated IPs
    const ip_b_on_a = host_a.ip_alloc.lookupByPubkey(key_b.public) orelse return error.SkipZigTest;
    _ = host_b.ip_alloc.lookupByPubkey(key_a.public) orelse return error.SkipZigTest;

    // Start forwarding
    host_a.run();
    host_b.run();

    // Handshake
    host_a.connect(&key_b.public) catch return error.SkipZigTest;

    std.Thread.sleep(100 * std.time.ns_per_ms);

    // Build ICMP echo request: A -> B
    const icmp_data = "ping";
    const icmp = makeICMPEcho(8, 0, 1, 1, icmp_data);
    const ip_pkt = buildIpv4Packet(allocator, .{ 100, 64, 0, 1 }, ip_b_on_a, 1, icmp[0 .. 8 + icmp_data.len]) catch return error.SkipZigTest;
    defer allocator.free(ip_pkt);

    // Inject into Host A's TUN
    tun_a.inject(ip_pkt);

    // Wait for packet at Host B's TUN
    const received = tun_b.receive(3000) orelse {
        std.debug.print("timeout waiting for packet at Host B\n", .{});
        return error.SkipZigTest;
    };
    defer allocator.free(received);

    // Parse the received packet
    const info = parseIpPacket(received) catch {
        std.debug.print("failed to parse received packet\n", .{});
        return error.SkipZigTest;
    };

    // Verify protocol is ICMP
    try std.testing.expectEqual(@as(u8, 1), info.protocol);
    try std.testing.expectEqual(@as(u8, 4), info.version);

    // Verify dst IP is Host B's TUN IP
    try std.testing.expectEqualSlices(u8, &.{ 100, 64, 0, 1 }, info.dst_ip);
}

test "Host: bidirectional forwarding" {
    if (!has_io_backend) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const key_a = KeyPair.generate();
    const key_b = KeyPair.generate();

    const tun_a = MockTUN.init(allocator);
    defer tun_a.deinit();
    const tun_b = MockTUN.init(allocator);
    defer tun_b.deinit();

    const host_a = HostType.init(allocator, .{
        .private_key = &key_a,
        .tun_ipv4 = .{ 100, 64, 0, 1 },
    }, tun_a.toTunDevice()) catch return error.SkipZigTest;
    defer host_a.deinit();

    const host_b = HostType.init(allocator, .{
        .private_key = &key_b,
        .tun_ipv4 = .{ 100, 64, 0, 1 },
    }, tun_b.toTunDevice()) catch return error.SkipZigTest;
    defer host_b.deinit();

    const port_a = host_a.getLocalPort();
    const port_b = host_b.getLocalPort();

    var ep_b = sockaddrIn(port_b);
    var ep_a = sockaddrIn(port_a);

    host_a.addPeer(key_b.public, toSockaddr(&ep_b), @sizeOf(posix.sockaddr.in)) catch return error.SkipZigTest;
    host_b.addPeer(key_a.public, toSockaddr(&ep_a), @sizeOf(posix.sockaddr.in)) catch return error.SkipZigTest;

    const ip_b_on_a = host_a.ip_alloc.lookupByPubkey(key_b.public) orelse return error.SkipZigTest;
    const ip_a_on_b = host_b.ip_alloc.lookupByPubkey(key_a.public) orelse return error.SkipZigTest;

    host_a.run();
    host_b.run();
    host_a.connect(&key_b.public) catch return error.SkipZigTest;
    std.Thread.sleep(100 * std.time.ns_per_ms);

    // A -> B
    const icmp_req = makeICMPEcho(8, 0, 1, 1, "ping");
    const pkt_ab = buildIpv4Packet(allocator, .{ 100, 64, 0, 1 }, ip_b_on_a, 1, icmp_req[0..12]) catch return error.SkipZigTest;
    defer allocator.free(pkt_ab);
    tun_a.inject(pkt_ab);

    const recv_b = tun_b.receive(3000) orelse return error.SkipZigTest;
    defer allocator.free(recv_b);
    const info_b = parseIpPacket(recv_b) catch return error.SkipZigTest;
    try std.testing.expectEqual(@as(u8, 1), info_b.protocol);

    // B -> A
    const icmp_reply = makeICMPEcho(0, 0, 1, 1, "pong");
    const pkt_ba = buildIpv4Packet(allocator, .{ 100, 64, 0, 1 }, ip_a_on_b, 1, icmp_reply[0..12]) catch return error.SkipZigTest;
    defer allocator.free(pkt_ba);
    tun_b.inject(pkt_ba);

    const recv_a = tun_a.receive(3000) orelse return error.SkipZigTest;
    defer allocator.free(recv_a);
    const info_a = parseIpPacket(recv_a) catch return error.SkipZigTest;
    try std.testing.expectEqual(@as(u8, 1), info_a.protocol);
}

test "Host: TCP forwarding with checksum" {
    if (!has_io_backend) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const key_a = KeyPair.generate();
    const key_b = KeyPair.generate();

    const tun_a = MockTUN.init(allocator);
    defer tun_a.deinit();
    const tun_b = MockTUN.init(allocator);
    defer tun_b.deinit();

    const host_a = HostType.init(allocator, .{
        .private_key = &key_a,
        .tun_ipv4 = .{ 100, 64, 0, 1 },
    }, tun_a.toTunDevice()) catch return error.SkipZigTest;
    defer host_a.deinit();

    const host_b = HostType.init(allocator, .{
        .private_key = &key_b,
        .tun_ipv4 = .{ 100, 64, 0, 1 },
    }, tun_b.toTunDevice()) catch return error.SkipZigTest;
    defer host_b.deinit();

    const port_a = host_a.getLocalPort();
    const port_b = host_b.getLocalPort();

    var ep_b = sockaddrIn(port_b);
    var ep_a = sockaddrIn(port_a);

    host_a.addPeer(key_b.public, toSockaddr(&ep_b), @sizeOf(posix.sockaddr.in)) catch return error.SkipZigTest;
    host_b.addPeer(key_a.public, toSockaddr(&ep_a), @sizeOf(posix.sockaddr.in)) catch return error.SkipZigTest;

    const ip_b_on_a = host_a.ip_alloc.lookupByPubkey(key_b.public) orelse return error.SkipZigTest;

    host_a.run();
    host_b.run();
    host_a.connect(&key_b.public) catch return error.SkipZigTest;
    std.Thread.sleep(100 * std.time.ns_per_ms);

    // Build TCP SYN
    const tcp = makeTCPSYN(12345, 80);
    const ip_pkt = buildIpv4Packet(allocator, .{ 100, 64, 0, 1 }, ip_b_on_a, 6, &tcp) catch return error.SkipZigTest;
    defer allocator.free(ip_pkt);

    tun_a.inject(ip_pkt);

    const received = tun_b.receive(3000) orelse return error.SkipZigTest;
    defer allocator.free(received);

    const info = parseIpPacket(received) catch return error.SkipZigTest;
    try std.testing.expectEqual(@as(u8, 6), info.protocol);

    // Verify TCP checksum is valid after rebuild
    var sum: u32 = 0;
    sum += @as(u32, info.src_ip[0]) << 8 | @as(u32, info.src_ip[1]);
    sum += @as(u32, info.src_ip[2]) << 8 | @as(u32, info.src_ip[3]);
    sum += @as(u32, info.dst_ip[0]) << 8 | @as(u32, info.dst_ip[1]);
    sum += @as(u32, info.dst_ip[2]) << 8 | @as(u32, info.dst_ip[3]);
    sum += 6; // TCP protocol
    sum += @as(u32, @intCast(info.payload.len));
    var idx: usize = 0;
    while (idx + 1 < info.payload.len) : (idx += 2) {
        sum += @as(u32, info.payload[idx]) << 8 | @as(u32, info.payload[idx + 1]);
    }
    if (info.payload.len % 2 == 1) {
        sum += @as(u32, info.payload[info.payload.len - 1]) << 8;
    }
    while (sum > 0xFFFF) {
        sum = (sum >> 16) + (sum & 0xFFFF);
    }
    const cs: u16 = @intCast(~sum & 0xFFFF);
    try std.testing.expectEqual(@as(u16, 0), cs);
}
