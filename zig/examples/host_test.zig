//! Host TUN integration test with real TUN devices.
//!
//! Requires root/sudo to create TUN devices.
//!
//! Usage:
//!   zig build host_test && sudo ./zig-out/bin/host_test

const std = @import("std");
const posix = std.posix;
const mem = std.mem;
const noise = @import("noise");
const tun = @import("tun");

const Key = noise.Key;
const KeyPair = noise.KeyPair;
const UDPType = noise.UDP;
const HostType = noise.Host(UDPType);
const TunDevice = noise.TunDevice;

// ============================================================================
// RealTun wrapper: adapts tun.Tun to TunDevice interface
// ============================================================================

const RealTun = struct {
    dev: *tun.Tun,

    fn read(ptr: *anyopaque, buf: []u8) TunDevice.ReadError!usize {
        const self: *RealTun = @ptrCast(@alignCast(ptr));
        return self.dev.read(buf) catch TunDevice.ReadError.IoError;
    }

    fn write(ptr: *anyopaque, data: []const u8) TunDevice.WriteError!usize {
        const self: *RealTun = @ptrCast(@alignCast(ptr));
        return self.dev.write(data) catch TunDevice.WriteError.IoError;
    }

    fn close(ptr: *anyopaque) void {
        const self: *RealTun = @ptrCast(@alignCast(ptr));
        self.dev.close();
    }

    fn toTunDevice(self: *RealTun) TunDevice {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    const vtable = TunDevice.VTable{
        .read = RealTun.read,
        .write = RealTun.write,
        .close = RealTun.close,
    };
};

// ============================================================================
// Main
// ============================================================================

const print = std.debug.print;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    print("=== Host TUN Integration Test (Zig) ===\n\n", .{});

    // Check root (macOS uses libc getuid)
    if (std.c.getuid() != 0) {
        print("ERROR: This test requires root privileges.\n", .{});
        print("  sudo ./zig-out/bin/host_test\n", .{});
        std.process.exit(1);
    }

    // Generate keypairs
    const key_a = KeyPair.generate();
    const key_b = KeyPair.generate();
    print("Host A pubkey: {x}\n", .{key_a.public.data[0..8].*});
    print("Host B pubkey: {x}\n\n", .{key_b.public.data[0..8].*});

    // --- Create and configure TUN devices ---
    print("[1/5] Creating TUN devices...\n", .{});

    var tun_a = tun.Tun.create(null) catch |err| {
        print("FATAL: create TUN A: {}\n", .{err});
        std.process.exit(1);
    };
    var tun_b = tun.Tun.create(null) catch |err| {
        tun_a.close();
        print("FATAL: create TUN B: {}\n", .{err});
        std.process.exit(1);
    };

    print("  TUN A: {s}\n", .{tun_a.getName()});
    print("  TUN B: {s}\n", .{tun_b.getName()});

    // Configure TUN A: 100.64.0.1/24
    tun_a.setMtu(1400) catch |err| {
        print("FATAL: set MTU A: {}\n", .{err});
        std.process.exit(1);
    };
    tun_a.setIPv4(.{ 100, 64, 0, 1 }, .{ 255, 255, 255, 0 }) catch |err| {
        print("FATAL: set IPv4 A: {}\n", .{err});
        std.process.exit(1);
    };
    tun_a.setUp() catch |err| {
        print("FATAL: up A: {}\n", .{err});
        std.process.exit(1);
    };
    print("  TUN A: 100.64.0.1/24 UP\n", .{});

    // Configure TUN B: 100.64.1.1/24
    tun_b.setMtu(1400) catch |err| {
        print("FATAL: set MTU B: {}\n", .{err});
        std.process.exit(1);
    };
    tun_b.setIPv4(.{ 100, 64, 1, 1 }, .{ 255, 255, 255, 0 }) catch |err| {
        print("FATAL: set IPv4 B: {}\n", .{err});
        std.process.exit(1);
    };
    tun_b.setUp() catch |err| {
        print("FATAL: up B: {}\n", .{err});
        std.process.exit(1);
    };
    print("  TUN B: 100.64.1.1/24 UP\n\n", .{});

    // --- Create Hosts ---
    print("[2/5] Creating Hosts...\n", .{});

    var real_tun_a = try allocator.create(RealTun);
    real_tun_a.* = .{ .dev = &tun_a };
    var real_tun_b = try allocator.create(RealTun);
    real_tun_b.* = .{ .dev = &tun_b };

    const host_a = HostType.init(allocator, .{
        .private_key = &key_a,
        .tun_ipv4 = .{ 100, 64, 0, 1 },
        .mtu = 1400,
    }, real_tun_a.toTunDevice()) catch {
        print("FATAL: create Host A\n", .{});
        std.process.exit(1);
    };

    const host_b = HostType.init(allocator, .{
        .private_key = &key_b,
        .tun_ipv4 = .{ 100, 64, 1, 1 },
        .mtu = 1400,
    }, real_tun_b.toTunDevice()) catch {
        print("FATAL: create Host B\n", .{});
        std.process.exit(1);
    };

    const port_a = host_a.getLocalPort();
    const port_b = host_b.getLocalPort();
    print("  Host A: UDP :{d}\n", .{port_a});
    print("  Host B: UDP :{d}\n", .{port_b});

    // Add peers with static IPs
    var ep_b: posix.sockaddr.in = .{
        .family = posix.AF.INET,
        .port = mem.nativeToBig(u16, port_b),
        .addr = mem.nativeToBig(u32, 0x7F000001), // 127.0.0.1
    };
    var ep_a: posix.sockaddr.in = .{
        .family = posix.AF.INET,
        .port = mem.nativeToBig(u16, port_a),
        .addr = mem.nativeToBig(u32, 0x7F000001),
    };

    host_a.addPeerWithIp(
        key_b.public,
        @as(*posix.sockaddr, @ptrCast(&ep_b)).*,
        @sizeOf(posix.sockaddr.in),
        .{ 100, 64, 0, 2 },
    ) catch {
        print("FATAL: add peer B on A\n", .{});
        std.process.exit(1);
    };

    host_b.addPeerWithIp(
        key_a.public,
        @as(*posix.sockaddr, @ptrCast(&ep_a)).*,
        @sizeOf(posix.sockaddr.in),
        .{ 100, 64, 1, 2 },
    ) catch {
        print("FATAL: add peer A on B\n", .{});
        std.process.exit(1);
    };

    print("  Host A: peer B = 100.64.0.2\n", .{});
    print("  Host B: peer A = 100.64.1.2\n\n", .{});

    // --- Start forwarding ---
    print("[3/5] Starting forwarding loops...\n", .{});
    host_a.run();
    host_b.run();
    print("  OK\n\n", .{});

    // --- Handshake ---
    print("[4/5] Noise IK handshake (A -> B)...\n", .{});
    host_a.connect(&key_b.public) catch {
        print("FATAL: handshake failed\n", .{});
        std.process.exit(1);
    };
    print("  Handshake complete!\n\n", .{});

    // Small delay for routes to settle
    std.Thread.sleep(200 * std.time.ns_per_ms);

    // --- Run tests ---
    print("[5/5] Running tests...\n\n", .{});

    var passed: u32 = 0;
    var failed: u32 = 0;

    // Test 1: ping from A side to B (100.64.0.2)
    if (runPingTest(allocator, "A->B", "100.64.0.2")) {
        passed += 1;
    } else {
        failed += 1;
    }

    // Test 2: ping from B side to A (100.64.1.2)
    if (runPingTest(allocator, "B->A", "100.64.1.2")) {
        passed += 1;
    } else {
        failed += 1;
    }

    // Summary
    print("\n=== Results ===\n", .{});
    print("  Passed: {d}\n", .{passed});
    print("  Failed: {d}\n\n", .{failed});

    if (failed > 0) {
        print("SOME TESTS FAILED\n", .{});
        std.process.exit(1);
    }
    print("All tests passed!\n", .{});
    // TODO(async-tun): Replace process.exit(0) with graceful host.close()
    // once TUN uses async I/O (kqueue/io_uring). Currently close(fd) cannot
    // reliably interrupt blocking read(fd) on macOS. See design/14-async-tun.md.
    std.process.exit(0);
}

/// Run `ping -c 3 <target>` and check if it succeeds.
fn runPingTest(allocator: std.mem.Allocator, name: []const u8, target: []const u8) bool {
    print("--- Test: {s} (ping {s}) ---\n", .{ name, target });

    const result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &.{ "ping", "-c", "3", target },
    }) catch |err| {
        print("  RESULT: FAIL (exec error: {})\n", .{err});
        return false;
    };
    defer {
        allocator.free(result.stdout);
        allocator.free(result.stderr);
    }

    // Print indented output
    var lines = mem.splitScalar(u8, mem.trim(u8, result.stdout, &std.ascii.whitespace), '\n');
    while (lines.next()) |line| {
        print("  {s}\n", .{line});
    }

    if (result.term.Exited != 0) {
        print("  RESULT: FAIL (exit code {d})\n", .{result.term.Exited});
        return false;
    }

    // Check for "0.0% packet loss" or "0% packet loss"
    if (mem.indexOf(u8, result.stdout, "0.0% packet loss") != null or
        mem.indexOf(u8, result.stdout, " 0% packet loss") != null)
    {
        print("  RESULT: PASS\n", .{});
        return true;
    }

    print("  RESULT: FAIL (packet loss)\n", .{});
    return false;
}
