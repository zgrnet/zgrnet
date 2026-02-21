//! KCP stream interoperability test — Zig side.
//!
//! Usage: kcp_test --name zig --config ../config.json

const std = @import("std");
const noise = @import("noise");

const Key = noise.Key;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Parse args.
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    var name: ?[]const u8 = null;
    var config_path: ?[]const u8 = null;
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--name") and i + 1 < args.len) {
            i += 1;
            name = args[i];
        } else if (std.mem.eql(u8, args[i], "--config") and i + 1 < args.len) {
            i += 1;
            config_path = args[i];
        }
    }
    const my_name = name orelse return error.MissingName;
    const cfg_path = config_path orelse return error.MissingConfig;

    // Parse config JSON.
    const config_data = try std.fs.cwd().readFileAlloc(allocator, cfg_path, 1024 * 1024);
    defer allocator.free(config_data);

    const parsed = try std.json.parseFromSlice(Config, allocator, config_data, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    const config = parsed.value;

    // Find our host.
    var my_host: ?HostInfo = null;
    var peer_host: ?HostInfo = null;
    for (config.hosts) |h| {
        if (std.mem.eql(u8, h.name, my_name)) {
            my_host = h;
        } else {
            peer_host = h;
        }
    }
    const me = my_host orelse return error.HostNotFound;
    const peer = peer_host orelse return error.PeerNotFound;

    // Parse keys.
    var priv_key: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&priv_key, me.private_key);
    const kp = noise.KeyPair.fromPrivate(Key.fromBytes(priv_key));

    var peer_priv: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&peer_priv, peer.private_key);
    const peer_kp = noise.KeyPair.fromPrivate(Key.fromBytes(peer_priv));

    std.log.info("[{s}] Public key: {x}...", .{ my_name, kp.public.asBytes()[0..8].* });
    std.log.info("[{s}] Role: {s}", .{ my_name, me.role });

    // Create UDP.
    const bind_addr_str = try std.fmt.allocPrint(allocator, "127.0.0.1:{d}", .{me.port});
    defer allocator.free(bind_addr_str);

    const udp = try noise.UDP.init(allocator, &kp, .{
        .bind_addr = bind_addr_str,
        .allow_unknown = true,
        .decrypt_workers = 1,
    });
    defer udp.deinit();

    std.log.info("[{s}] Listening on port {d}", .{ my_name, me.port });

    // Add peer.
    const Endpoint = noise.net.endpoint_mod.Endpoint;
    udp.setPeerEndpoint(peer_kp.public, Endpoint.init(.{ 127, 0, 0, 1 }, peer.port));

    // Determine mode.
    const mode = config.@"test".mode;
    const is_opener = std.mem.eql(u8, me.role, "opener");

    if (is_opener) {
        std.log.info("[{s}] Waiting for peer...", .{my_name});
        std.Thread.sleep(2 * std.time.ns_per_s);

        std.log.info("[{s}] Connecting...", .{my_name});
        try udp.connectTimeout(&peer_kp.public, 10_000);
        std.Thread.sleep(200 * std.time.ns_per_ms);

        // Open stream.
        var stream = try udp.openStream(&peer_kp.public, 1); // Service.proxy = 1
        defer stream.close();

        if (std.mem.eql(u8, mode, "echo") or mode.len == 0) {
            const msg = config.@"test".echo_message;
            _ = try stream.write(msg);
            std.log.info("[opener] Sent: {s}", .{msg});
            var buf: [4096]u8 = undefined;
            const n = try stream.read(&buf);
            std.log.info("[opener] Response: {s}", .{buf[0..n]});
        } else if (std.mem.eql(u8, mode, "streaming")) {
            const total = config.@"test".throughput_mb * 1024 * 1024;
            const chunk = try allocator.alloc(u8, 8192);
            defer allocator.free(chunk);
            @memset(chunk, 0x58);
            var sent: usize = 0;
            while (sent < total) {
                const n = try stream.write(chunk);
                sent += n;
            }
            std.log.info("[opener] Sent {d} bytes", .{sent});
        }

        std.Thread.sleep(1 * std.time.ns_per_s);
    } else {
        std.log.info("[{s}] Waiting for connection...", .{my_name});

        // Wait for opener to connect.
        std.Thread.sleep(5 * std.time.ns_per_s);

        const result = try udp.acceptStream(&peer_kp.public);
        var stream = result.stream;
        defer stream.close();

        std.log.info("[accepter] Accepted stream on service={d}", .{result.service});

        if (std.mem.eql(u8, mode, "echo") or mode.len == 0) {
            var buf: [4096]u8 = undefined;
            const n = try stream.read(&buf);
            std.log.info("[accepter] Received: {s}", .{buf[0..n]});
            const response = try std.fmt.allocPrint(allocator, "Echo: {s}", .{buf[0..n]});
            defer allocator.free(response);
            _ = try stream.write(response);
            std.log.info("[accepter] Sent: {s}", .{response});
        } else if (std.mem.eql(u8, mode, "streaming")) {
            const total = config.@"test".throughput_mb * 1024 * 1024;
            var buf: [65536]u8 = undefined;
            var recv: usize = 0;
            while (recv < total) {
                const n = try stream.read(&buf);
                if (n == 0) break;
                recv += n;
            }
            std.log.info("[accepter] Received {d} / {d} bytes", .{ recv, total });
            if (recv < total) return error.IncompleteTransfer;
        }

        std.Thread.sleep(1 * std.time.ns_per_s);
    }

    std.log.info("[{s}] Test completed successfully!", .{my_name});
}

const Config = struct {
    hosts: []HostInfo,
    @"test": TestConfig,
};

const HostInfo = struct {
    name: []const u8,
    private_key: []const u8,
    port: u16,
    role: []const u8,
};

const TestConfig = struct {
    mode: []const u8 = "",
    echo_message: []const u8 = "",
    throughput_mb: usize = 0,
    chunk_kb: usize = 0,
    num_streams: usize = 0,
    delay_ms: u64 = 0,
};
