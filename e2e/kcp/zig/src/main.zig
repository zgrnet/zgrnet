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
            const chunk_size = if (config.@"test".chunk_kb > 0) config.@"test".chunk_kb * 1024 else 8192;
            const chunk = try allocator.alloc(u8, chunk_size);
            defer allocator.free(chunk);
            @memset(chunk, 0x58);
            var sent: usize = 0;
            while (sent < total) {
                const n = try stream.write(chunk);
                sent += n;
            }
            std.log.info("[opener] Sent {d} bytes", .{sent});
        } else if (std.mem.eql(u8, mode, "multi_stream")) {
            const num_streams = if (config.@"test".num_streams > 0) config.@"test".num_streams else 10;
            const data = try allocator.alloc(u8, 100 * 1024);
            defer allocator.free(data);
            for (data, 0..) |*b, idx| b.* = @intCast(idx % 256);

            // First stream already opened above.
            _ = try stream.write(data);
            std.log.info("[opener] stream 0: sent {d} bytes", .{data.len});

            var i_stream: usize = 1;
            while (i_stream < num_streams) : (i_stream += 1) {
                var s = try udp.openStream(&peer_kp.public, 1);
                defer s.close();
                _ = try s.write(data);
                std.log.info("[opener] stream {d}: sent {d} bytes", .{ i_stream, data.len });
            }
            std.log.info("[opener] all {d} streams done", .{num_streams});
        } else if (std.mem.eql(u8, mode, "delayed_write")) {
            const delay_ms = if (config.@"test".delay_ms > 0) config.@"test".delay_ms else 2000;
            std.log.info("[opener] delaying {d}ms before writing...", .{delay_ms});
            std.Thread.sleep(delay_ms * std.time.ns_per_ms);
            _ = try stream.write("delayed hello");

            var buf: [4096]u8 = undefined;
            const n = try stream.read(&buf);
            std.log.info("[opener] delayed response: {s}", .{buf[0..n]});
        } else {
            std.log.err("unknown mode: {s}", .{mode});
            return error.InvalidMode;
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

        if (std.mem.eql(u8, mode, "echo") or mode.len == 0 or std.mem.eql(u8, mode, "delayed_write")) {
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
            var last_log: usize = 0;
            while (recv < total) {
                const n = try stream.read(&buf);
                if (n == 0) break;
                recv += n;
                if (recv - last_log >= 256 * 1024) {
                    std.log.info("[accepter] progress {d} / {d}", .{ recv, total });
                    last_log = recv;
                }
            }
            std.log.info("[accepter] Received {d} / {d} bytes", .{ recv, total });
            if (recv < total) return error.IncompleteTransfer;
        } else if (std.mem.eql(u8, mode, "multi_stream")) {
            const num_streams = if (config.@"test".num_streams > 0) config.@"test".num_streams else 10;
            const expected_per_stream: usize = 100 * 1024;

            // First stream already accepted above.
            {
                var buf: [65536]u8 = undefined;
                var recv: usize = 0;
                while (recv < expected_per_stream) {
                    const n = try stream.read(&buf);
                    if (n == 0) break;
                    recv += n;
                }
                std.log.info("[accepter] stream 0: received {d} bytes", .{recv});
            }

            var stream_idx: usize = 1;
            while (stream_idx < num_streams) : (stream_idx += 1) {
                const r = try udp.acceptStream(&peer_kp.public);
                var s = r.stream;
                defer s.close();

                var buf: [65536]u8 = undefined;
                var recv: usize = 0;
                while (recv < expected_per_stream) {
                    const n = try s.read(&buf);
                    if (n == 0) break;
                    recv += n;
                }
                std.log.info("[accepter] stream {d}: received {d} bytes", .{ stream_idx, recv });
            }
            std.log.info("[accepter] all {d} streams done", .{num_streams});
        } else {
            std.log.err("unknown mode: {s}", .{mode});
            return error.InvalidMode;
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
