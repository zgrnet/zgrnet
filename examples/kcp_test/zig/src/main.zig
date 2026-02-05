//! KCP stream interoperability test between Zig, Go, and Rust.
//!
//! Usage:
//!   zig build run -- --name zig --config ../config.json

const std = @import("std");
const posix = std.posix;
const noise = @import("noise");

const Key = noise.Key;
const KeyPair = noise.KeyPair;
const UDP = noise.UDP;
const KcpStream = noise.net.KcpStream;

/// JSON config structures
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
    echo_message: []const u8,
    throughput_mb: usize,
    chunk_kb: usize,
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Parse command line args
    var args = try std.process.argsWithAllocator(allocator);
    defer args.deinit();
    _ = args.next(); // skip program name

    var name: ?[]const u8 = null;
    var config_path: ?[]const u8 = null;

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--name")) {
            name = args.next();
        } else if (std.mem.eql(u8, arg, "--config")) {
            config_path = args.next();
        }
    }

    const my_name = name orelse {
        std.debug.print("Usage: --name <name> --config <path>\n", .{});
        return error.InvalidArgs;
    };
    const cfg_path = config_path orelse {
        std.debug.print("Usage: --name <name> --config <path>\n", .{});
        return error.InvalidArgs;
    };

    // Read config file
    const config_data = std.fs.cwd().readFileAlloc(allocator, cfg_path, 1024 * 1024) catch |e| {
        std.debug.print("Failed to read config {s}: {}\n", .{ cfg_path, e });
        return e;
    };
    defer allocator.free(config_data);

    // Parse JSON
    const parsed = std.json.parseFromSlice(Config, allocator, config_data, .{}) catch |e| {
        std.debug.print("Failed to parse config: {}\n", .{e});
        return e;
    };
    defer parsed.deinit();
    const config = parsed.value;

    // Find our host
    var my_host: ?HostInfo = null;
    for (config.hosts) |h| {
        if (std.mem.eql(u8, h.name, my_name)) {
            my_host = h;
            break;
        }
    }

    const host = my_host orelse {
        std.debug.print("Host {s} not found in config\n", .{my_name});
        return error.HostNotFound;
    };

    // Parse private key (hex string to bytes)
    var priv_key: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&priv_key, host.private_key) catch |e| {
        std.debug.print("Invalid private key: {}\n", .{e});
        return e;
    };
    const key_pair = KeyPair.fromPrivate(Key.fromBytes(priv_key));

    std.debug.print("[{s}] Public key: {x}...\n", .{ my_name, key_pair.public.data[0..8].* });
    std.debug.print("[{s}] Role: {s}\n", .{ my_name, host.role });

    // Create bind address string
    var bind_buf: [32]u8 = undefined;
    const bind_addr = std.fmt.bufPrint(&bind_buf, "0.0.0.0:{}", .{host.port}) catch "0.0.0.0:0";

    // Create UDP (new API - no poll() needed, internal threads handle everything)
    const udp = try UDP.init(allocator, &key_pair, .{
        .bind_addr = bind_addr,
        .allow_unknown = true,
    });
    defer udp.deinit();

    std.debug.print("[{s}] Listening on port {}\n", .{ my_name, udp.getLocalPort() });

    // Find peer (the one that's not us)
    var peer_host: ?HostInfo = null;
    for (config.hosts) |h| {
        if (!std.mem.eql(u8, h.name, my_name)) {
            peer_host = h;
            break;
        }
    }

    const peer = peer_host orelse {
        std.debug.print("No peer found in config\n", .{});
        return error.NoPeerFound;
    };

    // Parse peer's private key to get their public key
    var peer_priv: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&peer_priv, peer.private_key) catch |e| {
        std.debug.print("Invalid peer private key: {}\n", .{e});
        return e;
    };
    const peer_kp = KeyPair.fromPrivate(Key.fromBytes(peer_priv));

    // Add peer endpoint (localhost)
    var peer_addr: posix.sockaddr.in = .{
        .family = posix.AF.INET,
        .port = std.mem.nativeToBig(u16, peer.port),
        .addr = std.mem.nativeToBig(u32, 0x7F000001), // 127.0.0.1
    };
    udp.setPeerEndpoint(peer_kp.public, @as(*posix.sockaddr, @ptrCast(&peer_addr)).*, @sizeOf(posix.sockaddr.in));
    std.debug.print("[{s}] Added peer {s} at port {}\n", .{ my_name, peer.name, peer.port });

    // Run test based on role
    if (std.mem.eql(u8, host.role, "opener")) {
        // Wait for peer to start
        std.debug.print("[{s}] Waiting for peer to start...\n", .{my_name});
        std.Thread.sleep(2 * std.time.ns_per_s);

        // Connect to peer
        std.debug.print("[{s}] Connecting to {s}...\n", .{ my_name, peer.name });
        udp.connectTimeout(&peer_kp.public, 10 * std.time.ns_per_s) catch |e| {
            std.debug.print("[{s}] Failed to connect: {}\n", .{ my_name, e });
            return e;
        };
        std.debug.print("[{s}] Connected to {s}!\n", .{ my_name, peer.name });

        // Wait for mux initialization
        std.Thread.sleep(100 * std.time.ns_per_ms);

        try runOpenerTest(allocator, udp, &peer_kp.public, peer.name, &config.@"test", my_name);
    } else {
        // Accepter waits for incoming connection
        std.debug.print("[{s}] Waiting for connection from {s}...\n", .{ my_name, peer.name });
        try runAccepterTest(allocator, udp, &peer_kp.public, peer.name, &config.@"test", my_name);
    }

    std.debug.print("[{s}] Test completed successfully!\n", .{my_name});
    udp.close();
}

fn runOpenerTest(allocator: std.mem.Allocator, udp: *UDP, peer_pk: *const Key, peer_name: []const u8, test_cfg: *const TestConfig, my_name: []const u8) !void {
    std.debug.print("[opener] Opening stream to {s}...\n", .{peer_name});

    const stream = udp.openStream(peer_pk) catch |e| {
        std.debug.print("[opener] Failed to open stream: {}\n", .{e});
        return e;
    };

    std.debug.print("[opener] Opened stream {}\n", .{stream.getId()});

    // Echo test
    std.debug.print("[opener] Running echo test...\n", .{});
    _ = stream.write(test_cfg.echo_message) catch |e| {
        std.debug.print("[opener] Failed to write echo: {}\n", .{e});
        return e;
    };
    std.debug.print("[opener] Sent {} bytes: {s}\n", .{ test_cfg.echo_message.len, test_cfg.echo_message });

    // Read echo response with timeout (use blocking read)
    var response_buf: [1024]u8 = undefined;
    const n = stream.readBlocking(&response_buf, 5 * std.time.ns_per_s) catch |e| {
        std.debug.print("[opener] Failed to read echo response: {}\n", .{e});
        return e;
    };
    if (n == 0) {
        std.debug.print("[opener] Read timeout or EOF\n", .{});
        return error.ReadTimeout;
    }
    std.debug.print("[opener] Received echo response: {s}\n", .{response_buf[0..n]});

    // Bidirectional throughput test
    try runBidirectionalTest(allocator, stream, "opener", test_cfg, my_name);

    stream.shutdown();
}

fn runAccepterTest(allocator: std.mem.Allocator, udp: *UDP, peer_pk: *const Key, peer_name: []const u8, test_cfg: *const TestConfig, my_name: []const u8) !void {
    // The opener will connect to us. We just wait for streams.
    // The Noise handshake happens automatically when we receive the init message.
    std.debug.print("[accepter] Waiting for stream from {s}...\n", .{peer_name});

    // Wait for stream with timeout
    var stream: ?*KcpStream = null;
    const stream_deadline = std.time.nanoTimestamp() + 10 * std.time.ns_per_s;
    while (stream == null) {
        if (std.time.nanoTimestamp() > stream_deadline) {
            std.debug.print("[accepter] Timeout waiting for stream\n", .{});
            return error.StreamAcceptTimeout;
        }
        stream = udp.acceptStream(peer_pk);
        if (stream == null) {
            std.Thread.sleep(10 * std.time.ns_per_ms);
        }
    }

    const s = stream.?;
    std.debug.print("[accepter] Accepted stream {}\n", .{s.getId()});

    // Echo test - receive and echo back (use blocking read)
    var recv_buf: [1024]u8 = undefined;
    const n = s.readBlocking(&recv_buf, 5 * std.time.ns_per_s) catch |e| {
        std.debug.print("[accepter] Failed to read echo: {}\n", .{e});
        return e;
    };
    if (n == 0) {
        std.debug.print("[accepter] Read timeout or EOF\n", .{});
        return error.ReadTimeout;
    }
    const received = recv_buf[0..n];
    std.debug.print("[accepter] Received echo: {s}\n", .{received});

    // Echo back with prefix
    var response_buf: [256]u8 = undefined;
    const response = std.fmt.bufPrint(&response_buf, "Echo from accepter: {s}", .{received}) catch received[0..@min(received.len, 256)];
    _ = s.write(response) catch |e| {
        std.debug.print("[accepter] Failed to write echo response: {}\n", .{e});
        return e;
    };
    std.debug.print("[accepter] Sent echo response: {s}\n", .{response});

    // Small delay to let opener read echo response before starting throughput test
    // (KCP is stream-based, no message boundaries)
    std.Thread.sleep(100 * std.time.ns_per_ms);

    // Bidirectional throughput test
    try runBidirectionalTest(allocator, s, "accepter", test_cfg, my_name);

    // Wait for remaining data to flush
    std.Thread.sleep(1 * std.time.ns_per_s);
    s.shutdown();
}

fn runBidirectionalTest(allocator: std.mem.Allocator, stream: *KcpStream, role: []const u8, test_cfg: *const TestConfig, my_name: []const u8) !void {
    _ = my_name;

    const total_bytes: u64 = @intCast(test_cfg.throughput_mb * 1024 * 1024);
    const chunk_size = test_cfg.chunk_kb * 1024;

    std.debug.print("[{s}] Starting bidirectional test: {} MB each direction, {} KB chunks\n", .{ role, test_cfg.throughput_mb, test_cfg.chunk_kb });

    var sent_bytes = std.atomic.Value(u64).init(0);
    var recv_bytes = std.atomic.Value(u64).init(0);

    const start = std.time.nanoTimestamp();

    // Writer context
    const WriteCtx = struct {
        stream: *KcpStream,
        total_bytes: u64,
        chunk_size: usize,
        sent: *std.atomic.Value(u64),
        role: []const u8,
    };

    // Reader context
    const ReadCtx = struct {
        stream: *KcpStream,
        total_bytes: u64,
        recv: *std.atomic.Value(u64),
    };

    const write_ctx = WriteCtx{
        .stream = stream,
        .total_bytes = total_bytes,
        .chunk_size = chunk_size,
        .sent = &sent_bytes,
        .role = role,
    };

    const read_ctx = ReadCtx{
        .stream = stream,
        .total_bytes = total_bytes,
        .recv = &recv_bytes,
    };

    // Start writer thread
    const write_thread = try std.Thread.spawn(.{}, struct {
        fn writeFn(ctx: WriteCtx) void {
            const chunk = std.heap.page_allocator.alloc(u8, ctx.chunk_size) catch return;
            defer std.heap.page_allocator.free(chunk);
            for (chunk, 0..) |*b, i| b.* = @truncate(i);

            var sent: u64 = 0;
            while (sent < ctx.total_bytes) {
                const n = ctx.stream.write(chunk) catch break;
                sent += n;
                ctx.sent.store(sent, .seq_cst);
            }
        }
    }.writeFn, .{write_ctx});

    // Start reader thread (use blocking read)
    const read_thread = try std.Thread.spawn(.{}, struct {
        fn readFn(ctx: ReadCtx) void {
            var buf: [65536]u8 = undefined;
            var recv: u64 = 0;

            while (recv < ctx.total_bytes) {
                // Use blocking read with 100ms timeout
                const n = ctx.stream.readBlocking(&buf, 100 * std.time.ns_per_ms) catch break;
                if (n > 0) {
                    recv += n;
                    ctx.recv.store(recv, .seq_cst);
                } else {
                    // Check if stream is closed
                    const state = ctx.stream.getState();
                    if (state == .closed or state == .remote_close) break;
                }
            }
        }
    }.readFn, .{read_ctx});

    // Wait for completion
    write_thread.join();
    read_thread.join();

    const end = std.time.nanoTimestamp();
    const elapsed_ns = end - start;
    const elapsed_s = @as(f64, @floatFromInt(elapsed_ns)) / @as(f64, std.time.ns_per_s);

    const sent = sent_bytes.load(.seq_cst);
    const recv = recv_bytes.load(.seq_cst);
    const total_transfer = sent + recv;
    const throughput = @as(f64, @floatFromInt(total_transfer)) / elapsed_s / 1024 / 1024;

    std.debug.print("[{s}] ========== Bidirectional Results ==========\n", .{role});
    std.debug.print("[{s}] Sent:       {} bytes ({d:.2} MB)\n", .{ role, sent, @as(f64, @floatFromInt(sent)) / 1024 / 1024 });
    std.debug.print("[{s}] Received:   {} bytes ({d:.2} MB)\n", .{ role, recv, @as(f64, @floatFromInt(recv)) / 1024 / 1024 });
    std.debug.print("[{s}] Total:      {} bytes ({d:.2} MB)\n", .{ role, total_transfer, @as(f64, @floatFromInt(total_transfer)) / 1024 / 1024 });
    std.debug.print("[{s}] Time:       {d:.2} seconds\n", .{ role, elapsed_s });
    std.debug.print("[{s}] Throughput: {d:.2} MB/s (bidirectional)\n", .{ role, throughput });
    std.debug.print("[{s}] ============================================\n", .{role});

    _ = allocator;
}
