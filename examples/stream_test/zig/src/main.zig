//! KCP Stream throughput test - Zig to Zig.
//!
//! This test creates two UDP instances on localhost and measures
//! bidirectional KCP stream throughput using the new double-queue architecture.
//!
//! Usage:
//!   zig build stream_test && ./zig-out/bin/stream_test
//!   zig build stream_test -Doptimize=ReleaseFast && ./zig-out/bin/stream_test
//!
//! Or via Bazel:
//!   bazel run //zig:stream_test

const std = @import("std");
const posix = std.posix;
const mem = std.mem;
const Thread = std.Thread;
const Atomic = std.atomic.Value;
const noise = @import("noise");

const Key = noise.Key;
const KeyPair = noise.KeyPair;
const UDP = noise.UDP(noise.KqueueIO);
const UdpOptions = noise.UdpOptions;
const KcpStream = noise.net.KcpStream;

/// Test configuration
const Config = struct {
    /// Total bytes to transfer in each direction
    total_bytes: usize = 10 * 1024 * 1024, // 10 MB default
    /// Chunk size for each write
    chunk_size: usize = 32 * 1024, // 32 KB
    /// Run echo test first
    run_echo: bool = true,
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Parse command line args
    var config = Config{};
    var args = try std.process.argsWithAllocator(allocator);
    defer args.deinit();
    _ = args.next(); // skip program name

    while (args.next()) |arg| {
        if (mem.eql(u8, arg, "--size")) {
            if (args.next()) |val| {
                const mb = try std.fmt.parseInt(usize, val, 10);
                config.total_bytes = mb * 1024 * 1024;
            }
        } else if (mem.eql(u8, arg, "--chunk")) {
            if (args.next()) |val| {
                const kb = try std.fmt.parseInt(usize, val, 10);
                config.chunk_size = kb * 1024;
            }
        } else if (mem.eql(u8, arg, "--no-echo")) {
            config.run_echo = false;
        }
    }

    std.debug.print("\n=== Zig KCP Stream Test (Double-Queue UDP) ===\n", .{});
    std.debug.print("Transfer size: {} MB per direction\n", .{config.total_bytes / 1024 / 1024});
    std.debug.print("Chunk size: {} KB\n", .{config.chunk_size / 1024});
    std.debug.print("Echo test: {}\n\n", .{config.run_echo});

    // Generate keypairs
    const server_key = KeyPair.generate();
    const client_key = KeyPair.generate();

    std.debug.print("[server] Public key: {x}...\n", .{server_key.public.data[0..8].*});
    std.debug.print("[client] Public key: {x}...\n\n", .{client_key.public.data[0..8].*});

    // Create UDP instances with double-queue architecture
    const server = UDP.init(allocator, &server_key, .{
        .bind_addr = "127.0.0.1:0",
        .allow_unknown = true,
    }) catch |e| {
        std.debug.print("Failed to create server: {}\n", .{e});
        return e;
    };

    const client = UDP.init(allocator, &client_key, .{
        .bind_addr = "127.0.0.1:0",
        .allow_unknown = true,
    }) catch |e| {
        std.debug.print("Failed to create client: {}\n", .{e});
        server.deinit();
        return e;
    };

    std.debug.print("[server] Listening on port {}\n", .{server.getLocalPort()});
    std.debug.print("[client] Listening on port {}\n\n", .{client.getLocalPort()});

    // Set peer endpoints
    var server_addr: posix.sockaddr.in = .{
        .family = posix.AF.INET,
        .port = mem.nativeToBig(u16, server.getLocalPort()),
        .addr = mem.nativeToBig(u32, 0x7F000001), // 127.0.0.1
    };
    var client_addr: posix.sockaddr.in = .{
        .family = posix.AF.INET,
        .port = mem.nativeToBig(u16, client.getLocalPort()),
        .addr = mem.nativeToBig(u32, 0x7F000001),
    };

    client.setPeerEndpoint(server_key.public, @as(*posix.sockaddr, @ptrCast(&server_addr)).*, @sizeOf(posix.sockaddr.in));
    server.setPeerEndpoint(client_key.public, @as(*posix.sockaddr, @ptrCast(&client_addr)).*, @sizeOf(posix.sockaddr.in));

    // Start readFrom consumer threads (to drain non-KCP packets)
    var server_running = Atomic(bool).init(true);
    var client_running = Atomic(bool).init(true);
    var read_from_count = Atomic(u64).init(0);

    const server_read_thread = try Thread.spawn(.{}, readFromLoop, .{ server, &server_running, &read_from_count });
    const client_read_thread = try Thread.spawn(.{}, readFromLoop, .{ client, &client_running, &read_from_count });

    // Connect client to server
    std.debug.print("[client] Connecting to server...\n", .{});
    client.connectTimeout(&server_key.public, 5 * std.time.ns_per_s) catch |e| {
        std.debug.print("[client] Connection failed: {}\n", .{e});
        cleanup(server, client, &server_running, &client_running, server_read_thread, client_read_thread);
        return e;
    };
    std.debug.print("[client] Connected!\n\n", .{});

    // Wait for mux initialization
    Thread.sleep(100 * std.time.ns_per_ms);

    // Run KCP stream tests
    runKcpTests(allocator, client, server, &client_key, &server_key, config) catch |e| {
        std.debug.print("KCP test failed: {}\n", .{e});
        cleanup(server, client, &server_running, &client_running, server_read_thread, client_read_thread);
        return e;
    };

    std.debug.print("\n[stats] ReadFrom consumed: {} packets\n", .{read_from_count.load(.seq_cst)});
    std.debug.print("[done] All tests completed successfully!\n", .{});

    // Cleanup
    cleanup(server, client, &server_running, &client_running, server_read_thread, client_read_thread);
}

fn cleanup(
    server: *UDP,
    client: *UDP,
    server_running: *Atomic(bool),
    client_running: *Atomic(bool),
    server_thread: Thread,
    client_thread: Thread,
) void {
    server_running.store(false, .seq_cst);
    client_running.store(false, .seq_cst);
    client.deinit();
    server.deinit();
    server_thread.join();
    client_thread.join();
}

fn readFromLoop(udp: *UDP, running: *Atomic(bool), count: *Atomic(u64)) void {
    var buf: [65535]u8 = undefined;
    while (running.load(.seq_cst)) {
        const result = udp.readFrom(&buf) catch break;
        if (result.n > 0) {
            _ = count.fetchAdd(1, .seq_cst);
        }
    }
}

fn runKcpTests(
    allocator: std.mem.Allocator,
    client: *UDP,
    server: *UDP,
    client_key: *const KeyPair,
    server_key: *const KeyPair,
    config: Config,
) !void {
    // Open stream from client
    std.debug.print("[client] Opening stream...\n", .{});
    const client_stream = client.openStream(&server_key.public) catch |e| {
        std.debug.print("[client] Failed to open stream: {}\n", .{e});
        return e;
    };

    // Wait for server to accept
    std.debug.print("[server] Waiting to accept stream...\n", .{});
    var server_stream: ?*KcpStream = null;
    var wait_count: usize = 0;
    while (server_stream == null and wait_count < 200) : (wait_count += 1) {
        server_stream = server.acceptStream(&client_key.public);
        if (server_stream == null) {
            Thread.sleep(10 * std.time.ns_per_ms);
        }
    }

    if (server_stream == null) {
        std.debug.print("[server] Failed to accept stream (timeout)\n", .{});
        client_stream.close();
        return error.StreamAcceptTimeout;
    }

    std.debug.print("[stream] Established! Client stream ID: {}, Server stream ID: {}\n\n", .{
        client_stream.getId(),
        server_stream.?.getId(),
    });

    // Run echo test
    if (config.run_echo) {
        try runEchoTest(client_stream, server_stream.?);
    }

    // Run throughput benchmark
    try runThroughputBenchmark(allocator, client_stream, server_stream.?, config);

    // Cleanup streams
    client_stream.close();
    server_stream.?.close();
}

fn runEchoTest(client_stream: *KcpStream, server_stream: *KcpStream) !void {
    std.debug.print("[test] Running echo test...\n", .{});

    const test_msg = "Hello KCP Stream from Zig!";

    // Client sends
    _ = client_stream.write(test_msg) catch |e| {
        std.debug.print("[test] Client write failed: {}\n", .{e});
        return e;
    };

    // Server reads with timeout
    var buf: [1024]u8 = undefined;
    var received: usize = 0;
    var attempts: usize = 0;
    while (received == 0 and attempts < 100) : (attempts += 1) {
        const n = server_stream.read(&buf) catch break;
        if (n > 0) {
            received = n;
            break;
        }
        Thread.sleep(10 * std.time.ns_per_ms);
    }

    if (received == 0) {
        std.debug.print("[test] Echo failed: no data received\n", .{});
        return error.EchoFailed;
    }

    if (!mem.eql(u8, buf[0..received], test_msg)) {
        std.debug.print("[test] Echo mismatch!\n", .{});
        return error.EchoMismatch;
    }

    std.debug.print("[test] Echo passed: \"{s}\"\n\n", .{buf[0..received]});
}

fn runThroughputBenchmark(
    allocator: std.mem.Allocator,
    client_stream: *KcpStream,
    server_stream: *KcpStream,
    config: Config,
) !void {
    std.debug.print("[bench] Starting BIDIRECTIONAL throughput test\n", .{});
    std.debug.print("[bench] Each direction: {} MB, chunk: {} KB\n\n", .{
        config.total_bytes / 1024 / 1024,
        config.chunk_size / 1024,
    });

    // Allocate chunk buffer
    const chunk = try allocator.alloc(u8, config.chunk_size);
    defer allocator.free(chunk);
    for (chunk, 0..) |*b, i| b.* = @as(u8, @truncate(i));

    var client_tx = Atomic(u64).init(0);
    var client_rx = Atomic(u64).init(0);
    var server_tx = Atomic(u64).init(0);
    var server_rx = Atomic(u64).init(0);

    const start = std.time.nanoTimestamp();

    // Spawn 4 threads for bidirectional transfer
    const client_write_thread = try Thread.spawn(.{}, writerThread, .{
        client_stream,
        chunk,
        config.total_bytes,
        &client_tx,
    });

    const client_read_thread = try Thread.spawn(.{}, readerThread, .{
        client_stream,
        config.total_bytes,
        &client_rx,
    });

    const server_write_thread = try Thread.spawn(.{}, writerThread, .{
        server_stream,
        chunk,
        config.total_bytes,
        &server_tx,
    });

    const server_read_thread = try Thread.spawn(.{}, readerThread, .{
        server_stream,
        config.total_bytes,
        &server_rx,
    });

    // Progress reporting with timeout
    var last_report = start;
    const timeout_ns: i128 = 30 * std.time.ns_per_s; // 30 second timeout

    while (true) {
        const ctx = client_tx.load(.seq_cst);
        const crx = client_rx.load(.seq_cst);
        const stx = server_tx.load(.seq_cst);
        const srx = server_rx.load(.seq_cst);

        const now = std.time.nanoTimestamp();
        const elapsed = now - start;

        if (now - last_report > std.time.ns_per_s) {
            const total = ctx + crx + stx + srx;
            const target = config.total_bytes * 4;
            const pct = @as(f64, @floatFromInt(total)) / @as(f64, @floatFromInt(target)) * 100;
            std.debug.print("[bench] Progress: {d:.1}%\n", .{pct});
            last_report = now;
        }

        // Check completion
        if (ctx >= config.total_bytes and crx >= config.total_bytes and
            stx >= config.total_bytes and srx >= config.total_bytes)
        {
            break;
        }

        // Check timeout
        if (elapsed > timeout_ns) {
            std.debug.print("[bench] TIMEOUT after 30s! Final state:\n", .{});
            std.debug.print("[bench]   ctx:{d:.2}MB crx:{d:.2}MB stx:{d:.2}MB srx:{d:.2}MB\n", .{
                @as(f64, @floatFromInt(ctx)) / 1024 / 1024,
                @as(f64, @floatFromInt(crx)) / 1024 / 1024,
                @as(f64, @floatFromInt(stx)) / 1024 / 1024,
                @as(f64, @floatFromInt(srx)) / 1024 / 1024,
            });
            break;
        }

        Thread.sleep(100 * std.time.ns_per_ms);
    }


    // Wait for threads
    client_write_thread.join();
    client_read_thread.join();
    server_write_thread.join();
    server_read_thread.join();

    const end = std.time.nanoTimestamp();
    const elapsed_ns = end - start;
    const elapsed_s = @as(f64, @floatFromInt(elapsed_ns)) / @as(f64, std.time.ns_per_s);

    // Results
    const ctx = client_tx.load(.seq_cst);
    const crx = client_rx.load(.seq_cst);
    const stx = server_tx.load(.seq_cst);
    const srx = server_rx.load(.seq_cst);
    const total = ctx + crx + stx + srx;
    const throughput = @as(f64, @floatFromInt(total)) / elapsed_s / 1024 / 1024;

    std.debug.print("\n[bench] ========== KCP Bidirectional Results ==========\n", .{});
    std.debug.print("[bench] Client TX: {d:.2} MB\n", .{@as(f64, @floatFromInt(ctx)) / 1024 / 1024});
    std.debug.print("[bench] Client RX: {d:.2} MB\n", .{@as(f64, @floatFromInt(crx)) / 1024 / 1024});
    std.debug.print("[bench] Server TX: {d:.2} MB\n", .{@as(f64, @floatFromInt(stx)) / 1024 / 1024});
    std.debug.print("[bench] Server RX: {d:.2} MB\n", .{@as(f64, @floatFromInt(srx)) / 1024 / 1024});
    std.debug.print("[bench] Total:     {d:.2} MB\n", .{@as(f64, @floatFromInt(total)) / 1024 / 1024});
    std.debug.print("[bench] Time:      {d:.2} s\n", .{elapsed_s});
    std.debug.print("[bench] Throughput: {d:.2} MB/s (bidirectional)\n", .{throughput});
    std.debug.print("[bench] ================================================\n", .{});
}

fn writerThread(stream: *KcpStream, chunk: []const u8, total_bytes: usize, sent: *Atomic(u64)) void {
    var written: u64 = 0;
    while (written < total_bytes) {
        const n = stream.write(chunk) catch break;
        written += n;
        sent.store(written, .seq_cst);
    }
}

fn readerThread(stream: *KcpStream, total_bytes: usize, recv: *Atomic(u64)) void {
    var buf: [65536]u8 = undefined;
    var received: u64 = 0;
    while (received < total_bytes) {
        // Use blocking read with 100ms timeout
        const n = stream.readBlocking(&buf, 100 * std.time.ns_per_ms) catch break;
        if (n > 0) {
            received += n;
            recv.store(received, .seq_cst);
        } else if (n == 0) {
            // Check if stream is closed (EOF)
            const state = stream.getState();
            if (state == .closed or state == .remote_close) break;
            // Timeout, continue waiting
        }
    }
}
