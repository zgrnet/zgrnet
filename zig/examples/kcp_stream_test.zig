//! KCP Stream throughput test - Zig to Zig.
//!
//! This test creates two UDP instances on localhost and measures
//! bidirectional KCP stream throughput.
//!
//! Usage:
//!   zig build kcp_stream_test && ./zig-out/bin/kcp_stream_test
//!   zig build kcp_stream_test -Doptimize=ReleaseFast && ./zig-out/bin/kcp_stream_test

const std = @import("std");
const posix = std.posix;
const noise = @import("noise");

const Key = noise.Key;
const KeyPair = noise.KeyPair;
const UDP = noise.UDP;
const Stream = noise.Stream;

/// Test configuration
const Config = struct {
    /// Total bytes to transfer in each direction
    total_bytes: usize = 100 * 1024 * 1024, // 100 MB (same as Go/Rust)
    /// Chunk size for each write
    chunk_size: usize = 32 * 1024, // 32 KB (same as Go/Rust)
    /// Poll interval in milliseconds
    poll_interval_ms: u32 = 1,
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Parse command line args for optional config
    var config = Config{};
    var args = try std.process.argsWithAllocator(allocator);
    defer args.deinit();
    _ = args.next(); // skip program name

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--size-mb")) {
            if (args.next()) |val| {
                const mb = try std.fmt.parseInt(usize, val, 10);
                config.total_bytes = mb * 1024 * 1024;
            }
        } else if (std.mem.eql(u8, arg, "--chunk-kb")) {
            if (args.next()) |val| {
                const kb = try std.fmt.parseInt(usize, val, 10);
                config.chunk_size = kb * 1024;
            }
        }
    }

    std.debug.print("\n=== Zig KCP Stream Throughput Test ===\n", .{});
    std.debug.print("Transfer size: {} MB per direction\n", .{config.total_bytes / 1024 / 1024});
    std.debug.print("Chunk size: {} KB\n\n", .{config.chunk_size / 1024});

    // Generate keypairs
    const server_key = KeyPair.generate();
    const client_key = KeyPair.generate();

    std.debug.print("Server public key: {x}...\n", .{server_key.public.data[0..8].*});
    std.debug.print("Client public key: {x}...\n\n", .{client_key.public.data[0..8].*});

    // Create UDP instances
    const server = try UDP.init(allocator, server_key, .{
        .port = 0, // Random port
        .allow_unknown = true,
    });
    defer server.deinit();

    const client = try UDP.init(allocator, client_key, .{
        .port = 0,
        .allow_unknown = true,
    });
    defer client.deinit();

    std.debug.print("Server listening on port {}\n", .{server.port()});
    std.debug.print("Client listening on port {}\n\n", .{client.port()});

    // Set peer endpoints
    var server_addr: posix.sockaddr.in = .{
        .family = posix.AF.INET,
        .port = std.mem.nativeToBig(u16, server.port()),
        .addr = std.mem.nativeToBig(u32, 0x7F000001), // 127.0.0.1
    };
    var client_addr: posix.sockaddr.in = .{
        .family = posix.AF.INET,
        .port = std.mem.nativeToBig(u16, client.port()),
        .addr = std.mem.nativeToBig(u32, 0x7F000001),
    };

    client.setPeerEndpoint(server_key.public, @as(*posix.sockaddr, @ptrCast(&server_addr)).*, @sizeOf(posix.sockaddr.in));
    server.setPeerEndpoint(client_key.public, @as(*posix.sockaddr, @ptrCast(&client_addr)).*, @sizeOf(posix.sockaddr.in));

    // Connect client to server
    std.debug.print("Connecting client to server...\n", .{});

    // Start polling threads for handshake
    var server_running = std.atomic.Value(bool).init(true);
    var client_running = std.atomic.Value(bool).init(true);

    const ServerCtx = struct {
        udp: *UDP,
        running: *std.atomic.Value(bool),
    };
    const server_ctx = ServerCtx{ .udp = server, .running = &server_running };
    const client_ctx = ServerCtx{ .udp = client, .running = &client_running };

    const server_poll_thread = try std.Thread.spawn(.{}, struct {
        fn poll(ctx: ServerCtx) void {
            const start = std.time.milliTimestamp();
            while (ctx.running.load(.seq_cst)) {
                const current_ms: u32 = @truncate(@as(u64, @intCast(std.time.milliTimestamp() - start)));
                ctx.udp.poll(current_ms) catch {};
                // Busy poll for maximum throughput (use real timestamps)
            }
        }
    }.poll, .{server_ctx});

    const client_poll_thread = try std.Thread.spawn(.{}, struct {
        fn poll(ctx: ServerCtx) void {
            const start = std.time.milliTimestamp();
            while (ctx.running.load(.seq_cst)) {
                const current_ms: u32 = @truncate(@as(u64, @intCast(std.time.milliTimestamp() - start)));
                ctx.udp.poll(current_ms) catch {};
                // Busy poll for maximum throughput (use real timestamps)
            }
        }
    }.poll, .{client_ctx});

    // Give poll threads time to start
    std.Thread.sleep(10 * std.time.ns_per_ms);

    // Connect (handshake)
    client.connectTimeout(&server_key.public, 5 * std.time.ns_per_s) catch |e| {
        std.debug.print("Connection failed: {}\n", .{e});
        server_running.store(false, .seq_cst);
        client_running.store(false, .seq_cst);
        server_poll_thread.join();
        client_poll_thread.join();
        return e;
    };

    std.debug.print("Connected!\n\n", .{});

    // Wait for mux to initialize
    std.Thread.sleep(100 * std.time.ns_per_ms);

    // Open stream from client
    std.debug.print("Opening stream...\n", .{});
    const client_stream = client.openStream(&server_key.public) catch |e| {
        std.debug.print("Failed to open stream: {}\n", .{e});
        server_running.store(false, .seq_cst);
        client_running.store(false, .seq_cst);
        server_poll_thread.join();
        client_poll_thread.join();
        return e;
    };

    // Wait for server to accept the stream
    std.debug.print("Waiting for server to accept stream...\n", .{});
    var server_stream: ?*Stream = null;
    var wait_count: usize = 0;
    while (server_stream == null and wait_count < 100) : (wait_count += 1) {
        server_stream = server.acceptStream(&client_key.public);
        if (server_stream == null) {
            std.Thread.sleep(10 * std.time.ns_per_ms);
        }
    }

    if (server_stream == null) {
        std.debug.print("Failed to accept stream\n", .{});
        server_running.store(false, .seq_cst);
        client_running.store(false, .seq_cst);
        server_poll_thread.join();
        client_poll_thread.join();
        return error.StreamAcceptFailed;
    }

    std.debug.print("Stream established (id={})\n\n", .{client_stream.getId()});

    // Run bidirectional throughput test
    std.debug.print("Starting bidirectional throughput test...\n", .{});
    std.debug.print("Each direction: {} bytes ({} MB)\n\n", .{ config.total_bytes, config.total_bytes / 1024 / 1024 });

    var client_sent = std.atomic.Value(u64).init(0);
    var client_recv = std.atomic.Value(u64).init(0);
    var server_sent = std.atomic.Value(u64).init(0);
    var server_recv = std.atomic.Value(u64).init(0);

    const start_time = std.time.nanoTimestamp();

    // Client writer thread
    const ClientWriteCtx = struct {
        stream: *Stream,
        total_bytes: usize,
        chunk_size: usize,
        sent: *std.atomic.Value(u64),
    };
    const client_write_ctx = ClientWriteCtx{
        .stream = client_stream,
        .total_bytes = config.total_bytes,
        .chunk_size = config.chunk_size,
        .sent = &client_sent,
    };

    const client_write_thread = try std.Thread.spawn(.{}, struct {
        fn write(ctx: ClientWriteCtx) void {
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
    }.write, .{client_write_ctx});

    // Client reader thread
    const ClientReadCtx = struct {
        stream: *Stream,
        total_bytes: usize,
        recv: *std.atomic.Value(u64),
    };
    const client_read_ctx = ClientReadCtx{
        .stream = client_stream,
        .total_bytes = config.total_bytes,
        .recv = &client_recv,
    };

    const client_read_thread = try std.Thread.spawn(.{}, struct {
        fn readFn(ctx: ClientReadCtx) void {
            var buf: [65536]u8 = undefined;
            var recv: u64 = 0;
            while (recv < ctx.total_bytes) {
                const n = ctx.stream.read(&buf) catch break;
                if (n > 0) {
                    recv += n;
                    ctx.recv.store(recv, .seq_cst);
                }
            }
        }
    }.readFn, .{client_read_ctx});

    // Server writer thread
    const ServerWriteCtx = struct {
        stream: *Stream,
        total_bytes: usize,
        chunk_size: usize,
        sent: *std.atomic.Value(u64),
    };
    const server_write_ctx = ServerWriteCtx{
        .stream = server_stream.?,
        .total_bytes = config.total_bytes,
        .chunk_size = config.chunk_size,
        .sent = &server_sent,
    };

    const server_write_thread = try std.Thread.spawn(.{}, struct {
        fn write(ctx: ServerWriteCtx) void {
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
    }.write, .{server_write_ctx});

    // Server reader thread
    const ServerReadCtx = struct {
        stream: *Stream,
        total_bytes: usize,
        recv: *std.atomic.Value(u64),
    };
    const server_read_ctx = ServerReadCtx{
        .stream = server_stream.?,
        .total_bytes = config.total_bytes,
        .recv = &server_recv,
    };

    const server_read_thread = try std.Thread.spawn(.{}, struct {
        fn readFn(ctx: ServerReadCtx) void {
            var buf: [65536]u8 = undefined;
            var recv: u64 = 0;
            while (recv < ctx.total_bytes) {
                const n = ctx.stream.read(&buf) catch break;
                if (n > 0) {
                    recv += n;
                    ctx.recv.store(recv, .seq_cst);
                }
            }
        }
    }.readFn, .{server_read_ctx});

    // Progress reporting
    var last_report = start_time;
    while (true) {
        const cs = client_sent.load(.seq_cst);
        const cr = client_recv.load(.seq_cst);
        const ss = server_sent.load(.seq_cst);
        const sr = server_recv.load(.seq_cst);

        const now = std.time.nanoTimestamp();
        if (now - last_report > std.time.ns_per_s) {
            const total = cs + cr + ss + sr;
            const target = config.total_bytes * 4;
            const pct = @as(f64, @floatFromInt(total)) / @as(f64, @floatFromInt(target)) * 100;
            std.debug.print("Progress: {d:.1}% (client tx: {} MB, rx: {} MB, server tx: {} MB, rx: {} MB)\n", .{
                pct,
                cs / 1024 / 1024,
                cr / 1024 / 1024,
                ss / 1024 / 1024,
                sr / 1024 / 1024,
            });
            last_report = now;
        }

        // Check if done
        if (cs >= config.total_bytes and cr >= config.total_bytes and
            ss >= config.total_bytes and sr >= config.total_bytes)
        {
            break;
        }

        std.Thread.sleep(100 * std.time.ns_per_ms);
    }

    // Wait for threads to finish
    client_write_thread.join();
    client_read_thread.join();
    server_write_thread.join();
    server_read_thread.join();

    const end_time = std.time.nanoTimestamp();
    const elapsed_ns = end_time - start_time;
    const elapsed_s = @as(f64, @floatFromInt(elapsed_ns)) / @as(f64, std.time.ns_per_s);

    // Calculate results
    const total_bytes_transferred = client_sent.load(.seq_cst) + client_recv.load(.seq_cst) +
        server_sent.load(.seq_cst) + server_recv.load(.seq_cst);
    const throughput_mbps = @as(f64, @floatFromInt(total_bytes_transferred)) / elapsed_s / 1024 / 1024;

    std.debug.print("\n=== Results ===\n", .{});
    std.debug.print("Total transferred: {} bytes ({d:.2} GB)\n", .{ total_bytes_transferred, @as(f64, @floatFromInt(total_bytes_transferred)) / 1024 / 1024 / 1024 });
    std.debug.print("Time: {d:.2} seconds\n", .{elapsed_s});
    std.debug.print("Throughput: {d:.2} MB/s (bidirectional)\n", .{throughput_mbps});
    std.debug.print("Per-direction: {d:.2} MB/s\n", .{throughput_mbps / 2});

    // Cleanup
    client_stream.shutdown();
    server_stream.?.shutdown();

    server_running.store(false, .seq_cst);
    client_running.store(false, .seq_cst);
    server_poll_thread.join();
    client_poll_thread.join();

    std.debug.print("\nTest completed successfully!\n", .{});
}
