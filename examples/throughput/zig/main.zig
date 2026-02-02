//! Zig UDP throughput test using OS abstraction layer.
//!
//! Architecture:
//!   io_thread: socket -> decrypt_chan
//!   decrypt_workers (x N): decrypt_chan -> decrypt -> count
//!
//! Uses OS primitives from zig/src/os/:
//! - Channel: Thread-safe bounded queue
//! - Event: Ready signal (for shutdown)

const std = @import("std");
const posix = std.posix;
const noise = @import("noise");
const os = @import("noise").os;
const Os = os.Os;

const Allocator = std.mem.Allocator;
const Key = noise.Key;
const KeyPair = noise.KeyPair;
const UDP = noise.UDP;
const UdpError = noise.net.udp.UdpError;

const CHUNK_SIZE = 1200;
const NUM_WORKERS = 8;
const QUEUE_SIZE = 4096;

/// Packet structure.
const Packet = struct {
    data: [2048]u8 = undefined,
    len: usize = 0,
    from: posix.sockaddr = undefined,
    from_len: posix.socklen_t = 0,
};

/// Pre-allocated packet pool using simple mutex + stack.
const PacketPool = struct {
    packets: []Packet,
    free_stack: []usize,
    stack_top: std.atomic.Value(usize),
    mutex: Os.Mutex,

    fn init(allocator: Allocator, size: usize) !PacketPool {
        const packets = try allocator.alloc(Packet, size);
        for (packets) |*p| {
            p.* = Packet{};
        }

        const free_stack = try allocator.alloc(usize, size);
        // Initialize stack with all indices
        for (free_stack, 0..) |*slot, i| {
            slot.* = i;
        }

        return PacketPool{
            .packets = packets,
            .free_stack = free_stack,
            .stack_top = std.atomic.Value(usize).init(size),  // All available
            .mutex = Os.Mutex.init(),
        };
    }

    fn deinit(self: *PacketPool, allocator: Allocator) void {
        allocator.free(self.free_stack);
        allocator.free(self.packets);
    }

    /// Get a packet from the pool (non-blocking).
    fn acquire(self: *PacketPool) ?*Packet {
        self.mutex.lock();
        defer self.mutex.unlock();

        const top = self.stack_top.load(.monotonic);
        if (top == 0) return null;

        const new_top = top - 1;
        const idx = self.free_stack[new_top];
        self.stack_top.store(new_top, .release);
        return &self.packets[idx];
    }

    /// Return a packet to the pool.
    fn release(self: *PacketPool, pkt: *Packet) void {
        const idx = (@intFromPtr(pkt) - @intFromPtr(self.packets.ptr)) / @sizeOf(Packet);

        self.mutex.lock();
        defer self.mutex.unlock();

        const top = self.stack_top.load(.monotonic);
        self.free_stack[top] = idx;
        self.stack_top.store(top + 1, .release);
    }
};

/// Context for the pipeline.
const Context = struct {
    udp: *UDP,
    pool: *PacketPool,
    work_chan: *os.Darwin.Channel(*Packet),
    running: std.atomic.Value(bool),
    recv_bytes: std.atomic.Value(u64),
    recv_packets: std.atomic.Value(u64),
    io_reads: std.atomic.Value(u64),
    decrypt_processed: std.atomic.Value(u64),
    queue_full: std.atomic.Value(u64),
};

/// IO thread - read from socket, send to work channel.
fn ioThread(ctx: *Context) void {
    while (ctx.running.load(.acquire)) {
        // Get a packet from the pool
        const pkt = ctx.pool.acquire() orelse {
            _ = ctx.queue_full.fetchAdd(1, .release);
            std.Thread.yield() catch {};
            continue;
        };

        // Read from socket
        const raw = ctx.udp.processIO(&pkt.data) catch |err| {
            ctx.pool.release(pkt);
            if (err == UdpError.Closed) return;
            std.Thread.yield() catch {};
            continue;
        };

        pkt.len = raw.len;
        pkt.from = raw.from;
        pkt.from_len = raw.from_len;
        _ = ctx.io_reads.fetchAdd(1, .release);

        // Send to work channel (non-blocking - drop if full)
        if (!ctx.work_chan.trySend(pkt)) {
            ctx.pool.release(pkt);
            _ = ctx.queue_full.fetchAdd(1, .release);
        }
    }
}

/// Decrypt worker - receive from work channel, decrypt, count.
fn decryptWorker(ctx: *Context) void {
    var out_buf: [2048]u8 = undefined;

    while (true) {
        const pkt = ctx.work_chan.recv() orelse {
            // Channel closed
            return;
        };

        // Decrypt the packet
        const raw = noise.net.RawPacket{
            .data = &pkt.data,
            .len = pkt.len,
            .from = pkt.from,
            .from_len = pkt.from_len,
        };

        const dec = ctx.udp.processDecrypt(&raw, &out_buf);
        _ = ctx.decrypt_processed.fetchAdd(1, .release);

        if (dec.ok and !dec.is_handshake) {
            _ = ctx.recv_bytes.fetchAdd(@intCast(dec.len), .release);
            _ = ctx.recv_packets.fetchAdd(1, .release);
        }

        // Return packet to pool
        ctx.pool.release(pkt);
    }
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var args = try std.process.argsWithAllocator(allocator);
    defer args.deinit();

    var size_mb: usize = 100;
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--size")) {
            if (args.next()) |val| {
                size_mb = std.fmt.parseInt(usize, val, 10) catch 100;
            }
        }
    }

    std.debug.print("=== Zig OS Layer Pipeline ({} workers) ===\n", .{NUM_WORKERS});

    const server_key = KeyPair.generate();
    const client_key = KeyPair.generate();

    const server = try UDP.init(allocator, server_key, .{ .allow_unknown = true });
    defer server.deinit();

    const client = try UDP.init(allocator, client_key, .{ .allow_unknown = true });
    defer client.deinit();

    std.debug.print("Server: 127.0.0.1:{}\n", .{server.local_port});
    std.debug.print("Client: 127.0.0.1:{}\n", .{client.local_port});

    var server_endpoint: posix.sockaddr.in = .{
        .family = posix.AF.INET,
        .port = std.mem.nativeToBig(u16, server.local_port),
        .addr = std.mem.nativeToBig(u32, 0x7F000001),
    };
    var client_endpoint: posix.sockaddr.in = .{
        .family = posix.AF.INET,
        .port = std.mem.nativeToBig(u16, client.local_port),
        .addr = std.mem.nativeToBig(u32, 0x7F000001),
    };

    client.setPeerEndpoint(server_key.public, @as(*posix.sockaddr, @ptrCast(&server_endpoint)).*, @sizeOf(posix.sockaddr.in));
    server.setPeerEndpoint(client_key.public, @as(*posix.sockaddr, @ptrCast(&client_endpoint)).*, @sizeOf(posix.sockaddr.in));

    // Initialize packet pool and work channel
    var pool = try PacketPool.init(allocator, QUEUE_SIZE * 2);
    defer pool.deinit(allocator);

    var work_chan = try os.Darwin.Channel(*Packet).init(allocator, QUEUE_SIZE);
    defer work_chan.deinit();

    var ctx = Context{
        .udp = server,
        .pool = &pool,
        .work_chan = &work_chan,
        .running = std.atomic.Value(bool).init(true),
        .recv_bytes = std.atomic.Value(u64).init(0),
        .recv_packets = std.atomic.Value(u64).init(0),
        .io_reads = std.atomic.Value(u64).init(0),
        .decrypt_processed = std.atomic.Value(u64).init(0),
        .queue_full = std.atomic.Value(u64).init(0),
    };

    // Start IO thread
    const io_thread = try std.Thread.spawn(.{}, ioThread, .{&ctx});

    // Start decrypt workers
    var workers: [NUM_WORKERS]std.Thread = undefined;
    for (&workers) |*w| {
        w.* = try std.Thread.spawn(.{}, decryptWorker, .{&ctx});
    }

    // Client receive thread for handshake responses
    var client_running = std.atomic.Value(bool).init(true);
    const client_recv_thread = try std.Thread.spawn(.{}, struct {
        fn run(c: *UDP, r: *std.atomic.Value(bool)) void {
            var buf: [65535]u8 = undefined;
            while (r.load(.acquire)) {
                _ = c.readFrom(&buf) catch |err| {
                    if (err == UdpError.Closed) break;
                    continue;
                };
            }
        }
    }.run, .{ client, &client_running });

    std.debug.print("Connecting...\n", .{});
    try client.connect(&server_key.public);
    std.debug.print("Connected!\n", .{});

    const iterations = (size_mb * 1024 * 1024) / CHUNK_SIZE;
    const total_bytes: u64 = @intCast(iterations * CHUNK_SIZE);

    std.debug.print("Sending {} MB ({} packets)...\n", .{ size_mb, iterations });

    var chunk: [CHUNK_SIZE]u8 = undefined;
    for (&chunk, 0..) |*c, i| {
        c.* = @intCast(i % 256);
    }

    const start = std.time.nanoTimestamp();
    var sent_bytes: u64 = 0;

    for (0..iterations) |_| {
        client.writeTo(&server_key.public, &chunk) catch |err| {
            std.debug.print("Write failed: {}\n", .{err});
            break;
        };
        sent_bytes += CHUNK_SIZE;
    }
    const send_time = std.time.nanoTimestamp() - start;

    // Wait for all packets to be received
    const timeout_ns: i128 = 30 * std.time.ns_per_s;
    const wait_start = std.time.nanoTimestamp();
    while (ctx.recv_bytes.load(.acquire) < total_bytes) {
        if (std.time.nanoTimestamp() - wait_start > timeout_ns) {
            std.debug.print("Warning: Timeout\n", .{});
            break;
        }
        std.Thread.sleep(10 * std.time.ns_per_ms);
    }

    const total_time = std.time.nanoTimestamp() - start;

    // Shutdown
    ctx.running.store(false, .release);
    client_running.store(false, .release);

    // Close channel to wake blocked workers
    work_chan.close();

    client.close();
    server.close();

    io_thread.join();
    for (&workers) |*w| {
        w.join();
    }
    client_recv_thread.join();

    // Results
    const final_recv_bytes = ctx.recv_bytes.load(.acquire);
    const final_recv_packets = ctx.recv_packets.load(.acquire);
    const loss = @as(f64, @floatFromInt(iterations - final_recv_packets)) / @as(f64, @floatFromInt(iterations)) * 100.0;

    std.debug.print("\n=== Stats ===\n", .{});
    std.debug.print("  io_reads:          {}\n", .{ctx.io_reads.load(.acquire)});
    std.debug.print("  decrypt_processed: {}\n", .{ctx.decrypt_processed.load(.acquire)});
    std.debug.print("  queue_full:        {}\n", .{ctx.queue_full.load(.acquire)});

    std.debug.print("\n=== Results ===\n", .{});
    std.debug.print("Sent:     {} packets, {d:.2} MB\n", .{ iterations, @as(f64, @floatFromInt(sent_bytes)) / 1024.0 / 1024.0 });
    std.debug.print("Received: {} packets, {d:.2} MB\n", .{ final_recv_packets, @as(f64, @floatFromInt(final_recv_bytes)) / 1024.0 / 1024.0 });
    std.debug.print("Loss:     {d:.2}%\n", .{loss});
    std.debug.print("Send time: {d:.2} ms\n", .{@as(f64, @floatFromInt(send_time)) / 1000000.0});
    std.debug.print("Total time: {d:.2} ms\n", .{@as(f64, @floatFromInt(total_time)) / 1000000.0});
    std.debug.print("Throughput: {d:.2} MB/s\n", .{@as(f64, @floatFromInt(final_recv_bytes)) / 1024.0 / 1024.0 / (@as(f64, @floatFromInt(total_time)) / 1000000000.0)});
}
