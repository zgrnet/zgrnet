//! Zig UDP throughput test using double-queue architecture.
//!
//! The new UDP implementation has built-in double queue:
//!   ioLoop: socket -> decryptChan + outputChan
//!   decryptWorkers (x N): decryptChan -> decrypt -> signal ready
//!   readFrom: outputChan -> wait ready -> return
//!
//! This test just needs to use readFrom() to measure throughput.

const std = @import("std");
const posix = std.posix;
const noise = @import("noise");

const Allocator = std.mem.Allocator;
const Key = noise.Key;
const KeyPair = noise.KeyPair;
const UDP = noise.UDP(noise.KqueueIO);
const UdpError = noise.UdpError;

const CHUNK_SIZE = 1200;

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

    std.debug.print("=== Zig Double-Queue UDP Throughput Test ===\n", .{});

    const server_key = KeyPair.generate();
    const client_key = KeyPair.generate();

    // Create UDP instances (double-queue with N workers built-in)
    const server = try UDP.init(allocator, &server_key, .{ .allow_unknown = true });
    const client = try UDP.init(allocator, &client_key, .{ .allow_unknown = true });

    std.debug.print("Server: 127.0.0.1:{}\n", .{server.getLocalPort()});
    std.debug.print("Client: 127.0.0.1:{}\n", .{client.getLocalPort()});

    // Set peer endpoints
    var server_endpoint: posix.sockaddr.in = .{
        .family = posix.AF.INET,
        .port = std.mem.nativeToBig(u16, server.getLocalPort()),
        .addr = std.mem.nativeToBig(u32, 0x7F000001),
    };
    var client_endpoint: posix.sockaddr.in = .{
        .family = posix.AF.INET,
        .port = std.mem.nativeToBig(u16, client.getLocalPort()),
        .addr = std.mem.nativeToBig(u32, 0x7F000001),
    };

    server.setPeerEndpoint(client_key.public, @as(*posix.sockaddr, @ptrCast(&client_endpoint)).*, @sizeOf(posix.sockaddr.in));
    client.setPeerEndpoint(server_key.public, @as(*posix.sockaddr, @ptrCast(&server_endpoint)).*, @sizeOf(posix.sockaddr.in));

    // Receiver thread (uses built-in double queue via readFrom)
    var recv_bytes = std.atomic.Value(u64).init(0);
    var recv_packets = std.atomic.Value(u64).init(0);
    var recv_running = std.atomic.Value(bool).init(true);

    const recv_thread = try std.Thread.spawn(.{}, struct {
        fn run(s: *UDP, bytes: *std.atomic.Value(u64), packets: *std.atomic.Value(u64), running: *std.atomic.Value(bool)) void {
            var buf: [65535]u8 = undefined;
            while (running.load(.acquire)) {
                const result = s.readFrom(&buf) catch |err| {
                    if (err == UdpError.Closed) break;
                    continue;
                };
                _ = bytes.fetchAdd(@intCast(result.n), .release);
                _ = packets.fetchAdd(1, .release);
            }
        }
    }.run, .{ server, &recv_bytes, &recv_packets, &recv_running });

    // Client receiver for handshake
    var client_running = std.atomic.Value(bool).init(true);
    const client_recv_thread = try std.Thread.spawn(.{}, struct {
        fn run(c: *UDP, running: *std.atomic.Value(bool)) void {
            var buf: [65535]u8 = undefined;
            while (running.load(.acquire)) {
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
    while (recv_bytes.load(.acquire) < total_bytes) {
        if (std.time.nanoTimestamp() - wait_start > timeout_ns) {
            std.debug.print("Warning: Timeout\n", .{});
            break;
        }
        std.Thread.sleep(10 * std.time.ns_per_ms);
    }

    const total_time = std.time.nanoTimestamp() - start;

    // Shutdown
    recv_running.store(false, .release);
    client_running.store(false, .release);

    client.close();
    server.close();

    recv_thread.join();
    client_recv_thread.join();

    // Results
    const final_recv_bytes = recv_bytes.load(.acquire);
    const final_recv_packets = recv_packets.load(.acquire);
    const loss = @as(f64, @floatFromInt(iterations - final_recv_packets)) / @as(f64, @floatFromInt(iterations)) * 100.0;

    std.debug.print("\n=== Results ===\n", .{});
    std.debug.print("Sent:     {} packets, {d:.2} MB\n", .{ iterations, @as(f64, @floatFromInt(sent_bytes)) / 1024.0 / 1024.0 });
    std.debug.print("Received: {} packets, {d:.2} MB\n", .{ final_recv_packets, @as(f64, @floatFromInt(final_recv_bytes)) / 1024.0 / 1024.0 });
    std.debug.print("Loss:     {d:.2}%\n", .{loss});
    std.debug.print("Send time: {d:.2} ms\n", .{@as(f64, @floatFromInt(send_time)) / 1000000.0});
    std.debug.print("Total time: {d:.2} ms\n", .{@as(f64, @floatFromInt(total_time)) / 1000000000.0 * 1000.0});
    std.debug.print("Throughput: {d:.2} MB/s\n", .{@as(f64, @floatFromInt(final_recv_bytes)) / 1024.0 / 1024.0 / (@as(f64, @floatFromInt(total_time)) / 1000000000.0)});
}
