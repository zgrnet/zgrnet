//! Noise Protocol Benchmarks
//!
//! Run with: zig build bench

const std = @import("std");
const time = std.time;
const Thread = std.Thread;
const net = std.net;
const posix = std.posix;
const root = @import("noise.zig");
const noise = root.noise;
const net_mod = root.net;
const keypair = noise.keypair;
const cipher = noise.cipher;
const crypto = noise.crypto;
const state = noise.state;
const handshake = noise.handshake;
const session_mod = noise.session;
const Session = noise.Session;
const SessionManager = net_mod.SessionManager;

/// Helper for UDP benchmark setup - creates connected server and client sockets
const UdpBenchSetup = struct {
    server_fd: posix.fd_t,
    client_fd: posix.fd_t,

    pub fn init() !UdpBenchSetup {
        // Create server socket
        const server_addr = net.Address.initIp4(.{ 127, 0, 0, 1 }, 0);
        const server_fd = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM, 0);
        errdefer posix.close(server_fd);

        try posix.bind(server_fd, &server_addr.any, server_addr.getOsSockLen());

        // Get assigned port
        var bound_addr: net.Address = undefined;
        var bound_len: posix.socklen_t = @sizeOf(posix.sockaddr);
        try posix.getsockname(server_fd, &bound_addr.any, &bound_len);

        // Create client socket
        const client_fd = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM, 0);
        errdefer posix.close(client_fd);

        // Bind client to any port
        const client_addr = net.Address.initIp4(.{ 127, 0, 0, 1 }, 0);
        try posix.bind(client_fd, &client_addr.any, client_addr.getOsSockLen());

        // Connect client to server
        try posix.connect(client_fd, &bound_addr.any, bound_addr.getOsSockLen());

        return .{
            .server_fd = server_fd,
            .client_fd = client_fd,
        };
    }

    pub fn deinit(self: *UdpBenchSetup) void {
        posix.close(self.server_fd);
        posix.close(self.client_fd);
    }

    pub fn send(self: UdpBenchSetup, data: []const u8) !usize {
        return posix.send(self.client_fd, data, 0);
    }
};

fn doNotOptimize(ptr: anytype) void {
    // Prevent compiler from optimizing away the result
    const T = @TypeOf(ptr);
    const addr = @intFromPtr(ptr);
    _ = @as(*volatile T, @ptrFromInt(addr));
}

pub fn main() !void {
    std.debug.print("\n=== Zig Noise Protocol Benchmarks ===\n\n", .{});

    // Key Generation benchmark
    {
        const iterations: usize = 10000;
        const warmup: usize = 1000;

        for (0..warmup) |_| {
            const kp = keypair.KeyPair.generate();
            doNotOptimize(&kp);
        }

        const start = time.nanoTimestamp();
        for (0..iterations) |_| {
            const kp = keypair.KeyPair.generate();
            doNotOptimize(&kp);
        }
        const end = time.nanoTimestamp();

        const elapsed_ns = @as(f64, @floatFromInt(end - start));
        const per_op_us = elapsed_ns / @as(f64, iterations) / 1000.0;
        std.debug.print("key_generation: {d:.2} us/op ({d:.0} ops/sec)\n", .{
            per_op_us,
            1_000_000.0 / per_op_us,
        });
    }

    // DH benchmark
    {
        const iterations: usize = 10000;
        const warmup: usize = 1000;
        const alice = keypair.KeyPair.generate();
        const bob = keypair.KeyPair.generate();

        for (0..warmup) |_| {
            const shared = alice.dh(bob.public) catch keypair.Key.zero;
            doNotOptimize(&shared);
        }

        const start = time.nanoTimestamp();
        for (0..iterations) |_| {
            const shared = alice.dh(bob.public) catch keypair.Key.zero;
            doNotOptimize(&shared);
        }
        const end = time.nanoTimestamp();

        const elapsed_ns = @as(f64, @floatFromInt(end - start));
        const per_op_us = elapsed_ns / @as(f64, iterations) / 1000.0;
        std.debug.print("dh: {d:.2} us/op ({d:.0} ops/sec)\n", .{
            per_op_us,
            1_000_000.0 / per_op_us,
        });
    }

    // Hash benchmark
    {
        const iterations: usize = 1000000;
        const warmup: usize = 100000;
        const data = [_]u8{0} ** 64;

        for (0..warmup) |_| {
            const h = crypto.hash(&.{&data});
            doNotOptimize(&h);
        }

        const start = time.nanoTimestamp();
        for (0..iterations) |_| {
            const h = crypto.hash(&.{&data});
            doNotOptimize(&h);
        }
        const end = time.nanoTimestamp();

        const elapsed_ns = @as(f64, @floatFromInt(end - start));
        const per_op_ns = elapsed_ns / @as(f64, iterations);
        std.debug.print("hash: {d:.0} ns/op ({d:.0} ops/sec)\n", .{
            per_op_ns,
            1_000_000_000.0 / per_op_ns,
        });
    }

    // Encrypt 1KB benchmark
    {
        const iterations: usize = 1000000;
        const warmup: usize = 100000;
        const key = [_]u8{0} ** 32;
        const plaintext = [_]u8{0} ** 1024;
        var out: [1024 + 16]u8 = undefined;
        var nonce: u64 = 0;

        for (0..warmup) |_| {
            cipher.encrypt(&key, nonce, &plaintext, "", &out);
            nonce +%= 1;
        }

        nonce = 0;
        const start = time.nanoTimestamp();
        for (0..iterations) |_| {
            cipher.encrypt(&key, nonce, &plaintext, "", &out);
            nonce +%= 1;
        }
        const end = time.nanoTimestamp();

        const elapsed_ns = @as(f64, @floatFromInt(end - start));
        const per_op_ns = elapsed_ns / @as(f64, iterations);
        const throughput_gbps = (1024.0 * 8.0 * @as(f64, iterations)) / (elapsed_ns / 1_000_000_000.0) / 1e9;
        std.debug.print("encrypt_1kb: {d:.0} ns/op ({d:.2} Gbps)\n", .{
            per_op_ns,
            throughput_gbps,
        });
    }

    // Decrypt 1KB benchmark
    {
        const iterations: usize = 1000000;
        const warmup: usize = 100000;
        const key = [_]u8{0} ** 32;
        const plaintext = [_]u8{0} ** 1024;
        var ciphertext: [1024 + 16]u8 = undefined;
        cipher.encrypt(&key, 0, &plaintext, "", &ciphertext);
        var out: [1024]u8 = undefined;

        for (0..warmup) |_| {
            cipher.decrypt(&key, 0, &ciphertext, "", &out) catch {};
        }

        const start = time.nanoTimestamp();
        for (0..iterations) |_| {
            cipher.decrypt(&key, 0, &ciphertext, "", &out) catch {};
        }
        const end = time.nanoTimestamp();

        const elapsed_ns = @as(f64, @floatFromInt(end - start));
        const per_op_ns = elapsed_ns / @as(f64, iterations);
        const throughput_gbps = (1024.0 * 8.0 * @as(f64, iterations)) / (elapsed_ns / 1_000_000_000.0) / 1e9;
        std.debug.print("decrypt_1kb: {d:.0} ns/op ({d:.2} Gbps)\n", .{
            per_op_ns,
            throughput_gbps,
        });
    }

    // Handshake IK benchmark
    {
        const iterations: usize = 1000;
        const warmup: usize = 100;

        for (0..warmup) |_| {
            const initiator_static = keypair.KeyPair.generate();
            const responder_static = keypair.KeyPair.generate();

            var initiator = handshake.HandshakeState.init(.{
                .pattern = .IK,
                .initiator = true,
                .local_static = initiator_static,
                .remote_static = responder_static.public,
            }) catch continue;

            var responder = handshake.HandshakeState.init(.{
                .pattern = .IK,
                .initiator = false,
                .local_static = responder_static,
            }) catch continue;

            var msg1: [256]u8 = undefined;
            const msg1_len = initiator.writeMessage("", &msg1) catch continue;
            var p1: [64]u8 = undefined;
            _ = responder.readMessage(msg1[0..msg1_len], &p1) catch continue;

            var msg2: [256]u8 = undefined;
            const msg2_len = responder.writeMessage("", &msg2) catch continue;
            var p2: [64]u8 = undefined;
            _ = initiator.readMessage(msg2[0..msg2_len], &p2) catch continue;

            _ = initiator.split() catch continue;
            _ = responder.split() catch continue;
        }

        const start = time.nanoTimestamp();

        for (0..iterations) |_| {
            const initiator_static = keypair.KeyPair.generate();
            const responder_static = keypair.KeyPair.generate();

            var initiator = handshake.HandshakeState.init(.{
                .pattern = .IK,
                .initiator = true,
                .local_static = initiator_static,
                .remote_static = responder_static.public,
            }) catch continue;

            var responder = handshake.HandshakeState.init(.{
                .pattern = .IK,
                .initiator = false,
                .local_static = responder_static,
            }) catch continue;

            var msg1: [256]u8 = undefined;
            const msg1_len = initiator.writeMessage("", &msg1) catch continue;
            var p1: [64]u8 = undefined;
            _ = responder.readMessage(msg1[0..msg1_len], &p1) catch continue;

            var msg2: [256]u8 = undefined;
            const msg2_len = responder.writeMessage("", &msg2) catch continue;
            var p2: [64]u8 = undefined;
            _ = initiator.readMessage(msg2[0..msg2_len], &p2) catch continue;

            _ = initiator.split() catch continue;
            _ = responder.split() catch continue;
        }

        const end = time.nanoTimestamp();
        const elapsed_ns = @as(f64, @floatFromInt(end - start));
        const per_op_us = elapsed_ns / @as(f64, iterations) / 1000.0;

        std.debug.print("handshake_ik: {d:.2} us/op ({d:.0} ops/sec)\n", .{
            per_op_us,
            1_000_000.0 / per_op_us,
        });
    }

    // Transport 1KB benchmark
    {
        const initiator_static = keypair.KeyPair.generate();
        const responder_static = keypair.KeyPair.generate();

        var initiator = try handshake.HandshakeState.init(.{
            .pattern = .IK,
            .initiator = true,
            .local_static = initiator_static,
            .remote_static = responder_static.public,
        });

        var responder = try handshake.HandshakeState.init(.{
            .pattern = .IK,
            .initiator = false,
            .local_static = responder_static,
        });

        var msg1: [256]u8 = undefined;
        const msg1_len = try initiator.writeMessage("", &msg1);
        var p1: [64]u8 = undefined;
        _ = try responder.readMessage(msg1[0..msg1_len], &p1);

        var msg2: [256]u8 = undefined;
        const msg2_len = try responder.writeMessage("", &msg2);
        var p2: [64]u8 = undefined;
        _ = try initiator.readMessage(msg2[0..msg2_len], &p2);

        var send_i, _ = try initiator.split();
        _, var recv_r = try responder.split();

        const plaintext = [_]u8{0} ** 1024;
        const iterations: usize = 100000;
        const warmup: usize = 10000;

        // Warmup
        for (0..warmup) |_| {
            var ct: [1024 + 16]u8 = undefined;
            send_i.encrypt(&plaintext, "", &ct);
            var pt: [1024]u8 = undefined;
            recv_r.decrypt(&ct, "", &pt) catch continue;
        }

        const start = time.nanoTimestamp();

        for (0..iterations) |_| {
            var ct: [1024 + 16]u8 = undefined;
            send_i.encrypt(&plaintext, "", &ct);
            var pt: [1024]u8 = undefined;
            recv_r.decrypt(&ct, "", &pt) catch continue;
        }

        const end = time.nanoTimestamp();
        const elapsed_ns = @as(f64, @floatFromInt(end - start));
        const per_op_ns = elapsed_ns / @as(f64, iterations);
        const throughput_gbps = (1024.0 * 8.0 * @as(f64, iterations)) / (elapsed_ns / 1_000_000_000.0) / 1e9;

        std.debug.print("transport_1kb: {d:.0} ns/op ({d:.2} Gbps)\n", .{
            per_op_ns,
            throughput_gbps,
        });
    }

    // ==========================================================================
    // Concurrent Session Benchmarks
    // ==========================================================================
    std.debug.print("\n=== Concurrent Benchmarks ===\n\n", .{});

    // Concurrent Session Create benchmark
    {
        const num_threads: usize = 4;
        const ops_per_thread: usize = 1000;
        const allocator = std.heap.page_allocator;

        var manager = SessionManager.init(allocator);
        defer manager.deinit();

        const ThreadContext = struct {
            manager: *SessionManager,
            ops: usize,
        };

        const worker = struct {
            fn run(ctx: ThreadContext) void {
                for (0..ctx.ops) |_| {
                    const kp = keypair.KeyPair.generate();
                    const send_key = keypair.Key.fromBytes(crypto.hash(&.{"send"}));
                    const recv_key = keypair.Key.fromBytes(crypto.hash(&.{"recv"}));

                    if (ctx.manager.createSession(kp.public, send_key, recv_key)) |sess| {
                        ctx.manager.removeSession(sess.local_index);
                    } else |_| {}
                }
            }
        }.run;

        // Warmup
        for (0..100) |_| {
            const kp = keypair.KeyPair.generate();
            const send_key = keypair.Key.fromBytes(crypto.hash(&.{"send"}));
            const recv_key = keypair.Key.fromBytes(crypto.hash(&.{"recv"}));
            if (manager.createSession(kp.public, send_key, recv_key)) |sess| {
                manager.removeSession(sess.local_index);
            } else |_| {}
        }

        const ctx = ThreadContext{ .manager = &manager, .ops = ops_per_thread };
        var threads: [num_threads]Thread = undefined;

        const start = time.nanoTimestamp();
        for (0..num_threads) |i| {
            threads[i] = Thread.spawn(.{}, worker, .{ctx}) catch unreachable;
        }
        for (threads) |t| {
            t.join();
        }
        const end = time.nanoTimestamp();

        const total_ops = num_threads * ops_per_thread;
        const elapsed_ns = @as(f64, @floatFromInt(end - start));
        const per_op_us = elapsed_ns / @as(f64, @floatFromInt(total_ops)) / 1000.0;

        std.debug.print("concurrent_session_create ({d} threads): {d:.2} us/op ({d:.0} ops/sec)\n", .{
            num_threads,
            per_op_us,
            1_000_000.0 / per_op_us,
        });
    }

    // Concurrent Handshake benchmark
    {
        const num_threads: usize = 4;
        const ops_per_thread: usize = 500;

        const worker = struct {
            fn run(ops: usize) void {
                for (0..ops) |_| {
                    const initiator_static = keypair.KeyPair.generate();
                    const responder_static = keypair.KeyPair.generate();

                    var initiator = handshake.HandshakeState.init(.{
                        .pattern = .IK,
                        .initiator = true,
                        .local_static = initiator_static,
                        .remote_static = responder_static.public,
                    }) catch continue;

                    var responder = handshake.HandshakeState.init(.{
                        .pattern = .IK,
                        .initiator = false,
                        .local_static = responder_static,
                    }) catch continue;

                    var msg1: [256]u8 = undefined;
                    const msg1_len = initiator.writeMessage("", &msg1) catch continue;
                    var p1: [64]u8 = undefined;
                    _ = responder.readMessage(msg1[0..msg1_len], &p1) catch continue;

                    var msg2: [256]u8 = undefined;
                    const msg2_len = responder.writeMessage("", &msg2) catch continue;
                    var p2: [64]u8 = undefined;
                    _ = initiator.readMessage(msg2[0..msg2_len], &p2) catch continue;

                    _ = initiator.split() catch continue;
                    _ = responder.split() catch continue;
                }
            }
        }.run;

        var threads: [num_threads]Thread = undefined;

        const start = time.nanoTimestamp();
        for (0..num_threads) |i| {
            threads[i] = Thread.spawn(.{}, worker, .{ops_per_thread}) catch unreachable;
        }
        for (threads) |t| {
            t.join();
        }
        const end = time.nanoTimestamp();

        const total_ops = num_threads * ops_per_thread;
        const elapsed_ns = @as(f64, @floatFromInt(end - start));
        const per_op_us = elapsed_ns / @as(f64, @floatFromInt(total_ops)) / 1000.0;

        std.debug.print("concurrent_handshake_ik ({d} threads): {d:.2} us/op ({d:.0} ops/sec)\n", .{
            num_threads,
            per_op_us,
            1_000_000.0 / per_op_us,
        });
    }

    // Concurrent Session Encrypt benchmark
    {
        const num_threads: usize = 4;
        const ops_per_thread: usize = 100000;

        const send_key = keypair.Key.fromBytes(crypto.hash(&.{"send"}));
        const recv_key = keypair.Key.fromBytes(crypto.hash(&.{"recv"}));

        var session = Session.init(.{
            .local_index = 1,
            .remote_index = 2,
            .send_key = send_key,
            .recv_key = recv_key,
        });

        const ThreadContext = struct {
            session: *Session,
            ops: usize,
        };

        const worker = struct {
            fn run(ctx: ThreadContext) void {
                const plaintext = [_]u8{0} ** 1024;
                var out: [1024 + 16]u8 = undefined;

                for (0..ctx.ops) |_| {
                    _ = ctx.session.encrypt(&plaintext, &out) catch continue;
                }
            }
        }.run;

        const ctx = ThreadContext{ .session = &session, .ops = ops_per_thread };
        var threads: [num_threads]Thread = undefined;

        const start = time.nanoTimestamp();
        for (0..num_threads) |i| {
            threads[i] = Thread.spawn(.{}, worker, .{ctx}) catch unreachable;
        }
        for (threads) |t| {
            t.join();
        }
        const end = time.nanoTimestamp();

        const total_ops = num_threads * ops_per_thread;
        const elapsed_ns = @as(f64, @floatFromInt(end - start));
        const per_op_ns = elapsed_ns / @as(f64, @floatFromInt(total_ops));
        const throughput_gbps = (1024.0 * 8.0 * @as(f64, @floatFromInt(total_ops))) / (elapsed_ns / 1_000_000_000.0) / 1e9;

        std.debug.print("concurrent_session_encrypt_1kb ({d} threads): {d:.0} ns/op ({d:.2} Gbps total)\n", .{
            num_threads,
            per_op_ns,
            throughput_gbps,
        });
    }

    // ==========================================================================
    // UDP Transport Benchmarks
    // ==========================================================================
    std.debug.print("\n=== UDP Transport Benchmarks ===\n\n", .{});

    // UDP Throughput benchmark (using udp.Udp)
    {
        const iterations: usize = 100000;

        // Use helper for setup
        var setup = UdpBenchSetup.init() catch |e| {
            std.debug.print("Failed to setup UDP benchmark: {}\n", .{e});
            return;
        };

        // Server drain thread
        const server_thread = Thread.spawn(.{}, struct {
            fn run(fd: posix.fd_t) void {
                var buf: [1500]u8 = undefined;
                while (true) {
                    _ = posix.recv(fd, &buf, 0) catch break;
                }
            }
        }.run, .{setup.server_fd}) catch unreachable;

        const data = [_]u8{0} ** 1400;

        const start = time.nanoTimestamp();
        for (0..iterations) |_| {
            _ = setup.send(&data) catch break;
        }
        const end = time.nanoTimestamp();

        // Close server first to unblock recv, then join
        setup.deinit();
        server_thread.join();

        const elapsed_ns = @as(f64, @floatFromInt(end - start));
        const per_op_ns = elapsed_ns / @as(f64, iterations);
        const throughput_mbps = (1400.0 * @as(f64, iterations)) / (elapsed_ns / 1_000_000_000.0) / 1_000_000.0;
        std.debug.print("udp_throughput: {d:.0} ns/op ({d:.0} MB/s)\n", .{
            per_op_ns,
            throughput_mbps,
        });
    }

    // UDP + Noise Throughput benchmark (using udp.Udp)
    {
        const iterations: usize = 100000;

        // Use helper for setup
        var setup = UdpBenchSetup.init() catch return;

        // Create session
        const send_key = keypair.Key.fromBytes(crypto.hash(&.{"send"}));
        const recv_key = keypair.Key.fromBytes(crypto.hash(&.{"recv"}));

        var client_session = Session.init(.{
            .local_index = 1,
            .remote_index = 2,
            .send_key = send_key,
            .recv_key = recv_key,
        });

        // Server drain thread
        const server_thread = Thread.spawn(.{}, struct {
            fn run(fd: posix.fd_t) void {
                var buf: [1500]u8 = undefined;
                while (true) {
                    _ = posix.recv(fd, &buf, 0) catch break;
                }
            }
        }.run, .{setup.server_fd}) catch unreachable;

        const plaintext = [_]u8{0} ** 1400;
        var send_buf: [1500]u8 = undefined;

        const start = time.nanoTimestamp();
        for (0..iterations) |_| {
            // Encrypt
            const nonce = client_session.encrypt(&plaintext, send_buf[13..]) catch continue;

            // Build header
            send_buf[0] = 4; // MessageTypeTransport
            std.mem.writeInt(u32, send_buf[1..5], 2, .little);
            std.mem.writeInt(u64, send_buf[5..13], nonce, .little);

            // Send using connected UDP socket
            _ = setup.send(send_buf[0 .. 13 + plaintext.len + 16]) catch break;
        }
        const end = time.nanoTimestamp();

        // Close server first to unblock recv
        setup.deinit();
        server_thread.join();

        const elapsed_ns = @as(f64, @floatFromInt(end - start));
        const per_op_ns = elapsed_ns / @as(f64, iterations);
        const throughput_mbps = (1400.0 * @as(f64, iterations)) / (elapsed_ns / 1_000_000_000.0) / 1_000_000.0;
        std.debug.print("udp_noise_throughput: {d:.0} ns/op ({d:.0} MB/s)\n", .{
            per_op_ns,
            throughput_mbps,
        });
    }

    // Concurrent Multi-Session benchmark
    {
        const num_threads: usize = 4;
        const num_sessions: usize = 100;
        const ops_per_thread: usize = 10000;

        var sessions: [num_sessions]Session = undefined;
        for (0..num_sessions) |i| {
            const send_input = [_]u8{ @intCast(i), 's', 'e', 'n', 'd' };
            const recv_input = [_]u8{ @intCast(i), 'r', 'e', 'c', 'v' };
            const send_key = keypair.Key.fromBytes(crypto.hash(&.{&send_input}));
            const recv_key = keypair.Key.fromBytes(crypto.hash(&.{&recv_input}));
            sessions[i] = Session.init(.{
                .local_index = @intCast(i + 1),
                .remote_index = @intCast(i + 1001),
                .send_key = send_key,
                .recv_key = recv_key,
            });
        }

        const ThreadContext = struct {
            sessions: *[num_sessions]Session,
            ops: usize,
            thread_id: usize,
        };

        const worker = struct {
            fn run(ctx: ThreadContext) void {
                const plaintext = [_]u8{0} ** 256;
                var out: [256 + 16]u8 = undefined;

                for (0..ctx.ops) |i| {
                    const idx = (ctx.thread_id * ctx.ops + i) % num_sessions;
                    _ = ctx.sessions[idx].encrypt(&plaintext, &out) catch continue;
                }
            }
        }.run;

        var threads: [num_threads]Thread = undefined;

        const start = time.nanoTimestamp();
        for (0..num_threads) |i| {
            const ctx = ThreadContext{
                .sessions = &sessions,
                .ops = ops_per_thread,
                .thread_id = i,
            };
            threads[i] = Thread.spawn(.{}, worker, .{ctx}) catch unreachable;
        }
        for (threads) |t| {
            t.join();
        }
        const end = time.nanoTimestamp();

        const total_ops = num_threads * ops_per_thread;
        const elapsed_ns = @as(f64, @floatFromInt(end - start));
        const per_op_ns = elapsed_ns / @as(f64, @floatFromInt(total_ops));
        const throughput_gbps = (256.0 * 8.0 * @as(f64, @floatFromInt(total_ops))) / (elapsed_ns / 1_000_000_000.0) / 1e9;

        std.debug.print("concurrent_multi_session ({d} sessions, {d} threads): {d:.0} ns/op ({d:.2} Gbps total)\n", .{
            num_sessions,
            num_threads,
            per_op_ns,
            throughput_gbps,
        });
    }

    std.debug.print("\n", .{});
}
