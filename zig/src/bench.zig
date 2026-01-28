//! Noise Protocol Benchmarks
//!
//! Run with: zig build bench

const std = @import("std");
const time = std.time;
const noise = @import("noise.zig");
const keypair = noise.keypair;
const cipher = noise.cipher;
const crypto = noise.crypto;
const state = noise.state;
const handshake = noise.handshake;

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

    std.debug.print("\n", .{});
}
