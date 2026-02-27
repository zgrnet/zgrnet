const std = @import("std");

fn hexTo32(s: []const u8) ![32]u8 {
    var out: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&out, s);
    return out;
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var args = try std.process.argsWithAllocator(allocator);
    defer args.deinit();

    var iters: usize = 10000;
    _ = args.next(); // argv[0]
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--iters")) {
            if (args.next()) |v| iters = try std.fmt.parseInt(usize, v, 10);
        }
    }

    const X = std.crypto.dh.X25519;

    // RFC7748 base point (u=9)
    const basepoint: [32]u8 = .{9} ++ .{0} ** 31;

    // Repro keys from interop config style
    const sk1 = try hexTo32("0000000000000000000000000000000000000000000000000000000000000001");
    const sk2 = try hexTo32("0000000000000000000000000000000000000000000000000000000000000002");

    std.log.info("x25519 probe start: iters={d}", .{iters});

    // 1) Minimal repro candidate: scalarmult with fixed private keys.
    const pk1 = try X.scalarmult(sk1, basepoint);
    const pk2 = try X.scalarmult(sk2, basepoint);
    std.log.info("fixed-key public derivation ok, pk1[0]={d}, pk2[0]={d}", .{ pk1[0], pk2[0] });

    // 2) Stress loop to detect platform/runtime instability.
    var i: usize = 0;
    while (i < iters) : (i += 1) {
        var seed_a: [32]u8 = undefined;
        var seed_b: [32]u8 = undefined;
        std.mem.writeInt(u64, seed_a[0..8], @as(u64, @intCast(i + 1)), .little);
        std.mem.writeInt(u64, seed_b[0..8], @as(u64, @intCast(i + 0x9e3779b97f4a7c15)), .little);
        @memset(seed_a[8..], 0xA5);
        @memset(seed_b[8..], 0x5A);

        const ka = try X.KeyPair.generateDeterministic(seed_a);
        const kb = try X.KeyPair.generateDeterministic(seed_b);

        const sa = try X.scalarmult(ka.secret_key, kb.public_key);
        const sb = try X.scalarmult(kb.secret_key, ka.public_key);

        if (!std.mem.eql(u8, &sa, &sb)) {
            std.log.err("shared secret mismatch at iter={d}", .{i});
            return error.SharedSecretMismatch;
        }

        if ((i + 1) % 1000 == 0) {
            std.log.info("progress: {d}/{d}", .{ i + 1, iters });
        }
    }

    std.log.info("x25519 probe done", .{});
}
