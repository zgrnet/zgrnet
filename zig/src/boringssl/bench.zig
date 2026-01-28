const std = @import("std");
const aead = @import("aead.zig");

var g_ct: [1040]u8 = undefined;
var g_pt: [1024]u8 = undefined;
var g_sum: u64 = 0;

pub fn main() !void {
    const key = [_]u8{0} ** 32;
    const plaintext = [_]u8{0xAB} ** 1024;
    const iterations: usize = 500000;

    std.debug.print("\n=== Zig + BoringSSL ARM64 ASM ===\n\n", .{});

    aead.encrypt(&key, 0, &plaintext, &g_ct);
    try aead.decrypt(&key, 0, &g_ct, &g_pt);
    if (!std.mem.eql(u8, &plaintext, &g_pt)) {
        std.debug.print("ERROR!\n", .{});
        return;
    }
    std.debug.print("Verification: OK\n\n", .{});

    for (0..iterations / 10) |i| aead.encrypt(&key, i, &plaintext, &g_ct);
    var start = std.time.nanoTimestamp();
    for (0..iterations) |i| {
        aead.encrypt(&key, i, &plaintext, &g_ct);
        g_sum +%= g_ct[0];
    }
    var elapsed = @as(f64, @floatFromInt(std.time.nanoTimestamp() - start)) / @as(f64, iterations);
    std.debug.print("encrypt_1kb: {d:>6.0} ns ({d:.2} Gbps)\n", .{ elapsed, 8192.0 / elapsed });

    aead.encrypt(&key, 0, &plaintext, &g_ct);
    for (0..iterations / 10) |_| aead.decrypt(&key, 0, &g_ct, &g_pt) catch {};
    start = std.time.nanoTimestamp();
    for (0..iterations) |_| {
        aead.decrypt(&key, 0, &g_ct, &g_pt) catch {};
        g_sum +%= g_pt[0];
    }
    elapsed = @as(f64, @floatFromInt(std.time.nanoTimestamp() - start)) / @as(f64, iterations);
    std.debug.print("decrypt_1kb: {d:>6.0} ns ({d:.2} Gbps)\n", .{ elapsed, 8192.0 / elapsed });

    for (0..iterations / 10) |i| {
        aead.encrypt(&key, i, &plaintext, &g_ct);
        aead.decrypt(&key, i, &g_ct, &g_pt) catch {};
    }
    start = std.time.nanoTimestamp();
    for (0..iterations) |i| {
        aead.encrypt(&key, i, &plaintext, &g_ct);
        aead.decrypt(&key, i, &g_ct, &g_pt) catch {};
        g_sum +%= g_pt[0];
    }
    elapsed = @as(f64, @floatFromInt(std.time.nanoTimestamp() - start)) / @as(f64, iterations);
    std.debug.print("transport_1kb: {d:>6.0} ns ({d:.2} Gbps)\n", .{ elapsed, 8192.0 / elapsed });

    if (g_sum == 0) std.debug.print("", .{});
}
