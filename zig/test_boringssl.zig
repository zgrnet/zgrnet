const std = @import("std");
const c = @cImport({
    @cInclude("openssl/evp.h");
});

pub fn main() !void {
    const key = [_]u8{0} ** 32;
    const nonce = [_]u8{0} ** 12;
    const plaintext = [_]u8{0} ** 1024;
    var out: [1024 + 16]u8 = undefined;
    var out_len: usize = 0;

    const ctx = c.EVP_AEAD_CTX_new(c.EVP_aead_chacha20_poly1305(), &key, 32, 16);
    defer c.EVP_AEAD_CTX_free(ctx);

    const iterations: usize = 1000000;
    const warmup: usize = 100000;

    // Warmup
    var n: u64 = 0;
    for (0..warmup) |_| {
        var nonce_bytes: [12]u8 = nonce;
        std.mem.writeInt(u64, nonce_bytes[0..8], n, .little);
        _ = c.EVP_AEAD_CTX_seal(ctx, &out, &out_len, out.len, &nonce_bytes, 12, &plaintext, 1024, null, 0);
        n +%= 1;
    }

    n = 0;
    const start = std.time.nanoTimestamp();
    for (0..iterations) |_| {
        var nonce_bytes: [12]u8 = nonce;
        std.mem.writeInt(u64, nonce_bytes[0..8], n, .little);
        _ = c.EVP_AEAD_CTX_seal(ctx, &out, &out_len, out.len, &nonce_bytes, 12, &plaintext, 1024, null, 0);
        n +%= 1;
    }
    const end = std.time.nanoTimestamp();

    const elapsed_ns = @as(f64, @floatFromInt(end - start));
    const per_op_ns = elapsed_ns / @as(f64, iterations);
    const throughput_gbps = (1024.0 * 8.0 * @as(f64, iterations)) / (elapsed_ns / 1e9) / 1e9;

    std.debug.print("zig+boringssl encrypt_1kb: {d:.0} ns/op ({d:.2} Gbps)\n", .{per_op_ns, throughput_gbps});
}
