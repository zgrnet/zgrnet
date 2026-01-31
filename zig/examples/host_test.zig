//! Cross-language UDP communication demo.
//!
//! Usage:
//!   zig build && ./zig-out/bin/host_test --name zig

const std = @import("std");
const posix = std.posix;
const noise = @import("noise");

const Key = noise.Key;
const KeyPair = noise.KeyPair;
const UDP = noise.UDP;

const HostInfo = struct {
    name: []const u8,
    private_key: []const u8,
    port: u16,
};

// Hardcoded config (matching config.json)
const hosts = [_]HostInfo{
    .{ .name = "go", .private_key = "0000000000000000000000000000000000000000000000000000000000000001", .port = 10001 },
    .{ .name = "rust", .private_key = "0000000000000000000000000000000000000000000000000000000000000002", .port = 10002 },
    .{ .name = "zig", .private_key = "0000000000000000000000000000000000000000000000000000000000000003", .port = 10003 },
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Parse command line args
    var args = try std.process.argsWithAllocator(allocator);
    defer args.deinit();

    var name: ?[]const u8 = null;
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--name")) {
            name = args.next();
        }
    }

    const host_name = name orelse {
        std.debug.print("Usage: --name <name>\n", .{});
        return;
    };

    // Find our host
    var my_host: ?HostInfo = null;
    for (hosts) |h| {
        if (std.mem.eql(u8, h.name, host_name)) {
            my_host = h;
            break;
        }
    }

    const info = my_host orelse {
        std.debug.print("Host {s} not found\n", .{host_name});
        return;
    };

    // Parse private key
    var priv_key_bytes: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&priv_key_bytes, info.private_key) catch {
        std.debug.print("Invalid private key\n", .{});
        return;
    };
    const priv_key = Key.fromBytes(priv_key_bytes);

    const key_pair = KeyPair.fromPrivate(priv_key);

    // Print first 8 bytes of public key for identification
    std.debug.print("[{s}] Public key: {x}\n", .{ host_name, key_pair.public.data[0..8].* });

    // Pre-calculate peer keypairs for efficient lookups
    var peer_keypairs: [hosts.len]KeyPair = undefined;
    for (hosts, 0..) |h, i| {
        var pk_bytes: [32]u8 = undefined;
        _ = std.fmt.hexToBytes(&pk_bytes, h.private_key) catch continue;
        peer_keypairs[i] = KeyPair.fromPrivate(Key.fromBytes(pk_bytes));
    }

    // Create UDP
    const udp = UDP.init(allocator, key_pair, .{
        .port = info.port,
        .allow_unknown = true,
    }) catch |err| {
        std.debug.print("Failed to create UDP: {}\n", .{err});
        return;
    };
    defer udp.deinit();

    std.debug.print("[{s}] Listening on port {d}\n", .{ host_name, info.port });

    // Add other hosts as peers
    for (hosts) |h| {
        if (std.mem.eql(u8, h.name, host_name)) {
            continue;
        }

        var peer_priv_bytes: [32]u8 = undefined;
        _ = std.fmt.hexToBytes(&peer_priv_bytes, h.private_key) catch continue;
        const peer_kp = KeyPair.fromPrivate(Key.fromBytes(peer_priv_bytes));

        var endpoint: posix.sockaddr.in = .{
            .family = posix.AF.INET,
            .port = std.mem.nativeToBig(u16, h.port),
            .addr = std.mem.nativeToBig(u32, 0x7F000001), // 127.0.0.1 in network byte order
        };

        udp.setPeerEndpoint(peer_kp.public, @as(*posix.sockaddr, @ptrCast(&endpoint)).*, @sizeOf(posix.sockaddr.in));
        std.debug.print("[{s}] Added peer {s} at port {d}\n", .{ host_name, h.name, h.port });
    }

    // Wait for other hosts to start
    std.debug.print("[{s}] Waiting 2 seconds for other hosts...\n", .{host_name});
    std.Thread.sleep(2 * std.time.ns_per_s);

    // Start receive thread
    const RecvContext = struct {
        udp: *UDP,
        host_name: []const u8,
        peer_keypairs: *const [hosts.len]KeyPair,
        running: *std.atomic.Value(bool),
        allocator: std.mem.Allocator,
    };

    var running = std.atomic.Value(bool).init(true);
    const recv_ctx = RecvContext{
        .udp = udp,
        .host_name = host_name,
        .peer_keypairs = &peer_keypairs,
        .running = &running,
        .allocator = allocator,
    };

    const recv_thread = std.Thread.spawn(.{}, struct {
        fn run(ctx: RecvContext) void {
            var buf: [4096]u8 = undefined;
            while (ctx.running.load(.seq_cst) and !ctx.udp.isClosed()) {
                if (ctx.udp.readFrom(&buf)) |result| {
                    const from_name = findPeerNameCached(&result.pk, ctx.peer_keypairs);
                    std.debug.print("[{s}] Received from {s}: {s}\n", .{ ctx.host_name, from_name, buf[0..result.n] });

                    // Echo back if not an ACK
                    if (result.n < 3 or !std.mem.eql(u8, buf[0..3], "ACK")) {
                        var reply_buf: [256]u8 = undefined;
                        const reply = std.fmt.bufPrint(&reply_buf, "ACK from {s}: {s}", .{ ctx.host_name, buf[0..result.n] }) catch continue;
                        _ = ctx.udp.writeTo(&result.pk, reply) catch {};
                    }
                } else |_| {
                    // Error or timeout, continue
                }
            }
        }
    }.run, .{recv_ctx}) catch {
        std.debug.print("Failed to spawn receive thread\n", .{});
        return;
    };

    // Connect to and message other hosts
    for (hosts) |h| {
        if (std.mem.eql(u8, h.name, host_name)) {
            continue;
        }

        var peer_priv_bytes: [32]u8 = undefined;
        _ = std.fmt.hexToBytes(&peer_priv_bytes, h.private_key) catch continue;
        const peer_kp = KeyPair.fromPrivate(Key.fromBytes(peer_priv_bytes));

        std.debug.print("[{s}] Connecting to {s}...\n", .{ host_name, h.name });

        udp.connect(&peer_kp.public) catch |err| {
            std.debug.print("[{s}] Failed to connect to {s}: {}\n", .{ host_name, h.name, err });
            continue;
        };

        std.debug.print("[{s}] Connected to {s}!\n", .{ host_name, h.name });

        // Send test message
        var msg_buf: [128]u8 = undefined;
        const msg = std.fmt.bufPrint(&msg_buf, "Hello from {s} to {s}!", .{ host_name, h.name }) catch continue;

        udp.writeTo(&peer_kp.public, msg) catch |err| {
            std.debug.print("[{s}] Failed to send to {s}: {}\n", .{ host_name, h.name, err });
            continue;
        };

        std.debug.print("[{s}] Sent message to {s}\n", .{ host_name, h.name });
    }

    std.debug.print("[{s}] Running... Press Ctrl+C to exit\n", .{host_name});

    // Wait a bit for messages then exit
    std.Thread.sleep(5 * std.time.ns_per_s);
    running.store(false, .seq_cst);
    udp.close();
    recv_thread.join();
}

/// Find peer name using pre-calculated keypairs for O(1) key derivation.
fn findPeerNameCached(pubkey: *const Key, keypairs: *const [hosts.len]KeyPair) []const u8 {
    for (hosts, 0..) |h, i| {
        if (std.mem.eql(u8, &keypairs[i].public.data, &pubkey.data)) {
            return h.name;
        }
    }
    return "unknown";
}
