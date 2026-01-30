//! Cross-language Host communication demo.
//!
//! Usage:
//!   zig build && ./zig-out/bin/host_test --name zig
//!
//! Or run test directly:
//!   cd zig && zig run examples/host_test.zig -- --name zig

const std = @import("std");
const noise = @import("../src/noise.zig");

const Key = noise.Key;
const KeyPair = noise.KeyPair;
const Host = noise.Host;
const HostConfig = noise.HostConfig;
const Transport = noise.Transport;
const Addr = noise.Addr;
const UdpListener = noise.UdpListener;
const UdpAddr = noise.UdpAddr;
const Protocol = noise.Protocol;

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
    var priv_key: Key = undefined;
    _ = std.fmt.hexToBytes(&priv_key, info.private_key) catch {
        std.debug.print("Invalid private key\n", .{});
        return;
    };

    const key_pair = KeyPair.fromPrivate(priv_key);

    std.debug.print("[{s}] Public key: {s}\n", .{ host_name, std.fmt.fmtSliceHexLower(&key_pair.public) });

    // Pre-calculate peer keypairs for efficient lookups
    var peer_keypairs: [hosts.len]KeyPair = undefined;
    for (hosts, 0..) |h, i| {
        var pk: Key = undefined;
        _ = std.fmt.hexToBytes(&pk, h.private_key) catch continue;
        peer_keypairs[i] = KeyPair.fromPrivate(pk);
    }

    // Create UDP transport
    var bind_buf: [32]u8 = undefined;
    const bind_addr = try std.fmt.bufPrint(&bind_buf, "0.0.0.0:{d}", .{info.port});

    var udp = try UdpListener.bind(bind_addr);
    defer udp.close();

    std.debug.print("[{s}] Listening on port {d}\n", .{ host_name, udp.port() });

    // Create Host
    var host = try Host.init(allocator, .{
        .private_key = key_pair,
        .transport = udp.asTransport(),
        .mtu = 1280,
        .allow_unknown_peers = true,
    });
    defer host.deinit();

    // Add other hosts as peers
    for (hosts) |h| {
        if (std.mem.eql(u8, h.name, host_name)) {
            continue;
        }

        var peer_priv: Key = undefined;
        _ = std.fmt.hexToBytes(&peer_priv, h.private_key) catch continue;
        const peer_kp = KeyPair.fromPrivate(peer_priv);

        var addr_buf: [32]u8 = undefined;
        const addr_str = try std.fmt.bufPrint(&addr_buf, "127.0.0.1:{d}", .{h.port});
        const endpoint = UdpAddr.parse(addr_str) catch continue;

        host.addPeer(peer_kp.public, endpoint.toAddr()) catch continue;
        std.debug.print("[{s}] Added peer {s} at port {d}\n", .{ host_name, h.name, h.port });
    }

    // Wait for other hosts to start
    std.debug.print("[{s}] Waiting 2 seconds for other hosts...\n", .{host_name});
    std.time.sleep(2 * std.time.ns_per_s);

    // Connect to and message other hosts
    for (hosts) |h| {
        if (std.mem.eql(u8, h.name, host_name)) {
            continue;
        }

        var peer_priv: Key = undefined;
        _ = std.fmt.hexToBytes(&peer_priv, h.private_key) catch continue;
        const peer_kp = KeyPair.fromPrivate(peer_priv);

        std.debug.print("[{s}] Connecting to {s}...\n", .{ host_name, h.name });

        host.connect(peer_kp.public) catch |err| {
            std.debug.print("[{s}] Failed to connect to {s}: {}\n", .{ host_name, h.name, err });
            continue;
        };

        std.debug.print("[{s}] Connected to {s}!\n", .{ host_name, h.name });

        // Send test message
        var msg_buf: [128]u8 = undefined;
        const msg = try std.fmt.bufPrint(&msg_buf, "Hello from {s} to {s}!", .{ host_name, h.name });

        host.send(peer_kp.public, .chat, msg) catch |err| {
            std.debug.print("[{s}] Failed to send to {s}: {}\n", .{ host_name, h.name, err });
            continue;
        };

        std.debug.print("[{s}] Sent message to {s}\n", .{ host_name, h.name });
    }

    std.debug.print("[{s}] Running... Press Ctrl+C to exit\n", .{host_name});

    // Receive messages
    while (!host.isClosed()) {
        if (host.recvMessage()) |msg_opt| {
            if (msg_opt) |*msg| {
                defer msg.deinit();

                const from_name = findPeerNameCached(&msg.from, &peer_keypairs);
                std.debug.print("[{s}] Received from {s}: protocol={}, data={s}\n", .{ host_name, from_name, @intFromEnum(msg.protocol), msg.data });

                // Echo back if not an ACK
                if (msg.data.len < 3 or !std.mem.eql(u8, msg.data[0..3], "ACK")) {
                    var reply_buf: [256]u8 = undefined;
                    const reply = std.fmt.bufPrint(&reply_buf, "ACK from {s}: {s}", .{ host_name, msg.data }) catch continue;
                    _ = host.send(msg.from, msg.protocol, reply) catch {};
                }
            }
        } else |_| {
            // Error or timeout, continue
        }
    }
}

/// Find peer name using pre-calculated keypairs for O(1) key derivation.
fn findPeerNameCached(pubkey: *const Key, keypairs: []const KeyPair) []const u8 {
    for (hosts, 0..) |h, i| {
        if (std.mem.eql(u8, &keypairs[i].public, pubkey)) {
            return h.name;
        }
    }
    return "unknown";
}
