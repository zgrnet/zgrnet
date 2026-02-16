//! Node SDK interoperability test between Zig, Go, and Rust.
//!
//! Usage:
//!   zig build run -- --name zig --config ../config.json

const std = @import("std");
const noise = @import("noise");

const Key = noise.Key;
const KeyPair = noise.KeyPair;
const NodeType = noise.NodeType;
const Endpoint = noise.Endpoint;

/// JSON config structures
const Config = struct {
    hosts: []HostInfo,
    @"test": TestConfig,
};

const HostInfo = struct {
    name: []const u8,
    private_key: []const u8,
    port: u16,
    role: []const u8,
};

const TestConfig = struct {
    echo_message: []const u8,
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Parse command line args
    var args = try std.process.argsWithAllocator(allocator);
    defer args.deinit();
    _ = args.next(); // skip program name

    var my_name: ?[]const u8 = null;
    var config_path: ?[]const u8 = null;

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--name")) {
            my_name = args.next();
        } else if (std.mem.eql(u8, arg, "--config")) {
            config_path = args.next();
        }
    }

    const name = my_name orelse {
        std.debug.print("Usage: --name <name> --config <path>\n", .{});
        return error.InvalidArgs;
    };
    const cfg_path = config_path orelse {
        std.debug.print("Usage: --name <name> --config <path>\n", .{});
        return error.InvalidArgs;
    };

    // Read config file
    const config_data = std.fs.cwd().readFileAlloc(allocator, cfg_path, 1024 * 1024) catch |e| {
        std.debug.print("Failed to read config {s}: {}\n", .{ cfg_path, e });
        return e;
    };
    defer allocator.free(config_data);

    const parsed = std.json.parseFromSlice(Config, allocator, config_data, .{}) catch |e| {
        std.debug.print("Failed to parse config: {}\n", .{e});
        return e;
    };
    defer parsed.deinit();
    const config = parsed.value;

    // Find our host
    var my_host: ?HostInfo = null;
    for (config.hosts) |h| {
        if (std.mem.eql(u8, h.name, name)) {
            my_host = h;
            break;
        }
    }
    const host = my_host orelse {
        std.debug.print("Host {s} not found in config\n", .{name});
        return error.HostNotFound;
    };

    // Parse private key
    var priv_key: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&priv_key, host.private_key) catch |e| {
        std.debug.print("Invalid private key: {}\n", .{e});
        return e;
    };
    const key_pair = KeyPair.fromPrivate(Key.fromBytes(priv_key));

    std.debug.print("[{s}] Public key: {x}...\n", .{ name, key_pair.public.data[0..8].* });
    std.debug.print("[{s}] Role: {s}\n", .{ name, host.role });

    // Create Node
    var node = NodeType.init(.{
        .key = &key_pair,
        .listen_port = host.port,
        .allow_unknown = true,
        .allocator = allocator,
    }) catch |e| {
        std.debug.print("[{s}] Failed to create node: {}\n", .{ name, e });
        return e;
    };
    defer node.deinit();

    std.debug.print("[{s}] Node created\n", .{name});

    // Find peer
    var peer_host: ?HostInfo = null;
    for (config.hosts) |h| {
        if (!std.mem.eql(u8, h.name, name)) {
            peer_host = h;
            break;
        }
    }
    const peer = peer_host orelse {
        std.debug.print("No peer found in config\n", .{});
        return error.NoPeerFound;
    };

    // Parse peer's private key to get their public key
    var peer_priv: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&peer_priv, peer.private_key) catch |e| {
        std.debug.print("Invalid peer private key: {}\n", .{e});
        return e;
    };
    const peer_kp = KeyPair.fromPrivate(Key.fromBytes(peer_priv));

    // Add peer
    node.addPeer(.{
        .public_key = peer_kp.public,
        .endpoint = Endpoint.init(.{ 127, 0, 0, 1 }, peer.port),
    }) catch |e| {
        std.debug.print("[{s}] Failed to add peer: {}\n", .{ name, e });
        return e;
    };
    std.debug.print("[{s}] Added peer {s} at port {}\n", .{ name, peer.name, peer.port });

    if (std.mem.eql(u8, host.role, "opener")) {
        // Wait for peer to start
        std.debug.print("[{s}] Waiting for peer to start...\n", .{name});
        std.Thread.sleep(2 * std.time.ns_per_s);

        // Connect
        std.debug.print("[{s}] Connecting to {s}...\n", .{ name, peer.name });
        node.connect(&peer_kp.public) catch |e| {
            std.debug.print("[{s}] Failed to connect: {}\n", .{ name, e });
            return e;
        };
        std.debug.print("[{s}] Connected!\n", .{name});
        std.Thread.sleep(100 * std.time.ns_per_ms);

        // Dial
        std.debug.print("[opener] Dialing {s}:8080...\n", .{peer.name});
        var stream = node.dial(&peer_kp.public, 8080) catch |e| {
            std.debug.print("[opener] Failed to dial: {}\n", .{e});
            return e;
        };
        std.debug.print("[opener] Stream opened: proto={}\n", .{stream.proto()});

        // Write echo
        const msg = config.@"test".echo_message;
        _ = stream.write(msg) catch |e| {
            std.debug.print("[opener] Write failed: {}\n", .{e});
            return e;
        };
        stream.stream.flush() catch {};
        std.debug.print("[opener] Sent: {s}\n", .{msg});

        // Read response (poll)
        var buf: [1024]u8 = undefined;
        const nr = readTimeout(&stream, &buf, 10_000);
        if (nr == 0) {
            std.debug.print("[opener] FAIL: read timeout\n", .{});
            return error.ReadTimeout;
        }
        std.debug.print("[opener] Received: {s}\n", .{buf[0..nr]});

        // Verify
        var expected_buf: [256]u8 = undefined;
        const expected = std.fmt.bufPrint(&expected_buf, "Echo from {s}: {s}", .{ peer.name, msg }) catch "?";
        if (std.mem.eql(u8, buf[0..nr], expected)) {
            std.debug.print("[opener] PASS: echo verified\n", .{});
        } else {
            std.debug.print("[opener] FAIL: expected '{s}', got '{s}'\n", .{ expected, buf[0..nr] });
            return error.EchoMismatch;
        }

        std.Thread.sleep(500 * std.time.ns_per_ms);
        stream.close();
    } else {
        // Accepter
        std.debug.print("[accepter] Waiting for stream...\n", .{});

        const ns = node.acceptStream() orelse {
            std.debug.print("[accepter] FAIL: accept returned null\n", .{});
            return error.AcceptFailed;
        };
        var stream = ns;
        std.debug.print("[accepter] Accepted stream: proto={}\n", .{stream.proto()});

        // Read echo
        var buf: [1024]u8 = undefined;
        const nr = readTimeout(&stream, &buf, 10_000);
        if (nr == 0) {
            std.debug.print("[accepter] FAIL: read timeout\n", .{});
            return error.ReadTimeout;
        }
        std.debug.print("[accepter] Received: {s}\n", .{buf[0..nr]});

        // Echo back
        var reply_buf: [256]u8 = undefined;
        const reply = std.fmt.bufPrint(&reply_buf, "Echo from {s}: {s}", .{ name, buf[0..nr] }) catch "?";
        _ = stream.write(reply) catch |e| {
            std.debug.print("[accepter] Write failed: {}\n", .{e});
            return e;
        };
        // Flush KCP to ensure data is sent over the wire before exiting.
        stream.stream.flush() catch {};
        std.debug.print("[accepter] Sent: {s}\n", .{reply});

        std.Thread.sleep(1000 * std.time.ns_per_ms);
        stream.close();
    }

    std.debug.print("[{s}] Test completed successfully!\n", .{name});

    // Exit immediately — graceful deinit crashes on macOS because close(fd)
    // cannot reliably interrupt a blocking read(fd). Same workaround as
    // Go host_test. TODO: fix when async I/O lands.
    std.process.exit(0);
}

fn readTimeout(stream: *NodeType.NodeStream, buf: []u8, timeout_ms: u64) usize {
    const deadline = std.time.milliTimestamp() + @as(i64, @intCast(timeout_ms));
    while (std.time.milliTimestamp() < deadline) {
        const nr = stream.read(buf) catch return 0;
        if (nr > 0) return nr;
        std.Thread.sleep(1 * std.time.ns_per_ms);
    }
    return 0;
}
