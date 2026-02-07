//! Cross-language proxy interop test.
//!
//! Two roles:
//!   handler: echo TCP server + TCP_PROXY(69) KCP handler
//!   proxy:   opens KCP stream(proto=69) through tunnel, verifies echo
//!
//! Usage:
//!   zig build run -- --name handler --config ../config.json

const std = @import("std");
const posix = std.posix;
const noise = @import("noise");

const Key = noise.Key;
const KeyPair = noise.KeyPair;
const UDP = noise.UDP(noise.KqueueIO);
const KcpStream = noise.net.KcpStream;
const Address = noise.Address;
const Protocol = noise.Protocol;

const Config = struct {
    hosts: []HostInfo,
    echo_port: u16,
    @"test": TestConfig,
};

const HostInfo = struct {
    name: []const u8,
    private_key: []const u8,
    port: u16,
    role: []const u8,
};

const TestConfig = struct {
    message: []const u8,
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Parse args
    var args = try std.process.argsWithAllocator(allocator);
    defer args.deinit();
    _ = args.next(); // skip program name

    var my_name: ?[]const u8 = null;
    var cfg_path: ?[]const u8 = null;

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--name")) {
            my_name = args.next();
        } else if (std.mem.eql(u8, arg, "--config")) {
            cfg_path = args.next();
        }
    }

    const name = my_name orelse return error.InvalidArgs;
    const config_path = cfg_path orelse return error.InvalidArgs;

    // Read & parse config
    const config_data = try std.fs.cwd().readFileAlloc(allocator, config_path, 1024 * 1024);
    defer allocator.free(config_data);

    const parsed = try std.json.parseFromSlice(Config, allocator, config_data, .{});
    defer parsed.deinit();
    const config = parsed.value;

    // Find my host
    var my_host: ?HostInfo = null;
    for (config.hosts) |h| {
        if (std.mem.eql(u8, h.name, name)) {
            my_host = h;
            break;
        }
    }
    const host = my_host orelse return error.HostNotFound;

    // Parse key
    var priv_key: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&priv_key, host.private_key) catch return error.InvalidKey;
    const key_pair = KeyPair.fromPrivate(Key.fromBytes(priv_key));

    std.debug.print("[{s}] role={s} port={}\n", .{ name, host.role, host.port });

    // Create UDP
    var bind_buf: [32]u8 = undefined;
    const bind_addr = std.fmt.bufPrint(&bind_buf, "0.0.0.0:{}", .{host.port}) catch "0.0.0.0:0";

    const udp = try UDP.init(allocator, &key_pair, .{
        .bind_addr = bind_addr,
        .allow_unknown = true,
    });
    defer udp.deinit();

    // Find peer
    var peer_host: ?HostInfo = null;
    for (config.hosts) |h| {
        if (!std.mem.eql(u8, h.name, name)) {
            peer_host = h;
            break;
        }
    }
    const peer = peer_host orelse return error.PeerNotFound;

    var peer_priv: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&peer_priv, peer.private_key) catch return error.InvalidKey;
    const peer_kp = KeyPair.fromPrivate(Key.fromBytes(peer_priv));

    udp.setPeerEndpoint(&peer_kp.public, peer.port);

    if (std.mem.eql(u8, host.role, "handler")) {
        try runHandler(allocator, config, udp, &peer_kp.public);
    } else if (std.mem.eql(u8, host.role, "proxy")) {
        try runProxy(allocator, config, udp, &peer_kp.public);
    } else {
        std.debug.print("Unknown role: {s}\n", .{host.role});
        return error.UnknownRole;
    }
}

fn runHandler(allocator: std.mem.Allocator, config: Config, udp: *UDP, peer_pk: *const Key) !void {
    _ = allocator;

    // 1. Start TCP echo server
    const echo_addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, config.echo_port);
    const echo_server = try echo_addr.listen(.{ .reuse_address = true });
    std.debug.print("[handler] Echo on 127.0.0.1:{}\n", .{config.echo_port});

    // Echo server in background thread
    const echo_thread = try std.Thread.spawn(.{}, struct {
        fn run(srv: std.net.Server) void {
            var server = srv;
            while (true) {
                const conn = server.accept() catch return;
                const t = std.Thread.spawn(.{}, struct {
                    fn handle(c: std.net.Server.Connection) void {
                        var stream = c.stream;
                        defer stream.close();
                        var buf: [4096]u8 = undefined;
                        while (true) {
                            const n = stream.read(&buf) catch return;
                            if (n == 0) return;
                            _ = stream.write(buf[0..n]) catch return;
                        }
                    }
                }.handle, .{conn}) catch continue;
                t.detach();
            }
        }
    }.run, .{echo_server});
    echo_thread.detach();

    // 2. Wait for stream
    std.debug.print("[handler] Waiting for TCP_PROXY stream...\n", .{});
    const stream = udp.acceptStream(peer_pk) catch |e| {
        std.debug.print("[handler] acceptStream failed: {}\n", .{e});
        return e;
    };
    defer stream.close();

    std.debug.print("[handler] Got stream id={} proto={}\n", .{ stream.getId(), stream.getProto() });

    if (stream.getProto() != @intFromEnum(Protocol.tcp_proxy)) {
        std.debug.print("[handler] Expected proto=69, got {}\n", .{stream.getProto()});
        return error.WrongProto;
    }

    // 3. Decode address from metadata
    var host_buf: [64]u8 = undefined;
    const metadata = stream.getMetadata();
    const decode_result = Address.decode(metadata, &host_buf) catch |e| {
        std.debug.print("[handler] Decode address failed: {}\n", .{e});
        return e;
    };
    std.debug.print("[handler] Target: {s}:{}\n", .{ decode_result.addr.host, decode_result.addr.port });

    // 4. Connect to real target (echo server)
    const target_addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, decode_result.addr.port);
    const tcp_conn = try std.net.tcpConnectToAddress(target_addr);
    defer tcp_conn.close();

    // 5. Relay: stream ↔ tcp
    // stream → tcp
    const relay_thread = try std.Thread.spawn(.{}, struct {
        fn relay(s: *KcpStream, tcp: std.net.Stream) void {
            var buf: [4096]u8 = undefined;
            while (true) {
                const n = blockingRead(s, &buf);
                if (n == 0) return;
                _ = tcp.write(buf[0..n]) catch return;
            }
        }
    }.relay, .{ stream, tcp_conn });

    // tcp → stream
    var buf2: [4096]u8 = undefined;
    while (true) {
        const n = tcp_conn.read(&buf2) catch break;
        if (n == 0) break;
        stream.write(buf2[0..n]) catch break;
    }

    relay_thread.join();
    std.debug.print("[handler] Done!\n", .{});
}

fn runProxy(allocator: std.mem.Allocator, config: Config, udp: *UDP, peer_pk: *const Key) !void {
    _ = allocator;

    // 1. Connect to handler
    std.debug.print("[proxy] Connecting to handler...\n", .{});
    try udp.connect(peer_pk);
    std.debug.print("[proxy] Connected!\n", .{});
    std.time.sleep(200 * std.time.ns_per_ms);

    // 2. Open stream with proto=69 targeting echo server
    var addr_buf: [64]u8 = undefined;
    const addr = Address.ipv4("127.0.0.1", config.echo_port);
    const metadata = try addr.encode(&addr_buf);

    std.debug.print("[proxy] Opening stream proto=69 target=127.0.0.1:{}\n", .{config.echo_port});
    const stream = udp.openStream(peer_pk, @intFromEnum(Protocol.tcp_proxy), metadata) catch |e| {
        std.debug.print("[proxy] openStream failed: {}\n", .{e});
        return e;
    };
    defer stream.close();

    std.debug.print("[proxy] Stream opened id={}\n", .{stream.getId()});
    std.time.sleep(500 * std.time.ns_per_ms);

    // 3. Send test data
    const msg = config.@"test".message;
    std.debug.print("[proxy] Sending: \"{s}\"\n", .{msg});
    stream.write(msg) catch |e| {
        std.debug.print("[proxy] write failed: {}\n", .{e});
        return e;
    };

    // 4. Read echo
    var buf: [256]u8 = undefined;
    var total: usize = 0;
    const deadline = std.time.nanoTimestamp() + 5 * std.time.ns_per_s;
    while (total < msg.len) {
        if (std.time.nanoTimestamp() > deadline) {
            std.debug.print("[proxy] FAIL: timeout\n", .{});
            return error.Timeout;
        }
        const n = blockingRead(stream, buf[total..]);
        total += n;
    }

    const got = buf[0..total];
    if (!std.mem.eql(u8, got, msg)) {
        std.debug.print("[proxy] FAIL: echo mismatch: got \"{s}\", want \"{s}\"\n", .{ got, msg });
        return error.EchoMismatch;
    }

    std.debug.print("[proxy] Echo verified: \"{s}\"\n", .{got});
    std.debug.print("[proxy] PASS!\n", .{});
}

/// Blocking read from KCP stream (polls with 1ms sleep).
fn blockingRead(stream: *KcpStream, buf: []u8) usize {
    while (true) {
        if (stream.read(buf)) |data| {
            if (data.len > 0) return data.len;
        } else |_| {
            return 0;
        }
        std.time.sleep(1 * std.time.ns_per_ms);
    }
}
