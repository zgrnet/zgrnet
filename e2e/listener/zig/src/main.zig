//! Node.Listen interop test binary (Zig).
//!
//! Tests proto-specific stream routing across languages.
//! The "opener" sends streams with two different protos (128=chat, 200=file).
//! The "accepter" uses listen(128) for chat and acceptStream for file.

const std = @import("std");
const noise = @import("noise");

const Key = noise.Key;
const KeyPair = noise.KeyPair;
const NodeType = noise.NodeType;
const Endpoint = noise.Endpoint;

const proto_chat: u8 = 128;
const proto_file: u8 = 200;

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

    const name = my_name orelse return error.InvalidArgs;
    const cfg_path = config_path orelse return error.InvalidArgs;

    const config_data = std.fs.cwd().readFileAlloc(allocator, cfg_path, 1024 * 1024) catch |e| {
        std.debug.print("read config: {}\n", .{e});
        return e;
    };
    defer allocator.free(config_data);

    const parsed = std.json.parseFromSlice(Config, allocator, config_data, .{}) catch |e| {
        std.debug.print("parse config: {}\n", .{e});
        return e;
    };
    defer parsed.deinit();
    const config = parsed.value;

    var my_host: ?HostInfo = null;
    var peer_host: ?HostInfo = null;
    for (config.hosts) |h| {
        if (std.mem.eql(u8, h.name, name)) {
            my_host = h;
        } else {
            peer_host = h;
        }
    }
    const host = my_host orelse return error.HostNotFound;
    const peer = peer_host orelse return error.NoPeerFound;

    var priv_key: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&priv_key, host.private_key) catch return error.InvalidKey;
    const key_pair = KeyPair.fromPrivate(Key.fromBytes(priv_key));

    var peer_priv: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&peer_priv, peer.private_key) catch return error.InvalidKey;
    const peer_kp = KeyPair.fromPrivate(Key.fromBytes(peer_priv));

    std.debug.print("[{s}] role: {s}\n", .{ name, host.role });

    var node = NodeType.init(.{
        .key = &key_pair,
        .listen_port = host.port,
        .allow_unknown = true,
        .allocator = allocator,
    }) catch |e| {
        std.debug.print("[{s}] create node: {}\n", .{ name, e });
        return e;
    };
    defer node.deinit();

    node.addPeer(.{
        .public_key = peer_kp.public,
        .endpoint = Endpoint.init(.{ 127, 0, 0, 1 }, peer.port),
    }) catch |e| {
        std.debug.print("[{s}] add peer: {}\n", .{ name, e });
        return e;
    };

    if (std.mem.eql(u8, host.role, "opener")) {
        std.Thread.sleep(2 * std.time.ns_per_s);
        try runOpener(node, &peer_kp.public, config.@"test");
    } else {
        try runAccepter(node, config.@"test", name);
    }

    std.debug.print("[{s}] test completed successfully!\n", .{name});
    std.process.exit(0);
}

fn runOpener(node: *NodeType, peer_pk: *const Key, test_cfg: TestConfig) !void {
    std.debug.print("[opener] connecting...\n", .{});
    node.connect(peer_pk) catch |e| {
        std.debug.print("[opener] connect: {}\n", .{e});
        return e;
    };
    std.Thread.sleep(100 * std.time.ns_per_ms);

    // Open chat stream (proto=128).
    var chat_stream = node.openStream(peer_pk, proto_chat, "chat-meta") catch |e| {
        std.debug.print("[opener] open chat stream: {}\n", .{e});
        return e;
    };

    // Open file stream (proto=200).
    var file_stream = node.openStream(peer_pk, proto_file, "file-meta") catch |e| {
        std.debug.print("[opener] open file stream: {}\n", .{e});
        return e;
    };

    // Echo test on chat.
    _ = chat_stream.write(test_cfg.echo_message) catch return error.WriteFailed;
    chat_stream.stream.flush() catch {};
    std.debug.print("[opener] sent chat: {s}\n", .{test_cfg.echo_message});

    var buf: [1024]u8 = undefined;
    var nr = readTimeout(&chat_stream, &buf, 10_000);
    if (nr == 0) return error.ReadTimeout;

    var expected_buf: [256]u8 = undefined;
    const expected = std.fmt.bufPrint(&expected_buf, "chat-echo: {s}", .{test_cfg.echo_message}) catch "?";
    if (!std.mem.eql(u8, buf[0..nr], expected)) {
        std.debug.print("[opener] FAIL: chat got '{s}', want '{s}'\n", .{ buf[0..nr], expected });
        return error.EchoMismatch;
    }
    std.debug.print("[opener] PASS: chat echo verified\n", .{});

    // Echo test on file.
    _ = file_stream.write("file-data") catch return error.WriteFailed;
    file_stream.stream.flush() catch {};
    std.debug.print("[opener] sent file: file-data\n", .{});

    nr = readTimeout(&file_stream, &buf, 10_000);
    if (nr == 0) return error.ReadTimeout;
    if (!std.mem.eql(u8, buf[0..nr], "file-echo: file-data")) {
        std.debug.print("[opener] FAIL: file got '{s}'\n", .{buf[0..nr]});
        return error.EchoMismatch;
    }
    std.debug.print("[opener] PASS: file echo verified\n", .{});

    std.Thread.sleep(500 * std.time.ns_per_ms);
    chat_stream.close();
    file_stream.close();
}

fn runAccepter(node: *NodeType, test_cfg: TestConfig, name: []const u8) !void {
    _ = name;

    // Register listener for proto=128 (chat).
    const chat_ln = node.listen(proto_chat) catch |e| {
        std.debug.print("[accepter] listen(chat): {}\n", .{e});
        return e;
    };
    std.debug.print("[accepter] listening on proto={} (chat)\n", .{proto_chat});

    // Spawn thread for chat accept.
    const chat_thread = std.Thread.spawn(.{}, acceptChat, .{ chat_ln, test_cfg }) catch return error.SpawnFailed;

    // Accept file via acceptStream (no listener for proto=200).
    const file_ns = node.acceptStream() orelse return error.AcceptFailed;
    var file_stream = file_ns;
    if (file_stream.proto() != proto_file) {
        std.debug.print("[accepter] FAIL: file proto={}, want {}\n", .{ file_stream.proto(), proto_file });
        return error.ProtoMismatch;
    }
    std.debug.print("[accepter] accepted file stream (proto={})\n", .{file_stream.proto()});

    var buf: [1024]u8 = undefined;
    const nr = readTimeout(&file_stream, &buf, 10_000);
    if (nr == 0) return error.ReadTimeout;
    std.debug.print("[accepter] file received: {s}\n", .{buf[0..nr]});

    var reply_buf: [256]u8 = undefined;
    const reply = std.fmt.bufPrint(&reply_buf, "file-echo: {s}", .{buf[0..nr]}) catch "?";
    _ = file_stream.write(reply) catch return error.WriteFailed;
    file_stream.stream.flush() catch {};
    std.debug.print("[accepter] file sent: {s}\n", .{reply});

    std.Thread.sleep(200 * std.time.ns_per_ms);
    file_stream.close();

    chat_thread.join();
    std.Thread.sleep(500 * std.time.ns_per_ms);
}

fn acceptChat(chat_ln: *NodeType.StreamListener, test_cfg: TestConfig) void {
    _ = test_cfg;
    const ns = chat_ln.accept() orelse {
        std.debug.print("[accepter] FAIL: chat accept returned null\n", .{});
        return;
    };
    var stream = ns;
    if (stream.proto() != proto_chat) {
        std.debug.print("[accepter] FAIL: chat proto={}\n", .{stream.proto()});
        return;
    }
    std.debug.print("[accepter] accepted chat stream (proto={})\n", .{stream.proto()});

    var buf: [1024]u8 = undefined;
    const nr = readTimeout(&stream, &buf, 10_000);
    if (nr == 0) {
        std.debug.print("[accepter] FAIL: chat read timeout\n", .{});
        return;
    }
    std.debug.print("[accepter] chat received: {s}\n", .{buf[0..nr]});

    var reply_buf: [256]u8 = undefined;
    const reply = std.fmt.bufPrint(&reply_buf, "chat-echo: {s}", .{buf[0..nr]}) catch "?";
    _ = stream.write(reply) catch return;
    stream.stream.flush() catch {};
    std.debug.print("[accepter] chat sent: {s}\n", .{reply});

    std.Thread.sleep(200 * std.time.ns_per_ms);
    stream.close();
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
