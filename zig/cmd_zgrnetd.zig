//! zgrnetd - the zgrnet daemon (Zig implementation).
//!
//! Loads a JSON config file and starts:
//!   - TUN device with a CGNAT IP
//!   - Noise Protocol encrypted UDP transport
//!   - Host (bridges TUN <-> UDP, routes IP packets to/from peers)
//!   - Magic DNS server (resolves *.zigor.net -> TUN IPs)
//!   - RESTful API server (HTTP on TUN_IP:80)
//!   - Signal handling for graceful shutdown
//!
//! Usage:
//!   zgrnetd -c /path/to/config.json

const std = @import("std");
const posix = std.posix;
const mem = std.mem;
const fmt = std.fmt;
const noise = @import("noise");
const tun_mod = @import("tun");
const config_mod = noise.json_config;

const Key = noise.Key;
const KeyPair = noise.KeyPair;
const UDPType = noise.UDP;
const HostType = noise.Host(UDPType, noise.StdRt);
const TunDevice = noise.TunDevice;
const Endpoint = noise.Endpoint;
const IPAllocator = noise.IPAllocator;

const print = std.debug.print;
const Allocator = std.mem.Allocator;

// ============================================================================
// RealTun wrapper: adapts tun.Tun to TunDevice interface
// ============================================================================

const RealTun = struct {
    dev: *tun_mod.Tun,

    fn read(ptr: *anyopaque, buf: []u8) TunDevice.ReadError!usize {
        const self: *RealTun = @ptrCast(@alignCast(ptr));
        return self.dev.read(buf) catch TunDevice.ReadError.IoError;
    }

    fn write(ptr: *anyopaque, data: []const u8) TunDevice.WriteError!usize {
        const self: *RealTun = @ptrCast(@alignCast(ptr));
        return self.dev.write(data) catch TunDevice.WriteError.IoError;
    }

    fn close(ptr: *anyopaque) void {
        const self: *RealTun = @ptrCast(@alignCast(ptr));
        self.dev.close();
    }

    fn toTunDevice(self: *RealTun) TunDevice {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    const vtable = TunDevice.VTable{
        .read = RealTun.read,
        .write = RealTun.write,
        .close = RealTun.close,
    };
};

// ============================================================================
// Main
// ============================================================================

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Parse -c flag
    const config_path = parseArgs() orelse {
        print("Usage: zgrnetd -c <config.json>\n", .{});
        std.process.exit(1);
    };

    print("[zgrnetd] loading config: {s}\n", .{config_path});

    // 1. Load and validate config
    const parsed = config_mod.load(allocator, config_path) catch |err| {
        print("[zgrnetd] fatal: load config: {}\n", .{err});
        std.process.exit(1);
    };
    defer parsed.deinit();
    const cfg = &parsed.value;

    config_mod.validate(cfg) catch |err| {
        print("[zgrnetd] fatal: validate config: {}\n", .{err});
        std.process.exit(1);
    };

    // 2. Parse TUN IP
    const tun_ip = config_mod.parseIpv4(cfg.net.tun_ipv4) orelse {
        print("[zgrnetd] fatal: invalid tun_ipv4: {s}\n", .{cfg.net.tun_ipv4});
        std.process.exit(1);
    };

    // 3. Load or generate private key
    const key_pair = loadOrGenerateKey(allocator, cfg.net.private_key) catch |err| {
        print("[zgrnetd] fatal: private key: {}\n", .{err});
        std.process.exit(1);
    };
    print("[zgrnetd] public key: {x}\n", .{key_pair.public.data[0..8].*});

    // 4. Create TUN device
    print("[zgrnetd] creating TUN device...\n", .{});
    var tun_dev = tun_mod.Tun.create(null) catch |err| {
        print("[zgrnetd] fatal: create TUN: {}\n", .{err});
        std.process.exit(1);
    };

    tun_dev.setMtu(@as(u32, cfg.net.tun_mtu)) catch |err| {
        print("[zgrnetd] fatal: set MTU: {}\n", .{err});
        std.process.exit(1);
    };
    // /10 netmask = 255.192.0.0 for CGNAT range
    tun_dev.setIPv4(tun_ip, .{ 255, 192, 0, 0 }) catch |err| {
        print("[zgrnetd] fatal: set IPv4: {}\n", .{err});
        std.process.exit(1);
    };
    tun_dev.setUp() catch |err| {
        print("[zgrnetd] fatal: up TUN: {}\n", .{err});
        std.process.exit(1);
    };
    print("[zgrnetd] TUN {s}: {d}.{d}.{d}.{d}/10, MTU {d}\n", .{
        tun_dev.getName(), tun_ip[0], tun_ip[1], tun_ip[2], tun_ip[3], cfg.net.tun_mtu,
    });

    // 5-6. Create Host
    var real_tun = try allocator.create(RealTun);
    real_tun.* = .{ .dev = &tun_dev };

    const host = HostType.init(allocator, .{
        .private_key = &key_pair,
        .tun_ipv4 = tun_ip,
        .mtu = @as(usize, cfg.net.tun_mtu),
        .listen_port = cfg.net.listen_port,
    }, real_tun.toTunDevice()) catch {
        print("[zgrnetd] fatal: create host\n", .{});
        std.process.exit(1);
    };

    print("[zgrnetd] host listening on port {d}\n", .{host.getLocalPort()});

    // 7. Add peers from config
    var peers_iter = cfg.peers.map.iterator();
    while (peers_iter.next()) |entry| {
        const domain = entry.key_ptr.*;
        const peer_cfg = entry.value_ptr.*;

        var pk: [32]u8 = undefined;
        if (!config_mod.pubkeyFromDomain(domain, &pk)) {
            print("[zgrnetd] warning: invalid peer domain: {s}\n", .{domain});
            continue;
        }

        // Parse first direct endpoint if available
        if (peer_cfg.direct.len > 0) {
            const ep_str = peer_cfg.direct[0];
            // Parse "host:port" into Endpoint
            if (Endpoint.parse(ep_str)) |ep| {
                host.addPeer(Key{ .data = pk }, ep) catch {
                    print("[zgrnetd] warning: add peer failed: {s}\n", .{peer_cfg.alias});
                    continue;
                };
            } else {
                host.addPeer(Key{ .data = pk }, null) catch continue;
            }
        } else {
            host.addPeer(Key{ .data = pk }, null) catch continue;
        }
        print("[zgrnetd] peer added: {s}\n", .{peer_cfg.alias});
    }

    // 8. Start DNS server
    const dns_server = noise.dns_mod.server.Server.init(allocator, .{
        .tun_ipv4 = tun_ip,
    });

    _ = std.Thread.spawn(.{}, dnsLoop, .{ &dns_server, tun_ip }) catch |err| {
        print("[zgrnetd] warning: dns thread: {}\n", .{err});
    };

    // 9. Start Host forwarding
    host.run();

    // 10. Start API server
    var api_ctx = ApiContext{
        .allocator = allocator,
        .host = host,
        .config_path = config_path,
        .tun_ipv4 = cfg.net.tun_ipv4,
        .public_key = &key_pair.public,
    };
    _ = std.Thread.spawn(.{}, apiServe, .{ &api_ctx, tun_ip }) catch |err| {
        print("[zgrnetd] warning: api thread: {}\n", .{err});
    };

    print("[zgrnetd] running\n", .{});
    print("[zgrnetd]   TUN:   {s} ({d}.{d}.{d}.{d}/10)\n", .{
        tun_dev.getName(), tun_ip[0], tun_ip[1], tun_ip[2], tun_ip[3],
    });
    print("[zgrnetd]   UDP:   :{d}\n", .{host.getLocalPort()});
    print("[zgrnetd]   API:   {d}.{d}.{d}.{d}:80\n", .{ tun_ip[0], tun_ip[1], tun_ip[2], tun_ip[3] });
    print("[zgrnetd]   Peers: {d}\n", .{cfg.peers.map.count()});

    // 11. Wait for signal
    setupSignalHandler();
    waitForSignal();

    print("[zgrnetd] shutting down...\n", .{});
    host.close();
    tun_dev.close();
}

// ============================================================================
// API server — direct concrete types, no generics
// ============================================================================

const ApiContext = struct {
    allocator: Allocator,
    host: *HostType,
    config_path: []const u8,
    tun_ipv4: []const u8,
    public_key: *const Key,
};

fn apiServe(ctx: *ApiContext, tun_ip: [4]u8) void {
    const sa = std.net.Address.initIp4(tun_ip, 80);
    const sock = posix.socket(posix.AF.INET, posix.SOCK.STREAM, 0) catch return;

    const one: c_int = 1;
    posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.REUSEADDR, mem.asBytes(&one)) catch {};
    posix.bind(sock, &sa.any, sa.getOsSockLen()) catch return;
    posix.listen(sock, 128) catch return;

    print("[zgrnetd] api listening on {d}.{d}.{d}.{d}:80\n", .{ tun_ip[0], tun_ip[1], tun_ip[2], tun_ip[3] });

    while (true) {
        var client_addr: posix.sockaddr.storage = undefined;
        var client_len: posix.socklen_t = @sizeOf(posix.sockaddr.storage);
        const client = posix.accept(sock, @ptrCast(&client_addr), &client_len, 0) catch continue;
        _ = std.Thread.spawn(.{}, apiHandleConn, .{ ctx, client }) catch {
            posix.close(client);
            continue;
        };
    }
}

fn apiHandleConn(ctx: *ApiContext, client: posix.socket_t) void {
    defer posix.close(client);

    const tv = posix.timeval{ .sec = 10, .usec = 0 };
    posix.setsockopt(client, posix.SOL.SOCKET, posix.SO.RCVTIMEO, mem.asBytes(&tv)) catch {};

    var buf: [8192]u8 = undefined;
    const n = posix.read(client, &buf) catch return;
    if (n == 0) return;

    const req = buf[0..n];
    const first_line_end = mem.indexOf(u8, req, "\r\n") orelse return;
    var parts = mem.splitScalar(u8, req[0..first_line_end], ' ');
    const method = parts.next() orelse return;
    const full_path = parts.next() orelse return;

    const q_idx = mem.indexOfScalar(u8, full_path, '?');
    const path = if (q_idx) |qi| full_path[0..qi] else full_path;
    const query = if (q_idx) |qi| full_path[qi + 1 ..] else "";

    const body_start = mem.indexOf(u8, req, "\r\n\r\n");
    const body = if (body_start) |bs| req[bs + 4 ..] else "";

    const resp = apiRoute(ctx, method, path, query, body);
    defer ctx.allocator.free(resp);
    _ = writeAllFd(client, resp) catch {};
}

fn apiRoute(ctx: *ApiContext, method: []const u8, path: []const u8, query: []const u8, body: []const u8) []const u8 {
    const a = ctx.allocator;

    // GET /api/whoami
    if (eql(method, "GET") and eql(path, "/api/whoami")) {
        var hex: [64]u8 = undefined;
        _ = fmt.bufPrint(&hex, "{}", .{std.fmt.fmtSliceHexLower(&ctx.public_key.data)}) catch return httpResp(a, 500, "");
        return httpResp(a, 200, fmt.allocPrint(a,
            "{{\"pubkey\":\"{s}\",\"tun_ip\":\"{s}\"}}", .{ &hex, ctx.tun_ipv4 }) catch return httpResp(a, 500, ""));
    }

    // GET /api/config/net
    if (eql(method, "GET") and eql(path, "/api/config/net")) {
        return jsonSection(a, ctx.config_path, "net");
    }

    // GET /api/peers
    if (eql(method, "GET") and eql(path, "/api/peers")) {
        return jsonSection(a, ctx.config_path, "peers");
    }

    // POST /api/peers — add peer
    if (eql(method, "POST") and eql(path, "/api/peers")) {
        const pk_hex = jsonStr(body, "pubkey") orelse
            return httpResp(a, 400, "{\"error\":\"pubkey is required\"}");
        var pk_bytes: [32]u8 = undefined;
        _ = fmt.hexToBytes(&pk_bytes, pk_hex) catch
            return httpResp(a, 400, "{\"error\":\"invalid pubkey\"}");
        const ep_str = jsonStr(body, "endpoint") orelse "";
        const ep = if (ep_str.len > 0) Endpoint.parse(ep_str) else null;
        ctx.host.addPeer(Key{ .data = pk_bytes }, ep) catch
            return httpResp(a, 500, "{\"error\":\"add peer failed\"}");
        return httpResp(a, 201, body);
    }

    // DELETE /api/peers/:pubkey
    if (eql(method, "DELETE") and mem.startsWith(u8, path, "/api/peers/")) {
        const hex_pk = path["/api/peers/".len..];
        var pk_bytes: [32]u8 = undefined;
        _ = fmt.hexToBytes(&pk_bytes, hex_pk) catch
            return httpResp(a, 400, "{\"error\":\"invalid pubkey\"}");
        ctx.host.removePeer(Key{ .data = pk_bytes });
        return httpResp(a, 204, "");
    }

    // GET /api/lans
    if (eql(method, "GET") and eql(path, "/api/lans")) {
        return jsonSection(a, ctx.config_path, "lans");
    }

    // GET /api/policy
    if (eql(method, "GET") and eql(path, "/api/policy")) {
        return jsonSection(a, ctx.config_path, "inbound_policy");
    }

    // GET /api/routes
    if (eql(method, "GET") and eql(path, "/api/routes")) {
        return jsonSection(a, ctx.config_path, "route");
    }

    // GET /internal/identity?ip=x
    if (eql(method, "GET") and eql(path, "/internal/identity")) {
        const ip_str = queryParam(query, "ip") orelse
            return httpResp(a, 400, "{\"error\":\"ip parameter is required\"}");
        var ip: [4]u8 = undefined;
        parseIp4(ip_str, &ip) orelse
            return httpResp(a, 400, "{\"error\":\"invalid IP\"}");
        const pk = ctx.host.ip_alloc.lookupByIp(ip) orelse
            return httpResp(a, 404, "{\"error\":\"no peer for IP\"}");
        var hex: [64]u8 = undefined;
        _ = fmt.bufPrint(&hex, "{}", .{std.fmt.fmtSliceHexLower(&pk.data)}) catch return httpResp(a, 500, "");
        return httpResp(a, 200, fmt.allocPrint(a,
            "{{\"pubkey\":\"{s}\",\"ip\":\"{s}\"}}", .{ &hex, ip_str }) catch return httpResp(a, 500, ""));
    }

    // POST /api/config/reload
    if (eql(method, "POST") and eql(path, "/api/config/reload")) {
        return httpResp(a, 200, "{\"status\":\"no changes\"}");
    }

    return httpResp(a, 404, "{\"error\":\"not found\"}");
}

// ── API helpers ─────────────────────────────────────────────────────────────

fn httpResp(a: Allocator, status: u16, body: []const u8) []const u8 {
    const status_text: []const u8 = switch (status) {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        400 => "Bad Request",
        404 => "Not Found",
        500 => "Internal Server Error",
        else => "Unknown",
    };
    return fmt.allocPrint(a,
        "HTTP/1.1 {d} {s}\r\nContent-Type: application/json\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n{s}", .{
        status, status_text, body.len, body,
    }) catch "";
}

fn jsonSection(a: Allocator, config_path: []const u8, key: []const u8) []const u8 {
    const data = std.fs.cwd().readFileAlloc(a, config_path, 10 * 1024 * 1024) catch
        return httpResp(a, 500, "{\"error\":\"read config\"}");
    defer a.free(data);

    var parsed = std.json.parseFromSlice(std.json.Value, a, data, .{}) catch
        return httpResp(a, 500, "{\"error\":\"parse config\"}");
    defer parsed.deinit();

    const val = parsed.value.object.get(key) orelse return httpResp(a, 200, "{}");

    var buf = std.ArrayList(u8).init(a);
    std.json.stringify(val, .{}, buf.writer()) catch return httpResp(a, 500, "");
    const result = buf.toOwnedSlice() catch return httpResp(a, 500, "");
    return httpResp(a, 200, result);
}

fn jsonStr(data: []const u8, key: []const u8) ?[]const u8 {
    var i: usize = 0;
    while (i + key.len + 4 < data.len) : (i += 1) {
        if (data[i] == '"' and i + 1 + key.len < data.len and
            mem.eql(u8, data[i + 1 .. i + 1 + key.len], key) and
            data[i + 1 + key.len] == '"')
        {
            var j = i + 1 + key.len + 1;
            while (j < data.len and (data[j] == ':' or data[j] == ' ')) : (j += 1) {}
            if (j < data.len and data[j] == '"') {
                j += 1;
                const start = j;
                while (j < data.len and data[j] != '"') : (j += 1) {}
                return data[start..j];
            }
        }
    }
    return null;
}

fn queryParam(query: []const u8, key: []const u8) ?[]const u8 {
    var iter = mem.splitScalar(u8, query, '&');
    while (iter.next()) |pair| {
        if (mem.indexOfScalar(u8, pair, '=')) |eq| {
            if (mem.eql(u8, pair[0..eq], key)) return pair[eq + 1 ..];
        }
    }
    return null;
}

fn parseIp4(s: []const u8, out: *[4]u8) ?void {
    var p = mem.splitScalar(u8, s, '.');
    var i: usize = 0;
    while (p.next()) |part| {
        if (i >= 4) return null;
        out[i] = fmt.parseInt(u8, part, 10) catch return null;
        i += 1;
    }
    if (i != 4) return null;
}

fn eql(a: []const u8, b: []const u8) bool {
    return mem.eql(u8, a, b);
}

fn writeAllFd(fd: posix.socket_t, data: []const u8) !void {
    var written: usize = 0;
    while (written < data.len) {
        const n = posix.write(fd, data[written..]) catch |e| return e;
        written += n;
    }
}

// ============================================================================
// DNS loop
// ============================================================================

fn dnsLoop(server: *const noise.dns_mod.server.Server, tun_ip: [4]u8) void {
    const addr = posix.sockaddr.in{
        .family = posix.AF.INET,
        .port = mem.nativeToBig(u16, 53),
        .addr = mem.nativeToBig(u32, @as(u32, tun_ip[0]) << 24 | @as(u32, tun_ip[1]) << 16 | @as(u32, tun_ip[2]) << 8 | @as(u32, tun_ip[3])),
    };

    const sock = posix.socket(posix.AF.INET, posix.SOCK.DGRAM, 0) catch {
        print("[zgrnetd] dns: socket error\n", .{});
        return;
    };
    defer posix.close(sock);

    posix.bind(sock, @ptrCast(&addr), @sizeOf(posix.sockaddr.in)) catch {
        print("[zgrnetd] dns: bind error on port 53\n", .{});
        return;
    };

    print("[zgrnetd] dns listening on {d}.{d}.{d}.{d}:53\n", .{ tun_ip[0], tun_ip[1], tun_ip[2], tun_ip[3] });

    var query_buf: [4096]u8 = undefined;
    var resp_buf: [4096]u8 = undefined;
    var from_addr: posix.sockaddr.storage = undefined;
    var from_len: posix.socklen_t = @sizeOf(posix.sockaddr.storage);

    while (true) {
        from_len = @sizeOf(posix.sockaddr.storage);
        const n = posix.recvfrom(sock, &query_buf, 0, @ptrCast(&from_addr), &from_len) catch continue;
        if (n == 0) continue;

        const resp = server.handleQuery(query_buf[0..n], &resp_buf) catch continue;
        _ = posix.sendto(sock, resp, 0, @ptrCast(&from_addr), from_len) catch continue;
    }
}

// ============================================================================
// Signal handling
// ============================================================================

fn waitForSignal() void {
    while (!signal_received.load(.seq_cst)) {
        std.Thread.sleep(100 * std.time.ns_per_ms);
    }
    print("[zgrnetd] received signal, stopping\n", .{});
}

var signal_received = std.atomic.Value(bool).init(false);

fn setupSignalHandler() void {
    const handler = struct {
        fn h(_: c_int) callconv(.c) void {
            signal_received.store(true, .seq_cst);
        }
    }.h;

    const act = std.posix.Sigaction{
        .handler = .{ .handler = handler },
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    };
    std.posix.sigaction(std.posix.SIG.INT, &act, null);
    std.posix.sigaction(std.posix.SIG.TERM, &act, null);
}

// ============================================================================
// Key management
// ============================================================================

fn parseArgs() ?[]const u8 {
    var args = std.process.args();
    _ = args.skip(); // program name
    while (args.next()) |arg| {
        if (mem.eql(u8, arg, "-c")) {
            return args.next();
        }
    }
    return null;
}

// ============================================================================
// Tests
// ============================================================================

test "httpResp formats correctly" {
    const a = std.testing.allocator;
    const resp = httpResp(a, 200, "OK", "{\"status\":\"ok\"}");
    defer a.free(resp);
    try std.testing.expect(mem.startsWith(u8, resp, "HTTP/1.1 200 OK\r\n"));
    try std.testing.expect(mem.indexOf(u8, resp, "Content-Type: application/json") != null);
    try std.testing.expect(mem.indexOf(u8, resp, "{\"status\":\"ok\"}") != null);
}

test "httpResp 204 empty body" {
    const a = std.testing.allocator;
    const resp = httpResp(a, 204, "No Content", "");
    defer a.free(resp);
    try std.testing.expect(mem.startsWith(u8, resp, "HTTP/1.1 204 No Content\r\n"));
    try std.testing.expect(mem.indexOf(u8, resp, "Content-Length: 0") != null);
}

test "jsonStr extracts value" {
    const data = "{\"pubkey\":\"aabbcc\",\"alias\":\"test\"}";
    const pk = jsonStr(data, "pubkey");
    try std.testing.expect(pk != null);
    try std.testing.expectEqualStrings("aabbcc", pk.?);

    const alias = jsonStr(data, "alias");
    try std.testing.expect(alias != null);
    try std.testing.expectEqualStrings("test", alias.?);
}

test "jsonStr returns null for missing key" {
    const data = "{\"pubkey\":\"aabbcc\"}";
    try std.testing.expect(jsonStr(data, "missing") == null);
}

test "jsonStr returns null for empty data" {
    try std.testing.expect(jsonStr("", "key") == null);
    try std.testing.expect(jsonStr("{}", "key") == null);
}

test "queryParam extracts value" {
    try std.testing.expectEqualStrings("100.64.0.2", queryParam("ip=100.64.0.2", "ip").?);
    try std.testing.expectEqualStrings("100.64.0.2", queryParam("foo=bar&ip=100.64.0.2", "ip").?);
    try std.testing.expectEqualStrings("bar", queryParam("ip=100.64.0.2&foo=bar", "foo").?);
}

test "queryParam returns null for missing key" {
    try std.testing.expect(queryParam("foo=bar", "ip") == null);
    try std.testing.expect(queryParam("", "ip") == null);
}

test "parseIp4 valid" {
    var ip: [4]u8 = undefined;
    parseIp4("100.64.0.1", &ip) orelse unreachable;
    try std.testing.expectEqual([4]u8{ 100, 64, 0, 1 }, ip);
}

test "parseIp4 various addresses" {
    var ip: [4]u8 = undefined;
    parseIp4("0.0.0.0", &ip) orelse unreachable;
    try std.testing.expectEqual([4]u8{ 0, 0, 0, 0 }, ip);

    parseIp4("255.255.255.255", &ip) orelse unreachable;
    try std.testing.expectEqual([4]u8{ 255, 255, 255, 255 }, ip);
}

test "parseIp4 invalid" {
    var ip: [4]u8 = undefined;
    try std.testing.expect(parseIp4("not-an-ip", &ip) == null);
    try std.testing.expect(parseIp4("1.2.3", &ip) == null);
    try std.testing.expect(parseIp4("1.2.3.4.5", &ip) == null);
    try std.testing.expect(parseIp4("256.0.0.1", &ip) == null);
    try std.testing.expect(parseIp4("", &ip) == null);
}

test "eql helper" {
    try std.testing.expect(eql("GET", "GET"));
    try std.testing.expect(!eql("GET", "POST"));
    try std.testing.expect(!eql("GET", "GE"));
    try std.testing.expect(eql("", ""));
}

fn loadOrGenerateKey(_: std.mem.Allocator, path: []const u8) !KeyPair {
    // Try to read existing key
    if (std.fs.cwd().openFile(path, .{})) |file| {
        defer file.close();
        var buf: [128]u8 = undefined;
        const n = file.readAll(&buf) catch return error.ReadError;
        const hex_str = mem.trim(u8, buf[0..n], &[_]u8{ ' ', '\t', '\n', '\r' });
        if (hex_str.len != 64) return error.InvalidKeyFile;
        var key_bytes: [32]u8 = undefined;
        _ = std.fmt.hexToBytes(&key_bytes, hex_str) catch return error.InvalidKeyHex;
        return KeyPair.fromPrivate(Key{ .data = key_bytes });
    } else |_| {
        // Generate new key
        print("[zgrnetd] generating new private key: {s}\n", .{path});
        const kp = KeyPair.generate();

        // Write hex-encoded private key
        const file = std.fs.cwd().createFile(path, .{ .mode = 0o600 }) catch return error.WriteError;
        defer file.close();
        var hex_buf: [64]u8 = undefined;
        const hex_chars = "0123456789abcdef";
        for (kp.private.data, 0..) |b, i| {
            hex_buf[i * 2] = hex_chars[b >> 4];
            hex_buf[i * 2 + 1] = hex_chars[b & 0x0f];
        }
        file.writeAll(&hex_buf) catch return error.WriteError;
        file.writeAll("\n") catch return error.WriteError;

        return kp;
    }
}
