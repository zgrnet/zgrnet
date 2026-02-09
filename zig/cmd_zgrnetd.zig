//! zgrnetd - the zgrnet daemon (Zig implementation).
//!
//! Loads a JSON config file and starts:
//!   - TUN device with a CGNAT IP
//!   - Noise Protocol encrypted UDP transport
//!   - Host (bridges TUN <-> UDP, routes IP packets to/from peers)
//!   - Magic DNS server (resolves *.zigor.net -> TUN IPs)
//!   - Signal handling for graceful shutdown
//!
//! Usage:
//!   zgrnetd -c /path/to/config.json

const std = @import("std");
const posix = std.posix;
const mem = std.mem;
const noise = @import("noise");
const tun_mod = @import("tun");
const config_mod = noise.config;

const Key = noise.Key;
const KeyPair = noise.KeyPair;
const UDPType = noise.UDP(noise.KqueueIO);
const HostType = noise.Host(UDPType);
const TunDevice = noise.TunDevice;

const print = std.debug.print;

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
            // Parse "host:port" into sockaddr
            if (parseEndpoint(ep_str)) |ep| {
                host.addPeer(
                    Key{ .data = pk },
                    @as(*posix.sockaddr, @ptrCast(@constCast(&ep.addr))).*,
                    ep.len,
                ) catch {
                    print("[zgrnetd] warning: add peer failed: {s}\n", .{peer_cfg.alias});
                    continue;
                };
            } else {
                host.addPeer(Key{ .data = pk }, null, 0) catch continue;
            }
        } else {
            host.addPeer(Key{ .data = pk }, null, 0) catch continue;
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

    print("[zgrnetd] running\n", .{});
    print("[zgrnetd]   TUN:   {s} ({d}.{d}.{d}.{d}/10)\n", .{
        tun_dev.getName(), tun_ip[0], tun_ip[1], tun_ip[2], tun_ip[3],
    });
    print("[zgrnetd]   UDP:   :{d}\n", .{host.getLocalPort()});
    print("[zgrnetd]   Peers: {d}\n", .{cfg.peers.map.count()});

    // 10. Wait for signal
    setupSignalHandler();
    waitForSignal();

    print("[zgrnetd] shutting down...\n", .{});
    host.close();
    tun_dev.close();
}

// ============================================================================
// Helpers
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

fn dnsLoop(server: *const noise.dns_mod.server.Server, tun_ip: [4]u8) void {
    // Bind UDP socket
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

fn waitForSignal() void {
    // Simple approach: sleep and poll a signal flag
    // (Zig's std.posix doesn't expose sigwait on all platforms)
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

const Endpoint = struct {
    addr: posix.sockaddr.in,
    len: posix.socklen_t,
};

fn parseEndpoint(s: []const u8) ?Endpoint {
    // Find last ':' for port separator
    var colon_pos: ?usize = null;
    for (s, 0..) |c, i| {
        if (c == ':') colon_pos = i;
    }
    const cp = colon_pos orelse return null;

    const host_part = s[0..cp];
    const port_str = s[cp + 1 ..];

    const port = std.fmt.parseInt(u16, port_str, 10) catch return null;
    const ip = config_mod.parseIpv4(host_part) orelse return null;

    return .{
        .addr = .{
            .family = posix.AF.INET,
            .port = mem.nativeToBig(u16, port),
            .addr = mem.nativeToBig(u32, @as(u32, ip[0]) << 24 | @as(u32, ip[1]) << 16 | @as(u32, ip[2]) << 8 | @as(u32, ip[3])),
        },
        .len = @sizeOf(posix.sockaddr.in),
    };
}

fn loadOrGenerateKey(_: std.mem.Allocator, path: []const u8) !KeyPair {

    // Try to read existing key
    if (std.fs.cwd().openFile(path, .{})) |file| {
        defer file.close();
        var buf: [128]u8 = undefined;
        const n = file.readAll(&buf) catch return error.ReadError;
        // Trim whitespace
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
