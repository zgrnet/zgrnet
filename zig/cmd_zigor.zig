//! zigor — unified zgrnet management tool (Zig implementation).
//!
//! Replaces both zgrnet (CLI) and zgrnetd (daemon) with a single binary.
//!
//! Context directory: ~/.config/zigor/ (or $ZIGOR_CONFIG_DIR)
//! Config format: JSON (matching Zig config parser)
//!
//! Usage:
//!   zigor ctx list|create|delete|show|use
//!   zigor key generate|show
//!   zigor config show|path|net|reload
//!   zigor [--ctx <name>] host up|down|status|peers
//!   zigor peers list|add|get|remove
//!   zigor lans list|join|leave
//!   zigor policy show|add-rule|remove-rule
//!   zigor routes list|add|remove

const std = @import("std");
const posix = std.posix;
const mem = std.mem;
const fs = std.fs;
const fmt = std.fmt;
const noise = @import("noise");
const Key = noise.Key;
const KeyPair = noise.KeyPair;

const Allocator = std.mem.Allocator;

/// Write pre-formatted data directly to stdout, handling partial writes.
fn writeStdout(data: []const u8) void {
    var remaining = data;
    while (remaining.len > 0) {
        const n = posix.write(posix.STDOUT_FILENO, remaining) catch return;
        if (n == 0) return;
        remaining = remaining[n..];
    }
}

fn print(comptime format: []const u8, args: anytype) void {
    var buf: [4096]u8 = undefined;
    const slice = fmt.bufPrint(&buf, format, args) catch return;
    writeStdout(slice);
}

// ============================================================================
// Main
// ============================================================================

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2) {
        printUsage();
        return;
    }

    // Parse global flags
    var api_addr: ?[]const u8 = null;
    var ctx_override: ?[]const u8 = null;
    var json_output = false;
    var filtered: std.ArrayListUnmanaged([]const u8) = .{};
    defer filtered.deinit(allocator);

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        if (mem.eql(u8, args[i], "--api") and i + 1 < args.len) {
            api_addr = args[i + 1];
            i += 1;
        } else if (mem.eql(u8, args[i], "--ctx") and i + 1 < args.len) {
            ctx_override = args[i + 1];
            i += 1;
        } else if (mem.eql(u8, args[i], "--json")) {
            json_output = true;
        } else {
            try filtered.append(allocator, args[i]);
        }
    }

    if (filtered.items.len == 0) {
        printUsage();
        return;
    }

    const base_dir = try defaultConfigDir(allocator);
    defer allocator.free(base_dir);

    const cmd = filtered.items[0];
    const sub = filtered.items[1..];

    if (mem.eql(u8, cmd, "ctx")) {
        try runCtx(allocator, base_dir, sub);
    } else if (mem.eql(u8, cmd, "key")) {
        try runKey(allocator, base_dir, ctx_override, sub);
    } else if (mem.eql(u8, cmd, "config")) {
        try runConfig(allocator, base_dir, ctx_override, api_addr, json_output, sub);
    } else if (mem.eql(u8, cmd, "host")) {
        try runHost(allocator, base_dir, ctx_override, api_addr, json_output, sub);
    } else if (mem.eql(u8, cmd, "peers") or
        mem.eql(u8, cmd, "lans") or mem.eql(u8, cmd, "policy") or mem.eql(u8, cmd, "routes"))
    {
        try runOnline(allocator, base_dir, ctx_override, api_addr, json_output, cmd, sub);
    } else if (mem.eql(u8, cmd, "help") or mem.eql(u8, cmd, "-h") or mem.eql(u8, cmd, "--help")) {
        printUsage();
    } else if (mem.eql(u8, cmd, "version") or mem.eql(u8, cmd, "--version")) {
        print("zigor 0.1.0\n", .{});
    } else {
        print("error: unknown command \"{s}\" (run 'zigor help')\n", .{cmd});
        std.process.exit(1);
    }
}

// ============================================================================
// Context directory helpers
// ============================================================================

fn defaultConfigDir(allocator: Allocator) ![]const u8 {
    if (std.posix.getenv("ZIGOR_CONFIG_DIR")) |dir| {
        return try allocator.dupe(u8, dir);
    }
    const home = std.posix.getenv("HOME") orelse return error.NoHome;
    return try fmt.allocPrint(allocator, "{s}/.config/zigor", .{home});
}

fn validateContextName(name: []const u8) bool {
    if (name.len == 0) return false;
    if (mem.eql(u8, name, "current")) return false;
    if (mem.indexOfScalar(u8, name, '/') != null) return false;
    if (mem.indexOfScalar(u8, name, '\\') != null) return false;
    if (mem.indexOf(u8, name, "..") != null) return false;
    if (mem.indexOfScalar(u8, name, ' ') != null) return false;
    if (mem.indexOfScalar(u8, name, '\t') != null) return false;
    if (name[0] == '.') return false;
    return true;
}

/// Counts contexts by iterating directories that contain a private.key file.
/// Uses private.key as the language-agnostic context marker (Go/Rust use config.yaml,
/// Zig uses config.json, but all three create private.key with the same format).
fn countContexts(allocator: Allocator, base_dir: []const u8) usize {
    var dir = fs.cwd().openDir(base_dir, .{ .iterate = true }) catch return 0;
    defer dir.close();
    var count: usize = 0;
    var iter = dir.iterate();
    while (iter.next() catch null) |entry| {
        if (entry.kind != .directory) continue;
        const key_path = fmt.allocPrint(allocator, "{s}/{s}/private.key", .{ base_dir, entry.name }) catch continue;
        defer allocator.free(key_path);
        if (fs.cwd().access(key_path, .{})) |_| {
            count += 1;
        } else |_| {}
    }
    return count;
}

fn contextDir(allocator: Allocator, base_dir: []const u8, name: []const u8) ![]const u8 {
    return try fmt.allocPrint(allocator, "{s}/{s}", .{ base_dir, name });
}

fn currentContextName(allocator: Allocator, base_dir: []const u8) ![]const u8 {
    const path = try fmt.allocPrint(allocator, "{s}/current", .{base_dir});
    defer allocator.free(path);

    const data = fs.cwd().readFileAlloc(allocator, path, 1024) catch {
        print("error: no current context set (run: zigor ctx create <name>)\n", .{});
        std.process.exit(1);
    };
    defer allocator.free(data);

    const name = mem.trim(u8, data, &std.ascii.whitespace);
    if (name.len == 0) {
        print("error: current context file is empty\n", .{});
        std.process.exit(1);
    }
    return try allocator.dupe(u8, name);
}

fn contextConfigPath(allocator: Allocator, base_dir: []const u8, name: ?[]const u8) ![]const u8 {
    const ctx = if (name) |n| try allocator.dupe(u8, n) else try currentContextName(allocator, base_dir);
    defer allocator.free(ctx);
    return try fmt.allocPrint(allocator, "{s}/{s}/config.json", .{ base_dir, ctx });
}

const config_template =
    \\{
    \\  "net": {
    \\    "private_key": "private.key",
    \\    "tun_ipv4": "100.64.0.1",
    \\    "tun_mtu": 1400,
    \\    "listen_port": 51820
    \\  }
    \\}
    \\
;

// ============================================================================
// Context commands
// ============================================================================

fn runCtx(allocator: Allocator, base_dir: []const u8, args: []const []const u8) !void {
    if (args.len == 0) {
        print("usage: zigor ctx <list|create|delete|show|use>\n", .{});
        std.process.exit(1);
    }

    if (mem.eql(u8, args[0], "list")) {
        // List contexts
        var dir = fs.cwd().openDir(base_dir, .{ .iterate = true }) catch {
            print("(no contexts — run: zigor ctx create <name>)\n", .{});
            return;
        };
        defer dir.close();

        const current = currentContextName(allocator, base_dir) catch null;
        defer if (current) |c| allocator.free(c);

        var names: std.ArrayListUnmanaged([]const u8) = .{};
        defer {
            for (names.items) |n| allocator.free(n);
            names.deinit(allocator);
        }

        var iter = dir.iterate();
        while (try iter.next()) |entry| {
            if (entry.kind != .directory) continue;
            const key_path = try fmt.allocPrint(allocator, "{s}/{s}/private.key", .{ base_dir, entry.name });
            defer allocator.free(key_path);
            if (fs.cwd().access(key_path, .{})) |_| {
                try names.append(allocator, try allocator.dupe(u8, entry.name));
            } else |_| {}
        }

        mem.sort([]const u8, names.items, {}, struct {
            fn lessThan(_: void, a: []const u8, b: []const u8) bool {
                return mem.order(u8, a, b) == .lt;
            }
        }.lessThan);

        for (names.items) |name| {
            const marker: []const u8 = if (current != null and mem.eql(u8, name, current.?)) "* " else "  ";
            print("{s}{s}\n", .{ marker, name });
        }
        if (names.items.len == 0) {
            print("(no contexts — run: zigor ctx create <name>)\n", .{});
        }
    } else if (mem.eql(u8, args[0], "show")) {
        const name = try currentContextName(allocator, base_dir);
        defer allocator.free(name);
        print("{s}\n", .{name});
    } else if (mem.eql(u8, args[0], "use")) {
        if (args.len < 2) {
            print("usage: zigor ctx use <name>\n", .{});
            std.process.exit(1);
        }
        const dir = try contextDir(allocator, base_dir, args[1]);
        defer allocator.free(dir);
        fs.cwd().access(dir, .{}) catch {
            print("error: context \"{s}\" does not exist\n", .{args[1]});
            std.process.exit(1);
        };
        const path = try fmt.allocPrint(allocator, "{s}/current", .{base_dir});
        defer allocator.free(path);
        const file = try fs.cwd().createFile(path, .{});
        defer file.close();
        try file.writeAll(args[1]);
        try file.writeAll("\n");
        print("switched to context \"{s}\"\n", .{args[1]});
    } else if (mem.eql(u8, args[0], "create")) {
        if (args.len < 2) {
            print("usage: zigor ctx create <name>\n", .{});
            std.process.exit(1);
        }
        const name = args[1];
        if (!validateContextName(name)) {
            print("error: invalid context name \"{s}\"\n", .{name});
            std.process.exit(1);
        }
        const dir = try contextDir(allocator, base_dir, name);
        defer allocator.free(dir);

        // Check if already exists
        if (fs.cwd().access(dir, .{})) |_| {
            print("error: context \"{s}\" already exists\n", .{name});
            std.process.exit(1);
        } else |_| {}

        // Create directory structure
        const data_dir = try fmt.allocPrint(allocator, "{s}/data", .{dir});
        defer allocator.free(data_dir);
        try fs.cwd().makePath(data_dir);

        // Generate keypair
        const kp = KeyPair.generate();

        // Write private key
        const key_path = try fmt.allocPrint(allocator, "{s}/private.key", .{dir});
        defer allocator.free(key_path);
        {
            const kf = try fs.cwd().createFile(key_path, .{ .mode = 0o600 });
            defer kf.close();
            const hex_buf = std.fmt.bytesToHex(kp.private.data, .lower);
            try kf.writeAll(&hex_buf);
            try kf.writeAll("\n");
        }

        // Write template config
        const cfg_path = try fmt.allocPrint(allocator, "{s}/config.json", .{dir});
        defer allocator.free(cfg_path);
        {
            const cf = try fs.cwd().createFile(cfg_path, .{});
            defer cf.close();
            try cf.writeAll(config_template);
        }

        // Auto-set as current if it's the first context (matches Go/Rust behavior)
        const ctx_count = countContexts(allocator, base_dir);
        if (ctx_count == 1) {
            const cur_path = try fmt.allocPrint(allocator, "{s}/current", .{base_dir});
            defer allocator.free(cur_path);
            if (fs.cwd().createFile(cur_path, .{})) |f| {
                defer f.close();
                f.writeAll(name) catch {};
                f.writeAll("\n") catch {};
            } else |_| {}
        }

        // Show result
        const pub_hex = std.fmt.bytesToHex(kp.public.data, .lower);
        print("created context \"{s}\"\n", .{name});
        print("public key: {s}\n", .{&pub_hex});
    } else if (mem.eql(u8, args[0], "delete")) {
        if (args.len < 2) {
            print("usage: zigor ctx delete <name>\n", .{});
            std.process.exit(1);
        }
        // Check not current
        const current = currentContextName(allocator, base_dir) catch null;
        defer if (current) |c| allocator.free(c);
        if (current != null and mem.eql(u8, args[1], current.?)) {
            print("error: cannot delete the current context (switch to another first)\n", .{});
            std.process.exit(1);
        }
        const dir = try contextDir(allocator, base_dir, args[1]);
        defer allocator.free(dir);
        fs.cwd().deleteTree(dir) catch |e| {
            print("error: delete context: {}\n", .{e});
            std.process.exit(1);
        };
        print("deleted context \"{s}\"\n", .{args[1]});
    } else {
        print("error: unknown context subcommand \"{s}\"\n", .{args[0]});
        std.process.exit(1);
    }
}

// ============================================================================
// Key commands
// ============================================================================

fn runKey(allocator: Allocator, base_dir: []const u8, ctx: ?[]const u8, args: []const []const u8) !void {
    if (args.len == 0) {
        print("usage: zigor key <generate|show>\n", .{});
        std.process.exit(1);
    }

    const ctx_name = if (ctx) |c| try allocator.dupe(u8, c) else try currentContextName(allocator, base_dir);
    defer allocator.free(ctx_name);

    if (mem.eql(u8, args[0], "show")) {
        const key_path = try fmt.allocPrint(allocator, "{s}/{s}/private.key", .{ base_dir, ctx_name });
        defer allocator.free(key_path);
        const data = try fs.cwd().readFileAlloc(allocator, key_path, 1024);
        defer allocator.free(data);
        const hex_str = mem.trim(u8, data, &std.ascii.whitespace);
        const priv_key = Key.fromHex(hex_str) catch {
            print("error: invalid private key\n", .{});
            std.process.exit(1);
        };
        const kp = KeyPair.fromPrivate(priv_key);
        const pub_hex = std.fmt.bytesToHex(kp.public.data, .lower);
        print("{s}\n", .{&pub_hex});
    } else if (mem.eql(u8, args[0], "generate")) {
        const kp = KeyPair.generate();
        const key_path = try fmt.allocPrint(allocator, "{s}/{s}/private.key", .{ base_dir, ctx_name });
        defer allocator.free(key_path);
        const kf = try fs.cwd().createFile(key_path, .{ .mode = 0o600 });
        defer kf.close();
        const hex_buf = std.fmt.bytesToHex(kp.private.data, .lower);
        try kf.writeAll(&hex_buf);
        try kf.writeAll("\n");
        const pub_hex = std.fmt.bytesToHex(kp.public.data, .lower);
        print("new public key: {s}\n", .{&pub_hex});
    } else {
        print("error: unknown key subcommand \"{s}\"\n", .{args[0]});
        std.process.exit(1);
    }
}

// ============================================================================
// Config commands
// ============================================================================

fn runConfig(allocator: Allocator, base_dir: []const u8, ctx: ?[]const u8, api_addr: ?[]const u8, json_output: bool, args: []const []const u8) !void {
    if (args.len == 0) {
        print("usage: zigor config <show|path|net|reload>\n", .{});
        std.process.exit(1);
    }

    if (mem.eql(u8, args[0], "show")) {
        const path = try contextConfigPath(allocator, base_dir, ctx);
        defer allocator.free(path);
        const data = try fs.cwd().readFileAlloc(allocator, path, 1024 * 1024);
        defer allocator.free(data);
        // Write directly to stdout (bypasses print's 4KB buffer limit)
        writeStdout(data);
    } else if (mem.eql(u8, args[0], "path")) {
        const path = try contextConfigPath(allocator, base_dir, ctx);
        defer allocator.free(path);
        print("{s}\n", .{path});
    } else if (mem.eql(u8, args[0], "net")) {
        const addr = try resolveApiAddr(allocator, base_dir, ctx, api_addr);
        defer allocator.free(addr);
        const body = try httpGet(allocator, addr, "/api/config/net");
        defer allocator.free(body);
        printJsonOutput(body, json_output);
    } else if (mem.eql(u8, args[0], "reload")) {
        const addr = try resolveApiAddr(allocator, base_dir, ctx, api_addr);
        defer allocator.free(addr);
        const body = try httpPost(allocator, addr, "/api/config/reload", "");
        defer allocator.free(body);
        printJsonOutput(body, json_output);
    } else {
        print("error: unknown config subcommand \"{s}\"\n", .{args[0]});
        std.process.exit(1);
    }
}

// ============================================================================
// Up / Down
// ============================================================================

fn runHost(allocator: Allocator, base_dir: []const u8, ctx: ?[]const u8, api_addr: ?[]const u8, json_output: bool, args: []const []const u8) !void {
    if (args.len == 0) {
        print("usage: zigor host <up|down|status|peers>\n", .{});
        std.process.exit(1);
    }

    if (mem.eql(u8, args[0], "up")) {
        print("error: host up not implemented in Zig build (use Go build)\n", .{});
        std.process.exit(1);
    } else if (mem.eql(u8, args[0], "down")) {
        const ctx_name = if (ctx) |c| try allocator.dupe(u8, c) else try currentContextName(allocator, base_dir);
        defer allocator.free(ctx_name);

        const pid_path = try fmt.allocPrint(allocator, "{s}/{s}/data/zigor.pid", .{ base_dir, ctx_name });
        defer allocator.free(pid_path);

        const data = fs.cwd().readFileAlloc(allocator, pid_path, 64) catch {
            print("error: host is not running (no pidfile)\n", .{});
            std.process.exit(1);
        };
        defer allocator.free(data);

        const pid_str = mem.trim(u8, data, &std.ascii.whitespace);
        const pid = fmt.parseInt(posix.pid_t, pid_str, 10) catch {
            print("error: invalid pidfile\n", .{});
            std.process.exit(1);
        };

        posix.kill(pid, posix.SIG.TERM) catch |e| {
            print("error: send SIGTERM to pid {d}: {}\n", .{ pid, e });
            std.process.exit(1);
        };
        fs.cwd().deleteFile(pid_path) catch {};
        print("host stopped\n", .{});
    } else if (mem.eql(u8, args[0], "status")) {
        const ctx_name = if (ctx) |c| try allocator.dupe(u8, c) else try currentContextName(allocator, base_dir);
        defer allocator.free(ctx_name);

        const pid_path = try fmt.allocPrint(allocator, "{s}/{s}/data/zigor.pid", .{ base_dir, ctx_name });
        defer allocator.free(pid_path);

        _ = fs.cwd().readFileAlloc(allocator, pid_path, 64) catch {
            print("host is not running (context \"{s}\")\n", .{ctx_name});
            return;
        };

        const addr = try resolveApiAddr(allocator, base_dir, ctx, api_addr);
        defer allocator.free(addr);
        if (httpGet(allocator, addr, "/api/whoami")) |body| {
            defer allocator.free(body);
            printJsonOutput(body, json_output);
        } else |_| {
            print("host is running but API unreachable\n", .{});
        }
    } else if (mem.eql(u8, args[0], "peers")) {
        const addr = try resolveApiAddr(allocator, base_dir, ctx, api_addr);
        defer allocator.free(addr);
        const body = try httpGet(allocator, addr, "/api/peers");
        defer allocator.free(body);
        printJsonOutput(body, json_output);
    } else {
        print("error: unknown host subcommand \"{s}\"\n", .{args[0]});
        std.process.exit(1);
    }
}

// ============================================================================
// Online commands (API client)
// ============================================================================

fn runOnline(allocator: Allocator, base_dir: []const u8, ctx: ?[]const u8, api_addr: ?[]const u8, json_output: bool, cmd: []const u8, args: []const []const u8) !void {
    const addr = try resolveApiAddr(allocator, base_dir, ctx, api_addr);
    defer allocator.free(addr);

    if (mem.eql(u8, cmd, "status")) {
        const body = try httpGet(allocator, addr, "/api/whoami");
        defer allocator.free(body);
        printJsonOutput(body, json_output);
    } else if (mem.eql(u8, cmd, "peers")) {
        try runPeers(allocator, addr, json_output, args);
    } else if (mem.eql(u8, cmd, "lans")) {
        try runLans(allocator, addr, json_output, args);
    } else if (mem.eql(u8, cmd, "policy")) {
        try runPolicy(allocator, addr, json_output, args);
    } else if (mem.eql(u8, cmd, "routes")) {
        try runRoutes(allocator, addr, json_output, args);
    }
}

fn runPeers(allocator: Allocator, addr: []const u8, json_output: bool, args: []const []const u8) !void {
    if (args.len == 0) {
        print("usage: zigor peers <list|add|get|remove>\n", .{});
        std.process.exit(1);
    }
    if (mem.eql(u8, args[0], "list")) {
        const body = try httpGet(allocator, addr, "/api/peers");
        defer allocator.free(body);
        printJsonOutput(body, json_output);
    } else if (mem.eql(u8, args[0], "get")) {
        if (args.len < 2) { print("usage: zigor peers get <pubkey>\n", .{}); std.process.exit(1); }
        const path = try fmt.allocPrint(allocator, "/api/peers/{s}", .{args[1]});
        defer allocator.free(path);
        const body = try httpGet(allocator, addr, path);
        defer allocator.free(body);
        printJsonOutput(body, json_output);
    } else if (mem.eql(u8, args[0], "add")) {
        var pubkey: ?[]const u8 = null;
        var alias: []const u8 = "";
        var endpoint: []const u8 = "";
        var j: usize = 1;
        while (j < args.len) : (j += 1) {
            if (mem.eql(u8, args[j], "--alias") and j + 1 < args.len) { alias = args[j + 1]; j += 1; } else if (mem.eql(u8, args[j], "--endpoint") and j + 1 < args.len) { endpoint = args[j + 1]; j += 1; } else if (pubkey == null) { pubkey = args[j]; }
        }
        if (pubkey == null) { print("usage: zigor peers add <pubkey> [--alias <a>] [--endpoint <e>]\n", .{}); std.process.exit(1); }
        const req = try fmt.allocPrint(allocator, "{{\"pubkey\":\"{s}\",\"alias\":\"{s}\",\"endpoint\":\"{s}\"}}", .{ pubkey.?, alias, endpoint });
        defer allocator.free(req);
        const body = try httpPost(allocator, addr, "/api/peers", req);
        defer allocator.free(body);
        printJsonOutput(body, json_output);
    } else if (mem.eql(u8, args[0], "remove")) {
        if (args.len < 2) { print("usage: zigor peers remove <pubkey>\n", .{}); std.process.exit(1); }
        const path = try fmt.allocPrint(allocator, "/api/peers/{s}", .{args[1]});
        defer allocator.free(path);
        try httpDelete(allocator, addr, path);
        print("peer removed\n", .{});
    } else {
        print("error: unknown peers subcommand \"{s}\"\n", .{args[0]});
        std.process.exit(1);
    }
}

fn runLans(allocator: Allocator, addr: []const u8, json_output: bool, args: []const []const u8) !void {
    if (args.len == 0) { print("usage: zigor lans <list|join|leave>\n", .{}); std.process.exit(1); }
    if (mem.eql(u8, args[0], "list")) {
        const body = try httpGet(allocator, addr, "/api/lans");
        defer allocator.free(body);
        printJsonOutput(body, json_output);
    } else if (mem.eql(u8, args[0], "join")) {
        var domain: []const u8 = "";
        var pubkey: []const u8 = "";
        var endpoint: []const u8 = "";
        var j: usize = 1;
        while (j < args.len) : (j += 1) {
            if (mem.eql(u8, args[j], "--domain") and j + 1 < args.len) { domain = args[j + 1]; j += 1; } else if (mem.eql(u8, args[j], "--pubkey") and j + 1 < args.len) { pubkey = args[j + 1]; j += 1; } else if (mem.eql(u8, args[j], "--endpoint") and j + 1 < args.len) { endpoint = args[j + 1]; j += 1; }
        }
        if (domain.len == 0 or pubkey.len == 0 or endpoint.len == 0) { print("usage: zigor lans join --domain <d> --pubkey <pk> --endpoint <e>\n", .{}); std.process.exit(1); }
        const req = try fmt.allocPrint(allocator, "{{\"domain\":\"{s}\",\"pubkey\":\"{s}\",\"endpoint\":\"{s}\"}}", .{ domain, pubkey, endpoint });
        defer allocator.free(req);
        const body = try httpPost(allocator, addr, "/api/lans", req);
        defer allocator.free(body);
        printJsonOutput(body, json_output);
    } else if (mem.eql(u8, args[0], "leave")) {
        if (args.len < 2) { print("usage: zigor lans leave <domain>\n", .{}); std.process.exit(1); }
        const path = try fmt.allocPrint(allocator, "/api/lans/{s}", .{args[1]});
        defer allocator.free(path);
        try httpDelete(allocator, addr, path);
        print("lan left\n", .{});
    } else {
        print("error: unknown lans subcommand \"{s}\"\n", .{args[0]});
        std.process.exit(1);
    }
}

fn runPolicy(allocator: Allocator, addr: []const u8, json_output: bool, args: []const []const u8) !void {
    if (args.len == 0) { print("usage: zigor policy <show|add-rule|remove-rule>\n", .{}); std.process.exit(1); }
    if (mem.eql(u8, args[0], "show")) {
        const body = try httpGet(allocator, addr, "/api/policy");
        defer allocator.free(body);
        printJsonOutput(body, json_output);
    } else if (mem.eql(u8, args[0], "add-rule")) {
        if (args.len < 2) { print("usage: zigor policy add-rule '<json>'\n", .{}); std.process.exit(1); }
        const body = try httpPost(allocator, addr, "/api/policy/rules", args[1]);
        defer allocator.free(body);
        printJsonOutput(body, json_output);
    } else if (mem.eql(u8, args[0], "remove-rule")) {
        if (args.len < 2) { print("usage: zigor policy remove-rule <name>\n", .{}); std.process.exit(1); }
        const path = try fmt.allocPrint(allocator, "/api/policy/rules/{s}", .{args[1]});
        defer allocator.free(path);
        try httpDelete(allocator, addr, path);
        print("rule removed\n", .{});
    } else {
        print("error: unknown policy subcommand \"{s}\"\n", .{args[0]});
        std.process.exit(1);
    }
}

fn runRoutes(allocator: Allocator, addr: []const u8, json_output: bool, args: []const []const u8) !void {
    if (args.len == 0) { print("usage: zigor routes <list|add|remove>\n", .{}); std.process.exit(1); }
    if (mem.eql(u8, args[0], "list")) {
        const body = try httpGet(allocator, addr, "/api/routes");
        defer allocator.free(body);
        printJsonOutput(body, json_output);
    } else if (mem.eql(u8, args[0], "add")) {
        var domain: []const u8 = "";
        var peer: []const u8 = "";
        var j: usize = 1;
        while (j < args.len) : (j += 1) {
            if (mem.eql(u8, args[j], "--domain") and j + 1 < args.len) { domain = args[j + 1]; j += 1; } else if (mem.eql(u8, args[j], "--peer") and j + 1 < args.len) { peer = args[j + 1]; j += 1; }
        }
        if (domain.len == 0 or peer.len == 0) { print("usage: zigor routes add --domain <pattern> --peer <alias>\n", .{}); std.process.exit(1); }
        const req = try fmt.allocPrint(allocator, "{{\"domain\":\"{s}\",\"peer\":\"{s}\"}}", .{ domain, peer });
        defer allocator.free(req);
        const body = try httpPost(allocator, addr, "/api/routes", req);
        defer allocator.free(body);
        printJsonOutput(body, json_output);
    } else if (mem.eql(u8, args[0], "remove")) {
        if (args.len < 2) { print("usage: zigor routes remove <id>\n", .{}); std.process.exit(1); }
        const path = try fmt.allocPrint(allocator, "/api/routes/{s}", .{args[1]});
        defer allocator.free(path);
        try httpDelete(allocator, addr, path);
        print("route removed\n", .{});
    } else {
        print("error: unknown routes subcommand \"{s}\"\n", .{args[0]});
        std.process.exit(1);
    }
}

// ============================================================================
// Minimal HTTP client
// ============================================================================

fn resolveApiAddr(allocator: Allocator, base_dir: []const u8, ctx: ?[]const u8, override: ?[]const u8) ![]const u8 {
    if (override) |addr| return try allocator.dupe(u8, addr);

    // Try to read tun_ipv4 from config
    if (contextConfigPath(allocator, base_dir, ctx)) |path| {
        defer allocator.free(path);
        if (fs.cwd().readFileAlloc(allocator, path, 1024 * 1024)) |data| {
            defer allocator.free(data);
            // Quick parse: find tun_ipv4
            if (mem.indexOf(u8, data, "\"tun_ipv4\"")) |idx| {
                var pos = idx + "\"tun_ipv4\"".len;
                // Skip to value
                while (pos < data.len and (data[pos] == ':' or data[pos] == ' ' or data[pos] == '"')) : (pos += 1) {}
                const start = pos;
                while (pos < data.len and data[pos] != '"' and data[pos] != ',' and data[pos] != '}' and data[pos] != '\n') : (pos += 1) {}
                if (pos > start) {
                    const ip = data[start..pos];
                    return try fmt.allocPrint(allocator, "{s}:80", .{ip});
                }
            }
        } else |_| {}
    } else |_| {}

    return try allocator.dupe(u8, "100.64.0.1:80");
}

fn httpGet(allocator: Allocator, addr: []const u8, path: []const u8) ![]const u8 {
    return httpRequest(allocator, addr, "GET", path, null);
}

fn httpPost(allocator: Allocator, addr: []const u8, path: []const u8, body: []const u8) ![]const u8 {
    return httpRequest(allocator, addr, "POST", path, body);
}

fn httpDelete(allocator: Allocator, addr: []const u8, path: []const u8) !void {
    const result = try httpRequest(allocator, addr, "DELETE", path, null);
    allocator.free(result);
}

fn httpRequest(allocator: Allocator, addr: []const u8, method: []const u8, path: []const u8, body: ?[]const u8) ![]const u8 {
    // Parse host:port
    const colon = mem.lastIndexOfScalar(u8, addr, ':') orelse return error.InvalidAddress;
    const host = addr[0..colon];
    const port = fmt.parseInt(u16, addr[colon + 1 ..], 10) catch return error.InvalidAddress;

    const stream = try std.net.tcpConnectToHost(allocator, host, port);
    defer stream.close();

    // Send request
    const body_len = if (body) |b| b.len else 0;
    const header = try fmt.allocPrint(allocator, "{s} {s} HTTP/1.1\r\nHost: {s}\r\nContent-Type: application/json\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n", .{ method, path, addr, body_len });
    defer allocator.free(header);

    try stream.writeAll(header);
    if (body) |b| {
        if (b.len > 0) try stream.writeAll(b);
    }

    // Read response
    var resp_buf: std.ArrayListUnmanaged(u8) = .{};
    defer resp_buf.deinit(allocator);

    var read_buf: [4096]u8 = undefined;
    while (true) {
        const n = stream.read(&read_buf) catch break;
        if (n == 0) break;
        try resp_buf.appendSlice(allocator, read_buf[0..n]);
    }

    const resp = resp_buf.items;

    // Parse status
    const status_line_end = mem.indexOf(u8, resp, "\r\n") orelse return error.MalformedResponse;
    const status_str = blk: {
        var parts = mem.splitScalar(u8, resp[0..status_line_end], ' ');
        _ = parts.next(); // HTTP/1.1
        break :blk parts.next() orelse return error.MalformedResponse;
    };
    const status = fmt.parseInt(u16, status_str, 10) catch return error.MalformedResponse;

    // Extract body
    const body_start = mem.indexOf(u8, resp, "\r\n\r\n") orelse return error.MalformedResponse;
    const resp_body = resp[body_start + 4 ..];

    if (status >= 400) {
        print("error: {s} {s}: {d} — {s}\n", .{ method, path, status, resp_body });
        std.process.exit(1);
    }

    return try allocator.dupe(u8, resp_body);
}

// ============================================================================
// Helpers
// ============================================================================

fn printJsonOutput(data: []const u8, raw: bool) void {
    _ = raw;
    // For now just print as-is; Zig doesn't have a JSON pretty-printer in std
    print("{s}\n", .{data});
}

fn printUsage() void {
    print(
        \\zigor — zgrnet management tool (Zig)
        \\
        \\Usage: zigor [--ctx <name>] <command> [options]
        \\
        \\Context management (offline):
        \\  ctx list                     List all contexts
        \\  ctx create <name>            Create a new context (generates keypair)
        \\  ctx delete <name>            Delete a context
        \\  ctx show                     Show current context name
        \\  ctx use <name>               Switch to a context
        \\
        \\Host control:
        \\  host up [-d]                 Start host (-d for background)
        \\  host down                    Stop running host
        \\  host status                  Show host status
        \\  host peers                   List connected peers
        \\
        \\Key management:
        \\  key show                     Show public key of current context
        \\  key generate                 Generate a new keypair (overwrites existing)
        \\
        \\Config management:
        \\  config show                  Print config.json contents
        \\  config path                  Print config.json file path
        \\  config net                   Show network config (via API)
        \\  config reload                Reload config from disk (via API)
        \\
        \\Global flags:
        \\  --ctx <name>                 Override context
        \\  --api <addr>                 Override API address
        \\  --json                       Output raw JSON
        \\  --version                    Show version
        \\
    , .{});
}
