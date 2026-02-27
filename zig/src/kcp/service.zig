//! ServiceMux — per-service KCP + yamux stream multiplexing.
//!
//! Routes incoming KCP packets by service ID to independent KcpConn + yamux sessions.
//! Generic over `comptime Rt: type` for ESP32 compatibility.

const std = @import("std");
const conn_mod = @import("conn.zig");
const yamux_mod = @import("yamux.zig");

pub fn ServiceMux(comptime Rt: type) type {
    const KConn = conn_mod.KcpConn(Rt);
    const YMux = yamux_mod.Yamux(Rt);
    const YStream = yamux_mod.YamuxStream(Rt);

    return struct {
        const Self = @This();

        allocator: std.mem.Allocator,
        is_client: bool,
        services: std.AutoHashMapUnmanaged(u64, *ServiceEntry),
        mutex: Rt.Mutex,

        accept_queue: std.ArrayListUnmanaged(AcceptResult),
        accept_mutex: Rt.Mutex,
        accept_cond: Rt.Condition,

        closed: std.atomic.Value(bool),

        output_fn: *const fn (u64, []const u8, ?*anyopaque) void,
        output_ctx: ?*anyopaque,

        const ServiceEntry = struct {
            kcp_conn: *KConn,
            yamux: *YMux,
            accept_thread: ?Rt.Thread,
            poll_thread: ?Rt.Thread,
            output_ctx: ?*anyopaque, // for cleanup
            fwd_ctx: ?*ForwardCtxType, // for cleanup
        };

        pub const AcceptResult = struct {
            stream: *YStream,
            service: u64,
        };

        pub fn init(
            allocator: std.mem.Allocator,
            is_client: bool,
            output_fn: *const fn (u64, []const u8, ?*anyopaque) void,
            output_ctx: ?*anyopaque,
        ) !*Self {
            const self = try allocator.create(Self);
            self.* = .{
                .allocator = allocator,
                .is_client = is_client,
                .services = .{},
                .mutex = Rt.Mutex.init(),
                .accept_queue = .{},
                .accept_mutex = Rt.Mutex.init(),
                .accept_cond = Rt.Condition.init(),
                .closed = std.atomic.Value(bool).init(false),
                .output_fn = output_fn,
                .output_ctx = output_ctx,
            };
            return self;
        }

        pub fn deinit(self: *Self) void {
            self.close();
            // Close all KcpConns first to unblock yamux recv_threads.
            self.mutex.lock();
            var close_it = self.services.iterator();
            while (close_it.next()) |entry| {
                const se = entry.value_ptr.*;
                se.kcp_conn.close();
            }
            self.mutex.unlock();

            self.mutex.lock();
            var it = self.services.iterator();
            while (it.next()) |entry| {
                const se = entry.value_ptr.*;
                if (se.accept_thread) |t| t.join();
                if (se.poll_thread) |t| t.join();
                se.yamux.deinit();
                se.kcp_conn.deinit();
                if (se.output_ctx) |ctx| {
                    const typed: *struct { svc: u64, mux: *Self } = @ptrCast(@alignCast(ctx));
                    self.allocator.destroy(typed);
                }
                if (se.fwd_ctx) |fwd| self.allocator.destroy(fwd);
                self.allocator.destroy(se);
            }
            self.services.deinit(self.allocator);
            self.mutex.unlock();

            self.accept_mutex.lock();
            self.accept_queue.deinit(self.allocator);
            self.accept_mutex.unlock();

            self.mutex.deinit();
            self.accept_mutex.deinit();
            self.accept_cond.deinit();
            self.allocator.destroy(self);
        }

        pub fn input(self: *Self, service: u64, data: []const u8) void {
            if (self.closed.load(.acquire)) return;
            const entry = self.getOrCreate(service) catch return;
            entry.kcp_conn.input(data) catch {};
        }

        pub fn openStream(self: *Self, service: u64) !*YStream {
            if (self.closed.load(.acquire)) return error.SessionClosed;
            const entry = try self.getOrCreate(service);
            return entry.yamux.open();
        }

        pub fn acceptStream(self: *Self) !AcceptResult {
            self.accept_mutex.lock();
            defer self.accept_mutex.unlock();

            while (self.accept_queue.items.len == 0) {
                if (self.closed.load(.acquire)) return error.SessionClosed;
                _ = self.accept_cond.timedWait(&self.accept_mutex, 100 * std.time.ns_per_ms);
            }

            const result = self.accept_queue.items[0];
            std.mem.copyForwards(AcceptResult, self.accept_queue.items[0..], self.accept_queue.items[1..]);
            self.accept_queue.items.len -= 1;
            return result;
        }

        pub fn close(self: *Self) void {
            if (self.closed.swap(true, .acq_rel)) return;
            self.accept_cond.broadcast();

            // Cascade close to all services (stops yamux + KcpConn threads).
            self.mutex.lock();
            var it = self.services.iterator();
            while (it.next()) |entry| {
                const se = entry.value_ptr.*;
                se.yamux.close();
                se.kcp_conn.close();
            }
            self.mutex.unlock();
        }

        pub fn numServices(self: *Self) usize {
            self.mutex.lock();
            defer self.mutex.unlock();
            return self.services.count();
        }

        fn getOrCreate(self: *Self, service: u64) !*ServiceEntry {
            self.mutex.lock();
            if (self.services.get(service)) |entry| {
                self.mutex.unlock();
                return entry;
            }
            self.mutex.unlock();
            return self.createService(service);
        }

        fn createService(self: *Self, service: u64) !*ServiceEntry {
            self.mutex.lock();
            defer self.mutex.unlock();

            // Double check.
            if (self.services.get(service)) |entry| return entry;

            // Create KcpConn with output routed through ServiceMux output.
            const OutputCtx = struct {
                svc: u64,
                mux: *Self,
            };
            const ctx = try self.allocator.create(OutputCtx);
            ctx.* = .{ .svc = service, .mux = self };

            const kcp_conn = try KConn.init(self.allocator, @intCast(service & 0xFFFFFFFF), outputCallback, @ptrCast(ctx));

            // Create yamux over KcpConn.
            const mode: YMux.Mode = if (self.is_client) .client else .server;

            const TransportAdapter = struct {
                fn readFn(transport_ctx: *anyopaque, buf: []u8) anyerror!usize {
                    const kc: *KConn = @ptrCast(@alignCast(transport_ctx));
                    // Non-blocking read; Yamux session keeps an internal RX buffer
                    // to reassemble complete frames.
                    return kc.readNonBlock(buf);
                }
                fn writeFn(transport_ctx: *anyopaque, data: []const u8) anyerror!void {
                    const kc: *KConn = @ptrCast(@alignCast(transport_ctx));
                    _ = try kc.write(data);
                }
                fn pollFn(transport_ctx: *anyopaque) void {
                    const kc: *KConn = @ptrCast(@alignCast(transport_ctx));
                    _ = kc.poll();
                }
                fn selectFdFn(transport_ctx: *anyopaque) std.posix.fd_t {
                    const kc: *KConn = @ptrCast(@alignCast(transport_ctx));
                    return kc.selectFd();
                }
            };

            const yamux = try YMux.init(
                self.allocator,
                mode,
                @ptrCast(kcp_conn),
                TransportAdapter.readFn,
                TransportAdapter.writeFn,
                TransportAdapter.pollFn,
                TransportAdapter.selectFdFn,
            );

            const fwd = try self.allocator.create(ForwardCtxType);
            fwd.* = .{ .ymux = yamux, .svc = service, .smux = self };

            const entry = try self.allocator.create(ServiceEntry);
            entry.* = .{
                .kcp_conn = kcp_conn,
                .yamux = yamux,
                .accept_thread = Rt.Thread.spawn(.{}, acceptForwarder, .{fwd}) catch null,
                .poll_thread = Rt.Thread.spawn(.{}, pollDriver, .{fwd}) catch null,
                .output_ctx = @ptrCast(ctx),
                .fwd_ctx = fwd,
            };

            try self.services.put(self.allocator, service, entry);
            return entry;
        }

        fn outputCallback(data: []const u8, user: ?*anyopaque) void {
            const ctx: *struct { svc: u64, mux: *Self } = @ptrCast(@alignCast(user.?));
            ctx.mux.output_fn(ctx.svc, data, ctx.mux.output_ctx);
        }

        const ForwardCtxType = struct {
            ymux: *YMux,
            svc: u64,
            smux: *Self,
        };

        fn acceptForwarder(ctx: *ForwardCtxType) void {
            while (!ctx.smux.closed.load(.acquire)) {
                const stream = ctx.ymux.accept() catch return;
                ctx.smux.accept_mutex.lock();
                ctx.smux.accept_queue.append(ctx.smux.allocator, .{
                    .stream = stream,
                    .service = ctx.svc,
                }) catch {};
                ctx.smux.accept_mutex.unlock();
                ctx.smux.accept_cond.signal();
            }
        }

        fn pollDriver(ctx: *ForwardCtxType) void {
            while (!ctx.smux.closed.load(.acquire)) {
                const n = ctx.ymux.pollOptimized(64);
                if (n == 0) {
                    if (comptime @hasDecl(Rt, "sleepMs")) {
                        Rt.sleepMs(1);
                    } else {
                        std.Thread.sleep(std.time.ns_per_ms);
                    }
                }
            }
        }
    };
}

// ============================================================================
// Tests
// ============================================================================

const TestRt = if (@import("builtin").os.tag != .freestanding) struct {
    pub const Mutex = struct {
        inner: std.Thread.Mutex = .{},
        pub fn init() Mutex {
            return .{};
        }
        pub fn deinit(_: *Mutex) void {}
        pub fn lock(self: *Mutex) void {
            self.inner.lock();
        }
        pub fn unlock(self: *Mutex) void {
            self.inner.unlock();
        }
    };
    pub const Condition = struct {
        inner: std.Thread.Condition = .{},
        pub fn init() Condition {
            return .{};
        }
        pub fn deinit(_: *Condition) void {}
        pub fn wait(self: *Condition, mutex: *Mutex) void {
            self.inner.wait(&mutex.inner);
        }
        pub fn timedWait(self: *Condition, mutex: *Mutex, timeout_ns: u64) bool {
            self.inner.timedWait(&mutex.inner, timeout_ns) catch return true;
            return false;
        }
        pub fn signal(self: *Condition) void {
            self.inner.signal();
        }
        pub fn broadcast(self: *Condition) void {
            self.inner.broadcast();
        }
    };
    pub const Thread = std.Thread;
    pub fn nowMs() u64 {
        return @intCast(std.time.milliTimestamp());
    }
    pub fn sleepMs(ms: u32) void {
        std.Thread.sleep(@as(u64, ms) * std.time.ns_per_ms);
    }
} else struct {};

fn smuxPair() !struct {
    client: *ServiceMux(TestRt),
    server: *ServiceMux(TestRt),
} {
    if (@import("builtin").os.tag == .freestanding) return error.Unsupported;
    const SMux = ServiceMux(TestRt);
    const allocator = std.testing.allocator;

    const Ctx = struct {
        var client_ptr: ?*SMux = null;
        var server_ptr: ?*SMux = null;

        fn clientOutput(service: u64, data: []const u8, _: ?*anyopaque) void {
            if (server_ptr) |s| s.input(service, data);
        }
        fn serverOutput(service: u64, data: []const u8, _: ?*anyopaque) void {
            if (client_ptr) |c| c.input(service, data);
        }
    };
    Ctx.client_ptr = null;
    Ctx.server_ptr = null;

    const client = try SMux.init(allocator, true, Ctx.clientOutput, null);
    const server = try SMux.init(allocator, false, Ctx.serverOutput, null);
    Ctx.client_ptr = client;
    Ctx.server_ptr = server;

    return .{ .client = client, .server = server };
}

test "smux single service" {
    if (@import("builtin").os.tag == .freestanding) return;
    const pair = try smuxPair();
    defer pair.client.deinit();
    defer pair.server.deinit();

    // Server echo in background.
    const EchoThread = struct {
        fn run(server: *ServiceMux(TestRt)) void {
            const result = server.acceptStream() catch return;
            var buf: [4096]u8 = undefined;
            const n = result.stream.read(&buf) catch return;
            _ = result.stream.write(buf[0..n]) catch return;
            result.stream.close();
        }
    };
    const t = std.Thread.spawn(.{}, EchoThread.run, .{pair.server}) catch return;

    var cs = try pair.client.openStream(1);
    _ = try cs.write("hello smux");
    var buf: [256]u8 = undefined;
    const n = try cs.read(&buf);
    try std.testing.expectEqualStrings("hello smux", buf[0..n]);
    cs.close();
    t.join();

    try std.testing.expectEqual(@as(usize, 1), pair.client.numServices());
}

test "smux multi service 3" {
    if (@import("builtin").os.tag == .freestanding) return;
    const pair = try smuxPair();
    defer pair.client.deinit();
    defer pair.server.deinit();

    const EchoThread = struct {
        fn run(server: *ServiceMux(TestRt)) void {
            for (0..3) |_| {
                const result = server.acceptStream() catch return;
                var buf: [4096]u8 = undefined;
                const n = result.stream.read(&buf) catch return;
                _ = result.stream.write(buf[0..n]) catch return;
                result.stream.close();
            }
        }
    };
    const t = std.Thread.spawn(.{}, EchoThread.run, .{pair.server}) catch return;

    for (1..4) |svc| {
        var cs = try pair.client.openStream(@intCast(svc));
        var msg_buf: [32]u8 = undefined;
        const msg = std.fmt.bufPrint(&msg_buf, "svc-{}", .{svc}) catch "?";
        _ = try cs.write(msg);
        var buf: [256]u8 = undefined;
        const n = try cs.read(&buf);
        try std.testing.expectEqualStrings(msg, buf[0..n]);
        cs.close();
    }
    t.join();

    try std.testing.expectEqual(@as(usize, 3), pair.client.numServices());
}

test "smux accept then close" {
    if (@import("builtin").os.tag == .freestanding) return;
    const pair = try smuxPair();
    defer pair.client.deinit();

    // Accept in background — will block.
    const AcceptThread = struct {
        fn run(server: *ServiceMux(TestRt)) void {
            _ = server.acceptStream() catch {};
        }
    };
    const t = std.Thread.spawn(.{}, AcceptThread.run, .{pair.server}) catch return;

    TestRt.sleepMs(200);
    pair.server.close();
    t.join();
    pair.server.deinit();
    // If we reach here, close() unblocked acceptStream.
}
