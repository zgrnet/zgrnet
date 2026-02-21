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
            self.mutex.lock();
            var it = self.services.iterator();
            while (it.next()) |entry| {
                const se = entry.value_ptr.*;
                se.yamux.deinit();
                se.kcp_conn.deinit();
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
                    return kc.read(buf);
                }
                fn writeFn(transport_ctx: *anyopaque, data: []const u8) anyerror!void {
                    const kc: *KConn = @ptrCast(@alignCast(transport_ctx));
                    _ = try kc.write(data);
                }
            };

            const yamux = try YMux.init(
                self.allocator,
                mode,
                @ptrCast(kcp_conn),
                TransportAdapter.readFn,
                TransportAdapter.writeFn,
            );

            const fwd = try self.allocator.create(ForwardCtxType);
            fwd.* = .{ .ymux = yamux, .svc = service, .smux = self };

            const entry = try self.allocator.create(ServiceEntry);
            entry.* = .{
                .kcp_conn = kcp_conn,
                .yamux = yamux,
                .accept_thread = Rt.Thread.spawn(.{}, acceptForwarder, .{fwd}) catch null,
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
    };
}
