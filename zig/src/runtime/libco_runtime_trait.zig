//! libco_runtime_trait.zig - embed-zig Runtime trait implementation using libco
//!
//! This provides an alternative Runtime implementation that uses libco's M:N
//! coroutine scheduling instead of OS threads (std.Thread).
//!
//! Key differences from StdRuntime:
//! - Thread is implemented as a libco coroutine
//! - All coroutines in one OS thread share the same scheduler
//! - Context switch is ~50-100ns vs ~1-10μs for OS threads

const std = @import("std");
const libco = @import("libco_runtime.zig");

/// LibcoRuntime implements the embed-zig Runtime trait
/// This can be used as: `KcpConn(LibcoRuntime)` instead of `KcpConn(StdRuntime)`
pub const LibcoRuntime = struct {
    // =============================================================================
    // Time - same as std (using system time)
    // =============================================================================
    pub const Time = struct {
        pub fn nowMs() i64 {
            return std.time.milliTimestamp();
        }

        pub fn sleepMs(ms: i64) void {
            if (ms <= 0) return;

            // If called from within a coroutine, yield instead of blocking
            if (libco.self()) |_| {
                // Yield multiple times to approximate sleep duration
                // In production: use scheduler-aware sleep
                const yield_count = @as(u32, @intCast(@min(ms, 100)));
                for (0..yield_count) |_| {
                    libco.yield();
                }
            } else {
                // Called from main thread, use OS sleep
                std.time.sleep(@as(u64, @intCast(ms)) * std.time.ns_per_ms);
            }
        }
    };

    // =============================================================================
    // Thread - implemented using libco coroutines
    // =============================================================================
    pub const Thread = struct {
        co: *libco.Coroutine,
        started: std.atomic.Value(bool),
        completed: std.atomic.Value(bool),

        /// Spawn a new coroutine
        pub fn spawn(comptime _: anytype, comptime f: anytype, args: anytype) !Thread {
            // Ensure libco is initialized
            libco.initThread();

            // Create wrapper that calls the actual function
            const Context = struct {
                fn entry(arg: ?*anyopaque) callconv(.C) ?*anyopaque {
                    const ctx: *@TypeOf(args) = @ptrCast(@alignCast(arg.?));
                    @call(.auto, f, ctx.*);
                    return null;
                }
            };

            const co = try libco.create(Context.entry, @ptrCast(&args));

            var thread = Thread{
                .co = co,
                .started = std.atomic.Value(bool).init(false),
                .completed = std.atomic.Value(bool).init(false),
            };

            // Immediately enqueue to scheduler if available
            if (libco.threadScheduler()) |sched| {
                libco.schedulerEnqueue(sched, co);
            } else {
                // Create scheduler if none exists
                const sched = try libco.schedulerCreate();
                libco.schedulerEnqueue(sched, co);
                // Note: caller must run scheduler or we have leak
            }

            return thread;
        }

        /// Wait for coroutine to complete
        pub fn join(self: *Thread) void {
            // Poll until completed
            while (!self.completed.load(.acquire)) {
                if (libco.self()) |_| {
                    libco.yield();
                } else {
                    std.time.sleep(1 * std.time.ns_per_ms);
                }
            }
            libco.release(self.co);
        }

        /// Detach (coroutine will clean itself up)
        pub fn detach(self: *Thread) void {
            self.completed.store(true, .release);
            // Note: actual cleanup happens after completion
        }
    };

    // =============================================================================
    // Mutex - use std.Thread.Mutex (coroutine-safe in single-threaded scheduler)
    // =============================================================================
    pub const Mutex = std.Thread.Mutex;

    // =============================================================================
    // Condition - use std.Thread.Condition
    // Note: This may need custom implementation for coroutine-aware waiting
    // =============================================================================
    pub const Condition = std.Thread.Condition;

    // =============================================================================
    // Atomic - use std.atomic.Value directly
    // =============================================================================
    pub fn Atomic(comptime T: type) type {
        return std.atomic.Value(T);
    }

    // =============================================================================
    // Allocator - use std.heap.c_allocator or page_allocator
    // =============================================================================
    pub const Allocator = std.mem.Allocator;

    // Global allocator getter
    pub fn allocator() Allocator {
        return std.heap.c_allocator;
    }

    // =============================================================================
    // Log - use std.log
    // =============================================================================
    pub const Log = struct {
        pub fn debug(comptime fmt: []const u8, args: anytype) void {
            std.log.debug(fmt, args);
        }

        pub fn info(comptime fmt: []const u8, args: anytype) void {
            std.log.info(fmt, args);
        }

        pub fn warn(comptime fmt: []const u8, args: anytype) void {
            std.log.warn(fmt, args);
        }

        pub fn err(comptime fmt: []const u8, args: anytype) void {
            std.log.err(fmt, args);
        }
    };

    // =============================================================================
    // Scheduler management
    // =============================================================================

    /// Initialize libco for current thread
    pub fn init() void {
        libco.initThread();
    }

    /// Run scheduler until all coroutines complete
    pub fn runScheduler(timeout_ms: i32) i32 {
        if (libco.threadScheduler()) |sched| {
            return libco.schedulerRun(sched, timeout_ms);
        }
        return 0;
    }

    /// Run one scheduler iteration
    pub fn runSchedulerOnce() i32 {
        if (libco.threadScheduler()) |sched| {
            return libco.schedulerRunOnce(sched);
        }
        return 0;
    }
};

// =============================================================================
// Tests
// =============================================================================

test "LibcoRuntime time operations" {
    const rt = LibcoRuntime;

    const start = rt.Time.nowMs();
    rt.Time.sleepMs(10);
    const end = rt.Time.nowMs();

    try std.testing.expect(end >= start);
}

test "LibcoRuntime thread spawning" {
    const rt = LibcoRuntime;
    rt.init();

    var counter: u64 = 0;
    const Worker = struct {
        fn run(ptr: *u64) void {
            ptr.* = 42;
        }
    };

    var thread = try rt.Thread.spawn(.{}, Worker.run, .{&counter});

    // Need to run scheduler for coroutine to execute
    _ = rt.runSchedulerOnce();

    thread.join();

    try std.testing.expectEqual(counter, 42);
}

test "LibcoRuntime atomic operations" {
    const rt = LibcoRuntime;

    var value = rt.Atomic(u64).init(0);

    _ = value.fetchAdd(1, .monotonic);
    _ = value.fetchAdd(1, .monotonic);

    try std.testing.expectEqual(value.load(.monotonic), 2);
}

test "LibcoRuntime mutex" {
    const rt = LibcoRuntime;

    var mutex = rt.Mutex{};
    var counter: u64 = 0;

    mutex.lock();
    counter += 1;
    mutex.unlock();

    try std.testing.expectEqual(counter, 1);
}

// =============================================================================
// Multi-threaded M:N Scheduler Pool (for production use)
// =============================================================================

/// LibcoSchedulerPool provides multi-threaded M:N scheduling
/// M coroutines distributed across N OS threads
pub const LibcoSchedulerPool = struct {
    const Self = @This();

    allocator: std.mem.Allocator,
    pool: libco.SchedulerPool,

    /// Initialize with N OS threads
    pub fn init(allocator: std.mem.Allocator, num_threads: usize) !Self {
        return Self{
            .allocator = allocator,
            .pool = try libco.SchedulerPool.init(allocator, num_threads),
        };
    }

    /// Shutdown pool
    pub fn deinit(self: *Self) void {
        self.pool.deinit();
    }

    /// Spawn a coroutine in the pool
    pub fn spawn(self: *Self, comptime f: anytype, args: anytype) !void {
        const Context = struct {
            fn entry(arg: ?*anyopaque) callconv(.C) ?*anyopaque {
                const ctx: *@TypeOf(args) = @ptrCast(@alignCast(arg.?));
                @call(.auto, f, ctx.*);
                return null;
            }
        };

        const co = try libco.create(Context.entry, @ptrCast(&args));
        self.pool.enqueue(co);
    }
};

test "LibcoSchedulerPool M:N scheduling" {
    const allocator = std.testing.allocator;

    var pool = try LibcoSchedulerPool.init(allocator, 4); // 4 OS threads
    defer pool.deinit();

    var counter = std.atomic.Value(u64).init(0);

    const Worker = struct {
        fn run(ptr: *std.atomic.Value(u64)) void {
            for (0..1000) |_| {
                _ = ptr.fetchAdd(1, .monotonic);
            }
        }
    };

    // Spawn 100 coroutines across 4 threads
    for (0..100) |_| {
        try pool.spawn(Worker.run, .{&counter});
    }

    // Wait for completion (poll)
    var attempts: u32 = 0;
    while (counter.load(.monotonic) < 100 * 1000 and attempts < 1000) : (attempts += 1) {
        std.time.sleep(10 * std.time.ns_per_ms);
    }

    try std.testing.expectEqual(counter.load(.monotonic), 100 * 1000);
}
