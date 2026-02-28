//! libco_runtime.zig - Zig FFI wrapper for libco-mini
//!
//! Provides coroutine and M:N scheduler functionality based on Tencent libco.
const std = @import("std");

// C API declarations - using libco-mini wrapper
pub const c = @cImport({
    @cInclude("third_party/libco/libco_mini.h");
});

// Re-export opaque types
pub const Coroutine = c.co_coroutine_t;
pub const Scheduler = c.co_scheduler_t;

/// Error types for libco operations
pub const Error = error{
    CreateFailed,
    ResumeFailed,
    SchedulerCreateFailed,
    InvalidState,
    OutOfMemory,
};

/// Thread-local storage for initialization state
threadlocal var thread_inited: bool = false;

/// Initialize libco for current thread (call once per thread)
pub fn initThread() void {
    if (!thread_inited) {
        c.co_init_thread();
        thread_inited = true;
    }
}

/// Check if libco is initialized for current thread
pub fn threadInited() bool {
    return c.co_thread_inited() != 0;
}

/// Get current coroutine (null if called from main thread)
pub fn self() ?*Coroutine {
    const ptr = c.co_self();
    return if (ptr) @ptrCast(ptr) else null;
}

/// Coroutine entry function type
pub const RoutineFn = *const fn (?*anyopaque) callconv(.C) ?*anyopaque;

/// Create a new coroutine
/// The coroutine starts in suspended state, use resume() to start
pub fn create(routine: RoutineFn, arg: ?*anyopaque) Error!*Coroutine {
    var co: ?*Coroutine = null;
    const rc = c.co_create(&co, @ptrCast(routine), arg);
    if (rc != 0 or co == null) {
        return error.CreateFailed;
    }
    return co.?;
}

/// Resume a suspended coroutine
/// Returns true if coroutine completed, false if yielded
pub fn resumeCo(co: *Coroutine) Error!bool {
    const rc = c.co_resume(co);
    if (rc < 0) {
        return error.ResumeFailed;
    }
    return rc == 1; // 1 = completed, 0 = yielded
}

/// Yield control from current coroutine back to scheduler
pub fn yield() void {
    c.co_yield();
}

/// Release a coroutine and free its resources
/// Do not call on running coroutine
pub fn release(co: *Coroutine) void {
    c.co_release(co);
}

/// Reset a coroutine to initial state (reuse stack)
pub fn reset(co: *Coroutine) Error!void {
    const rc = c.co_reset(co);
    if (rc != 0) {
        return error.InvalidState;
    }
}

/// Create a scheduler for current thread
pub fn schedulerCreate() Error!*Scheduler {
    if (!thread_inited) {
        initThread();
    }

    const sched = c.co_scheduler_create();
    if (sched == null) {
        return error.SchedulerCreateFailed;
    }
    return sched.?;
}

/// Destroy scheduler (must have no running coroutines)
pub fn schedulerDestroy(sched: *Scheduler) void {
    c.co_scheduler_destroy(sched);
}

/// Enqueue a coroutine to scheduler's ready queue
pub fn schedulerEnqueue(sched: *Scheduler, co: *Coroutine) void {
    c.co_scheduler_enqueue(sched, co);
}

/// Run scheduler until all coroutines complete or timeout (ms)
/// Returns number of remaining coroutines (0 = all completed)
pub fn schedulerRun(sched: *Scheduler, timeout_ms: i32) i32 {
    return c.co_scheduler_run(sched, timeout_ms);
}

/// Run one iteration of scheduler
/// Returns number of coroutines still ready/running
pub fn schedulerRunOnce(sched: *Scheduler) i32 {
    return c.co_scheduler_run_once(sched);
}

/// Get number of pending/running coroutines in scheduler
pub fn schedulerCount(sched: *Scheduler) i32 {
    return c.co_scheduler_count(sched);
}

/// Get scheduler for current thread (null if not created)
pub fn threadScheduler() ?*Scheduler {
    const ptr = c.co_thread_scheduler();
    return if (ptr) @ptrCast(ptr) else null;
}

/// Set scheduler for current thread
pub fn setThreadScheduler(sched: ?*Scheduler) void {
    c.co_set_thread_scheduler(sched);
}

/// Get current time in milliseconds
pub fn nowMs() i64 {
    return c.co_now_ms();
}

/// Sleep/yield for specified milliseconds
pub fn sleepMs(ms: i32) void {
    c.co_sleep_ms(ms);
}

// =============================================================================
// High-level abstractions
// =============================================================================

/// SchedulerPool implements M:N scheduling across multiple OS threads
/// M coroutines are distributed across N OS threads
pub const SchedulerPool = struct {
    const Self = @This();

    allocator: std.mem.Allocator,
    threads: []std.Thread,
    schedulers: []*Scheduler,
    shutdown: std.atomic.Value(bool),

    /// Initialize pool with N OS threads
    pub fn init(allocator: std.mem.Allocator, num_threads: usize) Error!Self {
        const threads = try allocator.alloc(std.Thread, num_threads);
        errdefer allocator.free(threads);

        const schedulers = try allocator.alloc(*Scheduler, num_threads);
        errdefer allocator.free(schedulers);

        var shutdown = std.atomic.Value(bool).init(false);

        for (0..num_threads) |i| {
            // Create scheduler for this thread
            schedulers[i] = schedulerCreate() catch |err| {
                // Cleanup already created schedulers
                for (0..i) |j| {
                    schedulerDestroy(schedulers[j]);
                }
                allocator.free(schedulers);
                allocator.free(threads);
                return err;
            };

            // Spawn OS thread that will run scheduler
            threads[i] = std.Thread.spawn(.{}, schedulerThread, .{
                schedulers[i],
                &shutdown,
            }) catch |err| {
                // Cleanup
                for (0..i) |j| {
                    threads[j].join();
                    schedulerDestroy(schedulers[j]);
                }
                schedulerDestroy(schedulers[i]);
                allocator.free(schedulers);
                allocator.free(threads);
                return if (err == error.OutOfMemory) error.OutOfMemory else error.SchedulerCreateFailed;
            };
        }

        return Self{
            .allocator = allocator,
            .threads = threads,
            .schedulers = schedulers,
            .shutdown = shutdown,
        };
    }

    /// Shutdown pool and free resources
    pub fn deinit(self: *Self) void {
        // Signal all threads to shutdown
        self.shutdown.store(true, .release);

        // Wait for all threads
        for (self.threads) |t| {
            t.join();
        }

        // Destroy schedulers
        for (self.schedulers) |s| {
            schedulerDestroy(s);
        }

        self.allocator.free(self.schedulers);
        self.allocator.free(self.threads);
    }

    /// Enqueue a coroutine to one of the schedulers (round-robin)
    pub fn enqueue(self: *Self, co: *Coroutine) void {
        // Simple round-robin distribution
        // In production: use work-stealing queue
        const idx = @mod(@intFromPtr(co), self.schedulers.len);
        schedulerEnqueue(self.schedulers[idx], co);
    }

    /// Thread entry point that runs scheduler
    fn schedulerThread(sched: *Scheduler, shutdown: *std.atomic.Value(bool)) void {
        // Set thread-local scheduler
        setThreadScheduler(sched);

        // Run until shutdown
        while (!shutdown.load(.acquire)) {
            const remaining = schedulerRunOnce(sched);

            // If no work, yield to prevent busy loop
            if (remaining == 0) {
                std.time.sleep(1 * std.time.ns_per_ms); // 1ms
            }
        }

        // Drain remaining work
        _ = schedulerRun(sched, 1000);
    }
};

// =============================================================================
// Tests
// =============================================================================

test "basic coroutine lifecycle" {
    initThread();
    try std.testing.expect(threadInited());

    // Simple worker that sets counter
    var counter: u64 = 0;
    const Worker = struct {
        fn run(arg: ?*anyopaque) callconv(.C) ?*anyopaque {
            const ptr: *u64 = @ptrCast(@alignCast(arg.?));
            ptr.* = 42;
            yield();
            ptr.* += 1;
            return null;
        }
    };

    const co = try create(Worker.run, &counter);
    defer release(co);

    // Initially counter is 0
    try std.testing.expectEqual(counter, 0);

    // Resume coroutine (should set counter to 42 and yield)
    const done1 = try resumeCo(co);
    try std.testing.expect(!done1);
    try std.testing.expectEqual(counter, 42);

    // Resume again (should increment to 43 and complete)
    const done2 = try resumeCo(co);
    try std.testing.expect(done2);
    try std.testing.expectEqual(counter, 43);
}

test "scheduler basic operations" {
    initThread();

    const sched = try schedulerCreate();
    defer schedulerDestroy(sched);

    // Worker that increments counter
    var counter: u64 = 0;
    const Worker = struct {
        fn run(arg: ?*anyopaque) callconv(.C) ?*anyopaque {
            const ptr: *u64 = @ptrCast(@alignCast(arg.?));
            for (0..100) |_| {
                ptr.* += 1;
                yield();
            }
            return null;
        }
    };

    // Create and enqueue coroutines
    const num_coros = 10;
    var cos: [num_coros]*Coroutine = undefined;
    for (0..num_coros) |i| {
        cos[i] = try create(Worker.run, &counter);
        schedulerEnqueue(sched, cos[i]);
    }

    // Run scheduler
    const remaining = schedulerRun(sched, 5000);
    try std.testing.expectEqual(remaining, 0);
    try std.testing.expectEqual(counter, num_coros * 100);

    // Cleanup
    for (cos) |co| {
        release(co);
    }
}

test "M:N scheduler pool" {
    const allocator = std.testing.allocator;

    var pool = try SchedulerPool.init(allocator, 4); // 4 OS threads
    defer pool.deinit();

    // Counter for all workers
    var counter = std.atomic.Value(u64).init(0);

    const Worker = struct {
        fn run(arg: ?*anyopaque) callconv(.C) ?*anyopaque {
            const ptr: *std.atomic.Value(u64) = @ptrCast(@alignCast(arg.?));
            for (0..1000) |_| {
                _ = ptr.fetchAdd(1, .monotonic);
                yield();
            }
            return null;
        }
    };

    // Create many coroutines
    const num_coros = 100;
    var cos: [num_coros]*Coroutine = undefined;
    for (0..num_coros) |i| {
        cos[i] = try create(Worker.run, &counter);
        pool.enqueue(cos[i]);
    }

    // Wait for all to complete (poll for completion)
    var attempts: u32 = 0;
    while (counter.load(.monotonic) < num_coros * 1000 and attempts < 1000) : (attempts += 1) {
        std.time.sleep(10 * std.time.ns_per_ms);
    }

    const final_count = counter.load(.monotonic);
    try std.testing.expectEqual(final_count, num_coros * 1000);

    // Cleanup
    for (cos) |co| {
        release(co);
    }
}

test "yield from outside coroutine (no-op)" {
    // Calling yield from main thread should not crash
    yield();
}

test "time functions" {
    const start = nowMs();
    sleepMs(10);
    const end = nowMs();

    try std.testing.expect(end >= start);
}
