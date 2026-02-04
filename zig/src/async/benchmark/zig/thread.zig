//! Thread-based async runtime benchmarks
//!
//! Benchmarks for EventLoop task dispatch and timer scheduling.

const std = @import("std");
const async_mod = @import("async");
const Task = async_mod.Task;
const EventLoop = async_mod.thread.EventLoop;

/// Number of iterations for benchmarks
pub const ITERATIONS: usize = 1_000_000;

/// Number of warmup iterations
pub const WARMUP: usize = 10_000;

/// Benchmark EventLoop task throughput
pub fn benchTasks(allocator: std.mem.Allocator) void {
    var loop = EventLoop.init(allocator);
    defer loop.deinit();

    var counter: u64 = 0;

    const Context = struct {
        count: *u64,

        fn increment(self: *@This()) void {
            self.count.* += 1;
        }
    };

    var ctx = Context{ .count = &counter };

    // Warmup
    for (0..WARMUP) |_| {
        loop.executor().dispatchFn(Context, &ctx, Context.increment);
    }
    _ = loop.tick();
    counter = 0;

    // Benchmark: dispatch + tick
    const start = std.time.nanoTimestamp();

    for (0..ITERATIONS) |_| {
        loop.executor().dispatchFn(Context, &ctx, Context.increment);
    }

    // Process all tasks
    while (loop.tick() > 0) {}

    const end = std.time.nanoTimestamp();
    const elapsed_ns: u64 = @intCast(end - start);
    const elapsed_ms = @as(f64, @floatFromInt(elapsed_ns)) / 1_000_000.0;
    const tasks_per_sec = @as(f64, @floatFromInt(ITERATIONS)) / (@as(f64, @floatFromInt(elapsed_ns)) / 1_000_000_000.0);

    std.debug.print("EventLoop task throughput:  {d:.2} M tasks/sec ({d:.0}ms, {d} tasks)\n", .{
        tasks_per_sec / 1_000_000.0,
        elapsed_ms,
        counter,
    });
}

/// Benchmark EventLoop timer throughput
pub fn benchTimers(allocator: std.mem.Allocator) void {
    var loop = EventLoop.init(allocator);
    defer loop.deinit();

    var counter: u64 = 0;

    const Context = struct {
        count: *u64,

        fn fire(self: *@This()) void {
            self.count.* += 1;
        }
    };

    var ctx = Context{ .count = &counter };

    const timer_count: usize = 100_000;

    // Schedule timers (all fire immediately since delay=0)
    const start = std.time.nanoTimestamp();

    for (0..timer_count) |_| {
        _ = loop.timerService().scheduleFn(0, Context, &ctx, Context.fire);
    }

    // Advance time and fire all timers
    loop.current_time_ms = 1;
    _ = loop.fireTimers();

    const end = std.time.nanoTimestamp();
    const elapsed_ns: u64 = @intCast(end - start);
    const elapsed_ms = @as(f64, @floatFromInt(elapsed_ns)) / 1_000_000.0;
    const timers_per_sec = @as(f64, @floatFromInt(timer_count)) / (@as(f64, @floatFromInt(elapsed_ns)) / 1_000_000_000.0);

    std.debug.print("EventLoop timer throughput: {d:.2} M timers/sec ({d:.1}ms, {d} timers)\n", .{
        timers_per_sec / 1_000_000.0,
        elapsed_ms,
        counter,
    });
}

/// Benchmark Task creation overhead
pub fn benchTaskCreation() void {
    var dummy: u64 = 0;

    const Context = struct {
        val: *u64,

        fn noop(self: *@This()) void {
            self.val.* +%= 1;
        }
    };

    var ctx = Context{ .val = &dummy };

    // Warmup
    for (0..WARMUP) |_| {
        const task = Task.init(Context, &ctx, Context.noop);
        std.mem.doNotOptimizeAway(&task);
    }

    const start = std.time.nanoTimestamp();

    for (0..ITERATIONS) |_| {
        const task = Task.init(Context, &ctx, Context.noop);
        std.mem.doNotOptimizeAway(&task);
    }

    const end = std.time.nanoTimestamp();
    const elapsed_ns: u64 = @intCast(end - start);
    const ns_per_op = @as(f64, @floatFromInt(elapsed_ns)) / @as(f64, @floatFromInt(ITERATIONS));

    std.debug.print("Task creation overhead:     {d:.1} ns/task\n", .{ns_per_op});
}

/// Run all thread-based benchmarks
pub fn runAll(allocator: std.mem.Allocator) void {
    std.debug.print("[Thread Backend - EventLoop]\n", .{});
    benchTasks(allocator);
    benchTimers(allocator);
    benchTaskCreation();
}
