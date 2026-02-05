//! Minicoro-based async runtime benchmarks
//!
//! Benchmarks for CoroScheduler coroutine spawn, yield, and task execution.
//! Requires -Dminicoro=true to enable.

const std = @import("std");
const build_options = @import("build_options");
const async_mod = @import("async");
const minicoro = async_mod.minicoro;

/// Benchmark Minicoro task throughput (spawn + run)
pub fn benchTasks(allocator: std.mem.Allocator) void {
    if (!build_options.enable_minicoro) return;

    // Note: CoroScheduler.executor() runs tasks inline (no queue),
    // so we benchmark using spawn + tick for fair comparison
    var scheduler = minicoro.CoroScheduler.init(allocator);
    defer scheduler.deinit();

    var counter: u64 = 0;
    const task_count: usize = 10_000; // Fewer due to allocation

    const Context = struct {
        count: *u64,

        fn entry(ptr: *anyopaque) void {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.count.* += 1;
        }
    };

    var ctx = Context{ .count = &counter };

    // Benchmark: spawn tasks as coroutines and run them
    const start = std.time.nanoTimestamp();

    for (0..task_count) |_| {
        _ = scheduler.spawn(Context.entry, @ptrCast(&ctx)) catch break;
    }

    // Run all spawned coroutines
    scheduler.runUntilComplete();

    const end = std.time.nanoTimestamp();
    const elapsed_ns: u64 = @intCast(end - start);
    const elapsed_ms = @as(f64, @floatFromInt(elapsed_ns)) / 1_000_000.0;
    const tasks_per_sec = @as(f64, @floatFromInt(counter)) / (@as(f64, @floatFromInt(elapsed_ns)) / 1_000_000_000.0);

    std.debug.print("Minicoro task throughput:   {d:.2} M tasks/sec ({d:.0}ms, {d} tasks)\n", .{
        tasks_per_sec / 1_000_000.0,
        elapsed_ms,
        counter,
    });
}

/// Benchmark Minicoro spawn throughput
pub fn benchSpawn(allocator: std.mem.Allocator) void {
    if (!build_options.enable_minicoro) return;

    const spawn_count: usize = 10_000; // Fewer iterations due to allocation overhead

    var scheduler = minicoro.CoroScheduler.init(allocator);
    defer scheduler.deinit();

    const dummy_entry = struct {
        fn entry(_: *anyopaque) void {
            // Just return immediately
        }
    }.entry;

    const start = std.time.nanoTimestamp();

    for (0..spawn_count) |_| {
        _ = scheduler.spawn(dummy_entry, null) catch break;
    }

    const end = std.time.nanoTimestamp();
    const elapsed_ns: u64 = @intCast(end - start);
    const elapsed_ms = @as(f64, @floatFromInt(elapsed_ns)) / 1_000_000.0;
    const spawns_per_sec = @as(f64, @floatFromInt(spawn_count)) / (@as(f64, @floatFromInt(elapsed_ns)) / 1_000_000_000.0);

    std.debug.print("Minicoro spawn throughput:  {d:.2} K coros/sec ({d:.1}ms, {d} spawns)\n", .{
        spawns_per_sec / 1_000.0,
        elapsed_ms,
        spawn_count,
    });
}

/// Benchmark Minicoro yield/resume cycles
pub fn benchYield(allocator: std.mem.Allocator) void {
    if (!build_options.enable_minicoro) return;

    var scheduler = minicoro.CoroScheduler.init(allocator);
    defer scheduler.deinit();

    var yield_count: u64 = 0;
    const target_yields: u64 = 100_000;

    const YieldContext = struct {
        count: *u64,
        target: u64,

        fn entry(ptr: *anyopaque) void {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            while (self.count.* < self.target) {
                self.count.* += 1;
                minicoro.yield();
            }
        }
    };

    var ctx = YieldContext{
        .count = &yield_count,
        .target = target_yields,
    };

    _ = scheduler.spawn(YieldContext.entry, @ptrCast(&ctx)) catch return;

    const start = std.time.nanoTimestamp();

    // Run until the coroutine completes
    scheduler.runUntilComplete();

    const end = std.time.nanoTimestamp();
    const elapsed_ns: u64 = @intCast(end - start);
    const elapsed_ms = @as(f64, @floatFromInt(elapsed_ns)) / 1_000_000.0;
    const yields_per_sec = @as(f64, @floatFromInt(yield_count)) / (@as(f64, @floatFromInt(elapsed_ns)) / 1_000_000_000.0);

    std.debug.print("Minicoro yield/resume:      {d:.2} M cycles/sec ({d:.1}ms, {d} yields)\n", .{
        yields_per_sec / 1_000_000.0,
        elapsed_ms,
        yield_count,
    });
}

/// Run all minicoro benchmarks
pub fn runAll(allocator: std.mem.Allocator) void {
    if (!build_options.enable_minicoro) {
        std.debug.print("\n[Minicoro disabled - run with -Dminicoro=true to enable]\n", .{});
        return;
    }

    std.debug.print("\n[Minicoro Backend]\n", .{});
    benchTasks(allocator);
    benchSpawn(allocator);
    benchYield(allocator);
}
