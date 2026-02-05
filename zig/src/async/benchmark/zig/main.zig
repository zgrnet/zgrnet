//! Zig Async Runtime Benchmarks
//!
//! Compares performance of different async runtime implementations:
//! - Thread-based (EventLoop)
//! - Minicoro-based (CoroScheduler) - requires -Dminicoro=true
//!
//! Run with: zig build async_bench
//! Run with minicoro: zig build async_bench -Dminicoro=true

const std = @import("std");

const thread_bench = @import("thread.zig");
const minicoro_bench = @import("minicoro.zig");

pub fn main() !void {
    std.debug.print("\n", .{});
    std.debug.print("Async Runtime Benchmarks (Zig)\n", .{});
    std.debug.print("==============================\n\n", .{});

    // Get allocator
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Run thread-based benchmarks
    thread_bench.runAll(allocator);

    // Run minicoro benchmarks
    minicoro_bench.runAll(allocator);

    std.debug.print("\n", .{});
}
