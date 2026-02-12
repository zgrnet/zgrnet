//! zgrnet Runtime — extends embed-zig's std runtime with additional primitives.
//!
//! Adds timedWait on Condition, sleepMs, and nowMs which are needed by
//! KCP Mux and UDP network layer but not provided by embed-zig's minimal runtime.

const std = @import("std");
const std_impl = @import("std_impl");
const base_runtime = std_impl.runtime;

// Re-export Mutex unchanged
pub const Mutex = base_runtime.Mutex;

// Re-export spawn unchanged
pub const Options = base_runtime.Options;
pub const TaskFn = base_runtime.TaskFn;
pub const spawn = base_runtime.spawn;

/// Condition — extends base runtime Condition with timedWait.
pub const Condition = struct {
    inner: std.Thread.Condition,

    pub const TimedWaitResult = enum { signaled, timed_out };

    pub fn init() Condition {
        return .{ .inner = .{} };
    }

    pub fn deinit(self: *Condition) void {
        _ = self;
    }

    pub fn wait(self: *Condition, mutex: *Mutex) void {
        self.inner.wait(&mutex.inner);
    }

    pub fn timedWait(self: *Condition, mutex: *Mutex, timeout_ns: u64) TimedWaitResult {
        self.inner.timedWait(&mutex.inner, timeout_ns) catch {
            return .timed_out;
        };
        return .signaled;
    }

    pub fn signal(self: *Condition) void {
        self.inner.signal();
    }

    pub fn broadcast(self: *Condition) void {
        self.inner.broadcast();
    }
};

/// Returns current time in milliseconds.
pub fn nowMs() u64 {
    return @intCast(std.time.milliTimestamp());
}

/// Sleep for the given number of milliseconds.
pub fn sleepMs(ms: u32) void {
    std.Thread.sleep(@as(u64, ms) * std.time.ns_per_ms);
}
