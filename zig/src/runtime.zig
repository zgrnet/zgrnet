//! zgrnet Runtime — thin shim over embed-zig's std_impl.runtime.
//!
//! Re-exports everything from std_impl.runtime and adds two features
//! that embed-zig's std runtime does not yet provide:
//!   - Condition.timedWait (ESP32 runtime has it, std runtime doesn't)
//!   - sleepMs (ESP32 runtime has it, std runtime doesn't)
//!
//! Once embed-zig adds these to std_impl.runtime, this file can be deleted
//! and all imports replaced with `@import("std_impl").runtime`.

const std = @import("std");
const std_impl = @import("std_impl");
const base = std_impl.runtime;

// ============================================================================
// Re-exports from std_impl.runtime (unchanged)
// ============================================================================

pub const Mutex = base.Mutex;
pub const Options = base.Options;
pub const TaskFn = base.TaskFn;
pub const spawn = base.spawn;
pub const Thread = base.Thread;
pub const nowMs = base.nowMs;
pub const getCpuCount = base.getCpuCount;

// ============================================================================
// Condition — re-wraps base Condition to add timedWait
// ============================================================================

/// Condition variable with timedWait support.
/// embed-zig's std runtime Condition only has wait/signal/broadcast.
/// This wrapper adds timedWait using std.Thread.Condition.timedWait.
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

// ============================================================================
// sleepMs — not yet in embed-zig's std runtime (ESP32 has it)
// ============================================================================

/// Sleep for the given number of milliseconds.
pub fn sleepMs(ms: u32) void {
    std.Thread.sleep(@as(u64, ms) * std.time.ns_per_ms);
}
