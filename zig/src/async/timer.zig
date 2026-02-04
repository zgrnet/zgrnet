//! Timer - Time-based task scheduling.
//!
//! ## Comptime vs Runtime Polymorphism
//!
//! This module provides both:
//! 1. **Direct methods** on implementations (comptime, zero overhead)
//! 2. **TimerService vtable** for runtime polymorphism (when needed)
//!
//! Prefer using implementations directly with comptime generics:
//! ```zig
//! fn scheduleRetry(timer: anytype, delay_ms: u32, task: Task) TimerHandle {
//!     return timer.schedule(delay_ms, task);
//! }
//! ```
//!
//! ## Required Interface (comptime)
//!
//! Any type implementing TimerService must have:
//! - `schedule(self: *T, delay_ms: u32, task: Task) TimerHandle`
//! - `cancel(self: *T, handle: TimerHandle) void`
//!
//! Optional:
//! - `scheduleFn(...)` - convenience wrapper
//! - `nowMs(self: *T) u64` - current timestamp

const std = @import("std");
const Task = @import("task.zig").Task;

/// Handle to a scheduled timer, used for cancellation.
pub const TimerHandle = struct {
    id: u64,

    /// A null handle representing no timer.
    pub const null_handle: TimerHandle = .{ .id = 0 };

    /// Check if this is a valid (non-null) handle.
    pub fn isValid(self: TimerHandle) bool {
        return self.id != 0;
    }
};

// ============================================================================
// Runtime Polymorphism (vtable-based) - for legacy/FFI use
// ============================================================================

/// TimerService - Runtime polymorphic timer service interface.
///
/// Use this when you need to store timer services of different types in the same
/// variable or pass them through FFI boundaries. For comptime polymorphism,
/// use implementations directly with `anytype`.
pub const TimerService = struct {
    /// Opaque pointer to platform-specific timer service state
    ptr: *anyopaque,
    /// Virtual function table
    vtable: *const VTable,

    pub const VTable = struct {
        schedule: *const fn (ptr: *anyopaque, delay_ms: u32, task: Task) TimerHandle,
        cancel: *const fn (ptr: *anyopaque, handle: TimerHandle) void,
        now_ms: ?*const fn (ptr: *anyopaque) u64 = null,
    };

    /// Schedule a task to be executed after `delay_ms` milliseconds.
    pub fn schedule(self: TimerService, delay_ms: u32, task: Task) TimerHandle {
        return self.vtable.schedule(self.ptr, delay_ms, task);
    }

    /// Schedule a typed context with a method to be called after a delay.
    pub fn scheduleFn(
        self: TimerService,
        delay_ms: u32,
        comptime T: type,
        context: *T,
        comptime method: fn (*T) void,
    ) TimerHandle {
        return self.schedule(delay_ms, Task.init(T, context, method));
    }

    /// Cancel a scheduled timer.
    pub fn cancel(self: TimerService, handle: TimerHandle) void {
        if (handle.isValid()) {
            self.vtable.cancel(self.ptr, handle);
        }
    }

    /// Get the current time in milliseconds.
    pub fn nowMs(self: TimerService) ?u64 {
        if (self.vtable.now_ms) |now_fn| {
            return now_fn(self.ptr);
        }
        return null;
    }

    /// A null timer service that does nothing.
    pub const null_service: TimerService = .{
        .ptr = undefined,
        .vtable = &.{
            .schedule = struct {
                fn noop(_: *anyopaque, _: u32, _: Task) TimerHandle {
                    return TimerHandle.null_handle;
                }
            }.noop,
            .cancel = struct {
                fn noop(_: *anyopaque, _: TimerHandle) void {}
            }.noop,
        },
    };
};

// ============================================================================
// Implementations
// ============================================================================

/// SimpleTimerService - A basic timer service for testing.
///
/// This implementation stores scheduled timers and allows manual advancement
/// of time. Useful for unit testing time-dependent code.
///
/// ## Direct Usage (comptime, zero overhead)
/// ```zig
/// var timer_svc = SimpleTimerService.init(allocator);
/// const handle = timer_svc.schedule(100, my_task);
/// _ = timer_svc.advance(100);
/// ```
///
/// ## Runtime Polymorphism
/// ```zig
/// const ts: TimerService = timer_svc.timerService();
/// ts.schedule(100, my_task);
/// ```
pub const SimpleTimerService = struct {
    const TimerEntry = struct {
        handle: TimerHandle,
        fire_at: u64, // Absolute time in ms
        task: Task,
        cancelled: bool,
    };

    const TimerList = std.ArrayListAligned(TimerEntry, null);
    const TaskList = std.ArrayListAligned(Task, null);

    timers: TimerList,
    allocator: std.mem.Allocator,
    current_time: u64,
    next_id: u64,
    mutex: std.Thread.Mutex,

    pub fn init(allocator: std.mem.Allocator) SimpleTimerService {
        return .{
            .timers = .{},
            .allocator = allocator,
            .current_time = 0,
            .next_id = 1,
            .mutex = .{},
        };
    }

    pub fn deinit(self: *SimpleTimerService) void {
        self.timers.deinit(self.allocator);
    }

    /// Schedule a task to be executed after `delay_ms` milliseconds.
    ///
    /// Direct method - use this for comptime polymorphism.
    pub fn schedule(self: *SimpleTimerService, delay_ms: u32, task: Task) TimerHandle {
        self.mutex.lock();
        defer self.mutex.unlock();

        const handle = TimerHandle{ .id = self.next_id };
        self.next_id += 1;

        self.timers.append(self.allocator, .{
            .handle = handle,
            .fire_at = self.current_time + delay_ms,
            .task = task,
            .cancelled = false,
        }) catch return TimerHandle.null_handle;

        return handle;
    }

    /// Schedule a typed context with a method to be called after a delay.
    pub fn scheduleFn(
        self: *SimpleTimerService,
        delay_ms: u32,
        comptime T: type,
        context: *T,
        comptime method: fn (*T) void,
    ) TimerHandle {
        return self.schedule(delay_ms, Task.init(T, context, method));
    }

    /// Cancel a scheduled timer.
    ///
    /// Direct method - use this for comptime polymorphism.
    pub fn cancel(self: *SimpleTimerService, handle: TimerHandle) void {
        if (!handle.isValid()) return;

        self.mutex.lock();
        defer self.mutex.unlock();

        for (self.timers.items) |*entry| {
            if (entry.handle.id == handle.id) {
                entry.cancelled = true;
                return;
            }
        }
    }

    /// Get the current time in milliseconds.
    ///
    /// Direct method - use this for comptime polymorphism.
    pub fn nowMs(self: *SimpleTimerService) u64 {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.current_time;
    }

    /// Advance time and fire any due timers.
    ///
    /// Returns the number of timers that fired.
    pub fn advance(self: *SimpleTimerService, delta_ms: u64) usize {
        self.mutex.lock();

        self.current_time += delta_ms;
        const now = self.current_time;

        // Collect tasks to fire (we need to release lock before firing)
        var to_fire: TaskList = .{};
        defer to_fire.deinit(self.allocator);

        var i: usize = 0;
        while (i < self.timers.items.len) {
            const entry = &self.timers.items[i];
            if (!entry.cancelled and entry.fire_at <= now) {
                to_fire.append(self.allocator, entry.task) catch {};
                _ = self.timers.swapRemove(i);
            } else {
                i += 1;
            }
        }

        self.mutex.unlock();

        // Fire tasks outside of lock
        for (to_fire.items) |task| {
            task.run();
        }

        return to_fire.items.len;
    }

    /// Get the number of pending (non-cancelled) timers.
    pub fn pendingCount(self: *SimpleTimerService) usize {
        self.mutex.lock();
        defer self.mutex.unlock();

        var count: usize = 0;
        for (self.timers.items) |entry| {
            if (!entry.cancelled) count += 1;
        }
        return count;
    }

    /// Create a TimerService interface from this SimpleTimerService.
    ///
    /// Use this only when runtime polymorphism is needed.
    pub fn timerService(self: *SimpleTimerService) TimerService {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    const vtable: TimerService.VTable = .{
        .schedule = scheduleVtable,
        .cancel = cancelVtable,
        .now_ms = nowMsVtable,
    };

    fn scheduleVtable(ptr: *anyopaque, delay_ms: u32, task: Task) TimerHandle {
        const self: *SimpleTimerService = @ptrCast(@alignCast(ptr));
        return self.schedule(delay_ms, task);
    }

    fn cancelVtable(ptr: *anyopaque, handle: TimerHandle) void {
        const self: *SimpleTimerService = @ptrCast(@alignCast(ptr));
        self.cancel(handle);
    }

    fn nowMsVtable(ptr: *anyopaque) u64 {
        const self: *SimpleTimerService = @ptrCast(@alignCast(ptr));
        return self.nowMs();
    }
};

// ============================================================================
// Tests
// ============================================================================

test "SimpleTimerService direct schedule (comptime)" {
    var timer_svc = SimpleTimerService.init(std.testing.allocator);
    defer timer_svc.deinit();

    var fired: bool = false;

    const Context = struct {
        flag: *bool,
        fn fire(self: *@This()) void {
            self.flag.* = true;
        }
    };

    var ctx = Context{ .flag = &fired };

    // Direct schedule - comptime polymorphism
    const handle = timer_svc.schedule(100, Task.init(Context, &ctx, Context.fire));
    try std.testing.expect(handle.isValid());
    try std.testing.expectEqual(@as(usize, 1), timer_svc.pendingCount());

    // Advance 50ms - timer shouldn't fire yet
    try std.testing.expectEqual(@as(usize, 0), timer_svc.advance(50));
    try std.testing.expect(!fired);

    // Advance another 50ms - timer should fire
    try std.testing.expectEqual(@as(usize, 1), timer_svc.advance(50));
    try std.testing.expect(fired);
}

test "SimpleTimerService direct cancel (comptime)" {
    var timer_svc = SimpleTimerService.init(std.testing.allocator);
    defer timer_svc.deinit();

    var fired: bool = false;

    const Context = struct {
        flag: *bool,
        fn fire(self: *@This()) void {
            self.flag.* = true;
        }
    };

    var ctx = Context{ .flag = &fired };

    const handle = timer_svc.scheduleFn(100, Context, &ctx, Context.fire);

    // Direct cancel
    timer_svc.cancel(handle);

    _ = timer_svc.advance(200);
    try std.testing.expect(!fired);
}

test "SimpleTimerService vtable schedule (runtime)" {
    var timer_svc = SimpleTimerService.init(std.testing.allocator);
    defer timer_svc.deinit();

    const ts = timer_svc.timerService();

    var fired: bool = false;

    const Context = struct {
        flag: *bool,
        fn fire(self: *@This()) void {
            self.flag.* = true;
        }
    };

    var ctx = Context{ .flag = &fired };

    const handle = ts.scheduleFn(100, Context, &ctx, Context.fire);
    try std.testing.expect(handle.isValid());

    _ = timer_svc.advance(100);
    try std.testing.expect(fired);
}

test "SimpleTimerService.nowMs" {
    var timer_svc = SimpleTimerService.init(std.testing.allocator);
    defer timer_svc.deinit();

    try std.testing.expectEqual(@as(u64, 0), timer_svc.nowMs());

    _ = timer_svc.advance(42);

    try std.testing.expectEqual(@as(u64, 42), timer_svc.nowMs());

    // Via vtable
    const ts = timer_svc.timerService();
    try std.testing.expectEqual(@as(?u64, 42), ts.nowMs());
}

test "TimerHandle.null_handle is invalid" {
    try std.testing.expect(!TimerHandle.null_handle.isValid());
    const valid_handle = TimerHandle{ .id = 1 };
    try std.testing.expect(valid_handle.isValid());
}
