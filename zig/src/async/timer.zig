//! Timer - Time-based task scheduling.
//!
//! TimerService is a platform-provided interface for scheduling tasks to be
//! executed after a delay. This is essential for protocols like KCP that need
//! to schedule retransmissions.
//!
//! ## Design Principles
//! - Platform agnostic: Platform provides the actual timer implementation
//! - Cancellable: Timers can be cancelled before they fire
//! - Zero allocation in interface: Allocation is platform's responsibility
//!
//! ## Platform Implementation Example
//! The platform could use:
//! - Go: time.AfterFunc
//! - Rust: tokio::time::sleep
//! - C: libuv timers, epoll timerfd, etc.

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

/// TimerService - Platform-provided timer scheduling service.
///
/// This interface allows Zig code to schedule tasks to be executed after
/// a specified delay. The platform is responsible for the actual timing
/// mechanism.
pub const TimerService = struct {
    /// Opaque pointer to platform-specific timer service state
    ptr: *anyopaque,
    /// Virtual function table
    vtable: *const VTable,

    pub const VTable = struct {
        /// Schedule a task to be executed after `delay_ms` milliseconds.
        ///
        /// Returns a handle that can be used to cancel the timer.
        /// The task will be executed on an executor determined by the platform.
        ///
        /// ## Parameters
        /// - `ptr`: The timer service's opaque pointer
        /// - `delay_ms`: Delay in milliseconds before the task executes
        /// - `task`: The task to execute when the timer fires
        ///
        /// ## Returns
        /// A TimerHandle that can be used to cancel the timer.
        schedule: *const fn (ptr: *anyopaque, delay_ms: u32, task: Task) TimerHandle,

        /// Cancel a scheduled timer.
        ///
        /// If the timer has already fired or was already cancelled, this is a no-op.
        ///
        /// ## Parameters
        /// - `ptr`: The timer service's opaque pointer
        /// - `handle`: The handle returned from `schedule`
        cancel: *const fn (ptr: *anyopaque, handle: TimerHandle) void,

        /// Get the current time in milliseconds.
        ///
        /// This should return a monotonic timestamp suitable for use with
        /// protocols like KCP. The actual epoch doesn't matter, only that
        /// it's monotonically increasing.
        ///
        /// Optional: platforms can provide this for protocols that need timestamps.
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
    ///
    /// Returns null if the platform doesn't provide this.
    pub fn nowMs(self: TimerService) ?u64 {
        if (self.vtable.now_ms) |now_fn| {
            return now_fn(self.ptr);
        }
        return null;
    }

    /// A null timer service that does nothing.
    ///
    /// Useful as a placeholder. Scheduled tasks are silently dropped.
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

/// SimpleTimerService - A basic timer service for testing.
///
/// This implementation stores scheduled timers and allows manual advancement
/// of time. Useful for unit testing time-dependent code.
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

    /// Create a TimerService interface from this SimpleTimerService.
    pub fn timerService(self: *SimpleTimerService) TimerService {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
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

    const vtable: TimerService.VTable = .{
        .schedule = schedule,
        .cancel = cancel,
        .now_ms = nowMs,
    };

    fn schedule(ptr: *anyopaque, delay_ms: u32, task: Task) TimerHandle {
        const self: *SimpleTimerService = @ptrCast(@alignCast(ptr));
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

    fn cancel(ptr: *anyopaque, handle: TimerHandle) void {
        const self: *SimpleTimerService = @ptrCast(@alignCast(ptr));
        self.mutex.lock();
        defer self.mutex.unlock();

        for (self.timers.items) |*entry| {
            if (entry.handle.id == handle.id) {
                entry.cancelled = true;
                return;
            }
        }
    }

    fn nowMs(ptr: *anyopaque) u64 {
        const self: *SimpleTimerService = @ptrCast(@alignCast(ptr));
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.current_time;
    }
};

// ============================================================================
// Tests
// ============================================================================

test "SimpleTimerService schedules and fires timers" {
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

    // Schedule a timer for 100ms from now
    const handle = ts.scheduleFn(100, Context, &ctx, Context.fire);
    try std.testing.expect(handle.isValid());
    try std.testing.expectEqual(@as(usize, 1), timer_svc.pendingCount());

    // Advance 50ms - timer shouldn't fire yet
    try std.testing.expectEqual(@as(usize, 0), timer_svc.advance(50));
    try std.testing.expect(!fired);

    // Advance another 50ms - timer should fire
    try std.testing.expectEqual(@as(usize, 1), timer_svc.advance(50));
    try std.testing.expect(fired);
    try std.testing.expectEqual(@as(usize, 0), timer_svc.pendingCount());
}

test "SimpleTimerService cancels timers" {
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

    // Cancel before it fires
    ts.cancel(handle);

    // Advance past the fire time
    _ = timer_svc.advance(200);

    // Should not have fired
    try std.testing.expect(!fired);
}

test "TimerService.nowMs returns current time" {
    var timer_svc = SimpleTimerService.init(std.testing.allocator);
    defer timer_svc.deinit();

    const ts = timer_svc.timerService();

    try std.testing.expectEqual(@as(?u64, 0), ts.nowMs());

    _ = timer_svc.advance(42);

    try std.testing.expectEqual(@as(?u64, 42), ts.nowMs());
}

test "TimerHandle.null_handle is invalid" {
    try std.testing.expect(!TimerHandle.null_handle.isValid());
    const valid_handle = TimerHandle{ .id = 1 };
    try std.testing.expect(valid_handle.isValid());
}
