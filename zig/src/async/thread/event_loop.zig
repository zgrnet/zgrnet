//! EventLoop - A single-threaded event loop executor.
//!
//! This executor is designed to be driven by an external event source.
//! Tasks are queued and processed when `tick()` is called, making it
//! suitable for integration with platform event loops (libuv, io_uring, etc.)
//!
//! ## Usage Patterns
//!
//! ### Standalone (poll-based)
//! ```zig
//! var loop = EventLoop.init(allocator);
//! defer loop.deinit();
//!
//! // In your main loop
//! while (running) {
//!     loop.tick();  // Process pending tasks
//!     // ... do other work, sleep, etc.
//! }
//! ```
//!
//! ### With platform event loop (e.g., libuv)
//! ```c
//! // C side - call Zig when event loop is idle
//! void on_idle(uv_idle_t* handle) {
//!     zig_event_loop_tick(loop);
//! }
//! ```
//!
//! ### With coroutines (conceptual)
//! The EventLoop can be used as a scheduler for cooperative tasks.
//! Each "coroutine" is just a state machine that yields by returning
//! from its handler and gets resumed by dispatching another task.

const std = @import("std");
const Task = @import("../task.zig").Task;
const Executor = @import("../executor.zig").Executor;
const TimerService = @import("../timer.zig").TimerService;
const TimerHandle = @import("../timer.zig").TimerHandle;
const MpscQueue = @import("../mpsc.zig").MpscQueue;

/// A single-threaded event loop.
///
/// All tasks run on the thread that calls `tick()`.
/// `dispatch()` is thread-safe and can be called from any thread.
pub const EventLoop = struct {
    const Self = @This();

    /// Task queue (thread-safe for dispatch from other threads)
    tasks: MpscQueue(Task),

    /// Timer state
    timers: TimerState,

    /// Allocator
    allocator: std.mem.Allocator,

    /// Whether the loop is running
    running: bool,

    /// Current time in milliseconds (relative to start)
    current_time_ms: u64,

    /// Start time (from milliTimestamp)
    start_time: i64,

    const TimerEntry = struct {
        id: u64,
        fire_at: u64, // Relative to start_time
        task: Task,
        cancelled: bool,
    };

    const TimerList = std.ArrayListAligned(TimerEntry, null);

    const TimerState = struct {
        entries: TimerList,
        next_id: u64,
    };

    /// Initialize a new event loop.
    pub fn init(allocator: std.mem.Allocator) Self {
        return .{
            .tasks = MpscQueue(Task).init(allocator),
            .timers = .{
                .entries = .{},
                .next_id = 1,
            },
            .allocator = allocator,
            .running = true,
            .current_time_ms = 0,
            .start_time = std.time.milliTimestamp(),
        };
    }

    /// Deinitialize the event loop.
    pub fn deinit(self: *Self) void {
        self.tasks.deinit();
        self.timers.entries.deinit(self.allocator);
    }

    // ========================================================================
    // Direct dispatch methods (for comptime polymorphism)
    // ========================================================================

    /// Dispatch a task to be executed.
    ///
    /// Direct method - use this for comptime polymorphism (zero overhead).
    pub fn dispatch(self: *Self, task: Task) void {
        _ = self.tasks.push(task);
    }

    /// Dispatch a typed context with a method to be called.
    pub fn dispatchFn(
        self: *Self,
        comptime T: type,
        context: *T,
        comptime method: fn (*T) void,
    ) void {
        self.dispatch(Task.init(T, context, method));
    }

    /// Schedule a task to be executed after a delay.
    ///
    /// Direct method - use this for comptime polymorphism (zero overhead).
    pub fn schedule(self: *Self, delay_ms: u32, task: Task) TimerHandle {
        const id = self.timers.next_id;
        self.timers.next_id += 1;

        const fire_at = self.current_time_ms + delay_ms;

        self.timers.entries.append(self.allocator, .{
            .id = id,
            .fire_at = fire_at,
            .task = task,
            .cancelled = false,
        }) catch return TimerHandle.null_handle;

        return .{ .id = id };
    }

    /// Schedule a typed context with a method to be called after a delay.
    pub fn scheduleFn(
        self: *Self,
        delay_ms: u32,
        comptime T: type,
        context: *T,
        comptime method: fn (*T) void,
    ) TimerHandle {
        return self.schedule(delay_ms, Task.init(T, context, method));
    }

    /// Cancel a scheduled timer.
    ///
    /// Direct method - use this for comptime polymorphism (zero overhead).
    pub fn cancel(self: *Self, handle: TimerHandle) void {
        if (!handle.isValid()) return;

        for (self.timers.entries.items) |*entry| {
            if (entry.id == handle.id) {
                entry.cancelled = true;
                return;
            }
        }
    }

    // ========================================================================
    // vtable-based interfaces (for runtime polymorphism)
    // ========================================================================

    /// Create an Executor interface.
    ///
    /// Use this only when runtime polymorphism is needed.
    pub fn executor(self: *Self) Executor {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &executor_vtable,
        };
    }

    /// Create a TimerService interface.
    ///
    /// Use this only when runtime polymorphism is needed.
    pub fn timerService(self: *Self) TimerService {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &timer_vtable,
        };
    }

    /// Process pending tasks and timers.
    ///
    /// Call this from your main loop or when your platform's event
    /// loop signals that it's idle.
    ///
    /// Returns the number of tasks executed.
    pub fn tick(self: *Self) usize {
        // Update current time
        const now = std.time.milliTimestamp();
        self.current_time_ms = @intCast(@as(u64, @intCast(now - self.start_time)));

        var count: usize = 0;

        // Fire due timers
        count += self.fireTimers();

        // Process tasks
        while (self.tasks.pop()) |task| {
            task.run();
            count += 1;
        }

        return count;
    }

    /// Run the event loop until `stop()` is called.
    ///
    /// This is a convenience method for standalone usage.
    /// For integration with platform event loops, use `tick()` instead.
    pub fn run(self: *Self) void {
        while (self.running) {
            const processed = self.tick();
            if (processed == 0) {
                // Nothing to do, sleep briefly
                std.Thread.sleep(1 * std.time.ns_per_ms);
            }
        }
    }

    /// Stop the event loop.
    pub fn stop(self: *Self) void {
        self.running = false;
    }

    /// Get the current time in milliseconds (relative to loop start).
    pub fn nowMs(self: *Self) u64 {
        return self.current_time_ms;
    }

    /// Check if there are pending tasks or timers.
    pub fn hasPending(self: *Self) bool {
        if (!self.tasks.isEmpty()) return true;
        for (self.timers.entries.items) |entry| {
            if (!entry.cancelled) return true;
        }
        return false;
    }

    // ========================================================================
    // Executor implementation
    // ========================================================================

    const executor_vtable: Executor.VTable = .{
        .dispatch = executorDispatch,
        .is_current_thread = null, // Single-threaded, always "current"
    };

    fn executorDispatch(ptr: *anyopaque, task: Task) void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        _ = self.tasks.push(task);
    }

    // ========================================================================
    // Timer implementation
    // ========================================================================

    const timer_vtable: TimerService.VTable = .{
        .schedule = timerSchedule,
        .cancel = timerCancel,
        .now_ms = timerNowMs,
    };

    fn timerSchedule(ptr: *anyopaque, delay_ms: u32, task: Task) TimerHandle {
        const self: *Self = @ptrCast(@alignCast(ptr));

        const id = self.timers.next_id;
        self.timers.next_id += 1;

        self.timers.entries.append(self.allocator, .{
            .id = id,
            .fire_at = self.current_time_ms + delay_ms,
            .task = task,
            .cancelled = false,
        }) catch return TimerHandle.null_handle;

        return .{ .id = id };
    }

    fn timerCancel(ptr: *anyopaque, handle: TimerHandle) void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        for (self.timers.entries.items) |*entry| {
            if (entry.id == handle.id) {
                entry.cancelled = true;
                return;
            }
        }
    }

    fn timerNowMs(ptr: *anyopaque) u64 {
        const self: *Self = @ptrCast(@alignCast(ptr));
        return self.current_time_ms;
    }

    pub fn fireTimers(self: *Self) usize {
        const now = self.current_time_ms;
        var fired: usize = 0;

        var i: usize = 0;
        while (i < self.timers.entries.items.len) {
            const entry = &self.timers.entries.items[i];
            if (entry.cancelled) {
                _ = self.timers.entries.swapRemove(i);
            } else if (entry.fire_at <= now) {
                entry.task.run();
                _ = self.timers.entries.swapRemove(i);
                fired += 1;
            } else {
                i += 1;
            }
        }

        return fired;
    }
};

/// Coroutine - A cooperative task that can yield and resume.
///
/// This is a pattern for implementing coroutine-like behavior without
/// actual stackful coroutines. Each coroutine is a state machine that:
/// 1. Runs until it needs to wait for something
/// 2. Returns/yields by storing its state
/// 3. Gets resumed by dispatching a task to the executor
///
/// ## Example
/// ```zig
/// const MyCoroutine = struct {
///     state: enum { init, waiting_for_data, processing, done },
///     data: ?[]u8,
///     loop: *EventLoop,
///
///     pub fn start(self: *MyCoroutine) void {
///         self.state = .waiting_for_data;
///         // Simulate async operation - schedule resume after 100ms
///         _ = self.loop.timerService().scheduleFn(100, MyCoroutine, self, resume);
///     }
///
///     pub fn resume(self: *MyCoroutine) void {
///         switch (self.state) {
///             .waiting_for_data => {
///                 self.data = "received";
///                 self.state = .processing;
///                 // Continue processing on next tick
///                 self.loop.executor().dispatchFn(MyCoroutine, self, resume);
///             },
///             .processing => {
///                 // Do processing
///                 self.state = .done;
///             },
///             else => {},
///         }
///     }
/// };
/// ```
pub const Coroutine = struct {
    /// Coroutine state
    pub const State = enum {
        /// Not yet started
        created,
        /// Running/ready to run
        running,
        /// Waiting for something (timer, I/O, etc.)
        suspended,
        /// Finished
        completed,
    };

    state: State,

    pub fn init() Coroutine {
        return .{ .state = .created };
    }
};

// ============================================================================
// Tests
// ============================================================================

test "EventLoop processes tasks" {
    var loop = EventLoop.init(std.testing.allocator);
    defer loop.deinit();

    var counter: u32 = 0;

    const Context = struct {
        count: *u32,

        fn increment(self: *@This()) void {
            self.count.* += 1;
        }
    };

    var ctx = Context{ .count = &counter };

    // Dispatch tasks
    loop.executor().dispatchFn(Context, &ctx, Context.increment);
    loop.executor().dispatchFn(Context, &ctx, Context.increment);

    try std.testing.expectEqual(@as(u32, 0), counter);

    // Tick once
    const processed = loop.tick();

    try std.testing.expectEqual(@as(usize, 2), processed);
    try std.testing.expectEqual(@as(u32, 2), counter);
}

test "EventLoop timers fire when time advances" {
    var loop = EventLoop.init(std.testing.allocator);
    defer loop.deinit();

    var fired: bool = false;

    const Context = struct {
        flag: *bool,

        fn fire(self: *@This()) void {
            self.flag.* = true;
        }
    };

    var ctx = Context{ .flag = &fired };

    // Schedule timer for 50ms
    _ = loop.timerService().scheduleFn(50, Context, &ctx, Context.fire);

    // Tick immediately - timer shouldn't fire (current_time is 0)
    _ = loop.tick();
    try std.testing.expect(!fired);

    // Manually advance time and tick again
    loop.current_time_ms = 100;
    _ = loop.fireTimers();

    try std.testing.expect(fired);
}

test "EventLoop timer cancellation" {
    var loop = EventLoop.init(std.testing.allocator);
    defer loop.deinit();

    var fired: bool = false;

    const Context = struct {
        flag: *bool,

        fn fire(self: *@This()) void {
            self.flag.* = true;
        }
    };

    var ctx = Context{ .flag = &fired };

    const handle = loop.timerService().scheduleFn(50, Context, &ctx, Context.fire);

    // Cancel the timer
    loop.timerService().cancel(handle);

    // Advance time and tick
    loop.current_time_ms = 100;
    _ = loop.fireTimers();

    // Should not have fired
    try std.testing.expect(!fired);
}
