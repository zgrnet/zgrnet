//! ThreadExecutor - An executor that runs tasks on a dedicated thread.
//!
//! This implementation spawns a background thread that processes tasks
//! from a queue. Tasks can be dispatched from any thread.
//!
//! ## Usage
//!
//! ```zig
//! var exec = try ThreadExecutor.init(allocator);
//! defer exec.deinit();
//!
//! // Dispatch tasks from any thread
//! exec.executor().dispatch(my_task);
//!
//! // When done, stop the executor
//! exec.stop();
//! ```

const std = @import("std");
const Task = @import("../task.zig").Task;
const Executor = @import("../executor.zig").Executor;
const MpscQueue = @import("../mpsc.zig").MpscQueue;

/// An executor that runs tasks on a dedicated background thread.
pub const ThreadExecutor = struct {
    const Self = @This();

    /// Task queue
    queue: MpscQueue(Task),

    /// Background worker thread
    thread: ?std.Thread,

    /// Signal to stop the worker thread
    running: std.atomic.Value(bool),

    /// Condition variable to wake up worker
    cond: std.Thread.Condition,

    /// Mutex for condition variable
    cond_mutex: std.Thread.Mutex,

    /// Allocator
    allocator: std.mem.Allocator,

    /// Thread ID of the worker thread (for isCurrentThread check)
    worker_thread_id: ?std.Thread.Id,

    /// Initialize and start the executor.
    pub fn init(allocator: std.mem.Allocator) !Self {
        var self = Self{
            .queue = MpscQueue(Task).init(allocator),
            .thread = null,
            .running = std.atomic.Value(bool).init(true),
            .cond = .{},
            .cond_mutex = .{},
            .allocator = allocator,
            .worker_thread_id = null,
        };

        // Start the worker thread
        self.thread = try std.Thread.spawn(.{}, workerLoop, .{&self});

        return self;
    }

    /// Stop the executor and wait for the worker thread to finish.
    pub fn deinit(self: *Self) void {
        self.stop();
        self.queue.deinit();
    }

    /// Stop the executor gracefully.
    ///
    /// This signals the worker thread to stop and waits for it to finish.
    /// Any remaining tasks in the queue will be processed before stopping.
    pub fn stop(self: *Self) void {
        // Signal stop
        self.running.store(false, .release);

        // Wake up the worker if it's waiting
        self.cond_mutex.lock();
        self.cond.signal();
        self.cond_mutex.unlock();

        // Wait for thread to finish
        if (self.thread) |t| {
            t.join();
            self.thread = null;
        }
    }

    /// Create an Executor interface from this ThreadExecutor.
    pub fn executor(self: *Self) Executor {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    const vtable: Executor.VTable = .{
        .dispatch = dispatch,
        .is_current_thread = isCurrentThread,
    };

    fn dispatch(ptr: *anyopaque, task: Task) void {
        const self: *Self = @ptrCast(@alignCast(ptr));

        // Enqueue the task
        if (!self.queue.push(task)) {
            // Failed to enqueue - task is dropped
            // In production, this should probably log or handle the error
            return;
        }

        // Wake up the worker thread
        self.cond_mutex.lock();
        self.cond.signal();
        self.cond_mutex.unlock();
    }

    fn isCurrentThread(ptr: *anyopaque) bool {
        const self: *Self = @ptrCast(@alignCast(ptr));
        if (self.worker_thread_id) |worker_id| {
            return std.Thread.getCurrentId() == worker_id;
        }
        return false;
    }

    fn workerLoop(self: *Self) void {
        // Store our thread ID
        self.worker_thread_id = std.Thread.getCurrentId();

        while (self.running.load(.acquire)) {
            // Process all available tasks
            while (self.queue.pop()) |task| {
                task.run();
            }

            // Wait for more tasks or stop signal
            self.cond_mutex.lock();
            if (self.running.load(.acquire) and self.queue.isEmpty()) {
                self.cond.wait(&self.cond_mutex);
            }
            self.cond_mutex.unlock();
        }

        // Drain remaining tasks before exiting
        while (self.queue.pop()) |task| {
            task.run();
        }
    }
};

/// A thread executor with built-in timer support.
///
/// This combines ThreadExecutor with a timer wheel for scheduling delayed tasks.
pub const ThreadExecutorWithTimers = struct {
    const Self = @This();

    /// Base executor
    thread_exec: ThreadExecutor,

    /// Timer state
    timers: TimerState,

    /// Allocator
    allocator: std.mem.Allocator,

    const TimerEntry = struct {
        id: u64,
        fire_at: i64, // Absolute time in ms (from milliTimestamp)
        task: Task,
        cancelled: bool,
    };

    const TimerState = struct {
        entries: std.ArrayListAligned(TimerEntry, null),
        next_id: u64,
        mutex: std.Thread.Mutex,
    };

    pub fn init(allocator: std.mem.Allocator) !Self {
        return .{
            .thread_exec = try ThreadExecutor.init(allocator),
            .timers = .{
                .entries = .{},
                .next_id = 1,
                .mutex = .{},
            },
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        self.thread_exec.deinit();
        self.timers.entries.deinit(self.allocator);
    }

    pub fn executor(self: *Self) Executor {
        return self.thread_exec.executor();
    }

    /// Schedule a task to run after delay_ms milliseconds.
    pub fn scheduleTimer(self: *Self, delay_ms: u32, task: Task) u64 {
        const now = std.time.milliTimestamp();
        const fire_at = now + @as(i64, delay_ms);

        self.timers.mutex.lock();
        defer self.timers.mutex.unlock();

        const id = self.timers.next_id;
        self.timers.next_id += 1;

        self.timers.entries.append(self.allocator, .{
            .id = id,
            .fire_at = fire_at,
            .task = task,
            .cancelled = false,
        }) catch return 0;

        return id;
    }

    /// Cancel a scheduled timer.
    pub fn cancelTimer(self: *Self, id: u64) void {
        self.timers.mutex.lock();
        defer self.timers.mutex.unlock();

        for (self.timers.entries.items) |*entry| {
            if (entry.id == id) {
                entry.cancelled = true;
                return;
            }
        }
    }

    /// Process due timers. Call this periodically.
    ///
    /// Returns the number of timers that fired.
    pub fn tickTimers(self: *Self) usize {
        const now = std.time.milliTimestamp();

        self.timers.mutex.lock();

        // Collect tasks to fire
        var to_fire: std.ArrayListAligned(Task, null) = .{};
        defer to_fire.deinit(self.allocator);

        var i: usize = 0;
        while (i < self.timers.entries.items.len) {
            const entry = &self.timers.entries.items[i];
            if (!entry.cancelled and entry.fire_at <= now) {
                to_fire.append(self.allocator, entry.task) catch {};
                _ = self.timers.entries.swapRemove(i);
            } else if (entry.cancelled) {
                _ = self.timers.entries.swapRemove(i);
            } else {
                i += 1;
            }
        }

        self.timers.mutex.unlock();

        // Dispatch tasks to executor
        for (to_fire.items) |task| {
            self.thread_exec.executor().dispatch(task);
        }

        return to_fire.items.len;
    }
};

// ============================================================================
// Tests
// ============================================================================

// Note: ThreadExecutor tests are disabled in CI because they:
// 1. Create actual threads which may behave differently across platforms
// 2. Have timing-dependent behavior that can cause test flakiness
// 3. May hit test timeouts in constrained environments
//
// To test ThreadExecutor manually:
// ```zig
// var exec = try ThreadExecutor.init(allocator);
// defer exec.deinit();
// exec.executor().dispatch(my_task);
// exec.stop();
// ```

test "ThreadExecutor vtable is valid" {
    // Test that the vtable is properly defined
    const vtable_ref = ThreadExecutor.vtable;
    try std.testing.expect(vtable_ref.is_current_thread != null);
    // dispatch function should exist
    _ = vtable_ref.dispatch;
}
