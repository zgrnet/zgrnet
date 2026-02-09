//! SimpleTimerService — A basic timer service for testing and simple use cases.
//!
//! Stores scheduled timers and allows manual advancement of time.
//! Uses embed-zig trait.task.Task and TimerHandle types.
//!
//! Used by UDP's timerLoop which calls advance(1) every 1ms.

const std = @import("std");
const trait = @import("trait");

pub const Task = trait.task.Task;
pub const TimerHandle = trait.task.TimerHandle;

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

    /// Cancel a scheduled timer.
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
    pub fn nowMs(self: *SimpleTimerService) u64 {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.current_time;
    }

    /// Advance time and fire any due timers.
    /// Returns the number of timers that fired.
    pub fn advance(self: *SimpleTimerService, delta_ms: u64) usize {
        self.mutex.lock();

        self.current_time += delta_ms;
        const now = self.current_time;

        // Collect tasks to fire (release lock before firing)
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
};
