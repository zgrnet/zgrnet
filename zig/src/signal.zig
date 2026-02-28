//! Signal — lightweight one-shot notification (compatibility layer)
//!
//! This is a compatibility layer for embed-zig's Signal type.
//! Use for simple event signaling between threads.

const std = @import("std");

/// Signal — one-shot notification mechanism
///
/// Usage:
/// ```zig
/// var sig = Signal(Rt).init();
/// defer sig.deinit();
///
/// // Waiter:  sig.wait();
/// // Sender:  sig.notify();
/// ```
pub fn Signal(comptime Rt: type) type {
    return struct {
        const Self = @This();

        mutex: Rt.Mutex,
        cond: Rt.Condition,
        signaled: bool,

        /// Initialize a new signal (not signaled)
        pub fn init() Self {
            return .{
                .mutex = Rt.Mutex.init(),
                .cond = Rt.Condition.init(),
                .signaled = false,
            };
        }

        pub fn deinit(self: *Self) void {
            self.cond.deinit();
            self.mutex.deinit();
        }

        /// Wait for signal (blocking). Resets after wake.
        pub fn wait(self: *Self) void {
            self.mutex.lock();
            defer self.mutex.unlock();

            while (!self.signaled) {
                self.cond.wait(&self.mutex);
            }
            self.signaled = false;
        }

        /// Send signal, waking one waiter
        pub fn notify(self: *Self) void {
            self.mutex.lock();
            defer self.mutex.unlock();

            self.signaled = true;
            self.cond.signal();
        }

        /// Send signal, waking all waiters
        pub fn notifyAll(self: *Self) void {
            self.mutex.lock();
            defer self.mutex.unlock();

            self.signaled = true;
            self.cond.broadcast();
        }

        /// Check if signaled without waiting (non-blocking, consumes signal)
        pub fn tryWait(self: *Self) bool {
            self.mutex.lock();
            defer self.mutex.unlock();

            if (self.signaled) {
                self.signaled = false;
                return true;
            }
            return false;
        }
    };
}
