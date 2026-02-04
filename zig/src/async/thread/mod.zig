//! Thread-based async runtime implementations.
//!
//! This module provides executor implementations that use std.Thread
//! for background task processing.
//!
//! ## Components
//!
//! - `ThreadExecutor` - Runs tasks on a dedicated background thread
//! - `ThreadExecutorWithTimers` - ThreadExecutor with timer support
//! - `EventLoop` - Single-threaded event loop driven by `tick()` calls
//! - `Coroutine` - State machine pattern for cooperative tasks

const std = @import("std");

pub const executor = @import("executor.zig");
pub const event_loop = @import("event_loop.zig");

// Re-export types
pub const ThreadExecutor = executor.ThreadExecutor;
pub const ThreadExecutorWithTimers = executor.ThreadExecutorWithTimers;
pub const EventLoop = event_loop.EventLoop;
pub const Coroutine = event_loop.Coroutine;

test {
    std.testing.refAllDecls(@This());
}
