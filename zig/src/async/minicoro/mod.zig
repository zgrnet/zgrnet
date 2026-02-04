//! Minicoro-based async runtime implementation.
//!
//! This module provides stackful coroutines via the minicoro C library,
//! allowing code to yield at any point in the call stack.
//!
//! ## Building
//!
//! The minicoro.h header and wrapper.c must be compiled and linked.
//! This is handled automatically by the Zig build system.
//!
//! ## Components
//!
//! - `CoroScheduler` - Coroutine scheduler
//! - `Coroutine` - A managed coroutine handle

const std = @import("std");

pub const scheduler = @import("scheduler.zig");

// Re-export types
pub const CoroScheduler = scheduler.CoroScheduler;
pub const Coroutine = scheduler.Coroutine;
pub const CoroStatus = scheduler.CoroStatus;

/// Yield from the current coroutine.
pub const yield = CoroScheduler.yield;

test {
    std.testing.refAllDecls(@This());
}
