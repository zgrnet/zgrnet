//! zgrnet Runtime — thin shim over embed-zig's std_impl.runtime.
//!
//! Re-exports everything from std_impl.runtime and adds features
//! that embed-zig's std runtime does not yet provide natively.
//! These are patched in via patches/embed-zig-notify.patch:
//!   - Condition.timedWait
//!   - sleepMs
//!   - Notify (pipe-based lightweight event notification)
//!
//! Once embed-zig adopts these upstream, this file can be deleted
//! and all imports replaced with `@import("std_impl").runtime`.

const std_impl = @import("std_impl");
const base = std_impl.runtime;

pub const Mutex = base.Mutex;
pub const Condition = base.Condition;
pub const Thread = base.Thread;
pub const Notify = base.Notify;
pub const nowMs = base.nowMs;
pub const sleepMs = base.sleepMs;
pub const getCpuCount = base.getCpuCount;
