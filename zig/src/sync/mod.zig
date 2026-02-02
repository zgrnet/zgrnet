//! Synchronization primitives for zgrnet.
//!
//! This module provides:
//! - `Channel`: Generic bounded MPMC channel
//! - `ReadySignal`: Simple ready signal (like Go's close(chan struct{}))

pub const channel = @import("channel.zig");
pub const Channel = channel.Channel;
pub const ReadySignal = channel.ReadySignal;

test {
    _ = channel;
}
