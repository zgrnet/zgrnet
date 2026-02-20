# yamux + KcpConn Waker Deadlock — Investigation Notes

## Status: BLOCKED

yamux 0.13.8 over AsyncKcpConn deadlocks because Wakers from yamux's internal
poll_read don't properly wake when data arrives from the KCP thread.

## What Works
- yamux over tokio::io::duplex — PASS
- AsyncKcpConn basic read/write — PASS (5 tests)
- futures::channel::mpsc direct — PASS
- KCP data delivery to recv_tx — confirmed (debug prints)

## What Fails
- yamux over AsyncKcpConn — DEADLOCK (client opens, server never accepts)
- Server's futures::AsyncRead::poll_read returns Pending
- Data IS in the recv_rx channel (confirmed by capacity metrics)
- Server poll_read is called repeatedly (timer-based polling) but never sees data

## Root Cause (Suspected)
futures::channel::mpsc::Sender::try_send() from a std::thread may not properly
wake a Waker that was registered by yamux's poll context. The Waker dispatch
mechanism might require the sender to be in an async executor context.

## Fix Options
1. **Duplex bridge**: use tokio::io::duplex between KcpConn and yamux,
   with a bridge task that copies data. This adds one layer of indirection
   but guarantees Waker compatibility.

2. **Custom async channel**: implement a simple channel that stores the Waker
   and calls wake() directly from the sender thread, without relying on
   futures::channel's internal Waker dispatch.

3. **Use tokio::sync::mpsc**: revert to tokio mpsc and use tokio_util::compat
   to convert to futures traits. Investigate why the earlier attempt didn't work.
