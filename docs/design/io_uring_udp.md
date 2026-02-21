# io_uring UDP Transport Design

> Status: Design only — not implemented in this branch.

## Overview

io_uring (Linux 5.1+) provides asynchronous I/O with zero-copy, batched submission/completion,
and kernel-side polling. For UDP, it replaces the epoll + recvmmsg pattern with a ring-buffer
model that eliminates user-kernel context switches for sustained traffic.

## Architecture

```
                  User Space                      Kernel Space
            ┌──────────────────┐            ┌────────────────────┐
            │   Submission Q   │───push───→ │   SQ Ring Buffer   │
            │ (SQE: recv ops)  │            │   (IORING_OP_*)    │
            └──────────────────┘            └────────┬───────────┘
                                                     │ process
            ┌──────────────────┐            ┌────────▼───────────┐
            │  Completion Q    │←──poll───  │   CQ Ring Buffer   │
            │ (CQE: results)   │            │   (len, addr, buf) │
            └──────────────────┘            └────────────────────┘
```

### Submission Queue Entry (SQE) operations

| Operation | Use |
|-----------|-----|
| `IORING_OP_RECVMSG` | Receive one UDP packet with source address |
| `IORING_OP_SENDMSG` | Send one UDP packet to target address |
| `IORING_OP_RECV` | Receive from connected socket (no address) |
| `IORING_OP_SEND` | Send to connected socket (no address) |

For unconnected UDP (our case), `RECVMSG` and `SENDMSG` are needed because
they carry `struct msghdr` which includes the source/destination address.

### Registered Buffers

```c
// Pre-register buffer pool with kernel (avoids per-call copy)
struct iovec bufs[POOL_SIZE];
io_uring_register_buffers(ring, bufs, POOL_SIZE);

// SQE references buffer by index
sqe->buf_index = i;
sqe->flags |= IOSQE_FIXED_FILE | IOSQE_BUFFER_SELECT;
```

Benefits:
- Kernel pins pages once; subsequent I/O uses DMA directly
- Eliminates `copy_from_user`/`copy_to_user` on the data path

### Proposed Integration

```
Current architecture:
  ioLoop thread ──→ recvmmsg(64) ──→ decryptChan ──→ workers ──→ outputChan

io_uring architecture:
  submitter thread ──→ submit 256 RECVMSG SQEs (pre-armed)
  reaper thread    ──→ poll CQ ──→ for each CQE: dispatch to decryptChan
                       ──→ re-submit consumed SQE (refill ring)
```

Key change: the ioLoop no longer blocks in a syscall per batch. Instead:
1. **Submitter** pre-arms N recv operations into the SQ
2. **Reaper** polls CQ (or uses `IORING_ENTER_GETEVENTS`) to harvest completed recvs
3. Each CQE contains the buffer index and data length
4. Reaper wraps data into `packet` struct, sends to existing decryptChan/outputChan
5. Reaper re-submits the consumed SQE to keep the ring full

### Send Path

```
Current: sendToPeer() → encrypt → socket.WriteToUDP()
io_uring: sendToPeer() → encrypt → submit SENDMSG SQE → kernel sends async
```

For sends, io_uring allows fire-and-forget: submit the SQE and move on.
The CQE for sends can be harvested lazily or ignored (error handling via
periodic CQ drain).

## Buffer Management

```
Packet Pool (existing):       io_uring Buffer Ring:
┌──────────────────┐          ┌──────────────────┐
│ sync.Pool / alloc│          │ Registered Bufs   │
│ acquire/release  │          │ (pinned, indexed) │
└──────────────────┘          └──────────────────┘
        │                              │
        ▼                              ▼
  decryptWorker uses buf         kernel fills buf directly
  then releases to pool          reaper maps index → packet
```

Two options:
1. **Dual pool**: io_uring has its own registered buffers; reaper copies into packet pool.
   Simple but adds a copy.
2. **Unified pool**: Register the packet pool's buffers with io_uring.
   Zero-copy but requires fixed-size pool (not `sync.Pool`).

Recommendation: Option 2 for Zig (already uses fixed PacketPool).
Option 1 for Go/Rust initially (sync.Pool is harder to register).

## Kernel Feature Requirements

| Feature | Kernel | Purpose |
|---------|--------|---------|
| io_uring | 5.1 | Base support |
| IORING_OP_RECVMSG | 5.3 | UDP receive with address |
| IORING_OP_SENDMSG | 5.3 | UDP send with address |
| IORING_FEAT_FAST_POLL | 5.7 | Kernel-side poll (no separate epoll) |
| Buffer ring (PROVIDE_BUFFERS) | 5.7 | Kernel-managed buffer selection |
| Registered buffers | 5.1 | Pin user buffers for DMA |
| IORING_SETUP_SQPOLL | 5.1 | Kernel-side SQ polling (no submit syscall) |

Minimum viable: kernel 5.7 for FAST_POLL + buffer ring.

## API Surface Change

```go
// Go
type IOMode int
const (
    IOModePoll    IOMode = iota // epoll/kqueue (current)
    IOModeURing                 // io_uring (Linux 5.7+)
)

func WithIOMode(mode IOMode) Option

// Zig
const IOBackend = union(enum) {
    kqueue: KqueueIO,
    epoll: EpollIO,
    uring: UringIO,  // new
};
```

The `UDP` generic already accepts `IOBackend` as a type parameter.
Adding `UringIO` that implements the same trait is a clean extension.

## Risk Assessment

| Risk | Mitigation |
|------|------------|
| Kernel too old | Runtime detection via `io_uring_probe`; fallback to recvmmsg |
| Container restrictions | Some containers block io_uring (seccomp). Detect and fallback. |
| Complexity | io_uring state machine is complex; start with recv-only, add send later |
| Buffer lifetime | Registered buffers must not be freed while SQEs reference them |
| Error handling | CQE errors need mapping to our error types |

## Implementation Plan (future branch)

1. Zig `UringIO` backend implementing `IOBackend` trait
2. Go `IOURing` backend using `golang.org/x/sys/unix` io_uring wrappers
3. Rust `io-uring` crate integration
4. Benchmark: io_uring vs recvmmsg on sustained 1Mpps load
