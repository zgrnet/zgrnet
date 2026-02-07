//! UDP Network Layer with Noise Protocol
//!
//! This module implements a UDP-based network using the Noise Protocol,
//! with a double-queue architecture matching Go/Rust implementations:
//!
//! ## Architecture
//!
//! ```
//! socket -> ioLoop -> [decryptChan] -> workers -> signal ready
//!                  -> [outputChan] -> readFrom waits -> returns
//! ```
//!
//! - **ioLoop**: Single thread reading from socket, dispatches to both queues
//! - **decryptWorkers**: N threads processing packets in parallel
//! - **readFrom**: Waits for ready signal, returns decrypted data
//!
//! ## Design
//!
//! Uses comptime generics for IOService injection, allowing platform-specific
//! optimizations (kqueue on macOS, epoll on Linux, select fallback).

const std = @import("std");
const posix = std.posix;
const mem = std.mem;
const Allocator = mem.Allocator;
const Thread = std.Thread;
const Mutex = Thread.Mutex;
const Atomic = std.atomic.Value;

const noise = @import("../noise/mod.zig");
const relay_mod = @import("../relay/mod.zig");
const async_mod = @import("../async/mod.zig");
const kcp_mod = @import("../kcp/mod.zig");
const Channel = async_mod.channel.Channel;
const Signal = async_mod.channel.Signal;
const IOService = async_mod.IOService;
pub const SimpleTimerService = async_mod.SimpleTimerService;
pub const KcpMux = kcp_mod.Mux(SimpleTimerService);
pub const KcpStream = kcp_mod.Stream;

const Key = noise.Key;
const KeyPair = noise.KeyPair;
const Session = noise.Session;
const SessionConfig = noise.SessionConfig;
const SessionState = noise.SessionState;
const HandshakeState = noise.HandshakeState;
const message = noise.message;

// ============================================================================
// Constants
// ============================================================================

/// Default decrypt channel size (raw packets waiting for decryption).
pub const DecryptChanSize: usize = 4096;

/// Default output channel size (packets waiting for readFrom).
pub const OutputChanSize: usize = 256;

/// Default number of decrypt workers (0 = use CPU count).
pub const DefaultWorkers: usize = 0;

/// Accept queue capacity for incoming streams.
pub const AcceptQueueCapacity: usize = 16;

/// Maximum packet size.
pub const MaxPacketSize: usize = message.max_packet_size;

// ============================================================================
// Errors
// ============================================================================

pub const UdpError = error{
    /// Failed to bind the socket.
    BindFailed,
    /// Failed to send data.
    SendFailed,
    /// Failed to receive data.
    ReceiveFailed,
    /// No peer found for the given public key.
    PeerNotFound,
    /// Handshake failed.
    HandshakeFailed,
    /// Handshake timed out.
    HandshakeTimeout,
    /// Message too short to be valid.
    MessageTooShort,
    /// Decryption failed.
    DecryptFailed,
    /// UDP socket is closed.
    Closed,
    /// No data available (non-blocking).
    NoData,
    /// Accept queue is full.
    AcceptQueueFull,
    /// Out of memory.
    OutOfMemory,
    /// Channel closed.
    ChannelClosed,
};

// ============================================================================
// Packet
// ============================================================================

/// A packet in the processing pipeline.
/// Carries raw data and gets decrypted in parallel by workers.
/// Consumers wait on the ready signal before accessing decrypted data.
pub const Packet = struct {
    // Input (set by ioLoop)
    data: []u8, // Buffer (from pool)
    len: usize, // Actual data length
    from_addr: posix.sockaddr.in, // Sender address
    from_len: posix.socklen_t, // Address length

    // Output (set by decryptWorker)
    pk: Key, // Sender's public key
    protocol: u8, // Protocol byte
    payload: []u8, // Decrypted payload (slice into data or out_buf)
    payload_len: usize, // Payload length
    err: ?UdpError, // Decrypt error (if any)

    // Decryption output buffer
    out_buf: [MaxPacketSize]u8,

    // Synchronization
    ready: Signal, // Signaled when decryption is complete

    pub fn init() Packet {
        return Packet{
            .data = &[_]u8{},
            .len = 0,
            .from_addr = undefined,
            .from_len = 0,
            .pk = Key.zero,
            .protocol = 0,
            .payload = &[_]u8{},
            .payload_len = 0,
            .err = null,
            .out_buf = undefined,
            .ready = Signal.init(),
        };
    }

    pub fn reset(self: *Packet) void {
        self.len = 0;
        self.pk = Key.zero;
        self.protocol = 0;
        self.payload = &[_]u8{};
        self.payload_len = 0;
        self.err = null;
        self.ready.reset();
    }
};

// ============================================================================
// PacketPool
// ============================================================================

/// Pool of reusable packets to avoid allocation per-packet.
pub const PacketPool = struct {
    const Self = @This();

    packets: []Packet,
    buffers: []u8, // Contiguous buffer for all packet data
    free_stack: []usize, // Stack of free packet indices
    stack_top: Atomic(usize),
    mutex: Mutex,
    allocator: Allocator,
    capacity: usize,

    pub fn init(allocator: Allocator, capacity: usize) !Self {
        const packets = try allocator.alloc(Packet, capacity);
        const buffers = try allocator.alloc(u8, capacity * MaxPacketSize);

        // Initialize packets and assign buffer slices
        for (packets, 0..) |*pkt, i| {
            pkt.* = Packet.init();
            pkt.data = buffers[i * MaxPacketSize .. (i + 1) * MaxPacketSize];
        }

        // Initialize free stack
        const free_stack = try allocator.alloc(usize, capacity);
        for (free_stack, 0..) |*slot, i| {
            slot.* = i;
        }

        return Self{
            .packets = packets,
            .buffers = buffers,
            .free_stack = free_stack,
            .stack_top = Atomic(usize).init(capacity),
            .mutex = .{},
            .allocator = allocator,
            .capacity = capacity,
        };
    }

    pub fn deinit(self: *Self) void {
        self.allocator.free(self.free_stack);
        self.allocator.free(self.buffers);
        self.allocator.free(self.packets);
    }

    /// Acquire a packet from the pool. Returns null if pool is empty.
    pub fn acquire(self: *Self) ?*Packet {
        self.mutex.lock();
        defer self.mutex.unlock();

        const top = self.stack_top.load(.acquire);
        if (top == 0) return null;

        const new_top = top - 1;
        const idx = self.free_stack[new_top];
        self.stack_top.store(new_top, .release);

        const pkt = &self.packets[idx];
        pkt.reset();
        return pkt;
    }

    /// Release a packet back to the pool.
    pub fn release(self: *Self, pkt: *Packet) void {
        // Calculate index from pointer
        const pkt_addr = @intFromPtr(pkt);
        const base_addr = @intFromPtr(self.packets.ptr);
        const idx = (pkt_addr - base_addr) / @sizeOf(Packet);

        self.mutex.lock();
        defer self.mutex.unlock();

        const top = self.stack_top.load(.acquire);
        self.free_stack[top] = idx;
        self.stack_top.store(top + 1, .release);
    }
};

// ============================================================================
// Peer State
// ============================================================================

/// State for a single peer.
const PeerState = struct {
    pk: Key,
    endpoint: posix.sockaddr,
    endpoint_len: posix.socklen_t,
    session: ?*Session,
    handshake: ?*HandshakeState,

    // Statistics
    tx_bytes: Atomic(u64),
    rx_bytes: Atomic(u64),

    // Stream multiplexing (KCP)
    mux: ?*KcpMux,
    mux_ctx: ?*anyopaque, // For cleanup

    pub fn init(pk: Key) PeerState {
        return PeerState{
            .pk = pk,
            .endpoint = undefined,
            .endpoint_len = 0,
            .session = null,
            .handshake = null,
            .tx_bytes = Atomic(u64).init(0),
            .rx_bytes = Atomic(u64).init(0),
            .mux = null,
            .mux_ctx = null,
        };
    }
};


/// Pending handshake state.
const PendingHandshake = struct {
    hs: *HandshakeState,
    pk: Key,
    done: Signal,
    success: bool,
    created_at: i128,
};

// ============================================================================
// UDP Options
// ============================================================================

pub const UdpOptions = struct {
    /// Address to bind to (default: "0.0.0.0:0").
    bind_addr: []const u8 = "0.0.0.0:0",
    /// Allow connections from unknown peers.
    allow_unknown: bool = false,
    /// Number of decrypt workers (0 = CPU count).
    decrypt_workers: usize = DefaultWorkers,
    /// Decrypt channel size.
    decrypt_chan_size: usize = DecryptChanSize,
    /// Output channel size.
    output_chan_size: usize = OutputChanSize,
};

// ============================================================================
// ReadResult (module-level, independent of IO backend)
// ============================================================================

/// Read result from UDP.
pub const ReadResult = struct {
    pk: Key,
    n: usize,
};

/// Read result from UDP including protocol byte.
pub const ReadPacketResult = struct {
    pk: Key,
    protocol: u8,
    n: usize,
};

// ============================================================================
// UDP
// ============================================================================

/// UDP network layer with Noise Protocol encryption.
///
/// Generic over `IOBackend` to support platform-specific I/O backends
/// (e.g., KqueueIO on macOS/BSD, EpollIO on Linux).
/// The backend must implement the IOService interface.
pub fn UDP(comptime IOBackend: type) type {
    // Compile-time check that IOBackend implements IOService
    comptime async_mod.assertIOService(IOBackend);

    return struct {
        const Self = @This();

    // Core state
    allocator: Allocator,
    local_key: *const KeyPair,
    socket: posix.socket_t,
    local_port: u16,

    // Options
    allow_unknown: bool,

    // Relay forwarding
    router: ?relay_mod.Router,
    local_metrics: relay_mod.NodeMetrics,

    // Peer management
    peers_mutex: Mutex,
    peers: std.AutoHashMap([32]u8, *PeerState),
    by_index: std.AutoHashMap(u32, Key),

    // Pending handshakes
    pending_mutex: Mutex,
    pending: std.AutoHashMap(u32, *PendingHandshake),

    // Pipeline channels (Go-style double queue)
    packet_pool: PacketPool,
    decrypt_chan: Channel(*Packet),
    output_chan: Channel(*Packet),

    // Worker threads
    io_thread: ?Thread,
    timer_thread: ?Thread, // For KCP update ticks
    workers: []Thread,
    num_workers: usize,

    // IO service (platform-agnostic)
    io: IOService,
    io_backend: *IOBackend,

    // Timer service for KCP updates
    timer_service: SimpleTimerService,

    // Close signaling
    closed: Atomic(bool),
    close_signal: Signal,

    // Statistics
    total_tx: Atomic(u64),
    total_rx: Atomic(u64),
    last_seen: Atomic(i128),

    // Index generator
    next_index: Atomic(u32),

    /// Initialize a new UDP instance.
    pub fn init(
        allocator: Allocator,
        key: *const KeyPair,
        options: UdpOptions,
    ) UdpError!*Self {
        // Create socket
        const socket = posix.socket(posix.AF.INET, posix.SOCK.DGRAM, 0) catch return UdpError.BindFailed;
        errdefer posix.close(socket);

        // Set socket to non-blocking mode for clean shutdown
        const current_flags = posix.fcntl(socket, posix.F.GETFL, 0) catch 0;
        var o_flags: posix.O = @bitCast(@as(u32, @intCast(current_flags)));
        o_flags.NONBLOCK = true;
        _ = posix.fcntl(socket, posix.F.SETFL, @as(usize, @as(u32, @bitCast(o_flags)))) catch {};

        // Parse bind address
        var addr: posix.sockaddr.in = .{
            .family = posix.AF.INET,
            .port = 0,
            .addr = 0,
        };

        if (parseBindAddr(options.bind_addr)) |parsed| {
            addr = parsed;
        }

        // Bind socket
        posix.bind(socket, @ptrCast(&addr), @sizeOf(posix.sockaddr.in)) catch return UdpError.BindFailed;

        // Get bound address
        var bound_addr_len: posix.socklen_t = @sizeOf(posix.sockaddr.in);
        posix.getsockname(socket, @ptrCast(&addr), &bound_addr_len) catch return UdpError.BindFailed;
        const local_port = mem.bigToNative(u16, addr.port);

        // Determine worker count
        var num_workers = options.decrypt_workers;
        if (num_workers == 0) {
            num_workers = @max(1, Thread.getCpuCount() catch 4);
        }

        // Allocate self
        const self = allocator.create(Self) catch return UdpError.OutOfMemory;
        errdefer allocator.destroy(self);

        // Initialize packet pool
        const pool_size = options.decrypt_chan_size + options.output_chan_size;
        const packet_pool = PacketPool.init(allocator, pool_size) catch return UdpError.OutOfMemory;

        // Initialize channels
        const decrypt_chan = Channel(*Packet).init(allocator, options.decrypt_chan_size) catch return UdpError.OutOfMemory;
        const output_chan = Channel(*Packet).init(allocator, options.output_chan_size) catch return UdpError.OutOfMemory;

        // Allocate worker array
        const workers = allocator.alloc(Thread, num_workers) catch return UdpError.OutOfMemory;

        // Initialize IO backend
        const io_backend = allocator.create(IOBackend) catch return UdpError.OutOfMemory;
        io_backend.* = IOBackend.init(allocator) catch {
            allocator.destroy(io_backend);
            return UdpError.BindFailed;
        };
        errdefer {
            io_backend.deinit();
            allocator.destroy(io_backend);
        }

        self.* = Self{
            .allocator = allocator,
            .local_key = key,
            .socket = socket,
            .local_port = local_port,
            .allow_unknown = options.allow_unknown,
            .router = null,
            .local_metrics = .{},
            .peers_mutex = .{},
            .peers = std.AutoHashMap([32]u8, *PeerState).init(allocator),
            .by_index = std.AutoHashMap(u32, Key).init(allocator),
            .pending_mutex = .{},
            .pending = std.AutoHashMap(u32, *PendingHandshake).init(allocator),
            .packet_pool = packet_pool,
            .decrypt_chan = decrypt_chan,
            .output_chan = output_chan,
            .io_thread = null,
            .timer_thread = null,
            .workers = workers,
            .num_workers = num_workers,
            .io = io_backend.ioService(),
            .io_backend = io_backend,
            .timer_service = SimpleTimerService.init(allocator),
            .closed = Atomic(bool).init(false),
            .close_signal = Signal.init(),
            .total_tx = Atomic(u64).init(0),
            .total_rx = Atomic(u64).init(0),
            .last_seen = Atomic(i128).init(0),
            .next_index = Atomic(u32).init(1),
        };

        // Start IO thread
        self.io_thread = Thread.spawn(.{}, ioLoop, .{self}) catch return UdpError.OutOfMemory;

        // Start timer thread for KCP updates
        self.timer_thread = Thread.spawn(.{}, timerLoop, .{self}) catch return UdpError.OutOfMemory;

        // Start decrypt workers
        for (self.workers) |*w| {
            w.* = Thread.spawn(.{}, decryptWorker, .{self}) catch return UdpError.OutOfMemory;
        }

        return self;
    }

    /// Close the UDP instance.
    pub fn deinit(self: *Self) void {
        // Signal close
        self.closed.store(true, .release);
        self.close_signal.signal();

        // Wake ioLoop from blocking poll
        self.io.wake();

        // Close channels to wake blocked threads
        self.decrypt_chan.close();
        self.output_chan.close();

        // Close socket
        posix.close(self.socket);

        // Join threads
        if (self.io_thread) |t| {
            t.join();
        }
        if (self.timer_thread) |t| {
            t.join();
        }
        for (self.workers) |w| {
            w.join();
        }

        // Free peers first (before timer_service, as mux.deinit() needs to cancel timers)
        var peer_iter = self.peers.valueIterator();
        while (peer_iter.next()) |peer_ptr| {
            const peer = peer_ptr.*;
            if (peer.mux) |mux| {
                mux.deinit();
            }
            if (peer.mux_ctx) |ctx| {
                const ctx_ptr: *MuxOutputCtx = @ptrCast(@alignCast(ctx));
                self.allocator.destroy(ctx_ptr);
            }
            if (peer.session) |s| {
                self.allocator.destroy(s);
            }
            if (peer.handshake) |hs| {
                self.allocator.destroy(hs);
            }
            self.allocator.destroy(peer);
        }
        self.peers.deinit();
        self.by_index.deinit();

        // Free pending handshakes
        var pending_iter = self.pending.valueIterator();
        while (pending_iter.next()) |ph_ptr| {
            const ph = ph_ptr.*;
            self.allocator.destroy(ph.hs);
            self.allocator.destroy(ph);
        }
        self.pending.deinit();

        // Now cleanup internal resources
        self.io_backend.deinit();
        self.allocator.destroy(self.io_backend);
        self.timer_service.deinit();
        self.decrypt_chan.deinit();
        self.output_chan.deinit();
        self.packet_pool.deinit();
        self.allocator.free(self.workers);

        self.allocator.destroy(self);
    }

    /// Alias for deinit.
    pub fn close(self: *Self) void {
        self.deinit();
    }

    // ========================================================================
    // Public API
    // ========================================================================

    /// Get local port.
    pub fn getLocalPort(self: *Self) u16 {
        return self.local_port;
    }

    /// Set the relay router for forwarding relay packets.
    pub fn setRouter(self: *Self, router: relay_mod.Router) void {
        self.router = router;
    }

    /// Update the local node metrics for PONG responses.
    pub fn setLocalMetrics(self: *Self, metrics: relay_mod.NodeMetrics) void {
        self.local_metrics = metrics;
    }

    /// Set peer endpoint.
    pub fn setPeerEndpoint(self: *Self, pk: Key, endpoint: posix.sockaddr, endpoint_len: posix.socklen_t) void {
        self.peers_mutex.lock();
        defer self.peers_mutex.unlock();

        const peer = self.getOrCreatePeerLocked(pk);
        peer.endpoint = endpoint;
        peer.endpoint_len = endpoint_len;
    }

    /// Connect to a peer (initiate handshake).
    pub fn connect(self: *Self, pk: *const Key) UdpError!void {
        return self.connectTimeout(pk, 5 * std.time.ns_per_s);
    }

    /// Connect with timeout.
    pub fn connectTimeout(self: *Self, pk: *const Key, timeout_ns: i128) UdpError!void {
        if (self.closed.load(.acquire)) {
            return UdpError.Closed;
        }

        // Get or create peer
        const peer = blk: {
            self.peers_mutex.lock();
            defer self.peers_mutex.unlock();
            break :blk self.getOrCreatePeerLocked(pk.*);
        };

        // Check if already connected
        if (peer.session) |s| {
            if (s.getState() == .established) {
                return; // Already connected
            }
        }

        // Create handshake state
        const hs = self.allocator.create(HandshakeState) catch return UdpError.OutOfMemory;
        hs.* = HandshakeState.init(.{
            .pattern = .IK,
            .initiator = true,
            .local_static = self.local_key.*,
            .remote_static = pk.*,
        }) catch {
            self.allocator.destroy(hs);
            return UdpError.HandshakeFailed;
        };

        // Generate sender index
        const sender_index = self.next_index.fetchAdd(1, .monotonic);

        // Register pending handshake
        const pending = self.allocator.create(PendingHandshake) catch {
            self.allocator.destroy(hs);
            return UdpError.OutOfMemory;
        };
        pending.* = PendingHandshake{
            .hs = hs,
            .pk = pk.*,
            .done = Signal.init(),
            .success = false,
            .created_at = std.time.nanoTimestamp(),
        };

        {
            self.pending_mutex.lock();
            defer self.pending_mutex.unlock();
            self.pending.put(sender_index, pending) catch {
                self.allocator.destroy(pending);
                self.allocator.destroy(hs);
                return UdpError.OutOfMemory;
            };
        }

        // Build handshake init message
        var msg_buf: [message.handshake_init_size]u8 = undefined;
        var noise_msg: [80]u8 = undefined; // e(32) + es(48)

        _ = hs.writeMessage(&[_]u8{}, &noise_msg) catch {
            self.cleanupPending(sender_index);
            return UdpError.HandshakeFailed;
        };

        // Wire format: type(1) + sender_idx(4) + noise_msg(80) = 85
        msg_buf[0] = @intFromEnum(message.MessageType.handshake_init);
        mem.writeInt(u32, msg_buf[1..5], sender_index, .little);
        @memcpy(msg_buf[5..85], &noise_msg);

        // Send
        const endpoint = peer.endpoint;
        const endpoint_len = peer.endpoint_len;
        _ = posix.sendto(self.socket, &msg_buf, 0, &endpoint, endpoint_len) catch {
            self.cleanupPending(sender_index);
            return UdpError.SendFailed;
        };

        // Wait for response
        const timeout_u64: u64 = @intCast(@max(0, timeout_ns));
        if (!pending.done.waitTimeout(timeout_u64)) {
            self.cleanupPending(sender_index);
            return UdpError.HandshakeTimeout;
        }

        if (!pending.success) {
            self.cleanupPending(sender_index);
            return UdpError.HandshakeFailed;
        }

        // Success - cleanup pending (session already established)
        self.cleanupPending(sender_index);
    }

    /// Write data to a peer.
    pub fn writeTo(self: *Self, pk: *const Key, data: []const u8) UdpError!void {
        return self.writeToProtocol(pk, @intFromEnum(message.Protocol.chat), data);
    }

    /// Write data with protocol byte.
    pub fn writeToProtocol(self: *Self, pk: *const Key, protocol: u8, data: []const u8) UdpError!void {
        if (self.closed.load(.acquire)) {
            return UdpError.Closed;
        }

        // Get peer and session
        const peer = blk: {
            self.peers_mutex.lock();
            defer self.peers_mutex.unlock();
            break :blk self.peers.get(pk.data) orelse return UdpError.PeerNotFound;
        };

        const session = peer.session orelse return UdpError.PeerNotFound;
        if (session.getState() != .established) {
            return UdpError.PeerNotFound;
        }

        // Build transport message
        var msg_buf: [MaxPacketSize]u8 = undefined;

        // Encrypt: protocol(1) + data
        var plaintext: [MaxPacketSize]u8 = undefined;
        plaintext[0] = protocol;
        @memcpy(plaintext[1 .. data.len + 1], data);

        const plaintext_len = data.len + 1;
        const ciphertext_len = plaintext_len + noise.tag_size;

        // encrypt returns nonce, writes ciphertext to msg_buf[13..]
        const nonce = session.encrypt(plaintext[0..plaintext_len], msg_buf[13..]) catch {
            return UdpError.SendFailed;
        };

        // Header: type(1) + receiver_idx(4) + counter(8) = 13
        msg_buf[0] = @intFromEnum(message.MessageType.transport);
        mem.writeInt(u32, msg_buf[1..5], session.remote_index, .little);
        mem.writeInt(u64, msg_buf[5..13], nonce, .little);

        const msg_len = 13 + ciphertext_len;

        // Send
        const endpoint = peer.endpoint;
        const endpoint_len = peer.endpoint_len;
        const n = posix.sendto(self.socket, msg_buf[0..msg_len], 0, &endpoint, endpoint_len) catch {
            return UdpError.SendFailed;
        };

        _ = self.total_tx.fetchAdd(@intCast(n), .release);
        _ = peer.tx_bytes.fetchAdd(@intCast(n), .release);
    }

    /// Read decrypted data from any peer.
    /// Blocks until data is available or closed.
    pub fn readFrom(self: *Self, buf: []u8) UdpError!ReadResult {
        while (true) {
            if (self.closed.load(.acquire)) {
                return UdpError.Closed;
            }

            // Get packet from output channel
            const pkt = self.output_chan.recv() orelse {
                return UdpError.Closed;
            };

            // Wait for decryption to complete
            pkt.ready.wait();

            // Check for errors
            if (pkt.err != null) {
                self.packet_pool.release(pkt);
                continue; // Try next packet
            }

            // Copy data
            const n = @min(buf.len, pkt.payload_len);
            @memcpy(buf[0..n], pkt.payload[0..n]);
            const pk = pkt.pk;

            self.packet_pool.release(pkt);
            return ReadResult{ .pk = pk, .n = n };
        }
    }

    /// Read decrypted data from any peer, including the protocol byte.
    /// Blocks until data is available or closed.
    pub fn readPacket(self: *Self, buf: []u8) UdpError!ReadPacketResult {
        while (true) {
            if (self.closed.load(.acquire)) {
                return UdpError.Closed;
            }

            // Get packet from output channel
            const pkt = self.output_chan.recv() orelse {
                return UdpError.Closed;
            };

            // Wait for decryption to complete
            pkt.ready.wait();

            // Check for errors
            if (pkt.err != null) {
                self.packet_pool.release(pkt);
                continue; // Try next packet
            }

            // Copy data
            const n = @min(buf.len, pkt.payload_len);
            @memcpy(buf[0..n], pkt.payload[0..n]);
            const pk = pkt.pk;
            const protocol = pkt.protocol;

            self.packet_pool.release(pkt);
            return ReadPacketResult{ .pk = pk, .protocol = protocol, .n = n };
        }
    }

    // ========================================================================
    // KCP Stream API
    // ========================================================================

    /// Determine if we are the KCP client for a peer.
    /// Uses deterministic rule: smaller public key is client (uses odd stream IDs).
    pub fn isKcpClient(self: *Self, remote_pk: Key) bool {
        return mem.lessThan(u8, &self.local_key.public.data, &remote_pk.data);
    }

    /// Initialize Mux for a peer. Called when session is established.
    fn initMux(self: *Self, peer: *PeerState) void {
        // Close existing mux if any
        if (peer.mux) |old_mux| {
            old_mux.deinit();
        }
        // Free old context if any
        if (peer.mux_ctx) |old_ctx| {
            const ctx_ptr: *MuxOutputCtx = @ptrCast(@alignCast(old_ctx));
            self.allocator.destroy(ctx_ptr);
            peer.mux_ctx = null;
        }

        const is_client = self.isKcpClient(peer.pk);

        // Allocate output context
        const output_ctx = self.allocator.create(MuxOutputCtx) catch return;
        output_ctx.* = .{ .udp = self, .peer = peer };
        peer.mux_ctx = output_ctx;

        // Create Mux
        peer.mux = KcpMux.init(
            self.allocator,
            &self.timer_service,
            .{},
            is_client,
            MuxOutputCtx.output,
            onNewStream,
            output_ctx,
        ) catch {
            self.allocator.destroy(output_ctx);
            peer.mux_ctx = null;
            return;
        };
    }

    /// Output context for Mux - stored at file scope so we can reference it in cleanup.
    const MuxOutputCtx = struct {
        udp: *Self,
        peer: *PeerState,

        fn output(data: []const u8, user_data: ?*anyopaque) anyerror!void {
            const ctx: *MuxOutputCtx = @ptrCast(@alignCast(user_data.?));
            try ctx.udp.sendToPeer(ctx.peer, @intFromEnum(message.Protocol.kcp), data);
        }
    };

    /// Callback when a new stream is accepted.
    fn onNewStream(_: *KcpStream, _: ?*anyopaque) void {
        // Stream is pushed to accept_chan in Mux, nothing extra to do here
    }

    /// Send data to a peer with protocol byte.
    fn sendToPeer(self: *Self, peer: *PeerState, protocol: u8, data: []const u8) UdpError!void {
        const session = peer.session orelse return UdpError.PeerNotFound;
        if (session.getState() != .established) {
            return UdpError.PeerNotFound;
        }

        var msg_buf: [MaxPacketSize]u8 = undefined;
        var plaintext: [MaxPacketSize]u8 = undefined;
        plaintext[0] = protocol;
        @memcpy(plaintext[1 .. data.len + 1], data);

        const plaintext_len = data.len + 1;
        const ciphertext_len = plaintext_len + noise.tag_size;

        const nonce = session.encrypt(plaintext[0..plaintext_len], msg_buf[13..]) catch {
            return UdpError.SendFailed;
        };

        msg_buf[0] = @intFromEnum(message.MessageType.transport);
        mem.writeInt(u32, msg_buf[1..5], session.remote_index, .little);
        mem.writeInt(u64, msg_buf[5..13], nonce, .little);

        const msg_len = 13 + ciphertext_len;
        const endpoint = peer.endpoint;
        const endpoint_len = peer.endpoint_len;

        _ = posix.sendto(self.socket, msg_buf[0..msg_len], 0, &endpoint, endpoint_len) catch {
            return UdpError.SendFailed;
        };
    }

    /// Open a new stream to a peer with protocol type and metadata.
    /// proto specifies the stream protocol type (e.g., noise_mod.Protocol.tcp_proxy).
    /// metadata contains additional data sent with the SYN frame (e.g., encoded Address).
    /// Use proto=0 and metadata=&.{} for untyped streams.
    pub fn openStream(self: *Self, pk: *const Key, proto: u8, metadata: []const u8) UdpError!*KcpStream {
        if (self.closed.load(.acquire)) return UdpError.Closed;

        const peer = blk: {
            self.peers_mutex.lock();
            defer self.peers_mutex.unlock();
            break :blk self.peers.get(pk.data) orelse return UdpError.PeerNotFound;
        };

        // Initialize mux if not yet done
        if (peer.mux == null) {
            self.initMux(peer);
        }

        const mux = peer.mux orelse return UdpError.PeerNotFound;
        return mux.openStream(proto, metadata) catch return UdpError.OutOfMemory;
    }

    /// Accept an incoming stream from a peer.
    /// Blocks until a stream is available or the peer is closed.
    pub fn acceptStream(self: *Self, pk: *const Key) ?*KcpStream {
        if (self.closed.load(.acquire)) return null;

        const peer = blk: {
            self.peers_mutex.lock();
            defer self.peers_mutex.unlock();
            break :blk self.peers.get(pk.data) orelse return null;
        };

        const mux = peer.mux orelse return null;
        return mux.acceptStream();
    }

    /// Try to accept a stream without blocking.
    pub fn tryAcceptStream(self: *Self, pk: *const Key) ?*KcpStream {
        if (self.closed.load(.acquire)) return null;

        const peer = blk: {
            self.peers_mutex.lock();
            defer self.peers_mutex.unlock();
            break :blk self.peers.get(pk.data) orelse return null;
        };

        const mux = peer.mux orelse return null;
        return mux.tryAcceptStream();
    }

    // ========================================================================
    // Internal: IO Loop
    // ========================================================================

    fn ioLoop(self: *Self) void {
        // Register socket for read readiness via IOService callback
        self.io.registerRead(@intCast(self.socket), .{
            .ptr = @ptrCast(self),
            .callback = onSocketReady,
        });

        // Poll loop — blocks until events, callbacks fire inside poll()
        while (!self.closed.load(.acquire)) {
            _ = self.io.poll(-1); // block indefinitely, wake() interrupts
        }
    }

    /// Callback invoked by IOService when socket is readable.
    fn onSocketReady(ptr: ?*anyopaque, _: posix.fd_t) void {
        const self: *Self = @ptrCast(@alignCast(ptr.?));

        // Drain all available packets from socket
        while (!self.closed.load(.acquire)) {
            // Acquire packet from pool
            const pkt = self.packet_pool.acquire() orelse {
                // Pool exhausted — stop draining and return.
                // The IO backend uses level-triggered events, so the
                // callback will fire again on the next poll() while data
                // remains in the socket buffer. Consumers will release
                // packets back to the pool in the meantime.
                return;
            };

            // Read from socket (non-blocking)
            var from_addr: posix.sockaddr.in = undefined;
            var from_len: posix.socklen_t = @sizeOf(posix.sockaddr.in);

            const nr = posix.recvfrom(
                self.socket,
                pkt.data,
                0,
                @ptrCast(&from_addr),
                &from_len,
            ) catch |err| {
                self.packet_pool.release(pkt);
                if (err == error.WouldBlock) {
                    break; // No more data, wait for next event
                }
                return; // Other errors: exit callback
            };

            if (nr < 1) {
                self.packet_pool.release(pkt);
                continue;
            }

            pkt.len = nr;
            pkt.from_addr = from_addr;
            pkt.from_len = from_len;

            // Update stats
            _ = self.total_rx.fetchAdd(@intCast(nr), .release);
            self.last_seen.store(std.time.nanoTimestamp(), .release);

            // Dual-channel send: packet must be in both channels or neither.
            // Send to output_chan FIRST — reader blocks on ready.wait() so it
            // won't touch the packet until decrypt worker signals ready.
            if (!self.output_chan.trySend(pkt)) {
                // output_chan full, drop packet (nothing to undo)
                self.packet_pool.release(pkt);
                continue;
            }

            // Now send to decrypt_chan for worker processing.
            if (!self.decrypt_chan.trySend(pkt)) {
                // decrypt_chan full (rare). Packet is already in output_chan
                // and reader will block on ready.wait(). Signal ready with
                // error so reader can consume and release it — no leak.
                pkt.err = UdpError.NoData;
                pkt.ready.signal();
                continue;
            }
        }
    }

    // ========================================================================
    // Internal: Timer Loop (for KCP updates)
    // ========================================================================

    fn timerLoop(self: *Self) void {
        while (!self.closed.load(.acquire)) {
            // Sleep 1ms
            std.Thread.sleep(1 * std.time.ns_per_ms);

            if (self.closed.load(.acquire)) return;

            // Advance timer and fire due tasks
            _ = self.timer_service.advance(1);
        }
    }

    // ========================================================================
    // Internal: Decrypt Worker
    // ========================================================================

    fn decryptWorker(self: *Self) void {
        while (true) {
            // Get packet from decrypt channel
            const pkt = self.decrypt_chan.recv() orelse {
                return; // Channel closed
            };

            // Process packet
            self.processPacket(pkt);

            // Signal ready
            pkt.ready.signal();
        }
    }

    fn processPacket(self: *Self, pkt: *Packet) void {
        const data = pkt.data[0..pkt.len];

        if (data.len < 1) {
            pkt.err = UdpError.MessageTooShort;
            return;
        }

        const msg_type: message.MessageType = @enumFromInt(data[0]);

        switch (msg_type) {
            .handshake_init => {
                self.handleHandshakeInit(data, &pkt.from_addr, pkt.from_len);
                pkt.err = UdpError.NoData; // Not a data packet
            },
            .handshake_resp => {
                self.handleHandshakeResp(data, &pkt.from_addr, pkt.from_len);
                pkt.err = UdpError.NoData; // Not a data packet
            },
            .transport => {
                self.decryptTransport(pkt, data);
            },
            else => {
                pkt.err = UdpError.NoData;
            },
        }
    }

    fn decryptTransport(self: *Self, pkt: *Packet, data: []const u8) void {
        // Parse transport header
        const msg = message.parseTransportMessage(data) catch {
            pkt.err = UdpError.MessageTooShort;
            return;
        };

        // Find peer by receiver index
        const pk = blk: {
            self.peers_mutex.lock();
            defer self.peers_mutex.unlock();
            break :blk self.by_index.get(msg.receiver_index) orelse {
                pkt.err = UdpError.PeerNotFound;
                return;
            };
        };

        const peer = blk: {
            self.peers_mutex.lock();
            defer self.peers_mutex.unlock();
            break :blk self.peers.get(pk.data) orelse {
                pkt.err = UdpError.PeerNotFound;
                return;
            };
        };

        const session = peer.session orelse {
            pkt.err = UdpError.PeerNotFound;
            return;
        };

        // Decrypt - returns plaintext length
        const plaintext_len = session.decrypt(msg.ciphertext, msg.counter, &pkt.out_buf) catch {
            pkt.err = UdpError.DecryptFailed;
            return;
        };

        if (plaintext_len < 1) {
            pkt.err = UdpError.MessageTooShort;
            return;
        }

        const protocol = pkt.out_buf[0];
        const payload = pkt.out_buf[1..plaintext_len];

        // Route KCP protocol to Mux
        if (protocol == @intFromEnum(message.Protocol.kcp)) {
            if (peer.mux) |mux| {
                mux.input(payload) catch {};
            }
            pkt.err = UdpError.NoData; // Handled internally
            return;
        }

        // Route relay protocols
        if (protocol == @intFromEnum(message.Protocol.relay_0)) {
            if (self.router) |router| {
                if (relay_mod.handleRelay0(router, &pk.data, payload)) |action| {
                    self.executeRelayAction(&action);
                } else |_| {}
            }
            pkt.err = UdpError.NoData;
            return;
        }

        if (protocol == @intFromEnum(message.Protocol.relay_1)) {
            if (self.router) |router| {
                if (relay_mod.handleRelay1(router, payload)) |action| {
                    self.executeRelayAction(&action);
                } else |_| {}
            }
            pkt.err = UdpError.NoData;
            return;
        }

        if (protocol == @intFromEnum(message.Protocol.relay_2)) {
            if (relay_mod.handleRelay2(payload)) |result| {
                if (result.payload.len > 0) {
                    self.processRelayedPacket(pkt, &result.src_key, result.payload);
                } else {
                    pkt.err = UdpError.NoData;
                }
            } else |_| {
                pkt.err = UdpError.NoData;
            }
            _ = peer.rx_bytes.fetchAdd(@intCast(pkt.len), .release);
            return;
        }

        if (protocol == @intFromEnum(message.Protocol.ping)) {
            if (self.router != null) {
                if (relay_mod.handlePing(&pk.data, payload, &self.local_metrics)) |action| {
                    self.executeRelayAction(&action);
                } else |_| {}
            }
            pkt.err = UdpError.NoData;
            return;
        }

        // PONG: deliver to upper layer (ReadFrom)
        // Other protocols: also deliver to upper layer

        // Extract protocol and payload for other protocols
        pkt.pk = pk;
        pkt.protocol = protocol;
        pkt.payload = payload;
        pkt.payload_len = plaintext_len - 1;
        pkt.err = null;

        // Update stats
        _ = peer.rx_bytes.fetchAdd(@intCast(pkt.len), .release);
    }

    /// Execute a relay forwarding action by sending to the target peer.
    fn executeRelayAction(self: *Self, action: *const relay_mod.Action) void {
        const pk = Key{ .data = action.dst };

        self.peers_mutex.lock();
        const peer_opt = self.peers.get(pk.data);
        self.peers_mutex.unlock();

        const peer = peer_opt orelse return;
        self.sendToPeer(peer, action.protocol, action.data()) catch {};
    }

    /// Process a RELAY_2 inner payload: parse Type 4, find session, decrypt.
    /// The inner_payload points into pkt.out_buf, so we copy ciphertext to
    /// pkt.data (already consumed) before decrypting back into pkt.out_buf.
    fn processRelayedPacket(self: *Self, pkt: *Packet, src_key: *const [32]u8, inner_payload: []const u8) void {
        // Parse the inner Type 4 transport message
        const inner_msg = message.parseTransportMessage(inner_payload) catch {
            pkt.err = UdpError.NoData;
            return;
        };

        // Find the session by receiver index (our local index for the A-C session)
        const inner_pk = blk: {
            self.peers_mutex.lock();
            defer self.peers_mutex.unlock();
            break :blk self.by_index.get(inner_msg.receiver_index) orelse {
                pkt.err = UdpError.PeerNotFound;
                return;
            };
        };

        const inner_peer = blk: {
            self.peers_mutex.lock();
            defer self.peers_mutex.unlock();
            break :blk self.peers.get(inner_pk.data) orelse {
                pkt.err = UdpError.PeerNotFound;
                return;
            };
        };

        const inner_session = inner_peer.session orelse {
            pkt.err = UdpError.NoData;
            return;
        };

        // Copy inner ciphertext to pkt.data (temp buffer).
        // inner_msg.ciphertext points into pkt.out_buf which we'll overwrite.
        const ct_len = inner_msg.ciphertext.len;
        if (ct_len > pkt.data.len) {
            pkt.err = UdpError.NoData;
            return;
        }
        @memcpy(pkt.data[0..ct_len], inner_msg.ciphertext);

        // Decrypt into pkt.out_buf
        const inner_pt_len = inner_session.decrypt(pkt.data[0..ct_len], inner_msg.counter, &pkt.out_buf) catch {
            pkt.err = UdpError.DecryptFailed;
            return;
        };

        if (inner_pt_len < 1) {
            pkt.err = UdpError.NoData;
            return;
        }

        // Decode inner protocol + payload
        const inner_protocol = pkt.out_buf[0];
        const inner_data = pkt.out_buf[1..inner_pt_len];

        // Fill packet fields
        pkt.pk = Key{ .data = src_key.* };
        pkt.protocol = inner_protocol;
        pkt.payload = inner_data;
        pkt.payload_len = inner_pt_len - 1;
        pkt.err = null;

        // Route KCP internally
        if (inner_protocol == @intFromEnum(message.Protocol.kcp)) {
            if (inner_peer.mux) |mux| {
                mux.input(inner_data) catch {};
            }
            pkt.err = UdpError.NoData;
            return;
        }
    }

    // ========================================================================
    // Internal: Handshake Handling
    // ========================================================================

    fn handleHandshakeInit(self: *Self, data: []const u8, from: *const posix.sockaddr.in, from_len: posix.socklen_t) void {
        const msg = message.parseHandshakeInit(data) catch return;

        // Create responder handshake state
        var hs = HandshakeState.init(.{
            .pattern = .IK,
            .initiator = false,
            .local_static = self.local_key.*,
        }) catch return;

        // Build noise message from wire format
        var noise_msg: [80]u8 = undefined;
        @memcpy(noise_msg[0..32], &msg.ephemeral.data);
        @memcpy(noise_msg[32..80], &msg.static_encrypted);

        // Read message 1
        _ = hs.readMessage(&noise_msg, &[_]u8{}) catch return;

        // Get remote public key
        const remote_pk = hs.getRemoteStatic();

        // Check if we allow this peer
        if (!self.allow_unknown) {
            self.peers_mutex.lock();
            const exists = self.peers.contains(remote_pk.data);
            self.peers_mutex.unlock();
            if (!exists) return;
        }

        // Generate our sender index
        const sender_index = self.next_index.fetchAdd(1, .monotonic);

        // Write response
        var resp_noise: [48]u8 = undefined; // e(32) + ee(16)
        _ = hs.writeMessage(&[_]u8{}, &resp_noise) catch return;

        // Build wire message
        var resp_buf: [message.handshake_resp_size]u8 = undefined;
        resp_buf[0] = @intFromEnum(message.MessageType.handshake_resp);
        mem.writeInt(u32, resp_buf[1..5], sender_index, .little);
        mem.writeInt(u32, resp_buf[5..9], msg.sender_index, .little);
        @memcpy(resp_buf[9..41], resp_noise[0..32]); // ephemeral
        @memcpy(resp_buf[41..57], resp_noise[32..48]); // encrypted empty

        // Send response
        _ = posix.sendto(self.socket, &resp_buf, 0, @ptrCast(from), from_len) catch return;

        // Create session from split cipher states
        const send_cipher, const recv_cipher = hs.split() catch return;
        const session = self.allocator.create(Session) catch return;
        session.* = Session.init(.{
            .local_index = sender_index,
            .remote_index = msg.sender_index,
            .send_key = send_cipher.key,
            .recv_key = recv_cipher.key,
            .remote_pk = remote_pk,
        });

        // Store session
        self.peers_mutex.lock();

        const peer = self.getOrCreatePeerLocked(remote_pk);
        if (peer.session) |old| {
            self.allocator.destroy(old);
        }
        peer.session = session;
        peer.endpoint = @as(*const posix.sockaddr, @ptrCast(from)).*;
        peer.endpoint_len = from_len;

        self.by_index.put(sender_index, remote_pk) catch {};
        self.peers_mutex.unlock();

        // Initialize KCP mux for this peer
        self.initMux(peer);
    }

    fn handleHandshakeResp(self: *Self, data: []const u8, from: *const posix.sockaddr.in, from_len: posix.socklen_t) void {
        const msg = message.parseHandshakeResp(data) catch return;

        // Find pending handshake
        const pending = blk: {
            self.pending_mutex.lock();
            defer self.pending_mutex.unlock();
            break :blk self.pending.get(msg.receiver_index) orelse return;
        };

        // Build noise message
        var noise_msg: [48]u8 = undefined;
        @memcpy(noise_msg[0..32], &msg.ephemeral.data);
        @memcpy(noise_msg[32..48], &msg.empty_encrypted);

        // Read response
        _ = pending.hs.readMessage(&noise_msg, &[_]u8{}) catch {
            pending.success = false;
            pending.done.signal();
            return;
        };

        // Create session from split cipher states
        const send_cipher, const recv_cipher = pending.hs.split() catch {
            pending.success = false;
            pending.done.signal();
            return;
        };

        const session = self.allocator.create(Session) catch {
            pending.success = false;
            pending.done.signal();
            return;
        };

        session.* = Session.init(.{
            .local_index = msg.receiver_index,
            .remote_index = msg.sender_index,
            .send_key = send_cipher.key,
            .recv_key = recv_cipher.key,
            .remote_pk = pending.pk,
        });

        // Store session
        self.peers_mutex.lock();

        const peer = self.getOrCreatePeerLocked(pending.pk);
        if (peer.session) |old| {
            self.allocator.destroy(old);
        }
        peer.session = session;
        peer.endpoint = @as(*const posix.sockaddr, @ptrCast(from)).*;
        peer.endpoint_len = from_len;

        self.by_index.put(msg.receiver_index, pending.pk) catch {};
        self.peers_mutex.unlock();

        // Initialize KCP mux for this peer
        self.initMux(peer);

        pending.success = true;
        pending.done.signal();
    }

    // ========================================================================
    // Internal: Helpers
    // ========================================================================

    fn getOrCreatePeerLocked(self: *Self, pk: Key) *PeerState {
        if (self.peers.get(pk.data)) |peer| {
            return peer;
        }

        const peer = self.allocator.create(PeerState) catch unreachable;
        peer.* = PeerState.init(pk);
        self.peers.put(pk.data, peer) catch unreachable;
        return peer;
    }

    fn cleanupPending(self: *Self, index: u32) void {
        self.pending_mutex.lock();
        defer self.pending_mutex.unlock();

        if (self.pending.fetchRemove(index)) |kv| {
            self.allocator.destroy(kv.value.hs);
            self.allocator.destroy(kv.value);
        }
    }

    fn parseBindAddr(addr: []const u8) ?posix.sockaddr.in {
        // Simple parser for "host:port"
        var it = std.mem.splitScalar(u8, addr, ':');
        const host = it.next() orelse return null;
        const port_str = it.next() orelse return null;

        const port = std.fmt.parseInt(u16, port_str, 10) catch return null;

        var result: posix.sockaddr.in = .{
            .family = posix.AF.INET,
            .port = mem.nativeToBig(u16, port),
            .addr = 0,
        };

        if (std.mem.eql(u8, host, "0.0.0.0")) {
            result.addr = 0;
        } else if (std.mem.eql(u8, host, "127.0.0.1")) {
            result.addr = mem.nativeToBig(u32, 0x7F000001);
        } else {
            // Parse IP address
            var octets: [4]u8 = undefined;
            var octet_it = std.mem.splitScalar(u8, host, '.');
            for (&octets) |*octet| {
                const s = octet_it.next() orelse return null;
                octet.* = std.fmt.parseInt(u8, s, 10) catch return null;
            }
            result.addr = mem.bytesToValue(u32, &octets);
        }

        return result;
    }
    };
}

// ============================================================================
// Tests
// ============================================================================

test "PacketPool basic" {
    const allocator = std.testing.allocator;

    var pool = try PacketPool.init(allocator, 4);
    defer pool.deinit();

    // Acquire all packets
    const p1 = pool.acquire().?;
    const p2 = pool.acquire().?;
    const p3 = pool.acquire().?;
    const p4 = pool.acquire().?;

    // Pool should be empty
    try std.testing.expect(pool.acquire() == null);

    // Release one
    pool.release(p1);

    // Can acquire again
    const p5 = pool.acquire().?;
    try std.testing.expect(p5 == p1);

    // Cleanup
    pool.release(p2);
    pool.release(p3);
    pool.release(p4);
    pool.release(p5);
}

test "UDP end-to-end: handshake + send/recv" {
    const builtin = @import("builtin");
    const has_kqueue = comptime (builtin.os.tag == .macos or builtin.os.tag == .freebsd or
        builtin.os.tag == .netbsd or builtin.os.tag == .openbsd);

    if (comptime has_kqueue) {
        const KqueueIO = async_mod.KqueueIO;
        const UDPImpl = UDP(KqueueIO);

        const allocator = std.testing.allocator;

        // Create two keypairs
        var priv1: [32]u8 = undefined;
        var priv2: [32]u8 = undefined;
        @memset(&priv1, 0);
        @memset(&priv2, 0);
        priv1[31] = 1;
        priv2[31] = 2;
        const kp1 = noise.KeyPair.fromPrivate(noise.Key.fromBytes(priv1));
        const kp2 = noise.KeyPair.fromPrivate(noise.Key.fromBytes(priv2));

        // Create two UDP instances on random ports
        const udp1 = try UDPImpl.init(allocator, &kp1, .{
            .bind_addr = "127.0.0.1:0",
            .allow_unknown = true,
            .decrypt_workers = 1,
        });
        defer udp1.deinit();

        const udp2 = try UDPImpl.init(allocator, &kp2, .{
            .bind_addr = "127.0.0.1:0",
            .allow_unknown = true,
            .decrypt_workers = 1,
        });
        defer udp2.deinit();

        const port1 = udp1.getLocalPort();
        const port2 = udp2.getLocalPort();

        // Set peer endpoints
        var ep1: posix.sockaddr.in = .{
            .family = posix.AF.INET,
            .port = mem.nativeToBig(u16, port1),
            .addr = mem.nativeToBig(u32, 0x7F000001),
        };
        var ep2: posix.sockaddr.in = .{
            .family = posix.AF.INET,
            .port = mem.nativeToBig(u16, port2),
            .addr = mem.nativeToBig(u32, 0x7F000001),
        };

        udp1.setPeerEndpoint(kp2.public, @as(*posix.sockaddr, @ptrCast(&ep2)).*, @sizeOf(posix.sockaddr.in));
        udp2.setPeerEndpoint(kp1.public, @as(*posix.sockaddr, @ptrCast(&ep1)).*, @sizeOf(posix.sockaddr.in));

        // Handshake: udp1 connects to udp2
        try udp1.connect(&kp2.public);

        // Send a message from udp1 to udp2
        const msg = "hello from udp1";
        try udp1.writeTo(&kp2.public, msg);

        // Read on udp2
        var buf: [256]u8 = undefined;
        const result = try udp2.readFrom(&buf);
        try std.testing.expectEqual(msg.len, result.n);
        try std.testing.expectEqualSlices(u8, msg, buf[0..result.n]);
        try std.testing.expectEqualSlices(u8, &kp1.public.data, &result.pk.data);

        // Send reply from udp2 to udp1
        const reply = "hello back from udp2";
        try udp2.writeTo(&kp1.public, reply);

        // Read on udp1
        const result2 = try udp1.readFrom(&buf);
        try std.testing.expectEqual(reply.len, result2.n);
        try std.testing.expectEqualSlices(u8, reply, buf[0..result2.n]);
    }
}

test "Channel with Packet pointers" {
    const allocator = std.testing.allocator;

    var pool = try PacketPool.init(allocator, 4);
    defer pool.deinit();

    var ch = try Channel(*Packet).init(allocator, 4);
    defer ch.deinit();

    // Send packets through channel
    const p1 = pool.acquire().?;
    const p2 = pool.acquire().?;

    try ch.send(p1);
    try ch.send(p2);

    // Receive
    const r1 = ch.recv().?;
    const r2 = ch.recv().?;

    try std.testing.expect(r1 == p1);
    try std.testing.expect(r2 == p2);

    pool.release(r1);
    pool.release(r2);
}
