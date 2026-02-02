//! Unified UDP networking layer for zgrnet.
//!
//! Provides a single `UDP` type that manages multiple peers, handles
//! Noise Protocol handshakes, and supports roaming.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Mutex = std.Thread.Mutex;
const Atomic = std.atomic.Value;
const posix = std.posix;

const noise = @import("../noise/mod.zig");

pub const Key = noise.Key;
pub const KeyPair = noise.KeyPair;
pub const key_size = noise.key_size;
pub const Session = noise.Session;
pub const SessionConfig = noise.SessionConfig;
pub const HandshakeState = noise.HandshakeState;
pub const Config = noise.Config;
pub const Pattern = noise.Pattern;
const message = noise.message;

/// Peer connection state.
pub const PeerState = enum {
    /// Newly registered peer.
    new,
    /// Performing handshake.
    connecting,
    /// Session established.
    established,
    /// Connection failed.
    failed,

    pub fn format(
        self: PeerState,
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        try writer.writeAll(switch (self) {
            .new => "new",
            .connecting => "connecting",
            .established => "established",
            .failed => "failed",
        });
    }
};


/// Information about a peer.
pub const PeerInfo = struct {
    public_key: Key,
    endpoint_port: u16,
    endpoint_addr: u32, // IPv4 address in network byte order
    has_endpoint: bool,
    state: PeerState,
    rx_bytes: u64,
    tx_bytes: u64,
    last_seen_ns: i64,
};

/// Information about the local host.
pub const HostInfo = struct {
    public_key: Key,
    addr_port: u16,
    addr_ip: u32, // IPv4 address in network byte order
    peer_count: usize,
    rx_bytes: u64,
    tx_bytes: u64,
    last_seen_ns: i64,
};

/// A peer with its info.
pub const Peer = struct {
    info: PeerInfo,
};

/// Errors from UDP operations.
pub const UdpError = error{
    /// UDP socket is closed.
    Closed,
    /// Peer not found.
    PeerNotFound,
    /// Peer has no endpoint.
    NoEndpoint,
    /// Peer has no established session.
    NoSession,
    /// Handshake failed.
    HandshakeFailed,
    /// Handshake timeout.
    HandshakeTimeout,
    /// Socket bind failed.
    BindFailed,
    /// Socket receive failed.
    ReceiveFailed,
    /// Socket send failed.
    SendFailed,
    /// Encryption failed.
    EncryptFailed,
    /// Decryption failed.
    DecryptFailed,
    /// Out of memory.
    OutOfMemory,
    /// Message too short.
    MessageTooShort,
};

/// Result of reading from UDP.
pub const ReadResult = struct {
    pk: Key,
    n: usize,
};

/// Raw packet from socket (for pipeline processing).
/// The caller owns the data buffer and is responsible for freeing it.
pub const RawPacket = struct {
    /// Raw data buffer (caller-owned).
    data: []u8,
    /// Actual data length.
    len: usize,
    /// Sender's socket address.
    from: posix.sockaddr,
    /// Address length.
    from_len: posix.socklen_t,
};

/// Decrypted packet ready for consumption (for pipeline processing).
pub const DecryptedPacket = struct {
    /// Sender's public key.
    pk: Key,
    /// Protocol byte.
    protocol: u8,
    /// Decrypted payload (slice into caller's buffer).
    payload: []const u8,
    /// Payload length.
    len: usize,
    /// True if this is a handshake packet (handled internally).
    is_handshake: bool,
    /// True if decryption was successful.
    ok: bool,
};

/// Internal peer state.
const PeerStateInternal = struct {
    mutex: Mutex = .{},
    pk: Key,
    endpoint: ?posix.sockaddr,
    endpoint_len: posix.socklen_t,
    endpoint_port: u16, // Cached port (network byte order converted)
    endpoint_addr: u32, // Cached IPv4 addr (network byte order)
    session: ?Session,
    state: PeerState,
    rx_bytes: u64,
    tx_bytes: u64,
    last_seen: ?i128,
};

/// Pending handshake tracking.
const PendingHandshake = struct {
    peer_pk: Key,
    hs_state: HandshakeState,
    local_idx: u32,
    done: bool,
    result: ?UdpError,
    created_at: i128,
};

/// Options for creating a UDP instance.
pub const UdpOptions = struct {
    /// Address to bind to. Default is "0.0.0.0:0".
    bind_addr: ?[]const u8 = null,
    /// Port to bind to (overrides bind_addr port).
    port: u16 = 0,
    /// Allow connections from unknown peers.
    allow_unknown: bool = false,
};

/// UDP-based network using the Noise Protocol.
///
/// Manages multiple peers, handles handshakes, and supports roaming.
pub const UDP = struct {
    allocator: Allocator,
    socket: posix.socket_t,
    local_key: KeyPair,
    allow_unknown: bool,

    // Peer management
    peers_mutex: Mutex = .{},
    peers_map: std.AutoHashMap(Key, *PeerStateInternal),
    by_index: std.AutoHashMap(u32, Key),

    // Pending handshakes (as initiator)
    pending_mutex: Mutex = .{},
    pending: std.AutoHashMap(u32, *PendingHandshake),

    // Statistics
    total_rx: Atomic(u64) = Atomic(u64).init(0),
    total_tx: Atomic(u64) = Atomic(u64).init(0),
    last_seen: Atomic(i128) = Atomic(i128).init(0),

    // State
    closed: Atomic(bool) = Atomic(bool).init(false),

    // Local address
    local_addr: posix.sockaddr,
    local_addr_len: posix.socklen_t,
    local_port: u16,

    /// Creates a new UDP network.
    pub fn init(allocator: Allocator, key: KeyPair, opts: UdpOptions) UdpError!*UDP {
        const self = allocator.create(UDP) catch return UdpError.OutOfMemory;
        errdefer allocator.destroy(self);

        // Create socket
        const socket = posix.socket(posix.AF.INET, posix.SOCK.DGRAM, 0) catch return UdpError.BindFailed;
        errdefer posix.close(socket);

        // Set socket to non-blocking mode
        const current_flags = posix.fcntl(socket, posix.F.GETFL, 0) catch 0;
        var o_flags: posix.O = @bitCast(@as(u32, @truncate(current_flags)));
        o_flags.NONBLOCK = true;
        _ = posix.fcntl(socket, posix.F.SETFL, @as(usize, @as(u32, @bitCast(o_flags)))) catch {};

        // Bind address
        var addr: posix.sockaddr.in = .{
            .family = posix.AF.INET,
            .port = std.mem.nativeToBig(u16, opts.port),
            .addr = 0, // INADDR_ANY
        };

        posix.bind(socket, @ptrCast(&addr), @sizeOf(posix.sockaddr.in)) catch return UdpError.BindFailed;

        // Get actual bound address (reuse addr which is properly aligned)
        var bound_addr_len: posix.socklen_t = @sizeOf(posix.sockaddr.in);
        posix.getsockname(socket, @ptrCast(&addr), &bound_addr_len) catch return UdpError.BindFailed;

        // Extract the actual port after binding
        const local_port = std.mem.bigToNative(u16, addr.port);

        self.* = .{
            .allocator = allocator,
            .socket = socket,
            .local_key = key,
            .allow_unknown = opts.allow_unknown,
            .peers_map = std.AutoHashMap(Key, *PeerStateInternal).init(allocator),
            .by_index = std.AutoHashMap(u32, Key).init(allocator),
            .pending = std.AutoHashMap(u32, *PendingHandshake).init(allocator),
            .local_addr = @as(*posix.sockaddr, @ptrCast(&addr)).*,
            .local_addr_len = bound_addr_len,
            .local_port = local_port,
        };

        return self;
    }

    /// Cleanup and release all resources.
    pub fn deinit(self: *UDP) void {
        self.closed.store(true, .seq_cst);

        // Close socket
        posix.close(self.socket);

        // Free peers
        var peer_iter = self.peers_map.valueIterator();
        while (peer_iter.next()) |peer_ptr| {
            self.allocator.destroy(peer_ptr.*);
        }
        self.peers_map.deinit();
        self.by_index.deinit();

        // Free pending
        var pending_iter = self.pending.valueIterator();
        while (pending_iter.next()) |p_ptr| {
            self.allocator.destroy(p_ptr.*);
        }
        self.pending.deinit();

        self.allocator.destroy(self);
    }

    /// Sets or updates a peer's endpoint address.
    pub fn setPeerEndpoint(self: *UDP, pk: Key, addr: posix.sockaddr, addr_len: posix.socklen_t) void {
        if (self.closed.load(.seq_cst)) {
            return;
        }

        // Extract port and address from sockaddr (avoid alignment issues)
        // Note: sockaddr.in stores port and addr in network byte order (big endian)
        var ep_port: u16 = 0;
        var ep_addr: u32 = 0;
        if (addr_len >= @sizeOf(posix.sockaddr.in)) {
            // Use byte-level access to avoid alignment issues
            const bytes: [*]const u8 = @ptrCast(&addr);
            // readInt with .big interprets bytes as big-endian and returns native order
            ep_port = std.mem.readInt(u16, bytes[2..4], .big);
            ep_addr = std.mem.readInt(u32, bytes[4..8], .big);
        }

        self.peers_mutex.lock();
        defer self.peers_mutex.unlock();

        if (self.peers_map.get(pk)) |peer| {
            peer.mutex.lock();
            defer peer.mutex.unlock();
            peer.endpoint = addr;
            peer.endpoint_len = addr_len;
            peer.endpoint_port = ep_port;
            peer.endpoint_addr = ep_addr;
        } else {
            const peer = self.allocator.create(PeerStateInternal) catch return;
            peer.* = .{
                .pk = pk,
                .endpoint = addr,
                .endpoint_len = addr_len,
                .endpoint_port = ep_port,
                .endpoint_addr = ep_addr,
                .session = null,
                .state = .new,
                .rx_bytes = 0,
                .tx_bytes = 0,
                .last_seen = null,
            };
            self.peers_map.put(pk, peer) catch {
                self.allocator.destroy(peer);
            };
        }
    }

    /// Removes a peer.
    pub fn removePeer(self: *UDP, pk: *const Key) void {
        self.peers_mutex.lock();
        defer self.peers_mutex.unlock();

        if (self.peers_map.fetchRemove(pk.*)) |kv| {
            const peer = kv.value;
            {
                peer.mutex.lock();
                defer peer.mutex.unlock();
                if (peer.session) |*session| {
                    _ = self.by_index.remove(session.localIndex());
                }
            }
            self.allocator.destroy(peer);
        }
    }

    /// Returns the local public key.
    pub fn publicKey(self: *UDP) Key {
        return self.local_key.public;
    }

    /// Returns the local port.
    pub fn port(self: *UDP) u16 {
        return self.local_port;
    }

    /// Returns the peer count.
    pub fn peerCount(self: *UDP) usize {
        self.peers_mutex.lock();
        defer self.peers_mutex.unlock();
        return self.peers_map.count();
    }

    /// Returns the total received bytes.
    pub fn rxBytes(self: *UDP) u64 {
        return self.total_rx.load(.seq_cst);
    }

    /// Returns the total transmitted bytes.
    pub fn txBytes(self: *UDP) u64 {
        return self.total_tx.load(.seq_cst);
    }

    /// Returns information about a specific peer.
    pub fn peerInfo(self: *UDP, pk: *const Key) ?PeerInfo {
        const peer = blk: {
            self.peers_mutex.lock();
            defer self.peers_mutex.unlock();
            break :blk self.peers_map.get(pk.*) orelse return null;
        };

        peer.mutex.lock();
        defer peer.mutex.unlock();

        const has_endpoint = peer.endpoint != null;
        const last_seen_ns: i64 = if (peer.last_seen) |ls| @as(i64, @truncate(@mod(ls, std.math.maxInt(i64)))) else 0;

        return .{
            .public_key = peer.pk,
            .endpoint_port = peer.endpoint_port,
            .endpoint_addr = peer.endpoint_addr,
            .has_endpoint = has_endpoint,
            .state = peer.state,
            .rx_bytes = peer.rx_bytes,
            .tx_bytes = peer.tx_bytes,
            .last_seen_ns = last_seen_ns,
        };
    }

    /// Returns all peers.
    pub fn peers(self: *UDP, allocator: Allocator) ![]Peer {
        self.peers_mutex.lock();
        defer self.peers_mutex.unlock();

        var result = std.ArrayList(Peer).init(allocator);
        errdefer result.deinit();

        var iter = self.peers_map.valueIterator();
        while (iter.next()) |peer_ptr| {
            const peer = peer_ptr.*;
            peer.mutex.lock();
            defer peer.mutex.unlock();

            const has_endpoint = peer.endpoint != null;
            const last_seen_ns: i64 = if (peer.last_seen) |ls| @as(i64, @truncate(@mod(ls, std.math.maxInt(i64)))) else 0;

            try result.append(.{
                .info = .{
                    .public_key = peer.pk,
                    .endpoint_port = peer.endpoint_port,
                    .endpoint_addr = peer.endpoint_addr,
                    .has_endpoint = has_endpoint,
                    .state = peer.state,
                    .rx_bytes = peer.rx_bytes,
                    .tx_bytes = peer.tx_bytes,
                    .last_seen_ns = last_seen_ns,
                },
            });
        }

        return result.toOwnedSlice();
    }

    /// Sends encrypted data to a peer.
    pub fn writeTo(self: *UDP, pk: *const Key, data: []const u8) UdpError!void {
        if (self.closed.load(.seq_cst)) {
            return UdpError.Closed;
        }

        const peer = blk: {
            self.peers_mutex.lock();
            defer self.peers_mutex.unlock();
            break :blk self.peers_map.get(pk.*) orelse return UdpError.PeerNotFound;
        };

        peer.mutex.lock();
        defer peer.mutex.unlock();

        const endpoint = peer.endpoint orelse return UdpError.NoEndpoint;
        var session = peer.session orelse return UdpError.NoSession;

        // Encrypt the data
        var ciphertext: [message.max_packet_size]u8 = undefined;
        const nonce = session.encrypt(data, ciphertext[0 .. data.len + 16]) catch return UdpError.EncryptFailed;

        // Build transport message
        const header = message.buildTransportHeader(session.remoteIndex(), nonce);
        var msg: [message.max_packet_size]u8 = undefined;
        @memcpy(msg[0..message.transport_header_size], &header);
        @memcpy(msg[message.transport_header_size..][0 .. data.len + 16], ciphertext[0 .. data.len + 16]);

        const msg_len = message.transport_header_size + data.len + 16;

        // Send
        const n = posix.sendto(self.socket, msg[0..msg_len], 0, &endpoint, peer.endpoint_len) catch return UdpError.SendFailed;

        // Update stats
        _ = self.total_tx.fetchAdd(@intCast(n), .seq_cst);
        peer.tx_bytes += @intCast(n);
        peer.session = session;
    }

    // ========== Pipeline API for high-throughput scenarios ==========
    // These methods allow the caller to manage threads and queues externally.
    // Usage pattern:
    // 1. Call processIO() in an I/O thread to read raw packets
    // 2. Call processDecrypt() in worker threads to decrypt packets
    // 3. Consume DecryptedPacket results

    /// Reads a raw packet from the socket (for pipeline processing).
    /// The caller must provide a buffer and owns the returned data.
    /// This is a blocking call that returns when a packet is received.
    /// Returns RawPacket with data slice into the provided buffer.
    pub fn processIO(self: *UDP, buf: []u8) UdpError!RawPacket {
        if (self.closed.load(.seq_cst)) {
            return UdpError.Closed;
        }

        var from_addr: posix.sockaddr.in = undefined;
        var from_addr_len: posix.socklen_t = @sizeOf(posix.sockaddr.in);

        const nr = posix.recvfrom(self.socket, buf, 0, @ptrCast(&from_addr), &from_addr_len) catch |err| {
            if (err == error.WouldBlock) {
                return UdpError.ReceiveFailed;
            }
            if (self.closed.load(.seq_cst)) {
                return UdpError.Closed;
            }
            return UdpError.ReceiveFailed;
        };

        if (nr < 1) {
            return UdpError.MessageTooShort;
        }

        // Update stats
        _ = self.total_rx.fetchAdd(@intCast(nr), .seq_cst);
        self.last_seen.store(std.time.nanoTimestamp(), .seq_cst);

        return RawPacket{
            .data = buf[0..nr],
            .len = nr,
            .from = @as(*posix.sockaddr, @ptrCast(&from_addr)).*,
            .from_len = from_addr_len,
        };
    }

    /// Decrypts a raw packet and returns the result (for pipeline processing).
    /// The caller provides an output buffer for the decrypted payload.
    /// Handshakes are handled internally.
    pub fn processDecrypt(self: *UDP, raw: *const RawPacket, out_buf: []u8) DecryptedPacket {
        var result = DecryptedPacket{
            .pk = undefined,
            .protocol = 0,
            .payload = &[_]u8{},
            .len = 0,
            .is_handshake = false,
            .ok = false,
        };

        if (raw.len < 1) {
            return result;
        }

        // Parse message type
        const msg_type: message.MessageType = @enumFromInt(raw.data[0]);

        // Cast sockaddr to sockaddr.in for IPv4
        const from_addr: *const posix.sockaddr.in = @ptrCast(@alignCast(&raw.from));

        switch (msg_type) {
            .handshake_init => {
                self.handleHandshakeInit(raw.data[0..raw.len], from_addr, raw.from_len);
                result.is_handshake = true;
                result.ok = true;
                return result;
            },
            .handshake_resp => {
                self.handleHandshakeResp(raw.data[0..raw.len], from_addr, raw.from_len);
                result.is_handshake = true;
                result.ok = true;
                return result;
            },
            .transport => {
                // Process transport message
                if (self.processTransportPacket(raw.data[0..raw.len], from_addr, raw.from_len, out_buf)) |transport_result| {
                    result.pk = transport_result.pk;
                    result.payload = out_buf[0..transport_result.n];
                    result.len = transport_result.n;
                    result.ok = true;
                }
                return result;
            },
            else => return result,
        }
    }

    /// Internal: process a transport packet for pipeline use.
    fn processTransportPacket(self: *UDP, data: []const u8, from: *const posix.sockaddr.in, from_len: posix.socklen_t, out_buf: []u8) ?ReadResult {
        _ = from_len;
        // This is similar to handleTransport but returns the result instead of modifying buf
        const msg = message.parseTransportMessage(data) catch return null;

        // Find peer by receiver index
        const peer = blk: {
            self.peers_mutex.lock();
            defer self.peers_mutex.unlock();
            const pk = self.by_index.get(msg.receiver_index) orelse return null;
            break :blk self.peers_map.get(pk) orelse return null;
        };

        peer.mutex.lock();
        defer peer.mutex.unlock();

        var session = peer.session orelse return null;

        // Decrypt directly into out_buf
        const n = session.decrypt(msg.ciphertext, msg.counter, out_buf) catch return null;

        // Update peer state
        peer.endpoint = @as(*const posix.sockaddr, @ptrCast(from)).*;
        peer.endpoint_len = @sizeOf(posix.sockaddr.in);
        peer.endpoint_port = std.mem.bigToNative(u16, from.port);
        peer.endpoint_addr = std.mem.bigToNative(u32, from.addr);
        peer.rx_bytes += @intCast(data.len);
        peer.last_seen = std.time.nanoTimestamp();
        peer.session = session;

        return ReadResult{
            .pk = peer.pk,
            .n = n,
        };
    }

    // ========== End Pipeline API ==========

    /// Reads the next decrypted message from any peer.
    /// Handles handshakes internally and only returns transport data.
    /// Returns (sender_pk, bytes_read).
    pub fn readFrom(self: *UDP, buf: []u8) UdpError!ReadResult {
        if (self.closed.load(.seq_cst)) {
            return UdpError.Closed;
        }

        var recv_buf: [message.max_packet_size]u8 = undefined;

        while (true) {
            if (self.closed.load(.seq_cst)) {
                return UdpError.Closed;
            }

            // Read from socket (non-blocking)
            // Use sockaddr.in directly for IPv4 - this ensures proper alignment and size
            var from_addr: posix.sockaddr.in = undefined;
            var from_addr_len: posix.socklen_t = @sizeOf(posix.sockaddr.in);

            const nr = posix.recvfrom(self.socket, &recv_buf, 0, @ptrCast(&from_addr), &from_addr_len) catch |err| {
                if (err == error.WouldBlock) {
                    // Non-blocking, sleep a bit
                    std.Thread.sleep(1 * std.time.ns_per_ms);
                    continue;
                }
                if (self.closed.load(.seq_cst)) {
                    return UdpError.Closed;
                }
                return UdpError.ReceiveFailed;
            };

            if (nr < 1) {
                continue;
            }

            // Update stats
            _ = self.total_rx.fetchAdd(@intCast(nr), .seq_cst);
            self.last_seen.store(std.time.nanoTimestamp(), .seq_cst);

            // Parse message type
            const msg_type: message.MessageType = @enumFromInt(recv_buf[0]);

            switch (msg_type) {
                .handshake_init => {
                    self.handleHandshakeInit(recv_buf[0..nr], &from_addr, from_addr_len);
                    continue;
                },
                .handshake_resp => {
                    self.handleHandshakeResp(recv_buf[0..nr], &from_addr, from_addr_len);
                    continue;
                },
                .transport => {
                    if (self.handleTransport(recv_buf[0..nr], &from_addr, from_addr_len, buf)) |result| {
                        return result;
                    }
                    continue;
                },
                else => continue,
            }
        }
    }

    /// Initiates a handshake with a peer.
    pub fn connect(self: *UDP, pk: *const Key) UdpError!void {
        return self.connectTimeout(pk, 5 * std.time.ns_per_s);
    }

    /// Initiates a handshake with a peer with timeout.
    pub fn connectTimeout(self: *UDP, pk: *const Key, timeout_ns: i128) UdpError!void {
        if (self.closed.load(.seq_cst)) {
            return UdpError.Closed;
        }

        const peer = blk: {
            self.peers_mutex.lock();
            defer self.peers_mutex.unlock();
            break :blk self.peers_map.get(pk.*) orelse return UdpError.PeerNotFound;
        };

        const endpoint, const endpoint_len = blk: {
            peer.mutex.lock();
            defer peer.mutex.unlock();
            const ep = peer.endpoint orelse return UdpError.NoEndpoint;
            const ep_len = peer.endpoint_len;
            peer.state = .connecting;
            break :blk .{ ep, ep_len };
        };

        // Generate local index
        const local_idx = noise.session.generateIndex();

        // Create handshake state
        var hs = HandshakeState.init(.{
            .pattern = .IK,
            .initiator = true,
            .local_static = self.local_key,
            .remote_static = pk.*,
        }) catch return UdpError.HandshakeFailed;

        // Write handshake initiation
        var msg_buf: [256]u8 = undefined;
        const msg_len = hs.writeMessage(&.{}, &msg_buf) catch return UdpError.HandshakeFailed;

        // Build wire message
        const ephemeral = hs.local_ephemeral orelse return UdpError.HandshakeFailed;
        const wire_msg = message.buildHandshakeInit(local_idx, &ephemeral.public, msg_buf[key_size..msg_len]);

        // Register pending handshake
        const pending = self.allocator.create(PendingHandshake) catch return UdpError.OutOfMemory;
        pending.* = .{
            .peer_pk = pk.*,
            .hs_state = hs,
            .local_idx = local_idx,
            .done = false,
            .result = null,
            .created_at = std.time.nanoTimestamp(),
        };

        {
            self.pending_mutex.lock();
            defer self.pending_mutex.unlock();
            self.pending.put(local_idx, pending) catch {
                self.allocator.destroy(pending);
                return UdpError.OutOfMemory;
            };
        }

        // Send handshake initiation
        _ = posix.sendto(self.socket, &wire_msg, 0, &endpoint, endpoint_len) catch {
            self.pending_mutex.lock();
            defer self.pending_mutex.unlock();
            _ = self.pending.remove(local_idx);
            self.allocator.destroy(pending);
            return UdpError.SendFailed;
        };

        // Wait for response with timeout
        const start = std.time.nanoTimestamp();
        while (true) {
            self.pending_mutex.lock();
            const p = self.pending.get(local_idx);
            if (p) |pend| {
                if (pend.done) {
                    const result = pend.result;
                    _ = self.pending.remove(local_idx);
                    self.pending_mutex.unlock();
                    self.allocator.destroy(pend);
                    if (result) |err| {
                        return err;
                    }
                    return;
                }
            } else {
                // Already removed (completed)
                self.pending_mutex.unlock();
                return;
            }
            self.pending_mutex.unlock();

            const elapsed = std.time.nanoTimestamp() - start;
            if (elapsed > timeout_ns) {
                self.pending_mutex.lock();
                _ = self.pending.remove(local_idx);
                self.pending_mutex.unlock();
                self.allocator.destroy(pending);

                peer.mutex.lock();
                peer.state = .failed;
                peer.mutex.unlock();
                return UdpError.HandshakeTimeout;
            }

            std.Thread.sleep(10 * std.time.ns_per_ms);
        }
    }

    /// Closes the UDP network.
    pub fn close(self: *UDP) void {
        self.closed.store(true, .seq_cst);
    }

    /// Returns true if the UDP network is closed.
    pub fn isClosed(self: *UDP) bool {
        return self.closed.load(.seq_cst);
    }

    // Internal: handle incoming handshake initiation
    fn handleHandshakeInit(self: *UDP, data: []const u8, from: *const posix.sockaddr.in, from_len: posix.socklen_t) void {
        const msg = message.parseHandshakeInit(data) catch return;

        // Create handshake state to process the init
        var hs = HandshakeState.init(.{
            .pattern = .IK,
            .initiator = false,
            .local_static = self.local_key,
        }) catch return;

        // Build Noise message from wire format
        var noise_msg: [key_size + 48]u8 = undefined;
        @memcpy(noise_msg[0..key_size], msg.ephemeral.asBytes());
        @memcpy(noise_msg[key_size..][0..48], &msg.static_encrypted);

        // Read the handshake message
        var payload_buf: [64]u8 = undefined;
        _ = hs.readMessage(&noise_msg, &payload_buf) catch return;

        // Get the remote's public key
        const remote_pk = hs.getRemoteStatic();

        // Check if peer is known or if we allow unknown peers
        self.peers_mutex.lock();
        if (self.peers_map.get(remote_pk) == null) {
            if (!self.allow_unknown) {
                self.peers_mutex.unlock();
                return;
            }
            const peer = self.allocator.create(PeerStateInternal) catch {
                self.peers_mutex.unlock();
                return;
            };
            peer.* = .{
                .pk = remote_pk,
                .endpoint = @as(*const posix.sockaddr, @ptrCast(from)).*,
                .endpoint_len = from_len,
                .endpoint_port = std.mem.bigToNative(u16, from.port),
                .endpoint_addr = std.mem.bigToNative(u32, from.addr),
                .session = null,
                .state = .new,
                .rx_bytes = 0,
                .tx_bytes = 0,
                .last_seen = null,
            };
            self.peers_map.put(remote_pk, peer) catch {
                self.peers_mutex.unlock();
                self.allocator.destroy(peer);
                return;
            };
        }
        self.peers_mutex.unlock();

        // Generate local index for response
        const local_idx = noise.session.generateIndex();

        // Write response message
        var resp_buf: [256]u8 = undefined;
        const resp_len = hs.writeMessage(&.{}, &resp_buf) catch return;

        // Build wire message
        const ephemeral = hs.local_ephemeral orelse return;
        const wire_msg = message.buildHandshakeResp(local_idx, msg.sender_index, &ephemeral.public, resp_buf[key_size..resp_len]);

        // Send response - cast sockaddr.in to sockaddr for sendto
        _ = posix.sendto(self.socket, &wire_msg, 0, @ptrCast(from), from_len) catch return;

        // Complete handshake and create session
        const cipher_pair = hs.split() catch return;
        const send_cs = cipher_pair[0];
        const recv_cs = cipher_pair[1];

        const session = Session.init(.{
            .local_index = local_idx,
            .remote_index = msg.sender_index,
            .send_key = send_cs.key,
            .recv_key = recv_cs.key,
            .remote_pk = remote_pk,
        });

        // Find peer (release peers_mutex before acquiring peer.mutex)
        const peer_opt: ?*PeerStateInternal = blk: {
            self.peers_mutex.lock();
            defer self.peers_mutex.unlock();
            break :blk self.peers_map.get(remote_pk);
        };

        // Update peer state
        if (peer_opt) |peer| {
            peer.mutex.lock();
            defer peer.mutex.unlock();
            peer.endpoint = @as(*const posix.sockaddr, @ptrCast(from)).*;
            peer.endpoint_len = from_len;
            peer.endpoint_port = std.mem.bigToNative(u16, from.port);
            peer.endpoint_addr = std.mem.bigToNative(u32, from.addr);
            peer.session = session;
            peer.state = .established;
            peer.last_seen = std.time.nanoTimestamp();
        }

        // Register in index map
        {
            self.peers_mutex.lock();
            defer self.peers_mutex.unlock();
            self.by_index.put(local_idx, remote_pk) catch {};
        }
    }

    // Internal: handle incoming handshake response
    fn handleHandshakeResp(self: *UDP, data: []const u8, from: *const posix.sockaddr.in, from_len: posix.socklen_t) void {
        const msg = message.parseHandshakeResp(data) catch return;

        // Find the pending handshake
        const pending = blk: {
            self.pending_mutex.lock();
            defer self.pending_mutex.unlock();
            break :blk self.pending.get(msg.receiver_index) orelse return;
        };

        // Build Noise message from wire format
        var noise_msg: [key_size + 16]u8 = undefined;
        @memcpy(noise_msg[0..key_size], msg.ephemeral.asBytes());
        @memcpy(noise_msg[key_size..][0..16], &msg.empty_encrypted);

        // Read the handshake response
        var payload_buf: [64]u8 = undefined;
        _ = pending.hs_state.readMessage(&noise_msg, &payload_buf) catch {
            // Find peer (release peers_mutex before acquiring peer.mutex)
            const peer_opt: ?*PeerStateInternal = blk: {
                self.peers_mutex.lock();
                defer self.peers_mutex.unlock();
                break :blk self.peers_map.get(pending.peer_pk);
            };
            if (peer_opt) |peer| {
                peer.mutex.lock();
                defer peer.mutex.unlock();
                peer.state = .failed;
            }
            pending.done = true;
            pending.result = UdpError.HandshakeFailed;
            return;
        };

        // Complete handshake and create session
        const cipher_pair = pending.hs_state.split() catch {
            pending.done = true;
            pending.result = UdpError.HandshakeFailed;
            return;
        };
        const send_cs = cipher_pair[0];
        const recv_cs = cipher_pair[1];

        const session = Session.init(.{
            .local_index = pending.local_idx,
            .remote_index = msg.sender_index,
            .send_key = send_cs.key,
            .recv_key = recv_cs.key,
            .remote_pk = pending.peer_pk,
        });

        // Find peer (release peers_mutex before acquiring peer.mutex)
        const peer_opt: ?*PeerStateInternal = blk: {
            self.peers_mutex.lock();
            defer self.peers_mutex.unlock();
            break :blk self.peers_map.get(pending.peer_pk);
        };

        // Update peer state
        if (peer_opt) |peer| {
            peer.mutex.lock();
            defer peer.mutex.unlock();
            peer.endpoint = @as(*const posix.sockaddr, @ptrCast(from)).*;
            peer.endpoint_len = from_len;
            peer.endpoint_port = std.mem.bigToNative(u16, from.port);
            peer.endpoint_addr = std.mem.bigToNative(u32, from.addr);
            peer.session = session;
            peer.state = .established;
            peer.last_seen = std.time.nanoTimestamp();
        }

        // Register in index map
        {
            self.peers_mutex.lock();
            defer self.peers_mutex.unlock();
            self.by_index.put(pending.local_idx, pending.peer_pk) catch {};
        }

        // Signal completion
        pending.done = true;
        pending.result = null;
    }

    // Internal: handle incoming transport message
    fn handleTransport(self: *UDP, data: []const u8, from: *const posix.sockaddr.in, from_len: posix.socklen_t, out_buf: []u8) ?ReadResult {
        const msg = message.parseTransportMessage(data) catch return null;

        // Find peer by receiver index
        const peer = blk: {
            self.peers_mutex.lock();
            defer self.peers_mutex.unlock();
            const peer_pk = self.by_index.get(msg.receiver_index) orelse return null;
            break :blk self.peers_map.get(peer_pk) orelse return null;
        };

        peer.mutex.lock();
        defer peer.mutex.unlock();

        var session = peer.session orelse return null;

        // Decrypt
        const n = session.decrypt(msg.ciphertext, msg.counter, out_buf) catch return null;

        // Update peer state (roaming + stats)
        peer.endpoint = @as(*const posix.sockaddr, @ptrCast(from)).*;
        peer.endpoint_len = from_len;
        peer.endpoint_port = std.mem.bigToNative(u16, from.port);
        peer.endpoint_addr = std.mem.bigToNative(u32, from.addr);
        peer.rx_bytes += @intCast(data.len);
        peer.last_seen = std.time.nanoTimestamp();
        peer.session = session;

        return .{ .pk = peer.pk, .n = n };
    }
};

// =============================================================================
// Tests
// =============================================================================

test "new udp" {
    const allocator = std.testing.allocator;
    const key = KeyPair.generate();
    const udp = try UDP.init(allocator, key, .{});
    defer udp.deinit();
    try std.testing.expect(!udp.isClosed());
    udp.close();
    try std.testing.expect(udp.isClosed());
}

test "set peer endpoint" {
    const allocator = std.testing.allocator;
    const key = KeyPair.generate();
    const udp = try UDP.init(allocator, key, .{});
    defer udp.deinit();

    const peer_key = KeyPair.generate();
    var endpoint: posix.sockaddr.in = .{
        .family = posix.AF.INET,
        .port = std.mem.nativeToBig(u16, 12345),
        .addr = std.mem.nativeToBig(u32, 0x7F000001), // 127.0.0.1 in network byte order
    };

    udp.setPeerEndpoint(peer_key.public, @as(*posix.sockaddr, @ptrCast(&endpoint)).*, @sizeOf(posix.sockaddr.in));

    const info = udp.peerInfo(&peer_key.public);
    try std.testing.expect(info != null);
    try std.testing.expectEqual(PeerState.new, info.?.state);
}

test "remove peer" {
    const allocator = std.testing.allocator;
    const key = KeyPair.generate();
    const udp = try UDP.init(allocator, key, .{});
    defer udp.deinit();

    const peer_key = KeyPair.generate();
    var endpoint: posix.sockaddr.in = .{
        .family = posix.AF.INET,
        .port = std.mem.nativeToBig(u16, 12345),
        .addr = std.mem.nativeToBig(u32, 0x7F000001), // 127.0.0.1 in network byte order
    };

    udp.setPeerEndpoint(peer_key.public, @as(*posix.sockaddr, @ptrCast(&endpoint)).*, @sizeOf(posix.sockaddr.in));
    try std.testing.expect(udp.peerInfo(&peer_key.public) != null);

    udp.removePeer(&peer_key.public);
    try std.testing.expect(udp.peerInfo(&peer_key.public) == null);
}

test "host info methods" {
    const allocator = std.testing.allocator;
    const key = KeyPair.generate();
    const udp = try UDP.init(allocator, key, .{});
    defer udp.deinit();

    try std.testing.expect(std.mem.eql(u8, &udp.publicKey().data, &key.public.data));
    try std.testing.expectEqual(@as(usize, 0), udp.peerCount());
}

test "connect peer not found" {
    const allocator = std.testing.allocator;
    const key = KeyPair.generate();
    const udp = try UDP.init(allocator, key, .{});
    defer udp.deinit();

    const peer_key = KeyPair.generate();

    // Try to connect to unknown peer
    const result = udp.connect(&peer_key.public);
    try std.testing.expectError(UdpError.PeerNotFound, result);
}

test "connect no endpoint" {
    const allocator = std.testing.allocator;
    const key = KeyPair.generate();
    const udp = try UDP.init(allocator, key, .{});
    defer udp.deinit();

    const peer_key = KeyPair.generate();

    // Add peer without endpoint (directly to map without setPeerEndpoint)
    const peer = try allocator.create(PeerStateInternal);
    peer.* = .{
        .pk = peer_key.public,
        .endpoint = null,
        .endpoint_len = 0,
        .endpoint_port = 0,
        .endpoint_addr = 0,
        .session = null,
        .state = .new,
        .rx_bytes = 0,
        .tx_bytes = 0,
        .last_seen = null,
    };
    udp.peers_mutex.lock();
    try udp.peers_map.put(peer_key.public, peer);
    udp.peers_mutex.unlock();

    // Try to connect - should fail with no endpoint
    const result = udp.connect(&peer_key.public);
    try std.testing.expectError(UdpError.NoEndpoint, result);
}

test "connect after close" {
    const allocator = std.testing.allocator;
    const key = KeyPair.generate();
    const udp = try UDP.init(allocator, key, .{});

    const peer_key = KeyPair.generate();
    var endpoint: posix.sockaddr.in = .{
        .family = posix.AF.INET,
        .port = std.mem.nativeToBig(u16, 12345),
        .addr = std.mem.nativeToBig(u32, 0x7F000001),
    };
    udp.setPeerEndpoint(peer_key.public, @as(*posix.sockaddr, @ptrCast(&endpoint)).*, @sizeOf(posix.sockaddr.in));

    // Close and try to connect
    udp.close();
    udp.deinit();

    // Note: After deinit, we can't test connect as the struct is invalid
    // This test mainly ensures close/deinit work correctly
}

test "writeTo peer not found" {
    const allocator = std.testing.allocator;
    const key = KeyPair.generate();
    const udp = try UDP.init(allocator, key, .{});
    defer udp.deinit();

    const peer_key = KeyPair.generate();

    // Try to write to unknown peer
    const result = udp.writeTo(&peer_key.public, "test");
    try std.testing.expectError(UdpError.PeerNotFound, result);
}

test "writeTo no session" {
    const allocator = std.testing.allocator;
    const key = KeyPair.generate();
    const udp = try UDP.init(allocator, key, .{});
    defer udp.deinit();

    const peer_key = KeyPair.generate();
    var endpoint: posix.sockaddr.in = .{
        .family = posix.AF.INET,
        .port = std.mem.nativeToBig(u16, 12345),
        .addr = std.mem.nativeToBig(u32, 0x7F000001),
    };
    udp.setPeerEndpoint(peer_key.public, @as(*posix.sockaddr, @ptrCast(&endpoint)).*, @sizeOf(posix.sockaddr.in));

    // Try to write without session
    const result = udp.writeTo(&peer_key.public, "test");
    try std.testing.expectError(UdpError.NoSession, result);
}

test "writeTo after close" {
    const allocator = std.testing.allocator;
    const key = KeyPair.generate();
    const udp = try UDP.init(allocator, key, .{});
    defer udp.deinit();

    const peer_key = KeyPair.generate();

    // Close UDP
    udp.close();

    // Try to write after close
    const result = udp.writeTo(&peer_key.public, "test");
    try std.testing.expectError(UdpError.Closed, result);
}

test "readFrom after close" {
    const allocator = std.testing.allocator;
    const key = KeyPair.generate();
    const udp = try UDP.init(allocator, key, .{});
    defer udp.deinit();

    // Close UDP
    udp.close();

    // Try to read after close
    var buf: [1024]u8 = undefined;
    const result = udp.readFrom(&buf);
    try std.testing.expectError(UdpError.Closed, result);
}

test "peer state transitions" {
    const allocator = std.testing.allocator;
    const key = KeyPair.generate();
    const udp = try UDP.init(allocator, key, .{});
    defer udp.deinit();

    const peer_key = KeyPair.generate();
    var endpoint: posix.sockaddr.in = .{
        .family = posix.AF.INET,
        .port = std.mem.nativeToBig(u16, 12345),
        .addr = std.mem.nativeToBig(u32, 0x7F000001),
    };
    udp.setPeerEndpoint(peer_key.public, @as(*posix.sockaddr, @ptrCast(&endpoint)).*, @sizeOf(posix.sockaddr.in));

    // Initial state should be new
    const info = udp.peerInfo(&peer_key.public);
    try std.testing.expect(info != null);
    try std.testing.expectEqual(PeerState.new, info.?.state);
}

test "multiple peers" {
    const allocator = std.testing.allocator;
    const key = KeyPair.generate();
    const udp = try UDP.init(allocator, key, .{});
    defer udp.deinit();

    // Add multiple peers
    const num_peers = 5;
    var peers: [num_peers]KeyPair = undefined;

    for (0..num_peers) |i| {
        peers[i] = KeyPair.generate();
        var endpoint: posix.sockaddr.in = .{
            .family = posix.AF.INET,
            .port = std.mem.nativeToBig(u16, @intCast(12345 + i)),
            .addr = std.mem.nativeToBig(u32, 0x7F000001),
        };
        udp.setPeerEndpoint(peers[i].public, @as(*posix.sockaddr, @ptrCast(&endpoint)).*, @sizeOf(posix.sockaddr.in));
    }

    // Verify peer count
    try std.testing.expectEqual(@as(usize, num_peers), udp.peerCount());

    // Verify each peer exists
    for (peers) |peer| {
        try std.testing.expect(udp.peerInfo(&peer.public) != null);
    }

    // Remove one peer
    udp.removePeer(&peers[0].public);
    try std.testing.expectEqual(@as(usize, num_peers - 1), udp.peerCount());
    try std.testing.expect(udp.peerInfo(&peers[0].public) == null);
}

test "RawPacket and DecryptedPacket types" {
    // Test that the pipeline types are correctly defined
    var raw_buf: [1024]u8 = undefined;
    const raw_pkt = RawPacket{
        .data = &raw_buf,
        .len = 100,
        .from = undefined,
        .from_len = @sizeOf(posix.sockaddr.in),
    };
    try std.testing.expectEqual(@as(usize, 100), raw_pkt.len);

    const dec_pkt = DecryptedPacket{
        .pk = undefined,
        .protocol = 128,
        .payload = &[_]u8{},
        .len = 0,
        .is_handshake = false,
        .ok = true,
    };
    try std.testing.expectEqual(@as(u8, 128), dec_pkt.protocol);
    try std.testing.expect(dec_pkt.ok);
    try std.testing.expect(!dec_pkt.is_handshake);
}

test "processIO returns error when closed" {
    const allocator = std.testing.allocator;
    const key = KeyPair.generate();
    const udp = try UDP.init(allocator, key, .{});

    // Close the UDP
    udp.close();
    defer udp.deinit();

    // processIO should return Closed error
    var buf: [1024]u8 = undefined;
    const result = udp.processIO(&buf);
    try std.testing.expectError(UdpError.Closed, result);
}

test "processDecrypt handles empty packet" {
    const allocator = std.testing.allocator;
    const key = KeyPair.generate();
    const udp = try UDP.init(allocator, key, .{});
    defer udp.deinit();

    // Create an empty raw packet
    var raw_buf: [1024]u8 = undefined;
    const raw_pkt = RawPacket{
        .data = raw_buf[0..0], // empty
        .len = 0,
        .from = undefined,
        .from_len = @sizeOf(posix.sockaddr.in),
    };

    // processDecrypt should return not ok for empty packet
    var out_buf: [1024]u8 = undefined;
    const result = udp.processDecrypt(&raw_pkt, &out_buf);
    try std.testing.expect(!result.ok);
}
