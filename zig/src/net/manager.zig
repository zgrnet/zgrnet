//! Session manager for multiple peers.

const std = @import("std");
const Mutex = std.Thread.Mutex;
const Allocator = std.mem.Allocator;

const noise = @import("mod.zig");

pub const Key = noise.Key;
pub const Session = noise.Session;
pub const SessionConfig = noise.SessionConfig;

/// Manager errors.
pub const ManagerError = error{
    IndexInUse,
    OutOfMemory,
    NoFreeIndex,
};

/// Manages multiple sessions with different peers.
pub const SessionManager = struct {
    allocator: Allocator,
    mutex: Mutex = .{},
    by_index: std.AutoHashMap(u32, *Session),
    by_pubkey: std.AutoHashMap(Key, *Session),
    next_index: u32 = 1,

    /// Creates a new session manager.
    pub fn init(allocator: Allocator) SessionManager {
        return .{
            .allocator = allocator,
            .by_index = std.AutoHashMap(u32, *Session).init(allocator),
            .by_pubkey = std.AutoHashMap(Key, *Session).init(allocator),
        };
    }

    /// Deinitializes the manager and frees all sessions.
    pub fn deinit(self: *SessionManager) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        var it = self.by_index.valueIterator();
        while (it.next()) |session_ptr| {
            self.allocator.destroy(session_ptr.*);
        }

        self.by_index.deinit();
        self.by_pubkey.deinit();
    }

    /// Creates and registers a new session.
    pub fn createSession(
        self: *SessionManager,
        remote_pk: Key,
        send_key: Key,
        recv_key: Key,
    ) ManagerError!*Session {
        self.mutex.lock();
        defer self.mutex.unlock();

        const local_index = self.allocateIndex() orelse return ManagerError.NoFreeIndex;

        const session = self.allocator.create(Session) catch return ManagerError.OutOfMemory;
        session.* = Session.init(.{
            .local_index = local_index,
            .send_key = send_key,
            .recv_key = recv_key,
            .remote_pk = remote_pk,
        });

        // Remove existing session for this peer
        if (self.by_pubkey.fetchRemove(remote_pk)) |removed| {
            _ = self.by_index.remove(removed.value.local_index);
            self.allocator.destroy(removed.value);
        }

        self.by_index.put(local_index, session) catch {
            self.allocator.destroy(session);
            return ManagerError.OutOfMemory;
        };

        self.by_pubkey.put(remote_pk, session) catch {
            _ = self.by_index.remove(local_index);
            self.allocator.destroy(session);
            return ManagerError.OutOfMemory;
        };

        return session;
    }

    /// Registers an externally created session.
    pub fn registerSession(self: *SessionManager, session: *Session) ManagerError!void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const local_index = session.local_index;
        const remote_pk = session.remote_pk;

        if (self.by_index.contains(local_index)) {
            return ManagerError.IndexInUse;
        }

        // Remove existing session for this peer
        if (self.by_pubkey.fetchRemove(remote_pk)) |removed| {
            _ = self.by_index.remove(removed.value.local_index);
            self.allocator.destroy(removed.value);
        }

        self.by_index.put(local_index, session) catch return ManagerError.OutOfMemory;
        self.by_pubkey.put(remote_pk, session) catch {
            _ = self.by_index.remove(local_index);
            return ManagerError.OutOfMemory;
        };
    }

    /// Gets a session by local index.
    pub fn getByIndex(self: *SessionManager, index: u32) ?*Session {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.by_index.get(index);
    }

    /// Gets a session by remote public key.
    pub fn getByPubkey(self: *SessionManager, pk: Key) ?*Session {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.by_pubkey.get(pk);
    }

    /// Removes a session by local index.
    pub fn removeSession(self: *SessionManager, index: u32) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.by_index.get(index)) |session| {
            _ = self.by_pubkey.remove(session.remote_pk);
            _ = self.by_index.remove(index);
            self.allocator.destroy(session);
        }
    }

    /// Removes a session by remote public key.
    pub fn removeByPubkey(self: *SessionManager, pk: Key) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.by_pubkey.get(pk)) |session| {
            _ = self.by_index.remove(session.local_index);
            _ = self.by_pubkey.remove(pk);
            self.allocator.destroy(session);
        }
    }

    /// Removes all expired sessions.
    /// Returns the number of sessions removed.
    pub fn expireSessions(self: *SessionManager) usize {
        self.mutex.lock();
        defer self.mutex.unlock();

        var expired = std.ArrayListUnmanaged(u32){};
        defer expired.deinit(self.allocator);

        var it = self.by_index.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.*.isExpired()) {
                expired.append(self.allocator, entry.key_ptr.*) catch continue;
            }
        }

        for (expired.items) |index| {
            if (self.by_index.get(index)) |session| {
                _ = self.by_pubkey.remove(session.remote_pk);
                _ = self.by_index.remove(index);
                self.allocator.destroy(session);
            }
        }

        return expired.items.len;
    }

    /// Returns the number of sessions.
    pub fn count(self: *SessionManager) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.by_index.count();
    }

    /// Clears all sessions.
    pub fn clear(self: *SessionManager) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        var it = self.by_index.valueIterator();
        while (it.next()) |session_ptr| {
            self.allocator.destroy(session_ptr.*);
        }

        self.by_index.clearAndFree();
        self.by_pubkey.clearAndFree();
    }

    fn allocateIndex(self: *SessionManager) ?u32 {
        const start_index = self.next_index;
        while (true) {
            const index = self.next_index;
            self.next_index +%= 1;
            if (self.next_index == 0) {
                self.next_index = 1;
            }

            if (!self.by_index.contains(index)) {
                return index;
            }

            // Check if we've wrapped around completely
            if (self.next_index == start_index) {
                return null; // No free index available
            }
        }
    }
};

// Tests
const testing = std.testing;

test "create session" {
    var m = SessionManager.init(testing.allocator);
    defer m.deinit();

    const pk = Key.fromBytes([_]u8{1} ** 32);
    const session = try m.createSession(pk, Key.zero, Key.zero);

    try testing.expect(session.local_index > 0);
    try testing.expectEqual(@as(usize, 1), m.count());
}

test "get by index" {
    var m = SessionManager.init(testing.allocator);
    defer m.deinit();

    const pk = Key.fromBytes([_]u8{1} ** 32);
    const session = try m.createSession(pk, Key.zero, Key.zero);
    const index = session.local_index;

    try testing.expect(m.getByIndex(index) != null);
    try testing.expect(m.getByIndex(99999) == null);
}

test "get by pubkey" {
    var m = SessionManager.init(testing.allocator);
    defer m.deinit();

    const pk = Key.fromBytes([_]u8{1} ** 32);
    _ = try m.createSession(pk, Key.zero, Key.zero);

    try testing.expect(m.getByPubkey(pk) != null);
    try testing.expect(m.getByPubkey(Key.fromBytes([_]u8{9} ** 32)) == null);
}

test "remove session" {
    var m = SessionManager.init(testing.allocator);
    defer m.deinit();

    const pk = Key.fromBytes([_]u8{1} ** 32);
    const session = try m.createSession(pk, Key.zero, Key.zero);
    const index = session.local_index;

    m.removeSession(index);

    try testing.expect(m.getByIndex(index) == null);
    try testing.expect(m.getByPubkey(pk) == null);
    try testing.expectEqual(@as(usize, 0), m.count());
}

test "remove by pubkey" {
    var m = SessionManager.init(testing.allocator);
    defer m.deinit();

    const pk = Key.fromBytes([_]u8{1} ** 32);
    const session = try m.createSession(pk, Key.zero, Key.zero);
    const index = session.local_index;

    m.removeByPubkey(pk);

    try testing.expect(m.getByIndex(index) == null);
    try testing.expect(m.getByPubkey(pk) == null);
}

test "replace existing" {
    var m = SessionManager.init(testing.allocator);
    defer m.deinit();

    const pk = Key.fromBytes([_]u8{1} ** 32);

    const s1 = try m.createSession(pk, Key.zero, Key.zero);
    const idx1 = s1.local_index;

    const s2 = try m.createSession(pk, Key.fromBytes([_]u8{1} ** 32), Key.zero);
    const idx2 = s2.local_index;

    try testing.expect(m.getByIndex(idx1) == null);
    try testing.expect(m.getByIndex(idx2) != null);
    try testing.expectEqual(@as(usize, 1), m.count());
}

test "multiple peers" {
    var m = SessionManager.init(testing.allocator);
    defer m.deinit();

    var sessions: [5]*Session = undefined;
    var pks: [5]Key = undefined;

    for (0..5) |i| {
        pks[i] = Key.fromBytes([_]u8{@intCast(i)} ** 32);
        sessions[i] = try m.createSession(pks[i], Key.zero, Key.zero);
    }

    try testing.expectEqual(@as(usize, 5), m.count());

    for (0..5) |i| {
        try testing.expect(m.getByPubkey(pks[i]) != null);
        try testing.expect(m.getByIndex(sessions[i].local_index) != null);
    }
}

test "expire sessions" {
    var m = SessionManager.init(testing.allocator);
    defer m.deinit();

    const pk1 = Key.fromBytes([_]u8{1} ** 32);
    const pk2 = Key.fromBytes([_]u8{2} ** 32);

    const s1 = try m.createSession(pk1, Key.zero, Key.zero);
    _ = try m.createSession(pk2, Key.zero, Key.zero);

    s1.expire();

    const removed = m.expireSessions();
    try testing.expectEqual(@as(usize, 1), removed);

    try testing.expect(m.getByPubkey(pk1) == null);
    try testing.expect(m.getByPubkey(pk2) != null);
}

test "clear" {
    var m = SessionManager.init(testing.allocator);
    defer m.deinit();

    for (0..5) |i| {
        const pk = Key.fromBytes([_]u8{@intCast(i)} ** 32);
        _ = try m.createSession(pk, Key.zero, Key.zero);
    }

    m.clear();
    try testing.expectEqual(@as(usize, 0), m.count());
}

test "register session" {
    var m = SessionManager.init(testing.allocator);
    defer m.deinit();

    const session = try testing.allocator.create(Session);
    session.* = Session.init(.{
        .local_index = 12345,
        .send_key = Key.zero,
        .recv_key = Key.zero,
        .remote_pk = Key.fromBytes([_]u8{1} ** 32),
    });

    try m.registerSession(session);

    try testing.expect(m.getByIndex(12345) != null);
}

test "register session index collision" {
    var m = SessionManager.init(testing.allocator);
    defer m.deinit();

    const pk1 = Key.fromBytes([_]u8{1} ** 32);
    const s1 = try m.createSession(pk1, Key.zero, Key.zero);

    const s2 = try testing.allocator.create(Session);
    s2.* = Session.init(.{
        .local_index = s1.local_index,
        .send_key = Key.zero,
        .recv_key = Key.zero,
        .remote_pk = Key.fromBytes([_]u8{2} ** 32),
    });

    try testing.expectError(ManagerError.IndexInUse, m.registerSession(s2));
    testing.allocator.destroy(s2);
}
