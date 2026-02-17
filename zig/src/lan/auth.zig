//! Pluggable authentication for LAN join requests.
//!
//! The Authenticator interface defines how join requests are validated.
//! Built-in implementations: OpenAuth, PasswordAuth (SHA-256 based),
//! InviteCodeAuth, PubkeyWhitelistAuth.

const std = @import("std");
const noise = @import("../noise/mod.zig");
const Key = noise.Key;

/// Authentication errors.
pub const AuthError = error{
    InvalidCredential,
    InvalidPassword,
    InvalidInviteCode,
    InviteCodeExhausted,
    PubkeyNotWhitelisted,
};

/// Authenticator vtable — implemented by each auth method.
pub const Authenticator = struct {
    method_fn: *const fn (self: *const Authenticator) []const u8,
    authenticate_fn: *const fn (self: *const Authenticator, pubkey: Key, credential: []const u8) AuthError!void,

    pub fn method(self: *const Authenticator) []const u8 {
        return self.method_fn(self);
    }

    pub fn authenticate(self: *const Authenticator, pubkey: Key, credential: []const u8) AuthError!void {
        return self.authenticate_fn(self, pubkey, credential);
    }
};

// ── OpenAuth ────────────────────────────────────────────────────────────────

/// Allows any peer to join without credentials.
pub const OpenAuth = struct {
    iface: Authenticator,

    pub fn init() OpenAuth {
        return .{
            .iface = .{
                .method_fn = methodFn,
                .authenticate_fn = authFn,
            },
        };
    }

    pub fn authenticator(self: *OpenAuth) Authenticator {
        return self.iface;
    }

    fn methodFn(_: *const Authenticator) []const u8 {
        return "open";
    }

    fn authFn(_: *const Authenticator, _: Key, _: []const u8) AuthError!void {}
};

// ── PasswordAuth ────────────────────────────────────────────────────────────

/// Validates join requests against a stored password hash.
/// Uses SHA-256 hash comparison (Zig std doesn't have bcrypt).
/// For production, bcrypt should be used via C FFI.
pub const PasswordAuth = struct {
    iface: Authenticator,
    hash: [32]u8,

    /// Creates from a plaintext password (hashes with SHA-256).
    pub fn fromPlaintext(password: []const u8) PasswordAuth {
        var hash: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(password, &hash, .{});
        return .{
            .iface = .{
                .method_fn = methodFn,
                .authenticate_fn = authFn,
            },
            .hash = hash,
        };
    }

    pub fn authenticator(self: *PasswordAuth) Authenticator {
        return self.iface;
    }

    fn methodFn(_: *const Authenticator) []const u8 {
        return "password";
    }

    fn authFn(iface: *const Authenticator, _: Key, credential: []const u8) AuthError!void {
        const self: *const PasswordAuth = @fieldParentPtr("iface", iface);
        if (credential.len == 0) return AuthError.InvalidPassword;

        var cred_hash: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(credential, &cred_hash, .{});

        if (!std.mem.eql(u8, &self.hash, &cred_hash)) {
            return AuthError.InvalidPassword;
        }
    }
};

// ── InviteCodeAuth ──────────────────────────────────────────────────────────

/// Validates join requests against admin-generated invite codes.
pub const InviteCodeAuth = struct {
    iface: Authenticator,
    mutex: std.Thread.Mutex,
    codes: std.StringHashMap(InviteCode),
    allocator: std.mem.Allocator,

    pub const InviteCode = struct {
        max_uses: usize, // 0 = unlimited
        use_count: usize,
    };

    pub fn init(allocator: std.mem.Allocator) InviteCodeAuth {
        return .{
            .iface = .{
                .method_fn = methodFn,
                .authenticate_fn = authFn,
            },
            .mutex = .{},
            .codes = std.StringHashMap(InviteCode).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *InviteCodeAuth) void {
        var it = self.codes.keyIterator();
        while (it.next()) |k| {
            self.allocator.free(k.*);
        }
        self.codes.deinit();
    }

    pub fn authenticator(self: *InviteCodeAuth) Authenticator {
        return self.iface;
    }

    /// Generates a new invite code. Returns the code string (owned by the auth).
    pub fn generateCode(self: *InviteCodeAuth, max_uses: usize) ![]const u8 {
        var buf: [16]u8 = undefined;
        std.crypto.random.bytes(&buf);

        var hex_buf: [32]u8 = undefined;
        const hex_chars = "0123456789abcdef";
        for (buf, 0..) |byte, i| {
            hex_buf[i * 2] = hex_chars[byte >> 4];
            hex_buf[i * 2 + 1] = hex_chars[byte & 0x0f];
        }
        const hex: []const u8 = &hex_buf;

        self.mutex.lock();
        defer self.mutex.unlock();

        const code = try self.allocator.dupe(u8, hex);
        try self.codes.put(code, .{ .max_uses = max_uses, .use_count = 0 });
        return code;
    }

    /// Revokes an invite code.
    pub fn revokeCode(self: *InviteCodeAuth, code: []const u8) bool {
        self.mutex.lock();
        defer self.mutex.unlock();

        const entry = self.codes.fetchRemove(code);
        if (entry) |e| {
            self.allocator.free(e.key);
            return true;
        }
        return false;
    }

    fn methodFn(_: *const Authenticator) []const u8 {
        return "invite_code";
    }

    fn authFn(iface: *const Authenticator, _: Key, credential: []const u8) AuthError!void {
        const self: *InviteCodeAuth = @constCast(@fieldParentPtr("iface", iface));
        if (credential.len == 0) return AuthError.InvalidInviteCode;

        self.mutex.lock();
        defer self.mutex.unlock();

        const ic = self.codes.getPtr(credential) orelse return AuthError.InvalidInviteCode;
        if (ic.max_uses > 0 and ic.use_count >= ic.max_uses) {
            return AuthError.InviteCodeExhausted;
        }
        ic.use_count += 1;
    }
};

// ── PubkeyWhitelistAuth ────────────────────────────────────────────────────

/// Allows only pre-approved public keys to join.
pub const PubkeyWhitelistAuth = struct {
    iface: Authenticator,
    mutex: std.Thread.Mutex,
    allowed: std.AutoHashMap([32]u8, void),

    pub fn init(allocator: std.mem.Allocator, keys: []const Key) PubkeyWhitelistAuth {
        var allowed = std.AutoHashMap([32]u8, void).init(allocator);
        for (keys) |k| {
            allowed.put(k.data, {}) catch {};
        }
        return .{
            .iface = .{
                .method_fn = methodFn,
                .authenticate_fn = authFn,
            },
            .mutex = .{},
            .allowed = allowed,
        };
    }

    pub fn deinit(self: *PubkeyWhitelistAuth) void {
        self.allowed.deinit();
    }

    pub fn authenticator(self: *PubkeyWhitelistAuth) Authenticator {
        return self.iface;
    }

    pub fn addKey(self: *PubkeyWhitelistAuth, pk: Key) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.allowed.put(pk.data, {}) catch {};
    }

    pub fn removeKey(self: *PubkeyWhitelistAuth, pk: Key) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        _ = self.allowed.remove(pk.data);
    }

    fn methodFn(_: *const Authenticator) []const u8 {
        return "pubkey_whitelist";
    }

    fn authFn(iface: *const Authenticator, pubkey: Key, _: []const u8) AuthError!void {
        const self: *PubkeyWhitelistAuth = @constCast(@fieldParentPtr("iface", iface));

        self.mutex.lock();
        defer self.mutex.unlock();

        if (!self.allowed.contains(pubkey.data)) {
            return AuthError.PubkeyNotWhitelisted;
        }
    }
};

// ============================================================================
// Tests
// ============================================================================

fn testKey() Key {
    var seed: [32]u8 = undefined;
    std.crypto.random.bytes(&seed);
    return Key.fromBytes(seed);
}

test "open auth" {
    var open = OpenAuth.init();
    const a = open.authenticator();
    try std.testing.expectEqualStrings("open", a.method());
    try a.authenticate(testKey(), "");
}

test "password auth" {
    var pa = PasswordAuth.fromPlaintext("secret123");
    const a = pa.authenticator();
    try std.testing.expectEqualStrings("password", a.method());

    try a.authenticate(testKey(), "secret123");
    try std.testing.expectError(AuthError.InvalidPassword, a.authenticate(testKey(), "wrong"));
    try std.testing.expectError(AuthError.InvalidPassword, a.authenticate(testKey(), ""));
}

test "invite code auth" {
    const allocator = std.testing.allocator;

    var ica = InviteCodeAuth.init(allocator);
    defer ica.deinit();

    const code = try ica.generateCode(1); // single use
    const a = ica.authenticator();

    try std.testing.expectEqualStrings("invite_code", a.method());
    try a.authenticate(testKey(), code);
    try std.testing.expectError(AuthError.InviteCodeExhausted, a.authenticate(testKey(), code));
    try std.testing.expectError(AuthError.InvalidInviteCode, a.authenticate(testKey(), "nonexistent"));
    try std.testing.expectError(AuthError.InvalidInviteCode, a.authenticate(testKey(), ""));
}

test "invite code unlimited" {
    const allocator = std.testing.allocator;

    var ica = InviteCodeAuth.init(allocator);
    defer ica.deinit();

    const code = try ica.generateCode(0); // unlimited
    const a = ica.authenticator();

    var i: usize = 0;
    while (i < 10) : (i += 1) {
        try a.authenticate(testKey(), code);
    }
}

test "invite code revoke" {
    const allocator = std.testing.allocator;

    var ica = InviteCodeAuth.init(allocator);
    defer ica.deinit();

    const code = try ica.generateCode(0);
    try std.testing.expect(ica.revokeCode(code));
    try std.testing.expect(!ica.revokeCode(code));
}

test "pubkey whitelist auth" {
    const allocator = std.testing.allocator;

    const pk1 = testKey();
    const pk2 = testKey();
    const pk_unknown = testKey();

    const keys = [_]Key{ pk1, pk2 };
    var wl = PubkeyWhitelistAuth.init(allocator, &keys);
    defer wl.deinit();

    const a = wl.authenticator();
    try std.testing.expectEqualStrings("pubkey_whitelist", a.method());

    try a.authenticate(pk1, "");
    try a.authenticate(pk2, "");
    try std.testing.expectError(AuthError.PubkeyNotWhitelisted, a.authenticate(pk_unknown, ""));

    wl.addKey(pk_unknown);
    try a.authenticate(pk_unknown, "");

    wl.removeKey(pk1);
    try std.testing.expectError(AuthError.PubkeyNotWhitelisted, a.authenticate(pk1, ""));
}
