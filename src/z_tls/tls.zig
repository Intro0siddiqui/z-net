//! z_tls - TLS 1.3 Layer (rustls-backed via FFI)
//!
//! The Zig module is a thin handle around a rustls `ClientConnection`
//! that lives in the lean-net Rust engine (see `rust_net/src/lib.rs`).
//! The underlying TCP stream is owned by the Rust side; callers obtain
//! a `TlsConnection` via `TlsManager.connect`, then read and write
//! plaintext through the standard `send` / `recv` methods.

const std = @import("std");
const socket = @import("z_socket");
const z_proxy = @import("z_proxy");
const certificate = @import("certificate.zig");

// Error types for TLS operations
pub const TlsError = error{
    HandshakeFailed,
    VerificationFailed,
    CertificateError,
    ProtocolError,
    MemoryAllocationError,
    InvalidKeyFormat,
    UnsupportedCipher,
    LibraryNotLoaded,
    NotImplemented,
};

// TLS protocol versions
pub const TlsVersion = enum(u16) {
    tls_1_2 = 0x0303,
    tls_1_3 = 0x0304,
};

// Cipher suite identifiers
pub const CipherSuiteId = enum(u16) {
    aes_128_gcm_sha256 = 0x1301,
    aes_256_gcm_sha384 = 0x1302,
    chacha20_poly1305_sha256 = 0x1303,
};

// Handshake information
pub const TlsHandshakeInfo = struct {
    protocol: []const u8,
    cipher_suite: []const u8,
    peer_certificate: ?[]const u8,
    handshake_time: u64,
};

// Connection state
pub const TlsConnectionState = enum {
    Initial,
    HandshakeInProgress,
    Established,
    Closed,
    Failed,
};

// Opaque handle to the Rust-side TLS state. Mirrors `TlsHandle` in
// `rust_net/src/lib.rs`.
pub const TlsHandle = ?*anyopaque;

// ============================================================
// FFI declarations
// ============================================================

extern fn net_tls_create(
    engine: ?*anyopaque,
    host: [*:0]const u8,
    port: u16,
) TlsHandle;

extern fn net_tls_read(
    engine: ?*anyopaque,
    tls: TlsHandle,
    buffer: [*]u8,
    buffer_len: usize,
    bytes_read: *usize,
) i32;

extern fn net_tls_write(
    engine: ?*anyopaque,
    tls: TlsHandle,
    data: [*]const u8,
    data_len: usize,
    bytes_written: *usize,
) i32;

extern fn net_tls_protocol_version(
    engine: ?*anyopaque,
    tls: TlsHandle,
) u16;

extern fn net_tls_close(engine: ?*anyopaque, tls: TlsHandle) i32;

extern fn net_tls_verify_result(engine: ?*anyopaque, tls: TlsHandle) i32;
extern fn net_tls_peer_certificate(engine: ?*anyopaque, tls: TlsHandle, out: [*]u8, out_len: usize) i32;

// ============================================================
// Public API
// ============================================================

/// TLS Connection - API compatible with the previous stub. The
/// `engine` field is a borrow of the `NetEngine` created by the
/// `z_network_bridge` module; passing it is what gives the FFI access
/// to the engine's `tls_states` registry.
pub const TlsConnection = struct {
    allocator: std.mem.Allocator,
    engine: ?*anyopaque,
    handle: TlsHandle = null,
    state: TlsConnectionState = .Initial,
    version: TlsVersion = .tls_1_3,
    cipher_suite: CipherSuiteId = .aes_128_gcm_sha256,
    host: []const u8 = "",

    const Self = @This();

    /// Initialize a TLS connection. The actual rustls handshake is
    /// deferred to `connect` because the host string needs to be
    /// null-terminated for the FFI boundary.
    pub fn init(allocator: std.mem.Allocator, host: []const u8) TlsError!Self {
        return Self{
            .allocator = allocator,
            .engine = null,
            .handle = null,
            .state = .Initial,
            .host = host,
        };
    }

    /// Drive the rustls handshake. The passed socket is intentionally
    /// ignored: the Rust side opens its own blocking TcpStream and
    /// owns it for the lifetime of the connection. This matches the
    /// existing public API surface while keeping the FFI surface
    /// small.
    pub fn connect(self: *Self, sock: socket.Socket) TlsError!void {
        _ = sock;
        if (self.engine == null) return error.LibraryNotLoaded;
        if (self.host.len == 0) return error.HandshakeFailed;

        var host_buf: [256]u8 = undefined;
        if (self.host.len >= host_buf.len) return error.HandshakeFailed;
        @memcpy(host_buf[0..self.host.len], self.host);
        host_buf[self.host.len] = 0;

        self.state = .HandshakeInProgress;
        const handle = net_tls_create(
            self.engine,
            @ptrCast(&host_buf),
            443,
        );
        if (handle == null) {
            self.state = .Failed;
            return error.HandshakeFailed;
        }
        self.handle = handle;

        const version = net_tls_protocol_version(self.engine, self.handle);
        switch (version) {
            0x0303 => self.version = .tls_1_2,
            0x0304 => self.version = .tls_1_3,
            else => self.version = .tls_1_3,
        }
        self.state = .Established;
    }

    /// Send plaintext over TLS. Returns the number of plaintext bytes
    /// accepted by the rustls writer.
    pub fn send(self: *Self, data: []const u8) TlsError!usize {
        if (self.engine == null or self.handle == null) return error.LibraryNotLoaded;
        var written: usize = 0;
        const rc = net_tls_write(
            self.engine,
            self.handle,
            data.ptr,
            data.len,
            &written,
        );
        if (rc != 0) return error.ProtocolError;
        return written;
    }

    /// Receive plaintext over TLS. Returns the number of bytes
    /// decoded into `buffer`.
    pub fn recv(self: *Self, buffer: []u8) TlsError!usize {
        if (self.engine == null or self.handle == null) return error.LibraryNotLoaded;
        var got: usize = 0;
        const rc = net_tls_read(
            self.engine,
            self.handle,
            buffer.ptr,
            buffer.len,
            &got,
        );
        if (rc != 0) return error.ProtocolError;
        return got;
    }

    /// Get handshake information. Populates `peer_certificate` from
    /// the rustls FFI when the connection is established.
    pub fn getHandshakeInfo(self: *Self) TlsError!TlsHandshakeInfo {
        if (self.state != .Established) return error.NotImplemented;
        var cert_buf: [4096]u8 = undefined;
        const cert_len = net_tls_peer_certificate(self.engine, self.handle, &cert_buf, cert_buf.len);
        const peer_cert = if (cert_len > 0) blk: {
            const owned = try self.allocator.alloc(u8, @intCast(cert_len));
            @memcpy(owned, cert_buf[0..@intCast(cert_len)]);
            break :blk owned;
        } else null;
        return TlsHandshakeInfo{
            .protocol = switch (self.version) {
                .tls_1_2 => "TLS 1.2",
                .tls_1_3 => "TLS 1.3",
            },
            .cipher_suite = switch (self.cipher_suite) {
                .aes_128_gcm_sha256 => "TLS_AES_128_GCM_SHA256",
                .aes_256_gcm_sha384 => "TLS_AES_256_GCM_SHA384",
                .chacha20_poly1305_sha256 => "TLS_CHACHA20_POLY1305_SHA256",
            },
            .peer_certificate = peer_cert,
            .handshake_time = 0,
        };
    }

    /// Verify certificate using rustls's WebPKI verifier.
    pub fn verifyCertificate(self: *Self) TlsError!bool {
        if (self.engine == null or self.handle == null) return error.LibraryNotLoaded;
        const result = net_tls_verify_result(self.engine, self.handle);
        return switch (result) {
            0 => true,
            -1 => false,
            -2 => error.NotImplemented,
            else => error.NotImplemented,
        };
    }

    /// Close TLS connection.
    pub fn deinit(self: *Self) void {
        if (self.engine != null and self.handle != null) {
            _ = net_tls_close(self.engine, self.handle);
        }
        self.handle = null;
        self.state = .Closed;
    }
};

// Session cache for resumption
pub const TlsSessionCache = struct {
    allocator: std.mem.Allocator,
    max_sessions: usize = 100,
    sessions: std.StringHashMap(Session),

    const Session = struct {
        ticket: []u8,
        expires_at_ns: u64,
        last_used_ns: u64,
    };

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .allocator = allocator,
            .sessions = std.StringHashMap(Session).init(allocator),
        };
    }

    pub fn deinit(self: *Self) void {
        var it = self.sessions.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.ticket);
        }
        self.sessions.deinit();
    }

    pub fn count(self: *const Self) usize {
        return self.sessions.count();
    }

    /// Store (or replace) an opaque resumption ticket for `host`.
    pub fn put(self: *Self, host: []const u8, ticket: []const u8, now_ns: u64, ttl_ns: u64) !void {
        if (self.max_sessions == 0) return;

        if (self.sessions.getPtr(host)) |existing| {
            const copy = try self.allocator.dupe(u8, ticket);
            self.allocator.free(existing.ticket);
            existing.ticket = copy;
            existing.expires_at_ns = now_ns +| ttl_ns;
            existing.last_used_ns = now_ns;
            return;
        }

        if (self.sessions.count() >= self.max_sessions) self.evictOldest();

        const key = try self.allocator.dupe(u8, host);
        errdefer self.allocator.free(key);
        const value = try self.allocator.dupe(u8, ticket);
        errdefer self.allocator.free(value);
        try self.sessions.putNoClobber(key, .{
            .ticket = value,
            .expires_at_ns = now_ns +| ttl_ns,
            .last_used_ns = now_ns,
        });
    }

    /// Return the cached ticket and mark it as recently used. The slice is
    /// borrowed until the next cache mutation.
    pub fn get(self: *Self, host: []const u8, now_ns: u64) ?[]const u8 {
        const entry = self.sessions.getPtr(host) orelse return null;
        if (now_ns >= entry.expires_at_ns) {
            self.remove(host);
            return null;
        }
        entry.last_used_ns = now_ns;
        return entry.ticket;
    }

    pub fn remove(self: *Self, host: []const u8) void {
        if (self.sessions.fetchRemove(host)) |kv| {
            self.allocator.free(kv.key);
            self.allocator.free(kv.value.ticket);
        }
    }

    fn evictOldest(self: *Self) void {
        var oldest_key: ?[]const u8 = null;
        var oldest_ns: u64 = std.math.maxInt(u64);
        var it = self.sessions.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.last_used_ns < oldest_ns) {
                oldest_ns = entry.value_ptr.last_used_ns;
                oldest_key = entry.key_ptr.*;
            }
        }
        if (oldest_key) |key| self.remove(key);
    }
};

// Certificate validator
pub const CertificateValidator = struct {
    allocator: std.mem.Allocator,
    roots: std.crypto.Certificate.Bundle,
    now_sec: i64,

    const Self = @This();
    const max_chain_len = 8;

    /// Load the operating system trust store and validate chains against it.
    pub fn init(allocator: std.mem.Allocator, io: std.Io) !Self {
        var roots: std.crypto.Certificate.Bundle = .empty;
        errdefer roots.deinit(allocator);

        const now = std.Io.Clock.real.now(io);
        try roots.rescan(allocator, io, now);
        return Self{
            .allocator = allocator,
            .roots = roots,
            .now_sec = now.toSeconds(),
        };
    }

    /// Build a validator with an explicit set of DER-encoded trust anchors.
    pub fn initWithRoots(
        allocator: std.mem.Allocator,
        roots_der: []const []const u8,
        now_sec: i64,
    ) !Self {
        var roots: std.crypto.Certificate.Bundle = .empty;
        errdefer roots.deinit(allocator);

        for (roots_der) |der| {
            const start: u32 = @intCast(roots.bytes.items.len);
            try roots.bytes.appendSlice(allocator, der);
            try roots.parseCert(allocator, start, now_sec);
        }

        return Self{
            .allocator = allocator,
            .roots = roots,
            .now_sec = now_sec,
        };
    }

    pub fn deinit(self: *Self) void {
        self.roots.deinit(self.allocator);
    }

    /// Validate a DER-encoded chain, leaf first. Returns false for malformed
    /// certificates, broken signatures, expired/not-yet-valid certs, or a
    /// chain that does not terminate at a trusted root.
    pub fn validateChain(self: *const Self, chain: []const []const u8) TlsError!bool {
        return self.validateChainAt(chain, self.now_sec);
    }

    pub fn validateChainAt(self: *const Self, chain: []const []const u8, now_sec: i64) bool {
        if (chain.len == 0 or chain.len > max_chain_len) return false;

        var parsed: [max_chain_len]std.crypto.Certificate.Parsed = undefined;
        for (chain, 0..) |der, index| {
            parsed[index] = certificate.parse(der) catch return false;
        }

        var index: usize = 0;
        while (index + 1 < chain.len) : (index += 1) {
            parsed[index].verify(parsed[index + 1], now_sec) catch return false;
        }

        self.roots.verify(parsed[chain.len - 1], now_sec) catch return false;
        return true;
    }

    /// Validate the chain and check that the leaf covers `host`.
    pub fn validateChainForHost(self: *const Self, chain: []const []const u8, host: []const u8) bool {
        if (!self.validateChainAt(chain, self.now_sec)) return false;

        const leaf = certificate.parse(chain[0]) catch return false;
        if (!certificate.subjectAltNameIsWellFormed(leaf.subjectAltName())) return false;
        leaf.verifyHostName(host) catch return false;
        return true;
    }

    /// Check certificate pinning
    pub fn checkPinning(cert_der: []const u8, pinned_certs: []const []const u8) bool {
        for (pinned_certs) |pinned| {
            if (std.mem.eql(u8, cert_der, pinned)) {
                return true;
            }
        }
        return false;
    }
};

// TLS connection manager
pub const TlsManager = struct {
    allocator: std.mem.Allocator,
    session_cache: TlsSessionCache,
    engine: ?*anyopaque = null,
    proxy: ?*z_proxy.ProxyConfig = null,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .allocator = allocator,
            .session_cache = TlsSessionCache.init(allocator),
        };
    }

    /// Bind the manager to a `NetEngine` so subsequent `connect` calls
    /// can register the resulting TlsState in the engine.
    pub fn setEngine(self: *Self, engine: ?*anyopaque) void {
        self.engine = engine;
    }

    /// Configure a proxy to be honored for every subsequent TLS connection.
    pub fn setProxy(self: *Self, cfg: ?*z_proxy.ProxyConfig) void {
        self.proxy = cfg;
    }

    pub fn connect(self: *Self, sock: socket.Socket, host: []const u8) TlsError!TlsConnection {
        var tls_conn = try TlsConnection.init(self.allocator, host);
        tls_conn.engine = self.engine;
        try tls_conn.connect(sock);
        return tls_conn;
    }

    /// High-level helper: open a tunneled socket via the configured proxy
    /// (if any) and return it so the caller can hand it to `connect`.
    pub fn connectTunneled(
        self: *Self,
        io_ctx: *std.Io,
        target_host: []const u8,
        target_port: u16,
    ) !socket.Socket {
        const hop: ?z_proxy.ProxyHop = if (self.proxy) |cfg| blk: {
            const is_https = target_port == 443;
            break :blk z_proxy.resolveFor(cfg, target_host, is_https);
        } else null;
        return z_proxy.connectTunneled(io_ctx, hop, target_host, target_port, null);
    }

    pub fn deinit(self: *Self) void {
        self.session_cache.deinit();
    }
};

// Build configuration markers for build.zig integration
pub const BuildConfig = struct {
    pub const HAS_TLS = true;
    pub const HAS_TLS_1_2 = true;
    pub const HAS_TLS_1_3 = true;
    pub const BACKEND = "rustls";
    /// Set to true once the Rust FFI is linked and wired.
    pub const WIRED = false;
};

test "TlsConnection.init stores host" {
    const conn = try TlsConnection.init(std.testing.allocator, "example.com");
    try std.testing.expectEqualStrings("example.com", conn.host);
    try std.testing.expectEqual(TlsConnectionState.Initial, conn.state);
    try std.testing.expect(conn.engine == null);
    try std.testing.expect(conn.handle == null);
}

test "TlsManager.init produces a usable manager" {
    var mgr = TlsManager.init(std.testing.allocator);
    defer mgr.deinit();
    try std.testing.expect(mgr.engine == null);
    try std.testing.expect(mgr.proxy == null);
}

test "CertificateValidator.checkPinning matches exact bytes" {
    const pinned = [_][]const u8{ "ABCD", "EFGH" };
    try std.testing.expect(CertificateValidator.checkPinning("ABCD", &pinned));
    try std.testing.expect(!CertificateValidator.checkPinning("ZZZZ", &pinned));
}

const test_root_der = @embedFile("testdata/root.der");
const test_intermediate_der = @embedFile("testdata/int.der");
const test_leaf_der = @embedFile("testdata/leaf.der");
const test_other_root_der = @embedFile("testdata/other.der");
const test_wrong_issuer_der = @embedFile("testdata/wrong.der");

const test_chain = [_][]const u8{ test_leaf_der, test_intermediate_der, test_root_der };

fn testValidator(now_sec: i64) !CertificateValidator {
    const roots = [_][]const u8{test_root_der};
    return CertificateValidator.initWithRoots(std.testing.allocator, &roots, now_sec);
}

test "CertificateValidator.init loads the operating system trust store" {
    var validator = try CertificateValidator.init(std.testing.allocator, std.testing.io);
    defer validator.deinit();

    try std.testing.expect(validator.roots.map.count() > 0);
}

test "CertificateValidator validates a leaf -> intermediate -> root chain" {
    var validator = try testValidator(1_800_000_000);
    defer validator.deinit();

    try std.testing.expect(try validator.validateChain(&test_chain));
}

test "CertificateValidator rejects a chain that is not anchored in the trust store" {
    const other_roots = [_][]const u8{test_other_root_der};
    var validator = try CertificateValidator.initWithRoots(
        std.testing.allocator,
        &other_roots,
        1_800_000_000,
    );
    defer validator.deinit();

    try std.testing.expect(!try validator.validateChain(&test_chain));
}

test "CertificateValidator rejects a leaf signed by an untrusted issuer" {
    var validator = try testValidator(1_800_000_000);
    defer validator.deinit();

    const wrong_chain = [_][]const u8{ test_wrong_issuer_der, test_intermediate_der, test_root_der };
    try std.testing.expect(!try validator.validateChain(&wrong_chain));
}

test "CertificateValidator rejects tampered and malformed certificates" {
    var validator = try testValidator(1_800_000_000);
    defer validator.deinit();

    var tampered: [test_leaf_der.len]u8 = undefined;
    @memcpy(&tampered, test_leaf_der);
    tampered[tampered.len - 1] ^= 0xff;

    const tampered_chain = [_][]const u8{ &tampered, test_intermediate_der, test_root_der };
    try std.testing.expect(!try validator.validateChain(&tampered_chain));

    const malformed = [_]u8{ 0x30, 0x03, 0x01, 0x02, 0x03 };
    const malformed_chain = [_][]const u8{&malformed};
    try std.testing.expect(!try validator.validateChain(&malformed_chain));
}

test "CertificateValidator rejects truncated and random certificates without panicking" {
    var validator = try testValidator(1_800_000_000);
    defer validator.deinit();

    var length: usize = 0;
    while (length < test_leaf_der.len) : (length += 1) {
        const truncated = [_][]const u8{ test_leaf_der[0..length], test_intermediate_der, test_root_der };
        try std.testing.expect(!try validator.validateChain(&truncated));
    }

    var prng = std.Random.DefaultPrng.init(0x5eed);
    const random = prng.random();
    var buffer: [256]u8 = undefined;
    var iteration: usize = 0;
    while (iteration < 500) : (iteration += 1) {
        const len = random.intRangeAtMost(usize, 0, buffer.len);
        random.bytes(buffer[0..len]);
        const fuzz_chain = [_][]const u8{buffer[0..len]};
        try std.testing.expect(!try validator.validateChain(&fuzz_chain));
    }
}

test "CertificateValidator enforces the certificate validity window" {
    var validator = try testValidator(1_800_000_000);
    defer validator.deinit();

    // 2033-05-18: the leaf (valid for 825 days from 2026) has expired.
    try std.testing.expect(!validator.validateChainAt(&test_chain, 2_000_000_000));
    // Unix epoch: the leaf is not valid yet.
    try std.testing.expect(!validator.validateChainAt(&test_chain, 0));
}

test "CertificateValidator checks the leaf hostname" {
    var validator = try testValidator(1_800_000_000);
    defer validator.deinit();

    try std.testing.expect(validator.validateChainForHost(&test_chain, "example.com"));
    try std.testing.expect(!validator.validateChainForHost(&test_chain, "other.example"));
}

test "TlsSessionCache stores and replaces tickets" {
    var cache = TlsSessionCache.init(std.testing.allocator);
    defer cache.deinit();

    try cache.put("a.example", "ticket-1", 10, 100);
    try std.testing.expectEqualStrings("ticket-1", cache.get("a.example", 20).?);

    try cache.put("a.example", "ticket-2", 30, 100);
    try std.testing.expectEqual(@as(usize, 1), cache.count());
    try std.testing.expectEqualStrings("ticket-2", cache.get("a.example", 40).?);
}

test "TlsSessionCache evicts the least recently used ticket" {
    var cache = TlsSessionCache.init(std.testing.allocator);
    defer cache.deinit();
    cache.max_sessions = 2;

    try cache.put("a.example", "ticket-a", 10, 100);
    try cache.put("b.example", "ticket-b", 20, 100);

    // Touch `a` so `b` becomes the least recently used entry.
    _ = cache.get("a.example", 30);
    try cache.put("c.example", "ticket-c", 40, 100);

    try std.testing.expect(cache.get("a.example", 50) != null);
    try std.testing.expect(cache.get("b.example", 50) == null);
    try std.testing.expect(cache.get("c.example", 50) != null);
    try std.testing.expectEqual(@as(usize, 2), cache.count());
}

test "TlsSessionCache expires tickets" {
    var cache = TlsSessionCache.init(std.testing.allocator);
    defer cache.deinit();

    try cache.put("a.example", "ticket", 100, 50);
    try std.testing.expect(cache.get("a.example", 149) != null);
    try std.testing.expect(cache.get("a.example", 150) == null);
    try std.testing.expectEqual(@as(usize, 0), cache.count());
}
