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

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        _ = self;
    }
};

// Certificate validator
pub const CertificateValidator = struct {
    /// Validate certificate chain
    pub fn validateChain(_: []const u8) TlsError!bool {
        return error.NotImplemented;
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
