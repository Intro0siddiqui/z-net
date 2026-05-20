//! z_network_bridge - Rust FFI Integration Layer
//! 
//! Provides zero-copy bridge between Rust lean-net engine and Zig orchestration.
//! All data passes through without heap allocation.

const std = @import("std");

// ============================================================
// C ABI Type Bindings
// ============================================================

/// Opaque handle types (matching Rust definitions)
pub const NetEngineHandle = ?*anyopaque;
pub const ConnectionHandle = ?*anyopaque;
pub const FetchHandle = ?*anyopaque;
pub const ConnHandle = ?*anyopaque;
pub const BodyRingHandle = ?*anyopaque;

pub const BodyRingDescriptor = @import("z_body_ring.zig").BodyRingDescriptor;

/// Fetch options
pub const FetchOptions = extern struct {
    method: [*:0]const u8,
    timeout: u32,
    top_level_site: [*:0]const u8,
    origin: [*:0]const u8,
};

/// Network metrics
pub const NetworkMetrics = extern struct {
    total_packets_sent: u64,
    total_packets_received: u64,
    packet_loss_rate: f64,
    average_latency_ms: f64,
    jitter_ms: f64,
    throughput_mbps: f64,
    connection_quality_score: f64,
};

/// Error codes (matching Rust NetError enum)
pub const NetErrorCode = enum(i32) {
    None = 0,
    InvalidHandle = -1,
    NotConnected = -2,
    IoError = -3,
    TlsError = -4,
    WouldBlock = -5,
    OutOfMemory = -6,
    AlreadyRunning = -7,
};

/// Connection state
pub const ConnState = enum(i32) {
    Closed = 0,
    Connecting = 1,
    Handshaking = 2,
    Connected = 3,
    Closing = 4,
};

/// Maximum buffer sizes
pub const MAX_BUFFER_SIZE: usize = 16384;
pub const DNS_BUFFER_SIZE: usize = 512;

// ============================================================
// Extern C Functions (from Rust lean-net)
// ============================================================

/// Create network engine
extern fn net_engine_create() NetEngineHandle;

/// Destroy network engine  
extern fn net_engine_destroy(handle: NetEngineHandle) void;

/// Connect to host:port
extern fn net_connect(
    engine: NetEngineHandle,
    host: [*:0]const u8,
    port: u16,
) ConnectionHandle;

/// Close connection
extern fn net_close(
    engine: NetEngineHandle,
    conn: ConnectionHandle,
) i32;

/// Read data (zero-copy into provided buffer)
extern fn net_read(
    engine: NetEngineHandle,
    conn: ConnectionHandle,
    buffer: [*]u8,
    buffer_len: usize,
    bytes_read: *usize,
) i32;

/// Write data
extern fn net_write(
    engine: NetEngineHandle,
    conn: ConnectionHandle,
    data: [*]const u8,
    data_len: usize,
    bytes_written: *usize,
) i32;

/// Poll for readiness
extern fn net_poll(
    engine: NetEngineHandle,
    timeout_ms: i32,
) i32;

/// Get connection state
extern fn net_conn_state(
    engine: NetEngineHandle,
    conn: ConnectionHandle,
) i32;

/// Fetch create
extern fn net_fetch_create(url: [*:0]const u8, options: *const FetchOptions) FetchHandle;

/// HTTP/3 connect
extern fn net_http3_connect(engine: NetEngineHandle, host: [*:0]const u8, port: u16) ConnHandle;

/// Get metrics
extern fn net_get_metrics(engine: NetEngineHandle) *const NetworkMetrics;

/// BodyRing registration
extern fn net_body_ring_register(engine: NetEngineHandle, id: u64, descriptor: *BodyRingDescriptor) i32;
extern fn net_body_ring_unregister(engine: NetEngineHandle, id: u64) i32;
extern fn net_conn_bind_body_ring(engine: NetEngineHandle, conn: ConnectionHandle, id: u64) i32;

// ============================================================
// High-Level Zig API
// ============================================================

/// Network engine wrapper
pub const NetworkEngine = struct {
    handle: NetEngineHandle,

    const Self = @This();

    /// Create new engine
    pub fn init() Self {
        const handle = net_engine_create();
        return Self{ .handle = handle };
    }

    /// Destroy engine
    pub fn deinit(self: *Self) void {
        if (self.handle) |h| {
            net_engine_destroy(h); // Fixed call to net_engine_destroy
            self.handle = null;
        }
    }

    /// Connect to host
    pub fn connect(self: *Self, host: []const u8, port: u16) !Connection {
        if (self.handle == null) {
            return error.InvalidHandle;
        }

        // Null-terminate host string
        var host_buf: [256]u8 = undefined;
        if (host.len >= 256) return error.HostTooLong;
        @memcpy(host_buf[0..host.len], host);
        host_buf[host.len] = 0;

        const conn = net_connect(self.handle, @ptrCast(&host_buf), port);
        if (conn == null) {
            return error.ConnectionFailed;
        }

        return Connection{
            .engine = self.handle,
            .handle = conn,
        };
    }

    /// Fetch URL
    pub fn fetch(self: *Self, url: []const u8, method: []const u8, top_level_site: []const u8, origin: []const u8) !FetchHandle {
        _ = self;
        var url_buf: [1024]u8 = undefined;
        if (url.len >= 1024) return error.UrlTooLong;
        @memcpy(url_buf[0..url.len], url);
        url_buf[url.len] = 0;

        var method_buf: [16]u8 = undefined;
        if (method.len >= 16) return error.MethodTooLong;
        @memcpy(method_buf[0..method.len], method);
        method_buf[method.len] = 0;

        var tls_buf: [256]u8 = undefined;
        if (top_level_site.len >= 256) return error.HostTooLong;
        @memcpy(tls_buf[0..top_level_site.len], top_level_site);
        tls_buf[top_level_site.len] = 0;

        var origin_buf: [256]u8 = undefined;
        if (origin.len >= 256) return error.HostTooLong;
        @memcpy(origin_buf[0..origin.len], origin);
        origin_buf[origin.len] = 0;

        const opts = FetchOptions{
            .method = @ptrCast(&method_buf),
            .timeout = 30000,
            .top_level_site = @ptrCast(&tls_buf),
            .origin = @ptrCast(&origin_buf),
        };

        return net_fetch_create(@ptrCast(&url_buf), &opts);
    }

    /// HTTP/3 Connect
    pub fn connectHttp3(self: *Self, host: []const u8, port: u16) !ConnHandle {
        var host_buf: [256]u8 = undefined;
        if (host.len >= 256) return error.HostTooLong;
        @memcpy(host_buf[0..host.len], host);
        host_buf[host.len] = 0;

        return net_http3_connect(self.handle, @ptrCast(&host_buf), port);
    }

    /// Get Metrics
    pub fn getMetrics(self: *Self) !*const NetworkMetrics {
        const metrics = net_get_metrics(self.handle);
        if (@intFromPtr(metrics) == 0) return error.MetricsUnavailable;
        return metrics;
    }

    /// Register BodyRing
    pub fn registerBodyRing(self: *Self, id: u64, descriptor: *BodyRingDescriptor) !void {
        const result = net_body_ring_register(self.handle, id, descriptor);
        if (result != 0) return error.RegistrationFailed;
    }

    /// Unregister BodyRing
    pub fn unregisterBodyRing(self: *Self, id: u64) void {
        _ = net_body_ring_unregister(self.handle, id);
    }
};

/// Connection wrapper
pub const Connection = struct {
    engine: NetEngineHandle,
    handle: ConnectionHandle,

    const Self = @This();

    /// Bind BodyRing to connection
    pub fn bindBodyRing(self: *Self, id: u64) !void {
        const result = net_conn_bind_body_ring(self.engine, self.handle, id);
        if (result != 0) return error.BindFailed;
    }

    pub fn getBodyRing(self: *Self) ?*BodyRingDescriptor {
        // This would call into the engine to get the bound descriptor
        // Mocking for now as the actual mapping lives in Rust or a shared manager
        return null;
    }

    /// Read data into provided buffer (zero-copy)
    pub fn read(self: *Self, buffer: []u8) !usize {
        var bytes_read: usize = 0;
        const result = net_read(
            self.engine,
            self.handle,
            buffer.ptr,
            buffer.len,
            &bytes_read,
        );

        const err: NetErrorCode = @enumFromInt(result);
        switch (err) {
            .None => return bytes_read,
            .WouldBlock => return error.WouldBlock,
            .IoError => return error.IoError,
            .TlsError => return error.TlsError,
            else => return error.Unknown,
        }
    }

    /// Write data
    pub fn write(self: *Self, data: []const u8) !usize {
        var bytes_written: usize = 0;
        const result = net_write(
            self.engine,
            self.handle,
            data.ptr,
            data.len,
            &bytes_written,
        );

        const err: NetErrorCode = @enumFromInt(result);
        switch (err) {
            .None => return bytes_written,
            .WouldBlock => return error.WouldBlock,
            .IoError => return error.IoError,
            else => return error.Unknown,
        }
    }

    /// Close connection
    pub fn close(self: *Self) void {
        if (self.handle) |h| {
            _ = net_close(self.engine, h);
            self.handle = null;
        }
    }

    /// Get state
    pub fn getState(self: *Self) ConnState {
        const state = net_conn_state(self.engine, self.handle);
        return @enumFromInt(state);
    }
};

/// Poll engine for events
pub fn poll(engine: NetEngineHandle, timeout_ms: i32) !i32 {
    const result = net_poll(engine, timeout_ms);
    if (result < 0) {
        return error.PollFailed;
    }
    return result;
}

// ============================================================
// Error Types
// ============================================================

pub const NetworkError = error{
    InvalidHandle,
    ConnectionFailed,
    IoError,
    TlsError,
    WouldBlock,
    PollFailed,
    Unknown,
};