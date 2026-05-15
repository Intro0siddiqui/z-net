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
            net_engine_create(h);
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
        @memcpy(host_buf[0..host.len], host);
        host_buf[host.len] = 0;

        const conn = net_connect(self.handle, &host_buf, port);
        if (conn == null) {
            return error.ConnectionFailed;
        }

        return Connection{
            .engine = self.handle,
            .handle = conn,
        };
    }
};

/// Connection wrapper
pub const Connection = struct {
    engine: NetEngineHandle,
    handle: ConnectionHandle,

    const Self = @This();

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

        const err = @enumFromInt(NetErrorCode, result);
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

        const err = @enumFromInt(NetErrorCode, result);
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
        return @enumFromInt(ConnState, state);
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