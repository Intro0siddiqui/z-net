//! z_http3 - HTTP/3 Protocol Layer (Zig Shim)
const std = @import("std");
const bridge = @import("z_network_bridge");
const compression = @import("z_compression");

// FFI declarations for the QUIC state machine (consumed from
// rust_net/src/lib.rs::net_http3_drive and net_http3_close).
extern fn net_http3_drive(
    engine: bridge.NetEngineHandle,
    conn: bridge.ConnHandle,
) i32;

extern fn net_http3_close(
    engine: bridge.NetEngineHandle,
    conn: bridge.ConnHandle,
) i32;

/// Every HTTP/3 request we send must advertise the codings we can decode.
/// QPACK headers are static for `Accept-Encoding` (`:method`, `:scheme`, etc.)
/// but `Accept-Encoding` itself is a regular request header.
pub const ACCEPT_ENCODING_VALUE: []const u8 = "gzip, br, zstd, deflate";

pub const Http3Client = struct {
    engine: *bridge.NetworkEngine,
    accept_encoding: [64]u8 = undefined,
    accept_encoding_len: u16 = 0,

    pub fn init(engine: *bridge.NetworkEngine) !Http3Client {
        var client = Http3Client{ .engine = engine };
        client.accept_encoding_len = @intCast((try compression.defaultAcceptEncodingHeader(&client.accept_encoding)).len);
        return client;
    }

    /// Returns the cached `Accept-Encoding` header value. Used by the QPACK
    /// encoder when serializing the request HEADERS frame.
    pub fn getAcceptEncoding(self: *const Http3Client) []const u8 {
        return self.accept_encoding[0..self.accept_encoding_len];
    }

    pub fn connect(self: *Http3Client, host: []const u8, port: u16) !bridge.ConnHandle {
        return self.engine.connectHttp3(host, port);
    }

    /// Pump the underlying QUIC state machine forward: read incoming
    /// datagrams, drive the handshake, emit outgoing transmits. The
    /// returned count is the number of datagrams processed.
    pub fn drive(self: *Http3Client, conn: bridge.ConnHandle) !i32 {
        const result = net_http3_drive(@ptrCast(self.engine.handle), conn);
        if (result < 0) return error.DriveFailed;
        return result;
    }

    /// Close the QUIC connection and release the underlying socket.
    pub fn close(self: *Http3Client, conn: bridge.ConnHandle) !void {
        const result = net_http3_close(@ptrCast(self.engine.handle), conn);
        if (result != 0) return error.CloseFailed;
    }
};

test "C ABI symbols resolve" {
    _ = net_http3_drive;
    _ = net_http3_close;
}
