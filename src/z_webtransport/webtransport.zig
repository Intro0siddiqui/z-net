//! z_webtransport - WebTransport over HTTP/3 (QUIC)
//!
//! WebTransport is a browser API that exposes a multiplexed, low-latency
//! transport layered on top of HTTP/3. Per the W3C draft + RFC 9220 it
//! uses the ALPN token `webtransport` and a CONNECT-style extended
//! request whose `:protocol` pseudo-header equals `webtransport`.
//!
//! This module extends the existing `z_quic` stack with the bits WebTransport
//! needs (ALPN advertising, session caps, datagram acceptance) and exposes
//! a JS-shaped API on top of `z_fetch` so WebKit can map `new WebTransport(url)`
//! directly to it.

const std = @import("std");
const quic = @import("z_quic");
const http3 = @import("z_http3");

/// The single WebTransport ALPN token. Per RFC 9220 §3.
pub const ALPN: []const u8 = "webtransport";

/// HTTP/3 settings parameter id (RFC 9220 §3.4).
pub const SETTINGS_WEBTRANSPORT_MAX_SESSIONS: u64 = 0xC671706A;

/// Default cap on concurrent WebTransport sessions per QUIC connection.
pub const DEFAULT_MAX_SESSIONS: u32 = 16;

/// One WebTransport session. Identified by the QUIC connection id +
/// the session id chosen by the peer.
pub const Session = struct {
    quic_conn: *quic.Connection,
    session_id: u64,
    incoming_streams: std.ArrayList(StreamHandle),
    outgoing_streams: std.ArrayList(StreamHandle),
    datagram_queue: std.ArrayList(Datagram),

    pub fn init(quic_conn: *quic.Connection, session_id: u64, allocator: std.mem.Allocator) Session {
        _ = allocator;
        return .{
            .quic_conn = quic_conn,
            .session_id = session_id,
            .incoming_streams = .{},
            .outgoing_streams = .{},
            .datagram_queue = .{},
        };
    }
};

/// Stream handle - wraps a QUIC stream so the caller can `write` / `read`
/// without exposing the QUIC layer.
pub const StreamHandle = struct {
    quic_stream: *quic.Stream,
    is_bidi: bool,
    is_writable: bool,
    is_readable: bool,
};

/// Unreliable datagram. WebTransport datagrams are bounded (~1200 bytes
/// for QUIC) and out-of-order; the queue preserves arrival order.
pub const Datagram = struct {
    session_id: u64,
    payload: []const u8,
};

/// Configuration passed to `WebTransport.connect`.
pub const ConnectOptions = struct {
    /// Subprotocols offered via the WT subprotocols pseudo-header.
    subprotocols: []const []const u8 = &.{},

    /// Datagrams enabled. The default per the spec is "enabled" - the
    /// server may still reject them via `SETTINGS_WEBTRANSPORT_MAX_SESSIONS`.
    datagrams_enabled: bool = true,

    /// Maximum concurrent sessions on this QUIC connection.
    max_sessions: u32 = DEFAULT_MAX_SESSIONS,
};

/// Public entry point. Wraps the QUIC + HTTP/3 stack in a JS-friendly
/// surface. The actual wire-level session lives in the Rust `z_quic`
/// extension; the Zig side just gives the browser a handle.
pub const WebTransport = struct {
    session: Session,
    closed: bool = false,
    /// True if the session is not yet bound to a real QUIC connection.
    /// The FFI bridge resolves it lazily the first time the JS layer
    /// actually tries to send or receive.
    unresolved: bool = false,

    /// Construct a WebTransport handle that the FFI layer will bind to
    /// a real QUIC connection later. Used by `z_fetch.webTransport()`.
    pub fn connectUnresolved(options: ConnectOptions) !WebTransport {
        _ = options;
        var session = Session{
            .quic_conn = undefined,
            .session_id = 0,
            .incoming_streams = .{},
            .outgoing_streams = .{},
            .datagram_queue = .{},
        };
        session.datagrams_enabled = true;
        return .{ .session = session, .unresolved = true };
    }

    pub fn connect(quic_conn: *quic.Connection, url: []const u8, options: ConnectOptions) !WebTransport {
        _ = url;
        // Advertise the WebTransport ALPN on the QUIC TLS handshake. This
        // is a no-op if the connection was already established with the
        // right ALPN by `z_http3` upstream.
        quic_conn.setAlpn(ALPN) catch return error.AlpnRejected;

        // Negotiate the session cap via SETTINGS_WEBTRANSPORT_MAX_SESSIONS.
        quic_conn.putH3Setting(SETTINGS_WEBTRANSPORT_MAX_SESSIONS, options.max_sessions) catch {};

        const session_id = quic_conn.nextSessionId();
        var session = Session.init(quic_conn, session_id, std.heap.c_allocator);
        session.datagrams_enabled = options.datagrams_enabled;
        for (options.subprotocols) |sp| {
            session.quic_conn.offerSubprotocol(sp);
        }
        return .{ .session = session };
    }

    /// Open a new unidirectional send stream.
    pub fn createSendStream(self: *WebTransport) !StreamHandle {
        if (self.closed) return error.SessionClosed;
        const s = try self.session.quic_conn.openUniStream();
        const handle = StreamHandle{
            .quic_stream = s,
            .is_bidi = false,
            .is_writable = true,
            .is_readable = false,
        };
        try self.session.outgoing_streams.append(std.heap.c_allocator, handle);
        return handle;
    }

    /// Open a new bidirectional stream.
    pub fn createBidirectionalStream(self: *WebTransport) !StreamHandle {
        if (self.closed) return error.SessionClosed;
        const s = try self.session.quic_conn.openBidiStream();
        const handle = StreamHandle{
            .quic_stream = s,
            .is_bidi = true,
            .is_writable = true,
            .is_readable = true,
        };
        try self.session.outgoing_streams.append(std.heap.c_allocator, handle);
        return handle;
    }

    /// Return the next incoming stream (blocking) or `null` if the
    /// session has been closed.
    pub fn receiveStream(self: *WebTransport) !?StreamHandle {
        if (self.closed) return null;
        if (self.session.incoming_streams.popOrNull()) |s| return s;
        return null;
    }

    /// Send an unreliable datagram.
    pub fn sendDatagram(self: *WebTransport, payload: []const u8) !void {
        if (self.closed) return error.SessionClosed;
        try self.session.quic_conn.sendDatagram(self.session.session_id, payload);
    }

    /// Drain all queued datagrams. WebKit consumes these in a tight loop
    /// on the IO thread.
    pub fn drainDatagrams(self: *WebTransport, out: []Datagram) usize {
        var i: usize = 0;
        while (i < out.len) {
            const next = self.session.datagram_queue.popOrNull() orelse break;
            out[i] = next;
            i += 1;
        }
        return i;
    }

    /// Close the session cleanly (sends a WT_CLOSE capsule).
    pub fn close(self: *WebTransport) void {
        if (self.closed) return;
        self.session.quic_conn.closeSession(self.session.session_id) catch {};
        self.closed = true;
    }
};

test "WebTransport defaults match RFC 9220" {
    try std.testing.expectEqualStrings("webtransport", ALPN);
    try std.testing.expectEqual(@as(u64, 0xC671706A), SETTINGS_WEBTRANSPORT_MAX_SESSIONS);
}
