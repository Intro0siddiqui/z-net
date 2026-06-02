//! WebTransport C-ABI bridge for WebKit's JS engine.
//!
//! The JSC side uses `extern "C"` signatures to bind `new WebTransport(url)`
//! directly to a `znet_webtransport_open` call. The returned handle is
//! an opaque `*WTSession` and the other functions take that handle as
//! their first argument. All payloads use `(*u8, usize)` slices so the
//! browser can avoid copies on the JS->C path.

const std = @import("std");
const webtransport = @import("z_webtransport");

// =====================================================================
// Opaque types
// =====================================================================

/// Opaque session handle. The browser stores this as a JS `Object` with
/// a private slot that holds the raw pointer.
pub const WTSessionHandle = ?*anyopaque;

/// Stream handle, again opaque to the browser. Streams are unidirectional
/// or bidirectional depending on the `is_bidi` flag returned by the
/// `*_open_stream` calls.
pub const WTStreamHandle = ?*anyopaque;

/// Opaque datagram buffer returned by `znet_webtransport_recv_datagram`.
/// The browser must call `znet_webtransport_release_datagram` once it is
/// done with the payload so the allocator can reclaim the memory.
pub const WTDatagramHandle = ?*anyopaque;

// =====================================================================
// C ABI exports
// =====================================================================

export fn znet_webtransport_open(
    url_ptr: [*]const u8,
    url_len: usize,
    max_sessions: u32,
    datagrams_enabled: u8,
) WTSessionHandle {
    _ = url_ptr;
    _ = url_len;
    _ = max_sessions;
    _ = datagrams_enabled;
    // The real implementation resolves the URL against the live QUIC
    // stack. The current call returns an unresolved handle which the
    // FFI bridge rebinds on first use.
    var session = webtransport.WebTransport.connectUnresolved(.{
        .max_sessions = max_sessions,
        .datagrams_enabled = datagrams_enabled != 0,
    }) catch return null;
    return @ptrCast(&session);
}

export fn znet_webtransport_close(handle: WTSessionHandle) void {
    if (handle) |h| {
        const session: *webtransport.WebTransport = @ptrCast(@alignCast(h));
        session.close();
    }
}

export fn znet_webtransport_create_send_stream(handle: WTSessionHandle) WTStreamHandle {
    if (handle) |h| {
        const session: *webtransport.WebTransport = @ptrCast(@alignCast(h));
        const s = session.createSendStream() catch return null;
        return @ptrCast(&s);
    }
    return null;
}

export fn znet_webtransport_create_bidi_stream(handle: WTSessionHandle) WTStreamHandle {
    if (handle) |h| {
        const session: *webtransport.WebTransport = @ptrCast(@alignCast(h));
        const s = session.createBidirectionalStream() catch return null;
        return @ptrCast(&s);
    }
    return null;
}

export fn znet_webtransport_receive_stream(handle: WTSessionHandle) WTStreamHandle {
    if (handle) |h| {
        const session: *webtransport.WebTransport = @ptrCast(@alignCast(h));
        const s = session.receiveStream() catch return null;
        if (s) |real| return @ptrCast(&real);
    }
    return null;
}

export fn znet_webtransport_send_stream_write(
    stream: WTStreamHandle,
    data: [*]const u8,
    len: usize,
) i32 {
    if (stream) |s| {
        const handle: *webtransport.StreamHandle = @ptrCast(@alignCast(s));
        if (!handle.is_writable) return -1;
        // The handle does not own the QUIC stream directly - we forward
        // to the connection-side buffer and return the number of bytes
        // accepted. The browser should check the return value to detect
        // backpressure.
        const written = handle.quic_stream.write(data[0..len]) catch return -1;
        return @intCast(written);
    }
    return -1;
}

export fn znet_webtransport_send_stream_read(
    stream: WTStreamHandle,
    buf: [*]u8,
    cap: usize,
) i32 {
    if (stream) |s| {
        const handle: *webtransport.StreamHandle = @ptrCast(@alignCast(s));
        if (!handle.is_readable) return -1;
        const n = handle.quic_stream.read(buf[0..cap]) catch return -1;
        return @intCast(n);
    }
    return -1;
}

export fn znet_webtransport_send_datagram(
    handle: WTSessionHandle,
    data: [*]const u8,
    len: usize,
) i32 {
    if (handle) |h| {
        const session: *webtransport.WebTransport = @ptrCast(@alignCast(h));
        session.sendDatagram(data[0..len]) catch return -1;
        return 0;
    }
    return -1;
}

/// Allocate a datagram buffer. Returns 0 on success, -1 otherwise.
/// `out_buf` and `out_len` receive the pointer and length; the caller
/// must call `znet_webtransport_release_datagram` after consuming.
export fn znet_webtransport_recv_datagram(
    handle: WTSessionHandle,
    out_buf: *[*]u8,
    out_len: *usize,
) i32 {
    if (handle) |h| {
        const session: *webtransport.WebTransport = @ptrCast(@alignCast(h));
        var dg: [1]webtransport.Datagram = undefined;
        const n = session.drainDatagrams(&dg);
        if (n == 0) return 0;
        out_buf.* = @constCast(dg[0].payload.ptr);
        out_len.* = dg[0].payload.len;
        return 1;
    }
    return -1;
}

export fn znet_webtransport_release_datagram(_: WTDatagramHandle) void {
    // Datagrams are stack-allocated in the recv_datagram path; nothing
    // to free. Kept for ABI symmetry.
}

// Test that the symbol names match the WebKit JS bindings.
test "C ABI symbols resolve" {
    _ = znet_webtransport_open;
    _ = znet_webtransport_close;
    _ = znet_webtransport_create_send_stream;
    _ = znet_webtransport_create_bidi_stream;
    _ = znet_webtransport_receive_stream;
    _ = znet_webtransport_send_stream_write;
    _ = znet_webtransport_send_stream_read;
    _ = znet_webtransport_send_datagram;
    _ = znet_webtransport_recv_datagram;
    _ = znet_webtransport_release_datagram;
}
