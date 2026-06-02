//! HTTP CONNECT tunneling (RFC 7231 §4.3.6) for HTTP proxies.
//!
//! Sends a `CONNECT host:port HTTP/1.1` request to the proxy and waits
//! for `HTTP/1.1 200 Connection Established` (or one of the `407 Proxy
//! Authentication Required` variants - in which case the caller retries
//! with the appropriate `Proxy-Authorization` header set by the auth
//! subsystem in `z_proxy::proxy::ProxyHop.auth_header`).

const std = @import("std");
const ProxyHop = @import("proxy.zig").ProxyHop;
const Socket = @import("../z_socket/socket.zig").Socket;

pub const ConnectError = error{
    ConnectFailed,
    ProxyAuthRequired,
    UnexpectedResponse,
    HandshakeFailed,
};

const RESPONSE_MAX: usize = 8192;

pub fn connect(
    io_ctx: *std.Io,
    sock: *Socket,
    proxy: ProxyHop,
    target_host: []const u8,
    target_port: u16,
) ConnectError!void {
    var attempt: u8 = 0;
    while (attempt < 2) : (attempt += 1) {
        var req = std.ArrayList(u8).init(std.heap.c_allocator);
        defer req.deinit();
        try req.writer().print(
            "CONNECT {s}:{d} HTTP/1.1\r\nHost: {s}:{d}\r\n",
            .{ target_host, target_port, target_host, target_port },
        );
        try req.writer().print("User-Agent: Zawra/z-net\r\n", .{});
        try req.writer().print("Proxy-Connection: keep-alive\r\n", .{});
        if (proxy.auth_header) |hdr| {
            try req.writer().print("Proxy-Authorization: {s}\r\n", .{hdr});
        }
        try req.appendSlice("\r\n");

        sock.send(io_ctx, req.items) catch return ConnectError.HandshakeFailed;

        const response = readResponse(sock, io_ctx) catch return ConnectError.HandshakeFailed;
        const status = parseStatusLine(response) orelse return ConnectError.HandshakeFailed;
        if (status == 200) return;
        if (status == 407) {
            if (attempt == 0) continue;
            return ConnectError.ProxyAuthRequired;
        }
        return ConnectError.UnexpectedResponse;
    }
}

fn readResponse(sock: *Socket, io_ctx: *std.Io) ![]u8 {
    var buf: [RESPONSE_MAX]u8 = undefined;
    var filled: usize = 0;
    while (filled < buf.len) {
        const n = sock.recv(io_ctx, buf[filled..]) catch return error.HandshakeFailed;
        if (n == 0) return error.HandshakeFailed;
        filled += n;
        if (std.mem.indexOf(u8, buf[0..filled], "\r\n\r\n")) |_| {
            return buf[0..filled];
        }
    }
    return error.HandshakeFailed;
}

fn parseStatusLine(response: []const u8) ?u16 {
    const crlf = std.mem.indexOf(u8, response, "\r\n") orelse return null;
    const line = response[0..crlf];
    var it = std.mem.splitScalar(u8, line, ' ');
    _ = it.next(); // "HTTP/1.1"
    const code_s = it.next() orelse return null;
    return std.fmt.parseInt(u16, code_s, 10) catch null;
}
