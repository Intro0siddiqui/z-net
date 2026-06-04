//! SOCKS5 handshake (RFC 1928) and SOCKS4 connect.
//!
//! This is the low-level connect-time handshake only. The caller is
//! expected to use the established TCP socket for a downstream `z_tls`
//! handshake, just as if it had connected directly to the target host.

const std = @import("std");
const ProxyHop = @import("proxy.zig").ProxyHop;
const Socket = @import("../z_socket/socket.zig").Socket;

/// `Socket.recv` returns a short read; the SOCKS5 handshake needs exact-sized
/// frames, so we drain the buffer in a loop until every byte has arrived.
fn recvExact(sock: *Socket, io_ctx: *std.Io, buf: []u8) SocksError!void {
    var filled: usize = 0;
    while (filled < buf.len) {
        const n = sock.recv(io_ctx, buf[filled..]) catch return SocksError.HandshakeFailed;
        if (n == 0) return SocksError.HandshakeFailed;
        filled += n;
    }
}

pub const SocksError = error{
    HandshakeFailed,
    AuthRequired,
    UnsupportedAuthMethod,
    ConnectionRefused,
    NetworkUnreachable,
    HostUnreachable,
    TtlExpired,
    CommandNotSupported,
    AddressTypeNotSupported,
    UnknownError,
};

/// SOCKS5 authentication methods (RFC 1928 §4).
const SOCKS5_AUTH_NONE: u8 = 0x00;
const SOCKS5_AUTH_USERPASS: u8 = 0x02;
const SOCKS5_NO_ACCEPTABLE: u8 = 0xFF;

const SOCKS5_CMD_CONNECT: u8 = 0x01;
const SOCKS5_ATYP_IPV4: u8 = 0x01;
const SOCKS5_ATYP_DOMAIN: u8 = 0x03;
const SOCKS5_ATYP_IPV6: u8 = 0x04;

const SOCKS5_REP_SUCCESS: u8 = 0x00;
const SOCKS5_REP_GENERAL_FAILURE: u8 = 0x01;
const SOCKS5_REP_NOT_ALLOWED: u8 = 0x02;
const SOCKS5_REP_NET_UNREACHABLE: u8 = 0x03;
const SOCKS5_REP_HOST_UNREACHABLE: u8 = 0x04;
const SOCKS5_REP_REFUSED: u8 = 0x05;
const SOCKS5_REP_TTL: u8 = 0x06;
const SOCKS5_REP_CMD_UNSUPPORTED: u8 = 0x07;
const SOCKS5_REP_ATYP_UNSUPPORTED: u8 = 0x08;

/// Walk the full SOCKS5 CONNECT handshake over an already-connected socket.
/// After this returns successfully, the socket is bound to `target_host:target_port`
/// from the proxy's perspective and the caller can proceed with TLS etc.
pub fn connect(
    io_ctx: *std.Io,
    sock: *Socket,
    proxy: ProxyHop,
    target_host: []const u8,
    target_port: u16,
    credentials: ?Credentials,
) SocksError!void {
    // 1. Greeting: VER=5, NMETHODS, methods
    var greeting: [4]u8 = .{ 0x05, 0x01, SOCKS5_AUTH_NONE, 0x00 };
    if (credentials != null) greeting[1] = 0x02;
    sock.send(io_ctx, &greeting) catch return SocksError.HandshakeFailed;

    // 2. Server method selection
    var method_resp: [2]u8 = undefined;
    try recvExact(sock, io_ctx, &method_resp);
    if (method_resp[0] != 0x05) return SocksError.HandshakeFailed;
    const chosen = method_resp[1];
    if (chosen == SOCKS5_NO_ACCEPTABLE) return SocksError.UnsupportedAuthMethod;

    // 3. Optional username/password subnegotiation (RFC 1929)
    if (chosen == SOCKS5_AUTH_USERPASS) {
        const creds = credentials orelse return SocksError.AuthRequired;
        var auth_buf = std.ArrayList(u8).init(std.heap.c_allocator);
        defer auth_buf.deinit();
        try auth_buf.append(0x01); // VER
        try auth_buf.append(@intCast(creds.user.len));
        try auth_buf.appendSlice(creds.user);
        try auth_buf.append(@intCast(creds.pass.len));
        try auth_buf.appendSlice(creds.pass);
        try sock.send(io_ctx, auth_buf.items);
        var auth_resp: [2]u8 = undefined;
        try recvExact(sock, io_ctx, &auth_resp);
        if (auth_resp[1] != 0x00) return SocksError.AuthRequired;
    }

    // 4. CONNECT request
    var req = std.ArrayList(u8).init(std.heap.c_allocator);
    defer req.deinit();
    try req.append(0x05);
    try req.append(SOCKS5_CMD_CONNECT);
    try req.append(0x00); // RSV
    // Domain names use ATYP=0x03 followed by length-prefixed bytes.
    try req.append(SOCKS5_ATYP_DOMAIN);
    try req.append(@intCast(target_host.len));
    try req.appendSlice(target_host);
    var port_be: [2]u8 = undefined;
    memWriteU16Be(&port_be, target_port);
    try req.appendSlice(&port_be);
    sock.send(io_ctx, req.items) catch return SocksError.HandshakeFailed;

    // 5. Server reply
    var head: [4]u8 = undefined;
    try recvExact(sock, io_ctx, &head);
    if (head[0] != 0x05) return SocksError.HandshakeFailed;
    if (head[1] != SOCKS5_REP_SUCCESS) return mapError(head[1]);
    // Skip BND.ADDR per its ATYP
    const atyp = head[3];
    switch (atyp) {
        SOCKS5_ATYP_IPV4 => {
            var skip: [6]u8 = undefined;
            try recvExact(sock, io_ctx, &skip);
        },
        SOCKS5_ATYP_IPV6 => {
            var skip: [18]u8 = undefined;
            try recvExact(sock, io_ctx, &skip);
        },
        SOCKS5_ATYP_DOMAIN => {
            var len: [1]u8 = undefined;
            try recvExact(sock, io_ctx, &len);
            var skip: [256]u8 = undefined;
            try recvExact(sock, io_ctx, skip[0..len[0]]);
            var port_skip: [2]u8 = undefined;
            try recvExact(sock, io_ctx, &port_skip);
        },
        else => return SocksError.AddressTypeNotSupported,
    }
    _ = proxy;
}

pub const Credentials = struct {
    user: []const u8,
    pass: []const u8,
};

fn mapError(rep: u8) SocksError {
    return switch (rep) {
        SOCKS5_REP_NOT_ALLOWED, SOCKS5_REP_REFUSED => SocksError.ConnectionRefused,
        SOCKS5_REP_NET_UNREACHABLE => SocksError.NetworkUnreachable,
        SOCKS5_REP_HOST_UNREACHABLE => SocksError.HostUnreachable,
        SOCKS5_REP_TTL => SocksError.TtlExpired,
        SOCKS5_REP_CMD_UNSUPPORTED => SocksError.CommandNotSupported,
        SOCKS5_REP_ATYP_UNSUPPORTED => SocksError.AddressTypeNotSupported,
        else => SocksError.UnknownError,
    };
}

fn memWriteU16Be(buf: *[2]u8, v: u16) void {
    buf[0] = @intCast((v >> 8) & 0xFF);
    buf[1] = @intCast(v & 0xFF);
}
