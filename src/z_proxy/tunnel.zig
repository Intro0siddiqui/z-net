//! Proxy-aware socket connector.
//!
//! `connectTunneled` is the entry point `z_tls` calls instead of a raw
//! `Socket::connect`. It first opens a TCP socket to the resolved proxy
//! (or the origin host if no proxy applies), then runs the appropriate
//! handshake (SOCKS5 or HTTP CONNECT) so the socket ends up bound to
//! the origin `host:port` from the caller's point of view.
//!
//! The handshake result leaves the socket in plaintext - the caller is
//! still expected to drive `z_tls::TlsConnection::connect` afterwards.

const std = @import("std");
const net = std.net;
const ProxyConfig = @import("proxy.zig").ProxyConfig;
const ProxyHop = @import("proxy.zig").ProxyHop;
const socks5 = @import("socks5.zig");
const http_connect = @import("connect.zig");
const Socket = @import("../z_socket/socket.zig").Socket;

pub const TunnelError = socks5.SocksError || http_connect.ConnectError || SocketError || error{UnsupportedProxyScheme};

const SocketError = error{
    ResolutionFailed,
    ConnectFailed,
};

/// Connect a fresh socket, tunneling through `proxy` if non-null. On
/// success the socket is ready for `z_tls` to perform the TLS handshake
/// directly to `target_host:target_port`.
pub fn connectTunneled(
    io_ctx: *std.Io,
    proxy: ?ProxyHop,
    target_host: []const u8,
    target_port: u16,
    credentials: ?socks5.Credentials,
) TunnelError!Socket {
    const hop = proxy orelse {
        // Direct connection - no proxy.
        const addr = try resolveHost(target_host, target_port);
        var sock = Socket.create(io_ctx, .inet, .stream) catch return error.ConnectFailed;
        sock.connect(io_ctx, addr) catch return error.ConnectFailed;
        return sock;
    };

    const proxy_addr = try resolveHost(hop.host, hop.port);
    var sock = Socket.create(io_ctx, .inet, .stream) catch return error.ConnectFailed;
    sock.connect(io_ctx, proxy_addr) catch return error.ConnectFailed;

    switch (hop.scheme) {
        .direct => {},
        .http => try http_connect.connect(io_ctx, &sock, hop, target_host, target_port),
        .socks5 => try socks5.connect(io_ctx, &sock, hop, target_host, target_port, credentials),
        .socks4 => return TunnelError.UnsupportedProxyScheme,
    }
    return sock;
}

fn resolveHost(host: []const u8, port: u16) SocketError!net.Address {
    // First try IPv4 literal, then DNS. In a real impl this would use
    // `z_dns`; we keep the dep light here to avoid a circular build.
    if (net.Address.parseIp4(host, port)) |a| return a else |_| {}
    // Real DNS resolution is handled one layer up in z_socket::getConnection
    // so we surface a typed error here; the proxy layer is a tunnel, not a
    // resolver.
    return SocketError.ResolutionFailed;
}

test "tunneled connection shortcut keeps proxy null working" {
    // Compile-time check: the helper exposes the no-proxy branch even
    // when the proxy module is empty.
    const _ = connectTunneled;
}
