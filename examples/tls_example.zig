//! TLS Example - Demonstrating secure connection capabilities
//! Usage: zig run examples/tls_example.zig

const std = @import("std");
const builtin = @import("builtin");
const socket = @import("../src/z_socket/socket.zig");
const tls = @import("../src/z_tls/tls.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Initialize the OS-agnostic IO context (Zig 0.16 pattern)
    var io_ctx = std.Io.init();
    defer io_ctx.deinit();

    std.log.info("Starting z-net TLS Example", .{});

    // Test servers with different TLS configurations
    const test_servers = &[_]struct {
        host: []const u8,
        port: u16,
        description: []const u8,
    }{
        .{ .host = "www.google.com", .port = 443, .description = "Google (TLS 1.3)" },
        .{ .host = "www.cloudflare.com", .port = 443, .description = "Cloudflare (Modern TLS)" },
        .{ .host = "www.github.com", .port = 443, .description = "GitHub (Enterprise TLS)" },
    };

    // Example 1: Basic TLS Handshake
    std.log.info("\n=== Example 1: Basic TLS Handshake ===", .{});

    for (test_servers) |server| {
        std.log.info("Connecting to {}:{} ({})", .{ 
            server.host, 
            server.port, 
            server.description 
        });

        performTlsHandshake(allocator, &io_ctx, server.host, server.port) catch |err| {
            std.log.err("Handshake failed for {s}: {}", .{server.host, err});
        };
    }

    // Example 4: Certificate Validation
    std.log.info("\n=== Example 4: Certificate Validation ===", .{});

    const cert_host = "www.google.com";
    const cert_port: u16 = 443;

    std.log.info("Validating certificate for {s}", .{cert_host});

    var socket_conn = socket.Socket.create(&io_ctx, .inet, .stream) catch |err| {
        std.log.err("Socket creation failed: {}", .{err});
        return;
    };
    defer socket_conn.close(&io_ctx);

    const addr = std.net.Address.parseIp4(cert_host, cert_port) catch |err| {
        std.log.err("Address resolution failed: {}", .{err});
        return;
    };

    socket_conn.connect(&io_ctx, addr) catch |err| {
        std.log.err("Connection failed: {}", .{err});
        return;
    };

    var tls_conn = tls.TlsConnection.init(allocator, cert_host) catch |err| {
        std.log.err("TLS connection init failed: {}", .{err});
        return;
    };
    defer tls_conn.deinit();

    tls_conn.connect(socket_conn) catch |err| {
        std.log.err("Unexpected TLS failure: {}", .{err});
        return;
    };

    const cert_valid = try tls_conn.verifyCertificate();
    if (cert_valid) {
        std.log.info("✅ Certificate validation passed");
    }

    std.log.info("\n🎉 TLS Example completed successfully!", .{});
}

fn performTlsHandshake(allocator: std.mem.Allocator, io_ctx: *std.Io, host: []const u8, port: u16) !void {
    var socket_conn = try socket.Socket.create(io_ctx, .inet, .stream);
    defer socket_conn.close(io_ctx);

    const addr = try std.net.Address.parseIp4(host, port);

    try socket_conn.connect(io_ctx, addr);

    var tls_conn = try tls.TlsConnection.init(allocator, host);
    defer tls_conn.deinit();

    try tls_conn.connect(socket_conn);

    std.log.info("✅ TLS handshake successful with {s}:{}", .{host, port});

    // Send a simple HTTP request
    const http_request = "GET / HTTP/1.1\r\nHost: " ++ host ++ "\r\nConnection: close\r\n\r\n";
    _ = try tls_conn.send(http_request);

    // Receive response (simplified)
    var buffer: [1024]u8 = undefined;
    _ = try tls_conn.recv(&buffer);

    const handshake_info = try tls_conn.getHandshakeInfo();
    std.log.info("🔒 TLS Details: {s} - {s}", .{handshake_info.protocol, handshake_info.cipher_suite});
}
