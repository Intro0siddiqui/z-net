const std = @import("std");
const net = std.net;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // 10KB payload (reduced from 10MB to focus on overhead)
    const payload_size = 1024;
    const payload = try allocator.alloc(u8, payload_size);
    defer allocator.free(payload);
    @memset(payload, 'A');

    const address = try net.Address.parseIp("127.0.0.1", 8080);
    var server = try address.listen(.{ .reuse_address = true, .kernel_backlog = 1024 });
    defer server.deinit();

    std.debug.print("Native Zig server on 127.0.0.1:8080 (Memory-only, Keep-Alive)\n", .{});

    const response_header = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 1024\r\nConnection: keep-alive\r\n\r\n";

    while (true) {
        const conn = try server.accept();
        // Enable TCP_NODELAY
        const fd = conn.stream.handle;
        const builtin = @import("builtin");
        if (builtin.os.tag == .linux) {
            const level = std.os.linux.IPPROTO.TCP;
            const optname = std.os.linux.TCP.NODELAY;
            const value: c_int = 1;
            const val_bytes = std.mem.asBytes(&value);
            _ = std.os.linux.setsockopt(fd, level, optname, val_bytes, @intCast(val_bytes.len));
        }
        _ = try std.Thread.spawn(.{}, handleConnection, .{ conn, response_header, payload });
    }
}

fn handleConnection(conn: net.Server.Connection, header: []const u8, payload: []const u8) void {
    defer conn.stream.close();
    var buffer: [1024]u8 = undefined;

    while (true) {
        // Read the request (we don't parse it, just consume it)
        const n = conn.stream.read(&buffer) catch break;
        if (n == 0) break;

        // Write response
        _ = conn.stream.write(header) catch break;
        _ = conn.stream.write(payload) catch break;
    }
}
