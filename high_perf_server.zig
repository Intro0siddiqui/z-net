const std = @import("std");

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const addr = try std.Io.net.IpAddress.parseIp4("127.0.0.1", 8080);
    var server = try std.Io.net.IpAddress.listen(&addr, io, .{ .mode = .stream });

    const response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 1024\r\nConnection: keep-alive\r\n\r\n" ++ ("A" ** 1024);

    while (true) {
        const stream = try server.accept(io);
        _ = try std.Thread.spawn(.{}, handleConnection, .{ stream, io, response });
    }
}

fn handleConnection(stream: std.Io.net.Stream, io: std.Io, response: []const u8) void {
    defer stream.close(io);
    var buffer: [1024]u8 = undefined;
    while (true) {
        var data: [1][]u8 = .{&buffer};
        const n = io.vtable.netRead(io.userdata, stream.socket.handle, &data) catch break;
        if (n == 0) break;

        var messages: [1]std.Io.net.OutgoingMessage = .{.{
            .address = &stream.socket.address,
            .data_ptr = response.ptr,
            .data_len = response.len,
        }};
        _ = io.vtable.netSend(io.userdata, stream.socket.handle, &messages, .{}) ;
    }
}
