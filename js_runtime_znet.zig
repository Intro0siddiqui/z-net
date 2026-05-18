const std = @import("std");

pub fn main(init: std.process.Init) !void {
    var args_it = init.minimal.args.iterate();
    _ = args_it.next(); // exe
    _ = args_it.next(); // script

    var iterations: usize = 10000;
    if (args_it.next()) |arg| {
        iterations = try std.fmt.parseInt(usize, arg, 10);
    }

    const io = init.io;
    const host = "127.0.0.1";
    const port = 8080;
    const request = "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: keep-alive\r\n\r\n";

    const addr = try std.Io.net.IpAddress.parseIp4(host, port);
    var stream = try std.Io.net.IpAddress.connect(&addr, io, .{ .mode = .stream });
    defer stream.close(io);

    var buffer: [8192]u8 = undefined;
    for (0..iterations) |_| {
        var messages: [1]std.Io.net.OutgoingMessage = .{.{
            .address = &addr,
            .data_ptr = request.ptr,
            .data_len = request.len,
        }};
        _ = io.vtable.netSend(io.userdata, stream.socket.handle, &messages, .{}) ;

        var received: usize = 0;
        while (received < 1100) {
            var data: [1][]u8 = .{&buffer};
            const n = try io.vtable.netRead(io.userdata, stream.socket.handle, &data);
            if (n == 0) break;
            received += n;
        }
    }
}
