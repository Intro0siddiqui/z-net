const std = @import("std");
const bridge = @import("src/z_network_bridge.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    var iterations: usize = 50000;
    if (args.len >= 3) {
        iterations = try std.fmt.parseInt(usize, args[2], 10);
    }

    var engine = bridge.NetworkEngine.init();
    defer engine.deinit();

    const host = "127.0.0.1";
    const port = 8080;
    const request = "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n";

    var conn = try engine.connect(host, port);
    defer conn.close();

    var buffer: [4096]u8 = undefined;
    for (0..iterations) |i| {
        if (i % 1000 == 0) std.debug.print("Progress: {d}/{d}\n", .{ i, iterations });
        _ = try conn.write(request);

        var received: usize = 0;
        while (received < 1100) {
            const n = conn.read(&buffer) catch |err| {
                if (err == error.WouldBlock) {
                    _ = try bridge.poll(engine.handle, 1000);
                    continue;
                }
                break;
            };
            if (n == 0) break;
            received += n;
        }
    }
}
