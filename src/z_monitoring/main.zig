const std = @import("std");
const dashboard = @import("dashboard");
const validator = @import("z_config");
const checker = @import("z_health");

pub fn main() !void {
    var dbga: std.heap.DebugAllocator(.{}) = .init;
    defer _ = dbga.deinit();
    const allocator = dbga.allocator();

    std.debug.print("Starting z-net Monitor...\n", .{});

    // Initialize I/O runtime
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var io = threaded.io();

    // Initialize components
    var db_server = dashboard.DashboardServer.init(allocator, 8080);
    const config_val = validator.ConfigValidator.init(allocator);
    const health_chk = checker.HealthChecker.init(allocator);

    _ = config_val;
    _ = health_chk;

    // Start dashboard
    try db_server.start(&io);
}
