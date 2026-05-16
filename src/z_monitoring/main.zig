const std = @import("std");
const dashboard = @import("dashboard.zig");
const validator = @import("../z_config/validator.zig");
const checker = @import("../z_health/checker.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("Starting z-net Monitor...\n", .{});

    // Initialize components
    var db_server = dashboard.DashboardServer.init(allocator, 8080);
    const config_val = validator.ConfigValidator.init(allocator);
    const health_chk = checker.HealthChecker.init(allocator);

    _ = config_val;
    _ = health_chk;

    // Start dashboard in a separate thread or just run it here
    try db_server.start();
}
