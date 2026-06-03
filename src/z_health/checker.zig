const std = @import("std");
const net = std.net;
const mem = std.mem;

pub const HealthStatus = enum {
    healthy,
    degraded,
    critical,
    failing,
};

pub const HealthCheckResult = struct {
    name: []const u8,
    status: HealthStatus,
    message: []const u8,
    response_time_ms: i64,
};

pub const HealthChecker = struct {
    allocator: mem.Allocator,

    pub fn init(allocator: mem.Allocator) HealthChecker {
        return .{ .allocator = allocator };
    }

    pub fn checkTcpConnection(self: *HealthChecker, host: []const u8, port: u16, timeout_ns: u64) !HealthCheckResult {
        const start = std.time.milliTimestamp();
        const deadline = start + @as(i64, @intCast(timeout_ns / std.time.ns_per_ms));

        const address = net.Address.parseIp(host, port) catch {
            return HealthCheckResult{
                .name = "TCP Connection",
                .status = .failing,
                .message = "Invalid IP address",
                .response_time_ms = 0,
            };
        };

        const stream = blk: {
            var current = std.time.milliTimestamp();
            while (current < deadline) {
                if (net.tcpConnectToAddress(address)) |s| break :blk s;
                std.time.sleep(std.time.ns_per_ms * 10);
                current = std.time.milliTimestamp();
            }
            return HealthCheckResult{
                .name = "TCP Connection",
                .status = .failing,
                .message = try std.fmt.allocPrint(self.allocator, "Connection timed out after {} ms", .{timeout_ns / std.time.ns_per_ms}),
                .response_time_ms = current - start,
            };
        };
        stream.close();

        return HealthCheckResult{
            .name = "TCP Connection",
            .status = .healthy,
            .message = "TCP connection successful",
            .response_time_ms = std.time.milliTimestamp() - start,
        };
    }

    pub fn getSystemMetrics(self: *HealthChecker) !void {
        _ = self;
        // This is highly OS-dependent. For now, we'll provide a placeholder.
        // On Linux, we could read /proc/stat, /proc/meminfo, etc.
        std.debug.print("System metrics monitoring not fully implemented for this platform.\n", .{});
    }
};
