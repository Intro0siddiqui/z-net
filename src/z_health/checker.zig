const std = @import("std");
const net = std.Io.net;
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

    pub fn checkTcpConnection(self: *HealthChecker, io_ctx: *std.Io, host: []const u8, port: u16, timeout_ns: u64) !HealthCheckResult {
        const start = std.time.milliTimestamp();
        const deadline = start + @as(i64, @intCast(timeout_ns / std.time.ns_per_ms));

        const address = net.IpAddress.parse(host, port) catch {
            return HealthCheckResult{
                .name = "TCP Connection",
                .status = .failing,
                .message = "Invalid IP address",
                .response_time_ms = 0,
            };
        };

        var stream: net.Stream = undefined;
        var connected = false;
        var current = std.time.milliTimestamp();
        while (current < deadline) {
            if (net.Stream.connect(&address, io_ctx.*, .{})) |s| {
                stream = s;
                connected = true;
                break;
            } else |_| {
                std.time.sleep(std.time.ns_per_ms * 10);
                current = std.time.milliTimestamp();
            }
        }
        if (!connected) {
            return HealthCheckResult{
                .name = "TCP Connection",
                .status = .failing,
                .message = try std.fmt.allocPrint(self.allocator, "Connection timed out after {} ms", .{timeout_ns / std.time.ns_per_ms}),
                .response_time_ms = current - start,
            };
        }
        stream.close(io_ctx.*);

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
