const std = @import("std");
const net = std.net;
const http = std.http;
const mem = std.mem;

pub const MetricDataPoint = struct {
    timestamp: i64,
    metric_name: []const u8,
    value: f64,
    labels: std.StringHashMap([]const u8),

    pub fn init(allocator: mem.Allocator, name: []const u8, value: f64) MetricDataPoint {
        return .{
            .timestamp = std.time.milliTimestamp(),
            .metric_name = name,
            .value = value,
            .labels = std.StringHashMap([]const u8).init(allocator),
        };
    }

    pub fn deinit(self: *MetricDataPoint) void {
        self.labels.deinit();
    }
};

pub const AlertSeverity = enum {
    info,
    warning,
    critical,
    emergency,
};

pub const AlertData = struct {
    alert_id: []const u8,
    severity: AlertSeverity,
    title: []const u8,
    message: []const u8,
    timestamp: i64,
    source: []const u8,
    acknowledged: bool,
};

pub const DashboardServer = struct {
    allocator: mem.Allocator,
    port: u16,

    pub fn init(allocator: mem.Allocator, port: u16) DashboardServer {
        return .{
            .allocator = allocator,
            .port = port,
        };
    }

    pub fn start(self: *DashboardServer) !void {
        const address = try net.Address.parseIp("127.0.0.1", self.port);
        var server = try address.listen(.{ .reuse_address = true });
        defer server.deinit();

        std.debug.print("Dashboard server listening on http://127.0.0.1:{d}\n", .{self.port});

        while (true) {
            const conn = try server.accept();
            _ = try std.Thread.spawn(.{}, handleConnection, .{ self.allocator, conn });
        }
    }

    fn handleConnection(allocator: mem.Allocator, conn: net.Server.Connection) void {
        defer conn.stream.close();

        var read_buffer: [4096]u8 = undefined;
        var server = http.Server.init(conn, &read_buffer);

        var request = server.receiveHead() catch |err| {
            std.debug.print("Error receiving head: {}\n", .{err});
            return;
        };

        if (mem.eql(u8, request.head.target, "/") or mem.eql(u8, request.head.target, "/dashboard")) {
            handleRoot(allocator, &request) catch |err| {
                std.debug.print("Error handling root: {}\n", .{err});
            };
        } else if (mem.eql(u8, request.head.target, "/api/metrics")) {
            handleMetrics(allocator, &request) catch |err| {
                std.debug.print("Error handling metrics: {}\n", .{err});
            };
        } else {
            handleNotFound(&request) catch |err| {
                std.debug.print("Error handling not found: {}\n", .{err});
            };
        }
    }

    fn handleRoot(allocator: mem.Allocator, request: *http.Server.Request) !void {
        _ = allocator;
        var response = try request.respondHead(.ok, .{
            .content_type = .{ .override = "text/html" },
        });
        try response.writeAll(dashboard_html);
        try response.finish();
    }

    fn handleMetrics(allocator: mem.Allocator, request: *http.Server.Request) !void {
        _ = allocator;
        var response = try request.respondHead(.ok, .{
            .content_type = .{ .override = "application/json" },
        });
        try response.writeAll("{\"status\":\"ok\",\"metrics\":[]}");
        try response.finish();
    }

    fn handleNotFound(request: *http.Server.Request) !void {
        var response = try request.respondHead(.not_found, .{});
        try response.writeAll("Not Found");
        try response.finish();
    }
};

const dashboard_html =
    \\<!DOCTYPE html>
    \\<html>
    \\<head>
    \\    <title>Zawra Networking Stack Monitor (Zig)</title>
    \\    <style>
    \\        body { font-family: sans-serif; margin: 20px; background-color: #f0f2f5; }
    \\        .header { background: #1a73e8; color: white; padding: 20px; border-radius: 8px; }
    \\        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin-top: 20px; }
    \\        .card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
    \\    </style>
    \\</head>
    \\<body>
    \\    <div class="header">
    \\        <h1>Zawra Networking Stack Monitor (Zig)</h1>
    \\    </div>
    \\    <div class="grid">
    \\        <div class="card">
    \\            <h2>Network Latency</h2>
    \\            <p id="latency">Loading...</p>
    \\        </div>
    \\        <div class="card">
    \\            <h2>Throughput</h2>
    \\            <p id="throughput">Loading...</p>
    \\        </div>
    \\    </div>
    \\</body>
    \\</html>
;
