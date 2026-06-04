const std = @import("std");
const net = std.Io.net;
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

    pub fn start(self: *DashboardServer, io: std.Io) !void {
        const address = try net.IpAddress.parse("127.0.0.1", self.port);
        var server = try address.listen(io, .{ .reuse_address = true });
        defer server.deinit(io);

        std.debug.print("Dashboard server listening on http://127.0.0.1:{d}\n", .{self.port});

        while (true) {
            const stream = try server.accept(io);
            _ = try std.Thread.spawn(.{}, handleConnection, .{ self.allocator, io, stream });
        }
    }
};

fn handleConnection(allocator: mem.Allocator, io: std.Io, stream: net.Stream) void {
    defer stream.close(io);

    var recv_buffer: [4096]u8 = undefined;
    var send_buffer: [4096]u8 = undefined;
    var conn_reader = stream.reader(io, &recv_buffer);
    var conn_writer = stream.writer(io, &send_buffer);
    var server = http.Server.init(&conn_reader.interface, &conn_writer.interface);

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
    const headers = [_]http.Header{.{ .name = "Content-Type", .value = "text/html" }};
    try request.respond(dashboard_html, .{
        .extra_headers = &headers,
    });
}

fn handleMetrics(allocator: mem.Allocator, request: *http.Server.Request) !void {
    _ = allocator;
    const headers = [_]http.Header{.{ .name = "Content-Type", .value = "application/json" }};
    try request.respond("{\"status\":\"ok\",\"metrics\":[]}", .{
        .extra_headers = &headers,
    });
}

fn handleNotFound(request: *http.Server.Request) !void {
    try request.respond("Not Found", .{
        .status = .not_found,
    });
}

const dashboard_html =
    \\<!DOCTYPE html>
    \\<html>
    \\<head>
    \\    <title>z-net Networking Stack Monitor (Zig)</title>
    \\    <style>
    \\        body { font-family: sans-serif; margin: 20px; background-color: #f0f2f5; }
    \\        .header { background: #1a73e8; color: white; padding: 20px; border-radius: 8px; }
    \\        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin-top: 20px; }
    \\        .card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
    \\    </style>
    \\</head>
    \\<body>
    \\    <div class="header">
    \\        <h1>z-net Networking Stack Monitor (Zig)</h1>
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
