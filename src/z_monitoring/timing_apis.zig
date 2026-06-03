const std = @import("std");
const builtin = @import("builtin");
const os = std.os;

pub const TimingEvent = struct {
    timestamp: u64,
    event_type: TimingEventType,
    duration_ns: u64,
    protocol: Protocol,
    endpoint: []const u8,
    success: bool,
    error_code: ?u16,
    metadata: std.json.Value,
};

pub const TimingEventType = enum {
    DNS_LOOKUP_START,
    DNS_LOOKUP_END,
    TCP_CONNECT_START,
    TCP_CONNECT_END,
    TLS_HANDSHAKE_START,
    TLS_HANDSHAKE_END,
    HTTP_REQUEST_START,
    HTTP_REQUEST_END,
    HTTP2_STREAM_CREATE,
    HTTP2_STREAM_CLOSE,
    HTTP3_CONNECTION_CREATE,
    HTTP3_STREAM_CLOSE,
    DATA_TRANSFER_START,
    DATA_TRANSFER_END,
};

pub const Protocol = enum {
    DNS,
    TCP,
    TLS,
    HTTP1_1,
    HTTP2,
    HTTP3,
};

pub const TimingMetrics = struct {
    total_operations: u64,
    successful_operations: u64,
    failed_operations: u64,
    avg_latency_ns: f64,
    min_latency_ns: u64,
    max_latency_ns: u64,
    p95_latency_ns: u64,
    p99_latency_ns: u64,
    throughput_mbps: f64,
};

pub const TimingCollector = struct {
    allocator: std.mem.Allocator,
    events: std.ArrayList(TimingEvent),
    current_operations: std.AutoHashMap(u32, u64),
    metrics_by_protocol: std.AutoHashMap(Protocol, TimingMetrics),
    histogram: std.AutoHashMap(Protocol, LatencyHistogram),
    start_time: u64,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .allocator = allocator,
            .events = std.ArrayList(TimingEvent).init(allocator),
            .current_operations = std.AutoHashMap(u32, u64).init(allocator),
            .metrics_by_protocol = std.AutoHashMap(Protocol, TimingMetrics).init(allocator),
            .histogram = std.AutoHashMap(Protocol, LatencyHistogram).init(allocator),
            .start_time = getHighResolutionTimestamp(),
        };
    }

    pub fn deinit(self: *Self) void {
        self.events.deinit();
        self.current_operations.deinit();
        self.metrics_by_protocol.deinit();
        self.histogram.deinit();
    }

    pub fn startTiming(self: *Self, operation_id: u32, event_type: TimingEventType, protocol: Protocol, endpoint: []const u8) !void {
        const timestamp = getHighResolutionTimestamp();
        try self.current_operations.put(operation_id, timestamp);

        const event = TimingEvent{
            .timestamp = timestamp,
            .event_type = event_type,
            .duration_ns = 0,
            .protocol = protocol,
            .endpoint = self.allocator.dupe(u8, endpoint) catch "",
            .success = true,
            .error_code = null,
            .metadata = .null,
        };
        try self.events.append(event);
    }

    pub fn endTiming(self: *Self, operation_id: u32, success: bool, error_code: ?u16, metadata: std.json.Value) !void {
        const start_time = self.current_operations.get(operation_id) orelse return;
        const end_time = getHighResolutionTimestamp();
        const duration = end_time - start_time;

        // Update the last event with duration and status
        if (self.events.items.len > 0) {
            var event = &self.events.items[self.events.items.len - 1];
            event.duration_ns = duration;
            event.success = success;
            event.error_code = error_code;
            event.metadata = metadata;
        }

        // Update metrics
        try self.updateMetrics(operation_id, duration, success);

        _ = self.current_operations.remove(operation_id);
    }

    pub fn recordDNSLatency(self: *Self, query: []const u8, latency_ns: u64, success: bool) !void {
        const event = TimingEvent{
            .timestamp = getHighResolutionTimestamp(),
            .event_type = .DNS_LOOKUP_END,
            .duration_ns = latency_ns,
            .protocol = .DNS,
            .endpoint = self.allocator.dupe(u8, query) catch "",
            .success = success,
            .error_code = if (!success) @as(u16, 1) else null,
            .metadata = .null,
        };
        try self.events.append(event);

        const metrics = try self.getOrCreateMetrics(.DNS);
        metrics.total_operations += 1;
        if (success) {
            metrics.successful_operations += 1;
        } else {
            metrics.failed_operations += 1;
        }

        try self.updateLatencyStats(.DNS, latency_ns);
    }

    pub fn recordTCPLatency(self: *Self, host: []const u8, latency_ns: u64, success: bool) !void {
        const event = TimingEvent{
            .timestamp = getHighResolutionTimestamp(),
            .event_type = .TCP_CONNECT_END,
            .duration_ns = latency_ns,
            .protocol = .TCP,
            .endpoint = self.allocator.dupe(u8, host) catch "",
            .success = success,
            .error_code = if (!success) @as(u16, 2) else null,
            .metadata = .null,
        };
        try self.events.append(event);

        const metrics = try self.getOrCreateMetrics(.TCP);
        metrics.total_operations += 1;
        if (success) {
            metrics.successful_operations += 1;
        } else {
            metrics.failed_operations += 1;
        }

        try self.updateLatencyStats(.TCP, latency_ns);
    }

    pub fn recordTLSLatency(self: *Self, host: []const u8, latency_ns: u64, success: bool) !void {
        const event = TimingEvent{
            .timestamp = getHighResolutionTimestamp(),
            .event_type = .TLS_HANDSHAKE_END,
            .duration_ns = latency_ns,
            .protocol = .TLS,
            .endpoint = self.allocator.dupe(u8, host) catch "",
            .success = success,
            .error_code = if (!success) @as(u16, 3) else null,
            .metadata = .null,
        };
        try self.events.append(event);

        const metrics = try self.getOrCreateMetrics(.TLS);
        metrics.total_operations += 1;
        if (success) {
            metrics.successful_operations += 1;
        } else {
            metrics.failed_operations += 1;
        }

        try self.updateLatencyStats(.TLS, latency_ns);
    }

    pub fn recordHTTPLatency(self: *Self, url: []const u8, latency_ns: u64, protocol: Protocol, success: bool, bytes_transferred: u64) !void {
        const event_type = switch (protocol) {
            .HTTP1_1 => .HTTP_REQUEST_END,
            .HTTP2 => .HTTP2_STREAM_CLOSE,
            .HTTP3 => .HTTP3_STREAM_CLOSE,
            else => .HTTP_REQUEST_END,
        };

        const event = TimingEvent{
            .timestamp = getHighResolutionTimestamp(),
            .event_type = event_type,
            .duration_ns = latency_ns,
            .protocol = protocol,
            .endpoint = self.allocator.dupe(u8, url) catch "",
            .success = success,
            .error_code = if (!success) @as(u16, 4) else null,
            .metadata = .object(std.json.ObjectMap.init(self.allocator)),
        };
        try self.events.append(event);

        const metrics = try self.getOrCreateMetrics(protocol);
        metrics.total_operations += 1;
        if (success) {
            metrics.successful_operations += 1;
        } else {
            metrics.failed_operations += 1;
        }

        try self.updateLatencyStats(protocol, latency_ns);

        // Calculate throughput
        if (success and latency_ns > 0) {
            const duration_sec = @as(f64, @floatFromInt(latency_ns)) / 1_000_000_000.0;
            metrics.throughput_mbps = (@as(f64, @floatFromInt(bytes_transferred)) * 8.0) / duration_sec / 1_000_000.0;
        }
    }

    pub fn getMetrics(self: *Self, protocol: Protocol) ?TimingMetrics {
        return self.metrics_by_protocol.get(protocol);
    }

    pub fn getAllMetrics(self: *Self) !std.AutoHashMap(Protocol, TimingMetrics) {
        return self.metrics_by_protocol.clone() catch return error.OutOfMemory;
    }

    pub fn exportPrometheus(self: *Self) ![]const u8 {
        var buffer = std.ArrayList(u8).init(self.allocator);
        const writer = buffer.writer();

        try writer.print("# HELP z-net_dns_latency_ns DNS lookup latency in nanoseconds\n", .{});
        try writer.print("# TYPE z-net_dns_latency_ns histogram\n", .{});
        try writer.print("z-net_dns_latency_ns{quantile=\"0.5\"} {d}\n", .{@as(f64, @floatFromInt(self.getQuantileLatency(.DNS, 0.5))) / 1_000_000_000.0});
        try writer.print("z-net_dns_latency_ns{quantile=\"0.95\"} {d}\n", .{@as(f64, @floatFromInt(self.getQuantileLatency(.DNS, 0.95))) / 1_000_000_000.0});
        try writer.print("z-net_dns_latency_ns{quantile=\"0.99\"} {d}\n", .{@as(f64, @floatFromInt(self.getQuantileLatency(.DNS, 0.99))) / 1_000_000_000.0});
        
        try writer.print("# HELP z-net_tcp_connect_latency_ns TCP connection latency in nanoseconds\n", .{});
        try writer.print("# TYPE z-net_tcp_connect_latency_ns histogram\n", .{});
        try writer.print("z-net_tcp_connect_latency_ns{quantile=\"0.5\"} {d}\n", .{@as(f64, @floatFromInt(self.getQuantileLatency(.TCP, 0.5))) / 1_000_000_000.0});
        try writer.print("z-net_tcp_connect_latency_ns{quantile=\"0.95\"} {d}\n", .{@as(f64, @floatFromInt(self.getQuantileLatency(.TCP, 0.95))) / 1_000_000_000.0});
        try writer.print("z-net_tcp_connect_latency_ns{quantile=\"0.99\"} {d}\n", .{@as(f64, @floatFromInt(self.getQuantileLatency(.TCP, 0.99))) / 1_000_000_000.0});

        try writer.print("# HELP z-net_http_latency_ns HTTP request latency in nanoseconds\n", .{});
        try writer.print("# TYPE z-net_http_latency_ns histogram\n", .{});

        const http_protocols = [_]Protocol{ .HTTP1_1, .HTTP2, .HTTP3 };
        for (http_protocols) |proto| {
            if (self.getMetrics(proto)) |metrics| {
                try writer.print("z-net_http_latency_ns{{protocol=\"{}\",quantile=\"0.5\"}} {d}\n", .{
                    @tagName(proto),
                    @as(f64, @floatFromInt(metrics.p95_latency_ns)) / 1_000_000_000.0,
                });
                try writer.print("z-net_http_latency_ns{{protocol=\"{}\",quantile=\"0.95\"}} {d}\n", .{
                    @tagName(proto),
                    @as(f64, @floatFromInt(metrics.p95_latency_ns)) / 1_000_000_000.0,
                });
                try writer.print("z-net_http_latency_ns{{protocol=\"{}\",quantile=\"0.99\"}} {d}\n", .{
                    @tagName(proto),
                    @as(f64, @floatFromInt(metrics.p99_latency_ns)) / 1_000_000_000.0,
                });
            }
        }

        return buffer.items;
    }

    pub fn exportJSON(self: *Self) ![]const u8 {
        var root = std.json.ObjectMap.init(self.allocator);
        
        // Add metrics for each protocol
        var protocol_metrics = std.json.ObjectMap.init(self.allocator);
        
        var protocols = std.enums.EnumArray(Protocol).init(.{});
        for (std.meta.tags(Protocol)) |proto| {
            if (self.getMetrics(proto)) |metrics| {
                var metrics_obj = std.json.ObjectMap.init(self.allocator);
                try metrics_obj.put("total_operations", .{ .integer = metrics.total_operations });
                try metrics_obj.put("successful_operations", .{ .integer = metrics.successful_operations });
                try metrics_obj.put("failed_operations", .{ .integer = metrics.failed_operations });
                try metrics_obj.put("avg_latency_ns", .{ .float = metrics.avg_latency_ns });
                try metrics_obj.put("min_latency_ns", .{ .integer = metrics.min_latency_ns });
                try metrics_obj.put("max_latency_ns", .{ .integer = metrics.max_latency_ns });
                try metrics_obj.put("p95_latency_ns", .{ .integer = metrics.p95_latency_ns });
                try metrics_obj.put("p99_latency_ns", .{ .integer = metrics.p99_latency_ns });
                try metrics_obj.put("throughput_mbps", .{ .float = metrics.throughput_mbps });
                
                try protocol_metrics.put(@tagName(proto), .{ .object = metrics_obj });
            }
        }
        
        try root.put("protocol_metrics", .{ .object = protocol_metrics });
        try root.put("timestamp", .{ .integer = getHighResolutionTimestamp() });
        
        const json_string = try std.json.stringifyAlloc(self.allocator, .{ .object = root }, .{});
        return json_string;
    }

    fn getHighResolutionTimestamp() u64 {
        const now = std.time.Instant.now() catch {
            // Fallback to std.os.clock_gettime if Instant.now() fails
            var ts: os.timespec = undefined;
            _ = os.clock_gettime(os.CLOCK_MONOTONIC, &ts) catch return 0;
            return @as(u64, @intCast(ts.tv_sec)) * 1_000_000_000 + @as(u64, @intCast(ts.tv_nsec));
        };
        return now.nanos;
    }

    fn getOrCreateMetrics(self: *Self, protocol: Protocol) !*TimingMetrics {
        if (self.metrics_by_protocol.get(protocol)) |metrics| {
            return metrics;
        }

        const new_metrics = TimingMetrics{
            .total_operations = 0,
            .successful_operations = 0,
            .failed_operations = 0,
            .avg_latency_ns = 0,
            .min_latency_ns = std.math.maxInt(u64),
            .max_latency_ns = 0,
            .p95_latency_ns = 0,
            .p99_latency_ns = 0,
            .throughput_mbps = 0,
        };

        try self.metrics_by_protocol.put(protocol, new_metrics);
        return self.metrics_by_protocol.getPtr(protocol).?;
    }

    fn updateMetrics(self: *Self, operation_id: u32, duration_ns: u64, success: bool) !void {
        // This would be implemented to track ongoing operations and their metrics
        _ = operation_id;
        _ = duration_ns;
        _ = success;
        _ = self;
    }

    fn updateLatencyStats(self: *Self, protocol: Protocol, latency_ns: u64) !void {
        const metrics = try self.getOrCreateMetrics(protocol);
        
        // Update min/max
        if (latency_ns < metrics.min_latency_ns) metrics.min_latency_ns = latency_ns;
        if (latency_ns > metrics.max_latency_ns) metrics.max_latency_ns = latency_ns;

        // Update average (rolling)
        const total_ops = metrics.total_operations;
        metrics.avg_latency_ns = (metrics.avg_latency_ns * @as(f64, @floatFromInt(total_ops - 1)) + @as(f64, @floatFromInt(latency_ns))) / @as(f64, @floatFromInt(total_ops));

        // Update histogram for percentile calculations
        const histogram = try self.getOrCreateHistogram(protocol);
        try histogram.addLatency(latency_ns);
        metrics.p95_latency_ns = histogram.getPercentile(95);
        metrics.p99_latency_ns = histogram.getPercentile(99);
    }

    fn getOrCreateHistogram(self: *Self, protocol: Protocol) !*LatencyHistogram {
        if (self.histogram.get(protocol)) |histogram| {
            return histogram;
        }

        const new_histogram = LatencyHistogram.init(self.allocator);
        try self.histogram.put(protocol, new_histogram);
        return self.histogram.getPtr(protocol).?;
    }

    fn getQuantileLatency(self: *Self, protocol: Protocol, quantile: f64) u64 {
        const histogram = self.histogram.get(protocol) orelse return 0;
        return histogram.getPercentile(@as(u8, @intFromFloat(quantile * 100.0)));
    }
};

pub const LatencyHistogram = struct {
    buckets: std.AutoHashMap(u16, u64), // latency_range -> count
    total_samples: u64,
    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .buckets = std.AutoHashMap(u16, u64).init(allocator),
            .total_samples = 0,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        self.buckets.deinit();
    }

    pub fn addLatency(self: *Self, latency_ns: u64) !void {
        // Convert latency to milliseconds for bucketing
        const latency_ms = @as(u16, @intFromFloat(@as(f64, @floatFromInt(latency_ns)) / 1_000_000.0));
        const bucket_key = latency_ms / 10 * 10; // 10ms buckets
        
        const current_count = self.buckets.get(bucket_key) orelse 0;
        try self.buckets.put(bucket_key, current_count + 1);
        self.total_samples += 1;
    }

    pub fn getPercentile(self: *Self, percentile: u8) u64 {
        if (self.total_samples == 0) return 0;

        const target_count = @as(u64, @intFromFloat(@as(f64, self.total_samples) * @as(f64, @intFromFloat(percentile)) / 100.0));
        
        var cumulative_count: u64 = 0;
        var bucket_keys = std.ArrayList(u16).init(self.allocator);
        defer bucket_keys.deinit();

        // Collect and sort bucket keys
        var keys_iter = self.buckets.keyIterator();
        while (keys_iter.next()) |key| {
            try bucket_keys.append(key.*);
        }
        std.sort.insertion(u16, bucket_keys.items, {}, std.sort.asc(u16));

        // Find the percentile
        for (bucket_keys.items) |bucket_key| {
            const count = self.buckets.get(bucket_key).?;
            cumulative_count += count;
            if (cumulative_count >= target_count) {
                return @as(u64, @intFromFloat(bucket_key)) * 1_000_000; // Convert back to nanoseconds
            }
        }

        // Fallback to maximum latency if percentile not found
        return @as(u64, @intFromFloat(bucket_keys.items[bucket_keys.items.len - 1])) * 1_000_000;
    }
};