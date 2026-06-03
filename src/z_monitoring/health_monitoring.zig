const std = @import("std");
const json = std.json;

pub const HealthStatus = enum {
    HEALTHY,
    DEGRADED,
    UNHEALTHY,
    CRITICAL,
    UNKNOWN,
};

pub const ConnectionHealth = struct {
    connection_id: []const u8,
    host: []const u8,
    port: u16,
    protocol: ConnectionProtocol,
    status: HealthStatus,
    last_check_time: u64,
    response_time_ms: f64,
    success_rate: f64,
    error_count: u32,
    consecutive_failures: u32,
    health_score: f64,
    diagnostics: Diagnostics,
};

pub const ConnectionProtocol = enum {
    TCP,
    UDP,
    TLS,
    HTTP,
    HTTPS,
    HTTP2,
    HTTP3,
    DNS,
};

pub const HealthCheck = struct {
    check_id: []const u8,
    name: []const u8,
    check_type: HealthCheckType,
    target: []const u8,
    interval_ms: u64,
    timeout_ms: u64,
    retry_attempts: u32,
    enabled: bool,
    critical: bool,
};

pub const HealthCheckType = enum {
    CONNECTIVITY,
    LATENCY,
    THROUGHPUT,
    ERROR_RATE,
    DNS_RESOLUTION,
    TLS_HANDSHAKE,
    HTTP_RESPONSE,
    CUSTOM,
};

pub const Diagnostics = struct {
    last_error: ?[]const u8,
    error_code: ?u16,
    network_interface: ?[]const u8,
    dns_servers: [][]const u8,
    routing_info: ?[]const u8,
    connection_pool_status: ConnectionPoolStatus,
    resource_usage: ResourceUsage,
};

pub const ConnectionPoolStatus = struct {
    active_connections: u32,
    idle_connections: u32,
    max_connections: u32,
    connection_timeout_rate: f64,
    pool_health_score: f64,
};

pub const ResourceUsage = struct {
    memory_usage_mb: f64,
    cpu_usage_percent: f64,
    network_io_bytes_per_sec: u64,
    file_descriptor_count: u32,
};

pub const HealthMonitor = struct {
    allocator: std.mem.Allocator,
    connections: std.StringHashMap(ConnectionHealth),
    health_checks: std.StringHashMap(HealthCheck),
    check_schedules: std.ArrayList(CheckSchedule),
    health_history: std.ArrayList(HealthHistoryEntry),
    diagnostics_engine: *DiagnosticsEngine,
    notification_handler: *HealthNotificationHandler,
    is_monitoring: bool,
    start_time: u64,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, diagnostics_engine: *DiagnosticsEngine, notification_handler: *HealthNotificationHandler) Self {
        return Self{
            .allocator = allocator,
            .connections = std.StringHashMap(ConnectionHealth).init(allocator),
            .health_checks = std.StringHashMap(HealthCheck).init(allocator),
            .check_schedules = std.ArrayList(CheckSchedule).init(allocator),
            .health_history = std.ArrayList(HealthHistoryEntry).init(allocator),
            .diagnostics_engine = diagnostics_engine,
            .notification_handler = notification_handler,
            .is_monitoring = false,
            .start_time = std.time.Instant.now() catch @panic("Failed to get time"),
        };
    }

    pub fn deinit(self: *Self) void {
        // Free allocated memory
        var connections_iter = self.connections.valueIterator();
        while (connections_iter.next()) |conn| {
            self.freeConnectionHealth(conn);
        }
        self.connections.deinit();

        var checks_iter = self.health_checks.valueIterator();
        while (checks_iter.next()) |check| {
            self.freeHealthCheck(check);
        }
        self.health_checks.deinit();
        self.check_schedules.deinit();
        self.health_history.deinit();
    }

    pub fn startMonitoring(self: *Self) !void {
        self.is_monitoring = true;
        
        // Start all enabled health checks
        var checks_iter = self.health_checks.valueIterator();
        while (checks_iter.next()) |check| {
            if (check.enabled) {
                try self.scheduleHealthCheck(check);
            }
        }
    }

    pub fn stopMonitoring(self: *Self) void {
        self.is_monitoring = false;
        self.check_schedules.clearRetainingCapacity();
    }

    pub fn addConnection(self: *Self, connection_id: []const u8, host: []const u8, port: u16, protocol: ConnectionProtocol) !void {
        const health = ConnectionHealth{
            .connection_id = try self.allocator.dupe(u8, connection_id),
            .host = try self.allocator.dupe(u8, host),
            .port = port,
            .protocol = protocol,
            .status = .UNKNOWN,
            .last_check_time = 0,
            .response_time_ms = 0.0,
            .success_rate = 0.0,
            .error_count = 0,
            .consecutive_failures = 0,
            .health_score = 0.0,
            .diagnostics = try self.createEmptyDiagnostics(),
        };

        try self.connections.put(try self.allocator.dupe(u8, connection_id), health);
    }

    pub fn removeConnection(self: *Self, connection_id: []const u8) !void {
        if (self.connections.remove(connection_id)) |kv| {
            self.freeConnectionHealth(&kv.value);
        }
    }

    pub fn addHealthCheck(self: *Self, check: HealthCheck) !void {
        const stored_check = HealthCheck{
            .check_id = try self.allocator.dupe(u8, check.check_id),
            .name = try self.allocator.dupe(u8, check.name),
            .check_type = check.check_type,
            .target = try self.allocator.dupe(u8, check.target),
            .interval_ms = check.interval_ms,
            .timeout_ms = check.timeout_ms,
            .retry_attempts = check.retry_attempts,
            .enabled = check.enabled,
            .critical = check.critical,
        };

        try self.health_checks.put(try self.allocator.dupe(u8, check.check_id), stored_check);

        if (check.enabled) {
            try self.scheduleHealthCheck(&stored_check);
        }
    }

    pub fn removeHealthCheck(self: *Self, check_id: []const u8) !void {
        if (self.health_checks.remove(check_id)) |kv| {
            self.freeHealthCheck(&kv.value);
        }
    }

    pub fn executeHealthCheck(self: *Self, check_id: []const u8) !HealthCheckResult {
        const check = self.health_checks.get(check_id) orelse return HealthCheckResult{
            .check_id = check_id,
            .success = false,
            .status = .UNKNOWN,
            .response_time_ms = 0.0,
            .error_message = "Health check not found",
            .diagnostics_data = null,
        };

        const start_time = std.time.Instant.now() catch return self.createFailedResult(check, "Failed to get timestamp");
        
        const result = switch (check.check_type) {
            .CONNECTIVITY => try self.checkConnectivity(check),
            .LATENCY => try self.checkLatency(check),
            .THROUGHPUT => try self.checkThroughput(check),
            .ERROR_RATE => try self.checkErrorRate(check),
            .DNS_RESOLUTION => try self.checkDNSResolution(check),
            .TLS_HANDSHAKE => try self.checkTLSHandshake(check),
            .HTTP_RESPONSE => try self.checkHTTPResponse(check),
            .CUSTOM => try self.executeCustomCheck(check),
        };

        const end_time = std.time.Instant.now() catch return result;
        result.response_time_ms = @as(f64, @floatFromInt(end_time.since(start_time))) / 1_000_000.0;

        // Update connection health if this check is for a known connection
        if (self.connections.get(check.target)) |*conn| {
            try self.updateConnectionHealth(conn, &result);
        }

        // Log health check result
        try self.logHealthResult(&result);

        return result;
    }

    pub fn getConnectionHealth(self: *Self, connection_id: []const u8) ?*ConnectionHealth {
        return self.connections.getPtr(connection_id);
    }

    pub fn getAllConnectionsHealth(self: *Self) !std.StringHashMap(ConnectionHealth) {
        return self.connections.clone() catch return error.OutOfMemory;
    }

    pub fn getHealthSummary(self: *Self) !HealthSummary {
        var healthy_count: u32 = 0;
        var degraded_count: u32 = 0;
        var unhealthy_count: u32 = 0;
        var critical_count: u32 = 0;
        var unknown_count: u32 = 0;

        var connections_iter = self.connections.valueIterator();
        while (connections_iter.next()) |conn| {
            switch (conn.status) {
                .HEALTHY => healthy_count += 1,
                .DEGRADED => degraded_count += 1,
                .UNHEALTHY => unhealthy_count += 1,
                .CRITICAL => critical_count += 1,
                .UNKNOWN => unknown_count += 1,
            }
        }

        const total_connections = self.connections.count();
        const overall_health_score = if (total_connections > 0)
            (healthy_count * 100 + degraded_count * 70 + unhealthy_count * 30 + critical_count * 10) / total_connections
        else 0.0;

        return HealthSummary{
            .total_connections = total_connections,
            .healthy_connections = healthy_count,
            .degraded_connections = degraded_count,
            .unhealthy_connections = unhealthy_count,
            .critical_connections = critical_count,
            .unknown_connections = unknown_count,
            .overall_health_score = overall_health_score,
            .uptime_ms = self.getUptimeMs(),
        };
    }

    pub fn exportHealthReportJSON(self: *Self) ![]const u8 {
        var root = json.ObjectMap.init(self.allocator);

        // Summary
        const summary = try self.getHealthSummary();
        var summary_obj = json.ObjectMap.init(self.allocator);
        try summary_obj.put("total_connections", json.Value{ .integer = summary.total_connections });
        try summary_obj.put("healthy_connections", json.Value{ .integer = summary.healthy_connections });
        try summary_obj.put("degraded_connections", json.Value{ .integer = summary.degraded_connections });
        try summary_obj.put("unhealthy_connections", json.Value{ .integer = summary.unhealthy_connections });
        try summary_obj.put("critical_connections", json.Value{ .integer = summary.critical_connections });
        try summary_obj.put("unknown_connections", json.Value{ .integer = summary.unknown_connections });
        try summary_obj.put("overall_health_score", json.Value{ .float = summary.overall_health_score });
        try summary_obj.put("uptime_ms", json.Value{ .integer = summary.uptime_ms });
        try root.put("summary", json.Value{ .object = summary_obj });

        // Individual connections
        var connections_array = json.Array.init(self.allocator);
        var connections_iter = self.connections.valueIterator();
        while (connections_iter.next()) |conn| {
            var conn_obj = json.ObjectMap.init(self.allocator);
            try conn_obj.put("connection_id", json.Value{ .string = conn.connection_id });
            try conn_obj.put("host", json.Value{ .string = conn.host });
            try conn_obj.put("port", json.Value{ .integer = conn.port });
            try conn_obj.put("protocol", json.Value{ .string = @tagName(conn.protocol) });
            try conn_obj.put("status", json.Value{ .string = @tagName(conn.status) });
            try conn_obj.put("last_check_time", json.Value{ .integer = conn.last_check_time });
            try conn_obj.put("response_time_ms", json.Value{ .float = conn.response_time_ms });
            try conn_obj.put("success_rate", json.Value{ .float = conn.success_rate });
            try conn_obj.put("error_count", json.Value{ .integer = conn.error_count });
            try conn_obj.put("consecutive_failures", json.Value{ .integer = conn.consecutive_failures });
            try conn_obj.put("health_score", json.Value{ .float = conn.health_score });

            connections_array.append(json.Value{ .object = conn_obj });
        }
        try root.put("connections", json.Value{ .array = connections_array });

        // Recent health history
        var history_array = json.Array.init(self.allocator);
        const recent_history = self.health_history.items[@max(0, self.health_history.items.len - 20)..];
        for (recent_history) |entry| {
            var entry_obj = json.ObjectMap.init(self.allocator);
            try entry_obj.put("timestamp", json.Value{ .integer = entry.timestamp });
            try entry_obj.put("connection_id", json.Value{ .string = entry.connection_id });
            try entry_obj.put("previous_status", json.Value{ .string = @tagName(entry.previous_status) });
            try entry_obj.put("new_status", json.Value{ .string = @tagName(entry.new_status) });
            try entry_obj.put("health_score", json.Value{ .float = entry.health_score });
            try entry_obj.put("trigger_event", json.Value{ .string = entry.trigger_event });
            history_array.append(json.Value{ .object = entry_obj });
        }
        try root.put("health_history", json.Value{ .array = history_array });

        return json.stringifyAlloc(self.allocator, json.Value{ .object = root }, .{});
    }

    pub fn exportPrometheusMetrics(self: *Self) ![]const u8 {
        var buffer = std.ArrayList(u8).init(self.allocator);
        const writer = buffer.writer();

        try writer.print("# HELP z-net_connection_health_status Connection health status (0=unknown, 1=healthy, 2=degraded, 3=unhealthy, 4=critical)\n", .{});
        try writer.print("# TYPE z-net_connection_health_status gauge\n", .{});

        var connections_iter = self.connections.valueIterator();
        while (connections_iter.next()) |conn| {
            const status_value = switch (conn.status) {
                .UNKNOWN => 0,
                .HEALTHY => 1,
                .DEGRADED => 2,
                .UNHEALTHY => 3,
                .CRITICAL => 4,
            };
            try writer.print("z-net_connection_health_status{{connection=\"{s}\",host=\"{s}\",port=\"{d}\",protocol=\"{s}\"}} {d}\n",
                .{ conn.connection_id, conn.host, conn.port, @tagName(conn.protocol), status_value });
        }

        try writer.print("# HELP z-net_connection_response_time_ms Connection response time in milliseconds\n", .{});
        try writer.print("# TYPE z-net_connection_response_time_ms gauge\n", .{});

        connections_iter = self.connections.valueIterator();
        while (connections_iter.next()) |conn| {
            try writer.print("z-net_connection_response_time_ms{{connection=\"{s}\"}} {d:.3f}\n",
                .{ conn.connection_id, conn.response_time_ms });
        }

        try writer.print("# HELP z-net_connection_success_rate Connection success rate (0-1)\n", .{});
        try writer.print("# TYPE z-net_connection_success_rate gauge\n", .{});

        connections_iter = self.connections.valueIterator();
        while (connections_iter.next()) |conn| {
            try writer.print("z-net_connection_success_rate{{connection=\"{s}\"}} {d:.3f}\n",
                .{ conn.connection_id, conn.success_rate });
        }

        try writer.print("# HELP z-net_connection_health_score Connection health score (0-100)\n", .{});
        try writer.print("# TYPE z-net_connection_health_score gauge\n", .{});

        connections_iter = self.connections.valueIterator();
        while (connections_iter.next()) |conn| {
            try writer.print("z-net_connection_health_score{{connection=\"{s}\"}} {d:.1f}\n",
                .{ conn.connection_id, conn.health_score });
        }

        return buffer.items;
    }

    fn scheduleHealthCheck(self: *Self, check: *const HealthCheck) !void {
        const schedule = CheckSchedule{
            check_id = check.check_id,
            next_run_time = std.time.Instant.now() catch @panic("Failed to get time"),
            interval_ms = check.interval_ms,
        };
        try self.check_schedules.append(schedule);
    }

    fn checkConnectivity(self: *Self, check: *const HealthCheck) !HealthCheckResult {
        // Placeholder for connectivity check implementation
        // Would implement actual TCP/UDP connectivity testing
        _ = check;
        return HealthCheckResult{
            .check_id = check.check_id,
            .success = true,
            .status = .HEALTHY,
            .response_time_ms = 0.0,
            .error_message = null,
            .diagnostics_data = null,
        };
    }

    fn checkLatency(self: *Self, check: *const HealthCheck) !HealthCheckResult {
        // Placeholder for latency check implementation
        _ = check;
        return HealthCheckResult{
            .check_id = check.check_id,
            .success = true,
            .status = .HEALTHY,
            .response_time_ms = 10.5,
            .error_message = null,
            .diagnostics_data = null,
        };
    }

    fn checkThroughput(self: *Self, check: *const HealthCheck) !HealthCheckResult {
        // Placeholder for throughput check implementation
        _ = check;
        return HealthCheckResult{
            .check_id = check.check_id,
            .success = true,
            .status = .HEALTHY,
            .response_time_ms = 0.0,
            .error_message = null,
            .diagnostics_data = null,
        };
    }

    fn checkErrorRate(self: *Self, check: *const HealthCheck) !HealthCheckResult {
        // Placeholder for error rate check implementation
        _ = check;
        return HealthCheckResult{
            .check_id = check.check_id,
            .success = true,
            .status = .HEALTHY,
            .response_time_ms = 0.0,
            .error_message = null,
            .diagnostics_data = null,
        };
    }

    fn checkDNSResolution(self: *Self, check: *const HealthCheck) !HealthCheckResult {
        // Placeholder for DNS resolution check implementation
        _ = check;
        return HealthCheckResult{
            .check_id = check.check_id,
            .success = true,
            .status = .HEALTHY,
            .response_time_ms = 5.2,
            .error_message = null,
            .diagnostics_data = null,
        };
    }

    fn checkTLSHandshake(self: *Self, check: *const HealthCheck) !HealthCheckResult {
        // Placeholder for TLS handshake check implementation
        _ = check;
        return HealthCheckResult{
            .check_id = check.check_id,
            .success = true,
            .status = .HEALTHY,
            .response_time_ms = 25.1,
            .error_message = null,
            .diagnostics_data = null,
        };
    }

    fn checkHTTPResponse(self: *Self, check: *const HealthCheck) !HealthCheckResult {
        // Placeholder for HTTP response check implementation
        _ = check;
        return HealthCheckResult{
            .check_id = check.check_id,
            .success = true,
            .status = .HEALTHY,
            .response_time_ms = 100.0,
            .error_message = null,
            .diagnostics_data = null,
        };
    }

    fn executeCustomCheck(self: *Self, check: *const HealthCheck) !HealthCheckResult {
        // Placeholder for custom check implementation
        _ = check;
        return HealthCheckResult{
            .check_id = check.check_id,
            .success = true,
            .status = .HEALTHY,
            .response_time_ms = 0.0,
            .error_message = null,
            .diagnostics_data = null,
        };
    }

    fn createFailedResult(self: *Self, check: *const HealthCheck, error_message: []const u8) HealthCheckResult {
        return HealthCheckResult{
            .check_id = check.check_id,
            .success = false,
            .status = .UNHEALTHY,
            .response_time_ms = check.timeout_ms,
            .error_message = error_message,
            .diagnostics_data = null,
        };
    }

    fn updateConnectionHealth(self: *Self, connection: *ConnectionHealth, result: *const HealthCheckResult) !void {
        const previous_status = connection.status;
        
        // Update metrics
        connection.response_time_ms = result.response_time_ms;
        connection.last_check_time = std.time.Instant.now() catch @panic("Failed to get time");
        
        if (result.success) {
            connection.error_count = 0;
            connection.consecutive_failures = 0;
            connection.status = .HEALTHY;
        } else {
            connection.error_count += 1;
            connection.consecutive_failures += 1;
            
            // Determine status based on consecutive failures
            connection.status = if (connection.consecutive_failures >= 5) .CRITICAL
                else if (connection.consecutive_failures >= 3) .UNHEALTHY
                else .DEGRADED;
        }
        
        // Calculate health score (0-100)
        var health_score: f64 = 100.0;
        
        // Penalize for errors
        health_score -= @as(f64, @floatFromInt(connection.error_count)) * 0.1;
        
        // Penalize for high response times
        if (connection.response_time_ms > 1000) health_score -= 20;
        else if (connection.response_time_ms > 500) health_score -= 10;
        else if (connection.response_time_ms > 100) health_score -= 5;
        
        // Status penalties
        switch (connection.status) {
            .HEALTHY => health_score += 0,
            .DEGRADED => health_score -= 20,
            .UNHEALTHY => health_score -= 40,
            .CRITICAL => health_score -= 80,
            .UNKNOWN => health_score -= 10,
        }
        
        connection.health_score = @max(0.0, @min(100.0, health_score));

        // Log status change
        if (previous_status != connection.status) {
            try self.health_history.append(HealthHistoryEntry{
                .timestamp = connection.last_check_time,
                .connection_id = connection.connection_id,
                .previous_status = previous_status,
                .new_status = connection.status,
                .health_score = connection.health_score,
                .trigger_event = if (result.success) "health_check_passed" else "health_check_failed",
            });

            // Send notification for critical status changes
            if (connection.status == .CRITICAL or previous_status == .CRITICAL) {
                const message = try std.fmt.allocPrint(self.allocator,
                    "Connection {s} health status changed from {s} to {s}",
                    .{ connection.connection_id, @tagName(previous_status), @tagName(connection.status) });
                defer self.allocator.free(message);
                
                try self.notification_handler.sendHealthAlert(.CRITICAL, connection.connection_id, message);
            }
        }
    }

    fn logHealthResult(self: *Self, result: *const HealthCheckResult) !void {
        // Placeholder for logging implementation
        _ = result;
    }

    fn createEmptyDiagnostics(self: *Self) !Diagnostics {
        return Diagnostics{
            .last_error = null,
            .error_code = null,
            .network_interface = null,
            .dns_servers = &[_][]const u8{},
            .routing_info = null,
            .connection_pool_status = ConnectionPoolStatus{
                .active_connections = 0,
                .idle_connections = 0,
                .max_connections = 0,
                .connection_timeout_rate = 0.0,
                .pool_health_score = 0.0,
            },
            .resource_usage = ResourceUsage{
                .memory_usage_mb = 0.0,
                .cpu_usage_percent = 0.0,
                .network_io_bytes_per_sec = 0,
                .file_descriptor_count = 0,
            },
        };
    }

    fn freeConnectionHealth(self: *Self, health: *ConnectionHealth) void {
        self.allocator.free(health.connection_id);
        self.allocator.free(health.host);
        if (health.diagnostics.last_error) |error| {
            self.allocator.free(error);
        }
        if (health.diagnostics.network_interface) |interface| {
            self.allocator.free(interface);
        }
        for (health.diagnostics.dns_servers) |server| {
            self.allocator.free(server);
        }
        self.allocator.free(health.diagnostics.dns_servers);
        if (health.diagnostics.routing_info) |info| {
            self.allocator.free(info);
        }
    }

    fn freeHealthCheck(self: *Self, check: *const HealthCheck) void {
        self.allocator.free(check.check_id);
        self.allocator.free(check.name);
        self.allocator.free(check.target);
    }

    fn getUptimeMs(self: *Self) u64 {
        const current_time = std.time.Instant.now() catch return 0;
        return current_time.since(self.start_time);
    }
};

pub const HealthCheckResult = struct {
    check_id: []const u8,
    success: bool,
    status: HealthStatus,
    response_time_ms: f64,
    error_message: ?[]const u8,
    diagnostics_data: ?*anyopaque,
};

pub const HealthSummary = struct {
    total_connections: u32,
    healthy_connections: u32,
    degraded_connections: u32,
    unhealthy_connections: u32,
    critical_connections: u32,
    unknown_connections: u32,
    overall_health_score: f64,
    uptime_ms: u64,
};

pub const CheckSchedule = struct {
    check_id: []const u8,
    next_run_time: std.time.Instant,
    interval_ms: u64,
};

pub const HealthHistoryEntry = struct {
    timestamp: u64,
    connection_id: []const u8,
    previous_status: HealthStatus,
    new_status: HealthStatus,
    health_score: f64,
    trigger_event: []const u8,
};

pub const DiagnosticsEngine = struct {
    pub fn runDiagnostics(self: *DiagnosticsEngine, connection_id: []const u8) !DiagnosticsResult {
        _ = self;
        _ = connection_id;
        // Placeholder for diagnostics implementation
        return DiagnosticsResult{
            .connection_id = connection_id,
            .success = true,
            .diagnostic_data = "No diagnostics data available",
        };
    }
};

pub const DiagnosticsResult = struct {
    connection_id: []const u8,
    success: bool,
    diagnostic_data: []const u8,
};

pub const HealthNotificationHandler = struct {
    pub fn sendHealthAlert(self: *HealthNotificationHandler, severity: HealthStatus, connection_id: []const u8, message: []const u8) !void {
        _ = self;
        _ = severity;
        _ = connection_id;
        _ = message;
        // Placeholder for notification implementation
    }
};