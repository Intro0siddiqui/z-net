const std = @import("std");
const json = std.json;

pub const PerformanceBudget = struct {
    name: []const u8,
    metric_type: BudgetMetricType,
    threshold_value: f64,
    comparison_operator: ComparisonOperator,
    time_window_ms: u64,
    violation_count: u32,
    last_violation_time: ?u64,
    alert_config: AlertConfiguration,
    is_active: bool,
    description: []const u8,
};

pub const BudgetMetricType = enum {
    LATENCY_AVG,
    LATENCY_P95,
    LATENCY_P99,
    THROUGHPUT_MIN,
    THROUGHPUT_AVG,
    ERROR_RATE_MAX,
    CONNECTION_SUCCESS_RATE_MIN,
    DNS_LOOKUP_TIME_MAX,
    TCP_CONNECT_TIME_MAX,
    TLS_HANDSHAKE_TIME_MAX,
    HTTP_REQUEST_TIME_MAX,
    MEMORY_USAGE_MAX,
    CPU_USAGE_MAX,
};

pub const ComparisonOperator = enum {
    LESS_THAN,
    LESS_THAN_EQUAL,
    GREATER_THAN,
    GREATER_THAN_EQUAL,
    EQUAL,
};

pub const AlertConfiguration = struct {
    enabled: bool,
    severity: AlertSeverity,
    notification_channels: []const []const u8,
    cooldown_period_ms: u64,
    escalation_rules: []EscalationRule,
};

pub const AlertSeverity = enum {
    INFO,
    WARNING,
    CRITICAL,
    EMERGENCY,
};

pub const EscalationRule = struct {
    delay_ms: u64,
    escalation_level: AlertSeverity,
    notification_targets: []const []const u8,
};

pub const BudgetViolation = struct {
    timestamp: u64,
    budget_name: []const u8,
    metric_value: f64,
    threshold_value: f64,
    violation_details: []const u8,
    alert_sent: bool,
};

pub const BudgetManager = struct {
    allocator: std.mem.Allocator,
    budgets: std.StringHashMap(PerformanceBudget),
    violations: std.ArrayList(BudgetViolation),
    metric_collector: *MetricCollector,
    alert_handler: *AlertHandler,
    violation_tracker: ViolationTracker,
    budget_history: std.ArrayList(BudgetHistoryEntry),

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, metric_collector: *MetricCollector, alert_handler: *AlertHandler) Self {
        return Self{
            .allocator = allocator,
            .budgets = std.StringHashMap(PerformanceBudget).init(allocator),
            .violations = std.ArrayList(BudgetViolation).init(allocator),
            .metric_collector = metric_collector,
            .alert_handler = alert_handler,
            .violation_tracker = ViolationTracker.init(allocator),
            .budget_history = std.ArrayList(BudgetHistoryEntry).init(allocator),
        };
    }

    pub fn deinit(self: *Self) void {
        var budgets_iter = self.budgets.valueIterator();
        while (budgets_iter.next()) |budget| {
            self.allocator.free(budget.description);
            self.allocator.free(budget.alert_config.notification_channels);
            for (budget.alert_config.escalation_rules) |rule| {
                self.allocator.free(rule.notification_targets);
            }
        }
        self.budgets.deinit();
        self.violations.deinit();
        self.violation_tracker.deinit();
        self.budget_history.deinit();
    }

    pub fn addBudget(self: *Self, budget: PerformanceBudget) !void {
        // Make copies of string slices for storage
        const name_copy = try self.allocator.dupe(u8, budget.name);
        const desc_copy = try self.allocator.dupe(u8, budget.description);
        const notification_channels_copy = try self.allocator.alloc([]const u8, budget.alert_config.notification_channels.len);
        for (budget.alert_config.notification_channels, 0..) |channel, i| {
            notification_channels_copy[i] = try self.allocator.dupe(u8, channel);
        }

        var escalation_rules_copy = try self.allocator.alloc(EscalationRule, budget.alert_config.escalation_rules.len);
        for (budget.alert_config.escalation_rules, 0..) |rule, i| {
            const targets_copy = try self.allocator.alloc([]const u8, rule.notification_targets.len);
            for (rule.notification_targets, 0..) |target, j| {
                targets_copy[j] = try self.allocator.dupe(u8, target);
            }
            escalation_rules_copy[i] = EscalationRule{
                .delay_ms = rule.delay_ms,
                .escalation_level = rule.escalation_level,
                .notification_targets = targets_copy,
            };
        }

        const stored_budget = PerformanceBudget{
            .name = name_copy,
            .metric_type = budget.metric_type,
            .threshold_value = budget.threshold_value,
            .comparison_operator = budget.comparison_operator,
            .time_window_ms = budget.time_window_ms,
            .violation_count = 0,
            .last_violation_time = null,
            .alert_config = AlertConfiguration{
                .enabled = budget.alert_config.enabled,
                .severity = budget.alert_config.severity,
                .notification_channels = notification_channels_copy,
                .cooldown_period_ms = budget.alert_config.cooldown_period_ms,
                .escalation_rules = escalation_rules_copy,
            },
            .is_active = budget.is_active,
            .description = desc_copy,
        };

        try self.budgets.put(name_copy, stored_budget);
    }

    pub fn removeBudget(self: *Self, budget_name: []const u8) !void {
        if (self.budgets.remove(budget_name)) |kv| {
            // Free allocated memory
            self.allocator.free(kv.value.name);
            self.allocator.free(kv.value.description);
            for (kv.value.alert_config.notification_channels) |channel| {
                self.allocator.free(channel);
            }
            self.allocator.free(kv.value.alert_config.notification_channels);
            for (kv.value.alert_config.escalation_rules) |rule| {
                for (rule.notification_targets) |target| {
                    self.allocator.free(target);
                }
                self.allocator.free(rule.notification_targets);
            }
            self.allocator.free(kv.value.alert_config.escalation_rules);
        }
    }

    pub fn checkBudgets(self: *Self) !void {
        var budgets_iter = self.budgets.valueIterator();
        while (budgets_iter.next()) |budget| {
            if (!budget.is_active) continue;

            const current_value = try self.getCurrentMetricValue(budget.metric_type);
            if (self.evaluateBudget(budget, current_value)) {
                try self.handleBudgetViolation(budget, current_value);
            }
        }
    }

    pub fn evaluateBudget(self: *Self, budget: *const PerformanceBudget, current_value: f64) bool {
        return switch (budget.comparison_operator) {
            .LESS_THAN => current_value < budget.threshold_value,
            .LESS_THAN_EQUAL => current_value <= budget.threshold_value,
            .GREATER_THAN => current_value > budget.threshold_value,
            .GREATER_THAN_EQUAL => current_value >= budget.threshold_value,
            .EQUAL => @abs(current_value - budget.threshold_value) < 0.001,
        };
    }

    pub fn handleBudgetViolation(self: *Self, budget: *const PerformanceBudget, metric_value: f64) !void {
        const now = std.time.Instant.now() catch @panic("Failed to get current time");
        const current_time = now.nanos;

        // Check cooldown period
        if (budget.last_violation_time) |last_violation| {
            const time_since_last = current_time - last_violation;
            if (time_since_last < budget.alert_config.cooldown_period_ms * 1_000_000) {
                return; // Still in cooldown period
            }
        }

        // Record violation
        const violation_details = try std.fmt.allocPrint(self.allocator, 
            "Metric value {d:.3f} {s} threshold {d:.3f}", 
            .{ metric_value, @tagName(budget.comparison_operator), budget.threshold_value });
        defer self.allocator.free(violation_details);

        const violation = BudgetViolation{
            .timestamp = current_time,
            .budget_name = budget.name,
            .metric_value = metric_value,
            .threshold_value = budget.threshold_value,
            .violation_details = violation_details,
            .alert_sent = false,
        };

        try self.violations.append(violation);

        // Send alert if enabled
        if (budget.alert_config.enabled) {
            try self.sendBudgetAlert(budget, violation);
        }

        // Update violation tracking
        try self.violation_tracker.recordViolation(budget.name, current_time);

        // Update budget
        var budget_copy = self.budgets.getPtr(budget.name) orelse return;
        budget_copy.violation_count += 1;
        budget_copy.last_violation_time = current_time;

        // Add to history
        try self.budget_history.append(BudgetHistoryEntry{
            .timestamp = current_time,
            .budget_name = budget.name,
            .event_type = .VIOLATION,
            .metric_value = metric_value,
            .threshold_value = budget.threshold_value,
        });
    }

    pub fn sendBudgetAlert(self: *Self, budget: *const PerformanceBudget, violation: BudgetViolation) !void {
        const alert_message = try std.fmt.allocPrint(self.allocator,
            "Performance Budget Violation: {s}\nMetric: {d:.3f} (Threshold: {d:.3f})\nDescription: {s}\nTime: {s}",
            .{
                budget.name,
                violation.metric_value,
                violation.threshold_value,
                budget.description,
                self.formatTimestamp(violation.timestamp),
            });
        defer self.allocator.free(alert_message);

        // Send to primary notification channels
        for (budget.alert_config.notification_channels) |channel| {
            try self.alert_handler.sendAlert(budget.alert_config.severity, channel, alert_message);
        }

        // Handle escalation rules
        try self.handleEscalationRules(budget, violation);
    }

    pub fn handleEscalationRules(self: *Self, budget: *const PerformanceBudget, violation: BudgetViolation) !void {
        const current_time = std.time.Instant.now() catch return;
        const elapsed_time = current_time.nanos - violation.timestamp;

        for (budget.alert_config.escalation_rules) |rule| {
            if (elapsed_time >= rule.delay_ms * 1_000_000) {
                const escalation_message = try std.fsmt.allocPrint(self.allocator,
                    "ESCALATION: Performance Budget Violation: {s}\nEscalation Level: {s}\nOriginal Message: {s}",
                    .{ budget.name, @tagName(rule.escalation_level), violation.violation_details });
                defer self.allocator.free(escalation_message);

                for (rule.notification_targets) |target| {
                    try self.alert_handler.sendAlert(rule.escalation_level, target, escalation_message);
                }
            }
        }
    }

    pub fn getCurrentMetricValue(self: *Self, metric_type: BudgetMetricType) !f64 {
        return switch (metric_type) {
            .LATENCY_AVG => self.metric_collector.getAverageLatency(),
            .LATENCY_P95 => self.metric_collector.getPercentileLatency(95),
            .LATENCY_P99 => self.metric_collector.getPercentileLatency(99),
            .THROUGHPUT_MIN => self.metric_collector.getMinimumThroughput(),
            .THROUGHPUT_AVG => self.metric_collector.getAverageThroughput(),
            .ERROR_RATE_MAX => self.metric_collector.getErrorRate(),
            .CONNECTION_SUCCESS_RATE_MIN => self.metric_collector.getConnectionSuccessRate(),
            .DNS_LOOKUP_TIME_MAX => self.metric_collector.getAverageDNSLatency(),
            .TCP_CONNECT_TIME_MAX => self.metric_collector.getAverageTCPLatency(),
            .TLS_HANDSHAKE_TIME_MAX => self.metric_collector.getAverageTLSLatency(),
            .HTTP_REQUEST_TIME_MAX => self.metric_collector.getAverageHTTPLatency(),
            .MEMORY_USAGE_MAX => self.metric_collector.getMemoryUsagePercent(),
            .CPU_USAGE_MAX => self.metric_collector.getCPUUsagePercent(),
        };
    }

    pub fn exportBudgetsJSON(self: *Self) ![]const u8 {
        var root = json.ObjectMap.init(self.allocator);

        // Export all budgets
        var budgets_array = json.Array.init(self.allocator);
        var budgets_iter = self.budgets.valueIterator();
        while (budgets_iter.next()) |budget| {
            var budget_obj = json.ObjectMap.init(self.allocator);
            try budget_obj.put("name", json.Value{ .string = budget.name });
            try budget_obj.put("metric_type", json.Value{ .string = @tagName(budget.metric_type) });
            try budget_obj.put("threshold_value", json.Value{ .float = budget.threshold_value });
            try budget_obj.put("comparison_operator", json.Value{ .string = @tagName(budget.comparison_operator) });
            try budget_obj.put("time_window_ms", json.Value{ .integer = budget.time_window_ms });
            try budget_obj.put("violation_count", json.Value{ .integer = budget.violation_count });
            if (budget.last_violation_time) |timestamp| {
                try budget_obj.put("last_violation_time", json.Value{ .integer = timestamp });
            } else {
                try budget_obj.put("last_violation_time", json.Value{ .null = {} });
            }
            try budget_obj.put("is_active", json.Value{ .bool = budget.is_active });
            try budget_obj.put("description", json.Value{ .string = budget.description });

            // Alert configuration
            var alert_obj = json.ObjectMap.init(self.allocator);
            try alert_obj.put("enabled", json.Value{ .bool = budget.alert_config.enabled });
            try alert_obj.put("severity", json.Value{ .string = @tagName(budget.alert_config.severity) });
            
            var channels_array = json.Array.init(self.allocator);
            for (budget.alert_config.notification_channels) |channel| {
                try channels_array.append(json.Value{ .string = channel });
            }
            try alert_obj.put("notification_channels", json.Value{ .array = channels_array });
            
            try alert_obj.put("cooldown_period_ms", json.Value{ .integer = budget.alert_config.cooldown_period_ms });
            try budget_obj.put("alert_config", json.Value{ .object = alert_obj });

            try budgets_array.append(json.Value{ .object = budget_obj });
        }

        try root.put("budgets", json.Value{ .array = budgets_array });

        // Export recent violations
        var violations_array = json.Array.init(self.allocator);
        const recent_violations = self.violations.items[@max(0, self.violations.items.len - 10)..];
        for (recent_violations) |violation| {
            var violation_obj = json.ObjectMap.init(self.allocator);
            try violation_obj.put("timestamp", json.Value{ .integer = violation.timestamp });
            try violation_obj.put("budget_name", json.Value{ .string = violation.budget_name });
            try violation_obj.put("metric_value", json.Value{ .float = violation.metric_value });
            try violation_obj.put("threshold_value", json.Value{ .float = violation.threshold_value });
            try violation_obj.put("violation_details", json.Value{ .string = violation.violation_details });
            try violation_obj.put("alert_sent", json.Value{ .bool = violation.alert_sent });
            try violations_array.append(json.Value{ .object = violation_obj });
        }

        try root.put("recent_violations", json.Value{ .array = violations_array });

        return json.stringifyAlloc(self.allocator, json.Value{ .object = root }, .{});
    }

    pub fn exportPrometheusMetrics(self: *Self) ![]const u8 {
        var buffer = std.ArrayList(u8).init(self.allocator);
        const writer = buffer.writer();

        try writer.print("# HELP zawra_performance_budget_violations Number of budget violations\n", .{});
        try writer.print("# TYPE zawra_performance_budget_violations counter\n", .{});

        var budgets_iter = self.budgets.valueIterator();
        while (budgets_iter.next()) |budget| {
            try writer.print("zawra_performance_budget_violations{{budget=\"{s}\"}} {d}\n", 
                .{ budget.name, budget.violation_count });
        }

        try writer.print("# HELP zawra_performance_budget_active Whether budget is active\n", .{});
        try writer.print("# TYPE zawra_performance_budget_active gauge\n", .{});

        budgets_iter = self.budgets.valueIterator();
        while (budgets_iter.next()) |budget| {
            try writer.print("zawra_performance_budget_active{{budget=\"{s}\"}} {d}\n", 
                .{ budget.name, if (budget.is_active) 1 else 0 });
        }

        try writer.print("# HELP zawra_performance_budget_threshold Budget threshold value\n", .{});
        try writer.print("# TYPE zawra_performance_budget_threshold gauge\n", .{});

        budgets_iter = self.budgets.valueIterator();
        while (budgets_iter.next()) |budget| {
            try writer.print("zawra_performance_budget_threshold{{budget=\"{s}\",metric=\"{s}\"}} {d:.6f}\n", 
                .{ budget.name, @tagName(budget.metric_type), budget.threshold_value });
        }

        return buffer.items;
    }

    fn formatTimestamp(self: *Self, timestamp: u64) []const u8 {
        const seconds = timestamp / 1_000_000_000;
        const nanos = timestamp % 1_000_000_000;
        return std.fmt.allocPrint(self.allocator, "{d}.{09d}", .{ seconds, nanos }) catch return "";
    }
};

pub const MetricCollector = struct {
    pub fn getAverageLatency(self: *MetricCollector) f64 {
        _ = self;
        return 0.0; // Placeholder - would integrate with actual metric collection
    }

    pub fn getPercentileLatency(self: *MetricCollector, percentile: u8) f64 {
        _ = self;
        _ = percentile;
        return 0.0; // Placeholder
    }

    pub fn getMinimumThroughput(self: *MetricCollector) f64 {
        _ = self;
        return 0.0;
    }

    pub fn getAverageThroughput(self: *MetricCollector) f64 {
        _ = self;
        return 0.0;
    }

    pub fn getErrorRate(self: *MetricCollector) f64 {
        _ = self;
        return 0.0;
    }

    pub fn getConnectionSuccessRate(self: *MetricCollector) f64 {
        _ = self;
        return 0.0;
    }

    pub fn getAverageDNSLatency(self: *MetricCollector) f64 {
        _ = self;
        return 0.0;
    }

    pub fn getAverageTCPLatency(self: *MetricCollector) f64 {
        _ = self;
        return 0.0;
    }

    pub fn getAverageTLSLatency(self: *MetricCollector) f64 {
        _ = self;
        return 0.0;
    }

    pub fn getAverageHTTPLatency(self: *MetricCollector) f64 {
        _ = self;
        return 0.0;
    }

    pub fn getMemoryUsagePercent(self: *MetricCollector) f64 {
        _ = self;
        return 0.0;
    }

    pub fn getCPUUsagePercent(self: *MetricCollector) f64 {
        _ = self;
        return 0.0;
    }
};

pub const AlertHandler = struct {
    pub fn sendAlert(self: *AlertHandler, severity: AlertSeverity, target: []const u8, message: []const u8) !void {
        _ = self;
        _ = severity;
        _ = target;
        _ = message;
        // Placeholder - would implement actual alert sending logic
    }
};

pub const ViolationTracker = struct {
    allocator: std.mem.Allocator,
    violation_counts: std.StringHashMap(u32),
    last_violation_times: std.StringHashMap(u64),

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .allocator = allocator,
            .violation_counts = std.StringHashMap(u32).init(allocator),
            .last_violation_times = std.StringHashMap(u64).init(allocator),
        };
    }

    pub fn deinit(self: *Self) void {
        self.violation_counts.deinit();
        self.last_violation_times.deinit();
    }

    pub fn recordViolation(self: *Self, budget_name: []const u8, timestamp: u64) !void {
        const current_count = self.violation_counts.get(budget_name) orelse 0;
        try self.violation_counts.put(budget_name, current_count + 1);
        try self.last_violation_times.put(budget_name, timestamp);
    }
};

pub const BudgetHistoryEntry = struct {
    timestamp: u64,
    budget_name: []const u8,
    event_type: BudgetEventType,
    metric_value: f64,
    threshold_value: f64,
};

pub const BudgetEventType = enum {
    VIOLATION,
    RECOVERY,
    BUDGET_CREATED,
    BUDGET_MODIFIED,
    BUDGET_DELETED,
};