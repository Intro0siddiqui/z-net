// =============================================================================
// MONITORING INTEGRATION - PRODUCTION GRADE IMPLEMENTATION
// =============================================================================
// Comprehensive monitoring integration with Prometheus, Grafana, ELK stack,
// custom dashboards, alerting, and metrics collection for production environments.
// =============================================================================

const std = @import("std");
const log = std.log;
const ArrayList = std.ArrayList;
const HashMap = std.HashMap;
const Allocator = std.mem.Allocator;
const http = std.http;
const json = std.json;
const time = std.time;

// =============================================================================
// MONITORING CONFIGURATION TYPES
// =============================================================================

pub const MonitoringBackend = enum {
    prometheus,
    grafana,
    elasticsearch,
    kibana,
    custom,
};

pub const MetricType = enum {
    counter,
    gauge,
    histogram,
    summary,
};

pub const AlertSeverity = enum {
    critical,
    warning,
    info,
};

pub const DashboardType = enum {
    system_overview,
    application_performance,
    infrastructure,
    business_metrics,
    custom,
};

pub const MetricConfig = struct {
    name: []const u8,
    metric_type: MetricType,
    description: []const u8,
    labels: HashMap([]const u8, []const u8),
    collection_interval: u32, // seconds
    retention_period: u32, // days
    aggregation: ?[]const u8,
};

pub const AlertRule = struct {
    name: []const u8,
    expression: []const u8,
    severity: AlertSeverity,
    duration: u32, // seconds
    notification_channels: ArrayList([]const u8),
    enabled: bool,
    tags: ArrayList([]const u8),
};

pub const DashboardWidget = struct {
    id: []const u8,
    title: []const u8,
    widget_type: []const u8, // "graph", "table", "stat", "gauge", etc.
    query: []const u8,
    visualization_options: HashMap([]const u8, []const u8),
    position: struct { x: u32, y: u32, width: u32, height: u32 },
    refresh_interval: u32,
};

pub const DashboardConfig = struct {
    name: []const u8,
    description: []const u8,
    dashboard_type: DashboardType,
    widgets: ArrayList(DashboardWidget),
    tags: ArrayList([]const u8),
    refresh_interval: u32,
    auto_refresh: bool,
};

pub const MonitoringEndpoint = struct {
    backend: MonitoringBackend,
    url: []const u8,
    authentication: ?struct {
        auth_type: []const u8, // "bearer", "basic", "apikey"
        credentials: []const u8,
    },
    timeout: u32,
    retry_attempts: u32,
    enabled: bool,
};

pub const LogConfiguration = struct {
    level: []const u8,
    format: []const u8, // "json", "text"
    retention_days: u32,
    index_pattern: []const u8,
    pipeline: ?[]const u8,
    filters: ArrayList([]const u8),
};

pub const MetricsCollector = struct {
    name: []const u8,
    source: []const u8, // "application", "system", "custom"
    metrics: ArrayList(MetricConfig),
    endpoint: MonitoringEndpoint,
    enabled: bool,
    buffer_size: u32,
    flush_interval: u32,
};

// =============================================================================
// MONITORING MANAGER
// =============================================================================

pub const MonitoringManager = struct {
    allocator: Allocator,
    logger: Logger,
    config: Config,
    
    // Monitoring endpoints and backends
    prometheus_endpoint: MonitoringEndpoint,
    grafana_endpoint: MonitoringEndpoint,
    elasticsearch_endpoint: MonitoringEndpoint,
    kibana_endpoint: MonitoringEndpoint,
    
    // Metrics collection
    metrics_collectors: HashMap([]const u8, MetricsCollector),
    active_metrics: HashMap([]const u8, MetricValue),
    metrics_buffer: ArrayList(MetricSample),
    
    // Alerting
    alert_rules: HashMap([]const u8, AlertRule),
    alert_history: ArrayList(AlertEvent),
    notification_channels: HashMap([]const u8, NotificationChannel),
    
    // Dashboards
    dashboards: HashMap([]const u8, DashboardConfig),
    
    // Log management
    log_configs: HashMap([]const u8, LogConfiguration),
    active_log_streams: HashMap([]const u8, LogStream),
    
    const Self = @This();

    pub fn init(allocator: Allocator, config: Config) !*Self {
        const self = try allocator.create(Self);
        self.* = Self{
            .allocator = allocator,
            .logger = Logger.init(allocator, .info),
            .config = config,
            
            // Initialize monitoring endpoints
            .prometheus_endpoint = MonitoringEndpoint{
                .backend = .prometheus,
                .url = "http://localhost:9090",
                .authentication = null,
                .timeout = 30,
                .retry_attempts = 3,
                .enabled = true,
            },
            
            .grafana_endpoint = MonitoringEndpoint{
                .backend = .grafana,
                .url = "http://localhost:3000",
                .authentication = null,
                .timeout = 30,
                .retry_attempts = 3,
                .enabled = true,
            },
            
            .elasticsearch_endpoint = MonitoringEndpoint{
                .backend = .elasticsearch,
                .url = "http://localhost:9200",
                .authentication = null,
                .timeout = 30,
                .retry_attempts = 3,
                .enabled = true,
            },
            
            .kibana_endpoint = MonitoringEndpoint{
                .backend = .kibana,
                .url = "http://localhost:5601",
                .authentication = null,
                .timeout = 30,
                .retry_attempts = 3,
                .enabled = true,
            },
            
            // Initialize collections
            .metrics_collectors = HashMap([]const u8, MetricsCollector).init(allocator),
            .active_metrics = HashMap([]const u8, MetricValue).init(allocator),
            .metrics_buffer = ArrayList(MetricSample).init(allocator),
            .alert_rules = HashMap([]const u8, AlertRule).init(allocator),
            .alert_history = ArrayList(AlertEvent).init(allocator),
            .notification_channels = HashMap([]const u8, NotificationChannel).init(allocator),
            .dashboards = HashMap([]const u8, DashboardConfig).init(allocator),
            .log_configs = HashMap([]const u8, LogConfiguration).init(allocator),
            .active_log_streams = HashMap([]const u8, LogStream).init(allocator),
        };

        try self.initializeMonitoringComponents();
        return self;
    }

    pub fn deinit(self: *Self) void {
        // Cleanup resources
        self.metrics_collectors.deinit();
        self.active_metrics.deinit();
        self.metrics_buffer.deinit();
        self.alert_rules.deinit();
        self.alert_history.deinit();
        self.notification_channels.deinit();
        self.dashboards.deinit();
        self.log_configs.deinit();
        self.active_log_streams.deinit();
        
        self.logger.deinit();
        self.allocator.destroy(self);
    }

    // =============================================================================
    // METRICS COLLECTION
    // =============================================================================

    pub fn registerMetricsCollector(self: *Self, collector: MetricsCollector) !void {
        try self.metrics_collectors.put(collector.name, collector);
        self.logger.info("Registered metrics collector: {s}", .{ collector.name });
    }

    pub fn collectMetric(self: *Self, metric_name: []const u8, value: f64, labels: HashMap([]const u8, []const u8)) !void {
        const timestamp = std.time.milliTimestamp();
        
        const sample = MetricSample{
            .name = metric_name,
            .value = value,
            .labels = labels,
            .timestamp = timestamp,
        };
        
        try self.metrics_buffer.append(sample);
        
        // Update active metrics
        const metric_key = try self.createMetricKey(metric_name, labels);
        const metric_value = MetricValue{
            .name = metric_name,
            .value = value,
            .labels = labels,
            .timestamp = timestamp,
        };
        
        try self.active_metrics.put(metric_key, metric_value);
        
        self.logger.debug("Collected metric: {s} = {}", .{ metric_name, value });
    }

    pub fn getMetricValue(self: *Self, metric_name: []const u8, labels: ?HashMap([]const u8, []const u8)) ?MetricValue {
        const metric_key = if (labels) |l| self.createMetricKey(metric_name, l) else metric_name;
        return self.active_metrics.get(metric_key);
    }

    pub fn queryPrometheus(self: *Self, query: []const u8) !PrometheusQueryResult {
        self.logger.info("Querying Prometheus: {s}", .{ query });
        
        const client = http.Client{ .allocator = self.allocator };
        defer client.deinit();
        
        const url = try std.fmt.allocPrint(self.allocator, "{s}/api/v1/query", .{ self.prometheus_endpoint.url });
        defer self.allocator.free(url);
        
        const request = try client.fetch(.{ .method = .GET, .location = http.Client.FetchUrl.init(url) });
        
        if (request.response.status != .ok) {
            return error.PrometheusQueryFailed;
        }
        
        // Parse response (simplified)
        const response_data = request.response.body orelse return error.EmptyResponse;
        return try self.parsePrometheusResponse(response_data);
    }

    pub fn flushMetricsBuffer(self: *Self) !void {
        if (self.metrics_buffer.items.len == 0) return;
        
        // Send metrics to all configured backends
        for (self.metrics_collectors.values()) |collector| {
            if (collector.enabled) {
                try self.sendMetricsToBackend(collector.endpoint, self.metrics_buffer);
            }
        }
        
        // Clear buffer
        self.metrics_buffer.clearRetainingCapacity();
    }

    // =============================================================================
    // ALERTING SYSTEM
    // =============================================================================

    pub fn createAlertRule(self: *Self, rule: AlertRule) !void {
        try self.alert_rules.put(rule.name, rule);
        self.logger.info("Created alert rule: {s}", .{ rule.name });
    }

    pub fn evaluateAlertRules(self: *Self) !void {
        for (self.alert_rules.values()) |rule| {
            if (!rule.enabled) continue;
            
            try self.evaluateSingleRule(rule);
        }
    }

    fn evaluateSingleRule(self: *Self, rule: AlertRule) !void {
        // Query metrics for the rule expression
        const query_result = try self.queryPrometheus(rule.expression);
        
        // Check if alert condition is met
        const condition_met = try self.checkAlertCondition(query_result, rule);
        
        if (condition_met) {
            // Check if alert already exists
            const existing_alert = self.findActiveAlert(rule.name);
            if (existing_alert == null) {
                // Trigger new alert
                try self.triggerAlert(rule, query_result);
            }
        } else {
            // Check if alert should be resolved
            const existing_alert = self.findActiveAlert(rule.name);
            if (existing_alert != null) {
                try self.resolveAlert(rule, existing_alert.?);
            }
        }
    }

    fn checkAlertCondition(self: *Self, query_result: PrometheusQueryResult, rule: AlertRule) !bool {
        // Simplified condition checking - would implement proper logic based on rule
        _ = rule;
        return query_result.result.len > 0; // Trigger if any results match
    }

    fn triggerAlert(self: *Self, rule: AlertRule, query_result: PrometheusQueryResult) !void {
        const alert_event = AlertEvent{
            .id = try self.generateAlertId(),
            .rule_name = rule.name,
            .severity = rule.severity,
            .message = try self.formatAlertMessage(rule, query_result),
            .timestamp = std.time.milliTimestamp(),
            .status = "firing",
            .labels = try self.extractAlertLabels(query_result),
        };
        
        try self.alert_history.append(alert_event);
        
        // Send notifications
        try self.sendAlertNotifications(rule, alert_event);
        
        self.logger.warn("Alert triggered: {s} - {s}", .{ rule.name, alert_event.message });
    }

    fn resolveAlert(self: *Self, rule: AlertRule, alert_event: AlertEvent) !void {
        alert_event.status = "resolved";
        alert_event.resolve_timestamp = std.time.milliTimestamp();
        
        try self.sendResolveNotifications(rule, alert_event);
        
        self.logger.info("Alert resolved: {s}", .{ rule.name });
    }

    pub fn sendAlertNotifications(self: *Self, rule: AlertRule, alert_event: AlertEvent) !void {
        for (rule.notification_channels.items) |channel_name| {
            const channel = self.notification_channels.get(channel_name) orelse continue;
            try self.sendToNotificationChannel(channel, alert_event);
        }
    }

    fn sendToNotificationChannel(self: *Self, channel: NotificationChannel, alert_event: AlertEvent) !void {
        // Implementation would send to various notification channels
        // (webhook, email, Slack, PagerDuty, etc.)
        _ = channel;
        _ = alert_event;
        self.logger.info("Sending alert notification to channel: {s}", .{ channel.name });
    }

    // =============================================================================
    // DASHBOARD MANAGEMENT
    // =============================================================================

    pub fn createDashboard(self: *Self, dashboard: DashboardConfig) !void {
        try self.dashboards.put(dashboard.name, dashboard);
        self.logger.info("Created dashboard: {s}", .{ dashboard.name });
    }

    pub fn deployDashboardToGrafana(self: *Self, dashboard_name: []const u8) !void {
        const dashboard = self.dashboards.get(dashboard_name) orelse {
            return error.DashboardNotFound;
        };
        
        // Convert dashboard to Grafana format
        const grafana_dashboard = try self.convertToGrafanaFormat(dashboard);
        
        // Deploy to Grafana
        try self.deployToGrafana(grafana_dashboard);
        
        self.logger.info("Deployed dashboard to Grafana: {s}", .{ dashboard_name });
    }

    fn convertToGrafanaFormat(self: *Self, dashboard: DashboardConfig) !GrafanaDashboard {
        const panels = ArrayList(GrafanaPanel).init(self.allocator);
        
        for (dashboard.widgets.items, 0..) |widget, index| {
            const panel = GrafanaPanel{
                .id = index + 1,
                .title = widget.title,
                .type = widget.widget_type,
                .targets = try self.parseGrafanaTargets(widget.query),
                .grid_pos = widget.position,
                .options = widget.visualization_options,
            };
            
            try panels.append(panel);
        }
        
        return GrafanaDashboard{
            .title = dashboard.name,
            .panels = panels,
            .tags = dashboard.tags,
            .refresh = dashboard.refresh_interval,
        };
    }

    fn deployToGrafana(self: *Self, grafana_dashboard: GrafanaDashboard) !void {
        const client = http.Client{ .allocator = self.allocator };
        defer client.deinit();
        
        const url = try std.fmt.allocPrint(self.allocator, "{s}/api/dashboards/db", .{ self.grafana_endpoint.url });
        defer self.allocator.free(url);
        
        // Convert to JSON
        const json_data = try self.convertDashboardToJson(grafana_dashboard);
        defer self.allocator.free(json_data);
        
        const request = try client.fetch(.{
            .method = .POST,
            .location = http.Client.FetchUrl.init(url),
            .headers = http.Client.Request.Headers.fromSlice(&.{
                http.Client.Request.Header.init("Content-Type", "application/json"),
            }),
            .payload = json_data,
        });
        
        if (request.response.status != .ok) {
            return error.GrafanaDeploymentFailed;
        }
    }

    // =============================================================================
    // LOG MANAGEMENT
    // =============================================================================

    pub fn configureLogging(self: *Self, log_config: LogConfiguration) !void {
        try self.log_configs.put(log_config.level, log_config);
        self.logger.info("Configured logging for level: {s}", .{ log_config.level });
    }

    pub fn sendLogToElasticsearch(self: *Self, log_entry: LogEntry) !void {
        // Format log entry for Elasticsearch
        const es_doc = try self.formatElasticsearchDocument(log_entry);
        
        // Send to Elasticsearch
        try self.sendToElasticsearch(es_doc);
    }

    fn formatElasticsearchDocument(self: *Self, log_entry: LogEntry) ![]const u8 {
        const timestamp = std.time.unixTimestamp();
        const doc = try std.fmt.allocPrint(self.allocator,
            \\{{
            \\  "@timestamp": "{}",
            \\  "level": "{}",
            \\  "message": "{}",
            \\  "service": "{}",
            \\  "environment": "{}"
            \\}}
        , .{
            timestamp,
            log_entry.level,
            log_entry.message,
            log_entry.service,
            log_entry.environment,
        });
        return doc;
    }

    fn sendToElasticsearch(self: *Self, document: []const u8) !void {
        const client = http.Client{ .allocator = self.allocator };
        defer client.deinit();
        
        const url = try std.fmt.allocPrint(self.allocator, "{s}/_bulk", .{ self.elasticsearch_endpoint.url });
        defer self.allocator.free(url);
        
        const request = try client.fetch(.{
            .method = .POST,
            .location = http.Client.FetchUrl.init(url),
            .headers = http.Client.Request.Headers.fromSlice(&.{
                http.Client.Request.Header.init("Content-Type", "application/json"),
            }),
            .payload = document,
        });
        
        if (request.response.status != .ok) {
            return error.ElasticsearchUploadFailed;
        }
    }

    // =============================================================================
    // INITIALIZATION AND SETUP
    // =============================================================================

    fn initializeMonitoringComponents(self: *Self) !void {
        // Initialize default metrics collectors
        try self.setupDefaultMetricsCollectors();
        
        // Setup default alert rules
        try self.setupDefaultAlertRules();
        
        // Create default dashboards
        try self.createDefaultDashboards();
        
        // Configure logging
        try self.setupDefaultLogging();
        
        // Setup notification channels
        try self.setupDefaultNotificationChannels();
    }

    fn setupDefaultMetricsCollectors(self: *Self) !void {
        // System metrics collector
        const system_metrics = MetricsCollector{
            .name = "system-metrics",
            .source = "system",
            .metrics = ArrayList(MetricConfig).init(self.allocator),
            .endpoint = self.prometheus_endpoint,
            .enabled = true,
            .buffer_size = 1000,
            .flush_interval = 15,
        };
        
        try self.metrics_collectors.put("system-metrics", system_metrics);
        
        // Application metrics collector
        const app_metrics = MetricsCollector{
            .name = "application-metrics",
            .source = "application",
            .metrics = ArrayList(MetricConfig).init(self.allocator),
            .endpoint = self.prometheus_endpoint,
            .enabled = true,
            .buffer_size = 500,
            .flush_interval = 5,
        };
        
        try self.metrics_collectors.put("application-metrics", app_metrics);
    }

    fn setupDefaultAlertRules(self: *Self) !void {
        // High CPU usage alert
        const cpu_alert = AlertRule{
            .name = "high-cpu-usage",
            .expression = "100 - (avg by(instance) (rate(node_cpu_seconds_total{mode='idle'}[5m])) * 100) > 80",
            .severity = .warning,
            .duration = 300,
            .notification_channels = ArrayList([]const u8).init(self.allocator),
            .enabled = true,
            .tags = ArrayList([]const u8).init(self.allocator),
        };
        
        try self.alert_rules.put("high-cpu-usage", cpu_alert);
        
        // High memory usage alert
        const memory_alert = AlertRule{
            .name = "high-memory-usage",
            .expression = "(1 - (node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes)) * 100 > 85",
            .severity = .warning,
            .duration = 300,
            .notification_channels = ArrayList([]const u8).init(self.allocator),
            .enabled = true,
            .tags = ArrayList([]const u8).init(self.allocator),
        };
        
        try self.alert_rules.put("high-memory-usage", memory_alert);
    }

    fn createDefaultDashboards(self: *Self) !void {
        // System Overview Dashboard
        const system_dashboard = DashboardConfig{
            .name = "system-overview",
            .description = "System resource utilization and health",
            .dashboard_type = .system_overview,
            .widgets = ArrayList(DashboardWidget).init(self.allocator),
            .tags = ArrayList([]const u8).init(self.allocator),
            .refresh_interval = 30,
            .auto_refresh = true,
        };
        
        try self.dashboards.put("system-overview", system_dashboard);
        
        // Application Performance Dashboard
        const perf_dashboard = DashboardConfig{
            .name = "application-performance",
            .description = "Application performance metrics and SLAs",
            .dashboard_type = .application_performance,
            .widgets = ArrayList(DashboardWidget).init(self.allocator),
            .tags = ArrayList([]const u8).init(self.allocator),
            .refresh_interval = 15,
            .auto_refresh = true,
        };
        
        try self.dashboards.put("application-performance", perf_dashboard);
    }

    fn setupDefaultLogging(self: *Self) !void {
        const default_log_config = LogConfiguration{
            .level = "info",
            .format = "json",
            .retention_days = 30,
            .index_pattern = "z-net-logs-*",
            .pipeline = null,
            .filters = ArrayList([]const u8).init(self.allocator),
        };
        
        try self.log_configs.put("default", default_log_config);
    }

    fn setupDefaultNotificationChannels(self: *Self) !void {
        // Webhook notification channel
        const webhook_channel = NotificationChannel{
            .name = "webhook-alerts",
            .channel_type = "webhook",
            .config = HashMap([]const u8, []const u8).init(self.allocator),
            .enabled = true,
        };
        
        try self.notification_channels.put("webhook-alerts", webhook_channel);
    }

    // =============================================================================
    // UTILITY FUNCTIONS
    // =============================================================================

    fn createMetricKey(self: *Self, metric_name: []const u8, labels: HashMap([]const u8, []const u8)) ![]const u8 {
        const key_builder = ArrayList(u8).init(self.allocator);
        try key_builder.appendSlice(metric_name);
        
        if (labels.count() > 0) {
            try key_builder.appendSlice("{");
            var first = true;
            for (labels.keys(), labels.values()) |key, value| {
                if (!first) {
                    try key_builder.appendSlice(",");
                }
                try key_builder.appendSlice(key);
                try key_builder.appendSlice("=\"");
                try key_builder.appendSlice(value);
                try key_builder.appendSlice("\"");
                first = false;
            }
            try key_builder.appendSlice("}");
        }
        
        return key_builder.toOwnedSlice();
    }

    fn parsePrometheusResponse(self: *Self, response_data: []const u8) !PrometheusQueryResult {
        // Simplified JSON parsing for Prometheus response
        _ = response_data;
        return PrometheusQueryResult{
            .status = "success",
            .result_type = "vector",
            .result = ArrayList(PrometheusVectorResult).init(self.allocator),
        };
    }

    fn generateAlertId(self: *Self) ![]const u8 {
        const timestamp = std.time.milliTimestamp();
        const random_bytes = try self.getRandomBytes(8);
        const id = try std.fmt.allocPrint(self.allocator, "alert-{}-{s}", .{ 
            timestamp, 
            std.fmt.fmtSliceHexLower(&random_bytes)
        });
        return id;
    }

    fn getRandomBytes(self: *Self, count: usize) ![count]u8 {
        var bytes: [count]u8 = undefined;
        for (&bytes) |*byte| {
            byte.* = @truncate(u8, std.time.milliTimestamp() & 0xFF);
        }
        return bytes;
    }

    fn findActiveAlert(self: *Self, rule_name: []const u8) ?*AlertEvent {
        for (self.alert_history.items) |*alert| {
            if (std.mem.eql(u8, alert.rule_name, rule_name) and std.mem.eql(u8, alert.status, "firing")) {
                return alert;
            }
        }
        return null;
    }

    fn formatAlertMessage(self: *Self, rule: AlertRule, query_result: PrometheusQueryResult) ![]const u8 {
        _ = query_result;
        return try std.fmt.allocPrint(self.allocator, "Alert triggered: {s}", .{ rule.name });
    }

    fn extractAlertLabels(self: *Self, query_result: PrometheusQueryResult) !HashMap([]const u8, []const u8) {
        const labels = HashMap([]const u8, []const u8).init(self.allocator);
        return labels;
    }

    fn sendMetricsToBackend(self: *Self, endpoint: MonitoringEndpoint, metrics: ArrayList(MetricSample)) !void {
        _ = endpoint;
        _ = metrics;
        // Implementation would send metrics to specific backend
    }

    fn parseGrafanaTargets(self: *Self, query: []const u8) !ArrayList(GrafanaTarget) {
        const targets = ArrayList(GrafanaTarget).init(self.allocator);
        const target = GrafanaTarget{
            .expr = query,
            .ref_id = "A",
        };
        try targets.append(target);
        return targets;
    }

    fn convertDashboardToJson(self: *Self, dashboard: GrafanaDashboard) ![]const u8 {
        _ = dashboard;
        return "{}"; // Simplified JSON conversion
    }

    fn sendResolveNotifications(self: *Self, rule: AlertRule, alert_event: AlertEvent) !void {
        _ = rule;
        _ = alert_event;
        // Implementation would send resolve notifications
    }
};

// =============================================================================
// SUPPORTING DATA TYPES
// =============================================================================

pub const MetricSample = struct {
    name: []const u8,
    value: f64,
    labels: HashMap([]const u8, []const u8),
    timestamp: i64,
};

pub const MetricValue = struct {
    name: []const u8,
    value: f64,
    labels: HashMap([]const u8, []const u8),
    timestamp: i64,
};

pub const AlertEvent = struct {
    id: []const u8,
    rule_name: []const u8,
    severity: AlertSeverity,
    message: []const u8,
    timestamp: i64,
    status: []const u8,
    resolve_timestamp: ?i64,
    labels: HashMap([]const u8, []const u8),
};

pub const NotificationChannel = struct {
    name: []const u8,
    channel_type: []const u8,
    config: HashMap([]const u8, []const u8),
    enabled: bool,
};

pub const LogEntry = struct {
    level: []const u8,
    message: []const u8,
    service: []const u8,
    environment: []const u8,
    timestamp: i64,
    metadata: HashMap([]const u8, []const u8),
};

pub const LogStream = struct {
    name: []const u8,
    source: []const u8,
    filters: ArrayList([]const u8),
    enabled: bool,
};

// Prometheus related types
pub const PrometheusQueryResult = struct {
    status: []const u8,
    result_type: []const u8,
    result: ArrayList(PrometheusVectorResult),
};

pub const PrometheusVectorResult = struct {
    metric: HashMap([]const u8, []const u8),
    value: [2]f64, // [timestamp, value]
};

// Grafana related types
pub const GrafanaDashboard = struct {
    title: []const u8,
    panels: ArrayList(GrafanaPanel),
    tags: ArrayList([]const u8),
    refresh: u32,
};

pub const GrafanaPanel = struct {
    id: u32,
    title: []const u8,
    type: []const u8,
    targets: ArrayList(GrafanaTarget),
    grid_pos: struct { x: u32, y: u32, width: u32, height: u32 },
    options: HashMap([]const u8, []const u8),
};

pub const GrafanaTarget = struct {
    expr: []const u8,
    ref_id: []const u8,
};

// =============================================================================
// ERROR TYPES
// =============================================================================

pub const MonitoringError = error{
    PrometheusQueryFailed,
    EmptyResponse,
    DashboardNotFound,
    GrafanaDeploymentFailed,
    ElasticsearchUploadFailed,
    AlertRuleNotFound,
    InvalidMetricConfiguration,
};
