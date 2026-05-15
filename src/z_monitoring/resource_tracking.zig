const std = @import("std");
const json = std.json;
const builtin = @import("builtin");
const posix = std.posix;

pub const ResourceMetrics = struct {
    timestamp: u64,
    memory_usage: MemoryUsage,
    cpu_usage: CPUUsage,
    network_usage: NetworkUsage,
    disk_usage: DiskUsage,
    file_descriptors: FileDescriptorUsage,
    thread_usage: ThreadUsage,
};

pub const MemoryUsage = struct {
    total_bytes: u64,
    used_bytes: u64,
    available_bytes: u64,
    usage_percent: f64,
    heap_allocated: u64,
    heap_freed: u64,
    gc_collections: u32,
    memory_leak_detected: bool,
};

pub const CPUUsage = struct {
    user_time_ms: u64,
    system_time_ms: u64,
    idle_time_ms: u64,
    usage_percent: f64,
    load_average_1min: f64,
    load_average_5min: f64,
    load_average_15min: f64,
    context_switches: u64,
    interrupts: u64,
};

pub const NetworkUsage = struct {
    bytes_sent: u64,
    bytes_received: u64,
    packets_sent: u64,
    packets_received: u64,
    packets_dropped: u64,
    errors_total: u64,
    bandwidth_utilization_percent: f64,
    connections_active: u32,
    connections_listening: u32,
};

pub const DiskUsage = struct {
    total_bytes: u64,
    used_bytes: u64,
    available_bytes: u64,
    usage_percent: f64,
    read_bytes_per_sec: u64,
    write_bytes_per_sec: u64,
    read_operations_per_sec: u64,
    write_operations_per_sec: u64,
    io_utilization_percent: f64,
};

pub const FileDescriptorUsage = struct {
    current_count: u32,
    max_count: u32,
    usage_percent: f64,
    allocation_rate_per_min: f64,
    leak_detected: bool,
    per_process_usage: std.StringHashMap(u32),
};

pub const ThreadUsage = struct {
    current_count: u32,
    peak_count: u32,
    usage_percent: f64,
    context_switches_per_sec: f64,
    cpu_affinity_mask: u64,
};

pub const OptimizationSuggestion = struct {
    suggestion_id: []const u8,
    category: OptimizationCategory,
    priority: OptimizationPriority,
    title: []const u8,
    description: []const u8,
    expected_impact: ExpectedImpact,
    implementation_effort: ImplementationEffort,
    metrics_before: ?ResourceMetrics,
    metrics_after: ?ResourceMetrics,
};

pub const OptimizationCategory = enum {
    MEMORY_OPTIMIZATION,
    CPU_OPTIMIZATION,
    NETWORK_OPTIMIZATION,
    DISK_OPTIMIZATION,
    FILE_DESCRIPTOR_OPTIMIZATION,
    THREAD_OPTIMIZATION,
    ALGORITHM_OPTIMIZATION,
};

pub const OptimizationPriority = enum {
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL,
};

pub const ExpectedImpact = struct {
    memory_savings_percent: ?f64,
    cpu_usage_reduction_percent: ?f64,
    throughput_improvement_percent: ?f64,
    latency_reduction_percent: ?f64,
};

pub const ImplementationEffort = enum {
    MINOR,
    MODERATE,
    MAJOR,
    EXTENSIVE,
};

pub const ResourceTracker = struct {
    allocator: std.mem.Allocator,
    metrics_history: std.ArrayList(ResourceMetrics),
    current_metrics: ResourceMetrics,
    tracking_enabled: bool,
    collection_interval_ms: u64,
    history_retention_count: u64 = 1000,
    alerts_enabled: bool,
    optimization_engine: *OptimizationEngine,
    performance_profiler: *PerformanceProfiler,
    start_time: u64,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, optimization_engine: *OptimizationEngine, performance_profiler: *PerformanceProfiler) Self {
        return Self{
            .allocator = allocator,
            .metrics_history = std.ArrayList(ResourceMetrics).init(allocator),
            .current_metrics = ResourceMetrics{
                .timestamp = @intCast(u64, std.time.milliTimestamp()),
                .memory_usage = MemoryUsage{
                    .total_bytes = 0,
                    .used_bytes = 0,
                    .available_bytes = 0,
                    .usage_percent = 0.0,
                    .heap_allocated = 0,
                    .heap_freed = 0,
                    .gc_collections = 0,
                    .memory_leak_detected = false,
                },
                .cpu_usage = CPUUsage{
                    .user_time_ms = 0,
                    .system_time_ms = 0,
                    .idle_time_ms = 0,
                    .usage_percent = 0.0,
                    .load_average_1min = 0.0,
                    .load_average_5min = 0.0,
                    .load_average_15min = 0.0,
                    .context_switches = 0,
                    .interrupts = 0,
                },
                .network_usage = NetworkUsage{
                    .bytes_sent = 0,
                    .bytes_received = 0,
                    .packets_sent = 0,
                    .packets_received = 0,
                    .packets_dropped = 0,
                    .errors_total = 0,
                    .bandwidth_utilization_percent = 0.0,
                    .connections_active = 0,
                    .connections_listening = 0,
                },
                .disk_usage = DiskUsage{
                    .total_bytes = 0,
                    .used_bytes = 0,
                    .available_bytes = 0,
                    .usage_percent = 0.0,
                    .read_bytes_per_sec = 0,
                    .write_bytes_per_sec = 0,
                    .read_operations_per_sec = 0,
                    .write_operations_per_sec = 0,
                    .io_utilization_percent = 0.0,
                },
                .file_descriptors = FileDescriptorUsage{
                    .current_count = 0,
                    .max_count = 1024, // Default limit
                    .usage_percent = 0.0,
                    .allocation_rate_per_min = 0.0,
                    .leak_detected = false,
                    .per_process_usage = std.StringHashMap(u32).init(allocator),
                },
                .thread_usage = ThreadUsage{
                    .current_count = 0,
                    .peak_count = 0,
                    .usage_percent = 0.0,
                    .context_switches_per_sec = 0.0,
                    .cpu_affinity_mask = 0,
                },
            },
            .tracking_enabled = false,
            .collection_interval_ms = 5000, // 5 seconds
            .history_retention_count = 1000,
            .alerts_enabled = true,
            .optimization_engine = optimization_engine,
            .performance_profiler = performance_profiler,
            .start_time = @intCast(u64, std.time.milliTimestamp()),
        };
    }

    pub fn deinit(self: *Self) void {
        self.metrics_history.deinit();
        self.current_metrics.file_descriptors.per_process_usage.deinit();
    }

    pub fn startTracking(self: *Self) !void {
        self.tracking_enabled = true;
        
        // Collect initial metrics
        try self.collectSystemMetrics();
        
        // Start periodic collection
        const collection_thread = try std.Thread.spawn(.{}, Self.collectionLoop, .{self});
        collection_thread.detach();
    }

    pub fn stopTracking(self: *Self) void {
        self.tracking_enabled = false;
    }

    pub fn collectSystemMetrics(self: *Self) !void {
        self.current_metrics.timestamp = @intCast(u64, std.time.milliTimestamp());
        
        // One API, 3 fast code paths with zero runtime cost
        switch (builtin.os.tag) {
            .linux => try self.collectLinuxMetrics(),
            .macos, .freebsd, .openbsd, .netbsd, .dragonfly => try self.collectBsdMetrics(),
            .windows => try self.collectWindowsMetrics(),
            else => return error.UnsupportedOS,
        }
        
        // Add to history
        try self.metrics_history.append(self.current_metrics);
        
        // Maintain history size limit
        if (self.metrics_history.items.len > self.history_retention_count) {
            const excess = self.metrics_history.items.len - self.history_retention_count;
            for (0..excess) |_| {
                _ = self.metrics_history.orderedRemove(0);
            }
        }
        
        // Check for alerts and optimization opportunities
        if (self.alerts_enabled) {
            try self.checkResourceAlerts();
        }
        
        try self.optimization_engine.analyzeMetrics(self.current_metrics);
    }

    fn collectLinuxMetrics(self: *Self) !void {
        self.current_metrics.network_usage.bytes_received = try getRxBytesLinux("eth0");
        // Other metrics collection...
    }

    fn collectBsdMetrics(self: *Self) !void {
        self.current_metrics.network_usage.bytes_received = try getRxBytesBsd(self.allocator, "en0");
    }

    fn collectWindowsMetrics(self: *Self) !void {
        self.current_metrics.network_usage.bytes_received = try getRxBytesWindows("Ethernet");
    }

    fn collectionLoop(self: *Self) void {
        while (self.tracking_enabled) {
            self.collectSystemMetrics() catch {
                std.debug.print("Error collecting resource metrics\n", .{});
            };
            std.time.sleep(self.collection_interval_ms * std.time.ns_per_ms);
        }
    }

    // Helper functions for various metrics
    fn countActiveConnections(self: *Self) u32 { _ = self; return 0; }
    fn countListeningConnections(self: *Self) u32 { _ = self; return 0; }
    fn getHeapAllocated(self: *Self) u64 { _ = self; return 0; }
    fn getHeapFreed(self: *Self) u64 { _ = self; return 0; }
    fn getGCCollections(self: *Self) u32 { _ = self; return 0; }
    fn checkResourceAlerts(self: *Self) !void { _ = self; }
    fn detectMemoryLeak(self: *Self) ?ResourceLeak { _ = self; return null; }
    fn detectFileDescriptorLeak(self: *Self) ?ResourceLeak { _ = self; return null; }
    fn detectThreadLeak(self: *Self) ?ResourceLeak { _ = self; return null; }
};

// --- OS-Agnostic Implementation Templates (The Zig Method) ---

/// Public API: looks the same on every OS
pub fn getRxBytes(allocator: std.mem.Allocator, ifname: []const u8) !u64 {
    return switch (builtin.os.tag) {
       .linux => try getRxBytesLinux(ifname),
       .macos,.freebsd,.openbsd,.netbsd => try getRxBytesBsd(allocator, ifname),
       .windows => try getRxBytesWindows(ifname),
        else => error.UnsupportedOs,
    };
}

fn getRxBytesLinux(ifname: []const u8) !u64 {
    var path: [64]u8 = undefined;
    const full = try std.fmt.bufPrint(&path, "/sys/class/net/{s}/statistics/rx_bytes",.{ifname});

    const fd = try std.posix.open(full, .{ .ACCMODE = .RDONLY }, 0);
    defer std.posix.close(fd);

    var buf: [24]u8 = undefined;
    const n = try std.posix.read(fd, &buf);

    var val: u64 = 0;
    for (buf[0..n]) |b| {
        if (b == '\n') break;
        if (b >= '0' and b <= '9') {
            val = val * 10 + (b - '0');
        }
    }
    return val;
}

fn getRxBytesBsd(allocator: std.mem.Allocator, ifname: []const u8) !u64 {
    const c = @cImport({
        @cInclude("sys/sysctl.h");
        @cInclude("net/if.h");
        @cInclude("net/route.h");
    });

    var mib = [_]c_int{ c.CTL_NET, c.PF_ROUTE, 0, 0, c.NET_RT_IFLIST2, 0 };
    var len: usize = 0;

    if (c.sysctl(&mib, 6, null, &len, null, 0) != 0) return error.SysctlFailed;

    const buf = try allocator.alloc(u8, len);
    defer allocator.free(buf);

    if (c.sysctl(&mib, 6, buf.ptr, &len, null, 0) != 0) return error.SysctlFailed;

    var pos: usize = 0;
    while (pos < len) {
        const ifm: *align(1) const c.if_msghdr2 = @ptrCast(&buf[pos]);
        if (ifm.ifm_type == c.RTM_IFINFO2) {
            const name_start = pos + @sizeOf(c.if_msghdr2);
            const name = buf[name_start.. name_start + ifm.ifm_data.ifi_namelen - 1];
            if (std.mem.eql(u8, name, ifname)) {
                return ifm.ifm_data.ifi_ibytes;
            }
        }
        pos += ifm.ifm_msglen;
    }
    return error.InterfaceNotFound;
}

fn getRxBytesWindows(ifname: []const u8) !u64 {
    const c = @cImport({
        @cInclude("windows.h");
        @cInclude("iphlpapi.h");
    });

    var table: ?*c.MIB_IF_TABLE2 = null;
    if (c.GetIfTable2(&table) != c.NO_ERROR) return error.WinApiFailed;
    defer if (table) |t| c.FreeMibTable(t);

    const t = table.?;
    for (0..t.NumEntries) |i| {
        const row = t.Table[i];
        // For brevity: assuming the first interface or matching logic here
        _ = ifname;
        return row.InOctets;
    }
    return error.InterfaceNotFound;
}

// ... Rest of the types (ResourceAlert, OptimizationEngine, etc.) same as before ...
pub const ResourceAlert = struct {
    severity: AlertSeverity,
    resource_type: []const u8,
    message: []const u8,
    current_value: f64,
    threshold_value: f64,
    timestamp: u64,
};

pub const AlertSeverity = enum {
    INFO,
    WARNING,
    CRITICAL,
};

pub const OptimizationEngine = struct {
    pub fn analyzeMetrics(self: *OptimizationEngine, metrics: ResourceMetrics) !void {
        _ = self; _ = metrics;
    }
    pub fn generateSuggestions(self: *OptimizationEngine) std.ArrayList(OptimizationSuggestion) {
        _ = self; return std.ArrayList(OptimizationSuggestion).init(std.heap.page_allocator);
    }
};

pub const PerformanceProfiler = struct {
    pub fn profileOperation(self: *PerformanceProfiler, operation_name: []const u8, operation: fn() anyerror!void) !PerformanceProfileResult {
        _ = self; _ = operation_name; _ = operation;
        return PerformanceProfileResult{ .operation_name = "", .duration_ns = 0, .memory_allocated = 0, .cpu_cycles = 0, .success = false };
    }
};

pub const PerformanceProfileResult = struct {
    operation_name: []const u8,
    duration_ns: u64,
    memory_allocated: u64,
    cpu_cycles: u64,
    success: bool,
};
