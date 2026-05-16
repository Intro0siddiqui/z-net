/// z-net Advanced Performance Features v1.0
/// Implements connection coalescing, HTTP/2 prioritization, early hints,
/// intelligent retry logic, and performance optimizations for browser-grade networking.

const std = @import("std");
const socket = @import("../z_socket/socket.zig");
const tls = @import("../z_tls/tls.zig");
const http = @import("../z_http/http.zig");
const dns = @import("../z_dns/dns.zig");

/// Connection Pool Entry
pub const PooledConnection = struct {
    id: []const u8,
    domain: []const u8,
    port: u16,
    socket: *socket.Connection,
    tls: ?*tls.Connection,
    last_used: std.time.Instant,
    idle_timeout: std.time.Duration,
    max_requests: u32,
    request_count: u32,
    is_tls: bool,
    protocol_version: []const u8,
    reuse_count: u32,
    error_count: u32,
    last_error: ?[]const u8,
    traffic_class: enum { foreground, background, prefetch } = .foreground,
    
    pub fn init(
        allocator: std.mem.Allocator,
        id: []const u8,
        domain: []const u8,
        port: u16,
        socket_conn: *socket.Connection,
        tls_conn: ?*tls.Connection,
        protocol_version: []const u8,
    ) !*PooledConnection {
        const connection = try allocator.create(PooledConnection);
        
        connection.* = PooledConnection{
            .id = try allocator.dupe(u8, id),
            .domain = try allocator.dupe(u8, domain),
            .port = port,
            .socket = socket_conn,
            .tls = tls_conn,
            .last_used = std.time.Instant.now(),
            .idle_timeout = std.time.Duration.fromMinutes(5), // 5 minutes default
            .max_requests = 100, // Connection pooling limit
            .request_count = 0,
            .is_tls = tls_conn != null,
            .protocol_version = try allocator.dupe(u8, protocol_version),
            .reuse_count = 0,
            .error_count = 0,
            .last_error = null,
        };
        
        return connection;
    }
    
    pub fn canReuse(self: PooledConnection) bool {
        return self.request_count < self.max_requests and
               self.error_count < 3 and
               self.idle_time() < self.idle_timeout;
    }
    
    pub fn idle_time(self: PooledConnection) std.time.Duration {
        return std.time.Instant.now().since(self.last_used);
    }
    
    pub fn markUsed(self: *PooledConnection) void {
        self.last_used = std.time.Instant.now();
        self.request_count += 1;
        self.reuse_count += 1;
    }
    
    pub fn markError(self: *PooledConnection, error: []const u8) void {
        self.error_count += 1;
        self.last_error = error;
    }
    
    pub fn isHealthy(self: PooledConnection) bool {
        return self.error_count < 3;
    }
    
    pub fn shouldClose(self: PooledConnection) bool {
        return !self.canReuse() or
               !self.isHealthy() or
               self.idle_time() > self.idle_timeout;
    }
};

/// HTTP/2 Stream Prioritization
pub const StreamPriority = struct {
    weight: u8,
    parent: ?u32,
    exclusive: bool,
    stream_id: u32,
    group_id: u32,
    estimated_size: u64,
    dependency_depth: u16,
    
    pub fn init(stream_id: u32, weight: u8, parent: ?u32, exclusive: bool) StreamPriority {
        return StreamPriority{
            .weight = weight,
            .parent = parent,
            .exclusive = exclusive,
            .stream_id = stream_id,
            .group_id = 0, // Will be assigned by priority manager
            .estimated_size = 0,
            .dependency_depth = 0,
        };
    }
    
    pub fn computeEffectiveWeight(self: StreamPriority) u8 {
        // Calculate effective weight considering parent dependencies
        var effective_weight = self.weight;
        
        if (self.parent) |parent_id| {
            // Parent reduces child weight proportionally
            const reduction = @divFloor(effective_weight * 10, 100);
            effective_weight = @max(1, effective_weight - reduction);
        }
        
        return effective_weight;
    }
};

/// Priority Tree for HTTP/2 Stream Management
pub const PriorityTree = struct {
    streams: std.HashMap(u32, *StreamPriority, std.hash_map.AutoContext(u32)),
    root_group: u32,
    groups: std.ArrayList(*std.ArrayList(u32)),
    allocator: std.mem.Allocator,
    
    pub fn init(allocator: std.mem.Allocator) PriorityTree {
        const tree = allocator.create(PriorityTree) catch unreachable;
        tree.* = PriorityTree{
            .streams = std.HashMap(u32, *StreamPriority, std.hash_map.AutoContext(u32)).init(allocator),
            .root_group = 0,
            .groups = std.ArrayList(*std.ArrayList(u32)).init(allocator),
            .allocator = allocator,
        };
        
        // Create root group
        const root_group = try std.ArrayList(u32).initCapacity(allocator, 10);
        tree.groups.append(root_group);
        
        return tree.*;
    }
    
    pub fn addStream(self: *PriorityTree, priority: *StreamPriority) !void {
        // Assign group ID
        var group_id = self.groups.items.len;
        
        if (priority.parent) |parent_id| {
            // Create child group under parent
            const child_group = try std.ArrayList(u32).initCapacity(self.allocator, 5);
            self.groups.append(child_group);
            
            // Add to parent's group
            if (self.groups.items.len > parent_id) {
                const parent_group = self.groups.items[parent_id];
                try parent_group.append(group_id);
            }
        }
        
        priority.group_id = group_id;
        
        try self.streams.put(priority.stream_id, priority);
        
        // Add to appropriate group
        try self.groups.items[group_id].append(priority.stream_id);
    }
    
    pub fn removeStream(self: *PriorityTree, stream_id: u32) void {
        if (self.streams.get(stream_id)) |priority| {
            const group_id = priority.group_id;
            if (self.groups.items.len > group_id) {
                const group = self.groups.items[group_id];
                
                // Remove from group's stream list
                for (group.items, 0..) |id, i| {
                    if (id == stream_id) {
                        _ = group.orderedRemove(i);
                        break;
                    }
                }
            }
            
            self.streams.delete(stream_id);
        }
    }
    
    pub fn updatePriority(self: *PriorityTree, stream_id: u32, new_weight: u8, new_parent: ?u32, exclusive: bool) !void {
        const priority = self.streams.get(stream_id) orelse return;
        
        // Remove from current parent
        if (priority.parent) |old_parent| {
            if (self.groups.items.len > priority.group_id) {
                const old_group = self.groups.items[priority.group_id];
                for (old_group.items, 0..) |id, i| {
                    if (id == stream_id) {
                        _ = old_group.orderedRemove(i);
                        break;
                    }
                }
            }
        }
        
        // Update priority settings
        priority.weight = new_weight;
        priority.parent = new_parent;
        priority.exclusive = exclusive;
        
        // Re-add to new parent group
        var group_id = priority.group_id;
        if (new_parent) |parent_id| {
            if (self.groups.items.len > parent_id) {
                const parent_group = self.groups.items[parent_id];
                try parent_group.append(group_id);
            }
        } else {
            // Add to root group
            const root_group = self.groups.items[0];
            try root_group.append(group_id);
        }
    }
    
    pub fn getNextStream(self: *PriorityTree) ?*StreamPriority {
        // Simple round-robin selection with weight consideration
        for (self.groups.items) |group| {
            for (group.items) |stream_id| {
                if (self.streams.get(stream_id)) |priority| {
                    return priority;
                }
            }
        }
        return null;
    }
    
    pub fn computeFairShare(self: *PriorityTree, stream_id: u32) f64 {
        // Calculate fair share of bandwidth for a stream
        const priority = self.streams.get(stream_id) orelse return 1.0;
        const effective_weight = priority.computeEffectiveWeight();
        const total_weight = self.computeTotalWeight(priority.group_id);
        
        if (total_weight == 0) return 1.0;
        
        return @as(f64, @floatFromInt(effective_weight)) / @as(f64, @floatFromInt(total_weight));
    }
    
    fn computeTotalWeight(self: PriorityTree, group_id: u32) u32 {
        if (group_id >= self.groups.items.len) return 0;
        
        const group = self.groups.items[group_id];
        var total_weight: u32 = 0;
        
        for (group.items) |stream_id| {
            if (self.streams.get(stream_id)) |priority| {
                total_weight += priority.computeEffectiveWeight();
            }
        }
        
        return total_weight;
    }
};

/// Connection Coalescing Manager
pub const ConnectionCoalescer = struct {
    pools: std.HashMap([]const u8, *std.ArrayList(*PooledConnection), StringHash),
    dns_cache: *dns.Cache,
    connection_states: std.HashMap([]const u8, ConnectionState, StringHash),
    allocator: std.mem.Allocator,
    
    pub const ConnectionState = enum {
        Active,
        Idle,
        Establishing,
        Failed,
    };
    
    pub fn init(allocator: std.mem.Allocator, dns_cache: *dns.Cache) !ConnectionCoalescer {
        const coalescer = allocator.create(ConnectionCoalescer) catch unreachable;
        coalescer.* = ConnectionCoalescer{
            .pools = std.HashMap([]const u8, *std.ArrayList(*PooledConnection), StringHash).init(allocator),
            .dns_cache = dns_cache,
            .connection_states = std.HashMap([]const u8, ConnectionState, StringHash).init(allocator),
            .allocator = allocator,
        };
        return coalescer.*;
    }
    
    pub fn getOrCreateConnection(self: *ConnectionCoalescer, domain: []const u8, port: u16, protocol: []const u8) !*PooledConnection {
        const pool_key = self.getPoolKey(domain, port);
        
        // Check existing pool
        if (self.pools.get(pool_key)) |pool| {
            // Find healthy connection in pool
            for (pool.items) |connection| {
                if (connection.protocol_version.equal(protocol) and
                    connection.canReuse() and
                    connection.isHealthy()) {
                    connection.markUsed();
                    return connection;
                }
            }
        }
        
        // Create new connection
        return try self.createNewConnection(domain, port, protocol, pool_key);
    }
    
    fn getPoolKey(self: ConnectionCoalescer, domain: []const u8, port: u16) []const u8 {
        // Create unique key for connection pool
        // Format: domain:port:protocol
        var key = std.ArrayList(u8).init(self.allocator);
        defer key.deinit();
        
        key.appendSlice(domain);
        key.append(':');
        
        const port_str = std.fmt.allocPrintZ(self.allocator, "{}", .{port}) catch return domain;
        defer self.allocator.free(port_str);
        key.appendSlice(port_str);
        
        return key.items;
    }
    
    fn createNewConnection(self: *ConnectionCoalescer, domain: []const u8, port: u16, protocol: []const u8, pool_key: []const u8) !*PooledConnection {
        // Resolve domain to IP addresses
        const addresses = try self.dns_cache.resolve(domain);
        if (addresses.items.len == 0) return error.DNSResolutionFailed;
        
        // Use first address (could be improved with failover)
        const address = addresses.items[0];
        
        // Create socket connection
        const socket_conn = try self.socket_manager.connect(address);
        
        // Establish TLS if needed
        var tls_conn: ?*tls.Connection = null;
        if (port == 443) {
            tls_conn = try tls.Connection.init(self.allocator, socket_conn);
            try tls_conn.handshake();
        }
        
        // Create connection ID
        const conn_id = try std.fmt.allocPrintZ(self.allocator, "{s}:{d}:{d}", .{
            domain, port, std.time.milliTimestamp()
        });
        
        // Create pooled connection
        const pooled_conn = try PooledConnection.init(
            self.allocator,
            conn_id,
            domain,
            port,
            socket_conn,
            tls_conn,
            protocol
        );
        
        // Add to pool
        if (!self.pools.contains(pool_key)) {
            const new_pool = try std.ArrayList(*PooledConnection).initCapacity(self.allocator, 10);
            try self.pools.put(pool_key, new_pool);
        }
        
        const pool = self.pools.get(pool_key).?;
        try pool.append(pooled_conn);
        
        return pooled_conn;
    }
    
    pub fn returnConnection(self: *ConnectionCoalescer, connection: *PooledConnection) void {
        if (connection.shouldClose()) {
            // Close and clean up
            connection.socket.close();
            if (connection.tls) |tls_conn| {
                tls_conn.close();
            }
        } else {
            // Keep for reuse
            connection.last_used = std.time.Instant.now();
        }
    }
    
    pub fn cleanupIdleConnections(self: *ConnectionCoalescer) !void {
        const now = std.time.Instant.now();
        
        var it = self.pools.iterator();
        while (it.next()) |entry| {
            const pool = entry.value_ptr.*;
            
            // Remove idle or unhealthy connections
            var i: usize = 0;
            while (i < pool.items.len) {
                const connection = pool.items[i];
                if (connection.shouldClose() or
                    now.since(connection.last_used) > std.time.Duration.fromMinutes(10)) {
                    
                    // Close connection
                    connection.socket.close();
                    if (connection.tls) |tls_conn| {
                        tls_conn.close();
                    }
                    
                    // Remove from pool
                    _ = pool.orderedRemove(i);
                } else {
                    i += 1;
                }
            }
        }
    }
    
    var socket_manager: *socket.Manager,
};

/// Early Hints Manager
pub const EarlyHintsManager = struct {
    hints_cache: std.HashMap([]const u8, *EarlyHint, StringHash),
    pending_requests: std.ArrayList(*EarlyHintRequest),
    allocator: std.mem.Allocator,
    
    pub const EarlyHint = struct {
        hint_type: enum {
            Preconnect,
            DnsPrefetch,
            ResourceHint,
            ImageSrcset,
            ServiceWorker,
        },
        url: []const u8,
        priority: enum { low, medium, high } = .medium,
        attributes: std.HashMap([]const u8, []const u8, StringHash),
        timestamp: std.time.Instant,
        ttl: std.time.Duration,
        
        pub fn init(hint_type: EarlyHint.EHintType, url: []const u8, allocator: std.mem.Allocator) !*EarlyHint {
            const hint = allocator.create(EarlyHint) catch unreachable;
            hint.* = EarlyHint{
                .hint_type = hint_type,
                .url = try allocator.dupe(u8, url),
                .priority = .medium,
                .attributes = std.HashMap([]const u8, []const u8, StringHash).init(allocator),
                .timestamp = std.time.Instant.now(),
                .ttl = std.time.Duration.fromMinutes(5), // 5 minute default TTL
            };
            return hint;
        }
    };
    
    pub const EarlyHintRequest = struct {
        request_id: []const u8,
        main_url: []const u8,
        hints: std.ArrayList(*EarlyHint),
        completed: bool,
        
        pub fn init(request_id: []const u8, main_url: []const u8, allocator: std.mem.Allocator) *EarlyHintRequest {
            const req = allocator.create(EarlyHintRequest) catch unreachable;
            req.* = EarlyHintRequest{
                .request_id = try allocator.dupe(u8, request_id),
                .main_url = try allocator.dupe(u8, main_url),
                .hints = std.ArrayList(*EarlyHint).init(allocator),
                .completed = false,
            };
            return req;
        }
    };
    
    pub fn init(allocator: std.mem.Allocator) EarlyHintsManager {
        return EarlyHintsManager{
            .hints_cache = std.HashMap([]const u8, *EarlyHint, StringHash).init(allocator),
            .pending_requests = std.ArrayList(*EarlyHintRequest).init(allocator),
            .allocator = allocator,
        };
    }
    
    pub fn addEarlyHint(self: *EarlyHintsManager, hint_type: EarlyHint.EHintType, url: []const u8, priority: EarlyHint.EPriority, attributes: std.HashMap([]const u8, []const u8, StringHash)) !*EarlyHint {
        const hint = try EarlyHint.init(hint_type, url, self.allocator);
        hint.priority = priority;
        hint.attributes = attributes;
        
        try self.hints_cache.put(url, hint);
        return hint;
    }
    
    pub fn applyHints(self: *EarlyHintsManager, main_url: []const u8) !std.ArrayList(*EarlyHint) {
        const hints = std.ArrayList(*EarlyHint).init(self.allocator);
        
        // Extract base URL for hint matching
        var base_url = main_url;
        if (std.mem.indexOf(u8, main_url, "/")) |slash_pos| {
            base_url = main_url[0..slash_pos];
        }
        
        // Find relevant hints
        var it = self.hints_cache.iterator();
        while (it.next()) |entry| {
            const hint = entry.value_ptr.*;
            const age = std.time.Instant.now().since(hint.timestamp);
            
            // Skip expired hints
            if (age > hint.ttl) {
                continue;
            }
            
            // Check if hint is relevant
            if (self.hintIsRelevant(hint, main_url, base_url)) {
                try hints.append(hint);
            }
        }
        
        return hints;
    }
    
    fn hintIsRelevant(self: EarlyHintsManager, hint: *EarlyHint, main_url: []const u8, base_url: []const u8) bool {
        switch (hint.hint_type) {
            .DnsPrefetch, .Preconnect => {
                // DNS hints and preconnects apply to same domain
                const hint_domain = getDomainFromUrl(hint.url);
                const main_domain = getDomainFromUrl(main_url);
                return std.mem.eql(u8, hint_domain, main_domain);
            },
            .ResourceHint => {
                // Resource hints apply to same origin or same domain
                return std.mem.startsWith(u8, hint.url, base_url) or
                       getDomainFromUrl(hint.url) == getDomainFromUrl(main_url);
            },
            else => {
                return false;
            },
        }
    }
    
    fn getDomainFromUrl(url: []const u8) []const u8 {
        // Simple domain extraction from URL
        if (std.mem.indexOf(u8, url, "://")) |scheme_end| {
            var domain_start = scheme_end + 3;
            if (std.mem.indexOf(u8, url[domain_start..], "/")) |path_start| {
                return url[domain_start..domain_start + path_start];
            } else {
                return url[domain_start..];
            }
        }
        return url;
    }
};

/// Intelligent Retry Logic
pub const RetryManager = struct {
    policies: std.HashMap([]const u8, *RetryPolicy, StringHash),
    connection_states: std.HashMap([]const u8, ConnectionAttemptState, StringHash),
    allocator: std.mem.Allocator,
    
    pub const RetryPolicy = struct {
        max_attempts: u8 = 3,
        base_delay: std.time.Duration = std.time.Duration.fromMilliseconds(500),
        max_delay: std.time.Duration = std.time.Duration.fromMinutes(5),
        exponential_base: f64 = 2.0,
        jitter_enabled: bool = true,
        retryable_errors: std.ArrayList([]const u8),
        
        pub fn init(allocator: std.mem.Allocator) *RetryPolicy {
            const policy = allocator.create(RetryPolicy) catch unreachable;
            policy.* = RetryPolicy{
                .retryable_errors = std.ArrayList([]const u8).init(allocator),
            };
            
            // Add common retryable errors
            policy.retryable_errors.append("CONNECTION_TIMEOUT") catch {};
            policy.retryable_errors.append("DNS_TIMEOUT") catch {};
            policy.retryable_errors.append("TLS_HANDSHAKE_FAILED") catch {};
            policy.retryable_errors.append("NETWORK_UNREACHABLE") catch {};
            policy.retryable_errors.append("SERVICE_UNAVAILABLE") catch {};
            
            return policy;
        }
    };
    
    pub const ConnectionAttemptState = struct {
        attempts: u8,
        last_attempt: std.time.Instant,
        next_retry_time: std.time.Instant,
        last_error: []const u8,
        backoff_factor: f64,
        
        pub fn init(allocator: std.mem.Allocator) *ConnectionAttemptState {
            const state = allocator.create(ConnectionAttemptState) catch unreachable;
            state.* = ConnectionAttemptState{
                .attempts = 0,
                .last_attempt = std.time.Instant.now(),
                .next_retry_time = std.time.Instant.now(),
                .last_error = "",
                .backoff_factor = 1.0,
            };
            return state;
        }
    };
    
    pub fn init(allocator: std.mem.Allocator) RetryManager {
        return RetryManager{
            .policies = std.HashMap([]const u8, *RetryPolicy, StringHash).init(allocator),
            .connection_states = std.HashMap([]const u8, ConnectionAttemptState, StringHash).init(allocator),
            .allocator = allocator,
        };
    }
    
    pub fn shouldRetry(self: *RetryManager, connection_id: []const u8, error: []const u8) bool {
        const state = self.connection_states.get(connection_id) orelse {
            const new_state = ConnectionAttemptState.init(self.allocator);
            self.connection_states.put(connection_id, new_state) catch {};
            return true; // First attempt
        };
        
        const policy = self.getOrCreatePolicy(connection_id);
        state.attempts += 1;
        state.last_error = error;
        
        // Check if we should retry
        if (state.attempts > policy.max_attempts) {
            return false;
        }
        
        // Check if error is retryable
        var is_retryable = false;
        for (policy.retryable_errors.items) |retryable_error| {
            if (std.mem.indexOf(u8, error, retryable_error)) |pos| {
                is_retryable = true;
                break;
            }
        }
        
        if (!is_retryable) {
            return false;
        }
        
        // Calculate next retry time
        const delay = self.calculateRetryDelay(policy, state);
        state.next_retry_time = std.time.Instant.now().plus(delay);
        
        return std.time.Instant.now().compare(state.next_retry_time) == .lt;
    }
    
    fn getOrCreatePolicy(self: *RetryManager, connection_id: []const u8) *RetryPolicy {
        return self.policies.get(connection_id) orelse {
            const policy = RetryPolicy.init(self.allocator);
            self.policies.put(connection_id, policy) catch {};
            return policy;
        };
    }
    
    fn calculateRetryDelay(self: RetryManager, policy: *RetryPolicy, state: *ConnectionAttemptState) std.time.Duration {
        var delay_ms = policy.base_delay.asMilliseconds();
        
        // Exponential backoff
        delay_ms = @as(u64, @floatFromInt(delay_ms)) * @max(1, state.backoff_factor);
        
        // Apply jitter to prevent thundering herd
        if (policy.jitter_enabled) {
            const jitter = @as(u64, @floatFromInt(delay_ms) * (std.time.now() % 1000) / 1000);
            delay_ms += jitter;
        }
        
        // Cap at maximum delay
        delay_ms = @min(delay_ms, policy.max_delay.asMilliseconds());
        
        state.backoff_factor *= policy.exponential_base;
        
        return std.time.Duration.fromMilliseconds(delay_ms);
    }
    
    pub fn recordSuccessfulAttempt(self: *RetryManager, connection_id: []const u8) void {
        // Reset backoff on success
        if (self.connection_states.get(connection_id)) |state| {
            state.attempts = 0;
            state.backoff_factor = 1.0;
            state.last_attempt = std.time.Instant.now();
        }
    }
    
    pub fn getRetryTime(self: RetryManager, connection_id: []const u8) ?std.time.Instant {
        if (self.connection_states.get(connection_id)) |state| {
            return state.next_retry_time;
        }
        return null;
    }
};

/// Hash function for strings
const StringHash = struct {
    pub fn hash(self: StringHash, key: []const u8) u64 {
        var result: u64 = 0x9e3779b97f4a7c15;
        for (key) |byte| {
            result ^= result >> 6;
            result += result << 7;
            result ^= byte;
        }
        return result;
    }
    
    pub fn eql(self: StringHash, a: []const u8, b: []const u8) bool {
        return std.mem.eql(u8, a, b);
    }
};

test "Performance Features Basic Tests" {
    const allocator = std.testing.allocator;
    
    // Test connection pooling
    var coalescer = try ConnectionCoalescer.init(allocator, undefined);
    defer coalescer.deinit();
    
    // Test priority tree
    var priority_tree = PriorityTree.init(allocator);
    defer priority_tree.deinit();
    
    const priority = StreamPriority.init(1, 16, null, false);
    try priority_tree.addStream(priority);
    
    try testing.expect(priority_tree.streams.contains(1));
    
    // Test retry manager
    var retry_manager = RetryManager.init(allocator);
    defer retry_manager.deinit();
    
    const should_retry = retry_manager.shouldRetry("test-conn", "CONNECTION_TIMEOUT");
    try testing.expect(should_retry);
    
    // Test early hints
    var hints_manager = EarlyHintsManager.init(allocator);
    defer hints_manager.deinit();
    
    var attributes = std.HashMap([]const u8, []const u8, StringHash).init(allocator);
    var early_hint = try hints_manager.addEarlyHint(.DnsPrefetch, "https://example.com", .high, attributes);
    
    try testing.expect(early_hint.priority == .high);
}