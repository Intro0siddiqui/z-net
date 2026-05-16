//! z_event_loop - Main Event Loop Module
//! 
//! Unified event loop system for browser compatibility that integrates
//! Web APIs with z-net's async networking stack.

const std = @import("std");
const Allocator = std.mem.Allocator;
const StringHashMap = std.StringHashMap;

const event_loop = @import("event_loop.zig");
const web_api = @import("web_api_integration.zig");
const policy_engine = @import("z_policy/policy_engine.zig");
const policy = @import("z_policy/policy.zig");

usingnamespace event_loop;
usingnamespace web_api;
usingnamespace policy_engine;

pub const BrowserEventLoop = struct {
    allocator: Allocator,
    event_loop_manager: EventLoopManager,
    fetch_integration: FetchIntegration,
    websocket_integration: WebSocketIntegration,
    xhr_integration: XMLHttpRequestIntegration,
    promise_integration: PromiseIntegration,
    background_sync: BackgroundSyncIntegration,
    policy_manager: PolicyManager,
    is_initialized: bool,
    
    pub fn init(allocator: Allocator, policy_config: PolicyEngineConfig) !BrowserEventLoop {
        var event_loop_manager = EventLoopManager.init(allocator, 1000);
        
        var policy_manager = try PolicyManager.init(allocator, policy_config);
        
        return BrowserEventLoop{
            .allocator = allocator,
            .event_loop_manager = event_loop_manager,
            .fetch_integration = FetchIntegration.init(allocator, &event_loop_manager),
            .websocket_integration = WebSocketIntegration.init(allocator, &event_loop_manager),
            .xhr_integration = XMLHttpRequestIntegration.init(allocator, &event_loop_manager),
            .promise_integration = PromiseIntegration.init(allocator, &event_loop_manager),
            .background_sync = BackgroundSyncIntegration.init(allocator, &event_loop_manager),
            .policy_manager = policy_manager,
            .is_initialized = false,
        };
    }
    
    pub fn deinit(self: *BrowserEventLoop) void {
        if (self.is_initialized) {
            self.stop();
        }
        
        self.fetch_integration.deinit();
        self.websocket_integration.deinit();
        self.xhr_integration.deinit();
        self.promise_integration.deinit();
        self.background_sync.deinit();
        self.policy_manager.deinit();
        self.event_loop_manager.deinit();
    }
    
    /// Initialize the browser event loop
    pub fn initialize(inout self: *BrowserEventLoop) !void {
        if (self.is_initialized) {
            return error.AlreadyInitialized;
        }
        
        // Link policy manager with API integrations
        self.fetch_integration.setPolicyManager(&self.policy_manager);
        self.websocket_integration.setPolicyManager(&self.policy_manager);
        self.xhr_integration.setPolicyManager(&self.policy_manager);
        
        // Start the event loop manager
        try self.event_loop_manager.start();
        
        self.is_initialized = true;
        std.log.info("🌊 Browser Event Loop initialized successfully", .{});
    }
    
    /// Start the browser event loop
    pub fn start(inout self: *BrowserEventLoop) !void {
        if (!self.is_initialized) {
            try self.initialize();
        }
        
        std.log.info("🚀 Browser Event Loop started", .{});
    }
    
    /// Stop the browser event loop
    pub fn stop(inout self: *BrowserEventLoop) void {
        self.event_loop_manager.stop();
        self.is_initialized = false;
        std.log.info("🛑 Browser Event Loop stopped", .{});
    }
    
    /// Process a single event loop cycle
    pub fn processCycle(inout self: *BrowserEventLoop) !void {
        if (!self.is_initialized) {
            return error.NotInitialized;
        }
        
        // Process task queue
        try self.event_loop_manager.processTaskQueue();
        
        // Process background tasks
        try self.event_loop_manager.processBackgroundTasks();
        
        // Process API integrations
        try self.processAPIIntegrations();
    }
    
    /// Fetch API integration
    pub fn fetch(inout self: *BrowserEventLoop, url: []const u8, options: FetchOptions) !u64 {
        if (!self.is_initialized) {
            return error.NotInitialized;
        }
        
        var headers = StringHashMap([]const u8).init(self.allocator);
        defer headers.deinit();
        
        // Convert FetchOptions to headers
        var options_iter = options.headers.keyIterator();
        while (options_iter.next()) |header_name| {
            const header_value = options.headers.get(header_name.*).?;
            headers.put(header_name.*, header_value) catch {};
        }
        
        return try self.fetch_integration.executeFetch(url, options.method, headers, options.body);
    }
    
    /// Get fetch result
    pub fn getFetchResult(self: *BrowserEventLoop, fetch_id: u64) ?FetchResult {
        return self.fetch_integration.getFetchResult(fetch_id);
    }
    
    /// Cancel fetch request
    pub fn cancelFetch(inout self: *BrowserEventLoop, fetch_id: u64) !void {
        return try self.fetch_integration.cancelFetch(fetch_id);
    }
    
    /// WebSocket API integration
    pub fn connectWebSocket(inout self: *BrowserEventLoop, url: []const u8, protocols: ?ArrayList([]const u8)) !u64 {
        if (!self.is_initialized) {
            return error.NotInitialized;
        }
        
        return try self.websocket_integration.connectWebSocket(url, protocols);
    }
    
    /// Send WebSocket message
    pub fn sendWebSocketMessage(inout self: *BrowserEventLoop, connection_id: u64, message: []const u8) !void {
        return try self.websocket_integration.sendWebSocketMessage(connection_id, message);
    }
    
    /// Close WebSocket connection
    pub fn closeWebSocket(inout self: *BrowserEventLoop, connection_id: u64, code: u16, reason: []const u8) !void {
        return try self.websocket_integration.closeWebSocket(connection_id, code, reason);
    }
    
    /// XMLHttpRequest API integration
    pub fn createXMLHttpRequest(inout self: *BrowserEventLoop, url: []const u8, method: []const u8, async: bool) !u64 {
        if (!self.is_initialized) {
            return error.NotInitialized;
        }
        
        return try self.xhr_integration.executeXMLHttpRequest(url, method, async);
    }
    
    /// Set XMLHttpRequest header
    pub fn setXMLHttpRequestHeader(inout self: *BrowserEventLoop, request_id: u64, name: []const u8, value: []const u8) !void {
        return try self.xhr_integration.setRequestHeader(request_id, name, value);
    }
    
    /// Send XMLHttpRequest body
    pub fn sendXMLHttpRequestBody(inout self: *BrowserEventLoop, request_id: u64, body: []const u8) !void {
        return try self.xhr_integration.sendRequestBody(request_id, body);
    }
    
    /// Abort XMLHttpRequest
    pub fn abortXMLHttpRequest(inout self: *BrowserEventLoop, request_id: u64) !void {
        return try self.xhr_integration.abortRequest(request_id);
    }
    
    /// Promise API integration
    pub fn createPromise(inout self: *BrowserEventLoop) u64 {
        return self.promise_integration.createPromise();
    }
    
    /// Resolve promise
    pub fn resolvePromise(inout self: *BrowserEventLoop, promise_id: u64, data: ?[]const u8) !void {
        return try self.promise_integration.resolvePromise(promise_id, data);
    }
    
    /// Reject promise
    pub fn rejectPromise(inout self: *BrowserEventLoop, promise_id: u64, error: []const u8) !void {
        return try self.promise_integration.rejectPromise(promise_id, error);
    }
    
    /// Background sync integration
    pub fn scheduleBackgroundSync(inout self: *BrowserEventLoop, task_name: []const u8, data: []const u8, delay_ms: u64) !u64 {
        return try self.background_sync.scheduleSync(task_name, data, delay_ms);
    }
    
    /// Cancel background sync
    pub fn cancelBackgroundSync(inout self: *BrowserEventLoop, sync_id: u64) !void {
        return try self.background_sync.cancelSync(sync_id);
    }
    
    /// Configure CORS for an origin
    pub fn configureCORS(inout self: *BrowserEventLoop, origin: []const u8, options: CORSOptions) !void {
        return try self.policy_manager.configureCORS(origin, options);
    }
    
    /// Add CSP policy
    pub fn addCSPPolicy(inout self: *BrowserEventLoop, origin: []const u8, policy_header: []const u8) !void {
        return try self.policy_manager.addCSPPolicy(origin, policy_header);
    }
    
    /// Add whitelist origin
    pub fn addWhitelistOrigin(inout self: *BrowserEventLoop, origin: []const u8) !void {
        return try self.policy_manager.addWhitelistOrigin(origin);
    }
    
    /// Get comprehensive statistics
    pub fn getStatistics(self: *BrowserEventLoop) BrowserEventLoopStats {
        const event_stats = self.event_loop_manager.getStats();
        const policy_stats = self.policy_manager.getStats();
        
        return BrowserEventLoopStats{
            .event_loop = event_stats,
            .policy_engine = policy_stats,
            .active_fetches = self.fetch_integration.active_fetches.count(),
            .active_websockets = self.websocket_integration.active_connections.count(),
            .active_xhr = self.xhr_integration.active_requests.count(),
            .pending_promises = self.promise_integration.pending_promises.count(),
            .background_syncs = self.background_sync.sync_tasks.count(),
            .is_running = self.event_loop_manager.is_running,
        };
    }
    
    /// Clear all caches
    pub fn clearCaches(inout self: *BrowserEventLoop) void {
        self.policy_manager.clearCaches();
        std.log.info("🧹 All caches cleared", .{});
    }
    
    /// Get event loop status
    pub fn getStatus(self: *BrowserEventLoop) BrowserEventLoopStatus {
        return BrowserEventLoopStatus{
            .is_initialized = self.is_initialized,
            .is_running = self.event_loop_manager.is_running,
            .active_connections = self.websocket_integration.active_connections.count(),
            .pending_operations = self.fetch_integration.active_fetches.count() + 
                                 self.xhr_integration.active_requests.count(),
        };
    }
    
    // Private helper functions
    fn processAPIIntegrations(inout self: *BrowserEventLoop) !void {
        // Process any pending API operations
        // This is where you'd integrate with the actual network stack
        
        // Process fetch completions
        var fetch_iter = self.fetch_integration.active_fetches.keyIterator();
        while (fetch_iter.next()) |fetch_id| {
            // Check if fetch is complete and notify callbacks
            _ = fetch_id; // Would implement actual completion detection
        }
        
        // Process WebSocket events
        var ws_iter = self.websocket_integration.active_connections.keyIterator();
        while (ws_iter.next()) |connection_id| {
            // Process WebSocket message queue
            _ = connection_id; // Would implement actual message processing
        }
        
        // Process XMLHttpRequest completions
        var xhr_iter = self.xhr_integration.active_requests.keyIterator();
        while (xhr_iter.next()) |request_id| {
            // Check if request is complete
            _ = request_id; // Would implement actual completion detection
        }
    }
};

// Additional types for the browser event loop
pub const BrowserEventLoopStats = struct {
    event_loop: EventLoopStats,
    policy_engine: PolicyStats,
    active_fetches: usize,
    active_websockets: usize,
    active_xhr: usize,
    pending_promises: usize,
    background_syncs: usize,
    is_running: bool,
};

pub const BrowserEventLoopStatus = struct {
    is_initialized: bool,
    is_running: bool,
    active_connections: usize,
    pending_operations: usize,
};

// Simplified FetchOptions for integration
pub const FetchOptions = struct {
    method: []const u8,
    headers: StringHashMap([]const u8),
    body: ?[]const u8,
    
    pub fn init(allocator: Allocator, method: []const u8) FetchOptions {
        return FetchOptions{
            .method = method,
            .headers = StringHashMap([]const u8).init(allocator),
            .body = null,
        };
    }
    
    pub fn addHeader(inout self: *FetchOptions, name: []const u8, value: []const u8) void {
        self.headers.put(name, value) catch {};
    }
    
    pub fn setBody(inout self: *FetchOptions, body: []const u8) void {
        self.body = body;
    }
};

pub const BrowserEventLoopError = error{
    AlreadyInitialized,
    NotInitialized,
    PolicyViolation,
    InvalidConfiguration,
};

/// Main API for creating and managing browser event loop
pub fn createBrowserEventLoop(allocator: Allocator, policy_config: PolicyEngineConfig) !*BrowserEventLoop {
    const event_loop_ptr = try allocator.create(BrowserEventLoop);
    event_loop_ptr.* = try BrowserEventLoop.init(allocator, policy_config);
    return event_loop_ptr;
}

pub fn destroyBrowserEventLoop(inout event_loop: *BrowserEventLoop, allocator: Allocator) void {
    event_loop.deinit();
    allocator.destroy(event_loop);
}

/// Example usage and testing
pub fn exampleBrowserEventLoop() !void {
    const allocator = std.heap.c_allocator;
    
    // Create default policy configuration
    const policy_config = getDefaultPolicyConfig();
    
    // Create browser event loop
    var browser_event_loop = try createBrowserEventLoop(allocator, policy_config);
    defer destroyBrowserEventLoop(browser_event_loop, allocator);
    
    // Initialize
    try browser_event_loop.initialize();
    
    std.log.info("🌊 Browser Event Loop Example Started", .{});
    
    // Example 1: Fetch API
    var fetch_options = FetchOptions.init(allocator, "GET");
    fetch_options.addHeader("Accept", "application/json");
    fetch_options.addHeader("User-Agent", "z-net/1.0");
    
    const fetch_id = try browser_event_loop.fetch("https://api.example.com/data", fetch_options);
    std.log.info("📡 Fetch started with ID: {}", .{fetch_id});
    
    // Example 2: WebSocket
    var protocols = ArrayList([]const u8).init(allocator);
    protocols.append("chat") catch {};
    
    const ws_connection_id = try browser_event_loop.connectWebSocket("wss://echo.websocket.org", protocols);
    std.log.info("🔌 WebSocket connection started with ID: {}", .{ws_connection_id});
    
    // Example 3: XMLHttpRequest
    const xhr_id = try browser_event_loop.createXMLHttpRequest("https://example.com/api", "POST", true);
    try browser_event_loop.setXMLHttpRequestHeader(xhr_id, "Content-Type", "application/json");
    std.log.info("📋 XMLHttpRequest started with ID: {}", .{xhr_id});
    
    // Example 4: Promise
    const promise_id = browser_event_loop.createPromise();
    std.log.info("🤝 Promise created with ID: {}", .{promise_id});
    
    // Example 5: Background Sync
    const sync_id = try browser_event_loop.scheduleBackgroundSync("data-sync", "sync-data", 5000);
    std.log.info("🔄 Background sync scheduled with ID: {}", .{sync_id});
    
    // Process some cycles
    for (0..5) |i| {
        try browser_event_loop.processCycle();
        std.log.debug("⚡ Processed cycle {}", .{i + 1});
        
        // Simulate some async completions
        if (i == 2) {
            try browser_event_loop.resolvePromise(promise_id, "Promise resolved!");
        }
    }
    
    // Get statistics
    const stats = browser_event_loop.getStatistics();
    std.log.info("📊 Browser Event Loop Statistics:", .{});
    std.log.info("  - Active Fetches: {}", .{stats.active_fetches});
    std.log.info("  - Active WebSockets: {}", .{stats.active_websockets});
    std.log.info("  - Active XHR: {}", .{stats.active_xhr});
    std.log.info("  - Pending Promises: {}", .{stats.pending_promises});
    std.log.info("  - Background Syncs: {}", .{stats.background_syncs});
    
    // Get status
    const status = browser_event_loop.getStatus();
    std.log.info("🎯 Event Loop Status: Initialized={}, Running={}, Connections={}, Operations={}", .{
        status.is_initialized,
        status.is_running,
        status.active_connections,
        status.pending_operations,
    });
    
    // Cleanup
    try browser_event_loop.cancelFetch(fetch_id);
    try browser_event_loop.closeWebSocket(ws_connection_id, 1000, "Example completed");
    try browser_event_loop.abortXMLHttpRequest(xhr_id);
    try browser_event_loop.cancelBackgroundSync(sync_id);
    
    std.log.info("✅ Browser Event Loop Example Completed", .{});
}

test "browser event loop integration" {
    const allocator = std.testing.allocator;
    const policy_config = getDefaultPolicyConfig();
    
    var event_loop = try BrowserEventLoop.init(allocator, policy_config);
    defer event_loop.deinit();
    
    try event_loop.initialize();
    try std.testing.expect(event_loop.is_initialized);
    
    // Test status
    const status = event_loop.getStatus();
    try std.testing.expect(status.is_initialized);
    try std.testing.expect(status.is_running);
    try std.testing.expectEqual(@as(usize, 0), status.active_connections);
    try std.testing.expectEqual(@as(usize, 0), status.pending_operations);
    
    // Test statistics
    const stats = event_loop.getStatistics();
    try std.testing.expectEqual(@as(usize, 0), stats.active_fetches);
    try std.testing.expectEqual(@as(usize, 0), stats.active_websockets);
    try std.testing.expectEqual(@as(usize, 0), stats.active_xhr);
    try std.testing.expectEqual(@as(usize, 0), stats.pending_promises);
    try std.testing.expectEqual(@as(usize, 0), stats.background_syncs);
}