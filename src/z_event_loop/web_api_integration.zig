//! z_event_loop - Web API Integration Layer
//! 
//! Provides specific integration between Web APIs (Fetch, WebSocket, XMLHttpRequest)
//! and the z-net event loop system. Handles async operations, promise resolution,
//! and event routing.

const std = @import("std");
const Allocator = std.mem.Allocator;
const StringHashMap = std.StringHashMap;
const ArrayList = std.ArrayList;

const event_loop = @import("event_loop.zig");
const policy_engine = @import("z_policy/policy_engine.zig");
const policy = @import("z_policy/policy.zig");

// usingnamespace event_loop;
// usingnamespace policy_engine;

pub const FetchIntegration = struct {
    allocator: Allocator,
    event_loop: *EventLoopManager,
    active_fetches: AutoHashMap(u64, *FetchEventHandler),
    policy_manager: ?*PolicyManager,
    
    pub fn init(allocator: Allocator, event_loop: *EventLoopManager) FetchIntegration {
        return FetchIntegration{
            .allocator = allocator,
            .event_loop = event_loop,
            .active_fetches = AutoHashMap(u64, *FetchEventHandler).init(allocator),
            .policy_manager = null,
        };
    }
    
    pub fn deinit(self: *FetchIntegration) void {
        // Cancel all active fetches
        var fetch_iter = self.active_fetches.valueIterator();
        while (fetch_iter.next()) |handler| {
            self.allocator.destroy(handler);
        }
        self.active_fetches.deinit();
    }
    
    pub fn setPolicyManager(self: *FetchIntegration, policy_manager: *PolicyManager) void {
        self.policy_manager = policy_manager;
    }
    
    /// Execute a fetch request with event loop integration
    pub fn executeFetch(self: *FetchIntegration, url: []const u8, method: []const u8, headers: StringHashMap([]const u8), body: ?[]const u8) !u64 {
        // Validate request with policy engine
        if (self.policy_manager) |policy_mgr| {
            const page_origin = try Origin.parse("https://browser-page.com"); // Would come from actual page
            const validation_result = try policy_mgr.validateRequest(url, method, headers, page_origin);
            defer validation_result.deinit();
            
            if (!validation_result.allowed) {
                return error.PolicyViolation;
            }
        }
        
        // Create fetch handler
        const fetch_handler = try self.event_loop.createFetchHandler(url, method);
        errdefer self.allocator.destroy(fetch_handler);
        
        // Set up request headers
        var request_headers = headers;
        fetch_handler.headers = request_headers;
        
        if (body) |body_data| {
            fetch_handler.setRequestBody(body_data);
        }
        
        // Set up event callbacks
        fetch_handler.setEventCallback(.LOAD, &self.handleFetchLoad);
        fetch_handler.setEventCallback(.ERROR, &self.handleFetchError);
        fetch_handler.setEventCallback(.PROGRESS, &self.handleFetchProgress);
        fetch_handler.setEventCallback(.ABORT, &self.handleFetchAbort);
        
        // Store in active fetches
        try self.active_fetches.put(fetch_handler.fetch_id, fetch_handler);
        
        // Simulate async fetch execution
        try self.simulateFetchExecution(fetch_handler);
        
        return fetch_handler.fetch_id;
    }
    
    /// Get fetch result
    pub fn getFetchResult(self: *FetchIntegration, fetch_id: u64) ?FetchResult {
        const handler = self.active_fetches.get(fetch_id) orelse return null;
        
        if (handler.response_data) |data| {
            return FetchResult{
                .status_code = handler.status_code,
                .status_text = handler.status_text,
                .data = data,
                .headers = handler.response_headers,
                .completed = handler.status_code > 0,
            };
        }
        
        return null;
    }
    
    /// Cancel a fetch request
    pub fn cancelFetch(self: *FetchIntegration, fetch_id: u64) !void {
        const handler = self.active_fetches.get(fetch_id) orelse return error.FetchNotFound;
        
        handler.emitAbort();
        
        // Clean up
        _ = self.active_fetches.remove(fetch_id);
        self.allocator.destroy(handler);
    }
    
    /// Event handlers (callback functions)
    fn handleFetchLoad(event: WebAPIEvent) void {
        std.log.info("📥 Fetch completed: {} bytes", .{event.data.?.len});
    }
    
    fn handleFetchError(event: WebAPIEvent) void {
        std.log.warn("❌ Fetch error: {}", .{event.data.?});
    }
    
    fn handleFetchProgress(event: WebAPIEvent) void {
        const loaded = event.metadata.get("loaded") orelse "0";
        const total = event.metadata.get("total") orelse "0";
        std.log.debug("📊 Fetch progress: {}/{}", .{ loaded, total });
    }
    
    fn handleFetchAbort(event: WebAPIEvent) void {
        std.log.info("🚫 Fetch aborted: {}", .{event.data.?});
    }
    
    /// Simulate fetch execution (would integrate with actual network layer)
    fn simulateFetchExecution(self: *FetchIntegration, handler: *FetchEventHandler) !void {
        // This would integrate with the actual z-net pipeline/network stack
        // For now, simulate async execution
        
        var task = BackgroundTask.init(handler.fetch_id, "fetch-execution", "simulate");
        task.setCallback(&self.simulatedFetchCallback);
        task.setInterval(100, false); // Execute after 100ms
        
        try self.event_loop.scheduleBackgroundTask(task);
    }
    
    fn simulatedFetchCallback(data: []const u8) void {
        const fetch_id = std.fmt.parseInt(u64, data, 10) catch return;
        
        // This would be called from the actual network completion
        // For simulation, we'll complete it immediately
        _ = fetch_id;
    }
};

pub const WebSocketIntegration = struct {
    allocator: Allocator,
    event_loop: *EventLoopManager,
    active_connections: AutoHashMap(u64, *WebSocketEventHandler),
    policy_manager: ?*PolicyManager,
    
    pub fn init(allocator: Allocator, event_loop: *EventLoopManager) WebSocketIntegration {
        return WebSocketIntegration{
            .allocator = allocator,
            .event_loop = event_loop,
            .active_connections = AutoHashMap(u64, *WebSocketEventHandler).init(allocator),
            .policy_manager = null,
        };
    }
    
    pub fn deinit(self: *WebSocketIntegration) void {
        // Close all active connections
        var conn_iter = self.active_connections.valueIterator();
        while (conn_iter.next()) |handler| {
            handler.handleClose(1000, "Connection closed by application");
            self.allocator.destroy(handler);
        }
        self.active_connections.deinit();
    }
    
    pub fn setPolicyManager(self: *WebSocketIntegration, policy_manager: *PolicyManager) void {
        self.policy_manager = policy_manager;
    }
    
    /// Connect to WebSocket
    pub fn connectWebSocket(self: *WebSocketIntegration, url: []const u8, protocols: ?ArrayList([]const u8)) !u64 {
        // Validate WebSocket URL with policy engine
        if (self.policy_manager) |policy_mgr| {
            const page_origin = try Origin.parse("https://browser-page.com"); // Would come from actual page
            const validation_result = try policy_mgr.validateRequest(url, "GET", StringHashMap([]const u8).init(std.heap.c_allocator), page_origin);
            defer validation_result.deinit();
            
            if (!validation_result.allowed) {
                return error.PolicyViolation;
            }
        }
        
        // Create WebSocket handler
        const ws_handler = try self.event_loop.createWebSocketHandler();
        errdefer self.allocator.destroy(ws_handler);
        
        // Set up event callbacks
        ws_handler.setEventCallback(.OPEN, &self.handleWebSocketOpen);
        ws_handler.setEventCallback(.CLOSE, &self.handleWebSocketClose);
        ws_handler.setEventCallback(.MESSAGE, &self.handleWebSocketMessage);
        ws_handler.setEventCallback(.ERROR, &self.handleWebSocketError);
        
        // Store in active connections
        try self.active_connections.put(ws_handler.connection_id, ws_handler);
        
        // Simulate WebSocket connection
        try self.simulateWebSocketConnection(ws_handler);
        
        return ws_handler.connection_id;
    }
    
    /// Send WebSocket message
    pub fn sendWebSocketMessage(self: *WebSocketIntegration, connection_id: u64, message: []const u8) !void {
        const handler = self.active_connections.get(connection_id) orelse return error.ConnectionNotFound;
        
        if (!handler.is_open) {
            return error.ConnectionNotOpen;
        }
        
        // This would integrate with actual WebSocket protocol implementation
        std.log.debug("📤 WebSocket message sent: {} bytes", .{message.len});
    }
    
    /// Close WebSocket connection
    pub fn closeWebSocket(self: *WebSocketIntegration, connection_id: u64, code: u16, reason: []const u8) !void {
        const handler = self.active_connections.get(connection_id) orelse return error.ConnectionNotFound;
        
        handler.handleClose(code, reason);
        
        // Clean up
        _ = self.active_connections.remove(connection_id);
        self.allocator.destroy(handler);
    }
    
    /// Event handlers
    fn handleWebSocketOpen(event: WebAPIEvent) void {
        std.log.info("🔌 WebSocket connection opened", .{});
    }
    
    fn handleWebSocketClose(event: WebAPIEvent) void {
        const code = event.metadata.get("code") orelse "unknown";
        const reason = event.metadata.get("reason") orelse "No reason";
        std.log.info("🔌 WebSocket connection closed: {} - {}", .{ code, reason });
    }
    
    fn handleWebSocketMessage(event: WebAPIEvent) void {
        std.log.debug("📨 WebSocket message received: {} bytes", .{event.data.?.len});
    }
    
    fn handleWebSocketError(event: WebAPIEvent) void {
        std.log.warn("❌ WebSocket error: {}", .{event.data.?});
    }
    
    /// Simulate WebSocket connection
    fn simulateWebSocketConnection(self: *WebSocketIntegration, handler: *WebSocketEventHandler) !void {
        var task = BackgroundTask.init(handler.connection_id, "ws-connect", "simulate");
        task.setCallback(&self.simulatedWebSocketCallback);
        task.setInterval(200, false); // Execute after 200ms
        
        try self.event_loop.scheduleBackgroundTask(task);
    }
    
    fn simulatedWebSocketCallback(data: []const u8) void {
        const connection_id = std.fmt.parseInt(u64, data, 10) catch return;
        
        // Simulate connection opening
        // This would be called when actual WebSocket connection is established
        _ = connection_id;
    }
};

pub const XMLHttpRequestIntegration = struct {
    allocator: Allocator,
    event_loop: *EventLoopManager,
    active_requests: AutoHashMap(u64, *XMLHttpRequestEventHandler),
    policy_manager: ?*PolicyManager,
    
    pub fn init(allocator: Allocator, event_loop: *EventLoopManager) XMLHttpRequestIntegration {
        return XMLHttpRequestIntegration{
            .allocator = allocator,
            .event_loop = event_loop,
            .active_requests = AutoHashMap(u64, *XMLHttpRequestEventHandler).init(allocator),
            .policy_manager = null,
        };
    }
    
    pub fn deinit(self: *XMLHttpRequestIntegration) void {
        // Cancel all active requests
        var req_iter = self.active_requests.valueIterator();
        while (req_iter.next()) |handler| {
            handler.emitError("Request cancelled - integration shutting down");
            self.allocator.destroy(handler);
        }
        self.active_requests.deinit();
    }
    
    pub fn setPolicyManager(self: *XMLHttpRequestIntegration, policy_manager: *PolicyManager) void {
        self.policy_manager = policy_manager;
    }
    
    /// Execute XMLHttpRequest
    pub fn executeXMLHttpRequest(self: *XMLHttpRequestIntegration, url: []const u8, method: []const u8, async: bool) !u64 {
        // Validate request with policy engine
        if (self.policy_manager) |policy_mgr| {
            const page_origin = try Origin.parse("https://browser-page.com"); // Would come from actual page
            const validation_result = try policy_mgr.validateRequest(url, method, StringHashMap([]const u8).init(std.heap.c_allocator), page_origin);
            defer validation_result.deinit();
            
            if (!validation_result.allowed) {
                return error.PolicyViolation;
            }
        }
        
        // Create XHR handler
        const xhr_handler = try self.event_loop.createXMLHttpRequestHandler();
        errdefer self.allocator.destroy(xhr_handler);
        
        // Set up event callbacks
        xhr_handler.setEventCallback(.READY_STATE_CHANGE, &self.handleReadyStateChange);
        xhr_handler.setEventCallback(.LOAD, &self.handleXHRLoad);
        xhr_handler.setEventCallback(.ERROR, &self.handleXHRError);
        xhr_handler.setEventCallback(.ABORT, &self.handleXHRAbort);
        
        // Initialize request
        xhr_handler.setReadyState(.OPENED);
        
        // Store in active requests
        try self.active_requests.put(xhr_handler.request_id, xhr_handler);
        
        // Simulate async execution
        try self.simulateXMLHttpRequest(xhr_handler);
        
        return xhr_handler.request_id;
    }
    
    /// Set request headers
    pub fn setRequestHeader(self: *XMLHttpRequestIntegration, request_id: u64, name: []const u8, value: []const u8) !void {
        const handler = self.active_requests.get(request_id) orelse return error.RequestNotFound;
        handler.addHeader(name, value);
    }
    
    /// Send request body
    pub fn sendRequestBody(self: *XMLHttpRequestIntegration, request_id: u64, body: []const u8) !void {
        const handler = self.active_requests.get(request_id) orelse return error.RequestNotFound;
        handler.setResponseData(body); // For simulation
    }
    
    /// Abort request
    pub fn abortRequest(self: *XMLHttpRequestIntegration, request_id: u64) !void {
        const handler = self.active_requests.get(request_id) orelse return error.RequestNotFound;
        
        handler.emitAbort();
        
        // Clean up
        _ = self.active_requests.remove(request_id);
        self.allocator.destroy(handler);
    }
    
    /// Event handlers
    fn handleReadyStateChange(event: WebAPIEvent) void {
        const ready_state = event.metadata.get("readyState") orelse "unknown";
        const status = event.metadata.get("status") orelse "0";
        std.log.debug("🔄 XHR readyState changed: {} (status: {})", .{ ready_state, status });
    }
    
    fn handleXHRLoad(event: WebAPIEvent) void {
        std.log.info("📥 XHR request completed: {} bytes", .{event.data.?.len});
    }
    
    fn handleXHRError(event: WebAPIEvent) void {
        std.log.warn("❌ XHR error: {}", .{event.data.?});
    }
    
    fn handleXHRAbort(event: WebAPIEvent) void {
        std.log.info("🚫 XHR request aborted: {}", .{event.data.?});
    }
    
    /// Simulate XMLHttpRequest execution
    fn simulateXMLHttpRequest(self: *XMLHttpRequestIntegration, handler: *XMLHttpRequestEventHandler) !void {
        var task = BackgroundTask.init(handler.request_id, "xhr-execute", "simulate");
        task.setCallback(&self.simulatedXMLHttpRequestCallback);
        task.setInterval(150, false); // Execute after 150ms
        
        try self.event_loop.scheduleBackgroundTask(task);
    }
    
    fn simulatedXMLHttpRequestCallback(data: []const u8) void {
        const request_id = std.fmt.parseInt(u64, data, 10) catch return;
        
        // Simulate request progression
        // This would be called when actual network operation completes
        _ = request_id;
    }
};

pub const PromiseIntegration = struct {
    allocator: Allocator,
    event_loop: *EventLoopManager,
    pending_promises: AutoHashMap(u64, PromiseResolver),
    promise_id_counter: u64,
    
    pub fn init(allocator: Allocator, event_loop: *EventLoopManager) PromiseIntegration {
        return PromiseIntegration{
            .allocator = allocator,
            .event_loop = event_loop,
            .pending_promises = AutoHashMap(u64, PromiseResolver).init(allocator),
            .promise_id_counter = 1,
        };
    }
    
    pub fn deinit(self: *PromiseIntegration) void {
        self.pending_promises.deinit();
    }
    
    /// Create a new promise
    pub fn createPromise(self: *PromiseIntegration) u64 {
        const promise_id = self.promise_id_counter;
        self.promise_id_counter += 1;
        
        var resolver = PromiseResolver.init();
        try self.pending_promises.put(promise_id, resolver);
        
        return promise_id;
    }
    
    /// Resolve a promise
    pub fn resolvePromise(self: *PromiseIntegration, promise_id: u64, data: ?[]const u8) !void {
        const resolver = self.pending_promises.get(promise_id) orelse return error.PromiseNotFound;
        resolver.resolve(data);
        _ = self.pending_promises.remove(promise_id);
    }
    
    /// Reject a promise
    pub fn rejectPromise(self: *PromiseIntegration, promise_id: u64, error: []const u8) !void {
        const resolver = self.pending_promises.get(promise_id) orelse return error.PromiseNotFound;
        resolver.reject(error);
        _ = self.pending_promises.remove(promise_id);
    }
    
    /// Get promise resolver for callbacks
    pub fn getPromiseResolver(self: *PromiseIntegration, promise_id: u64) ?*PromiseResolver {
        return self.pending_promises.get(promise_id);
    }
};

pub const BackgroundSyncIntegration = struct {
    allocator: Allocator,
    event_loop: *EventLoopManager,
    sync_tasks: AutoHashMap(u64, BackgroundTask),
    sync_id_counter: u64,
    
    pub fn init(allocator: Allocator, event_loop: *EventLoopManager) BackgroundSyncIntegration {
        return BackgroundSyncIntegration{
            .allocator = allocator,
            .event_loop = event_loop,
            .sync_tasks = AutoHashMap(u64, BackgroundTask).init(allocator),
            .sync_id_counter = 1,
        };
    }
    
    pub fn deinit(self: *BackgroundSyncIntegration) void {
        self.sync_tasks.deinit();
    }
    
    /// Schedule background sync
    pub fn scheduleSync(self: *BackgroundSyncIntegration, task_name: []const u8, data: []const u8, delay_ms: u64) !u64 {
        const sync_id = self.sync_id_counter;
        self.sync_id_counter += 1;
        
        var task = BackgroundTask.init(sync_id, task_name, data);
        task.setInterval(delay_ms, false); // One-time execution
        
        try self.sync_tasks.put(sync_id, task);
        try self.event_loop.scheduleBackgroundTask(task);
        
        return sync_id;
    }
    
    /// Cancel background sync
    pub fn cancelSync(self: *BackgroundSyncIntegration, sync_id: u64) !void {
        self.event_loop.cancelBackgroundTask(sync_id);
        _ = self.sync_tasks.remove(sync_id);
    }
};

// Data structures for API responses
pub const FetchResult = struct {
    status_code: u16,
    status_text: []const u8,
    data: []const u8,
    headers: StringHashMap([]const u8),
    completed: bool,
};

pub const WebSocketResult = struct {
    connection_id: u64,
    is_open: bool,
    last_message: ?[]const u8 = null,
    message_count: u64 = 0,
};

pub const XMLHttpRequestResult = struct {
    request_id: u64,
    ready_state: ReadyState,
    status_code: u16,
    response_data: []const u8,
    headers: StringHashMap([]const u8),
    completed: bool,
};

// Error types
pub const WebAPIError = error{
    PolicyViolation,
    FetchNotFound,
    ConnectionNotFound,
    ConnectionNotOpen,
    RequestNotFound,
    PromiseNotFound,
    InvalidReadyState,
};

test "fetch integration" {
    const allocator = std.testing.allocator;
    var event_loop = EventLoopManager.init(allocator, 100);
    defer event_loop.deinit();
    
    var fetch_integration = FetchIntegration.init(allocator, &event_loop);
    defer fetch_integration.deinit();
    
    var headers = StringHashMap([]const u8).init(allocator);
    defer headers.deinit();
    
    headers.put("Content-Type", "application/json") catch {};
    
    const fetch_id = fetch_integration.executeFetch("https://api.example.com/data", "GET", headers, null) catch {
        try std.testing.expect(false);
        return;
    };
    
    try std.testing.expect(fetch_id > 0);
    try std.testing.expect(fetch_integration.active_fetches.contains(fetch_id));
}

test "webSocket integration" {
    const allocator = std.testing.allocator;
    var event_loop = EventLoopManager.init(allocator, 100);
    defer event_loop.deinit();
    
    var ws_integration = WebSocketIntegration.init(allocator, &event_loop);
    defer ws_integration.deinit();
    
    const connection_id = ws_integration.connectWebSocket("wss://echo.websocket.org", null) catch {
        try std.testing.expect(false);
        return;
    };
    
    try std.testing.expect(connection_id > 0);
    try std.testing.expect(ws_integration.active_connections.contains(connection_id));
}

test "promise integration" {
    const allocator = std.testing.allocator;
    var event_loop = EventLoopManager.init(allocator, 100);
    defer event_loop.deinit();
    
    var promise_integration = PromiseIntegration.init(allocator, &event_loop);
    defer promise_integration.deinit();
    
    const promise_id = promise_integration.createPromise();
    try std.testing.expect(promise_id > 0);
    
    try promise_integration.resolvePromise(promise_id, "success");
    try std.testing.expect(!promise_integration.pending_promises.contains(promise_id));
}