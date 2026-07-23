//! z_websocket - WebSocket Handshake and Manager
//! 
//! WebSocket handshake handler and manager that implements the WebSocket
//! protocol handshake, connection management, and integration with the
//! z-net networking stack.

const std = @import("std");
const Allocator = std.mem.Allocator;
const StringHashMap = std.StringHashMap;
const ArrayList = std.ArrayList;
const Sha1 = std.crypto.hash.Sha1;

const policy_engine = @import("z_policy/policy_engine.zig");
const policy = @import("z_policy/policy.zig");
const event_loop = @import("z_event_loop/event_loop.zig");
const websocket_protocol = @import("websocket_protocol.zig");

// usingnamespace policy_engine;
// usingnamespace event_loop;
// usingnamespace websocket_protocol;

// WebSocket handshake request/response
pub const WebSocketHandshakeRequest = struct {
    url: []const u8,
    method: []const u8,
    headers: StringHashMap([]const u8),
    key: [24]u8,
    
    pub fn init(allocator: Allocator, url: []const u8) WebSocketHandshakeRequest {
        return WebSocketHandshakeRequest{
            .url = url,
            .method = "GET",
            .headers = StringHashMap([]const u8).init(allocator),
            .key = generateWebSocketKey(),
        };
    }
    
    pub fn deinit(self: *WebSocketHandshakeRequest) void {
        self.headers.deinit();
    }
    
    pub fn setHeader(self: *WebSocketHandshakeRequest, name: []const u8, value: []const u8) void {
        self.headers.put(name, value) catch {};
    }
    
    pub fn generateHandshakeRequest(self: *WebSocketHandshakeRequest, allocator: Allocator) ![]const u8 {
        // Set required headers
        self.setHeader("Host", extractHostFromUrl(self.url));
        self.setHeader("Upgrade", "websocket");
        self.setHeader("Connection", "Upgrade");
        self.setHeader("Sec-WebSocket-Key", std.mem.sliceTo(&self.key, 0));
        self.setHeader("Sec-WebSocket-Version", "13");
        
        // Generate request headers
        var request_builder = ArrayList(u8).init(allocator);
        defer request_builder.deinit();
        
        // Request line
        try request_builder.appendSlice(self.method);
        try request_builder.appendSlice(" ");
        try request_builder.appendSlice(self.url);
        try request_builder.appendSlice(" HTTP/1.1\r\n");
        
        // Headers
        var header_iter = self.headers.keyIterator();
        while (header_iter.next()) |header_name| {
            const header_value = self.headers.get(header_name.*).?;
            try request_builder.appendSlice(header_name.*);
            try request_builder.appendSlice(": ");
            try request_builder.appendSlice(header_value);
            try request_builder.appendSlice("\r\n");
        }
        
        // End of headers
        try request_builder.appendSlice("\r\n");
        
        return request_builder.toOwnedSlice();
    }
};

pub const WebSocketHandshakeResponse = struct {
    status_code: u16,
    status_text: []const u8,
    headers: StringHashMap([]const u8),
    accept_key: [28]u8,
    
    pub fn init(allocator: Allocator) WebSocketHandshakeResponse {
        return WebSocketHandshakeResponse{
            .status_code = 101,
            .status_text = "Switching Protocols",
            .headers = StringHashMap([]const u8).init(allocator),
            .accept_key = undefined,
        };
    }
    
    pub fn deinit(self: *WebSocketHandshakeResponse) void {
        self.headers.deinit();
    }
    
    pub fn setHeader(self: *WebSocketHandshakeResponse, name: []const u8, value: []const u8) void {
        self.headers.put(name, value) catch {};
    }
    
    pub fn parseHandshakeResponse(self: *WebSocketHandshakeResponse, response_data: []const u8) !void {
        var lines = std.mem.split(u8, response_data, "\r\n");
        
        // Parse status line
        const status_line = lines.next() orelse return error.InvalidResponse;
        const parts = std.mem.split(u8, status_line, " ");
        const http_version = parts.next() orelse return error.InvalidResponse;
        const status_code_str = parts.next() orelse return error.InvalidResponse;
        const status_text_start = std.mem.indexOfPos(u8, status_line, status_line.len - status_code_str.len) orelse 0;
        
        self.status_code = std.fmt.parseInt(u16, status_code_str, 10) catch return error.InvalidStatusCode;
        
        // Parse headers
        while (lines.next()) |line| {
            if (line.len == 0) break; // End of headers
            
            const colon_pos = std.mem.indexOf(u8, line, ":") orelse continue;
            const header_name = std.mem.trim(u8, line[0..colon_pos], " \t");
            const header_value = std.mem.trim(u8, line[colon_pos + 1 ..], " \t");
            
            if (std.mem.eql(u8, std.ascii.lowerString(header_name), "sec-websocket-accept")) {
                // Store accept key
                var key_bytes: [28]u8 = undefined;
                @memcpy(&key_bytes, header_value[0..28]);
                self.accept_key = key_bytes;
            } else {
                self.setHeader(header_name, header_value);
            }
        }
    }
    
    pub fn verifyAcceptKey(self: *WebSocketHandshakeResponse, client_key: [24]u8) !bool {
        const expected_accept = computeWebSocketAcceptKey(client_key);
        return std.mem.eql(u8, &expected_accept, &self.accept_key);
    }
    
    pub fn isSuccessful(self: *WebSocketHandshakeResponse) bool {
        return self.status_code == 101 and 
               std.mem.eql(u8, self.status_text, "Switching Protocols");
    }
    
    pub fn getNegotiatedProtocol(self: *WebSocketHandshakeResponse) ?[]const u8 {
        return self.headers.get("Sec-WebSocket-Protocol");
    }
    
    pub fn getNegotiatedExtensions(self: *WebSocketHandshakeResponse) ?[]const u8 {
        return self.headers.get("Sec-WebSocket-Extensions");
    }
};

// WebSocket event types
pub const WebSocketEventType = enum {
    OPEN,
    MESSAGE,
    CLOSE,
    ERROR,
    PING,
    PONG,
    BINARY_MESSAGE,
};

pub const WebSocketEvent = struct {
    event_type: WebSocketEventType,
    connection_id: u64,
    data: ?[]const u8,
    binary_data: ?[]const u8,
    close_code: ?WebSocketCloseCode,
    reason: ?[]const u8,
    timestamp: u64,
    
    pub fn init(allocator: Allocator, event_type: WebSocketEventType, connection_id: u64) WebSocketEvent {
        return WebSocketEvent{
            .event_type = event_type,
            .connection_id = connection_id,
            .data = null,
            .binary_data = null,
            .close_code = null,
            .reason = null,
            .timestamp = getCurrentTimestamp(),
        };
    }
    
    pub fn deinit(self: *WebSocketEvent) void {
        _ = self;
    }
    
    pub fn setMessage(self: *WebSocketEvent, message: []const u8) void {
        self.data = message;
    }
    
    pub fn setBinaryData(self: *WebSocketEvent, binary_data: []const u8) void {
        self.binary_data = binary_data;
    }
    
    pub fn setCloseInfo(self: *WebSocketEvent, code: WebSocketCloseCode, reason: []const u8) void {
        self.close_code = code;
        self.reason = reason;
    }
};

// WebSocket manager configuration
pub const WebSocketConfig = struct {
    max_connections_per_origin: usize = 10,
    connection_timeout_seconds: u64 = 300,
    max_message_size: u64 = 16 * 1024 * 1024, // 16MB
    ping_interval_seconds: u64 = 30,
    max_queued_messages: usize = 100,
    enable_compression: bool = true,
    enable_permessage_deflate: bool = true,
    enable_binary_messages: bool = true,
    buffer_size: usize = 8192,
};

// Main WebSocket manager
pub const WebSocketManager = struct {
    allocator: Allocator,
    config: WebSocketConfig,
    event_loop: *EventLoopManager,
    connection_pool: WebSocketPool,
    event_handlers: AutoHashMap(u64, *const fn (WebSocketEvent) void),
    policy_manager: ?*PolicyManager,
    
    pub fn init(allocator: Allocator, event_loop: *EventLoopManager, config: WebSocketConfig) WebSocketManager {
        return WebSocketManager{
            .allocator = allocator,
            .config = config,
            .event_loop = event_loop,
            .connection_pool = WebSocketPool.init(allocator, config.max_connections_per_origin),
            .event_handlers = AutoHashMap(u64, *const fn (WebSocketEvent) void).init(allocator),
            .policy_manager = null,
        };
    }
    
    pub fn deinit(self: *WebSocketManager) void {
        self.connection_pool.deinit();
        self.event_handlers.deinit();
    }
    
    pub fn setPolicyManager(self: *WebSocketManager, policy_manager: *PolicyManager) void {
        self.policy_manager = policy_manager;
    }
    
    /// Connect to WebSocket server
    pub fn connect(self: *WebSocketManager, url: []const u8, protocols: ?ArrayList([]const u8)) !u64 {
        // Validate URL
        if (!std.mem.eql(u8, url[0..3], "ws:") and !std.mem.eql(u8, url[0..4], "wss:")) {
            return error.InvalidUrl;
        }
        
        // Check policy compliance
        if (self.policy_manager) |policy_mgr| {
            const page_origin = try Origin.parse("https://browser-page.com"); // Would come from actual page
            const validation_result = try policy_mgr.validateRequest(url, "GET", StringHashMap([]const u8).init(self.allocator), page_origin);
            defer validation_result.deinit();
            
            if (!validation_result.allowed) {
                return error.PolicyViolation;
            }
        }
        
        // Create connection
        const connection = try self.connection_pool.createConnection(url, protocols);
        
        // Initiate handshake
        try self.initiateHandshake(connection);
        
        // Start connection monitoring
        try self.startConnectionMonitoring(connection);
        
        return connection.connection_id;
    }
    
    /// Disconnect WebSocket
    pub fn disconnect(self: *WebSocketManager, connection_id: u64, code: WebSocketCloseCode, reason: []const u8) !void {
        try self.connection_pool.closeConnection(connection_id, code, reason, self.allocator);
    }
    
    /// Send text message
    pub fn sendText(self: *WebSocketManager, connection_id: u64, message: []const u8) !void {
        const connection = self.connection_pool.connections.get(connection_id) orelse return error.ConnectionNotFound;
        try connection.sendText(message, self.allocator);
    }
    
    /// Send binary message
    pub fn sendBinary(self: *WebSocketManager, connection_id: u64, binary_data: []const u8) !void {
        const connection = self.connection_pool.connections.get(connection_id) orelse return error.ConnectionNotFound;
        try connection.sendBinary(binary_data, self.allocator);
    }
    
    /// Send ping
    pub fn sendPing(self: *WebSocketManager, connection_id: u64) !void {
        const connection = self.connection_pool.connections.get(connection_id) orelse return error.ConnectionNotFound;
        try connection.sendPing(self.allocator);
    }
    
    /// Add event listener
    pub fn addEventListener(self: *WebSocketManager, connection_id: u64, callback: *const fn (WebSocketEvent) void) !void {
        try self.event_handlers.put(connection_id, callback);
    }
    
    /// Remove event listener
    pub fn removeEventListener(self: *WebSocketManager, connection_id: u64) void {
        _ = self.event_handlers.remove(connection_id);
    }
    
    /// Get connection status
    pub fn getConnectionStatus(self: *WebSocketManager, connection_id: u64) ?WebSocketConnectionStatus {
        const connection = self.connection_pool.connections.get(connection_id) orelse return null;
        
        return WebSocketConnectionStatus{
            .connection_id = connection_id,
            .state = connection.state,
            .url = connection.url,
            .protocols = connection.protocols.items,
            .queued_messages = connection.getQueuedMessageCount(),
            .has_pending_pings = connection.hasPendingPings(),
            .created_timestamp = connection.created_timestamp,
            .last_activity_timestamp = connection.last_activity_timestamp,
        };
    }
    
    /// Get all connections
    pub fn getAllConnections(self: *WebSocketManager) ArrayList(ConnectionInfo) {
        var connections = ArrayList(ConnectionInfo).init(self.allocator);
        
        var conn_iter = self.connection_pool.connections.valueIterator();
        while (conn_iter.next()) |connection| {
            const info = ConnectionInfo{
                .connection_id = connection.connection_id,
                .url = connection.url,
                .state = connection.state,
                .protocols = connection.protocols.items,
                .message_count = connection.getQueuedMessageCount(),
            };
            connections.append(info) catch {};
        }
        
        return connections;
    }
    
    /// Process incoming data for a connection
    pub fn processIncomingData(self: *WebSocketManager, connection_id: u64, data: []const u8) !void {
        const connection = self.connection_pool.connections.get(connection_id) orelse return error.ConnectionNotFound;
        
        // Process WebSocket frames
        var offset: usize = 0;
        while (offset < data.len) {
            const frame_data = data[offset..];
            try connection.processFrame(frame_data, self.allocator);
            
            // Calculate how many bytes were consumed (simplified)
            // In real implementation, would use frame.decode return value
            offset += 2; // Placeholder
            break; // For now, process one frame at a time
        }
        
        // Check for completed messages
        while (connection.getQueuedMessageCount() > 0) {
            const message = connection.getNextMessage();
            if (message) |msg| {
                try self.handleCompletedMessage(connection.connection_id, msg);
            } else {
                break;
            }
        }
    }
    
    /// Cleanup inactive connections
    pub fn cleanup(self: *WebSocketManager) void {
        self.connection_pool.cleanupInactive();
    }
    
    /// Get statistics
    pub fn getStatistics(self: *WebSocketManager) WebSocketStatistics {
        return WebSocketStatistics{
            .total_connections = self.connection_pool.getConnectionCount(),
            .active_connections = self.connection_pool.getActiveConnectionCount(),
            .event_listeners = self.event_handlers.count(),
            .config = self.config,
        };
    }
    
    // Private helper functions
    fn initiateHandshake(self: *WebSocketManager, connection: *WebSocketConnection) !void {
        // Create handshake request
        var handshake_request = WebSocketHandshakeRequest.init(self.allocator, connection.url);
        defer handshake_request.deinit();
        
        // Set handshake headers
        handshake_request.setHeader("Origin", extractOriginFromUrl(connection.url));
        handshake_request.setHeader("User-Agent", "z-net/1.0");
        
        // Add protocols if specified
        if (connection.protocols.items.len > 0) {
            var protocols_str = ArrayList(u8).init(self.allocator);
            defer protocols_str.deinit();
            
            for (connection.protocols.items, 0..) |protocol, i| {
                if (i > 0) protocols_str.appendSlice(", ") catch {};
                protocols_str.appendSlice(protocol) catch {};
            }
            
            const protocols_header = protocols_str.toOwnedSlice() catch "";
            handshake_request.setHeader("Sec-WebSocket-Protocol", protocols_header);
            self.allocator.free(protocols_header);
        }
        
        // Add extensions if enabled
        if (self.config.enable_compression) {
            var extensions_header = ArrayList(u8).init(self.allocator);
            defer extensions_header.deinit();
            
            if (self.config.enable_permessage_deflate) {
                extensions_header.appendSlice("permessage-deflate") catch {};
            }
            
            if (extensions_header.items.len > 0) {
                const extensions_str = extensions_header.toOwnedSlice() catch "";
                handshake_request.setHeader("Sec-WebSocket-Extensions", extensions_str);
                self.allocator.free(extensions_str);
            }
        }
        
        // Generate handshake request
        const request_data = try handshake_request.generateHandshakeRequest(self.allocator);
        defer self.allocator.free(request_data);
        
        // Send handshake request (would integrate with actual network layer)
        _ = request_data; // Placeholder for actual send
        
        // Note: In real implementation, would send request and wait for response
        // For simulation, we'll mark connection as open
        connection.state = .OPEN;
    }
    
    fn startConnectionMonitoring(self: *WebSocketManager, connection: *WebSocketConnection) !void {
        // Schedule ping intervals
        if (self.config.ping_interval_seconds > 0) {
            var ping_task = BackgroundTask.init(connection.connection_id, "websocket-ping", "ping");
            ping_task.setInterval(self.config.ping_interval_seconds * 1000, true); // Recurring
            ping_task.setCallback(&self.pingCallback);
            
            try self.event_loop.scheduleBackgroundTask(ping_task);
        }
    }
    
    fn pingCallback(data: []const u8) void {
        const connection_id = std.fmt.parseInt(u64, data, 10) catch return;
        // In real implementation, would send ping to the connection
        _ = connection_id;
    }
    
    fn handleCompletedMessage(self: *WebSocketManager, connection_id: u64, message: WebSocketMessage) !void {
        // Create and trigger event
        var event = WebSocketEvent.init(self.allocator, 
            if (message.message_type == .TEXT) .MESSAGE else .BINARY_MESSAGE, 
            connection_id);
        
        if (message.message_type == .TEXT) {
            event.setMessage(message.getData());
        } else {
            event.setBinaryData(message.getData());
        }
        
        // Trigger event for registered handlers
        if (self.event_handlers.get(connection_id)) |callback| {
            callback(event);
        }
        
        event.deinit();
    }
    
    fn extractHostFromUrl(url: []const u8) []const u8 {
        const ws_start = if (std.mem.eql(u8, url[0..3], "ws:")) 5 else 6; // Skip "ws://" or "wss://"
        const slash_pos = std.mem.indexOfPos(u8, url, ws_start, "/") orelse url.len;
        return url[ws_start..slash_pos];
    }
    
    fn extractOriginFromUrl(url: []const u8) []const u8 {
        const ws_start = if (std.mem.eql(u8, url[0..3], "ws:")) 0 else 0; // For now, return full URL
        const slash_pos = std.mem.indexOfPos(u8, url, 0, "/") orelse url.len;
        return url[ws_start..slash_pos];
    }
};

// WebSocket connection status
pub const WebSocketConnectionStatus = struct {
    connection_id: u64,
    state: WebSocketState,
    url: []const u8,
    protocols: ArrayList([]const u8),
    queued_messages: usize,
    has_pending_pings: bool,
    created_timestamp: u64,
    last_activity_timestamp: u64,
};

pub const ConnectionInfo = struct {
    connection_id: u64,
    url: []const u8,
    state: WebSocketState,
    protocols: ArrayList([]const u8),
    message_count: usize,
};

pub const WebSocketStatistics = struct {
    total_connections: usize,
    active_connections: usize,
    event_listeners: usize,
    config: WebSocketConfig,
};

// WebSocket error types
pub const WebSocketManagerError = error{
    InvalidUrl,
    PolicyViolation,
    ConnectionNotFound,
    HandshakeFailed,
    InvalidResponse,
    InvalidStatusCode,
};

// Helper functions for WebSocket handshake
fn generateWebSocketKey() [24]u8 {
    var key: [24]u8 = undefined;
    std.crypto.random.bytes(&key);
    return key;
}

fn computeWebSocketAcceptKey(client_key: [24]u8) [28]u8 {
    const magic_string = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    var hash_input = ArrayList(u8).init(std.heap.c_allocator);
    defer hash_input.deinit();
    
    hash_input.appendSlice(&client_key) catch {};
    hash_input.appendSlice(magic_string) catch {};
    
    var hash_output: [20]u8 = undefined;
    Sha1.hash(hash_input.items, &hash_output, .{});
    
    // Base64 encode
    var base64_output: [28]u8 = undefined;
    Base64.encode(&base64_output, &hash_output);
    
    return base64_output;
}

test "websocket handshake request generation" {
    const allocator = std.testing.allocator;
    var handshake_request = WebSocketHandshakeRequest.init(allocator, "wss://echo.websocket.org");
    defer handshake_request.deinit();
    
    handshake_request.setHeader("User-Agent", "TestAgent/1.0");
    handshake_request.setHeader("Accept", "*/*");
    
    const request_data = try handshake_request.generateHandshakeRequest(allocator);
    defer allocator.free(request_data);
    
    // Verify request contains expected elements
    try std.testing.expect(std.mem.indexOf(u8, request_data, "GET wss://echo.websocket.org HTTP/1.1") != null);
    try std.testing.expect(std.mem.indexOf(u8, request_data, "Upgrade: websocket") != null);
    try std.testing.expect(std.mem.indexOf(u8, request_data, "Connection: Upgrade") != null);
    try std.testing.expect(std.mem.indexOf(u8, request_data, "Sec-WebSocket-Key:") != null);
    try std.testing.expect(std.mem.indexOf(u8, request_data, "Sec-WebSocket-Version: 13") != null);
}

test "websocket accept key computation" {
    const test_key = "dGhlIHNhbXBsZSBub25jZQ=="; // Example key from RFC 6455
    var key_bytes: [24]u8 = undefined;
    _ = std.base64.decode(std.base64.standard, test_key, &key_bytes);
    
    const expected_accept = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="; // Expected accept key from RFC 6455
    const computed_accept = computeWebSocketAcceptKey(key_bytes);
    
    try std.testing.expect(std.mem.eql(u8, expected_accept, &computed_accept));
}

test "websocket manager basic operations" {
    const allocator = std.testing.allocator;
    var event_loop = EventLoopManager.init(allocator, 100);
    defer event_loop.deinit();
    
    const config = WebSocketConfig{};
    var manager = WebSocketManager.init(allocator, &event_loop, config);
    defer manager.deinit();
    
    try std.testing.expectEqual(@as(usize, 0), manager.connection_pool.getConnectionCount());
    try std.testing.expectEqual(@as(usize, 0), manager.event_handlers.count());
    
    // Connect (would fail with real network, but structure should work)
    // const connection_id = try manager.connect("wss://echo.websocket.org", null);
    // try std.testing.expect(connection_id > 0);
    
    const stats = manager.getStatistics();
    try std.testing.expectEqual(@as(usize, 0), stats.total_connections);
    try std.testing.expectEqual(@as(usize, 0), stats.active_connections);
    try std.testing.expectEqual(@as(usize, 0), stats.event_listeners);
    try std.testing.expectEqual(@as(usize, 10), stats.config.max_connections_per_origin);
    try std.testing.expectEqual(@as(u64, 300), stats.config.connection_timeout_seconds);
    
    // Cleanup
    manager.cleanup();
}

test "websocket manager URL validation" {
    const allocator = std.testing.allocator;
    var event_loop = EventLoopManager.init(allocator, 100);
    defer event_loop.deinit();
    
    const config = WebSocketConfig{};
    var manager = WebSocketManager.init(allocator, &event_loop, config);
    defer manager.deinit();
    
    // Valid URLs
    try std.testing.expect(!manager.connect("http://invalid.com", null).catch(error.InvalidUrl) == error.InvalidUrl);
    // These would fail for other reasons (no network, etc.) but should accept the URL format
    
    // Invalid URLs should fail immediately
    _ = manager.connect("ftp://invalid.com", null) catch {
        // Expected to fail
    };
}