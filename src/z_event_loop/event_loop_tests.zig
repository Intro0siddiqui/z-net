//! z_event_loop - Comprehensive Tests
//! 
//! Comprehensive test suite for the Event Loop Integration system
//! covering Web API bridges, promise resolution, and event handling.

const std = @import("std");
const testing = std.testing;

const event_loop = @import("event_loop.zig");
const web_api = @import("web_api_integration.zig");
const main = @import("event_loop_main.zig");
const policy = @import("z_policy/policy.zig");

// usingnamespace event_loop;
// usingnamespace web_api;
// usingnamespace main;
// usingnamespace policy;

test "event loop manager basic operations" {
    const allocator = testing.allocator;
    var event_loop = EventLoopManager.init(allocator, 100);
    defer event_loop.deinit();
    
    try testing.expect(!event_loop.is_running);
    try testing.expectEqual(@as(usize, 0), event_loop.task_queue.current_size);
    try testing.expectEqual(@as(usize, 100), event_loop.task_queue.max_size);
    
    // Start event loop
    try event_loop.start();
    try testing.expect(event_loop.is_running);
    
    // Stop event loop
    event_loop.stop();
    try testing.expect(!event_loop.is_running);
}

test "webSocket event handler lifecycle" {
    const allocator = testing.allocator;
    var event_loop = EventLoopManager.init(allocator, 100);
    defer event_loop.deinit();
    
    const handler = try event_loop.createWebSocketHandler();
    defer event_loop.allocator.destroy(handler);
    
    try testing.expect(!handler.is_open);
    try testing.expect(handler.connection_id > 0);
    
    // Simulate connection open
    handler.handleOpen();
    try testing.expect(handler.is_open);
    
    // Simulate message
    handler.handleMessage("Hello WebSocket!");
    
    // Simulate connection close
    handler.handleClose(1000, "Normal closure");
    try testing.expect(!handler.is_open);
}

test "xmlHttpRequest event handler ready states" {
    const allocator = testing.allocator;
    var event_loop = EventLoopManager.init(allocator, 100);
    defer event_loop.deinit();
    
    const handler = try event_loop.createXMLHttpRequestHandler();
    defer event_loop.allocator.destroy(handler);
    
    try testing.expectEqual(ReadyState.UNSENT, handler.ready_state);
    try testing.expectEqual(@as(u16, 0), handler.status_code);
    
    // Test ready state progression
    handler.setReadyState(.OPENED);
    try testing.expectEqual(ReadyState.OPENED, handler.ready_state);
    
    handler.setReadyState(.HEADERS_RECEIVED);
    try testing.expectEqual(ReadyState.HEADERS_RECEIVED, handler.ready_state);
    
    handler.setReadyState(.LOADING);
    try testing.expectEqual(ReadyState.LOADING, handler.ready_state);
    
    handler.setReadyState(.DONE);
    try testing.expectEqual(ReadyState.DONE, handler.ready_state);
    
    // Test status and response
    handler.setStatus(200);
    handler.setResponseData("{\"success\": true}");
    handler.addHeader("Content-Type", "application/json");
    
    try testing.expectEqual(@as(u16, 200), handler.status_code);
    try testing.expect(std.mem.eql(u8, "{\"success\": true}", handler.response_data));
    try testing.expect(handler.headers.get("Content-Type") != null);
}

test "fetch event handler workflow" {
    const allocator = testing.allocator;
    var event_loop = EventLoopManager.init(allocator, 100);
    defer event_loop.deinit();
    
    const handler = try event_loop.createFetchHandler("https://api.example.com/data", "POST");
    defer event_loop.allocator.destroy(handler);
    
    try testing.expect(std.mem.eql(u8, "https://api.example.com/data", handler.url));
    try testing.expect(std.mem.eql(u8, "POST", handler.method));
    try testing.expectEqual(@as(u16, 0), handler.status_code);
    
    // Set request body
    handler.setRequestBody("{\"key\": \"value\"}");
    try testing.expect(handler.body != null);
    try testing.expect(handler.headers.get("Content-Length") != null);
    
    // Simulate response
    var response_headers = StringHashMap([]const u8).init(allocator);
    defer response_headers.deinit();
    response_headers.put("Content-Type", "application/json") catch {};
    response_headers.put("Content-Length", "15") catch {};
    
    handler.setResponse(200, "OK", "{\"result\": \"success\"}", response_headers);
    
    try testing.expectEqual(@as(u16, 200), handler.status_code);
    try testing.expect(std.mem.eql(u8, "OK", handler.status_text));
    try testing.expect(handler.response_data != null);
    try testing.expectEqual(@as(usize, 2), handler.response_headers.count());
}

test "background task scheduling and execution" {
    const allocator = testing.allocator;
    var event_loop = EventLoopManager.init(allocator, 100);
    defer event_loop.deinit();
    
    var task = BackgroundTask.init(1, "test-task", "test-data");
    task.setInterval(100, true); // 100ms interval, recurring
    
    try event_loop.scheduleBackgroundTask(task);
    try testing.expectEqual(@as(usize, 1), event_loop.background_tasks.count());
    
    // Initially not due
    try testing.expect(!task.isDue());
    
    // Simulate time passing (would be tested with actual timing in real implementation)
    // For now, just verify the task was scheduled correctly
    event_loop.cancelBackgroundTask(1);
    try testing.expectEqual(@as(usize, 0), event_loop.background_tasks.count());
}

test "promise integration lifecycle" {
    const allocator = testing.allocator;
    var event_loop = EventLoopManager.init(allocator, 100);
    defer event_loop.deinit();
    
    var promise_integration = PromiseIntegration.init(allocator, &event_loop);
    defer promise_integration.deinit();
    
    // Create promise
    const promise_id = promise_integration.createPromise();
    try testing.expect(promise_id > 0);
    try testing.expect(promise_integration.pending_promises.contains(promise_id));
    
    // Resolve promise
    try promise_integration.resolvePromise(promise_id, "success data");
    try testing.expect(!promise_integration.pending_promises.contains(promise_id));
    
    // Create and reject promise
    const promise_id2 = promise_integration.createPromise();
    try promise_integration.rejectPromise(promise_id2, "error message");
    try testing.expect(!promise_integration.pending_promises.contains(promise_id2));
}

test "fetch integration workflow" {
    const allocator = testing.allocator;
    var event_loop = EventLoopManager.init(allocator, 100);
    defer event_loop.deinit();
    
    var fetch_integration = FetchIntegration.init(allocator, &event_loop);
    defer fetch_integration.deinit();
    
    var headers = StringHashMap([]const u8).init(allocator);
    defer headers.deinit();
    
    headers.put("Content-Type", "application/json") catch {};
    headers.put("Accept", "application/json") catch {};
    
    // Execute fetch
    const fetch_id = try fetch_integration.executeFetch("https://api.example.com/data", "GET", headers, null);
    try testing.expect(fetch_id > 0);
    try testing.expect(fetch_integration.active_fetches.contains(fetch_id));
    
    // Get result (should be null until completed)
    const result = fetch_integration.getFetchResult(fetch_id);
    try testing.expect(result == null); // Not completed yet
    
    // Cancel fetch
    try fetch_integration.cancelFetch(fetch_id);
    try testing.expect(!fetch_integration.active_fetches.contains(fetch_id));
}

test "webSocket integration lifecycle" {
    const allocator = testing.allocator;
    var event_loop = EventLoopManager.init(allocator, 100);
    defer event_loop.deinit();
    
    var ws_integration = WebSocketIntegration.init(allocator, &event_loop);
    defer ws_integration.deinit();
    
    var protocols = ArrayList([]const u8).init(allocator);
    defer protocols.deinit();
    protocols.append("chat") catch {};
    
    // Connect WebSocket
    const connection_id = try ws_integration.connectWebSocket("wss://echo.websocket.org", protocols);
    try testing.expect(connection_id > 0);
    try testing.expect(ws_integration.active_connections.contains(connection_id));
    
    // Send message
    try ws_integration.sendWebSocketMessage(connection_id, "Hello WebSocket!");
    
    // Close connection
    try ws_integration.closeWebSocket(connection_id, 1000, "Normal closure");
    try testing.expect(!ws_integration.active_connections.contains(connection_id));
}

test "xmlHttpRequest integration workflow" {
    const allocator = testing.allocator;
    var event_loop = EventLoopManager.init(allocator, 100);
    defer event_loop.deinit();
    
    var xhr_integration = XMLHttpRequestIntegration.init(allocator, &event_loop);
    defer xhr_integration.deinit();
    
    // Create XMLHttpRequest
    const request_id = try xhr_integration.executeXMLHttpRequest("https://api.example.com/data", "POST", true);
    try testing.expect(request_id > 0);
    try testing.expect(xhr_integration.active_requests.contains(request_id));
    
    // Set headers
    try xhr_integration.setRequestHeader(request_id, "Content-Type", "application/json");
    try xhr_integration.setRequestHeader(request_id, "Authorization", "Bearer token123");
    
    // Send body
    try xhr_integration.sendRequestBody(request_id, "{\"key\": \"value\"}");
    
    // Abort request
    try xhr_integration.abortRequest(request_id);
    try testing.expect(!xhr_integration.active_requests.contains(request_id));
}

test "background sync integration" {
    const allocator = testing.allocator;
    var event_loop = EventLoopManager.init(allocator, 100);
    defer event_loop.deinit();
    
    var background_sync = BackgroundSyncIntegration.init(allocator, &event_loop);
    defer background_sync.deinit();
    
    // Schedule background sync
    const sync_id = try background_sync.scheduleSync("data-sync", "sync-data", 5000);
    try testing.expect(sync_id > 0);
    try testing.expect(background_sync.sync_tasks.contains(sync_id));
    
    // Cancel background sync
    try background_sync.cancelSync(sync_id);
    try testing.expect(!background_sync.sync_tasks.contains(sync_id));
}

test "browser event loop comprehensive test" {
    const allocator = testing.allocator;
    const policy_config = getDefaultPolicyConfig();
    
    var event_loop = try BrowserEventLoop.init(allocator, policy_config);
    defer event_loop.deinit();
    
    try testing.expect(!event_loop.is_initialized);
    
    // Initialize
    try event_loop.initialize();
    try testing.expect(event_loop.is_initialized);
    
    // Test status
    const status = event_loop.getStatus();
    try testing.expect(status.is_initialized);
    try testing.expect(status.is_running);
    try testing.expectEqual(@as(usize, 0), status.active_connections);
    try testing.expectEqual(@as(usize, 0), status.pending_operations);
    
    // Test statistics
    const stats = event_loop.getStatistics();
    try testing.expectEqual(@as(usize, 0), stats.active_fetches);
    try testing.expectEqual(@as(usize, 0), stats.active_websockets);
    try testing.expectEqual(@as(usize, 0), stats.active_xhr);
    try testing.expectEqual(@as(usize, 0), stats.pending_promises);
    try testing.expectEqual(@as(usize, 0), stats.background_syncs);
    try testing.expect(stats.event_loop.is_running);
    
    // Test CORS configuration
    var cors_options = CORSOptions.init(allocator);
    defer cors_options.deinit();
    
    cors_options.origin = "https://api.example.com";
    cors_options.addMethod(.GET);
    cors_options.addMethod(.POST);
    try event_loop.configureCORS("https://api.example.com", cors_options);
    
    // Test CSP policy
    try event_loop.addCSPPolicy("https://example.com", "default-src 'self'");
    
    // Test whitelist origin
    try event_loop.addWhitelistOrigin("https://trusted-site.com");
    
    // Test event loop cycles
    try event_loop.processCycle();
    
    // Test clear caches
    event_loop.clearCaches();
    
    // Stop event loop
    event_loop.stop();
    try testing.expect(!event_loop.is_initialized);
}

test "policy integration with event loop" {
    const allocator = testing.allocator;
    const policy_config = getDefaultPolicyConfig();
    
    var event_loop = try BrowserEventLoop.init(allocator, policy_config);
    defer event_loop.deinit();
    
    try event_loop.initialize();
    
    // Test CORS integration
    var cors_options = CORSOptions.init(allocator);
    defer cors_options.deinit();
    
    cors_options.origin = "https://api.example.com";
    cors_options.addMethod(.GET);
    cors_options.addMethod(.POST);
    cors_options.addHeader("Content-Type");
    cors_options.credentials = true;
    
    try event_loop.configureCORS("https://api.example.com", cors_options);
    
    // Test CSP integration
    const csp_policy = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' https://fonts.googleapis.com";
    try event_loop.addCSPPolicy("https://example.com", csp_policy);
    
    // Test whitelist integration
    try event_loop.addWhitelistOrigin("https://trusted-partner.com");
    
    // Verify policy manager integration
    const stats = event_loop.getStatistics();
    try testing.expect(stats.policy_engine.csp_policies > 0);
    
    // Test cache integration
    event_loop.clearCaches();
}

test "task queue operations" {
    const allocator = testing.allocator;
    var task_queue = TaskQueue.init(allocator, 5);
    defer task_queue.deinit();
    
    try testing.expectEqual(@as(usize, 0), task_queue.current_size);
    try testing.expectEqual(@as(usize, 5), task_queue.max_size);
    
    // Enqueue tasks
    var resolver1 = PromiseResolver.init();
    var resolver2 = PromiseResolver.init();
    
    try task_queue.enqueue(resolver1);
    try testing.expectEqual(@as(usize, 1), task_queue.current_size);
    
    try task_queue.enqueue(resolver2);
    try testing.expectEqual(@as(usize, 2), task_queue.current_size);
    
    // Dequeue tasks
    const dequeued1 = task_queue.dequeue();
    try testing.expect(dequeued1 != null);
    try testing.expectEqual(@as(usize, 1), task_queue.current_size);
    
    const dequeued2 = task_queue.dequeue();
    try testing.expect(dequeued2 != null);
    try testing.expectEqual(@as(usize, 0), task_queue.current_size);
    
    // Queue should be empty now
    const dequeued3 = task_queue.dequeue();
    try testing.expect(dequeued3 == null);
}

test "event metadata handling" {
    const allocator = testing.allocator;
    
    var event = WebAPIEvent.init(allocator, .MESSAGE, 123);
    defer event.deinit();
    
    try testing.expectEqual(EventType.MESSAGE, event.event_type);
    try testing.expectEqual(@as(u64, 123), event.source_id);
    try testing.expectEqual(EventPriority.NORMAL, event.priority);
    try testing.expect(event.data == null);
    try testing.expectEqual(@as(usize, 0), event.metadata.count());
    
    // Set data
    event.setData("Test message");
    try testing.expect(event.data != null);
    try testing.expect(std.mem.eql(u8, "Test message", event.data.?));
    
    // Set priority
    event.setPriority(.HIGH);
    try testing.expectEqual(EventPriority.HIGH, event.priority);
    
    // Add metadata
    event.addMetadata("type", "test");
    event.addMetadata("count", "42");
    
    try testing.expectEqual(@as(usize, 2), event.metadata.count());
    try testing.expect(event.metadata.get("type") != null);
    try testing.expect(event.metadata.get("count") != null);
    try testing.expect(std.mem.eql(u8, "test", event.metadata.get("type").?));
    try testing.expect(std.mem.eql(u8, "42", event.metadata.get("count").?));
}

test "event loop integration patterns" {
    const allocator = testing.allocator;
    var event_loop = EventLoopManager.init(allocator, 100);
    defer event_loop.deinit();
    
    // Test multiple handler creation
    const ws_handler = try event_loop.createWebSocketHandler();
    defer event_loop.allocator.destroy(ws_handler);
    
    const xhr_handler = try event_loop.createXMLHttpRequestHandler();
    defer event_loop.allocator.destroy(xhr_handler);
    
    const fetch_handler = try event_loop.createFetchHandler("https://example.com", "GET");
    defer event_loop.allocator.destroy(fetch_handler);
    
    // Verify all handlers have unique IDs
    try testing.expect(ws_handler.connection_id != xhr_handler.request_id);
    try testing.expect(xhr_handler.request_id != fetch_handler.fetch_id);
    try testing.expect(ws_handler.connection_id != fetch_handler.fetch_id);
    
    // Test event loop statistics
    const stats = event_loop.getStats();
    try testing.expect(stats.active_event_handlers >= 3);
    try testing.expect(stats.next_source_id > 3);
    
    // Test background task scheduling
    var task1 = BackgroundTask.init(1, "test-1", "data-1");
    var task2 = BackgroundTask.init(2, "test-2", "data-2");
    
    try event_loop.scheduleBackgroundTask(task1);
    try event_loop.scheduleBackgroundTask(task2);
    
    try testing.expectEqual(@as(usize, 2), event_loop.background_tasks.count());
}