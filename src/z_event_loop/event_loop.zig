//! z_event_loop - Web API Event Loop Integration
//! 
//! Integrates Web APIs with z-net's async event system using tokio.
//! Provides bridges for WebSocket, XMLHttpRequest, Fetch, Service Workers,
//! and Promise/callback systems.

const std = @import("std");
const Allocator = std.mem.Allocator;
const AutoHashMap = std.AutoHashMap;
const StringHashMap = std.StringHashMap;
const ArrayList = std.ArrayList;
const AsyncEvent = std.event.Loop;
const Task = std.Thread.Futex;

const policy_engine = @import("z_policy/policy_engine.zig");
const policy = @import("z_policy/policy.zig");

usingnamespace policy_engine;

pub const EventType = enum {
    TIMEOUT,
    INTERVAL,
    READY_STATE_CHANGE,
    LOAD,
    ERROR,
    ABORT,
    PROGRESS,
    MESSAGE,
    OPEN,
    CLOSE,
    MESSAGE_ERROR,
    FETCH,
    PROMISE,
    CALLBACK,
    BACKGROUND_SYNC,
}

pub const EventPriority = enum(u2) {
    LOW = 0,
    NORMAL = 1,
    HIGH = 2,
    CRITICAL = 3,
}

pub const WebAPIEvent = struct {
    event_type: EventType,
    event_id: u64,
    source_id: u64,
    priority: EventPriority,
    data: ?[]const u8,
    timestamp: u64,
    metadata: StringHashMap([]const u8),
    
    pub fn init(allocator: Allocator, event_type: EventType, source_id: u64) WebAPIEvent {
        return WebAPIEvent{
            .event_type = event_type,
            .event_id = generateEventId(),
            .source_id = source_id,
            .priority = .NORMAL,
            .data = null,
            .timestamp = getCurrentTimestamp(),
            .metadata = StringHashMap([]const u8).init(allocator),
        };
    }
    
    pub fn deinit(self: *WebAPIEvent) void {
        self.metadata.deinit();
    }
    
    pub fn setData(inout self: WebAPIEvent, data: []const u8) void {
        self.data = data;
    }
    
    pub fn setPriority(inout self: WebAPIEvent, priority: EventPriority) void {
        self.priority = priority;
    }
    
    pub fn addMetadata(inout self: WebAPIEvent, key: []const u8, value: []const u8) void {
        self.metadata.put(key, value) catch {};
    }
};

pub const PromiseResolver = struct {
    resolve_callback: ?*const fn (?[]const u8) void,
    reject_callback: ?*const fn ([]const u8) void,
    state: PromiseState,
    
    pub fn init() PromiseResolver {
        return PromiseResolver{
            .resolve_callback = null,
            .reject_callback = null,
            .state = .PENDING,
        };
    }
    
    pub fn setResolveCallback(inout self: *PromiseResolver, callback: *const fn (?[]const u8) void) void {
        self.resolve_callback = callback;
    }
    
    pub fn setRejectCallback(inout self: *PromiseResolver, callback: *const fn ([]const u8) void) void {
        self.reject_callback = callback;
    }
    
    pub fn resolve(self: *PromiseResolver, data: ?[]const u8) void {
        if (self.resolve_callback) |callback| {
            callback(data);
            self.state = .FULFILLED;
        }
    }
    
    pub fn reject(self: *PromiseResolver, error: []const u8) void {
        if (self.reject_callback) |callback| {
            callback(error);
            self.state = .REJECTED;
        }
    }
};

pub const PromiseState = enum {
    PENDING,
    FULFILLED,
    REJECTED,
};

pub const TaskQueue = struct {
    tasks: ArrayList(PromiseResolver),
    max_size: usize,
    current_size: usize,
    
    pub fn init(allocator: Allocator, max_size: usize) TaskQueue {
        return TaskQueue{
            .tasks = ArrayList(PromiseResolver).init(allocator),
            .max_size = max_size,
            .current_size = 0,
        };
    }
    
    pub fn deinit(self: *TaskQueue) void {
        self.tasks.deinit();
    }
    
    pub fn enqueue(inout self: *TaskQueue, resolver: PromiseResolver) !void {
        if (self.current_size >= self.max_size) {
            return error.QueueFull;
        }
        
        self.tasks.append(resolver) catch {};
        self.current_size += 1;
    }
    
    pub fn dequeue(inout self: *TaskQueue) ?PromiseResolver {
        if (self.tasks.items.len == 0) {
            return null;
        }
        
        const resolver = self.tasks.orderedRemove(0);
        self.current_size -= 1;
        return resolver;
    }
    
    pub fn peek(inout self: *TaskQueue) ?*PromiseResolver {
        if (self.tasks.items.len == 0) {
            return null;
        }
        
        return &self.tasks.items[0];
    }
};

pub const BackgroundTask = struct {
    task_id: u64,
    task_type: []const u8,
    data: []const u8,
    scheduled_time: u64,
    interval: u64,
    recurring: bool,
    callback: ?*const fn ([]const u8) void,
    
    pub fn init(task_id: u64, task_type: []const u8, data: []const u8) BackgroundTask {
        return BackgroundTask{
            .task_id = task_id,
            .task_type = task_type,
            .data = data,
            .scheduled_time = getCurrentTimestamp(),
            .interval = 0,
            .recurring = false,
            .callback = null,
        };
    }
    
    pub fn setInterval(inout self: *BackgroundTask, interval_ms: u64, recurring: bool) void {
        self.interval = interval_ms;
        self.recurring = recurring;
        self.scheduled_time = getCurrentTimestamp() + interval_ms;
    }
    
    pub fn setCallback(inout self: *BackgroundTask, callback: *const fn ([]const u8) void) void {
        self.callback = callback;
    }
    
    pub fn isDue(self: *BackgroundTask) bool {
        return getCurrentTimestamp() >= self.scheduled_time;
    }
    
    pub fn execute(inout self: *BackgroundTask) void {
        if (self.callback) |callback| {
            callback(self.data);
        }
        
        if (self.recurring) {
            self.scheduled_time = getCurrentTimestamp() + self.interval;
        }
    }
};

pub const WebSocketEventHandler = struct {
    connection_id: u64,
    event_callbacks: AutoHashMap(EventType, *const fn (WebAPIEvent) void),
    message_queue: ArrayList([]const u8),
    is_open: bool,
    
    pub fn init(allocator: Allocator, connection_id: u64) WebSocketEventHandler {
        return WebSocketEventHandler{
            .connection_id = connection_id,
            .event_callbacks = AutoHashMap(EventType, *const fn (WebAPIEvent) void).init(allocator),
            .message_queue = ArrayList([]const u8).init(allocator),
            .is_open = false,
        };
    }
    
    pub fn deinit(self: *WebSocketEventHandler) void {
        self.event_callbacks.deinit();
        self.message_queue.deinit();
    }
    
    pub fn setEventCallback(inout self: *WebSocketEventHandler, event_type: EventType, callback: *const fn (WebAPIEvent) void) void {
        self.event_callbacks.put(event_type, callback) catch {};
    }
    
    pub fn handleOpen(inout self: *WebSocketEventHandler) void {
        self.is_open = true;
        var event = WebAPIEvent.init(std.heap.c_allocator, .OPEN, self.connection_id);
        event.setData("WebSocket connection opened");
        
        if (self.event_callbacks.get(.OPEN)) |callback| {
            callback(event);
        }
        
        event.deinit();
    }
    
    pub fn handleClose(inout self: *WebSocketEventHandler, code: u16, reason: []const u8) void {
        self.is_open = false;
        var event = WebAPIEvent.init(std.heap.c_allocator, .CLOSE, self.connection_id);
        
        var metadata_str = std.fmt.allocPrint(std.heap.c_allocator, "code={},reason={}", .{ code, reason }) catch "";
        event.setData(metadata_str);
        event.addMetadata("code", std.fmt.allocPrint(std.heap.c_allocator, "{}", .{code}) catch "");
        event.addMetadata("reason", reason);
        
        if (self.event_callbacks.get(.CLOSE)) |callback| {
            callback(event);
        }
        
        event.deinit();
    }
    
    pub fn handleMessage(inout self: *WebSocketEventHandler, message: []const u8) void {
        var event = WebAPIEvent.init(std.heap.c_allocator, .MESSAGE, self.connection_id);
        event.setData(message);
        
        // Queue message for ordered delivery
        self.message_queue.append(message) catch {};
        
        if (self.event_callbacks.get(.MESSAGE)) |callback| {
            callback(event);
        }
        
        event.deinit();
    }
    
    pub fn handleError(inout self: *WebSocketEventHandler, error_message: []const u8) void {
        var event = WebAPIEvent.init(std.heap.c_allocator, .ERROR, self.connection_id);
        event.setData(error_message);
        event.setPriority(.CRITICAL);
        
        if (self.event_callbacks.get(.ERROR)) |callback| {
            callback(event);
        }
        
        event.deinit();
    }
};

pub const XMLHttpRequestEventHandler = struct {
    request_id: u64,
    ready_state: ReadyState,
    response_data: []const u8,
    status_code: u16,
    headers: StringHashMap([]const u8),
    callbacks: AutoHashMap(EventType, *const fn (WebAPIEvent) void),
    
    pub fn init(allocator: Allocator, request_id: u64) XMLHttpRequestEventHandler {
        return XMLHttpRequestEventHandler{
            .request_id = request_id,
            .ready_state = .UNSENT,
            .response_data = "",
            .status_code = 0,
            .headers = StringHashMap([]const u8).init(allocator),
            .callbacks = AutoHashMap(EventType, *const fn (WebAPIEvent) void).init(allocator),
        };
    }
    
    pub fn deinit(self: *XMLHttpRequestEventHandler) void {
        self.headers.deinit();
        self.callbacks.deinit();
    }
    
    pub fn setReadyState(inout self: *XMLHttpRequestEventHandler, ready_state: ReadyState) void {
        self.ready_state = ready_state;
        self.emitReadyStateChange();
    }
    
    pub fn setStatus(inout self: *XMLHttpRequestEventHandler, status_code: u16) void {
        self.status_code = status_code;
    }
    
    pub fn setResponseData(inout self: *XMLHttpRequestEventHandler, data: []const u8) void {
        self.response_data = data;
    }
    
    pub fn addHeader(inout self: *XMLHttpRequestEventHandler, name: []const u8, value: []const u8) void {
        self.headers.put(name, value) catch {};
    }
    
    pub fn setEventCallback(inout self: *XMLHttpRequestEventHandler, event_type: EventType, callback: *const fn (WebAPIEvent) void) void {
        self.callbacks.put(event_type, callback) catch {};
    }
    
    fn emitReadyStateChange(inout self: *XMLHttpRequestEventHandler) void {
        var event = WebAPIEvent.init(std.heap.c_allocator, .READY_STATE_CHANGE, self.request_id);
        event.setData(@tagName(self.ready_state));
        event.addMetadata("readyState", @tagName(self.ready_state));
        event.addMetadata("status", std.fmt.allocPrint(std.heap.c_allocator, "{}", .{self.status_code}) catch "");
        
        if (self.callbacks.get(.READY_STATE_CHANGE)) |callback| {
            callback(event);
        }
        
        event.deinit();
    }
    
    pub fn emitLoad(inout self: *XMLHttpRequestEventHandler) void {
        var event = WebAPIEvent.init(std.heap.c_allocator, .LOAD, self.request_id);
        event.setData(self.response_data);
        
        if (self.callbacks.get(.LOAD)) |callback| {
            callback(event);
        }
        
        event.deinit();
    }
    
    pub fn emitError(inout self: *XMLHttpRequestEventHandler, error_message: []const u8) void {
        var event = WebAPIEvent.init(std.heap.c_allocator, .ERROR, self.request_id);
        event.setData(error_message);
        event.setPriority(.HIGH);
        
        if (self.callbacks.get(.ERROR)) |callback| {
            callback(event);
        }
        
        event.deinit();
    }
};

pub const ReadyState = enum {
    UNSENT,
    OPENED,
    HEADERS_RECEIVED,
    LOADING,
    DONE,
};

pub const FetchEventHandler = struct {
    fetch_id: u64,
    url: []const u8,
    method: []const u8,
    headers: StringHashMap([]const u8),
    body: ?[]const u8,
    response_data: ?[]const u8,
    status_code: u16,
    status_text: []const u8,
    response_headers: StringHashMap([]const u8),
    callbacks: AutoHashMap(EventType, *const fn (WebAPIEvent) void),
    
    pub fn init(allocator: Allocator, fetch_id: u64, url: []const u8, method: []const u8) FetchEventHandler {
        var handler = FetchEventHandler{
            .fetch_id = fetch_id,
            .url = url,
            .method = method,
            .headers = StringHashMap([]const u8).init(allocator),
            .body = null,
            .response_data = null,
            .status_code = 0,
            .status_text = "",
            .response_headers = StringHashMap([]const u8).init(allocator),
            .callbacks = AutoHashMap(EventType, *const fn (WebAPIEvent) void).init(allocator),
        };
        
        // Set default headers
        handler.headers.put("User-Agent", "z-net/1.0") catch {};
        handler.headers.put("Accept", "*/*") catch {};
        
        return handler;
    }
    
    pub fn deinit(self: *FetchEventHandler) void {
        self.headers.deinit();
        self.response_headers.deinit();
        self.callbacks.deinit();
    }
    
    pub fn setRequestBody(inout self: *FetchEventHandler, body: []const u8) void {
        self.body = body;
        self.headers.put("Content-Length", std.fmt.allocPrint(std.heap.c_allocator, "{}", .{body.len}) catch "") catch {};
    }
    
    pub fn setResponse(inout self: *FetchEventHandler, status_code: u16, status_text: []const u8, response_data: []const u8, response_headers: StringHashMap([]const u8)) void {
        self.status_code = status_code;
        self.status_text = status_text;
        self.response_data = response_data;
        
        // Clear existing response headers
        self.response_headers.clear();
        
        // Copy response headers
        var headers_iter = response_headers.keyIterator();
        while (headers_iter.next()) |header_name| {
            const header_value = response_headers.get(header_name.*).?;
            self.response_headers.put(header_name.*, header_value) catch {};
        }
    }
    
    pub fn setEventCallback(inout self: *FetchEventHandler, event_type: EventType, callback: *const fn (WebAPIEvent) void) void {
        self.callbacks.put(event_type, callback) catch {};
    }
    
    pub fn emitProgress(inout self: *FetchEventHandler, loaded: u64, total: u64) void {
        var event = WebAPIEvent.init(std.heap.c_allocator, .PROGRESS, self.fetch_id);
        
        const progress_data = std.fmt.allocPrint(std.heap.c_allocator, "loaded={},total={}", .{ loaded, total }) catch "";
        event.setData(progress_data);
        event.addMetadata("loaded", std.fmt.allocPrint(std.heap.c_allocator, "{}", .{loaded}) catch "");
        event.addMetadata("total", std.fmt.allocPrint(std.heap.c_allocator, "{}", .{total}) catch "");
        
        if (self.callbacks.get(.PROGRESS)) |callback| {
            callback(event);
        }
        
        event.deinit();
    }
    
    pub fn emitLoad(inout self: *FetchEventHandler) void {
        var event = WebAPIEvent.init(std.heap.c_allocator, .LOAD, self.fetch_id);
        
        if (self.response_data) |data| {
            event.setData(data);
        }
        
        event.addMetadata("status", std.fmt.allocPrint(std.heap.c_allocator, "{}", .{self.status_code}) catch "");
        event.addMetadata("statusText", self.status_text);
        event.addMetadata("url", self.url);
        
        if (self.callbacks.get(.LOAD)) |callback| {
            callback(event);
        }
        
        event.deinit();
    }
    
    pub fn emitError(inout self: *FetchEventHandler, error_message: []const u8) void {
        var event = WebAPIEvent.init(std.heap.c_allocator, .ERROR, self.fetch_id);
        event.setData(error_message);
        event.setPriority(.HIGH);
        
        if (self.callbacks.get(.ERROR)) |callback| {
            callback(event);
        }
        
        event.deinit();
    }
    
    pub fn emitAbort(inout self: *FetchEventHandler) void {
        var event = WebAPIEvent.init(std.heap.c_allocator, .ABORT, self.fetch_id);
        event.setData("Request aborted");
        
        if (self.callbacks.get(.ABORT)) |callback| {
            callback(event);
        }
        
        event.deinit();
    }
};

/// Main Event Loop Manager
pub const EventLoopManager = struct {
    allocator: Allocator,
    task_queue: TaskQueue,
    background_tasks: AutoHashMap(u64, BackgroundTask),
    event_handlers: AutoHashMap(u64, *anyopaque), // Polymorphic handlers
    next_source_id: u64,
    is_running: bool,
    
    pub fn init(allocator: Allocator, max_queue_size: usize) EventLoopManager {
        return EventLoopManager{
            .allocator = allocator,
            .task_queue = TaskQueue.init(allocator, max_queue_size),
            .background_tasks = AutoHashMap(u64, BackgroundTask).init(allocator),
            .event_handlers = AutoHashMap(u64, *anyopaque).init(allocator),
            .next_source_id = 1,
            .is_running = false,
        };
    }
    
    pub fn deinit(self: *EventLoopManager) void {
        self.task_queue.deinit();
        
        var task_iter = self.background_tasks.valueIterator();
        while (task_iter.next()) |task| {
            // Tasks are stack allocated, no deinit needed
            _ = task;
        }
        self.background_tasks.deinit();
        self.event_handlers.deinit();
    }
    
    /// Start the event loop
    pub fn start(inout self: *EventLoopManager) !void {
        if (self.is_running) {
            return error.AlreadyRunning;
        }
        
        self.is_running = true;
        std.log.info("🌊 Event Loop Manager started", .{});
        
        // Start background task processing
        try self.processBackgroundTasks();
    }
    
    /// Stop the event loop
    pub fn stop(inout self: *EventLoopManager) void {
        self.is_running = false;
        std.log.info("🛑 Event Loop Manager stopped", .{});
    }
    
    /// Create a new WebSocket event handler
    pub fn createWebSocketHandler(inout self: *EventLoopManager) !*WebSocketEventHandler {
        const handler = try self.allocator.create(WebSocketEventHandler);
        const source_id = self.allocateSourceId();
        
        handler.* = WebSocketEventHandler.init(self.allocator, source_id);
        
        // Store handler for later retrieval
        const handler_ptr: *WebSocketEventHandler = handler;
        self.event_handlers.put(source_id, handler_ptr) catch {};
        
        return handler_ptr;
    }
    
    /// Create a new XMLHttpRequest event handler
    pub fn createXMLHttpRequestHandler(inout self: *EventLoopManager) !*XMLHttpRequestEventHandler {
        const handler = try self.allocator.create(XMLHttpRequestEventHandler);
        const source_id = self.allocateSourceId();
        
        handler.* = XMLHttpRequestEventHandler.init(self.allocator, source_id);
        
        const handler_ptr: *XMLHttpRequestEventHandler = handler;
        self.event_handlers.put(source_id, handler_ptr) catch {};
        
        return handler_ptr;
    }
    
    /// Create a new Fetch event handler
    pub fn createFetchHandler(inout self: *EventLoopManager, url: []const u8, method: []const u8) !*FetchEventHandler {
        const handler = try self.allocator.create(FetchEventHandler);
        const source_id = self.allocateSourceId();
        
        handler.* = FetchEventHandler.init(self.allocator, source_id, url, method);
        
        const handler_ptr: *FetchEventHandler = handler;
        self.event_handlers.put(source_id, handler_ptr) catch {};
        
        return handler_ptr;
    }
    
    /// Schedule a background task
    pub fn scheduleBackgroundTask(inout self: *EventLoopManager, task: BackgroundTask) !void {
        try self.background_tasks.put(task.task_id, task);
        std.log.info("📅 Background task scheduled: {} (ID: {})", .{ task.task_type, task.task_id });
    }
    
    /// Remove a background task
    pub fn cancelBackgroundTask(inout self: *EventLoopManager, task_id: u64) void {
        _ = self.background_tasks.remove(task_id);
        std.log.info("❌ Background task cancelled: {}", .{task_id});
    }
    
    /// Process task queue
    pub fn processTaskQueue(inout self: *EventLoopManager) !void {
        var processed_count: usize = 0;
        const max_process_per_cycle = 100; // Prevent blocking the loop
        
        while (processed_count < max_process_per_cycle) {
            const resolver = self.task_queue.dequeue() orelse break;
            
            // Process the resolver
            // This would typically call the actual promise resolution
            _ = resolver; // Avoid unused variable warning
            
            processed_count += 1;
        }
        
        if (processed_count > 0) {
            std.log.debug("⚡ Processed {} tasks from queue", .{processed_count});
        }
    }
    
    /// Process background tasks
    fn processBackgroundTasks(inout self: *EventLoopManager) !void {
        var task_iter = self.background_tasks.valueIterator();
        var to_reschedule = ArrayList(BackgroundTask).init(self.allocator);
        defer to_reschedule.deinit();
        
        while (task_iter.next()) |task| {
            if (task.isDue()) {
                task.execute();
                
                if (task.recurring) {
                    try to_reschedule.append(task.*);
                }
            }
        }
        
        // Reschedule recurring tasks
        for (to_reschedule.items) |task| {
            const new_task = BackgroundTask{
                .task_id = task.task_id,
                .task_type = task.task_type,
                .data = task.data,
                .scheduled_time = getCurrentTimestamp() + task.interval,
                .interval = task.interval,
                .recurring = task.recurring,
                .callback = task.callback,
            };
            
            try self.background_tasks.put(task.task_id, new_task);
        }
    }
    
    /// Get event loop statistics
    pub fn getStats(self: *EventLoopManager) EventLoopStats {
        return EventLoopStats{
            .task_queue_size = self.task_queue.current_size,
            .task_queue_capacity = self.task_queue.max_size,
            .background_task_count = self.background_tasks.count(),
            .active_event_handlers = self.event_handlers.count(),
            .next_source_id = self.next_source_id,
            .is_running = self.is_running,
        };
    }
    
    /// Allocate a new source ID
    fn allocateSourceId(inout self: *EventLoopManager) u64 {
        const id = self.next_source_id;
        self.next_source_id += 1;
        return id;
    }
};

pub const EventLoopStats = struct {
    task_queue_size: usize,
    task_queue_capacity: usize,
    background_task_count: usize,
    active_event_handlers: usize,
    next_source_id: u64,
    is_running: bool,
};

// Helper functions
fn generateEventId() u64 {
    var hasher = std.hash.Wyhash.init(0);
    hasher.update(&std.time.timestamp());
    return hasher.final();
}

fn getCurrentTimestamp() u64 {
    return std.time.timestamp();
}

test "event loop manager initialization" {
    const allocator = std.testing.allocator;
    var event_loop = EventLoopManager.init(allocator, 1000);
    defer event_loop.deinit();
    
    try std.testing.expect(!event_loop.is_running);
    try std.testing.expectEqual(@as(usize, 0), event_loop.task_queue.current_size);
    try std.testing.expectEqual(@as(usize, 1000), event_loop.task_queue.max_size);
}

test "background task scheduling" {
    const allocator = std.testing.allocator;
    var event_loop = EventLoopManager.init(allocator, 100);
    defer event_loop.deinit();
    
    var task = BackgroundTask.init(1, "test-task", "test-data");
    task.setInterval(1000, true); // 1 second interval, recurring
    
    try event_loop.scheduleBackgroundTask(task);
    
    try std.testing.expectEqual(@as(usize, 1), event_loop.background_tasks.count());
}

test "webSocket event handler" {
    const allocator = std.testing.allocator;
    var event_loop = EventLoopManager.init(allocator, 100);
    defer event_loop.deinit();
    
    const handler = try event_loop.createWebSocketHandler();
    defer event_loop.allocator.destroy(handler);
    
    try std.testing.expect(!handler.is_open);
    try std.testing.expect(handler.connection_id > 0);
}// ============================================================
// Rust Network Bridge Integration (Phase 2.3)
// ============================================================

/// Data callback from Rust layer - zero-copy slice creation
pub const RustDataCallback = struct {
    callback_fn: *const fn ([*]u8, usize) void,
    user_data: ?*anyopaque,
};

/// Callback registry for Rust network events
pub const RustCallbackRegistry = struct {
    allocator: Allocator,
    read_callbacks: AutoHashMap(ConnectionHandle, RustDataCallback),
    write_callbacks: AutoHashMap(ConnectionHandle, RustDataCallback),
    error_callbacks: AutoHashMap(ConnectionHandle, RustDataCallback),

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return Self{
            .allocator = allocator,
            .read_callbacks = AutoHashMap(ConnectionHandle, RustDataCallback).init(allocator),
            .write_callbacks = AutoHashMap(ConnectionHandle, RustDataCallback).init(allocator),
            .error_callbacks = AutoHashMap(ConnectionHandle, RustDataCallback).init(allocator),
        };
    }

    pub fn deinit(self: *Self) void {
        self.read_callbacks.deinit();
        self.write_callbacks.deinit();
        self.error_callbacks.deinit();
    }

    /// Register a read callback for a connection
    pub fn registerReadCallback(
        self: *Self,
        conn: ConnectionHandle,
        callback: *const fn ([*]u8, usize) void,
        user_data: ?*anyopaque,
    ) void {
        self.read_callbacks.put(conn, RustDataCallback{
            .callback_fn = callback,
            .user_data = user_data,
        }) catch {};
    }

    /// Invoke read callback with raw pointer (zero-copy slice)
    pub fn invokeReadCallback(
        self: *Self,
        conn: ConnectionHandle,
        data_ptr: [*]u8,
        data_len: usize,
    ) void {
        if (self.read_callbacks.get(conn)) |cb| {
            // Create slice directly from pointer - NO ALLOCATION
            cb.callback_fn(data_ptr[0..data_len], 0);
        }
    }
};

/// Rust event source for the event loop
pub const RustEventSource = struct {
    engine_handle: NetEngineHandle,
    allocator: Allocator,
    callback_registry: RustCallbackRegistry,

    const Self = @This();

    pub fn init(allocator: Allocator, engine: NetEngineHandle) Self {
        return Self{
            .engine_handle = engine,
            .allocator = allocator,
            .callback_registry = RustCallbackRegistry.init(allocator),
        };
    }

    pub fn deinit(self: *Self) void {
        self.callback_registry.deinit();
    }

    /// Poll Rust engine and dispatch events
    pub fn pollAndDispatch(self: *Self, timeout_ms: i32) !void {
        const ready_count = try network_bridge.poll(self.engine_handle, timeout_ms);
        
        // Process each ready event
        var i: i32 = 0;
        while (i < ready_count) : (i += 1) {
            // Find corresponding connection and invoke callback
            // This is where the zero-copy data flows from Rust to Zig
        }
    }

    /// Process received data through callback (zero-copy)
    pub fn processReceivedData(
        self: *Self,
        conn: ConnectionHandle,
        data: []u8,
    ) void {
        // Pass raw slice directly to callback - no copying
        self.callback_registry.invokeReadCallback(
            conn, 
            data.ptr, 
            data.len,
        );
    }
};