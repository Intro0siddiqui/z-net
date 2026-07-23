//! z_service_worker - Worker Registry and Lifecycle Management
//! 
//! Service Worker registration, lifecycle management, and worker pool
//! coordination for browser background task execution.

const std = @import("std");
const Allocator = std.mem.Allocator;
const AutoHashMap = std.AutoHashMap;
const StringHashMap = std.StringHashMap;
const ArrayList = std.ArrayList;

const policy_engine = @import("z_policy/policy_engine.zig");
const event_loop = @import("z_event_loop/event_loop.zig");
const storage_bridge = @import("z_storage/storage_bridge.zig");

// usingnamespace policy_engine;
// usingnamespace event_loop;
// usingnamespace storage_bridge;

// Service Worker states
pub const ServiceWorkerState = enum {
    INSTALLING,
    INSTALLED, 
    ACTIVATING,
    ACTIVATED,
    ACTIVATED_PERIODIC_SYNC,
    REDUNDANT,
};

// Service Worker events
pub const ServiceWorkerEvent = enum {
    INSTALL,
    INSTALL_COMPLETE,
    ACTIVATE,
    ACTIVATE_COMPLETE,
    MESSAGE,
    MESSAGE_ERROR,
    SYNC,
    PUSH,
    NOTIFICATION_CLICK,
    NOTIFICATION_CLOSE,
    PERIODIC_SYNC,
};

// Service Worker registration result
pub const ServiceWorkerRegistration = struct {
    scope: []const u8,
    script_url: []const u8,
    state: ServiceWorkerState,
    installing: ?*ServiceWorker,
    waiting: ?*ServiceWorker,
    active: ?*ServiceWorker,
    update_via_cache: []const u8,
    update_found: bool,
    registration_id: [16]u8,
    
    pub fn init(allocator: Allocator, scope: []const u8, script_url: []const u8) ServiceWorkerRegistration {
        return ServiceWorkerRegistration{
            .scope = scope,
            .script_url = script_url,
            .state = ServiceWorkerState.INSTALLING,
            .installing = null,
            .waiting = null,
            .active = null,
            .update_via_cache = "importscripts",
            .update_found = false,
            .registration_id = generateRegistrationId(),
        };
    }
    
    pub fn deinit(self: *ServiceWorkerRegistration) void {
        // Clean up worker references
        if (self.installing) |worker| worker.deinit();
        if (self.waiting) |worker| worker.deinit();
        if (self.active) |worker| worker.deinit();
    }
};

// Service Worker instance
pub const ServiceWorker = struct {
    id: [16]u8,
    script_url: []const u8,
    state: ServiceWorkerState,
    registration: *ServiceWorkerRegistration,
    script_hash: [32]u8, // SHA-256 hash of script
    last_update: i64, // Timestamp
    cache_names: ArrayList([]const u8),
    event_handlers: StringHashMap(EventHandler),
    control_clients: ArrayList(*Client),
    message_port: ?*MessagePort,
    
    pub fn init(allocator: Allocator, script_url: []const u8, registration: *ServiceWorkerRegistration) ServiceWorker {
        return ServiceWorker{
            .id = generateWorkerId(),
            .script_url = script_url,
            .state = ServiceWorkerState.INSTALLING,
            .registration = registration,
            .script_hash = calculateScriptHash(script_url),
            .last_update = std.time.milliTimestamp(),
            .cache_names = ArrayList([]const u8).init(allocator),
            .event_handlers = StringHashMap(EventHandler).init(allocator),
            .control_clients = ArrayList(*Client).init(allocator),
            .message_port = null,
        };
    }
    
    pub fn deinit(self: *ServiceWorker) void {
        self.cache_names.deinit();
        self.event_handlers.deinit();
        self.control_clients.deinit();
    }
    
    pub fn start(self: *ServiceWorker) !void {
        self.state = ServiceWorkerState.INSTALLED;
        self.registration.installing = self;
        
        // Fire install event
        self.fireEvent(.INSTALL_COMPLETE) catch {};
    }
    
    pub fn activate(self: *ServiceWorker) !void {
        self.state = ServiceWorkerState.ACTIVATED;
        
        // Update registration
        if (self.registration.waiting) |waiting_worker| {
            waiting_worker.deinit();
        }
        self.registration.active = self;
        self.registration.waiting = null;
        self.registration.update_found = false;
        
        // Fire activate event
        self.fireEvent(.ACTIVATE_COMPLETE) catch {};
    }
    
    pub fn sendMessage(self: *ServiceWorker, client: *Client, data: anytype) !void {
        // Send message to worker via message port
        if (self.message_port) |port| {
            port.postMessage(data) catch {};
        } else {
            // Store message for later delivery
            self.enqueueMessage(client, data) catch {};
        }
    }
    
    pub fn addEventListener(self: *ServiceWorker, event: ServiceWorkerEvent, handler: EventHandler) !void {
        try self.event_handlers.put(@tagName(event), handler);
    }
    
    pub fn removeEventListener(self: *ServiceWorker, event: ServiceWorkerEvent) void {
        _ = self.event_handlers.remove(@tagName(event));
    }
    
    fn fireEvent(self: *ServiceWorker, event_type: ServiceWorkerEvent) !void {
        if (self.event_handlers.get(@tagName(event_type))) |handler| {
            try handler(self, event_type);
        }
    }
    
    fn enqueueMessage(self: *ServiceWorker, client: *Client, data: anytype) !void {
        // Store message in event loop for later processing
        try addBackgroundTask("worker_message", client, data);
    }
};

// Event handler type
pub const EventHandler = fn (*ServiceWorker, ServiceWorkerEvent) anyerror!void;

// Service Worker registry
pub const ServiceWorkerRegistry = struct {
    allocator: Allocator,
    registrations: AutoHashMap([]const u8, *ServiceWorkerRegistration),
    worker_pool: AutoHashMap([16]u8, *ServiceWorker),
    active_workers: u32,
    max_workers: u32,
    lifecycle_queue: ArrayList(*ServiceWorker),
    
    pub fn init(allocator: Allocator) ServiceWorkerRegistry {
        return ServiceWorkerRegistry{
            .allocator = allocator,
            .registrations = AutoHashMap([]const u8, *ServiceWorkerRegistration).init(allocator),
            .worker_pool = AutoHashMap([16]u8, *ServiceWorker).init(allocator),
            .active_workers = 0,
            .max_workers = 64,
            .lifecycle_queue = ArrayList(*ServiceWorker).init(allocator),
        };
    }
    
    pub fn deinit(self: *ServiceWorkerRegistry) void {
        // Clean up all registrations
        var reg_iter = self.registrations.valueIterator();
        while (reg_iter.next()) |registration| {
            registration.*.deinit();
            self.allocator.destroy(registration.*);
        }
        self.registrations.deinit();
        
        // Clean up worker pool
        var worker_iter = self.worker_pool.valueIterator();
        while (worker_iter.next()) |worker| {
            worker.*.deinit();
            self.allocator.destroy(worker.*);
        }
        self.worker_pool.deinit();
        
        self.lifecycle_queue.deinit();
    }
    
    pub fn register(self: *ServiceWorkerRegistry, scope: []const u8, script_url: []const u8) !*ServiceWorkerRegistration {
        // Validate scope
        try self.validateScope(scope);
        
        // Check if already registered
        if (self.registrations.get(scope)) |existing| {
            return existing;
        }
        
        // Create new registration
        const registration = self.allocator.create(ServiceWorkerRegistration) catch |err| {
            return error.RegistrationFailed;
        };
        registration.* = ServiceWorkerRegistration.init(self.allocator, scope, script_url);
        
        // Create service worker instance
        const worker = self.allocator.create(ServiceWorker) catch |err| {
            self.allocator.destroy(registration);
            return error.WorkerCreationFailed;
        };
        worker.* = ServiceWorker.init(self.allocator, script_url, registration);
        registration.installing = worker;
        
        // Store in registry
        try self.registrations.put(scope, registration);
        try self.worker_pool.put(worker.id, worker);
        
        // Start worker lifecycle
        try self.startWorker(worker);
        
        return registration;
    }
    
    pub fn unregister(self: *ServiceWorkerRegistry, scope: []const u8) !bool {
        if (self.registrations.get(scope)) |registration| {
            // Mark as redundant
            if (registration.active) |worker| {
                worker.state = ServiceWorkerState.REDUNDANT;
            }
            
            // Remove from registry
            _ = self.registrations.remove(scope);
            registration.deinit();
            self.allocator.destroy(registration);
            
            return true;
        }
        
        return false;
    }
    
    pub fn getRegistration(self: *ServiceWorkerRegistry, scope: []const u8) ?*ServiceWorkerRegistration {
        return self.registrations.get(scope);
    }
    
    pub fn getAllRegistrations(self: *ServiceWorkerRegistry) ArrayList(*ServiceWorkerRegistration) {
        var registrations = ArrayList(*ServiceWorkerRegistration).init(self.allocator);
        
        var iter = self.registrations.valueIterator();
        while (iter.next()) |reg| {
            registrations.append(reg.*) catch {};
        }
        
        return registrations;
    }
    
    pub fn update(self: *ServiceWorkerRegistry, registration: *ServiceWorkerRegistration) !void {
        // Check for new script version
        const new_hash = calculateScriptHash(registration.script_url);
        
        if (registration.active) |active_worker| {
            if (!std.mem.eql(u8, &active_worker.script_hash, &new_hash)) {
                // New version found
                registration.update_found = true;
                
                // Create new worker for new version
                const new_worker = self.allocator.create(ServiceWorker) catch |err| {
                    return error.WorkerCreationFailed;
                };
                new_worker.* = ServiceWorker.init(self.allocator, registration.script_url, registration);
                
                // Mark as waiting
                registration.waiting = new_worker;
                try self.worker_pool.put(new_worker.id, new_worker);
            }
        }
    }
    
    fn validateScope(self: *ServiceWorkerRegistry, scope: []const u8) !void {
        // Validate scope URL format
        if (!std.mem.eql(u8, scope[0..8], "https://") and !std.mem.eql(u8, scope[0..7], "http://")) {
            return error.InvalidScope;
        }
        
        // Scope must be same-origin as script
        // This would be validated against the policy engine
    }
    
    fn startWorker(self: *ServiceWorkerRegistry, worker: *ServiceWorker) !void {
        // Check worker pool limits
        if (self.active_workers >= self.max_workers) {
            return error.WorkerPoolFull;
        }
        
        // Queue for lifecycle processing
        try self.lifecycle_queue.append(worker);
        
        // Process in background
        try addBackgroundTask("worker_lifecycle", worker, null);
    }
};

// Client representation
pub const Client = struct {
    id: [16]u8,
    url: []const u8,
    frame_type: []const u8,
    visibility_state: []const u8,
    focused: bool,
    controller: ?*ServiceWorker,
    
    pub fn init(allocator: Allocator, url: []const u8) Client {
        return Client{
            .id = generateClientId(),
            .url = url,
            .frame_type = "window",
            .visibility_state = "visible",
            .focused = true,
            .controller = null,
        };
    }
};

// Message Port for worker communication
pub const MessagePort = struct {
    id: [16]u8,
    owner_worker: *ServiceWorker,
    event_handlers: StringHashMap(EventHandler),
    message_queue: ArrayList(Message),
    
    pub fn init(allocator: Allocator, owner_worker: *ServiceWorker) MessagePort {
        return MessagePort{
            .id = generatePortId(),
            .owner_worker = owner_worker,
            .event_handlers = StringHashMap(EventHandler).init(allocator),
            .message_queue = ArrayList(Message).init(allocator),
        };
    }
    
    pub fn deinit(self: *MessagePort) void {
        self.event_handlers.deinit();
        self.message_queue.deinit();
    }
    
    pub fn postMessage(self: *MessagePort, data: anytype) !void {
        // Add to message queue
        try self.message_queue.append(.{
            .data = data,
            .timestamp = std.time.milliTimestamp(),
        });
        
        // Trigger message event
        if (self.event_handlers.get("message")) |handler| {
            try handler(self.owner_worker, .MESSAGE);
        }
    }
};

// Message structure
pub const Message = struct {
    data: anytype,
    timestamp: i64,
};

// Utility functions
fn generateRegistrationId() [16]u8 {
    var id: [16]u8 = undefined;
    std.crypto.random.bytes(&id);
    return id;
}

fn generateWorkerId() [16]u8 {
    var id: [16]u8 = undefined;
    std.crypto.random.bytes(&id);
    return id;
}

fn generateClientId() [16]u8 {
    var id: [16]u8 = undefined;
    std.crypto.random.bytes(&id);
    return id;
}

fn generatePortId() [16]u8 {
    var id: [16]u8 = undefined;
    std.crypto.random.bytes(&id);
    return id;
}

fn calculateScriptHash(script_url: []const u8) [32]u8 {
    var hash: [32]u8 = undefined;
    // Would implement SHA-256 hash calculation
    // For now, return mock hash
    for (0..32) |i| {
        hash[i] = 0;
    }
    return hash;
}

// Event loop integration
fn addBackgroundTask(task_type: []const u8, context: anytype, data: anytype) !void {
    // Add background task to event loop
    // This integrates with the event loop from z_event_loop
}