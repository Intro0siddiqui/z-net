//! z_service_worker - Lifecycle Management
//! 
//! Service Worker lifecycle state management, transitions, and event handling
//! including installation, activation, and termination.

const std = @import("std");
const Allocator = std.mem.Allocator;
const AutoHashMap = std.AutoHashMap;
const ArrayList = std.ArrayList;
const StringHashMap = std.StringHashMap;

const worker_registry = @import("worker_registry.zig");
const policy_engine = @import("z_policy/policy_engine.zig");
const event_loop = @import("z_event_loop/event_loop.zig");
const storage_bridge = @import("z_storage/storage_bridge.zig");

usingnamespace worker_registry;
usingnamespace policy_engine;
usingnamespace event_loop;
usingnamespace storage_bridge;

// Lifecycle state transition result
pub const LifecycleResult = enum {
    SUCCESS,
    PENDING,
    FAILED,
    TIMEOUT,
    CANCELLED,
};

// Lifecycle event with extended data
pub const LifecycleEvent = struct {
    worker: *ServiceWorker,
    event_type: ServiceWorkerEvent,
    state: ServiceWorkerState,
    previous_state: ServiceWorkerState,
    timestamp: i64,
    data: ?anytype,
    error: ?anyerror,
};

// Lifecycle state machine
pub const LifecycleStateMachine = struct {
    allocator: Allocator,
    workers: AutoHashMap([16]u8, *ServiceWorker),
    event_queue: ArrayList(LifecycleEvent),
    timeout_handlers: AutoHashMap([16]u8, TimeoutHandler),
    active_transitions: AutoHashMap([16]u8, TransitionContext),
    
    pub fn init(allocator: Allocator) LifecycleStateMachine {
        return LifecycleStateMachine{
            .allocator = allocator,
            .workers = AutoHashMap([16]u8, *ServiceWorker).init(allocator),
            .event_queue = ArrayList(LifecycleEvent).init(allocator),
            .timeout_handlers = AutoHashMap([16]u8, TimeoutHandler).init(allocator),
            .active_transitions = AutoHashMap([16]u8, TransitionContext).init(allocator),
        };
    }
    
    pub fn deinit(self: *LifecycleStateMachine) void {
        self.workers.deinit();
        self.event_queue.deinit();
        self.timeout_handlers.deinit();
        self.active_transitions.deinit();
    }
    
    pub fn addWorker(self: *LifecycleStateMachine, worker: *ServiceWorker) !void {
        try self.workers.put(worker.id, worker);
    }
    
    pub fn removeWorker(self: *LifecycleStateMachine, worker: *ServiceWorker) !void {
        _ = self.workers.remove(worker.id);
    }
    
    pub fn transitionTo(self: *LifecycleStateMachine, worker: *ServiceWorker, new_state: ServiceWorkerState) !LifecycleResult {
        const current_state = worker.state;
        if (current_state == new_state) {
            return .SUCCESS;
        }
        
        // Create transition context
        const context = TransitionContext{
            .worker = worker,
            .from_state = current_state,
            .to_state = new_state,
            .start_time = std.time.milliTimestamp(),
            .steps = getTransitionSteps(current_state, new_state),
        };
        
        try self.active_transitions.put(worker.id, context);
        
        // Execute transition steps
        const result = try self.executeTransition(worker.id);
        
        if (result == .SUCCESS) {
            worker.state = new_state;
        }
        
        return result;
    }
    
    pub fn handleEvent(self: *LifecycleStateMachine, event: LifecycleEvent) !void {
        // Add to event queue
        try self.event_queue.append(event);
        
        // Process events asynchronously
        try self.processEventQueue();
    }
    
    pub fn processInstall(self: *LifecycleStateMachine, worker: *ServiceWorker) !LifecycleResult {
        worker.state = ServiceWorkerState.INSTALLING;
        
        // Validate script
        try self.validateScript(worker);
        
        // Load script
        try self.loadScript(worker);
        
        // Execute install event
        try self.fireInstallEvent(worker);
        
        worker.state = ServiceWorkerState.INSTALLED;
        return .SUCCESS;
    }
    
    pub fn processActivate(self: *LifecycleStateMachine, worker: *ServiceWorker) !LifecycleResult {
        worker.state = ServiceWorkerState.ACTIVATING;
        
        // Wait for all clients to release control
        try self.waitForClients(worker);
        
        // Claim clients
        try self.claimClients(worker);
        
        // Fire activate event
        try self.fireActivateEvent(worker);
        
        worker.state = ServiceWorkerState.ACTIVATED;
        return .SUCCESS;
    }
    
    pub fn processTerminate(self: *LifecycleStateMachine, worker: *ServiceWorker) !LifecycleResult {
        // Clean up resources
        try self.cleanupWorker(worker);
        
        // Notify clients
        try self.notifyClientsOfTermination(worker);
        
        // Remove from registry
        worker.state = ServiceWorkerState.REDUNDANT;
        
        return .SUCCESS;
    }
    
    fn validateScript(self: *LifecycleStateMachine, worker: *ServiceWorker) !void {
        // Validate script syntax
        // Check CORS permissions
        // Validate security constraints
        // This integrates with the policy engine
    }
    
    fn loadScript(self: *LifecycleStateMachine, worker: *ServiceWorker) !void {
        // Load the service worker script
        // Cache it for execution
        // Verify integrity
    }
    
    fn fireInstallEvent(self: *LifecycleStateMachine, worker: *ServiceWorker) !void {
        // Create install event
        const event = LifecycleEvent{
            .worker = worker,
            .event_type = .INSTALL,
            .state = worker.state,
            .previous_state = ServiceWorkerState.INSTALLING,
            .timestamp = std.time.milliTimestamp(),
            .data = null,
            .error = null,
        };
        
        // Process event
        try self.handleEvent(event);
    }
    
    fn fireActivateEvent(self: *LifecycleStateMachine, worker: *ServiceWorker) !void {
        // Create activate event
        const event = LifecycleEvent{
            .worker = worker,
            .event_type = .ACTIVATE,
            .state = worker.state,
            .previous_state = ServiceWorkerState.ACTIVATING,
            .timestamp = std.time.milliTimestamp(),
            .data = null,
            .error = null,
        };
        
        // Process event
        try self.handleEvent(event);
    }
    
    fn waitForClients(self: *LifecycleStateMachine, worker: *ServiceWorker) !void {
        // Wait for existing active workers to finish
        // Timeout after 30 seconds
    }
    
    fn claimClients(self: *LifecycleStateMachine, worker: *ServiceWorker) !void {
        // Claim all clients in scope
        for (worker.control_clients.items) |client| {
            client.controller = worker;
        }
    }
    
    fn cleanupWorker(self: *LifecycleStateMachine, worker: *ServiceWorker) !void {
        // Clean up caches
        for (worker.cache_names.items) |cache_name| {
            try self.cleanupCache(cache_name);
        }
        
        // Clean up event handlers
        worker.event_handlers.clearRetainingCapacity();
        
        // Close message ports
        if (worker.message_port) |port| {
            port.deinit();
        }
    }
    
    fn cleanupCache(self: *LifecycleStateMachine, cache_name: []const u8) !void {
        // Remove cache from storage
        // This integrates with the cache manager
    }
    
    fn notifyClientsOfTermination(self: *LifecycleStateMachine, worker: *ServiceWorker) !void {
        // Send termination notifications to clients
        for (worker.control_clients.items) |client| {
            if (client.controller == worker) {
                client.controller = null;
            }
        }
    }
    
    fn executeTransition(self: *LifecycleStateMachine, worker_id: [16]u8) !LifecycleResult {
        if (self.active_transitions.get(worker_id)) |context| {
            // Execute transition steps
            for (context.steps) |step| {
                try step(context.worker);
            }
            
            // Remove completed transition
            _ = self.active_transitions.remove(worker_id);
            
            return .SUCCESS;
        }
        
        return .FAILED;
    }
    
    fn processEventQueue(self: *LifecycleStateMachine) !void {
        while (self.event_queue.items.len > 0) {
            const event = self.event_queue.orderedRemove(0);
            
            // Process the event
            try self.processLifecycleEvent(event);
        }
    }
    
    fn processLifecycleEvent(self: *LifecycleStateMachine, event: LifecycleEvent) !void {
        // Handle different event types
        switch (event.event_type) {
            .INSTALL_COMPLETE => {
                // Installation completed
            },
            .ACTIVATE_COMPLETE => {
                // Activation completed
            },
            .MESSAGE => {
                // Handle message events
            },
            .SYNC => {
                // Handle background sync events
            },
            .PUSH => {
                // Handle push notification events
            },
            else => {
                // Other events
            },
        }
    }
    
    fn processEvent(self: *LifecycleStateMachine, event: LifecycleEvent) !void {
        // Process specific event types
        switch (event.event_type) {
            .INSTALL => {
                try self.processInstall(event.worker);
            },
            .ACTIVATE => {
                try self.processActivate(event.worker);
            },
            .INSTALL_COMPLETE, .ACTIVATE_COMPLETE => {
                // Post-transition processing
            },
            else => {
                // Forward to worker
                if (event.worker.event_handlers.get(@tagName(event.event_type))) |handler| {
                    try handler(event.worker, event.event_type);
                }
            },
        }
    }
};

// Transition context for tracking state changes
pub const TransitionContext = struct {
    worker: *ServiceWorker,
    from_state: ServiceWorkerState,
    to_state: ServiceWorkerState,
    start_time: i64,
    steps: []TransitionStep,
};

// Transition step function
pub const TransitionStep = fn (*ServiceWorker) anyerror!void;

// Get transition steps between two states
fn getTransitionSteps(from: ServiceWorkerState, to: ServiceWorkerState) []TransitionStep {
    switch (from) {
        .INSTALLING => switch (to) {
            .INSTALLED => &[_]TransitionStep{validateInstall, completeInstall},
            else => &[_]TransitionStep{},
        },
        .INSTALLED => switch (to) {
            .ACTIVATING => &[_]TransitionStep{startActivation},
            .REDUNDANT => &[_]TransitionStep{markRedundant},
            else => &[_]TransitionStep{},
        },
        .ACTIVATING => switch (to) {
            .ACTIVATED => &[_]TransitionStep{completeActivation},
            .REDUNDANT => &[_]TransitionStep{cancelActivation},
            else => &[_]TransitionStep{},
        },
        .ACTIVATED => switch (to) {
            .REDUNDANT => &[_]TransitionStep{initiateTermination},
            else => &[_]TransitionStep{},
        },
        else => &[_]TransitionStep{},
    }
}

// Transition step implementations
fn validateInstall(worker: *ServiceWorker) !void {
    // Validate installation prerequisites
}

fn completeInstall(worker: *ServiceWorker) !void {
    // Complete installation process
}

fn startActivation(worker: *ServiceWorker) !void {
    // Begin activation process
}

fn completeActivation(worker: *ServiceWorker) !void {
    // Complete activation process
}

fn cancelActivation(worker: *ServiceWorker) !void {
    // Cancel activation
}

fn markRedundant(worker: *ServiceWorker) !void {
    // Mark worker as redundant
}

fn initiateTermination(worker: *ServiceWorker) !void {
    // Begin termination process
}

// Timeout handler
pub const TimeoutHandler = struct {
    worker_id: [16]u8,
    timeout_ms: u64,
    timeout_type: []const u8,
    callback: fn (*ServiceWorker, []const u8) anyerror!void,
    
    pub fn init(worker_id: [16]u8, timeout_ms: u64, timeout_type: []const u8, callback: fn (*ServiceWorker, []const u8) anyerror!void) TimeoutHandler {
        return TimeoutHandler{
            .worker_id = worker_id,
            .timeout_ms = timeout_ms,
            .timeout_type = timeout_type,
            .callback = callback,
        };
    }
};

// Lifecycle manager
pub const LifecycleManager = struct {
    allocator: Allocator,
    state_machine: LifecycleStateMachine,
    active_workers: AutoHashMap([16]u8, *ServiceWorker),
    worker_lifecycles: AutoHashMap([16]u8, WorkerLifecycle),
    
    pub fn init(allocator: Allocator) LifecycleManager {
        return LifecycleManager{
            .allocator = allocator,
            .state_machine = LifecycleStateMachine.init(allocator),
            .active_workers = AutoHashMap([16]u8, *ServiceWorker).init(allocator),
            .worker_lifecycles = AutoHashMap([16]u8, WorkerLifecycle).init(allocator),
        };
    }
    
    pub fn deinit(self: *LifecycleManager) void {
        self.state_machine.deinit();
        self.active_workers.deinit();
        self.worker_lifecycles.deinit();
    }
    
    pub fn startWorker(self: *LifecycleManager, worker: *ServiceWorker) !void {
        try self.state_machine.addWorker(worker);
        try self.active_workers.put(worker.id, worker);
        
        // Start install process
        const result = self.state_machine.transitionTo(worker, ServiceWorkerState.INSTALLED);
        
        if (result == .FAILED) {
            return error.WorkerInstallFailed;
        }
    }
    
    pub fn activateWorker(self: *LifecycleManager, worker: *ServiceWorker) !void {
        const result = self.state_machine.transitionTo(worker, ServiceWorkerState.ACTIVATED);
        
        if (result == .FAILED) {
            return error.WorkerActivationFailed;
        }
    }
    
    pub fn terminateWorker(self: *LifecycleManager, worker: *ServiceWorker) !void {
        const result = self.state_machine.transitionTo(worker, ServiceWorkerState.REDUNDANT);
        
        if (result == .SUCCESS) {
            _ = self.active_workers.remove(worker.id);
            worker.deinit();
        }
    }
    
    pub fn handleEvent(self: *LifecycleManager, event: LifecycleEvent) !void {
        try self.state_machine.handleEvent(event);
    }
    
    pub fn getWorkerState(self: *LifecycleManager, worker: *ServiceWorker) ServiceWorkerState {
        return worker.state;
    }
    
    pub fn isWorkerActive(self: *LifecycleManager, worker: *ServiceWorker) bool {
        return switch (worker.state) {
            .ACTIVATED, .ACTIVATED_PERIODIC_SYNC => true,
            else => false,
        };
    }
    
    pub fn getActiveWorkers(self: *LifecycleManager) ArrayList(*ServiceWorker) {
        var workers = ArrayList(*ServiceWorker).init(self.allocator);
        
        var iter = self.active_workers.valueIterator();
        while (iter.next()) |worker| {
            if (self.isWorkerActive(worker.*)) {
                workers.append(worker.*) catch {};
            }
        }
        
        return workers;
    }
};

// Worker lifecycle tracking
pub const WorkerLifecycle = struct {
    worker: *ServiceWorker,
    start_time: i64,
    last_activity: i64,
    install_duration: i64,
    activate_duration: i64,
    total_messages_processed: u32,
    error_count: u32,
    
    pub fn init(worker: *ServiceWorker) WorkerLifecycle {
        return WorkerLifecycle{
            .worker = worker,
            .start_time = std.time.milliTimestamp(),
            .last_activity = std.time.milliTimestamp(),
            .install_duration = 0,
            .activate_duration = 0,
            .total_messages_processed = 0,
            .error_count = 0,
        };
    }
    
    pub fn updateActivity(self: *WorkerLifecycle) void {
        self.last_activity = std.time.milliTimestamp();
    }
    
    pub fn recordMessage(self: *WorkerLifecycle) void {
        self.total_messages_processed += 1;
        self.updateActivity();
    }
    
    pub fn recordError(self: *WorkerLifecycle) void {
        self.error_count += 1;
    }
}