//! z_service_worker - Background Sync
//! 
//! Service Worker background synchronization, periodic sync events,
//! and offline queue management for data synchronization.

const std = @import("std");
const Allocator = std.mem.Allocator;
const AutoHashMap = std.AutoHashMap;
const ArrayList = std.ArrayList;
const StringHashMap = std.StringHashMap;

const policy_engine = @import("z_policy/policy_engine.zig");
const event_loop = @import("z_event_loop/event_loop.zig");
const storage_bridge = @import("z_storage/storage_bridge.zig");

// usingnamespace policy_engine;
// usingnamespace event_loop;
// usingnamespace storage_bridge;

// Background sync registration
pub const SyncRegistration = struct {
    tag: []const u8,
    worker: *ServiceWorker,
    options: SyncOptions,
    registration_id: [16]u8,
    created_at: i64,
    last_attempt: ?i64,
    attempt_count: u32,
    max_attempts: u32,
    
    pub fn init(allocator: Allocator, tag: []const u8, worker: *ServiceWorker, options: SyncOptions) SyncRegistration {
        return SyncRegistration{
            .tag = tag,
            .worker = worker,
            .options = options,
            .registration_id = generateSyncId(),
            .created_at = std.time.milliTimestamp(),
            .last_attempt = null,
            .attempt_count = 0,
            .max_attempts = 3,
        };
    }
    
    pub fn deinit(self: *SyncRegistration) void {
        self.options.deinit();
    }
};

// Background sync event
pub const SyncEvent = struct {
    id: [16]u8,
    worker: *ServiceWorker,
    registration: *SyncRegistration,
    tag: []const u8,
    last_chance: bool,
    timestamp: i64,
    
    pub fn init(allocator: Allocator, worker: *ServiceWorker, registration: *SyncRegistration, last_chance: bool) SyncEvent {
        return SyncEvent{
            .id = generateSyncEventId(),
            .worker = worker,
            .registration = registration,
            .tag = registration.tag,
            .last_chance = last_chance,
            .timestamp = std.time.milliTimestamp(),
        };
    }
    
    pub fn deinit(self: *SyncEvent) void {
        self.registration.deinit();
    }
};

// Background sync options
pub const SyncOptions = struct {
    min_interval: u64, // Minimum interval between sync attempts (milliseconds)
    max_attempts: u32,
    network_type: []const u8, // "wifi", "cellular", "any"
    battery_saver: bool,
    
    pub fn init() SyncOptions {
        return SyncOptions{
            .min_interval = 60000, // 1 minute
            .max_attempts = 3,
            .network_type = "any",
            .battery_saver = false,
        };
    }
    
    pub fn deinit(self: *SyncOptions) void {
        _ = self; // No additional cleanup needed
    }
};

// Periodic sync registration
pub const PeriodicSyncRegistration = struct {
    tag: []const u8,
    worker: *ServiceWorker,
    min_interval: u64, // Minimum interval between sync attempts (milliseconds)
    network_type: []const u8,
    battery_saver: bool,
    registration_id: [16]u8,
    created_at: i64,
    last_sync: ?i64,
    next_sync: ?i64,
    
    pub fn init(allocator: Allocator, tag: []const u8, worker: *ServiceWorker, min_interval: u64) PeriodicSyncRegistration {
        return PeriodicSyncRegistration{
            .tag = tag,
            .worker = worker,
            .min_interval = min_interval,
            .network_type = "any",
            .battery_saver = false,
            .registration_id = generatePeriodicSyncId(),
            .created_at = std.time.milliTimestamp(),
            .last_sync = null,
            .next_sync = null,
        };
    }
    
    pub fn deinit(self: *PeriodicSyncRegistration) void {
        _ = self; // No additional cleanup needed
    }
};

// Periodic sync event
pub const PeriodicSyncEvent = struct {
    id: [16]u8,
    worker: *ServiceWorker,
    registration: *PeriodicSyncRegistration,
    tag: []const u8,
    timestamp: i64,
    
    pub fn init(allocator: Allocator, worker: *ServiceWorker, registration: *PeriodicSyncRegistration) PeriodicSyncEvent {
        return PeriodicSyncEvent{
            .id = generatePeriodicSyncEventId(),
            .worker = worker,
            .registration = registration,
            .tag = registration.tag,
            .timestamp = std.time.milliTimestamp(),
        };
    }
    
    pub fn deinit(self: *PeriodicSyncEvent) void {
        self.registration.deinit();
    }
};

// Sync task queue
pub const SyncTask = struct {
    id: [16]u8,
    tag: []const u8,
    worker: *ServiceWorker,
    data: ArrayList(u8),
    priority: TaskPriority,
    created_at: i64,
    retry_count: u32,
    max_retries: u32,
    
    pub const TaskPriority = enum {
        LOW,
        NORMAL,
        HIGH,
        CRITICAL,
    };
    
    pub fn init(allocator: Allocator, tag: []const u8, worker: *ServiceWorker, data: []const u8, priority: TaskPriority) SyncTask {
        return SyncTask{
            .id = generateTaskId(),
            .tag = tag,
            .worker = worker,
            .data = ArrayList(u8).fromOwnedSlice(allocator, data) catch undefined,
            .priority = priority,
            .created_at = std.time.milliTimestamp(),
            .retry_count = 0,
            .max_retries = 3,
        };
    }
    
    pub fn deinit(self: *SyncTask) void {
        self.data.deinit();
    }
};

// Background sync manager
pub const BackgroundSyncManager = struct {
    allocator: Allocator,
    sync_registrations: AutoHashMap([]const u8, *SyncRegistration), // tag -> registration
    periodic_syncs: AutoHashMap([]const u8, *PeriodicSyncRegistration), // tag -> periodic sync
    task_queues: AutoHashMap([]const u8, ArrayList(*SyncTask)), // tag -> task queue
    worker_syncs: AutoHashMap([16]u8, ArrayList([]const u8)), // worker_id -> sync tags
    network_monitor: *NetworkMonitor,
    sync_scheduler: *SyncScheduler,
    
    pub fn init(allocator: Allocator, network_monitor: *NetworkMonitor, sync_scheduler: *SyncScheduler) BackgroundSyncManager {
        return BackgroundSyncManager{
            .allocator = allocator,
            .sync_registrations = AutoHashMap([]const u8, *SyncRegistration).init(allocator),
            .periodic_syncs = AutoHashMap([]const u8, *PeriodicSyncRegistration).init(allocator),
            .task_queues = AutoHashMap([]const u8, ArrayList(*SyncTask)).init(allocator),
            .worker_syncs = AutoHashMap([16]u8, ArrayList([]const u8)).init(allocator),
            .network_monitor = network_monitor,
            .sync_scheduler = sync_scheduler,
        };
    }
    
    pub fn deinit(self: *BackgroundSyncManager) void {
        // Clean up sync registrations
        var iter = self.sync_registrations.valueIterator();
        while (iter.next()) |registration| {
            registration.*.deinit();
            self.allocator.destroy(registration.*);
        }
        self.sync_registrations.deinit();
        
        // Clean up periodic sync registrations
        var periodic_iter = self.periodic_syncs.valueIterator();
        while (periodic_iter.next()) |registration| {
            registration.*.deinit();
            self.allocator.destroy(registration.*);
        }
        self.periodic_syncs.deinit();
        
        // Clean up task queues
        var queue_iter = self.task_queues.valueIterator();
        while (queue_iter.next()) |queue| {
            for (queue.*.items) |task| {
                task.deinit();
                self.allocator.destroy(task);
            }
            queue.*.deinit();
        }
        self.task_queues.deinit();
        
        // Clean up worker associations
        var worker_iter = self.worker_syncs.valueIterator();
        while (worker_iter.next()) |sync_list| {
            sync_list.*.deinit();
        }
        self.worker_syncs.deinit();
    }
    
    pub fn register(self: *BackgroundSyncManager, worker: *ServiceWorker, tag: []const u8, options: SyncOptions) !*SyncRegistration {
        // Check if already registered
        if (self.sync_registrations.get(tag)) |existing| {
            return existing;
        }
        
        // Create new registration
        const registration = self.allocator.create(SyncRegistration) catch |err| {
            return error.RegistrationFailed;
        };
        registration.* = SyncRegistration.init(self.allocator, tag, worker, options);
        
        // Store registration
        try self.sync_registrations.put(tag, registration);
        try self.associateWorkerWithSync(worker.id, tag);
        
        // Create task queue
        if (!self.task_queues.contains(tag)) {
            var queue = ArrayList(*SyncTask).init(self.allocator);
            try self.task_queues.put(tag, queue);
        }
        
        return registration;
    }
    
    pub fn unregister(self: *BackgroundSyncManager, tag: []const u8) !bool {
        if (self.sync_registrations.get(tag)) |registration| {
            // Remove from all worker associations
            self.disassociateWorkerFromSync(registration.worker.id, tag);
            
            // Clean up task queue
            if (self.task_queues.get(tag)) |queue| {
                for (queue.*.items) |task| {
                    task.deinit();
                    self.allocator.destroy(task);
                }
                queue.*.deinit();
            }
            _ = self.task_queues.remove(tag);
            
            // Remove registration
            _ = self.sync_registrations.remove(tag);
            registration.deinit();
            self.allocator.destroy(registration);
            
            return true;
        }
        
        return false;
    }
    
    pub fn registerPeriodicSync(self: *BackgroundSyncManager, worker: *ServiceWorker, tag: []const u8, min_interval: u64) !*PeriodicSyncRegistration {
        // Check if already registered
        if (self.periodic_syncs.get(tag)) |existing| {
            return existing;
        }
        
        // Create new registration
        const registration = self.allocator.create(PeriodicSyncRegistration) catch |err| {
            return error.RegistrationFailed;
        };
        registration.* = PeriodicSyncRegistration.init(self.allocator, tag, worker, min_interval);
        
        // Store registration
        try self.periodic_syncs.put(tag, registration);
        
        // Schedule first sync
        registration.next_sync = std.time.milliTimestamp() + min_interval;
        
        return registration;
    }
    
    pub fn unregisterPeriodicSync(self: *BackgroundSyncManager, tag: []const u8) !bool {
        if (self.periodic_syncs.get(tag)) |registration| {
            _ = self.periodic_syncs.remove(tag);
            registration.deinit();
            self.allocator.destroy(registration);
            
            return true;
        }
        
        return false;
    }
    
    pub fn addTask(self: *BackgroundSyncManager, worker: *ServiceWorker, tag: []const u8, data: []const u8, priority: SyncTask.TaskPriority) !void {
        // Create task
        const task = self.allocator.create(SyncTask) catch |err| {
            return error.TaskCreationFailed;
        };
        task.* = SyncTask.init(self.allocator, tag, worker, data, priority);
        
        // Add to queue
        if (self.task_queues.get(tag)) |queue| {
            try queue.append(task);
            
            // Sort by priority
            std.sort.sort(*SyncTask, queue.items, {}, taskPriorityCompare);
        } else {
            // Create new queue
            var queue = ArrayList(*SyncTask).init(self.allocator);
            try queue.append(task);
            try self.task_queues.put(tag, queue);
        }
        
        // Attempt to trigger sync if conditions are met
        try self.maybeTriggerSync(tag);
    }
    
    pub fn triggerSync(self: *BackgroundSyncManager, tag: []const u8, last_chance: bool) !void {
        if (self.sync_registrations.get(tag)) |registration| {
            // Create sync event
            const event = self.allocator.create(SyncEvent) catch |err| {
                return error.EventCreationFailed;
            };
            event.* = SyncEvent.init(self.allocator, registration.worker, registration, last_chance);
            
            // Update registration
            registration.last_attempt = std.time.milliTimestamp();
            registration.attempt_count += 1;
            
            // Send event to worker
            try self.dispatchSyncEvent(event);
        }
    }
    
    pub fn processSyncEvent(self: *BackgroundSyncManager, event: *SyncEvent) !void {
        // Get tasks for this sync tag
        if (self.task_queues.get(event.tag)) |queue| {
            // Process all tasks in queue
            while (queue.items.len > 0) {
                const task = queue.orderedRemove(0);
                
                // Send task to worker
                try self.dispatchTaskToWorker(task);
                
                // If task fails, re-queue it
                // Implementation would handle task completion/failure
            }
        }
        
        // Update registration status
        event.registration.worker.state = ServiceWorkerState.ACTIVATED_PERIODIC_SYNC;
    }
    
    pub fn processPeriodicSyncEvent(self: *BackgroundSyncManager, event: *PeriodicSyncEvent) !void {
        // Update registration
        event.registration.last_sync = std.time.milliTimestamp();
        event.registration.next_sync = std.time.milliTimestamp() + event.registration.min_interval;
        
        // Send event to worker
        try self.dispatchPeriodicSyncEvent(event);
    }
    
    pub fn getRegistrations(self: *BackgroundSyncManager, worker: *ServiceWorker) ArrayList(*SyncRegistration) {
        var registrations = ArrayList(*SyncRegistration).init(self.allocator);
        
        if (self.worker_syncs.get(worker.id)) |worker_syncs| {
            for (worker_syncs.*.items) |tag| {
                if (self.sync_registrations.get(tag)) |registration| {
                    registrations.append(registration.*) catch {};
                }
            }
        }
        
        return registrations;
    }
    
    fn associateWorkerWithSync(self: *BackgroundSyncManager, worker_id: [16]u8, tag: []const u8) !void {
        if (self.worker_syncs.get(worker_id)) |existing_list| {
            const sync_list = existing_list.*;
            if (std.mem.indexOfScalar([]const u8, sync_list.items, tag) == null) {
                try sync_list.append(tag);
            }
        } else {
            var sync_list = ArrayList([]const u8).init(self.allocator);
            try sync_list.append(tag);
            try self.worker_syncs.put(worker_id, sync_list);
        }
    }
    
    fn disassociateWorkerFromSync(self: *BackgroundSyncManager, worker_id: [16]u8, tag: []const u8) void {
        if (self.worker_syncs.get(worker_id)) |worker_syncs| {
            const sync_list = worker_syncs.*;
            const index = std.mem.indexOfScalar([]const u8, sync_list.items, tag);
            if (index) |i| {
                _ = sync_list.orderedRemove(i);
            }
        }
    }
    
    fn maybeTriggerSync(self: *BackgroundSyncManager, tag: []const u8) !void {
        // Check if network conditions allow sync
        if (self.network_monitor.isOnline() and 
            self.network_monitor.isNetworkTypeAllowed(tag) and
            !self.network_monitor.isBatteryLow()) {
            
            try self.triggerSync(tag, false);
        }
    }
    
    fn dispatchSyncEvent(self: *BackgroundSyncManager, event: *SyncEvent) !void {
        // Send sync event to worker
        // This integrates with the worker's event system
        if (event.worker.event_handlers.get("sync")) |handler| {
            try handler(event.worker, .SYNC);
        }
    }
    
    fn dispatchTaskToWorker(self: *BackgroundSyncManager, task: *SyncTask) !void {
        // Send task to worker for processing
        // This would integrate with the worker's message system
    }
    
    fn dispatchPeriodicSyncEvent(self: *BackgroundSyncManager, event: *PeriodicSyncEvent) !void {
        // Send periodic sync event to worker
        if (event.worker.event_handlers.get("periodicsync")) |handler| {
            try handler(event.worker, .PERIODIC_SYNC);
        }
    }
};

// Network monitor for sync conditions
pub const NetworkMonitor = struct {
    allocator: Allocator,
    is_online: bool,
    network_type: []const u8,
    battery_level: f32,
    battery_saver_enabled: bool,
    signal_strength: SignalStrength,
    
    pub const SignalStrength = enum {
        NO_SIGNAL,
        POOR,
        FAIR,
        GOOD,
        EXCELLENT,
    };
    
    pub fn init(allocator: Allocator) NetworkMonitor {
        return NetworkMonitor{
            .allocator = allocator,
            .is_online = true,
            .network_type = "wifi",
            .battery_level = 0.8,
            .battery_saver_enabled = false,
            .signal_strength = SignalStrength.GOOD,
        };
    }
    
    pub fn deinit(self: *NetworkMonitor) void {
        _ = self; // No additional cleanup needed
    }
    
    pub fn isOnline(self: *NetworkMonitor) bool {
        return self.is_online;
    }
    
    pub fn isNetworkTypeAllowed(self: *NetworkMonitor, tag: []const u8) bool {
        // Check if network type is allowed for this sync
        _ = tag; // Would check against sync options
        return true;
    }
    
    pub fn isBatteryLow(self: *NetworkMonitor) bool {
        return self.battery_level < 0.2 or self.battery_saver_enabled;
    }
    
    pub fn updateNetworkStatus(self: *NetworkMonitor, is_online: bool, network_type: []const u8, battery_level: f32, battery_saver: bool) void {
        self.is_online = is_online;
        self.network_type = network_type;
        self.battery_level = battery_level;
        self.battery_saver_enabled = battery_saver;
        
        // Notify sync manager of network changes
        try self.notifyNetworkChange();
    }
    
    fn notifyNetworkChange(self: *NetworkMonitor) !void {
        // Notify background sync manager of network changes
        // This would trigger sync attempts if conditions improve
    }
};

// Sync scheduler for timing sync operations
pub const SyncScheduler = struct {
    allocator: Allocator,
    scheduled_syncs: AutoHashMap([]const u8, i64), // tag -> next_sync_time
    sync_delays: AutoHashMap([]const u8, u64), // tag -> delay_ms
    
    pub fn init(allocator: Allocator) SyncScheduler {
        return SyncScheduler{
            .allocator = allocator,
            .scheduled_syncs = AutoHashMap([]const u8, i64).init(allocator),
            .sync_delays = AutoHashMap([]const u8, u64).init(allocator),
        };
    }
    
    pub fn deinit(self: *SyncScheduler) void {
        self.scheduled_syncs.deinit();
        self.sync_delays.deinit();
    }
    
    pub fn scheduleSync(self: *SyncScheduler, tag: []const u8, delay_ms: u64) !void {
        const next_sync = std.time.milliTimestamp() + delay_ms;
        try self.scheduled_syncs.put(tag, next_sync);
        try self.sync_delays.put(tag, delay_ms);
    }
    
    pub fn processScheduledSyncs(self: *SyncScheduler, sync_manager: *BackgroundSyncManager) !void {
        const now = std.time.milliTimestamp();
        
        var to_trigger = ArrayList([]const u8).init(self.allocator);
        defer to_trigger.deinit();
        
        var iter = self.scheduled_syncs.iterator();
        while (iter.next()) |entry| {
            if (entry.value_ptr.* <= now) {
                try to_trigger.append(entry.key_ptr.*);
            }
        }
        
        // Trigger due syncs
        for (to_trigger.items) |tag| {
            try sync_manager.triggerSync(tag, false);
            
            // Reschedule if recurring
            if (self.sync_delays.get(tag)) |delay| {
                try self.scheduleSync(tag, delay);
            } else {
                _ = self.scheduled_syncs.remove(tag);
            }
        }
    }
};

// Utility functions
fn generateSyncId() [16]u8 {
    var id: [16]u8 = undefined;
    std.crypto.random.bytes(&id);
    return id;
}

fn generateSyncEventId() [16]u8 {
    var id: [16]u8 = undefined;
    std.crypto.random.bytes(&id);
    return id;
}

fn generatePeriodicSyncId() [16]u8 {
    var id: [16]u8 = undefined;
    std.crypto.random.bytes(&id);
    return id;
}

fn generatePeriodicSyncEventId() [16]u8 {
    var id: [16]u8 = undefined;
    std.crypto.random.bytes(&id);
    return id;
}

fn generateTaskId() [16]u8 {
    var id: [16]u8 = undefined;
    std.crypto.random.bytes(&id);
    return id;
}

fn taskPriorityCompare(_: void, a: *SyncTask, b: *SyncTask) bool {
    return @intFromEnum(a.priority) > @intFromEnum(b.priority);
}