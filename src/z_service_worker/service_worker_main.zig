//! z_service_worker - Service Worker Main Module
//! 
//! Unified Service Worker implementation integrating registration, lifecycle,
//! fetch interception, caching, push notifications, background sync,
//! message passing, and scope routing.

const std = @import("std");
const Allocator = std.mem.Allocator;

const worker_registry = @import("worker_registry.zig");
const lifecycle_manager = @import("lifecycle_manager.zig");
const fetch_interceptor = @import("fetch_interceptor.zig");
const cache_manager = @import("cache_manager.zig");
const push_notifications = @import("push_notifications.zig");
const background_sync = @import("background_sync.zig");
const worker_messaging = @import("worker_messaging.zig");
const scope_routing = @import("scope_routing.zig");

const policy_engine = @import("z_policy/policy_engine.zig");
const event_loop = @import("z_event_loop/event_loop.zig");
const storage_bridge = @import("z_storage/storage_bridge.zig");

usingnamespace worker_registry;
usingnamespace lifecycle_manager;
usingnamespace fetch_interceptor;
usingnamespace cache_manager;
usingnamespace push_notifications;
usingnamespace background_sync;
usingnamespace worker_messaging;
usingnamespace scope_routing;
usingnamespace policy_engine;
usingnamespace event_loop;
usingnamespace storage_bridge;

// Service Worker main configuration
pub const ServiceWorkerConfig = struct {
    enable_fetch_interception: bool,
    enable_caching: bool,
    enable_push_notifications: bool,
    enable_background_sync: bool,
    enable_messaging: bool,
    enable_scope_routing: bool,
    max_active_workers: u32,
    max_cache_size: usize,
    default_ttl: i64,
    network_timeout: u64,
    
    pub fn init() ServiceWorkerConfig {
        return ServiceWorkerConfig{
            .enable_fetch_interception = true,
            .enable_caching = true,
            .enable_push_notifications = true,
            .enable_background_sync = true,
            .enable_messaging = true,
            .enable_scope_routing = true,
            .max_active_workers = 16,
            .max_cache_size = 50 * 1024 * 1024, // 50MB
            .default_ttl = 24 * 60 * 60 * 1000, // 24 hours
            .network_timeout = 30000, // 30 seconds
        };
    }
};

// Service Worker statistics
pub const ServiceWorkerStats = struct {
    active_workers: u32,
    total_registrations: u32,
    cache_hit_rate: f64,
    messages_processed: u64,
    fetch_interceptions: u64,
    push_notifications_sent: u32,
    background_syncs_completed: u32,
    memory_usage: usize,
    
    pub fn init() ServiceWorkerStats {
        return ServiceWorkerStats{
            .active_workers = 0,
            .total_registrations = 0,
            .cache_hit_rate = 0.0,
            .messages_processed = 0,
            .fetch_interceptions = 0,
            .push_notifications_sent = 0,
            .background_syncs_completed = 0,
            .memory_usage = 0,
        };
    }
};

// Main Service Worker Manager
pub const ServiceWorkerManager = struct {
    allocator: Allocator,
    config: ServiceWorkerConfig,
    registry: *ServiceWorkerRegistry,
    lifecycle_manager: *LifecycleManager,
    fetch_interceptor: ?*FetchInterceptor,
    cache_manager: ?*CacheManager,
    notification_manager: ?*NotificationManager,
    background_sync_manager: ?*BackgroundSyncManager,
    message_manager: ?*MessageManager,
    scope_router: ?*ScopeRouter,
    network_monitor: *NetworkMonitor,
    sync_scheduler: *SyncScheduler,
    stats: ServiceWorkerStats,
    event_handlers: StringHashMap(ServiceWorkerEventHandler),
    
    pub fn init(allocator: Allocator, config: ServiceWorkerConfig) !ServiceWorkerManager {
        // Initialize all components
        const registry = allocator.create(ServiceWorkerRegistry) catch |err| {
            return error.RegistryCreationFailed;
        };
        registry.* = ServiceWorkerRegistry.init(allocator);
        
        const lifecycle_mgr = allocator.create(LifecycleManager) catch |err| {
            return error.LifecycleCreationFailed;
        };
        lifecycle_mgr.* = LifecycleManager.init(allocator);
        
        const network_monitor = allocator.create(NetworkMonitor) catch |err| {
            return error.NetworkMonitorCreationFailed;
        };
        network_monitor.* = NetworkMonitor.init(allocator);
        
        const sync_scheduler = allocator.create(SyncScheduler) catch |err| {
            return error.SyncSchedulerCreationFailed;
        };
        sync_scheduler.* = SyncScheduler.init(allocator);
        
        var manager = ServiceWorkerManager{
            .allocator = allocator,
            .config = config,
            .registry = registry,
            .lifecycle_manager = lifecycle_mgr,
            .fetch_interceptor = null,
            .cache_manager = null,
            .notification_manager = null,
            .background_sync_manager = null,
            .message_manager = null,
            .scope_router = null,
            .network_monitor = network_monitor,
            .sync_scheduler = sync_scheduler,
            .stats = ServiceWorkerStats.init(),
            .event_handlers = StringHashMap(ServiceWorkerEventHandler).init(allocator),
        };
        
        // Initialize optional components based on config
        if (config.enable_fetch_interception) {
            manager.fetch_interceptor = try manager.createFetchInterceptor();
        }
        
        if (config.enable_caching) {
            const cache_config = CacheManagerConfig.init();
            cache_config.max_cache_size = config.max_cache_size;
            cache_config.default_ttl = config.default_ttl;
            
            manager.cache_manager = allocator.create(CacheManager) catch |err| {
                return error.CacheManagerCreationFailed;
            };
            manager.cache_manager.* = CacheManager.init(allocator, cache_config);
        }
        
        if (config.enable_push_notifications) {
            const push_config = PushServiceConfig.init();
            
            const push_manager = allocator.create(PushManager) catch |err| {
                return error.PushManagerCreationFailed;
            };
            push_manager.* = PushManager.init(allocator, push_config);
            
            manager.notification_manager = allocator.create(NotificationManager) catch |err| {
                return error.NotificationManagerCreationFailed;
            };
            manager.notification_manager.* = NotificationManager.init(allocator, push_manager);
        }
        
        if (config.enable_background_sync) {
            manager.background_sync_manager = allocator.create(BackgroundSyncManager) catch |err| {
                return error.BackgroundSyncManagerCreationFailed;
            };
            manager.background_sync_manager.* = BackgroundSyncManager.init(allocator, network_monitor, sync_scheduler);
        }
        
        if (config.enable_messaging) {
            manager.message_manager = allocator.create(MessageManager) catch |err| {
                return error.MessageManagerCreationFailed;
            };
            manager.message_manager.* = MessageManager.init(allocator);
        }
        
        if (config.enable_scope_routing) {
            manager.scope_router = allocator.create(ScopeRouter) catch |err| {
                return error.ScopeRouterCreationFailed;
            };
            manager.scope_router.* = ScopeRouter.init(allocator);
        }
        
        return manager;
    }
    
    pub fn deinit(self: *ServiceWorkerManager) void {
        // Clean up all components
        self.registry.*.deinit();
        self.allocator.destroy(self.registry);
        
        self.lifecycle_manager.*.deinit();
        self.allocator.destroy(self.lifecycle_manager);
        
        if (self.fetch_interceptor) |interceptor| {
            interceptor.*.deinit();
            self.allocator.destroy(interceptor);
        }
        
        if (self.cache_manager) |cache_mgr| {
            cache_mgr.*.deinit();
            self.allocator.destroy(cache_mgr);
        }
        
        if (self.notification_manager) |notif_mgr| {
            notif_mgr.*.deinit();
            self.allocator.destroy(notif_mgr);
        }
        
        if (self.background_sync_manager) |sync_mgr| {
            sync_mgr.*.deinit();
            self.allocator.destroy(sync_mgr);
        }
        
        if (self.message_manager) |msg_mgr| {
            msg_mgr.*.deinit();
            self.allocator.destroy(msg_mgr);
        }
        
        if (self.scope_router) |router| {
            router.*.deinit();
            self.allocator.destroy(router);
        }
        
        self.network_monitor.*.deinit();
        self.allocator.destroy(self.network_monitor);
        
        self.sync_scheduler.*.deinit();
        self.allocator.destroy(self.sync_scheduler);
        
        self.event_handlers.deinit();
    }
    
    pub fn register(self: *ServiceWorkerManager, scope: []const u8, script_url: []const u8) !*ServiceWorkerRegistration {
        // Check worker limits
        if (self.stats.active_workers >= self.config.max_active_workers) {
            return error.TooManyWorkers;
        }
        
        // Register worker
        const registration = try self.registry.register(scope, script_url);
        
        // Add lifecycle management
        if (registration.installing) |worker| {
            try self.lifecycle_manager.startWorker(worker);
        }
        
        // Set up fetch interception if enabled
        if (self.fetch_interceptor) |interceptor| {
            try interceptor.addFetchHandler(scope, defaultFetchHandler);
        }
        
        // Update statistics
        self.stats.total_registrations += 1;
        self.stats.active_workers += 1;
        
        return registration;
    }
    
    pub fn unregister(self: *ServiceWorkerManager, scope: []const u8) !bool {
        const unregistered = try self.registry.unregister(scope);
        
        if (unregistered) {
            self.stats.active_workers -= 1;
        }
        
        return unregistered;
    }
    
    pub fn getRegistration(self: *ServiceWorkerManager, scope: []const u8) ?*ServiceWorkerRegistration {
        return self.registry.getRegistration(scope);
    }
    
    pub fn getAllRegistrations(self: *ServiceWorkerManager) ArrayList(*ServiceWorkerRegistration) {
        return self.registry.getAllRegistrations();
    }
    
    pub fn handleFetch(self: *ServiceWorkerManager, worker: *ServiceWorker, request: Request) !FetchEvent {
        if (self.fetch_interceptor) |interceptor| {
            return try interceptor.intercept(worker, request);
        } else {
            return error.FetchInterceptionDisabled;
        }
    }
    
    pub fn getCache(self: *ServiceWorkerManager, worker_id: [16]u8, cache_name: []const u8) !*Cache {
        if (self.cache_manager) |cache_mgr| {
            return try cache_mgr.open(worker_id, cache_name);
        } else {
            return error.CachingDisabled;
        }
    }
    
    pub fn showNotification(self: *ServiceWorkerManager, worker: *ServiceWorker, title: []const u8, body: []const u8, options: NotificationOptions) !NotificationResult {
        if (self.notification_manager) |notif_mgr| {
            return try notif_mgr.showNotification(worker, options);
        } else {
            return error.NotificationsDisabled;
        }
    }
    
    pub fn registerBackgroundSync(self: *ServiceWorkerManager, worker: *ServiceWorker, tag: []const u8, options: SyncOptions) !*SyncRegistration {
        if (self.background_sync_manager) |sync_mgr| {
            return try sync_mgr.register(worker, tag, options);
        } else {
            return error.BackgroundSyncDisabled;
        }
    }
    
    pub fn addBackgroundSyncTask(self: *ServiceWorkerManager, worker: *ServiceWorker, tag: []const u8, data: []const u8, priority: SyncTask.TaskPriority) !void {
        if (self.background_sync_manager) |sync_mgr| {
            try sync_mgr.addTask(worker, tag, data, priority);
        } else {
            return error.BackgroundSyncDisabled;
        }
    }
    
    pub fn createMessageChannel(self: *ServiceWorkerManager, worker: *ServiceWorker) !MessageChannel {
        if (self.message_manager) |msg_mgr| {
            return MessageChannel.init(msg_mgr, worker);
        } else {
            return error.MessagingDisabled;
        }
    }
    
    pub fn postMessageToWorker(self: *ServiceWorkerManager, client_id: [16]u8, worker_id: [16]u8, data: anytype, response_handler: ?ResponseHandler) !void {
        if (self.message_manager) |msg_mgr| {
            try msg_mgr.postMessageToWorker(client_id, worker_id, data, response_handler);
        } else {
            return error.MessagingDisabled;
        }
    }
    
    pub fn addWorkerScope(self: *ServiceWorkerManager, scope: *WorkerScope) !void {
        if (self.scope_router) |router| {
            try router.addScope(scope);
        } else {
            return error.ScopeRoutingDisabled;
        }
    }
    
    pub fn routeRequest(self: *ServiceWorkerManager, request: Request) !*WorkerScope {
        if (self.scope_router) |router| {
            return try router.routeRequest(request);
        } else {
            return error.ScopeRoutingDisabled;
        }
    }
    
    pub fn getStats(self: *ServiceWorkerManager) ServiceWorkerStats {
        return self.stats;
    }
    
    pub fn updateNetworkStatus(self: *ServiceWorkerManager, is_online: bool, network_type: []const u8, battery_level: f32, battery_saver: bool) void {
        self.network_monitor.updateNetworkStatus(is_online, network_type, battery_level, battery_saver);
        
        // Trigger background sync if conditions improve
        if (is_online and !battery_saver and self.background_sync_manager) |sync_mgr| {
            // Check for pending syncs and trigger them
        }
    }
    
    pub fn processBackgroundTasks(self: *ServiceWorkerManager) !void {
        // Process scheduled sync events
        if (self.sync_scheduler) |scheduler| {
            if (self.background_sync_manager) |sync_mgr| {
                try scheduler.processScheduledSyncs(sync_mgr);
            }
        }
    }
    
    fn createFetchInterceptor(self: *ServiceWorkerManager) !*FetchInterceptor {
        const interceptor = self.allocator.create(FetchInterceptor) catch |err| {
            return error.FetchInterceptorCreationFailed;
        };
        interceptor.* = FetchInterceptor.init(self.allocator);
        
        // Set up cache manager if available
        if (self.cache_manager) |cache_mgr| {
            try interceptor.registerCacheManager("default", cache_mgr);
        }
        
        return interceptor;
    }
    
    // Default event handlers
    fn defaultFetchHandler(worker: *ServiceWorker, request: Request) anyerror!Response {
        var response = Response.init(std.heap.c_allocator);
        response.status = 200;
        response.status_text = "OK";
        
        // Default response body
        const body = "Service Worker handled request";
        response.body = ArrayList(u8).fromOwnedSlice(std.heap.c_allocator, body) catch undefined;
        
        return response;
    }
};

// Service Worker event handler type
pub const ServiceWorkerEventHandler = fn (ServiceWorkerEvent, anytype) anyerror!void;

// Public interface functions
pub fn createServiceWorkerManager(allocator: Allocator, config: ServiceWorkerConfig) !*ServiceWorkerManager {
    const manager = allocator.create(ServiceWorkerManager) catch |err| {
        return error.ManagerCreationFailed;
    };
    manager.* = try ServiceWorkerManager.init(allocator, config);
    return manager;
}

pub fn destroyServiceWorkerManager(manager: *ServiceWorkerManager) void {
    manager.deinit();
}

// Service Worker global functions for browser integration
pub fn registerServiceWorker(scope: []const u8, script_url: []const u8) !*ServiceWorkerRegistration {
    // This would integrate with the global service worker manager
    // For now, return error as manager needs to be created first
    return error.ManagerNotInitialized;
}

pub fn getServiceWorkerRegistration(scope: []const u8) ?*ServiceWorkerRegistration {
    // This would integrate with the global service worker manager
    return null;
}

pub fn getServiceWorkerRegistrations() ArrayList(*ServiceWorkerRegistration) {
    // This would integrate with the global service worker manager
    return ArrayList(*ServiceWorkerRegistration).init(std.heap.c_allocator);
}

// Utility functions
fn addBackgroundTask(task_type: []const u8, context: anytype, data: anytype) !void {
    // Add background task to event loop
    // This integrates with the event loop from z_event_loop
}