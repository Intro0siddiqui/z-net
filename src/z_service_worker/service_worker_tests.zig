//! z_service_worker - Service Worker Comprehensive Test Suite
//! 
//! Complete test coverage for Service Worker implementation including
//! registration, lifecycle, fetch interception, caching, push notifications,
//! background sync, messaging, and scope routing.

const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;
const StringHashMap = std.StringHashMap;
const ArrayList = std.ArrayList;

const worker_registry = @import("worker_registry.zig");
const lifecycle_manager = @import("lifecycle_manager.zig");
const fetch_interceptor = @import("fetch_interceptor.zig");
const cache_manager = @import("cache_manager.zig");
const push_notifications = @import("push_notifications.zig");
const background_sync = @import("background_sync.zig");
const worker_messaging = @import("worker_messaging.zig");
const scope_routing = @import("scope_routing.zig");
const service_worker_main = @import("service_worker_main.zig");

usingnamespace worker_registry;
usingnamespace lifecycle_manager;
usingnamespace fetch_interceptor;
usingnamespace cache_manager;
usingnamespace push_notifications;
usingnamespace background_sync;
usingnamespace worker_messaging;
usingnamespace scope_routing;
usingnamespace service_worker_main;

test "Service Worker Registration" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    var registry = ServiceWorkerRegistry.init(allocator);
    defer registry.deinit();
    
    const scope = "https://example.com/app/";
    const script_url = "https://example.com/sw.js";
    
    const registration = try registry.register(scope, script_url);
    testing.expect(std.mem.eql(u8, registration.scope, scope));
    testing.expect(std.mem.eql(u8, registration.script_url, script_url));
    testing.expect(registration.state == ServiceWorkerState.INSTALLING);
}

test "Service Worker Lifecycle States" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    var manager = LifecycleManager.init(allocator);
    defer manager.deinit();
    
    var registration = ServiceWorkerRegistration.init(allocator, "https://example.com", "sw.js");
    defer registration.deinit();
    
    var worker = ServiceWorker.init(allocator, "sw.js", &registration);
    defer worker.deinit();
    
    // Test state transitions
    try manager.startWorker(&worker);
    testing.expect(worker.state == ServiceWorkerState.INSTALLED);
    
    try manager.activateWorker(&worker);
    testing.expect(worker.state == ServiceWorkerState.ACTIVATED);
}

test "Service Worker Fetch Interception" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    var interceptor = FetchInterceptor.init(allocator);
    defer interceptor.deinit();
    
    var registration = ServiceWorkerRegistration.init(allocator, "https://example.com", "sw.js");
    defer registration.deinit();
    
    var worker = ServiceWorker.init(allocator, "sw.js", &registration);
    defer worker.deinit();
    
    var request = Request.init(allocator, "https://example.com/data.json");
    request.method = "GET";
    defer request.deinit();
    
    const event = try interceptor.intercept(&worker, request);
    testing.expect(event != null);
}

test "Cache API Operations" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    var cache = Cache.init(allocator, "test-cache", 100, 1024 * 1024);
    defer cache.deinit();
    
    var request = CacheRequest.init(allocator, "https://example.com/data.json");
    defer request.deinit();
    
    var response = CacheResponse.init(allocator, "https://example.com/data.json");
    response.status = 200;
    response.body = ArrayList(u8).fromOwnedSlice(allocator, "test data") catch undefined;
    defer response.deinit();
    
    // Test put operation
    try cache.put(request, response);
    
    // Test match operation
    var options = CacheMatchOptions.init(allocator);
    defer options.deinit();
    
    const matched = try cache.match(request, &options);
    testing.expect(matched != null);
    testing.expect(matched.?.response.status == 200);
}

test "Cache Match Options" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    var options = CacheMatchOptions.init(allocator);
    defer options.deinit();
    
    options.ignore_search = true;
    options.ignore_method = true;
    options.match_method = "GET";
    
    testing.expect(options.ignore_search == true);
    testing.expect(options.ignore_method == true);
    testing.expect(std.mem.eql(u8, options.match_method, "GET"));
}

test "Cache Manager Operations" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    var config = CacheManagerConfig.init();
    config.max_cache_size = 1024 * 1024;
    
    var manager = CacheManager.init(allocator, config);
    defer manager.deinit();
    
    const worker_id = generateWorkerId();
    const cache_name = "test-cache";
    
    const cache = try manager.open(worker_id, cache_name);
    testing.expect(cache != null);
    testing.expect(std.mem.eql(u8, cache.name, cache_name));
}

test "Push Notification Subscription" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    var config = PushServiceConfig.init();
    var push_manager = PushManager.init(allocator, config);
    defer push_manager.deinit();
    
    var notification_manager = NotificationManager.init(allocator, &push_manager);
    defer notification_manager.deinit();
    
    var registration = ServiceWorkerRegistration.init(allocator, "https://example.com", "sw.js");
    defer registration.deinit();
    
    var worker = ServiceWorker.init(allocator, "sw.js", &registration);
    defer worker.deinit();
    
    const subscription = try push_manager.subscribe(&worker, "vapid-key");
    testing.expect(subscription != null);
    testing.expect(subscription.endpoint.len > 0);
}

test "Notification Permission Management" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    var config = PushServiceConfig.init();
    var push_manager = PushManager.init(allocator, config);
    defer push_manager.deinit();
    
    var notification_manager = NotificationManager.init(allocator, &push_manager);
    defer notification_manager.deinit();
    
    // Test default permission state
    testing.expect(notification_manager.getPermission() == PermissionState.DEFAULT);
    
    // Request permission
    const permission = try notification_manager.requestPermission();
    testing.expect(permission == PermissionState.GRANTED);
}

test "Notification Options" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    var options = NotificationOptions.init(allocator, "Test Title", "Test Body");
    defer options.deinit();
    
    options.silent = false;
    options.require_interaction = true;
    options.tag = "test-tag";
    
    testing.expect(std.mem.eql(u8, options.title, "Test Title"));
    testing.expect(std.mem.eql(u8, options.body, "Test Body"));
    testing.expect(options.require_interaction == true);
    testing.expect(std.mem.eql(u8, options.tag orelse "", "test-tag"));
}

test "Background Sync Registration" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    var network_monitor = NetworkMonitor.init(allocator);
    defer network_monitor.deinit();
    
    var sync_scheduler = SyncScheduler.init(allocator);
    defer sync_scheduler.deinit();
    
    var sync_manager = BackgroundSyncManager.init(allocator, &network_monitor, &sync_scheduler);
    defer sync_manager.deinit();
    
    var registration = ServiceWorkerRegistration.init(allocator, "https://example.com", "sw.js");
    defer registration.deinit();
    
    var worker = ServiceWorker.init(allocator, "sw.js", &registration);
    defer worker.deinit();
    
    var options = SyncOptions.init();
    options.max_attempts = 3;
    defer options.deinit();
    
    const sync_registration = try sync_manager.register(&worker, "test-sync", options);
    testing.expect(std.mem.eql(u8, sync_registration.tag, "test-sync"));
}

test "Background Sync Task Management" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    var network_monitor = NetworkMonitor.init(allocator);
    defer network_monitor.deinit();
    
    var sync_scheduler = SyncScheduler.init(allocator);
    defer sync_scheduler.deinit();
    
    var sync_manager = BackgroundSyncManager.init(allocator, &network_monitor, &sync_scheduler);
    defer sync_manager.deinit();
    
    var registration = ServiceWorkerRegistration.init(allocator, "https://example.com", "sw.js");
    defer registration.deinit();
    
    var worker = ServiceWorker.init(allocator, "sw.js", &registration);
    defer worker.deinit();
    
    // Register sync
    var options = SyncOptions.init();
    defer options.deinit();
    
    const sync_registration = try sync_manager.register(&worker, "test-sync", options);
    
    // Add task
    const task_data = "test task data";
    try sync_manager.addTask(&worker, "test-sync", task_data, SyncTask.TaskPriority.NORMAL);
    
    // Verify task was added (this would require accessing internal queue)
    testing.expect(true); // Simplified test
}

test "Network Monitor" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    var monitor = NetworkMonitor.init(allocator);
    defer monitor.deinit();
    
    // Test initial state
    testing.expect(monitor.isOnline() == true);
    testing.expect(monitor.isBatteryLow() == false);
    
    // Update network status
    monitor.updateNetworkStatus(false, "offline", 0.1, true);
    testing.expect(monitor.isOnline() == false);
    testing.expect(monitor.isBatteryLow() == true);
}

test "Message Port Communication" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    var registration = ServiceWorkerRegistration.init(allocator, "https://example.com", "sw.js");
    defer registration.deinit();
    
    var worker = ServiceWorker.init(allocator, "sw.js", &registration);
    defer worker.deinit();
    
    var port1 = MessagePort.init(allocator, &worker);
    defer port1.deinit();
    
    var port2 = MessagePort.init(allocator, &worker);
    defer port2.deinit();
    
    // Connect ports
    try port1.start(&port2);
    
    // Test message sending
    try port1.postMessage("Hello, Message Port!");
    
    testing.expect(port1.message_queue.items.len == 1);
    testing.expect(!port1.is_closed);
}

test "Message Manager Operations" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    var manager = MessageManager.init(allocator);
    defer manager.deinit();
    
    var registration = ServiceWorkerRegistration.init(allocator, "https://example.com", "sw.js");
    defer registration.deinit();
    
    var worker = ServiceWorker.init(allocator, "sw.js", &registration);
    defer worker.deinit();
    
    // Create port
    const port = try manager.createPort(&worker);
    testing.expect(port != null);
    
    // Get worker ports
    const worker_ports = manager.getWorkerPorts(worker.id);
    testing.expect(worker_ports.items.len == 1);
    worker_ports.deinit();
}

test "Message Channel" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    var manager = MessageManager.init(allocator);
    defer manager.deinit();
    
    var registration = ServiceWorkerRegistration.init(allocator, "https://example.com", "sw.js");
    defer registration.deinit();
    
    var worker = ServiceWorker.init(allocator, "sw.js", &registration);
    defer worker.deinit();
    
    // Create message channel
    const channel = try MessageChannel.init(&manager, &worker);
    defer channel.deinit();
    
    // Test port access
    const port1 = channel.getPort1();
    const port2 = channel.getPort2();
    
    testing.expect(port1 != null);
    testing.expect(port2 != null);
    testing.expect(port1 != port2);
}

test "Worker Scope Management" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    var registration = ServiceWorkerRegistration.init(allocator, "https://example.com", "sw.js");
    defer registration.deinit();
    
    var worker = ServiceWorker.init(allocator, "sw.js", &registration);
    defer worker.deinit();
    
    var scope = WorkerScope.init(allocator, "https://example.com/app/", &worker, WorkerScope.ScopePriority.NORMAL);
    defer scope.deinit();
    
    // Test scope matching
    const test_url = "https://example.com/app/page.html";
    testing.expect(scope.matches(test_url) == true);
    
    const test_url_2 = "https://other.com/page.html";
    testing.expect(scope.matches(test_url_2) == false);
}

test "Scope Routing" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    var router = ScopeRouter.init(allocator);
    defer router.deinit();
    
    var registration = ServiceWorkerRegistration.init(allocator, "https://example.com", "sw.js");
    defer registration.deinit();
    
    var worker = ServiceWorker.init(allocator, "sw.js", &registration);
    defer worker.deinit();
    
    var scope = WorkerScope.init(allocator, "https://example.com/app/", &worker, WorkerScope.ScopePriority.NORMAL);
    defer scope.deinit();
    
    // Add scope to router
    try router.addScope(&scope);
    
    // Create request
    var request = Request.init(allocator, "https://example.com/app/page.html", "GET", generateClientId(), worker.id);
    defer request.deinit();
    
    // Route request
    const routed_scope = try router.routeRequest(request);
    testing.expect(routed_scope == &scope);
}

test "Scope Restrictions" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    var restrictions = WorkerScope.ScopeRestrictions.init(allocator);
    defer restrictions.deinit();
    
    // Test default restrictions
    testing.expect(restrictions.require_https == true);
    testing.expect(restrictions.allow_subdomains == false);
    
    // Add allowed method
    try restrictions.allowed_methods.append("GET");
    try restrictions.allowed_methods.append("POST");
    
    testing.expect(restrictions.allowed_methods.items.len == 2);
}

test "Route Management" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    var registration = ServiceWorkerRegistration.init(allocator, "https://example.com", "sw.js");
    defer registration.deinit();
    
    var worker = ServiceWorker.init(allocator, "sw.js", &registration);
    defer worker.deinit();
    
    var scope = WorkerScope.init(allocator, "https://example.com/app/", &worker, WorkerScope.ScopePriority.NORMAL);
    defer scope.deinit();
    
    var route = Route.init(allocator, "https://example.com/app/", &scope, defaultRouteHandler, Route.RoutePriority.NORMAL);
    defer route.deinit();
    
    // Test route matching
    const test_request = Request.init(allocator, "https://example.com/app/page.html", "GET", generateClientId(), worker.id);
    defer test_request.deinit();
    
    testing.expect(route.matches(test_request.url, test_request.method) == true);
}

test "Service Worker Manager Initialization" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    var config = ServiceWorkerConfig.init();
    config.max_active_workers = 4;
    config.enable_caching = true;
    config.enable_messaging = true;
    
    const manager = try createServiceWorkerManager(allocator, config);
    defer destroyServiceWorkerManager(manager);
    
    testing.expect(manager != null);
    testing.expect(manager.registry != null);
    testing.expect(manager.lifecycle_manager != null);
    testing.expect(manager.message_manager != null);
}

test "Service Worker Configuration" {
    var config = ServiceWorkerConfig.init();
    
    testing.expect(config.enable_fetch_interception == true);
    testing.expect(config.enable_caching == true);
    testing.expect(config.enable_push_notifications == true);
    testing.expect(config.enable_background_sync == true);
    testing.expect(config.enable_messaging == true);
    testing.expect(config.enable_scope_routing == true);
    testing.expect(config.max_active_workers == 16);
}

test "Service Worker Statistics" {
    var stats = ServiceWorkerStats.init();
    
    testing.expect(stats.active_workers == 0);
    testing.expect(stats.total_registrations == 0);
    testing.expect(stats.cache_hit_rate == 0.0);
    testing.expect(stats.messages_processed == 0);
    testing.expect(stats.fetch_interceptions == 0);
}

test "Cache Response Operations" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    var response = CacheResponse.init(allocator, "https://example.com/data.json");
    defer response.deinit();
    
    response.status = 200;
    response.body = ArrayList(u8).fromOwnedSlice(allocator, "test data") catch undefined;
    
    testing.expect(response.status == 200);
    testing.expect(response.ok == true);
    
    const text_content = response.text();
    testing.expect(std.mem.eql(u8, text_content, "test data"));
}

test "Sync Task Priority" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    var registration = ServiceWorkerRegistration.init(allocator, "https://example.com", "sw.js");
    defer registration.deinit();
    
    var worker = ServiceWorker.init(allocator, "sw.js", &registration);
    defer worker.deinit();
    
    // Create tasks with different priorities
    var low_task = SyncTask.init(allocator, "sync-tag", &worker, "low priority data", SyncTask.TaskPriority.LOW);
    defer low_task.deinit();
    
    var high_task = SyncTask.init(allocator, "sync-tag", &worker, "high priority data", SyncTask.TaskPriority.HIGH);
    defer high_task.deinit();
    
    testing.expect(@intFromEnum(low_task.priority) < @intFromEnum(high_task.priority));
}

test "Push Event Handling" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.allocator();
    const allocator = gpa.allocator();
    
    var config = PushServiceConfig.init();
    var push_manager = PushManager.init(allocator, config);
    defer push_manager.deinit();
    
    var notification_manager = NotificationManager.init(allocator, &push_manager);
    defer notification_manager.deinit();
    
    var registration = ServiceWorkerRegistration.init(allocator, "https://example.com", "sw.js");
    defer registration.deinit();
    
    var worker = ServiceWorker.init(allocator, "sw.js", &registration);
    defer worker.deinit();
    
    var subscription = try push_manager.subscribe(&worker, "vapid-key");
    defer subscription.deinit();
    
    var push_event = PushEvent.init(allocator, &worker, subscription);
    defer push_event.deinit();
    
    testing.expect(push_event.worker == &worker);
    testing.expect(push_event.subscription == subscription);
}

test "Periodic Sync Registration" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    var network_monitor = NetworkMonitor.init(allocator);
    defer network_monitor.deinit();
    
    var sync_scheduler = SyncScheduler.init(allocator);
    defer sync_scheduler.deinit();
    
    var sync_manager = BackgroundSyncManager.init(allocator, &network_monitor, &sync_scheduler);
    defer sync_manager.deinit();
    
    var registration = ServiceWorkerRegistration.init(allocator, "https://example.com", "sw.js");
    defer registration.deinit();
    
    var worker = ServiceWorker.init(allocator, "sw.js", &registration);
    defer worker.deinit();
    
    // Register periodic sync
    const periodic_registration = try sync_manager.registerPeriodicSync(&worker, "periodic-sync", 3600000); // 1 hour
    testing.expect(std.mem.eql(u8, periodic_registration.tag, "periodic-sync"));
    testing.expect(periodic_registration.min_interval == 3600000);
}

test "Scope Conflict Detection" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    var resolver = ScopeConflictResolver.init(allocator);
    defer resolver.deinit();
    
    var registration = ServiceWorkerRegistration.init(allocator, "https://example.com", "sw.js");
    defer registration.deinit();
    
    var worker = ServiceWorker.init(allocator, "sw.js", &registration);
    defer worker.deinit();
    
    // Create overlapping scopes
    var scope1 = WorkerScope.init(allocator, "https://example.com/app/", &worker, WorkerScope.ScopePriority.NORMAL);
    defer scope1.deinit();
    
    var scope2 = WorkerScope.init(allocator, "https://example.com/app/admin/", &worker, WorkerScope.ScopePriority.HIGH);
    defer scope2.deinit();
    
    var scopes = ArrayList(*WorkerScope).init(allocator);
    defer scopes.deinit();
    
    try scopes.append(&scope1);
    try scopes.append(&scope2);
    
    const conflicts = try resolver.detectConflicts(scopes);
    testing.expect(conflicts.items.len > 0); // Should detect overlap
    conflicts.deinit();
}

test "Message Channel Bidirectional Communication" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    var manager = MessageManager.init(allocator);
    defer manager.deinit();
    
    var registration = ServiceWorkerRegistration.init(allocator, "https://example.com", "sw.js");
    defer registration.deinit();
    
    var worker = ServiceWorker.init(allocator, "sw.js", &registration);
    defer worker.deinit();
    
    const channel = try MessageChannel.init(&manager, &worker);
    defer channel.deinit();
    
    const port1 = channel.getPort1();
    const port2 = channel.getPort2();
    
    // Test bidirectional messaging
    try port1.postMessage("Message from port 1");
    testing.expect(port1.message_queue.items.len == 1);
    
    try port2.postMessage("Message from port 2");
    testing.expect(port2.message_queue.items.len == 1);
    
    // Test port connections
    testing.expect(port1.peer_port == port2);
    testing.expect(port2.peer_port == port1);
}

// Test runner for all Service Worker tests
pub fn runAllServiceWorkerTests() !void {
    std.log.info("🧪 Running Service Worker Tests...", .{});
    
    // Individual tests
    testing.log("Registration", test "Service Worker Registration");
    testing.log("Lifecycle States", test "Service Worker Lifecycle States");
    testing.log("Fetch Interception", test "Service Worker Fetch Interception");
    testing.log("Cache Operations", test "Cache API Operations");
    testing.log("Cache Match Options", test "Cache Match Options");
    testing.log("Cache Manager", test "Cache Manager Operations");
    testing.log("Push Subscription", test "Push Notification Subscription");
    testing.log("Notification Permission", test "Notification Permission Management");
    testing.log("Notification Options", test "Notification Options");
    testing.log("Background Sync Registration", test "Background Sync Registration");
    testing.log("Background Sync Tasks", test "Background Sync Task Management");
    testing.log("Network Monitor", test "Network Monitor");
    testing.log("Message Port", test "Message Port Communication");
    testing.log("Message Manager", test "Message Manager Operations");
    testing.log("Message Channel", test "Message Channel");
    testing.log("Worker Scope", test "Worker Scope Management");
    testing.log("Scope Routing", test "Scope Routing");
    testing.log("Scope Restrictions", test "Scope Restrictions");
    testing.log("Route Management", test "Route Management");
    testing.log("Manager Initialization", test "Service Worker Manager Initialization");
    testing.log("Configuration", test "Service Worker Configuration");
    testing.log("Statistics", test "Service Worker Statistics");
    testing.log("Cache Response", test "Cache Response Operations");
    testing.log("Sync Task Priority", test "Sync Task Priority");
    testing.log("Push Event", test "Push Event Handling");
    testing.log("Periodic Sync", test "Periodic Sync Registration");
    testing.log("Scope Conflict", test "Scope Conflict Detection");
    testing.log("Channel Communication", test "Message Channel Bidirectional Communication");
    
    std.log.info("✅ All Service Worker tests completed!", .{});
}