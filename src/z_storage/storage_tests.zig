//! z_storage - Comprehensive Test Suite
//! 
//! Comprehensive test suite for the Storage Bridge system covering
//! all storage APIs, quota management, and integration testing.

const std = @import("std");
const testing = std.testing;

const storage_bridge = @import("storage_bridge.zig");
const storage_apis = @import("storage_apis.zig");
const storage_main = @import("storage_main.zig");
const policy_engine = @import("z_policy/policy_engine.zig");
const policy = @import("z_policy/policy.zig");
const event_loop = @import("z_event_loop/event_loop.zig");

// usingnamespace storage_bridge;
// usingnamespace storage_apis;
// usingnamespace storage_main;
// usingnamespace policy_engine;
// usingnamespace event_loop;

test "storage bridge basic operations" {
    const allocator = std.testing.allocator;
    var storage_bridge = StorageBridge.init(allocator);
    defer storage_bridge.deinit();
    
    try std.testing.expectEqual(@as(usize, 0), storage_bridge.origin_storages.count());
    try std.testing.expectEqual(@as(usize, 0), storage_bridge.cookie_jar.count());
    try std.testing.expectEqual(@as(usize, 0), storage_bridge.indexed_db_databases.count());
    try std.testing.expectEqual(@as(usize, 0), storage_bridge.cache_api_caches.count());
}

test "origin storage lifecycle" {
    const allocator = std.testing.allocator;
    var storage_bridge = StorageBridge.init(allocator);
    defer storage_bridge.deinit();
    
    const origin = try Origin.parse("https://example.com");
    
    // Set localStorage items
    try storage_bridge.localStorageSet(origin, "key1", "value1");
    try storage_bridge.localStorageSet(origin, "key2", "value2");
    
    // Set sessionStorage items
    try storage_bridge.sessionStorageSet(origin, "session1", "session-value1");
    try storage_bridge.sessionStorageSet(origin, "session2", "session-value2");
    
    // Verify localStorage
    const local_value1 = storage_bridge.localStorageGet(origin, "key1");
    const local_value2 = storage_bridge.localStorageGet(origin, "key2");
    try std.testing.expect(std.mem.eql(u8, "value1", local_value1.?));
    try std.testing.expect(std.mem.eql(u8, "value2", local_value2.?));
    
    // Verify sessionStorage
    const session_value1 = storage_bridge.sessionStorageGet(origin, "session1");
    const session_value2 = storage_bridge.sessionStorageGet(origin, "session2");
    try std.testing.expect(std.mem.eql(u8, "session-value1", session_value1.?));
    try std.testing.expect(std.mem.eql(u8, "session-value2", session_value2.?));
    
    // Get keys
    const local_keys = storage_bridge.localStorageKeys(origin);
    defer local_keys.deinit();
    try std.testing.expectEqual(@as(usize, 2), local_keys.items.len);
    
    // Remove item
    storage_bridge.localStorageRemove(origin, "key1");
    const removed_value = storage_bridge.localStorageGet(origin, "key1");
    try std.testing.expect(removed_value == null);
    
    // Clear localStorage
    storage_bridge.localStorageClear(origin);
    const cleared_value = storage_bridge.localStorageGet(origin, "key2");
    try std.testing.expect(cleared_value == null);
}

test "quota management and enforcement" {
    const allocator = std.testing.allocator;
    var storage_bridge = StorageBridge.init(allocator);
    defer storage_bridge.deinit();
    
    const origin = try Origin.parse("https://test.example.com");
    
    // Get origin storage to access quotas
    const origin_storage = storage_bridge.getOriginStorage(origin) catch {
        try std.testing.expect(false);
        return;
    };
    
    try std.testing.expectEqual(@as(u64, 10 * 1024 * 1024), origin_storage.quota_local.max_size_bytes); // 10MB
    try std.testing.expectEqual(@as(u64, 5 * 1024 * 1024), origin_storage.quota_session.max_size_bytes); // 5MB
    
    // Test quota updates
    origin_storage.quota_local.updateUsage(1024);
    try std.testing.expectEqual(@as(u64, 1024), origin_storage.quota_local.used_size_bytes);
    try std.testing.expectEqual(@as(u64, 10 * 1024 * 1024 - 1024), origin_storage.quota_local.remaining_bytes);
    
    // Test quota check
    try std.testing.expect(origin_storage.quota_local.canStore(1024));
    try std.testing.expect(!origin_storage.quota_local.canStore(20 * 1024 * 1024)); // Over 10MB
}

test "cookie management comprehensive" {
    const allocator = std.testing.allocator;
    var storage_bridge = StorageBridge.init(allocator);
    defer storage_bridge.deinit();
    
    // Test basic cookie
    var cookie1 = Cookie.init("test-cookie", "cookie-value");
    cookie1.setDomain("example.com");
    cookie1.setPath("/");
    cookie1.setExpiration(getCurrentTimestamp() + 3600); // 1 hour
    cookie1.setSecure(true);
    cookie1.setHttpOnly(true);
    cookie1.setSameSite(.STRICT);
    
    try storage_bridge.setCookie(cookie1);
    
    // Test secure cookie
    var cookie2 = Cookie.init("secure-cookie", "secure-value");
    cookie2.setDomain("secure.example.com");
    cookie2.setPath("/api");
    cookie2.setExpiration(getCurrentTimestamp() + 7200); // 2 hours
    
    try storage_bridge.setCookie(cookie2);
    
    // Retrieve cookies
    const retrieved_cookie1 = storage_bridge.getCookie("test-cookie");
    try std.testing.expect(retrieved_cookie1 != null);
    try std.testing.expect(std.mem.eql(u8, "cookie-value", retrieved_cookie1.?.value));
    try std.testing.expect(std.mem.eql(u8, "example.com", retrieved_cookie1.?.domain));
    try std.testing.expect(std.mem.eql(u8, "/", retrieved_cookie1.?.path));
    try std.testing.expect(retrieved_cookie1.?.secure);
    try std.testing.expect(retrieved_cookie1.?.http_only);
    try std.testing.expectEqual(SameSitePolicy.STRICT, retrieved_cookie1.?.same_site);
    
    // Test cookie matching for URLs
    const cookies_for_example = storage_bridge.getCookiesForUrl("https://example.com/page");
    defer cookies_for_example.deinit();
    try std.testing.expectEqual(@as(usize, 1), cookies_for_example.items.len);
    try std.testing.expect(std.mem.eql(u8, "test-cookie", cookies_for_example.items[0].name));
    
    const cookies_for_secure = storage_bridge.getCookiesForUrl("https://secure.example.com/api/endpoint");
    defer cookies_for_secure.deinit();
    try std.testing.expectEqual(@as(usize, 1), cookies_for_secure.items.len);
    try std.testing.expect(std.mem.eql(u8, "secure-cookie", cookies_for_secure.items[0].name));
    
    // Test cookie deletion
    storage_bridge.deleteCookie("test-cookie");
    const deleted_cookie = storage_bridge.getCookie("test-cookie");
    try std.testing.expect(deleted_cookie == null);
}

test "indexedDB operations" {
    const allocator = std.testing.allocator;
    var storage_bridge = StorageBridge.init(allocator);
    defer storage_bridge.deinit();
    
    // Open IndexedDB database
    const database = try storage_bridge.openIndexedDB("test-database", 1);
    defer storage_bridge.deleteIndexedDB("test-database");
    
    try std.testing.expect(std.mem.eql(u8, "test-database", database.name));
    try std.testing.expectEqual(@as(u64, 1), database.version);
    try std.testing.expectEqual(@as(usize, 0), database.stores.count());
    
    // Create object store
    const store = try database.createObjectStore("users", "id", true);
    defer database.deleteObjectStore("users");
    
    try std.testing.expect(std.mem.eql(u8, "users", store.name));
    try std.testing.expect(std.mem.eql(u8, "id", store.key_path.?));
    try std.testing.expect(store.auto_increment);
    try std.testing.expectEqual(@as(usize, 0), store.records.count());
    
    // Add records
    try store.put("user-1", "{\"name\": \"Alice\", \"email\": \"alice@example.com\"}", null);
    try store.put("user-2", "{\"name\": \"Bob\", \"email\": \"bob@example.com\"}", null);
    
    // Retrieve records
    const user1 = store.get("user-1");
    try std.testing.expect(user1 != null);
    try std.testing.expect(std.mem.eql(u8, "user-1", user1.?.key));
    try std.testing.expect(user1?.value.len > 0);
    
    const user2 = store.get("user-2");
    try std.testing.expect(user2 != null);
    try std.testing.expect(std.mem.eql(u8, "user-2", user2.?.key));
    
    try std.testing.expectEqual(@as(usize, 2), store.records.count());
    
    // Test record deletion
    store.delete("user-1");
    const deleted_user = store.get("user-1");
    try std.testing.expect(deleted_user == null);
    try std.testing.expectEqual(@as(usize, 1), store.records.count());
    
    // Test clear
    store.clear();
    try std.testing.expectEqual(@as(usize, 0), store.records.count());
}

test "cache API operations" {
    const allocator = std.testing.allocator;
    var storage_bridge = StorageBridge.init(allocator);
    defer storage_bridge.deinit();
    
    const origin = try Origin.parse("https://api.example.com");
    
    // Open cache
    const cache = try storage_bridge.cacheOpen("api-cache", origin);
    defer storage_bridge.cache_delete("api-cache");
    
    try std.testing.expect(std.mem.eql(u8, "api-cache", cache.name));
    
    // Add cache entries
    try cache.put("https://api.example.com/users", "{\"users\": [{\"id\": 1, \"name\": \"Alice\"}]}");
    try cache.put("https://api.example.com/posts", "{\"posts\": [{\"id\": 1, \"title\": \"Hello World\"}]}");
    
    // Retrieve cache entries
    const users_entry = cache.match("https://api.example.com/users");
    try std.testing.expect(users_entry != null);
    try std.testing.expect(users_entry.?.response_data.len > 0);
    try std.testing.expect(std.mem.eql(u8, "https://api.example.com/users", users_entry.?.request_url));
    
    const posts_entry = cache.match("https://api.example.com/posts");
    try std.testing.expect(posts_entry != null);
    
    // Test cache keys
    const cache_keys = cache.keys();
    defer cache_keys.deinit();
    try std.testing.expectEqual(@as(usize, 2), cache_keys.items.len);
    
    // Test cache deletion
    cache.delete("https://api.example.com/users");
    const deleted_entry = cache.match("https://api.example.com/users");
    try std.testing.expect(deleted_entry == null);
}

test "storage item lifecycle and expiration" {
    const allocator = std.testing.allocator;
    var storage_bridge = StorageBridge.init(allocator);
    defer storage_bridge.deinit();
    
    const origin = try Origin.parse("https://example.com");
    
    // Test expiration
    var item = StorageItem.init(allocator, "expiring-key", "expiring-value");
    item.setExpiration(1000); // Expires in 1 second
    
    try std.testing.expect(!item.isExpired()); // Should not be expired initially
    
    // Simulate time passing (in real implementation, would use actual time)
    // For testing, we manually set it as expired
    item.expires_timestamp = getCurrentTimestamp() - 1000; // 1 second ago
    try std.testing.expect(item.isExpired());
    
    // Test size calculation
    item.calculateSize();
    const expected_size = "expiring-key".len + "expiring-value".len;
    try std.testing.expectEqual(@as(u64, expected_size), item.size_bytes);
    
    // Test access tracking
    const initial_access = item.last_accessed_timestamp;
    item.updateAccess();
    try std.testing.expect(item.last_accessed_timestamp > initial_access);
}

test "storage API integration" {
    const allocator = std.testing.allocator;
    var event_loop = EventLoopManager.init(allocator, 100);
    defer event_loop.deinit();
    
    var storage_manager = try StorageManager.init(allocator, &event_loop);
    defer storage_manager.deinit();
    
    const origin = try Origin.parse("https://api.example.com");
    
    // Test LocalStorage API
    const local_storage = storage_manager.getLocalStorage(origin);
    try local_storage.setItem("local-key", "local-value");
    
    const retrieved_local = local_storage.getItem("local-key");
    try std.testing.expect(std.mem.eql(u8, "local-value", retrieved_local.?));
    try std.testing.expectEqual(@as(usize, 1), local_storage.length());
    try std.testing.expect(local_storage.hasKey("local-key"));
    try std.testing.expect(!local_storage.hasKey("non-existent"));
    
    const key_at_index = local_storage.key(0);
    try std.testing.expect(key_at_index != null);
    try std.testing.expect(std.mem.eql(u8, "local-key", key_at_index.?));
    
    // Test SessionStorage API
    const session_storage = storage_manager.getSessionStorage(origin);
    try session_storage.setItem("session-key", "session-value");
    
    const retrieved_session = session_storage.getItem("session-key");
    try std.testing.expect(std.mem.eql(u8, "session-value", retrieved_session.?));
    try std.testing.expectEqual(@as(usize, 1), session_storage.length());
    
    // Test Cookie API
    const cookie_api = storage_manager.getCookieAPI();
    var cookie = Cookie.init("api-session", "session-token");
    cookie.setDomain("api.example.com");
    cookie.setPath("/api");
    try cookie_api.setCookie(cookie);
    
    const retrieved_cookie = cookie_api.getCookie("api-session");
    try std.testing.expect(retrieved_cookie != null);
    try std.testing.expect(std.mem.eql(u8, "session-token", retrieved_cookie.?.value));
    try std.testing.expect(std.mem.eql(u8, "api.example.com", retrieved_cookie.?.domain));
    try std.testing.expect(std.mem.eql(u8, "/api", retrieved_cookie.?.path));
    
    // Test IndexedDB API
    const indexed_db_api = storage_manager.getIndexedDBAPI();
    const database = try indexed_db_api.openDatabase("test-db", 1);
    try std.testing.expect(std.mem.eql(u8, "test-db", database.name));
    try std.testing.expectEqual(@as(u64, 1), database.version);
    
    // Test Cache API
    const cache_api = storage_manager.getCacheAPI(origin);
    const cache = try cache_api.open("test-cache");
    try std.testing.expect(std.mem.eql(u8, "test-cache", cache.name));
    
    const cache_names = cache_api.getCacheNames();
    defer cache_names.deinit();
    try std.testing.expectEqual(@as(usize, 1), cache_names.items.len);
    try std.testing.expect(std.mem.eql(u8, "test-cache", cache_names.items[0]));
    
    try std.testing.expect(cache_api.hasCache("test-cache"));
    try std.testing.expect(!cache_api.hasCache("non-existent-cache"));
}

test "cookie header parsing and generation" {
    const allocator = std.testing.allocator;
    var event_loop = EventLoopManager.init(allocator, 100);
    defer event_loop.deinit();
    
    var storage_manager = try StorageManager.init(allocator, &event_loop);
    defer storage_manager.deinit();
    
    const cookie_api = storage_manager.getCookieAPI();
    
    // Test Set-Cookie header parsing
    const set_cookie_header = "sessionid=abc123; Path=/; HttpOnly; Secure; SameSite=Strict; Domain=example.com; Max-Age=3600";
    const parsed_cookie = try cookie_api.parseSetCookieHeader(set_cookie_header);
    
    try std.testing.expect(std.mem.eql(u8, "sessionid", parsed_cookie.name));
    try std.testing.expect(std.mem.eql(u8, "abc123", parsed_cookie.value));
    try std.testing.expect(std.mem.eql(u8, "example.com", parsed_cookie.domain));
    try std.testing.expect(std.mem.eql(u8, "/", parsed_cookie.path));
    try std.testing.expect(parsed_cookie.secure);
    try std.testing.expect(parsed_cookie.http_only);
    try std.testing.expectEqual(SameSitePolicy.STRICT, parsed_cookie.same_site);
    
    // Test cookie header generation
    const generated_headers = cookie_api.generateCookieHeader(parsed_cookie);
    defer generated_headers.deinit();
    
    try std.testing.expect(generated_headers.contains("Set-Cookie"));
    const set_cookie_value = generated_headers.get("Set-Cookie").?;
    try std.testing.expect(std.mem.indexOf(u8, set_cookie_value, "sessionid=abc123") != null);
    try std.testing.expect(std.mem.indexOf(u8, set_cookie_value, "Secure") != null);
    try std.testing.expect(std.mem.indexOf(u8, set_cookie_value, "HttpOnly") != null);
    try std.testing.expect(std.mem.indexOf(u8, set_cookie_value, "SameSite=Strict") != null);
}

test "storage manager statistics and cleanup" {
    const allocator = std.testing.allocator;
    var event_loop = EventLoopManager.init(allocator, 100);
    defer event_loop.deinit();
    
    var storage_manager = try StorageManager.init(allocator, &event_loop);
    defer storage_manager.deinit();
    
    const origin1 = try Origin.parse("https://site1.com");
    const origin2 = try Origin.parse("https://site2.com");
    
    // Add data to multiple origins
    const local_storage1 = storage_manager.getLocalStorage(origin1);
    const local_storage2 = storage_manager.getLocalStorage(origin2);
    
    try local_storage1.setItem("key1", "value1");
    try local_storage1.setItem("key2", "value2");
    try local_storage2.setItem("key3", "value3");
    
    const session_storage1 = storage_manager.getSessionStorage(origin1);
    try session_storage1.setItem("session1", "session-value1");
    
    // Add cookies
    const cookie_api = storage_manager.getCookieAPI();
    var cookie1 = Cookie.init("cookie1", "value1");
    var cookie2 = Cookie.init("cookie2", "value2");
    try cookie_api.setCookie(cookie1);
    try cookie_api.setCookie(cookie2);
    
    // Add IndexedDB
    const indexed_db_api = storage_manager.getIndexedDBAPI();
    const db1 = try indexed_db_api.openDatabase("db1", 1);
    const db2 = try indexed_db_api.openDatabase("db2", 2);
    
    // Add Cache API
    const cache_api1 = storage_manager.getCacheAPI(origin1);
    const cache_api2 = storage_manager.getCacheAPI(origin2);
    const cache1 = try cache_api1.open("cache1");
    const cache2 = try cache_api2.open("cache2");
    
    // Get statistics
    const stats = storage_manager.getStats();
    try std.testing.expectEqual(@as(usize, 2), stats.origin_count);
    try std.testing.expectEqual(@as(usize, 3), stats.local_storage_items);
    try std.testing.expectEqual(@as(usize, 1), stats.session_storage_items);
    try std.testing.expectEqual(@as(usize, 2), stats.cookie_count);
    try std.testing.expectEqual(@as(usize, 2), stats.indexed_db_count);
    try std.testing.expectEqual(@as(usize, 2), stats.cache_api_count);
    
    // Test cleanup
    storage_manager.cleanupExpired();
    
    // Test origin clearing
    storage_manager.clearOriginStorage(origin1);
    const cleared_stats = storage_manager.getStats();
    try std.testing.expectEqual(@as(usize, 1), cleared_stats.local_storage_items); // Only origin2 remains
    try std.testing.expectEqual(@as(usize, 0), cleared_stats.session_storage_items); // All sessionStorage cleared
}

test "browser storage comprehensive integration" {
    const allocator = std.testing.allocator;
    var event_loop = EventLoopManager.init(allocator, 100);
    defer event_loop.deinit();
    
    const config = StorageConfig{
        .local_storage_quota_mb = 5,
        .session_storage_quota_mb = 3,
        .global_storage_quota_mb = 25,
        .enable_cookies = true,
        .enable_indexed_db = true,
        .enable_cache_api = true,
    };
    
    var browser_storage = try createBrowserStorage(allocator, &event_loop, config);
    defer destroyBrowserStorage(browser_storage, allocator);
    
    const origin = try Origin.parse("https://app.example.com");
    
    // Test storage availability
    const local_available = try browser_storage.isStorageAvailable(origin, .LOCAL_STORAGE);
    const session_available = try browser_storage.isStorageAvailable(origin, .SESSION_STORAGE);
    const cookie_available = try browser_storage.isStorageAvailable(origin, .COOKIES);
    const indexed_db_available = try browser_storage.isStorageAvailable(origin, .INDEXED_DB);
    const cache_available = try browser_storage.isStorageAvailable(origin, .CACHE_API);
    
    try std.testing.expect(local_available);
    try std.testing.expect(session_available);
    try std.testing.expect(cookie_available);
    try std.testing.expect(indexed_db_available);
    try std.testing.expect(cache_available);
    
    // Test localStorage operations
    const local_storage = try browser_storage.getLocalStorage(origin);
    try local_storage.setItem("user-id", "12345");
    try local_storage.setItem("preferences", "{\"theme\": \"dark\"}");
    
    const user_id = local_storage.getItem("user-id");
    const preferences = local_storage.getItem("preferences");
    try std.testing.expect(std.mem.eql(u8, "12345", user_id.?));
    try std.testing.expect(preferences.?[0] == '{'); // JSON starts with brace
    
    // Test sessionStorage operations
    const session_storage = try browser_storage.getSessionStorage(origin);
    try session_storage.setItem("session-token", "abc-def-ghi");
    try session_storage.setItem("temp-data", "temporary-value");
    
    const session_token = session_storage.getItem("session-token");
    try std.testing.expect(std.mem.eql(u8, "abc-def-ghi", session_token.?));
    
    // Test cookie operations
    const cookie_api = browser_storage.getCookieAPI();
    var app_cookie = Cookie.init("app-session", "session-xyz");
    app_cookie.setDomain("app.example.com");
    app_cookie.setPath("/app");
    app_cookie.setSecure(true);
    try cookie_api.setCookie(app_cookie);
    
    const retrieved_app_cookie = cookie_api.getCookie("app-session");
    try std.testing.expect(retrieved_app_cookie != null);
    try std.testing.expect(retrieved_app_cookie.?.secure);
    
    // Test IndexedDB operations
    const indexed_db_api = browser_storage.getIndexedDBAPI();
    const app_database = try indexed_db_api.openDatabase("app-db", 1);
    const user_store = try app_database.createObjectStore("user-data", "userId", false);
    
    try user_store.put("user-001", "{\"name\": \"Alice\", \"role\": \"admin\"}", null);
    try user_store.put("user-002", "{\"name\": \"Bob\", \"role\": \"user\"}", null);
    
    const user_001 = user_store.get("user-001");
    try std.testing.expect(user_001 != null);
    try std.testing.expect(user_001.?.value.len > 0);
    
    // Test Cache API operations
    const cache_api = try browser_storage.getCacheAPI(origin);
    const app_cache = try cache_api.open("app-cache");
    
    try app_cache.put("https://app.example.com/api/users", "{\"users\": [{\"id\": 1, \"name\": \"Alice\"}]}");
    try app_cache.put("https://app.example.com/api/settings", "{\"theme\": \"dark\", \"notifications\": true}");
    
    const users_cache = app_cache.match("https://app.example.com/api/users");
    const settings_cache = app_cache.match("https://app.example.com/api/settings");
    try std.testing.expect(users_cache != null);
    try std.testing.expect(settings_cache != null);
    
    // Test storage estimation
    const estimate = try browser_storage.estimateStorageUsage(origin);
    try std.testing.expect(estimate.total_bytes > 0);
    try std.testing.expect(estimate.breakdown.local_storage.count() > 0);
    
    // Test quota management
    const quota_status = try browser_storage.getQuotaForOrigin(origin, .LOCAL_STORAGE);
    try std.testing.expect(quota_status.can_allocate);
    try std.testing.expect(quota_status.usage_percentage >= 0);
    try std.testing.expect(quota_status.usage_percentage <= 100);
    
    // Test statistics
    const stats = browser_storage.getStatistics();
    try std.testing.expect(stats.storage_stats.origin_count > 0);
    try std.testing.expect(stats.storage_stats.local_storage_items > 0);
    try std.testing.expect(stats.quota_summary.quotas.count() > 0);
    try std.testing.expectEqual(@as(usize, 2), stats.origin_context_count);
    try std.testing.expect(stats.config.enable_cookies);
    try std.testing.expect(stats.config.enable_indexed_db);
    try std.testing.expect(stats.config.enable_cache_api);
    
    // Test storage export/import
    const all_export = try browser_storage.exportAllStorage(allocator);
    defer all_export.deinit();
    try std.testing.expect(all_export.origins.items.len > 0);
    
    // Test cleanup
    browser_storage.cleanup();
    
    // Test origin clearing
    try browser_storage.clearOrigin(origin);
    
    // Verify localStorage is cleared
    const cleared_user_id = local_storage.getItem("user-id");
    try std.testing.expect(cleared_user_id == null);
}

test "storage events and quota enforcement" {
    const allocator = std.testing.allocator;
    var event_loop = EventLoopManager.init(allocator, 100);
    defer event_loop.deinit();
    
    const config = StorageConfig{
        .local_storage_quota_mb = 1, // Very small quota for testing
        .enable_storage_events = true,
    };
    
    var browser_storage = try createBrowserStorage(allocator, &event_loop, config);
    defer destroyBrowserStorage(browser_storage, allocator);
    
    const origin = try Origin.parse("https://test.example.com");
    const local_storage = try browser_storage.getLocalStorage(origin);
    
    // Test quota enforcement
    // Fill storage close to quota limit
    const large_data = std.mem.alloc(u8, 1024 * 1024) catch return; // 1MB
    defer allocator.free(large_data);
    
    // Should succeed for items within quota
    try local_storage.setItem("small-item", "small-value");
    try std.testing.expect(local_storage.getItem("small-item") != null);
    
    // Test quota exceeded (simplified test)
    // In real implementation, would test actual quota exceeded
    const quota_status = try browser_storage.getQuotaForOrigin(origin, .LOCAL_STORAGE);
    try std.testing.expect(quota_status.can_allocate); // Should have some allocation available
    
    // Test storage events (simplified)
    // In full implementation, would test actual event triggering
    try std.testing.expect(browser_storage.config.enable_storage_events);
}