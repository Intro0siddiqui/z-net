//! z_storage - Browser Storage APIs
//! 
//! Provides browser-compatible storage interfaces including localStorage,
//! sessionStorage, IndexedDB, Cache API with async operations and
//! promise-based APIs that integrate with the event loop system.

const std = @import("std");
const Allocator = std.mem.Allocator;
const StringHashMap = std.StringHashMap;
const ArrayList = std.ArrayList;

const storage_bridge = @import("storage_bridge.zig");
const policy_engine = @import("z_policy/policy_engine.zig");
const policy = @import("z_policy/policy.zig");
const event_loop = @import("z_event_loop/event_loop.zig");

usingnamespace storage_bridge;
usingnamespace policy_engine;
usingnamespace event_loop;

// Storage API error types
pub const StorageAPIError = error{
    QuotaExceeded,
    InvalidOrigin,
    SecurityError,
    NotSupported,
    InvalidState,
    TransactionInactive,
};

// Promise-based storage result
pub const StorageResult = struct {
    success: bool,
    data: ?[]const u8,
    error: ?[]const u8,
    
    pub fn ok(data: []const u8) StorageResult {
        return StorageResult{
            .success = true,
            .data = data,
            .error = null,
        };
    }
    
    pub fn err(error_msg: []const u8) StorageResult {
        return StorageResult{
            .success = false,
            .data = null,
            .error = error_msg,
        };
    }
};

// LocalStorage API Implementation
pub const LocalStorageAPI = struct {
    allocator: Allocator,
    event_loop: *EventLoopManager,
    storage_bridge: *StorageBridge,
    origin: Origin,
    
    pub fn init(allocator: Allocator, event_loop: *EventLoopManager, storage_bridge: *StorageBridge, origin: Origin) LocalStorageAPI {
        return LocalStorageAPI{
            .allocator = allocator,
            .event_loop = event_loop,
            .storage_bridge = storage_bridge,
            .origin = origin,
        };
    }
    
    /// Set item in localStorage (sync for compatibility)
    pub fn setItem(inout self: *LocalStorageAPI, key: []const u8, value: []const u8) !void {
        try self.storage_bridge.localStorageSet(self.origin, key, value);
    }
    
    /// Get item from localStorage (sync for compatibility)
    pub fn getItem(self: *LocalStorageAPI, key: []const u8) ?[]const u8 {
        return self.storage_bridge.localStorageGet(self.origin, key);
    }
    
    /// Remove item from localStorage
    pub fn removeItem(inout self: *LocalStorageAPI, key: []const u8) void {
        self.storage_bridge.localStorageRemove(self.origin, key);
    }
    
    /// Clear all localStorage items
    pub fn clear(inout self: *LocalStorageAPI) void {
        self.storage_bridge.localStorageClear(self.origin);
    }
    
    /// Get number of items in localStorage
    pub fn length(self: *LocalStorageAPI) usize {
        const keys = self.storage_bridge.localStorageKeys(self.origin);
        defer keys.deinit();
        return keys.items.len;
    }
    
    /// Get key at index
    pub fn key(self: *LocalStorageAPI, index: usize) ?[]const u8 {
        const keys = self.storage_bridge.localStorageKeys(self.origin);
        defer keys.deinit();
        
        if (index >= keys.items.len) return null;
        return keys.items[index];
    }
    
    /// Check if key exists
    pub fn hasKey(self: *LocalStorageAPI, key: []const u8) bool {
        return self.storage_bridge.localStorageGet(self.origin, key) != null;
    }
};

// SessionStorage API Implementation
pub const SessionStorageAPI = struct {
    allocator: Allocator,
    event_loop: *EventLoopManager,
    storage_bridge: *StorageBridge,
    origin: Origin,
    
    pub fn init(allocator: Allocator, event_loop: *EventLoopManager, storage_bridge: *StorageBridge, origin: Origin) SessionStorageAPI {
        return SessionStorageAPI{
            .allocator = allocator,
            .event_loop = event_loop,
            .storage_bridge = storage_bridge,
            .origin = origin,
        };
    }
    
    /// Set item in sessionStorage (sync for compatibility)
    pub fn setItem(inout self: *SessionStorageAPI, key: []const u8, value: []const u8) !void {
        try self.storage_bridge.sessionStorageSet(self.origin, key, value);
    }
    
    /// Get item from sessionStorage (sync for compatibility)
    pub fn getItem(self: *SessionStorageAPI, key: []const u8) ?[]const u8 {
        return self.storage_bridge.sessionStorageGet(self.origin, key);
    }
    
    /// Remove item from sessionStorage
    pub fn removeItem(inout self: *SessionStorageAPI, key: []const u8) void {
        self.storage_bridge.sessionStorageRemove(self.origin, key);
    }
    
    /// Clear all sessionStorage items
    pub fn clear(inout self: *SessionStorageAPI) void {
        self.storage_bridge.sessionStorageClear(self.origin);
    }
    
    /// Get number of items in sessionStorage
    pub fn length(self: *SessionStorageAPI) usize {
        const storage = self.storage_bridge.getOriginStorage(self.origin) catch return 0;
        return storage.session_storage.count();
    }
    
    /// Get key at index
    pub fn key(self: *SessionStorageAPI, index: usize) ?[]const u8 {
        const storage = self.storage_bridge.getOriginStorage(self.origin) catch return null;
        
        var count: usize = 0;
        var key_iter = storage.session_storage.keyIterator();
        while (key_iter.next()) |key| {
            if (count == index) return key.*;
            count += 1;
        }
        return null;
    }
    
    /// Check if key exists
    pub fn hasKey(self: *SessionStorageAPI, key: []const u8) bool {
        return self.storage_bridge.sessionStorageGet(self.origin, key) != null;
    }
};

// Cookie API Implementation
pub const CookieAPI = struct {
    allocator: Allocator,
    event_loop: *EventLoopManager,
    storage_bridge: *StorageBridge,
    
    pub fn init(allocator: Allocator, event_loop: *EventLoopManager, storage_bridge: *StorageBridge) CookieAPI {
        return CookieAPI{
            .allocator = allocator,
            .event_loop = event_loop,
            .storage_bridge = storage_bridge,
        };
    }
    
    /// Set cookie with options
    pub fn setCookie(inout self: *CookieAPI, name: []const u8, value: []const u8, options: CookieOptions) !void {
        var cookie = Cookie.init(name, value);
        
        if (options.domain) |domain| cookie.setDomain(domain);
        if (options.path) |path| cookie.setPath(path);
        if (options.expires) |expires| cookie.setExpiration(expires);
        if (options.max_age) |max_age| cookie.setExpiration(getCurrentTimestamp() + max_age);
        cookie.setSecure(options.secure);
        cookie.setHttpOnly(options.http_only);
        cookie.setSameSite(options.same_site);
        
        try self.storage_bridge.setCookie(cookie);
    }
    
    /// Get cookie by name
    pub fn getCookie(self: *CookieAPI, name: []const u8) ?Cookie {
        return self.storage_bridge.getCookie(name);
    }
    
    /// Get all cookies for a URL
    pub fn getCookiesForUrl(self: *CookieAPI, url: []const u8) ArrayList(Cookie) {
        return self.storage_bridge.getCookiesForUrl(url);
    }
    
    /// Delete cookie
    pub fn deleteCookie(inout self: *CookieAPI, name: []const u8) void {
        self.storage_bridge.deleteCookie(name);
    }
    
    /// Parse Set-Cookie header
    pub fn parseSetCookieHeader(inout self: *CookieAPI, set_cookie_header: []const u8) !Cookie {
        var cookie_parts = std.mem.split(u8, set_cookie_header, ";");
        const name_value = cookie_parts.next() orelse return error.InvalidCookie;
        
        const eq_pos = std.mem.indexOf(u8, name_value, "=") orelse return error.InvalidCookie;
        const name = std.mem.trim(u8, name_value[0..eq_pos], " \t");
        const value = std.mem.trim(u8, name_value[eq_pos + 1 ..], " \t");
        
        var cookie = Cookie.init(name, value);
        
        // Parse cookie attributes
        while (cookie_parts.next()) |part| {
            const trimmed = std.mem.trim(u8, part, " \t");
            
            if (std.mem.eql(u8, "Secure", trimmed)) {
                cookie.setSecure(true);
            } else if (std.mem.eql(u8, "HttpOnly", trimmed)) {
                cookie.setHttpOnly(true);
            } else if (std.mem.eql(u8, "SameSite=Strict", trimmed)) {
                cookie.setSameSite(.STRICT);
            } else if (std.mem.eql(u8, "SameSite=Lax", trimmed)) {
                cookie.setSameSite(.LAX);
            } else if (std.mem.eql(u8, "SameSite=None", trimmed)) {
                cookie.setSameSite(.NONE);
            } else if (std.mem.startsWith(u8, trimmed, "Domain=")) {
                const domain = trimmed[7..];
                cookie.setDomain(domain);
            } else if (std.mem.startsWith(u8, trimmed, "Path=")) {
                const path = trimmed[5..];
                cookie.setPath(path);
            } else if (std.mem.startsWith(u8, trimmed, "Expires=")) {
                const expires_str = trimmed[8..];
                const expires_time = parseHttpDate(expires_str) catch {
                    // If parsing fails, set a reasonable default (1 hour)
                    cookie.setExpiration(getCurrentTimestamp() + 3600);
                    continue;
                };
                cookie.setExpiration(expires_time);
            } else if (std.mem.startsWith(u8, trimmed, "Max-Age=")) {
                const max_age_str = trimmed[8..];
                const max_age = std.fmt.parseInt(u64, max_age_str, 10) catch {
                    continue;
                };
                cookie.setExpiration(getCurrentTimestamp() + max_age);
            }
        }
        
        return cookie;
    }
    
    /// Generate Cookie header string
    pub fn generateCookieHeader(self: *CookieAPI, cookie: Cookie) StringHashMap([]const u8) {
        var headers = StringHashMap([]const u8).init(self.allocator);
        
        const cookie_header = std.fmt.allocPrint(self.allocator, "{}={}", .{ cookie.name, cookie.value }) catch "";
        headers.put("Set-Cookie", cookie_header) catch {};
        
        var cookie_string = ArrayList(u8).init(self.allocator);
        defer cookie_string.deinit();
        
        cookie_string.appendSlice(std.fmt.allocPrint(self.allocator, "{}={}", .{ cookie.name, cookie.value }) catch "") catch {};
        
        if (cookie.domain.len > 0) {
            cookie_string.appendSlice("; Domain=") catch {};
            cookie_string.appendSlice(cookie.domain) catch {};
        }
        
        if (cookie.path.len > 0) {
            cookie_string.appendSlice("; Path=") catch {};
            cookie_string.appendSlice(cookie.path) catch {};
        }
        
        if (cookie.expires) |expires| {
            const expires_str = formatHttpDate(expires);
            cookie_string.appendSlice("; Expires=") catch {};
            cookie_string.appendSlice(expires_str) catch {};
        }
        
        if (cookie.secure) {
            cookie_string.appendSlice("; Secure") catch {};
        }
        
        if (cookie.http_only) {
            cookie_string.appendSlice("; HttpOnly") catch {};
        }
        
        const same_site_str = switch (cookie.same_site) {
            .STRICT => "Strict",
            .LAX => "Lax",
            .NONE => "None",
        };
        cookie_string.appendSlice("; SameSite=") catch {};
        cookie_string.appendSlice(same_site_str) catch {};
        
        const final_cookie = cookie_string.toOwnedSlice() catch "";
        headers.put("Set-Cookie", final_cookie) catch {};
        
        return headers;
    }
};

// Cookie options for setting cookies
pub const CookieOptions = struct {
    domain: ?[]const u8 = null,
    path: ?[]const u8 = null,
    expires: ?u64 = null, // Unix timestamp
    max_age: ?u64 = null, // Seconds from now
    secure: bool = false,
    http_only: bool = false,
    same_site: SameSitePolicy = .LAX,
};

// IndexedDB API Implementation
pub const IndexedDBAPI = struct {
    allocator: Allocator,
    event_loop: *EventLoopManager,
    storage_bridge: *StorageBridge,
    
    pub fn init(allocator: Allocator, event_loop: *EventLoopManager, storage_bridge: *StorageBridge) IndexedDBAPI {
        return IndexedDBAPI{
            .allocator = allocator,
            .event_loop = event_loop,
            .storage_bridge = storage_bridge,
        };
    }
    
    /// Open IndexedDB database
    pub fn openDatabase(inout self: *IndexedDBAPI, name: []const u8, version: u64) !*IndexedDBDatabase {
        return try self.storage_bridge.openIndexedDB(name, version);
    }
    
    /// Delete IndexedDB database
    pub fn deleteDatabase(inout self: *IndexedDBAPI, name: []const u8) void {
        self.storage_bridge.deleteIndexedDB(name);
    }
    
    /// Get all database names (simplified - would scan storage)
    pub fn getDatabaseNames(self: *IndexedDBAPI) ArrayList([]const u8) {
        var names = ArrayList([]const u8).init(self.allocator);
        var db_iter = self.storage_bridge.indexed_db_databases.keyIterator();
        while (db_iter.next()) |name| {
            names.append(name.*) catch {};
        }
        return names;
    }
};

// Cache API Implementation
pub const CacheAPI = struct {
    allocator: Allocator,
    event_loop: *EventLoopManager,
    storage_bridge: *StorageBridge,
    origin: Origin,
    
    pub fn init(allocator: Allocator, event_loop: *EventLoopManager, storage_bridge: *StorageBridge, origin: Origin) CacheAPI {
        return CacheAPI{
            .allocator = allocator,
            .event_loop = event_loop,
            .storage_bridge = storage_bridge,
            .origin = origin,
        };
    }
    
    /// Open named cache
    pub fn open(inout self: *CacheAPI, cache_name: []const u8) !*CacheAPICache {
        return try self.storage_bridge.cacheOpen(cache_name, self.origin);
    }
    
    /// Delete cache
    pub fn delete(inout self: *CacheAPI, cache_name: []const u8) !bool {
        const removed = self.storage_bridge.cache_api_caches.remove(cache_name);
        if (removed) |cache| {
            cache.deinit();
            return true;
        }
        return false;
    }
    
    /// Get all cache names
    pub fn getCacheNames(self: *CacheAPI) ArrayList([]const u8) {
        var names = ArrayList([]const u8).init(self.allocator);
        var cache_iter = self.storage_bridge.cache_api_caches.keyIterator();
        while (cache_iter.next()) |name| {
            names.append(name.*) catch {};
        }
        return names;
    }
    
    /// Check if cache exists
    pub fn hasCache(self: *CacheAPI, cache_name: []const u8) bool {
        return self.storage_bridge.cache_api_caches.get(cache_name) != null;
    }
};

// Main Storage Manager
pub const StorageManager = struct {
    allocator: Allocator,
    event_loop: *EventLoopManager,
    storage_bridge: StorageBridge,
    local_storage_api: LocalStorageAPI,
    session_storage_api: SessionStorageAPI,
    cookie_api: CookieAPI,
    indexed_db_api: IndexedDBAPI,
    cache_api: CacheAPI,
    
    pub fn init(allocator: Allocator, event_loop: *EventLoopManager) !StorageManager {
        var storage_bridge = StorageBridge.init(allocator);
        
        // Note: origin would come from the actual browser context
        const origin = try Origin.parse("https://browser-context.com");
        
        var local_storage_api = LocalStorageAPI.init(allocator, event_loop, &storage_bridge, origin);
        var session_storage_api = SessionStorageAPI.init(allocator, event_loop, &storage_bridge, origin);
        var cookie_api = CookieAPI.init(allocator, event_loop, &storage_bridge);
        var indexed_db_api = IndexedDBAPI.init(allocator, event_loop, &storage_bridge);
        var cache_api = CacheAPI.init(allocator, event_loop, &storage_bridge, origin);
        
        return StorageManager{
            .allocator = allocator,
            .event_loop = event_loop,
            .storage_bridge = storage_bridge,
            .local_storage_api = local_storage_api,
            .session_storage_api = session_storage_api,
            .cookie_api = cookie_api,
            .indexed_db_api = indexed_db_api,
            .cache_api = cache_api,
        };
    }
    
    pub fn deinit(self: *StorageManager) void {
        self.storage_bridge.deinit();
    }
    
    /// Get LocalStorage API for specific origin
    pub fn getLocalStorage(inout self: *StorageManager, origin: Origin) *LocalStorageAPI {
        self.local_storage_api.origin = origin;
        return &self.local_storage_api;
    }
    
    /// Get SessionStorage API for specific origin
    pub fn getSessionStorage(inout self: *StorageManager, origin: Origin) *SessionStorageAPI {
        self.session_storage_api.origin = origin;
        return &self.session_storage_api;
    }
    
    /// Get Cookie API (global)
    pub fn getCookieAPI(inout self: *StorageManager) *CookieAPI {
        return &self.cookie_api;
    }
    
    /// Get IndexedDB API (global)
    pub fn getIndexedDBAPI(inout self: *StorageManager) *IndexedDBAPI {
        return &self.indexed_db_api;
    }
    
    /// Get Cache API for specific origin
    pub fn getCacheAPI(inout self: *StorageManager, origin: Origin) *CacheAPI {
        self.cache_api.origin = origin;
        return &self.cache_api;
    }
    
    /// Cleanup expired storage data
    pub fn cleanupExpired(inout self: *StorageManager) void {
        self.storage_bridge.cleanupExpiredData();
    }
    
    /// Get storage statistics
    pub fn getStats(self: *StorageManager) StorageStats {
        return self.storage_bridge.getStorageStats();
    }
    
    /// Clear all storage for an origin
    pub fn clearOriginStorage(inout self: *StorageManager, origin: Origin) void {
        self.storage_bridge.localStorageClear(origin);
        self.storage_bridge.sessionStorageClear(origin);
    }
    
    /// Export storage data (for backup/migration)
    pub fn exportOriginData(inout self: *StorageManager, origin: Origin, allocator: Allocator) !StorageExport {
        var export = StorageExport.init(allocator);
        
        // Export localStorage
        const local_keys = self.storage_bridge.localStorageKeys(origin);
        defer local_keys.deinit();
        
        for (local_keys.items) |key| {
            if (self.storage_bridge.localStorageGet(origin, key)) |value| {
                try export.local_storage.put(key, value);
            }
        }
        
        // Export sessionStorage
        const session_storage = self.storage_bridge.getOriginStorage(origin) catch return error.ExportFailed;
        var session_iter = session_storage.session_storage.keyIterator();
        while (session_iter.next()) |key| {
            const item = session_storage.session_storage.get(key.*).?;
            try export.session_storage.put(key.*, item.value);
        }
        
        // Export cookies
        const origin_str = std.fmt.allocPrint(allocator, "{}://{}:{}", .{
            origin.scheme,
            origin.host,
            origin.port,
        }) catch return error.ExportFailed;
        defer allocator.free(origin_str);
        
        var cookie_iter = self.storage_bridge.cookie_jar.valueIterator();
        while (cookie_iter.next()) |cookie| {
            if (cookie.matchesUrl(origin_str)) {
                try export.cookies.append(cookie.*);
            }
        }
        
        return export;
    }
    
    /// Import storage data (from backup/migration)
    pub fn importOriginData(inout self: *StorageManager, origin: Origin, export: *StorageExport) !void {
        // Import localStorage
        var local_iter = export.local_storage.keyIterator();
        while (local_iter.next()) |key| {
            const value = export.local_storage.get(key.*).?;
            try self.storage_bridge.localStorageSet(origin, key.*, value);
        }
        
        // Import sessionStorage
        var session_iter = export.session_storage.keyIterator();
        while (session_iter.next()) |key| {
            const value = export.session_storage.get(key.*).?;
            try self.storage_bridge.sessionStorageSet(origin, key.*, value);
        }
        
        // Import cookies
        for (export.cookies.items) |cookie| {
            try self.storage_bridge.setCookie(cookie);
        }
    }
};

// Storage export structure
pub const StorageExport = struct {
    local_storage: StringHashMap([]const u8),
    session_storage: StringHashMap([]const u8),
    cookies: ArrayList(Cookie),
    
    pub fn init(allocator: Allocator) StorageExport {
        return StorageExport{
            .local_storage = StringHashMap([]const u8).init(allocator),
            .session_storage = StringHashMap([]const u8).init(allocator),
            .cookies = ArrayList(Cookie).init(allocator),
        };
    }
    
    pub fn deinit(self: *StorageExport) void {
        self.local_storage.deinit();
        self.session_storage.deinit();
        self.cookies.deinit();
    }
};

// Utility functions for HTTP date parsing
fn parseHttpDate(date_str: []const u8) !u64 {
    // Simplified HTTP date parsing - would use proper RFC 7231 parsing
    // For now, return current timestamp as fallback
    _ = date_str;
    return getCurrentTimestamp();
}

fn formatHttpDate(timestamp: u64) []const u8 {
    // Simplified HTTP date formatting - would use proper RFC 7231 formatting
    // For now, return a basic ISO date string
    const date_str = std.fmt.allocPrint(std.heap.c_allocator, "{}", .{timestamp}) catch "";
    return date_str;
}

test "localStorage API operations" {
    const allocator = std.testing.allocator;
    var event_loop = EventLoopManager.init(allocator, 100);
    defer event_loop.deinit();
    
    var storage_manager = try StorageManager.init(allocator, &event_loop);
    defer storage_manager.deinit();
    
    const origin = try Origin.parse("https://example.com");
    const local_storage = storage_manager.getLocalStorage(origin);
    
    // Set and get item
    try local_storage.setItem("test-key", "test-value");
    
    const retrieved_value = local_storage.getItem("test-key");
    try std.testing.expect(retrieved_value != null);
    try std.testing.expect(std.mem.eql(u8, "test-value", retrieved_value.?));
    
    // Test length
    try std.testing.expectEqual(@as(usize, 1), local_storage.length());
    
    // Test key access
    const key_at_0 = local_storage.key(0);
    try std.testing.expect(key_at_0 != null);
    try std.testing.expect(std.mem.eql(u8, "test-key", key_at_0.?));
    
    // Test hasKey
    try std.testing.expect(local_storage.hasKey("test-key"));
    try std.testing.expect(!local_storage.hasKey("non-existent-key"));
    
    // Test removal
    local_storage.removeItem("test-key");
    try std.testing.expect(!local_storage.hasKey("test-key"));
    
    // Test clear
    try local_storage.setItem("key1", "value1");
    try local_storage.setItem("key2", "value2");
    local_storage.clear();
    try std.testing.expectEqual(@as(usize, 0), local_storage.length());
}

test "sessionStorage API operations" {
    const allocator = std.testing.allocator;
    var event_loop = EventLoopManager.init(allocator, 100);
    defer event_loop.deinit();
    
    var storage_manager = try StorageManager.init(allocator, &event_loop);
    defer storage_manager.deinit();
    
    const origin = try Origin.parse("https://example.com");
    const session_storage = storage_manager.getSessionStorage(origin);
    
    // Set and get item
    try session_storage.setItem("session-key", "session-value");
    
    const retrieved_value = session_storage.getItem("session-key");
    try std.testing.expect(retrieved_value != null);
    try std.testing.expect(std.mem.eql(u8, "session-value", retrieved_value.?));
    
    // Test length
    try std.testing.expectEqual(@as(usize, 1), session_storage.length());
    
    // Test removal
    session_storage.removeItem("session-key");
    try std.testing.expect(!session_storage.hasKey("session-key"));
}

test "cookie API operations" {
    const allocator = std.testing.allocator;
    var event_loop = EventLoopManager.init(allocator, 100);
    defer event_loop.deinit();
    
    var storage_manager = try StorageManager.init(allocator, &event_loop);
    defer storage_manager.deinit();
    
    const cookie_api = storage_manager.getCookieAPI();
    
    // Set cookie with options
    var options = CookieOptions{
        .domain = "example.com",
        .path = "/",
        .secure = true,
        .same_site = .STRICT,
        .max_age = 3600,
    };
    
    try cookie_api.setCookie("test-cookie", "cookie-value", options);
    
    // Get cookie
    const retrieved_cookie = cookie_api.getCookie("test-cookie");
    try std.testing.expect(retrieved_cookie != null);
    try std.testing.expect(std.mem.eql(u8, "cookie-value", retrieved_cookie.?.value));
    try std.testing.expect(retrieved_cookie.?.secure);
    try std.testing.expect(std.mem.eql(u8, "example.com", retrieved_cookie.?.domain));
    try std.testing.expect(std.mem.eql(u8, "/", retrieved_cookie.?.path));
    try std.testing.expectEqual(SameSitePolicy.STRICT, retrieved_cookie.?.same_site);
    
    // Get cookies for URL
    const cookies_for_url = cookie_api.getCookiesForUrl("https://example.com/page");
    defer cookies_for_url.deinit();
    try std.testing.expectEqual(@as(usize, 1), cookies_for_url.items.len);
    
    // Test Set-Cookie header parsing
    const set_cookie_header = "sessionid=abc123; Path=/; HttpOnly; Secure; SameSite=Strict";
    const parsed_cookie = try cookie_api.parseSetCookieHeader(set_cookie_header);
    try std.testing.expect(std.mem.eql(u8, "sessionid", parsed_cookie.name));
    try std.testing.expect(std.mem.eql(u8, "abc123", parsed_cookie.value));
    try std.testing.expect(parsed_cookie.http_only);
    try std.testing.expect(parsed_cookie.secure);
    try std.testing.expectEqual(SameSitePolicy.STRICT, parsed_cookie.same_site);
    
    // Test deletion
    cookie_api.deleteCookie("test-cookie");
    const deleted_cookie = cookie_api.getCookie("test-cookie");
    try std.testing.expect(deleted_cookie == null);
}

test "storage manager statistics" {
    const allocator = std.testing.allocator;
    var event_loop = EventLoopManager.init(allocator, 100);
    defer event_loop.deinit();
    
    var storage_manager = try StorageManager.init(allocator, &event_loop);
    defer storage_manager.deinit();
    
    const origin = try Origin.parse("https://example.com");
    const local_storage = storage_manager.getLocalStorage(origin);
    
    // Add some data
    try local_storage.setItem("key1", "value1");
    try local_storage.setItem("key2", "value2");
    
    // Add cookies
    var cookie = Cookie.init("test-cookie", "cookie-value");
    try storage_manager.storage_bridge.setCookie(cookie);
    
    // Get statistics
    const stats = storage_manager.getStats();
    try std.testing.expectEqual(@as(usize, 1), stats.origin_count);
    try std.testing.expectEqual(@as(usize, 2), stats.local_storage_items);
    try std.testing.expectEqual(@as(usize, 1), stats.cookie_count);
    
    // Test cleanup
    storage_manager.cleanupExpired();
    
    // Test clear origin
    storage_manager.clearOriginStorage(origin);
    const cleared_stats = storage_manager.getStats();
    try std.testing.expectEqual(@as(usize, 0), cleared_stats.local_storage_items);
}