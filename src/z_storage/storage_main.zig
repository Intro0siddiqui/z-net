//! z_storage - Main Storage Module
//! 
//! Unified storage system that provides browser-compatible storage interfaces
//! with origin-based isolation, quota management, and policy integration.

const std = @import("std");
const Allocator = std.mem.Allocator;
const StringHashMap = std.StringHashMap;
const ArrayList = std.ArrayList;

const storage_bridge = @import("storage_bridge.zig");
const storage_apis = @import("storage_apis.zig");
const policy_engine = @import("z_policy/policy_engine.zig");
const policy = @import("z_policy/policy.zig");
const event_loop = @import("z_event_loop/event_loop.zig");

// usingnamespace storage_bridge;
// usingnamespace storage_apis;
// usingnamespace policy_engine;
// usingnamespace event_loop;

pub const StorageConfig = struct {
    local_storage_quota_mb: u64 = 10,
    session_storage_quota_mb: u64 = 5,
    global_storage_quota_mb: u64 = 50,
    enable_cookies: bool = true,
    enable_indexed_db: bool = true,
    enable_cache_api: bool = true,
    cleanup_interval_ms: u64 = 300000, // 5 minutes
    max_cookie_age_days: u64 = 365,
    enable_storage_events: bool = true,
};

pub const StorageEvent = struct {
    event_type: StorageEventType,
    origin: Origin,
    storage_type: StorageType,
    key: []const u8,
    old_value: ?[]const u8,
    new_value: ?[]const u8,
    timestamp: u64,
    
    pub fn init(allocator: Allocator, event_type: StorageEventType, origin: Origin, storage_type: StorageType, key: []const u8) StorageEvent {
        return StorageEvent{
            .event_type = event_type,
            .origin = origin,
            .storage_type = storage_type,
            .key = key,
            .old_value = null,
            .new_value = null,
            .timestamp = getCurrentTimestamp(),
        };
    }
    
    pub fn deinit(self: *StorageEvent) void {
        _ = self;
    }
    
    pub fn setOldValue(self: *StorageEvent, old_value: []const u8) void {
        self.old_value = old_value;
    }
    
    pub fn setNewValue(self: *StorageEvent, new_value: []const u8) void {
        self.new_value = new_value;
    }
};

pub const StorageEventType = enum {
    SET_ITEM,
    REMOVE_ITEM,
    CLEAR,
    QUOTA_EXCEEDED,
    EXPIRED_ITEM_REMOVED,
};

pub const StorageQuotaManager = struct {
    quotas: AutoHashMap(StorageType, StorageQuota),
    origin_quotas: AutoHashMap([]const u8, OriginQuotaInfo),
    
    pub fn init(allocator: Allocator, config: StorageConfig) StorageQuotaManager {
        var quotas = AutoHashMap(StorageType, StorageQuota).init(allocator);
        
        quotas.put(.LOCAL_STORAGE, StorageQuota.init(.LOCAL_STORAGE, config.local_storage_quota_mb * 1024 * 1024)) catch {};
        quotas.put(.SESSION_STORAGE, StorageQuota.init(.SESSION_STORAGE, config.session_storage_quota_mb * 1024 * 1024)) catch {};
        quotas.put(.INDEXED_DB, StorageQuota.init(.INDEXED_DB, config.global_storage_quota_mb * 1024 * 1024)) catch {};
        quotas.put(.CACHE_API, StorageQuota.init(.CACHE_API, config.global_storage_quota_mb * 1024 * 1024)) catch {};
        
        return StorageQuotaManager{
            .quotas = quotas,
            .origin_quotas = AutoHashMap([]const u8, OriginQuotaInfo).init(allocator),
        };
    }
    
    pub fn deinit(self: *StorageQuotaManager) void {
        self.quotas.deinit();
        
        var origin_iter = self.origin_quotas.valueIterator();
        while (origin_iter.next()) |origin_quota| {
            origin_quota.deinit();
        }
        self.origin_quotas.deinit();
    }
    
    pub fn checkQuota(self: *StorageQuotaManager, storage_type: StorageType, origin_key: []const u8, required_bytes: u64) !bool {
        const global_quota = self.quotas.get(storage_type) orelse return false;
        
        if (!global_quota.canStore(required_bytes)) {
            return error.QuotaExceeded;
        }
        
        // Check origin-specific quota
        const origin_quota = self.getOriginQuota(origin_key);
        if (!origin_quota.canStore(required_bytes)) {
            return error.QuotaExceeded;
        }
        
        return true;
    }
    
    pub fn updateUsage(self: *StorageQuotaManager, storage_type: StorageType, origin_key: []const u8, delta_bytes: i64) !void {
        // Update global quota
        if (self.quotas.get(storage_type)) |global_quota| {
            const new_used = if (delta_bytes >= 0) 
                global_quota.used_size_bytes + @as(u64, delta_bytes)
            else
                global_quota.used_size_bytes - @as(u64, -delta_bytes);
            global_quota.updateUsage(new_used);
        }
        
        // Update origin quota
        var origin_quota = self.getOriginQuota(origin_key);
        const new_used = if (delta_bytes >= 0) 
            origin_quota.used_size_bytes + @as(u64, delta_bytes)
        else
            origin_quota.used_size_bytes - @as(u64, -delta_bytes);
        origin_quota.updateUsage(new_used);
    }
    
    fn getOriginQuota(self: *StorageQuotaManager, origin_key: []const u8) *OriginQuotaInfo {
        if (self.origin_quotas.get(origin_key)) |existing| {
            return existing;
        }
        
        // Create new origin quota with default limits
        var origin_quota = OriginQuotaInfo.init(origin_key);
        self.origin_quotas.put(origin_key, origin_quota) catch {};
        return self.origin_quotas.get(origin_key).?;
    }
    
    pub fn getQuotaStatus(self: *StorageQuotaManager, storage_type: StorageType, origin_key: []const u8) QuotaStatus {
        const global_quota = self.quotas.get(storage_type) orelse return .UNKNOWN;
        
        const origin_quota = self.getOriginQuota(origin_key);
        
        return .{
            .global_quota = global_quota.*,
            .origin_quota = origin_quota.*,
            .can_allocate = global_quota.canStore(1024) and origin_quota.canStore(1024),
            .usage_percentage = (global_quota.used_size_bytes * 100) / global_quota.max_size_bytes,
        };
    }
};

pub const OriginQuotaInfo = struct {
    origin_key: []const u8,
    quota: StorageQuota,
    
    pub fn init(origin_key: []const u8) OriginQuotaInfo {
        // Default origin quota is 25% of global quota
        return OriginQuotaInfo{
            .origin_key = origin_key,
            .quota = StorageQuota.init(.LOCAL_STORAGE, 10 * 1024 * 1024), // 10MB default per origin
        };
    }
    
    pub fn deinit(self: *OriginQuotaInfo) void {
        _ = self;
    }
    
    pub fn canStore(self: *OriginQuotaInfo, size_bytes: u64) bool {
        return self.quota.canStore(size_bytes);
    }
    
    pub fn updateUsage(self: *OriginQuotaInfo, new_used: u64) void {
        self.quota.updateUsage(new_used);
    }
};

pub const QuotaStatus = struct {
    global_quota: StorageQuota,
    origin_quota: OriginQuotaInfo,
    can_allocate: bool,
    usage_percentage: u64,
};

pub const BrowserStorage = struct {
    allocator: Allocator,
    config: StorageConfig,
    storage_manager: StorageManager,
    quota_manager: StorageQuotaManager,
    event_handlers: AutoHashMap(u64, *const fn (StorageEvent) void),
    storage_manager_ptr: *StorageManager,
    origin_storage_map: AutoHashMap([]const u8, OriginStorageContext),
    
    pub fn init(allocator: Allocator, event_loop: *EventLoopManager, config: StorageConfig) !BrowserStorage {
        var storage_manager = try StorageManager.init(allocator, event_loop);
        var quota_manager = StorageQuotaManager.init(allocator, config);
        
        return BrowserStorage{
            .allocator = allocator,
            .config = config,
            .storage_manager = storage_manager,
            .quota_manager = quota_manager,
            .event_handlers = AutoHashMap(u64, *const fn (StorageEvent) void).init(allocator),
            .storage_manager_ptr = &storage_manager,
            .origin_storage_map = AutoHashMap([]const u8, OriginStorageContext).init(allocator),
        };
    }
    
    pub fn deinit(self: *BrowserStorage) void {
        self.event_handlers.deinit();
        self.origin_storage_map.deinit();
        self.quota_manager.deinit();
        self.storage_manager.deinit();
    }
    
    /// Get LocalStorage for specific origin
    pub fn getLocalStorage(self: *BrowserStorage, origin: Origin) !*LocalStorageAPI {
        const origin_key = try self.getOriginKey(origin);
        
        // Create or update origin storage context
        if (!self.origin_storage_map.contains(origin_key)) {
            var context = OriginStorageContext.init(self.allocator, origin);
            try self.origin_storage_map.put(origin_key, context);
        }
        
        return self.storage_manager.getLocalStorage(origin);
    }
    
    /// Get SessionStorage for specific origin
    pub fn getSessionStorage(self: *BrowserStorage, origin: Origin) !*SessionStorageAPI {
        return self.storage_manager.getSessionStorage(origin);
    }
    
    /// Get Cookie API (global)
    pub fn getCookieAPI(self: *BrowserStorage) *CookieAPI {
        return self.storage_manager.getCookieAPI();
    }
    
    /// Get IndexedDB API (global)
    pub fn getIndexedDBAPI(self: *BrowserStorage) *IndexedDBAPI {
        return self.storage_manager.getIndexedDBAPI();
    }
    
    /// Get Cache API for specific origin
    pub fn getCacheAPI(self: *BrowserStorage, origin: Origin) !*CacheAPI {
        return self.storage_manager.getCacheAPI(origin);
    }
    
    /// Check storage availability for an origin
    pub fn isStorageAvailable(self: *BrowserStorage, origin: Origin, storage_type: StorageType) !bool {
        const origin_key = try self.getOriginKey(origin);
        
        switch (storage_type) {
            .LOCAL_STORAGE => {
                if (!self.config.enable_cookies) return false;
                return try self.quota_manager.checkQuota(.LOCAL_STORAGE, origin_key, 1024);
            },
            .SESSION_STORAGE => {
                if (!self.config.enable_cookies) return false;
                return try self.quota_manager.checkQuota(.SESSION_STORAGE, origin_key, 1024);
            },
            .COOKIES => {
                if (!self.config.enable_cookies) return false;
                return true; // Cookies are always available if enabled
            },
            .INDEXED_DB => {
                if (!self.config.enable_indexed_db) return false;
                return try self.quota_manager.checkQuota(.INDEXED_DB, origin_key, 1024);
            },
            .CACHE_API => {
                if (!self.config.enable_cache_api) return false;
                return try self.quota_manager.checkQuota(.CACHE_API, origin_key, 1024);
            },
        }
    }
    
    /// Estimate storage usage for an origin
    pub fn estimateStorageUsage(self: *BrowserStorage, origin: Origin) !StorageEstimate {
        const origin_key = try self.getOriginKey(origin);
        
        var total_bytes: u64 = 0;
        var breakdown = StorageBreakdown.init(self.allocator);
        
        // Estimate localStorage
        const local_storage = self.storage_manager.getLocalStorage(origin);
        var local_keys = local_storage.keys();
        defer local_keys.deinit();
        
        for (local_keys.items) |key| {
            if (local_storage.getItem(key)) |value| {
                const item_size = key.len + value.len;
                total_bytes += item_size;
                try breakdown.local_storage.put(key, item_size);
            }
        }
        
        // Estimate sessionStorage
        const session_storage = self.storage_manager.getSessionStorage(origin);
        var session_iter = session_storage.length();
        if (session_iter > 0) {
            // Simplified estimation - would iterate through actual items
            total_bytes += session_iter * 100; // Rough estimate
        }
        
        // Estimate cookies
        const cookie_api = self.storage_manager.getCookieAPI();
        const origin_str = std.fmt.allocPrint(self.allocator, "{}://{}:{}", .{
            origin.scheme,
            origin.host,
            origin.port,
        }) catch return error.EstimateFailed;
        defer self.allocator.free(origin_str);
        
        var cookies_for_origin = cookie_api.getCookiesForUrl(origin_str);
        defer cookies_for_origin.deinit();
        
        for (cookies_for_origin.items) |cookie| {
            total_bytes += cookie.size_bytes;
        }
        
        // Estimate IndexedDB (simplified)
        const indexed_db_api = self.storage_manager.getIndexedDBAPI();
        var db_names = indexed_db_api.getDatabaseNames();
        defer db_names.deinit();
        total_bytes += db_names.items.len * 1024; // Rough estimate
        
        // Estimate Cache API
        const cache_api = self.storage_manager.getCacheAPI(origin);
        var cache_names = cache_api.getCacheNames();
        defer cache_names.deinit();
        total_bytes += cache_names.items.len * 2048; // Rough estimate
        
        return StorageEstimate{
            .total_bytes = total_bytes,
            .breakdown = breakdown,
        };
    }
    
    /// Add storage event listener
    pub fn addEventListener(self: *BrowserStorage, handler_id: u64, callback: *const fn (StorageEvent) void) !void {
        try self.event_handlers.put(handler_id, callback);
    }
    
    /// Remove storage event listener
    pub fn removeEventListener(self: *BrowserStorage, handler_id: u64) void {
        _ = self.event_handlers.remove(handler_id);
    }
    
    /// Trigger storage event
    fn triggerStorageEvent(self: *BrowserStorage, event: StorageEvent) void {
        if (!self.config.enable_storage_events) return;
        
        var handler_iter = self.event_handlers.valueIterator();
        while (handler_iter.next()) |callback| {
            callback(event);
        }
    }
    
    /// Clear storage for an origin
    pub fn clearOrigin(self: *BrowserStorage, origin: Origin) !void {
        // Trigger clear event
        var event = StorageEvent.init(self.allocator, .CLEAR, origin, .LOCAL_STORAGE, "");
        event.setNewValue(""); // Empty indicates clear all
        self.triggerStorageEvent(event);
        event.deinit();
        
        self.storage_manager.clearOriginStorage(origin);
    }
    
    /// Get storage quota for an origin
    pub fn getQuotaForOrigin(self: *BrowserStorage, origin: Origin, storage_type: StorageType) !QuotaStatus {
        const origin_key = try self.getOriginKey(origin);
        return self.quota_manager.getQuotaStatus(storage_type, origin_key);
    }
    
    /// Request persistent storage for an origin
    pub fn requestPersistentStorage(self: *BrowserStorage, origin: Origin, estimated_bytes: u64) !bool {
        // Simplified implementation - would check actual storage usage and quota
        _ = estimated_bytes;
        _ = origin;
        return true; // Always grant for now
    }
    
    /// Check if origin has persistent storage
    pub fn hasPersistentStorage(self: *BrowserStorage, origin: Origin) !bool {
        _ = origin;
        return true; // Simplified - would check persistence grants
    }
    
    /// Cleanup expired and old data
    pub fn cleanup(self: *BrowserStorage) void {
        self.storage_manager.cleanupExpired();
        
        // Cleanup origin storage contexts
        var to_remove = ArrayList([]const u8).init(self.allocator);
        defer to_remove.deinit();
        
        var origin_iter = self.origin_storage_map.valueIterator();
        while (origin_iter.next()) |context| {
            if (context.shouldRemove()) {
                const key = context.origin_key;
                to_remove.append(key) catch {};
            }
        }
        
        for (to_remove.items) |key| {
            const removed = self.origin_storage_map.remove(key);
            if (removed) |context| {
                context.deinit();
            }
        }
    }
    
    /// Get comprehensive storage statistics
    pub fn getStatistics(self: *BrowserStorage) BrowserStorageStats {
        const storage_stats = self.storage_manager.getStats();
        const quotas = self.quota_manager.quotas;
        
        var quota_summary = QuotaSummary.init(self.allocator);
        var quota_iter = quotas.keyIterator();
        while (quota_iter.next()) |quota_type| {
            const quota = quotas.get(quota_type.*).?;
            try quota_summary.put(@tagName(quota_type.*), quota.getUsagePercentage());
        }
        
        return BrowserStorageStats{
            .storage_stats = storage_stats,
            .quota_summary = quota_summary,
            .origin_context_count = self.origin_storage_map.count(),
            .event_listener_count = self.event_handlers.count(),
            .config = self.config,
        };
    }
    
    /// Export all storage data for backup
    pub fn exportAllStorage(self: *BrowserStorage, allocator: Allocator) !AllStorageExport {
        var export = AllStorageExport.init(allocator);
        
        // Export all origins
        var origin_iter = self.storage_manager.storage_bridge.origin_storages.keyIterator();
        while (origin_iter.next()) |origin_key| {
            const origin = try Origin.parse(origin_key.*);
            const origin_export = try self.storage_manager.exportOriginData(origin, allocator);
            try export.origins.append(origin_export);
        }
        
        return export;
    }
    
    /// Import storage data from backup
    pub fn importAllStorage(self: *BrowserStorage, export: *AllStorageExport) !void {
        for (export.origins.items) |origin_export| {
            const origin = try Origin.parse(origin_export.origin_key);
            try self.storage_manager.importOriginData(origin, &origin_export.export_data);
        }
    }
    
    // Private helper functions
    fn getOriginKey(self: *BrowserStorage, origin: Origin) ![]const u8 {
        return std.fmt.allocPrint(self.allocator, "{}://{}:{}", .{
            origin.scheme,
            origin.host,
            origin.port,
        });
    }
};

pub const OriginStorageContext = struct {
    origin: Origin,
    origin_key: []const u8,
    last_accessed: u64,
    reference_count: u64,
    
    pub fn init(allocator: Allocator, origin: Origin) OriginStorageContext {
        const origin_key = std.fmt.allocPrint(allocator, "{}://{}:{}", .{
            origin.scheme,
            origin.host,
            origin.port,
        }) catch "";
        
        return OriginStorageContext{
            .origin = origin,
            .origin_key = origin_key,
            .last_accessed = getCurrentTimestamp(),
            .reference_count = 1,
        };
    }
    
    pub fn deinit(self: *OriginStorageContext) void {
        self.origin_key = "";
    }
    
    pub fn updateAccess(self: *OriginStorageContext) void {
        self.last_accessed = getCurrentTimestamp();
        self.reference_count += 1;
    }
    
    pub fn shouldRemove(self: *OriginStorageContext) bool {
        // Remove context if not accessed in 1 hour and no active references
        return (getCurrentTimestamp() - self.last_accessed) > 3600 and self.reference_count == 0;
    }
};

pub const StorageEstimate = struct {
    total_bytes: u64,
    breakdown: StorageBreakdown,
};

pub const StorageBreakdown = struct {
    local_storage: AutoHashMap([]const u8, u64),
    session_storage: u64,
    cookies: u64,
    indexed_db: u64,
    cache_api: u64,
    
    pub fn init(allocator: Allocator) StorageBreakdown {
        return StorageBreakdown{
            .local_storage = AutoHashMap([]const u8, u64).init(allocator),
            .session_storage = 0,
            .cookies = 0,
            .indexed_db = 0,
            .cache_api = 0,
        };
    }
    
    pub fn deinit(self: *StorageBreakdown) void {
        self.local_storage.deinit();
    }
};

pub const BrowserStorageStats = struct {
    storage_stats: StorageStats,
    quota_summary: QuotaSummary,
    origin_context_count: usize,
    event_listener_count: usize,
    config: StorageConfig,
};

pub const QuotaSummary = struct {
    quotas: StringHashMap(u64),
    
    pub fn init(allocator: Allocator) QuotaSummary {
        return QuotaSummary{
            .quotas = StringHashMap(u64).init(allocator),
        };
    }
    
    pub fn deinit(self: *QuotaSummary) void {
        self.quotas.deinit();
    }
    
    pub fn put(self: *QuotaSummary, key: []const u8, value: u64) !void {
        try self.quotas.put(key, value);
    }
};

pub const AllStorageExport = struct {
    origins: ArrayList(OriginStorageExport),
    
    pub fn init(allocator: Allocator) AllStorageExport {
        return AllStorageExport{
            .origins = ArrayList(OriginStorageExport).init(allocator),
        };
    }
    
    pub fn deinit(self: *AllStorageExport) void {
        for (self.origins.items) |*origin_export| {
            origin_export.deinit();
        }
        self.origins.deinit();
    }
};

pub const OriginStorageExport = struct {
    origin_key: []const u8,
    export_data: StorageExport,
    
    pub fn deinit(self: *OriginStorageExport) void {
        self.export_data.deinit();
    }
};

// Error types
pub const StorageError = error{
    QuotaExceeded,
    OriginNotFound,
    InvalidStorage,
    EstimateFailed,
    ImportFailed,
    ExportFailed,
};

// Helper functions
fn getCurrentTimestamp() u64 {
    return std.time.timestamp();
}

/// Create a browser storage instance
pub fn createBrowserStorage(allocator: Allocator, event_loop: *EventLoopManager, config: StorageConfig) !*BrowserStorage {
    const storage_ptr = try allocator.create(BrowserStorage);
    storage_ptr.* = try BrowserStorage.init(allocator, event_loop, config);
    return storage_ptr;
}

pub fn destroyBrowserStorage(storage: *BrowserStorage, allocator: Allocator) void {
    storage.deinit();
    allocator.destroy(storage);
}

test "browser storage initialization" {
    const allocator = std.testing.allocator;
    var event_loop = EventLoopManager.init(allocator, 100);
    defer event_loop.deinit();
    
    const config = StorageConfig{};
    var storage = try createBrowserStorage(allocator, &event_loop, config);
    defer destroyBrowserStorage(storage, allocator);
    
    try std.testing.expect(storage.config.enable_cookies);
    try std.testing.expect(storage.config.enable_indexed_db);
    try std.testing.expect(storage.config.enable_cache_api);
}

test "storage availability check" {
    const allocator = std.testing.allocator;
    var event_loop = EventLoopManager.init(allocator, 100);
    defer event_loop.deinit();
    
    const config = StorageConfig{};
    var storage = try createBrowserStorage(allocator, &event_loop, config);
    defer destroyBrowserStorage(storage, allocator);
    
    const origin = try Origin.parse("https://example.com");
    
    // Check localStorage availability
    const local_available = try storage.isStorageAvailable(origin, .LOCAL_STORAGE);
    try std.testing.expect(local_available);
    
    // Check cookies availability
    const cookie_available = try storage.isStorageAvailable(origin, .COOKIES);
    try std.testing.expect(cookie_available);
    
    // Check IndexedDB availability
    const indexed_db_available = try storage.isStorageAvailable(origin, .INDEXED_DB);
    try std.testing.expect(indexed_db_available);
    
    // Check Cache API availability
    const cache_available = try storage.isStorageAvailable(origin, .CACHE_API);
    try std.testing.expect(cache_available);
}

test "storage operations with origins" {
    const allocator = std.testing.allocator;
    var event_loop = EventLoopManager.init(allocator, 100);
    defer event_loop.deinit();
    
    const config = StorageConfig{};
    var storage = try createBrowserStorage(allocator, &event_loop, config);
    defer destroyBrowserStorage(storage, allocator);
    
    const origin = try Origin.parse("https://example.com");
    
    // Get LocalStorage and perform operations
    const local_storage = try storage.getLocalStorage(origin);
    
    try local_storage.setItem("test-key", "test-value");
    
    const retrieved_value = local_storage.getItem("test-key");
    try std.testing.expect(retrieved_value != null);
    try std.testing.expect(std.mem.eql(u8, "test-value", retrieved_value.?));
    
    // Get Cookie API
    const cookie_api = storage.getCookieAPI();
    var cookie = Cookie.init("session", "abc123");
    try cookie_api.setCookie(cookie);
    
    // Get IndexedDB API
    const indexed_db_api = storage.getIndexedDBAPI();
    _ = indexed_db_api; // Would use for actual IndexedDB operations
    
    // Test storage estimation
    const estimate = try storage.estimateStorageUsage(origin);
    try std.testing.expect(estimate.total_bytes > 0);
    
    // Test quota check
    const quota_status = try storage.getQuotaForOrigin(origin, .LOCAL_STORAGE);
    try std.testing.expect(quota_status.can_allocate);
    try std.testing.expect(quota_status.usage_percentage >= 0);
    try std.testing.expect(quota_status.usage_percentage <= 100);
}