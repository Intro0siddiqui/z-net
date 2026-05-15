//! z_service_worker - Cache Management
//! 
//! Service Worker Cache API implementation for offline-first applications,
//! resource caching, and dynamic content management.

const std = @import("std");
const Allocator = std.mem.Allocator;
const AutoHashMap = std.AutoHashMap;
const StringHashMap = std.StringHashMap;
const ArrayList = std.ArrayList;

const policy_engine = @import("z_policy/policy_engine.zig");
const storage_bridge = @import("z_storage/storage_bridge.zig");
const lifecycle_manager = @import("lifecycle_manager.zig");

usingnamespace policy_engine;
usingnamespace storage_bridge;
usingnamespace lifecycle_manager;

// Cache match options
pub const CacheMatchOptions = struct {
    ignore_search: bool,
    ignore_method: bool,
    ignore_vary: bool,
    cache_name: ?[]const u8,
    match_method: []const u8,
    match_vary: StringHashMap([]const u8),
    
    pub fn init(allocator: Allocator) CacheMatchOptions {
        return CacheMatchOptions{
            .ignore_search = false,
            .ignore_method = false,
            .ignore_vary = false,
            .cache_name = null,
            .match_method = "GET",
            .match_vary = StringHashMap([]const u8).init(allocator),
        };
    }
    
    pub fn deinit(self: *CacheMatchOptions) void {
        self.match_vary.deinit();
    }
};

// Cache request
pub const CacheRequest = struct {
    url: []const u8,
    method: []const u8,
    headers: StringHashMap([]const u8),
    credentials: []const u8,
    mode: []const u8,
    redirect: []const u8,
    referrer: []const u8,
    referrer_policy: []const u8,
    integrity: []const u8,
    cache: []const u8,
    keepalive: bool,
    
    pub fn init(allocator: Allocator, url: []const u8) CacheRequest {
        return CacheRequest{
            .url = url,
            .method = "GET",
            .headers = StringHashMap([]const u8).init(allocator),
            .credentials = "same-origin",
            .mode = "cors",
            .redirect = "follow",
            .referrer = "",
            .referrer_policy = "no-referrer",
            .integrity = "",
            .cache = "default",
            .keepalive = false,
        };
    }
    
    pub fn deinit(self: *CacheRequest) void {
        self.headers.deinit();
    }
    
    pub fn clone(self: *CacheRequest, allocator: Allocator) !CacheRequest {
        var cloned = CacheRequest.init(allocator, self.url);
        cloned.method = self.method;
        cloned.credentials = self.credentials;
        cloned.mode = self.mode;
        cloned.redirect = self.redirect;
        cloned.referrer = self.referrer;
        cloned.referrer_policy = self.referrer_policy;
        cloned.integrity = self.integrity;
        cloned.cache = self.cache;
        cloned.keepalive = self.keepalive;
        
        // Clone headers
        var iter = self.headers.iterator();
        while (iter.next()) |entry| {
            try cloned.headers.put(entry.key_ptr.*, entry.value_ptr.*);
        }
        
        return cloned;
    }
};

// Cache response
pub const CacheResponse = struct {
    url: []const u8,
    status: u16,
    status_text: []const u8,
    ok: bool,
    headers: StringHashMap([]const u8),
    body: ?ArrayList(u8),
    type: []const u8,
    redirected: bool,
    cache_state: CacheState,
    timestamp: i64,
    
    pub fn init(allocator: Allocator, url: []const u8) CacheResponse {
        return CacheResponse{
            .url = url,
            .status = 200,
            .status_text = "OK",
            .ok = true,
            .headers = StringHashMap([]const u8).init(allocator),
            .body = null,
            .type = "basic",
            .redirected = false,
            .cache_state = CacheState.VALID,
            .timestamp = std.time.milliTimestamp(),
        };
    }
    
    pub fn deinit(self: *CacheResponse) void {
        self.headers.deinit();
        if (self.body) |*body| {
            body.deinit();
        }
    }
    
    pub fn text(self: *CacheResponse) []const u8 {
        if (self.body) |body| {
            return body.items;
        }
        return "";
    }
    
    pub fn json(self: *CacheResponse) !std.json.Value {
        if (self.body) |body| {
            const text = body.items;
            return std.json.parse(std.json.Value, std.json.jsonParse(text, .{}) catch |err| {
                return error.JsonParseFailed;
            });
        }
        return error.NoBody;
    }
}

// Cache state tracking
pub const CacheState = enum {
    VALID,
    STALE,
    EXPIRED,
    INVALIDATED,
    DELETED,
};

// Individual cache entry
pub const CacheEntry = struct {
    request: CacheRequest,
    response: CacheResponse,
    key: []const u8,
    size: usize,
    hit_count: u32,
    last_access: i64,
    ttl: i64, // Time to live in milliseconds
    
    pub fn init(allocator: Allocator, request: CacheRequest, response: CacheResponse) CacheEntry {
        const key = generateCacheKey(&request);
        
        var entry = CacheEntry{
            .request = request,
            .response = response,
            .key = key,
            .size = calculateResponseSize(&response),
            .hit_count = 0,
            .last_access = std.time.milliTimestamp(),
            .ttl = calculateTTL(&response),
        };
        
        return entry;
    }
    
    pub fn deinit(self: *CacheEntry) void {
        self.request.deinit();
        self.response.deinit();
    }
    
    pub fn isExpired(self: *CacheEntry) bool {
        return std.time.milliTimestamp() > (self.last_access + self.ttl);
    }
    
    pub fn updateAccess(self: *CacheEntry) void {
        self.last_access = std.time.milliTimestamp();
        self.hit_count += 1;
    }
};

// Cache implementation
pub const Cache = struct {
    name: []const u8,
    allocator: Allocator,
    entries: AutoHashMap([]const u8, *CacheEntry),
    max_entries: u32,
    max_size: usize,
    current_size: usize,
    eviction_policy: EvictionPolicy,
    
    pub const EvictionPolicy = enum {
        LRU, // Least Recently Used
        LFU, // Least Frequently Used
        FIFO, // First In, First Out
        TTL, // Time To Live
    };
    
    pub fn init(allocator: Allocator, name: []const u8, max_entries: u32, max_size: usize) Cache {
        return Cache{
            .name = name,
            .allocator = allocator,
            .entries = AutoHashMap([]const u8, *CacheEntry).init(allocator),
            .max_entries = max_entries,
            .max_size = max_size,
            .current_size = 0,
            .eviction_policy = .LRU,
        };
    }
    
    pub fn deinit(self: *Cache) void {
        // Clean up all entries
        var iter = self.entries.valueIterator();
        while (iter.next()) |entry| {
            entry.*.deinit();
            self.allocator.destroy(entry.*);
        }
        self.entries.deinit();
    }
    
    pub fn put(self: *Cache, request: CacheRequest, response: CacheResponse) !void {
        const entry = self.allocator.create(CacheEntry) catch |err| {
            return error.CacheEntryCreationFailed;
        };
        entry.* = CacheEntry.init(self.allocator, request, response);
        
        // Check if we need to evict entries
        if (self.entries.count() >= self.max_entries) {
            try self.evictEntries(1);
        }
        
        if (self.current_size + entry.size > self.max_size) {
            try self.evictBySize(entry.size);
        }
        
        try self.entries.put(entry.key, entry);
        self.current_size += entry.size;
    }
    
    pub fn match(self: *Cache, request: CacheRequest, options: *CacheMatchOptions) !?*CacheEntry {
        // Find matching entries
        var candidates = ArrayList(*CacheEntry).init(self.allocator);
        defer candidates.deinit();
        
        var iter = self.entries.valueIterator();
        while (iter.next()) |entry| {
            if (try self.matchesRequest(entry, &request, options)) {
                candidates.append(entry.*) catch {};
            }
        }
        
        if (candidates.items.len == 0) {
            return null;
        }
        
        // Sort by last access (LRU)
        std.sort.sort(*CacheEntry, candidates.items, {}, cacheEntryCompare);
        
        const best_match = candidates.items[0];
        best_match.updateAccess();
        
        return best_match;
    }
    
    pub fn matchAll(self: *Cache, request: CacheRequest, options: *CacheMatchOptions) !ArrayList(*CacheEntry) {
        var matches = ArrayList(*CacheEntry).init(self.allocator);
        
        var iter = self.entries.valueIterator();
        while (iter.next()) |entry| {
            if (try self.matchesRequest(entry, &request, options)) {
                try matches.append(entry.*);
            }
        }
        
        // Sort by last access
        std.sort.sort(*CacheEntry, matches.items, {}, cacheEntryCompare);
        
        return matches;
    }
    
    pub fn delete(self: *Cache, request: CacheRequest, options: *CacheMatchOptions) !bool {
        if (try self.match(request, options)) |entry| {
            self.current_size -= entry.size;
            _ = self.entries.remove(entry.key);
            entry.deinit();
            self.allocator.destroy(entry);
            return true;
        }
        return false;
    }
    
    pub fn keys(self: *Cache) ArrayList([]const u8) {
        var keys = ArrayList([]const u8).init(self.allocator);
        
        var iter = self.entries.keyIterator();
        while (iter.next()) |key| {
            keys.append(key.*) catch {};
        }
        
        return keys;
    }
    
    pub fn size(self: *Cache) usize {
        return self.entries.count();
    }
    
    pub fn storageUsage(self: *Cache) usize {
        return self.current_size;
    }
    
    fn matchesRequest(self: *Cache, entry: *CacheEntry, request: *CacheRequest, options: *CacheMatchOptions) !bool {
        // Check cache name if specified
        if (options.cache_name != null and !std.mem.eql(u8, self.name, options.cache_name.?)) {
            return false;
        }
        
        // Check method if not ignoring
        if (!options.ignore_method and !std.mem.eql(u8, entry.request.method, options.match_method)) {
            return false;
        }
        
        // Check VARY headers if not ignoring
        if (!options.ignore_vary) {
            var vary_iter = options.match_vary.iterator();
            while (vary_iter.next()) |vary| {
                if (entry.response.headers.get(vary.key_ptr.*)) |cached_value| {
                    if (!std.mem.eql(u8, cached_value, vary.value_ptr.*)) {
                        return false;
                    }
                }
            }
        }
        
        // Check expiration
        if (entry.isExpired()) {
            return false;
        }
        
        return true;
    }
    
    fn evictEntries(self: *Cache, count: u32) !void {
        var to_evict = count;
        
        switch (self.eviction_policy) {
            .LRU => {
                // Find least recently used entries
                var entries = ArrayList(*CacheEntry).init(self.allocator);
                defer entries.deinit();
                
                var iter = self.entries.valueIterator();
                while (iter.next()) |entry| {
                    try entries.append(entry.*);
                }
                
                std.sort.sort(*CacheEntry, entries.items, {}, cacheEntryLRUCompare);
                
                for (entries.items[0..@min(entries.items.len, to_evict)]) |entry| {
                    self.current_size -= entry.size;
                    _ = self.entries.remove(entry.key);
                    entry.deinit();
                    self.allocator.destroy(entry);
                }
            },
            .LFU => {
                // Find least frequently used entries
                // Similar implementation but sort by hit count
            },
            else => {
                // Other eviction policies
            },
        }
    }
    
    fn evictBySize(self: *Cache, required_size: usize) !void {
        var remaining_to_evict = required_size;
        
        // Keep evicting until we have enough space
        while (remaining_to_evict > 0) {
            // Find largest entry (reverse of LRU)
            var largest_entry: ?*CacheEntry = null;
            var largest_size: usize = 0;
            
            var iter = self.entries.valueIterator();
            while (iter.next()) |entry| {
                if (entry.*.size > largest_size) {
                    largest_size = entry.*.size;
                    largest_entry = entry.*;
                }
            }
            
            if (largest_entry) |entry| {
                self.current_size -= entry.size;
                _ = self.entries.remove(entry.key);
                entry.deinit();
                self.allocator.destroy(entry);
                
                remaining_to_evict = @min(remaining_to_evict, largest_size);
            } else {
                break; // No more entries to evict
            }
        }
    }
    
    fn matchesRequestURL(self: *Cache, entry: *CacheEntry, request: *CacheRequest) bool {
        // Basic URL matching
        // In real implementation, would handle query parameters, fragments, etc.
        return std.mem.eql(u8, entry.request.url, request.url);
    }
};

// Cache manager for Service Workers
pub const CacheManager = struct {
    allocator: Allocator,
    caches: AutoHashMap([]const u8, *Cache),
    worker_caches: AutoHashMap([16]u8, ArrayList([]const u8)), // worker_id -> cache_names
    global_config: CacheManagerConfig,
    
    pub fn init(allocator: Allocator, config: CacheManagerConfig) CacheManager {
        return CacheManager{
            .allocator = allocator,
            .caches = AutoHashMap([]const u8, *Cache).init(allocator),
            .worker_caches = AutoHashMap([16]u8, ArrayList([]const u8)).init(allocator),
            .global_config = config,
        };
    }
    
    pub fn deinit(self: *CacheManager) void {
        // Clean up all caches
        var iter = self.caches.valueIterator();
        while (iter.next()) |cache| {
            cache.*.deinit();
            self.allocator.destroy(cache.*);
        }
        self.caches.deinit();
        
        // Clean up worker cache associations
        var worker_iter = self.worker_caches.valueIterator();
        while (worker_iter.next()) |cache_list| {
            cache_list.*.deinit();
        }
        self.worker_caches.deinit();
    }
    
    pub fn open(self: *CacheManager, worker_id: [16]u8, cache_name: []const u8) !*Cache {
        if (self.caches.get(cache_name)) |existing_cache| {
            // Associate worker with existing cache
            try self.associateWorkerWithCache(worker_id, cache_name);
            return existing_cache;
        }
        
        // Create new cache
        const cache = self.allocator.create(Cache) catch |err| {
            return error.CacheCreationFailed;
        };
        cache.* = Cache.init(self.allocator, cache_name, self.global_config.max_cache_entries, self.global_config.max_cache_size);
        
        try self.caches.put(cache_name, cache);
        try self.associateWorkerWithCache(worker_id, cache_name);
        
        return cache;
    }
    
    pub fn delete(self: *CacheManager, worker_id: [16]u8, cache_name: []const u8) !bool {
        if (self.caches.get(cache_name)) |cache| {
            // Check if worker has access to this cache
            if (self.worker_caches.get(worker_id)) |worker_cache_list| {
                var cache_names = worker_cache_list.*;
                const index = std.mem.indexOfScalar([]const u8, cache_names.items, cache_name);
                if (index) |i| {
                    _ = cache_names.orderedRemove(i);
                }
            }
            
            // If no more workers use this cache, delete it
            if (!self.isCacheUsedByOtherWorker(worker_id, cache_name)) {
                cache.*.deinit();
                self.allocator.destroy(cache);
                _ = self.caches.remove(cache_name);
                return true;
            }
        }
        
        return false;
    }
    
    pub fn keys(self: *CacheManager, worker_id: [16]u8) !ArrayList([]const u8) {
        if (self.worker_caches.get(worker_id)) |worker_cache_list| {
            var cache_names = ArrayList([]const u8).init(self.allocator);
            
            for (worker_cache_list.*.items) |cache_name| {
                try cache_names.append(cache_name);
            }
            
            return cache_names;
        }
        
        return ArrayList([]const u8).init(self.allocator);
    }
    
    pub fn addAll(self: *CacheManager, worker_id: [16]u8, cache_name: []const u8, requests: []CacheRequest, responses: []CacheResponse) !void {
        if (self.caches.get(cache_name)) |cache| {
            // Check if all requests/responses are for the same worker
            // Implementation would validate worker permissions
            
            for (requests, responses) |request, response| {
                try cache.put(request, response);
            }
        }
    }
    
    pub fn put(self: *CacheManager, worker_id: [16]u8, cache_name: []const u8, request: CacheRequest, response: CacheResponse) !void {
        if (self.caches.get(cache_name)) |cache| {
            try cache.put(request, response);
        } else {
            return error.CacheNotFound;
        }
    }
    
    pub fn match(self: *CacheManager, worker_id: [16]u8, cache_name: []const u8, request: CacheRequest, options: *CacheMatchOptions) !?*CacheEntry {
        if (self.caches.get(cache_name)) |cache| {
            // Verify worker has access
            if (self.workerHasCacheAccess(worker_id, cache_name)) {
                return try cache.match(request, options);
            }
        }
        return null;
    }
    
    pub fn matchAll(self: *CacheManager, worker_id: [16]u8, cache_name: []const u8, request: CacheRequest, options: *CacheMatchOptions) !ArrayList(*CacheEntry) {
        if (self.caches.get(cache_name)) |cache| {
            if (self.workerHasCacheAccess(worker_id, cache_name)) {
                return try cache.matchAll(request, options);
            }
        }
        
        return ArrayList(*CacheEntry).init(self.allocator);
    }
    
    pub fn getGlobalStorageUsage(self: *CacheManager) usize {
        var total_size: usize = 0;
        
        var iter = self.caches.valueIterator();
        while (iter.next()) |cache| {
            total_size += cache.*.storageUsage();
        }
        
        return total_size;
    }
    
    fn associateWorkerWithCache(self: *CacheManager, worker_id: [16]u8, cache_name: []const u8) !void {
        if (self.worker_caches.get(worker_id)) |existing_list| {
            // Add cache name to existing list if not already present
            const cache_names = existing_list.*;
            if (std.mem.indexOfScalar([]const u8, cache_names.items, cache_name) == null) {
                try cache_names.append(cache_name);
            }
        } else {
            // Create new cache list for worker
            var cache_names = ArrayList([]const u8).init(self.allocator);
            try cache_names.append(cache_name);
            try self.worker_caches.put(worker_id, cache_names);
        }
    }
    
    fn workerHasCacheAccess(self: *CacheManager, worker_id: [16]u8, cache_name: []const u8) bool {
        if (self.worker_caches.get(worker_id)) |worker_cache_list| {
            const cache_names = worker_cache_list.*;
            return std.mem.indexOfScalar([]const u8, cache_names.items, cache_name) != null;
        }
        return false;
    }
    
    fn isCacheUsedByOtherWorker(self: *CacheManager, exclude_worker_id: [16]u8, cache_name: []const u8) bool {
        var iter = self.worker_caches.iterator();
        while (iter.next()) |entry| {
            if (!std.mem.eql(u8, &entry.key_ptr.*, &exclude_worker_id)) {
                const cache_names = entry.value_ptr.*;
                if (std.mem.indexOfScalar([]const u8, cache_names.items, cache_name) != null) {
                    return true;
                }
            }
        }
        return false;
    }
};

// Cache manager configuration
pub const CacheManagerConfig = struct {
    max_cache_entries: u32,
    max_cache_size: usize,
    default_ttl: i64,
    enable_compression: bool,
    enable_encryption: bool,
    
    pub fn init() CacheManagerConfig {
        return CacheManagerConfig{
            .max_cache_entries = 1000,
            .max_cache_size = 50 * 1024 * 1024, // 50MB
            .default_ttl = 24 * 60 * 60 * 1000, // 24 hours
            .enable_compression = true,
            .enable_encryption = false,
        };
    }
};

// Utility functions
fn generateCacheKey(request: *CacheRequest) []const u8 {
    // Generate a cache key from request
    // In real implementation, would hash URL + method + headers
    return request.url;
}

fn calculateResponseSize(response: *CacheResponse) usize {
    var size: usize = 0;
    
    // Calculate header size
    var iter = response.headers.iterator();
    while (iter.next()) |entry| {
        size += entry.key_ptr.*.len + entry.value_ptr.*.len + 4; // +4 for ": \r\n"
    }
    
    // Calculate body size
    if (response.body) |body| {
        size += body.items.len;
    }
    
    return size;
}

fn calculateTTL(response: *CacheResponse) i64 {
    // Calculate TTL from Cache-Control or Expires headers
    // For now, return default TTL
    return 24 * 60 * 60 * 1000; // 24 hours
}

// Comparison functions for sorting
fn cacheEntryCompare(_: void, a: *CacheEntry, b: *CacheEntry) bool {
    return a.last_access < b.last_access;
}

fn cacheEntryLRUCompare(_: void, a: *CacheEntry, b: *CacheEntry) bool {
    return a.last_access < b.last_access;
}