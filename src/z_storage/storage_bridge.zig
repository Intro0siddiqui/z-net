//! z_storage - Browser Storage Bridge
//! 
//! Provides browser-compatible storage interfaces including localStorage,
//! sessionStorage, IndexedDB, Cache API, and cookie management with
//! origin-based isolation and quota enforcement.

const std = @import("std");
const Allocator = std.mem.Allocator;
const AutoHashMap = std.AutoHashMap;
const StringHashMap = std.StringHashMap;
const ArrayList = std.ArrayList;
const Json = std.json;

const policy_engine = @import("z_policy/policy_engine.zig");
const policy = @import("z_policy/policy.zig");

usingnamespace policy_engine;

pub const StorageType = enum {
    LOCAL_STORAGE,
    SESSION_STORAGE,
    INDEXED_DB,
    CACHE_API,
    COOKIES,
}

pub const StorageQuota = struct {
    max_size_bytes: u64,
    used_size_bytes: u64,
    remaining_bytes: u64,
    quota_type: StorageType,
    
    pub fn init(quota_type: StorageType, max_size: u64) StorageQuota {
        return StorageQuota{
            .max_size_bytes = max_size,
            .used_size_bytes = 0,
            .remaining_bytes = max_size,
            .quota_type = quota_type,
        };
    }
    
    pub fn updateUsage(inout self: *StorageQuota, new_used: u64) void {
        self.used_size_bytes = new_used;
        if (self.used_size_bytes > self.max_size_bytes) {
            self.remaining_bytes = 0;
        } else {
            self.remaining_bytes = self.max_size_bytes - self.used_size_bytes;
        }
    }
    
    pub fn canStore(inout self: *StorageQuota, size_bytes: u64) bool {
        return (self.used_size_bytes + size_bytes) <= self.max_size_bytes;
    }
    
    pub fn getUsagePercentage(self: *StorageQuota) f64 {
        if (self.max_size_bytes == 0) return 0.0;
        return (@as(f64, self.used_size_bytes) / @as(f64, self.max_size_bytes)) * 100.0;
    }
};

pub const StorageItem = struct {
    key: []const u8,
    value: []const u8,
    size_bytes: u64,
    created_timestamp: u64,
    last_accessed_timestamp: u64,
    expires_timestamp: ?u64,
    metadata: StringHashMap([]const u8),
    
    pub fn init(allocator: Allocator, key: []const u8, value: []const u8) StorageItem {
        return StorageItem{
            .key = key,
            .value = value,
            .size_bytes = key.len + value.len,
            .created_timestamp = getCurrentTimestamp(),
            .last_accessed_timestamp = getCurrentTimestamp(),
            .expires_timestamp = null,
            .metadata = StringHashMap([]const u8).init(allocator),
        };
    }
    
    pub fn deinit(self: *StorageItem) void {
        self.metadata.deinit();
    }
    
    pub fn setExpiration(inout self: *StorageItem, expires_in_ms: u64) void {
        self.expires_timestamp = getCurrentTimestamp() + expires_in_ms;
    }
    
    pub fn isExpired(self: *StorageItem) bool {
        if (self.expires_timestamp) |expires| {
            return getCurrentTimestamp() > expires;
        }
        return false;
    }
    
    pub fn updateAccess(inout self: *StorageItem) void {
        self.last_accessed_timestamp = getCurrentTimestamp();
    }
    
    pub fn calculateSize(inout self: *StorageItem) void {
        self.size_bytes = self.key.len + self.value.len;
        
        // Add metadata size
        var metadata_size: usize = 0;
        var metadata_iter = self.metadata.keyIterator();
        while (metadata_iter.next()) |meta_key| {
            metadata_size += meta_key.len;
            const meta_value = self.metadata.get(meta_key.*).?;
            metadata_size += meta_value.len;
        }
        
        self.size_bytes += metadata_size;
    }
};

pub const OriginStorage = struct {
    origin: Origin,
    local_storage: AutoHashMap([]const u8, StorageItem),
    session_storage: AutoHashMap([]const u8, StorageItem),
    quota_local: StorageQuota,
    quota_session: StorageQuota,
    
    pub fn init(allocator: Allocator, origin: Origin) OriginStorage {
        return OriginStorage{
            .origin = origin,
            .local_storage = AutoHashMap([]const u8, StorageItem).init(allocator),
            .session_storage = AutoHashMap([]const u8, StorageItem).init(allocator),
            .quota_local = StorageQuota.init(.LOCAL_STORAGE, 10 * 1024 * 1024), // 10MB default
            .quota_session = StorageQuota.init(.SESSION_STORAGE, 5 * 1024 * 1024), // 5MB default
        };
    }
    
    pub fn deinit(self: *OriginStorage) void {
        // Clean up local storage items
        var local_iter = self.local_storage.valueIterator();
        while (local_iter.next()) |item| {
            item.deinit();
        }
        self.local_storage.deinit();
        
        // Clean up session storage items
        var session_iter = self.session_storage.valueIterator();
        while (session_iter.next()) |item| {
            item.deinit();
        }
        self.session_storage.deinit();
    }
    
    pub fn getOriginString(self: *OriginStorage) []const u8 {
        const origin_str = std.fmt.allocPrint(std.heap.c_allocator, "{}://{}:{}", .{
            self.origin.scheme,
            self.origin.host,
            self.origin.port,
        }) catch "";
        return origin_str;
    }
};

pub const Cookie = struct {
    name: []const u8,
    value: []const u8,
    domain: []const u8,
    path: []const u8,
    expires: ?u64,
    secure: bool,
    http_only: bool,
    same_site: SameSitePolicy,
    size_bytes: u64,
    
    pub fn init(name: []const u8, value: []const u8) Cookie {
        return Cookie{
            .name = name,
            .value = value,
            .domain = "",
            .path = "/",
            .expires = null,
            .secure = false,
            .http_only = false,
            .same_site = .LAX,
            .size_bytes = name.len + value.len,
        };
    }
    
    pub fn setDomain(inout self: *Cookie, domain: []const u8) void {
        self.domain = domain;
        self.calculateSize();
    }
    
    pub fn setPath(inout self: *Cookie, path: []const u8) void {
        self.path = path;
        self.calculateSize();
    }
    
    pub fn setExpiration(inout self: *Cookie, expires_timestamp: u64) void {
        self.expires = expires_timestamp;
    }
    
    pub fn setSecure(inout self: *Cookie, secure: bool) void {
        self.secure = secure;
    }
    
    pub fn setHttpOnly(inout self: *Cookie, http_only: bool) void {
        self.http_only = http_only;
    }
    
    pub fn setSameSite(inout self: *Cookie, policy: SameSitePolicy) void {
        self.same_site = policy;
    }
    
    pub fn isExpired(self: *Cookie) bool {
        if (self.expires) |expires| {
            return getCurrentTimestamp() > expires;
        }
        return false;
    }
    
    pub fn matchesUrl(inout self: *Cookie, url: []const u8) bool {
        // Basic cookie matching logic
        const url_origin = Origin.parse(url) catch return false;
        
        // Domain matching
        if (self.domain.len > 0) {
            if (!std.mem.endsWith(u8, url_origin.host, self.domain) and
                !std.mem.eql(u8, url_origin.host, self.domain)) {
                return false;
            }
        }
        
        // Path matching
        if (!std.mem.startsWith(u8, url, self.path)) {
            return false;
        }
        
        return true;
    }
    
    fn calculateSize(inout self: *Cookie) void {
        var size = self.name.len + self.value.len;
        if (self.domain.len > 0) size += self.domain.len + 7; // "; Domain="
        if (self.path.len > 0) size += self.path.len + 6; // "; Path="
        if (self.expires) |_| size += 20; // Approximate "; Expires=" length
        if (self.secure) size += 9; // "; Secure"
        if (self.http_only) size += 12; // "; HttpOnly"
        size += 15; // "; SameSite=" + policy name
        
        self.size_bytes = size;
    }
};

pub const SameSitePolicy = enum {
    STRICT,
    LAX,
    NONE,
};

pub const IndexedDBDatabase = struct {
    name: []const u8,
    version: u64,
    stores: AutoHashMap([]const u8, IndexedDBObjectStore),
    
    pub fn init(allocator: Allocator, name: []const u8, version: u64) IndexedDBDatabase {
        return IndexedDBDatabase{
            .name = name,
            .version = version,
            .stores = AutoHashMap([]const u8, IndexedDBObjectStore).init(allocator),
        };
    }
    
    pub fn deinit(self: *IndexedDBDatabase) void {
        var store_iter = self.stores.valueIterator();
        while (store_iter.next()) |store| {
            store.deinit();
        }
        self.stores.deinit();
    }
    
    pub fn createObjectStore(inout self: *IndexedDBDatabase, name: []const u8, key_path: ?[]const u8, auto_increment: bool) !*IndexedDBObjectStore {
        const store = try self.allocator.create(IndexedDBObjectStore);
        store.* = IndexedDBObjectStore.init(self.allocator, name, key_path, auto_increment);
        
        try self.stores.put(name, store.*);
        return store;
    }
    
    pub fn getObjectStore(inout self: *IndexedDBDatabase, name: []const u8) ?*IndexedDBObjectStore {
        return self.stores.get(name);
    }
    
    pub fn deleteObjectStore(inout self: *IndexedDBDatabase, name: []const u8) void {
        const removed = self.stores.remove(name);
        if (removed) |store| {
            store.deinit();
        }
    }
};

pub const IndexedDBObjectStore = struct {
    name: []const u8,
    key_path: ?[]const u8,
    auto_increment: bool,
    records: AutoHashMap([]const u8, IndexedDBRecord),
    indices: AutoHashMap([]const u8, IndexedDBIndex),
    
    pub fn init(allocator: Allocator, name: []const u8, key_path: ?[]const u8, auto_increment: bool) IndexedDBObjectStore {
        return IndexedDBObjectStore{
            .name = name,
            .key_path = key_path,
            .auto_increment = auto_increment,
            .records = AutoHashMap([]const u8, IndexedDBRecord).init(allocator),
            .indices = AutoHashMap([]const u8, IndexedDBIndex).init(allocator),
        };
    }
    
    pub fn deinit(self: *IndexedDBObjectStore) void {
        var record_iter = self.records.valueIterator();
        while (record_iter.next()) |record| {
            record.deinit();
        }
        self.records.deinit();
        
        var index_iter = self.indices.valueIterator();
        while (index_iter.next()) |index| {
            index.deinit();
        }
        self.indices.deinit();
    }
    
    pub fn put(inout self: *IndexedDBObjectStore, key: []const u8, value: []const u8, metadata: ?StringHashMap([]const u8)) !void {
        var record = IndexedDBRecord.init(key, value);
        if (metadata) |meta| {
            var meta_iter = meta.keyIterator();
            while (meta_iter.next()) |meta_key| {
                const meta_value = meta.get(meta_key.*).?;
                record.metadata.put(meta_key.*, meta_value) catch {};
            }
        }
        
        try self.records.put(key, record);
    }
    
    pub fn get(self: *IndexedDBObjectStore, key: []const u8) ?IndexedDBRecord {
        return self.records.get(key);
    }
    
    pub fn delete(inout self: *IndexedDBObjectStore, key: []const u8) void {
        _ = self.records.remove(key);
    }
    
    pub fn clear(inout self: *IndexedDBObjectStore) void {
        var record_iter = self.records.valueIterator();
        while (record_iter.next()) |record| {
            record.deinit();
        }
        self.records.clear();
    }
};

pub const IndexedDBRecord = struct {
    key: []const u8,
    value: []const u8,
    metadata: StringHashMap([]const u8),
    created_timestamp: u64,
    modified_timestamp: u64,
    
    pub fn init(key: []const u8, value: []const u8) IndexedDBRecord {
        return IndexedDBRecord{
            .key = key,
            .value = value,
            .metadata = StringHashMap([]const u8).init(std.heap.c_allocator),
            .created_timestamp = getCurrentTimestamp(),
            .modified_timestamp = getCurrentTimestamp(),
        };
    }
    
    pub fn deinit(self: *IndexedDBRecord) void {
        self.metadata.deinit();
    }
};

pub const IndexedDBIndex = struct {
    name: []const u8,
    key_path: []const u8,
    unique: bool,
    multi_entry: bool,
    
    pub fn init(name: []const u8, key_path: []const u8, unique: bool, multi_entry: bool) IndexedDBIndex {
        return IndexedDBIndex{
            .name = name,
            .key_path = key_path,
            .unique = unique,
            .multi_entry = multi_entry,
        };
    }
    
    pub fn deinit(self: *IndexedDBIndex) void {
        _ = self;
    }
};

pub const CacheAPIEntry = struct {
    request_url: []const u8,
    response_data: []const u8,
    response_headers: StringHashMap([]const u8),
    request_headers: StringHashMap([]const u8),
    created_timestamp: u64,
    expires_timestamp: ?u64,
    
    pub fn init(request_url: []const u8, response_data: []const u8) CacheAPIEntry {
        return CacheAPIEntry{
            .request_url = request_url,
            .response_data = response_data,
            .response_headers = StringHashMap([]const u8).init(std.heap.c_allocator),
            .request_headers = StringHashMap([]const u8).init(std.heap.c_allocator),
            .created_timestamp = getCurrentTimestamp(),
            .expires_timestamp = null,
        };
    }
    
    pub fn deinit(self: *CacheAPIEntry) void {
        self.response_headers.deinit();
        self.request_headers.deinit();
    }
    
    pub fn setExpiration(inout self: *CacheAPIEntry, expires_in_ms: u64) void {
        self.expires_timestamp = getCurrentTimestamp() + expires_in_ms;
    }
    
    pub fn isExpired(self: *CacheAPIEntry) bool {
        if (self.expires_timestamp) |expires| {
            return getCurrentTimestamp() > expires;
        }
        return false;
    }
    
    pub fn matchesRequest(inout self: *CacheAPIEntry, url: []const u8) bool {
        return std.mem.eql(u8, self.request_url, url);
    }
};

pub const CacheAPICache = struct {
    name: []const u8,
    origin: Origin,
    entries: AutoHashMap([]const u8, CacheAPIEntry),
    
    pub fn init(allocator: Allocator, name: []const u8, origin: Origin) CacheAPICache {
        return CacheAPICache{
            .name = name,
            .origin = origin,
            .entries = AutoHashMap([]const u8, CacheAPIEntry).init(allocator),
        };
    }
    
    pub fn deinit(self: *CacheAPICache) void {
        var entry_iter = self.entries.valueIterator();
        while (entry_iter.next()) |entry| {
            entry.deinit();
        }
        self.entries.deinit();
    }
    
    pub fn put(inout self: *CacheAPICache, request_url: []const u8, response_data: []const u8) !void {
        var entry = CacheAPIEntry.init(request_url, response_data);
        try self.entries.put(request_url, entry);
    }
    
    pub fn match(inout self: *CacheAPICache, request_url: []const u8) ?*CacheAPIEntry {
        return self.entries.get(request_url);
    }
    
    pub fn delete(inout self: *CacheAPICache, request_url: []const u8) void {
        const removed = self.entries.remove(request_url);
        if (removed) |entry| {
            entry.deinit();
        }
    }
    
    pub fn keys(inout self: *CacheAPICache) ArrayList([]const u8) {
        var keys = ArrayList([]const u8).init(std.heap.c_allocator);
        var key_iter = self.entries.keyIterator();
        while (key_iter.next()) |key| {
            keys.append(key.*) catch {};
        }
        return keys;
    }
};

pub const StorageError = error{
    QuotaExceeded,
    InvalidKey,
    InvalidValue,
    StorageUnavailable,
    SecurityError,
    NotFound,
};

/// Main Storage Bridge Manager
pub const StorageBridge = struct {
    allocator: Allocator,
    origin_storages: AutoHashMap([]const u8, OriginStorage),
    cookie_jar: AutoHashMap([]const u8, Cookie),
    indexed_db_databases: AutoHashMap([]const u8, IndexedDBDatabase),
    cache_api_caches: AutoHashMap([]const u8, CacheAPICache),
    global_quota: StorageQuota,
    
    pub fn init(allocator: Allocator) StorageBridge {
        return StorageBridge{
            .allocator = allocator,
            .origin_storages = AutoHashMap([]const u8, OriginStorage).init(allocator),
            .cookie_jar = AutoHashMap([]const u8, Cookie).init(allocator),
            .indexed_db_databases = AutoHashMap([]const u8, IndexedDBDatabase).init(allocator),
            .cache_api_caches = AutoHashMap([]const u8, CacheAPICache).init(allocator),
            .global_quota = StorageQuota.init(.LOCAL_STORAGE, 50 * 1024 * 1024), // 50MB global quota
        };
    }
    
    pub fn deinit(self: *StorageBridge) void {
        // Clean up origin storages
        var origin_iter = self.origin_storages.valueIterator();
        while (origin_iter.next()) |origin_storage| {
            origin_storage.deinit();
        }
        self.origin_storages.deinit();
        
        // Clean up cookies
        var cookie_iter = self.cookie_jar.valueIterator();
        while (cookie_iter.next()) |cookie| {
            // Cookies are stack allocated, no deinit needed
            _ = cookie;
        }
        self.cookie_jar.deinit();
        
        // Clean up IndexedDB databases
        var db_iter = self.indexed_db_databases.valueIterator();
        while (db_iter.next()) |database| {
            database.deinit();
        }
        self.indexed_db_databases.deinit();
        
        // Clean up Cache API caches
        var cache_iter = self.cache_api_caches.valueIterator();
        while (cache_iter.next()) |cache| {
            cache.deinit();
        }
        self.cache_api_caches.deinit();
    }
    
    /// Get or create origin storage
    fn getOriginStorage(inout self: *StorageBridge, origin: Origin) !*OriginStorage {
        const origin_key = try std.fmt.allocPrint(self.allocator, "{}://{}:{}", .{
            origin.scheme,
            origin.host,
            origin.port,
        });
        defer self.allocator.free(origin_key);
        
        if (self.origin_storages.get(origin_key)) |existing| {
            return existing;
        }
        
        // Create new origin storage
        var new_storage = try self.allocator.create(OriginStorage);
        new_storage.* = OriginStorage.init(self.allocator, origin);
        
        try self.origin_storages.put(origin_key, new_storage.*);
        return new_storage;
    }
    
    /// LocalStorage API
    pub fn localStorageGet(inout self: *StorageBridge, origin: Origin, key: []const u8) ?[]const u8 {
        const storage = self.getOriginStorage(origin) catch return null;
        
        const item = storage.local_storage.get(key) orelse return null;
        
        // Check expiration
        if (item.isExpired()) {
            _ = storage.local_storage.remove(key);
            return null;
        }
        
        // Update access time
        var mutable_item = item.*;
        mutable_item.updateAccess();
        
        return item.value;
    }
    
    pub fn localStorageSet(inout self: *StorageBridge, origin: Origin, key: []const u8, value: []const u8) !void {
        const storage = try self.getOriginStorage(origin);
        
        // Check quota
        const item_size = key.len + value.len;
        if (!storage.quota_local.canStore(item_size)) {
            return error.QuotaExceeded;
        }
        
        var item = StorageItem.init(self.allocator, key, value);
        item.calculateSize();
        
        try storage.local_storage.put(key, item);
        storage.quota_local.updateUsage(storage.quota_local.used_size_bytes + item_size);
    }
    
    pub fn localStorageRemove(inout self: *StorageBridge, origin: Origin, key: []const u8) void {
        const storage = self.getOriginStorage(origin) catch return;
        
        const removed = storage.local_storage.remove(key);
        if (removed) |item| {
            storage.quota_local.updateUsage(storage.quota_local.used_size_bytes - item.size_bytes);
            item.deinit();
        }
    }
    
    pub fn localStorageClear(inout self: *StorageBridge, origin: Origin) void {
        const storage = self.getOriginStorage(origin) catch return;
        
        var item_iter = storage.local_storage.valueIterator();
        while (item_iter.next()) |item| {
            item.deinit();
        }
        storage.local_storage.clear();
        storage.quota_local.updateUsage(0);
    }
    
    pub fn localStorageKeys(inout self: *StorageBridge, origin: Origin) ArrayList([]const u8) {
        const storage = self.getOriginStorage(origin) catch {
            return ArrayList([]const u8).init(self.allocator);
        };
        
        var keys = ArrayList([]const u8).init(self.allocator);
        var key_iter = storage.local_storage.keyIterator();
        while (key_iter.next()) |key| {
            keys.append(key.*) catch {};
        }
        return keys;
    }
    
    /// SessionStorage API (same interface as localStorage but separate storage)
    pub fn sessionStorageGet(inout self: *StorageBridge, origin: Origin, key: []const u8) ?[]const u8 {
        const storage = self.getOriginStorage(origin) catch return null;
        
        const item = storage.session_storage.get(key) orelse return null;
        
        if (item.isExpired()) {
            _ = storage.session_storage.remove(key);
            return null;
        }
        
        return item.value;
    }
    
    pub fn sessionStorageSet(inout self: *StorageBridge, origin: Origin, key: []const u8, value: []const u8) !void {
        const storage = try self.getOriginStorage(origin);
        
        const item_size = key.len + value.len;
        if (!storage.quota_session.canStore(item_size)) {
            return error.QuotaExceeded;
        }
        
        var item = StorageItem.init(self.allocator, key, value);
        item.calculateSize();
        
        try storage.session_storage.put(key, item);
        storage.quota_session.updateUsage(storage.quota_session.used_size_bytes + item_size);
    }
    
    pub fn sessionStorageRemove(inout self: *StorageBridge, origin: Origin, key: []const u8) void {
        const storage = self.getOriginStorage(origin) catch return;
        
        const removed = storage.session_storage.remove(key);
        if (removed) |item| {
            storage.quota_session.updateUsage(storage.quota_session.used_size_bytes - item.size_bytes);
            item.deinit();
        }
    }
    
    pub fn sessionStorageClear(inout self: *StorageBridge, origin: Origin) void {
        const storage = self.getOriginStorage(origin) catch return;
        
        var item_iter = storage.session_storage.valueIterator();
        while (item_iter.next()) |item| {
            item.deinit();
        }
        storage.session_storage.clear();
        storage.quota_session.updateUsage(0);
    }
    
    /// Cookie Management
    pub fn setCookie(inout self: *StorageBridge, cookie: Cookie) !void {
        // Clean up expired cookies
        self.cleanupExpiredCookies();
        
        try self.cookie_jar.put(cookie.name, cookie);
    }
    
    pub fn getCookie(self: *StorageBridge, name: []const u8) ?Cookie {
        const cookie = self.cookie_jar.get(name) orelse return null;
        
        if (cookie.isExpired()) {
            _ = self.cookie_jar.remove(name);
            return null;
        }
        
        return cookie.*;
    }
    
    pub fn getCookiesForUrl(self: *StorageBridge, url: []const u8) ArrayList(Cookie) {
        var matching_cookies = ArrayList(Cookie).init(self.allocator);
        
        var cookie_iter = self.cookie_jar.valueIterator();
        while (cookie_iter.next()) |cookie| {
            if (!cookie.isExpired() and cookie.matchesUrl(url)) {
                matching_cookies.append(cookie.*) catch {};
            }
        }
        
        return matching_cookies;
    }
    
    pub fn deleteCookie(inout self: *StorageBridge, name: []const u8) void {
        _ = self.cookie_jar.remove(name);
    }
    
    /// IndexedDB Management
    pub fn openIndexedDB(inout self: *StorageBridge, name: []const u8, version: u64) !*IndexedDBDatabase {
        // Clean up expired databases (simplified - would check version changes)
        if (self.indexed_db_databases.get(name)) |existing| {
            if (existing.version == version) {
                return existing;
            }
        }
        
        // Create new database
        var database = try self.allocator.create(IndexedDBDatabase);
        database.* = IndexedDBDatabase.init(self.allocator, name, version);
        
        try self.indexed_db_databases.put(name, database.*);
        return database;
    }
    
    pub fn deleteIndexedDB(inout self: *StorageBridge, name: []const u8) void {
        const removed = self.indexed_db_databases.remove(name);
        if (removed) |database| {
            database.deinit();
        }
    }
    
    /// Cache API Management
    pub fn cacheOpen(inout self: *StorageBridge, name: []const u8, origin: Origin) !*CacheAPICache {
        if (self.cache_api_caches.get(name)) |existing| {
            return existing;
        }
        
        var cache = try self.allocator.create(CacheAPICache);
        cache.* = CacheAPICache.init(self.allocator, name, origin);
        
        try self.cache_api_caches.put(name, cache.*);
        return cache;
    }
    
    pub fn cacheDelete(inout self: *StorageBridge, name: []const u8) void {
        const removed = self.cache_api_caches.remove(name);
        if (removed) |cache| {
            cache.deinit();
        }
    }
    
    /// Cleanup functions
    fn cleanupExpiredCookies(inout self: *StorageBridge) void {
        var to_remove = ArrayList([]const u8).init(self.allocator);
        defer to_remove.deinit();
        
        var cookie_iter = self.cookie_jar.keyIterator();
        while (cookie_iter.next()) |cookie_name| {
            const cookie = self.cookie_jar.get(cookie_name.*).?;
            if (cookie.isExpired()) {
                to_remove.append(cookie_name.*) catch {};
            }
        }
        
        for (to_remove.items) |name| {
            _ = self.cookie_jar.remove(name);
        }
    }
    
    pub fn cleanupExpiredData(inout self: *StorageBridge) void {
        // Clean up expired cookies
        self.cleanupExpiredCookies();
        
        // Clean up expired storage items
        var origin_iter = self.origin_storages.valueIterator();
        while (origin_iter.next()) |origin_storage| {
            // Clean up localStorage
            var to_remove_local = ArrayList([]const u8).init(self.allocator);
            var local_iter = origin_storage.local_storage.keyIterator();
            while (local_iter.next()) |key| {
                const item = origin_storage.local_storage.get(key.*).?;
                if (item.isExpired()) {
                    to_remove_local.append(key.*) catch {};
                }
            }
            
            for (to_remove_local.items) |key| {
                const removed = origin_storage.local_storage.remove(key);
                if (removed) |item| {
                    origin_storage.quota_local.updateUsage(origin_storage.quota_local.used_size_bytes - item.size_bytes);
                    item.deinit();
                }
            }
            
            // Clean up sessionStorage
            var to_remove_session = ArrayList([]const u8).init(self.allocator);
            var session_iter = origin_storage.session_storage.keyIterator();
            while (session_iter.next()) |key| {
                const item = origin_storage.session_storage.get(key.*).?;
                if (item.isExpired()) {
                    to_remove_session.append(key.*) catch {};
                }
            }
            
            for (to_remove_session.items) |key| {
                const removed = origin_storage.session_storage.remove(key);
                if (removed) |item| {
                    origin_storage.quota_session.updateUsage(origin_storage.quota_session.used_size_bytes - item.size_bytes);
                    item.deinit();
                }
            }
        }
    }
    
    /// Statistics and monitoring
    pub fn getStorageStats(self: *StorageBridge) StorageStats {
        var total_origins: usize = 0;
        var total_local_storage_items: usize = 0;
        var total_session_storage_items: usize = 0;
        var total_cookies: usize = 0;
        var total_indexed_db_databases: usize = 0;
        var total_cache_caches: usize = 0;
        
        total_origins = self.origin_storages.count();
        
        var origin_iter = self.origin_storages.valueIterator();
        while (origin_iter.next()) |origin_storage| {
            total_local_storage_items += origin_storage.local_storage.count();
            total_session_storage_items += origin_storage.session_storage.count();
        }
        
        total_cookies = self.cookie_jar.count();
        total_indexed_db_databases = self.indexed_db_databases.count();
        total_cache_caches = self.cache_api_caches.count();
        
        return StorageStats{
            .origin_count = total_origins,
            .local_storage_items = total_local_storage_items,
            .session_storage_items = total_session_storage_items,
            .cookie_count = total_cookies,
            .indexed_db_count = total_indexed_db_databases,
            .cache_api_count = total_cache_caches,
            .global_quota_used = self.global_quota.used_size_bytes,
            .global_quota_total = self.global_quota.max_size_bytes,
        };
    }
};

pub const StorageStats = struct {
    origin_count: usize,
    local_storage_items: usize,
    session_storage_items: usize,
    cookie_count: usize,
    indexed_db_count: usize,
    cache_api_count: usize,
    global_quota_used: u64,
    global_quota_total: u64,
};

// Helper functions
fn getCurrentTimestamp() u64 {
    return std.time.timestamp();
}

// Test functions
test "storage bridge initialization" {
    const allocator = std.testing.allocator;
    var storage_bridge = StorageBridge.init(allocator);
    defer storage_bridge.deinit();
    
    try std.testing.expectEqual(@as(usize, 0), storage_bridge.origin_storages.count());
    try std.testing.expectEqual(@as(usize, 0), storage_bridge.cookie_jar.count());
    try std.testing.expectEqual(@as(usize, 0), storage_bridge.indexed_db_databases.count());
    try std.testing.expectEqual(@as(usize, 0), storage_bridge.cache_api_caches.count());
}

test "localStorage operations" {
    const allocator = std.testing.allocator;
    var storage_bridge = StorageBridge.init(allocator);
    defer storage_bridge.deinit();
    
    const origin = try Origin.parse("https://example.com");
    
    // Set item
    try storage_bridge.localStorageSet(origin, "test-key", "test-value");
    
    // Get item
    const value = storage_bridge.localStorageGet(origin, "test-key");
    try std.testing.expect(value != null);
    try std.testing.expect(std.mem.eql(u8, "test-value", value.?));
    
    // Get keys
    const keys = storage_bridge.localStorageKeys(origin);
    defer keys.deinit();
    try std.testing.expectEqual(@as(usize, 1), keys.items.len);
    try std.testing.expect(std.mem.eql(u8, "test-key", keys.items[0]));
    
    // Remove item
    storage_bridge.localStorageRemove(origin, "test-key");
    
    // Verify removal
    const removed_value = storage_bridge.localStorageGet(origin, "test-key");
    try std.testing.expect(removed_value == null);
}

test "sessionStorage operations" {
    const allocator = std.testing.allocator;
    var storage_bridge = StorageBridge.init(allocator);
    defer storage_bridge.deinit();
    
    const origin = try Origin.parse("https://example.com");
    
    // Set item
    try storage_bridge.sessionStorageSet(origin, "session-key", "session-value");
    
    // Get item
    const value = storage_bridge.sessionStorageGet(origin, "session-key");
    try std.testing.expect(value != null);
    try std.testing.expect(std.mem.eql(u8, "session-value", value.?));
    
    // Clear session storage
    storage_bridge.sessionStorageClear(origin);
    
    // Verify clear
    const cleared_value = storage_bridge.sessionStorageGet(origin, "session-key");
    try std.testing.expect(cleared_value == null);
}

test "cookie management" {
    const allocator = std.testing.allocator;
    var storage_bridge = StorageBridge.init(allocator);
    defer storage_bridge.deinit();
    
    // Set cookie
    var cookie = Cookie.init("test-cookie", "cookie-value");
    cookie.setDomain("example.com");
    cookie.setPath("/");
    cookie.setExpiration(getCurrentTimestamp() + 3600); // 1 hour from now
    cookie.setSecure(true);
    
    try storage_bridge.setCookie(cookie);
    
    // Get cookie
    const retrieved_cookie = storage_bridge.getCookie("test-cookie");
    try std.testing.expect(retrieved_cookie != null);
    try std.testing.expect(std.mem.eql(u8, "cookie-value", retrieved_cookie.?.value));
    try std.testing.expect(retrieved_cookie.?.secure);
    try std.testing.expect(std.mem.eql(u8, "/", retrieved_cookie.?.path));
    
    // Get cookies for URL
    const cookies_for_url = storage_bridge.getCookiesForUrl("https://example.com/page");
    defer cookies_for_url.deinit();
    try std.testing.expectEqual(@as(usize, 1), cookies_for_url.items.len);
    try std.testing.expect(std.mem.eql(u8, "test-cookie", cookies_for_url.items[0].name));
    
    // Delete cookie
    storage_bridge.deleteCookie("test-cookie");
    
    // Verify deletion
    const deleted_cookie = storage_bridge.getCookie("test-cookie");
    try std.testing.expect(deleted_cookie == null);
}