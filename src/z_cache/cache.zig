//! z_cache - BrowserDB Integration Layer
//! High-performance caching for HTTP responses, DNS records, and metadata

const std = @import("std");
const browserdb = @import("browserdb");

pub const HttpHeader = struct {
    name: []const u8,
    value: []const u8,
};

pub const HttpResponse = struct {
    status_code: u16,
    headers: []HttpHeader,
    body: []const u8,
};

pub const CacheError = error{
    NotFound,
    Expired,
    SerializationError,
    DeserializationError,
    StorageError,
    RevalidationRequired,
};

pub const CacheEntry = struct {
    key: []const u8,
    value: []const u8,
    created_at: i64,
    expires_at: i64,
    access_count: u32,
    last_accessed: i64,
    metadata: CacheMetadata,
};

pub const CacheMetadata = struct {
    content_type: ?[]const u8,
    content_encoding: ?[]const u8,
    etag: ?[]const u8,
    last_modified: ?[]const u8,
    vary_headers: ?[]const u8,
    size: usize,
    compressed: bool,
};

pub const CacheConfig = struct {
    max_size: usize = 100 * 1024 * 1024, // 100MB
    max_entries: usize = 10000,
    default_ttl: u32 = 300, // 5 minutes
    compression_threshold: usize = 1024, // Compress if > 1KB
    enable_hot_data: bool = true,
    hot_data_threshold: u32 = 10, // Access count threshold for hot data
};

pub const CacheStats = struct {
    total_size: usize,
    total_entries: u32,
    hit_count: u64,
    miss_count: u64,
    hit_rate: f64,
    hot_data_count: u32,
    average_entry_size: f64,
    compression_ratio: f64,
};

pub const Cache = struct {
    db: *browserdb.BrowserDB,
    allocator: std.mem.Allocator,
    config: CacheConfig,
    stats: CacheStats,
    lock: std.Thread.Mutex,
    io_ctx: *std.Io,

    const Self = @This();

    pub fn init(db: *browserdb.BrowserDB, allocator: std.mem.Allocator, config: CacheConfig, io_ctx: *std.Io) Self {
        return Self{
            .db = db,
            .allocator = allocator,
            .config = config,
            .io_ctx = io_ctx,
            .stats = CacheStats{
                .total_size = 0,
                .total_entries = 0,
                .hit_count = 0,
                .miss_count = 0,
                .hit_rate = 0.0,
                .hot_data_count = 0,
                .average_entry_size = 0.0,
                .compression_ratio = 1.0,
            },
            .lock = std.Thread.Mutex{},
        };
    }

    pub fn get(self: *Self, key: []const u8) CacheError!?CacheEntry {
        self.lock.lock();
        defer self.lock.unlock();

        // Get from BrowserDB using io_uring if available via io_ctx
        const db_entry = self.db.get(key) catch return error.StorageError;

        if (db_entry == null) {
            self.stats.miss_count += 1;
            self.stats.hit_rate = @as(f64, @floatFromInt(self.stats.hit_count)) / @as(f64, @floatFromInt(self.stats.hit_count + self.stats.miss_count));
            return null;
        }

        var entry = try deserializeCacheEntry(db_entry, self.allocator);

        // Check freshness according to RFC 7234
        const now = std.time.timestamp();
        if (now >= entry.expires_at) {
            // Entry is stale, but we keep it for revalidation
            self.stats.miss_count += 1;
            self.stats.hit_rate = @as(f64, @floatFromInt(self.stats.hit_count)) / @as(f64, @floatFromInt(self.stats.hit_count + self.stats.miss_count));
            return entry;
        }

        // Update access statistics
        entry.access_count += 1;
        entry.last_accessed = now;
        self.stats.hit_count += 1;
        self.stats.hit_rate = @as(f64, @floatFromInt(self.stats.hit_count)) / @as(f64, @floatFromInt(self.stats.hit_count + self.stats.miss_count));

        // Store updated entry back to DB
        const serialized = try serializeCacheEntry(&entry, self.allocator);
        self.db.put(key, serialized) catch return error.StorageError;
        self.allocator.free(serialized);

        return entry;
    }

    pub fn put(self: *Self, key: []const u8, value: []const u8, metadata: CacheMetadata, ttl: ?u32) CacheError!void {
        self.lock.lock();
        defer self.lock.unlock();

        const now = std.time.timestamp();
        const expires_at = now + (ttl orelse self.config.default_ttl);

        // Compress if necessary
        var final_value = value;
        var compressed = false;
        var final_metadata = metadata;

        if (value.len > self.config.compression_threshold) {
            if (self.compress(value)) |compressed_value| {
                final_value = compressed_value;
                compressed = true;
                final_metadata.compressed = true;
            }
        }

        // Check storage limits
        if (self.stats.total_size + final_value.len > self.config.max_size or 
            self.stats.total_entries >= self.config.max_entries) {
            try self.evict();
        }

        const entry = CacheEntry{
            .key = try self.allocator.dupe(u8, key),
            .value = final_value,
            .created_at = now,
            .expires_at = expires_at,
            .access_count = 1,
            .last_accessed = now,
            .metadata = final_metadata,
        };

        // Store in BrowserDB
        const serialized = try serializeCacheEntry(&entry, self.allocator);
        defer self.allocator.free(serialized);

        self.db.put(key, serialized) catch return error.StorageError;

        // Update statistics
        self.stats.total_size += final_value.len;
        self.stats.total_entries += 1;
        self.stats.average_entry_size = @as(f64, @floatFromInt(self.stats.total_size)) / @as(f64, @floatFromInt(self.stats.total_entries));

        if (final_metadata.compressed) {
            const compression_ratio = @as(f64, @floatFromInt(final_value.len)) / @as(f64, @floatFromInt(value.len));
            self.stats.compression_ratio = (self.stats.compression_ratio + compression_ratio) / 2.0;
        }
    }

    pub fn invalidate(self: *Self, key_pattern: []const u8) CacheError!void {
        self.lock.lock();
        defer self.lock.unlock();

        // Get all matching keys
        const matching_keys = self.db.getByPrefix(key_pattern) catch return error.StorageError;

        for (matching_keys) |key| {
            if (self.db.delete(key)) {
                // Update statistics
                if (self.db.getSize(key)) |size| {
                    self.stats.total_size -= size;
                    self.stats.total_entries -= 1;
                }
            }
        }

        if (self.stats.total_entries > 0) {
            self.stats.average_entry_size = @as(f64, @floatFromInt(self.stats.total_size)) / @as(f64, @floatFromInt(self.stats.total_entries));
        }
    }

    pub fn getStats(self: *Self) CacheStats {
        self.lock.lock();
        defer self.lock.unlock();
        return self.stats;
    }

    pub fn cleanup(self: *Self) void {
        self.lock.lock();
        defer self.lock.unlock();

        const now = std.time.timestamp();
        const expired_keys = self.db.getExpiredEntries(now) catch return;

        for (expired_keys) |key| {
            if (self.db.delete(key)) {
                if (self.db.getSize(key)) |size| {
                    self.stats.total_size -= size;
                    self.stats.total_entries -= 1;
                }
            }
        }

        if (self.stats.total_entries > 0) {
            self.stats.average_entry_size = @as(f64, @floatFromInt(self.stats.total_size)) / @as(f64, @floatFromInt(self.stats.total_entries));
        }
    }

    fn evict(self: *Self) CacheError!void {
        // Strategy: Remove oldest or least accessed entries
        const all_entries = self.db.getAllEntries() catch return error.StorageError;

        // Sort by last access time and access count (LRU + LFU hybrid)
        var entries = std.ArrayList(struct {
            key: []const u8,
            score: f64,
        }).init(self.allocator);
        defer entries.deinit();

        for (all_entries) |entry_data| {
            const entry = try deserializeCacheEntry(entry_data.value, self.allocator);
            const score = @as(f64, @floatFromInt(entry.access_count)) / @as(f64, @floatFromInt(@as(i64, std.time.timestamp()) - entry.last_accessed + 1));
            try entries.append(.{ .key = entry.key, .score = score });
        }

        // Sort by score (ascending - least valuable first)
        std.mem.sort(struct { key: []const u8, score: f64 }, entries.items, struct {
            fn lessThan(a: struct { key: []const u8, score: f64 }, b: struct { key: []const u8, score: f64 }) bool {
                return a.score < b.score;
            }
        }.lessThan);

        // Evict entries until we're under the limit
        var space_freed: usize = 0;
        var entries_freed: u32 = 0;

        for (entries.items) |entry| {
            if (self.stats.total_size <= self.config.max_size * 90 / 100 and 
                self.stats.total_entries <= self.config.max_entries * 90 / 100) {
                break;
            }

            if (self.db.delete(entry.key)) {
                if (self.db.getSize(entry.key)) |size| {
                    space_freed += size;
                    entries_freed += 1;
                    self.stats.total_size -= size;
                    self.stats.total_entries -= 1;
                }
            }
        }

        if (self.stats.total_entries > 0) {
            self.stats.average_entry_size = @as(f64, @floatFromInt(self.stats.total_size)) / @as(f64, @floatFromInt(self.stats.total_entries));
        }
    }

    fn compress(self: *Self, data: []const u8) ?[]const u8 {
        // Simple compression using zlib
        const compressed = std.compress.zlib.compress(data, self.allocator) catch return null;
        
        // Only use compression if it's actually smaller
        if (compressed.len < data.len) {
            return compressed;
        } else {
            self.allocator.free(compressed);
            return null;
        }
    }
};

// HTTP Response Cache
pub const HttpCache = struct {
    cache: Cache,
    vary_cache: std.StringArrayHashMap([]const u8),

    const Self = @This();

    pub fn init(db: *browserdb.BrowserDB, allocator: std.mem.Allocator, config: CacheConfig, io_ctx: *std.Io) Self {
        return Self{
            .cache = Cache.init(db, allocator, config, io_ctx),
            .vary_cache = std.StringArrayHashMap([]const u8).init(allocator),
        };
    }

    pub fn getHttpResponse(self: *Self, url: []const u8, request_headers: std.StringArrayHashMap([]const u8)) CacheError!?HttpCacheEntry {
        // Build cache key including vary headers
        var cache_key = try std.fmt.allocPrint(self.cache.allocator, "http:{}", .{url});
        defer self.cache.allocator.free(cache_key);

        // Check vary headers
        const vary_key = self.buildVaryKey(url, request_headers);
        defer if (vary_key.ptr != url.ptr) self.cache.allocator.free(vary_key);
        if (self.vary_cache.get(vary_key)) |key| {
            cache_key = key;
        }

        const entry_opt = self.cache.get(cache_key) catch return null;
        if (entry_opt) |e| {
            const now = std.time.timestamp();
            const is_expired = now >= e.expires_at;

            // RFC 7234 Freshness Check
            if (!is_expired) {
                // Check if client provided conditional headers
                if (request_headers.get("If-None-Match")) |etag| {
                    if (e.metadata.etag) |cached_etag| {
                        if (std.mem.eql(u8, etag, cached_etag)) {
                            // Return 304 Not Modified directly, bypassing network
                            return HttpCacheEntry{
                                .url = e.key,
                                .status_code = 304,
                                .headers = try parseHeadersFromEntry(&e),
                                .body = &.{},
                                .metadata = e.metadata,
                                .created_at = e.created_at,
                                .expires_at = e.expires_at,
                                .etag = e.metadata.etag,
                                .last_modified = e.metadata.last_modified,
                            };
                        }
                    }
                }

                // Return 200 OK with cached body
                return HttpCacheEntry{
                    .url = e.key,
                    .status_code = 200,
                    .headers = try parseHeadersFromEntry(&e),
                    .body = e.value,
                    .metadata = e.metadata,
                    .created_at = e.created_at,
                    .expires_at = e.expires_at,
                    .etag = e.metadata.etag,
                    .last_modified = e.metadata.last_modified,
                };
            }

            // Stale entry - revalidation required
            return error.RevalidationRequired;
        }
        return null;
    }

    pub fn putHttpResponse(self: *Self, url: []const u8, response: HttpResponse, ttl: ?u32) CacheError!void {
        // Determine TTL based on RFC 7234 headers
        var calculated_ttl: u32 = ttl orelse self.cache.config.default_ttl;
        var can_cache = true;

        // Check Cache-Control header directives
        for (response.headers) |header| {
            if (std.mem.eql(u8, header.name, "Cache-Control")) {
                if (std.mem.indexOf(u8, header.value, "no-store") != null) {
                    can_cache = false;
                } else if (std.mem.indexOf(u8, header.value, "no-cache") != null) {
                    calculated_ttl = 0; // Must revalidate
                } else if (std.mem.indexOf(u8, header.value, "max-age=")) |idx| {
                    const val = header.value[idx + 8..];
                    var end: usize = 0;
                    while (end < val.len and std.ascii.isDigit(val[end])) : (end += 1) {}
                    calculated_ttl = std.fmt.parseInt(u32, val[0..end], 10) catch calculated_ttl;
                }
            } else if (std.mem.eql(u8, header.name, "Expires")) {
                // Simplified Expires handling
                calculated_ttl = self.cache.config.default_ttl;
            }
        }

        if (!can_cache) return;

        // Create metadata
        var metadata = CacheMetadata{
            .content_type = null,
            .content_encoding = null,
            .etag = null,
            .last_modified = null,
            .vary_headers = null,
            .size = response.body.len,
            .compressed = false,
        };

        for (response.headers) |header| {
            if (std.mem.eql(u8, header.name, "Content-Type")) {
                metadata.content_type = header.value;
            } else if (std.mem.eql(u8, header.name, "Content-Encoding")) {
                metadata.content_encoding = header.value;
            } else if (std.mem.eql(u8, header.name, "ETag")) {
                metadata.etag = header.value;
            } else if (std.mem.eql(u8, header.name, "Last-Modified")) {
                metadata.last_modified = header.value;
            } else if (std.mem.eql(u8, header.name, "Vary")) {
                metadata.vary_headers = header.value;
            }
        }

        // Build cache key
        const cache_key = try std.fmt.allocPrint(self.cache.allocator, "http:{}", .{url});

        // Serialize response
        const serialized = try serializeHttpResponse(response, self.cache.allocator);
        defer self.cache.allocator.free(serialized);

        try self.cache.put(cache_key, serialized, metadata, calculated_ttl);
        self.cache.allocator.free(cache_key);
    }

    fn buildVaryKey(self: *Self, url: []const u8, request_headers: std.StringArrayHashMap([]const u8)) []const u8 {
        var vary_headers = std.ArrayList(u8).init(self.cache.allocator);

        for (request_headers.keys(), request_headers.values()) |header_name, header_value| {
            if (self.shouldVaryOn(header_name)) {
                vary_headers.appendSlice(header_name);
                vary_headers.appendSlice("=");
                vary_headers.appendSlice(header_value);
                vary_headers.append(';');
            }
        }

        const vary_key = std.fmt.allocPrint(self.cache.allocator, "vary:{s}:{}", .{ url, vary_headers.items }) catch return url;
        self.cache.allocator.free(vary_headers.items);
        return vary_key;
    }

    fn shouldVaryOn(self: *Self, header_name: []const u8) bool {
        _ = self;
        // Common headers that affect cache variations
        const vary_headers = &[_][]const u8{
            "Accept",
            "Accept-Encoding", 
            "Accept-Language",
            "User-Agent",
            "Cookie",
            "Authorization",
        };

        for (vary_headers) |vary_header| {
            if (std.mem.eql(u8, header_name, vary_header)) {
                return true;
            }
        }

        return false;
    }
};

pub const HttpCacheEntry = struct {
    url: []const u8,
    status_code: u16,
    headers: []HttpHeader,
    body: []const u8,
    metadata: CacheMetadata,
    created_at: i64,
    expires_at: i64,
    etag: ?[]const u8,
    last_modified: ?[]const u8,
};

// DNS Cache
pub const DnsCache = struct {
    cache: Cache,

    const Self = @This();

    pub fn init(db: *browserdb.BrowserDB, allocator: std.mem.Allocator, config: CacheConfig, io_ctx: *std.Io) Self {
        var dns_config = config;
        dns_config.default_ttl = 300; // 5 minutes for DNS
        return Self{
            .cache = Cache.init(db, allocator, dns_config, io_ctx),
        };
    }

    pub fn getDnsRecords(self: *Self, domain: []const u8, record_type: @TypeOf(.enum_literal)) ?DnsCacheEntry {
        const key = std.fmt.allocPrint(self.cache.allocator, "dns:{s}:{d}", .{ domain, @intFromEnum(record_type) }) catch return null;
        defer self.cache.allocator.free(key);

        const entry = self.cache.get(key) catch return null;
        return if (entry) |e| DnsCacheEntry{
            .domain = e.key,
            .record_type = record_type,
            .records = e.value,
            .ttl = @intCast(e.expires_at - std.time.timestamp()),
            .created_at = e.created_at,
        } else null;
    }

    pub fn putDnsRecords(self: *Self, domain: []const u8, record_type: @TypeOf(.enum_literal), records: []const u8, ttl: u32) CacheError!void {
        const key = std.fmt.allocPrint(self.cache.allocator, "dns:{s}:{d}", .{ domain, @intFromEnum(record_type) }) catch return error.StorageError;
        defer self.cache.allocator.free(key);

        const metadata = CacheMetadata{
            .content_type = "application/dns",
            .content_encoding = null,
            .etag = null,
            .last_modified = null,
            .vary_headers = null,
            .size = records.len,
            .compressed = false,
        };

        try self.cache.put(key, records, metadata, ttl);
    }
};

pub const DnsCacheEntry = struct {
    domain: []const u8,
    record_type: @TypeOf(.enum_literal),
    records: []const u8,
    ttl: u32,
    created_at: i64,
};

// Cookie Cache
pub const CookieCache = struct {
    cache: Cache,

    const Self = @This();

    pub fn init(db: *browserdb.BrowserDB, allocator: std.mem.Allocator, config: CacheConfig, io_ctx: *std.Io) Self {
        var cookie_config = config;
        cookie_config.default_ttl = 86400; // 24 hours for cookies
        return Self{
            .cache = Cache.init(db, allocator, cookie_config, io_ctx),
        };
    }

    pub fn getCookies(self: *Self, domain: []const u8, path: []const u8) ?[]CookieEntry {
        const key = std.fmt.allocPrint(self.cache.allocator, "cookies:{s}:{s}", .{ domain, path }) catch return null;
        defer self.cache.allocator.free(key);

        const entry = self.cache.get(key) catch return null;
        return if (entry) |e| parseCookieEntries(e.value) else null;
    }

    pub fn putCookies(self: *Self, domain: []const u8, path: []const u8, cookies: []CookieEntry, ttl: ?u32) CacheError!void {
        const key = std.fmt.allocPrint(self.cache.allocator, "cookies:{s}:{s}", .{ domain, path }) catch return error.StorageError;
        defer self.cache.allocator.free(key);

        const serialized = try serializeCookieEntries(cookies, self.cache.allocator);
        defer self.cache.allocator.free(serialized);

        const metadata = CacheMetadata{
            .content_type = "text/plain",
            .content_encoding = null,
            .etag = null,
            .last_modified = null,
            .vary_headers = null,
            .size = serialized.len,
            .compressed = false,
        };

        try self.cache.put(key, serialized, metadata, ttl);
    }
};

pub const CookieEntry = struct {
    name: []const u8,
    value: []const u8,
    domain: []const u8,
    path: []const u8,
    secure: bool,
    http_only: bool,
    same_site: ?[]const u8,
    expires: ?i64,
};

// Serialization/Deserialization functions
fn serializeCacheEntry(entry: *const CacheEntry, allocator: std.mem.Allocator) ![]u8 {
    var writer = std.ArrayList(u8).init(allocator);
    
    // Write entry metadata
    try writer.appendSlice(&std.mem.toBytes(entry.created_at));
    try writer.appendSlice(&std.mem.toBytes(entry.expires_at));
    try writer.appendSlice(&std.mem.toBytes(entry.access_count));
    try writer.appendSlice(&std.mem.toBytes(entry.last_accessed));
    
    // Write metadata
    const metadata_json = std.json.stringify(entry.metadata, .{}, allocator) catch return error.SerializationError;
    defer allocator.free(metadata_json);
    
    try writer.appendSlice(&std.mem.toBytes(@as(u32, metadata_json.len)));
    try writer.appendSlice(metadata_json);
    
    // Write value
    try writer.appendSlice(&std.mem.toBytes(@as(u32, entry.value.len)));
    try writer.appendSlice(entry.value);
    
    return writer.toOwnedSlice();
}

fn deserializeCacheEntry(data: []const u8, allocator: std.mem.Allocator) !CacheEntry {
    var offset: usize = 0;
    
    // Read metadata
    const created_at = std.mem.readInt(i64, data[offset..offset + 8], .big);
    offset += 8;
    
    const expires_at = std.mem.readInt(i64, data[offset..offset + 8], .big);
    offset += 8;
    
    const access_count = std.mem.readInt(u32, data[offset..offset + 4], .big);
    offset += 4;
    
    const last_accessed = std.mem.readInt(i64, data[offset..offset + 8], .big);
    offset += 8;
    
    const metadata_len = std.mem.readInt(u32, data[offset..offset + 4], .big);
    offset += 4;
    
    const metadata_json = data[offset..offset + metadata_len];
    offset += metadata_len;
    
    const metadata = try std.json.parseFromSlice(CacheMetadata, allocator, metadata_json, .{});
    defer metadata.deinit();
    
    const value_len = std.mem.readInt(u32, data[offset..offset + 4], .big);
    offset += 4;
    
    const value = data[offset..offset + value_len];
    
    return CacheEntry{
        .key = "", // Will be set by caller
        .value = value,
        .created_at = created_at,
        .expires_at = expires_at,
        .access_count = access_count,
        .last_accessed = last_accessed,
        .metadata = metadata.value,
    };
}

// Helper functions for HTTP response serialization
fn serializeHttpResponse(response: HttpResponse, allocator: std.mem.Allocator) ![]u8 {
    // Simplified serialization - in practice would use a proper protocol
    var buffer = std.ArrayList(u8).init(allocator);
    
    // Write status code and basic info
    try buffer.appendSlice(&std.mem.toBytes(response.status_code));
    
    // Write headers as JSON
    const headers_json = std.json.stringify(response.headers, .{}, allocator) catch return error.SerializationError;
    defer allocator.free(headers_json);
    
    try buffer.appendSlice(&std.mem.toBytes(@as(u32, headers_json.len)));
    try buffer.appendSlice(headers_json);
    
    // Write body
    try buffer.appendSlice(&std.mem.toBytes(@as(u32, response.body.len)));
    try buffer.appendSlice(response.body);
    
    return buffer.toOwnedSlice();
}

fn parseStatusCodeFromEntry(entry: *const CacheEntry) !u16 {
    // Parse status code from serialized entry
    const status_code = std.mem.readInt(u16, entry.value[0..2], .big);
    return status_code;
}

fn parseHeadersFromEntry(entry: *const CacheEntry) ![]HttpHeader {
    const headers_len = std.mem.readInt(u32, entry.value[2..6], .big);
    const headers_json = entry.value[6..6 + headers_len];
    
    const parsed = std.json.parseFromSlice([]HttpHeader, std.heap.page_allocator, headers_json, .{}) catch return error.DeserializationError;
    return parsed.value;
}

// Cookie serialization functions
fn parseCookieEntries(data: []const u8) []CookieEntry {
    _ = data;
    // Simplified cookie parsing
    // In practice would parse proper cookie format
    return &[_]CookieEntry{};
}

fn serializeCookieEntries(cookies: []CookieEntry, allocator: std.mem.Allocator) ![]u8 {
    // Simplified cookie serialization
    return try std.json.stringify(cookies, .{}, allocator);
}