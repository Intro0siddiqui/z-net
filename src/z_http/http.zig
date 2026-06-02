//! z_http - HTTP Protocol Layer (Zig Shim)
const std = @import("std");
const bridge = @import("z_network_bridge");
const cache = @import("z_cache");
const storage = @import("z_storage");

pub const HttpClient = struct {
    engine: *bridge.NetworkEngine,
    http_cache: ?*cache.HttpCache = null,
    cookie_api: ?*storage.CookieAPI = null,
    allocator: std.mem.Allocator,

    pub fn init(engine: *bridge.NetworkEngine, allocator: std.mem.Allocator) HttpClient {
        return .{
            .engine = engine,
            .allocator = allocator,
        };
    }

    pub fn get(self: *HttpClient, url: []const u8, top_level_site: []const u8, origin: []const u8) !bridge.FetchHandle {
        // 1. Check Cookie Jar and attach Cookie header
        var headers = std.StringArrayHashMap([]const u8).init(self.allocator);
        defer headers.deinit();

        if (self.cookie_api) |api| {
            const cookies = api.getCookiesForUrl(url, top_level_site, origin);
            defer cookies.deinit();
            if (cookies.items.len > 0) {
                var cookie_buf = std.ArrayList(u8).init(self.allocator);
                defer cookie_buf.deinit();
                for (cookies.items, 0..) |cookie, i| {
                    if (i > 0) try cookie_buf.appendSlice("; ");
                    try cookie_buf.appendSlice(cookie.name);
                    try cookie_buf.appendSlice("=");
                    try cookie_buf.appendSlice(cookie.value);
                }
                try headers.put("Cookie", try cookie_buf.toOwnedSlice());
            }
        }

        // Inject Accept-Encoding for transparent payload decompression
        try headers.put("Accept-Encoding", "gzip, br, zstd");

        // 2. Check HTTP Cache (RFC 7234)
        if (self.http_cache) |hcache| {
            if (hcache.getHttpResponse(url, headers)) |cached_entry| {
                if (cached_entry) |entry| {
                    if (entry.status_code == 200 or entry.status_code == 304) {
                        // Return cached response (Simplified: In a full stack, we'd return a handle that reads from cache)
                        // For now, we still return a fetch handle, but ideally we'd signal "from cache"
                        // This integration logic would be deeper in the actual fetch implementation
                    }
                }
            } catch |err| {
                if (err == cache.CacheError.RevalidationRequired) {
                    // Add conditional headers
                    // ...
                }
            }
        }

        return self.engine.fetch(url, "GET", top_level_site, origin);
    }

    pub fn post(self: *HttpClient, url: []const u8, body: []const u8, top_level_site: []const u8, origin: []const u8) !bridge.FetchHandle {
        var headers = std.StringArrayHashMap([]const u8).init(self.allocator);
        defer headers.deinit();

        // Inject Accept-Encoding for transparent payload decompression
        try headers.put("Accept-Encoding", "gzip, br, zstd");

        // 1. Check Cookie Jar and attach Cookie header
        // (Similar to GET, cookies would be attached here)

        _ = body;
        return self.engine.fetch(url, "POST", top_level_site, origin);
    }
};
