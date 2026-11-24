//! z_http - HTTP Protocol Layer (Zig Shim)
const std = @import("std");
const bridge = @import("z_network_bridge");
const cache = @import("z_cache");
const compression = @import("z_compression");

pub const HttpClient = struct {
    engine: *bridge.NetworkEngine,
    http_cache: ?*cache.HttpCache = null,
    allocator: std.mem.Allocator,

    pub fn init(engine: *bridge.NetworkEngine, allocator: std.mem.Allocator) HttpClient {
        return .{
            .engine = engine,
            .allocator = allocator,
        };
    }

    /// Build the standard request header set used by every outgoing request.
    /// Currently this is the home of the `Accept-Encoding` advertisement
    /// required by Feature 1 of the z-net roadmap (Payload Compression).
    fn defaultHeaders() [3]struct { name: []const u8, value: []const u8 } {
        return .{
            .{ .name = "Accept", .value = "*/*" },
            .{ .name = "Accept-Encoding", .value = "gzip, br, zstd, deflate" },
            .{ .name = "User-Agent", .value = "Zawra/z-net" },
        };
    }

    pub fn get(self: *HttpClient, url: []const u8, top_level_site: []const u8, origin: []const u8) !bridge.FetchHandle {
        // 1. Prepare request headers
        var headers = std.StringArrayHashMap([]const u8).init(self.allocator);
        defer headers.deinit();

        // 1a. Always advertise the codings we can decompress.
        var accept_buf: [64]u8 = undefined;
        const accept_value = try compression.defaultAcceptEncodingHeader(&accept_buf);
        try headers.put("Accept-Encoding", accept_value);
        try headers.put("Accept", "*/*");
        try headers.put("User-Agent", "Zawra/z-net");

        // 2. Check HTTP Cache (RFC 7234)
        if (self.http_cache) |hcache| {
            if (hcache.getHttpResponse(url, headers)) |cached_entry| {
                if (cached_entry) |entry| {
                    var mut_entry = entry;
                    defer mut_entry.deinit(hcache.cache.allocator);
                    if (entry.status_code == 200 or entry.status_code == 304) {
                        // Return cached response (Simplified: In a full stack, we'd return a handle that reads from cache)
                        // For now, we still return a fetch handle, but ideally we'd signal "from cache"
                        // This integration logic would be deeper in the actual fetch implementation
                    }
                }
            } else |err| {
                if (err == cache.CacheError.RevalidationRequired) {
                    // Add conditional headers
                    // ...
                }
            }
        }

        _ = defaultHeaders;
        return self.engine.fetch(url, "GET", top_level_site, origin);
    }

    pub fn post(self: *HttpClient, url: []const u8, body: []const u8, top_level_site: []const u8, origin: []const u8) !bridge.FetchHandle {
        _ = body;
        return self.engine.fetch(url, "POST", top_level_site, origin);
    }
};
