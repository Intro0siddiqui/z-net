//! z_fetch - Fetch API (Zig Shim)
const std = @import("std");
const bridge = @import("z_network_bridge");
const cache = @import("z_cache");
const storage = @import("z_storage");

pub const Fetch = struct {
    engine: *bridge.NetworkEngine,
    http_cache: ?*cache.HttpCache = null,
    cookie_api: ?*storage.CookieAPI = null,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, engine: *bridge.NetworkEngine) !Fetch {
        return Fetch{
            .allocator = allocator,
            .engine = engine,
        };
    }

    pub fn get(self: *Fetch, url: []const u8, options: bridge.FetchOptions) !bridge.FetchHandle {
        // Integrate Cookie Jar
        if (self.cookie_api) |api| {
            // Attach cookies from Zig-side Partitioned Cookie Jar
            const cookies = api.getCookiesForUrl(url, std.mem.span(options.top_level_site), std.mem.span(options.origin));
            defer cookies.deinit();
            // ... logic to attach to request via engine
        }

        // Integrate HTTP Cache
        if (self.http_cache) |hcache| {
            // Check Zig-side RFC 7234 Cache
            // (Simplified integration)
            _ = hcache;
        }

        return self.engine.fetch(url, std.mem.span(options.method), std.mem.span(options.top_level_site), std.mem.span(options.origin));
    }
};

pub fn fetch(engine: *bridge.NetworkEngine, url: []const u8, options: bridge.FetchOptions) !bridge.FetchHandle {
    return engine.fetch(url, std.mem.span(options.method), std.mem.span(options.top_level_site), std.mem.span(options.origin));
}
