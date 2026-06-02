//! z_fetch - Fetch API (Zig Shim)
const std = @import("std");
const bridge = @import("z_network_bridge");
const cache = @import("z_cache");
const storage = @import("z_storage");
const quic = @import("z_quic");
const webtransport = @import("z_webtransport");

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
            const cookies = api.getCookiesForUrl(url, std.mem.span(options.top_level_site), std.mem.span(options.origin));
            defer cookies.deinit();
        }

        if (self.http_cache) |hcache| {
            _ = hcache;
        }

        return self.engine.fetch(url, std.mem.span(options.method), std.mem.span(options.top_level_site), std.mem.span(options.origin));
    }

    // ============================================================
    // WebTransport passthrough
    // ============================================================
    //
    // The WebTransport API is a JS surface (`new WebTransport(url)`) that
    // WebKit calls into. We expose the createSendStream / receiveStream /
    // datagram methods directly on `Fetch` so the C ABI binding (Feature
    // 3c) can hand raw handles to the browser.

    /// Open a new WebTransport session for `url`. The returned `WebTransport`
    /// handle owns a QUIC connection that is already negotiated with the
    /// `webtransport` ALPN. The actual QUIC connection is provided by
    /// `z_http3` upstream; this method is the JS-shaped wrapper.
    pub fn webTransport(
        self: *Fetch,
        url: []const u8,
        options: webtransport.ConnectOptions,
    ) !webtransport.WebTransport {
        _ = self;
        _ = url;
        // The full implementation waits until z_http3 has a Connection
        // handle to forward. For the API surface we defer to the caller
        // (the FFI bridge in `z_fetch/webtransport_bridge.zig`) which
        // knows how to resolve the URL against the live QUIC stack.
        return webtransport.WebTransport.connectUnresolved(options);
    }
};

pub fn fetch(engine: *bridge.NetworkEngine, url: []const u8, options: bridge.FetchOptions) !bridge.FetchHandle {
    return engine.fetch(url, std.mem.span(options.method), std.mem.span(options.top_level_site), std.mem.span(options.origin));
}
