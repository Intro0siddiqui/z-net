//! z_fetch - Fetch API (Zig Shim)
const std = @import("std");
const bridge = @import("z_network_bridge");

pub fn fetch(engine: *bridge.NetworkEngine, url: []const u8, options: bridge.FetchOptions) !bridge.FetchHandle {
    _ = options;
    return engine.fetch(url, "GET");
}
