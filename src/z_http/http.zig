//! z_http - HTTP Protocol Layer (Zig Shim)
const std = @import("std");
const bridge = @import("z_network_bridge");

pub const HttpClient = struct {
    engine: *bridge.NetworkEngine,

    pub fn init(engine: *bridge.NetworkEngine) HttpClient {
        return .{ .engine = engine };
    }

    pub fn get(self: *HttpClient, url: []const u8) !bridge.FetchHandle {
        return self.engine.fetch(url, "GET");
    }

    pub fn post(self: *HttpClient, url: []const u8, body: []const u8) !bridge.FetchHandle {
        // Implementation would use the bridge to send body
        _ = body;
        return self.engine.fetch(url, "POST");
    }
};
