//! z_http3 - HTTP/3 Protocol Layer (Zig Shim)
const std = @import("std");
const bridge = @import("z_network_bridge");

pub const Http3Client = struct {
    engine: *bridge.NetworkEngine,

    pub fn init(engine: *bridge.NetworkEngine) Http3Client {
        return .{ .engine = engine };
    }

    pub fn connect(self: *Http3Client, host: []const u8, port: u16) !bridge.ConnHandle {
        return self.engine.connectHttp3(host, port);
    }
};
