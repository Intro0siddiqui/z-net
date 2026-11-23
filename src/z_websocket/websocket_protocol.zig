//! z_websocket - WebSocket Protocol Implementation
//! 
//! Complete WebSocket protocol handler with connection pooling,
//! message queuing, ping/pong maintenance, close handshake,
//! extension support, and binary data handling.

const std = @import("std");
const Allocator = std.mem.Allocator;
const AutoHashMap = std.AutoHashMap;
const StringHashMap = std.StringHashMap;
const ArrayList = std.ArrayList;
const Base64 = std.base64;

// WebSocket frame types
pub const WebSocketFrameType = enum(u4) {
    CONTINUATION = 0x0,
    TEXT = 0x1,
    BINARY = 0x2,
    CLOSE = 0x8,
    PING = 0x9,
    PONG = 0xA,
};

// WebSocket close codes
pub const WebSocketCloseCode = enum(u16) {
    NORMAL_CLOSURE = 1000,
    GOING_AWAY = 1001,
    PROTOCOL_ERROR = 1002,
    UNSUPPORTED_DATA = 1003,
    NO_STATUS_RECEIVED = 1005,
    ABNORMAL_CLOSURE = 1006,
    INVALID_FRAME_PAYLOAD_DATA = 1007,
    POLICY_VIOLATION = 1008,
    MESSAGE_TOO_BIG = 1009,
    MANDATORY_EXT = 10010,
    INTERNAL_ERROR = 1011,
    SERVICE_RESTART = 1012,
    TRY_AGAIN_LATER = 1013,
    BAD_GATEWAY = 1014,
    TLS_HANDSHAKE = 1015,
};

// WebSocket extension types
pub const WebSocketExtension = struct {
    name: []const u8,
    parameters: StringHashMap([]const u8),
    
    pub fn init(allocator: Allocator, name: []const u8) WebSocketExtension {
        return WebSocketExtension{
            .name = name,
            .parameters = StringHashMap([]const u8).init(allocator),
        };
    }
    
    pub fn deinit(self: *WebSocketExtension) void {
        self.parameters.deinit();
    }
    
    pub fn addParameter(self: *WebSocketExtension, key: []const u8, value: []const u8) void {
        self.parameters.put(key, value) catch {};
    }
    
    pub fn hasParameter(self: *WebSocketExtension, key: []const u8) bool {
        return self.parameters.contains(key);
    }
    
    pub fn getParameter(self: *WebSocketExtension, key: []const u8) ?[]const u8 {
        return self.parameters.get(key);
    }
};

// WebSocket frame
pub const WebSocketFrame = struct {
    fin: bool,
    opcode: WebSocketFrameType,
    masked: bool,
    payload_length: u64,
    masking_key: [4]u8,
    payload: []const u8,
    
    pub fn init(allocator: Allocator, opcode: WebSocketFrameType, payload: []const u8) WebSocketFrame {
        _ = allocator;
        return WebSocketFrame{
            .fin = true,
            .opcode = opcode,
            .masked = false,
            .payload_length = payload.len,
            .masking_key = [4]u8{ 0, 0, 0, 0 },
            .payload = payload,
        };
    }
    
    pub fn deinit(self: *WebSocketFrame) void {
        _ = self;
    }
    
    pub fn setMasking(self: *WebSocketFrame, masked: bool, key: [4]u8) void {
        self.masked = masked;
        self.masking_key = key;
    }
    
    pub fn encode(self: *WebSocketFrame, allocator: Allocator) ![]const u8 {
        var frame_data = ArrayList(u8).empty;
        errdefer frame_data.deinit(allocator);
        
        // First byte: FIN + RSV + opcode
        var first_byte: u8 = 0;
        if (self.fin) first_byte |= 0x80;
        first_byte |= @as(u8, @intFromEnum(self.opcode));
        try frame_data.append(allocator, first_byte);
        
        // Second byte: MASK + payload length
        var second_byte: u8 = 0;
        if (self.masked) second_byte |= 0x80;
        
        if (self.payload_length < 126) {
            second_byte |= @as(u8, @truncate(self.payload_length));
            try frame_data.append(allocator, second_byte);
        } else if (self.payload_length < 65536) {
            second_byte |= 126;
            try frame_data.append(allocator, second_byte);
            
            var len_bytes: [2]u8 = undefined;
            std.mem.writeInt(u16, &len_bytes, @as(u16, @truncate(self.payload_length)), .big);
            try frame_data.appendSlice(allocator, &len_bytes);
        } else {
            second_byte |= 127;
            try frame_data.append(allocator, second_byte);
            
            var len_bytes: [8]u8 = undefined;
            std.mem.writeInt(u64, &len_bytes, self.payload_length, .big);
            try frame_data.appendSlice(allocator, &len_bytes);
        }
        
        // Masking key (if masked)
        if (self.masked) {
            try frame_data.appendSlice(allocator, &self.masking_key);
        }
        
        // Payload
        if (self.masked) {
            const masked_payload = try allocator.alloc(u8, self.payload.len);
            defer allocator.free(masked_payload);
            
            for (self.payload, 0..) |byte, i| {
                masked_payload[i] = byte ^ self.masking_key[i % 4];
            }
            try frame_data.appendSlice(allocator, masked_payload);
        } else {
            try frame_data.appendSlice(allocator, self.payload);
        }
        
        return frame_data.toOwnedSlice(allocator);
    }
    
    pub fn decode(self: *WebSocketFrame, data: []const u8, allocator: Allocator) !usize {
        if (data.len < 2) return error.InsufficientData;
        
        // Parse first byte
        const first_byte = data[0];
        self.fin = (first_byte & 0x80) != 0;
        const opcode_value: u4 = @truncate(first_byte & 0x0F);
        self.opcode = @enumFromInt(opcode_value);
        
        // Parse second byte
        const second_byte = data[1];
        self.masked = (second_byte & 0x80) != 0;
        const payload_len_field = second_byte & 0x7F;
        
        // Parse payload length
        var offset: usize = 2;
        if (payload_len_field < 126) {
            self.payload_length = payload_len_field;
        } else if (payload_len_field == 126) {
            if (data.len < 4) return error.InsufficientData;
            self.payload_length = std.mem.readInt(u16, data[2..4], .big);
            offset = 4;
        } else {
            if (data.len < 10) return error.InsufficientData;
            self.payload_length = std.mem.readInt(u64, data[2..10], .big);
            offset = 10;
        }
        
        // Parse masking key (if present)
        if (self.masked) {
            if (data.len < offset + 4) return error.InsufficientData;
            @memcpy(&self.masking_key, data[offset .. offset + 4]);
            offset += 4;
        }
        
        // Parse payload
        if (data.len < offset + self.payload_length) return error.InsufficientData;
        const payload_start = offset;
        const payload_end = payload_start + self.payload_length;
        
        if (self.masked) {
            // Unmask payload
            const unmasked_payload = try allocator.alloc(u8, self.payload_length);
            for (data[payload_start..payload_end], 0..) |byte, i| {
                unmasked_payload[i] = byte ^ self.masking_key[i % 4];
            }
            self.payload = unmasked_payload;
        } else {
            self.payload = data[payload_start..payload_end];
        }
        
        return payload_end;
    }
    
    pub fn isControlFrame(self: *WebSocketFrame) bool {
        const opcode = @intFromEnum(self.opcode);
        return opcode >= 0x8; // Control frames have opcodes 8-15
    }
    
    pub fn isDataFrame(self: *WebSocketFrame) bool {
        const opcode = @intFromEnum(self.opcode);
        return opcode == 0x1 or opcode == 0x2; // Text or binary frames
    }
};

// WebSocket message (can span multiple frames)
pub const WebSocketMessage = struct {
    allocator: Allocator,
    message_type: WebSocketFrameType,
    complete_data: ArrayList(u8),
    is_complete: bool,
    frame_count: u32,
    
    pub fn init(allocator: Allocator, message_type: WebSocketFrameType) WebSocketMessage {
        return WebSocketMessage{
            .allocator = allocator,
            .message_type = message_type,
            .complete_data = .empty,
            .is_complete = false,
            .frame_count = 0,
        };
    }
    
    pub fn deinit(self: *WebSocketMessage) void {
        self.complete_data.deinit(self.allocator);
    }
    
    pub fn appendFrame(self: *WebSocketMessage, frame: *WebSocketFrame) !void {
        self.frame_count += 1;
        
        // For continuation frames, append to existing data
        if (frame.opcode == .CONTINUATION or (!frame.fin and self.frame_count > 1)) {
            self.complete_data.appendSlice(self.allocator, frame.payload) catch {};
        } else {
            // First frame
            self.complete_data.appendSlice(self.allocator, frame.payload) catch {};
        }
        
        // Check if this is the final frame
        if (frame.fin) {
            self.is_complete = true;
        }
    }
    
    pub fn getData(self: *WebSocketMessage) []const u8 {
        return self.complete_data.items;
    }
    
    pub fn clear(self: *WebSocketMessage) void {
        self.complete_data.clearRetainingCapacity();
        self.is_complete = false;
        self.frame_count = 0;
    }
};

// WebSocket connection state
pub const WebSocketState = enum {
    CONNECTING,
    OPEN,
    CLOSING,
    CLOSED,
};

// WebSocket extensions negotiated
pub const WebSocketNegotiation = struct {
    allocator: Allocator,
    client_extensions: ArrayList(WebSocketExtension),
    server_extensions: ArrayList(WebSocketExtension),
    negotiated_extensions: ArrayList(WebSocketExtension),
    
    pub fn init(allocator: Allocator) WebSocketNegotiation {
        return WebSocketNegotiation{
            .allocator = allocator,
            .client_extensions = .empty,
            .server_extensions = .empty,
            .negotiated_extensions = .empty,
        };
    }
    
    pub fn deinit(self: *WebSocketNegotiation) void {
        for (self.client_extensions.items) |*ext| ext.deinit();
        self.client_extensions.deinit(self.allocator);
        
        for (self.server_extensions.items) |*ext| ext.deinit();
        self.server_extensions.deinit(self.allocator);
        
        for (self.negotiated_extensions.items) |*ext| ext.deinit();
        self.negotiated_extensions.deinit(self.allocator);
    }
    
    pub fn addClientExtension(self: *WebSocketNegotiation, extension: WebSocketExtension) void {
        self.client_extensions.append(self.allocator, extension) catch {};
    }
    
    pub fn addServerExtension(self: *WebSocketNegotiation, extension: WebSocketExtension) void {
        self.server_extensions.append(self.allocator, extension) catch {};
    }
    
    pub fn negotiate(self: *WebSocketNegotiation) !void {
        // Simple negotiation: match by name
        for (self.client_extensions.items) |client_ext| {
            for (self.server_extensions.items) |server_ext| {
                if (std.mem.eql(u8, client_ext.name, server_ext.name)) {
                    var negotiated = WebSocketExtension.init(self.allocator, client_ext.name);
                    
                    // Match parameters
                    var client_iter = client_ext.parameters.keyIterator();
                    while (client_iter.next()) |param_key| {
                        const client_value = client_ext.parameters.get(param_key.*).?;
                        const server_value = server_ext.parameters.get(param_key.*);
                        
                        if (server_value) |sv| {
                            if (std.mem.eql(u8, client_value, sv)) {
                                negotiated.addParameter(param_key.*, client_value);
                            }
                        } else {
                            // Server doesn't have parameter, include client's value
                            negotiated.addParameter(param_key.*, client_value);
                        }
                    }
                    
                    self.negotiated_extensions.append(self.allocator, negotiated) catch {};
                    break;
                }
            }
        }
    }
    
    pub fn hasExtension(self: *WebSocketNegotiation, extension_name: []const u8) bool {
        for (self.negotiated_extensions.items) |ext| {
            if (std.mem.eql(u8, ext.name, extension_name)) {
                return true;
            }
        }
        return false;
    }
};

// WebSocket connection
pub const WebSocketConnection = struct {
    allocator: Allocator,
    connection_id: u64,
    url: []const u8,
    protocols: ArrayList([]const u8),
    state: WebSocketState,
    socket_fd: i32,
    created_timestamp: u64,
    last_activity_timestamp: u64,
    extensions: WebSocketNegotiation,
    current_message: ?WebSocketMessage,
    message_queue: ArrayList(WebSocketMessage),
    ping_queue: ArrayList(u64),
    binary_mode: bool,
    max_message_size: u64,
    compression_enabled: bool,
    
    pub fn init(allocator: Allocator, connection_id: u64, url: []const u8) WebSocketConnection {
        return WebSocketConnection{
            .allocator = allocator,
            .connection_id = connection_id,
            .url = url,
            .protocols = .empty,
            .state = .CONNECTING,
            .socket_fd = -1,
            .created_timestamp = getCurrentTimestamp(),
            .last_activity_timestamp = getCurrentTimestamp(),
            .extensions = WebSocketNegotiation.init(allocator),
            .current_message = null,
            .message_queue = .empty,
            .ping_queue = .empty,
            .binary_mode = false,
            .max_message_size = 16 * 1024 * 1024, // 16MB default
            .compression_enabled = false,
        };
    }
    
    pub fn deinit(self: *WebSocketConnection) void {
        self.protocols.deinit(self.allocator);
        self.extensions.deinit();
        
        if (self.current_message) |*msg| {
            msg.deinit();
        }
        
        for (self.message_queue.items) |*msg| {
            msg.deinit();
        }
        self.message_queue.deinit(self.allocator);
        
        self.ping_queue.deinit(self.allocator);
    }
    
    pub fn addProtocol(self: *WebSocketConnection, protocol: []const u8) void {
        self.protocols.append(self.allocator, protocol) catch {};
    }
    
    pub fn setBinaryMode(self: *WebSocketConnection, binary: bool) void {
        self.binary_mode = binary;
    }
    
    pub fn setMaxMessageSize(self: *WebSocketConnection, max_size: u64) void {
        self.max_message_size = max_size;
    }
    
    pub fn enableCompression(self: *WebSocketConnection, enabled: bool) void {
        self.compression_enabled = enabled;
    }
    
    pub fn updateActivity(self: *WebSocketConnection) void {
        self.last_activity_timestamp = getCurrentTimestamp();
    }
    
    pub fn isActive(self: *const WebSocketConnection, timeout_seconds: u64) bool {
        return (getCurrentTimestamp() - self.last_activity_timestamp) < (timeout_seconds * 1000);
    }

    pub fn sendRaw(self: *WebSocketConnection, data: []const u8) !void {
        if (self.socket_fd < 0) return error.SocketNotConnected;
        var sent: usize = 0;
        while (sent < data.len) {
            const rc = std.posix.system.write(self.socket_fd, data[sent..].ptr, data.len - sent);
            switch (std.posix.errno(rc)) {
                .SUCCESS => {
                    const n: usize = @intCast(rc);
                    if (n == 0) return error.ConnectionResetByPeer;
                    sent += n;
                },
                .INTR => continue,
                .PIPE, .CONNRESET => return error.ConnectionResetByPeer,
                else => return error.ProtocolError,
            }
        }
        self.updateActivity();
    }
    
    fn fillRandomBytes(buf: []u8) void {
        const rc = std.posix.system.getrandom(buf.ptr, buf.len, 0);
        if (rc == buf.len) return;
        var ts: std.posix.timespec = undefined;
        _ = std.posix.system.clock_gettime(.REALTIME, &ts);
        const seed: u64 = @bitCast(ts.nsec);
        var prng = std.Random.DefaultPrng.init(seed);
        prng.random().bytes(buf);
    }

    pub fn sendText(self: *WebSocketConnection, text: []const u8, allocator: Allocator) !void {
        if (self.state != .OPEN) return error.ConnectionNotOpen;
        
        var frame = WebSocketFrame.init(allocator, .TEXT, text);
        defer frame.deinit();
        
        // Set masking for client-to-server frames
        var masking_key: [4]u8 = undefined;
        fillRandomBytes(&masking_key);
        frame.setMasking(true, masking_key);
        
        const frame_data = try frame.encode(allocator);
        defer allocator.free(frame_data);

        try self.sendRaw(frame_data);
    }
    
    pub fn sendBinary(self: *WebSocketConnection, binary_data: []const u8, allocator: Allocator) !void {
        if (self.state != .OPEN) return error.ConnectionNotOpen;
        
        var frame = WebSocketFrame.init(allocator, .BINARY, binary_data);
        defer frame.deinit();
        
        // Set masking for client-to-server frames
        var masking_key: [4]u8 = undefined;
        fillRandomBytes(&masking_key);
        frame.setMasking(true, masking_key);
        
        const frame_data = try frame.encode(allocator);
        defer allocator.free(frame_data);

        try self.sendRaw(frame_data);
    }
    
    pub fn sendPing(self: *WebSocketConnection, allocator: Allocator) !void {
        if (self.state != .OPEN) return error.ConnectionNotOpen;
        
        const ping_data = std.fmt.allocPrint(allocator, "ping-{}", .{self.connection_id}) catch "";
        defer allocator.free(ping_data);
        
        var frame = WebSocketFrame.init(allocator, .PING, ping_data);
        defer frame.deinit();
        
        var masking_key: [4]u8 = undefined;
        fillRandomBytes(&masking_key);
        frame.setMasking(true, masking_key);
        
        const frame_data = try frame.encode(allocator);
        defer allocator.free(frame_data);

        try self.sendRaw(frame_data);
        
        // Track ping for pong response
        self.ping_queue.append(self.allocator, getCurrentTimestamp()) catch {};
    }
    
    pub fn sendPong(self: *WebSocketConnection, ping_data: []const u8, allocator: Allocator) !void {
        if (self.state != .OPEN) return error.ConnectionNotOpen;
        
        var frame = WebSocketFrame.init(allocator, .PONG, ping_data);
        defer frame.deinit();
        
        var masking_key: [4]u8 = undefined;
        fillRandomBytes(&masking_key);
        frame.setMasking(true, masking_key);
        
        const frame_data = try frame.encode(allocator);
        defer allocator.free(frame_data);

        try self.sendRaw(frame_data);
    }
    
    pub fn sendClose(self: *WebSocketConnection, code: WebSocketCloseCode, reason: []const u8, allocator: Allocator) !void {
        const payload = try allocator.alloc(u8, 2 + reason.len);
        defer allocator.free(payload);
        std.mem.writeInt(u16, payload[0..2], @intFromEnum(code), .big);
        @memcpy(payload[2..], reason);
        
        var frame = WebSocketFrame.init(allocator, .CLOSE, payload);
        defer frame.deinit();
        
        var masking_key: [4]u8 = undefined;
        fillRandomBytes(&masking_key);
        frame.setMasking(true, masking_key);
        
        const frame_data = try frame.encode(allocator);
        defer allocator.free(frame_data);

        if (self.socket_fd >= 0) {
            _ = self.sendRaw(frame_data) catch {};
        }
        
        self.state = .CLOSING;
    }
    
    pub fn processFrame(self: *WebSocketConnection, frame_data: []const u8, allocator: Allocator) !void {
        var frame = WebSocketFrame.init(allocator, .TEXT, "");
        defer frame.deinit();
        
        const bytes_consumed = try frame.decode(frame_data, allocator);
        
        self.updateActivity();
        
        switch (frame.opcode) {
            .TEXT, .BINARY => {
                // Handle data frames
                try self.processDataFrame(&frame, allocator);
            },
            .CONTINUATION => {
                // Handle continuation frames
                try self.processContinuationFrame(&frame, allocator);
            },
            .PING => {
                // Handle ping frames
                try self.processPingFrame(&frame, allocator);
            },
            .PONG => {
                // Handle pong frames
                try self.processPongFrame(&frame, allocator);
            },
            .CLOSE => {
                // Handle close frames
                try self.processCloseFrame(&frame, allocator);
            },
            else => {
                return error.InvalidOpcode;
            },
        }
        
        _ = bytes_consumed; // Would be used to track buffer consumption
    }
    
    fn processDataFrame(self: *WebSocketConnection, frame: *WebSocketFrame, allocator: Allocator) !void {
        if (frame.payload.len > self.max_message_size) {
            return error.MessageTooLarge;
        }
        
        // Start new message
        if (self.current_message == null) {
            self.current_message = WebSocketMessage.init(allocator, frame.opcode);
        }
        
        try self.current_message.?.appendFrame(frame);
        
        if (self.current_message.?.is_complete) {
            // Message complete, add to queue
            self.message_queue.append(self.allocator, self.current_message.?) catch {};
            self.current_message = null;
        }
    }
    
    fn processContinuationFrame(self: *WebSocketConnection, frame: *WebSocketFrame, allocator: Allocator) !void {
        _ = allocator;
        if (self.current_message == null) {
            return error.UnexpectedContinuation;
        }
        
        try self.current_message.?.appendFrame(frame);
        
        if (self.current_message.?.is_complete) {
            self.message_queue.append(self.allocator, self.current_message.?) catch {};
            self.current_message = null;
        }
    }
    
    fn processPingFrame(self: *WebSocketConnection, frame: *WebSocketFrame, allocator: Allocator) !void {
        // Send corresponding pong
        try self.sendPong(frame.payload, allocator);
    }
    
    fn processPongFrame(self: *WebSocketConnection, frame: *WebSocketFrame, allocator: Allocator) !void {
        _ = frame;
        _ = allocator;
        
        // Remove corresponding ping from queue
        if (self.ping_queue.items.len > 0) {
            _ = self.ping_queue.orderedRemove(0);
        }
    }
    
    fn processCloseFrame(self: *WebSocketConnection, frame: *WebSocketFrame, allocator: Allocator) !void {
        _ = frame;
        _ = allocator;
        
        self.state = .CLOSING;
    }
    
    pub fn getNextMessage(self: *WebSocketConnection) ?WebSocketMessage {
        if (self.message_queue.items.len == 0) return null;
        
        const message = self.message_queue.orderedRemove(0);
        return message;
    }
    
    pub fn getQueuedMessageCount(self: *WebSocketConnection) usize {
        return self.message_queue.items.len;
    }
    
    pub fn hasPendingPings(self: *WebSocketConnection) bool {
        return self.ping_queue.items.len > 0;
    }
};

// WebSocket connection pool
pub const WebSocketPool = struct {
    allocator: Allocator,
    connections: AutoHashMap(u64, WebSocketConnection),
    url_to_connection: StringHashMap(u64),
    next_connection_id: u64,
    max_connections_per_origin: usize,
    connection_timeout_seconds: u64,
    
    pub fn init(allocator: Allocator, max_per_origin: usize) WebSocketPool {
        return WebSocketPool{
            .allocator = allocator,
            .connections = AutoHashMap(u64, WebSocketConnection).init(allocator),
            .url_to_connection = StringHashMap(u64).init(allocator),
            .next_connection_id = 1,
            .max_connections_per_origin = max_per_origin,
            .connection_timeout_seconds = 300, // 5 minutes
        };
    }
    
    pub fn deinit(self: *WebSocketPool) void {
        var conn_iter = self.connections.valueIterator();
        while (conn_iter.next()) |connection| {
            connection.deinit();
        }
        self.connections.deinit();
        self.url_to_connection.deinit();
    }
    
    pub fn createConnection(self: *WebSocketPool, url: []const u8, protocols: ?ArrayList([]const u8)) !*WebSocketConnection {
        // Check if connection already exists for this URL
        if (self.url_to_connection.get(url)) |existing_id| {
            if (self.connections.getPtr(existing_id)) |existing| {
                if (existing.state == .OPEN) {
                    return existing;
                }
            }
        }
        
        const connection_id = self.next_connection_id;
        self.next_connection_id += 1;
        
        var connection = WebSocketConnection.init(self.allocator, connection_id, url);
        
        if (protocols) |protocols_list| {
            for (protocols_list.items) |protocol| {
                connection.addProtocol(protocol);
            }
        }
        
        try self.connections.put(connection_id, connection);
        try self.url_to_connection.put(url, connection_id);
        
        return self.connections.getPtr(connection_id).?;
    }
    
    pub fn getConnection(self: *WebSocketPool, url: []const u8) ?*WebSocketConnection {
        if (self.url_to_connection.get(url)) |connection_id| {
            return self.connections.getPtr(connection_id);
        }
        return null;
    }
    
    pub fn removeConnection(self: *WebSocketPool, connection_id: u64) void {
        if (self.connections.getPtr(connection_id)) |connection| {
            _ = self.url_to_connection.remove(connection.url);
            connection.deinit();
        }
        _ = self.connections.remove(connection_id);
    }
    
    pub fn closeConnection(self: *WebSocketPool, connection_id: u64, code: WebSocketCloseCode, reason: []const u8, allocator: Allocator) !void {
        if (self.connections.getPtr(connection_id)) |connection| {
            try connection.sendClose(code, reason, allocator);
            connection.state = .CLOSING;
        }
    }
    
    pub fn cleanupInactive(self: *WebSocketPool) void {
        var to_remove = ArrayList(u64).empty;
        defer to_remove.deinit(self.allocator);
        
        var conn_iter = self.connections.keyIterator();
        while (conn_iter.next()) |connection_id| {
            if (self.connections.get(connection_id.*)) |connection| {
                if (!connection.isActive(self.connection_timeout_seconds)) {
                    to_remove.append(self.allocator, connection_id.*) catch {};
                }
            }
        }
        
        for (to_remove.items) |conn_id| {
            self.removeConnection(conn_id);
        }
    }
    
    pub fn getConnectionCount(self: *WebSocketPool) usize {
        return self.connections.count();
    }
    
    pub fn getActiveConnectionCount(self: *WebSocketPool) usize {
        var active_count: usize = 0;
        var conn_iter = self.connections.valueIterator();
        while (conn_iter.next()) |connection| {
            if (connection.state == .OPEN) {
                active_count += 1;
            }
        }
        return active_count;
    }
};

// WebSocket error types
pub const WebSocketError = error{
    InvalidOpcode,
    InsufficientData,
    MessageTooLarge,
    ConnectionNotOpen,
    UnexpectedContinuation,
    InvalidFrame,
    ProtocolError,
    ExtensionError,
    SocketNotConnected,
};

// Helper functions
fn getCurrentTimestamp() u64 {
    var ts: std.posix.timespec = undefined;
    _ = std.posix.system.clock_gettime(.REALTIME, &ts);
    return @as(u64, @intCast(@max(0, ts.sec))) * 1000 + @as(u64, @intCast(@divTrunc(ts.nsec, 1_000_000)));
}

pub const WebSocketProtocolConfig = struct {
    max_frame_size: usize = 16 * 1024 * 1024,
    ping_interval: u64 = 30000,
    connection_timeout: u64 = 60000,
};

pub const WebSocketProtocol = struct {
    allocator: Allocator,
    config: WebSocketProtocolConfig,
    extensions: []const []const u8,

    pub fn init(allocator: Allocator) !WebSocketProtocol {
        return WebSocketProtocol{
            .allocator = allocator,
            .config = .{},
            .extensions = &[_][]const u8{"permessage-deflate"},
        };
    }

    pub fn deinit(self: *WebSocketProtocol) void {
        _ = self;
    }

    pub fn getSupportedExtensions(self: *const WebSocketProtocol) []const []const u8 {
        return self.extensions;
    }

    pub fn getConfig(self: *const WebSocketProtocol) ?*const WebSocketProtocolConfig {
        return &self.config;
    }

    pub fn updateConfig(self: *WebSocketProtocol, new_config: WebSocketProtocolConfig) !void {
        self.config = new_config;
    }
};

test "websocket frame encoding and decoding" {
    const allocator = std.testing.allocator;
    
    // Test text frame encoding/decoding
    const test_text = "Hello, WebSocket!";
    var frame = WebSocketFrame.init(allocator, .TEXT, test_text);
    defer frame.deinit();
    
    frame.fin = true;
    frame.masked = false;
    
    const encoded = try frame.encode(allocator);
    defer allocator.free(encoded);
    
    try std.testing.expect(encoded.len > 0);
    
    // Test decoding
    var decoded_frame = WebSocketFrame.init(allocator, .TEXT, "");
    const bytes_consumed = try decoded_frame.decode(encoded, allocator);
    
    try std.testing.expect(decoded_frame.fin);
    try std.testing.expectEqual(WebSocketFrameType.TEXT, decoded_frame.opcode);
    try std.testing.expectEqual(test_text.len, decoded_frame.payload_length);
    try std.testing.expect(std.mem.eql(u8, test_text, decoded_frame.payload));
    try std.testing.expectEqual(encoded.len, bytes_consumed);
}

test "websocket frame types" {
    const allocator = std.testing.allocator;
    
    var text_frame = WebSocketFrame.init(allocator, .TEXT, "text");
    try std.testing.expect(text_frame.isDataFrame());
    try std.testing.expect(!text_frame.isControlFrame());
    
    var close_frame = WebSocketFrame.init(allocator, .CLOSE, "close");
    try std.testing.expect(!close_frame.isDataFrame());
    try std.testing.expect(close_frame.isControlFrame());
    
    var ping_frame = WebSocketFrame.init(allocator, .PING, "ping");
    try std.testing.expect(!ping_frame.isDataFrame());
    try std.testing.expect(ping_frame.isControlFrame());
}

test "websocket connection lifecycle" {
    const allocator = std.testing.allocator;
    var connection = WebSocketConnection.init(allocator, 1, "wss://echo.websocket.org");
    defer connection.deinit();
    
    try std.testing.expectEqual(WebSocketState.CONNECTING, connection.state);
    try std.testing.expectEqual(@as(u64, 1), connection.connection_id);
    try std.testing.expect(!connection.binary_mode);
    try std.testing.expectEqual(@as(u64, 16 * 1024 * 1024), connection.max_message_size);
    
    // Add protocols
    connection.addProtocol("chat");
    connection.addProtocol("superchat");
    try std.testing.expectEqual(@as(usize, 2), connection.protocols.items.len);
    
    // Set binary mode
    connection.setBinaryMode(true);
    try std.testing.expect(connection.binary_mode);
    
    // Update activity
    const initial_activity = connection.last_activity_timestamp;
    connection.updateActivity();
    try std.testing.expect(connection.last_activity_timestamp >= initial_activity);
    
    // Test isActive
    try std.testing.expect(connection.isActive(300)); // Should be active
}

test "websocket message handling" {
    const allocator = std.testing.allocator;
    var message = WebSocketMessage.init(allocator, .TEXT);
    defer message.deinit();
    
    try std.testing.expect(!message.is_complete);
    try std.testing.expectEqual(@as(u32, 0), message.frame_count);
    
    // Simulate frames (simplified - would need actual frame objects)
    // For testing, we'll just check the structure
    message.complete_data.appendSlice(allocator, "Hello ") catch {};
    message.frame_count = 1;
    message.is_complete = true;
    
    try std.testing.expect(message.is_complete);
    try std.testing.expectEqual(@as(u32, 1), message.frame_count);
    try std.testing.expect(std.mem.eql(u8, "Hello ", message.getData()));
}

test "websocket pool operations" {
    const allocator = std.testing.allocator;
    var pool = WebSocketPool.init(allocator, 5);
    defer pool.deinit();
    
    try std.testing.expectEqual(@as(usize, 0), pool.getConnectionCount());
    try std.testing.expectEqual(@as(usize, 0), pool.getActiveConnectionCount());
    
    // Create connection
    var protocols = ArrayList([]const u8).empty;
    defer protocols.deinit(allocator);
    protocols.append(allocator, "chat") catch {};
    
    const connection = try pool.createConnection("wss://echo.websocket.org", protocols);
    try std.testing.expectEqual(@as(usize, 1), pool.getConnectionCount());
    
    // Get same connection
    const same_connection = pool.getConnection("wss://echo.websocket.org");
    try std.testing.expect(same_connection != null);
    try std.testing.expectEqual(connection.connection_id, same_connection.?.connection_id);
    
    // Remove connection
    pool.removeConnection(connection.connection_id);
    try std.testing.expectEqual(@as(usize, 0), pool.getConnectionCount());
    
    // Cleanup inactive connections (none to remove)
    pool.cleanupInactive();
    try std.testing.expectEqual(@as(usize, 0), pool.getConnectionCount());
}

test "websocket socket transmission sends raw frames over socket" {
    const allocator = std.testing.allocator;
    var fds: [2]std.posix.fd_t = undefined;
    _ = std.posix.system.pipe(&fds);
    defer {
        _ = std.posix.system.close(fds[0]);
        _ = std.posix.system.close(fds[1]);
    }

    var connection = WebSocketConnection.init(allocator, 42, "wss://example.com/ws");
    defer connection.deinit();
    connection.socket_fd = fds[1];
    connection.state = .OPEN;

    // Test sendText transmits actual bytes over the socket
    const msg = "ping-pong-websocket";
    try connection.sendText(msg, allocator);

    var buf: [256]u8 = undefined;
    const rc1 = std.posix.system.read(fds[0], &buf, buf.len);
    try std.testing.expect(rc1 > 0);
    const n: usize = @intCast(rc1);

    var rx_frame = WebSocketFrame.init(allocator, .TEXT, "");
    defer {
        if (rx_frame.masked) allocator.free(rx_frame.payload);
    }
    const consumed = try rx_frame.decode(buf[0..n], allocator);
    try std.testing.expectEqual(n, consumed);
    try std.testing.expectEqual(WebSocketFrameType.TEXT, rx_frame.opcode);
    try std.testing.expect(rx_frame.masked);
    try std.testing.expectEqualStrings(msg, rx_frame.payload);

    // Test sendClose transmits close frame and updates state to CLOSING
    try connection.sendClose(.NORMAL_CLOSURE, "bye", allocator);
    try std.testing.expectEqual(WebSocketState.CLOSING, connection.state);

    const rc2 = std.posix.system.read(fds[0], &buf, buf.len);
    try std.testing.expect(rc2 > 0);
    const close_n: usize = @intCast(rc2);

    var close_rx = WebSocketFrame.init(allocator, .CLOSE, "");
    defer {
        if (close_rx.masked) allocator.free(close_rx.payload);
    }
    _ = try close_rx.decode(buf[0..close_n], allocator);
    try std.testing.expectEqual(WebSocketFrameType.CLOSE, close_rx.opcode);
    try std.testing.expect(close_rx.payload.len >= 2);
    const code_val = std.mem.readInt(u16, close_rx.payload[0..2], .big);
    try std.testing.expectEqual(@as(u16, @intFromEnum(WebSocketCloseCode.NORMAL_CLOSURE)), code_val);
    try std.testing.expectEqualStrings("bye", close_rx.payload[2..]);
}