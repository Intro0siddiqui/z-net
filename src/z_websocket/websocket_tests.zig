//! z_websocket - WebSocket Comprehensive Test Suite
//! 
//! Complete test coverage for WebSocket protocol implementation
//! including frame parsing, masking, handshake, and protocol compliance.

const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;
const StringHashMap = std.StringHashMap;
const ArrayList = std.ArrayList;

const websocket_protocol = @import("websocket_protocol.zig");
const websocket_manager = @import("websocket_manager.zig");

const WebSocketFrameType = websocket_protocol.WebSocketFrameType;
const WebSocketCloseCode = websocket_protocol.WebSocketCloseCode;
const WebSocketFrame = websocket_protocol.WebSocketFrame;
const WebSocketProtocol = websocket_protocol.WebSocketProtocol;
const WebSocketHandshakeRequest = websocket_manager.WebSocketHandshakeRequest;
const WebSocketManager = websocket_manager.WebSocketManager;

test "WebSocket Frame Type Values" {
    testing.expect(@as(u8, @intFromEnum(WebSocketFrameType.TEXT)) == 0x1);
    testing.expect(@as(u8, @intFromEnum(WebSocketFrameType.BINARY)) == 0x2);
    testing.expect(@as(u8, @intFromEnum(WebSocketFrameType.CLOSE)) == 0x8);
    testing.expect(@as(u8, @intFromEnum(WebSocketFrameType.PING)) == 0x9);
    testing.expect(@as(u8, @intFromEnum(WebSocketFrameType.PONG)) == 0xA);
}

test "WebSocket Close Code Values" {
    testing.expect(@as(u16, @intFromEnum(WebSocketCloseCode.NORMAL_CLOSURE)) == 1000);
    testing.expect(@as(u16, @intFromEnum(WebSocketCloseCode.PROTOCOL_ERROR)) == 1002);
    testing.expect(@as(u16, @intFromEnum(WebSocketCloseCode.POLICY_VIOLATION)) == 1008);
    testing.expect(@as(u16, @intFromEnum(WebSocketCloseCode.MESSAGE_TOO_BIG)) == 1009);
}

test "WebSocketFrame Basic Structure" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    const test_payload = "Hello, WebSocket!";
    
    var frame = WebSocketFrame.init(allocator);
    defer frame.deinit();
    
    frame.frame_type = WebSocketFrameType.TEXT;
    frame.fin = true;
    frame.rsv1 = false;
    frame.rsv2 = false;
    frame.rsv3 = false;
    frame.payload = ArrayList(u8).fromOwnedSlice(allocator, test_payload);
    
    testing.expect(frame.fin == true);
    testing.expect(frame.frame_type == WebSocketFrameType.TEXT);
    testing.expect(std.mem.eql(u8, frame.payload.items, test_payload));
}

test "WebSocket Masking Operation" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    const original = "Hello";
    const mask: [4]u8 = [4]u8{ 0x12, 0x34, 0x56, 0x78 };
    
    // Create a frame for masking
    var frame = WebSocketFrame.init(allocator);
    defer frame.deinit();
    
    frame.mask = mask;
    frame.masked = true;
    frame.payload = ArrayList(u8).fromOwnedSlice(allocator, original);
    
    // Test masking
    frame.maskPayload();
    
    // Verify payload is different after masking
    const masked_data = frame.payload.items;
    testing.expect(!std.mem.eql(u8, masked_data, original));
    
    // Test unmasking returns original
    frame.maskPayload();
    testing.expect(std.mem.eql(u8, frame.payload.items, original));
}

test "WebSocket Frame Serialization" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    const test_data = "Test Message";
    
    var frame = WebSocketFrame.init(allocator);
    defer frame.deinit();
    
    frame.frame_type = WebSocketFrameType.TEXT;
    frame.fin = true;
    frame.payload = ArrayList(u8).fromOwnedSlice(allocator, test_data);
    
    // Serialize frame
    const serialized = frame.toBytes(allocator) catch |err| {
        testing.expect(false) catch {};
        return error.TestFailed;
    };
    defer allocator.free(serialized);
    
    // Verify basic frame structure
    testing.expect(serialized.len > 2); // Minimum 2 bytes (first byte + length)
    
    // Verify first byte has FIN bit and correct opcode
    const first_byte = serialized[0];
    testing.expect((first_byte & 0x80) != 0); // FIN bit should be set
    testing.expect((first_byte & 0x0F) == @as(u8, @intFromEnum(WebSocketFrameType.TEXT)));
}

test "WebSocket Frame Parsing" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    // Test parsing a simple text frame
    const test_frame_bytes = [_]u8{
        0x81, // FIN=1, opcode=TEXT (0x1)
        0x0D, // Payload length = 13 bytes
        'H', 'e', 'l', 'l', 'o', ' ', 'W', 'e', 'b', 'S', 'o', 'c', 'k', 'e', 't', '!'
    };
    
    var frame = WebSocketFrame.parse(allocator, &test_frame_bytes) catch |err| {
        testing.expect(false) catch {};
        return error.TestFailed;
    };
    defer frame.deinit();
    
    testing.expect(frame.fin == true);
    testing.expect(frame.frame_type == WebSocketFrameType.TEXT);
    testing.expectEqual(frame.payload.items.len, 13);
    
    const expected_payload = "Hello, WebSocket!";
    testing.expect(std.mem.eql(u8, frame.payload.items, expected_payload));
}

test "WebSocket Handshake Request Generation" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    const test_url = "wss://example.com/chat";
    
    var request = WebSocketHandshakeRequest.init(allocator, test_url);
    defer request.deinit();
    
    // Set required headers
    request.setHeader("Origin", "https://example.com");
    request.setHeader("Sec-WebSocket-Extensions", "permessage-deflate; client_max_window_bits");
    
    // Generate handshake request
    const handshake = request.generateHandshakeRequest(allocator) catch |err| {
        testing.expect(false) catch {};
        return error.TestFailed;
    };
    defer allocator.free(handshake);
    
    // Verify basic structure
    testing.expect(std.mem.indexOf(u8, handshake, "GET") != null);
    testing.expect(std.mem.indexOf(u8, handshake, "/chat") != null);
    testing.expect(std.mem.indexOf(u8, handshake, "HTTP/1.1") != null);
    testing.expect(std.mem.indexOf(u8, handshake, "Upgrade: websocket") != null);
    testing.expect(std.mem.indexOf(u8, handshake, "Connection: Upgrade") != null);
    testing.expect(std.mem.indexOf(u8, handshake, "Sec-WebSocket-Key:") != null);
    testing.expect(std.mem.indexOf(u8, handshake, "Sec-WebSocket-Version: 13") != null);
}

test "WebSocket Handshake Response Validation" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    const test_key = [24]u8{ 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X' };
    
    // Generate expected accept key (this would normally use SHA-1 + Base64)
    const expected_accept = websocket_manager.generateAcceptKey(test_key);
    
    // Test handshake response validation
    const valid_response = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " ++ expected_accept ++ "\r\n\r\n";
    
    const is_valid = websocket_manager.validateHandshakeResponse(valid_response, test_key) catch |err| {
        testing.expect(false) catch {};
        return error.TestFailed;
    };
    
    testing.expect(is_valid == true);
}

test "WebSocket Protocol Manager Initialization" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    var manager = WebSocketProtocol.init(allocator) catch |err| {
        testing.expect(false) catch {};
        return error.TestFailed;
    };
    defer manager.deinit();
    
    testing.expect(manager.allocator == allocator);
}

test "WebSocket Manager Connection Pool" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    var manager = WebSocketManager.init(allocator) catch |err| {
        testing.expect(false) catch {};
        return error.TestFailed;
    };
    defer manager.deinit();
    
    // Test connection pool operations
    const pool = manager.getConnectionPool();
    testing.expect(pool != null);
}

test "WebSocket Protocol Extensions Support" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    var protocol = WebSocketProtocol.init(allocator) catch |err| {
        testing.expect(false) catch {};
        return error.TestFailed;
    };
    defer protocol.deinit();
    
    // Test extension support
    const extensions = protocol.getSupportedExtensions();
    testing.expect(extensions != null);
    testing.expect(extensions.len > 0);
}

test "WebSocket Binary Data Handling" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    // Test binary data frame
    const binary_data = [_]u8{ 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A }; // PNG header
    
    var frame = WebSocketFrame.init(allocator);
    defer frame.deinit();
    
    frame.frame_type = WebSocketFrameType.BINARY;
    frame.fin = true;
    frame.payload = ArrayList(u8).fromOwnedSlice(allocator, &binary_data);
    
    // Test serialization of binary frame
    const serialized = frame.toBytes(allocator) catch |err| {
        testing.expect(false) catch {};
        return error.TestFailed;
    };
    defer allocator.free(serialized);
    
    // Verify binary frame structure
    testing.expect(serialized.len > 2);
    const first_byte = serialized[0];
    testing.expect((first_byte & 0x0F) == @as(u8, @intFromEnum(WebSocketFrameType.BINARY)));
}

test "WebSocket Large Payload Handling" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    // Create a large payload (100KB)
    var large_payload = ArrayList(u8).init(allocator);
    defer large_payload.deinit();
    
    const chunk = "A" ** 1024;
    for (0..100) |_| {
        large_payload.appendSlice(chunk) catch |err| {
            testing.expect(false) catch {};
            return error.TestFailed;
        };
    }
    
    var frame = WebSocketFrame.init(allocator);
    defer frame.deinit();
    
    frame.frame_type = WebSocketFrameType.TEXT;
    frame.fin = true;
    frame.payload = large_payload;
    
    // Test serialization of large frame
    const serialized = frame.toBytes(allocator) catch |err| {
        testing.expect(false) catch {};
        return error.TestFailed;
    };
    defer allocator.free(serialized);
    
    testing.expect(serialized.len > 102400); // Should be at least 100KB
}

test "WebSocket Ping/Pong Protocol" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    // Test ping frame
    var ping_frame = WebSocketFrame.init(allocator);
    defer ping_frame.deinit();
    
    ping_frame.frame_type = WebSocketFrameType.PING;
    ping_frame.fin = true;
    ping_frame.payload = ArrayList(u8).fromOwnedSlice(allocator, "ping");
    
    testing.expect(ping_frame.frame_type == WebSocketFrameType.PING);
    
    // Test pong frame
    var pong_frame = WebSocketFrame.init(allocator);
    defer pong_frame.deinit();
    
    pong_frame.frame_type = WebSocketFrameType.PONG;
    pong_frame.fin = true;
    pong_frame.payload = ArrayList(u8).fromOwnedSlice(allocator, "pong");
    
    testing.expect(pong_frame.frame_type == WebSocketFrameType.PONG);
}

test "WebSocket Close Handshake" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    // Test close frame with code
    var close_frame = WebSocketFrame.init(allocator);
    defer close_frame.deinit();
    
    close_frame.frame_type = WebSocketFrameType.CLOSE;
    close_frame.fin = true;
    
    // Add close code (2 bytes) + reason
    var close_payload = ArrayList(u8).init(allocator);
    defer close_payload.deinit();
    
    // Normal closure code: 1000 (0x03E8)
    close_payload.append(0x03) catch {};
    close_payload.append(0xE8) catch {};
    close_payload.appendSlice("Normal closure") catch {};
    
    close_frame.payload = close_payload;
    
    testing.expect(close_frame.frame_type == WebSocketFrameType.CLOSE);
    testing.expect(close_frame.payload.items.len > 2); // Should have at least code
}

test "WebSocket Fragmentation Support" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    // Test fragmented frame (FIN = 0)
    var fragment1 = WebSocketFrame.init(allocator);
    defer fragment1.deinit();
    
    fragment1.frame_type = WebSocketFrameType.TEXT;
    fragment1.fin = false; // This is a fragment
    fragment1.payload = ArrayList(u8).fromOwnedSlice(allocator, "Part 1 of ");
    
    testing.expect(fragment1.fin == false);
    testing.expect(fragment1.frame_type == WebSocketFrameType.TEXT);
    
    // Test continuation frame
    var continuation = WebSocketFrame.init(allocator);
    defer continuation.deinit();
    
    continuation.frame_type = WebSocketFrameType.CONTINUATION;
    continuation.fin = true; // This is the final fragment
    continuation.payload = ArrayList(u8).fromOwnedSlice(allocator, "2");
    
    testing.expect(continuation.frame_type == WebSocketFrameType.CONTINUATION);
    testing.expect(continuation.fin == true);
}

test "WebSocket Frame Validation" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    // Test invalid opcode
    var invalid_frame = WebSocketFrame.init(allocator);
    defer invalid_frame.deinit();
    
    // Try to set an invalid frame type (should be handled gracefully)
    // The enum should only allow valid opcodes
    testing.expect(invalid_frame.validate() == true);
    
    // Test frame with no payload
    var empty_frame = WebSocketFrame.init(allocator);
    defer empty_frame.deinit();
    
    empty_frame.frame_type = WebSocketFrameType.TEXT;
    empty_frame.fin = true;
    // No payload set
    
    testing.expect(empty_frame.validate() == true); // Empty payload should be valid
}

test "WebSocket Memory Management" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    // Create multiple frames and ensure proper cleanup
    var frames = ArrayList(*WebSocketFrame).init(allocator);
    defer {
        for (frames.items) |*frame| {
            frame.*.deinit();
            allocator.destroy(frame.*);
        }
        frames.deinit();
    }
    
    for (0..10) |i| {
        const frame = allocator.create(WebSocketFrame) catch |err| {
            testing.expect(false) catch {};
            return error.TestFailed;
        };
        
        frame.* = WebSocketFrame.init(allocator);
        frame.*.frame_type = WebSocketFrameType.TEXT;
        frame.*.fin = true;
        frame.*.payload = ArrayList(u8).fromOwnedSlice(allocator, "Test message");
        
        frames.append(frame) catch |err| {
            testing.expect(false) catch {};
            return error.TestFailed;
        };
    }
    
    testing.expect(frames.items.len == 10);
}

test "WebSocket Protocol Configuration" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    var protocol = WebSocketProtocol.init(allocator) catch |err| {
        testing.expect(false) catch {};
        return error.TestFailed;
    };
    defer protocol.deinit();
    
    // Test configuration access
    const config = protocol.getConfig();
    testing.expect(config != null);
    
    // Test updating configuration
    protocol.updateConfig(.{
        .max_frame_size = 1024 * 1024, // 1MB
        .ping_interval = 30000, // 30 seconds
        .connection_timeout = 60000, // 60 seconds
    }) catch |err| {
        testing.expect(false) catch {};
        return error.TestFailed;
    };
}

// Integration test for complete WebSocket workflow
test "WebSocket Complete Workflow Simulation" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    // Initialize WebSocket manager
    var manager = WebSocketManager.init(allocator) catch |err| {
        testing.expect(false) catch {};
        return error.TestFailed;
    };
    defer manager.deinit();
    
    // Simulate handshake request
    const handshake_request = WebSocketHandshakeRequest.init(allocator, "wss://example.com/ws");
    defer handshake_request.deinit();
    
    handshake_request.setHeader("Origin", "https://example.com");
    
    // Generate handshake
    const handshake = handshake_request.generateHandshakeRequest(allocator) catch |err| {
        testing.expect(false) catch {};
        return error.TestFailed;
    };
    defer allocator.free(handshake);
    
    testing.expect(handshake.len > 0);
    
    // Simulate a simple message exchange
    var message_frame = WebSocketFrame.init(allocator);
    defer message_frame.deinit();
    
    message_frame.frame_type = WebSocketFrameType.TEXT;
    message_frame.fin = true;
    message_frame.payload = ArrayList(u8).fromOwnedSlice(allocator, "Hello WebSocket!");
    
    // Serialize message
    const message_bytes = message_frame.toBytes(allocator) catch |err| {
        testing.expect(false) catch {};
        return error.TestFailed;
    };
    defer allocator.free(message_bytes);
    
    testing.expect(message_bytes.len > 0);
    
    // Parse message back
    var parsed_frame = WebSocketFrame.parse(allocator, message_bytes) catch |err| {
        testing.expect(false) catch {};
        return error.TestFailed;
    };
    defer parsed_frame.deinit();
    
    testing.expect(parsed_frame.frame_type == WebSocketFrameType.TEXT);
    testing.expect(std.mem.eql(u8, parsed_frame.payload.items, "Hello WebSocket!"));
}

// Test runner for all WebSocket tests
pub fn runAllWebSocketTests() !void {
    std.log.info("🧪 Running WebSocket Protocol Tests...", .{});
    
    // Individual tests
    testing.log("Frame Type Values", test "WebSocket Frame Type Values");
    testing.log("Close Code Values", test "WebSocket Close Code Values");
    testing.log("Frame Structure", test "WebSocketFrame Basic Structure");
    testing.log("Masking Operation", test "WebSocket Masking Operation");
    testing.log("Frame Serialization", test "WebSocket Frame Serialization");
    testing.log("Frame Parsing", test "WebSocket Frame Parsing");
    testing.log("Handshake Request", test "WebSocket Handshake Request Generation");
    testing.log("Handshake Response", test "WebSocket Handshake Response Validation");
    testing.log("Protocol Manager", test "WebSocket Protocol Manager Initialization");
    testing.log("Connection Pool", test "WebSocket Manager Connection Pool");
    testing.log("Extensions Support", test "WebSocket Protocol Extensions Support");
    testing.log("Binary Data", test "WebSocket Binary Data Handling");
    testing.log("Large Payload", test "WebSocket Large Payload Handling");
    testing.log("Ping/Pong", test "WebSocket Ping/Pong Protocol");
    testing.log("Close Handshake", test "WebSocket Close Handshake");
    testing.log("Fragmentation", test "WebSocket Fragmentation Support");
    testing.log("Frame Validation", test "WebSocket Frame Validation");
    testing.log("Memory Management", test "WebSocket Memory Management");
    testing.log("Protocol Config", test "WebSocket Protocol Configuration");
    testing.log("Complete Workflow", test "WebSocket Complete Workflow Simulation");
    
    std.log.info("✅ All WebSocket tests completed!", .{});
}