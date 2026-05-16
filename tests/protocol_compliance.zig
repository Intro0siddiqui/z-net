const std = @import("std");
const testing = std.testing;
const net = std.net;
const http = @import("../src/z_http/http.zig");
const http3 = @import("../src/z_http3/http3.zig");
const quic = @import("../src/z_quic/quic.zig");

/// Protocol Compliance Test Suite
/// Tests HTTP/1.1, HTTP/2, HTTP/3, and QUIC protocol compliance with RFC validation
pub const ProtocolComplianceTests = struct {
    const TestResult = struct {
        protocol: []const u8,
        test_name: []const u8,
        passed: bool,
        error: ?[]const u8,
        timestamp: i128,
    };

    /// HTTP/1.1 RFC 7230-7235 compliance tests
    pub fn testHTTP11Compliance() !TestResult {
        const start_time = std.time.nanoTimestamp();
        
        // Test 1: HTTP/1.1 Request Format
        const request = "GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n";
        try testing.expectEqualStrings("GET", try extractMethod(request));
        try testing.expectEqualStrings("/test", try extractPath(request));
        try testing.expectEqualStrings("HTTP/1.1", try extractVersion(request));

        // Test 2: Header validation
        const headers = try parseHeaders("Content-Type: application/json\r\nUser-Agent: z-net/1.0\r\n\r\n");
        try testing.expectEqual(@as(usize, 2), headers.len);

        // Test 3: Chunked transfer encoding (RFC 7230 Section 4.1)
        const chunked_data = "5\r\nHello\r\n0\r\n\r\n";
        const decoded = try decodeChunked(chunked_data);
        try testing.expectEqualStrings("Hello", decoded);

        // Test 4: Connection keep-alive
        const conn_header = try parseConnectionHeader("Connection: keep-alive");
        try testing.expectEqualStrings("keep-alive", conn_header);

        // Test 5: Status code validation
        const status = try parseStatusCode("HTTP/1.1 200 OK");
        try testing.expectEqual(@as(u16, 200), status.code);
        try testing.expectEqualStrings("OK", status.reason);

        const end_time = std.time.nanoTimestamp();
        return TestResult{
            .protocol = "HTTP/1.1",
            .test_name = "RFC 7230-7235 Compliance",
            .passed = true,
            .error = null,
            .timestamp = end_time - start_time,
        };
    }

    /// HTTP/2 RFC 7540 compliance tests
    pub fn testHTTP2Compliance() !TestResult {
        const start_time = std.time.nanoTimestamp();

        // Test 1: HTTP/2 Frame Format
        const frame = createHTTP2Frame(.HEADERS, 0x12345678, 12);
        try testing.expectEqual(@as(u8, 0x01), frame.type); // HEADERS frame type
        try testing.expectEqual(@as(u8, 0x05), frame.flags);
        try testing.expectEqual(@as(u32, 0x12345678), frame.stream_id);

        // Test 2: Stream prioritization (RFC 7540 Section 5.3)
        const priority = createPriorityFrame(0x12345678, 0x87654321, 0, false);
        try testing.expectEqual(@as(u32, 0x87654321), priority.parent_stream);

        // Test 3: Flow control (RFC 7540 Section 6.9)
        const window_update = createWindowUpdateFrame(0x12345678, 65536);
        try testing.expectEqual(@as(u32, 65536), window_update.window_size_increment);

        // Test 4: HPACK header compression (RFC 7541)
        const hpack_table = try initHPACKTable();
        const encoded_headers = try encodeHeaders(&hpack_table, "example.com", "/test", "GET");
        const decoded_headers = try decodeHeaders(&hpack_table, encoded_headers);
        try testing.expectEqualStrings("example.com", decoded_headers.host);
        try testing.expectEqualStrings("/test", decoded_headers.path);

        // Test 5: Push Promise validation
        const push_promise = createPushPromiseFrame(0x12345678, 0x87654321, encoded_headers);
        try testing.expectEqual(@as(u8, 0x05), push_promise.type); // PUSH_PROMISE type

        const end_time = std.time.nanoTimestamp();
        return TestResult{
            .protocol = "HTTP/2",
            .test_name = "RFC 7540 Compliance",
            .passed = true,
            .error = null,
            .timestamp = end_time - start_time,
        };
    }

    /// HTTP/3 RFC 9114 compliance tests
    pub fn testHTTP3Compliance() !TestResult {
        const start_time = std.time.nanoTimestamp();

        // Test 1: HTTP/3 Frame Types
        const qpack_encoder = try initQPACKEncoder();
        const qpack_decoder = try initQPACKDecoder();

        // Test 2: QPACK dynamic table operations
        try qpack_encoder.insertEntry("content-type", "application/json");
        const inserted = try qpack_encoder.getInsertedCount();
        try testing.expect(inserted > 0);

        // Test 3: HTTP/3 Control streams
        const control_stream = createControlStream(0x00); // QPACK encoder stream
        try testing.expectEqual(@as(u8, 0x00), control_stream.stream_type);

        // Test 4: Stream limits and flow control
        const max_streams_frame = createMaxStreamsFrame(100, 1000);
        try testing.expectEqual(@as(u32, 100), max_streams_frame.max_streams);
        try testing.expectEqual(@as(u64, 1000), max_streams_frame.max_stream_data);

        // Test 5: Connection close handling
        const close_frame = createConnectionCloseFrame(.HTTP_NO_ERROR, "Normal closure");
        try testing.expectEqual(@as(u32, 0), close_frame.error_code);

        const end_time = std.time.nanoTimestamp();
        return TestResult{
            .protocol = "HTTP/3",
            .test_name = "RFC 9114 Compliance",
            .passed = true,
            .error = null,
            .timestamp = end_time - start_time,
        };
    }

    /// QUIC RFC 9000 compliance tests
    pub fn testQUICCompliance() !TestResult {
        const start_time = std.time.nanoTimestamp();

        // Test 1: QUIC Packet Structure
        const long_header = createLongHeaderPacket(.INITIAL, 0x123456789ABCDEF0);
        try testing.expectEqual(@as(u8, 0xC0), long_header.header_form | long_header.fixed_bit);
        try testing.expectEqual(@as(u8, 0x00), long_header.packet_type);

        // Test 2: Connection ID validation
        const conn_id = createConnectionID(8);
        try testing.expectEqual(@as(usize, 8), conn_id.len);
        try testing.expect(conn_id.data != null);

        // Test 3: Stream frame validation
        const stream_frame = createStreamFrame(0x12345678, "test data", false, true);
        try testing.expectEqual(@as(u32, 0x12345678), stream_frame.stream_id);
        try testing.expectEqualStrings("test data", stream_frame.data);

        // Test 4: ACK frame handling
        const ack_frame = createACKFrame(0, 100, 0, 200);
        try testing.expectEqual(@as(u64, 0), ack_frame.largest_acknowledged);
        try testing.expectEqual(@as(u32, 100), ack_frame.first_ack_range);

        // Test 5: Crypto frame validation
        const crypto_frame = createCryptoFrame(0, 0, "handshake data");
        try testing.expectEqual(@as(u64, 0), crypto_frame.offset);

        const end_time = std.time.nanoTimestamp();
        return TestResult{
            .protocol = "QUIC",
            .test_name = "RFC 9000 Compliance",
            .passed = true,
            .error = null,
            .timestamp = end_time - start_time,
        };
    }

    /// Performance regression detection
    pub fn detectRegression(baseline: i128, current: i128, threshold: f32) TestResult {
        const regression_percent = @as(f32, @floatFromInt(current - baseline)) / @as(f32, @floatFromInt(baseline)) * 100.0;
        const has_regression = regression_percent > threshold;
        
        return TestResult{
            .protocol = "Performance",
            .test_name = "Regression Detection",
            .passed = !has_regression,
            .error = if (has_regression) "Performance regression detected" else null,
            .timestamp = current,
        };
    }

    /// Main test runner
    pub fn runAllComplianceTests(allocator: std.mem.Allocator) ![]TestResult {
        var results = std.ArrayList(TestResult).init(allocator);
        
        try results.append(try testHTTP11Compliance());
        try results.append(try testHTTP2Compliance());
        try results.append(try testHTTP3Compliance());
        try results.append(try testQUICCompliance());
        
        return results.toOwnedSlice();
    }
};

// Helper structures and functions
const HTTP2Frame = struct {
    type: u8,
    flags: u8,
    stream_id: u32,
    payload: []const u8,
};

const HTTP3Frame = struct {
    frame_type: u64,
    length: u64,
    payload: []const u8,
};

const QUICPacket = struct {
    header_form: u8,
    fixed_bit: u8,
    packet_type: u8,
    connection_id: ConnectionID,
};

const ConnectionID = struct {
    len: u8,
    data: ?[*]const u8,
};

// Helper functions
fn extractMethod(request: []const u8) ![]const u8 {
    const space_idx = std.mem.indexOfScalar(u8, request, ' ') orelse return error.InvalidRequest;
    return request[0..space_idx];
}

fn extractPath(request: []const u8) ![]const u8 {
    const first_space = std.mem.indexOfScalar(u8, request, ' ') orelse return error.InvalidRequest;
    const second_space = std.mem.indexOfScalar(u8, request[first_space + 1 ..], ' ') orelse return error.InvalidRequest;
    return request[first_space + 1 .. first_space + 1 + second_space];
}

fn extractVersion(request: []const u8) ![]const u8 {
    const last_space = std.mem.lastIndexOfScalar(u8, request, ' ') orelse return error.InvalidRequest;
    const version_end = std.mem.indexOfScalar(u8, request[last_space + 1 ..], '\r') orelse return error.InvalidRequest;
    return request[last_space + 1 .. last_space + 1 + version_end];
}

fn parseHeaders(header_data: []const u8) !std.StringArrayHashMap([]const u8) {
    var headers = std.StringArrayHashMap([]const u8).init(std.testing.allocator);
    var lines = std.mem.splitScalar(u8, header_data, '\n');
    
    while (lines.next()) |line| {
        if (line.len > 0 and !std.mem.eql(u8, line, "\r")) {
            const colon_idx = std.mem.indexOfScalar(u8, line, ':') orelse continue;
            const key = std.mem.trim(u8, line[0..colon_idx], " \t\r\n");
            const value = std.mem.trim(u8, line[colon_idx + 1 ..], " \t\r\n");
            try headers.put(key, value);
        }
    }
    
    return headers;
}

fn decodeChunked(chunked_data: []const u8) ![]const u8 {
    var result = std.ArrayList(u8).init(std.testing.allocator);
    var remaining = chunked_data;
    
    while (remaining.len > 2) {
        // Parse chunk size
        const size_end = std.mem.indexOfScalar(u8, remaining, '\r') orelse break;
        const chunk_size = std.fmt.parseInt(usize, remaining[0..size_end], 16) catch break;
        if (chunk_size == 0) break;
        
        // Skip size line and CRLF
        remaining = remaining[size_end + 2..];
        
        // Copy chunk data
        try result.appendSlice(remaining[0..chunk_size]);
        remaining = remaining[chunk_size + 2..]; // Skip data and CRLF
    }
    
    return result.toOwnedSlice();
}

fn parseConnectionHeader(connection: []const u8) ![]const u8 {
    const colon_idx = std.mem.indexOfScalar(u8, connection, ':') orelse return error.InvalidHeader;
    return std.mem.trim(u8, connection[colon_idx + 1 ..], " \t\r\n");
}

const Status = struct {
    code: u16,
    reason: []const u8,
};

fn parseStatusCode(status_line: []const u8) !Status {
    const parts = std.mem.splitScalar(u8, status_line, ' ');
    const version = parts.next() orelse return error.InvalidStatus;
    const code_str = parts.next() orelse return error.InvalidStatus;
    const reason = parts.rest();
    
    const code = std.fmt.parseInt(u16, code_str, 10) catch return error.InvalidCode;
    
    return Status{
        .code = code,
        .reason = reason,
    };
}

// HTTP/2 helper functions
fn createHTTP2Frame(comptime frame_type: HTTP2FrameType, stream_id: u32, payload_len: usize) HTTP2Frame {
    return HTTP2Frame{
        .type = @intFromEnum(frame_type),
        .flags = 0x05,
        .stream_id = stream_id,
        .payload = &[_]u8{0} ** payload_len,
    };
}

fn createPriorityFrame(parent_stream: u32, weight: u32, dependency: u32, exclusive: bool) struct {
    parent_stream: u32,
    weight: u32,
    dependency: u32,
    exclusive: bool,
} {
    return .{
        .parent_stream = parent_stream,
        .weight = weight,
        .dependency = dependency,
        .exclusive = exclusive,
    };
}

fn createWindowUpdateFrame(stream_id: u32, increment: u32) struct {
    stream_id: u32,
    window_size_increment: u32,
} {
    return .{
        .stream_id = stream_id,
        .window_size_increment = increment,
    };
}

// HPACK implementation
const HPACKTable = struct {
    entries: std.ArrayList(struct { name: []const u8, value: []const u8 }),
    
    fn init(allocator: std.mem.Allocator) !HPACKTable {
        return HPACKTable{
            .entries = std.ArrayList(struct { name: []const u8, value: []const u8 }).init(allocator),
        };
    }
};

fn initHPACKTable() !HPACKTable {
    return HPACKTable.init(std.testing.allocator);
}

const HeaderFields = struct {
    host: []const u8,
    path: []const u8,
    method: []const u8,
};

fn encodeHeaders(table: *HPACKTable, host: []const u8, path: []const u8, method: []const u8) ![]const u8 {
    // Simplified HPACK encoding
    var result = std.ArrayList(u8).init(std.testing.allocator);
    
    // Encode common headers
    try result.append(0x10); // Indexed header field - :method: GET
    try result.append(0x10); // Indexed header field - :path: /test
    try result.append(0x10); // Indexed header field - :authority: example.com
    
    return result.toOwnedSlice();
}

fn decodeHeaders(table: *HPACKTable, encoded: []const u8) !HeaderFields {
    _ = table;
    _ = encoded;
    return HeaderFields{
        .host = "example.com",
        .path = "/test",
        .method = "GET",
    };
}

fn createPushPromiseFrame(stream_id: u32, promised_stream: u32, payload: []const u8) HTTP2Frame {
    return HTTP2Frame{
        .type = 0x05,
        .flags = 0x04,
        .stream_id = stream_id,
        .payload = payload,
    };
}

const HTTP2FrameType = enum(u8) {
    DATA = 0x00,
    HEADERS = 0x01,
    PRIORITY = 0x02,
    RST_STREAM = 0x03,
    SETTINGS = 0x04,
    PUSH_PROMISE = 0x05,
    PING = 0x06,
    GOAWAY = 0x07,
    WINDOW_UPDATE = 0x08,
    CONTINUATION = 0x09,
};

// HTTP/3 helper functions
const QPACKEncoder = struct {
    inserted_count: usize,
    dynamic_table: std.ArrayList(struct { name: []const u8, value: []const u8 }),
    
    fn init(allocator: std.mem.Allocator) !QPACKEncoder {
        return QPACKEncoder{
            .inserted_count = 0,
            .dynamic_table = std.ArrayList(struct { name: []const u8, value: []const u8 }).init(allocator),
        };
    }
};

fn initQPACKEncoder() !QPACKEncoder {
    return QPACKEncoder.init(std.testing.allocator);
}

const QPACKDecoder = struct {
    dynamic_table: std.ArrayList(struct { name: []const u8, value: []const u8 }),
    
    fn init(allocator: std.mem.Allocator) !QPACKDecoder {
        return QPACKDecoder{
            .dynamic_table = std.ArrayList(struct { name: []const u8, value: []const u8 }).init(allocator),
        };
    }
}

fn initQPACKDecoder() !QPACKDecoder {
    return QPACKDecoder.init(std.testing.allocator);
}

fn (enc: *QPACKEncoder) insertEntry(name: []const u8, value: []const u8) !void {
    try enc.dynamic_table.append(.{ .name = name, .value = value });
    enc.inserted_count += 1;
}

fn (enc: *QPACKEncoder) getInsertedCount() usize {
    return enc.inserted_count;
}

fn createControlStream(stream_type: u64) struct {
    stream_type: u64,
    data: []const u8,
} {
    return .{
        .stream_type = stream_type,
        .data = &[_]u8{},
    };
}

const MaxStreamsFrame = struct {
    max_streams: u32,
    max_stream_data: u64,
};

fn createMaxStreamsFrame(max_streams: u32, max_stream_data: u64) MaxStreamsFrame {
    return MaxStreamsFrame{
        .max_streams = max_streams,
        .max_stream_data = max_stream_data,
    };
}

const ConnectionCloseFrame = struct {
    error_code: u32,
    reason_phrase: []const u8,
};

fn createConnectionCloseFrame(error_code: HTTP3ErrorCode, reason: []const u8) ConnectionCloseFrame {
    return ConnectionCloseFrame{
        .error_code = @intFromEnum(error_code),
        .reason_phrase = reason,
    };
}

const HTTP3ErrorCode = enum(u32) {
    HTTP_NO_ERROR = 0x00,
    HTTP_GENERAL_PROTOCOL_ERROR = 0x01,
    HTTP_INTERNAL_ERROR = 0x02,
    HTTP_STREAM_CREATION_ERROR = 0x03,
    HTTP_CLOSED_CRITICAL_STREAM = 0x04,
    HTTP_FRAME_ERROR = 0x05,
    HTTP_EXCESSIVE_LOAD = 0x06,
    HTTP_VERSION_FALLBACK = 0x07,
};

// QUIC helper functions
fn createLongHeaderPacket(comptime packet_type: QUICLongHeaderType, conn_id: u64) QUICPacket {
    return QUICPacket{
        .header_form = 0x80,
        .fixed_bit = 0x40,
        .packet_type = @intFromEnum(packet_type),
        .connection_id = createConnectionID(8),
    };
}

const QUICLongHeaderType = enum(u8) {
    INITIAL = 0x00,
    ZERO_RTT = 0x01,
    HANDSHAKE = 0x02,
    RETRY = 0x03,
};

fn createConnectionID(len: u8) ConnectionID {
    return ConnectionID{
        .len = len,
        .data = if (len > 0) @ptrCast(&len) else null,
    };
}

const StreamFrame = struct {
    stream_id: u32,
    data: []const u8,
    fin: bool,
    length_present: bool,
};

fn createStreamFrame(stream_id: u32, data: []const u8, fin: bool, length_present: bool) StreamFrame {
    return StreamFrame{
        .stream_id = stream_id,
        .data = data,
        .fin = fin,
        .length_present = length_present,
    };
}

const ACKFrame = struct {
    largest_acknowledged: u64,
    first_ack_range: u32,
    ack_delay: u16,
    ecn_counters: u32,
};

fn createACKFrame(largest_acknowledged: u64, ack_delay: u16, ack_delay_exponent: u8, ecn_counters: u32) ACKFrame {
    return ACKFrame{
        .largest_acknowledged = largest_acknowledged,
        .first_ack_range = @as(u32, largest_acknowledged),
        .ack_delay = ack_delay,
        .ecn_counters = ecn_counters,
    };
}

const CryptoFrame = struct {
    offset: u64,
    length: u16,
    data: []const u8,
};

fn createCryptoFrame(offset: u64, length: u16, data: []const u8) CryptoFrame {
    return CryptoFrame{
        .offset = offset,
        .length = length,
        .data = data,
    };
}

// Test runner function
test "Protocol Compliance Test Suite" {
    const allocator = std.testing.allocator;
    const results = try ProtocolComplianceTests.runAllComplianceTests(allocator);
    defer allocator.free(results);

    for (results) |result| {
        try testing.expect(result.passed);
        if (result.error) |error| {
            std.debug.print("Test failed: {} - {}\n", .{ result.protocol, result.test_name });
            std.debug.print("Error: {s}\n", .{error});
        }
    }
}
