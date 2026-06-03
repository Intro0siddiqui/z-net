//! z_dns - DNS Resolution Layer
//! Support for DoH (DNS over HTTPS), DoT (DNS over TLS), and raw UDP DNS

const std = @import("std");
const json = std.json;
const http = @import("z_http");
const socket = @import("z_socket");
const tls = @import("tls");

pub const DnsError = error{
    NoResponse,
    ParseError,
    Timeout,
    NetworkError,
    InvalidQuery,
    UnsupportedRecord,
};

pub const DnsRecordType = enum(u16) {
    A = 1,
    AAAA = 28,
    CNAME = 5,
    MX = 15,
    NS = 2,
    TXT = 16,
    SRV = 33,
    CAA = 257,
};

pub const DnsQuery = struct {
    name: []const u8,
    record_type: DnsRecordType,
    class: u16 = 1, // IN (Internet)
};

pub const DnsAnswer = struct {
    name: []const u8,
    record_type: DnsRecordType,
    ttl: u32,
    data: []const u8,
};

pub const DnsResponse = struct {
    id: u16,
    flags: u16,
    questions: usize,
    answers: usize,
    authority: usize,
    additional: usize,
    queries: []DnsQuery,
    answers_list: []DnsAnswer,
};

pub const DnsResolver = struct {
    allocator: std.mem.Allocator,
    io_ctx: *std.Io,
    cache: *DnsCache,
    timeout: u32 = 5000, // 5 seconds
    prefer_doh: bool = true,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, io_ctx: *std.Io, cache: *DnsCache) Self {
        return Self{
            .allocator = allocator,
            .io_ctx = io_ctx,
            .cache = cache,
        };
    }

    pub fn resolve(self: *Self, query: DnsQuery) DnsError![]DnsAnswer {
        // Check cache first
        if (self.cache.get(query.name, query.record_type)) |cached| {
            return cached;
        }

        // Try DoH first if preferred
        var answers: []DnsAnswer = undefined;
        
        if (self.prefer_doh) {
            answers = self.resolveDoh(query) catch {
                // Fall back to DoT
                answers = self.resolveDot(query) catch {
                    // Fall back to UDP
                    answers = self.resolveUdp(query) catch {
                        return error.NoResponse;
                    };
                };
            };
        } else {
            // Try UDP first
            answers = self.resolveUdp(query) catch {
                // Fall back to DoH
                answers = self.resolveDoh(query) catch {
                    // Fall back to DoT
                    answers = self.resolveDot(query) catch {
                        return error.NoResponse;
                    };
                };
            };
        }

        // Cache the results
        self.cache.put(query.name, query.record_type, answers);

        return answers;
    }

    fn resolveDoh(self: *Self, query: DnsQuery) DnsError![]DnsAnswer {
        // DNS over HTTPS implementation
        const doh_server = "https://dns.cloudflare.com/dns-query";
        const dns_query = try encodeDnsQuery(query);
        
        // Create HTTP request
        var http_req = http.HttpRequest.init(self.allocator);
        defer http_req.deinit();

        const headers = try std.fmt.allocPrint(self.allocator, 
            "Accept: application/dns-json\r\n", 
            .{});
        defer self.allocator.free(headers);

        const response = try http_req.get(doh_server, &.{
            .headers = headers,
            .timeout = self.timeout,
        });

        const json_response = try json.parseFromSlice(std.json.Value, self.allocator, response.body, .{});
        defer json_response.deinit();

        return try parseDoHResponse(json_response.value, query, self.allocator);
    }

    fn resolveDot(self: *Self, query: DnsQuery) DnsError![]DnsAnswer {
        // DNS over TLS implementation
        const dot_servers = &[_][]const u8{
            "1.1.1.1:853", // Cloudflare
            "8.8.8.8:853", // Google
            "9.9.9.9:853", // Quad9
        };

        for (dot_servers) |server| {
            const colon_idx = std.mem.indexOf(u8, server, ":").?;
            const host = server[0..colon_idx];
            const port = std.fmt.parseInt(u16, server[colon_idx + 1..], 10) catch continue;

            // Create TLS socket
            var socket_conn = socket.Socket.create(self.io_ctx, .inet, .stream) catch continue;
            defer socket_conn.close(self.io_ctx);

            const addr = std.net.Address.parseIp4(host, port) catch continue;
            socket_conn.connect(self.io_ctx, addr) catch continue;

            // Wrap in TLS
            var tls_conn = tls.TlsConnection.init(self.allocator, host) catch continue;
            defer tls_conn.deinit();
            
            tls_conn.connect(socket_conn) catch continue;

            // Send DNS query over TLS
            const dns_query = try encodeDnsQuery(query);
            const sent = tls_conn.send(dns_query) catch continue;

            if (sent == dns_query.len) {
                // Receive response
                var response_buffer: [4096]u8 = undefined;
                const received = tls_conn.recv(&response_buffer) catch continue;

                if (received > 0) {
                    return try parseDnsResponse(response_buffer[0..received], query, self.allocator);
                }
            }
        }

        return error.NoResponse;
    }

    fn resolveUdp(self: *Self, query: DnsQuery) DnsError![]DnsAnswer {
        // Raw UDP DNS implementation
        const dns_servers = &[_][]const u8{
            "1.1.1.1:53",   // Cloudflare
            "8.8.8.8:53",   // Google
            "9.9.9.9:53",   // Quad9
        };

        for (dns_servers) |server| {
            const colon_idx = std.mem.indexOf(u8, server, ":").?;
            const host = server[0..colon_idx];
            const port = std.fmt.parseInt(u16, server[colon_idx + 1..], 10) catch continue;

            // Create UDP socket
            var socket_conn = socket.Socket.create(self.io_ctx, .inet, .dgram) catch continue;
            defer socket_conn.close(self.io_ctx);

            const addr = std.net.Address.parseIp4(host, port) catch continue;

            // Send DNS query
            const dns_query = try encodeDnsQuery(query);
            const sent = socket_conn.send(self.io_ctx, dns_query) catch continue;

            if (sent == dns_query.len) {
                // Receive response
                var response_buffer: [4096]u8 = undefined;
                const received = socket_conn.recv(self.io_ctx, &response_buffer) catch continue;

                if (received > 0) {
                    return try parseDnsResponse(response_buffer[0..received], query, self.allocator);
                }
            }
        }

        return error.NoResponse;
    }
};

pub const DnsCache = struct {
    allocator: std.mem.Allocator,
    entries: std.StringArrayHashMap(CacheEntry),

    const CacheEntry = struct {
        answers: []DnsAnswer,
        expires_at: i64,
    },

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .allocator = allocator,
            .entries = std.StringArrayHashMap(CacheEntry).init(allocator),
        };
    }

    pub fn get(self: *Self, name: []const u8, record_type: DnsRecordType) ?[]DnsAnswer {
        const key = try std.fmt.allocPrint(self.allocator, "{s}:{d}", .{ name, @intFromEnum(record_type) });
        defer self.allocator.free(key);

        if (self.entries.get(key)) |entry| {
            if (std.time.timestamp() < entry.expires_at) {
                return entry.answers;
            }
        }

        return null;
    }

    pub fn put(self: *Self, name: []const u8, record_type: DnsRecordType, answers: []DnsAnswer) !void {
        const key = try std.fmt.allocPrint(self.allocator, "{s}:{d}", .{ name, @intFromEnum(record_type) });
        defer self.allocator.free(key);

        // Calculate expiry time
        const now = std.time.timestamp();
        var max_ttl: u32 = 300; // Default 5 minutes
        for (answers) |answer| {
            max_ttl = @max(max_ttl, answer.ttl);
        }

        const expires_at = now + max_ttl;

        // Store in cache
        try self.entries.put(key, CacheEntry{
            .answers = answers,
            .expires_at = expires_at,
        });
    }

    pub fn cleanup(self: *Self) void {
        const now = std.time.timestamp();
        var keys_to_remove = std.ArrayList([]u8).init(self.allocator);
        defer keys_to_remove.deinit();

        for (self.entries.keys(), self.entries.values()) |key, entry| {
            if (now >= entry.expires_at) {
                keys_to_remove.append(key) catch continue;
            }
        }

        for (keys_to_remove.items) |key| {
            self.entries.remove(key);
        }
    }

    pub fn deinit(self: *Self) void {
        for (self.entries.values()) |entry| {
            self.allocator.free(entry.answers);
        }
        self.entries.deinit();
    }
};

// DNS message encoding/decoding
fn encodeDnsQuery(query: DnsQuery) ![]u8 {
    var buffer = std.ArrayList(u8).init(std.heap.page_allocator);
    defer buffer.deinit();

    // DNS header
    const id = @as(u16, @bitCast(u16, std.crypto.random.int(u16)));
    const flags = 0x0100; // Standard query, recursion desired

    buffer.appendSlice(&std.mem.toBytes(id));
    buffer.appendSlice(&std.mem.toBytes(flags));
    buffer.appendSlice(&std.mem.toBytes(@as(u16, 1))); // Questions: 1
    buffer.appendSlice(&std.mem.toBytes(@as(u16, 0))); // Answers: 0
    buffer.appendSlice(&std.mem.toBytes(@as(u16, 0))); // Authority: 0
    buffer.appendSlice(&std.mem.toBytes(@as(u16, 0))); // Additional: 0

    // Question section
    const labels = std.mem.split(u8, query.name, ".");
    while (labels.next()) |label| {
        buffer.append(@intCast(u8, label.len));
        buffer.appendSlice(label);
    }
    buffer.append(0); // End of name

    buffer.appendSlice(&std.mem.toBytes(@intFromEnum(query.record_type)));
    buffer.appendSlice(&std.mem.toBytes(query.class));

    return buffer.toOwnedSlice();
}

fn parseDnsResponse(data: []const u8, query: DnsQuery, allocator: std.mem.Allocator) DnsError![]DnsAnswer {
    if (data.len < 12) return error.ParseError;

    var offset: usize = 0;

    // Parse header
    const id = std.mem.readInt(u16, data[offset..offset + 2], .big);
    offset += 2;

    const flags = std.mem.readInt(u16, data[offset..offset + 2], .big);
    offset += 2;

    const questions = std.mem.readInt(u16, data[offset..offset + 2], .big);
    offset += 2;

    const answers = std.mem.readInt(u16, data[offset..offset + 2], .big);
    offset += 2;

    // Skip to answers section
    offset += 4; // Authority + Additional

    // Skip question section
    for (0..questions) |_| {
        while (data[offset] != 0) {
            if (data[offset] & 0xC0 != 0) {
                offset += 2;
                break;
            }
            offset += data[offset] + 1;
        }
        offset += 5; // Type + Class + TTL + Length
    }

    // Parse answers
    var answer_list = std.ArrayList(DnsAnswer).init(allocator);
    for (0..answers) |_| {
        const name = try parseDomainName(data, &offset, allocator);
        const answer_type = std.mem.readInt(u16, data[offset..offset + 2], .big);
        offset += 2;

        const answer_class = std.mem.readInt(u16, data[offset..offset + 2], .big);
        offset += 2;

        const ttl = std.mem.readInt(u32, data[offset..offset + 4], .big);
        offset += 4;

        const data_length = std.mem.readInt(u16, data[offset..offset + 2], .big);
        offset += 2;

        const answer_data = data[offset..offset + data_length];
        offset += data_length;

        try answer_list.append(DnsAnswer{
            .name = name,
            .record_type = @enumFromInt(answer_type),
            .ttl = ttl,
            .data = answer_data,
        });
    }

    return answer_list.toOwnedSlice();
}

fn parseDoHResponse(json_response: std.json.Value, query: DnsQuery, allocator: std.mem.Allocator) DnsError![]DnsAnswer {
    var answer_list = std.ArrayList(DnsAnswer).init(allocator);

    if (json_response.Object.get("Answer")) |answers_array| {
        if (answers_array.Array) |answers| {
            for (answers.items) |answer| {
                if (answer.Object) |answer_obj| {
                    const name = try allocator.dupe(u8, answer_obj.get("name").?.String);
                    const record_type = @enumFromInt(std.fmt.parseInt(u16, answer_obj.get("type").?.String, 10) catch 1);
                    const ttl = std.fmt.parseInt(u32, answer_obj.get("TTL").?.String, 10) catch 300;
                    const data = try allocator.dupe(u8, answer_obj.get("data").?.String);

                    try answer_list.append(DnsAnswer{
                        .name = name,
                        .record_type = record_type,
                        .ttl = ttl,
                        .data = data,
                    });
                }
            }
        }
    }

    return answer_list.toOwnedSlice();
}

fn parseDomainName(data: []const u8, offset: *usize, allocator: std.mem.Allocator) ![]const u8 {
    var labels = std.ArrayList(u8).init(allocator);
    errdefer labels.deinit();

    var current_offset = offset.*;
    var jumped = false;
    var return_offset = offset.*;
    var jumps_left: u8 = 16;

    while (current_offset < data.len) {
        const len_byte = data[current_offset];
        if (len_byte == 0) {
            current_offset += 1;
            break;
        }
        if ((len_byte & 0xC0) == 0xC0) {
            if (current_offset + 1 >= data.len) return error.MalformedDnsMessage;
            if (jumps_left == 0) return error.MalformedDnsMessage;
            jumps_left -= 1;
            const ptr: usize = (@as(usize, len_byte & 0x3F) << 8) | @as(usize, data[current_offset + 1]);
            if (ptr >= current_offset) return error.MalformedDnsMessage;
            if (!jumped) {
                return_offset = current_offset + 2;
                jumped = true;
            }
            current_offset = ptr;
            continue;
        }
        if ((len_byte & 0xC0) != 0) return error.MalformedDnsMessage;

        const label_length: usize = len_byte;
        current_offset += 1;
        if (current_offset + label_length > data.len) return error.MalformedDnsMessage;

        if (labels.items.len > 0) try labels.append('.');
        try labels.appendSlice(data[current_offset..current_offset + label_length]);
        current_offset += label_length;
    }

    offset.* = if (jumped) return_offset else current_offset;
    return labels.toOwnedSlice();
}