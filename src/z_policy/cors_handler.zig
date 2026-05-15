//! z_policy - CORS Handler
//! 
//! Cross-Origin Resource Sharing (CORS) request/response handler
//! that integrates with the Policy Engine for browser compatibility.

const std = @import("std");
const Allocator = std.mem.Allocator;
const StringHashMap = std.StringHashMap;
const ArrayList = std.ArrayList;
const policy_engine = @import("policy_engine");

usingnamespace policy_engine;

pub const CORSMethod = enum {
    GET,
    POST,
    PUT,
    DELETE,
    PATCH,
    OPTIONS,
    HEAD,
    CONNECT,
    TRACE,
    
    pub fn fromString(method: []const u8) CORSMethod {
        const upper_method = std.ascii.upperString(method);
        inline for (@typeInfo(CORSMethod).Enum.fields) |field| {
            if (std.mem.eql(u8, upper_method, field.name)) {
                return @field(CORSMethod, field.name);
            }
        }
        return .GET;
    }
};

pub const CORSHeader = struct {
    name: []const u8,
    value: []const u8,
    
    pub fn init(name: []const u8, value: []const u8) CORSHeader {
        return CORSHeader{
            .name = name,
            .value = value,
        };
    }
};

pub const CORSOptions = struct {
    methods: ArrayList(CORSMethod),
    headers: ArrayList([]const u8),
    credentials: bool,
    max_age: i32,
    origin: []const u8,
    expose_headers: ArrayList([]const u8),
    
    pub fn init(allocator: Allocator) CORSOptions {
        return CORSOptions{
            .methods = ArrayList(CORSMethod).init(allocator),
            .headers = ArrayList([]const u8).init(allocator),
            .credentials = false,
            .max_age = 86400, // 24 hours
            .origin = "",
            .expose_headers = ArrayList([]const u8).init(allocator),
        };
    }
    
    pub fn deinit(self: *CORSOptions) void {
        self.methods.deinit();
        self.headers.deinit();
        self.expose_headers.deinit();
    }
    
    pub fn addMethod(inout self: CORSOptions, method: CORSMethod) void {
        self.methods.append(method) catch {};
    }
    
    pub fn addHeader(inout self: CORSOptions, header: []const u8) void {
        self.headers.append(header) catch {};
    }
    
    pub fn addExposeHeader(inout self: CORSOptions, header: []const u8) void {
        self.expose_headers.append(header) catch {};
    }
};

pub const CORSPreflightRequest = struct {
    origin: []const u8,
    method: CORSMethod,
    headers: ArrayList([]const u8),
    
    pub fn init(allocator: Allocator) CORSPreflightRequest {
        return CORSPreflightRequest{
            .origin = "",
            .method = .GET,
            .headers = ArrayList([]const u8).init(allocator),
        };
    }
    
    pub fn deinit(self: *CORSPreflightRequest) void {
        self.headers.deinit();
    }
};

pub const CORSPreflightResponse = struct {
    allow_origin: []const u8,
    allow_methods: ArrayList(CORSMethod),
    allow_headers: ArrayList([]const u8),
    allow_credentials: bool,
    max_age: i32,
    vary: ?[]const u8,
    
    pub fn init(allocator: Allocator) CORSPreflightResponse {
        return CORSPreflightResponse{
            .allow_origin = "",
            .allow_methods = ArrayList(CORSMethod).init(allocator),
            .allow_headers = ArrayList([]const u8).init(allocator),
            .allow_credentials = false,
            .max_age = 86400,
            .vary = null,
        };
    }
    
    pub fn deinit(self: *CORSPreflightResponse) void {
        self.allow_methods.deinit();
        self.allow_headers.deinit();
    }
};

pub const CORSError = error{
    PreflightFailed,
    InvalidMethod,
    InvalidHeader,
    OriginMismatch,
    MethodNotAllowed,
    HeaderNotAllowed,
};

/// CORS Handler - Core Implementation
pub const CORSHangler = struct {
    allocator: Allocator,
    preflight_cache: AutoHashMap(PreflightCacheKey, CORSPreflightResponse),
    allowed_origins: AutoHashMap([]const u8, bool),
    allowed_methods: AutoHashMap([]const u8, bool),
    allowed_headers: AutoHashMap([]const u8, bool),
    
    const PreflightCacheKey = struct {
        origin: []const u8,
        method: []const u8,
        headers_hash: u64,
        
        pub fn hash(self: PreflightCacheKey) u64 {
            var hasher = std.hash.Wyhash.init(0);
            hasher.update(self.origin);
            hasher.update(self.method);
            hasher.update(&std.mem.toBytes(self.headers_hash));
            return hasher.final();
        }
        
        pub fn eql(self: PreflightCacheKey, other: PreflightCacheKey) bool {
            return std.mem.eql(u8, self.origin, other.origin) and
                   std.mem.eql(u8, self.method, other.method) and
                   self.headers_hash == other.headers_hash;
        }
    };
    
    pub fn init(allocator: Allocator) CORSHangler {
        return CORSHangler{
            .allocator = allocator,
            .preflight_cache = AutoHashMap(PreflightCacheKey, CORSPreflightResponse).init(allocator),
            .allowed_origins = AutoHashMap([]const u8, bool).init(allocator),
            .allowed_methods = AutoHashMap([]const u8, bool).init(allocator),
            .allowed_headers = AutoHashMap([]const u8, bool).init(allocator),
        };
    }
    
    pub fn deinit(self: *CORSHangler) void {
        var cache_iter = self.preflight_cache.valueIterator();
        while (cache_iter.next()) |response| {
            response.deinit();
        }
        self.preflight_cache.deinit();
        self.allowed_origins.deinit();
        self.allowed_methods.deinit();
        self.allowed_headers.deinit();
    }
    
    /// Handle CORS preflight request (OPTIONS)
    pub fn handlePreflight(self: *CORSHangler, request: CORSPreflightRequest) !CORSPreflightResponse {
        const origin = request.origin;
        const method = @tagName(request.method);
        
        // Check if origin is allowed
        if (!self.allowed_origins.get(origin) orelse false) {
            return CORSError.OriginMismatch;
        }
        
        // Check if method is allowed
        if (!self.allowed_methods.get(method) orelse false) {
            return CORSError.MethodNotAllowed;
        }
        
        // Check if headers are allowed
        for (request.headers.items) |header| {
            if (!self.allowed_headers.get(header) orelse false) {
                return CORSError.HeaderNotAllowed;
            }
        }
        
        // Check cache
        const cache_key = self.createCacheKey(origin, method, request.headers);
        if (self.preflight_cache.get(cache_key)) |cached_response| {
            return cached_response;
        }
        
        // Create response
        var response = CORSPreflightResponse.init(self.allocator);
        response.allow_origin = origin;
        
        // Copy allowed methods
        var allowed_methods_iter = self.allowed_methods.keyIterator();
        while (allowed_methods_iter.next()) |allowed_method| {
            const method_enum = CORSMethod.fromString(allowed_method.*);
            response.allow_methods.append(method_enum) catch {};
        }
        
        // Copy allowed headers
        var allowed_headers_iter = self.allowed_headers.keyIterator();
        while (allowed_headers_iter.next()) |allowed_header| {
            response.allow_headers.append(allowed_header.*) catch {};
        }
        
        response.allow_credentials = true; // Configurable
        response.max_age = 86400; // 24 hours
        response.vary = "Origin";
        
        // Cache response
        self.preflight_cache.put(cache_key, response) catch {};
        
        return response;
    }
    
    /// Handle CORS actual request
    pub fn handleActualRequest(self: *CORSHangler, origin: []const u8, request_headers: StringHashMap([]const u8)) !ValidationResult {
        var result = ValidationResult.init(self.allocator);
        
        // Check origin
        if (!self.allowed_origins.get(origin) orelse false) {
            result.allowed = false;
            result.reason = "Origin not allowed by CORS";
            return result;
        }
        
        // Check for credentials
        const credentials_header = request_headers.get("Access-Control-Request-Credentials");
        if (credentials_header) |creds| {
            if (std.mem.eql(u8, std.ascii.lowerString(creds), "true")) {
                result.headers.put("Access-Control-Allow-Credentials", "true") catch {};
                result.headers.put("Access-Control-Allow-Origin", origin) catch {};
            }
        } else {
            result.headers.put("Access-Control-Allow-Origin", origin) catch {};
        }
        
        // Add expose headers
        var expose_iter = self.allowed_headers.keyIterator();
        while (expose_iter.next()) |expose_header| {
            // Only expose non-sensitive headers
            if (!isSensitiveHeader(expose_header.*)) {
                result.headers.put("Access-Control-Expose-Headers", expose_header.*) catch {};
            }
        }
        
        result.allowed = true;
        result.reason = "CORS actual request allowed";
        
        return result;
    }
    
    /// Check if request is a CORS preflight
    pub fn isPreflightRequest(self: *CORSHangler, method: []const u8, headers: StringHashMap([]const u8)) bool {
        if (!std.mem.eql(u8, std.ascii.upperString(method), "OPTIONS")) {
            return false;
        }
        
        return headers.contains("Origin") and 
               (headers.contains("Access-Control-Request-Method") or
                headers.contains("Access-Control-Request-Headers"));
    }
    
    /// Extract preflight request from HTTP request
    pub fn extractPreflightRequest(self: *CORSHangler, method: []const u8, headers: StringHashMap([]const u8)) !CORSPreflightRequest {
        const origin = headers.get("Origin") orelse return CORSError.PreflightFailed;
        const request_method = headers.get("Access-Control-Request-Method") orelse return CORSError.PreflightFailed;
        const request_headers = headers.get("Access-Control-Request-Headers");
        
        var preflight = CORSPreflightRequest.init(self.allocator);
        preflight.origin = origin;
        preflight.method = CORSMethod.fromString(request_method);
        
        if (request_headers) |headers_str| {
            // Parse comma-separated headers
            var header_iter = std.mem.split(u8, headers_str, ",");
            while (header_iter.next()) |header| {
                const trimmed_header = std.mem.trim(u8, header, " \t\r\n");
                preflight.headers.append(trimmed_header) catch {};
            }
        }
        
        return preflight;
    }
    
    /// Generate CORS response headers
    pub fn generateCORSHeaders(self: *CORSHangler, origin: []const u8, allow_credentials: bool) StringHashMap([]const u8) {
        var headers = StringHashMap([]const u8).init(self.allocator);
        
        headers.put("Access-Control-Allow-Origin", origin) catch {};
        
        if (allow_credentials) {
            headers.put("Access-Control-Allow-Credentials", "true") catch {};
        }
        
        // Add allowed methods
        var methods_list = ArrayList([]const u8).init(self.allocator);
        var methods_iter = self.allowed_methods.keyIterator();
        while (methods_iter.next()) |method| {
            methods_list.append(method.*) catch {};
        }
        
        const methods_str = std.mem.join(self.allocator, ", ", methods_list.items) catch "";
        headers.put("Access-Control-Allow-Methods", methods_str) catch {};
        methods_list.deinit();
        
        // Add allowed headers
        var headers_list = ArrayList([]const u8).init(self.allocator);
        var headers_iter = self.allowed_headers.keyIterator();
        while (headers_iter.next()) |header| {
            headers_list.append(header.*) catch {};
        }
        
        const headers_str = std.mem.join(self.allocator, ", ", headers_list.items) catch "";
        headers.put("Access-Control-Allow-Headers", headers_str) catch {};
        headers_list.deinit();
        
        headers.put("Access-Control-Max-Age", "86400") catch {}; // 24 hours
        
        return headers;
    }
    
    /// Configure CORS options
    pub fn configure(self: *CORSHangler, options: CORSOptions) !void {
        // Clear existing configuration
        self.allowed_origins.clear();
        self.allowed_methods.clear();
        self.allowed_headers.clear();
        
        // Set origin
        if (options.origin.len > 0) {
            try self.allowed_origins.put(options.origin, true);
        }
        
        // Set methods
        for (options.methods.items) |method| {
            const method_str = @tagName(method);
            try self.allowed_methods.put(method_str, true);
        }
        
        // Set headers
        for (options.headers.items) |header| {
            try self.allowed_headers.put(header, true);
        }
        
        // Add default headers
        self.addDefaultHeaders();
    }
    
    /// Add default allowed headers
    fn addDefaultHeaders(self: *CORSHangler) void {
        const default_headers = &[_][]const u8{
            "Accept",
            "Accept-Language", 
            "Content-Language",
            "Content-Type",
            "Range",
        };
        
        for (default_headers) |header| {
            self.allowed_headers.put(header, true) catch {};
        }
    }
    
    /// Create cache key for preflight response
    fn createCacheKey(self: *CORSHangler, origin: []const u8, method: []const u8, headers: ArrayList([]const u8)) PreflightCacheKey {
        var hasher = std.hash.Wyhash.init(0);
        
        // Hash origin
        hasher.update(origin);
        
        // Hash method
        hasher.update(method);
        
        // Hash headers
        var combined_headers = ArrayList(u8).init(self.allocator);
        defer combined_headers.deinit();
        
        for (headers.items, 0..) |header, i| {
            if (i > 0) combined_headers.append(',') catch {};
            combined_headers.appendSlice(header) catch {};
        }
        
        const headers_hash = std.hash.Wyhash.hash(0, combined_headers.items);
        
        return PreflightCacheKey{
            .origin = origin,
            .method = method,
            .headers_hash = headers_hash,
        };
    }
    
    /// Check if header is sensitive (should not be exposed)
    fn isSensitiveHeader(header: []const u8) bool {
        const sensitive_headers = &[_][]const u8{
            "Authorization",
            "Cookie",
            "Set-Cookie",
            "X-Requested-With",
            "Host",
            "Origin",
            "Referer",
        };
        
        for (sensitive_headers) |sensitive| {
            if (std.mem.eql(u8, std.ascii.lowerString(header), std.ascii.lowerString(sensitive))) {
                return true;
            }
        }
        
        return false;
    }
    
    /// Clear preflight cache
    pub fn clearCache(self: *CORSHangler) void {
        self.preflight_cache.clear();
    }
    
    /// Get cache statistics
    pub fn getCacheStats(self: *CORSHangler) struct { cached_responses: usize, cache_size: usize } {
        return .{
            .cached_responses = self.preflight_cache.count(),
            .cache_size = self.preflight_cache.estimated_capacity,
        };
    }
};

test "cors method parsing" {
    try std.testing.expectEqual(CORSMethod.GET, CORSMethod.fromString("get"));
    try std.testing.expectEqual(CORSMethod.POST, CORSMethod.fromString("POST"));
    try std.testing.expectEqual(CORSMethod.DELETE, CORSMethod.fromString("delete"));
}

test "cors handler init" {
    const allocator = std.testing.allocator;
    var handler = CORSHangler.init(allocator);
    defer handler.deinit();
    
    // Test basic initialization
    const origin = "https://example.com";
    const options = CORSOptions.init(allocator);
    defer options.deinit();
    
    options.origin = origin;
    options.addMethod(.GET);
    options.addMethod(.POST);
    options.addHeader("Content-Type");
    
    try handler.configure(options);
    
    try std.testing.expect(handler.allowed_origins.get(origin) != null);
    try std.testing.expect(handler.allowed_methods.get("GET") != null);
    try std.testing.expect(handler.allowed_headers.get("Content-Type") != null);
}

test "preflight request detection" {
    const allocator = std.testing.allocator;
    var handler = CORSHangler.init(allocator);
    defer handler.deinit();
    
    var headers = StringHashMap([]const u8).init(allocator);
    defer headers.deinit();
    
    headers.put("Origin", "https://example.com") catch {};
    headers.put("Access-Control-Request-Method", "POST") catch {};
    
    try std.testing.expect(handler.isPreflightRequest("OPTIONS", headers));
    try std.testing.expect(!handler.isPreflightRequest("POST", headers));
}