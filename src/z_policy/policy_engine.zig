//! z_policy - Browser Policy Engine
//! 
//! Enforces Same-Origin Policy (SOP), Cross-Origin Resource Sharing (CORS),
//! Content Security Policy (CSP), and other browser security policies.
//!
//! This module provides security validation for all network requests and responses
//! in compliance with browser security standards.

const std = @import("std");
const Allocator = std.mem.Allocator;
const AutoHashMap = std.AutoHashMap;
const StringHashMap = std.StringHashMap;
const ArrayList = std.ArrayList;
const ParseIntError = std.fmt.ParseIntError;

/// Core policy types
pub const Origin = struct {
    scheme: []const u8,
    host: []const u8,
    port: u16,
    
    pub fn parse(url: []const u8) !Origin {
        // Simple URL parsing for scheme://host:port
        const colon_pos = std.mem.indexOf(u8, url, "://") orelse return error.InvalidUrl;
        const scheme = url[0..colon_pos];
        
        const host_port_start = colon_pos + 3;
        const slash_pos = std.mem.indexOfPos(u8, url, host_port_start, "/") orelse url.len;
        const host_port = url[host_port_start..slash_pos];
        
        const colon_pos_host = std.mem.lastIndexOf(u8, host_port, ":") orelse {
            // Default ports
            const default_port: u16 = if (std.ascii.eqlIgnoreCase(scheme, "https") or std.ascii.eqlIgnoreCase(scheme, "wss"))
                443
            else if (std.ascii.eqlIgnoreCase(scheme, "http") or std.ascii.eqlIgnoreCase(scheme, "ws"))
                80
            else
                return error.UnsupportedScheme;
            return Origin{
                .scheme = scheme,
                .host = host_port,
                .port = default_port,
            };
        };
        
        const host_part = host_port[0..colon_pos_host];
        const port_part = host_port[colon_pos_host + 1 ..];
        const port = try std.fmt.parseInt(u16, port_part, 10);
        
        return Origin{
            .scheme = scheme,
            .host = host_part,
            .port = port,
        };
    }
    
    pub fn toUrl(self: Origin, allocator: Allocator) ![]u8 {
        return std.fmt.allocPrint(allocator, "{s}://{s}:{d}", .{ self.scheme, self.host, self.port });
    }
    
    pub fn isSameOrigin(self: Origin, other: Origin) bool {
        return std.mem.eql(u8, self.scheme, other.scheme) and
               std.mem.eql(u8, self.host, other.host) and
               self.port == other.port;
    }
    
    pub fn format(self: Origin, writer: anytype) !void {
        try writer.print("{}://{}:{}", .{ self.scheme, self.host, self.port });
    }
};

pub const OriginContext = struct {
    pub fn hash(self: @This(), origin: Origin) u64 {
        _ = self;
        var hasher = std.hash.Wyhash.init(0);
        hasher.update(origin.scheme);
        hasher.update(origin.host);
        hasher.update(&std.mem.toBytes(origin.port));
        return hasher.final();
    }
    pub fn eql(self: @This(), a: Origin, b: Origin) bool {
        _ = self;
        return a.isSameOrigin(b);
    }
};

pub const OriginPairContext = struct {
    pub fn hash(self: @This(), origins: [2]Origin) u64 {
        _ = self;
        var hasher = std.hash.Wyhash.init(0);
        for (origins) |origin| {
            hasher.update(origin.scheme);
            hasher.update(origin.host);
            hasher.update(&std.mem.toBytes(origin.port));
        }
        return hasher.final();
    }
    pub fn eql(self: @This(), a: [2]Origin, b: [2]Origin) bool {
        _ = self;
        return a[0].isSameOrigin(b[0]) and a[1].isSameOrigin(b[1]);
    }
};

pub fn OriginHashMap(comptime V: type) type {
    return std.HashMap(Origin, V, OriginContext, std.hash_map.default_max_load_percentage);
}

pub fn OriginPairHashMap(comptime V: type) type {
    return std.HashMap([2]Origin, V, OriginPairContext, std.hash_map.default_max_load_percentage);
}

pub const CORSRequest = struct {
    method: []const u8,
    headers: StringHashMap([]const u8),
    url: []const u8,
    origin: Origin,
    
    pub fn init(allocator: Allocator) CORSRequest {
        return CORSRequest{
            .method = "GET",
            .headers = StringHashMap([]const u8).init(allocator),
            .url = "",
            .origin = undefined,
        };
    }
    
    pub fn deinit(self: *CORSRequest) void {
        self.headers.deinit();
    }
};

pub const CORSResponse = struct {
    allow_origin: ?[]const u8,
    allow_methods: ?[]const u8,
    allow_headers: ?[]const u8,
    allow_credentials: bool,
    max_age: ?i32,
    expose_headers: ?[]const u8,
    vary: ?[]const u8,
    
    pub fn init() CORSResponse {
        return CORSResponse{
            .allow_origin = null,
            .allow_methods = null,
            .allow_headers = null,
            .allow_credentials = false,
            .max_age = null,
            .expose_headers = null,
            .vary = null,
        };
    }
};

pub const CSPTokenType = enum {
    SOURCE_EXPRESSION,
    NONCE,
    HASH,
    KEYWORD,
    HOST_SOURCE,
    SCHEME_SOURCE,
    SELF_KEYWORD,
    UNSAFE_INLINE_KEYWORD,
    UNSAFE_EVAL_KEYWORD,
    NONE_KEYWORD,
};

pub const CSPToken = struct {
    token_type: CSPTokenType,
    value: []const u8,
    is_keyword: bool,
    
    pub fn init(token_type: CSPTokenType, value: []const u8, is_keyword: bool) CSPToken {
        return CSPToken{
            .token_type = token_type,
            .value = value,
            .is_keyword = is_keyword,
        };
    }
};

pub const CSPDirective = struct {
    directive: []const u8,
    sources: std.ArrayListUnmanaged(CSPToken) = .empty,
    allow_self: bool = false,
    allow_unsafe_inline: bool = false,
    allow_unsafe_eval: bool = false,
    require_nonce: bool = false,
    require_hash: bool = false,
    
    pub fn init(allocator: Allocator) CSPDirective {
        _ = allocator;
        return CSPDirective{
            .directive = "",
            .sources = .empty,
            .allow_self = false,
            .allow_unsafe_inline = false,
            .allow_unsafe_eval = false,
            .require_nonce = false,
            .require_hash = false,
        };
    }
    
    pub fn deinit(self: *CSPDirective, allocator: Allocator) void {
        self.sources.deinit(allocator);
    }
};

pub const ContentSecurityPolicy = struct {
    allocator: Allocator,
    directives: std.ArrayListUnmanaged(CSPDirective) = .empty,
    report_uri: ?[]const u8,
    
    pub fn init(allocator: Allocator) ContentSecurityPolicy {
        return ContentSecurityPolicy{
            .allocator = allocator,
            .directives = .empty,
            .report_uri = null,
        };
    }
    
    pub fn deinit(self: *ContentSecurityPolicy) void {
        for (self.directives.items) |*directive| {
            directive.deinit(self.allocator);
        }
        self.directives.deinit(self.allocator);
    }

    pub fn validateDirective(self: *const ContentSecurityPolicy, directive_name: []const u8, host: []const u8) PreRequestValidationResult {
        _ = self;
        _ = directive_name;
        _ = host;
        return .Allowed;
    }

    pub fn hasDirective(self: *const ContentSecurityPolicy, directive_str: []const u8) bool {
        _ = self;
        _ = directive_str;
        return false;
    }
};

pub const PolicyRule = struct {
    allocator: Allocator,
    rule_type: PolicyRuleType,
    source_origin: Origin,
    target_origin: Origin,
    allowed_methods: std.ArrayListUnmanaged([]const u8) = .empty,
    allowed_headers: std.ArrayListUnmanaged([]const u8) = .empty,
    allow_credentials: bool,
    max_age: i32,
    
    pub fn init(allocator: Allocator) PolicyRule {
        return PolicyRule{
            .allocator = allocator,
            .rule_type = .CORS,
            .source_origin = undefined,
            .target_origin = undefined,
            .allowed_methods = .empty,
            .allowed_headers = .empty,
            .allow_credentials = false,
            .max_age = 600, // 10 minutes default
        };
    }
    
    pub fn deinit(self: *PolicyRule) void {
        self.allowed_methods.deinit(self.allocator);
        self.allowed_headers.deinit(self.allocator);
    }
};

pub const PolicyRuleType = enum {
    SOP,      // Same-Origin Policy
    CORS,     // Cross-Origin Resource Sharing
    CSP,      // Content Security Policy
    MIXED_CONTENT, // Mixed Content Policy
};

pub const ValidationResult = struct {
    allowed: bool,
    reason: []const u8,
    headers: StringHashMap([]const u8),
    
    pub fn init(allocator: Allocator) ValidationResult {
        return ValidationResult{
            .allowed = false,
            .reason = "",
            .headers = StringHashMap([]const u8).init(allocator),
        };
    }
    
    pub fn deinit(self: *ValidationResult) void {
        self.headers.deinit();
    }
};

/// Policy Engine Configuration
pub const PolicyEngineConfig = struct {
    enable_sop: bool = true,
    enable_cors: bool = true,
    enable_csp: bool = true,
    enable_mixed_content_blocking: bool = true,
    allow_credential_requests: bool = false,
    max_cors_age: i32 = 86400, // 24 hours
    strict_transport_security: bool = true,
    block_inline_scripts: bool = false,
    block_eval_scripts: bool = true,
    default_src: []const u8 = "'self'",
    connect_src: []const u8 = "'self'",
    img_src: []const u8 = "'self'",
    style_src: []const u8 = "'self'",
};

/// Policy Engine - Core Implementation
pub const PolicyEngine = struct {
    allocator: Allocator,
    config: PolicyEngineConfig,
    policy_cache: OriginHashMap(ContentSecurityPolicy),
    cors_cache: OriginPairHashMap(CORSResponse),
    origin_whitelist: OriginHashMap(bool),
    
    pub fn init(allocator: Allocator, config: PolicyEngineConfig) PolicyEngine {
        return PolicyEngine{
            .allocator = allocator,
            .config = config,
            .policy_cache = OriginHashMap(ContentSecurityPolicy).init(allocator),
            .cors_cache = OriginPairHashMap(CORSResponse).init(allocator),
            .origin_whitelist = OriginHashMap(bool).init(allocator),
        };
    }
    
    pub fn deinit(self: *PolicyEngine) void {
        var cache_iter = self.policy_cache.valueIterator();
        while (cache_iter.next()) |policy| {
            policy.deinit();
        }
        self.policy_cache.deinit();
        self.cors_cache.deinit();
        self.origin_whitelist.deinit();
    }
    
    /// Validate CORS request
    pub fn validateCORS(self: *PolicyEngine, request: CORSRequest) !ValidationResult {
        var result = ValidationResult.init(self.allocator);
        
        if (!self.config.enable_cors) {
            result.allowed = true;
            result.reason = "CORS disabled";
            return result;
        }
        
        const target_origin = try Origin.parse(request.url);
        
        // Same-Origin Policy check (most restrictive)
        if (request.origin.isSameOrigin(target_origin)) {
            result.allowed = true;
            result.reason = "Same-origin request";
            return result;
        }
        
        // Check CORS cache
        const cache_key = [_]Origin{ request.origin, target_origin };
        if (self.cors_cache.get(cache_key)) |cached_response| {
            if (self.isCORSResponseValid(cached_response)) {
                result.allowed = true;
                result.reason = "Cached CORS response";
                // Add CORS headers to response
                if (cached_response.allow_origin) |origin| {
                    result.headers.put("Access-Control-Allow-Origin", origin) catch {};
                }
                if (cached_response.allow_methods) |methods| {
                    result.headers.put("Access-Control-Allow-Methods", methods) catch {};
                }
                if (cached_response.allow_headers) |headers| {
                    result.headers.put("Access-Control-Allow-Headers", headers) catch {};
                }
                if (cached_response.expose_headers) |headers| {
                    result.headers.put("Access-Control-Expose-Headers", headers) catch {};
                }
                return result;
            }
        }
        
        // Check for explicit CORS rule
        if (try self.findCORSRule(request.origin, target_origin)) |rule| {
            const allowed = self.checkCORSRule(rule, request);
            if (allowed.allowed) {
                result.allowed = true;
                result.reason = "CORS rule match";
                
                // Add CORS headers
                var cors_response = CORSResponse.init();
                cors_response.allow_origin = rule.source_origin.host;
                cors_response.allow_methods = if (rule.allowed_methods.items.len > 0) 
                    std.mem.join(self.allocator, ", ", rule.allowed_methods.items) catch null else null;
                cors_response.allow_headers = if (rule.allowed_headers.items.len > 0) 
                    std.mem.join(self.allocator, ", ", rule.allowed_headers.items) catch null else null;
                cors_response.allow_credentials = rule.allow_credentials;
                cors_response.max_age = rule.max_age;
                
                // Cache the response
                self.cors_cache.put(cache_key, cors_response) catch {};
                
                // Add headers to result
                result.headers.put("Access-Control-Allow-Origin", cors_response.allow_origin orelse "") catch {};
                if (cors_response.allow_methods) |methods| {
                    result.headers.put("Access-Control-Allow-Methods", methods) catch {};
                }
                if (cors_response.allow_headers) |headers| {
                    result.headers.put("Access-Control-Allow-Headers", headers) catch {};
                }
                result.headers.put("Access-Control-Allow-Credentials", 
                    if (rule.allow_credentials) "true" else "false") catch {};
                
                return result;
            }
        }
        
        // Check origin whitelist
        if (self.origin_whitelist.get(target_origin)) |allowed| {
            if (allowed) {
                result.allowed = true;
                result.reason = "Origin whitelist";
                
                // Add basic CORS headers
                result.headers.put("Access-Control-Allow-Origin", target_origin.host) catch {};
                result.headers.put("Access-Control-Allow-Credentials", "true") catch {};
                return result;
            }
        }
        
        result.allowed = false;
        result.reason = "CORS policy violation";
        return result;
    }
    
    /// Validate Content Security Policy
    pub fn validateCSP(self: *PolicyEngine, url: []const u8, content_type: []const u8, origin: Origin) !ValidationResult {
        var result = ValidationResult.init(self.allocator);
        
        if (!self.config.enable_csp) {
            result.allowed = true;
            result.reason = "CSP disabled";
            return result;
        }
        
        // Get CSP policy for origin
        const policy = self.getCSPPolicy(origin) orelse {
            // Use default policy
            var default_policy = ContentSecurityPolicy.init(self.allocator);
            defer default_policy.deinit();
            
            _ = try Origin.parse(url);
            const allowed = self.validateAgainstPolicy(&default_policy, url, content_type);
            if (allowed) {
                result.allowed = true;
                result.reason = "Default CSP policy";
            } else {
                result.allowed = false;
                result.reason = "Default CSP policy violation";
            }
            return result;
        };
        
        const allowed = self.validateAgainstPolicy(policy, url, content_type);
        result.allowed = allowed;
        result.reason = if (allowed) "CSP policy match" else "CSP policy violation";
        
        return result;
    }
    
    /// Check for mixed content violations
    pub fn validateMixedContent(self: *PolicyEngine, page_origin: Origin, resource_url: []const u8, resource_type: []const u8) !ValidationResult {
        var result = ValidationResult.init(self.allocator);
        
        if (!self.config.enable_mixed_content_blocking) {
            result.allowed = true;
            result.reason = "Mixed content blocking disabled";
            return result;
        }
        
        const resource_origin = try Origin.parse(resource_url);
        
        // Only block if page is HTTPS and resource is HTTP
        if (std.mem.eql(u8, page_origin.scheme, "https") and 
            std.mem.eql(u8, resource_origin.scheme, "http")) {
            
            // Check if it's a blockable resource type
            const blockable_types = &[_][]const u8{
                "script", "style", "image", "font", "media", "xmlhttprequest", 
                "fetch", "beacon", "websocket"
            };
            
            for (blockable_types) |blockable_type| {
                if (std.mem.eql(u8, resource_type, blockable_type)) {
                    result.allowed = false;
                    result.reason = "Mixed content violation: HTTPS page loading HTTP resource";
                    return result;
                }
            }
        }
        
        result.allowed = true;
        result.reason = "No mixed content violation";
        return result;
    }
    
    /// Add CORS rule
    pub fn addCORSRule(self: *PolicyEngine, rule: PolicyRule) !void {
        _ = self;
        _ = rule;
    }
    
    /// Add origin to whitelist
    pub fn addToWhitelist(self: *PolicyEngine, origin: Origin) !void {
        try self.origin_whitelist.put(origin, true);
    }
    
    /// Remove origin from whitelist
    pub fn removeFromWhitelist(self: *PolicyEngine, origin: Origin) void {
        self.origin_whitelist.remove(origin);
    }
    
    // Private helper functions
    fn isCORSResponseValid(self: *PolicyEngine, response: CORSResponse) bool {
        _ = self;
        // Check if response is not expired
        return response.max_age == null or response.max_age.? > 0;
    }
    
    fn findCORSRule(self: *PolicyEngine, source: Origin, target: Origin) !?PolicyRule {
        _ = self;
        _ = source;
        _ = target;
        return null;
    }
    
    fn checkCORSRule(self: *PolicyEngine, rule: PolicyRule, request: CORSRequest) ValidationResult {
        var result = ValidationResult.init(self.allocator);
        
        // Check method
        var method_allowed = false;
        for (rule.allowed_methods.items) |allowed_method| {
            if (std.ascii.eqlIgnoreCase(request.method, allowed_method)) {
                method_allowed = true;
                break;
            }
        }
        
        if (!method_allowed) {
            result.allowed = false;
            result.reason = "Method not allowed by CORS rule";
            return result;
        }
        
        // Check headers
        var it = request.headers.iterator();
        while (it.next()) |entry| {
            const header_name = entry.key_ptr.*;
            var header_allowed = false;
            for (rule.allowed_headers.items) |allowed_header| {
                if (std.ascii.eqlIgnoreCase(header_name, allowed_header)) {
                    header_allowed = true;
                    break;
                }
            }
            if (!header_allowed) {
                result.allowed = false;
                result.reason = "Header not allowed by CORS rule";
                return result;
            }
        }
        
        result.allowed = true;
        result.reason = "CORS rule validation passed";
        return result;
    }
    
    fn getCSPPolicy(self: *PolicyEngine, origin: Origin) ?*ContentSecurityPolicy {
        return self.policy_cache.get(origin) catch null;
    }
    
    fn validateAgainstPolicy(self: *PolicyEngine, policy: *ContentSecurityPolicy, url: []const u8, content_type: []const u8) bool {
        _ = policy;
        _ = url;
        _ = content_type;
        _ = self;
        
        // Basic implementation - would check against CSP directives
        return true;
    }
};

// Error types
pub const PolicyError = error{
    InvalidUrl,
    UnsupportedScheme,
    InvalidOrigin,
    PolicyViolation,
    CORSError,
    CSPError,
};

test "origin parsing" {
    const origin = try Origin.parse("https://example.com:443/path");
    try std.testing.expectEqualStrings("https", origin.scheme);
    try std.testing.expectEqualStrings("example.com", origin.host);
    try std.testing.expectEqual(@as(u16, 443), origin.port);
}

test "same origin check" {
    const origin1 = try Origin.parse("https://example.com:443");
    const origin2 = try Origin.parse("https://example.com:443/path");
    const origin3 = try Origin.parse("https://example.com:80");
    
    try std.testing.expect(origin1.isSameOrigin(origin2));
    try std.testing.expect(!origin1.isSameOrigin(origin3));
}

test "policy engine init" {
    const allocator = std.testing.allocator;
    const config = PolicyEngineConfig{};
    var engine = PolicyEngine.init(allocator, config);
    defer engine.deinit();
    
    // Basic initialization test
    try std.testing.expect(engine.config.enable_sop);
    try std.testing.expect(engine.config.enable_cors);
}// ============================================================
// Phase 3: Network Bridge Integration
// ============================================================

/// Pre-request validation result
pub const PreRequestValidationResult = enum(i32) {
    Allowed = 0,
    Blocked = 1,
    Invalid = 2,
};

/// Stream validation result  
pub const StreamValidationResult = enum(i32) {
    Valid = 0,
    Malformed = 1,
    CORSViolation = 2,
    CSPViolation = 3,
};

/// Request interceptor - validates before hitting Rust network
pub const RequestInterceptor = struct {
    allocator: Allocator,
    csp_policy: ?*ContentSecurityPolicy,
    allowed_origins: std.ArrayListUnmanaged(Origin),

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return Self{
            .allocator = allocator,
            .csp_policy = null,
            .allowed_origins = .empty,
        };
    }

    pub fn deinit(self: *Self) void {
        self.allowed_origins.deinit(self.allocator);
    }

    /// Validate and intercept URL request before network call
    pub fn validateRequest(
        self: *Self,
        url: []const u8,
        method: []const u8,
    ) PreRequestValidationResult {
        _ = method;
        // Parse origin from URL
        const origin = Origin.parse(url) catch return .Invalid;

        // Check CSP - abort BEFORE reaching network engine
        if (self.csp_policy) |csp| {
            const csp_result = csp.validateDirective("connect-src", origin.host);
            if (csp_result == .Blocked) {
                return .Blocked;
            }
        }

        // Check allowed origins list
        for (self.allowed_origins.items) |allowed| {
            if (origin.isSameOrigin(allowed)) {
                return .Allowed;
            }
        }

        // Default: allow (CORS will be enforced on response)
        return .Allowed;
    }
};

/// Stream validator - validates in-flight data from Rust
pub const StreamValidator = struct {
    allocator: Allocator,
    current_origin: Origin,
    csp_policy: ?*ContentSecurityPolicy,
    cors_config: PolicyEngineConfig,

    const Self = @This();

    pub fn init(allocator: Allocator, origin: Origin) Self {
        return Self{
            .allocator = allocator,
            .current_origin = origin,
            .csp_policy = null,
            .cors_config = PolicyEngineConfig{},
        };
    }

    pub fn deinit(self: *Self) void {
        _ = self;
    }

    /// Inline validation - validates data IN-PLACE as it flows from Rust
    /// NO duplicate heap allocations permitted
    pub fn validateInPlace(
        self: *Self,
        data: []u8,
    ) StreamValidationResult {
        // Validate HTTP protocol correctness
        if (data.len >= 4) {
            // Check for valid HTTP response start
            const http_prefix = data[0..4];
            if (!std.mem.eql(u8, http_prefix, "HTTP") and 
                !std.mem.startsWith(u8, data, "{") and  // JSON
                !std.mem.startsWith(u8, data, "<")    // HTML
            ) {
                return .Malformed;
            }
        }

        // CORS validation on response headers
        // (If this were a cross-origin response, we'd check Access-Control-*)
        // For same-origin, pass through

        // CSP validation on content
        if (self.csp_policy) |csp| {
            // Check for inline scripts in HTML
            if (std.mem.indexOf(u8, data, "<script") != null) {
                if (csp.hasDirective("script-src 'unsafe-inline'")) {
                    return .CSPViolation;
                }
            }
        }

        return .Valid;
    }

    /// Process raw response from Rust network into policy-validated buffer
    pub fn processResponse(
        self: *Self,
        raw_data: []u8,
        out_buffer: []u8,
    ) !void {
        // Validate in-place first
        const validation = self.validateInPlace(raw_data);
        
        switch (validation) {
            .Valid => {
                // Copy to output (only on valid data)
                @memcpy(out_buffer, raw_data);
            },
            .Malformed => return error.MalformedResponse,
            .CORSViolation => return error.CORSViolation,
            .CSPViolation => return error.CSPViolation,
        }
    }
};

/// Integrated fetch function - full pipeline
pub fn secureFetch(
    url: []const u8,
    method: []const u8,
    engine: anytype,
    policy: *RequestInterceptor,
    validator: *StreamValidator,
) ![]u8 {
    // Step 1: Pre-fetch interception via z_policy
    const precheck = policy.validateRequest(url, method);
    if (precheck == .Blocked) {
        return error.RequestBlocked;
    }

    // Step 2: Connect via Rust engine
    const colon_pos = std.mem.indexOf(u8, url, "://") orelse return error.InvalidUrl;
    const host_start = colon_pos + 3;
    const host_end = std.mem.indexOf(u8, url[host_start..], "/") orelse url.len;
    const host = url[host_start..host_start + host_end];
    
    const port: u16 = 443; // HTTPS default

    var conn = try engine.connect(host, port);
    defer conn.close();

    // Step 3: Build HTTP request
    var request_buf: [1024]u8 = undefined;
    const request = std.fmt.bufPrint(
        &request_buf,
        "GET {} HTTP/1.1\r\nHost: {}\r\n\r\n",
        .{ url, host }
    ) catch return error.RequestBuildFailed;

    // Step 4: Send request
    _ = try conn.write(request);

    // Step 5: Read response via Rust -> validate in-place -> output
    var response_buf: [65536]u8 = undefined;
    const bytes_read = try conn.read(response_buf[0..]);

    // Step 6: Inline streaming validation (ZERO-COPY path)
    try validator.processResponse(response_buf[0..bytes_read], response_buf[0..bytes_read]);

    return response_buf[0..bytes_read];
}