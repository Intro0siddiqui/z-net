//! z_security - Security Headers Automation Module
//! Security headers automation (CSP, HSTS, X-Frame-Options, etc.) with validation and enforcement
//! Comprehensive security headers management for web applications

const std = @import("std");
const http = @import("z_http/http.zig");

// Security Headers Errors
pub const SecurityHeaderError = error{
    InvalidHeaderValue,
    PolicyParsingError,
    UnsupportedDirective,
    ValidationFailed,
    MissingRequiredHeader,
    HeaderTooLong,
    InvalidDirectiveValue,
    CspSyntaxError,
    InvalidSourceList,
};

// Security header types
pub const SecurityHeaderType = enum {
    content_security_policy,
    strict_transport_security,
    x_frame_options,
    x_content_type_options,
    x_xss_protection,
    referrer_policy,
    permissions_policy,
    cross_origin_opener_policy,
    cross_origin_embedder_policy,
    cross_origin_resource_policy,
    feature_policy,
    reporting_endpoints,
    expect_ct,
};

// CSP Directive types
pub const CspDirective = enum {
    default_src,
    script_src,
    style_src,
    img_src,
    connect_src,
    font_src,
    object_src,
    media_src,
    frame_src,
    worker_src,
    child_src,
    manifest_src,
    base_uri,
    form_action,
    frame_ancestors,
    upgrade_insecure_requests,
    block_all_mixed_content,
    require_trusted_types_for,
};

// CSP Source expression types
pub const CspSourceType = enum {
    keyword_src,    // 'self', 'unsafe-inline', etc.
    scheme_src,     // https:, data:, etc.
    host_src,       // *.example.com
    nonce_src,      // 'nonce-abc123'
    hash_src,       // 'sha256-...'
};

// CSP Source expression
pub const CspSource = struct {
    source_type: CspSourceType,
    value: []const u8,
    is_wildcard: bool = false,
    
    const Self = @This();
    
    pub fn parse(source_str: []const u8) !Self {
        if (std.mem.eql(u8, source_str, "'self'") or 
            std.mem.eql(u8, source_str, "'unsafe-inline'") or
            std.mem.eql(u8, source_str, "'unsafe-eval'") or
            std.mem.eql(u8, source_str, "'unsafe-hashes'") or
            std.mem.eql(u8, source_str, "'strict-dynamic'") or
            std.mem.eql(u8, source_str, "'report-sample'") or
            std.mem.eql(u8, source_str, "'none'")) {
            return Self{
                .source_type = .keyword_src,
                .value = source_str,
            };
        }
        
        if (std.mem.eql(u8, source_str, "https:") or 
            std.mem.eql(u8, source_str, "http:") or
            std.mem.eql(u8, source_str, "data:") or
            std.mem.eql(u8, source_str, "blob:") or
            std.mem.eql(u8, source_str, "filesystem:") or
            std.mem.eql(u8, source_str, "mediastream:") or
            std.mem.eql(u8, source_str, "ws:") or
            std.mem.eql(u8, source_str, "wss:")) {
            return Self{
                .source_type = .scheme_src,
                .value = source_str,
            };
        }
        
        if (std.mem.startsWith(u8, source_str, "'nonce-")) {
            return Self{
                .source_type = .nonce_src,
                .value = source_str,
            };
        }
        
        if (std.mem.startsWith(u8, source_str, "'sha256-") or 
            std.mem.startsWith(u8, source_str, "'sha384-") or
            std.mem.startsWith(u8, source_str, "'sha512-")) {
            return Self{
                .source_type = .hash_src,
                .value = source_str,
            };
        }
        
        // Host source (includes wildcard support)
        const is_wildcard = std.mem.endsWith(u8, source_str, "*");
        return Self{
            .source_type = .host_src,
            .value = source_str,
            .is_wildcard = is_wildcard,
        };
    }
};

// Content Security Policy structure
pub const ContentSecurityPolicy = struct {
    directives: std.StringArrayHashMap(std.ArrayList(CspSource)),
    report_only: bool = false,
    report_uri: ?[]const u8 = null,
    
    const Self = @This();
    
    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .directives = std.StringArrayHashMap(std.ArrayList(CspSource)).init(allocator),
        };
    }
    
    pub fn addDirective(self: *Self, directive: CspDirective, sources: []const []const u8) !void {
        const directive_name = @tagName(directive);
        var source_list = std.ArrayList(CspSource).init(self.directives.allocator);
        
        for (sources) |source_str| {
            const source = try CspSource.parse(source_str);
            try source_list.append(source);
        }
        
        try self.directives.put(directive_name, source_list);
    }
    
    pub fn generateHeaderValue(self: *Self) []const u8 {
        var header_parts = std.ArrayList(u8).init(self.directives.allocator);
        
        for (self.directives.keys()) |directive_name, i| {
            if (i > 0) {
                header_parts.append(';') catch {};
            }
            
            // Add directive name
            header_parts.appendSlice(directive_name) catch {};
            header_parts.append(' ') catch {};
            
            // Add sources
            const sources = self.directives.get(directive_name).?;
            for (sources.items, 0..) |source, j| {
                if (j > 0) {
                    header_parts.append(' ') catch {};
                }
                header_parts.appendSlice(source.value) catch {};
            }
        }
        
        if (self.report_uri) |uri| {
            header_parts.append(';') catch {};
            header_parts.appendSlice(" report-uri ") catch {};
            header_parts.appendSlice(uri) catch {};
        }
        
        return header_parts.toOwnedSlice() catch "";
    }
    
    pub fn deinit(self: *Self) void {
        for (self.directives.values()) |*list| {
            list.deinit();
        }
        self.directives.deinit();
    }
};

// Security Header configuration
pub const SecurityHeaderConfig = struct {
    content_security_policy: ?ContentSecurityPolicy = null,
    strict_transport_security: ?[]const u8 = null,
    x_frame_options: ?[]const u8 = null,
    x_content_type_options: ?[]const u8 = null,
    x_xss_protection: ?[]const u8 = null,
    referrer_policy: ?[]const u8 = null,
    permissions_policy: ?[]const u8 = null,
    cross_origin_opener_policy: ?[]const u8 = null,
    cross_origin_embedder_policy: ?[]const u8 = null,
    cross_origin_resource_policy: ?[]const u8 = null,
    feature_policy: ?[]const u8 = null,
    reporting_endpoints: ?[]const u8 = null,
    expect_ct: ?[]const u8 = null,
    
    const Self = @This();
    
    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{};
    }
    
    pub fn withCsp(self: *Self, csp: ContentSecurityPolicy) *Self {
        self.content_security_policy = csp;
        return self;
    }
    
    pub fn withHsts(self: *Self, max_age: u64, include_sub_domains: bool, preload: bool) *Self {
        self.strict_transport_security = try std.fmt.allocPrint(std.heap.c_allocator, 
            "max-age={d}{s}{s}", .{
                max_age,
                if (include_sub_domains) "; includeSubDomains" else "",
                if (preload) "; preload" else ""
            });
        return self;
    }
    
    pub fn withXFrameOptions(self: *Self, mode: []const u8) *Self {
        self.x_frame_options = mode;
        return self;
    }
    
    pub fn withXContentTypeOptions(self: *Self) *Self {
        self.x_content_type_options = "nosniff";
        return self;
    }
    
    pub fn withXXssProtection(self: *Self, mode: []const u8) *Self {
        self.x_xss_protection = mode;
        return self;
    }
    
    pub fn withReferrerPolicy(self: *Self, policy: []const u8) *Self {
        self.referrer_policy = policy;
        return self;
    }
    
    pub fn withPermissionsPolicy(self: *Self, policy: []const u8) *Self {
        self.permissions_policy = policy;
        return self;
    }
    
    pub fn withCrossOriginPolicy(self: *Self, coop: []const u8, coep: []const u8, corp: []const u8) *Self {
        self.cross_origin_opener_policy = coop;
        self.cross_origin_embedder_policy = coep;
        self.cross_origin_resource_policy = corp;
        return self;
    }
    
    pub fn deinit(self: *Self) void {
        if (self.content_security_policy) |csp| {
            csp.deinit();
        }
    }
};

// Predefined security header configurations
pub const SecurityProfiles = struct {
    pub const minimal = SecurityHeaderConfig{
        .strict_transport_security = "max-age=31536000; includeSubDomains",
        .x_content_type_options = "nosniff",
        .referrer_policy = "strict-origin-when-cross-origin",
    };
    
    pub const moderate = SecurityHeaderConfig{
        .strict_transport_security = "max-age=31536000; includeSubDomains; preload",
        .x_content_type_options = "nosniff",
        .x_frame_options = "DENY",
        .x_xss_protection = "1; mode=block",
        .referrer_policy = "strict-origin-when-cross-origin",
        .cross_origin_opener_policy = "same-origin",
        .cross_origin_resource_policy = "same-site",
    };
    
    pub const strict = SecurityHeaderConfig{
        .strict_transport_security = "max-age=31536000; includeSubDomains; preload",
        .x_content_type_options = "nosniff",
        .x_frame_options = "DENY",
        .x_xss_protection = "1; mode=block",
        .referrer_policy = "no-referrer",
        .cross_origin_opener_policy = "same-origin",
        .cross_origin_embedder_policy = "require-corp",
        .cross_origin_resource_policy = "same-site",
    };
};

// Security Header Generator
pub const SecurityHeaderGenerator = struct {
    allocator: std.mem.Allocator,
    
    const Self = @This();
    
    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .allocator = allocator,
        };
    }
    
    pub fn generateHeaders(self: *Self, config: SecurityHeaderConfig) ![]http.HttpHeader {
        var headers = std.ArrayList(http.HttpHeader).init(self.allocator);
        
        // Content-Security-Policy
        if (config.content_security_policy) |csp| {
            const header_value = csp.generateHeaderValue();
            const header_name = if (csp.report_only) "Content-Security-Policy-Report-Only" else "Content-Security-Policy";
            try headers.append(http.HttpHeader{ .name = header_name, .value = header_value });
        }
        
        // Strict-Transport-Security
        if (config.strict_transport_security) |hsts| {
            try headers.append(http.HttpHeader{ .name = "Strict-Transport-Security", .value = hsts });
        }
        
        // X-Frame-Options
        if (config.x_frame_options) |xfo| {
            try headers.append(http.HttpHeader{ .name = "X-Frame-Options", .value = xfo });
        }
        
        // X-Content-Type-Options
        if (config.x_content_type_options) |xcto| {
            try headers.append(http.HttpHeader{ .name = "X-Content-Type-Options", .value = xcto });
        }
        
        // X-XSS-Protection
        if (config.x_xss_protection) |xss| {
            try headers.append(http.HttpHeader{ .name = "X-XSS-Protection", .value = xss });
        }
        
        // Referrer-Policy
        if (config.referrer_policy) |ref| {
            try headers.append(http.HttpHeader{ .name = "Referrer-Policy", .value = ref });
        }
        
        // Permissions-Policy
        if (config.permissions_policy) |perm| {
            try headers.append(http.HttpHeader{ .name = "Permissions-Policy", .value = perm });
        }
        
        // Cross-Origin-Opener-Policy
        if (config.cross_origin_opener_policy) |coop| {
            try headers.append(http.HttpHeader{ .name = "Cross-Origin-Opener-Policy", .value = coop });
        }
        
        // Cross-Origin-Embedder-Policy
        if (config.cross_origin_embedder_policy) |coep| {
            try headers.append(http.HttpHeader{ .name = "Cross-Origin-Embedder-Policy", .value = coep });
        }
        
        // Cross-Origin-Resource-Policy
        if (config.cross_origin_resource_policy) |corp| {
            try headers.append(http.HttpHeader{ .name = "Cross-Origin-Resource-Policy", .value = corp });
        }
        
        // Feature-Policy (deprecated, but included for compatibility)
        if (config.feature_policy) |feat| {
            try headers.append(http.HttpHeader{ .name = "Feature-Policy", .value = feat });
        }
        
        // Reporting-Endpoints
        if (config.reporting_endpoints) |report| {
            try headers.append(http.HttpHeader{ .name = "Reporting-Endpoints", .value = report });
        }
        
        // Expect-CT
        if (config.expect_ct) |ect| {
            try headers.append(http.HttpHeader{ .name = "Expect-CT", .value = ect });
        }
        
        return headers.toOwnedSlice();
    }
    
    pub fn generateDefaultCsp(self: *Self, site_url: []const u8) !ContentSecurityPolicy {
        var csp = ContentSecurityPolicy.init(self.allocator);
        
        // Default CSP for secure web applications
        try csp.addDirective(.default_src, &[_][]const u8{ "'self'" });
        try csp.addDirective(.script_src, &[_][]const u8{ "'self'", "'unsafe-inline'", "'unsafe-eval'" });
        try csp.addDirective(.style_src, &[_][]const u8{ "'self'", "'unsafe-inline'" });
        try csp.addDirective(.img_src, &[_][]const u8{ "'self'", "data:", "https:" });
        try csp.addDirective(.font_src, &[_][]const u8{ "'self'", "https:", "data:" });
        try csp.addDirective(.connect_src, &[_][]const u8{ "'self'", "https:" });
        try csp.addDirective(.frame_src, &[_][]const u8{ "'none'" });
        try csp.addDirective(.object_src, &[_][]const u8{ "'none'" });
        try csp.addDirective(.base_uri, &[_][]const u8{ "'self'" });
        try csp.addDirective(.form_action, &[_][]const u8{ "'self'" });
        try csp.addDirective(.upgrade_insecure_requests, &[_][]const u8{""});
        
        return csp;
    }
    
    pub fn validateHeader(self: *Self, header_type: SecurityHeaderType, value: []const u8) SecurityHeaderError!void {
        switch (header_type) {
            .content_security_policy => return self.validateCsp(value),
            .strict_transport_security => return self.validateHsts(value),
            .x_frame_options => return self.validateXFrameOptions(value),
            .x_content_type_options => return self.validateXContentTypeOptions(value),
            .x_xss_protection => return self.validateXXssProtection(value),
            .referrer_policy => return self.validateReferrerPolicy(value),
            else => return {}, // For now, accept other headers as valid
        }
    }
    
    fn validateCsp(self: *Self, csp_value: []const u8) SecurityHeaderError!void {
        var directives = std.mem.split(u8, csp_value, ";");
        
        while (directives.next()) |directive| {
            const trimmed_directive = std.mem.trim(u8, directive, " \t");
            if (trimmed_directive.len == 0) continue;
            
            const space_index = std.mem.indexOf(u8, trimmed_directive, " ") orelse trimmed_directive.len;
            const directive_name = trimmed_directive[0..space_index];
            const sources_str = if (space_index < trimmed_directive.len) 
                std.mem.trim(u8, trimmed_directive[space_index..], " \t") else "";
            
            // Validate directive name (simplified)
            const valid_directives = &[_][]const u8{
                "default-src", "script-src", "style-src", "img-src", "connect-src",
                "font-src", "object-src", "media-src", "frame-src", "worker-src",
                "child-src", "manifest-src", "base-uri", "form-action", "frame-ancestors",
                "upgrade-insecure-requests", "block-all-mixed-content",
            };
            
            var is_valid_directive = false;
            for (valid_directives) |valid_name| {
                if (std.mem.eql(u8, directive_name, valid_name)) {
                    is_valid_directive = true;
                    break;
                }
            }
            
            if (!is_valid_directive) {
                return error.UnsupportedDirective;
            }
            
            // Validate sources (simplified)
            if (sources_str.len > 0) {
                var sources = std.mem.split(u8, sources_str, " ");
                while (sources.next()) |source| {
                    if (source.len == 0) continue;
                    _ = CspSource.parse(source) catch return error.InvalidSourceList;
                }
            }
        }
    }
    
    fn validateHsts(self: *Self, hsts_value: []const u8) SecurityHeaderError!void {
        if (hsts_value.len > 2000) return error.HeaderTooLong;
        
        const has_max_age = std.mem.indexOf(u8, hsts_value, "max-age=") != null;
        if (!has_max_age) return error.InvalidHeaderValue;
        
        // Validate max-age value
        const max_age_start = std.mem.indexOf(u8, hsts_value, "max-age=").? + 8;
        const max_age_end = std.mem.indexOf(u8, hsts_value[max_age_start..], ";") orelse hsts_value.len;
        const max_age_str = hsts_value[max_age_start..max_age_end];
        
        if (max_age_str.len == 0) return error.InvalidMaxAge;
        
        const max_age = std.fmt.parseInt(u64, max_age_str, 10) catch return error.InvalidMaxAge;
        if (max_age == 0) return error.InvalidMaxAge;
        
        // Validate optional directives
        const directives = std.mem.split(u8, hsts_value, ";");
        while (directives.next()) |directive| {
            const trimmed = std.mem.trim(u8, directive, " \t");
            if (trimmed.len == 0) continue;
            
            if (std.mem.eql(u8, trimmed, "includeSubDomains") or 
                std.mem.eql(u8, trimmed, "preload")) {
                continue;
            }
            
            if (!std.mem.startsWith(u8, trimmed, "max-age=")) {
                return error.InvalidDirectiveValue;
            }
        }
    }
    
    fn validateXFrameOptions(self: *Self, xfo_value: []const u8) SecurityHeaderError!void {
        const trimmed = std.mem.trim(u8, xfo_value, " \t");
        if (std.mem.eql(u8, trimmed, "DENY") or 
            std.mem.eql(u8, trimmed, "SAMEORIGIN")) {
            return;
        }
        
        // ALLOW-FROM is deprecated but still supported
        if (std.mem.startsWith(u8, trimmed, "ALLOW-FROM ")) {
            const origin = trimmed[11..];
            // Basic origin validation
            if (origin.len < 4) return error.InvalidHeaderValue;
            return;
        }
        
        return error.InvalidHeaderValue;
    }
    
    fn validateXContentTypeOptions(self: *Self, xcto_value: []const u8) SecurityHeaderError!void {
        const trimmed = std.mem.trim(u8, xcto_value, " \t");
        if (!std.mem.eql(u8, trimmed, "nosniff")) {
            return error.InvalidHeaderValue;
        }
    }
    
    fn validateXXssProtection(self: *Self, xss_value: []const u8) SecurityHeaderError!void {
        const trimmed = std.mem.trim(u8, xss_value, " \t");
        
        if (std.mem.eql(u8, trimmed, "0")) return;
        if (std.mem.eql(u8, trimmed, "1")) return;
        
        if (std.mem.startsWith(u8, trimmed, "1; mode=")) {
            const mode = trimmed[8..];
            if (std.mem.eql(u8, mode, "block") or std.mem.eql(u8, mode, "report")) {
                return;
            }
        }
        
        return error.InvalidHeaderValue;
    }
    
    fn validateReferrerPolicy(self: *Self, policy_value: []const u8) SecurityHeaderError!void {
        const valid_policies = &[_][]const u8{
            "no-referrer", "no-referrer-when-downgrade", "origin", "origin-when-cross-origin",
            "same-origin", "strict-origin", "strict-origin-when-cross-origin", "unsafe-url",
        };
        
        const trimmed = std.mem.trim(u8, policy_value, " \t");
        
        for (valid_policies) |valid_policy| {
            if (std.mem.eql(u8, trimmed, valid_policy)) {
                return;
            }
        }
        
        return error.InvalidHeaderValue;
    }
    
    pub fn deinit(self: *Self) void {}
};

// Security Headers Middleware for HTTP server
pub const SecurityHeadersMiddleware = struct {
    allocator: std.mem.Allocator,
    generator: SecurityHeaderGenerator,
    config: SecurityHeaderConfig,
    validate_on_add: bool = true,
    
    const Self = @This();
    
    pub fn init(allocator: std.mem.Allocator, config: SecurityHeaderConfig) Self {
        return Self{
            .allocator = allocator,
            .generator = SecurityHeaderGenerator.init(allocator),
            .config = config,
        };
    }
    
    pub fn processResponse(self: *Self, response: *http.HttpResponse) !void {
        const headers = try self.generator.generateHeaders(self.config);
        
        // Add security headers to response
        for (headers) |header| {
            // Validate header if enabled
            if (self.validate_on_add) {
                const header_type = self.getHeaderType(header.name);
                if (header_type) |ht| {
                    self.generator.validateHeader(ht, header.value) catch {
                        std.log.warn("Invalid security header {s}: {s}", .{ header.name, header.value });
                        continue;
                    };
                }
            }
            
            try response.headers.append(header);
        }
        
        // Clean up generated headers
        for (headers) |header| {
            self.allocator.free(header.name);
            self.allocator.free(header.value);
        }
    }
    
    pub fn processRequest(self: *Self, request: *http.HttpRequest) !void {
        // Could implement request-side security header processing here
        // For example, checking for security headers in incoming requests
        _ = request;
    }
    
    fn getHeaderType(self: *Self, header_name: []const u8) ?SecurityHeaderType {
        const headers_map = std.ComptimeStringMap(SecurityHeaderType, .{
            .{ "Content-Security-Policy", .content_security_policy },
            .{ "Content-Security-Policy-Report-Only", .content_security_policy },
            .{ "Strict-Transport-Security", .strict_transport_security },
            .{ "X-Frame-Options", .x_frame_options },
            .{ "X-Content-Type-Options", .x_content_type_options },
            .{ "X-XSS-Protection", .x_xss_protection },
            .{ "Referrer-Policy", .referrer_policy },
            .{ "Permissions-Policy", .permissions_policy },
            .{ "Cross-Origin-Opener-Policy", .cross_origin_opener_policy },
            .{ "Cross-Origin-Embedder-Policy", .cross_origin_embedder_policy },
            .{ "Cross-Origin-Resource-Policy", .cross_origin_resource_policy },
            .{ "Feature-Policy", .feature_policy },
            .{ "Reporting-Endpoints", .reporting_endpoints },
            .{ "Expect-CT", .expect_ct },
        });
        
        return headers_map.get(header_name);
    }
    
    pub fn setConfig(self: *Self, config: SecurityHeaderConfig) void {
        self.config = config;
    }
    
    pub fn enableValidation(self: *Self, enabled: bool) void {
        self.validate_on_add = enabled;
    }
    
    pub fn getSecurityReport(self: self) struct {
        csp_enabled: bool,
        hsts_enabled: bool,
        xfo_enabled: bool,
        xcto_enabled: bool,
        xss_enabled: bool,
        referrer_policy: ?[]const u8,
        total_headers: usize,
    } {
        return .{
            .csp_enabled = self.config.content_security_policy != null,
            .hsts_enabled = self.config.strict_transport_security != null,
            .xfo_enabled = self.config.x_frame_options != null,
            .xcto_enabled = self.config.x_content_type_options != null,
            .xss_enabled = self.config.x_xss_protection != null,
            .referrer_policy = self.config.referrer_policy,
            .total_headers = @as(usize, 0) +
                if (self.config.content_security_policy != null) 1 else 0 +
                if (self.config.strict_transport_security != null) 1 else 0 +
                if (self.config.x_frame_options != null) 1 else 0 +
                if (self.config.x_content_type_options != null) 1 else 0 +
                if (self.config.x_xss_protection != null) 1 else 0 +
                if (self.config.referrer_policy != null) 1 else 0 +
                if (self.config.permissions_policy != null) 1 else 0 +
                if (self.config.cross_origin_opener_policy != null) 1 else 0 +
                if (self.config.cross_origin_embedder_policy != null) 1 else 0 +
                if (self.config.cross_origin_resource_policy != null) 1 else 0,
        };
    }
    
    pub fn deinit(self: *Self) void {
        self.generator.deinit();
        self.config.deinit();
    }
};
