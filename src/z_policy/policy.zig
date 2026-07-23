//! z_policy - Browser Policy Module
//! 
//! Main module that combines SOP, CORS, CSP, and mixed content enforcement
//! into a unified policy validation system for browser compatibility.

const std = @import("std");
const Allocator = std.mem.Allocator;
const StringHashMap = std.StringHashMap;
const ArrayList = std.ArrayList;

pub const policy_engine = @import("policy_engine");
pub const cors_handler = @import("cors_handler");
pub const csp_validator = @import("csp_validator");

// usingnamespace policy_engine;
// usingnamespace cors_handler;
// usingnamespace csp_validator;

pub const RequestValidation = struct {
    /// Main request validation entry point
    pub fn validateRequest(
        allocator: Allocator,
        request_url: []const u8,
        request_method: []const u8,
        request_headers: StringHashMap([]const u8),
        page_origin: Origin,
        config: PolicyEngineConfig,
    ) !ValidationResult {
        var result = ValidationResult.init(allocator);
        
        // Parse request URL
        const request_origin = try Origin.parse(request_url);
        
        // 1. Same-Origin Policy Check
        if (config.enable_sop) {
            const sop_result = try validateSameOriginPolicy(page_origin, request_origin);
            if (!sop_result.allowed) {
                result.allowed = false;
                result.reason = "Same-Origin Policy violation";
                result.headers = sop_result.headers;
                return result;
            }
        }
        
        // 2. Mixed Content Check
        if (config.enable_mixed_content_blocking) {
            const mixed_result = try validateMixedContentPolicy(page_origin, request_url, "fetch");
            if (!mixed_result.allowed) {
                result.allowed = false;
                result.reason = "Mixed content violation";
                result.headers = mixed_result.headers;
                return result;
            }
        }
        
        // 3. CORS Validation
        if (config.enable_cors) {
            const cors_request = CORSRequest{
                .method = request_method,
                .headers = request_headers,
                .url = request_url,
                .origin = page_origin,
            };
            
            const cors_result = try validateCORSRequest(cors_request, config);
            if (!cors_result.allowed) {
                result.allowed = false;
                result.reason = "CORS policy violation";
                result.headers = cors_result.headers;
                return result;
            }
            
            // Merge CORS headers
            var cors_headers_iter = cors_result.headers.keyIterator();
            while (cors_headers_iter.next()) |header_name| {
                const header_value = cors_result.headers.get(header_name.*).?;
                result.headers.put(header_name.*, header_value) catch {};
            }
        }
        
        // 4. Content Security Policy Check
        if (config.enable_csp) {
            const csp_result = try validateCSPResource(request_url, "fetch", page_origin);
            if (!csp_result.allowed) {
                result.allowed = false;
                result.reason = "CSP policy violation";
                return result;
            }
        }
        
        result.allowed = true;
        result.reason = "Request passed all policy checks";
        return result;
    }
    
    /// Validate response for security policy compliance
    pub fn validateResponse(
        allocator: Allocator,
        response_url: []const u8,
        response_headers: StringHashMap([]const u8),
        page_origin: Origin,
        config: PolicyEngineConfig,
    ) !ValidationResult {
        var result = ValidationResult.init(allocator);
        
        // 1. CSP Response Headers
        if (config.enable_csp) {
            if (response_headers.get("Content-Security-Policy")) |csp_header| {
                const origin = try Origin.parse(response_url);
                // Would parse and store CSP policy here
                _ = origin; // Avoid unused variable warning
            }
        }
        
        // 2. CORS Response Headers
        if (config.enable_cors) {
            if (response_headers.get("Access-Control-Allow-Origin")) |cors_header| {
                // Validate CORS response headers
                if (response_headers.get("Access-Control-Allow-Credentials")) |credentials| {
                    if (std.mem.eql(u8, std.ascii.lowerString(credentials), "true") and
                        std.mem.eql(u8, cors_header, "*")) {
                        result.allowed = false;
                        result.reason = "CORS credential conflict: wildcard origin with credentials";
                        return result;
                    }
                }
            }
        }
        
        // 3. Security Headers Validation
        if (config.strict_transport_security) {
            if (response_headers.get("Strict-Transport-Security")) |hsts| {
                // Validate HSTS header format
                if (!isValidHSTSHeader(hsts)) {
                    result.allowed = false;
                    result.reason = "Invalid HSTS header format";
                    return result;
                }
            }
        }
        
        result.allowed = true;
        result.reason = "Response passed security validation";
        return result;
    }
    
    /// Validate inline script content
    pub fn validateInlineScript(
        allocator: Allocator,
        script_content: []const u8,
        script_nonce: ?[]const u8,
        document_origin: Origin,
        config: PolicyEngineConfig,
    ) !ValidationResult {
        var result = ValidationResult.init(allocator);
        
        if (!config.enable_csp) {
            result.allowed = true;
            result.reason = "CSP disabled";
            return result;
        }
        
        // Validate against CSP
        var context = CSPValidationContext.init("<inline>", "script", document_origin.host);
        context.script_nonce = script_nonce;
        
        const csp_result = try validateInlineCSP(script_content, context);
        
        result.allowed = csp_result.allowed;
        result.reason = csp_result.reason;
        
        return result;
    }
};

pub const PolicyManager = struct {
    allocator: Allocator,
    config: PolicyEngineConfig,
    policy_engine: PolicyEngine,
    cors_handler: CORSHangler,
    csp_validator: CSPValidator,
    
    pub fn init(allocator: Allocator, config: PolicyEngineConfig) PolicyManager {
        return PolicyManager{
            .allocator = allocator,
            .config = config,
            .policy_engine = PolicyEngine.init(allocator, config),
            .cors_handler = CORSHangler.init(allocator),
            .csp_validator = CSPValidator.init(allocator),
        };
    }
    
    pub fn deinit(self: *PolicyManager) void {
        self.policy_engine.deinit();
        self.cors_handler.deinit();
        self.csp_validator.deinit();
    }
    
    /// Configure CORS for a specific origin
    pub fn configureCORS(self: *PolicyManager, origin: []const u8, options: CORSOptions) !void {
        options.origin = origin;
        try self.cors_handler.configure(options);
    }
    
    /// Add CSP policy for an origin
    pub fn addCSPPolicy(self: *PolicyManager, origin: []const u8, policy_header: []const u8) !void {
        const parsed_origin = try Origin.parse(origin);
        _ = try self.csp_validator.parseCSPHeader(policy_header, parsed_origin);
    }
    
    /// Add origin to whitelist
    pub fn addWhitelistOrigin(self: *PolicyManager, origin: []const u8) !void {
        const parsed_origin = try Origin.parse(origin);
        try self.policy_engine.addToWhitelist(parsed_origin);
    }
    
    /// Remove origin from whitelist
    pub fn removeWhitelistOrigin(self: *PolicyManager, origin: []const u8) !void {
        const parsed_origin = try Origin.parse(origin);
        self.policy_engine.removeFromWhitelist(parsed_origin);
    }
    
    /// Validate complete request
    pub fn validateRequest(self: *PolicyManager, request_url: []const u8, request_method: []const u8, request_headers: StringHashMap([]const u8), page_origin: Origin) !ValidationResult {
        return RequestValidation.validateRequest(
            self.allocator,
            request_url,
            request_method,
            request_headers,
            page_origin,
            self.config,
        );
    }
    
    /// Validate complete response
    pub fn validateResponse(self: *PolicyManager, response_url: []const u8, response_headers: StringHashMap([]const u8), page_origin: Origin) !ValidationResult {
        return RequestValidation.validateResponse(
            self.allocator,
            response_url,
            response_headers,
            page_origin,
            self.config,
        );
    }
    
    /// Handle CORS preflight request
    pub fn handlePreflightRequest(self: *PolicyManager, request_headers: StringHashMap([]const u8)) !CORSPreflightResponse {
        const origin = request_headers.get("Origin") orelse return CORSError.PreflightFailed;
        
        var preflight_request = self.cors_handler.extractPreflightRequest("OPTIONS", request_headers) catch {
            return CORSError.PreflightFailed;
        };
        defer preflight_request.deinit();
        
        return self.cors_handler.handlePreflight(preflight_request);
    }
    
    /// Generate CORS response headers
    pub fn generateCORSHeaders(self: *PolicyManager, origin: []const u8, allow_credentials: bool) StringHashMap([]const u8) {
        return self.cors_handler.generateCORSHeaders(origin, allow_credentials);
    }
    
    /// Get policy statistics
    pub fn getStats(self: *PolicyManager) PolicyStats {
        const cors_stats = self.cors_handler.getCacheStats();
        const csp_stats = self.csp_validator.getStats();
        
        return PolicyStats{
            .cors_cache_size = cors_stats.cached_responses,
            .cors_cache_capacity = cors_stats.cache_size,
            .csp_policies = csp_stats.policy_count,
            .policy_engine_config = self.config,
        };
    }
    
    /// Clear all caches
    pub fn clearCaches(self: *PolicyManager) void {
        self.cors_handler.clearCache();
        self.csp_validator.clearNonceCache();
        self.csp_validator.clearHashCache();
    }
};

pub const PolicyStats = struct {
    cors_cache_size: usize,
    cors_cache_capacity: usize,
    csp_policies: usize,
    policy_engine_config: PolicyEngineConfig,
};

pub const PolicyError = error{
    InvalidUrl,
    InvalidOrigin,
    PreflightFailed,
    CSPParseError,
    ValidationFailed,
};

/// Public API functions
pub fn createPolicyManager(allocator: Allocator, config: PolicyEngineConfig) !PolicyManager {
    return PolicyManager.init(allocator, config);
}

pub fn getDefaultPolicyConfig() PolicyEngineConfig {
    return PolicyEngineConfig{
        .enable_sop = true,
        .enable_cors = true,
        .enable_csp = true,
        .enable_mixed_content_blocking = true,
        .allow_credential_requests = false,
        .max_cors_age = 86400, // 24 hours
        .strict_transport_security = true,
        .block_inline_scripts = false,
        .block_eval_scripts = true,
        .default_src = "'self'",
        .connect_src = "'self'",
        .img_src = "'self'",
        .style_src = "'self'",
    };
}

// Private helper functions
fn validateSameOriginPolicy(page_origin: Origin, request_origin: Origin) !ValidationResult {
    var result = ValidationResult.init(std.heap.c_allocator);
    
    if (page_origin.isSameOrigin(request_origin)) {
        result.allowed = true;
        result.reason = "Same-origin request";
    } else {
        result.allowed = false;
        result.reason = "Cross-origin request blocked by SOP";
    }
    
    return result;
}

fn validateMixedContentPolicy(page_origin: Origin, resource_url: []const u8, resource_type: []const u8) !ValidationResult {
    var result = ValidationResult.init(std.heap.c_allocator);
    
    const resource_origin = try Origin.parse(resource_url);
    
    // Block mixed content: HTTPS page loading HTTP resource
    if (std.mem.eql(u8, page_origin.scheme, "https") and 
        std.mem.eql(u8, resource_origin.scheme, "http")) {
        
        result.allowed = false;
        result.reason = "Mixed content violation";
    } else {
        result.allowed = true;
        result.reason = "No mixed content violation";
    }
    
    return result;
}

fn validateCORSRequest(request: CORSRequest, config: PolicyEngineConfig) !ValidationResult {
    var engine = PolicyEngine.init(std.heap.c_allocator, config);
    defer engine.deinit();
    
    return engine.validateCORS(request);
}

fn validateCSPResource(url: []const u8, content_type: []const u8, origin: Origin) !ValidationResult {
    var validator = CSPValidator.init(std.heap.c_allocator);
    defer validator.deinit();
    
    var context = CSPValidationContext.init(url, content_type, origin.host);
    return validator.validateResource(context);
}

fn validateInlineCSP(script_content: []const u8, context: CSPValidationContext) !ValidationResult {
    var validator = CSPValidator.init(std.heap.c_allocator);
    defer validator.deinit();
    
    return validator.validateInlineScript(script_content, context);
}

fn isValidHSTSHeader(hsts: []const u8) bool {
    // Basic HSTS validation
    if (!std.mem.startsWith(u8, hsts, "max-age=")) {
        return false;
    }
    
    const max_age_start = 8; // len("max-age=")
    if (max_age_start >= hsts.len) {
        return false;
    }
    
    const max_age_str = hsts[max_age_start..];
    const max_age_comma = std.mem.indexOf(u8, max_age_str, ",") orelse max_age_str.len;
    const max_age_part = max_age_str[0..max_age_comma];
    
    // Parse max-age value
    _ = std.fmt.parseInt(u64, max_age_part, 10) catch {
        return false;
    };
    
    return true;
}

test "policy manager init" {
    const allocator = std.testing.allocator;
    const config = getDefaultPolicyConfig();
    var manager = try createPolicyManager(allocator, config);
    defer manager.deinit();
    
    try std.testing.expect(manager.config.enable_sop);
    try std.testing.expect(manager.config.enable_cors);
    try std.testing.expect(manager.config.enable_csp);
}

test "request validation basic" {
    const allocator = std.testing.allocator;
    const config = getDefaultPolicyConfig();
    
    var request_headers = StringHashMap([]const u8).init(allocator);
    defer request_headers.deinit();
    
    request_headers.put("Content-Type", "application/json") catch {};
    
    const page_origin = try Origin.parse("https://example.com");
    const result = RequestValidation.validateRequest(
        allocator,
        "https://example.com/api/data",
        "GET",
        request_headers,
        page_origin,
        config,
    ) catch {
        try std.testing.expect(false);
        return;
    };
    
    defer result.deinit();
    
    try std.testing.expect(result.allowed);
}