//! z_policy - Policy Engine Tests
//! 
//! Tests for the Browser Policy Engine components to verify
//! Same-Origin Policy, CORS, and CSP functionality.

const std = @import("std");
const testing = std.testing;

const policy_engine = @import("policy_engine");
const cors_handler = @import("cors_handler");
const csp_validator = @import("csp_validator");
const policy = @import("policy.zig");

usingnamespace policy_engine;
usingnamespace cors_handler;
usingnamespace csp_validator;
usingnamespace policy;

test "origin parsing and comparison" {
    const origin1 = try Origin.parse("https://example.com:443/path");
    const origin2 = try Origin.parse("https://example.com:443/different");
    const origin3 = try Origin.parse("http://example.com:443");
    const origin4 = try Origin.parse("https://example.com:80");
    
    // Same origin should match
    try testing.expect(origin1.isSameOrigin(origin2));
    
    // Different schemes should not match
    try testing.expect(!origin1.isSameOrigin(origin3));
    
    // Different ports should not match
    try testing.expect(!origin1.isSameOrigin(origin4));
}

test "policy engine initialization" {
    const allocator = testing.allocator;
    const config = PolicyEngineConfig{};
    var engine = PolicyEngine.init(allocator, config);
    defer engine.deinit();
    
    // Test that engine initializes correctly
    try testing.expect(engine.config.enable_sop);
    try testing.expect(engine.config.enable_cors);
    try testing.expect(engine.config.enable_csp);
    
    // Test origin whitelist functionality
    const origin = try Origin.parse("https://trusted-site.com");
    try engine.addToWhitelist(origin);
    try testing.expect(engine.origin_whitelist.get(origin) != null);
}

test "cors preflight request detection" {
    const allocator = testing.allocator;
    var handler = CORSHangler.init(allocator);
    defer handler.deinit();
    
    var headers = StringHashMap([]const u8).init(allocator);
    defer headers.deinit();
    
    // Setup CORS preflight headers
    headers.put("Origin", "https://example.com") catch {};
    headers.put("Access-Control-Request-Method", "POST") catch {};
    headers.put("Access-Control-Request-Headers", "Content-Type,Authorization") catch {};
    
    // Should detect as preflight request
    try testing.expect(handler.isPreflightRequest("OPTIONS", headers));
    
    // Setup normal request headers
    headers.clear();
    headers.put("Content-Type", "application/json") catch {};
    
    // Should not detect as preflight
    try testing.expect(!handler.isPreflightRequest("POST", headers));
}

test "cors handler configuration" {
    const allocator = testing.allocator;
    var handler = CORSHangler.init(allocator);
    defer handler.deinit();
    
    var options = CORSOptions.init(allocator);
    defer options.deinit();
    
    // Configure CORS for specific origin
    options.origin = "https://api.example.com";
    options.addMethod(.GET);
    options.addMethod(.POST);
    options.addMethod(.PUT);
    options.addHeader("Content-Type");
    options.addHeader("Authorization");
    options.credentials = true;
    
    try handler.configure(options);
    
    // Verify configuration
    try testing.expect(handler.allowed_origins.get("https://api.example.com") != null);
    try testing.expect(handler.allowed_methods.get("GET") != null);
    try testing.expect(handler.allowed_methods.get("POST") != null);
    try testing.expect(handler.allowed_headers.get("Content-Type") != null);
    try testing.expect(handler.allowed_headers.get("Authorization") != null);
}

test "cors preflight request handling" {
    const allocator = testing.allocator;
    var handler = CORSHangler.init(allocator);
    defer handler.deinit();
    
    // Configure allowed origins and methods
    var options = CORSOptions.init(allocator);
    defer options.deinit();
    
    options.origin = "https://example.com";
    options.addMethod(.GET);
    options.addMethod(.POST);
    options.addHeader("Content-Type");
    
    try handler.configure(options);
    
    // Create preflight request
    var headers = StringHashMap([]const u8).init(allocator);
    defer headers.deinit();
    
    headers.put("Origin", "https://example.com") catch {};
    headers.put("Access-Control-Request-Method", "POST") catch {};
    headers.put("Access-Control-Request-Headers", "Content-Type") catch {};
    
    const preflight_request = try handler.extractPreflightRequest("OPTIONS", headers);
    defer preflight_request.deinit();
    
    try testing.expectEqual(@as([]const u8, "https://example.com"), preflight_request.origin);
    try testing.expectEqual(CORSMethod.POST, preflight_request.method);
    try testing.expectEqual(@as(usize, 1), preflight_request.headers.items.len);
    try testing.expect(std.mem.eql(u8, preflight_request.headers.items[0], "Content-Type"));
    
    // Handle preflight request
    const preflight_response = handler.handlePreflight(preflight_request) catch {
        try testing.expect(false);
        return;
    };
    defer preflight_response.deinit();
    
    try testing.expect(std.mem.eql(u8, "https://example.com", preflight_response.allow_origin));
    try testing.expect(preflight_response.allow_credentials);
}

test "csp directive parsing" {
    const allocator = testing.allocator;
    var validator = CSPValidator.init(allocator);
    defer validator.deinit();
    
    const policy_header = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' https://fonts.googleapis.com";
    const origin = try Origin.parse("https://example.com");
    
    const policy_parsed = try validator.parseCSPHeader(policy_header, origin);
    defer policy_parsed.deinit();
    
    // Should have 3 directives
    try testing.expectEqual(@as(usize, 3), policy_parsed.directives.items.len);
    
    // Check default-src directive
    const default_src = policy_parsed.directives.items[0];
    try testing.expect(std.mem.eql(u8, "default-src", default_src.directive));
    try testing.expectEqual(@as(usize, 1), default_src.sources.items.len);
    try testing.expect(default_src.allow_self);
    
    // Check script-src directive
    const script_src = policy_parsed.directives.items[1];
    try testing.expect(std.mem.eql(u8, "script-src", script_src.directive));
    try testing.expectEqual(@as(usize, 2), script_src.sources.items.len);
    try testing.expect(script_src.allow_unsafe_inline);
}

test "csp validation context" {
    const allocator = testing.allocator;
    var validator = CSPValidator.init(allocator);
    defer validator.deinit();
    
    var context = CSPValidationContext.init("https://example.com/script.js", "script", "https://example.com/page.html");
    
    try testing.expect(std.mem.eql(u8, "https://example.com/script.js", context.resource_url));
    try testing.expect(std.mem.eql(u8, "script", context.resource_type));
    try testing.expect(std.mem.eql(u8, "https://example.com/page.html", context.document_url));
}

test "policy manager creation" {
    const allocator = testing.allocator;
    const config = getDefaultPolicyConfig();
    
    var manager = try createPolicyManager(allocator, config);
    defer manager.deinit();
    
    // Test default configuration
    try testing.expect(manager.config.enable_sop);
    try testing.expect(manager.config.enable_cors);
    try testing.expect(manager.config.enable_csp);
    try testing.expect(manager.config.enable_mixed_content_blocking);
    
    // Test CORS configuration
    var cors_options = CORSOptions.init(allocator);
    defer cors_options.deinit();
    
    cors_options.origin = "https://api.trusted.com";
    cors_options.addMethod(.GET);
    cors_options.addMethod(.POST);
    
    try manager.configureCORS("https://api.trusted.com", cors_options);
    
    // Test whitelist functionality
    try manager.addWhitelistOrigin("https://trusted-partner.com");
    
    // Verify configuration
    const stats = manager.getStats();
    try testing.expect(stats.csp_policies >= 0); // Should be non-negative
}

test "request validation same origin" {
    const allocator = testing.allocator;
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
        try testing.expect(false);
        return;
    };
    defer result.deinit();
    
    try testing.expect(result.allowed);
    try testing.expect(std.mem.eql(u8, "Request passed all policy checks", result.reason));
}

test "request validation cross origin without CORS" {
    const allocator = testing.allocator;
    const config = PolicyEngineConfig{
        .enable_sop = true,
        .enable_cors = false, // CORS disabled
        .enable_csp = false,
        .enable_mixed_content_blocking = false,
    };
    
    var request_headers = StringHashMap([]const u8).init(allocator);
    defer request_headers.deinit();
    
    request_headers.put("Content-Type", "application/json") catch {};
    
    const page_origin = try Origin.parse("https://example.com");
    const result = RequestValidation.validateRequest(
        allocator,
        "https://different-origin.com/api/data",
        "GET",
        request_headers,
        page_origin,
        config,
    ) catch {
        try testing.expect(false);
        return;
    };
    defer result.deinit();
    
    // With SOP enabled and cross-origin, should be blocked
    try testing.expect(!result.allowed);
    try testing.expect(std.mem.eql(u8, "Same-Origin Policy violation", result.reason));
}

test "mixed content validation" {
    const page_origin = try Origin.parse("https://secure-site.com");
    
    // HTTPS page loading HTTP resource should be blocked
    const http_resource = "http://insecure-cdn.com/script.js";
    const mixed_result = validateMixedContentPolicy(page_origin, http_resource, "script") catch {
        try testing.expect(false);
        return;
    };
    
    try testing.expect(!mixed_result.allowed);
    try testing.expect(std.mem.eql(u8, "Mixed content violation", mixed_result.reason));
    
    // HTTPS page loading HTTPS resource should be allowed
    const https_resource = "https://secure-cdn.com/script.js";
    const secure_result = validateMixedContentPolicy(page_origin, https_resource, "script") catch {
        try testing.expect(false);
        return;
    };
    
    try testing.expect(secure_result.allowed);
}

test "policy stats and cache management" {
    const allocator = testing.allocator;
    var manager = try createPolicyManager(allocator, getDefaultPolicyConfig());
    defer manager.deinit();
    
    // Add some CORS configurations to populate cache
    var cors_options = CORSOptions.init(allocator);
    defer cors_options.deinit();
    
    cors_options.origin = "https://api.example.com";
    cors_options.addMethod(.GET);
    
    try manager.configureCORS("https://api.example.com", cors_options);
    
    // Get statistics
    const stats = manager.getStats();
    try testing.expect(stats.cors_cache_size >= 0);
    try testing.expect(stats.cors_cache_capacity > 0);
    try testing.expect(stats.csp_policies >= 0);
    
    // Clear caches
    manager.clearCaches();
    
    // Stats should remain the same (capacity doesn't change)
    const stats_after_clear = manager.getStats();
    try testing.expectEqual(stats.cors_cache_capacity, stats_after_clear.cors_cache_capacity);
}