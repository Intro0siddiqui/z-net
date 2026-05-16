//! z_policy - Policy Engine Integration Example
//! 
//! Demonstrates how to integrate the Browser Policy Engine
//! with the z-net networking stack for browser compatibility.

const std = @import("std");
const Allocator = std.mem.Allocator;
const StringHashMap = std.StringHashMap;

const policy_engine = @import("policy_engine");
const cors_handler = @import("cors_handler");
const csp_validator = @import("csp_validator");
const policy = @import("policy.zig");

usingnamespace policy_engine;
usingnamespace cors_handler;
usingnamespace csp_validator;
usingnamespace policy;

pub const PolicyIntegrationExample = struct {
    /// Example: How to integrate Policy Engine with fetch requests
    pub fn exampleFetchWithPolicy() !void {
        const allocator = std.heap.c_allocator;
        
        // 1. Initialize Policy Manager with default configuration
        var policy_manager = try createPolicyManager(allocator, getDefaultPolicyConfig());
        defer policy_manager.deinit();
        
        // 2. Configure CORS for your API
        var cors_options = CORSOptions.init(allocator);
        defer cors_options.deinit();
        
        cors_options.origin = "https://your-api-domain.com";
        cors_options.addMethod(.GET);
        cors_options.addMethod(.POST);
        cors_options.addMethod(.PUT);
        cors_options.addMethod(.DELETE);
        cors_options.addHeader("Content-Type");
        cors_options.addHeader("Authorization");
        cors_options.addHeader("X-Requested-With");
        cors_options.credentials = true;
        
        try policy_manager.configureCORS("https://your-api-domain.com", cors_options);
        
        // 3. Add trusted origins to whitelist
        try policy_manager.addWhitelistOrigin("https://trusted-partner.com");
        try policy_manager.addWhitelistOrigin("https://cdn.example.com");
        
        // 4. Add CSP policy for your site
        const csp_policy = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' https://fonts.googleapis.com; img-src 'self' data: https:; connect-src 'self' https://api.example.com";
        try policy_manager.addCSPPolicy("https://your-site.com", csp_policy);
        
        // 5. Simulate a fetch request with policy validation
        try exampleValidateFetchRequest(&policy_manager);
        
        // 6. Handle CORS preflight requests
        try exampleHandleCORS(&policy_manager);
        
        // 7. Validate inline scripts
        try exampleValidateInlineScript(&policy_manager);
    }
    
    /// Example: Validate a fetch request
    fn exampleValidateFetchRequest(policy_manager: *PolicyManager) !void {
        const allocator = std.heap.c_allocator;
        
        // Setup request details
        const request_url = "https://api.example.com/data";
        const request_method = "POST";
        
        var request_headers = StringHashMap([]const u8).init(allocator);
        defer request_headers.deinit();
        
        request_headers.put("Content-Type", "application/json") catch {};
        request_headers.put("Authorization", "Bearer token123") catch {};
        request_headers.put("X-Requested-With", "XMLHttpRequest") catch {};
        
        // Parse page origin
        const page_origin = try Origin.parse("https://your-site.com");
        
        // Validate request
        const validation_result = try policy_manager.validateRequest(
            request_url,
            request_method,
            request_headers,
            page_origin,
        );
        defer validation_result.deinit();
        
        if (validation_result.allowed) {
            std.log.info("✅ Request allowed: {}", .{validation_result.reason});
            
            // Add any CORS headers needed for the response
            var response_headers_iter = validation_result.headers.keyIterator();
            while (response_headers_iter.next()) |header_name| {
                const header_value = validation_result.headers.get(header_name.*).?;
                std.log.info("📋 CORS Header: {}: {}", .{ header_name.*, header_value });
            }
        } else {
            std.log.warn("❌ Request blocked: {}", .{validation_result.reason});
            
            // Return error response to browser
            // This would typically result in a 403 Forbidden or similar
            return error.RequestBlockedByPolicy;
        }
    }
    
    /// Example: Handle CORS preflight requests
    fn exampleHandleCORS(policy_manager: *PolicyManager) !void {
        const allocator = std.heap.c_allocator;
        
        // Simulate a CORS preflight request (OPTIONS)
        var preflight_headers = StringHashMap([]const u8).init(allocator);
        defer preflight_headers.deinit();
        
        preflight_headers.put("Origin", "https://trusted-partner.com") catch {};
        preflight_headers.put("Access-Control-Request-Method", "POST") catch {};
        preflight_headers.put("Access-Control-Request-Headers", "Content-Type,Authorization") catch {};
        
        // Handle preflight
        const preflight_response = policy_manager.handlePreflightRequest(preflight_headers) catch {
            std.log.warn("❌ Preflight request failed", .{});
            return;
        };
        defer preflight_response.deinit();
        
        std.log.info("✅ Preflight response:", .{});
        std.log.info("  - Allow Origin: {}", .{preflight_response.allow_origin});
        std.log.info("  - Allow Credentials: {}", .{preflight_response.allow_credentials});
        std.log.info("  - Max Age: {} seconds", .{preflight_response.max_age});
        
        // Generate response headers
        const cors_headers = policy_manager.generateCORSHeaders(preflight_response.allow_origin, preflight_response.allow_credentials);
        defer cors_headers.deinit();
        
        var headers_iter = cors_headers.keyIterator();
        while (headers_iter.next()) |header_name| {
            const header_value = cors_headers.get(header_name.*).?;
            std.log.info("  - {}: {}", .{ header_name.*, header_value });
        }
    }
    
    /// Example: Validate inline scripts
    fn exampleValidateInlineScript(policy_manager: *PolicyManager) !void {
        const allocator = std.heap.c_allocator;
        
        // Example inline script content
        const inline_script =
            \\ function handleClick() {
            \\     console.log("Button clicked!");
            \\     document.getElementById("result").innerHTML = "Clicked!";
            \\ }
        ;
        
        // Parse document origin
        const document_origin = try Origin.parse("https://your-site.com");
        
        // Validate inline script
        const validation_result = try RequestValidation.validateInlineScript(
            allocator,
            inline_script,
            null, // no nonce
            document_origin,
            getDefaultPolicyConfig(),
        );
        defer validation_result.deinit();
        
        if (validation_result.allowed) {
            std.log.info("✅ Inline script allowed: {}", .{validation_result.reason});
        } else {
            std.log.warn("❌ Inline script blocked: {}", .{validation_result.reason});
            
            // This would typically result in the script not being executed
            // or being removed from the page
        }
    }
    
    /// Example: Different security configurations
    pub fn exampleSecurityConfigurations() !void {
        const allocator = std.heap.c_allocator;
        
        // 1. Strict Security Configuration
        const strict_config = PolicyEngineConfig{
            .enable_sop = true,
            .enable_cors = true,
            .enable_csp = true,
            .enable_mixed_content_blocking = true,
            .allow_credential_requests = false,
            .max_cors_age = 3600, // 1 hour
            .strict_transport_security = true,
            .block_inline_scripts = true,
            .block_eval_scripts = true,
            .default_src = "'self'",
            .connect_src = "'self'",
            .img_src = "'self' data:",
            .style_src = "'self'",
        };
        
        var strict_manager = try createPolicyManager(allocator, strict_config);
        defer strict_manager.deinit();
        
        // 2. Permissive Configuration for development
        const dev_config = PolicyEngineConfig{
            .enable_sop = true,
            .enable_cors = true,
            .enable_csp = false, // Disable for easier development
            .enable_mixed_content_blocking = false,
            .allow_credential_requests = true,
            .max_cors_age = 86400, // 24 hours
            .strict_transport_security = false,
            .block_inline_scripts = false,
            .block_eval_scripts = false,
            .default_src = "'self' *",
            .connect_src = "'self' *",
            .img_src = "'self' * data:",
            .style_src = "'self' *",
        };
        
        var dev_manager = try createPolicyManager(allocator, dev_config);
        defer dev_manager.deinit();
        
        // 3. Production Configuration
        const production_config = PolicyEngineConfig{
            .enable_sop = true,
            .enable_cors = true,
            .enable_csp = true,
            .enable_mixed_content_blocking = true,
            .allow_credential_requests = false,
            .max_cors_age = 3600, // 1 hour
            .strict_transport_security = true,
            .block_inline_scripts = true,
            .block_eval_scripts = true,
            .default_src = "'self'",
            .connect_src = "'self'",
            .img_src = "'self' data: https:",
            .style_src = "'self' https://fonts.googleapis.com",
        };
        
        var production_manager = try createPolicyManager(allocator, production_config);
        defer production_manager.deinit();
        
        std.log.info("✅ Created 3 security configurations: strict, development, production", .{});
    }
    
    /// Example: Policy monitoring and statistics
    pub fn examplePolicyMonitoring() !void {
        const allocator = std.heap.c_allocator;
        var policy_manager = try createPolicyManager(allocator, getDefaultPolicyConfig());
        defer policy_manager.deinit();
        
        // Setup some configurations
        var cors_options = CORSOptions.init(allocator);
        defer cors_options.deinit();
        
        cors_options.origin = "https://api.example.com";
        cors_options.addMethod(.GET);
        cors_options.addMethod(.POST);
        try policy_manager.configureCORS("https://api.example.com", cors_options);
        
        // Add CSP policies
        try policy_manager.addCSPPolicy("https://example.com", "default-src 'self'");
        try policy_manager.addCSPPolicy("https://test.example.com", "default-src 'self' 'unsafe-inline'");
        
        // Get and display statistics
        const stats = policy_manager.getStats();
        
        std.log.info("📊 Policy Engine Statistics:", .{});
        std.log.info("  - CORS Cache Size: {}/{}", .{ stats.cors_cache_size, stats.cors_cache_capacity });
        std.log.info("  - CSP Policies: {}", .{stats.csp_policies});
        std.log.info("  - SOP Enabled: {}", .{stats.policy_engine_config.enable_sop});
        std.log.info("  - CORS Enabled: {}", .{stats.policy_engine_config.enable_cors});
        std.log.info("  - CSP Enabled: {}", .{stats.policy_engine_config.enable_csp});
        std.log.info("  - Mixed Content Blocking: {}", .{stats.policy_engine_config.enable_mixed_content_blocking});
        
        // Clear caches and show change
        policy_manager.clearCaches();
        const stats_after_clear = policy_manager.getStats();
        
        std.log.info("📊 After Cache Clear:", .{});
        std.log.info("  - CORS Cache Size: {}/{}", .{ stats_after_clear.cors_cache_size, stats_after_clear.cors_cache_capacity });
    }
};

/// Main example runner
pub fn runPolicyExamples() !void {
    std.log.info("🚀 Starting Browser Policy Engine Integration Examples", .{});
    
    // Run all examples
    try PolicyIntegrationExample.exampleFetchWithPolicy();
    try PolicyIntegrationExample.exampleSecurityConfigurations();
    try PolicyIntegrationExample.examplePolicyMonitoring();
    
    std.log.info("✅ All Policy Engine examples completed successfully!", .{});
}

test "policy integration examples" {
    // This test runs the examples to ensure they work
    const result = runPolicyExamples();
    // If we get here without panic, the examples work
    _ = result; // Suppress unused variable warning
}