//! Security Module Example
//! Demonstrates usage of Certificate Transparency, OCSP Stapling, HSTS Preload, 
//! Privacy DNS, and Security Headers

const std = @import("std");
const z_security = @import("z_security");
const http = @import("z_http");
const dns = @import("z_dns");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{ .safety = true }){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.log.info("=== z-net Networking Stack Security Module Demo ===", .{});

    // Demo 1: Security Manager Setup
    try demoSecurityManager(allocator);

    // Demo 2: Certificate Transparency
    try demoCertificateTransparency(allocator);

    // Demo 3: OCSP Stapling
    try demoOcspStapling(allocator);

    // Demo 4: HSTS Preload
    try demoHstsPreload(allocator);

    // Demo 5: Security Headers
    try demoSecurityHeaders(allocator);

    // Demo 6: Security Validation
    try demoSecurityValidation(allocator);

    std.log.info("Security module demo completed successfully!", .{});
}

fn demoSecurityManager(allocator: std.mem.Allocator) !void {
    std.log.info("\n--- Demo 1: Security Manager Setup ---", .{});

    // Create basic security configuration
    var config = z_security.SecurityConfig.init();
    config.enable_certificate_transparency = true;
    config.enable_ocsp_stapling = true;
    config.enable_hsts_preload = true;
    config.enable_privacy_dns = true;
    config.enable_security_headers = true;

    // Initialize security manager
    var security_manager = try z_security.SecurityManager.init(allocator, config);
    defer security_manager.cleanup();

    // Get security status
    const status = security_manager.getSecurityStatus();
    std.log.info("Security Status - CT: {}, OCSP: {}, HSTS: {}, DNS: {}, Headers: {}, Level: {s}", .{
        status.ct_enabled, status.ocsp_enabled, status.hsts_enabled,
        status.privacy_dns_enabled, status.security_headers_enabled, status.security_level
    });

    // Apply security level
    try security_manager.applySecurityLevel(.moderate);
    const updated_status = security_manager.getSecurityStatus();
    std.log.info("Updated security level applied - Score: {}/100", .{updated_status.overall_score});
}

fn demoCertificateTransparency(allocator: std.mem.Allocator) !void {
    std.log.info("\n--- Demo 2: Certificate Transparency ---", .{});

    // Create mock HTTP client
    const http_client = http.HttpClient.init(allocator);

    // Initialize CT validator
    var ct_validator = z_security.certificate_transparency.CtValidator.init(allocator, &http_client);
    defer ct_validator.deinit();

    // Simulate certificate validation
    const mock_cert_der: []const u8 = "mock_certificate_der_data";
    const mock_scts = [_][]const u8{ "mock_sct_data_1", "mock_sct_data_2" };

    // This would normally validate against real CT logs
    std.log.info("Certificate Transparency validation configured", .{});
    std.log.info("Known CT logs loaded: Let's Encrypt, Cloudflare, Google", .{});

    // Get certificate transparency status
    const status = ct_validator.getCertificateTransparencyStatus(mock_cert_der, &mock_scts);
    std.log.info("CT Status - In valid logs: {}, Validation passed: {}, Valid SCTs: {}/{}", .{
        status.in_valid_logs, status.validation_passed, status.valid_scts, status.total_scts
    });
}

fn demoOcspStapling(allocator: std.mem.Allocator) !void {
    std.log.info("\n--- Demo 3: OCSP Stapling ---", .{});

    // Create OCSP stapling manager
    const http_client = http.HttpClient.init(allocator);
    var ocsp_manager = z_security.OcspStaplingManager.init(allocator, http_client);
    defer ocsp_manager.close();

    // Check certificate status
    const mock_cert: []const u8 = "mock_certificate_data";
    const status = ocsp_manager.check_certificate_status(mock_cert);
    
    std.log.info("OCSP Certificate Status: {}", .{ @tagName(status) });

    // Get OCSP status info
    const status_info = ocsp_manager.get_ocsp_status_info("example.com", mock_cert);
    std.log.info("OCSP Status Info: {}", .{status_info});

    // Configure OCSP settings
    ocsp_manager.set_cache_ttl(3600); // 1 hour cache
    ocsp_manager.set_max_cache_size(1000); // 1000 entries max

    std.log.info("OCSP Stapling configured with 1 hour TTL and 1000 entry cache", .{});
}

fn demoHstsPreload(allocator: std.mem.Allocator) !void {
    std.log.info("\n--- Demo 4: HSTS Preload ---", .{});

    // Initialize HSTS components
    var preload_manager = z_security.hsts_preload.HstsPreloadManager.init(allocator);
    defer preload_manager.deinit();

    const http_client = http.HttpClient.init(allocator);
    var hsts_client = z_security.hsts_preload.HstsHttpClient.init(allocator, &http_client);
    defer hsts_client.deinit();

    // Check if domains are preloaded
    const known_domains = [_][]const u8{
        "google.com", "github.com", "twitter.com", "paypal.com", "stripe.com"
    };

    for (known_domains) |domain| {
        const is_preloaded = preload_manager.isPreloaded(domain);
        if (is_preloaded) {
            std.log.info("Domain {s} is HSTS preloaded", .{domain});
        } else {
            std.log.info("Domain {s} is not HSTS preloaded", .{domain});
        }
    }

    // Get HSTS status for a domain
    const hsts_status = hsts_client.getHstsStatus("google.com");
    std.log.info("Google.com HSTS Status - Force HTTPS: {}, Include SubDomains: {}, Is Preloaded: {}, Max Age: {}", .{
        hsts_status.force_https, hsts_status.include_sub_domains, 
        hsts_status.is_preloaded, hsts_status.policy_max_age
    });
}

fn demoSecurityHeaders(allocator: std.mem.Allocator) !void {
    std.log.info("\n--- Demo 5: Security Headers ---", .{});

    // Initialize security header generator
    var generator = z_security.security_headers.SecurityHeaderGenerator.init(allocator);
    defer generator.deinit();

    // Create security header configuration using the strict profile
    var config = z_security.security_headers.SecurityProfiles.strict;
    defer config.deinit();

    // Generate security headers
    const headers = try generator.generateHeaders(config);
    defer {
        for (headers) |header| {
            allocator.free(header.name);
            allocator.free(header.value);
        }
        allocator.free(headers);
    }

    std.log.info("Generated {} security headers:", .{headers.len});
    for (headers) |header| {
        std.log.info("  {s}: {s}", .{ header.name, header.value });
    }

    // Test header validation
    try generator.validateHeader(.x_content_type_options, "nosniff");
    std.log.info("Header validation test passed", .{});

    // Generate default CSP
    const default_csp = try generator.generateDefaultCsp("https://example.com");
    defer default_csp.deinit();

    const csp_header = default_csp.generateHeaderValue();
    defer allocator.free(csp_header);
    
    std.log.info("Generated default CSP: {s}", .{csp_header});
}

fn demoSecurityValidation(allocator: std.mem.Allocator) !void {
    std.log.info("\n--- Demo 6: Security Validation ---", .{});

    // Initialize security validator
    var validator = z_security.SecurityValidator.init(allocator);
    defer validator.deinit();

    // Test minimal security configuration
    var minimal_config = z_security.SecurityConfig.init();
    minimal_config.enable_certificate_transparency = false;
    minimal_config.enable_ocsp_stapling = false;
    minimal_config.enable_hsts_preload = false;
    minimal_config.enable_privacy_dns = false;
    minimal_config.enable_security_headers = true;

    const minimal_validation = try validator.validateSecuritySetup(minimal_config);
    std.log.info("Minimal Config Validation - Valid: {}, Score: {}/100", .{
        minimal_validation.valid, minimal_validation.score
    });

    // Test high security configuration
    var high_security_config = z_security.SecuritySetup.getHighSecurityConfig();
    const high_security_validation = try validator.validateSecuritySetup(high_security_config);
    std.log.info("High Security Config Validation - Valid: {}, Score: {}/100", .{
        high_security_validation.valid, high_security_validation.score
    });

    // Initialize security auditor
    var auditor = z_security.SecurityAuditor.init(allocator);
    defer auditor.deinit();

    // Create a mock security manager for the auditor
    var mock_manager = z_security.SecurityManager.init(allocator, high_security_config) catch unreachable;
    auditor.setSecurityManager(&mock_manager);

    // Generate security report
    const report = try auditor.generateSecurityReport();
    defer allocator.free(report);
    
    std.log.info("Security Audit Report:\n{s}", .{report});

    // Cleanup
    mock_manager.cleanup();
}

// Helper function to demonstrate privacy DNS (note: this is in Mojo, so we'll simulate)
fn demoPrivacyDns(allocator: std.mem.Allocator) !void {
    std.log.info("\n--- Demo 7: Privacy DNS ---", .{});

    std.log.info("Privacy DNS features configured:", .{});
    std.log.info("  - DNS over HTTPS v3 (DoH3)", .{});
    std.log.info("  - DNS over TLS v1.2 (DoT)", .{});
    std.log.info("  - Encrypted Client Hello (ECH)", .{});
    std.log.info("  - Response caching", .{});
    std.log.info("  - Multiple resolver support", .{});

    std.log.info("Supported DNS providers:", .{});
    std.log.info("  - Cloudflare (1.1.1.1)", .{});
    std.log.info("  - Quad9 (9.9.9.9)", .{});
    std.log.info("  - Google (8.8.8.8)", .{});
    std.log.info("  - Custom DoH/DoT endpoints", .{});
}

// Additional demo function for security middleware integration
fn demoSecurityMiddleware(allocator: std.mem.Allocator) !void {
    std.log.info("\n--- Demo 8: Security Middleware ---", .{});

    // Create security headers middleware with moderate profile
    var config = z_security.security_headers.SecurityProfiles.moderate;
    defer config.deinit();

    var middleware = z_security.security_headers.SecurityHeadersMiddleware.init(allocator, config);
    defer middleware.deinit();

    // Get security report
    const report = middleware.getSecurityReport();
    std.log.info("Security Middleware Report:", .{});
    std.log.info("  CSP Enabled: {}", .{report.csp_enabled});
    std.log.info("  HSTS Enabled: {}", .{report.hsts_enabled});
    std.log.info("  X-Frame-Options Enabled: {}", .{report.xfo_enabled});
    std.log.info("  X-Content-Type-Options Enabled: {}", .{report.xcto_enabled});
    std.log.info("  X-XSS-Protection Enabled: {}", .{report.xss_enabled});
    std.log.info("  Total Headers: {}", .{report.total_headers});

    // Enable validation
    middleware.enableValidation(true);
    std.log.info("Header validation enabled", .{});
}
