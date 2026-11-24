//! z_policy - Content Security Policy Validator
//! 
//! Implements Content Security Policy (CSP) validation for browser security.
//! Enforces CSP directives to prevent XSS and other content injection attacks.

const std = @import("std");
const Allocator = std.mem.Allocator;
const StringHashMap = std.StringHashMap;
const ArrayList = std.ArrayList;
const AutoHashMap = std.AutoHashMap;
const policy_engine = @import("policy_engine.zig");

pub const Origin = policy_engine.Origin;
pub const ContentSecurityPolicy = policy_engine.ContentSecurityPolicy;
pub const CSPDirective = policy_engine.CSPDirective;
pub const PolicyEngineConfig = policy_engine.PolicyEngineConfig;
pub const ValidationResult = policy_engine.ValidationResult;
pub const CSPTokenType = policy_engine.CSPTokenType;
pub const CSPToken = policy_engine.CSPToken;
pub const CSPDirectiveRule = CSPDirective;
pub const OriginHashMap = policy_engine.OriginHashMap;

pub const CSPViolation = struct {
    directive: []const u8,
    blocked_uri: []const u8,
    violated_directive: []const u8,
    original_policy: []const u8,
    source_file: ?[]const u8 = null,
    line_number: ?usize = null,
    column_number: ?usize = null,
    
    pub fn init(directive: []const u8, blocked_uri: []const u8, policy: []const u8) CSPViolation {
        return CSPViolation{
            .directive = directive,
            .blocked_uri = blocked_uri,
            .violated_directive = directive,
            .original_policy = policy,
        };
    }
};

pub const CSPValidationContext = struct {
    resource_url: []const u8,
    resource_type: []const u8,
    script_nonce: ?[]const u8,
    script_hash: ?[]const u8,
    document_url: []const u8,
    parent_url: ?[]const u8 = null,
    
    pub fn init(resource_url: []const u8, resource_type: []const u8, document_url: []const u8) CSPValidationContext {
        return CSPValidationContext{
            .resource_url = resource_url,
            .resource_type = resource_type,
            .script_nonce = null,
            .script_hash = null,
            .document_url = document_url,
            .parent_url = null,
        };
    }
};

pub const CSPValidationResult = struct {
    allowed: bool,
    reason: []const u8,
    violation: ?CSPViolation,
    
    pub fn initAllowed(reason: []const u8) CSPValidationResult {
        return CSPValidationResult{
            .allowed = true,
            .reason = reason,
            .violation = null,
        };
    }
    
    pub fn initBlocked(reason: []const u8, violation: CSPViolation) CSPValidationResult {
        return CSPValidationResult{
            .allowed = false,
            .reason = reason,
            .violation = violation,
        };
    }
};

/// CSP Validator - Core Implementation
pub const CSPValidator = struct {
    allocator: Allocator,
    policies: OriginHashMap(ContentSecurityPolicy),
    nonce_cache: StringHashMap(bool),
    hash_cache: StringHashMap(bool),
    
    pub fn init(allocator: Allocator) CSPValidator {
        return CSPValidator{
            .allocator = allocator,
            .policies = OriginHashMap(ContentSecurityPolicy).init(allocator),
            .nonce_cache = StringHashMap(bool).init(allocator),
            .hash_cache = StringHashMap(bool).init(allocator),
        };
    }
    
    pub fn deinit(self: *CSPValidator) void {
        var policy_iter = self.policies.valueIterator();
        while (policy_iter.next()) |policy| {
            policy.deinit();
        }
        self.policies.deinit();
        self.nonce_cache.deinit();
        self.hash_cache.deinit();
    }
    
    /// Validate resource against CSP
    pub fn validateResource(self: *CSPValidator, context: CSPValidationContext) !CSPValidationResult {
        const origin = try Origin.parse(context.document_url);
        
        // Get CSP policy for document origin
        var policy = self.policies.get(origin) orelse {
            // No CSP policy, allow by default
            return CSPValidationResult.initAllowed("No CSP policy defined");
        };
        
        // Find appropriate directive
        const directive_name = self.getDirectiveForResourceType(context.resource_type);
        const directive = self.findDirective(&policy, directive_name);
        
        if (directive == null) {
            // No directive found, check default-src
            const default_directive = self.findDirective(&policy, "default-src");
            if (default_directive) |default_src| {
                return self.validateAgainstDirective(default_src.*, context);
            } else {
                // No restrictions
                return CSPValidationResult.initAllowed("No CSP restrictions");
            }
        }
        
        return self.validateAgainstDirective(directive.?.*, context);
    }
    
    /// Validate inline script
    pub fn validateInlineScript(self: *CSPValidator, script_content: []const u8, context: CSPValidationContext) !CSPValidationResult {
        const origin = try Origin.parse(context.document_url);
        var policy = self.policies.get(origin) orelse {
            return CSPValidationResult.initAllowed("No CSP policy defined");
        };
        
        // Check script-src directive
        const script_directive = self.findDirective(&policy, "script-src");
        if (script_directive) |directive| {
            // Check for 'unsafe-inline'
            if (directive.allow_unsafe_inline) {
                return CSPValidationResult.initAllowed("unsafe-inline allowed");
            }
            
            // Check for nonce
            if (context.script_nonce) |nonce| {
                if (self.isNonceValid(nonce)) {
                    return CSPValidationResult.initAllowed("Valid nonce");
                }
            }
            
            // Check for hash
            if (context.script_hash) |hash| {
                const computed_hash = self.computeContentHash(script_content);
                if (std.mem.eql(u8, hash, computed_hash)) {
                    return CSPValidationResult.initAllowed("Valid hash");
                }
            }
            
            // Violation
            const violation = CSPViolation.init("script-src", "<inline>", "");
            return CSPValidationResult.initBlocked("Inline script blocked by CSP", violation);
        }
        
        // Check default-src
        const default_directive = self.findDirective(&policy, "default-src");
        if (default_directive) |default_src| {
            if (default_src.allow_unsafe_inline) {
                return CSPValidationResult.initAllowed("unsafe-inline allowed by default-src");
            }
        }
        
        // No unsafe-inline allowed
        const violation = CSPViolation.init("script-src", "<inline>", "");
        return CSPValidationResult.initBlocked("Inline script blocked by CSP", violation);
    }
    
    /// Parse CSP header value
    pub fn parseCSPHeader(self: *CSPValidator, header_value: []const u8, origin: Origin) !ContentSecurityPolicy {
        var policy = ContentSecurityPolicy.init(self.allocator);
        var directives_iter = std.mem.splitScalar(u8, header_value, ';');
        
        while (directives_iter.next()) |directive_str| {
            const trimmed = std.mem.trim(u8, directive_str, " \t\r\n");
            if (trimmed.len == 0) continue;
            
            var directive = CSPDirectiveRule.init(self.allocator);
            errdefer directive.deinit(self.allocator);
            
            try self.parseDirective(trimmed, &directive);
            policy.directives.append(self.allocator, directive) catch {
                directive.deinit(self.allocator);
            };
        }
        
        try self.policies.put(origin, policy);
        return policy;
    }
    
    /// Add CSP policy for origin
    pub fn addPolicy(self: *CSPValidator, origin: Origin, policy: ContentSecurityPolicy) !void {
        try self.policies.put(origin, policy);
    }
    
    /// Remove CSP policy for origin
    pub fn removePolicy(self: *CSPValidator, origin: Origin) void {
        const removed = self.policies.remove(origin);
        if (removed) |policy| {
            policy.deinit();
        }
    }
    
    /// Generate CSP report
    pub fn generateReport(self: *CSPValidator, violation: CSPViolation) StringHashMap([]const u8) {
        var report = StringHashMap([]const u8).init(self.allocator);
        
        report.put("document-uri", violation.source_file orelse "") catch {};
        report.put("violated-directive", violation.violated_directive) catch {};
        report.put("blocked-uri", violation.blocked_uri) catch {};
        report.put("original-policy", violation.original_policy) catch {};
        report.put("disposition", "enforce") catch {};
        
        if (violation.line_number) |line| {
            const line_str = std.fmt.allocPrint(self.allocator, "{}", .{line}) catch "";
            report.put("line-number", line_str) catch {};
        }
        
        if (violation.column_number) |col| {
            const col_str = std.fmt.allocPrint(self.allocator, "{}", .{col}) catch "";
            report.put("column-number", col_str) catch {};
        }
        
        return report;
    }
    
    // Private helper functions
    fn validateAgainstDirective(self: *CSPValidator, directive: CSPDirectiveRule, context: CSPValidationContext) CSPValidationResult {
        const resource_origin = Origin.parse(context.resource_url) catch {
            return CSPValidationResult.initAllowed("Invalid resource URL");
        };
        
        // Check allow_self
        if (directive.allow_self) {
            const doc_origin = Origin.parse(context.document_url) catch {
                return CSPValidationResult.initAllowed("Invalid document URL");
            };
            
            if (resource_origin.isSameOrigin(doc_origin)) {
                return CSPValidationResult.initAllowed("Self origin allowed");
            }
        }
        
        // Check each source
        for (directive.sources.items) |source| {
            if (self.matchSource(source, resource_origin, context)) {
                return CSPValidationResult.initAllowed("Source matched");
            }
        }
        
        // No sources matched
        const violation = CSPViolation.init(directive.directive, context.resource_url, "");
        return CSPValidationResult.initBlocked("No CSP sources matched", violation);
    }
    
    fn matchSource(self: *CSPValidator, source: CSPToken, resource_origin: Origin, context: CSPValidationContext) bool {
        switch (source.token_type) {
            .SELF_KEYWORD => {
                const doc_origin = Origin.parse(context.document_url) catch return false;
                return resource_origin.isSameOrigin(doc_origin);
            },
            .HOST_SOURCE => {
                return self.matchHostSource(source.value, resource_origin);
            },
            .SCHEME_SOURCE => {
                return std.mem.eql(u8, source.value, resource_origin.scheme);
            },
            .NONE_KEYWORD => {
                return false; // Never match
            },
            .NONCE => {
                if (context.script_nonce) |nonce| {
                    return std.mem.eql(u8, source.value, nonce);
                }
                return false;
            },
            .HASH => {
                // Would need to compute hash of content
                return false;
            },
            else => {
                // Handle other token types
                return false;
            }
        }
    }
    
    fn matchHostSource(self: *CSPValidator, host_source: []const u8, resource_origin: Origin) bool {
        _ = self;
        // Handle wildcards
        if (std.mem.indexOf(u8, host_source, "*") != null) {
            // Basic wildcard matching
            if (host_source.len >= 2 and host_source[0] == '*') {
                // *.example.com matches subdomains
                if (host_source.len > 2 and host_source[1] == '.') {
                    const domain = host_source[2..];
                    return std.mem.endsWith(u8, resource_origin.host, domain);
                }
            }
        }
        
        // Exact match
        return std.mem.eql(u8, host_source, resource_origin.host);
    }
    
    fn getDirectiveForResourceType(self: *CSPValidator, resource_type: []const u8) []const u8 {
        _ = self;
        if (std.mem.eql(u8, resource_type, "script")) return "script-src";
        if (std.mem.eql(u8, resource_type, "style")) return "style-src";
        if (std.mem.eql(u8, resource_type, "img")) return "img-src";
        if (std.mem.eql(u8, resource_type, "font")) return "font-src";
        if (std.mem.eql(u8, resource_type, "media")) return "media-src";
        if (std.mem.eql(u8, resource_type, "connect")) return "connect-src";
        if (std.mem.eql(u8, resource_type, "frame")) return "frame-src";
        if (std.mem.eql(u8, resource_type, "object")) return "object-src";
        if (std.mem.eql(u8, resource_type, "worker")) return "worker-src";
        return "default-src";
    }
    
    fn findDirective(self: *CSPValidator, policy: *ContentSecurityPolicy, directive_name: []const u8) ?*CSPDirectiveRule {
        _ = self;
        for (policy.directives.items) |*directive| {
            if (std.mem.eql(u8, directive.directive, directive_name)) {
                return directive;
            }
        }
        return null;
    }
    
    fn parseDirective(self: *CSPValidator, directive_str: []const u8, directive: *CSPDirectiveRule) !void {
        // Split directive name and sources
        const first_space = std.mem.indexOf(u8, directive_str, " ") orelse directive_str.len;
        directive.directive = directive_str[0..first_space];
        
        if (first_space < directive_str.len) {
            const sources_str = directive_str[first_space + 1 ..];
            var sources_iter = std.mem.splitScalar(u8, sources_str, ' ');
            
            while (sources_iter.next()) |source_str| {
                const trimmed = std.mem.trim(u8, source_str, " \t");
                if (trimmed.len == 0) continue;
                
                const token = try self.parseSourceToken(trimmed);
                if (token.token_type == .SELF_KEYWORD) directive.allow_self = true;
                if (token.token_type == .UNSAFE_INLINE_KEYWORD) directive.allow_unsafe_inline = true;
                if (token.token_type == .UNSAFE_EVAL_KEYWORD) directive.allow_unsafe_eval = true;
                directive.sources.append(self.allocator, token) catch {};
            }
        }
    }
    
    fn parseSourceToken(self: *CSPValidator, source_str: []const u8) !CSPToken {
        _ = self;
        // Handle keywords
        if (std.mem.eql(u8, source_str, "'self'")) {
            return CSPToken.init(.SELF_KEYWORD, source_str, true);
        }
        if (std.mem.eql(u8, source_str, "'unsafe-inline'")) {
            return CSPToken.init(.UNSAFE_INLINE_KEYWORD, source_str, true);
        }
        if (std.mem.eql(u8, source_str, "'unsafe-eval'")) {
            return CSPToken.init(.UNSAFE_EVAL_KEYWORD, source_str, true);
        }
        if (std.mem.eql(u8, source_str, "'none'")) {
            return CSPToken.init(.NONE_KEYWORD, source_str, true);
        }
        
        // Handle nonces and hashes
        if (std.mem.startsWith(u8, source_str, "'nonce-")) {
            const nonce_value = source_str[7..source_str.len - 1]; // Remove 'nonce-' and closing '
            return CSPToken.init(.NONCE, nonce_value, false);
        }
        
        if (std.mem.startsWith(u8, source_str, "'sha")) {
            // SHA hashes: 'sha256-...', 'sha384-...', 'sha512-...'
            return CSPToken.init(.HASH, source_str, false);
        }
        
        // Handle schemes
        if (std.mem.indexOf(u8, source_str, "://") != null) {
            return CSPToken.init(.SCHEME_SOURCE, source_str, false);
        }
        
        // Handle host sources
        return CSPToken.init(.HOST_SOURCE, source_str, false);
    }
    
    fn isNonceValid(self: *CSPValidator, nonce: []const u8) bool {
        return self.nonce_cache.get(nonce) orelse false;
    }
    
    fn computeContentHash(self: *CSPValidator, content: []const u8) []const u8 {
        // Basic hash computation - would use proper crypto hash in production
        var hasher = std.hash.Wyhash.init(0);
        hasher.update(content);
        const hash = hasher.final();
        
        const hash_str = std.fmt.allocPrint(self.allocator, "{x}", .{hash}) catch "";
        return hash_str;
    }
    
    /// Clear nonce cache
    pub fn clearNonceCache(self: *CSPValidator) void {
        self.nonce_cache.clearRetainingCapacity();
    }
    
    /// Clear hash cache
    pub fn clearHashCache(self: *CSPValidator) void {
        self.hash_cache.clearRetainingCapacity();
    }
    
    /// Get statistics
    pub fn getStats(self: *CSPValidator) struct { policy_count: usize, nonce_cache_size: usize, hash_cache_size: usize } {
        return .{
            .policy_count = self.policies.count(),
            .nonce_cache_size = self.nonce_cache.capacity(),
            .hash_cache_size = self.hash_cache.capacity(),
        };
    }
};

test "csp token parsing" {
    const allocator = std.testing.allocator;
    var validator = CSPValidator.init(allocator);
    defer validator.deinit();
    
    const token = try validator.parseSourceToken("'self'");
    try std.testing.expectEqual(CSPTokenType.SELF_KEYWORD, token.token_type);
    try std.testing.expect(token.is_keyword);
    
    const host_token = try validator.parseSourceToken("example.com");
    try std.testing.expectEqual(CSPTokenType.HOST_SOURCE, host_token.token_type);
    try std.testing.expect(!host_token.is_keyword);
}

test "csp directive validation" {
    const allocator = std.testing.allocator;
    var validator = CSPValidator.init(allocator);
    defer validator.deinit();
    
    // Create test context
    const context = CSPValidationContext.init("https://example.com/script.js", "script", "https://example.com/page.html");
    
    // Test with no policy (should allow)
    const result = validator.validateResource(context) catch {
        try std.testing.expect(false);
        return;
    };
    
    try std.testing.expect(result.allowed);
}