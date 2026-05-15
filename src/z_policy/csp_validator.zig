//! z_policy - Content Security Policy Validator
//! 
//! Implements Content Security Policy (CSP) validation for browser security.
//! Enforces CSP directives to prevent XSS and other content injection attacks.

const std = @import("std");
const Allocator = std.mem.Allocator;
const StringHashMap = std.StringHashMap;
const ArrayList = std.ArrayList;
const AutoHashMap = std.AutoHashMap;
const policy_engine = @import("policy_engine");

usingnamespace policy_engine;

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

pub const CSPDirectiveRule = struct {
    directive: []const u8,
    sources: ArrayList(CSPToken),
    allow_self: bool,
    allow_unsafe_inline: bool,
    allow_unsafe_eval: bool,
    require_nonce: bool,
    require_hash: bool,
    
    pub fn init(allocator: Allocator) CSPDirectiveRule {
        return CSPDirectiveRule{
            .directive = "",
            .sources = ArrayList(CSPToken).init(allocator),
            .allow_self = false,
            .allow_unsafe_inline = false,
            .allow_unsafe_eval = false,
            .require_nonce = false,
            .require_hash = false,
        };
    }
    
    pub fn deinit(self: *CSPDirectiveRule) void {
        self.sources.deinit();
    }
};

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
    
    pub fn allowed(reason: []const u8) CSPValidationResult {
        return CSPValidationResult{
            .allowed = true,
            .reason = reason,
            .violation = null,
        };
    }
    
    pub fn blocked(reason: []const u8, violation: CSPViolation) CSPValidationResult {
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
    policies: AutoHashMap(Origin, ContentSecurityPolicy),
    nonce_cache: AutoHashMap([]const u8, bool),
    hash_cache: AutoHashMap([]const u8, bool),
    
    pub fn init(allocator: Allocator) CSPValidator {
        return CSPValidator{
            .allocator = allocator,
            .policies = AutoHashMap(Origin, ContentSecurityPolicy).init(allocator),
            .nonce_cache = AutoHashMap([]const u8, bool).init(allocator),
            .hash_cache = AutoHashMap([]const u8, bool).init(allocator),
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
        const policy = self.policies.get(origin) orelse {
            // No CSP policy, allow by default
            return CSPValidationResult.allowed("No CSP policy defined");
        };
        
        // Find appropriate directive
        const directive_name = self.getDirectiveForResourceType(context.resource_type);
        const directive = self.findDirective(policy, directive_name);
        
        if (directive == null) {
            // No directive found, check default-src
            const default_directive = self.findDirective(policy, "default-src");
            if (default_directive) |default_src| {
                return self.validateAgainstDirective(default_src, context);
            } else {
                // No restrictions
                return CSPValidationResult.allowed("No CSP restrictions");
            }
        }
        
        return self.validateAgainstDirective(directive.?, context);
    }
    
    /// Validate inline script
    pub fn validateInlineScript(self: *CSPValidator, script_content: []const u8, context: CSPValidationContext) !CSPValidationResult {
        const origin = try Origin.parse(context.document_url);
        const policy = self.policies.get(origin) orelse {
            return CSPValidationResult.allowed("No CSP policy defined");
        };
        
        // Check script-src directive
        const script_directive = self.findDirective(policy, "script-src");
        if (script_directive) |directive| {
            // Check for 'unsafe-inline'
            if (directive.allow_unsafe_inline) {
                return CSPValidationResult.allowed("unsafe-inline allowed");
            }
            
            // Check for nonce
            if (context.script_nonce) |nonce| {
                if (self.isNonceValid(nonce)) {
                    return CSPValidationResult.allowed("Valid nonce");
                }
            }
            
            // Check for hash
            if (context.script_hash) |hash| {
                const computed_hash = self.computeContentHash(script_content);
                if (std.mem.eql(u8, hash, computed_hash)) {
                    return CSPValidationResult.allowed("Valid hash");
                }
            }
            
            // Violation
            const violation = CSPViolation.init("script-src", "<inline>", policy);
            return CSPValidationResult.blocked("Inline script blocked by CSP", violation);
        }
        
        // Check default-src
        const default_directive = self.findDirective(policy, "default-src");
        if (default_directive) |default_src| {
            if (default_src.allow_unsafe_inline) {
                return CSPValidationResult.allowed("unsafe-inline allowed by default-src");
            }
        }
        
        // No unsafe-inline allowed
        const violation = CSPViolation.init("script-src", "<inline>", policy);
        return CSPValidationResult.blocked("Inline script blocked by CSP", violation);
    }
    
    /// Parse CSP header value
    pub fn parseCSPHeader(self: *CSPValidator, header_value: []const u8, origin: Origin) !ContentSecurityPolicy {
        var policy = ContentSecurityPolicy.init(self.allocator);
        var directives_iter = std.mem.split(u8, header_value, ";");
        
        while (directives_iter.next()) |directive_str| {
            const trimmed = std.mem.trim(u8, directive_str, " \t\r\n");
            if (trimmed.len == 0) continue;
            
            var directive = CSPDirectiveRule.init(self.allocator);
            defer directive.deinit();
            
            try self.parseDirective(trimmed, &directive);
            policy.directives.append(directive) catch {};
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
            return CSPValidationResult.allowed("Invalid resource URL");
        };
        
        // Check allow_self
        if (directive.allow_self) {
            const doc_origin = Origin.parse(context.document_url) catch {
                return CSPValidationResult.allowed("Invalid document URL");
            };
            
            if (resource_origin.isSameOrigin(doc_origin)) {
                return CSPValidationResult.allowed("Self origin allowed");
            }
        }
        
        // Check each source
        for (directive.sources.items) |source| {
            if (self.matchSource(source, resource_origin, context)) {
                return CSPValidationResult.allowed("Source matched");
            }
        }
        
        // No sources matched
        const violation = CSPViolation.init(directive.directive, context.resource_url, "");
        return CSPValidationResult.blocked("No CSP sources matched", violation);
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
        // Map resource types to CSP directives
        const directive_map = std.ComptimeStringMap([]const u8, .{
            .{ "script", "script-src" },
            .{ "style", "style-src" },
            .{ "img", "img-src" },
            .{ "font", "font-src" },
            .{ "media", "media-src" },
            .{ "connect", "connect-src" },
            .{ "frame", "frame-src" },
            .{ "object", "object-src" },
            .{ "worker", "worker-src" },
        });
        
        return directive_map.get(resource_type) orelse "default-src";
    }
    
    fn findDirective(self: *CSPValidator, policy: *ContentSecurityPolicy, directive_name: []const u8) ?*CSPDirectiveRule {
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
            var sources_iter = std.mem.split(u8, sources_str, " ");
            
            while (sources_iter.next()) |source_str| {
                const trimmed = std.mem.trim(u8, source_str, " \t");
                if (trimmed.len == 0) continue;
                
                const token = try self.parseSourceToken(trimmed);
                directive.sources.append(token) catch {};
            }
        }
    }
    
    fn parseSourceToken(self: *CSPValidator, source_str: []const u8) !CSPToken {
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
        self.nonce_cache.clear();
    }
    
    /// Clear hash cache
    pub fn clearHashCache(self: *CSPValidator) void {
        self.hash_cache.clear();
    }
    
    /// Get statistics
    pub fn getStats(self: *CSPValidator) struct { policy_count: usize, nonce_cache_size: usize, hash_cache_size: usize } {
        return .{
            .policy_count = self.policies.count(),
            .nonce_cache_size = self.nonce_cache.estimated_capacity,
            .hash_cache_size = self.hash_cache.estimated_capacity,
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
    var context = CSPValidationContext.init("https://example.com/script.js", "script", "https://example.com/page.html");
    
    // Test with no policy (should allow)
    const result = validator.validateResource(context) catch {
        try std.testing.expect(false);
        return;
    };
    
    try std.testing.expect(result.allowed);
}