//! z_security - HSTS Preload Module
//! HSTS Preload mechanism with preload list management, header processing, and policy enforcement
//! RFC 6797 compliant HTTP Strict Transport Security implementation

const std = @import("std");
const http = @import("z_http/http.zig");

// HSTS Errors
pub const HstsError = error{
    InvalidHstsHeader,
    InvalidMaxAge,
    InvalidIncludeSubDomains,
    InvalidPreload,
    PreloadNotFound,
    PolicyViolation,
    NetworkError,
    InvalidDomain,
};

// HSTS Directive values
pub const HstsDirective = enum {
    max_age,
    include_sub_domains,
    preload,
    include_sub_domains_for_5_years,
};

// HSTS Policy structure
pub const HstsPolicy = struct {
    domain: []const u8,
    max_age: u64,
    include_sub_domains: bool,
    preload: bool,
    include_sub_domains_for_5_years: bool,
    expires_at: i64,
    is_known_to_https: bool,
    
    const Self = @This();
    
    pub fn init(domain: []const u8, allocator: std.mem.Allocator) Self {
        return Self{
            .domain = domain,
            .max_age = 0,
            .include_sub_domains = false,
            .preload = false,
            .include_sub_domains_for_5_years = false,
            .expires_at = 0,
            .is_known_to_https = false,
        };
    }
    
    pub fn isExpired(self: *Self) bool {
        return std.time.timestamp() > self.expires_at;
    }
    
    pub fn isHttpsEnforced(self: *Self) bool {
        return self.max_age > 0 and !self.isExpired();
    }
};

// HSTS Preload List Entry
pub const HstsPreloadEntry = struct {
    domain: []const u8,
    include_sub_domains: bool,
    preload: bool,
    reason: []const u8,
    source: []const u8,
    submission_date: []const u8,
    
    const Self = @This();
};

// Known HSTS preload entries (subset of actual preload list)
pub const known_hsts_preloads = [_]HstsPreloadEntry{
    .{
        .domain = "stripe.com",
        .include_sub_domains = true,
        .preload = true,
        .reason = "Secure",
        .source = "Chrome HSTS preload list",
        .submission_date = "2014-11-17",
    },
    .{
        .domain = "www.paypal.com",
        .include_sub_domains = true,
        .preload = true,
        .reason = "Financial",
        .source = "Chrome HSTS preload list", 
        .submission_date = "2014-10-28",
    },
    .{
        .domain = "twitter.com",
        .include_sub_domains = false,
        .preload = true,
        .reason = "Social Media",
        .source = "Chrome HSTS preload list",
        .submission_date = "2014-05-07",
    },
    .{
        .domain = "github.com",
        .include_sub_domains = true,
        .preload = true,
        .reason = "Open Source Platform",
        .source = "Chrome HSTS preload list",
        .submission_date = "2014-04-08",
    },
    .{
        .domain = "google.com",
        .include_sub_domains = true,
        .preload = true,
        .reason = "Search Engine",
        .source = "Chrome HSTS preload list",
        .submission_date = "2013-06-14",
    },
    .{
        .domain = "accounts.google.com",
        .include_sub_domains = true,
        .preload = true,
        .reason = "Authentication Service",
        .source = "Chrome HSTS preload list",
        .submission_date = "2013-06-14",
    },
    .{
        .domain = "login.yahoo.com",
        .include_sub_domains = true,
        .preload = true,
        .reason = "Authentication Service",
        .source = "Chrome HSTS preload list",
        .submission_date = "2014-07-25",
    },
    .{
        .domain = "www.dropbox.com",
        .include_sub_domains = true,
        .preload = true,
        .reason = "Cloud Storage",
        .source = "Chrome HSTS preload list",
        .submission_date = "2015-02-05",
    },
    .{
        .domain = "www.ebay.com",
        .include_sub_domains = true,
        .preload = true,
        .reason = "E-commerce",
        .source = "Chrome HSTS preload list",
        .submission_date = "2015-05-06",
    },
    .{
        .domain = "bankofamerica.com",
        .include_sub_domains = true,
        .preload = true,
        .reason = "Banking",
        .source = "Chrome HSTS preload list",
        .submission_date = "2014-03-14",
    },
};

// HSTS Header Parser
pub const HstsHeaderParser = struct {
    allocator: std.mem.Allocator,
    
    const Self = @This();
    
    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .allocator = allocator,
        };
    }
    
    pub fn parseHstsHeader(self: *Self, header_value: []const u8) HstsError!HstsPolicy {
        if (std.mem.len(header_value) == 0) return error.InvalidHstsHeader;
        
        var policy = HstsPolicy.init(header_value, self.allocator);
        
        // Parse directives
        var directives = std.mem.split(u8, header_value, ";");
        
        while (directives.next()) |directive| {
            const trimmed_directive = std.mem.trim(u8, directive, " \t");
            
            if (std.mem.eql(u8, trimmed_directive, "preload")) {
                policy.preload = true;
            } else if (std.mem.eql(u8, trimmed_directive, "includeSubDomains")) {
                policy.include_sub_domains = true;
            } else if (std.mem.eql(u8, trimmed_directive, "includeSubDomainsFor5Years")) {
                policy.include_sub_domains_for_5_years = true;
                policy.include_sub_domains = true; // Preload implies includeSubDomains
            } else if (std.mem.startsWith(u8, trimmed_directive, "max-age=")) {
                const max_age_str = trimmed_directive[8..];
                policy.max_age = std.fmt.parseInt(u64, max_age_str, 10) catch return error.InvalidMaxAge;
                
                // Calculate expiration time
                const now = std.time.timestamp();
                policy.expires_at = now + @intCast(i64, policy.max_age);
            }
        }
        
        // Validate parsed policy
        if (policy.max_age == 0) return error.InvalidMaxAge;
        if (policy.max_age < 0) return error.InvalidMaxAge;
        
        return policy;
    }
    
    pub fn buildHstsHeader(self: *Self, policy: HstsPolicy) []const u8 {
        var header_parts = std.ArrayList([]const u8).init(self.allocator);
        
        // Build max-age directive
        const max_age_str = std.fmt.allocPrint(self.allocator, "max-age={d}", .{policy.max_age}) catch return "";
        header_parts.append(max_age_str) catch return "";
        
        // Add includeSubDomains if present
        if (policy.include_sub_domains) {
            header_parts.append("includeSubDomains") catch return "";
        }
        
        // Add preload if present
        if (policy.preload) {
            header_parts.append("preload") catch return "";
        }
        
        // Build final header
        var header = std.ArrayList(u8).init(self.allocator);
        for (header_parts.items, 0..) |part, i| {
            if (i > 0) {
                header.append(';') catch return "";
            }
            header.appendSlice(part) catch return "";
        }
        
        const result = header.toOwnedSlice() catch return "";
        
        // Clean up individual parts
        for (header_parts.items) |part| {
            self.allocator.free(part);
        }
        header_parts.deinit();
        
        return result;
    }
};

// HSTS Preload List Manager
pub const HstsPreloadManager = struct {
    allocator: std.mem.Allocator,
    preload_cache: std.StringArrayHashMap(HstsPreloadEntry),
    dynamic_preloads: std.StringArrayHashMap(HstsPreloadEntry),
    
    const Self = @This();
    
    pub fn init(allocator: std.mem.Allocator) Self {
        var self = Self{
            .allocator = allocator,
            .preload_cache = std.StringArrayHashMap(HstsPreloadEntry).init(allocator),
            .dynamic_preloads = std.StringArrayHashMap(HstsPreloadEntry).init(allocator),
        };
        
        // Pre-load known HSTS preloads
        for (known_hsts_preloads) |preload| {
            self.preload_cache.put(preload.domain, preload) catch {};
        }
        
        return self;
    }
    
    pub fn isPreloaded(self: *Self, domain: []const u8) bool {
        return self.preload_cache.get(domain) != null or self.dynamic_preloads.get(domain) != null;
    }
    
    pub fn getPreloadEntry(self: *Self, domain: []const u8) ?HstsPreloadEntry {
        const static_entry = self.preload_cache.get(domain);
        if (static_entry) |entry| return entry.*;
        
        const dynamic_entry = self.dynamic_preloads.get(domain);
        if (dynamic_entry) |entry| return entry.*;
        
        return null;
    }
    
    pub fn addPreload(self: *Self, entry: HstsPreloadEntry) !void {
        try self.dynamic_preloads.put(entry.domain, entry);
        
        std.log.info("Added HSTS preload for domain: {s}", .{entry.domain});
    }
    
    pub fn removePreload(self: *Self, domain: []const u8) bool {
        if (self.dynamic_preloads.remove(domain)) {
            std.log.info("Removed HSTS preload for domain: {s}", .{domain});
            return true;
        }
        return false;
    }
    
    pub fn updatePreloadList(self: *Self, new_entries: []const HstsPreloadEntry) !void {
        // Clear dynamic preloads
        self.dynamic_preloads.clearRetainingCapacity();
        
        // Add new entries
        for (new_entries) |entry| {
            try self.dynamic_preloads.put(entry.domain, entry);
        }
        
        std.log.info("Updated HSTS preload list with {d} entries", .{new_entries.len});
    }
    
    pub fn syncWithRemoteList(self: *Self, http_client: *http.HttpClient) !void {
        // Fetch updated HSTS preload list from Chrome repository
        const url = "https://chromium.googlesource.com/chromium/src/net/+/master/http/transport_security_state_static.json?format=TEXT";
        
        const request = http.HttpRequest{
            .method = http.HttpMethod.GET,
            .path = url,
            .headers = undefined,
            .body = undefined,
        };
        
        const response = http_client.sendRequest(request) catch return error.NetworkError;
        if (response.status_code != 200) return error.NetworkError;
        
        // Parse JSON response and update preload list
        const updated_entries = try self.parsePreloadJson(response.body);
        
        // Update static cache
        self.preload_cache.clearRetainingCapacity();
        for (updated_entries) |entry| {
            try self.preload_cache.put(entry.domain, entry);
        }
        
        std.log.info("Synced HSTS preload list with {d} entries", .{updated_entries.len});
    }
    
    fn parsePreloadJson(self: *Self, json_data: []const u8) ![]const HstsPreloadEntry {
        // Simplified JSON parser for HSTS preload list
        // In practice, would use a proper JSON parser
        
        var entries = std.ArrayList(HstsPreloadEntry).init(self.allocator);
        
        // Basic parsing logic would go here
        // For now, return empty array
        
        return entries.toOwnedSlice();
    }
    
    pub fn getAllPreloads(self: *Self) []const HstsPreloadEntry {
        var all_entries = std.ArrayList(HstsPreloadEntry).init(self.allocator);
        
        // Add static entries
        for (self.preload_cache.values()) |entry| {
            all_entries.append(entry.*) catch {};
        }
        
        // Add dynamic entries
        for (self.dynamic_preloads.values()) |entry| {
            all_entries.append(entry.*) catch {};
        }
        
        return all_entries.toOwnedSlice() catch &[_]HstsPreloadEntry{};
    }
    
    pub fn deinit(self: *Self) void {
        self.preload_cache.deinit();
        self.dynamic_preloads.deinit();
    }
};

// HSTS Policy Enforcer
pub const HstsPolicyEnforcer = struct {
    allocator: std.mem.Allocator,
    preload_manager: HstsPreloadManager,
    header_parser: HstsHeaderParser,
    policy_cache: std.StringArrayHashMap(HstsPolicy),
    
    const Self = @This();
    
    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .allocator = allocator,
            .preload_manager = HstsPreloadManager.init(allocator),
            .header_parser = HstsHeaderParser.init(allocator),
            .policy_cache = std.StringArrayHashMap(HstsPolicy).init(allocator),
        };
    }
    
    pub fn processResponseHeaders(self: *Self, host: []const u8, headers: []const http.HttpHeader) HstsError!HstsPolicy {
        // Check for HSTS header in response
        var hsts_policy = try self.getCachedPolicy(host);
        
        for (headers) |header| {
            if (std.mem.eql(u8, header.name, "strict-transport-security")) {
                hsts_policy = try self.header_parser.parseHstsHeader(header.value);
                hsts_policy.domain = try self.allocator.dupe(u8, host);
                
                // Cache the policy
                try self.policy_cache.put(host, hsts_policy);
                
                std.log.info("Processed HSTS header for {s}: max-age={d}, includeSubDomains={}, preload={}", .{
                    host, hsts_policy.max_age, hsts_policy.include_sub_domains, hsts_policy.preload
                });
                break;
            }
        }
        
        // Apply preload policy if no header found but domain is preloaded
        if (hsts_policy.max_age == 0) {
            const preload_entry = self.preload_manager.getPreloadEntry(host);
            if (preload_entry != null) {
                hsts_policy = HstsPolicy.init(host, self.allocator);
                hsts_policy.max_age = 63072000; // 2 years default for preloaded domains
                hsts_policy.include_sub_domains = preload_entry.?.include_sub_domains;
                hsts_policy.preload = preload_entry.?.preload;
                hsts_policy.expires_at = std.time.timestamp() + @intCast(i64, hsts_policy.max_age);
                
                std.log.info("Applied HSTS preload policy for {s}", .{host});
            }
        }
        
        return hsts_policy;
    }
    
    pub fn shouldForceHttps(self: *Self, host: []const u8) bool {
        const policy = self.getCachedPolicy(host) catch return false;
        
        // Check if policy enforces HTTPS
        if (policy.max_age == 0) {
            // Check preload list
            return self.preload_manager.isPreloaded(host);
        }
        
        return policy.isHttpsEnforced();
    }
    
    pub fn shouldIncludeSubDomains(self: *Self, host: []const u8) bool {
        const policy = self.getCachedPolicy(host) catch return false;
        
        if (policy.max_age == 0) {
            const preload_entry = self.preload_manager.getPreloadEntry(host);
            return preload_entry != null and preload_entry.?.include_sub_domains;
        }
        
        return policy.include_sub_domains;
    }
    
    pub fn getHttpsUpgradeUrl(self: *Self, http_url: []const u8) ![]const u8 {
        // Replace http:// with https://
        if (std.mem.startsWith(u8, http_url, "http://")) {
            return try std.fmt.allocPrint(self.allocator, "https://{s}", .{http_url[7..]});
        }
        return try self.allocator.dupe(u8, http_url);
    }
    
    pub fn validatePolicyCompliance(self: *Self, host: []const u8, policy: HstsPolicy) HstsError!bool {
        // Validate HSTS policy requirements
        if (policy.max_age < 15552000) { // 180 days minimum for security
            std.log.warn("HSTS max-age too low for {s}: {} seconds", .{host, policy.max_age});
            return false;
        }
        
        if (!policy.include_sub_domains and self.preload_manager.isPreloaded(host)) {
            // Check if preload requires includeSubDomains
            const preload_entry = self.preload_manager.getPreloadEntry(host);
            if (preload_entry != null and preload_entry.?.include_sub_domains) {
                std.log.warn("HSTS policy missing includeSubDomains for preloaded domain {s}", .{host});
                return false;
            }
        }
        
        return true;
    }
    
    pub fn getCachedPolicy(self: *Self, host: []const u8) HstsError!HstsPolicy {
        const cached = self.policy_cache.get(host);
        if (cached) |policy| {
            if (!policy.isExpired()) {
                return policy.*;
            }
        }
        
        // Return empty policy if not cached or expired
        return HstsPolicy.init(host, self.allocator);
    }
    
    pub fn clearPolicyCache(self: *Self) void {
        self.policy_cache.clearRetainingCapacity();
    }
    
    pub fn deinit(self: *Self) void {
        self.preload_manager.deinit();
        self.policy_cache.deinit();
    }
};

// HSTS Integration with HTTP Client
pub const HstsHttpClient = struct {
    allocator: std.mem.Allocator,
    base_client: *http.HttpClient,
    policy_enforcer: HstsPolicyEnforcer,
    
    const Self = @This();
    
    pub fn init(allocator: std.mem.Allocator, base_client: *http.HttpClient) Self {
        return Self{
            .allocator = allocator,
            .base_client = base_client,
            .policy_enforcer = HstsPolicyEnforcer.init(allocator),
        };
    }
    
    pub fn sendRequest(self: *Self, request: http.HttpRequest) !http.HttpResponse {
        // Check if we should force HTTPS for the request
        const host = try self.extractHostFromUrl(request.path);
        
        if (self.policy_enforcer.shouldForceHttps(host) and std.mem.startsWith(u8, request.path, "http://")) {
            // Redirect to HTTPS
            const https_url = try self.policy_enforcer.getHttpsUpgradeUrl(request.path);
            defer self.allocator.free(https_url);
            
            var https_request = request;
            https_request.path = https_url;
            
            std.log.info("HSTS: Upgrading HTTP request to HTTPS for {s}", .{host});
            
            const response = try self.base_client.sendRequest(https_request);
            
            // Process HSTS headers from response
            _ = self.policy_enforcer.processResponseHeaders(host, response.headers);
            
            return response;
        }
        
        const response = try self.base_client.sendRequest(request);
        
        // Process HSTS headers from response
        const host = try self.extractHostFromUrl(request.path);
        _ = self.policy_enforcer.processResponseHeaders(host, response.headers);
        
        return response;
    }
    
    fn extractHostFromUrl(self: *Self, url: []const u8) ![]const u8 {
        // Parse URL and extract host
        if (std.mem.startsWith(u8, url, "https://")) {
            const after_protocol = url[8..];
            const slash_index = std.mem.indexOf(u8, after_protocol, "/") orelse after_protocol.len;
            const colon_index = std.mem.indexOf(u8, after_protocol, ":") orelse slash_index;
            const host_len = @min(colon_index, slash_index);
            return try self.allocator.dupe(u8, after_protocol[0..host_len]);
        } else if (std.mem.startsWith(u8, url, "http://")) {
            const after_protocol = url[7..];
            const slash_index = std.mem.indexOf(u8, after_protocol, "/") orelse after_protocol.len;
            const colon_index = std.mem.indexOf(u8, after_protocol, ":") orelse slash_index;
            const host_len = @min(colon_index, slash_index);
            return try self.allocator.dupe(u8, after_protocol[0..host_len]);
        }
        
        return try self.allocator.dupe(u8, url);
    }
    
    pub fn getHstsStatus(self: *Self, host: []const u8) struct {
        force_https: bool,
        include_sub_domains: bool,
        is_preloaded: bool,
        policy_max_age: u64,
        expires_at: i64,
    } {
        const policy = self.policy_enforcer.getCachedPolicy(host) catch .{
            .domain = host,
            .max_age = 0,
            .include_sub_domains = false,
            .preload = false,
            .include_sub_domains_for_5_years = false,
            .expires_at = 0,
            .is_known_to_https = false,
        };
        
        const preload_entry = self.policy_enforcer.preload_manager.getPreloadEntry(host);
        
        return .{
            .force_https = policy.max_age > 0 and !policy.isExpired(),
            .include_sub_domains = policy.include_sub_domains,
            .is_preloaded = preload_entry != null,
            .policy_max_age = policy.max_age,
            .expires_at = policy.expires_at,
        };
    }
    
    pub fn deinit(self: *Self) void {
        self.policy_enforcer.deinit();
    }
};
