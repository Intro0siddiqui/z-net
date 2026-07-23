//! z_service_worker - Scope and Routing
//! 
//! Service Worker scope management, URL routing, and request handling
//! for multi-worker routing and navigation control.

const std = @import("std");
const Allocator = std.mem.Allocator;
const AutoHashMap = std.AutoHashMap;
const StringHashMap = std.StringHashMap;
const ArrayList = std.ArrayList;

const policy_engine = @import("z_policy/policy_engine.zig");
const event_loop = @import("z_event_loop/event_loop.zig");
const storage_bridge = @import("z_storage/storage_bridge.zig");

// usingnamespace policy_engine;
// usingnamespace event_loop;
// usingnamespace storage_bridge;

// Service Worker scope
pub const WorkerScope = struct {
    url: []const u8,
    pattern: []const u8,
    worker: *ServiceWorker,
    priority: ScopePriority,
    max_scope_depth: u8,
    allowed_origins: ArrayList([]const u8),
    restrictions: ScopeRestrictions,
    
    pub const ScopePriority = enum {
        LOW,
        NORMAL,
        HIGH,
        CRITICAL,
    };
    
    pub const ScopeRestrictions = struct {
        require_https: bool,
        allow_subdomains: bool,
        max_url_length: usize,
        allowed_methods: ArrayList([]const u8),
        blocked_paths: ArrayList([]const u8),
        custom_filters: StringHashMap([]const u8),
        
        pub fn init(allocator: Allocator) ScopeRestrictions {
            return ScopeRestrictions{
                .require_https = true,
                .allow_subdomains = false,
                .max_url_length = 2048,
                .allowed_methods = ArrayList([]const u8).init(allocator),
                .blocked_paths = ArrayList([]const u8).init(allocator),
                .custom_filters = StringHashMap([]const u8).init(allocator),
            };
        }
        
        pub fn deinit(self: *ScopeRestrictions) void {
            self.allowed_methods.deinit();
            self.blocked_paths.deinit();
            self.custom_filters.deinit();
        }
    };
    
    pub fn init(allocator: Allocator, url: []const u8, worker: *ServiceWorker, priority: ScopePriority) WorkerScope {
        return WorkerScope{
            .url = url,
            .pattern = generateScopePattern(url),
            .worker = worker,
            .priority = priority,
            .max_scope_depth = calculateMaxScopeDepth(url),
            .allowed_origins = ArrayList([]const u8).init(allocator),
            .restrictions = ScopeRestrictions.init(allocator),
        };
    }
    
    pub fn deinit(self: *WorkerScope) void {
        self.allowed_origins.deinit();
        self.restrictions.deinit();
    }
    
    pub fn matches(self: *WorkerScope, url: []const u8) bool {
        // Check basic scope matching
        if (!urlStartsWith(url, self.url)) {
            return false;
        }
        
        // Check scope depth
        if (calculateDepth(url) > self.max_scope_depth) {
            return false;
        }
        
        // Check restrictions
        if (!self.restrictions.require_https or urlStartsWith(url, "https://")) {
            // Additional restriction checks would go here
        }
        
        return true;
    }
    
    pub fn addAllowedOrigin(self: *WorkerScope, origin: []const u8) !void {
        try self.allowed_origins.append(origin);
    }
    
    pub fn addAllowedMethod(self: *WorkerScope, method: []const u8) !void {
        try self.restrictions.allowed_methods.append(method);
    }
    
    pub fn addBlockedPath(self: *WorkerScope, path: []const u8) !void {
        try self.restrictions.blocked_paths.append(path);
    }
};

// Route entry for request routing
pub const Route = struct {
    pattern: []const u8,
    worker_scope: *WorkerScope,
    handler: RouteHandler,
    priority: RoutePriority,
    match_conditions: MatchConditions,
    route_id: [16]u8,
    
    pub const RoutePriority = enum {
        LOWEST = 0,
        LOW = 1,
        NORMAL = 2,
        HIGH = 3,
        HIGHEST = 4,
        CRITICAL = 5,
    };
    
    pub const MatchConditions = struct {
        exact_match: bool,
        prefix_match: bool,
        regex_match: bool,
        custom_match: fn ([]const u8, []const u8) bool,
        
        pub fn init() MatchConditions {
            return MatchConditions{
                .exact_match = false,
                .prefix_match = true,
                .regex_match = false,
                .custom_match = null,
            };
        }
    };
    
    pub fn init(allocator: Allocator, pattern: []const u8, worker_scope: *WorkerScope, handler: RouteHandler, priority: RoutePriority) Route {
        return Route{
            .pattern = pattern,
            .worker_scope = worker_scope,
            .handler = handler,
            .priority = priority,
            .match_conditions = MatchConditions.init(),
            .route_id = generateRouteId(),
        };
    }
    
    pub fn deinit(self: *Route) void {
        self.worker_scope.deinit();
    }
    
    pub fn matches(self: *Route, url: []const u8, method: []const u8) bool {
        // Check if method is allowed
        for (self.worker_scope.restrictions.allowed_methods.items) |allowed_method| {
            if (std.mem.eql(u8, method, allowed_method)) {
                return true;
            }
        }
        
        // If no methods specified, allow all
        if (self.worker_scope.restrictions.allowed_methods.items.len == 0) {
            return self.matchesPattern(url);
        }
        
        return false;
    }
    
    fn matchesPattern(self: *Route, url: []const u8) bool {
        if (self.match_conditions.exact_match) {
            return std.mem.eql(u8, url, self.pattern);
        } else if (self.match_conditions.prefix_match) {
            return std.mem.indexOf(u8, url, self.pattern) == 0;
        } else if (self.match_conditions.regex_match) {
            // Would implement regex matching here
            return false;
        } else if (self.match_conditions.custom_match) |match_fn| {
            return match_fn(url, self.pattern);
        }
        
        // Default prefix matching
        return std.mem.indexOf(u8, url, self.pattern) == 0;
    }
};

// Route handler function
pub const RouteHandler = fn (Request, *WorkerScope) anyerror!Response;

// Request context for routing
pub const Request = struct {
    url: []const u8,
    method: []const u8,
    headers: StringHashMap([]const u8),
    body: ?ArrayList(u8),
    client_id: [16]u8,
    worker_id: [16]u8,
    
    pub fn init(allocator: Allocator, url: []const u8, method: []const u8, client_id: [16]u8, worker_id: [16]u8) Request {
        return Request{
            .url = url,
            .method = method,
            .headers = StringHashMap([]const u8).init(allocator),
            .body = null,
            .client_id = client_id,
            .worker_id = worker_id,
        };
    }
    
    pub fn deinit(self: *Request) void {
        self.headers.deinit();
        if (self.body) |*body| {
            body.deinit();
        }
    }
};

// Response for routing
pub const Response = struct {
    status: u16,
    status_text: []const u8,
    headers: StringHashMap([]const u8),
    body: ?ArrayList(u8),
    redirected: bool,
    
    pub fn init(allocator: Allocator) Response {
        return Response{
            .status = 200,
            .status_text = "OK",
            .headers = StringHashMap([]const u8).init(allocator),
            .body = null,
            .redirected = false,
        };
    }
    
    pub fn deinit(self: *Response) void {
        self.headers.deinit();
        if (self.body) |*body| {
            body.deinit();
        }
    }
};

// Scope router for managing multiple worker scopes
pub const ScopeRouter = struct {
    allocator: Allocator,
    scopes: AutoHashMap([]const u8, *WorkerScope), // scope_url -> scope
    routes: ArrayList(*Route),
    default_scope: ?*WorkerScope,
    routing_rules: ArrayList(RoutingRule),
    
    pub fn init(allocator: Allocator) ScopeRouter {
        return ScopeRouter{
            .allocator = allocator,
            .scopes = AutoHashMap([]const u8, *WorkerScope).init(allocator),
            .routes = ArrayList(*Route).init(allocator),
            .default_scope = null,
            .routing_rules = ArrayList(RoutingRule).init(allocator),
        };
    }
    
    pub fn deinit(self: *ScopeRouter) void {
        // Clean up scopes
        var iter = self.scopes.valueIterator();
        while (iter.next()) |scope| {
            scope.*.deinit();
            self.allocator.destroy(scope.*);
        }
        self.scopes.deinit();
        
        // Clean up routes
        for (self.routes.items) |route| {
            route.deinit();
            self.allocator.destroy(route);
        }
        self.routes.deinit();
        
        self.routing_rules.deinit();
    }
    
    pub fn addScope(self: *ScopeRouter, scope: *WorkerScope) !void {
        // Add scope to routing table
        try self.scopes.put(scope.url, scope);
        
        // Add default route for this scope
        const route = self.allocator.create(Route) catch |err| {
            return error.RouteCreationFailed;
        };
        route.* = Route.init(self.allocator, scope.pattern, scope, defaultRouteHandler, Route.RoutePriority.NORMAL);
        
        try self.routes.append(route);
    }
    
    pub fn removeScope(self: *ScopeRouter, scope_url: []const u8) !bool {
        if (self.scopes.get(scope_url)) |scope| {
            // Remove associated routes
            var i: usize = 0;
            while (i < self.routes.items.len) {
                if (self.routes.items[i].worker_scope == scope) {
                    const route = self.routes.orderedRemove(i);
                    route.deinit();
                    self.allocator.destroy(route);
                } else {
                    i += 1;
                }
            }
            
            // Remove scope
            _ = self.scopes.remove(scope_url);
            scope.deinit();
            self.allocator.destroy(scope);
            
            return true;
        }
        
        return false;
    }
    
    pub fn routeRequest(self: *ScopeRouter, request: Request) !*WorkerScope {
        // Find matching scope
        var best_match: ?*WorkerScope = null;
        var best_match_length: usize = 0;
        
        var iter = self.scopes.valueIterator();
        while (iter.next()) |scope| {
            if (scope.*.matches(request.url)) {
                const match_length = scope.*.url.len;
                if (match_length > best_match_length) {
                    best_match = scope.*;
                    best_match_length = match_length;
                }
            }
        }
        
        // Return best match or default scope
        if (best_match) |scope| {
            return scope;
        } else if (self.default_scope) |default| {
            return default;
        } else {
            return error.NoMatchingScope;
        }
    }
    
    pub fn getScopeForUrl(self: *ScopeRouter, url: []const u8) ?*WorkerScope {
        var iter = self.scopes.valueIterator();
        while (iter.next()) |scope| {
            if (scope.*.matches(url)) {
                return scope.*;
            }
        }
        return null;
    }
    
    pub fn getAllScopes(self: *ScopeRouter) ArrayList(*WorkerScope) {
        var scopes = ArrayList(*WorkerScope).init(self.allocator);
        
        var iter = self.scopes.valueIterator();
        while (iter.next()) |scope| {
            scopes.append(scope.*) catch {};
        }
        
        return scopes;
    }
    
    pub fn setDefaultScope(self: *ScopeRouter, scope: *WorkerScope) void {
        self.default_scope = scope;
    }
    
    pub fn addRoutingRule(self: *ScopeRouter, rule: RoutingRule) !void {
        try self.routing_rules.append(rule);
    }
    
    pub fn removeRoutingRule(self: *ScopeRouter, rule_id: [16]u8) !bool {
        var i: usize = 0;
        while (i < self.routing_rules.items.len) {
            if (std.mem.eql(u8, &self.routing_rules.items[i].rule_id, &rule_id)) {
                _ = self.routing_rules.orderedRemove(i);
                return true;
            }
            i += 1;
        }
        return false;
    }
    
    pub fn applyRoutingRules(self: *ScopeRouter, request: Request) !*WorkerScope {
        // Apply custom routing rules
        for (self.routing_rules.items) |rule| {
            if (try rule.matches(request)) {
                if (self.scopes.get(rule.target_scope)) |scope| {
                    return scope;
                }
            }
        }
        
        // Fall back to default routing
        return self.routeRequest(request);
    }
};

// Routing rule for custom routing logic
pub const RoutingRule = struct {
    rule_id: [16]u8,
    name: []const u8,
    source_pattern: []const u8,
    target_scope: []const u8,
    conditions: ArrayList(RoutingCondition),
    priority: i8,
    enabled: bool,
    
    pub const RoutingCondition = struct {
        field: []const u8,
        operator: []const u8,
        value: []const u8,
    };
    
    pub fn init(rule_id: [16]u8, name: []const u8, source_pattern: []const u8, target_scope: []const u8, priority: i8) RoutingRule {
        return RoutingRule{
            .rule_id = rule_id,
            .name = name,
            .source_pattern = source_pattern,
            .target_scope = target_scope,
            .conditions = ArrayList(RoutingCondition).init(std.heap.c_allocator),
            .priority = priority,
            .enabled = true,
        };
    }
    
    pub fn deinit(self: *RoutingRule) void {
        self.conditions.deinit();
    }
    
    pub fn matches(self: *RoutingRule, request: Request) !bool {
        // Check source pattern
        if (std.mem.indexOf(u8, request.url, self.source_pattern) != 0) {
            return false;
        }
        
        // Check conditions
        for (self.conditions.items) |condition| {
            if (!self.checkCondition(condition, request)) {
                return false;
            }
        }
        
        return true;
    }
    
    fn checkCondition(self: *RoutingRule, condition: RoutingCondition, request: Request) bool {
        const field_value = self.getFieldValue(condition.field, request);
        
        switch (std.hashString(condition.operator)) {
            std.hashString("equals") => return std.mem.eql(u8, field_value, condition.value),
            std.hashString("contains") => return std.mem.indexOf(u8, field_value, condition.value) != null,
            std.hashString("starts_with") => return std.mem.indexOf(u8, field_value, condition.value) == 0,
            std.hashString("ends_with") => return std.mem.endsWith(field_value, condition.value),
            else => return false,
        }
    }
    
    fn getFieldValue(self: *RoutingRule, field: []const u8, request: Request) []const u8 {
        if (std.mem.eql(u8, field, "url")) {
            return request.url;
        } else if (std.mem.eql(u8, field, "method")) {
            return request.method;
        } else if (self.request.headers.get(field)) |value| {
            return value;
        }
        return "";
    }
};

// Scope conflict resolver
pub const ScopeConflictResolver = struct {
    conflicts: ArrayList(ScopeConflict),
    resolution_strategies: StringHashMap(ConflictResolutionStrategy),
    
    pub const ScopeConflict = struct {
        url: []const u8,
        conflicting_scopes: ArrayList(*WorkerScope),
        conflict_type: ConflictType,
        
        pub const ConflictType = enum {
            OVERLAPPING_SCOPES,
            SAME_PRIORITY_SCOPES,
            DUPLICATE_SCOPES,
        };
    };
    
    pub const ConflictResolutionStrategy = struct {
        strategy_type: StrategyType,
        priority_weight: f32,
        custom_resolver: fn ([]const u8, ArrayList(*WorkerScope)) anyerror!*WorkerScope,
        
        pub const StrategyType = enum {
            PRIORITY_BASED,
            LENGTH_BASED,
            FIRST_REGISTERED,
            LAST_REGISTERED,
            CUSTOM,
        };
    };
    
    pub fn init(allocator: Allocator) ScopeConflictResolver {
        return ScopeConflictResolver{
            .conflicts = ArrayList(ScopeConflict).init(allocator),
            .resolution_strategies = StringHashMap(ConflictResolutionStrategy).init(allocator),
        };
    }
    
    pub fn deinit(self: *ScopeConflictResolver) void {
        self.conflicts.deinit();
        self.resolution_strategies.deinit();
    }
    
    pub fn detectConflicts(self: *ScopeConflictResolver, scopes: ArrayList(*WorkerScope)) !ArrayList(*ScopeConflict) {
        var conflicts = ArrayList(*ScopeConflict).init(self.allocator);
        
        // Check for overlapping scopes
        for (scopes.items) |scope1| {
            for (scopes.items) |scope2| {
                if (scope1 != scope2 and self.scopesOverlap(scope1, scope2)) {
                    const conflict = self.createConflict(scope1, scope2);
                    try conflicts.append(conflict);
                }
            }
        }
        
        return conflicts;
    }
    
    pub fn resolveConflict(self: *ScopeConflictResolver, conflict: *ScopeConflict) !*WorkerScope {
        const strategy = self.getResolutionStrategy("priority_based") orelse {
            return error.NoResolutionStrategy;
        };
        
        return switch (strategy.strategy_type) {
            .PRIORITY_BASED => self.resolveByPriority(conflict),
            .LENGTH_BASED => self.resolveByLength(conflict),
            .FIRST_REGISTERED => self.resolveByFirstRegistered(conflict),
            .LAST_REGISTERED => self.resolveByLastRegistered(conflict),
            .CUSTOM => strategy.custom_resolver(conflict.url, conflict.conflicting_scopes),
        };
    }
    
    fn scopesOverlap(self: *ScopeConflictResolver, scope1: *WorkerScope, scope2: *WorkerScope) bool {
        return std.mem.indexOf(u8, scope1.url, scope2.url) != null or
               std.mem.indexOf(u8, scope2.url, scope1.url) != null;
    }
    
    fn createConflict(self: *ScopeConflictResolver, scope1: *WorkerScope, scope2: *WorkerScope) *ScopeConflict {
        const conflict = self.allocator.create(ScopeConflict) catch |err| {
            return error.ConflictCreationFailed;
        };
        
        conflict.* = ScopeConflict{
            .url = "", // Would calculate overlap URL
            .conflicting_scopes = ArrayList(*WorkerScope).init(self.allocator),
            .conflict_type = .OVERLAPPING_SCOPES,
        };
        
        conflict.conflicting_scopes.append(scope1) catch {};
        conflict.conflicting_scopes.append(scope2) catch {};
        
        return conflict;
    }
    
    fn resolveByPriority(self: *ScopeConflictResolver, conflict: *ScopeConflict) !*WorkerScope {
        var best_scope: ?*WorkerScope = null;
        var best_priority: i32 = -1;
        
        for (conflict.conflicting_scopes.items) |scope| {
            const priority_value = @intFromEnum(scope.priority);
            if (priority_value > best_priority) {
                best_priority = priority_value;
                best_scope = scope;
            }
        }
        
        return best_scope orelse error.NoScopeResolved;
    }
    
    fn resolveByLength(self: *ScopeConflictResolver, conflict: *ScopeConflict) !*WorkerScope {
        var best_scope: ?*WorkerScope = null;
        var best_length: usize = 0;
        
        for (conflict.conflicting_scopes.items) |scope| {
            if (scope.url.len > best_length) {
                best_length = scope.url.len;
                best_scope = scope;
            }
        }
        
        return best_scope orelse error.NoScopeResolved;
    }
    
    fn resolveByFirstRegistered(self: *ScopeConflictResolver, conflict: *ScopeConflict) !*WorkerScope {
        // Would check registration timestamps
        return conflict.conflicting_scopes.items[0];
    }
    
    fn resolveByLastRegistered(self: *ScopeConflictResolver, conflict: *ScopeConflict) !*WorkerScope {
        // Would check registration timestamps
        const len = conflict.conflicting_scopes.items.len;
        return conflict.conflicting_scopes.items[len - 1];
    }
};

// Utility functions
fn generateScopePattern(url: []const u8) []const u8 {
    // Generate a pattern from URL
    return url;
}

fn calculateMaxScopeDepth(url: []const u8) u8 {
    // Calculate maximum scope depth from URL
    var depth: u8 = 0;
    var count: usize = 0;
    for (url) |char| {
        if (char == '/') {
            count += 1;
        }
    }
    return @intCast(count);
}

fn urlStartsWith(url: []const u8, prefix: []const u8) bool {
    return std.mem.indexOf(u8, url, prefix) == 0;
}

fn calculateDepth(url: []const u8) u8 {
    var depth: u8 = 0;
    for (url) |char| {
        if (char == '/') {
            depth += 1;
        }
    }
    return depth;
}

fn generateRouteId() [16]u8 {
    var id: [16]u8 = undefined;
    std.crypto.random.bytes(&id);
    return id;
}

// Default route handler
fn defaultRouteHandler(request: Request, scope: *WorkerScope) anyerror!Response {
    var response = Response.init(std.heap.c_allocator);
    response.status = 404;
    response.status_text = "Not Found";
    return response;
}

// Hash function for strings
fn hashString(s: []const u8) u64 {
    var hash: u64 = 0;
    for (s) |char| {
        hash = hash * 31 + char;
    }
    return hash;
}