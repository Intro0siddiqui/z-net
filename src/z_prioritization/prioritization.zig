/// Zawra HTTP/2 Prioritization System v1.0
/// Advanced HTTP/2 stream prioritization with dependency trees,
/// weighted fair scheduling, and server push coordination.

const std = @import("std");
const socket = @import("../z_socket/socket.zig");
const http = @import("../z_http/http.zig");

/// HTTP/2 Frame Types
const FRAME_TYPE_DATA: u8 = 0x0;
const FRAME_TYPE_HEADERS: u8 = 0x1;
const FRAME_TYPE_PRIORITY: u8 = 0x2;
const FRAME_TYPE_RST_STREAM: u8 = 0x3;
const FRAME_TYPE_SETTINGS: u8 = 0x4;
const FRAME_TYPE_PUSH_PROMISE: u8 = 0x5;
const FRAME_TYPE_PING: u8 = 0x6;
const FRAME_TYPE_GOAWAY: u8 = 0x7;
const FRAME_TYPE_WINDOW_UPDATE: u8 = 0x8;
const FRAME_TYPE_CONTINUATION: u8 = 0x9;

/// HTTP/2 Settings
const SETTINGS_HEADER_TABLE_SIZE: u16 = 0x1;
const SETTINGS_ENABLE_PUSH: u16 = 0x2;
const SETTINGS_MAX_CONCURRENT_STREAMS: u16 = 0x3;
const SETTINGS_INITIAL_WINDOW_SIZE: u16 = 0x4;
const SETTINGS_MAX_FRAME_SIZE: u16 = 0x5;
const SETTINGS_MAX_HEADER_LIST_SIZE: u16 = 0x6;

/// HTTP/2 Error Codes
const ERROR_NO_ERROR: u32 = 0x0;
const ERROR_PROTOCOL_ERROR: u32 = 0x1;
const ERROR_INTERNAL_ERROR: u32 = 0x2;
const ERROR_FLOW_CONTROL_ERROR: u32 = 0x3;
const ERROR_SETTINGS_TIMEOUT: u32 = 0x4;
const ERROR_STREAM_CLOSED: u32 = 0x5;
const ERROR_FRAME_SIZE_ERROR: u32 = 0x6;
const ERROR_REFUSED_STREAM: u32 = 0x7;
const ERROR_CANCEL: u8 = 0x8;
const ERROR_COMPRESSION_ERROR: u32 = 0x9;
const ERROR_CONNECT_ERROR: u32 = 0xa;
const ERROR_ENHANCE_YOUR_CALM: u32 = 0xb;
const ERROR_INADEQUATE_SECURITY: u32 = 0xc;
const ERROR_HTTP_1_1_REQUIRED: u32 = 0xd;

/// HTTP/2 Stream States
const STREAM_STATE_IDLE: u8 = 0x1;
const STREAM_STATE_RESERVED_LOCAL: u8 = 0x3;
const STREAM_STATE_RESERVED_REMOTE: u8 = 0x2;
const STREAM_STATE_OPEN: u8 = 0x4;
const STREAM_STATE_HALF_CLOSED_LOCAL: u8 = 0x5;
const STREAM_STATE_HALF_CLOSED_REMOTE: u8 = 0x6;
const STREAM_STATE_CLOSED: u8 = 0x7;

/// HTTP/2 Stream Priority Information
pub const HTTP2StreamPriority = struct {
    stream_id: u32,
    weight: u8,
    exclusive: bool,
    parent_stream_id: ?u32,
    dependency_depth: u16,
    estimated_size: u64,
    transfer_rate: u64, // bytes per second
    actual_rate: u64,   // actual transferred bytes per second
    priority_class: enum { critical, high, normal, low, background } = .normal,
    is_blocked: bool,
    last_activity: std.time.Instant,
    receive_window: u32,
    send_window: u32,
    buffered_data: u64,
    
    pub fn init(stream_id: u32, weight: u8, parent: ?u32, exclusive: bool) HTTP2StreamPriority {
        return HTTP2StreamPriority{
            .stream_id = stream_id,
            .weight = weight,
            .exclusive = exclusive,
            .parent_stream_id = parent,
            .dependency_depth = 0,
            .estimated_size = 0,
            .transfer_rate = 0,
            .actual_rate = 0,
            .priority_class = .normal,
            .is_blocked = false,
            .last_activity = std.time.Instant.now(),
            .receive_window = 65535, // Default window size
            .send_window = 65535,
            .buffered_data = 0,
        };
    }
    
    pub fn computeEffectiveWeight(self: HTTP2StreamPriority) u8 {
        var effective_weight = self.weight;
        
        // Account for parent priority (inheritance)
        if (self.parent_stream_id) |parent_id| {
            const parent_influence = @divFloor(effective_weight, 4);
            effective_weight = @max(1, effective_weight - parent_influence);
        }
        
        // Apply priority class modifiers
        effective_weight = switch (self.priority_class) {
            .critical => @min(255, effective_weight * 4),
            .high => @min(255, effective_weight * 2),
            .low => @max(1, @divFloor(effective_weight, 2)),
            .background => @max(1, @divFloor(effective_weight, 4)),
            else => effective_weight,
        };
        
        return @as(u8, @intCast(effective_weight));
    }
    
    pub fn updateActivity(self: *HTTP2StreamPriority) void {
        self.last_activity = std.time.Instant.now();
    }
    
    pub fn getTransferEfficiency(self: HTTP2StreamPriority) f64 {
        if (self.actual_rate == 0) return 1.0;
        return @as(f64, @floatFromInt(self.transfer_rate)) / @as(f64, @floatFromInt(self.actual_rate));
    }
};

/// HTTP/2 Dependency Tree Node
pub const DependencyTreeNode = struct {
    stream_id: u32,
    priority: *HTTP2StreamPriority,
    children: std.ArrayList(*DependencyTreeNode),
    parent: ?*DependencyTreeNode,
    exclusive_children: std.ArrayList(*DependencyTreeNode),
    is_exclusive: bool,
    allocator: std.mem.Allocator,
    
    pub fn init(allocator: std.mem.Allocator, stream_id: u32, priority: *HTTP2StreamPriority, parent: ?*DependencyTreeNode) !*DependencyTreeNode {
        const node = allocator.create(DependencyTreeNode) catch unreachable;
        node.* = DependencyTreeNode{
            .stream_id = stream_id,
            .priority = priority,
            .children = std.ArrayList(*DependencyTreeNode).init(allocator),
            .parent = parent,
            .exclusive_children = std.ArrayList(*DependencyTreeNode).init(allocator),
            .is_exclusive = false,
            .allocator = allocator,
        };
        
        // Calculate dependency depth
        var depth: u16 = 0;
        var current = parent;
        while (current) |node_ptr| {
            depth += 1;
            current = node_ptr.parent;
        }
        priority.dependency_depth = depth;
        
        return node;
    }
    
    pub fn addChild(self: *DependencyTreeNode, child_node: *DependencyTreeNode) !void {
        child_node.parent = self;
        
        if (child_node.is_exclusive) {
            try self.exclusive_children.append(child_node);
            
            // Make all current children exclusive as well
            for (self.children.items) |existing_child| {
                try existing_child.makeExclusive();
            }
            
            // Move all current children to the new exclusive child
            for (self.children.items) |existing_child| {
                try child_node.children.append(existing_child);
                existing_child.parent = child_node;
            }
            self.children.clearRetainingCapacity();
        } else {
            try self.children.append(child_node);
        }
    }
    
    pub fn makeExclusive(self: *DependencyTreeNode) void {
        self.is_exclusive = true;
        self.priority.exclusive = true;
    }
    
    pub fn removeChild(self: *DependencyTreeNode, child_id: u32) bool {
        // Remove from children
        for (self.children.items, 0..) |child, i| {
            if (child.stream_id == child_id) {
                child.parent = null;
                _ = self.children.orderedRemove(i);
                return true;
            }
        }
        
        // Remove from exclusive children
        for (self.exclusive_children.items, 0..) |child, i| {
            if (child.stream_id == child_id) {
                child.parent = null;
                _ = self.exclusive_children.orderedRemove(i);
                return true;
            }
        }
        
        return false;
    }
    
    pub fn getActiveChildren(self: *DependencyTreeNode) std.ArrayList(*DependencyTreeNode) {
        var active = std.ArrayList(*DependencyTreeNode).init(self.allocator);
        
        // Add exclusive children first (higher priority)
        for (self.exclusive_children.items) |child| {
            if (child.priority.is_blocked) continue;
            active.append(child) catch {};
        }
        
        // Then regular children
        for (self.children.items) |child| {
            if (child.priority.is_blocked) continue;
            active.append(child) catch {};
        }
        
        return active;
    }
    
    pub fn computeSubtreeWeight(self: *DependencyTreeNode) u32 {
        var total_weight: u32 = self.priority.computeEffectiveWeight();
        
        // Include exclusive children
        for (self.exclusive_children.items) |child| {
            total_weight += child.computeSubtreeWeight();
        }
        
        // Include regular children proportionally
        for (self.children.items) |child| {
            const child_weight = child.computeSubtreeWeight();
            total_weight += @divFloor(child_weight, @max(1, self.children.items.len));
        }
        
        return total_weight;
    }
    
    pub fn destroy(self: *DependencyTreeNode) void {
        // Clean up children
        for (self.children.items) |child| {
            child.destroy();
        }
        for (self.exclusive_children.items) |child| {
            child.destroy();
        }
        
        self.allocator.destroy(self);
    }
};

/// HTTP/2 Stream Manager
pub const HTTP2StreamManager = struct {
    streams: std.HashMap(u32, *HTTP2StreamPriority, std.hash_map.AutoContext(u32)),
    dependency_tree_root: *DependencyTreeNode,
    max_concurrent_streams: u32,
    concurrent_streams: u32,
    initial_window_size: u32,
    connection_window: u32,
    window_update_interval: std.time.Duration,
    last_window_update: std.time.Instant,
    allocator: std.mem.Allocator,
    
    pub fn init(allocator: std.mem.Allocator, max_concurrent_streams: u32, initial_window_size: u32) !HTTP2StreamManager {
        // Create root node (stream 0 - dependency tree root)
        const root_priority = try allocator.create(HTTP2StreamPriority);
        root_priority.* = HTTP2StreamPriority.init(0, 16, null, false);
        root_priority.priority_class = .critical; // Root gets highest priority
        
        const root_node = try DependencyTreeNode.init(allocator, 0, root_priority, null);
        
        return HTTP2StreamManager{
            .streams = std.HashMap(u32, *HTTP2StreamPriority, std.hash_map.AutoContext(u32)).init(allocator),
            .dependency_tree_root = root_node,
            .max_concurrent_streams = max_concurrent_streams,
            .concurrent_streams = 0,
            .initial_window_size = initial_window_size,
            .connection_window = initial_window_size,
            .window_update_interval = std.time.Duration.fromMilliseconds(100),
            .last_window_update = std.time.Instant.now(),
            .allocator = allocator,
        };
    }
    
    pub fn createStream(self: *HTTP2StreamManager, stream_id: u32, weight: u8, parent: ?u32, exclusive: bool) !*HTTP2StreamPriority {
        // Check stream limit
        if (self.concurrent_streams >= self.max_concurrent_streams) {
            return error.MaxStreamsExceeded;
        }
        
        // Create priority information
        const priority = try allocator.create(HTTP2StreamPriority);
        priority.* = HTTP2StreamPriority.init(stream_id, weight, parent, exclusive);
        
        // Add to streams map
        try self.streams.put(stream_id, priority);
        self.concurrent_streams += 1;
        
        // Add to dependency tree
        const priority_ptr = priority;
        var parent_node: ?*DependencyTreeNode = null;
        
        if (parent) |parent_id| {
            if (parent_id == 0) {
                parent_node = self.dependency_tree_root;
            } else {
                parent_node = self.findDependencyNode(parent_id);
            }
        } else {
            parent_node = self.dependency_tree_root;
        }
        
        const node = try DependencyTreeNode.init(self.allocator, stream_id, priority_ptr, parent_node);
        try parent_node.?.addChild(node);
        
        return priority;
    }
    
    pub fn updateStreamPriority(self: *HTTP2StreamManager, stream_id: u32, new_weight: u8, new_parent: ?u32, exclusive: bool) !void {
        const priority = self.streams.get(stream_id) orelse return error.StreamNotFound;
        
        // Remove from current parent
        if (priority.parent_stream_id) |old_parent| {
            const old_parent_node = self.findDependencyNode(old_parent);
            if (old_parent_node) |node| {
                _ = node.removeChild(stream_id);
            }
        }
        
        // Update priority settings
        priority.weight = new_weight;
        priority.parent_stream_id = new_parent;
        priority.exclusive = exclusive;
        
        // Add to new parent
        var parent_node: ?*DependencyTreeNode = null;
        if (new_parent) |parent_id| {
            if (parent_id == 0) {
                parent_node = self.dependency_tree_root;
            } else {
                parent_node = self.findDependencyNode(parent_id);
            }
        } else {
            parent_node = self.dependency_tree_root;
        }
        
        if (parent_node) |node| {
            const new_node = try DependencyTreeNode.init(self.allocator, stream_id, priority, node);
            try node.addChild(new_node);
        }
    }
    
    pub fn closeStream(self: *HTTP2StreamManager, stream_id: u32) !void {
        const priority = self.streams.get(stream_id) orelse return error.StreamNotFound;
        
        // Remove from dependency tree
        if (priority.parent_stream_id) |parent_id| {
            const parent_node = self.findDependencyNode(parent_id);
            if (parent_node) |node| {
                _ = node.removeChild(stream_id);
            }
        }
        
        // Remove from streams
        _ = self.streams.remove(stream_id);
        
        if (self.concurrent_streams > 0) {
            self.concurrent_streams -= 1;
        }
        
        // Free memory
        self.allocator.destroy(priority);
    }
    
    pub fn getNextStream(self: *HTTP2StreamManager) ?*HTTP2StreamPriority {
        return self.selectNextStream();
    }
    
    fn selectNextStream(self: *HTTP2StreamManager) ?*HTTP2StreamPriority {
        const active_children = self.dependency_tree_root.getActiveChildren();
        defer active_children.deinit();
        
        if (active_children.items.len == 0) return null;
        
        // Simple weighted round-robin selection
        var total_weight: u32 = 0;
        for (active_children.items) |child| {
            total_weight += child.computeSubtreeWeight();
        }
        
        if (total_weight == 0) {
            // No weight assigned, use first available
            return active_children.items[0].priority;
        }
        
        // Weighted random selection
        var random_weight = @rem(@as(u64, @intCast(std.time.milliTimestamp())), total_weight);
        
        for (active_children.items) |child| {
            const child_weight = child.computeSubtreeWeight();
            if (random_weight < child_weight) {
                return child.priority;
            }
            random_weight -= child_weight;
        }
        
        return active_children.items[0].priority; // Fallback
    }
    
    fn findDependencyNode(self: *HTTP2StreamManager, stream_id: u32) ?*DependencyTreeNode {
        return self.findNodeRecursive(self.dependency_tree_root, stream_id);
    }
    
    fn findNodeRecursive(self: *HTTP2StreamManager, node: *DependencyTreeNode, stream_id: u32) ?*DependencyTreeNode {
        if (node.stream_id == stream_id) {
            return node;
        }
        
        // Check children
        for (node.children.items) |child| {
            if (self.findNodeRecursive(child, stream_id)) |found| {
                return found;
            }
        }
        
        for (node.exclusive_children.items) |child| {
            if (self.findNodeRecursive(child, stream_id)) |found| {
                return found;
            }
        }
        
        return null;
    }
    
    pub fn updateWindow(self: *HTTP2StreamManager, stream_id: u32, delta: i32) !void {
        const priority = self.streams.get(stream_id) orelse return error.StreamNotFound;
        
        const new_window = @as(i32, @intCast(priority.receive_window)) + delta;
        if (new_window < 0) {
            return error.FlowControlError;
        }
        
        priority.receive_window = @as(u32, @intCast(new_window));
        priority.updateActivity();
    }
    
    pub fn updateConnectionWindow(self: *HTTP2StreamManager, delta: i32) !void {
        const new_window = @as(i32, @intCast(self.connection_window)) + delta;
        if (new_window < 0) {
            return error.FlowControlError;
        }
        
        self.connection_window = @as(u32, @intCast(new_window));
        self.last_window_update = std.time.Instant.now();
    }
    
    pub fn sendWindowUpdate(self: *HTTP2StreamManager, stream_id: u32) ![]u8 {
        const priority = self.streams.get(stream_id) orelse return error.StreamNotFound;
        
        // Calculate increment (simplified - in real implementation, would use proper window update logic)
        const increment = @min(1024 * 1024, priority.receive_window); // 1MB or current window
        
        // Create WINDOW_UPDATE frame
        var frame_data = std.ArrayList(u8).init(self.allocator);
        try frame_data.append(@as(u8, @truncate(stream_id >> 24)));
        try frame_data.append(@as(u8, @truncate(stream_id >> 16)));
        try frame_data.append(@as(u8, @truncate(stream_id >> 8)));
        try frame_data.append(@as(u8, @truncate(stream_id)));
        try frame_data.append(@as(u8, @truncate(increment >> 24)));
        try frame_data.append(@as(u8, @truncate(increment >> 16)));
        try frame_data.append(@as(u8, @truncate(increment >> 8)));
        try frame_data.append(@as(u8, @truncate(increment)));
        
        priority.receive_window += increment;
        priority.updateActivity();
        
        return frame_data.toOwnedSlice();
    }
    
    pub fn shouldUpdateWindows(self: HTTP2StreamManager) bool {
        return std.time.Instant.now().since(self.last_window_update) >= self.window_update_interval;
    }
    
    pub fn getStreamStats(self: *HTTP2StreamManager, stream_id: u32) ?StreamStats {
        const priority = self.streams.get(stream_id) orelse return null;
        
        return StreamStats{
            .stream_id = priority.stream_id,
            .weight = priority.weight,
            .priority_class = priority.priority_class,
            .dependency_depth = priority.dependency_depth,
            .is_blocked = priority.is_blocked,
            .send_window = priority.send_window,
            .receive_window = priority.receive_window,
            .buffered_data = priority.buffered_data,
            .last_activity = priority.last_activity,
        };
    }
    
    pub fn cleanup(self: *HTTP2StreamManager) !void {
        // Close idle streams
        var idle_threshold = std.time.Duration.fromMinutes(5);
        var now = std.time.Instant.now();
        
        var to_close = std.ArrayList(u32).init(self.allocator);
        defer to_close.deinit();
        
        var it = self.streams.valueIterator();
        while (it.next()) |priority| {
            if (now.since(priority.last_activity) > idle_threshold and
                priority.send_window == 0 and
                priority.buffered_data == 0) {
                try to_close.append(priority.stream_id);
            }
        }
        
        for (to_close.items) |stream_id| {
            try self.closeStream(stream_id);
        }
    }
    
    pub fn destroy(self: *HTTP2StreamManager) void {
        // Clean up all streams
        var it = self.streams.valueIterator();
        while (it.next()) |priority| {
            self.allocator.destroy(priority.*);
        }
        
        // Clean up dependency tree
        self.dependency_tree_root.destroy();
        
        self.allocator.destroy(self);
    }
};

/// HTTP/2 Stream Statistics
pub const StreamStats = struct {
    stream_id: u32,
    weight: u8,
    priority_class: @TypeOf(HTTP2StreamPriority{ .priority_class = .normal }).priority_class,
    dependency_depth: u16,
    is_blocked: bool,
    send_window: u32,
    receive_window: u32,
    buffered_data: u64,
    last_activity: std.time.Instant,
};

/// HTTP/2 Server Push Manager
pub const ServerPushManager = struct {
    push_promises: std.HashMap(u32, *PushPromise, std.hash_map.AutoContext(u32)),
    active_pushes: std.ArrayList(*PushPromise),
    max_concurrent_pushes: u32,
    concurrent_pushes: u32,
    push_resources: std.HashMap([]const u8, *PushResource, StringHash),
    allocator: std.mem.Allocator,
    
    pub const PushPromise = struct {
        push_id: u32,
        stream_id: u32,
        method: []const u8,
        url: []const u8,
        headers: std.HashMap([]const u8, []const u8, StringHash),
        priority: *HTTP2StreamPriority,
        promise_state: enum { promised, in_progress, completed, cancelled },
        estimated_size: u64,
        actual_size: u64,
        timestamp: std.time.Instant,
        timeout: std.time.Duration,
        
        pub fn init(allocator: std.mem.Allocator, push_id: u32, stream_id: u32) *PushPromise {
            const promise = allocator.create(PushPromise) catch unreachable;
            promise.* = PushPromise{
                .push_id = push_id,
                .stream_id = stream_id,
                .method = "GET",
                .url = "",
                .headers = std.HashMap([]const u8, []const u8, StringHash).init(allocator),
                .priority = undefined, // Will be set later
                .promise_state = .promised,
                .estimated_size = 0,
                .actual_size = 0,
                .timestamp = std.time.Instant.now(),
                .timeout = std.time.Duration.fromSeconds(30),
            };
            return promise;
        }
    };
    
    pub const PushResource = struct {
        url: []const u8,
        content_type: []const u8,
        content_encoding: []const u8,
        cache_key: []const u8,
        etag: []const u8,
        last_modified: std.time.Instant,
        expires: std.time.Instant,
        size: u64,
        is_cached: bool,
        
        pub fn init(url: []const u8, allocator: std.mem.Allocator) *PushResource {
            const resource = allocator.create(PushResource) catch unreachable;
            resource.* = PushResource{
                .url = try allocator.dupe(u8, url),
                .content_type = "application/octet-stream",
                .content_encoding = "identity",
                .cache_key = try allocator.dupe(u8, url),
                .etag = "",
                .last_modified = std.time.Instant.now(),
                .expires = std.time.Instant.now().plus(std.time.Duration.fromHours(1)),
                .size = 0,
                .is_cached = false,
            };
            return resource;
        }
    };
    
    pub fn init(allocator: std.mem.Allocator, max_concurrent_pushes: u32) ServerPushManager {
        return ServerPushManager{
            .push_promises = std.HashMap(u32, *PushPromise, std.hash_map.AutoContext(u32)).init(allocator),
            .active_pushes = std.ArrayList(*PushPromise).init(allocator),
            .max_concurrent_pushes = max_concurrent_pushes,
            .concurrent_pushes = 0,
            .push_resources = std.HashMap([]const u8, *PushResource, StringHash).init(allocator),
            .allocator = allocator,
        };
    }
    
    pub fn createPushPromise(self: *ServerPushManager, stream_id: u32, url: []const u8, headers: std.HashMap([]const u8, []const u8, StringHash)) !u32 {
        const push_id = @as(u32, @intCast(std.time.milliTimestamp()));
        
        const promise = PushPromise.init(self.allocator, push_id, stream_id);
        promise.url = try self.allocator.dupe(u8, url);
        promise.headers = headers;
        
        // Create priority for push stream (child of originating stream)
        promise.priority = try self.allocator.create(HTTP2StreamPriority);
        promise.priority.* = HTTP2StreamPriority.init(push_id, 16, stream_id, false);
        promise.priority.priority_class = .high;
        
        try self.push_promises.put(push_id, promise);
        
        return push_id;
    }
    
    pub fn startPush(self: *ServerPushManager, push_id: u32) !void {
        const promise = self.push_promises.get(push_id) orelse return error.PushPromiseNotFound;
        
        if (self.concurrent_pushes >= self.max_concurrent_pushes) {
            return error.MaxPushesExceeded;
        }
        
        promise.promise_state = .in_progress;
        try self.active_pushes.append(promise);
        self.concurrent_pushes += 1;
    }
    
    pub fn cancelPush(self: *ServerPushManager, push_id: u32) !void {
        const promise = self.push_promises.get(push_id) orelse return error.PushPromiseNotFound;
        
        promise.promise_state = .cancelled;
        
        // Remove from active pushes
        for (self.active_pushes.items, 0..) |active_push, i| {
            if (active_push.push_id == push_id) {
                _ = self.active_pushes.orderedRemove(i);
                break;
            }
        }
        
        if (self.concurrent_pushes > 0) {
            self.concurrent_pushes -= 1;
        }
    }
    
    pub fn completePush(self: *ServerPushManager, push_id: u32) !void {
        const promise = self.push_promises.get(push_id) orelse return error.PushPromiseNotFound;
        
        promise.promise_state = .completed;
        
        // Remove from active pushes
        for (self.active_pushes.items, 0..) |active_push, i| {
            if (active_push.push_id == push_id) {
                _ = self.active_pushes.orderedRemove(i);
                break;
            }
        }
        
        if (self.concurrent_pushes > 0) {
            self.concurrent_pushes -= 1;
        }
        
        // Cache the resource if applicable
        if (promise.estimated_size > 0) {
            try self.cachePushResource(promise);
        }
    }
    
    fn cachePushResource(self: *ServerPushManager, promise: *PushPromise) !void {
        const resource = PushResource.init(promise.url, self.allocator);
        resource.content_type = promise.headers.get("content-type") orelse "application/octet-stream";
        resource.size = promise.actual_size;
        
        try self.push_resources.put(promise.url, resource);
    }
    
    pub fn getNextPush(self: *ServerPushManager) ?*PushPromise {
        if (self.active_pushes.items.len == 0) return null;
        
        // Simple priority-based selection
        var best_push: ?*PushPromise = null;
        var best_priority: u8 = 0;
        
        for (self.active_pushes.items) |push| {
            if (push.priority.priority_class == .critical or
                (push.priority.priority_class == .high and push.priority.weight > best_priority)) {
                best_push = push;
                best_priority = push.priority.weight;
            }
        }
        
        return best_push orelse self.active_pushes.items[0];
    }
    
    pub fn cleanup(self: *ServerPushManager) !void {
        const now = std.time.Instant.now();
        
        // Remove expired push promises
        var to_remove = std.ArrayList(u32).init(self.allocator);
        defer to_remove.deinit();
        
        var it = self.push_promises.valueIterator();
        while (it.next()) |promise| {
            if (now.since(promise.timestamp) > promise.timeout) {
                try to_remove.append(promise.push_id);
            }
        }
        
        for (to_remove.items) |push_id| {
            const promise = self.push_promises.get(push_id).?;
            if (promise.promise_state == .in_progress) {
                try self.cancelPush(push_id);
            }
            
            // Clean up resources
            self.allocator.destroy(promise);
            _ = self.push_promises.remove(push_id);
        }
    }
};

test "HTTP2 Prioritization Tests" {
    const allocator = std.testing.allocator;
    
    // Test stream manager
    var stream_manager = try HTTP2StreamManager.init(allocator, 100, 65536);
    defer stream_manager.destroy();
    
    // Create test streams
    const stream1 = try stream_manager.createStream(1, 16, null, false);
    const stream2 = try stream_manager.createStream(2, 32, 1, false);
    const stream3 = try stream_manager.createStream(3, 8, 1, false);
    
    try testing.expect(stream1.?.stream_id == 1);
    try testing.expect(stream2.?.parent_stream_id == 1);
    try testing.expect(stream3.?.parent_stream_id == 1);
    
    // Test priority update
    try stream_manager.updateStreamPriority(2, 24, null, false);
    
    const updated_priority = stream_manager.streams.get(2);
    try testing.expect(updated_priority.?.weight == 24);
    
    // Test stream selection
    const next_stream = stream_manager.getNextStream();
    try testing.expect(next_stream != null);
    
    try testing.expect(true); // Basic functionality test passed
}