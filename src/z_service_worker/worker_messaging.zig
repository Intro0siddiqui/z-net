//! z_service_worker - Message Passing
//! 
//! Service Worker message passing, postMessage communication, and
//! client-worker messaging coordination.

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

// Message port for communication
pub const MessagePort = struct {
    id: [16]u8,
    owner_worker: *ServiceWorker,
    peer_port: ?*MessagePort,
    event_handlers: StringHashMap(MessageHandler),
    message_queue: ArrayList(Message),
    is_closed: bool,
    created_at: i64,
    
    pub fn init(allocator: Allocator, owner_worker: *ServiceWorker) MessagePort {
        return MessagePort{
            .id = generatePortId(),
            .owner_worker = owner_worker,
            .peer_port = null,
            .event_handlers = StringHashMap(MessageHandler).init(allocator),
            .message_queue = ArrayList(Message).init(allocator),
            .is_closed = false,
            .created_at = std.time.milliTimestamp(),
        };
    }
    
    pub fn deinit(self: *MessagePort) void {
        self.event_handlers.deinit();
        self.message_queue.deinit();
    }
    
    pub fn postMessage(self: *MessagePort, data: anytype) !void {
        if (self.is_closed) {
            return error.PortClosed;
        }
        
        // Create message
        const message = Message{
            .data = data,
            .port_id = self.id,
            .timestamp = std.time.milliTimestamp(),
            .type = .MESSAGE,
        };
        
        // Add to queue
        try self.message_queue.append(message);
        
        // If we have a peer port, forward the message
        if (self.peer_port) |peer| {
            try peer.enqueueMessage(message);
        }
        
        // Trigger message event
        if (self.event_handlers.get("message")) |handler| {
            try handler(self, .MESSAGE);
        }
    }
    
    pub fn start(self: *MessagePort, peer_port: *MessagePort) !void {
        self.peer_port = peer_port;
        peer_port.peer_port = self;
        
        // Set up peer ports
        peer_port.peer_port = self;
    }
    
    pub fn close(self: *MessagePort) void {
        self.is_closed = true;
        
        // Close peer port if connected
        if (self.peer_port) |peer| {
            peer.is_closed = true;
        }
        
        // Clear queues
        self.message_queue.clearRetainingCapacity();
        if (self.peer_port) |peer| {
            peer.message_queue.clearRetainingCapacity();
        }
    }
    
    pub fn enqueueMessage(self: *MessagePort, message: Message) !void {
        try self.message_queue.append(message);
        
        // Trigger message event
        if (self.event_handlers.get("message")) |handler| {
            try handler(self, .MESSAGE);
        }
    }
    
    pub fn addEventListener(self: *MessagePort, event: MessageEventType, handler: MessageHandler) !void {
        try self.event_handlers.put(@tagName(event), handler);
    }
    
    pub fn removeEventListener(self: *MessagePort, event: MessageEventType) void {
        _ = self.event_handlers.remove(@tagName(event));
    }
};

// Message structure
pub const Message = struct {
    data: anytype,
    port_id: [16]u8,
    timestamp: i64,
    type: MessageType,
    
    pub const MessageType = enum {
        MESSAGE,
        ERROR,
        PING,
        PONG,
    };
};

// Message event types
pub const MessageEventType = enum {
    MESSAGE,
    MESSAGE_ERROR,
    PING,
    PONG,
};

// Message handler function
pub const MessageHandler = fn (*MessagePort, MessageEventType) anyerror!void;

// Message event
pub const MessageEvent = struct {
    id: [16]u8,
    source_port: *MessagePort,
    target_port: *MessagePort,
    data: anytype,
    ports: ArrayList(*MessagePort),
    timestamp: i64,
    
    pub fn init(allocator: Allocator, source_port: *MessagePort, target_port: *MessagePort, data: anytype) MessageEvent {
        return MessageEvent{
            .id = generateMessageEventId(),
            .source_port = source_port,
            .target_port = target_port,
            .data = data,
            .ports = ArrayList(*MessagePort).init(allocator),
            .timestamp = std.time.milliTimestamp(),
        };
    }
    
    pub fn deinit(self: *MessageEvent) void {
        self.ports.deinit();
    }
};

// Client-worker message communication
pub const ClientWorkerMessage = struct {
    client_id: [16]u8,
    worker_id: [16]u8,
    message_type: MessageType,
    data: anytype,
    response_expected: bool,
    message_id: [16]u8,
    timestamp: i64,
    
    pub fn init(client_id: [16]u8, worker_id: [16]u8, message_type: MessageType, data: anytype, response_expected: bool) ClientWorkerMessage {
        return ClientWorkerMessage{
            .client_id = client_id,
            .worker_id = worker_id,
            .message_type = message_type,
            .data = data,
            .response_expected = response_expected,
            .message_id = generateMessageId(),
            .timestamp = std.time.milliTimestamp(),
        };
    }
    
    pub const MessageType = enum {
        POST_MESSAGE,
        PING,
        PONG,
        SYNC_REQUEST,
        SYNC_RESPONSE,
        ERROR,
    };
};

// Message manager for handling all message passing
pub const MessageManager = struct {
    allocator: Allocator,
    ports: AutoHashMap([16]u8, *MessagePort), // port_id -> port
    worker_ports: AutoHashMap([16]u8, ArrayList([16]u8)), // worker_id -> port_ids
    client_messages: AutoHashMap([16]u8, ClientWorkerMessage), // message_id -> message
    pending_responses: AutoHashMap([16]u8, ResponseHandler), // message_id -> response handler
    event_handlers: StringHashMap(EventHandler),
    
    pub fn init(allocator: Allocator) MessageManager {
        return MessageManager{
            .allocator = allocator,
            .ports = AutoHashMap([16]u8, *MessagePort).init(allocator),
            .worker_ports = AutoHashMap([16]u8, ArrayList([16]u8)).init(allocator),
            .client_messages = AutoHashMap([16]u8, ClientWorkerMessage).init(allocator),
            .pending_responses = AutoHashMap([16]u8, ResponseHandler).init(allocator),
            .event_handlers = StringHashMap(EventHandler).init(allocator),
        };
    }
    
    pub fn deinit(self: *MessageManager) void {
        // Clean up all ports
        var iter = self.ports.valueIterator();
        while (iter.next()) |port| {
            port.*.deinit();
            self.allocator.destroy(port.*);
        }
        self.ports.deinit();
        
        // Clean up worker associations
        var worker_iter = self.worker_ports.valueIterator();
        while (worker_iter.next()) |port_list| {
            port_list.*.deinit();
        }
        self.worker_ports.deinit();
        
        self.client_messages.deinit();
        self.pending_responses.deinit();
        self.event_handlers.deinit();
    }
    
    pub fn createPort(self: *MessageManager, worker: *ServiceWorker) !*MessagePort {
        const port = self.allocator.create(MessagePort) catch |err| {
            return error.PortCreationFailed;
        };
        port.* = MessagePort.init(self.allocator, worker);
        
        // Store port
        try self.ports.put(port.id, port);
        try self.associateWorkerWithPort(worker.id, port.id);
        
        return port;
    }
    
    pub fn connectPorts(self: *MessageManager, port1: *MessagePort, port2: *MessagePort) !void {
        // Start bidirectional communication
        try port1.start(port2);
    }
    
    pub fn postMessageToPort(self: *MessageManager, port_id: [16]u8, data: anytype) !void {
        if (self.ports.get(port_id)) |port| {
            try port.postMessage(data);
        } else {
            return error.PortNotFound;
        }
    }
    
    pub fn postMessageToWorker(self: *MessageManager, client_id: [16]u8, worker_id: [16]u8, data: anytype, response_handler: ?ResponseHandler) !void {
        // Create message
        const message = ClientWorkerMessage.init(client_id, worker_id, .POST_MESSAGE, data, response_handler != null);
        
        // Store message
        try self.client_messages.put(message.message_id, message);
        
        // Store response handler if expected
        if (response_handler) |handler| {
            try self.pending_responses.put(message.message_id, handler);
        }
        
        // Send to worker
        try self.sendMessageToWorker(worker_id, message);
    }
    
    pub fn sendMessageToClient(self: *MessageManager, worker_id: [16]u8, client_id: [16]u8, data: anytype, response_handler: ?ResponseHandler) !void {
        // Create message
        const message = ClientWorkerMessage.init(client_id, worker_id, .POST_MESSAGE, data, response_handler != null);
        
        // Store message
        try self.client_messages.put(message.message_id, message);
        
        // Store response handler if expected
        if (response_handler) |handler| {
            try self.pending_responses.put(message.message_id, handler);
        }
        
        // Send to client
        try self.sendMessageToClient(worker_id, message);
    }
    
    pub fn pingPort(self: *MessageManager, port_id: [16]u8) !void {
        if (self.ports.get(port_id)) |port| {
            const ping_message = Message{
                .data = null,
                .port_id = port.id,
                .timestamp = std.time.milliTimestamp(),
                .type = .PING,
            };
            
            try port.enqueueMessage(ping_message);
        } else {
            return error.PortNotFound;
        }
    }
    
    pub fn closePort(self: *MessageManager, port_id: [16]u8) !void {
        if (self.ports.get(port_id)) |port| {
            // Close the port
            port.close();
            
            // Remove from tracking
            _ = self.ports.remove(port_id);
            self.disassociateWorkerFromPort(port.owner_worker.id, port_id);
            
            // Clean up
            port.deinit();
            self.allocator.destroy(port);
        } else {
            return error.PortNotFound;
        }
    }
    
    pub fn getPort(self: *MessageManager, port_id: [16]u8) ?*MessagePort {
        return self.ports.get(port_id);
    }
    
    pub fn getWorkerPorts(self: *MessageManager, worker_id: [16]u8) ArrayList(*MessagePort) {
        var ports = ArrayList(*MessagePort).init(self.allocator);
        
        if (self.worker_ports.get(worker_id)) |port_ids| {
            for (port_ids.*.items) |port_id| {
                if (self.ports.get(port_id)) |port| {
                    ports.append(port) catch {};
                }
            }
        }
        
        return ports;
    }
    
    pub fn broadcastToWorker(self: *MessageManager, worker_id: [16]u8, data: anytype) !void {
        if (self.worker_ports.get(worker_id)) |port_ids| {
            for (port_ids.*.items) |port_id| {
                if (self.ports.get(port_id)) |port| {
                    try port.postMessage(data);
                }
            }
        }
    }
    
    pub fn broadcastToAllWorkers(self: *MessageManager, data: anytype) !void {
        var iter = self.worker_ports.valueIterator();
        while (iter.next()) |port_ids| {
            for (port_ids.*.items) |port_id| {
                if (self.ports.get(port_id)) |port| {
                    try port.postMessage(data);
                }
            }
        }
    }
    
    fn associateWorkerWithPort(self: *MessageManager, worker_id: [16]u8, port_id: [16]u8) !void {
        if (self.worker_ports.get(worker_id)) |existing_list| {
            const port_list = existing_list.*;
            if (std.mem.indexOfScalar([16]u8, port_list.items, port_id) == null) {
                try port_list.append(port_id);
            }
        } else {
            var port_list = ArrayList([16]u8).init(self.allocator);
            try port_list.append(port_id);
            try self.worker_ports.put(worker_id, port_list);
        }
    }
    
    fn disassociateWorkerFromPort(self: *MessageManager, worker_id: [16]u8, port_id: [16]u8) void {
        if (self.worker_ports.get(worker_id)) |port_list| {
            const index = std.mem.indexOfScalar([16]u8, port_list.items, port_id);
            if (index) |i| {
                _ = port_list.orderedRemove(i);
            }
        }
    }
    
    fn sendMessageToWorker(self: *MessageManager, worker_id: [16]u8, message: ClientWorkerMessage) !void {
        // Find worker's event handlers
        // This would integrate with the worker registry
        // For now, just trigger the message event
        
        // Trigger worker message event
        if (self.event_handlers.get("worker_message")) |handler| {
            try handler(worker_id, message);
        }
    }
    
    fn sendMessageToClient(self: *MessageManager, worker_id: [16]u8, message: ClientWorkerMessage) !void {
        // This would integrate with the client communication system
        // For now, just trigger the client message event
        
        // Trigger client message event
        if (self.event_handlers.get("client_message")) |handler| {
            try handler(message.client_id, message);
        }
    }
};

// Response handler for message acknowledgments
pub const ResponseHandler = struct {
    message_id: [16]u8,
    worker_id: [16]u8,
    callback: fn (anytype) anyerror!void,
    timeout_ms: u64,
    created_at: i64,
    
    pub fn init(message_id: [16]u8, worker_id: [16]u8, callback: fn (anytype) anyerror!void, timeout_ms: u64) ResponseHandler {
        return ResponseHandler{
            .message_id = message_id,
            .worker_id = worker_id,
            .callback = callback,
            .timeout_ms = timeout_ms,
            .created_at = std.time.milliTimestamp(),
        };
    }
};

// Global event handler type
pub const EventHandler = fn (anytype, anytype) anyerror!void;

// Message channel for structured communication
pub const MessageChannel = struct {
    port1: *MessagePort,
    port2: *MessagePort,
    message_manager: *MessageManager,
    
    pub fn init(message_manager: *MessageManager, worker: *ServiceWorker) !MessageChannel {
        const port1 = try message_manager.createPort(worker);
        const port2 = try message_manager.createPort(worker);
        
        try message_manager.connectPorts(port1, port2);
        
        return MessageChannel{
            .port1 = port1,
            .port2 = port2,
            .message_manager = message_manager,
        };
    }
    
    pub fn deinit(self: *MessageChannel) void {
        // Close both ports
        self.message_manager.closePort(self.port1.id) catch {};
        self.message_manager.closePort(self.port2.id) catch {};
    }
    
    pub fn getPort1(self: *MessageChannel) *MessagePort {
        return self.port1;
    }
    
    pub fn getPort2(self: *MessageChannel) *MessagePort {
        return self.port2;
    }
};

// Utility functions
fn generatePortId() [16]u8 {
    var id: [16]u8 = undefined;
    std.crypto.random.bytes(&id);
    return id;
}

fn generateMessageEventId() [16]u8 {
    var id: [16]u8 = undefined;
    std.crypto.random.bytes(&id);
    return id;
}

fn generateMessageId() [16]u8 {
    var id: [16]u8 = undefined;
    std.crypto.random.bytes(&id);
    return id;
}

// Event loop integration
fn addBackgroundTask(task_type: []const u8, context: anytype, data: anytype) !void {
    // Add background task to event loop
    // This integrates with the event loop from z_event_loop
}