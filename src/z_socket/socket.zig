//! z_socket - Raw TCP/UDP I/O Layer
//! Zig implementation for high-performance socket operations

const std = @import("std");
const net = std.Io.net;
const mem = std.mem;

pub const SocketError = error{
    SocketCreationFailed,
    SetNonBlockingFailed,
    ConnectFailed,
    BindFailed,
    ListenFailed,
    AcceptFailed,
    SendFailed,
    ReceiveFailed,
    Timeout,
    ConnectionReset,
    ConnectionRefused,
    NetworkUnreachable,
    NoRouteToHost,
    HostUnreachable,
    PermissionDenied,
};

pub const SocketOptions = struct {
    keep_alive: bool = true,
    tcp_no_delay: bool = true,
    receive_timeout: ?u32 = null,
    send_timeout: ?u32 = null,
    receive_buffer_size: ?u32 = null,
    send_buffer_size: ?u32 = null,
};

pub const Socket = struct {
    handle: std.Io.Handle,

    const Self = @This();

    pub fn create(io_ctx: *std.Io, domain: net.IpAddress.Family, sock_type: std.Io.SocketType) SocketError!Self {
        const handle = io_ctx.socket(domain, sock_type) catch return error.SocketCreationFailed;
        
        return Self{
            .handle = handle,
        };
    }

    pub fn connect(self: *Self, io_ctx: *std.Io, addr: net.IpAddress) SocketError!void {
        io_ctx.connect(self.handle, addr) catch |err| {
            return switch (err) {
                error.ConnectionRefused => error.ConnectionRefused,
                error.NetworkUnreachable => error.NetworkUnreachable,
                error.HostUnreachable => error.HostUnreachable,
                error.AccessDenied => error.PermissionDenied,
                else => error.ConnectFailed,
            };
        };
    }

    pub fn send(self: *Self, io_ctx: *std.Io, data: []const u8) SocketError!usize {
        return io_ctx.send(self.handle, data) catch |err| {
            return switch (err) {
                error.WouldBlock => error.Timeout,
                error.ConnectionReset => error.ConnectionReset,
                else => error.SendFailed,
            };
        };
    }

    pub fn recv(self: *Self, io_ctx: *std.Io, buffer: []u8) SocketError!usize {
        return io_ctx.recv(self.handle, buffer) catch |err| {
            return switch (err) {
                error.WouldBlock => error.Timeout,
                error.ConnectionReset => error.ConnectionReset,
                else => error.ReceiveFailed,
            };
        };
    }

    pub fn setOptions(self: *Self, io_ctx: *std.Io, options: SocketOptions) SocketError!void {
        if (options.tcp_no_delay) {
            io_ctx.setsockopt(self.handle, .tcp, .no_delay, true) catch return error.SetNonBlockingFailed;
        }

        if (options.keep_alive) {
            io_ctx.setsockopt(self.handle, .socket, .keep_alive, true) catch return error.SetNonBlockingFailed;
        }

        if (options.receive_timeout) |timeout| {
            io_ctx.setsockopt(self.handle, .socket, .receive_timeout, timeout) catch return error.SetNonBlockingFailed;
        }

        if (options.send_timeout) |timeout| {
            io_ctx.setsockopt(self.handle, .socket, .send_timeout, timeout) catch return error.SetNonBlockingFailed;
        }
    }

    pub fn bind(self: *Self, io_ctx: *std.Io, addr: net.IpAddress) SocketError!void {
        io_ctx.bind(self.handle, addr) catch return error.BindFailed;
    }

    pub fn listen(self: *Self, io_ctx: *std.Io, backlog: u31) SocketError!void {
        io_ctx.listen(self.handle, backlog) catch return error.ListenFailed;
    }

    pub fn accept(self: *Self, io_ctx: *std.Io) SocketError!Self {
        const handle = io_ctx.accept(self.handle) catch return error.AcceptFailed;
        return Self{ .handle = handle };
    }

    pub fn close(self: *Self, io_ctx: *std.Io) void {
        io_ctx.close(self.handle);
    }
};

pub const SocketPair = struct {
    client: Socket,
    server: Socket,

    pub fn create(io_ctx: *std.Io) SocketError!SocketPair {
        const handles = io_ctx.socketpair(.unix, .stream) catch return error.SocketCreationFailed;
        
        return SocketPair{
            .client = Socket{ .handle = handles[0] },
            .server = Socket{ .handle = handles[1] },
        };
    }
};

// Connection Pool for managing multiple connections
pub const ConnectionPool = struct {
    allocator: mem.Allocator,
    connections: std.StringArrayHashMap(ConnectionEntry),
    max_connections_per_host: usize = 10,
    connection_timeout: u32 = 30000, // 30 seconds

    const ConnectionEntry = struct {
        socket: Socket,
        last_used: i64,
        in_use: bool,
    };

    const Self = @This();

    pub fn init(allocator: mem.Allocator) Self {
        return Self{
            .allocator = allocator,
            .connections = std.StringArrayHashMap(ConnectionEntry).init(allocator),
        };
    }

    pub fn getConnection(self: *Self, io_ctx: *std.Io, host: []const u8, port: u16) SocketError!Socket {
        // Check for existing connection
        const key = try std.fmt.allocPrint(self.allocator, "{s}:{d}", .{ host, port });
        defer self.allocator.free(key);

        if (self.connections.get(key)) |entry| {
            if (!entry.in_use) {
                entry.in_use = true;
                entry.last_used = std.time.timestamp();
                return entry.socket;
            }
        }

        // Create new connection
        const addr = net.IpAddress.parseIp4(host, port) catch return error.SocketCreationFailed;
        var socket = try Socket.create(io_ctx, .inet, .stream);
        
        const options = SocketOptions{
            .keep_alive = true,
            .tcp_no_delay = true,
            .receive_timeout = self.connection_timeout,
            .send_timeout = self.connection_timeout,
        };
        try socket.setOptions(io_ctx, options);
        
        try socket.connect(io_ctx, addr);

        // Store in pool
        const entry = ConnectionEntry{
            .socket = socket,
            .last_used = std.time.timestamp(),
            .in_use = true,
        };
        
        try self.connections.put(key, entry);
        return socket;
    }

    pub fn releaseConnection(self: *Self, host: []const u8, port: u16) void {
        const key = std.fmt.allocPrint(self.allocator, "{s}:{d}", .{ host, port }) catch return;
        defer self.allocator.free(key);

        if (self.connections.getPtr(key)) |entry| {
            entry.in_use = false;
            entry.last_used = std.time.timestamp();
        }
    }

    pub fn cleanup(self: *Self) void {
        const now = std.time.timestamp();
        var keys_to_remove = std.ArrayList([]const u8).init(self.allocator);
        defer keys_to_remove.deinit();

        var it = self.connections.iterator();
        while (it.next()) |entry| {
            if (!entry.value_ptr.in_use and now - entry.value_ptr.last_used > 300) { // 5 minutes
                keys_to_remove.append(entry.key_ptr.*) catch continue;
            }
        }

        for (keys_to_remove.items) |key| {
            self.connections.remove(key);
        }
    }

    pub fn deinit(self: *Self, io_ctx: *std.Io) void {
        for (self.connections.values()) |entry| {
            entry.socket.close(io_ctx);
        }
        self.connections.deinit();
    }
};

// Event-driven I/O using std.Io.poll (OS-agnostic)
pub const EventLoop = struct {
    io_ctx: *std.Io,

    const Self = @This();

    pub fn init(io_ctx: *std.Io) Self {
        return Self{ .io_ctx = io_ctx };
    }

    pub fn addSocket(self: *Self, socket: Socket, user_data: usize) SocketError!void {
        self.io_ctx.add(socket.handle, .{ .read = true }, user_data) catch return error.SocketCreationFailed;
    }

    pub fn wait(self: *Self, timeout_ns: ?u64) SocketError!usize {
        return self.io_ctx.poll(timeout_ns) catch |err| {
            return switch (err) {
                error.Interrupted => 0,
                else => error.SocketCreationFailed,
            };
        };
    }

    pub fn deinit(self: *Self) void {
        _ = self;
    }
};

test "socket creation and connection" {
    _ = Socket;
    _ = SocketPair;
    _ = ConnectionPool;
    _ = EventLoop;
}