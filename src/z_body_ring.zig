//! z_body_ring - Unified Shared Memory Body Transfer Protocol
//!
//! Implements a "Pull-Style" shared memory interface for zero-copy
//! body transfers between the networking stack and other processes.

const std = @import("std");

pub const BodyRingError = error{
    Full,
    Empty,
    InvalidRegion,
    AlreadyRegistered,
    NotRegistered,
};

pub const BodyRingDescriptor = extern struct {
    buffer_ptr: [*]u8,
    capacity: usize,
    _pad1: [64]u8, // Cache line padding to prevent false sharing
    head: std.atomic.Value(u64), // Producer (Zig) updates this
    _pad2: [64]u8,
    tail: std.atomic.Value(u64), // Consumer (Rust) updates this
    _pad3: [64]u8,
    is_closed: std.atomic.Value(bool),

    pub fn init(ptr: [*]u8, capacity: usize) BodyRingDescriptor {
        return .{
            .buffer_ptr = ptr,
            .capacity = capacity,
            ._pad1 = undefined,
            .head = std.atomic.Value(u64).init(0),
            ._pad2 = undefined,
            .tail = std.atomic.Value(u64).init(0),
            ._pad3 = undefined,
            .is_closed = std.atomic.Value(bool).init(false),
        };
    }

    pub fn getAvailableWrite(self: *const BodyRingDescriptor) usize {
        const head = self.head.load(.acquire);
        const tail = self.tail.load(.acquire);
        return self.capacity - @as(usize, @intCast(head - tail));
    }

    pub fn getAvailableRead(self: *const BodyRingDescriptor) usize {
        const head = self.head.load(.acquire);
        const tail = self.tail.load(.acquire);
        return @as(usize, @intCast(head - tail));
    }

    /// Returns iovec-style slices for scatter-gather I/O
    pub fn getWriteBuffers(self: *BodyRingDescriptor) [2][]u8 {
        const head = self.head.load(.acquire);
        const tail = self.tail.load(.acquire);
        const capacity = self.capacity;

        const head_idx = head % capacity;
        const tail_idx = tail % capacity;

        if (head - tail == capacity) return .{ &.{}, &.{} };

        if (head_idx >= tail_idx) {
            // Case 1: [---tail++++head---]
            // Case 2: [++++head---tail++++] (Wait, if head-tail < capacity, this case is different)
            // If head_idx >= tail_idx, write buffer is from head_idx to end, and then 0 to tail_idx
            return .{
                self.buffer_ptr[head_idx..capacity],
                self.buffer_ptr[0..tail_idx],
            };
        } else {
            // Case: [+++head----tail+++]
            return .{
                self.buffer_ptr[head_idx..tail_idx],
                &.{},
            };
        }
    }

    pub fn commitWrite(self: *BodyRingDescriptor, bytes: usize) void {
        _ = self.head.fetchAdd(bytes, .release);
    }

    pub fn isFull(self: *const BodyRingDescriptor) bool {
        return self.getAvailableWrite() == 0;
    }

    pub fn shouldStopReading(self: *const BodyRingDescriptor) bool {
        // High watermark: 95%
        return self.getAvailableRead() > (self.capacity * 95 / 100);
    }

    pub fn shouldResumeReading(self: *const BodyRingDescriptor) bool {
        // Low watermark: 50%
        return self.getAvailableRead() < (self.capacity * 50 / 100);
    }
};

pub const BodyRingManager = struct {
    regions: std.AutoHashMap(u64, BodyRingDescriptor),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) BodyRingManager {
        return .{
            .regions = std.AutoHashMap(u64, BodyRingDescriptor).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *BodyRingManager) void {
        self.regions.deinit();
    }

    pub fn registerRegion(self: *BodyRingManager, id: u64, ptr: [*]u8, capacity: usize) BodyRingError!void {
        if (self.regions.contains(id)) return error.AlreadyRegistered;
        try self.regions.put(id, BodyRingDescriptor.init(ptr, capacity));
    }

    pub fn getRegion(self: *BodyRingManager, id: u64) ?*BodyRingDescriptor {
        return self.regions.getPtr(id);
    }

    pub fn unregisterRegion(self: *BodyRingManager, id: u64) void {
        _ = self.regions.remove(id);
    }
};
