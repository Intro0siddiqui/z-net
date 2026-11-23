//! z_body_ring - Unified Shared Memory Body Transfer Protocol
//!
//! Implements a "Pull-Style" shared memory interface for zero-copy
//! body transfers between the networking stack and other processes.

const std = @import("std");
const builtin = @import("builtin");

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
    _pad3: [48]u8,
    pause_fd: std.atomic.Value(i32),
    futex_word: std.atomic.Value(u32),
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
            .pause_fd = std.atomic.Value(i32).init(-1),
            .futex_word = std.atomic.Value(u32).init(0),
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

    pub fn signalResume(self: *BodyRingDescriptor) void {
        const pfd = self.pause_fd.load(.acquire);
        if (pfd >= 0) {
            if (comptime builtin.os.tag == .linux) {
                const val: u64 = 1;
                _ = std.os.linux.syscall3(.write, @as(usize, @intCast(pfd)), @intFromPtr(&val), 8);
            }
        }
        _ = self.futex_word.fetchAdd(1, .release);
        if (comptime builtin.os.tag == .linux) {
            _ = std.os.linux.syscall3(.futex, @intFromPtr(&self.futex_word), std.os.linux.FUTEX.WAKE, 1);
        }
    }

    pub fn waitDrain(self: *BodyRingDescriptor, timeout_ns: u64) void {
        const pfd = self.pause_fd.load(.acquire);
        if (pfd >= 0) {
            if (comptime builtin.os.tag == .linux) {
                var pfd_poll = [_]std.os.linux.pollfd{.{
                    .fd = pfd,
                    .events = std.os.linux.POLL.IN,
                    .revents = 0,
                }};
                const timeout_ms = @as(i32, @intCast(@min(timeout_ns / 1_000_000, 100)));
                _ = std.os.linux.syscall3(.poll, @intFromPtr(&pfd_poll), 1, @as(usize, @intCast(timeout_ms)));
                var val: u64 = 0;
                _ = std.os.linux.syscall3(.read, @as(usize, @intCast(pfd)), @intFromPtr(&val), 8);
            } else {
                std.time.sleep(@min(timeout_ns, 10_000_000));
            }
        } else {
            if (comptime builtin.os.tag == .linux) {
                const cur = self.futex_word.load(.acquire);
                const ts = std.os.linux.timespec{
                    .sec = 0,
                    .nsec = @as(isize, @intCast(@min(timeout_ns, 10_000_000))),
                };
                _ = std.os.linux.syscall4(.futex, @intFromPtr(&self.futex_word), std.os.linux.FUTEX.WAIT, cur, @intFromPtr(&ts));
            } else {
                std.time.sleep(@min(timeout_ns, 10_000_000));
            }
        }
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
