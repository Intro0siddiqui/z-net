# Zig Engineering Rules

This document outlines the core strategies used in the `z-net` project for high-performance, OS-agnostic engineering.

## 1. Unified I/O (Zig 0.16+)
Always use the `std.Io` interface for networking, file systems, and timers. This pattern centralizes I/O and uses dependency injection (similar to `std.mem.Allocator`).

**Rule:** All structs or functions performing I/O must accept an `io_ctx: *std.Io` parameter.

```zig
pub fn connect(self: *Self, io_ctx: *std.Io, addr: net.Address) !void {
    // Zero-cost abstraction over epoll/kqueue/IOCP
    return io_ctx.connect(self.handle, addr);
}
```

---

## 2. The "Zig Method" for OS-Agnosticism
When implementing OS-specific logic (such as reading system metrics), use compile-time dispatch to provide the fastest native implementation for each platform while maintaining a single public API.

**Rule:** **1 API, 3 Fast Code Paths.**

```zig
const std = @import("std");
const builtin = @import("builtin");

/// Public API: looks the same on every OS
pub fn getRxBytes(allocator: std.mem.Allocator, ifname: []const u8) !u64 {
    return switch (builtin.os.tag) {
       .linux => try getRxBytesLinux(ifname),
       .macos, .freebsd, .openbsd, .netbsd => try getRxBytesBsd(allocator, ifname),
       .windows => try getRxBytesWindows(ifname),
        else => error.UnsupportedOs,
    };
}
```

### Native Implementation Patterns:

1. **Linux version:** Read `/sys` or `/proc` directly, keeping file descriptors open where possible for speed.
2. **macOS/BSD version:** Use `sysctl` to fetch kernel structs directly (avoiding expensive text parsing).
3. **Windows version:** Use direct Win32 API struct access (e.g., `GetIfTable2`).

### Why this is the Zig method:
1. **1 API for the user**: The consumer doesn't care which OS they are on.
2. **0 runtime cost**: `switch(builtin.os.tag)` is evaluated at **compile-time**. The Windows code is physically deleted from the Linux binary.
3. **No dependencies**: Rely on the standard library and native kernel APIs for maximum efficiency.
