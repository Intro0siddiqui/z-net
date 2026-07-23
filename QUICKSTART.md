# Quick Start Guide 🚀

Get up and running with z-net in 5 minutes!

## Prerequisites

Make sure you have these installed:

```bash
# Check your versions
zig version      # Should be 0.16.0+
rustc --version  # Latest
```

## 1. Clone & Build

```bash
git clone https://github.com/Intro0siddiqui/z-net
cd z-net

# Build libznet.a static library and tools using Zig 0.16.0
zig build -Doptimize=ReleaseFast
```

Build outputs:
- Static C-ABI Library: `zig-out/lib/libznet.a` (for Go / CGO interop)
- Monitor Executable: `zig-out/bin/znet-monitor`

## 2. Your First Request (Zig)

Create `hello_world.zig`:

```zig
const std = @import("std");
const znet = @import("znet");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    // Initialize the stack
    try znet.init(allocator);
    defer znet.deinit();
    
    // Create a fetch client
    var fetch = try znet.Fetch.init(allocator);
    defer fetch.deinit();
    
    // Simple GET request
    const response = try fetch.get("https://httpbin.org/get", .{});
    defer response.deinit();
    
    std.debug.print("Status: {d}\n", .{response.status});
    if (response.body) |body| {
        std.debug.print("Body: {s}\n", .{body});
    }
}
```

## 3. Advanced Usage (Headers & POST)

```zig
const std = @import("std");
const znet = @import("znet");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    try znet.init(allocator);
    defer znet.deinit();
    
    var fetch = try znet.Fetch.init(allocator);
    defer fetch.deinit();
    
    // Configure options
    var options = znet.FetchOptions.init(allocator);
    defer options.deinit();
    try options.headers.put("Content-Type", "application/json");
    options.timeout_ms = 10000;
    
    // POST request with JSON body
    const body = "{\"name\": \"z-net\", \"version\": \"1.0\"}";
    const response = try fetch.post("https://httpbin.org/post", body, options);
    defer response.deinit();
    
    if (response.status == 200) {
        std.debug.print("POST Successful!\n", .{});
    }
}
```

## 4. Caching & Performance

```zig
const std = @import("std");
const znet = @import("znet");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    try znet.init(allocator);
    defer znet.deinit();
    
    var fetch = try znet.Fetch.init(allocator);
    defer fetch.deinit();
    
    var options = znet.FetchOptions.init(allocator);
    defer options.deinit();
    options.enable_cache = true;
    
    // First request - Fetch from network
    const res1 = try fetch.get("https://httpbin.org/get", options);
    std.debug.print("Request 1 - From Cache: {any}\n", .{res1.from_cache});
    res1.deinit();
    
    // Second request - Served from local z_cache
    const res2 = try fetch.get("https://httpbin.org/get", options);
    std.debug.print("Request 2 - From Cache: {any}\n", .{res2.from_cache});
    res2.deinit();
}
```

## 📚 Next Steps

- Read [DEVELOPER_GUIDE.md](DEVELOPER_GUIDE.md) for advanced usage.
- Check [API_REFERENCE.md](API_REFERENCE.md) for complete API documentation.
- See [ARCHITECTURE.md](ARCHITECTURE.md) for a deep dive into how z-net works.

---

**Ready to build something amazing? 🎉**
