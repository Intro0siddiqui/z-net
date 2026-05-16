# Quick Start Guide 🚀

Get up and running with the Zawra Networking Stack in 5 minutes!

## Prerequisites

Make sure you have these installed:

```bash
# Check your versions
zig version      # Should be 0.12+
rustc --version  # Latest
```

## 1. Clone & Build

```bash
git clone <repository-url>
cd zawra-netstack

# Build everything using the Zig build system
zig build

# Or use the helper script
./build.sh build
```

## 2. Your First Request (Zig)

Create `hello_world.zig`:

```zig
const std = @import("std");
const zawra = @import("zawra_netstack");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    // Initialize the stack
    try zawra.init(allocator);
    defer zawra.deinit();
    
    // Create a fetch client
    var fetch = try zawra.Fetch.init(allocator);
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
const zawra = @import("zawra_netstack");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    try zawra.init(allocator);
    defer zawra.deinit();
    
    var fetch = try zawra.Fetch.init(allocator);
    defer fetch.deinit();
    
    // Configure options
    var options = zawra.FetchOptions.init(allocator);
    defer options.deinit();
    try options.headers.put("Content-Type", "application/json");
    options.timeout_ms = 10000;
    
    // POST request with JSON body
    const body = "{\"name\": \"Zawra\", \"version\": \"1.0\"}";
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
const zawra = @import("zawra_netstack");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    try zawra.init(allocator);
    defer zawra.deinit();
    
    var fetch = try zawra.Fetch.init(allocator);
    defer fetch.deinit();
    
    var options = zawra.FetchOptions.init(allocator);
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
- See [ARCHITECTURE.md](ARCHITECTURE.md) for a deep dive into how Zawra works.

---

**Ready to build something amazing? 🎉**
