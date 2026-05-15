# Quick Start Guide 🚀

Get up and running with the Zawra Networking Stack in 5 minutes!

## Prerequisites

Make sure you have these installed:

```bash
# Check your versions
zig --version    # Should be 0.11+
mojo --version   # Latest
rustc --version  # Latest
```

## 1. Clone & Build

```bash
git clone <repository-url>
cd zawra-netstack

# Build everything
./build.sh

# Verify build
./build.sh test
```

## 2. Your First Request

Create `hello_world.zig`:

```zig
const std = @import("std");
const zawra = @import("zawra_netstack");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    
    var fetch = zawra.ZawraFetch.init(.{
        .allocator = gpa.allocator(),
    });
    defer fetch.deinit();
    
    // Simple GET request
    const result = try fetch.get("https://httpbin.org/get", .{});
    defer result.deinit();
    
    std.log.info("Status: {}", .{result.status});
    std.log.info("Response: {}", .{result.body});
}
```

Run it:
```bash
zig run hello_world.zig
```

## 3. HTTP/2 with Headers

```zig
const std = @import("std");
const zawra = @import("zawra_netstack");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    
    var fetch = zawra.ZawraFetch.init(.{
        .allocator = gpa.allocator(),
    });
    defer fetch.deinit();
    
    var options = zawra.FetchOptions.init();
    try options.set_header("User-Agent", "MyApp/1.0");
    try options.set_header("Accept", "application/json");
    
    const result = try fetch.get("https://httpbin.org/headers", options);
    defer result.deinit();
    
    std.log.info("Status: {}", .{result.status});
    std.log.info("Headers received: {}", .{result.headers});
}
```

## 4. POST Request with JSON

```zig
const std = @import("std");
const zawra = @import("zawra_netstack");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    
    var fetch = zawra.ZawraFetch.init(.{
        .allocator = gpa.allocator(),
    });
    defer fetch.deinit();
    
    var options = zawra.FetchOptions.init();
    try options.set_header("Content-Type", "application/json");
    
    const json_data = "{\"name\": \"John\", \"age\": 30}";
    const result = try fetch.post("https://httpbin.org/post", json_data, options);
    defer result.deinit();
    
    std.log.info("Status: {}", .{result.status});
    std.log.info("Response: {}", .{result.body});
}
```

## 5. Enable HTTP/2 & Advanced Features

```zig
const std = @import("std");
const zawra = @import("zawra_netstack");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    
    var fetch = zawra.ZawraFetch.init(.{
        .allocator = gpa.allocator(),
        .enable_http2 = true,
        .enable_connection_coalescing = true,
        .enable_early_hints = true,
    });
    defer fetch.deinit();
    
    var options = zawra.FetchOptions.init();
    try options.set_performance_budget(.{
        .max_response_time = 5000, // 5 seconds
        .max_cache_size = 100 * 1024 * 1024, // 100MB
    });
    
    const result = try fetch.get("https://httpbin.org/delay/1", options);
    defer result.deinit();
    
    std.log.info("HTTP/2 Response: {}", .{result.body});
}
```

## 6. Enable Monitoring

```zig
const std = @import("std");
const zawra = @import("zawra_netstack");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    
    // Enable real-time monitoring
    var monitor = zawra.MonitoringDashboard.init(.{
        .allocator = gpa.allocator(),
    });
    defer monitor.deinit();
    
    try monitor.enable_real_time_metrics();
    try monitor.start_web_server(8080); // http://localhost:8080
    
    var fetch = zawra.ZawraFetch.init(.{
        .allocator = gpa.allocator(),
    });
    defer fetch.deinit();
    
    // Make requests while monitoring
    const result = try fetch.get("https://httpbin.org/get", .{});
    defer result.deinit();
    
    std.log.info("Request completed! Check http://localhost:8080 for metrics");
}
```

## 7. Error Handling

```zig
const std = @import("std");
const zawra = @import("zawra_netstack");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    
    var fetch = zawra.ZawraFetch.init(.{
        .allocator = gpa.allocator(),
    });
    defer fetch.deinit();
    
    // Handle different error cases
    const result = fetch.get("https://nonexistent-domain.invalid", .{});
    
    switch (result) {
        .ok => |resp| {
            defer resp.deinit();
            std.log.info("Success: {}", .{resp.status});
        },
        .err => |err| {
            std.log.err("Request failed: {}", .{err});
            // Handle specific error types
            switch (err) {
                .dns_resolution_failed => std.log.err("DNS resolution failed", .{}),
                .connection_timeout => std.log.err("Connection timed out", .{}),
                .tls_handshake_failed => std.log.err("TLS handshake failed", .{}),
                else => std.log.err("Unknown error: {}", .{err}),
            }
        },
    }
}
```

## 8. QUIC/HTTP3 Usage

```zig
const std = @import("std");
const zawra = @import("zawra_netstack");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    
    var quic_options = zawra.QuicOptions.init();
    quic_options.enable_0rtt = true;
    quic_options.enable_connection_migration = true;
    
    var fetch = zawra.ZawraFetch.init(.{
        .allocator = gpa.allocator(),
        .quic_options = quic_options,
    });
    defer fetch.deinit();
    
    const result = try fetch.get("https://http3.cloudflare-dns.com/dns-query", .{});
    defer result.deinit();
    
    std.log.info("QUIC Response: {}", .{result.body});
}
```

## 9. Performance Tips

### Connection Pooling
```zig
var fetch = zawra.ZawraFetch.init(.{
    .allocator = gpa.allocator(),
    .max_connections_per_host = 10,
    .connection_timeout = 30000, // 30s
    .enable_keep_alive = true,
});
```

### Caching
```zig
var options = zawra.FetchOptions.init();
try options.enable_cache(true);
try options.set_cache_ttl(3600); // 1 hour
```

### Rate Limiting
```zig
var fetch = zawra.ZawraFetch.init(.{
    .allocator = gpa.allocator(),
    .rate_limit_per_host = 5, // 5 requests per host
    .rate_limit_window = 1000, // per second
});
```

## 🆘 Common Issues

### Build Errors
```bash
# Clean build
rm -rf build/
./build.sh

# Check dependencies
./build.sh check-deps
```

### Connection Issues
```bash
# Test connectivity
curl -v https://httpbin.org/get

# Check DNS resolution
nslookup httpbin.org
```

### Performance Issues
- Enable HTTP/2 for multiplexing
- Use connection coalescing
- Enable caching for static resources
- Monitor with the built-in dashboard

## 📚 Next Steps

- Read [DEVELOPER_GUIDE.md](DEVELOPER_GUIDE.md) for advanced usage
- Check [API_REFERENCE.md](API_REFERENCE.md) for complete API docs
- See [ARCHITECTURE.md](ARCHITECTURE.md) for system design
- Try the examples in `/examples` directory

## 🆘 Getting Help

- **Documentation**: Check the docs folder
- **Examples**: See `/examples` directory
- **Issues**: Open a GitHub issue
- **Discussions**: Use GitHub Discussions

---

**Ready to build something amazing? 🎉**