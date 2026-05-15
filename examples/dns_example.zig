//! DNS Example - Demonstrating DNS resolution capabilities
//! Usage: zig run examples/dns_example.zig

const std = @import("std");
const dns = @import("../src/z_dns/dns.zig");
const socket = @import("../src/z_socket/socket.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.log.info("Starting Zawra DNS Example", .{});

    // Create DNS resolver
    var dns_cache = dns.DnsCache.init(allocator);
    defer dns_cache.deinit();

    var resolver = dns.DnsResolver.init(allocator, &dns_cache);

    // Test domains
    const test_domains = &[_][]const u8{
        "google.com",
        "github.com",
        "cloudflare.com",
        "stackoverflow.com",
        "reddit.com",
        "discord.com",
        "openai.com",
        "microsoft.com",
        "amazon.com",
        "youtube.com",
    };

    // Example 1: Basic DNS resolution
    std.log.info("\n=== Example 1: Basic DNS Resolution ===", .{});
    
    for (test_domains) |domain| {
        std.log.info("Resolving {}", .{domain});

        // Resolve A records (IPv4)
        var a_query = dns.DnsQuery{
            .name = domain,
            .record_type = dns.DnsRecordType.A,
        };

        const a_result = resolver.resolve(a_query) catch |err| {
            std.log.err("A record resolution failed: {}", .{err});
            continue;
        };

        if (a_result.len > 0) {
            std.log.info("✅ IPv4 addresses for {}:", .{domain});
            for (a_result) |answer| {
                std.log.info("  {}", .{answer.data});
            }
        } else {
            std.log.warn("⚠️ No IPv4 addresses found for {}", .{domain});
        }

        // Resolve AAAA records (IPv6)
        var aaaa_query = dns.DnsQuery{
            .name = domain,
            .record_type = dns.DnsRecordType.AAAA,
        };

        const aaaa_result = resolver.resolve(aaaa_query) catch |err| {
            std.log.err("AAAA record resolution failed: {}", .{err});
            continue;
        };

        if (aaaa_result.len > 0) {
            std.log.info("✅ IPv6 addresses for {}:", .{domain});
            for (aaaa_result) |answer| {
                std.log.info("  {}", .{answer.data});
            }
        } else {
            std.log.info("ℹ️ No IPv6 addresses found for {}", .{domain});
        }
    }

    // Example 2: Different DNS protocols
    std.log.info("\n=== Example 2: DNS Protocol Comparison ===", .{});

    var resolver_doh = dns.DnsResolver.init(allocator, &dns_cache);
    resolver_doh.prefer_doh = true; // Prefer DNS over HTTPS

    var resolver_dot = dns.DnsResolver.init(allocator, &dns_cache);
    resolver_dot.prefer_doh = false; // Prefer DNS over TLS

    const test_domain = "example.com";

    std.log.info("Testing {} with different DNS protocols", .{test_domain});

    // Test DoH
    var doh_query = dns.DnsQuery{
        .name = test_domain,
        .record_type = dns.DnsRecordType.A,
    };

    const doh_start = std.time.timestamp();
    const doh_result = resolver_doh.resolve(doh_query) catch |err| {
        std.log.err("DoH resolution failed: {}", .{err});
        return;
    };
    const doh_end = std.time.timestamp();
    const doh_time = @intToFloat(f64, doh_end - doh_start);

    std.log.info("✅ DoH result: {} addresses in {:.3}s", .{
        doh_result.len,
        doh_time,
    });

    // Test DoT
    var dot_query = dns.DnsQuery{
        .name = test_domain,
        .record_type = dns.DnsRecordType.A,
    };

    const dot_start = std.time.timestamp();
    const dot_result = resolver_dot.resolve(dot_query) catch |err| {
        std.log.err("DoT resolution failed: {}", .{err});
        return;
    };
    const dot_end = std.time.timestamp();
    const dot_time = @intToFloat(f64, dot_end - dot_start);

    std.log.info("✅ DoT result: {} addresses in {:.3}s", .{
        dot_result.len,
        dot_time,
    });

    // Example 3: Cache testing
    std.log.info("\n=== Example 3: DNS Cache Testing ===", .{});

    const cache_test_domain = "cache-test.example.com";
    var cache_query = dns.DnsQuery{
        .name = cache_test_domain,
        .record_type = dns.DnsRecordType.A,
    };

    // First resolution (should be a miss)
    const miss_start = std.time.timestamp();
    const miss_result = resolver.resolve(cache_query) catch |err| {
        std.log.err("Cache test resolution failed: {}", .{err});
        return;
    };
    const miss_end = std.time.timestamp();
    const miss_time = @intToFloat(f64, miss_end - miss_start);

    std.log.info("📊 First resolution (cache miss): {} addresses in {:.3}s", .{
        miss_result.len,
        miss_time,
    });

    // Second resolution (should be a hit)
    const hit_start = std.time.timestamp();
    const hit_result = resolver.resolve(cache_query) catch |err| {
        std.log.err("Cache test resolution failed: {}", .{err});
        return;
    };
    const hit_end = std.time.timestamp();
    const hit_time = @intToFloat(f64, hit_end - hit_start);

    std.log.info("⚡ Second resolution (cache hit): {} addresses in {:.3}s", .{
        hit_result.len,
        hit_time,
    });

    if (hit_time < miss_time) {
        const speedup = miss_time / hit_time;
        std.log.info("🚀 Cache speedup: {:.1}x faster", .{speedup});
    }

    // Example 4: Error handling
    std.log.info("\n=== Example 4: Error Handling ===", .{});

    const invalid_domains = &[_][]const u8{
        "invalid-domain-that-does-not-exist.com",
        "",
        "invalid..double..dots.com",
        "http://invalid-protocol.com", // Should be treated as hostname
    };

    for (invalid_domains) |domain| {
        std.log.info("Testing invalid domain: '{}'", .{domain});

        var invalid_query = dns.DnsQuery{
            .name = domain,
            .record_type = dns.DnsRecordType.A,
        };

        const invalid_result = resolver.resolve(invalid_query) catch |err| {
            std.log.err("✅ Expected error: {}", .{err});
            continue;
        };

        std.log.warn("⚠️ Unexpected success with invalid domain", .{});
        _ = invalid_result;
    }

    // Example 5: Performance comparison
    std.log.info("\n=== Example 5: Performance Comparison ===", .{});

    const perf_domains = &[_][]const u8{
        "1.1.1.1",
        "8.8.8.8", 
        "9.9.9.9",
        "1.0.0.1",
        "208.67.222.222",
    };

    var total_time: f64 = 0.0;
    var successful_resolutions: u32 = 0;
    var failed_resolutions: u32 = 0;

    for (perf_domains) |domain| {
        std.log.info("Benchmarking resolution of {}", .{domain});

        var query = dns.DnsQuery{
            .name = domain,
            .record_type = dns.DnsRecordType.A,
        };

        const start = std.time.timestamp();
        const result = resolver.resolve(query);
        const end = std.time.timestamp();
        const resolution_time = @intToFloat(f64, end - start);

        if (result) |answers| {
            std.log.info("✅ {}: {} addresses in {:.3}s", .{ 
                domain, 
                answers.len, 
                resolution_time 
            });
            successful_resolutions += 1;
        } else |err| {
            std.log.err("❌ {}: failed in {:.3}s ({})", .{
                domain,
                resolution_time,
                err,
            });
            failed_resolutions += 1;
        }

        total_time += resolution_time;
    }

    if (successful_resolutions > 0) {
        const avg_time = total_time / @intToFloat(f64, successful_resolutions);
        std.log.info("📊 Performance Summary:", .{});
        std.log.info("  ✅ Successful: {}", .{successful_resolutions});
        std.log.info("  ❌ Failed: {}", .{failed_resolutions});
        std.log.info("  ⏱️ Average time: {:.3}s", .{avg_time});
        std.log.info("  🚀 Total time: {:.3}s", .{total_time});
    }

    // Example 6: Reverse DNS lookup simulation
    std.log.info("\n=== Example 6: Reverse DNS Lookup ===", .{});

    const ip_addresses = &[_][]const u8{
        "1.1.1.1",
        "8.8.8.8",
        "9.9.9.9",
    };

    for (ip_addresses) |ip| {
        std.log.info("Reverse lookup for IP: {}", .{ip});

        // Convert IP to reverse lookup format
        var ip_parts: [4]u8 = undefined;
        var part_index: usize = 0;
        
        var ip_str = ip;
        var start: usize = 0;
        
        for (ip.len + 1) |i| {
            if (i == ip.len or ip[i] == '.') {
                if (part_index < 4) {
                    ip_parts[part_index] = std.fmt.parseInt(u8, ip_str[start..i], 10) catch 0;
                    part_index += 1;
                }
                start = i + 1;
            }
        }

        if (part_index == 4) {
            const reverse_name = std.fmt.allocPrint(allocator, 
                "{}.{}.{}.{}.in-addr.arpa", .{
                    ip_parts[3], ip_parts[2], ip_parts[1], ip_parts[0]
                }) catch unreachable;
            defer allocator.free(reverse_name);

            std.log.info("🔄 Reverse lookup: {}", .{reverse_name});

            var ptr_query = dns.DnsQuery{
                .name = reverse_name,
                .record_type = dns.DnsRecordType.PTR, // Not implemented in current version
            };

            // Note: PTR record type would need to be added to DnsRecordType enum
            // For now, just show the reverse lookup format
            std.log.info("ℹ️ PTR lookup format ready for: {}", .{reverse_name});
        }
    }

    std.log.info("\n🎉 DNS Example completed successfully!", .{});
    std.log.info("💡 DNS Cache contains {} entries", .{dns_cache.entries.count()});
}