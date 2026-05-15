const std = @import("std");

pub fn build(b: *std.Build) void {
    const optimize = b.standardOptimizeOption(.{});
    const target = b.standardTargetOptions(.{});

    // ============================================================
    // Phase 4.1: Automate Cargo Build Step
    // ============================================================
    // Build Rust lean-net library before Zig compilation
    const rust_manifest_path = b.path("rust_net/Cargo.toml");
    const cargo_build = b.addSystemCommand(&.{ 
        "cargo", "build", "--release", "--lib", 
        "--manifest-path", rust_manifest_path.getPath() 
    });
    
    // Get output path for linking
    const rust_target_dir = b.path("rust_net/target/release");
    const rust_lib_path = rust_target_dir.join("liblean_net.a");

    // ============================================================
    // Module Definitions
    // ============================================================

    // z_socket - Foundation Layer
    const z_socket = b.addModule(.{
        .name = "z_socket",
        .root_source_file = b.path("src/z_socket/socket.zig"),
        .target = target,
        .optimize = optimize,
        .test = true,
    });

    // z_network_bridge - Rust FFI Layer
    const z_network_bridge = b.addModule(.{
        .name = "z_network_bridge",
        .root_source_file = b.path("src/z_network_bridge.zig"),
        .target = target,
        .optimize = optimize,
        .test = true,
    });

    // z_tls - (Deprecated, use z_network_bridge instead)
    const z_tls = b.addModule(.{
        .name = "z_tls",
        .root_source_file = b.path("src/z_tls/tls.zig"),
        .target = target,
        .optimize = optimize,
        .test = true,
    });

    // z_dns - DNS Resolution Layer
    const z_dns = b.addModule(.{
        .name = "z_dns",
        .root_source_file = b.path("src/z_dns/dns.zig"),
        .target = target,
        .optimize = optimize,
        .test = true,
        .dependencies = &.{
            z_socket,
            z_network_bridge,
        },
    });

    // z_http - HTTP Protocol Layer
    const z_http = b.addModule(.{
        .name = "z_http",
        .root_source_file = b.path("src/z_http/http.mojo"),
        .target = target,
        .optimize = optimize,
        .test = true,
        .dependencies = &.{
            z_socket,
            z_dns,
        },
    });

    // z_cache - Caching Layer
    const z_cache = b.addModule(.{
        .name = "z_cache",
        .root_source_file = b.path("src/z_cache/cache.zig"),
        .target = target,
        .optimize = optimize,
        .test = true,
    });

    // z_security - Security and Privacy Layer
    const z_security = b.addModule(.{
        .name = "z_security",
        .root_source_file = b.path("src/z_security/security.zig"),
        .target = target,
        .optimize = optimize,
        .test = true,
    });

    // Root module that combines everything
    b.addModule(.{
        .name = "zawra_netstack",
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .test = true,
        .dependencies = &.{
            z_socket,
            z_network_bridge,
            z_tls,
            z_dns,
            z_http,
            z_cache,
            z_security,
        },
    });

    // ============================================================
    // Example Programs with Rust Integration
    // ============================================================
    addHttpExample(b, target, optimize, &.{
        z_http,
        z_network_bridge,
        z_dns,
        z_cache,
        z_security,
    });

    addDnsExample(b, target, optimize, &.{
        z_dns,
        z_socket,
    });

    addTlsExample(b, target, optimize, &.{
        z_network_bridge,
        z_socket,
    });

    // ============================================================
    // Benchmarks
    // ============================================================
    addBenchmark(b, target, optimize, &.{
        z_socket,
        z_network_bridge,
        z_dns,
        z_http,
        z_cache,
        z_security,
    });

    // ============================================================
    // Tests
    // ============================================================
    const test_step = b.step("test", "Run all tests");
    test_step.dependOn(z_socket.test);
    test_step.dependOn(z_network_bridge.test);
    test_step.dependOn(z_dns.test);
    test_step.dependOn(z_http.test);
    test_step.dependOn(z_cache.test);
    test_step.dependOn(z_security.test);
}

// ============================================================
// Phase 4.2: Link Static Artifacts
// ============================================================

fn addRustLinkedExecutable(
    b: *std.Build,
    name: []const u8,
    target: std.Build.Target,
    optimize: std.builtin.OptimizeMode,
    root_source: std.Build.Path,
    deps: []const *std.Build.Module,
    rust_lib: std.Build.Path,
) *std.Build.CompileStep {
    const exe = b.addExecutable(.{
        .name = name,
        .root_source_file = root_source,
        .target = target,
        .optimize = optimize,
    });

    // Add Zig module dependencies
    for (deps) |dep| {
        exe.addModule(dep);
    }

    // Link Rust static library (Step 4.2)
    exe.addObject(rust_lib);

    // Link C library for FFI alignment
    exe.linkLibC();

    return exe;
}

fn addHttpExample(b: *std.Build, target: std.Build.Target, optimize: std.builtin.OptimizeMode, dependencies: []const *std.Build.Module) void {
    const example = b.addExecutable(.{
        .name = "http_example",
        .root_source_file = b.path("examples/http_example.zig"),
        .target = target,
        .optimize = optimize,
    });

    for (dependencies) |dep| {
        example.addModule(dep);
    }

    const run_example = b.addRunArtifact(example);
    b.getInstallStep(.{}).dependOn(&run_example.step);

    const example_step = b.step("example-http", "Run HTTP example");
    example_step.dependOn(&run_example.step);
}

fn addDnsExample(b: *std.Build, target: std.Build.Target, optimize: std.builtin.OptimizeMode, dependencies: []const *std.Build.Module) void {
    const example = b.addExecutable(.{
        .name = "dns_example",
        .root_source_file = b.path("examples/dns_example.zig"),
        .target = target,
        .optimize = optimize,
    });

    for (dependencies) |dep| {
        example.addModule(dep);
    }

    const run_example = b.addRunArtifact(example);
    const example_step = b.step("example-dns", "Run DNS example");
    example_step.dependOn(&run_example.step);
}

fn addTlsExample(b: *std.Build, target: std.Build.Target, optimize: std.builtin.OptimizeMode, dependencies: []const *std.Build.Module) void {
    const example = b.addExecutable(.{
        .name = "tls_example",
        .root_source_file = b.path("examples/tls_example.zig"),
        .target = target,
        .optimize = optimize,
    });

    for (dependencies) |dep| {
        example.addModule(dep);
    }

    const run_example = b.addRunArtifact(example);
    const example_step = b.step("example-tls", "Run TLS example");
    example_step.dependOn(&run_example.step);
}

fn addBenchmark(b: *std.Build, target: std.Build.Target, optimize: std.builtin.OptimizeMode, dependencies: []const *std.Build.Module) void {
    const benchmark = b.addExecutable(.{
        .name = "netstack_benchmark",
        .root_source_file = b.path("benchmark/benchmark.zig"),
        .target = target,
        .optimize = optimize,
    });

    for (dependencies) |dep| {
        benchmark.addModule(dep);
    }

    const run_benchmark = b.addRunArtifact(benchmark);
    const benchmark_step = b.step("benchmark", "Run performance benchmarks");
    benchmark_step.dependOn(&run_benchmark.step);
}