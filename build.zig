const std = @import("std");

pub fn build(b: *std.Build) void {
    const optimize = b.standardOptimizeOption(.{});
    const target = b.standardTargetOptions(.{});

    // ============================================================
    // Phase 4.1: Automate Cargo Build Step
    // ============================================================
    const cargo_build = b.addSystemCommand(&.{
        "cargo", "build", "--release", "--lib",
        "--manifest-path", "engine/Cargo.toml"
    });

    const rust_lib_path = b.path("engine/target/release/libz_net_engine.a");

    // Module Definitions
    const z_socket = b.addModule("z_socket", .{
        .root_source_file = b.path("src/z_socket/socket.zig"),
        .target = target,
        .optimize = optimize,
    });

    const z_network_bridge = b.addModule("z_network_bridge", .{
        .root_source_file = b.path("src/z_network_bridge.zig"),
        .target = target,
        .optimize = optimize,
    });

    const z_config = b.addModule("z_config", .{
        .root_source_file = b.path("src/z_config/validator.zig"),
        .target = target,
        .optimize = optimize,
    });

    const z_health = b.addModule("z_health", .{
        .root_source_file = b.path("src/z_health/checker.zig"),
        .target = target,
        .optimize = optimize,
    });

    const z_monitoring = b.addModule("z_monitoring", .{
        .root_source_file = b.path("src/z_monitoring/dashboard.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Feature 1: Compression
    const z_compression = b.addModule("z_compression", .{
        .root_source_file = b.path("src/z_compression/compression.zig"),
        .target = target,
        .optimize = optimize,
    });
    z_compression.addImport("z_body_ring", b.createModule(.{
        .root_source_file = b.path("src/z_body_ring.zig"),
        .target = target,
        .optimize = optimize,
    }));

    // Feature 2: Proxies
    const z_proxy = b.addModule("z_proxy", .{
        .root_source_file = b.path("src/z_proxy/proxy.zig"),
        .target = target,
        .optimize = optimize,
    });
    z_proxy.addImport("z_socket", z_socket);

    // Feature 3: WebTransport
    const z_webtransport = b.addModule("z_webtransport", .{
        .root_source_file = b.path("src/z_webtransport/webtransport.zig"),
        .target = target,
        .optimize = optimize,
    });
    const z_quic = b.addModule("z_quic", .{
        .root_source_file = b.path("src/z_quic/quic.zig"),
        .target = target,
        .optimize = optimize,
    });
    // z_tls is backed by the rustls C ABI in lean-net (see
    // `engine/src/lib.rs`). The static library itself is gated on a
    // build option so the default test build does not need the full
    // transitive Rust dependency graph; passing `-Dznet-link-rust=true`
    // enables the FFI link for downstream executables that need a
    // real TLS implementation.
    const link_rust = b.option(bool, "znet-link-rust", "Link the z-net-engine static lib (libz_net_engine.a) into Zig modules that consume its C ABI") orelse false;
    const z_tls = b.createModule(.{
        .root_source_file = b.path("src/z_tls/tls.zig"),
        .target = target,
        .optimize = optimize,
    });
    if (link_rust) {
        z_tls.addObjectFile(rust_lib_path);
        z_tls.link_libc = true;
    }
    z_tls.addImport("z_socket", z_socket);
    z_tls.addImport("z_proxy", z_proxy);
    z_quic.addImport("z_socket", z_socket);
    z_quic.addImport("z_tls", z_tls);
    z_webtransport.addImport("z_quic", z_quic);
    z_webtransport.addImport("z_http3", b.createModule(.{
        .root_source_file = b.path("src/z_http3/http3.zig"),
        .target = target,
        .optimize = optimize,
    }));

    // Root module
    const znet = b.addModule("znet", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    znet.addImport("z_socket", z_socket);
    znet.addImport("z_network_bridge", z_network_bridge);
    znet.addImport("z_config", z_config);
    znet.addImport("z_health", z_health);
    znet.addImport("z_monitoring", z_monitoring);
    znet.addImport("z_compression", z_compression);
    znet.addImport("z_proxy", z_proxy);
    znet.addImport("z_webtransport", z_webtransport);

    // Monitor Executable
    const monitor_exe = b.addExecutable(.{
        .name = "znet-monitor",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/z_monitoring/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    monitor_exe.root_module.addImport("dashboard", z_monitoring);
    monitor_exe.root_module.addImport("z_config", z_config);
    monitor_exe.root_module.addImport("z_health", z_health);
    b.installArtifact(monitor_exe);

    // Tests
    const test_step = b.step("test", "Run all tests");

    const modules_to_test = [_]*std.Build.Module{
        z_socket, z_network_bridge, z_config, z_health, z_monitoring,
        z_compression, z_proxy, z_tls, z_webtransport,
    };

    for (modules_to_test) |mod| {
        const t = b.addTest(.{
            .root_module = mod,
        });
        const run_t = b.addRunArtifact(t);
        test_step.dependOn(&run_t.step);
    }

    _ = cargo_build;
}
