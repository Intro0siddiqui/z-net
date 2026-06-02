const std = @import("std");

pub fn build(b: *std.Build) void {
    const optimize = b.standardOptimizeOption(.{});
    const target = b.standardTargetOptions(.{});

    // ============================================================
    // Phase 4.1: Automate Cargo Build Step
    // ============================================================
    const cargo_build = b.addSystemCommand(&.{ 
        "cargo", "build", "--release", "--lib", 
        "--manifest-path", "rust_net/Cargo.toml"
    });
    
    const rust_lib_path = b.path("rust_net/target/release/liblean_net.a");

    // Module Definitions
    const z_socket = b.addModule("z_socket", .{
        .root_source_file = b.path("src/z_socket/socket.zig"),
        .target = target,
        .optimize = optimize,
    });
    z_socket.linkSystemLibrary("z", .{});
    z_socket.linkSystemLibrary("brotlidec", .{});
    z_socket.linkSystemLibrary("brotlicommon", .{});
    z_socket.linkSystemLibrary("zstd", .{});

    const z_network_bridge = b.addModule("z_network_bridge", .{
        .root_source_file = b.path("src/z_network_bridge.zig"),
        .target = target,
        .optimize = optimize,
    });
    z_network_bridge.linkSystemLibrary("z", .{});
    z_network_bridge.linkSystemLibrary("brotlidec", .{});
    z_network_bridge.linkSystemLibrary("brotlicommon", .{});
    z_network_bridge.linkSystemLibrary("zstd", .{});

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

    // Monitor Executable
    const monitor_exe = b.addExecutable(.{
        .name = "znet-monitor",
        .root_source_file = b.path("src/z_monitoring/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    monitor_exe.root_module.addImport("dashboard", z_monitoring);
    monitor_exe.root_module.addImport("z_config", z_config);
    monitor_exe.root_module.addImport("z_health", z_health);
    b.installArtifact(monitor_exe);

    // Tests
    const test_step = b.step("test", "Run all tests");

    const modules_to_test = [_]*std.Build.Module{
        z_socket, z_network_bridge, z_config, z_health, z_monitoring,
    };

    for (modules_to_test) |mod| {
        const t = b.addTest(.{
            .root_source_file = mod.root_source_file.?,
            .target = target,
            .optimize = optimize,
        });
        const run_t = b.addRunArtifact(t);
        test_step.dependOn(&run_t.step);
    }

    _ = cargo_build;
    _ = rust_lib_path;
}
