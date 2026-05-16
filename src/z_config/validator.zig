const std = @import("std");
const fs = std.fs;
const mem = std.mem;
const json = std.json;

pub const ValidationSeverity = enum {
    info,
    warning,
    err,
    critical,
};

pub const ValidationResult = struct {
    file_path: []const u8,
    is_valid: bool,
    severity: ValidationSeverity,
    message: []const u8,
};

pub const ConfigValidator = struct {
    allocator: mem.Allocator,

    pub fn init(allocator: mem.Allocator) ConfigValidator {
        return .{ .allocator = allocator };
    }

    pub fn validateFile(self: *ConfigValidator, path: []const u8) !ValidationResult {
        const file = try fs.cwd().openFile(path, .{});
        defer file.close();

        const content = try file.readToEndMax(self.allocator, 10 * 1024 * 1024);
        defer self.allocator.free(content);

        // Simple JSON validation as an example
        var parser = json.Parser.init(self.allocator, .external);
        defer parser.deinit();

        var tree = parser.parse(content) catch |err| {
            return ValidationResult{
                .file_path = try self.allocator.dupe(u8, path),
                .is_valid = false,
                .severity = .err,
                .message = try std.fmt.allocPrint(self.allocator, "JSON parse error: {}", .{err}),
            };
        };
        tree.deinit();

        return ValidationResult{
            .file_path = try self.allocator.dupe(u8, path),
            .is_valid = true,
            .severity = .info,
            .message = "Configuration is valid",
        };
    }

    pub fn detectDrift(self: *ConfigValidator, dir_path: []const u8, reference_hashes: std.StringHashMap([32]u8)) !void {
        var dir = try fs.cwd().openIterableDir(dir_path, .{});
        defer dir.close();

        var walker = try dir.walk(self.allocator);
        defer walker.deinit();

        while (try walker.next()) |entry| {
            if (entry.kind == .file) {
                const file_path = try fs.path.join(self.allocator, &[_][]const u8{ dir_path, entry.path });
                defer self.allocator.free(file_path);

                const file = try fs.cwd().openFile(file_path, .{});
                defer file.close();

                const content = try file.readToEndMax(self.allocator, 10 * 1024 * 1024);
                defer self.allocator.free(content);

                var hash: [32]u8 = undefined;
                std.crypto.hash.sha2.Sha256.hash(content, &hash, .{});

                if (reference_hashes.get(entry.path)) |ref_hash| {
                    if (!mem.eql(u8, &hash, &ref_hash)) {
                        std.debug.print("Drift detected in file: {s}\n", .{entry.path});
                    }
                }
            }
        }
    }
};
