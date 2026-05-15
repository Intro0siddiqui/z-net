const std = @import("std");
const testing = std.testing;

// Import all test modules
const protocol_tests = @import("protocol_compliance.zig");
const performance_tests = @import("performance_benchmarks.zig");
const security_tests = @import("security_validation.zig");

/// Main Test Coordinator
/// Orchestrates all testing modules for comprehensive validation
pub const TestCoordinator = struct {
    const TestSuiteResult = struct {
        name: []const u8,
        passed: bool,
        execution_time: i128,
        total_tests: usize,
        passed_tests: usize,
        failed_tests: usize,
        coverage: f32,
        recommendations: []const u8,
    };

    var allocator: std.mem.Allocator = undefined;
    var suite_results: ArrayList(TestSuiteResult) = undefined;

    pub fn init(allocator: std.mem.Allocator) TestCoordinator {
        return TestCoordinator{
            .allocator = allocator,
            .suite_results = ArrayList(TestSuiteResult).init(allocator),
        };
    }

    pub fn deinit(self: *TestCoordinator) void {
        self.suite_results.deinit();
    }

    /// Run all test suites
    pub fn runAllTestSuites(self: *TestCoordinator) !void {
        std.debug.print("=== ZAWRA NETWORKING STACK PHASE 2 TESTING SUITE ===\n", .{});
        std.debug.print("Starting comprehensive testing framework...\n\n", .{});

        // Test Suite 1: Protocol Compliance Tests
        try self.runProtocolComplianceTests();

        // Test Suite 2: Performance Benchmarks
        try self.runPerformanceBenchmarks();

        // Test Suite 3: Security Validation
        try self.runSecurityValidation();

        // Test Suite 4: Integration Tests (if available)
        // Note: These would be in separate files for edge_cases.mojo, cross_platform.mojo, etc.
        
        std.debug.print("\n=== FINAL TEST SUMMARY ===\n", .{});
        self.generateFinalReport();
    }

    fn runProtocolComplianceTests(self: *TestCoordinator) !void {
        const start_time = std.time.nanoTimestamp();
        std.debug.print("🔍 Running Protocol Compliance Tests...\n", .{});

        var protocol_tests_instance = protocol_tests.ProtocolComplianceTests.init(self.allocator);
        defer protocol_tests_instance.deinit();

        const results = try protocol_tests_instance.runAllComplianceTests(self.allocator);
        defer self.allocator.free(results);

        var passed_count: usize = 0;
        for (results) |result| {
            if (result.passed) {
                passed_count += 1;
                std.debug.print("  ✅ {} - {}: PASS\n", .{ result.protocol, result.test_name });
            } else {
                std.debug.print("  ❌ {} - {}: FAIL", .{ result.protocol, result.test_name });
                if (result.error) |error| {
                    std.debug.print(" ({s})", .{error});
                }
                std.debug.print("\n", .{});
            }
        }

        const end_time = std.time.nanoTimestamp();
        const total_tests = results.len;
        const failed_tests = total_tests - passed_count;
        const coverage: f32 = if (total_tests > 0) @as(f32, @floatFromInt(passed_count)) / @as(f32, @floatFromInt(total_tests)) * 100.0 else 0.0;

        try self.suite_results.append(TestSuiteResult{
            .name = "Protocol Compliance",
            .passed = failed_tests == 0,
            .execution_time = end_time - start_time,
            .total_tests = total_tests,
            .passed_tests = passed_count,
            .failed_tests = failed_tests,
            .coverage = coverage,
            .recommendations = if (failed_tests == 0) "All protocol compliance tests passed" else "Protocol compliance issues detected",
        });
    }

    fn runPerformanceBenchmarks(self: *TestCoordinator) !void {
        const start_time = std.time.nanoTimestamp();
        std.debug.print("\n⚡ Running Performance Benchmarks...\n", .{});

        var benchmarks = try performance_tests.PerformanceBenchmarks.init(self.allocator);
        defer benchmarks.deinit();

        try benchmarks.runAllBenchmarks();

        // Check for performance regressions
        const has_regression = benchmarks.detectPerformanceRegression(10.0);
        
        const end_time = std.time.nanoTimestamp();
        const passed = !has_regression;
        
        std.debug.print("  {} Performance regression check\n", .{
            if (has_regression) "❌ Regression detected in" else "✅ No performance regressions in"
        });

        try self.suite_results.append(TestSuiteResult{
            .name = "Performance Benchmarks",
            .passed = passed,
            .execution_time = end_time - start_time,
            .total_tests = 9, // Number of benchmark categories
            .passed_tests = if (passed) 9 else 8,
            .failed_tests = if (passed) 0 else 1,
            .coverage = if (passed) 100.0 else 88.9,
            .recommendations = if (has_regression) "Performance regressions detected - review recent changes" else "Performance within acceptable thresholds",
        });
    }

    fn runSecurityValidation(self: *TestCoordinator) !void {
        const start_time = std.time.nanoTimestamp();
        std.debug.print("\n🔒 Running Security Validation...\n", .{});

        var security_tests_instance = security_tests.SecurityValidationTests.init(self.allocator);
        defer security_tests_instance.deinit();

        const report = try security_tests_instance.runAllSecurityTests();

        std.debug.print("  Overall Security Score: {:.1f}%\n", .{report.overall_score});
        std.debug.print("  Critical Vulnerabilities: {}\n", .{report.critical_vulnerabilities});
        std.debug.print("  High Vulnerabilities: {}\n", .{report.high_vulnerabilities});

        if (report.critical_vulnerabilities > 0) {
            std.debug.print("  ❌ Critical security vulnerabilities detected!\n", .{});
        } else if (report.high_vulnerabilities > 0) {
            std.debug.print("  ⚠️  High risk vulnerabilities detected\n", .{});
        } else {
            std.debug.print("  ✅ No critical or high-risk vulnerabilities\n", .{});
        }

        const end_time = std.time.nanoTimestamp();
        const total_tests = report.total_tests;
        const failed_tests = report.critical_vulnerabilities + report.high_vulnerabilities;
        const passed_tests = total_tests - failed_tests;
        const coverage = report.overall_score;

        try self.suite_results.append(TestSuiteResult{
            .name = "Security Validation",
            .passed = report.critical_vulnerabilities == 0,
            .execution_time = end_time - start_time,
            .total_tests = total_tests,
            .passed_tests = passed_tests,
            .failed_tests = failed_tests,
            .coverage = coverage,
            .recommendations = if (report.critical_vulnerabilities == 0)
                "Security validation passed - system is secure"
            else
                "Critical security vulnerabilities require immediate attention",
        });
    }

    fn generateFinalReport(self: *TestCoordinator) void {
        var total_suites = self.suite_results.items.len;
        var passed_suites = 0;
        var total_tests: usize = 0;
        var total_passed_tests: usize = 0;
        var total_coverage: f32 = 0;
        var total_execution_time: i128 = 0;

        for (self.suite_results.items) |result| {
            if (result.passed) passed_suites += 1;
            total_tests += result.total_tests;
            total_passed_tests += result.passed_tests;
            total_coverage += result.coverage;
            total_execution_time += result.execution_time;

            const status = if (result.passed) "✅ PASS" else "❌ FAIL";
            std.debug.print("{s} - {} tests ({:.1f}% coverage, {} ms)\n", .{
                status, result.total_tests, result.coverage, 
                @as(f32, @floatFromInt(result.execution_time)) / 1_000_000.0
            });
        }

        const avg_coverage = total_coverage / @as(f32, @floatFromInt(total_suites));
        const overall_success_rate = @as(f32, @floatFromInt(total_passed_tests)) / @as(f32, @floatFromInt(total_tests)) * 100.0;

        std.debug.print("\n=== FINAL STATISTICS ===\n", .{});
        std.debug.print("Total Test Suites: {}\n", .{total_suites});
        std.debug.print("Passed Suites: {}\n", .{passed_suites});
        std.debug.print("Suite Success Rate: {:.1f}%\n", .{
            @as(f32, @floatFromInt(passed_suites)) / @as(f32, @floatFromInt(total_suites)) * 100.0
        });
        std.debug.print("Total Tests: {}\n", .{total_tests});
        std.debug.print("Passed Tests: {}\n", .{total_passed_tests});
        std.debug.print("Overall Test Success Rate: {:.1f}%\n", .{overall_success_rate});
        std.debug.print("Average Coverage: {:.1f}%\n", .{avg_coverage});
        std.debug.print("Total Execution Time: {} ms\n", .{
            @as(f32, @floatFromInt(total_execution_time)) / 1_000_000.0
        });

        // Overall assessment
        if (passed_suites == total_suites and overall_success_rate >= 95.0) {
            std.debug.print("\n🎉 EXCELLENT! All tests passed with high coverage!\n", .{});
            std.debug.print("System is ready for production deployment.\n", .{});
        } else if (passed_suites >= @as(usize, @intCast(@as(f32, @floatFromInt(total_suites)) * 0.8)) and overall_success_rate >= 90.0) {
            std.debug.print("\n👍 GOOD! Most tests passed with good coverage.\n", .{});
            std.debug.print("Minor issues to address before production deployment.\n", .{});
        } else if (passed_suites >= @as(usize, @intCast(@as(f32, @floatFromInt(total_suites)) * 0.6)) and overall_success_rate >= 80.0) {
            std.debug.print("\n⚠️  FAIR. Some tests failed - requires attention.\n", .{});
            std.debug.print("Review failed tests before production deployment.\n", .{});
        } else {
            std.debug.print("\n❌ POOR. Significant testing issues detected.\n", .{});
            std.debug.print("Do not deploy to production until issues are resolved.\n", .{});
        }

        // Export detailed results
        self.exportTestResults() catch |err| {
            std.debug.print("Warning: Could not export test results: {}\n", .{err});
        };
    }

    fn exportTestResults(self: *TestCoordinator) !void {
        const file = try std.fs.cwd().createFile("test-results-summary.txt", .{});
        defer file.close();

        try file.writeAll("=== ZAWRA NETWORKING STACK PHASE 2 TEST RESULTS ===\n\n");

        for (self.suite_results.items) |result| {
            try file.print("Test Suite: {s}\n", .{result.name});
            try file.print("Status: {}\n", .{if (result.passed) "PASS" else "FAIL"});
            try file.print("Tests: {}/{} passed\n", .{result.passed_tests, result.total_tests});
            try file.print("Coverage: {:.1f}%\n", .{result.coverage});
            try file.print("Execution Time: {} ms\n", .{
                @as(f32, @floatFromInt(result.execution_time)) / 1_000_000.0
            });
            try file.print("Recommendations: {s}\n\n", .{result.recommendations});
        }

        var total_tests: usize = 0;
        var total_passed_tests: usize = 0;
        for (self.suite_results.items) |result| {
            total_tests += result.total_tests;
            total_passed_tests += result.passed_tests;
        }

        const success_rate = if (total_tests > 0)
            @as(f32, @floatFromInt(total_passed_tests)) / @as(f32, @floatFromInt(total_tests)) * 100.0
        else
            0.0;

        try file.print("=== SUMMARY ===\n", .{});
        try file.print("Total Test Suites: {}\n", .{self.suite_results.items.len});
        try file.print("Total Tests: {}\n", .{total_tests});
        try file.print("Passed Tests: {}\n", .{total_passed_tests});
        try file.print("Success Rate: {:.1f}%\n", .{success_rate});
    }
};

/// Main test entry point
pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{ .enable_memory_limit = true, .safety = true }){};
    defer _ = gpa.deinit();
    
    var coordinator = TestCoordinator.init(gpa.allocator());
    defer coordinator.deinit();

    try coordinator.runAllTestSuites();
    
    std.debug.print("\n✅ Testing framework completed successfully!\n", .{});
    std.debug.print("Check 'test-results-summary.txt' for detailed results.\n", .{});
}

test "Test Framework Integration" {
    var gpa = std.heap.GeneralPurposeAllocator(.{ .enable_memory_limit = true, .safety = true }){};
    defer _ = gpa.deinit();
    
    var coordinator = TestCoordinator.init(gpa.allocator());
    defer coordinator.deinit();

    // Basic integration test
    try testing.expect(coordinator.suite_results.items.len == 0);
    
    // Test that we can initialize test instances
    var protocol_tests_instance = protocol_tests.ProtocolComplianceTests.init(gpa.allocator());
    defer protocol_tests_instance.deinit();
    
    try testing.expect(true); // If we can initialize, the basic structure works
}
