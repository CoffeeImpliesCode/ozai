const std = @import("std");
const ev = @import("gate_evidence.zig");
const scan = @import("gate_zbc_scan.zig");
const policy = @import("gate_zbc_policy.zig");
const files = @import("gate_files.zig");

pub const RunError = std.mem.Allocator.Error || ev.RunError || files.ReadFileError ||
    files.HashFileError || policy.AuthenticateError || scan.Error || std.process.RunError ||
    std.Io.Dir.WriteFileError || error{
    MissingZbcLibraryPath,
    ZbcRuntimeMustBeAbsolute,
    MissingZbcLoader,
    MissingHome,
    MissingZbc,
    ZbcBinaryMustBeAbsolute,
    ZbcToolChanged,
    ZbcSourceExceptionsChanged,
    MissingSources,
    ZbcCommandFailed,
};
const CaptureError = std.mem.Allocator.Error || std.process.RunError ||
    std.Io.Dir.WriteFileError;
const RunToolError = CaptureError || files.ReadFileError || files.HashFileError ||
    policy.AuthenticateError || scan.Error ||
    error{ ZbcCommandFailed, ZbcToolChanged, ZbcSourceExceptionsChanged };

pub fn run(runner: ev.Runner) RunError!void {
    // Match zig-gate's files() and the project's configured BRE exclusions.
    // Keep find's own failure binding rather than accepting a partial walk.
    const inventory = try runner.run("zbc-inventory", &.{
        "find",
        ".",
        "-name",
        "*.zig",
        "-not",
        "-name",
        "vk.zig",
        "-not",
        "-path",
        "./zig-pkg/*",
        "-not",
        "-path",
        "./.zig-cache/*",
        "-not",
        "-path",
        "./zig-out/*",
        "-not",
        "-path",
        "./zig-cache/*",
        "-not",
        "-path",
        "./zig-global-cache/*",
        "-not",
        "-path",
        "./vendor/*",
        "-not",
        "-path",
        "*/.zig-cache/*",
        "-not",
        "-path",
        "*/zig-out/*",
        "-not",
        "-path",
        "*/zig-cache/*",
        "-not",
        "-path",
        "*/zig-global-cache/*",
        "-not",
        "-path",
        "*/zig-pkg/*",
    });
    defer runner.gpa.free(inventory.stdout);
    defer runner.gpa.free(inventory.stderr);
    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(runner.gpa);
    const loader = runner.environment.get("OZAI_ZBC_LOADER");
    const libraries = runner.environment.get("OZAI_ZBC_LIBRARY_PATH");
    if (loader) |path| {
        const library_path = libraries orelse return error.MissingZbcLibraryPath;
        if (!std.fs.path.isAbsolute(path) or !std.fs.path.isAbsolute(library_path))
            return error.ZbcRuntimeMustBeAbsolute;
        try argv.appendSlice(runner.gpa, &.{ path, "--library-path", library_path });
    } else if (libraries != null) {
        return error.MissingZbcLoader;
    }
    // Selection happens before execution; a failed installer is never retried
    // with another binary or loader.
    const home = runner.environment.get("HOME") orelse return error.MissingHome;
    const default_binary = try std.fs.path.join(runner.gpa, &.{ home, ".local", "bin", "zbc" });
    defer runner.gpa.free(default_binary);
    const binary = runner.environment.get("ZBC") orelse default_binary;
    if (binary.len == 0) return error.MissingZbc;
    if (!std.fs.path.isAbsolute(binary)) return error.ZbcBinaryMustBeAbsolute;
    const tool = try ev.artifact(runner.gpa, runner.io, binary);
    defer runner.gpa.free(tool.sha256);
    try argv.append(runner.gpa, binary);
    const source_start = argv.items.len;
    try appendSources(runner.gpa, &argv, inventory.stdout);
    try runTool(runner, tool, argv.items, argv.items[source_start..]);
}

fn runTool(
    runner: ev.Runner,
    tool: ev.Artifact,
    argv: []const []const u8,
    inventory: []const []const u8,
) RunToolError!void {
    const policy_bytes = try ev.readFile(runner.gpa, runner.io, ".zbc-source-exceptions.json");
    defer runner.gpa.free(policy_bytes);
    const before = try policy.authenticate(
        runner.gpa,
        runner.io,
        policy_bytes,
        tool.sha256,
        inventory,
    );
    const output = try capture(runner, argv);
    defer runner.gpa.free(output.stdout);
    defer runner.gpa.free(output.stderr);
    checkExit(output.term) catch |err| {
        std.log.err("ZBC failed ({any}); retained evidence: {s}", .{ output.term, runner.root });
        return err;
    };
    const current_tool = try ev.artifact(runner.gpa, runner.io, tool.path);
    defer runner.gpa.free(current_tool.sha256);
    if (!std.mem.eql(u8, tool.sha256, current_tool.sha256)) return error.ZbcToolChanged;
    const after = try policy.authenticate(
        runner.gpa,
        runner.io,
        policy_bytes,
        current_tool.sha256,
        inventory,
    );
    if (before != after) return error.ZbcSourceExceptionsChanged;
    const parsed = try scan.parse(output.stdout, output.stderr, inventory);
    try report(runner, parsed, after);
}

fn appendSources(
    gpa: std.mem.Allocator,
    argv: *std.ArrayList([]const u8),
    inventory: []const u8,
) (std.mem.Allocator.Error || error{MissingSources})!void {
    const before = argv.items.len;
    var paths = std.mem.tokenizeScalar(u8, inventory, '\n');
    while (paths.next()) |path| try argv.append(gpa, path);
    if (argv.items.len == before) return error.MissingSources;
}

fn capture(runner: ev.Runner, argv: []const []const u8) CaptureError!std.process.RunResult {
    const command = try std.json.Stringify.valueAlloc(runner.gpa, argv, .{});
    defer runner.gpa.free(command);
    try writeLog(runner, "zbc.command.json", command);
    const result = try std.process.run(runner.gpa, runner.io, .{
        .argv = argv,
        .environ_map = runner.environment,
        .expand_arg0 = .expand,
    });
    errdefer {
        runner.gpa.free(result.stdout);
        runner.gpa.free(result.stderr);
    }
    try writeLog(runner, "zbc.stdout", result.stdout);
    try writeLog(runner, "zbc.stderr", result.stderr);
    const term = try std.json.Stringify.valueAlloc(runner.gpa, result.term, .{});
    defer runner.gpa.free(term);
    try writeLog(runner, "zbc.term.json", term);
    return result;
}

fn writeLog(
    runner: ev.Runner,
    name: []const u8,
    bytes: []const u8,
) (std.mem.Allocator.Error || std.Io.Dir.WriteFileError)!void {
    const destination = try runner.path(name);
    defer runner.gpa.free(destination);
    try std.Io.Dir.cwd().writeFile(runner.io, .{ .sub_path = destination, .data = bytes });
}

fn checkExit(term: std.process.Child.Term) error{ZbcCommandFailed}!void {
    switch (term) {
        .exited => |code| if (code != 0) return error.ZbcCommandFailed,
        else => return error.ZbcCommandFailed,
    }
}

fn report(
    runner: ev.Runner,
    parsed: scan.Scan,
    annotated_files: usize,
) (std.mem.Allocator.Error || std.Io.Dir.WriteFileError)!void {
    const counts = .{
        .selected = parsed.selected,
        .analyzed = parsed.selected,
        .failed = 0,
        .raw_findings = 0,
        .active_errors = 0,
        .active_warnings = 0,
        .source_exception_files = annotated_files,
        .unresolved_import_lookups = parsed.unresolved_import_lookups,
    };
    std.log.info("ZBC selected={d} analyzed={d} failed=0 findings=0; annotated files={d}", .{
        counts.selected, counts.analyzed, counts.source_exception_files,
    });
    const json = try std.json.Stringify.valueAlloc(
        runner.gpa,
        counts,
        .{ .whitespace = .indent_2 },
    );
    defer runner.gpa.free(json);
    try writeLog(runner, "zbc.counts.json", json);
}

test "ZBC rejects an empty source inventory" {
    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(std.testing.allocator);
    try std.testing.expectError(
        error.MissingSources,
        appendSources(std.testing.allocator, &argv, "\n"),
    );
}

test "ZBC requires exit zero even when a scan reports reviewed findings" {
    try checkExit(.{ .exited = 0 });
    try std.testing.expectError(error.ZbcCommandFailed, checkExit(.{ .exited = 1 }));
    try std.testing.expectError(error.ZbcCommandFailed, checkExit(.{ .exited = 2 }));
    try std.testing.expectError(error.ZbcCommandFailed, checkExit(.{ .unknown = 9 }));
}
