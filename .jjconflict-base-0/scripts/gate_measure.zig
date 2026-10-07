const std = @import("std");
const ev = @import("gate_evidence.zig");
const raw = @import("gate_raw.zig");
const reports = @import("gate_report.zig");
const record = @import("gate_record.zig");
const policy = @import("coverage_policy.zig");
const Dir = std.Io.Dir;
const Mode = struct { root: []const u8, raw_root: []const u8, prefix: []const u8, cache: []const u8 };
const Accumulator = struct {
    artifacts: std.ArrayList(ev.Artifact) = .empty,
    items: std.ArrayList(policy.Item) = .empty,
    reports: std.ArrayList(reports.ModeEvidence) = .empty,
};
pub fn run(runner: ev.Runner, zig: []const u8, compiler: []const u8) !record.Measurement {
    const inventory = try ev.sources(runner.gpa, runner.io);
    const digest = try ev.sourceDigest(runner.gpa, inventory);
    const runtime = runner.environment.get("OZAI_COVERAGE_RT") orelse return error.MissingRuntime;
    if (!std.fs.path.isAbsolute(runtime)) return error.MissingRuntime;
    _ = try ev.artifact(runner.gpa, runner.io, runtime);
    var result: Accumulator = .{};
    for (policy.modes) |mode| try measureMode(runner, zig, runtime, mode, inventory, &result);
    const current_digest = try ev.sourceDigest(runner.gpa, try ev.sources(runner.gpa, runner.io));
    if (!std.mem.eql(u8, digest, current_digest)) return error.SourceChangedDuringGate;
    const compiler_artifact = try ev.artifact(runner.gpa, runner.io, zig);
    const measurement: record.Measurement = .{ .source_digest = digest, .compiler = compiler,
        .compiler_sha256 = compiler_artifact.sha256, .sources = inventory,
        .artifacts = result.artifacts.items, .cold_items = result.items.items,
        .reports = result.reports.items };
    try Dir.cwd().writeFile(runner.io, .{ .sub_path = try runner.path("measurement.json"),
        .data = try std.json.Stringify.valueAlloc(runner.gpa, measurement, .{ .whitespace = .indent_2 }) });
    return measurement;
}
fn modePaths(runner: ev.Runner, name: []const u8) !Mode {
    const root = try runner.path(name);
    return .{ .root = root, .raw_root = try std.fs.path.join(runner.gpa, &.{ root, "raw" }),
        .prefix = try std.fs.path.join(runner.gpa, &.{ root, "artifacts" }),
        .cache = try std.fs.path.join(runner.gpa, &.{ root, "cache" }) };
}
fn buildMode(runner: ev.Runner, zig: []const u8, runtime: []const u8, name: []const u8, mode: Mode) !void {
    const optimize = try std.fmt.allocPrint(runner.gpa, "-Doptimize={s}", .{name});
    const common = [_][]const u8{ optimize, "--cache-dir", mode.cache, "--prefix", mode.prefix,
        "--summary", "all" };
    const stages = [_][]const []const u8{ &.{}, &.{ "test", "test-portable", "quic-test" },
        &.{ "coverage-all", "-Dcoverage=true", try std.fmt.allocPrint(runner.gpa,
            "-Dcoverage-rt={s}", .{runtime}) } };
    for (stages, 0..) |stage, index| {
        var argv: std.ArrayList([]const u8) = .empty;
        try argv.appendSlice(runner.gpa, &.{ zig, "build" });
        try argv.appendSlice(runner.gpa, stage);
        try argv.appendSlice(runner.gpa, &common);
        _ = try runner.run(try std.fmt.allocPrint(runner.gpa, "{s}-build-{d}", .{ name, index }), argv.items);
    }
}
fn installed(runner: ev.Runner, prefix: []const u8, result: *Accumulator) ![raw.binary_names.len]ev.Artifact {
    var expected: [raw.binary_names.len]ev.Artifact = undefined;
    for (raw.binary_names, 0..) |name, index| {
        expected[index] = try ev.artifact(runner.gpa, runner.io,
            try std.fs.path.join(runner.gpa, &.{ prefix, "bin", name }));
        try result.artifacts.append(runner.gpa, expected[index]);
    }
    return expected;
}
fn rawFiles(runner: ev.Runner, root: []const u8, result: *Accumulator) ![]const []const u8 {
    var directory = try Dir.cwd().openDir(runner.io, root, .{ .iterate = true });
    defer directory.close(runner.io);
    var iterator = directory.iterate();
    var paths: std.ArrayList([]const u8) = .empty;
    while (try iterator.next(runner.io)) |entry| {
        if (paths.items.len >= 4096) return error.TooManyArtifacts;
        if (entry.kind != .file or !std.mem.endsWith(u8, entry.name, ".zcov")) return error.UnexpectedRawArtifact;
        const path = try std.fs.path.join(runner.gpa, &.{ root, entry.name });
        try paths.append(runner.gpa, path);
        try result.artifacts.append(runner.gpa, try ev.artifact(runner.gpa, runner.io, path));
    }
    std.mem.sort([]const u8, paths.items, {}, struct {
        fn less(_: void, a: []const u8, b: []const u8) bool { return std.mem.lessThan(u8, a, b); }
    }.less);
    return paths.items;
}
fn emitReport(runner: ev.Runner, mode: []const u8, path: []const u8, paths: []const []const u8) !void {
    var cwd_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const cwd = cwd_buffer[0..try Dir.cwd().realPath(runner.io, &cwd_buffer)];
    var argv: std.ArrayList([]const u8) = .empty;
    try argv.appendSlice(runner.gpa, &.{ "zig-cov", "report",
        try std.fmt.allocPrint(runner.gpa, "--project={s}", .{cwd}), "--format=json",
        try std.fmt.allocPrint(runner.gpa, "--output={s}", .{path}) });
    try argv.appendSlice(runner.gpa, paths);
    const output = try runner.run(try std.fmt.allocPrint(runner.gpa, "{s}-report", .{mode}), argv.items);
    if (std.mem.indexOf(u8, output.stderr, "warning:") != null or
        std.mem.indexOf(u8, output.stderr, "error:") != null) return error.PartialMapping;
}
fn measureMode(runner: ev.Runner, zig: []const u8, runtime: []const u8, name: []const u8,
    inventory: []const ev.Source, result: *Accumulator) !void
{
    const mode = try modePaths(runner, name);
    try Dir.cwd().createDirPath(runner.io, mode.raw_root);
    try runner.environment.put("ZIG_COV_DIR", mode.raw_root);
    try buildMode(runner, zig, runtime, name, mode);
    const expected = try installed(runner, mode.prefix, result);
    const paths = try rawFiles(runner, mode.raw_root, result);
    const auditor: ev.Runner = .{ .gpa = runner.gpa, .io = runner.io,
        .environment = runner.environment, .root = mode.root };
    const counters = try raw.audit(auditor, paths, &expected);
    const report_path = try std.fs.path.join(runner.gpa, &.{ mode.root, "report.json" });
    try emitReport(runner, name, report_path, paths);
    const report = try reports.parse(runner.gpa, runner.io, report_path);
    try reports.checkCounters(report, counters);
    const report_artifact = try ev.artifact(runner.gpa, runner.io, report_path);
    try result.artifacts.append(runner.gpa, report_artifact);
    try result.reports.append(runner.gpa, .{ .mode = name, .report = report_artifact,
        .blocks_found = report.summary.blocks_found, .blocks_hit = report.summary.blocks_hit,
        .lines_found = report.summary.lines_found, .lines_hit = report.summary.lines_hit });
    try reports.collectItems(runner.gpa, runner.io, report, name, inventory, &result.items);
}
