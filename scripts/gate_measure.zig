const std = @import("std");
const ev = @import("gate_evidence.zig");
const raw = @import("gate_raw.zig");
const reports = @import("gate_report.zig");
const record = @import("gate_record.zig");
const policy = @import("coverage_policy.zig");
const Dir = std.Io.Dir;
const files = @import("gate_files.zig");
const sources = @import("gate_sources.zig");

pub const SafetyError = std.mem.Allocator.Error || ev.RunError;
pub const MeasureError = std.mem.Allocator.Error || sources.SourcesError ||
    files.ReadFileError || files.HashFileError || ev.RunError || raw.AuditError ||
    reports.CheckError || reports.CollectError || Dir.CreateDirPathError ||
    Dir.WriteFileError || Dir.OpenError || Dir.Iterator.Error || error{
    MissingRuntime,
    SourceChangedDuringGate,
    RuntimeChangedDuringGate,
    TooManyArtifacts,
    UnexpectedRawArtifact,
};
const Mode = struct {
    root: []const u8,
    raw_root: []const u8,
    prefix: []const u8,
    cache: []const u8,

    fn deinit(self: Mode, gpa: std.mem.Allocator) void {
        gpa.free(self.root);
        gpa.free(self.raw_root);
        gpa.free(self.prefix);
        gpa.free(self.cache);
    }
};
const Accumulator = struct {
    artifacts: std.ArrayList(ev.Artifact) = .empty,
    items: std.ArrayList(policy.Item) = .empty,
    reports: std.ArrayList(reports.ModeEvidence) = .empty,
};
pub fn run(runner: ev.Runner, zig: []const u8, compiler: []const u8) MeasureError!record.Measurement {
    // Measurement strings and slices escape to the command's arena; argv and
    // serialization buffers below are local and are released before returning.
    const inventory = try ev.sources(runner.gpa, runner.io);
    const digest = try ev.sourceDigest(runner.gpa, inventory);
    const runtime = runner.environment.get("OZAI_COVERAGE_RT") orelse return error.MissingRuntime;
    if (!std.fs.path.isAbsolute(runtime)) return error.MissingRuntime;
    const runtime_path = try runner.gpa.dupe(u8, runtime);
    errdefer runner.gpa.free(runtime_path);
    const runtime_artifact = try ev.artifact(runner.gpa, runner.io, runtime_path);
    errdefer runner.gpa.free(runtime_artifact.sha256);
    var result: Accumulator = .{};
    for (policy.modes) |mode| try measureMode(runner, zig, runtime_path, mode, inventory, &result);
    const current_runtime = try ev.artifact(runner.gpa, runner.io, runtime_path);
    defer runner.gpa.free(current_runtime.sha256);
    if (!std.mem.eql(u8, runtime_artifact.sha256, current_runtime.sha256))
        return error.RuntimeChangedDuringGate;
    const current_inventory = try ev.sources(runner.gpa, runner.io);
    defer {
        for (current_inventory) |source| {
            runner.gpa.free(source.path);
            runner.gpa.free(source.sha256);
        }
        runner.gpa.free(current_inventory);
    }
    const current_digest = try ev.sourceDigest(runner.gpa, current_inventory);
    defer runner.gpa.free(current_digest);
    if (!std.mem.eql(u8, digest, current_digest)) return error.SourceChangedDuringGate;
    const compiler_artifact = try ev.artifact(runner.gpa, runner.io, zig);
    const measurement: record.Measurement = .{
        .schema = policy.schema_version,
        .scope = policy.scope,
        .modes = policy.modes,
        .source_digest = digest,
        .compiler = compiler,
        .compiler_sha256 = compiler_artifact.sha256,
        .runtime = runtime_artifact,
        .sources = inventory,
        .artifacts = result.artifacts.items,
        .cold_items = result.items.items,
        .reports = result.reports.items,
    };
    const destination = try runner.path("measurement.json");
    defer runner.gpa.free(destination);
    const serialized = try std.json.Stringify.valueAlloc(
        runner.gpa,
        measurement,
        .{ .whitespace = .indent_2 },
    );
    defer runner.gpa.free(serialized);
    try Dir.cwd().writeFile(runner.io, .{ .sub_path = destination, .data = serialized });
    std.log.info("fresh coverage measurement written: {s}", .{destination});
    return measurement;
}
/// Runs uninstrumented builds and every policy scope test in both safety modes.
/// Uses the same first two stages as fresh measurement, without a coverage runtime.
pub fn runSafetyModes(runner: ev.Runner, zig: []const u8) SafetyError!void {
    for (policy.modes) |name| {
        const mode = try modePaths(runner, name);
        defer mode.deinit(runner.gpa);
        try runSafetyMode(runner, zig, name, mode);
    }
}

fn modePaths(runner: ev.Runner, name: []const u8) std.mem.Allocator.Error!Mode {
    const root = try runner.path(name);
    errdefer runner.gpa.free(root);
    const raw_root = try std.fs.path.join(runner.gpa, &.{ root, "raw" });
    errdefer runner.gpa.free(raw_root);
    const prefix = try std.fs.path.join(runner.gpa, &.{ root, "artifacts" });
    errdefer runner.gpa.free(prefix);
    return .{
        .root = root,
        .raw_root = raw_root,
        .prefix = prefix,
        .cache = try std.fs.path.join(runner.gpa, &.{ root, "cache" }),
    };
}

fn runSafetyMode(runner: ev.Runner, zig: []const u8, name: []const u8, mode: Mode) SafetyError!void {
    try runBuildStage(runner, zig, name, mode, &.{}, 0);
    try runBuildStage(runner, zig, name, mode, policy.scope, 1);
}

fn buildMode(
    runner: ev.Runner,
    zig: []const u8,
    runtime: []const u8,
    name: []const u8,
    mode: Mode,
) SafetyError!void {
    try runSafetyMode(runner, zig, name, mode);
    const coverage_runtime = try std.fmt.allocPrint(runner.gpa, "-Dcoverage-rt={s}", .{runtime});
    defer runner.gpa.free(coverage_runtime);
    try runBuildStage(
        runner,
        zig,
        name,
        mode,
        &.{ "coverage-all", "-Dcoverage=true", coverage_runtime },
        2,
    );
}

fn runBuildStage(
    runner: ev.Runner,
    zig: []const u8,
    name: []const u8,
    mode: Mode,
    stage: []const []const u8,
    index: usize,
) SafetyError!void {
    const optimize_mode = if (std.mem.eql(u8, name, "Debug")) "debug" else "safe";
    const optimize = try std.fmt.allocPrint(runner.gpa, "-Doptimize={s}", .{optimize_mode});
    defer runner.gpa.free(optimize);
    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(runner.gpa);
    try argv.appendSlice(runner.gpa, &.{ zig, "build" });
    try argv.appendSlice(runner.gpa, stage);
    try argv.appendSlice(runner.gpa, &.{
        optimize, "--cache-dir", mode.cache, "--prefix", mode.prefix, "--summary", "all",
    });
    const label = try std.fmt.allocPrint(runner.gpa, "{s}-build-{d}", .{ name, index });
    defer runner.gpa.free(label);
    const output = try runner.run(label, argv.items);
    defer runner.gpa.free(output.stdout);
    defer runner.gpa.free(output.stderr);
}
fn installed(
    runner: ev.Runner,
    prefix: []const u8,
    result: *Accumulator,
) files.HashFileError![raw.binary_names.len]ev.Artifact {
    var expected: [raw.binary_names.len]ev.Artifact = undefined;
    for (raw.binary_names, 0..) |name, index| {
        const path = try std.fs.path.join(runner.gpa, &.{ prefix, "bin", name });
        expected[index] = try ev.artifact(runner.gpa, runner.io, path);
        try result.artifacts.append(runner.gpa, expected[index]);
    }
    // The full binary_names loop initializes every slot; errors exit before this return.
    // zbc-disable-next-line: use-undefined
    return expected;
}
fn rawFiles(
    runner: ev.Runner,
    root: []const u8,
    result: *Accumulator,
) (files.HashFileError || Dir.OpenError || Dir.Iterator.Error ||
    error{ TooManyArtifacts, UnexpectedRawArtifact })![]const []const u8 {
    // The immediately deferred close owns the handle; Iterator only borrows it.
    // zwanzig-disable-next-line: store-violations-engine
    var directory = try Dir.cwd().openDir(runner.io, root, .{ .iterate = true });
    defer directory.close(runner.io);
    var iterator = directory.iterate();
    var paths: std.ArrayList([]const u8) = .empty;
    errdefer paths.deinit(runner.gpa);
    while (try iterator.next(runner.io)) |entry| {
        if (paths.items.len >= 4096) return error.TooManyArtifacts;
        if (entry.kind != .file or !std.mem.endsWith(u8, entry.name, ".zcov"))
            return error.UnexpectedRawArtifact;
        const path = try std.fs.path.join(runner.gpa, &.{ root, entry.name });
        try paths.append(runner.gpa, path);
        try result.artifacts.append(runner.gpa, try ev.artifact(runner.gpa, runner.io, path));
    }
    std.mem.sort([]const u8, paths.items, {}, struct {
        fn less(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.lessThan(u8, a, b);
        }
    }.less);
    const owned_paths = try paths.toOwnedSlice(runner.gpa);
    return owned_paths;
}
fn measureMode(
    runner: ev.Runner,
    zig: []const u8,
    runtime: []const u8,
    name: []const u8,
    inventory: []const ev.Source,
    result: *Accumulator,
) MeasureError!void {
    const mode = try modePaths(runner, name);
    defer mode.deinit(runner.gpa);
    try Dir.cwd().createDirPath(runner.io, mode.raw_root);
    try runner.environment.put("ZIG_COV_DIR", mode.raw_root);
    try buildMode(runner, zig, runtime, name, mode);
    const expected = try installed(runner, mode.prefix, result);
    const paths = try rawFiles(runner, mode.raw_root, result);
    defer runner.gpa.free(paths);
    const auditor: ev.Runner = .{
        .gpa = runner.gpa,
        .io = runner.io,
        .environment = runner.environment,
        .root = mode.root,
    };
    const audit = try raw.audit(auditor, paths, &expected);
    defer audit.report.deinit(runner.gpa);
    const counters = audit.counters;
    const report = audit.report;
    try reports.checkCounters(report, counters);
    const report_path = try std.fs.path.join(runner.gpa, &.{ mode.root, "report.json" });
    const serialized = try std.json.Stringify.valueAlloc(
        runner.gpa,
        report,
        .{ .whitespace = .indent_2 },
    );
    defer runner.gpa.free(serialized);
    try Dir.cwd().writeFile(runner.io, .{ .sub_path = report_path, .data = serialized });
    const report_artifact = try ev.artifact(runner.gpa, runner.io, report_path);
    try result.artifacts.append(runner.gpa, report_artifact);
    try result.reports.append(runner.gpa, .{
        .mode = name,
        .report = report_artifact,
        .blocks_found = report.summary.blocks_found,
        .blocks_hit = report.summary.blocks_hit,
        .lines_found = report.summary.lines_found,
        .lines_hit = report.summary.lines_hit,
        .unmapped_project_blocks = counters.unmapped_project_blocks,
        .unmapped_project_hits = counters.unmapped_project_hits,
        .unowned_blocks = counters.unowned_blocks,
        .unowned_hits = counters.unowned_hits,
    });
    try reports.collectItems(runner.gpa, runner.io, report, name, inventory, &result.items);
}
