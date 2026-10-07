const std = @import("std");
const ev = @import("gate_evidence.zig");
const raw = @import("gate_raw.zig");
const reports = @import("gate_report.zig");
const policy = @import("coverage_policy.zig");
const Allocator = std.mem.Allocator;
pub const Measurement = struct {
    schema: u32 = 1,
    source_digest: []const u8,
    compiler: []const u8,
    compiler_sha256: []const u8,
    scope: []const []const u8 = policy.scope,
    modes: []const []const u8 = policy.modes,
    sources: []const ev.Source,
    artifacts: []const ev.Artifact,
    cold_items: []const policy.Item,
    reports: []const reports.ModeEvidence,
};
pub fn validateLedger(gpa: Allocator, io: std.Io, measurement: Measurement) !void {
    try validateManifest(measurement);
    for (measurement.artifacts) |entry| {
        std.Io.Dir.cwd().access(io, entry.path, .{}) catch return error.MissingArtifact;
    }
    const markdown = try ev.readFile(gpa, io, "docs/COVERAGE-LEDGER.md");
    const parsed = try std.json.parseFromSlice(policy.Ledger, gpa, try policy.extractRecord(markdown), .{});
    defer parsed.deinit();
    try policy.validate(gpa, parsed.value, measurement.source_digest,
        measurement.compiler, measurement.cold_items);
}
pub fn validate(gpa: Allocator, io: std.Io, path: []const u8, env: *const std.process.Environ.Map) !void {
    const root = std.fs.path.dirname(path) orelse return error.MissingArtifact;
    try ev.validateRoot(gpa, io, env, root);
    const parsed = try std.json.parseFromSlice(Measurement, gpa, try ev.readFile(gpa, io, path), .{});
    const measurement = parsed.value;
    try validateManifest(measurement);
    for (measurement.artifacts) |entry| {
        if (!std.mem.startsWith(u8, entry.path, root) or entry.path.len <= root.len or
            entry.path[root.len] != '/') return error.UnexpectedArtifactPath;
    }
    const inventory = try ev.sources(gpa, io);
    const digest = try ev.sourceDigest(gpa, inventory);
    if (!std.mem.eql(u8, measurement.source_digest, digest)) return error.StaleMeasurement;
    const zig = env.get("ZIG") orelse return error.MissingCompiler;
    try verifyArtifact(gpa, io, .{ .path = zig, .sha256 = measurement.compiler_sha256 });
    for (measurement.artifacts) |entry| try verifyArtifact(gpa, io, entry);
    var items: std.ArrayList(policy.Item) = .empty;
    for (measurement.reports, policy.modes) |mode, expected| {
        if (!std.mem.eql(u8, mode.mode, expected)) return error.PartialScope;
        try validateMode(gpa, io, env, measurement, mode, inventory, &items);
    }
    var regenerated = measurement;
    regenerated.cold_items = items.items;
    try validateLedger(gpa, io, regenerated);
}
fn verifyArtifact(gpa: Allocator, io: std.Io, expected: ev.Artifact) !void {
    const current = try ev.artifact(gpa, io, expected.path);
    if (!std.mem.eql(u8, current.sha256, expected.sha256)) return error.StaleArtifact;
}
fn lookup(measurement: Measurement, path: []const u8) !ev.Artifact {
    for (measurement.artifacts) |entry| {
        if (std.mem.eql(u8, entry.path, path)) return entry;
    }
    return error.MissingArtifact;
}
fn validateMode(gpa: Allocator, io: std.Io, env: *const std.process.Environ.Map,
    measurement: Measurement, mode: reports.ModeEvidence, inventory: []const ev.Source,
    items: *std.ArrayList(policy.Item)) !void
{
    const root = std.fs.path.dirname(mode.report.path) orelse return error.MissingArtifact;
    try ev.validateRoot(gpa, io, env, root);
    var environment = try env.clone(gpa);
    defer environment.deinit();
    const runner: ev.Runner = .{ .gpa = gpa, .io = io, .environment = &environment, .root = root };
    var expected: [raw.binary_names.len]ev.Artifact = undefined;
    for (raw.binary_names, 0..) |name, index| {
        expected[index] = try lookup(measurement, try std.fs.path.join(gpa,
            &.{ root, "artifacts", "bin", name }));
    }
    var paths: std.ArrayList([]const u8) = .empty;
    const prefix = try std.fs.path.join(gpa, &.{ root, "raw" });
    for (measurement.artifacts) |entry| {
        if (std.mem.startsWith(u8, entry.path, prefix) and entry.path.len > prefix.len and
            entry.path[prefix.len] == '/' and std.mem.endsWith(u8, entry.path, ".zcov"))
            try paths.append(gpa, entry.path);
    }
    const counters = try raw.audit(runner, paths.items, &expected);
    const report = try reports.parse(gpa, io, mode.report.path);
    try reports.checkCounters(report, counters);
    if (mode.blocks_found != report.summary.blocks_found or mode.blocks_hit != report.summary.blocks_hit or
        mode.lines_found != report.summary.lines_found or mode.lines_hit != report.summary.lines_hit)
        return error.PartialMapping;
    try reports.collectItems(gpa, io, report, mode.mode, inventory, items);
}
fn exactList(actual: []const []const u8, expected: []const []const u8) bool {
    if (actual.len != expected.len) return false;
    for (actual, expected) |a, b| {
        if (!std.mem.eql(u8, a, b)) return false;
    }
    return true;
}
fn validateManifest(measurement: Measurement) !void {
    if (measurement.schema != 1 or measurement.reports.len != policy.modes.len or
        measurement.artifacts.len > 8192 or measurement.sources.len > 65536 or
        measurement.cold_items.len > 1_000_000) return error.IncompleteReport;
    if (!std.mem.eql(u8, measurement.compiler, "0.16.0") or measurement.compiler_sha256.len != 64 or
        !exactList(measurement.scope, policy.scope) or !exactList(measurement.modes, policy.modes))
        return error.PartialScope;
    for (measurement.reports, policy.modes) |mode, expected_mode| {
        if (!std.mem.eql(u8, mode.mode, expected_mode)) return error.PartialScope;
        try validateModeManifest(measurement, mode);
    }
}
fn validateModeManifest(measurement: Measurement, mode: reports.ModeEvidence) !void {
    const root = std.fs.path.dirname(mode.report.path) orelse return error.MissingArtifact;
    var binaries: [raw.binary_names.len]bool = @splat(false);
    var raw_found = false;
    var report_found = false;
    for (measurement.artifacts) |entry| {
        if (std.mem.eql(u8, entry.path, mode.report.path) and
            std.mem.eql(u8, entry.sha256, mode.report.sha256)) report_found = true;
        if (!std.mem.startsWith(u8, entry.path, root) or entry.path.len <= root.len or
            entry.path[root.len] != '/') continue;
        const relative = entry.path[root.len + 1 ..];
        if (std.mem.startsWith(u8, relative, "raw/") and std.mem.endsWith(u8, relative, ".zcov")) raw_found = true;
        if (std.mem.startsWith(u8, relative, "artifacts/bin/")) {
            const name = relative["artifacts/bin/".len..];
            for (raw.binary_names, 0..) |expected, index| {
                if (std.mem.eql(u8, name, expected)) binaries[index] = true;
            }
        }
    }
    if (!raw_found or !report_found) return error.MissingArtifact;
    for (binaries) |present| {
        if (!present) return error.MissingArtifact;
    }
}
test "plausible two mode report with omitted artifact manifest fails" {
    const mode: reports.ModeEvidence = .{ .mode = "Debug",
        .report = .{ .path = "/scratch/Debug/report.json", .sha256 = "hash" },
        .blocks_found = 2, .blocks_hit = 1, .lines_found = 2, .lines_hit = 1 };
    var safe = mode;
    safe.mode = "ReleaseSafe";
    safe.report.path = "/scratch/ReleaseSafe/report.json";
    const measurement: Measurement = .{ .source_digest = "digest", .compiler = "0.16.0",
        .compiler_sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        .sources = &.{}, .artifacts = &.{}, .cold_items = &.{}, .reports = &.{ mode, safe } };
    try std.testing.expectError(error.MissingArtifact, validateManifest(measurement));
}
