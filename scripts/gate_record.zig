const std = @import("std");
const ev = @import("gate_evidence.zig");
const raw = @import("gate_raw.zig");
const reports = @import("gate_report.zig");
const policy = @import("coverage_policy.zig");
const projection = @import("gate_projection.zig");
const Allocator = std.mem.Allocator;
const files = @import("gate_files.zig");
const sources = @import("gate_sources.zig");
const gate_scratch = @import("gate_scratch.zig");

pub const ReplayError = Allocator.Error || std.json.ParseError(std.json.Scanner) ||
    files.ReadFileError || files.HashFileError || sources.SourcesError ||
    gate_scratch.ValidateError || raw.AuditError || reports.ParseError || reports.CollectError ||
    policy.ValidateError || policy.CountsError || policy.ReferenceError ||
    std.Io.Dir.OpenError || std.Io.Dir.Iterator.Error || error{
    UnreferencedMeasurement,
    MeasurementHashMismatch,
    StaleMeasurement,
    MissingCompiler,
    CompilerMustBeAbsolute,
    DuplicateArtifact,
    ColdItemsMismatch,
    SourceChangedDuringGate,
    StaleArtifact,
    UnexpectedArtifactPath,
    TooManyArtifacts,
    UnexpectedRawArtifact,
    MissingArtifact,
    StaleLedger,
    MissingCoveragePolicy,
    CoveragePolicyMustBeAbsolute,
    IncompleteReport,
    PartialScope,
    PartialMapping,
    EvidenceLimitExceeded,
    InvalidRuntimeIdentity,
};
const ManifestError = error{
    IncompleteReport,
    PartialScope,
    PartialMapping,
    EvidenceLimitExceeded,
    MissingArtifact,
    InvalidRuntimeIdentity,
};
pub const Measurement = struct {
    schema: u32,
    source_digest: []const u8,
    compiler: []const u8,
    compiler_sha256: []const u8,
    runtime: ev.Artifact,
    scope: []const []const u8,
    modes: []const []const u8,
    sources: []const ev.Source,
    artifacts: []const ev.Artifact,
    cold_items: []const policy.Item,
    reports: []const reports.ModeEvidence,
};
/// Replays the source-bound snapshot named by the external coverage policy.
/// Temporary parsing and replay storage is released before returning.
pub fn validateRetained(
    gpa: Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
) ReplayError!void {
    var temporary = std.heap.ArenaAllocator.init(gpa);
    defer temporary.deinit();
    const scratch = temporary.allocator();
    const ledger = try loadLedger(scratch, io, env);
    try validateSnapshot(scratch, io, ledger.measurement.path, env, ledger);
}

/// Replays only the policy-referenced path and captured SHA, never an arbitrary manifest.
pub fn validate(
    gpa: Allocator,
    io: std.Io,
    path: []const u8,
    env: *const std.process.Environ.Map,
) ReplayError!void {
    var temporary = std.heap.ArenaAllocator.init(gpa);
    defer temporary.deinit();
    const scratch = temporary.allocator();
    try validateSnapshot(scratch, io, path, env, try loadLedger(scratch, io, env));
}

// Parsed strings borrow arena-owned bounded reads throughout replay.
fn loadLedger(
    arena: Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
) (files.ReadFileError || std.json.ParseError(std.json.Scanner) ||
    policy.ReferenceError || error{
    StaleLedger,
    MissingCoveragePolicy,
    CoveragePolicyMustBeAbsolute,
})!policy.Ledger {
    const path = env.get("OZAI_COVERAGE_POLICY") orelse return error.MissingCoveragePolicy;
    if (!std.fs.path.isAbsolute(path)) return error.CoveragePolicyMustBeAbsolute;
    const bytes = try ev.readFile(arena, io, path);
    const ledger = try std.json.parseFromSliceLeaky(
        policy.Ledger,
        arena,
        bytes,
        .{ .allocate = .alloc_if_needed },
    );
    if (ledger.schema != policy.schema_version) return error.StaleLedger;
    try policy.validateReference(ledger.measurement);
    return ledger;
}

fn readReferencedMeasurement(
    gpa: Allocator,
    io: std.Io,
    reference: policy.MeasurementReference,
    path: []const u8,
) (files.ReadFileError || policy.ReferenceError ||
    error{ UnreferencedMeasurement, MeasurementHashMismatch })![]const u8 {
    try policy.validateReference(reference);
    if (!std.mem.eql(u8, path, reference.path)) return error.UnreferencedMeasurement;
    const bytes = try ev.readFile(gpa, io, path);
    errdefer gpa.free(bytes);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    if (!std.ascii.eqlIgnoreCase(reference.sha256, &std.fmt.bytesToHex(digest, .lower)))
        return error.MeasurementHashMismatch;
    return bytes;
}

fn validateSnapshot(
    gpa: Allocator,
    io: std.Io,
    path: []const u8,
    env: *const std.process.Environ.Map,
    ledger: policy.Ledger,
) ReplayError!void {
    const bytes = try readReferencedMeasurement(gpa, io, ledger.measurement, path);
    const root = std.fs.path.dirname(path) orelse return error.MissingArtifact;
    try ev.validateRoot(gpa, io, env, root);
    const measurement = try std.json.parseFromSliceLeaky(
        Measurement,
        gpa,
        bytes,
        .{ .allocate = .alloc_if_needed },
    );
    try validateManifest(measurement);
    try validateArtifactPaths(measurement, root);
    try verifyArtifact(gpa, io, measurement.runtime);
    const inventory = try ev.sources(gpa, io);
    const digest = try ev.sourceDigest(gpa, inventory);
    if (!std.mem.eql(u8, measurement.source_digest, digest)) return error.StaleMeasurement;
    if (measurement.sources.len != inventory.len) return error.StaleMeasurement;
    for (measurement.sources, inventory) |stored, current| {
        if (!std.mem.eql(u8, stored.path, current.path) or
            !std.mem.eql(u8, stored.sha256, current.sha256)) return error.StaleMeasurement;
    }
    const zig = env.get("ZIG") orelse return error.MissingCompiler;
    if (!std.fs.path.isAbsolute(zig)) return error.CompilerMustBeAbsolute;
    try verifyArtifact(gpa, io, .{ .path = zig, .sha256 = measurement.compiler_sha256 });
    var artifact_paths: std.StringHashMapUnmanaged(void) = .empty;
    defer artifact_paths.deinit(gpa);
    for (measurement.artifacts) |entry| {
        const identity = try artifact_paths.getOrPut(gpa, entry.path);
        if (identity.found_existing) return error.DuplicateArtifact;
        try verifyArtifact(gpa, io, entry);
    }
    var items: std.ArrayList(policy.Item) = .empty;
    defer items.deinit(gpa);
    for (measurement.reports) |mode|
        try validateMode(gpa, io, env, measurement, mode, inventory, &items);
    try validateColdItems(gpa, measurement.cold_items, items.items);
    try policy.validate(gpa, ledger, digest, measurement.compiler, items.items);
    try validateCounts(ledger, measurement.reports);
    const manifest = try ev.artifact(gpa, io, path);
    defer gpa.free(manifest.sha256);
    if (!std.ascii.eqlIgnoreCase(manifest.sha256, ledger.measurement.sha256))
        return error.MeasurementHashMismatch;
    const current = try ev.sourceDigest(gpa, try ev.sources(gpa, io));
    if (!std.mem.eql(u8, digest, current)) return error.SourceChangedDuringGate;
    std.log.info("accepted current retained coverage snapshot: {s}", .{path});
}

fn validateColdItems(
    gpa: Allocator,
    stored: []const policy.Item,
    actual: []const policy.Item,
) (Allocator.Error || error{ColdItemsMismatch})!void {
    if (stored.len != actual.len) return error.ColdItemsMismatch;
    var identities: std.HashMap(policy.Item, bool, policy.ItemContext, 80) = .init(gpa);
    defer identities.deinit();
    for (actual) |item| {
        const entry = try identities.getOrPut(item);
        if (entry.found_existing) return error.ColdItemsMismatch;
        entry.value_ptr.* = false;
    }
    for (stored) |item| {
        const matched = identities.getPtr(item) orelse return error.ColdItemsMismatch;
        if (matched.*) return error.ColdItemsMismatch;
        matched.* = true;
    }
}

fn validateCounts(
    ledger: policy.Ledger,
    evidence: []const reports.ModeEvidence,
) policy.CountsError!void {
    var unmapped: [policy.modes.len]policy.UnmappedCounts = undefined;
    var unowned: [policy.modes.len]policy.UnownedCounts = undefined;
    for (evidence, 0..) |mode, index| {
        unmapped[index] = .{
            .mode = mode.mode,
            .unmapped_project_blocks = mode.unmapped_project_blocks,
            .unmapped_project_hits = mode.unmapped_project_hits,
        };
        unowned[index] = .{
            .mode = mode.mode,
            .unowned_blocks = mode.unowned_blocks,
            .unowned_hits = mode.unowned_hits,
        };
    }
    try policy.validateUnmapped(ledger, &unmapped);
    try policy.validateUnowned(ledger, &unowned);
}
fn verifyArtifact(
    gpa: Allocator,
    io: std.Io,
    expected: ev.Artifact,
) (files.HashFileError || error{StaleArtifact})!void {
    const current = try ev.artifact(gpa, io, expected.path);
    defer gpa.free(current.sha256);
    if (!std.mem.eql(u8, current.sha256, expected.sha256)) return error.StaleArtifact;
}
fn lookup(measurement: Measurement, path: []const u8) error{MissingArtifact}!ev.Artifact {
    for (measurement.artifacts) |entry| {
        if (std.mem.eql(u8, entry.path, path)) return entry;
    }
    return error.MissingArtifact;
}
fn validateMode(
    gpa: Allocator,
    io: std.Io,
    env: *const std.process.Environ.Map,
    measurement: Measurement,
    mode: reports.ModeEvidence,
    inventory: []const ev.Source,
    items: *std.ArrayList(policy.Item),
) ReplayError!void {
    const root = std.fs.path.dirname(mode.report.path) orelse return error.MissingArtifact;
    try ev.validateRoot(gpa, io, env, root);
    var environment = try env.clone(gpa);
    defer environment.deinit();
    const runner: ev.Runner = .{ .gpa = gpa, .io = io, .environment = &environment, .root = root };
    var expected: [raw.binary_names.len]ev.Artifact = undefined;
    for (raw.binary_names, 0..) |name, index| {
        const binary_path = try std.fs.path.join(gpa, &.{ root, "artifacts", "bin", name });
        defer gpa.free(binary_path);
        expected[index] = try lookup(measurement, binary_path);
    }
    var paths: std.ArrayList([]const u8) = .empty;
    defer paths.deinit(gpa);
    const prefix = try std.fs.path.join(gpa, &.{ root, "raw" });
    defer gpa.free(prefix);
    for (measurement.artifacts) |entry| {
        if (std.mem.startsWith(u8, entry.path, prefix) and entry.path.len > prefix.len and
            entry.path[prefix.len] == '/' and std.mem.endsWith(u8, entry.path, ".zcov"))
            try paths.append(gpa, entry.path);
    }
    try validateRawDirectory(gpa, io, prefix, paths.items);
    std.mem.sort([]const u8, paths.items, {}, struct {
        fn less(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.lessThan(u8, a, b);
        }
    }.less);
    const audit = try raw.audit(runner, paths.items, &expected);
    defer audit.report.deinit(gpa);
    const report = try reports.parse(gpa, io, mode.report.path);
    defer report.deinit(gpa);
    try reports.checkReplay(mode, report, audit);
    try reports.collectItems(gpa, io, report, mode.mode, inventory, items);
}

fn modeRelativePath(root: []const u8, mode: []const u8, path: []const u8) ?[]const u8 {
    if (!std.mem.startsWith(u8, path, root) or path.len <= root.len or
        path[root.len] != '/') return null;
    const relative = path[root.len + 1 ..];
    if (!std.mem.startsWith(u8, relative, mode) or relative.len <= mode.len or
        relative[mode.len] != '/') return null;
    return relative[mode.len + 1 ..];
}

fn validateArtifactPaths(measurement: Measurement, root: []const u8) error{UnexpectedArtifactPath}!void {
    for (measurement.reports) |mode| {
        const relative = modeRelativePath(root, mode.mode, mode.report.path) orelse
            return error.UnexpectedArtifactPath;
        if (!std.mem.eql(u8, relative, "report.json")) return error.UnexpectedArtifactPath;
    }
    for (measurement.artifacts) |entry| {
        var allowed = false;
        for (measurement.reports) |mode| {
            const relative = modeRelativePath(root, mode.mode, entry.path) orelse continue;
            if (std.mem.eql(u8, relative, "report.json")) allowed = true;
            if (std.mem.startsWith(u8, relative, "raw/") and
                std.mem.endsWith(u8, relative, ".zcov") and
                std.mem.indexOfScalar(u8, relative["raw/".len..], '/') == null)
                allowed = true;
            if (std.mem.startsWith(u8, relative, "artifacts/bin/")) {
                const name = relative["artifacts/bin/".len..];
                for (raw.binary_names) |expected| {
                    if (std.mem.eql(u8, name, expected)) allowed = true;
                }
            }
        }
        if (!allowed) return error.UnexpectedArtifactPath;
    }
}

fn validateRawDirectory(
    gpa: Allocator,
    io: std.Io,
    root: []const u8,
    paths: []const []const u8,
) (Allocator.Error || std.Io.Dir.OpenError || std.Io.Dir.Iterator.Error ||
    error{ TooManyArtifacts, UnexpectedRawArtifact, MissingArtifact })!void {
    if (paths.len > 4096) return error.TooManyArtifacts;
    var expected: std.StringHashMapUnmanaged(void) = .empty;
    defer expected.deinit(gpa);
    for (paths) |path| try expected.put(gpa, std.fs.path.basename(path), {});
    var directory = try std.Io.Dir.cwd().openDir(io, root, .{ .iterate = true });
    defer directory.close(io);
    var iterator = directory.iterate();
    var count: usize = 0;
    for (0..4097) |_| {
        const entry = try iterator.next(io) orelse break;
        if (entry.kind != .file or !expected.contains(entry.name))
            return error.UnexpectedRawArtifact;
        count += 1;
    } else return error.TooManyArtifacts;
    if (count != paths.len) return error.MissingArtifact;
}

fn exactList(actual: []const []const u8, expected: []const []const u8) bool {
    if (actual.len != expected.len) return false;
    for (actual, expected) |a, b| {
        if (!std.mem.eql(u8, a, b)) return false;
    }
    return true;
}
fn validateManifest(measurement: Measurement) ManifestError!void {
    if (measurement.schema != policy.schema_version or
        measurement.reports.len != policy.modes.len or measurement.artifacts.len > 8192 or
        measurement.sources.len > 65536 or measurement.cold_items.len > 1_000_000)
    {
        return error.IncompleteReport;
    }
    if (!std.mem.eql(u8, measurement.compiler, "0.17.0") or measurement.compiler_sha256.len != 64 or
        !exactList(measurement.scope, policy.scope) or !exactList(measurement.modes, policy.modes))
        return error.PartialScope;
    try validateRuntimeIdentity(measurement.runtime);
    for (measurement.reports, policy.modes) |mode, expected_mode| {
        if (!std.mem.eql(u8, mode.mode, expected_mode)) return error.PartialScope;
        try validateModeManifest(measurement, mode);
    }
}

fn validateRuntimeIdentity(runtime: ev.Artifact) error{InvalidRuntimeIdentity}!void {
    if (!std.fs.path.isAbsolute(runtime.path) or runtime.path.len <= 1 or
        runtime.sha256.len != 64) return error.InvalidRuntimeIdentity;
    for (runtime.sha256) |byte| {
        if (!std.ascii.isHex(byte)) return error.InvalidRuntimeIdentity;
    }
}
fn validateModeManifest(measurement: Measurement, mode: reports.ModeEvidence) error{
    PartialMapping,
    EvidenceLimitExceeded,
    MissingArtifact,
}!void {
    if (mode.unmapped_project_hits > mode.unmapped_project_blocks or
        mode.unowned_hits > mode.unowned_blocks)
        return error.PartialMapping;
    if (mode.unmapped_project_blocks > 16 * 1024 * 1024 or
        mode.unowned_blocks > 16 * 1024 * 1024)
        return error.EvidenceLimitExceeded;
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
        if (std.mem.startsWith(u8, relative, "raw/") and
            std.mem.endsWith(u8, relative, ".zcov")) raw_found = true;
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
    const mode: reports.ModeEvidence = .{
        .mode = "Debug",
        .report = .{
            .path = "/scratch/Debug/report.json",
            .sha256 = "hash",
        },
        .blocks_found = 2,
        .blocks_hit = 1,
        .lines_found = 2,
        .lines_hit = 1,
        .unmapped_project_blocks = 0,
        .unmapped_project_hits = 0,
        .unowned_blocks = 0,
        .unowned_hits = 0,
    };
    var safe = mode;
    safe.mode = "ReleaseSafe";
    safe.report.path = "/scratch/ReleaseSafe/report.json";
    const measurement: Measurement = .{
        .schema = policy.schema_version,
        .scope = policy.scope,
        .modes = policy.modes,
        .source_digest = "digest",
        .compiler = "0.17.0",
        .compiler_sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        .runtime = .{ .path = "/captured/zig-cov-rt.o", .sha256 = &@as([64:0]u8, @splat('a')) },
        .sources = &.{},
        .artifacts = &.{},
        .cold_items = &.{},
        .reports = &.{ mode, safe },
    };
    try std.testing.expectError(error.MissingArtifact, validateManifest(measurement));
}

test "mode manifest rejects impossible unmapped hit counts before artifact lookup" {
    const mode: reports.ModeEvidence = .{
        .mode = "Debug",
        .report = .{
            .path = "/scratch/Debug/report.json",
            .sha256 = "hash",
        },
        .blocks_found = 2,
        .blocks_hit = 1,
        .lines_found = 2,
        .lines_hit = 1,
        .unmapped_project_blocks = 1,
        .unmapped_project_hits = 2,
        .unowned_blocks = 0,
        .unowned_hits = 0,
    };
    const measurement: Measurement = .{
        .schema = policy.schema_version,
        .scope = policy.scope,
        .modes = policy.modes,
        .source_digest = "digest",
        .compiler = "0.17.0",
        .compiler_sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        .runtime = .{ .path = "/captured/zig-cov-rt.o", .sha256 = &@as([64:0]u8, @splat('a')) },
        .sources = &.{},
        .artifacts = &.{},
        .cold_items = &.{},
        .reports = &.{},
    };
    try std.testing.expectError(error.PartialMapping, validateModeManifest(measurement, mode));
}

test "mode manifest rejects impossible and excessive unowned counts before artifact lookup" {
    var mode: reports.ModeEvidence = .{
        .mode = "Debug",
        .report = .{
            .path = "/scratch/Debug/report.json",
            .sha256 = "hash",
        },
        .blocks_found = 2,
        .blocks_hit = 1,
        .lines_found = 2,
        .lines_hit = 1,
        .unmapped_project_blocks = 0,
        .unmapped_project_hits = 0,
        .unowned_blocks = 1,
        .unowned_hits = 2,
    };
    const measurement: Measurement = .{
        .schema = policy.schema_version,
        .scope = policy.scope,
        .modes = policy.modes,
        .source_digest = "digest",
        .compiler = "0.17.0",
        .compiler_sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        .runtime = .{ .path = "/captured/zig-cov-rt.o", .sha256 = &@as([64:0]u8, @splat('a')) },
        .sources = &.{},
        .artifacts = &.{},
        .cold_items = &.{},
        .reports = &.{},
    };
    try std.testing.expectError(error.PartialMapping, validateModeManifest(measurement, mode));
    mode.unowned_blocks = 16 * 1024 * 1024 + 1;
    mode.unowned_hits = 0;
    try std.testing.expectError(
        error.EvidenceLimitExceeded,
        validateModeManifest(measurement, mode),
    );
    mode.unowned_blocks = 16 * 1024 * 1024;
    mode.unowned_hits = mode.unowned_blocks;
    try std.testing.expectError(error.MissingArtifact, validateModeManifest(measurement, mode));
    mode.unowned_blocks = 0;
    mode.unowned_hits = 0;
    try std.testing.expectError(error.MissingArtifact, validateModeManifest(measurement, mode));
}

test "retained manifest reference rejects changed file bytes before parsing" {
    try std.testing.expectError(
        error.MeasurementHashMismatch,
        readReferencedMeasurement(std.testing.allocator, std.testing.io, .{
            .path = "scripts/gate_record.zig",
            .sha256 = &@as([64:0]u8, @splat('0')),
        }, "scripts/gate_record.zig"),
    );
}

test "replayed cold tuple metadata cannot be forged omitted or duplicated" {
    const gpa = std.testing.allocator;
    const cwd = try std.process.currentPathAlloc(std.testing.io, gpa);
    defer gpa.free(cwd);
    const path = try std.fs.path.join(gpa, &.{ cwd, "src/a.zig" });
    defer gpa.free(path);
    const report: projection.Report = .{
        .version = 1,
        .tool = "ozai-zcov-raw",
        .summary = .{ .blocks_found = 2, .blocks_hit = 0, .lines_found = 2, .lines_hit = 0 },
        .files = &.{.{
            .path = path,
            .lines_found = 2,
            .lines_hit = 0,
            .lines = &.{ .{ .line = 7, .hits = 0 }, .{ .line = 9, .hits = 0 } },
        }},
    };
    var actual: std.ArrayList(policy.Item) = .empty;
    defer actual.deinit(gpa);
    try reports.collectItems(gpa, std.testing.io, report, "Debug", &.{.{
        .path = "src/a.zig",
        .sha256 = &@as([64:0]u8, @splat('a')),
    }}, &actual);
    var stored = actual.items[0];
    const copied_path = try gpa.dupe(u8, stored.path);
    defer gpa.free(copied_path);
    stored.path = copied_path;
    try validateColdItems(gpa, &.{ stored, actual.items[1] }, actual.items);
    inline for (.{ "mode", "path", "source_sha256", "unit" }) |field| {
        var forged = stored;
        @field(forged, field) = "forged";
        try std.testing.expectError(
            error.ColdItemsMismatch,
            validateColdItems(gpa, &.{ forged, actual.items[1] }, actual.items),
        );
    }
    var forged = stored;
    forged.line += 1;
    try std.testing.expectError(
        error.ColdItemsMismatch,
        validateColdItems(gpa, &.{ forged, actual.items[1] }, actual.items),
    );
    try std.testing.expectError(
        error.ColdItemsMismatch,
        validateColdItems(gpa, &.{stored}, actual.items),
    );
    try std.testing.expectError(
        error.ColdItemsMismatch,
        validateColdItems(gpa, &.{ stored, stored }, actual.items),
    );
    try std.testing.expectError(
        error.ColdItemsMismatch,
        validateColdItems(gpa, &.{ stored, actual.items[1], actual.items[1] }, actual.items),
    );
}

test "serialized measurement cannot omit captured runtime identity" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const missing_runtime =
        \\{"schema":3,"source_digest":"current","compiler":"0.16.0",
        \\ "compiler_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        \\ "scope":["test","test-portable","quic-test","invariants","test-gate-policy"],
        \\ "modes":["Debug","ReleaseSafe"],"sources":[],"artifacts":[],
        \\ "cold_items":[],"reports":[]}
    ;
    try std.testing.expectError(
        error.MissingField,
        std.json.parseFromSliceLeaky(Measurement, arena.allocator(), missing_runtime, .{}),
    );
}

test "retained runtime identity requires an absolute object path and SHA256" {
    const identities = [_]ev.Artifact{
        .{ .path = "", .sha256 = &@as([64:0]u8, @splat('a')) },
        .{ .path = "zig-cov-rt.o", .sha256 = &@as([64:0]u8, @splat('a')) },
        .{ .path = "/", .sha256 = &@as([64:0]u8, @splat('a')) },
        .{ .path = "/captured/zig-cov-rt.o", .sha256 = "" },
        .{ .path = "/captured/zig-cov-rt.o", .sha256 = &@as([63:0]u8, @splat('a')) },
        .{ .path = "/captured/zig-cov-rt.o", .sha256 = &@as([64:0]u8, @splat('g')) },
    };
    for (identities) |identity| {
        try std.testing.expectError(error.InvalidRuntimeIdentity, validateRuntimeIdentity(identity));
    }
}

test "serialized retained runtime identity cannot omit path or SHA256" {
    const missing = [_][]const u8{
        \\{"path":"/captured/zig-cov-rt.o"}
        ,
        \\{"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
        ,
    };
    for (missing) |json| {
        try std.testing.expectError(
            error.MissingField,
            std.json.parseFromSlice(ev.Artifact, std.testing.allocator, json, .{}),
        );
    }
}
