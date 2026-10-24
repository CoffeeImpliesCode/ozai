const std = @import("std");
const ev = @import("gate_evidence.zig");
const measure = @import("gate_measure.zig");
const record = @import("gate_record.zig");
const reports = @import("gate_report.zig");
const raw = @import("gate_raw.zig");
const raw_mapping = @import("gate_raw_mapping.zig");
const projection = @import("gate_projection.zig");
const dwarf_universe = @import("gate_dwarf_universe.zig");
const zbc = @import("gate_zbc.zig");
const zbc_scan = @import("gate_zbc_scan.zig");
const zbc_policy = @import("gate_zbc_policy.zig");
const files = @import("gate_files.zig");
const sources = @import("gate_sources.zig");
const scratch = @import("gate_scratch.zig");

pub const MainError = std.process.Args.ToSliceError || std.mem.Allocator.Error ||
    sources.SourcesError || scratch.CreateError || ev.RunError || files.ReadFileError ||
    zbc.RunError || measure.MeasureError || record.ReplayError ||
    std.process.CurrentPathAllocError || error{
    Usage,
    MissingCompiler,
    CompilerMustBeAbsolute,
    CompilerPinMismatch,
    SourceChangedDuringGate,
    SkippedConfiguredCheck,
};
const SourceDigestError = std.mem.Allocator.Error || sources.SourcesError;
const CompilerError = std.mem.Allocator.Error || ev.RunError || files.ReadFileError ||
    error{CompilerPinMismatch};
const ConfiguredChecksError = std.mem.Allocator.Error || std.process.CurrentPathAllocError ||
    ev.RunError || zbc.RunError || error{SkippedConfiguredCheck};

pub fn main(init: std.process.Init) MainError!void {
    const gpa = init.arena.allocator();
    const args = try init.minimal.args.toSlice(gpa);
    if (args.len < 2 or args.len > 3) return error.Usage;
    const command = args[1];
    if (std.mem.eql(u8, command, "validate")) {
        if (args.len != 3) return error.Usage;
        try record.validate(gpa, init.io, args[2], init.environ_map);
        return;
    }
    if (args.len != 2 or (!std.mem.eql(u8, command, "gate") and
        !std.mem.eql(u8, command, "measure"))) return error.Usage;
    var environment = try init.environ_map.clone(gpa);
    defer environment.deinit();
    const root = try ev.createRoot(init, &environment);
    std.log.info("retained gate evidence: {s}", .{root});
    const runner: ev.Runner = .{
        .gpa = gpa,
        .io = init.io,
        .environment = &environment,
        .root = root,
    };
    const zig = environment.get("ZIG") orelse return error.MissingCompiler;
    if (!std.fs.path.isAbsolute(zig)) return error.CompilerMustBeAbsolute;
    const digest = try currentSourceDigest(gpa, init.io);
    defer gpa.free(digest);
    const compiler = try checkCompiler(runner, zig);
    const is_gate = std.mem.eql(u8, command, "gate");
    if (is_gate) {
        try configuredChecks(runner);
        try measure.runSafetyModes(runner, zig);
        try checkCurrentSource(gpa, init.io, digest);
        if (environment.get("OZAI_COVERAGE_POLICY") != null) {
            try record.validateRetained(gpa, init.io, &environment);
            try checkCurrentSource(gpa, init.io, digest);
        }
    } else {
        const measurement = try measure.run(runner, zig, compiler);
        if (!std.mem.eql(u8, digest, measurement.source_digest))
            return error.SourceChangedDuringGate;
        try checkCurrentSource(gpa, init.io, digest);
    }
}

fn currentSourceDigest(gpa: std.mem.Allocator, io: std.Io) SourceDigestError![]const u8 {
    const inventory = try ev.sources(gpa, io);
    defer {
        for (inventory) |source| {
            gpa.free(source.path);
            gpa.free(source.sha256);
        }
        gpa.free(inventory);
    }
    return ev.sourceDigest(gpa, inventory);
}

fn checkCurrentSource(
    gpa: std.mem.Allocator,
    io: std.Io,
    expected: []const u8,
) (SourceDigestError || error{SourceChangedDuringGate})!void {
    const current = try currentSourceDigest(gpa, io);
    defer gpa.free(current);
    if (!std.mem.eql(u8, expected, current)) return error.SourceChangedDuringGate;
}

fn checkCompiler(runner: ev.Runner, zig: []const u8) CompilerError![]const u8 {
    const result = try runner.run("compiler", &.{ zig, "version" });
    const compiler = std.mem.trim(u8, result.stdout, " \r\n");
    const manifest = try ev.readFile(runner.gpa, runner.io, "build.zig.zon");
    defer runner.gpa.free(manifest);
    const pin = try std.fmt.allocPrint(runner.gpa, ".minimum_zig_version = \"{s}\"", .{compiler});
    defer runner.gpa.free(pin);
    if (std.mem.indexOf(u8, manifest, pin) == null) return error.CompilerPinMismatch;
    return compiler;
}
fn configuredChecks(runner: ev.Runner) ConfiguredChecksError!void {
    const env = runner.environment;
    // Both source inventories belong to this project, regardless of inherited driver settings.
    const cwd = try std.process.currentPathAlloc(runner.io, runner.gpa);
    defer runner.gpa.free(cwd);
    try env.put("ZIG_GATE_DIR", cwd);
    try env.put("ZBC_STRICT", "1");
    try env.put("ZWANZIG_ARGS", "--max-states-per-point 200");
    try env.put(
        "GATE_EXCLUDE",
        "^[.]/vendor/ /[.]zig-cache/ /zig-out/ /zig-cache/ /zig-global-cache/ /zig-pkg/",
    );
    try env.put("GATE_CACHE_DIR", try runner.path("configured-cache"));
    try env.put("GATE_GLOBAL_CACHE_DIR", try runner.path("global-cache"));
    const zbc_result = zbc.run(runner);
    const result = runner.run("configured-checks", &.{ "zig-gate", "--no-zbc" }) catch |err| {
        try zbc_result;
        return err;
    };
    defer runner.gpa.free(result.stdout);
    defer runner.gpa.free(result.stderr);
    try zbc_result;
    if (std.mem.indexOf(u8, result.stdout, "skipped") != null) return error.SkippedConfiguredCheck;
}
test "strict gate module regressions" {
    std.testing.refAllDecls(record);
    std.testing.refAllDecls(reports);
    std.testing.refAllDecls(raw);
    std.testing.refAllDecls(raw_mapping);
    std.testing.refAllDecls(projection);
    std.testing.refAllDecls(dwarf_universe);
    std.testing.refAllDecls(measure);
    std.testing.refAllDecls(ev);
    std.testing.refAllDecls(zbc);
    std.testing.refAllDecls(zbc_scan);
    std.testing.refAllDecls(zbc_policy);
}
