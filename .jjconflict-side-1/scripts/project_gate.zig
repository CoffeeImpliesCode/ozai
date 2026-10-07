const std = @import("std");
const ev = @import("gate_evidence.zig");
const measure = @import("gate_measure.zig");
const record = @import("gate_record.zig");

pub fn main(init: std.process.Init) !void {
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
    const runner: ev.Runner = .{ .gpa = gpa, .io = init.io, .environment = &environment, .root = root };
    const zig = environment.get("ZIG") orelse return error.MissingCompiler;
    if (!std.fs.path.isAbsolute(zig)) return error.CompilerMustBeAbsolute;
    const compiler = try checkCompiler(runner, zig);
    const digest = try ev.sourceDigest(gpa, try ev.sources(gpa, init.io));
    const is_gate = std.mem.eql(u8, command, "gate");
    if (is_gate) try configuredChecks(runner);
    const measurement = try measure.run(runner, zig, compiler);
    if (!std.mem.eql(u8, digest, measurement.source_digest)) return error.SourceChangedDuringGate;
    if (is_gate) try record.validateLedger(gpa, init.io, measurement);
}
fn checkCompiler(runner: ev.Runner, zig: []const u8) ![]const u8 {
    const result = try runner.run("compiler", &.{ zig, "version" });
    const compiler = std.mem.trim(u8, result.stdout, " \r\n");
    const manifest = try ev.readFile(runner.gpa, runner.io, "build.zig.zon");
    const pin = try std.fmt.allocPrint(runner.gpa, ".minimum_zig_version = \"{s}\"", .{compiler});
    if (std.mem.indexOf(u8, manifest, pin) == null) return error.CompilerPinMismatch;
    return compiler;
}
fn configuredChecks(runner: ev.Runner) !void {
    const env = runner.environment;
    try env.put("ZBC_STRICT", "1");
    try env.put("GATE_EXCLUDE", "^[.]/vendor/ /[.]zig-cache/ /zig-out/ /zig-cache/ /zig-global-cache/ /zig-pkg/");
    try env.put("GATE_CACHE_DIR", try runner.path("configured-cache"));
    try env.put("GATE_GLOBAL_CACHE_DIR", try runner.path("global-cache"));
    const result = try runner.run("configured-checks", &.{"zig-gate"});
    if (std.mem.indexOf(u8, result.stdout, "skipped") != null) return error.SkippedConfiguredCheck;
}
test "strict gate module regressions" {
    std.testing.refAllDecls(@import("gate_record.zig"));
    std.testing.refAllDecls(@import("gate_report.zig"));
    std.testing.refAllDecls(@import("gate_raw.zig"));
    std.testing.refAllDecls(@import("gate_measure.zig"));
    std.testing.refAllDecls(@import("gate_evidence.zig"));
}
