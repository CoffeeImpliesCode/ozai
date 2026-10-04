//! Running the groups the caller asked for, and turning each outcome into a
//! recorded result.
//!
//! The driver decides what to run and where; this module runs it. It does not
//! stop at the first failure: the receipt is the evidence, and one broken suite
//! should not hide the state of the other ten. Every step is therefore recorded
//! with whether it was required, so a reader can tell "ran and passed" from
//! "was never asked to run" from the receipt alone.

const std = @import("std");
const scope = @import("gate_scope.zig");
const steps = @import("gate_steps.zig");
const zbc = @import("gate_zbc.zig");

/// What the caller asked for. The driver parses the command line; this module
/// needs only the selection and the bounds.
pub const Ask = struct {
    prefix: []const u8,
    fuzz_runs: u32,
    groups: []const []const u8,

    /// An empty selection means every group. Asking for nothing was never a way
    /// to ask for less than everything.
    pub fn wants(self: Ask, group: []const u8) bool {
        if (self.groups.len == 0) return true;
        for (self.groups) |name| {
            if (std.mem.eql(u8, name, group)) return true;
        }
        return false;
    }
};

pub fn runGroups(
    gpa: std.mem.Allocator,
    io: std.Io,
    ask: Ask,
    environ: *const std.process.Environ.Map,
    compiler: scope.Compiler,
    sources: scope.Scope,
    results: *std.ArrayList(steps.Result),
    verdict: *?zbc.Verdict,
    text: *std.Io.Writer,
) !bool {
    // `zbc` finds its toolchain through PATH and `ZIG_LIB_DIR`, so the child is
    // given the compiler this gate selected rather than whatever the shim on
    // PATH resolves to.
    var child_env = try environ.clone(gpa);
    try child_env.put("ZIG_LIB_DIR", compiler.lib_dir);
    if (child_env.get("PATH")) |path| {
        try child_env.put("PATH", try std.fmt.allocPrint(gpa, "{s}:{s}", .{
            compiler.bin_dir,
            path,
        }));
    }
    const inputs: steps.Inputs = .{
        .compiler = compiler,
        .prefix = ask.prefix,
        .fuzz_runs = ask.fuzz_runs,
        .all = sources.all,
        .first_party = sources.first_party,
        .static_environ = &child_env,
    };

    var failed = false;
    for (steps.groups) |group| {
        if (std.mem.eql(u8, group, "compiler")) continue;
        if (!ask.wants(group)) continue;
        if (std.mem.eql(u8, group, "refdecls")) {
            failed = try runSweepCheck(gpa, io, results, text) or failed;
            continue;
        }
        var group_steps: std.ArrayList(steps.Step) = .empty;
        try steps.buildSteps(gpa, inputs, group, &group_steps);
        for (group_steps.items) |step| {
            const result = steps.run(gpa, io, step);
            try results.append(gpa, result);
            try text.print("gate: {s} {s} ({s}){s}{s}\n", .{
                step.label,
                @tagName(result.status),
                @tagName(step.requirement),
                if (result.detail.len == 0) "" else " — ",
                result.detail,
            });
            failed = !steps.gatePassed(step, result) or failed;
            // A fuzz run that found a crashing input is a failure the exit
            // status does not carry, so it is read out of the report and the
            // verdict is corrected here rather than inherited from the child.
            if (std.mem.eql(u8, step.label, "fuzz") and steps.fuzzReportedFailure(result.stdout)) {
                try results.append(gpa, .{
                    .label = "fuzz:reported-failure",
                    .argv = result.argv,
                    .exit_code = 1,
                    .status = .fail,
                    .requirement = .required,
                    .detail = "the bounded run reported a failing input",
                });
                try text.print(
                    "gate: fuzz:reported-failure fail (required) — a bounded run reported a failing input\n",
                    .{},
                );
                failed = true;
            }
            // Triaged whenever the tool actually ran, empty output included: a
            // report that cannot be read is a failure, and skipping it because
            // it was empty is how a tool that died mid-run comes to look clean.
            if (std.mem.eql(u8, step.label, "static:zbc") and result.exit_code != null) {
                failed = try triageStatic(gpa, result, sources, results, verdict, text) or failed;
            }
        }
        if (std.mem.eql(u8, group, "static")) {
            for (steps.unconfigured_tools) |tool| try results.append(gpa, .{
                .label = try std.fmt.allocPrint(gpa, "static:{s}", .{tool}),
                .argv = &.{},
                .status = .not_configured,
                .requirement = .optional,
                .detail = "no configured invocation in this repository",
            });
        }
    }
    return failed;
}

/// The zbc verdict. Every reviewed finding is a disposition, not a pass; a
/// diagnostic outside them fails, and so does a reviewed one whose file has
/// changed since it was read, because the disposition describes code that is no
/// longer there. The tool's raw exit and its unresolved import lookups are
/// carried rather than rounded away by a policy that only knows what it has
/// seen, and a report that cannot be read is a failure rather than no verdict.
fn triageStatic(
    gpa: std.mem.Allocator,
    result: steps.Result,
    sources: scope.Scope,
    results: *std.ArrayList(steps.Result),
    verdict: *?zbc.Verdict,
    text: *std.Io.Writer,
) !bool {
    const parsed = zbc.triage(gpa, result.stdout, result.exit_code orelse 1, sources) catch |err| {
        try text.print(
            "gate: static:zbc-triage failed — the report could not be read ({t})\n",
            .{err},
        );
        try results.append(gpa, .{
            .label = "static:zbc-triage",
            .argv = &.{},
            .status = .fail,
            .requirement = .required,
            .detail = @errorName(err),
        });
        return true;
    };
    verdict.* = parsed;
    try text.print(
        "gate: static:zbc-triage {s}: {d} findings, {d} accepted, {d} rejected, " ++
            "{d} dispositions unused, raw exit {d}\n",
        .{
            if (parsed.passes()) "pass" else "fail",
            parsed.findings,
            parsed.accepted,
            parsed.rejected.len,
            parsed.stale,
            parsed.raw_exit,
        },
    );
    // The figure that bounds what this run proved is on the tool's stderr,
    // which `gate_steps.Step` inherits rather than captures, so the report this
    // triage reads cannot state it. It is printed as a limit rather than
    // dropped, because a run nobody bounds looks like a run over everything.
    try text.print(
        "gate:   zbc limit: unresolved-import lookups {s}\n",
        .{parsed.coverage.text()},
    );
    for (parsed.rejected) |match| try text.print(
        "gate:   {s} ({s}) — {s}\n",
        .{ match.key, @tagName(match.rejection), match.detail },
    );
    try results.append(gpa, .{
        .label = "static:zbc-triage",
        .argv = &.{},
        .exit_code = if (parsed.passes()) 0 else 1,
        .status = if (parsed.passes()) .pass else .fail,
        .requirement = .required,
        .detail = try std.fmt.allocPrint(gpa, "{s}: {d} rejected of {d} findings", .{
            parsed.summary,
            parsed.rejected.len,
            parsed.findings,
        }),
    });
    return !parsed.passes();
}

/// Every root the declaration sweep covers must reach declarations. A root that
/// dropped its sweep still compiles, still runs, and still exits 0, so it is
/// checked against the named list rather than assumed.
fn runSweepCheck(
    gpa: std.mem.Allocator,
    io: std.Io,
    results: *std.ArrayList(steps.Result),
    text: *std.Io.Writer,
) !bool {
    const cwd = std.Io.Dir.cwd();
    var failed = false;
    for (scope.sweep_roots) |root| {
        const label = try std.fmt.allocPrint(gpa, "refdecls:{s}", .{root});
        const swept = scope.sweepsDecls(gpa, io, cwd, root) catch |err| {
            try text.print("gate: {s} could not be read ({t})\n", .{ label, err });
            try results.append(gpa, .{
                .label = label,
                .argv = &.{},
                .status = .fail,
                .requirement = .required,
                .detail = @errorName(err),
            });
            failed = true;
            continue;
        };
        try results.append(gpa, .{
            .label = label,
            .argv = &.{},
            .exit_code = @as(u8, @intFromBool(!swept)),
            .status = if (swept) .pass else .fail,
            .requirement = .required,
            .detail = if (swept) "" else "no refAllDecls call: unreferenced decls go unanalysed",
        });
        if (!swept) {
            try text.print(
                "gate: {s} has no refAllDecls sweep; add one, or drop it from the list\n",
                .{label},
            );
            failed = true;
        }
    }
    return failed;
}
