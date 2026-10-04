//! The commands of each gate group, and how one of them runs.
//!
//! `compile-all` is a group rather than part of `test`: it compiles every root
//! without running it, so a type error is reported before a suite spends
//! minutes producing a thousand results. `test` is the package suite plus the
//! vendored core, and `portable` is the socket-free root that overlaps it —
//! separately named, because an overlapping run that is not labelled looks
//! additive when it is not.

const std = @import("std");
const scope = @import("gate_scope.zig");
const proc = @import("gate_child.zig");

/// The modes every compile is run in. A gate that only ran one of them proves
/// the tree builds in the mode it happened to pick.
pub const modes = [_][]const u8{ "Debug", "ReleaseSafe" };

/// The groups, in the order they run. A group nobody asked for is skipped;
/// asking for a group that does not exist is a refusal.
pub const groups = [_][]const u8{
    "compiler",
    "fmt",
    "ast",
    "refdecls",
    "compile-all",
    "build",
    "test",
    "portable",
    "fuzz",
    "lint",
    "static",
};

/// Tools the house rules name and this repository has not configured. They are
/// recorded `not_configured` with that reason, which is the honest label and
/// never a pass.
pub const unconfigured_tools = [_][]const u8{ "zippy", "sanitizers" };

/// How much parallelism a child gets. The house convention for these machines
/// is two; it is a constant rather than a flag because a gate whose CPU
/// appetite can be raised from a command line is a gate whose reproducibility
/// depends on who typed it.
pub const job_limit = 2;
const build_jobs = std.fmt.comptimePrint("-j{d}", .{job_limit});
const zbc_jobs = std.fmt.comptimePrint("--jobs={d}", .{job_limit});

/// Whether a step must have run for this gate to mean anything. An optional
/// step that is absent is recorded as absent and is not a pass; it simply is
/// not the difference between a gate that ran and one that did not.
pub const Requirement = enum { required, optional };

pub const Status = enum {
    pass,
    fail,
    /// The command could not be started because it is not on this host. A tool
    /// that is present and refuses to start fails instead: it was found, and
    /// recording it as absent would drop a broken tool out of the gate.
    not_available,
    /// The tool has no configured invocation in this repository.
    not_configured,
};

pub const Inputs = struct {
    compiler: scope.Compiler,
    prefix: []const u8,
    fuzz_runs: u32,
    all: []const []const u8,
    first_party: []const []const u8,
    /// The environment `zbc` runs in: this compiler first on PATH and its own
    /// `lib/`, which is how the recorded audit run reached a toolchain that
    /// the broken shim cannot resolve.
    static_environ: ?*const std.process.Environ.Map = null,
};

/// One command. `scope_files` is the list handed to the tool on stdin, for the
/// tools that read their scope from there rather than from argv. `binding` is
/// false for a command whose exit status is not the verdict — `zbc` exits 1 over
/// the reviewed findings, and the triage beside it decides.
pub const Step = struct {
    label: []const u8,
    argv: []const []const u8,
    scope_files: ?[]const []const u8 = null,
    requirement: Requirement = .required,
    binding: bool = true,
    /// Take the child's stdout instead of passing it through, for the tool
    /// whose output is the evidence.
    capture: bool = false,
    environ_map: ?*const std.process.Environ.Map = null,
};

pub const Result = struct {
    label: []const u8,
    argv: []const []const u8,
    exit_code: ?u8 = null,
    status: Status,
    requirement: Requirement,
    detail: []const u8 = "",
    stdout: []const u8 = "",
};

/// A captured report is bounded: a tool that prints without end is a tool whose
/// verdict this gate would have to trust unread.
const max_capture = 16 << 20;

pub fn buildSteps(
    gpa: std.mem.Allocator,
    inputs: Inputs,
    group: []const u8,
    out: *std.ArrayList(Step),
) !void {
    if (std.mem.eql(u8, group, "fmt")) {
        try out.append(gpa, .{
            .label = "fmt",
            .argv = try gpa.dupe([]const u8, &.{ inputs.compiler.path, "fmt", "--check", "." }),
        });
    } else if (std.mem.eql(u8, group, "ast")) {
        for (inputs.all) |path| try out.append(gpa, .{
            .label = try std.fmt.allocPrint(gpa, "ast:{s}", .{path}),
            .argv = try gpa.dupe([]const u8, &.{ inputs.compiler.path, "ast-check", path }),
        });
    } else if (std.mem.eql(u8, group, "compile-all")) {
        try appendPerMode(gpa, inputs, "compile-all", &.{"compile-all"}, out);
    } else if (std.mem.eql(u8, group, "build")) {
        try appendPerMode(gpa, inputs, "build", &.{}, out);
    } else if (std.mem.eql(u8, group, "test")) {
        try appendPerMode(gpa, inputs, "test", &.{ "test", "quic-test" }, out);
    } else if (std.mem.eql(u8, group, "portable")) {
        try appendPerMode(gpa, inputs, "portable", &.{"test-portable"}, out);
    } else if (std.mem.eql(u8, group, "fuzz")) {
        // Arena storage, released whole when `main` returns: `gpa` is the gate's
        // own arena (gate.zig:105) and the argv it is printed into belongs to a
        // child that has exited by the time the receipt is written. There is no
        // per-allocation owner here to hand a free to.
        // zwanzig-disable-next-line: store-violations-engine
        const bound = try std.fmt.allocPrint(gpa, "--fuzz={d}", .{inputs.fuzz_runs});
        try out.append(gpa, .{
            .label = "fuzz",
            .argv = try gpa.dupe([]const u8, &.{
                inputs.compiler.path, "build", "fuzz", bound, build_jobs, "--prefix", inputs.prefix,
            }),
            // Captured, because a run step that fails under `--fuzz=N` does not
            // reach `zig build`'s own exit status: the mutation is reported by
            // the test runner and the build still exits 0. Without the output
            // this group would record a decoder crash as a pass, which is the
            // one thing a bounded fuzz run exists to prevent.
            .capture = true,
        });
    } else if (std.mem.eql(u8, group, "lint")) {
        // `zlint` and `ziglint` are this repository's configured linters
        // (`zlint.json`, and the recorded findings it has to answer for), so
        // their findings decide the gate and their absence is a failure.
        try out.append(gpa, .{
            .label = "lint:zlint",
            .argv = &.{ "zlint", "-c", "zlint.json", "-S" },
            .scope_files = inputs.all,
        });
        try out.append(gpa, .{
            .label = "lint:ziglint",
            .argv = try argvWith(
                gpa,
                &.{ "ziglint", "--zig-lib-path", inputs.compiler.lib_dir },
                inputs.first_party,
            ),
        });
        // `zwanzig` is opt-in per `AGENTS.md` §6: absent is recorded absent and
        // is not a pass, but it is not the difference between a gate that ran
        // and one that did not. Present, it binds.
        try out.append(gpa, .{
            .label = "lint:zwanzig",
            .argv = try argvWith(gpa, &.{"zwanzig"}, inputs.first_party),
            .requirement = .optional,
        });
    } else if (std.mem.eql(u8, group, "static")) {
        // Its exit status is not the verdict: `zbc` exits 1 on the 25 reviewed
        // findings, and the verdict is whether a diagnostic outside them
        // appeared. The triage in `gate_zbc.zig` decides, and it binds.
        try out.append(gpa, .{
            .label = "static:zbc",
            .argv = try argvWith(
                gpa,
                &.{ "zbc", "--format=json", zbc_jobs },
                inputs.first_party,
            ),
            .capture = true,
            .binding = false,
            .environ_map = inputs.static_environ,
        });
    } else {
        return error.UnknownGroup;
    }
}

fn appendPerMode(
    gpa: std.mem.Allocator,
    inputs: Inputs,
    label: []const u8,
    steps: []const []const u8,
    out: *std.ArrayList(Step),
) !void {
    for (modes) |mode| {
        var argv: std.ArrayList([]const u8) = .empty;
        try argv.appendSlice(gpa, &.{ inputs.compiler.path, "build" });
        try argv.appendSlice(gpa, steps);
        try argv.append(gpa, try std.fmt.allocPrint(gpa, "-Doptimize={s}", .{mode}));
        try argv.appendSlice(gpa, &.{ build_jobs, "--prefix", inputs.prefix });
        try out.append(gpa, .{
            .label = try std.fmt.allocPrint(gpa, "{s}:{s}", .{ label, mode }),
            .argv = argv.items,
        });
    }
}

pub fn argvWith(
    gpa: std.mem.Allocator,
    head: []const []const u8,
    tail: []const []const u8,
) ![]const []const u8 {
    var argv: std.ArrayList([]const u8) = .empty;
    try argv.appendSlice(gpa, head);
    try argv.appendSlice(gpa, tail);
    return argv.items;
}

pub fn run(gpa: std.mem.Allocator, io: std.Io, step: Step) Result {
    var child = std.process.spawn(io, .{
        .argv = step.argv,
        .environ_map = step.environ_map,
        .stdin = if (step.scope_files != null) .pipe else .inherit,
        .stdout = if (step.capture) .pipe else .inherit,
        .stderr = .inherit,
    }) catch |err| return spawnRefusal(step, err);
    if (step.scope_files) |files| {
        // `.stdin` is `.pipe` exactly when `scope_files` is set (the spawn
        // options above), so the optional is non-null on the arm that is here.
        // zwanzig-disable-next-line: optional-unwrap
        writeScope(io, child.stdin.?, files) catch |err| {
            proc.dispose(io, &child);
            return refusal(step, @errorName(err));
        };
        // Ownership moves: `wait` closes what is still recorded here, so the
        // write end is closed here and taken off the child first.
        // The same binding as the write above: this arm is reached only when
        // `.stdin = .pipe` was asked for.
        // zwanzig-disable-next-line: optional-unwrap
        child.stdin.?.close(io);
        child.stdin = null;
    }
    var captured: []const u8 = "";
    if (step.capture) {
        var buffer: [64 * 1024]u8 = undefined;
        // `.stdout` is `.pipe` exactly when `capture` is set, same arming.
        // zwanzig-disable-next-line: optional-unwrap
        var reader = child.stdout.?.readerStreaming(io, &buffer);
        captured = reader.interface.allocRemaining(gpa, .limited(max_capture)) catch |err| {
            proc.dispose(io, &child);
            return refusal(step, @errorName(err));
        };
    }
    const term = proc.wait(io, &child) catch |err| return refusal(step, @errorName(err));
    const code = switch (term) {
        .exited => |status| status,
        else => return refusal(step, @tagName(term)),
    };
    return .{
        .label = step.label,
        .argv = step.argv,
        .exit_code = code,
        .status = if (code == 0) .pass else .fail,
        .requirement = step.requirement,
        .stdout = captured,
    };
}

fn refusal(step: Step, detail: []const u8) Result {
    return .{
        .label = step.label,
        .argv = step.argv,
        .status = .fail,
        .requirement = step.requirement,
        .detail = detail,
    };
}

/// Why a step never started. Only `FileNotFound` is an absent tool: it is the
/// one spawn error that says the name resolved to nothing. Every other one —
/// a file that is there and not executable, an executable that will not load,
/// a refused or exhausted host — means the tool was found and could not run,
/// and that fails whether or not the step is optional: an installed linter
/// recorded as absent is a gate that has quietly stopped checking the tree.
/// Either way the reader gets the error the spawn actually produced.
fn spawnRefusal(step: Step, err: std.process.SpawnError) Result {
    return .{
        .label = step.label,
        .argv = step.argv,
        .status = if (err == error.FileNotFound) .not_available else .fail,
        .requirement = step.requirement,
        .detail = @errorName(err),
    };
}

fn writeScope(
    io: std.Io,
    file: std.Io.File,
    files: []const []const u8,
) !void {
    var buffer: [8192]u8 = undefined;
    var writer = file.writerStreaming(io, &buffer);
    for (files) |path| try writer.interface.print("{s}\n", .{path});
    try writer.flush();
}

/// Whether one result fails the gate.
///
/// A required step must have run and must have passed: an absent linter is not
/// a clean tree, and there is no flag that turns it into one. A non-binding
/// step's exit status is not its verdict — `zbc` exits 1 over the reviewed
/// findings by design — but a step that never reached an exit status at all
/// (killed, unable to write its scope, unable to be waited for) never produced
/// the verdict either, and fails whatever its binding is. An optional step
/// that ran and failed does fail; one that never ran is recorded and left alone.
pub fn gatePassed(step: Step, result: Result) bool {
    if (result.exit_code == null and result.status == .fail) return false;
    return switch (result.status) {
        .pass => true,
        .fail => !step.binding,
        .not_available, .not_configured => switch (step.requirement) {
            .required => false,
            .optional => true,
        },
    };
}

/// Whether a bounded fuzz run reported a failing input, read from its output.
///
/// `zig build fuzz --fuzz=N` does not carry a run step's failure into its own
/// exit status, so the verdict has to come from the report instead. Both
/// markers are the test runner's own: `input saved to` names the artifact it
/// wrote for a crashing input, and `error: test '` prefixes its per-test
/// failure line. A target that merely logs a stack trace prints neither.
pub fn fuzzReportedFailure(output: []const u8) bool {
    return std.mem.indexOf(u8, output, "input saved to") != null or
        std.mem.indexOf(u8, output, "error: test '") != null;
}
