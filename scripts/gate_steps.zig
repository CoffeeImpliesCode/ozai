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

/// Which of a child's output streams are the evidence for its result.
///
/// A stream not named here is inherited, so the operator still sees a run going
/// by. Naming both is not a preference: a child that fills one pipe while the
/// gate reads only the other deadlocks, and the build runner writes its whole
/// report — the `FUZZING REPORT` block and every `error:` line alike — on
/// stderr, so a step that reads only stdout reads nothing that decides its
/// result.
pub const Capture = enum { none, stdout, both };

/// What a step's captured output is read for, on the steps whose verdict is
/// their report rather than their exit status. `.none` is the ordinary case.
pub const Report = enum {
    none,
    /// A bounded `--fuzz=N` run. `zig build` reports a crashing input on its
    /// stderr and still exits 0: the fuzz worker catches the failure, prints it
    /// and returns, so the build's own failure count never moves.
    bounded_fuzz,
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
    capture: Capture = .none,
    report: Report = .none,
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
    /// The child's stderr, for the steps whose verdict is read out of it. A
    /// step that inherits stderr has none here, so a reader must not take an
    /// absent channel for a report that came back empty.
    stderr: []const u8 = "",
};

/// A captured report is bounded: a tool that prints without end is a tool whose
/// verdict this gate would have to trust unread. The ceiling is per stream, so
/// a step naming two of them is bounded at twice this.
const max_capture = 16 << 20;

/// The room a drain asks for past what it has already taken. It bounds how far
/// a capture can overshoot `max_capture` — one read of slack per stream — and
/// keeps the number of syscalls proportional to the report rather than to its
/// size.
const capture_reserve = 64 * 1024;

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
            // Both streams, and read as a report, because a run that fails under
            // `--fuzz=N` never reaches `zig build`'s own exit status: the mutation
            // is reported by the test runner, the fuzz worker prints it and
            // returns, and the build exits 0 having counted no failure. Both the
            // `error:` line and the whole `======= FUZZING REPORT =======` block
            // are written to stderr, so a capture that read stdout alone recorded
            // a decoder crash as a pass — the one thing a bounded fuzz run exists
            // to prevent.
            .capture = .both,
            .report = .bounded_fuzz,
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
            .capture = .stdout,
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
        .stdout = if (step.capture == .none) .inherit else .pipe,
        .stderr = if (step.capture == .both) .pipe else .inherit,
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
    const captured = capture(gpa, io, &child, step.capture) catch |err| {
        proc.dispose(io, &child);
        return refusal(step, @errorName(err));
    };
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
        .stdout = captured.stdout,
        .stderr = captured.stderr,
    };
}

/// What a child wrote on the streams its step named as evidence.
const Captured = struct {
    stdout: []const u8 = "",
    stderr: []const u8 = "",
};

/// Drains the child's evidence streams, before it is waited on.
///
/// Returns ahead of `proc.wait`, so the child still owns both pipe handles when
/// this returns and closes each exactly once; this reads copies of them and
/// closes nothing. A stream that outgrows the capture ceiling ends the pass as
/// a refusal rather than a short report, and the caller disposes the child.
fn capture(
    gpa: std.mem.Allocator,
    io: std.Io,
    child: *std.process.Child,
    which: Capture,
) !Captured {
    // `which` is the same value `run` armed the spawn with, so every pipe read
    // below is `.pipe` exactly on the arm that names it and the optional is
    // non-null where it is unwrapped.
    if (which == .none) return .{};
    if (which == .stdout) {
        // zwanzig-disable-next-line: optional-unwrap
        const only = [1]std.Io.File{child.stdout.?};
        return .{ .stdout = (try drain(gpa, io, 1, only))[0] };
    }
    // zwanzig-disable-next-line: optional-unwrap
    const both = [2]std.Io.File{ child.stdout.?, child.stderr.? };
    const owned = try drain(gpa, io, 2, both);
    return .{ .stdout = owned[0], .stderr = owned[1] };
}

/// One bounded pass over `count` pipes, drained together.
///
/// Concurrent reads across the whole set are what make this deadlock-free: a
/// child that fills one pipe while the gate drains only the other blocks
/// forever, and the multi-reader re-arms whichever pipe has room, so neither
/// starves. It is the mechanism `std.process.run` uses for exactly this shape.
///
/// `max_capture` is a refusal, not a truncation. A stream that crosses it ends
/// this pass at once, the caller kills and reaps the child, and the step is
/// recorded failed: a report too long to hold is a report this gate cannot
/// vouch for, and the part it did read is not evidence about the rest. The
/// label it refuses with is the same `StreamTooLong` the single-stream capture
/// refused with, so naming a second stream has not also introduced a second
/// notion of too long.
fn drain(
    gpa: std.mem.Allocator,
    io: std.Io,
    comptime count: usize,
    files: [count]std.Io.File,
) ![count][]const u8 {
    var storage: std.Io.File.MultiReader.Buffer(count) = undefined;
    var reader: std.Io.File.MultiReader = undefined;
    reader.init(gpa, io, storage.toStreams(), &files);
    // Closed by the `defer` on this line once the loop below ends and when any
    // `return` in it unwinds, so the pending reads are cancelled and the
    // reader's buffers are released on every path out; the engine does not
    // follow a `defer` to the scope exit it arms.
    defer reader.deinit();
    while (reader.fill(capture_reserve, .none)) |_| {
        for (0..count) |index| {
            if (reader.reader(index).buffered().len > max_capture) return error.StreamTooLong;
        }
    } else |err| {
        switch (err) {
            error.EndOfStream => {},
            else => |other| return other,
        }
    }
    try reader.checkAnyError();
    var owned: [count][]const u8 = undefined;
    for (0..count) |index| owned[index] = try reader.toOwnedSlice(index);
    return owned;
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

/// What one captured bounded fuzz run actually proved.
///
/// A run that stopped short of the bound it was given has proved nothing about
/// the inputs it never reached, so `short` is an answer of its own rather than
/// a flavour of pass: it is the state an exit status of 0 cannot tell apart
/// from success.
pub const FuzzVerdict = union(enum) {
    /// Every target the report names reached the bound, and the build runner
    /// reported no failure against any of them.
    complete,
    /// The build runner reported a failing test, in its own words.
    reported: []const u8,
    /// The run did not finish what it was asked to. The payload is what the
    /// report says about how far it got.
    short: []const u8,
};

/// The build runner's own marker for a step it is reporting as failed. Every
/// recorded step error is printed behind it, so a run carrying one failed
/// whatever its exit status says — and a test that merely logs a stack trace
/// carries none.
const build_failure_marker = "error:";

/// The field of a fuzzing report that says how far a target got.
const runs_field = "Runs:";

/// Said when a run printed no accounting at all: a report that cannot be read
/// is a failure, not an absent verdict.
const no_fuzz_report = "the build runner printed no fuzzing report";

/// One target's accounting in a fuzzing report: the runs the build runner had
/// heard of when it last spoke to the fuzzer, and the ones the fuzzer had
/// executed by the time it stopped.
const Runs = struct {
    heard: u64,
    done: u64,
};

/// Reads a captured bounded fuzz run's verdict out of the run's own streams.
///
/// `requested` is the bound the run was given, and it is checked against what
/// the report says rather than taken on trust: a run that crashed on input
/// 5450 of 10000 exits 0, and this accounting is where the 5450 is. Both
/// streams are read because the build runner prints on stderr and no child
/// promises to stay there.
pub fn readFuzzReport(stdout: []const u8, stderr: []const u8, requested: u32) FuzzVerdict {
    const streams = [_][]const u8{ stderr, stdout };
    for (streams) |stream| {
        var lines = std.mem.splitScalar(u8, stream, '\n');
        while (lines.next()) |line| {
            const trimmed = std.mem.trim(u8, line, " \t\r");
            if (std.mem.startsWith(u8, trimmed, build_failure_marker)) {
                return .{ .reported = trimmed };
            }
        }
    }
    var targets: u64 = 0;
    var short: ?[]const u8 = null;
    for (streams) |stream| {
        var lines = std.mem.splitScalar(u8, stream, '\n');
        while (lines.next()) |line| {
            const entry = runsEntry(line) orelse continue;
            targets += 1;
            if (entry.done < requested and short == null) {
                short = std.mem.trim(u8, line, " \t\r");
            }
        }
    }
    if (short) |line| return .{ .short = line };
    if (targets == 0) return .{ .short = no_fuzz_report };
    return .complete;
}

/// The `Runs: heard -> done` line of a fuzzing report, when this line is one.
fn runsEntry(line: []const u8) ?Runs {
    const trimmed = std.mem.trim(u8, line, " \t\r");
    if (!std.mem.startsWith(u8, trimmed, runs_field)) return null;
    var fields = std.mem.tokenizeAny(u8, trimmed[runs_field.len..], " \t");
    const heard = std.fmt.parseInt(u64, fields.next() orelse return null, 10) catch return null;
    if (!std.mem.eql(u8, fields.next() orelse return null, "->")) return null;
    const done = std.fmt.parseInt(u64, fields.next() orelse return null, 10) catch return null;
    return .{ .heard = heard, .done = done };
}

/// The result a captured report adds to the gate's own list.
///
/// A step whose verdict is its report rather than its exit status has to be
/// read, and what the report said becomes a result of its own so the receipt
/// carries the report's own words instead of a paraphrase of them. Null when
/// the report agrees with an exit status of zero, and null when that status
/// already failed: one failure is recorded once, by the step that owns it.
pub fn reportResult(
    gpa: std.mem.Allocator,
    step: Step,
    result: Result,
    fuzz_runs: u32,
) !?Result {
    const code = result.exit_code orelse return null;
    if (code != 0) return null;
    const verdict = switch (step.report) {
        .none => return null,
        .bounded_fuzz => readFuzzReport(result.stdout, result.stderr, fuzz_runs),
    };
    return switch (verdict) {
        .complete => null,
        .reported => |line| .{
            .label = "fuzz:reported-failure",
            .argv = result.argv,
            .exit_code = 1,
            .status = .fail,
            .requirement = step.requirement,
            .detail = try std.fmt.allocPrint(
                gpa,
                "the bounded run reported a failing test: {s}",
                .{line},
            ),
        },
        .short => |line| .{
            .label = "fuzz:incomplete-run",
            .argv = result.argv,
            .exit_code = 1,
            .status = .fail,
            .requirement = step.requirement,
            .detail = try std.fmt.allocPrint(
                gpa,
                "the bounded run did not reach {d} runs: {s}",
                .{ fuzz_runs, line },
            ),
        },
    };
}
