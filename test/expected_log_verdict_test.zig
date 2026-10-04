//! Verdict regressions for `test/expected_log_runner.zig`, read from outside
//! the process that reaches it: each test starts a fixture executable wearing
//! that runner, drives it over the run protocol, and checks its exit status and
//! its stderr. `test/expected_log_cases.zig` only logs, so the runner is the
//! only implementation of the rule under test.
//!
//! A verdict is an exit status. A process that did not exit on its own — a
//! signal, a stop, one this file never reaped — is a broken fixture and says
//! nothing about the runner, so every negative case below rejects it rather
//! than accepting it as a failed run.

const std = @import("std");
const posix = std.posix;

const t = std.testing;

const fixture_options = @import("expected_log_verdict_options");

const once_executable = fixture_options.once_executable;
const twice_executable = fixture_options.twice_executable;

/// The cross-test executor, prepended to a child's command line exactly as
/// `test/two_process_test.zig` prepends its own: a QEMU-run test must use that
/// executor for its children too, because the host kernel need not have
/// binfmt_misc or native 32-bit execution enabled.
const executor = fixture_options.executor;

/// Duplicated from `test/expected_log_cases.zig` rather than imported from it:
/// a verdict test that imported the fixture would pull its `test` blocks into
/// its own compilation, where they would log the refusals being judged.
const refusal_scope = "expected_log_case";
const refusal_text = "expected-log case refused peer 7 of 9";

/// What the runner prints for one refusal, at the level it was logged at. A
/// tolerance decides whether a message is also a failure, never whether it is
/// a message, so this line is asserted in every scenario that produces one.
const refusal_line = std.fmt.comptimePrint(
    "[{s}] (err): {s}\n",
    .{ refusal_scope, refusal_text },
);

/// A scope no fixture logs under.
const absent_scope = "expected_log_case_other";

/// A message no fixture produces.
const absent_text = "expected-log case refused peer 1 of 1";

const deadline_ms = 20_000;
const poll_step_ms = 50;

/// The three answers a child process can give.
const Verdict = enum {
    /// Exited zero: the run tolerated everything it was told to tolerate.
    passed,
    /// Exited non-zero: the run refused something.
    failed,
    /// Signalled, stopped, or never reaped. Says nothing about the runner, and
    /// a negative case that accepted it would pass on a crash.
    broken,
};

const Run = struct {
    term: ?std.process.Child.Term,
    stderr: []u8,
};

test "one refusal named in full, once, passes the run and is still printed at error level" {
    const run = try runFixture(t.allocator, t.io, once_executable, &.{
        refusal_scope, refusal_text,
    });
    defer t.allocator.free(run.stderr);

    try expectVerdict(run, .passed);
    try expectPrinted(run, 1);
}

test "the same refusal logged twice fails the run, and both copies are still printed" {
    const run = try runFixture(t.allocator, t.io, twice_executable, &.{
        refusal_scope, refusal_text,
    });
    defer t.allocator.free(run.stderr);

    try expectVerdict(run, .failed);
    // Twice: printing one copy of a message the code under test logged twice
    // has silenced half of what it said, and printing none has silenced all
    // of it. Both are the quiet way to make this verdict pass.
    try expectPrinted(run, 2);
}

test "two identical expectations fail the run with a refusal naming the row" {
    // Two rows say one thing, one observation answers both, and nothing in the
    // run says which of them the witness belonged to. The decision held here
    // is fail-closed rejection rather than counting the rows as two answers: a
    // duplicated entry is a command line somebody wrote by accident, and the
    // safest reading of it is none.
    const run = try runFixture(t.allocator, t.io, once_executable, &.{
        refusal_scope, refusal_text,
        refusal_scope, refusal_text,
    });
    defer t.allocator.free(run.stderr);

    try expectVerdict(run, .failed);
    // Refused while the command line was parsed, so no test ran and there is no
    // product log to have printed; what is on stderr is the refusal itself. A
    // process that merely died cannot satisfy this — it neither exits on its
    // own nor says which row it refused.
    try expectPrinted(run, 0);
    try expectNamed(run, refusal_scope, refusal_text);
}

test "an expectation naming another scope fails the run, and the refusal is still printed" {
    const run = try runFixture(t.allocator, t.io, once_executable, &.{
        absent_scope, refusal_text,
    });
    defer t.allocator.free(run.stderr);

    try expectVerdict(run, .failed);
    try expectPrinted(run, 1);
}

test "an expectation no fixture produced fails the run, and the refusal is still printed" {
    const run = try runFixture(t.allocator, t.io, once_executable, &.{
        refusal_scope, absent_text,
    });
    defer t.allocator.free(run.stderr);

    try expectVerdict(run, .failed);
    try expectPrinted(run, 1);
}

test "an expectation naming part of the message fails the run, and the refusal is still printed" {
    // The whole rendered message is the unit, from both ends: a run matching
    // only the start tolerates every shorter wording of this refusal, and one
    // matching only the tail tolerates every longer one. Both tolerate a
    // message the run never made.
    const shorter = refusal_text[0 .. refusal_text.len / 2];
    const longer = refusal_text ++ " for the second time";
    const short_run = try runFixture(t.allocator, t.io, once_executable, &.{
        refusal_scope, shorter,
    });
    defer t.allocator.free(short_run.stderr);
    const long_run = try runFixture(t.allocator, t.io, once_executable, &.{
        refusal_scope, longer,
    });
    defer t.allocator.free(long_run.stderr);

    try expectVerdict(short_run, .failed);
    try expectPrinted(short_run, 1);
    try expectVerdict(long_run, .failed);
    try expectPrinted(long_run, 1);
}

/// Start one fixture process, drive it, and take everything it printed.
fn runFixture(
    gpa: std.mem.Allocator,
    io: std.Io,
    executable: []const u8,
    expect_log: []const []const u8,
) !Run {
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var argv: std.ArrayList([]const u8) = .empty;
    if (executor) |cross| try argv.append(arena, cross);
    try argv.append(arena, executable);
    // The runner's only mode, and the flag `std.Build.Step.Run` puts on every
    // test artifact it drives.
    try argv.append(arena, "--listen=-");
    std.debug.assert(expect_log.len % 2 == 0);
    var at: usize = 0;
    while (at < expect_log.len) : (at += 2) {
        try argv.append(arena, "--expect-log");
        try argv.append(arena, expect_log[at]);
        try argv.append(arena, expect_log[at + 1]);
    }

    var child = try std.process.spawn(io, .{
        .argv = argv.items,
        .stdin = .pipe,
        // The protocol's replies come back on stdout and nothing here reads
        // them; a reply left in a pipe this file never drains is a reply that
        // could block the child.
        .stdout = .ignore,
        .stderr = .pipe,
    });
    errdefer child.kill(io);

    const stdin_pipe = child.stdin orelse return error.NoStdinPipe;
    // A fixture that answered without being driven has closed its stdin, and
    // the write that finds it closed is `BrokenPipe` — the verdict is on stderr
    // either way. Any other error is a fault in this harness rather than a
    // child refusing its input, and is not read as one.
    drive(io, stdin_pipe) catch |drive_err| switch (drive_err) {
        error.BrokenPipe => {},
        else => |other| return other,
    };

    const stderr_pipe = child.stderr orelse return error.NoStderrPipe;
    var collected: std.ArrayList(u8) = .empty;
    errdefer collected.deinit(gpa);

    // Taken to end of file before the reap: `wait` closes the pipes, so a
    // verdict read after the child is gone is a verdict with nothing in it.
    try readStderr(gpa, io, stderr_pipe, &collected);
    const stderr = try collected.toOwnedSlice(gpa);
    errdefer gpa.free(stderr);

    const term = try child.wait(io);
    return .{ .term = term, .stderr = stderr };
}

/// Run the fixture's one test, then stop.
///
/// `std.zig.Server` reads `std.zig.Client.Message` headers: eight little-endian
/// bytes of tag and body length, then the body. `run_test`'s body is one
/// little-endian `u32` index into `builtin.test_functions`, which is 0 because
/// `build.zig` compiles each fixture with a `filters` selection of one test.
/// `exit` has no body, and answering it is what calls `finish`, where the exit
/// code is set, so the four bytes between the two headers are the whole run.
fn drive(io: std.Io, pipe: std.Io.File) !void {
    var message: [20]u8 = undefined;
    writeHeader(message[0..8], .run_test, 4);
    std.mem.writeInt(u32, message[8..12], 0, .little);
    writeHeader(message[12..20], .exit, 0);
    try writeAll(io, pipe, &message);
}

fn writeHeader(header: []u8, tag: std.zig.Client.Message.Tag, body_len: u32) void {
    std.mem.writeInt(u32, header[0..4], @intFromEnum(tag), .little);
    std.mem.writeInt(u32, header[4..8], body_len, .little);
}

/// A pipe may take fewer bytes than it was given, and a half-sent header is a
/// fixture that hangs rather than one that answers.
fn writeAll(io: std.Io, pipe: std.Io.File, bytes: []const u8) !void {
    var written: usize = 0;
    while (written < bytes.len) {
        const got = try pipe.writeStreaming(io, &.{}, &.{bytes[written..]}, 1);
        if (got == 0) return error.FixtureRefusedInput;
        written += got;
    }
}

/// Take stderr until the child closes it, or end the run at the deadline. The
/// step count is bounded by the budget, so a fixture that neither writes nor
/// closes is ended rather than waited on.
fn readStderr(
    gpa: std.mem.Allocator,
    io: std.Io,
    pipe: std.Io.File,
    into: *std.ArrayList(u8),
) !void {
    const deadline = nowMs(io) + deadline_ms;
    const max_steps: usize = @intCast(@divTrunc(deadline_ms, poll_step_ms) + 1);
    for (0..max_steps) |_| {
        var fds = [_]posix.pollfd{.{
            .fd = pipe.handle,
            .events = posix.POLL.IN,
            .revents = 0,
        }};
        if (try posix.poll(&fds, poll_step_ms) == 0) {
            if (nowMs(io) > deadline) return error.FixtureOutlivedDeadline;
            continue;
        }
        var chunk: [4096]u8 = undefined;
        const got = pipe.readStreaming(io, &.{&chunk}) catch |err| switch (err) {
            error.EndOfStream => return,
            else => return err,
        };
        try into.appendSlice(gpa, chunk[0..got]);
    }
    return error.FixtureOutlivedDeadline;
}

fn classify(run: Run) Verdict {
    const ended = run.term orelse return .broken;
    return switch (ended) {
        .exited => |code| if (code == 0) .passed else .failed,
        else => .broken,
    };
}

fn expectVerdict(run: Run, want: Verdict) !void {
    const got = classify(run);
    if (got != want) report(run, "the exit status");
    try t.expectEqual(want, got);
}

fn expectPrinted(run: Run, want: usize) !void {
    const got = countOf(run.stderr, refusal_line);
    if (got != want) report(run, "the printed refusal line");
    try t.expectEqual(want, got);
}

/// That the process said which expectation it refused.
fn expectNamed(run: Run, scope: []const u8, text: []const u8) !void {
    for ([_]struct { []const u8, []const u8 }{
        .{ scope, "the refused scope" },
        .{ text, "the refused message" },
    }) |part| {
        if (std.mem.indexOf(u8, run.stderr, part[0]) == null) {
            report(run, part[1]);
            return error.UndiagnosedRefusal;
        }
    }
}

/// The exit status and the whole of stderr. A verdict that cannot show what the
/// process said is indistinguishable from a verdict about the wrong process.
fn report(run: Run, subject: []const u8) void {
    std.debug.print(
        "\nthis fixture run did not answer about {s}:\n  exited: {any}\n" ++
            "  --- fixture stderr ---\n{s}  --- end fixture stderr ---\n",
        .{ subject, run.term, run.stderr },
    );
}

/// Non-overlapping occurrences of `needle` in `haystack`, bounded by its length.
fn countOf(haystack: []const u8, needle: []const u8) usize {
    var found: usize = 0;
    var rest = haystack;
    for (0..haystack.len + 1) |_| {
        const at = std.mem.indexOf(u8, rest, needle) orelse return found;
        found += 1;
        rest = rest[at + needle.len ..];
    }
    return found;
}

fn nowMs(io: std.Io) i64 {
    return @intCast(@divTrunc(std.Io.Clock.awake.now(io).nanoseconds, std.time.ns_per_ms));
}
