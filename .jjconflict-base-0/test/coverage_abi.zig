//! The fuzz runtime's runner ABI, for a binary that links that runtime and
//! never drives it.
//!
//! # Why a coverage build needs it at all
//!
//! `-ffuzz` links the fuzz runtime whether or not anything drives it, and that
//! runtime calls back through seven `runner_*` exports, so every fuzz-linked
//! binary has to define them. Coverage is what puts a binary with no fuzz test
//! in that position: `fuzz` is the only switch that makes LLVM emit counters,
//! the self-hosted backends emit none, and the runtime flushes from a libc
//! atexit handler. `build.zig` hands this module to every artifact on its
//! coverage list — each custom test runner among them, and the node, which has
//! no test runner at all.
//!
//! # Why all seven refuse
//!
//! Every one of them is called from inside `fuzzer_main`, and the only thing
//! that calls `fuzzer_main` is the start message a test runner answers.
//! `test/expected_log_runner.zig` refuses that message, and a program that is
//! not a test never enters the fuzzer. So an artifact wearing this ABI has no
//! session to serve, and an entry that returned quietly would turn a build
//! wired wrongly into a binary that misbehaves somewhere later instead. Each
//! one below panics with the name it was reached under and the arguments that
//! got it there.
//!
//! # Why the names are exports and not declarations
//!
//! `std.Build.abi.fuzz` declares these seven and its runtime resolves every
//! call it makes through them, so the spelling is the link contract rather
//! than a name this file picks: a rename leaves the symbol undefined when a
//! fuzz-linked binary is linked. Exporting keeps the Zig underneath camelCase,
//! so the seven identifier-style suppressions that seven `export fn`s would
//! need are not here to rot.

const std = @import("std");

/// The one type in these signatures that is not a Zig primitive: the fuzz
/// runtime's by-value slice. Spelled once, so the ABI this file answers to has
/// a single place in it that changes when the runtime's does.
const Slice = std.Build.abi.fuzz.Slice;

/// Why one of the exports below was reached, given the name it answers to and
/// whatever its arguments say about which call it was. A panic rather than a
/// return because there is no answer to give: a wrong one is a fuzz session
/// nobody agreed to, running to completion and reporting that it worked.
fn noFuzzSession(name: []const u8, args: anytype) noreturn {
    @disableInstrumentation();
    std.debug.panic(
        "the fuzz runtime called {s}({any}), which no session in this binary " ++
            "can serve: coverage reaches its counters through -ffuzz, and an " ++
            "artifact wearing this ABI is instrumented rather than fuzzed. " ++
            "The test runner refuses the start message before the fuzzer runs, " ++
            "and a program that is not a test never enters it",
        .{ name, args },
    );
}

/// Runs test `i`, which the runtime chose out of the list it was given.
fn runnerTestRun(i: u32) callconv(.c) void {
    @disableInstrumentation();
    noFuzzSession("runner_test_run", .{i});
}

/// Names test `i` for a person reading a run.
fn runnerTestName(i: u32) callconv(.c) Slice {
    @disableInstrumentation();
    noFuzzSession("runner_test_name", .{i});
}

/// Hands `bytes` to test `test_i` as its next input. Nothing here has a corpus
/// to offer one from.
fn runnerBroadcastInput(test_i: u32, bytes: Slice) callconv(.c) void {
    @disableInstrumentation();
    noFuzzSession("runner_broadcast_input", .{ test_i, bytes.len });
}

/// Starts the poller that feeds inputs in from the build runner's cache.
fn runnerStartInputPoller() callconv(.c) void {
    @disableInstrumentation();
    noFuzzSession("runner_start_input_poller", .{});
}

/// Stops that poller.
fn runnerStopInputPoller() callconv(.c) void {
    @disableInstrumentation();
    noFuzzSession("runner_stop_input_poller", .{});
}

/// Parks on a futex and reports whether it was cancelled. Nothing in an
/// instrumented build waits on one, so the answer is never asked for.
fn runnerFutexWait(ptr: *const u32, value: u32) callconv(.c) bool {
    @disableInstrumentation();
    noFuzzSession("runner_futex_wait", .{ ptr.*, value });
}

/// Wakes `waiters` on a futex.
fn runnerFutexWake(ptr: *const u32, waiters: u32) callconv(.c) void {
    @disableInstrumentation();
    noFuzzSession("runner_futex_wake", .{ ptr.*, waiters });
}

comptime {
    // Strong linkage, which is what `export fn` gave these before, so the
    // runtime's call lands on exactly this definition: a second copy in one
    // binary is a link error rather than two answers.
    @export(&runnerTestRun, .{ .name = "runner_test_run" });
    @export(&runnerTestName, .{ .name = "runner_test_name" });
    @export(&runnerBroadcastInput, .{ .name = "runner_broadcast_input" });
    @export(&runnerStartInputPoller, .{ .name = "runner_start_input_poller" });
    @export(&runnerStopInputPoller, .{ .name = "runner_stop_input_poller" });
    @export(&runnerFutexWait, .{ .name = "runner_futex_wait" });
    @export(&runnerFutexWake, .{ .name = "runner_futex_wake" });
}
