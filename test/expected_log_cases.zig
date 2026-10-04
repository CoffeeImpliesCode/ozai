//! The two fixture executables `test/expected_log_verdict_test.zig` starts.
//!
//! `build.zig` compiles one test block below into each executable through
//! `.filters`, so each holds exactly one test and `run_test` index 0 is that
//! test. Neither is a run step: the scenarios that must fail would fail the
//! build. Nothing here decides anything — the code under test is the runner's
//! accounting, and a fixture's whole job is to produce a message for it to
//! account or refuse.

const std = @import("std");

const refusal_log = std.log.scoped(.expected_log_case);

test "expected-log case: one refusal" {
    refusal_log.err("expected-log case refused peer {d} of {d}", .{ 7, 9 });
}

test "expected-log case: the same refusal twice" {
    refusal_log.err("expected-log case refused peer {d} of {d}", .{ 7, 9 });
    refusal_log.err("expected-log case refused peer {d} of {d}", .{ 7, 9 });
}
