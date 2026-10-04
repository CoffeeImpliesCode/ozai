//! A test runner for an artifact that makes the code under test log an error on
//! purpose, and a supported way to keep such an artifact in `zig build test`.
//!
//! # Why the generated runner cannot do this
//!
//! `zig test` compiles `lib/compiler/test_runner.zig` as the *root* of the
//! compilation, and `std.options` is read off the root — `lib/std/std.zig`
//! says `if (@hasDecl(root, "std_options")) root.std_options`. A `std_options`
//! in the file under test is therefore never consulted: the runner's own is,
//! and its `log` counts every message at error level into `log_err_count`,
//! which it reports per test and `std.Build.Step.Run` turns into a step error.
//!
//! `b.addTest` takes `.test_runner`, and that is what changes the fact.
//! `--test-runner <path>` compiles the named file as the thing that runs the
//! tests and as the root `std` resolves `std_options` against, so the
//! declaration below is the one that counts and the generated runner is not
//! in the compilation at all.
//!
//! # What this does not do
//!
//! It does not stop the log, does not demote it, and does not touch the
//! assertion that provoked it. Every message is printed at the level the code
//! under test chose, in the form the default runner printed it. Only the
//! accounting changes, and only for a message the build named on the command
//! line:
//!
//!     --expect-log <scope> <text>
//!
//! An expectation is a scope and the whole rendered message, compared whole.
//! Not a severity and not a substring: another TLS failure, the same refusal
//! arriving from the other end, or an error from anywhere else in the stack is
//! counted and fails the run exactly as it would have without this runner.
//!
//! An expectation is spent by the first message that matches it and by no
//! other: the same refusal arriving a second time is one message too many, and
//! it fails the run as an error nothing accounted for. A command line that
//! names one expectation twice is refused before any test runs, because one
//! message cannot answer two rows and nothing in the run could then say which
//! of them it answered.
//!
//! An expectation nothing matched fails the run too, once every test has
//! reported and the build asks the runner to stop. That is what keeps the list
//! from rotting quietly: if the vendored core changes how it words a refusal,
//! the new wording is counted as an error and the `--expect-log` in `build.zig`
//! has to be re-read rather than left alone.
//!
//! The tests are the ones the root module reaches. `zig test` still generates
//! `builtin.test_functions` for the whole compilation, and the module's own
//! root file is left alone: naming this file as the root module's source as
//! well is an error — `file exists in modules 'root' and 'root'` — because
//! `--test-runner` puts the file into the root module rather than replacing
//! what is in it.
//!
//! # Coverage
//!
//! Coverage reaches LLVM's counters through the `fuzz` switch, so an
//! instrumented build of an artifact wearing this runner links the fuzz
//! runtime with nothing driving it. That runtime calls back through seven
//! `runner_*` exports, and they are defined once in `test/coverage_abi.zig`
//! rather than in a copy here: `build.zig` hands that module to every
//! artifact on its coverage list, this runner's among them, and the `comptime`
//! block below is what brings it into this compilation.
//!
//! Every one of those seven refuses rather than answering, because
//! `mainServer` refuses the start message that is the only way into
//! `fuzzer_main`. `src/node/main.zig` wears the same module for the same
//! reason and has no runner of its own to refuse anything.

const std = @import("std");
const builtin = @import("builtin");
const coverage_abi = @import("coverage_abi");

const Io = std.Io;
const testing = std.testing;

pub const std_options: std.Options = .{ .logFn = log };

/// One tolerated message: the scope it was logged under and the message as it
/// renders. Both are compared whole, and `seen` records that this expectation
/// has been spent — that one message has claimed it — so a second copy of that
/// message finds nothing left to claim.
const Expected = struct {
    scope: []const u8,
    text: []const u8,
    seen: bool = false,
};

/// The arenas the runner itself runs on. `std.testing`'s own allocator is per
/// test and belongs to the code under test, not to the harness around it.
var fba_buffer: [8192]u8 = undefined;
var fba: std.heap.FixedBufferAllocator = .init(&fba_buffer);

var stdin_buffer: [4096]u8 = undefined;
var stdout_buffer: [4096]u8 = undefined;
var stdin_reader: Io.File.Reader = undefined;
var stdout_writer: Io.File.Writer = undefined;

/// Where the runner's own pipes go: the same Io the default runner uses, and
/// the one `std.debug` writes through, so a log line and a protocol message
/// interleave the way they always have.
const runner_io: Io = Io.Threaded.global_single_threaded.io();

/// What this run tolerates, and the error-level messages the test now running
/// logged that nothing accounted for.
var expected: std.ArrayList(Expected) = .empty;
var unexpected: usize = 0;

/// Whether any test has reported an error-level message nothing accounted for.
///
/// `unexpected` counts the test now running and is reset for the next one, so
/// the run as a whole cannot be judged by whatever the last test happened to
/// leave in it. `finish` answers this instead, and for the reason its own doc
/// gives.
var unaccounted: bool = false;

// Only coverage attaches this module; leave its import lazy in a plain build.
comptime {
    if (builtin.fuzz) _ = coverage_abi;
}

/// The whole process. Errors travel out rather than through `std.debug.panic`
/// so that a failure here is a refusal the entry point names and exits 1 on,
/// not an abort that reads as a crash of the code under test.
pub fn main(init: std.process.Init.Minimal) !void {
    @disableInstrumentation();
    const gpa = fba.allocator();
    const args = try init.args.toSlice(gpa);

    var opt_cache_dir: ?[]const u8 = null;
    var index: usize = 1;
    while (index < args.len) {
        const arg = args[index];
        index += 1;
        if (std.mem.eql(u8, arg, "--expect-log")) {
            if (index + 1 >= args.len) std.debug.panic(
                "--expect-log takes a scope and a message, and was given neither",
                .{},
            );
            if (namedAlready(args[index], args[index + 1])) refuse(
                "--expect-log names the same expectation twice, and one message " ++
                    "cannot answer two rows:\n  --expect-log {s} {s}",
                .{ args[index], args[index + 1] },
            );
            try expected.append(gpa, .{
                .scope = args[index],
                .text = args[index + 1],
            });
            index += 2;
        } else if (std.mem.startsWith(u8, arg, "--seed=")) {
            testing.random_seed = std.fmt.parseUnsigned(u32, arg["--seed=".len..], 0) catch
                @panic("unable to parse --seed command line argument");
        } else if (std.mem.startsWith(u8, arg, "--cache-dir=")) {
            opt_cache_dir = arg["--cache-dir=".len..];
        } else if (std.mem.eql(u8, arg, "--listen=-")) {
            // The only mode there is. `std.Build.addRunArtifact` puts every
            // test artifact in server mode, and this runner speaks it.
        } else {
            std.debug.panic("unrecognized command line argument: {s}", .{arg});
        }
    }

    if (builtin.fuzz) {
        // Coverage reaches LLVM counters through the `fuzz` switch, so an
        // instrumented build of an artifact wearing this runner links the fuzz
        // runtime with nothing driving it, and the runtime has to be told
        // where the cache is before anything else runs.
        const cache_dir = opt_cache_dir orelse @panic("missing --cache-dir=[path] argument");
        std.Build.abi.fuzz.fuzzer_init(.fromSlice(cache_dir));
    }

    try mainServer(init);
}

/// Serve one `run_test` per test, over the protocol `std.Build.Step.Run` drives
/// a test artifact with.
fn mainServer(init: std.process.Init.Minimal) !void {
    stdin_reader = .initStreaming(.stdin(), runner_io, &stdin_buffer);
    stdout_writer = .initStreaming(.stdout(), runner_io, &stdout_buffer);
    var server = try std.zig.Server.init(.{
        .in = &stdin_reader.interface,
        .out = &stdout_writer.interface,
        .zig_version = builtin.zig_version_string,
    });

    while (true) {
        const header = try server.receiveMessage();
        switch (header.tag) {
            .exit => return finish(),
            .query_test_metadata => try queryMetadata(&server),
            .run_test => try runTest(&server, init),
            .start_fuzzing => std.debug.panic(
                "this runner reports a fixed list of tests and cannot drive the fuzzer; " ++
                    "an artifact wearing it has no fuzz test",
                .{},
            ),
            else => {
                std.debug.print("unsupported message: {x}\n", .{@intFromEnum(header.tag)});
                std.process.exit(1);
            },
        }
    }
}

/// Tell the build which tests exist and what they are called. This message is
/// the whole of discovery: the build counts its tests from it, and a
/// compilation that reaches no test block answers it with an empty list and
/// still exits 0.
fn queryMetadata(server: *std.zig.Server) !void {
    testing.allocator_instance = .{};
    defer if (testing.allocator_instance.deinit() == .leak) {
        @panic("internal test runner memory leak");
    };

    var string_bytes: std.ArrayList(u8) = .empty;
    defer string_bytes.deinit(testing.allocator);
    try string_bytes.append(testing.allocator, 0); // Reserve 0 for null.

    const test_fns = builtin.test_functions;
    const names = try testing.allocator.alloc(u32, test_fns.len);
    defer testing.allocator.free(names);
    const expected_panic_msgs = try testing.allocator.alloc(u32, test_fns.len);
    defer testing.allocator.free(expected_panic_msgs);

    for (test_fns, names, expected_panic_msgs) |test_fn, *name, *expected_panic_msg| {
        // Narrow where the offset is written, not where the table grows: the
        // ABI spells a name offset as a `u32` and the table it indexes is a
        // `usize`, so a bare `@intCast` traps in Debug on the one table it
        // cannot describe and wraps in a build that checks nothing. The
        // message header spells that same length as a `u32`, so a table this
        // refuses is one no arm could serve.
        const offset: u32 = std.math.cast(u32, string_bytes.items.len) orelse
            return error.NameTableTooWide;
        name.* = offset;
        try string_bytes.ensureUnusedCapacity(testing.allocator, test_fn.name.len + 1);
        string_bytes.appendSliceAssumeCapacity(test_fn.name);
        string_bytes.appendAssumeCapacity(0);
        expected_panic_msg.* = 0;
    }

    try server.serveTestMetadata(.{
        .names = names,
        .expected_panic_msgs = expected_panic_msgs,
        .string_bytes = string_bytes.items,
    });
}

/// Run the one test the build asked for and report what it did: whether it
/// passed, what it leaked, and how many error-level logs nothing accounted
/// for. The last is the only number this runner computes differently, and it is
/// what keeps the rest of the suite able to notice a real one.
fn runTest(server: *std.zig.Server, init: std.process.Init.Minimal) !void {
    testing.environ = init.environ;
    testing.allocator_instance = .{};
    testing.io_instance = .init(testing.allocator, .{
        .argv0 = .init(init.args),
        .environ = init.environ,
    });
    unexpected = 0;
    const index = try server.receiveBody_u32();
    const test_fn = builtin.test_functions[index];
    // The build times a test from this acknowledgement, not from when it
    // asked, because asking happens while the machine may be busy elsewhere.
    try server.serveStringMessage(.test_started, &.{});

    const TestResults = std.zig.Server.Message.TestResults;
    const status: TestResults.Status = if (test_fn.func()) |v| s: {
        v;
        break :s .pass;
    } else |err| switch (err) {
        error.SkipZigTest => .skip,
        else => s: {
            if (@errorReturnTrace()) |trace| std.debug.dumpErrorReturnTrace(trace);
            break :s .fail;
        },
    };
    testing.io_instance.deinit();
    const leak_count = testing.allocator_instance.detectLeaks();
    testing.allocator_instance.deinitWithoutLeakChecks();

    try server.serveTestResults(.{
        .index = index,
        .flags = .{
            .status = status,
            // Nothing here can call `std.testing.fuzz`: the fuzz protocol is
            // answered by refusing it, above.
            .fuzz = false,
            // Refuse a count the wire cannot spell rather than reporting a
            // wrapped one. Both fields are narrower than a `usize`, and
            // `log_err_count` is the number that fails the run: a wrapped one
            // is a gate that stops failing in silence.
            .log_err_count = std.math.cast(
                @FieldType(TestResults.Flags, "log_err_count"),
                unexpected,
            ) orelse return error.LogCountTooWide,
            .leak_count = std.math.cast(
                @FieldType(TestResults.Flags, "leak_count"),
                leak_count,
            ) orelse return error.LeakCountTooWide,
        },
    });
}

/// End the run, and exit non-zero if it did not go as the command line said.
///
/// The build reads a runner's exit code here and nowhere else: it fails a run
/// whose child closed stdout on a term other than `exited 0`, so this is the
/// one place a list of expectations can be checked as a whole rather than one
/// message at a time. Two whole-run facts are checked here, and both are also
/// reported per test: an expectation nothing met, and an error-level message
/// nothing accounted for — a message no expectation had left to claim, which
/// is what a second copy of an expected refusal is.
fn finish() noreturn {
    for (expected.items) |want| {
        if (!want.seen) {
            std.debug.print(
                "\nthis run expected an error log no test produced, so nothing it\n" ++
                    "tolerated happened and the expectation is stale:\n" ++
                    "  [{s}] (err): {s}\n",
                .{ want.scope, want.text },
            );
            std.process.exit(1);
        }
    }
    if (unaccounted) {
        std.debug.print(
            "\nthis run logged an error message no expectation had left to claim, so\n" ++
                "something was said that this run does not account for. Every message\n" ++
                "is printed above at the level it was logged at.\n",
            .{},
        );
        std.process.exit(1);
    }
    std.process.exit(0);
}

/// Whether `level` is one this runner prints. `Level` runs `err`, `warn`,
/// `info`, `debug`, so this admits the three up to and including `warn` and
/// drops `debug` alone. It is a fixed threshold rather than
/// `std.testing.log_level`, and it cannot hide anything that counts: `err` is
/// the lowest of the four, so no threshold could drop one.
fn wanted(comptime level: std.log.Level) bool {
    return @intFromEnum(level) <= @intFromEnum(std.log.Level.warn);
}

/// What a message too long for the render buffer is printed as. It is a thing
/// to print and never a thing to compare against; `log` states why.
const unrenderable = "a message this runner could not render, and so cannot account for";

/// The `std_options.logFn`, and the whole of what this runner changes about
/// how a test binary treats error logs.
///
/// The message is rendered once, into a buffer rather than straight to the
/// stream, because that is the only way to know whether it is one the build
/// named. Rendering is the same as `std.log.defaultLog`'s, and the line is
/// printed either way: a tolerance decides whether a message is also a
/// failure, never whether it is a message.
fn log(
    comptime level: std.log.Level,
    comptime scope: @EnumLiteral(),
    comptime format: []const u8,
    args: anytype,
) void {
    @disableInstrumentation();
    if (!wanted(level)) return;

    // A fixed buffer, because a test runner does not allocate on the logging
    // path. Its size decides how much of a long message an operator gets to
    // read, and not whether the run fails: one that does not fit is counted
    // whatever the build named, never tolerated. `std.heap.DebugAllocator`'s
    // leak report is over a kilobyte with its traces, so it is the reachable
    // message that lands here.
    var room: [1024]u8 = undefined;
    const rendered = std.fmt.bufPrint(&room, format, args) catch null;
    const text = rendered orelse unrenderable;
    // A message this runner could not render is one it cannot account for, so
    // it is counted whatever the build named. `unrenderable` is a thing to
    // print and never a thing to compare against: a build that expected that
    // exact sentence would otherwise tolerate a message nobody read.
    if (level == .err and (rendered == null or !accounted(@tagName(scope), text))) {
        unexpected += 1;
        unaccounted = true;
    }

    std.debug.print("[{s}] ({s}): {s}\n", .{ @tagName(scope), @tagName(level), text });
}

/// Whether `text` is a message the build named, spending the one expectation it
/// matches.
///
/// The first match and only the first. An expectation is a claim that one
/// refusal happens once, and a second copy of the same message under the same
/// scope is one message too many: marking every row again would let the same
/// refusal answer as many times as it arrived, and a runner that tolerates a
/// message however often it is said tolerates it not at all.
fn accounted(scope: []const u8, text: []const u8) bool {
    for (expected.items) |*want| {
        if (want.seen) continue;
        if (std.mem.eql(u8, want.scope, scope) and std.mem.eql(u8, want.text, text)) {
            want.seen = true;
            return true;
        }
    }
    return false;
}

/// Whether this command line has already named this exact expectation.
///
/// Two rows that say one thing would both be met by one message, and the run
/// could not say which of them that message answered, so the second row is
/// refused here rather than left to decide it later.
fn namedAlready(scope: []const u8, text: []const u8) bool {
    for (expected.items) |want| {
        if (std.mem.eql(u8, want.scope, scope) and std.mem.eql(u8, want.text, text)) return true;
    }
    return false;
}

/// Refuse a command line this runner will not run, naming it and stopping.
///
/// Not a `std.debug.panic`: that aborts, and an abort reads as a crash of the
/// code under test rather than as a refusal of its own arguments. This exits 1
/// with the reason on stderr, which is what a command line asking for one
/// message to be tolerated twice is.
fn refuse(comptime reason: []const u8, args: anytype) noreturn {
    std.debug.print("this runner refuses to run: " ++ reason ++ "\n", args);
    std.process.exit(1);
}
