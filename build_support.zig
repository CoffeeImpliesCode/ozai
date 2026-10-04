//! The build rules that are about *how an artifact is built*, kept apart from
//! `build.zig`, which is about *what this project builds*.
//!
//! Six responsibilities live here, and each of them is a rule every artifact
//! of its kind obeys rather than a wrapper around one call:
//!
//! 1. The vendored tree's invariant gate — including the test root that runs
//!    it and the cross-check that its embedded file list still equals the
//!    directory.
//! 2. The wiring every test artifact needs: the `ozai` import, `link_libc`,
//!    and which runner drives it.
//! 3. The executor a test starts its child processes under.
//! 4. The wiring every fuzz artifact needs, including the optimize mode the
//!    fuzzer's error path requires.
//! 5. The runner's own regressions: the fixture executables they need, which
//!    are compiled and never run.
//! 6. Coverage instrumentation, which is a property of a *set* of artifacts
//!    and not of any one of them.
//!
//! This file is at the top of the tree for the reason `build.zig` used to be:
//! `@embedFile` may not leave the package root, and the invariant gate embeds
//! `vendor/quic/src/**`, so the module that runs it has to be rooted at the
//! top. Rooting it at `test/vendored_invariants.zig` instead compiles to an
//! error about an embed path, which says nothing about the invariant that was
//! actually broken.

const std = @import("std");

const vendored_invariants = @import("test/vendored_invariants.zig");

// Runs the gate's own tests. `_ = vendored_invariants` is the same idiom
// `vendor/quic/src/test_all.zig` uses and for the same reason: under lazy
// analysis a test block in a file the compilation never analyses is not a slow
// test, it is no test at all, and the run still exits 0.
test {
    _ = vendored_invariants;
}

/// What every test root here produces: the compile step, which is what
/// `compile-all` and coverage need, and the run step, which is what `test`
/// needs. Both are kept because they are different requests about the same
/// artifact, and a caller wanting both should not have to build it twice.
pub const TestArtifact = struct {
    compile: *std.Build.Step.Compile,
    run: *std.Build.Step.Run,
};

/// The gate's test root, rooted here rather than at `test/vendored_invariants.zig`
/// for the embed reason in this file's header.
pub fn addVendoredInvariants(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) TestArtifact {
    const module = b.createModule(.{
        .root_source_file = b.path("build_support.zig"),
        .target = target,
        .optimize = optimize,
    });
    const artifact = b.addTest(.{ .root_module = module });
    return .{ .compile = artifact, .run = b.addRunArtifact(artifact) };
}

/// One error-level log an artifact provokes on purpose, named in full rather
/// than by severity: a refusal the vendored core reports, which the test that
/// asks for it asserts. The runner prints every such message either way and
/// fails on any other error log, and it fails if a named message stops being
/// said as often as the row said it would be.
///
/// A list rather than one optional row, because an artifact may refuse a
/// certificate *and* a protocol: two distinct claims, each provable only by its
/// own message. And a single message may be the claim more than once — two
/// handshakes refused the same way, each refused once on the side that refuses
/// it, is one sentence said twice rather than two sentences.
///
/// `count` is how many copies this artifact provokes deliberately, and it is a
/// statement of fact rather than a tolerance. It is one or more: a count of
/// zero claims a refusal that never happens, which is no claim, and the runner
/// refuses it. A row naming 2 accounts for the second copy as well as the
/// first and a third copy is one message too many, which is the whole
/// accounting: the number of deliberate refusals is written down here instead
/// of being left to be inferred from how often the runner was asked to
/// tolerate one. A row that says nothing counts once.
///
/// It is also the only way to write down that repetition. Two rows of one scope
/// and message are refused by the runner before any test runs, whatever count
/// either row carried, because one message cannot answer two rows and a count
/// says how many copies arrive rather than which row any of them belongs to.
/// Saying a refusal twice is raising `count` on the one row that names it.
pub const ExpectLog = struct {
    scope: []const u8,
    text: []const u8,
    count: usize = 1,
};

/// The module every test root gets: the library under test, and libc, because
/// the syscall layer is uncompiled until a test opens a socket — see
/// `src/transport/socket.zig`'s module doc. The module is returned rather than
/// finished, so a caller that has options to add (`test/two_process_test.zig`)
/// adds them before the artifact is created.
pub fn createTestModule(
    b: *std.Build,
    lib_mod: *std.Build.Module,
    root: []const u8,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) *std.Build.Module {
    const module = b.createModule(.{
        .root_source_file = b.path(root),
        .target = target,
        .optimize = optimize,
    });
    module.addImport("ozai", lib_mod);
    module.link_libc = true;
    return module;
}

/// Which runner drives an artifact's tests. The choice belongs to the
/// artifact, not to this file: `test/expected_log_runner.zig` exists for the
/// artifacts whose tests provoke an error-level log on purpose, and the
/// generated runner is the right answer everywhere else, where an error log
/// is a finding rather than an expectation.
pub const Runner = enum { generated, expected_log };

/// What one test artifact is: the runner that drives it, and the
/// error-level logs it provokes on purpose.
pub const TestSpec = struct {
    runner: Runner = .expected_log,
    expect_log: []const ExpectLog = &.{},
};

/// The project's own test runner and the run step that executes the artifact.
///
/// `--test-runner` puts `test/expected_log_runner.zig` in the compilation as
/// the thing that runs the tests, so its `std_options` is the one
/// `std.options` reads and the generated runner is not in the picture at all.
pub fn addTestRun(
    b: *std.Build,
    module: *std.Build.Module,
    name: []const u8,
    spec: TestSpec,
) TestArtifact {
    const artifact = b.addTest(.{
        .name = b.fmt("ozai-test-{s}", .{name}),
        .root_module = module,
        .test_runner = switch (spec.runner) {
            .generated => null,
            .expected_log => .{ .path = b.path("test/expected_log_runner.zig"), .mode = .server },
        },
    });
    const run = b.addRunArtifact(artifact);
    for (spec.expect_log) |log| {
        // The count is on the command line only when it is not one, so an
        // artifact that provokes each of its refusals once is wired exactly as
        // it was before a count existed.
        if (log.count == 1) {
            run.addArgs(&.{ "--expect-log", log.scope, log.text });
        } else {
            run.addArgs(&.{
                "--expect-log",
                log.scope,
                log.text,
                b.fmt("{d}", .{log.count}),
            });
        }
    }
    return .{ .compile = artifact, .run = run };
}

/// The executor a test starts its child processes under, or null for the host
/// kernel. A foreign-target test must use the executor its own run step uses:
/// the host need not have binfmt_misc or native foreign execution enabled. The
/// named option wins over the cross profile's environment, which is what
/// `cross-test.profile.sh` sets for a whole run.
pub fn resolveExecutor(b: *std.Build, option_name: []const u8, help: []const u8) ?[]const u8 {
    const environ = b.graph.environ_map;
    const cross = if (std.mem.eql(u8, environ.get("CROSS_TEST_RUNNER_KIND") orelse "", "exec"))
        environ.get("CROSS_TEST_RUNNER")
    else
        null;
    return b.option([]const u8, option_name, help) orelse cross;
}

/// One pair per decoder: a target file and a corpus directory, and nothing
/// else. Later milestones add a sibling of this pair, not a second harness.
pub const FuzzSpec = struct { name: []const u8, file: []const u8 };

/// A fuzz artifact. Zig 0.16 exposes no build-script entry point for the
/// fuzzer: `zig build fuzz --fuzz=N` finds the run steps whose tests called
/// `std.testing.fuzz` and drives them, so the artifact carries no `fuzz` of its
/// own — a binary that already has it crashes outside the fuzzer's driver.
///
/// The optimize mode is pinned off Debug either way, because that rebuild is
/// what meets the toolchain's fuzz error path: it hands `@errorReturnTrace()`
/// to a `std.debug.writeStackTrace` wanting a different `StackTrace`, and only
/// `-ffuzz` analyses it (ziglang/zig#36326). ReleaseSafe is the fastest mode
/// that builds, and it keeps the safety checks a decoder bug trips.
///
/// Both modules are registered because both are the sanctioned consumer routes
/// and nothing forces a root to name both: no `src/` file re-exports the core's
/// `packet`, `frame` or `tls13` types, so a root naming them has to add `quic`
/// itself, and a relative path into `vendor/` would compile a second copy of
/// the core at the fuzz optimize mode.
pub fn addFuzzRun(
    b: *std.Build,
    lib_mod: *std.Build.Module,
    quic_mod: *std.Build.Module,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    spec: FuzzSpec,
) *std.Build.Step.Run {
    const fuzz_optimize: std.builtin.OptimizeMode =
        if (optimize == .Debug) .ReleaseSafe else optimize;
    const module = b.createModule(.{
        .root_source_file = b.path(spec.file),
        .target = target,
        .optimize = fuzz_optimize,
    });
    module.addImport("ozai", lib_mod);
    module.addImport("quic", quic_mod);
    return b.addRunArtifact(b.addTest(.{
        .name = b.fmt("ozai-fuzz-{s}", .{spec.name}),
        .root_module = module,
    }));
}

/// What the runner's verdict regressions produce: the root that drives them,
/// its run step, and the two fixture executables it starts.
pub const Verdict = struct {
    compile: *std.Build.Step.Compile,
    run: *std.Build.Step.Run,
    /// Compiled by `compile-all` and handed to the verdict root as emitted
    /// paths. Never run: every case they hold is a failure the verdict test
    /// expects, and a run step over one would fail the build on the very
    /// refusal it exists to provoke.
    cases: [2]*std.Build.Step.Compile,
};

/// The expected-log runner's own regressions, read from outside the process
/// that reaches them: `test/expected_log_verdict_test.zig` starts each fixture
/// and reads its exit status and its stderr.
///
/// The fixtures wear the runner the verdict root is judging, and each holds
/// exactly one case, so the `run_test` index the root sends is that case and
/// no other. The root itself gets `link_libc` because it spawns those
/// processes and reads their stderr through a pipe.
pub fn addExpectedLogVerdict(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    executor: ?[]const u8,
) Verdict {
    const once_case = addLogCase(b, target, optimize, "once", "expected-log case: one refusal");
    const twice_case = addLogCase(
        b,
        target,
        optimize,
        "twice",
        "expected-log case: the same refusal twice",
    );

    const module = b.createModule(.{
        .root_source_file = b.path("test/expected_log_verdict_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    module.link_libc = true;
    // The emitted paths, not install paths: a child found by name under a
    // prefix another configuration wrote is the stale-binary failure the node
    // test's options module already answers for.
    const options = b.addOptions();
    options.addOptionPath("once_executable", once_case.getEmittedBin());
    options.addOptionPath("twice_executable", twice_case.getEmittedBin());
    options.addOption(?[]const u8, "executor", executor);
    module.addOptions("expected_log_verdict_options", options);

    const artifact = b.addTest(.{
        .name = "ozai-test-expected-log-verdict",
        .root_module = module,
        .test_runner = .{ .path = b.path("test/expected_log_runner.zig"), .mode = .server },
    });
    return .{
        .compile = artifact,
        .run = b.addRunArtifact(artifact),
        .cases = .{ once_case, twice_case },
    };
}

/// One fixture executable holding exactly the named case, selected by
/// `.filters` rather than by splitting the source, so the two cases cannot
/// drift into one artifact and make the `run_test` index ambiguous.
fn addLogCase(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    name: []const u8,
    case_name: []const u8,
) *std.Build.Step.Compile {
    const module = b.createModule(.{
        .root_source_file = b.path("test/expected_log_cases.zig"),
        .target = target,
        .optimize = optimize,
    });
    return b.addTest(.{
        .name = b.fmt("ozai-expected-log-case-{s}", .{name}),
        .root_module = module,
        .filters = &.{case_name},
        .test_runner = .{ .path = b.path("test/expected_log_runner.zig"), .mode = .server },
    });
}

/// Coverage is opt-in because it pins the LLVM backend, links the zig-cov
/// runtime into the artifacts and makes them write a `.zcov` file on exit; none
/// of that belongs in a plain build. It is applied to a *set* of artifacts
/// because the switch has to be uniform across them or a test's node child is
/// left uninstrumented while the test that drives it is not.
pub fn instrumentCoverage(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    artifacts: []const *std.Build.Step.Compile,
    cov_rt: []const u8,
) void {
    // The fuzz runtime's `runner_*` callbacks, which every artifact links once
    // `fuzz` is on and none of them can ever be reached: the test runners among
    // them refuse the start message that is the only way into `fuzzer_main`,
    // and the node is not a test and has no runner to ask. One module owns them
    // all so the answer is written once.
    const abi_module = b.createModule(.{
        .root_source_file = b.path("test/coverage_abi.zig"),
        .target = target,
        .optimize = optimize,
    });
    for (artifacts) |artifact| {
        // The self-hosted backends emit no counters, `fuzz` is the only switch
        // that makes LLVM emit them, and the runtime flushes from a libc atexit
        // handler, so all three settings are load-bearing.
        artifact.use_llvm = true;
        artifact.root_module.fuzz = true;
        artifact.root_module.link_libc = true;
        artifact.root_module.addObjectFile(.{ .cwd_relative = cov_rt });
        // Attached to the root of each of them, so `test/coverage_abi.zig`
        // resolves from the node's own `main` as well as from a runner
        // compiled into a test artifact. A root that does not reach it keeps no
        // import to name and is unaffected outside coverage.
        artifact.root_module.addImport("coverage_abi", abi_module);
    }
}

/// Every `.zig` file under `vendor/quic/src`, relative to that root. Walked
/// here and nowhere else: the gate runs on every `zig build test` and may not
/// read the filesystem, because it audits a tree by embedding it.
fn collectVendoredSources(
    gpa: std.mem.Allocator,
    io: std.Io,
    dir: std.Io.Dir,
    prefix: []const u8,
    out: *std.ArrayList([]const u8),
) !void {
    var entries = dir.iterate();
    while (try entries.next(io)) |entry| {
        if (entry.kind == .directory) {
            var sub = try dir.openDir(io, entry.name, .{ .iterate = true });
            defer sub.close(io);
            try collectVendoredSources(gpa, io, sub, try std.fmt.allocPrint(gpa, "{s}{s}/", .{
                prefix,
                entry.name,
            }), out);
            continue;
        }
        if (!std.mem.endsWith(u8, entry.name, ".zig")) continue;
        try out.append(gpa, try std.fmt.allocPrint(gpa, "{s}{s}", .{ prefix, entry.name }));
    }
}

/// Fails the configure when the gate's file list and the tree disagree, in
/// either direction. `@embedFile` cannot glob, so that list is the gate's
/// entire coverage: a file missing from it is a file nothing reads, and the
/// gate would keep reporting full coverage while proving nothing about it.
///
/// Every refusal is a `std.debug.panic` carrying the specific disagreement
/// rather than a bare `@panic`. `std.Build`'s `build` returns `void` on this
/// toolchain and `std.Build` has no `fatal`, so a configure-time failure has
/// no way to return an error and the panic message is the only channel there
/// is. That makes the message the whole of the improvement available here,
/// and one naming the path that disagrees is all the person fixing it has to
/// go on.
pub fn checkVendoredFileList(b: *std.Build) void {
    const root = "vendor/quic/src";
    const gpa = b.allocator;
    const io = b.graph.io;

    var found: std.ArrayList([]const u8) = .empty;
    defer found.deinit(gpa);
    // The `catch` arm below fails the build and never returns, and the `defer`
    // after it closes the handle on every path that does reach it; the engine
    // does not follow a `defer` to the scope exit it arms.
    // zwanzig-disable-next-line: store-violations-engine
    var dir = b.build_root.handle.openDir(io, root, .{ .iterate = true }) catch |err| {
        std.debug.panic("cannot read {s}: {s}", .{ root, @errorName(err) });
    };
    defer dir.close(io);
    collectVendoredSources(gpa, io, dir, "", &found) catch |err| {
        std.debug.panic("cannot walk {s}: {s}", .{ root, @errorName(err) });
    };

    for (found.items) |relative| {
        const wanted = std.fmt.allocPrint(gpa, "{s}/{s}", .{ root, relative }) catch
            std.debug.panic("out of memory formatting the path of {s}/{s}", .{ root, relative });
        const listed = for (vendored_invariants.vendored_files) |entry| {
            if (std.mem.eql(u8, entry, wanted)) break true;
        } else false;
        if (!listed) {
            std.debug.panic(
                \\
                \\{s}/{s} exists but is not in `vendored_files` in
                \\test/vendored_invariants.zig, so the invariant gate never reads
                \\it. That is the failure this check exists for: a file the gate
                \\does not read is a file nothing is watching, and the gate still
                \\reports full coverage of the tree.
                \\
                \\Add the path to `vendored_files`, in sorted order.
            , .{ root, relative });
        }
    }
    for (vendored_invariants.vendored_files) |entry| {
        const relative = entry[root.len + 1 ..];
        const present = for (found.items) |name| {
            if (std.mem.eql(u8, name, relative)) break true;
        } else false;
        if (!present) {
            std.debug.panic(
                \\
                \\`vendored_files` in test/vendored_invariants.zig lists {s},
                \\which is not in {s}. Delete the entry — or restore the file.
                \\Left alone, @embedFile fails on it with an error that names the
                \\path and none of the reasoning above.
            , .{ entry, root });
        }
    }
}
