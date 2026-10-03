const std = @import("std");

/// The gate on what the vendored tree is allowed to reach for, held as a
/// container-scope import rather than a root of its own for one reason:
/// `@embedFile` may not leave the package root, and the package root is the
/// directory of the root source file. The gate lives in `test/` and has to
/// embed `vendor/quic/src/**`, so the module that runs it is rooted here, at the
/// top of the tree, and reaches it through this import. Rooting the module at
/// `test/vendored_invariants.zig` instead compiles to an error about an embed
/// path, which says nothing about the invariant that was actually broken.
const vendored_invariants = @import("test/vendored_invariants.zig");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // ozai is a library first. Every crate in the iroh family is consumed as a
    // dependency, so the public surface is a module importers add; the static
    // artifact exists so a plain `zig build` proves the whole tree type-checks.
    const lib_mod = b.addModule("ozai", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    const lib = b.addLibrary(.{
        .linkage = .static,
        .name = "ozai",
        .root_module = lib_mod,
    });
    b.installArtifact(lib);

    // The QUIC substrate, vendored from endel/quic-zig at the SHA recorded in
    // vendor/quic/VENDORED.md. A separate module, not a folder under src/: it
    // is third-party code carrying its own history, and the patch ozai applies
    // to it is a short list in that file rather than a diff nobody can review.
    // The socket-owning layers were never vendored, so nothing here opens a
    // socket. The comment above used to claim that also meant no `link_libc`;
    // it did not, because `sys.zig` read the clock through `std.c`. The clock
    // is a parameter now and those functions are gone, so the claim holds —
    // and if a future patch reintroduces a `std.c` call, the missing
    // `link_libc` fails the build rather than quietly costing a dependency.
    //
    // The module is declared and then compiled, because a vendored tree that
    // nothing references is a vendored tree nobody has proved still builds.
    const quic_mod = b.addModule("quic", .{
        .root_source_file = b.path("vendor/quic/src/lib.zig"),
        .target = target,
        .optimize = optimize,
    });
    // Both modules are registered consumer routes. The bridge imports the
    // same core module, while consumers add "quic" explicitly when naming
    // the core's types in their own module.
    lib_mod.addImport("quic", quic_mod);

    // The test root is `test_all.zig`, not `lib.zig`. A root that only
    // re-exports discovers zero tests and still exits 0, which is a green step
    // proving nothing; `test_all.zig` names every file carrying test blocks so
    // the vendored suite actually runs.
    const quic_test_mod = b.createModule(.{
        .root_source_file = b.path("vendor/quic/src/test_all.zig"),
        .target = target,
        .optimize = optimize,
    });
    const run_quic_tests = b.addRunArtifact(b.addTest(.{ .root_module = quic_test_mod }));
    const quic_step = b.step("quic-test", "Run the vendored QUIC core's own tests");
    quic_step.dependOn(&run_quic_tests.step);

    // The gate reads the vendored tree as text and tokenizes it, so it needs
    // nothing of the library and nothing of the vendored module: a tree under
    // audit must not become a dependency of the audit.
    const invariants_mod = b.createModule(.{
        .root_source_file = b.path("build.zig"),
        .target = target,
        .optimize = optimize,
    });
    const invariants_tests = b.addTest(.{ .root_module = invariants_mod });
    const run_invariants_tests = b.addRunArtifact(invariants_tests);

    // `@embedFile` cannot glob, so the gate names every vendored file in a
    // list. Comparing that list against the directory is the only way an
    // addition can be noticed: a file the list omits is a file the gate never
    // reads, and it would go on looking exactly like coverage.
    checkVendoredFileList(b);

    // Examples are separate executables, never part of the library: an example
    // that only exists as a doc comment has never been run.
    const examples = [_]struct { name: []const u8, file: []const u8 }{
        .{ .name = "ozai-node-id", .file = "src/examples/node_id.zig" },
    };

    const examples_step = b.step("examples", "Build every example");
    for (examples) |example| {
        const module = b.createModule(.{
            .root_source_file = b.path(example.file),
            .target = target,
            .optimize = optimize,
        });
        module.addImport("ozai", lib_mod);

        const executable = b.addExecutable(.{
            .name = example.name,
            .root_module = module,
        });
        examples_step.dependOn(&b.addInstallArtifact(executable, .{}).step);

        const run = b.addRunArtifact(executable);
        run.step.dependOn(b.getInstallStep());
        if (b.args) |args| run.addArgs(args);
        b.step(
            b.fmt("run-{s}", .{example.name}),
            b.fmt("Run {s}", .{example.name}),
        ).dependOn(&run.step);
    }

    // The first program in the project. A separate module rooted at
    // `src/node/main.zig` and not an entry under `examples`, because it is not
    // an example: it is the thing `src/node/node.zig` exists to make runnable,
    // and an example directory would say it is a demonstration of something
    // else. `link_libc` is here for the reason `socket.zig`'s module doc gives
    // — `socket`, `bind`, `sendmsg`, `recvmsg` and `close` are libc's.
    //
    // It is installed rather than only run, because a binary that can only be
    // reached through the build runner is a binary nobody can put in a
    // supervisor.
    const node_main_mod = b.createModule(.{
        .root_source_file = b.path("src/node/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    node_main_mod.addImport("ozai", lib_mod);
    node_main_mod.link_libc = true;
    const node_exe = b.addExecutable(.{
        .name = "ozai-node",
        .root_module = node_main_mod,
    });
    b.installArtifact(node_exe);

    const run_node = b.addRunArtifact(node_exe);
    run_node.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_node.addArgs(args);
    b.step(
        "run-ozai-node",
        "Run an ozai node until it is stopped",
    ).dependOn(&run_node.step);

    // testing

    // The unit tests get a root module no other compilation imports: coverage
    // hangs the runtime object off the root module, and a shared `lib_mod` would
    // hand a second copy of it to every link that imports the library. The
    // module is otherwise identical, so the unit-test compile is unchanged.
    const lib_test_mod = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    // The test root reaches `quic` through `src/root.zig`, and a fresh module
    // does not inherit the imports of the module it was split from, so the
    // import is repeated rather than reached through `lib_mod`.
    lib_test_mod.addImport("quic", quic_mod);
    // `src/transport/socket.zig` reaches libc for `sendmsg`, `recvmsg` and the
    // socket options. It is here, not on `lib_mod`, because Zig does not
    // analyse a function body until something calls it: while nothing called
    // the socket, no module needed libc and the whole syscall layer sat
    // uncompiled. The first test that opens one is what makes this line
    // necessary, and removing it turns that test into a link error rather than
    // a silent hole. The vendored QUIC core must never need this — it opens no
    // socket — and `test/vendored_invariants.zig` is what keeps that true.
    lib_test_mod.link_libc = true;
    const lib_unit_tests = b.addTest(.{ .root_module = lib_test_mod });
    const run_lib_unit_tests = b.addRunArtifact(lib_unit_tests);

    const portable_test_mod = b.createModule(.{
        .root_source_file = b.path("src/portable_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    portable_test_mod.addImport("quic", quic_mod);
    const run_portable_tests = b.addRunArtifact(b.addTest(.{ .root_module = portable_test_mod }));
    const portable_step = b.step("test-portable", "Run socket-free protocol and state-machine tests");
    portable_step.dependOn(&run_portable_tests.step);

    // Integration tests live outside `src/` and get their own module: Zig only
    // runs the test blocks a root file reaches, so a test in a library file is
    // vacuous unless the library root imports it.
    const integration_mod = b.createModule(.{
        .root_source_file = b.path("test/integration_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    integration_mod.addImport("ozai", lib_mod);
    integration_mod.link_libc = true;
    const integration_tests = b.addTest(.{ .root_module = integration_mod });
    const run_integration_tests = b.addRunArtifact(integration_tests);

    // The loopback test gets its own module for the same reason, and one more
    // reason of its own: it is the only artifact that runs both halves of the
    // stack against a kernel, so a failure in it is a finding about the stack
    // rather than about a module boundary.
    const loopback_mod = b.createModule(.{
        .root_source_file = b.path("test/loopback_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    loopback_mod.addImport("ozai", lib_mod);
    loopback_mod.link_libc = true;

    // It is driven by `test/expected_log_runner.zig` rather than by the runner
    // `zig test` generates, because one of its two tests makes the vendored
    // core refuse a certificate at error level and the generated runner fails
    // any binary that logged one. `--test-runner` puts that file in the
    // compilation as the thing that runs the tests, so its `std_options` is
    // the one `std.options` reads and the generated runner is not in the
    // picture at all.
    const loopback_tests = b.addTest(.{
        .root_module = loopback_mod,
        .test_runner = .{ .path = b.path("test/expected_log_runner.zig"), .mode = .server },
    });
    const run_loopback_tests = b.addRunArtifact(loopback_tests);
    // The one error-level log this artifact provokes on purpose, named in
    // full rather than by severity: the refusal the core reports for a
    // certificate it will not accept, which the wrong-peer test asserts. The
    // runner prints it either way and fails on any other error log, and it
    // fails if this message stops being said at all.
    run_loopback_tests.addArgs(&.{
        "--expect-log",
        "default",
        "TLS 1.3 handshake error: error.BadCertificate",
    });

    // The first application protocol over a real connection, in its own module
    // for the same reason as the loopback artifact, and with the same
    // `link_libc`: it opens sockets, reaches into `blobs/protocol.zig` and
    // `gossip/`, and its codec borrows `postcard`'s varints rather than
    // inventing a width.
    //
    // It runs under the same custom runner, and declares no `--expect-log`:
    // nothing in it provokes an error-level log on purpose, so an error log
    // here is a finding rather than an expectation. The runner is what turns
    // that finding into a failed run, and the generated runner would have
    // failed the artifact for the same reason.
    const protocol_mod = b.createModule(.{
        .root_source_file = b.path("test/protocol_loopback_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    protocol_mod.addImport("ozai", lib_mod);
    protocol_mod.link_libc = true;
    const protocol_tests = b.addTest(.{
        .root_module = protocol_mod,
        .test_runner = .{ .path = b.path("test/expected_log_runner.zig"), .mode = .server },
    });
    const run_protocol_tests = b.addRunArtifact(protocol_tests);

    // The first *transfer* over a real connection, in its own module for the
    // same reason as the two artifacts above, and with the same `link_libc`:
    // it opens sockets and reaches into `blobs/protocol.zig`. Its provider half
    // is its own, because the module is a codec and has no server.
    //
    // It runs under the same custom runner and declares no `--expect-log`:
    // nothing in it provokes an error-level log on purpose, so an error log
    // here is a finding rather than an expectation.
    const transfer_mod = b.createModule(.{
        .root_source_file = b.path("test/blobs_transfer_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    transfer_mod.addImport("ozai", lib_mod);
    transfer_mod.link_libc = true;
    const transfer_tests = b.addTest(.{
        .root_module = transfer_mod,
        .test_runner = .{ .path = b.path("test/expected_log_runner.zig"), .mode = .server },
    });
    const run_transfer_tests = b.addRunArtifact(transfer_tests);

    // The first test that puts two nodes in two *processes*, wired like the
    // three above and for the same reason: it opens real sockets and needs
    // `link_libc`. Its isolation is the point of it — one process means one
    // allocator, one cancellation scope and one lifetime, so every path that
    // only bites when two things die independently is never reached — and that
    // is worth a step of its own rather than another `addTest` folded into the
    // ones above.
    const two_process_mod = b.createModule(.{
        .root_source_file = b.path("test/two_process_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    two_process_mod.addImport("ozai", lib_mod);
    two_process_mod.link_libc = true;
    // An install path can name a stale native or uninstrumented child when a
    // test build uses another prefix, target, or coverage mode. The emitted
    // path and its options dependency select and build that exact child.
    const node_test_options = b.addOptions();
    node_test_options.addOptionPath("node_executable", node_exe.getEmittedBin());
    // A QEMU-run test must use that executor for its children too: the host
    // kernel need not have binfmt_misc or native 32-bit execution enabled.
    const cross_executor = if (std.mem.eql(
        u8,
        b.graph.environ_map.get("CROSS_TEST_RUNNER_KIND") orelse "",
        "exec",
    )) b.graph.environ_map.get("CROSS_TEST_RUNNER") else null;
    const node_executor = b.option(
        []const u8,
        "test-node-executor",
        "Executor for foreign node-test children",
    ) orelse cross_executor;
    node_test_options.addOption(?[]const u8, "node_executor", node_executor);
    two_process_mod.addOptions("node_test_options", node_test_options);
    const two_process_tests = b.addTest(.{
        .root_module = two_process_mod,
        .test_runner = .{ .path = b.path("test/expected_log_runner.zig"), .mode = .server },
    });
    const run_two_process_tests = b.addRunArtifact(two_process_tests);

    // The relay reached the way a peer reaches one: by a relay URL, over a
    // real socket, against a relay that did not place it. Wired like the four
    // artifacts above and for the same reason — it opens sockets, so it needs
    // `link_libc` — and it runs under the same custom runner with no
    // `--expect-log`, because nothing in it provokes an error-level log on
    // purpose and an error log here is a finding about the relay rather than
    // an expectation.
    const relay_wire_mod = b.createModule(.{
        .root_source_file = b.path("test/relay_wire_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    relay_wire_mod.addImport("ozai", lib_mod);
    relay_wire_mod.link_libc = true;
    const relay_wire_tests = b.addTest(.{
        .root_module = relay_wire_mod,
        .test_runner = .{ .path = b.path("test/expected_log_runner.zig"), .mode = .server },
    });
    const run_relay_wire_tests = b.addRunArtifact(relay_wire_tests);

    // Coverage instrumentation is opt-in because it pins the LLVM backend,
    // links the zig-cov runtime into the artifacts, and makes them write a
    // `.zcov` file on exit; none of that belongs in a plain build.
    // Process tests drive the node child. Instrument that same compile too —
    // it is the artifact the options module above hands them, not a second
    // copy of it — or those tests leave the CLI, signal readiness, and live
    // snapshots unmeasured.
    const coverage = b.option(
        bool,
        "coverage",
        "Instrument tests and their node child",
    ) orelse false;
    const coverage_rt = b.option([]const u8, "coverage-rt", "Path to zig-cov-rt.o");
    if (coverage) {
        const rt = coverage_rt orelse std.debug.panic(
            "-Dcoverage=true also needs -Dcoverage-rt=<path to zig-cov-rt.o>. " ++
                "Run coverage through `zig-cov test`, which passes both.",
            .{},
        );

        // The fuzz runtime's `runner_*` callbacks, which every artifact below
        // links once `fuzz` is on and none of them can ever be reached: the
        // test runners among them refuse the start message that is the only
        // way into `fuzzer_main`, and the node is not a test and has no runner
        // to ask. One module owns all seven so the answer is written once.
        const coverage_abi_mod = b.createModule(.{
            .root_source_file = b.path("test/coverage_abi.zig"),
            .target = target,
            .optimize = optimize,
        });
        for ([_]*std.Build.Step.Compile{
            lib_unit_tests,
            integration_tests,
            loopback_tests,
            protocol_tests,
            transfer_tests,
            two_process_tests,
            relay_wire_tests,
            node_exe,
        }) |artifact| {
            // The self-hosted backends emit no counters, `fuzz` is the only
            // switch that makes LLVM emit them, and the runtime flushes from a
            // libc atexit handler, so all three settings are load-bearing.
            artifact.use_llvm = true;
            artifact.root_module.fuzz = true;
            artifact.root_module.link_libc = true;
            artifact.root_module.addObjectFile(.{ .cwd_relative = rt });
            // Attached to the root of each of them, so `test/coverage_abi.zig`
            // resolves from the node's own `main` as well as from a runner
            // compiled into a test artifact. A root that does not reach it
            // keeps no import to name and is unaffected outside coverage.
            artifact.root_module.addImport("coverage_abi", coverage_abi_mod);
        }
    }

    const test_step = b.step("test", "Run unit tests and integration tests");
    test_step.dependOn(&run_lib_unit_tests.step);
    test_step.dependOn(&run_integration_tests.step);
    test_step.dependOn(&run_loopback_tests.step);
    test_step.dependOn(&run_protocol_tests.step);
    test_step.dependOn(&run_transfer_tests.step);
    test_step.dependOn(&run_two_process_tests.step);
    test_step.dependOn(&run_relay_wire_tests.step);
    test_step.dependOn(&run_invariants_tests.step);

    // fuzzing
    //
    // Zig 0.16 exposes no build-script entry point for the fuzzer. The build
    // runner reads `--fuzz[=N]` from its own command line, records which of the
    // tests a run step owns called `std.testing.fuzz`, then rebuilds those run
    // steps with `-ffuzz` and drives them. This step is what puts a run step on
    // that path; the runner's flag is what bounds the run, and a bare
    // `zig build fuzz` replays the seed corpus and stops, which is the form a
    // commit gate can afford on every change.
    //
    // The artifact therefore carries no `fuzz = true` of its own: the rebuild
    // adds `-ffuzz`, and a binary that already has it crashes when a fuzz test
    // runs outside the fuzzer's own driver, which is exactly what a bare
    // `zig build fuzz` is. The optimize mode is still pinned off Debug,
    // because that rebuild is what meets the toolchain's fuzz error path: it
    // hands `@errorReturnTrace()` to a `std.debug.writeStackTrace` wanting a
    // different StackTrace, and only `-ffuzz` analyses it
    // (ziglang/zig#36326). ReleaseSafe is the fastest mode that builds, and it
    // keeps the safety checks a decoder bug trips.
    //
    // The artifact is also absent from the coverage list above, and that is
    // where the two features collide: coverage turns `fuzz` on as its switch
    // for LLVM counters, so a coverage build of this artifact would hand it
    // `-ffuzz` outside the fuzzer's driver, which is the crash above. Separate
    // artifacts are how that exclusion is expressed.
    const fuzz_optimize: std.builtin.OptimizeMode =
        if (optimize == .Debug) .ReleaseSafe else optimize;
    // One pair per decoder: a target file and a corpus directory, and nothing
    // else. Later milestones add a sibling of this pair, not a second harness.
    const fuzz_targets = [_]struct { name: []const u8, file: []const u8 }{
        .{ .name = "base32", .file = "test/base32_fuzz.zig" },
        .{ .name = "range-spec", .file = "test/range_spec_fuzz.zig" },
        .{ .name = "endpoint-ticket", .file = "test/endpoint_ticket_fuzz.zig" },
        .{ .name = "blob-ticket", .file = "test/blob_ticket_fuzz.zig" },
        .{ .name = "pkarr", .file = "test/pkarr_fuzz.zig" },
        .{ .name = "relay-frame", .file = "test/relay_frame_fuzz.zig" },
        .{ .name = "postcard", .file = "test/postcard_fuzz.zig" },
    };
    const fuzz_step = b.step("fuzz", "Run the decoder fuzz targets, `--fuzz=N` to mutate");
    for (fuzz_targets) |fuzz_target| {
        const fuzz_mod = b.createModule(.{
            .root_source_file = b.path(fuzz_target.file),
            .target = target,
            .optimize = fuzz_optimize,
        });
        fuzz_mod.addImport("ozai", lib_mod);
        fuzz_step.dependOn(&b.addRunArtifact(b.addTest(.{
            .name = b.fmt("ozai-fuzz-{s}", .{fuzz_target.name}),
            .root_module = fuzz_mod,
        })).step);
    }

    // docs

    const install_docs = b.addInstallDirectory(.{
        .source_dir = lib.getEmittedDocs(),
        .install_dir = .prefix,
        .install_subdir = "docs",
    });
    b.step("docs", "Install docs into zig-out/docs").dependOn(&install_docs.step);
}

// Runs the gate's own tests. Reaching it from a root at the top of the tree is
// the reason for the import at the top of this file; `_ = vendored_invariants`
// is the same idiom `vendor/quic/src/test_all.zig` uses and for the same
// reason. Under lazy analysis a test block in a file the compilation never
// analyses is not a slow test, it is no test at all, and the run still exits 0.
test {
    _ = vendored_invariants;
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
    var it = dir.iterate();
    while (try it.next(io)) |entry| {
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
fn checkVendoredFileList(b: *std.Build) void {
    const root = "vendor/quic/src";
    const gpa = b.allocator;
    const io = b.graph.io;

    var found: std.ArrayList([]const u8) = .empty;
    defer found.deinit(gpa);
    var dir = b.build_root.handle.openDir(io, root, .{ .iterate = true }) catch |err| {
        std.debug.panic("cannot read {s}: {s}", .{ root, @errorName(err) });
    };
    defer dir.close(io);
    collectVendoredSources(gpa, io, dir, "", &found) catch |err| {
        std.debug.panic("cannot walk {s}: {s}", .{ root, @errorName(err) });
    };

    for (found.items) |relative| {
        const wanted = std.fmt.allocPrint(gpa, "{s}/{s}", .{ root, relative }) catch @panic("oom");
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
