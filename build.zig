const std = @import("std");

/// The build rules that are about *how an artifact is built* — the vendored
/// invariant gate, the test and fuzz artifact wiring, coverage instrumentation
/// — rather than about what this project builds. They were in this file, and
/// the file carried a size it should not; what moved and why is in
/// `build_support.zig`'s header.
const build_support = @import("build_support.zig");

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
    // proving nothing. Two mechanisms there find them and it needs both: an
    // explicit `_ = @import` for every module `lib.zig` does not export — the
    // internal ones and the test-only ones — and a `refAllDecls` sweep over the
    // declarations `lib.zig` does export, which is what reaches a module the
    // list does not name. So not every test-bearing file is a direct import,
    // and none has to be while `lib.zig` exports it. The sweep is declaration
    // reachability, not proof that a test ran: the executed count is the build
    // summary `zig build quic-test` prints.
    const quic_test_mod = b.createModule(.{
        .root_source_file = b.path("vendor/quic/src/test_all.zig"),
        .target = target,
        .optimize = optimize,
    });
    const quic_tests = b.addTest(.{ .root_module = quic_test_mod });
    const run_quic_tests = b.addRunArtifact(quic_tests);
    const quic_step = b.step("quic-test", "Run the vendored QUIC core's own tests");
    quic_step.dependOn(&run_quic_tests.step);

    // The gate reads the vendored tree as text and tokenizes it, so it needs
    // nothing of the library and nothing of the vendored module: a tree under
    // audit must not become a dependency of the audit.
    //
    // `@embedFile` cannot glob, so the gate names every vendored file in a
    // list. Comparing that list against the directory is the only way an
    // addition can be noticed: a file the list omits is a file the gate never
    // reads, and it would go on looking exactly like coverage. That list is
    // the scanner's coverage and nothing more: it says nothing about which
    // files carry test blocks or whether `quic-test` discovers them, which is
    // what the root above is for.
    const invariants = build_support.addVendoredInvariants(b, target, optimize);
    build_support.checkVendoredFileList(b);

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

    // `ozai-interop-peer`: the other end of the wave's external exchange. A
    // program and not an entry under `examples`, for the reason the node is one
    // — it is not a demonstration of something in this repository, it is a
    // process `test/rust_partner/` talks to — and it is installed rather than
    // only run, because the partner is started beside it by a supervisor that
    // has to be able to name the path. Wired like the node for the same reasons:
    // its own module, the `ozai` import, and `link_libc` because
    // `src/transport/socket.zig` reaches libc for `socket`, `sendmsg`,
    // `recvmsg` and `close`. It needs no options module: every byte of the
    // scenario is on its command line, which is where a run's two ends have to
    // be able to differ.
    //
    // It is not in `compile-all` either, and `ozai-node` is the reason: both are
    // programs on the install step, so `zig build` already type-checks them and
    // listing one twice would buy a second report of the same error.
    //
    // It is absent from the coverage list, and for the reason the fuzz targets
    // are: an instrumented copy of this binary is only useful to a run that
    // passes both `-Dcoverage` and the coverage runtime to whatever starts it,
    // and the exchange that starts it is this wave's, not this build's.
    const interop_peer_mod = b.createModule(.{
        .root_source_file = b.path("test/interop_peer.zig"),
        .target = target,
        .optimize = optimize,
    });
    interop_peer_mod.addImport("ozai", lib_mod);
    interop_peer_mod.link_libc = true;
    const interop_peer_exe = b.addExecutable(.{
        .name = "ozai-interop-peer",
        .root_module = interop_peer_mod,
    });
    b.installArtifact(interop_peer_exe);

    // One end of an exchange is not a whole run — the partner is a second
    // process the caller starts beside it — so this step takes the command line
    // it was given and prints the rest of the grammar on `--help`, exactly as
    // the node's run step does.
    const run_interop_peer = b.addRunArtifact(interop_peer_exe);
    run_interop_peer.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_interop_peer.addArgs(args);
    b.step(
        "run-ozai-interop-peer",
        "Run one end of a live interop exchange against the Rust partner",
    ).dependOn(&run_interop_peer.step);

    // testing

    // The unit tests get a root module no other compilation imports: coverage
    // hangs the runtime object off the root module, and a shared `lib_mod` would
    // hand a second copy of it to every link that imports the library. The private
    // root also reaches the extracted Node tests without exporting them.
    const lib_test_mod = b.createModule(.{
        .root_source_file = b.path("src/unit_test.zig"),
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
    // It declares its expectations too, because the two ALPN-withdrawal
    // vectors in `quic_bridge.zig` are handshakes that legitimately end in
    // `no_application_protocol`: one offer leaves only a withdrawn protocol
    // and the other offers a withdrawn one alone. Those are the refusals
    // under test, so they are named here rather than passed over — a refusal
    // arriving once more than this row declares is one message too many, and
    // a row the run does not fill fails as the stale expectation it then is.
    //
    // Counted as two, not two rows: the runner refuses a command line that
    // names one message twice, and a count is how an artifact says the same
    // message arrived twice.
    const unit = build_support.addTestRun(
        b,
        lib_test_mod,
        "unit",
        .{ .expect_log = &.{
            .{
                .scope = "default",
                .text = "TLS 1.3 handshake error: error.NoApplicationProtocol",
                .count = 2,
            },
        } },
    );

    // Socket-free tests, in their own root and their own module, so the scope
    // that has no Linux adapter can be run and reported on its own. Labelled
    // separately from `test` because these are the same tests again, not more
    // of them.
    const portable_test_mod = b.createModule(.{
        .root_source_file = b.path("src/portable_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    portable_test_mod.addImport("quic", quic_mod);
    // The same row the unit root declares above, and for the same reason: this
    // root reaches the same ALPN-withdrawal handshakes in `quic_bridge.zig`,
    // whose two refused offers are the same message said twice. The runner
    // prints every message either way, fails on an error log no row claims, and
    // fails when a copy arrives beyond the count or a row is never filled, so
    // the refusals are named rather than passed over. The generated runner
    // this root wore has no account to give them and fails any binary that
    // logged at error level, which is how two deliberate refusals failed a run
    // whose every test passed.
    const portable = build_support.addTestRun(
        b,
        portable_test_mod,
        "portable",
        .{ .expect_log = &.{
            .{
                .scope = "default",
                .text = "TLS 1.3 handshake error: error.NoApplicationProtocol",
                .count = 2,
            },
        } },
    );
    const portable_step = b.step("test-portable", "Run socket-free protocol and state-machine tests");
    portable_step.dependOn(&portable.run.step);

    // Integration tests live outside `src/` and get their own module: Zig only
    // runs the test blocks a root file reaches, so a test in a library file is
    // vacuous unless the library root imports it.
    const integration = build_support.addTestRun(
        b,
        build_support.createTestModule(b, lib_mod, "test/integration_test.zig", target, optimize),
        "integration",
        // The generated runner, and the only `addTestRun` artifact here that
        // takes it: nothing in this root provokes an error-level log on
        // purpose, so the runner under it would have nothing to account for,
        // and it would put a custom runner in this one step's command line for
        // no verdict. The choice is per artifact because the five artifacts
        // below do provoke one.
        .{ .runner = .generated },
    );

    // The loopback test gets its own module for the same reason, and one more
    // reason of its own: it is the only artifact that runs both halves of the
    // stack against a kernel, so a failure in it is a finding about the stack
    // rather than about a module boundary.
    //
    // It is the artifact that declares the expected logs: the refusals the
    // vendored core reports, one for a certificate it will not accept and one
    // for a protocol it will not speak. Each row is spent by the first message
    // that matches it, so the two are accountable separately and a second copy
    // of either fails the run.
    const loopback = build_support.addTestRun(
        b,
        build_support.createTestModule(b, lib_mod, "test/loopback_test.zig", target, optimize),
        "loopback",
        .{ .expect_log = &.{
            .{
                .scope = "default",
                .text = "TLS 1.3 handshake error: error.BadCertificate",
            },
            .{
                .scope = "default",
                .text = "TLS 1.3 handshake error: error.NoApplicationProtocol",
            },
        } },
    );

    // The first application protocol over a real connection, in its own module
    // for the same reason as the loopback artifact, and with the same
    // `link_libc`: it opens sockets, reaches into `blobs/protocol.zig` and
    // `gossip/`, and its codec borrows `postcard`'s varints rather than
    // inventing a width.
    //
    // It runs under the same custom runner and declares no expectation:
    // nothing in it provokes an error-level log on purpose, so an error log
    // here is a finding rather than an expectation.
    const protocol = build_support.addTestRun(
        b,
        build_support.createTestModule(
            b,
            lib_mod,
            "test/protocol_loopback_test.zig",
            target,
            optimize,
        ),
        "protocol-loopback",
        .{},
    );

    // The first *transfer* over a real connection, in its own module for the
    // same reason as the two artifacts above, and with the same `link_libc`:
    // it opens sockets and reaches into `blobs/protocol.zig`. Its provider half
    // is its own, because the module is a codec and has no server.
    const transfer = build_support.addTestRun(
        b,
        build_support.createTestModule(
            b,
            lib_mod,
            "test/blobs_transfer_test.zig",
            target,
            optimize,
        ),
        "blobs-transfer",
        .{},
    );

    // The first test that puts two nodes in two *processes*, wired like the
    // three above and for the same reason: it opens real sockets and needs
    // `link_libc`. Its isolation is the point of it — one process means one
    // allocator, one cancellation scope and one lifetime, so every path that
    // only bites when two things die independently is never reached — and that
    // is worth a step of its own rather than another `addTest` folded into the
    // ones above.
    const two_process_mod = build_support.createTestModule(
        b,
        lib_mod,
        "test/two_process_test.zig",
        target,
        optimize,
    );
    // An install path can name a stale native or uninstrumented child when a
    // test build uses another prefix, target, or coverage mode. The emitted
    // path and its options dependency select and build that exact child.
    const node_test_options = b.addOptions();
    node_test_options.addOptionPath("node_executable", node_exe.getEmittedBin());
    // A QEMU-run test must use that executor for its children too: the host
    // kernel need not have binfmt_misc or native 32-bit execution enabled. The
    // rule is `build_support`'s because the verdict root below starts children
    // the same way and must resolve the executor the same way.
    const node_executor = build_support.resolveExecutor(
        b,
        "test-node-executor",
        "Executor for foreign node-test children",
    );
    node_test_options.addOption(?[]const u8, "node_executor", node_executor);
    two_process_mod.addOptions("node_test_options", node_test_options);
    const two_process = build_support.addTestRun(b, two_process_mod, "two-process", .{});

    // The relay reached the way a peer reaches one: by a relay URL, over a
    // real socket, against a relay that did not place it. Wired like the four
    // artifacts above and for the same reason — it opens sockets, so it needs
    // `link_libc` — and it runs under the same custom runner with no
    // expectation, because nothing in it provokes an error-level log on
    // purpose and an error log here is a finding about the relay rather than
    // an expectation.
    const relay_wire = build_support.addTestRun(
        b,
        build_support.createTestModule(b, lib_mod, "test/relay_wire_test.zig", target, optimize),
        "relay-wire",
        .{},
    );

    // The per-protocol handlers on the *production* accept loop: a `Node` with
    // its own socket, real peers speaking real QUIC over real UDP, and one
    // handler per configured protocol rather than one handler for all of them.
    // Wired like the artifacts above and for the same reason — it opens
    // sockets, so it needs the `link_libc` `createTestModule` gives every test
    // root.
    //
    // The expected-log count accounts for the three actual handshake refusals
    // exercised by this artifact. They share the same NoApplicationProtocol
    // message, so one counted row accounts for all three; a fourth copy fails
    // the run rather than silently accepting an unexpected refusal.
    // Warnings remain visible on stderr but do not count as error-level rows.
    const runtime_handlers = build_support.addTestRun(
        b,
        build_support.createTestModule(
            b,
            lib_mod,
            "test/runtime_handlers_test.zig",
            target,
            optimize,
        ),
        "runtime-handlers",
        .{ .expect_log = &.{
            .{
                .scope = "default",
                .text = "TLS 1.3 handshake error: error.NoApplicationProtocol",
                .count = 3,
            },
        } },
    );
    b.step("runtime-handlers-test", "Run per-protocol handler and lifetime regressions")
        .dependOn(&runtime_handlers.run.step);

    // The recorded Rust client's first datagram, read the way a server reads
    // one: the long header, the Initial keys its own destination connection id
    // derives, header protection, the payload, and the frames behind it.
    //
    // Its own module for the reason every other root above has one — Zig runs
    // only the test blocks a root reaches — and the `quic` import for the
    // reason `lib_test_mod` carries it: this root names the core's own
    // `packet`, `frame` and `connection_manager`, and a fresh module does not
    // inherit the imports of the module it was split from. The import is added
    // to this module alone; putting it on `lib_mod` would hand the core to
    // every consumer of the library rather than to the one root that names it.
    //
    // It reaches no socket, so the `link_libc` `createTestModule` gives every
    // test root is unused here rather than absent.
    //
    // It drives `t.fuzz`, and the expected-log runner does not export `fuzz`,
    // so this artifact wears the generated runner. That is also the right
    // choice on the merits: this root drives the receive path over recorded
    // and core-built bytes and provokes no error-level log on purpose, so an
    // error log here would be a finding rather than a claim to account for.
    const rust_wire_initial_mod = build_support.createTestModule(
        b,
        lib_mod,
        "test/rust_wire_initial_test.zig",
        target,
        optimize,
    );
    rust_wire_initial_mod.addImport("quic", quic_mod);
    const rust_wire_initial = build_support.addTestRun(
        b,
        rust_wire_initial_mod,
        "rust-wire-initial",
        .{ .runner = .generated },
    );

    // The runner's own regressions, which are the only artifacts here that
    // wear it while judging it: the verdict root starts two fixture
    // executables that hold one intentional-failure case each and reads their
    // exit status. The fixtures are compiled by `compile-all` and are
    // deliberately not run steps — the cases they hold would fail the build —
    // and they stay out of the coverage list for the reason
    // `build_support` records: under `-Dcoverage` the runner's `main` requires
    // a `--cache-dir` the verdict driver does not pass.
    const verdict = build_support.addExpectedLogVerdict(
        b,
        target,
        optimize,
        build_support.resolveExecutor(
            b,
            "test-fixture-executor",
            "Executor for foreign expected-log fixture children",
        ),
    );
    b.step("verdict-test", "Run the expected-log runner's verdict regressions")
        .dependOn(&verdict.run.step);

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
        build_support.instrumentCoverage(b, target, optimize, &.{
            unit.compile,
            integration.compile,
            loopback.compile,
            protocol.compile,
            transfer.compile,
            two_process.compile,
            relay_wire.compile,
            runtime_handlers.compile,
            rust_wire_initial.compile,
            verdict.compile,
            node_exe,
        }, rt);
    }

    const test_step = b.step("test", "Run unit tests and integration tests");
    test_step.dependOn(&unit.run.step);
    test_step.dependOn(&integration.run.step);
    test_step.dependOn(&loopback.run.step);
    test_step.dependOn(&protocol.run.step);
    test_step.dependOn(&transfer.run.step);
    test_step.dependOn(&two_process.run.step);
    test_step.dependOn(&relay_wire.run.step);
    test_step.dependOn(&runtime_handlers.run.step);
    test_step.dependOn(&rust_wire_initial.run.step);
    test_step.dependOn(&verdict.run.step);
    test_step.dependOn(&invariants.run.step);

    // Every root, compiled but not run. It is a group of its own because a
    // type error is worth hearing about before a suite spends minutes
    // producing a thousand results, and because the declaration sweep in each
    // root is only analysis that happens while a root compiles.
    const compile_all = b.step("compile-all", "Compile every test root without running it");
    for ([_]*std.Build.Step.Compile{
        unit.compile,
        quic_tests,
        portable.compile,
        integration.compile,
        loopback.compile,
        protocol.compile,
        transfer.compile,
        two_process.compile,
        relay_wire.compile,
        runtime_handlers.compile,
        rust_wire_initial.compile,
        verdict.compile,
        invariants.compile,
    }) |artifact| compile_all.dependOn(&artifact.step);
    // The two fixture executables are roots of their own: compiled so a type
    // error in either case is heard before a suite runs, never run.
    for (verdict.cases) |fixture| compile_all.dependOn(&fixture.step);

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
    // The artifact is absent from the coverage list above, and that is where the
    // two features collide: coverage turns `fuzz` on as its switch for LLVM
    // counters, so a coverage build of one of these would hand it `-ffuzz`
    // outside the fuzzer's driver, which is the crash the artifact's own
    // construction avoids. Separate artifacts are how that exclusion is
    // expressed.
    const fuzz_targets = [_]build_support.FuzzSpec{
        .{ .name = "base32", .file = "test/base32_fuzz.zig" },
        .{ .name = "range-spec", .file = "test/range_spec_fuzz.zig" },
        .{ .name = "endpoint-ticket", .file = "test/endpoint_ticket_fuzz.zig" },
        .{ .name = "blob-ticket", .file = "test/blob_ticket_fuzz.zig" },
        .{ .name = "pkarr", .file = "test/pkarr_fuzz.zig" },
        .{ .name = "relay-frame", .file = "test/relay_frame_fuzz.zig" },
        .{ .name = "postcard", .file = "test/postcard_fuzz.zig" },
        // Registered under the wave's build-registration contract: the
        // vendored core's wire and TLS families, and the first-party decoders
        // that had no permanent bounded target. `zig build fuzz` needs every
        // root listed here to exist — a table naming a file that is not there
        // is a table whose row proves nothing — so a row is added when its root
        // lands, never before.
        .{ .name = "quic-wire", .file = "test/quic_wire_fuzz.zig" },
        .{ .name = "tls", .file = "test/tls_fuzz.zig" },
        .{ .name = "dns", .file = "test/dns_fuzz.zig" },
        .{ .name = "blobs-protocol", .file = "test/blobs_protocol_fuzz.zig" },
        // The control-message decoder, which had a property and no target to
        // drive it: the Smith oracle is a test root of its own so the corpus
        // runs on every change and the fuzzer mutates the same seeds.
        .{ .name = "ancillary", .file = "test/ancillary_fuzz.zig" },
    };
    const fuzz_step = b.step("fuzz", "Run the decoder fuzz targets, `--fuzz=N` to mutate");
    for (fuzz_targets) |fuzz_target| {
        const run = build_support.addFuzzRun(b, lib_mod, quic_mod, target, optimize, fuzz_target);
        fuzz_step.dependOn(&run.step);
    }

    // docs

    const install_docs = b.addInstallDirectory(.{
        .source_dir = lib.getEmittedDocs(),
        .install_dir = .prefix,
        .install_subdir = "docs",
    });
    b.step("docs", "Install docs into zig-out/docs").dependOn(&install_docs.step);
}
