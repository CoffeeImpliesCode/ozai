const std = @import("std");

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
    const lib_unit_tests = b.addTest(.{ .root_module = lib_test_mod });
    const run_lib_unit_tests = b.addRunArtifact(lib_unit_tests);

    // Integration tests live outside `src/` and get their own module: Zig only
    // runs the test blocks a root file reaches, so a test in a library file is
    // vacuous unless the library root imports it.
    const integration_mod = b.createModule(.{
        .root_source_file = b.path("test/integration_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    integration_mod.addImport("ozai", lib_mod);
    const integration_tests = b.addTest(.{ .root_module = integration_mod });
    const run_integration_tests = b.addRunArtifact(integration_tests);

    // Coverage instrumentation is opt-in because it pins the LLVM backend,
    // links the zig-cov runtime into the test binary, and makes that binary
    // write a `.zcov` file on exit; none of that belongs in a plain build.
    // `zig-cov test` turns it on by passing both options below. Both test
    // artifacts are instrumented because they reach different code, and an
    // uninstrumented one under-reports in silence rather than failing.
    const coverage = b.option(bool, "coverage", "Instrument the test binaries") orelse false;
    const coverage_rt = b.option([]const u8, "coverage-rt", "Path to zig-cov-rt.o");
    if (coverage) {
        const rt = coverage_rt orelse std.debug.panic(
            "-Dcoverage=true also needs -Dcoverage-rt=<path to zig-cov-rt.o>. " ++
                "Run coverage through `zig-cov test`, which passes both.",
            .{},
        );
        for ([_]*std.Build.Step.Compile{ lib_unit_tests, integration_tests }) |artifact| {
            // The self-hosted backends emit no counters, `fuzz` is the only
            // switch that makes LLVM emit them, and the runtime flushes from a
            // libc atexit handler, so all three settings are load-bearing.
            artifact.use_llvm = true;
            artifact.root_module.fuzz = true;
            artifact.root_module.link_libc = true;
            artifact.root_module.addObjectFile(.{ .cwd_relative = rt });
        }
    }

    const test_step = b.step("test", "Run unit tests and integration tests");
    test_step.dependOn(&run_lib_unit_tests.step);
    test_step.dependOn(&run_integration_tests.step);

    // docs

    const install_docs = b.addInstallDirectory(.{
        .source_dir = lib.getEmittedDocs(),
        .install_dir = .prefix,
        .install_subdir = "docs",
    });
    b.step("docs", "Install docs into zig-out/docs").dependOn(&install_docs.step);
}
