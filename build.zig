const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // ozai is a library first. Every crate in the iroh family is consumed as a
    // dependency, so the public surface is a module that importers add, and
    // the static artifact exists only so a plain `zig build` proves the whole
    // tree type-checks.
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
    const examples = b.addOptions();
    examples.addOptionPath("example_dir", "src/examples");

    const example_step = b.step("examples", "Build every example");
    for ([_][]const u8{
        "echo",
    }) |name| {
        const mod = b.createModule(.{
            .root_source_file = b.path(b.fmt("src/examples/{s}.zig", .{name})),
            .target = target,
            .optimize = optimize,
        });
        mod.addImport("ozai", lib_mod);
        const exe = b.addExecutable(.{
            .name = b.fmt("ozai-{s}", .{name}),
            .root_module = mod,
        });
        const install = b.addInstallArtifact(exe, .{});
        example_step.dependOn(&install.step);

        const run_cmd = b.addRunArtifact(exe);
        run_cmd.step.dependOn(b.getInstallStep());
        if (b.args) |args| run_cmd.addArgs(args);
        b.step(b.fmt("run-{s}", .{name}), b.fmt("Run the {s} example", .{name})).dependOn(&run_cmd.step);
    }

    // testing

    const lib_unit_tests = b.addTest(.{ .root_module = lib_mod });
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
