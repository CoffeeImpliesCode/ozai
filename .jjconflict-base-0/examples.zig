//! The example executables, the `examples` step that installs them, and one
//! `run-<name>` step for each.
//!
//! An example is its own module with `ozai` added to it by name, and its own
//! executable, and it is never part of the library: an example that only exists
//! as a doc comment has never been run, and one folded into the library is a
//! public API surface nobody chose. Each row of the table below is therefore a
//! whole example — its root source file, its executable name, the install that
//! reaches it and the step that runs it — so adding one is a row and not
//! another block.

const std = @import("std");

pub fn addExamples(
    b: *std.Build,
    lib_mod: *std.Build.Module,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) void {
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
}
