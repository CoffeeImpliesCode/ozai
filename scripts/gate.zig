//! The repository's verification driver. `devenv shell -- gate` runs this file.
//!
//! It exists because the wrapper the house rules name (`zig-gate`) resolves its
//! toolchain through the anyzig shim, which on this host re-downloads the
//! pinned release and exits 1 in silence, so the recorded audit reached every
//! check by invoking the pinned compiler directly. This driver installs
//! nothing, replaces nothing and re-resolves nothing: the compiler is data
//! (`--zig PATH`, else `OZAIGATE_ZIG`), its reported version is cross-checked
//! against `.minimum_zig_version`, and the file it resolved to is what the
//! receipt names and hashes.
//!
//! `zig run scripts/gate.zig -- [--zig PATH] [--group NAME]... [--fuzz-runs N]
//!     [--scratch DIR] [--receipts PATH] [--prefix DIR] [--list]`
//!
//! `--scratch` names the approved local scratch root, and `--prefix` and
//! `--receipts` are honoured only inside it: a build that lands in the source
//! repository, on a network mount or in a system temporary is the one thing
//! this gate has to refuse before it starts, so `scripts/gate_paths.zig` checks
//! all of it before a child is spawned.
//!
//! Every group runs unless it was not asked for, and a run reports every group
//! rather than stopping at the first failure, because the receipt is the
//! evidence. Both safety modes run explicitly and are labelled separately:
//! `test` is the package suite plus the vendored core, `portable` is the
//! socket-free root that overlaps `test` and is not additive to it, and `fuzz`
//! is bounded by `--fuzz-runs`.
//!
//! Exit status is the verdict, and there is no argument that turns it: 0 when
//! every required step ran and passed, 1 when one did not, 2 when the run was
//! refused before it started. A tool that is absent is recorded
//! `not_available` and one with no configured invocation is recorded
//! `not_configured`; neither is ever reported as a pass. An absent tool fails
//! the gate when it is required, and is simply absent — recorded, not passed —
//! when it is optional.

const std = @import("std");
const paths = @import("gate_paths.zig");
const receipts = @import("gate_receipts.zig");
const runner = @import("gate_run.zig");
const scope = @import("gate_scope.zig");
const steps = @import("gate_steps.zig");
const zbc = @import("gate_zbc.zig");

const Options = struct {
    zig: []const u8 = "zig",
    zig_explicit: bool = false,
    chosen: []const []const u8 = &.{},
    scratch: ?[]const u8 = null,
    prefix: ?[]const u8 = null,
    receipts: ?[]const u8 = null,
    fuzz_runs: u32 = 10_000,
    list: bool = false,

    fn parse(gpa: std.mem.Allocator, args: []const [:0]const u8) !Options {
        var self: Options = .{};
        var chosen: std.ArrayList([]const u8) = .empty;
        var index: usize = 1;
        while (index < args.len) : (index += 1) {
            const arg = args[index];
            if (std.mem.eql(u8, arg, "--list")) {
                self.list = true;
                continue;
            }
            if (index + 1 >= args.len) return error.InvalidArgument;
            const value = args[index + 1];
            index += 1;
            if (std.mem.eql(u8, arg, "--zig")) {
                self.zig = value;
                self.zig_explicit = true;
            } else if (std.mem.eql(u8, arg, "--group")) {
                try chosen.append(gpa, value);
            } else if (std.mem.eql(u8, arg, "--scratch")) {
                self.scratch = value;
            } else if (std.mem.eql(u8, arg, "--receipts")) {
                self.receipts = value;
            } else if (std.mem.eql(u8, arg, "--prefix")) {
                self.prefix = value;
            } else if (std.mem.eql(u8, arg, "--fuzz-runs")) {
                // A zero bound is no run at all, so it is refused rather than
                // reported as a fuzz pass.
                self.fuzz_runs = std.fmt.parseUnsigned(u32, value, 10) catch
                    return error.InvalidArgument;
                if (self.fuzz_runs == 0) return error.InvalidArgument;
            } else {
                return error.InvalidArgument;
            }
        }
        for (chosen.items) |group| {
            if (!isGroup(group)) return error.InvalidArgument;
        }
        self.chosen = chosen.items;
        return self;
    }
};

fn isGroup(name: []const u8) bool {
    for (steps.groups) |group| {
        if (std.mem.eql(u8, group, name)) return true;
    }
    return false;
}

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const gpa = init.arena.allocator();
    var out_buffer: [4096]u8 = undefined;
    var out = std.Io.File.stdout().writerStreaming(io, &out_buffer);
    const text = &out.interface;

    var code: u8 = 0;
    if (drive(gpa, io, &init.minimal.args, init.environ_map, text)) |status| {
        code = status;
    } else |err| {
        try text.print("gate: {t}\n", .{err});
        code = 2;
    }
    // A receipt nobody can read is not a receipt: a failed flush is as fatal as
    // a failed write, and neither is swallowed.
    try out.flush();
    return code;
}

fn drive(
    gpa: std.mem.Allocator,
    io: std.Io,
    args: *const std.process.Args,
    environ: *std.process.Environ.Map,
    text: *std.Io.Writer,
) !u8 {
    var options = Options.parse(gpa, try args.toSlice(gpa)) catch |err| {
        try text.print("gate: {t}; --list names the groups\n", .{err});
        return 2;
    };
    if (options.list) {
        for (steps.groups) |group| try text.print("{s}\n", .{group});
        return 0;
    }
    if (!options.zig_explicit) {
        if (environ.get("OZAIGATE_ZIG")) |from_environment| {
            options.zig = from_environment;
        }
    }

    const layout = switch (try paths.plan(
        gpa,
        io,
        options.scratch,
        options.prefix,
        options.receipts,
        environ,
    )) {
        .ok => |ok| ok,
        .refused => |refusal| {
            try text.print("gate: {s}: {s}\n", .{ refusal.subject, refusal.reason });
            return 2;
        },
    };

    // Closed by the `defer` on the next line when the walk below finishes and
    // when a `try` after it unwinds, so the handle is released on every path;
    // the engine does not follow a `defer` to the scope exit it arms.
    // zwanzig-disable-next-line: store-violations-engine
    var source_dir = try std.Io.Dir.cwd().openDir(io, ".", .{ .iterate = true });
    defer source_dir.close(io);
    const sources = scope.Scope.collect(gpa, io, source_dir) catch |err| {
        try text.print("gate: cannot enumerate the source tree: {t}\n", .{err});
        return 2;
    };

    var results: std.ArrayList(steps.Result) = .empty;
    var verdict: ?zbc.Verdict = null;
    // An unresolved compiler leaves the gate failed rather than untried: every
    // result below it would have been produced by a toolchain this repository
    // does not claim. It still reaches the receipt, because "which compiler
    // answered" is part of what a reader needs even when the answer is no.
    var failed = true;
    var compiler: ?scope.Compiler = null;
    if (try selectCompiler(gpa, io, options.zig, environ.get("PATH"), &results, text)) |selected| {
        compiler = selected;
        failed = try runner.runGroups(gpa, io, .{
            .prefix = layout.prefix,
            .fuzz_runs = options.fuzz_runs,
            .groups = options.chosen,
        }, environ, selected, sources, &results, &verdict, text);
    }

    receipts.write(gpa, io, .{
        .layout = layout,
        .fuzz_runs = options.fuzz_runs,
        .compiler = compiler,
        .sources = sources,
        .results = results.items,
        .zbc_verdict = verdict,
        .environment = try describeEnvironment(gpa, environ),
        .path = environ.get("PATH") orelse "",
    }) catch |err| {
        try text.print("gate: cannot write the receipt {s}: {t}\n", .{ layout.receipts, err });
        return 2;
    };
    try text.print("gate: {d} recorded steps over {d} source files, receipt {s}: {s}\n", .{
        results.items.len, sources.all.len, layout.receipts, if (failed) "FAILED" else "passed",
    });
    return @intFromBool(failed);
}

/// The pinned compiler, recorded as the first result of every run. Null means
/// the selected compiler is not the pinned one, which fails the gate outright.
fn selectCompiler(
    gpa: std.mem.Allocator,
    io: std.Io,
    requested: []const u8,
    search: ?[]const u8,
    results: *std.ArrayList(steps.Result),
    text: *std.Io.Writer,
) !?scope.Compiler {
    const compiler = preflight(gpa, io, requested, search, text) catch |err| {
        try results.append(gpa, .{
            .label = "compiler",
            .argv = &.{},
            .status = .fail,
            .requirement = .required,
            .detail = @errorName(err),
        });
        return null;
    };
    try results.append(gpa, .{
        .label = "compiler",
        .argv = try gpa.dupe([]const u8, &.{ compiler.path, "version" }),
        .exit_code = 0,
        .status = .pass,
        .requirement = .required,
        .detail = try std.fmt.allocPrint(gpa, "{s} {s}, pin {s}", .{
            compiler.path, compiler.version, compiler.pin,
        }),
    });
    return compiler;
}

fn preflight(
    gpa: std.mem.Allocator,
    io: std.Io,
    requested: []const u8,
    search: ?[]const u8,
    text: *std.Io.Writer,
) !scope.Compiler {
    const path = scope.resolveOnPath(gpa, io, requested, search) catch |err| {
        try text.print(
            "gate: cannot resolve compiler {s} ({t}); pass --zig PATH or set OZAIGATE_ZIG\n",
            .{ requested, err },
        );
        return error.CompilerNotFound;
    };
    const bin_dir = std.Io.Dir.path.dirname(path) orelse {
        try text.print("gate: {s} has no parent directory to find lib/ in\n", .{path});
        return error.CompilerIsNotAFile;
    };
    const pin = try scope.minimumZigVersion(gpa, io);
    const version = scope.readVersion(gpa, io, path) catch |err| {
        try text.print(
            "gate: {s} did not report a version ({t}). The anyzig shim exits 1 in\n" ++
                "      silence when it cannot extract a toolchain, so select the pinned\n" ++
                "      compiler explicitly with --zig or OZAIGATE_ZIG.\n",
            .{ path, err },
        );
        return error.CompilerUnresolved;
    };
    if (!std.mem.eql(u8, version, pin)) {
        try text.print(
            "gate: zig {s} does not match .minimum_zig_version {s}\n",
            .{ version, pin },
        );
        return error.CompilerDoesNotMatchPin;
    }
    return .{
        .requested = requested,
        .path = path,
        .bin_dir = bin_dir,
        .lib_dir = try std.fmt.allocPrint(gpa, "{s}/lib", .{bin_dir}),
        .version = version,
        .pin = pin,
    };
}

fn describeEnvironment(
    gpa: std.mem.Allocator,
    environ: *std.process.Environ.Map,
) ![]const receipts.Env {
    var described: std.ArrayList(receipts.Env) = .empty;
    for (paths.recorded_variables) |name| try described.append(gpa, .{
        .name = name,
        .value = environ.get(name) orelse "",
    });
    return described.items;
}
