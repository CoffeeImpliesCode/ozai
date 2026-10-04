//! One receipt per run: what ran, with which compiler, over which exact file
//! list, hashed.
//!
//! A gate whose evidence cannot be replayed is a gate whose green means only
//! that it ran. So the receipt carries the resolved compiler, the digest of
//! every external tool that produced a result, the digests of the configuration
//! files, the per-file digests of the exact scope, the environment the children
//! inherited, and every command with its argv, exit status and recorded status.
//!
//! The disposition table the static-analysis verdict was decided against is not
//! duplicated here: it is a source file, so its digest is already in `sources`,
//! and a receipt that carried a second copy of it could disagree with the copy
//! that actually decided.

const std = @import("std");
const paths = @import("gate_paths.zig");
const scope = @import("gate_scope.zig");
const steps = @import("gate_steps.zig");
const zbc = @import("gate_zbc.zig");

/// Configuration that decides the result and is not a source file. The Zig
/// sources are hashed by the source list; these are not in it.
pub const config_files = [_][]const u8{ "build.zig.zon", "devenv.nix", "zlint.json" };

pub const Env = struct { name: []const u8, value: []const u8 };

pub const Report = struct {
    layout: paths.Layout,
    fuzz_runs: u32,
    compiler: ?scope.Compiler,
    sources: scope.Scope,
    results: []const steps.Result,
    zbc_verdict: ?zbc.Verdict,
    environment: []const Env,
    /// The PATH the tools were resolved through, so a tool digest in this
    /// receipt names the file that answered on this host and not merely the
    /// name it was invoked by.
    path: []const u8,
};

pub fn write(gpa: std.mem.Allocator, io: std.Io, report: Report) !void {
    var body: std.Io.Writer.Allocating = .init(gpa);
    defer body.deinit();
    const out = &body.writer;
    const cwd = std.Io.Dir.cwd();

    try out.writeAll("{\n  \"gate\": \"scripts/gate.zig\",\n  \"compiler\": ");
    try compilerJson(out, report.compiler);
    try out.writeAll(",\n  \"scratch\": ");
    try jsonString(out, report.layout.scratch);
    try out.writeAll(",\n  \"prefix\": ");
    try jsonString(out, report.layout.prefix);
    try out.writeAll(",\n  \"receipts\": ");
    try jsonString(out, report.layout.receipts);
    try out.print(",\n  \"mount_types_checked\": {s}", .{
        if (report.layout.mount_types_checked) "true" else "false",
    });
    try out.print(",\n  \"jobs\": {d}", .{steps.job_limit});
    try out.print(",\n  \"fuzz_runs\": {d}", .{report.fuzz_runs});
    try out.writeAll(",\n  \"modes\": [");
    for (steps.modes, 0..) |mode, index| {
        try out.print("{s}\"{s}\"", .{ if (index == 0) "" else ", ", mode });
    }
    try out.writeAll("],\n  \"environment\": {");
    for (report.environment, 0..) |entry, index| {
        try out.print("{s}\n    ", .{if (index == 0) "" else ","});
        try jsonString(out, entry.name);
        try out.writeAll(": ");
        try jsonString(out, entry.value);
    }
    try out.writeAll("\n  },\n  \"tools\": [");
    for (try toolDigests(gpa, io, report), 0..) |tool, index| {
        try out.print("{s}\n    {{\"name\": ", .{if (index == 0) "" else ","});
        try jsonString(out, tool.name);
        try out.writeAll(", \"path\": ");
        try jsonString(out, tool.path);
        try out.writeAll(", \"sha256\": ");
        if (tool.sha256) |digest| {
            try out.print("\"{s}\"", .{digest});
        } else {
            try out.writeAll("null");
        }
        try out.writeAll(", \"detail\": ");
        try jsonString(out, tool.detail);
        try out.writeAll("}");
    }
    try out.writeAll("\n  ],\n  \"config\": [");
    for (config_files, 0..) |config, index| {
        const bytes = try cwd.readFileAlloc(io, config, gpa, .limited(1 << 20));
        try out.print("{s}\n    {{\"path\": \"{s}\", \"sha256\": \"{s}\"}}", .{
            if (index == 0) "" else ", ", config, scope.sha256Hex(bytes),
        });
    }
    try out.writeAll("\n  ],\n  \"sources\": [");
    for (report.sources.hashes, 0..) |source, index| {
        try out.print("{s}\n    {{\"path\": ", .{if (index == 0) "" else ","});
        try jsonString(out, source.path);
        try out.print(", \"sha256\": \"{s}\"}}", .{source.sha256});
    }
    try out.writeAll("\n  ],\n  \"zbc\": ");
    try zbcJson(out, report.zbc_verdict);
    try out.writeAll(",\n  \"steps\": [");
    for (report.results, 0..) |result, index| {
        try out.print("{s}\n    {{\"label\": ", .{if (index == 0) "" else ","});
        try jsonString(out, result.label);
        try out.print(", \"status\": \"{s}\"", .{@tagName(result.status)});
        try out.print(", \"requirement\": \"{s}\"", .{@tagName(result.requirement)});
        if (result.exit_code) |code| try out.print(", \"exit_code\": {d}", .{code});
        try out.writeAll(", \"argv\": [");
        for (result.argv, 0..) |argument, position| {
            try out.print("{s}", .{if (position == 0) "" else ", "});
            try jsonString(out, argument);
        }
        try out.writeAll("], \"detail\": ");
        try jsonString(out, result.detail);
        try out.writeAll("}");
    }
    try out.writeAll("\n  ]\n}\n");

    if (std.Io.Dir.path.dirname(report.layout.receipts)) |parent|
        try cwd.createDirPath(io, parent);
    try cwd.writeFile(io, .{ .sub_path = report.layout.receipts, .data = body.written() });
}

/// An external tool this run used: the name it was invoked by, the file that
/// answered, and that file's digest.
pub const Tool = struct {
    name: []const u8,
    path: []const u8,
    sha256: ?[64]u8,
    /// Why there is no digest. A tool that ran and cannot be read back is
    /// still a tool that ran, so the entry is kept and the reason is named.
    detail: []const u8 = "",
};

/// The tools this run used. A tool that could not be started appears in its
/// own result as `not_available` instead — a label that is not a pass.
fn toolDigests(gpa: std.mem.Allocator, io: std.Io, report: Report) ![]const Tool {
    var tools: std.ArrayList(Tool) = .empty;
    for (report.results) |result| {
        if (result.argv.len == 0 or result.status == .not_available) continue;
        const name = result.argv[0];
        const seen = for (tools.items) |tool| {
            if (std.mem.eql(u8, tool.name, name)) break true;
        } else false;
        if (seen) continue;
        try tools.append(gpa, try describeTool(gpa, io, name, report));
    }
    return tools.items;
}

/// The name a command was invoked by is resolved the same way the shell would
/// have resolved it — through the PATH this run inherited — so the digest is
/// the file that answered rather than a failed guess at a bare name.
fn describeTool(gpa: std.mem.Allocator, io: std.Io, name: []const u8, report: Report) !Tool {
    const is_compiler = if (report.compiler) |compiler|
        std.mem.eql(u8, compiler.path, name)
    else
        false;
    const path = if (is_compiler) name else scope.resolveOnPath(gpa, io, name, report.path) catch |err| {
        return .{ .name = name, .path = name, .sha256 = null, .detail = @errorName(err) };
    };
    const hashed = scope.hashFile(io, std.Io.Dir.cwd(), path) catch |err| {
        return .{ .name = name, .path = path, .sha256 = null, .detail = @errorName(err) };
    };
    return .{ .name = name, .path = hashed.path, .sha256 = hashed.sha256 };
}

fn compilerJson(out: *std.Io.Writer, compiler: ?scope.Compiler) !void {
    if (compiler == null) {
        try out.writeAll("null");
        return;
    }
    try out.writeAll("{\"requested\": ");
    try jsonString(out, compiler.?.requested);
    try out.writeAll(", \"path\": ");
    try jsonString(out, compiler.?.path);
    try out.writeAll(", \"version\": ");
    try jsonString(out, compiler.?.version);
    try out.writeAll(", \"pin\": ");
    try jsonString(out, compiler.?.pin);
    try out.writeAll(", \"lib_dir\": ");
    try jsonString(out, compiler.?.lib_dir);
    try out.writeAll("}");
}

fn zbcJson(out: *std.Io.Writer, verdict: ?zbc.Verdict) !void {
    if (verdict == null) {
        try out.writeAll("null");
        return;
    }
    try out.print(
        "{{\"findings\": {d}, \"accepted\": {d}, \"stale_dispositions\": {d}, " ++
            "\"raw_exit\": {d}, \"unresolved_imports\": {d}, \"summary\": ",
        .{
            verdict.?.findings,
            verdict.?.accepted,
            verdict.?.stale,
            verdict.?.raw_exit,
            verdict.?.unresolved_imports,
        },
    );
    try jsonString(out, verdict.?.summary);
    try out.writeAll(", \"rejected\": [");
    for (verdict.?.rejected, 0..) |match, index| {
        try out.print("{s}\n      {{\"key\": ", .{if (index == 0) "" else ","});
        try jsonString(out, match.key);
        try out.print(", \"rejection\": \"{s}\", \"detail\": ", .{@tagName(match.rejection)});
        try jsonString(out, match.detail);
        try out.writeAll("}");
    }
    try out.writeAll("]}");
}

fn jsonString(out: *std.Io.Writer, text: []const u8) !void {
    try out.writeByte('"');
    for (text) |byte| {
        switch (byte) {
            '"', '\\' => {
                try out.writeByte('\\');
                try out.writeByte(byte);
            },
            '\n' => try out.writeAll("\\n"),
            else => try out.writeByte(byte),
        }
    }
    try out.writeByte('"');
}
