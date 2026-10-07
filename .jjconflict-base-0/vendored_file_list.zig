//! The configure-time half of the gate on the vendored QUIC core: walk
//! `vendor/quic/src` and refuse to configure when the walk and the list in
//! `test/vendored_invariants.zig` disagree in either direction.
//!
//! # Why this file sits at the package root
//!
//! `@embedFile` may not leave the package root, and the package root is the
//! directory of the root source file — `build.zig`, at the top of the tree.
//! `test/vendored_invariants.zig` has to embed `vendor/quic/src/**`, so it can
//! only be compiled by a module rooted at the top of the tree. That is why
//! `build.zig` reaches it as a container-scope import instead of declaring it
//! a root of its own, and why this file is beside `build.zig` and not under
//! `src/`: it is still that same module, so the embed path still resolves, and
//! the module `zig build test` runs is still the one that compiles it.
//!
//! # What is here and what is not
//!
//! This half reads the directory, once, on the configure path, before anything
//! is compiled. The scan that reads the vendored tree's *text* is
//! `test/vendored_invariants.zig`, and the two together are the whole gate:
//! this file is what notices a file the scan never reads, and the scan is what
//! notices a rule the file broke.

const std = @import("std");
const vendored_invariants = @import("test/vendored_invariants.zig");

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
pub fn checkVendoredFileList(b: *std.Build) void {
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
