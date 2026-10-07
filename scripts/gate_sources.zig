const std = @import("std");
const files = @import("gate_files.zig");
const Allocator = std.mem.Allocator;
const Dir = std.Io.Dir;

pub const Source = struct { path: []const u8, sha256: []const u8 };
const entry_limit = 1_000_000;

fn skippedDirectory(name: []const u8) bool {
    const skipped = [_][]const u8{
        ".git", ".jj", ".devenv", ".direnv", ".zig-cache", "zig-cache",
        "zig-global-cache", "zig-out", "zig-pkg", "target", "node_modules",
    };
    for (skipped) |skip| {
        if (std.mem.eql(u8, name, skip)) return true;
    }
    return false;
}

fn relevant(path: []const u8) bool {
    const suffixes = [_][]const u8{
        ".zig", ".zon", ".nix", ".json", ".toml", ".lock", ".rs", ".c", ".h", ".sh",
    };
    for (suffixes) |suffix| {
        if (std.mem.endsWith(u8, path, suffix)) return true;
    }
    return false;
}

pub fn sources(gpa: Allocator, io: std.Io) ![]Source {
    var directory = try Dir.cwd().openDir(io, ".", .{ .iterate = true });
    defer directory.close(io);
    var walker = try directory.walkSelectively(gpa);
    defer walker.deinit();
    var list: std.ArrayList(Source) = .empty;
    errdefer {
        for (list.items) |source| {
            gpa.free(source.path);
            gpa.free(source.sha256);
        }
        list.deinit(gpa);
    }
    for (0..entry_limit) |_| {
        const entry = try walker.next(io) orelse break;
        if (entry.kind == .directory) {
            if (!skippedDirectory(entry.basename) and !std.mem.eql(u8, entry.path, "docs"))
                try walker.enter(io, entry);
        } else if (entry.kind == .sym_link and relevant(entry.path)) {
            return error.SourceSymlink;
        } else if (entry.kind == .file and relevant(entry.path)) {
            const path = try gpa.dupe(u8, entry.path);
            errdefer gpa.free(path);
            const digest = try files.hashFile(gpa, io, entry.path, false);
            errdefer gpa.free(digest);
            try list.append(gpa, .{ .path = path, .sha256 = digest });
        }
    } else return error.SourceInventoryTooLarge;
    std.mem.sort(Source, list.items, {}, less);
    if (list.items.len == 0) return error.MissingSources;
    return list.toOwnedSlice(gpa);
}

fn less(_: void, a: Source, b: Source) bool {
    return std.mem.lessThan(u8, a.path, b.path);
}

pub fn sourceDigest(gpa: Allocator, inventory: []const Source) ![]const u8 {
    const encoded = try std.json.Stringify.valueAlloc(gpa, inventory, .{});
    defer gpa.free(encoded);
    return files.hashBytes(gpa, encoded);
}

test "configuration and tooling participate in source freshness" {
    try std.testing.expect(relevant("devenv.nix"));
    try std.testing.expect(relevant("scripts/project_gate.zig"));
    try std.testing.expect(relevant("build.zig.zon"));
    try std.testing.expect(!relevant("docs/COVERAGE-LEDGER.md"));
    try std.testing.expect(skippedDirectory("zig-pkg"));
}
