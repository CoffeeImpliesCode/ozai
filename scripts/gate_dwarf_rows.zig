//! Pure validation and source-path reconstruction for the pinned DWARF row cache.
const std = @import("std");
const Cache = std.debug.Dwarf.CompileUnit.SrcLocCache;

pub const Row = struct { file_index: usize, line: u32 };

/// Invalid end-sequence entries and line zero make no numeric source claim.
pub fn numericRow(
    version: u16,
    entry: Cache.LineEntry,
    files_count: usize,
) error{InvalidDebugInfo}!?Row {
    if (version < 2 or version > 5) return error.InvalidDebugInfo;
    if (entry.isInvalid()) return null;
    if (entry.line == 0) return null;
    const correction: u32 = if (version < 5) 1 else 0;
    if (entry.file < correction) return error.InvalidDebugInfo;
    const file_index = entry.file - correction;
    if (file_index >= files_count) return error.InvalidDebugInfo;
    return .{ .file_index = file_index, .line = entry.line };
}

pub const SourcePathOptions = struct {
    compilation_directory: []const u8,
    directory: []const u8,
    file: []const u8,
};

/// Returns an owned lexical absolute path, using the actual DW_AT_comp_dir.
/// Relative directories are CU-relative, never project-root-relative.
pub fn sourcePath(
    gpa: std.mem.Allocator,
    options: SourcePathOptions,
) error{ OutOfMemory, InvalidDebugInfo }![]u8 {
    if (!std.fs.path.isAbsolute(options.compilation_directory)) return error.InvalidDebugInfo;
    if (options.file.len == 0) return error.InvalidDebugInfo;
    return std.fs.path.resolve(gpa, &.{
        options.compilation_directory,
        options.directory,
        options.file,
    });
}

/// Both inputs are canonical absolute paths, with no trailing slash except root.
pub fn owns(path: []const u8, project_root: []const u8) bool {
    if (!std.mem.startsWith(u8, path, project_root)) return false;
    if (project_root.len == 1 and project_root[0] == '/') return true;
    if (path.len == project_root.len) return true;
    return path[project_root.len] == '/';
}

test "numeric rows correct DWARF 4 and 5 file indices and reject bad bounds" {
    const row: Cache.LineEntry = .{ .line = 7, .column = 0, .file = 1 };
    try std.testing.expectEqual(@as(usize, 0), (try numericRow(4, row, 2)).?.file_index);
    try std.testing.expectEqual(@as(usize, 1), (try numericRow(5, row, 2)).?.file_index);
    try std.testing.expectError(error.InvalidDebugInfo, numericRow(4, .{
        .line = 7,
        .column = 0,
        .file = 0,
    }, 2));
    try std.testing.expectError(error.InvalidDebugInfo, numericRow(5, row, 1));
    try std.testing.expectError(error.InvalidDebugInfo, numericRow(6, row, 2));
    try std.testing.expectEqual(@as(?Row, null), try numericRow(4, .invalid, 0));
    try std.testing.expectEqual(@as(?Row, null), try numericRow(5, .{
        .line = 0,
        .column = 0,
        .file = 99,
    }, 0));
}

test "source paths use actual compilation directory for relative or empty tables" {
    const gpa = std.testing.allocator;
    const cases = [_]struct {
        directory: []const u8,
        file: []const u8,
        expected: []const u8,
    }{
        .{ .directory = "", .file = "src/entry.zig", .expected = "/project/src/entry.zig" },
        .{ .directory = "src", .file = "entry.zig", .expected = "/project/src/entry.zig" },
        .{ .directory = "/other", .file = "entry.zig", .expected = "/other/entry.zig" },
        .{ .directory = "src", .file = "/other/entry.zig", .expected = "/other/entry.zig" },
        .{ .directory = "src", .file = "../entry.zig", .expected = "/project/entry.zig" },
    };
    for (cases) |case| {
        const path = try sourcePath(gpa, .{
            .compilation_directory = "/project",
            .directory = case.directory,
            .file = case.file,
        });
        defer gpa.free(path);
        try std.testing.expectEqualStrings(case.expected, path);
    }
    try std.testing.expectError(error.InvalidDebugInfo, sourcePath(gpa, .{
        .compilation_directory = "relative",
        .directory = "src",
        .file = "entry.zig",
    }));
    try std.testing.expectError(error.InvalidDebugInfo, sourcePath(gpa, .{
        .compilation_directory = "/project",
        .directory = "src",
        .file = "",
    }));
}

test "canonical project ownership respects component boundaries" {
    try std.testing.expect(owns("/project/src/entry.zig", "/project"));
    try std.testing.expect(owns("/project", "/project"));
    try std.testing.expect(!owns("/project-other/src/entry.zig", "/project"));
    try std.testing.expect(!owns("/other/entry.zig", "/project"));
    try std.testing.expect(owns("/entry.zig", "/"));
}

test "source path allocations propagate failures without retaining temporary storage" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, sourcePathAllocation, .{});
}

fn sourcePathAllocation(gpa: std.mem.Allocator) !void {
    const path = try sourcePath(gpa, .{
        .compilation_directory = "/project",
        .directory = "src",
        .file = "../entry.zig",
    });
    defer gpa.free(path);
    try std.testing.expectEqualStrings("/project/entry.zig", path);
}
