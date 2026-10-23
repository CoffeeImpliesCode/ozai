//! Seeds the full numeric DWARF universe without assigning hits or resolving PCs.
//! The caller has already validated the binary artifact and its full DWARF sections.
const std = @import("std");
const builtin = @import("builtin");
const projection = @import("gate_projection.zig");
const rows = @import("gate_dwarf_rows.zig");
const Dwarf = std.debug.Dwarf;
const DieAttribute = std.meta.Child(@FieldType(Dwarf.Die, "attrs"));
const FileEntry = std.meta.Child(@FieldType(Dwarf.CompileUnit.SrcLocCache, "files"));

/// Borrowed absolute paths; the binary must be a verified native full-DWARF artifact.
pub const Options = struct {
    binary_path: []const u8,
    project_root: []const u8,
};

pub const Error = std.debug.Info.LoadError || std.Io.Dir.OpenError || error{
    PartialMapping,
    EvidenceLimitExceeded,
};

const metadata_entries_max = 16 * 1024 * 1024;

/// Declares every valid positive numeric project row cold, preserving existing hits.
/// Temporary mappings, debug caches and reconstructed paths are released before return.
/// Only `paths` and `builder` retain data, owned through `gpa`; errors are fail-closed,
/// so a caller must discard the partial audit rather than publish a partial universe.
pub fn collect(
    gpa: std.mem.Allocator,
    io: std.Io,
    options: Options,
    paths: *projection.Paths,
    builder: *projection.Builder,
) Error!void {
    if (builtin.os.tag != .linux or builtin.object_format != .elf or
        builtin.cpu.arch != .x86_64) return error.UnsupportedDebugInfo;
    if (!std.fs.path.isAbsolute(options.binary_path) or
        !std.fs.path.isAbsolute(options.project_root)) return error.PartialMapping;

    // The arena also reclaims intermediate allocations on failed std cache construction.
    var temporary = std.heap.ArenaAllocator.init(gpa);
    defer temporary.deinit();
    const scratch = temporary.allocator();
    const project_root = try std.fs.path.resolve(scratch, &.{options.project_root});
    var coverage: std.debug.Coverage = .init;
    defer coverage.deinit(scratch);
    const binary_directory = std.fs.path.dirname(options.binary_path) orelse
        return error.PartialMapping;
    const directory = try std.Io.Dir.openDirAbsolute(io, binary_directory, .{});
    defer directory.close(io);
    var info = try std.debug.Info.load(scratch, io, .{
        .root_dir = .{ .handle = directory, .path = binary_directory },
        .sub_path = std.fs.path.basename(options.binary_path),
    }, &coverage, builtin.object_format, builtin.cpu.arch);
    defer info.deinit(scratch);

    const elf = switch (info.impl) {
        .elf => |*file| file,
        else => return error.UnsupportedDebugInfo,
    };
    const dwarf = if (elf.dwarf) |*value| value else return error.MissingDebugInfo;
    if (dwarf.compile_unit_list.items.len == 0) return error.MissingDebugInfo;
    if (dwarf.compile_unit_list.items.len > metadata_entries_max)
        return error.EvidenceLimitExceeded;

    for (dwarf.compile_unit_list.items) |*unit| {
        // Missing stmt_list is legal. A present but unusable table is not.
        const offset = (try statementList(&unit.die)) orelse continue;
        try checkLineSection(dwarf.section(.debug_line), offset);
        try dwarf.populateSrcLocCache(scratch, elf.endian, unit);
        const cache = if (unit.src_loc_cache) |*value| value else return error.MissingDebugInfo;
        if (cache.version < 2 or cache.version > 5) return error.InvalidDebugInfo;
        if (cache.files.len > metadata_entries_max or
            cache.directories.len > metadata_entries_max or
            cache.line_table.count() > metadata_entries_max)
            return error.EvidenceLimitExceeded;
        const compilation_directory = try unit.die.getAttrString(
            dwarf,
            elf.endian,
            std.dwarf.AT.comp_dir,
            dwarf.section(.debug_line_str),
            unit,
        );
        // Only borrowed cache tables and the independent path pool are accessed, not the CU list.
        // zbc-disable-next-line: slice-loop-reentrant-grow
        const file_paths = try collectFilePaths(gpa, .{
            .cache = cache,
            .compilation_directory = compilation_directory,
            .project_root = project_root,
        }, paths);
        defer gpa.free(file_paths);

        for (cache.line_table.values()) |entry| {
            // Scalar inputs and a by-value row give this pure helper no list handle to grow.
            // zbc-disable-next-line: slice-loop-reentrant-grow
            const row = (try rows.numericRow(cache.version, entry, file_paths.len)) orelse continue;
            const path = file_paths[row.file_index] orelse continue;
            try builder.declare(gpa, path, row.line);
        }
    }
}

const FilePathOptions = struct {
    cache: *const Dwarf.CompileUnit.SrcLocCache,
    compilation_directory: []const u8,
    project_root: []const u8,
};

fn collectFilePaths(
    gpa: std.mem.Allocator,
    options: FilePathOptions,
    paths: *projection.Paths,
) error{ OutOfMemory, InvalidDebugInfo, EvidenceLimitExceeded }![]?[]const u8 {
    const file_paths = try gpa.alloc(?[]const u8, options.cache.files.len);
    errdefer gpa.free(file_paths);
    for (options.cache.files, file_paths) |file, *slot| {
        if (file.dir_index >= options.cache.directories.len) return error.InvalidDebugInfo;
        const absolute_path = try rows.sourcePath(gpa, .{
            .compilation_directory = options.compilation_directory,
            .directory = options.cache.directories[file.dir_index].path,
            .file = file.path,
        });
        defer gpa.free(absolute_path);
        slot.* = if (rows.owns(absolute_path, options.project_root))
            try paths.intern(gpa, absolute_path, options.project_root)
        else
            null;
    }
    return file_paths;
}

fn statementList(die: *const Dwarf.Die) error{InvalidDebugInfo}!?u64 {
    var result: ?u64 = null;
    for (die.attrs) |attribute| {
        if (attribute.id != std.dwarf.AT.stmt_list) continue;
        if (result != null) return error.InvalidDebugInfo;
        result = switch (attribute.value) {
            .udata, .sec_offset => |offset| offset,
            .sdata => |offset| std.math.cast(u64, offset) orelse return error.InvalidDebugInfo,
            else => return error.InvalidDebugInfo,
        };
    }
    return result;
}

fn checkLineSection(section: ?[]const u8, offset: u64) error{
    MissingDebugInfo,
    InvalidDebugInfo,
}!void {
    const bytes = section orelse return error.MissingDebugInfo;
    if (offset >= bytes.len) return error.InvalidDebugInfo;
    if (bytes.len - @as(usize, @intCast(offset)) < 4) return error.InvalidDebugInfo;
}
test "a CU without statement list is distinct from a malformed statement list" {
    const absent: Dwarf.Die = .{ .tag_id = 0, .has_children = false, .attrs = &.{} };
    try std.testing.expectEqual(@as(?u64, null), try statementList(&absent));
    const valid: Dwarf.Die = .{
        .tag_id = 0,
        .has_children = false,
        .attrs = @constCast(&[_]DieAttribute{
            .{ .id = std.dwarf.AT.stmt_list, .value = .{ .sec_offset = 0 } },
        }),
    };
    try std.testing.expectEqual(@as(?u64, 0), try statementList(&valid));
    const malformed: Dwarf.Die = .{
        .tag_id = 0,
        .has_children = false,
        .attrs = @constCast(&[_]DieAttribute{
            .{ .id = std.dwarf.AT.stmt_list, .value = .{ .flag = true } },
        }),
    };
    try std.testing.expectError(error.InvalidDebugInfo, statementList(&malformed));
    const negative: Dwarf.Die = .{
        .tag_id = 0,
        .has_children = false,
        .attrs = @constCast(&[_]DieAttribute{
            .{ .id = std.dwarf.AT.stmt_list, .value = .{ .sdata = -1 } },
        }),
    };
    try std.testing.expectError(error.InvalidDebugInfo, statementList(&negative));
    const duplicate: Dwarf.Die = .{
        .tag_id = 0,
        .has_children = false,
        .attrs = @constCast(&[_]DieAttribute{
            .{ .id = std.dwarf.AT.stmt_list, .value = .{ .sec_offset = 0 } },
            .{ .id = std.dwarf.AT.stmt_list, .value = .{ .sec_offset = 4 } },
        }),
    };
    try std.testing.expectError(error.InvalidDebugInfo, statementList(&duplicate));
}

test "statement list must refer to an available bounded line section" {
    try std.testing.expectError(error.MissingDebugInfo, checkLineSection(null, 0));
    try std.testing.expectError(error.InvalidDebugInfo, checkLineSection("", 0));
    try std.testing.expectError(error.InvalidDebugInfo, checkLineSection("abcd", 4));
    try std.testing.expectError(error.InvalidDebugInfo, checkLineSection("abcd", 1));
    try checkLineSection("abcd", 0);
}

test "file tables preserve actual CU paths for both DWARF index conventions" {
    const gpa = std.testing.allocator;
    var paths: projection.Paths = .empty;
    defer paths.deinit(gpa);
    var cache: Dwarf.CompileUnit.SrcLocCache = .{
        .line_table = .empty,
        .directories = &.{ .{ .path = "" }, .{ .path = "src" } },
        .files = @constCast(&[_]FileEntry{
            .{ .path = "entry.zig", .dir_index = 1 },
            .{ .path = "/other/entry.zig", .dir_index = 0 },
        }),
        .version = 4,
    };
    const file_paths = try collectFilePaths(gpa, .{
        .cache = &cache,
        .compilation_directory = "/project",
        .project_root = "/project",
    }, &paths);
    defer gpa.free(file_paths);
    try std.testing.expectEqualStrings("/project/src/entry.zig", file_paths[0].?);
    try std.testing.expectEqual(@as(?[]const u8, null), file_paths[1]);
    const row: Dwarf.CompileUnit.SrcLocCache.LineEntry = .{
        .file = 1,
        .line = 7,
        .column = 0,
    };
    try std.testing.expectEqual(@as(usize, 0), (try rows.numericRow(4, row, 2)).?.file_index);
    try std.testing.expectEqual(@as(usize, 1), (try rows.numericRow(5, row, 2)).?.file_index);
    const outside: Dwarf.CompileUnit.SrcLocCache = .{
        .line_table = .empty,
        .directories = &.{.{ .path = "" }},
        .files = @constCast(&[_]FileEntry{.{ .path = "src/entry.zig", .dir_index = 0 }}),
        .version = 5,
    };
    const outside_paths = try collectFilePaths(gpa, .{
        .cache = &outside,
        .compilation_directory = "/other",
        .project_root = "/project",
    }, &paths);
    defer gpa.free(outside_paths);
    try std.testing.expectEqual(@as(?[]const u8, null), outside_paths[0]);
    cache.files = @constCast(&[_]FileEntry{.{ .path = "entry.zig", .dir_index = 2 }});
    try std.testing.expectError(error.InvalidDebugInfo, collectFilePaths(gpa, .{
        .cache = &cache,
        .compilation_directory = "/project",
        .project_root = "/project",
    }, &paths));
}

test "CU file-path preparation releases partial allocations on every OOM" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, filePathAllocation, .{});
}

fn filePathAllocation(gpa: std.mem.Allocator) !void {
    var paths: projection.Paths = .empty;
    defer paths.deinit(gpa);
    const cache: Dwarf.CompileUnit.SrcLocCache = .{
        .line_table = .empty,
        .directories = &.{.{ .path = "src" }},
        .files = @constCast(&[_]FileEntry{
            .{ .path = "entry.zig", .dir_index = 0 },
            .{ .path = "entry.zig", .dir_index = 0 },
        }),
        .version = 5,
    };
    const file_paths = try collectFilePaths(gpa, .{
        .cache = &cache,
        .compilation_directory = "/project",
        .project_root = "/project",
    }, &paths);
    defer gpa.free(file_paths);
    try std.testing.expectEqual(file_paths[0].?.ptr, file_paths[1].?.ptr);
    try std.testing.expectEqualStrings("/project/src/entry.zig", file_paths[0].?);
}
