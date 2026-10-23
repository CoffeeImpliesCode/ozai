//! Pure grouping of all numeric DWARF rows with hits from fully merged direct raw PCs.
//! Grouping borrows canonical paths; `finish` copies them into the output allocator.

const std = @import("std");

const rows_max = 16 * 1024 * 1024;

/// A positive source line and the number of hit unique PCs assigned to it.
pub const Line = struct { line: u32, hits: u64 };

/// One canonical absolute project path, with ascending positive source lines.
/// Storage belongs to its containing `Report`.
pub const File = struct {
    path: []const u8,
    lines_found: u64,
    lines_hit: u64,
    lines: []const Line,
};

/// Line counts count distinct numbered rows; block counts include unknown project lines.
pub const Summary = struct {
    lines_found: u64,
    lines_hit: u64,
    blocks_found: u64,
    blocks_hit: u64,
};

/// Deep-owned report. Copies share one owner, which calls `deinit` exactly once.
pub const Report = struct {
    version: u32,
    tool: []const u8,
    summary: Summary,
    files: []const File,

    /// Releases tool, file paths, line rows and files through their original allocator.
    /// Invalidates the report and every borrowed view into it.
    pub fn deinit(report: Report, gpa: std.mem.Allocator) void {
        freeFiles(gpa, report.files);
        gpa.free(report.files);
        gpa.free(report.tool);
    }
};

/// Interns canonical source paths without retaining command-output slices.
/// One pool serves one absolute project root; its allocator must match `deinit`.
pub const Paths = struct {
    spellings: std.StringHashMapUnmanaged([]const u8),
    canonical: std.StringHashMapUnmanaged(void),

    pub const empty: Paths = .{ .spellings = .empty, .canonical = .empty };

    /// Resolves each distinct spelling once; equivalent paths share one stable identity.
    /// Returned storage lives until `deinit`; on OOM the pool remains deinitializable.
    pub fn intern(
        paths: *Paths,
        gpa: std.mem.Allocator,
        input: []const u8,
        cwd: []const u8,
    ) error{ OutOfMemory, EvidenceLimitExceeded }![]const u8 {
        if (paths.spellings.get(input)) |path| return path;
        if (paths.spellings.count() >= rows_max or paths.canonical.count() >= rows_max)
            return error.EvidenceLimitExceeded;
        const path = owned: {
            const resolved = try std.fs.path.resolve(gpa, &.{ cwd, input });
            errdefer gpa.free(resolved);
            if (paths.canonical.getKey(resolved)) |existing| {
                gpa.free(resolved);
                break :owned existing;
            }
            try paths.canonical.put(gpa, resolved, {});
            break :owned resolved;
        };
        const spelling = if (std.mem.eql(u8, input, path)) path else try gpa.dupe(u8, input);
        errdefer if (spelling.ptr != path.ptr) gpa.free(spelling);
        try paths.spellings.put(gpa, spelling, path);
        return path;
    }

    /// Releases owned names and maps; invalidates this pool and all borrowed paths.
    /// Call exactly once with the allocator used by `intern`.
    pub fn deinit(paths: *Paths, gpa: std.mem.Allocator) void {
        var spellings = paths.spellings.iterator();
        while (spellings.next()) |entry| {
            if (entry.key_ptr.*.ptr != entry.value_ptr.*.ptr) gpa.free(entry.key_ptr.*);
        }
        paths.spellings.deinit(gpa);
        var canonical = paths.canonical.keyIterator();
        while (canonical.next()) |path| gpa.free(path.*);
        paths.canonical.deinit(gpa);
        paths.* = undefined;
    }
};

/// Audited project-block totals, including PCs without numeric source lines.
pub const Blocks = struct { found: u64, hit: u64 };

const Rows = std.AutoHashMapUnmanaged(u32, u64);

/// Groups numeric DWARF declarations and already deduplicated direct PCs.
/// Paths borrow caller storage until `deinit`; containers use the supplied scratch allocator.
pub const Builder = struct {
    files: std.StringHashMapUnmanaged(Rows),
    pcs: usize,
    rows: usize,

    pub const empty: Builder = .{ .files = .empty, .pcs = 0, .rows = 0 };

    /// Seeds one positive DWARF source row without counting a PC or changing existing hits.
    /// Rejects line zero/nonabsolute paths and bounds distinct rows independently of PCs.
    /// Allocation failure leaves storage deinitializable with the same allocator.
    pub fn declare(
        builder: *Builder,
        scratch: std.mem.Allocator,
        path: []const u8,
        line: u32,
    ) error{ OutOfMemory, PartialMapping, EvidenceLimitExceeded }!void {
        _ = try builder.getRow(scratch, path, line);
    }

    /// Adds one unique PC, not an observation. Rejects line zero and nonabsolute paths.
    /// PCs and distinct rows are independently bounded; OOM leaves storage deinitializable.
    pub fn add(
        builder: *Builder,
        scratch: std.mem.Allocator,
        path: []const u8,
        line: u32,
        hit: bool,
    ) error{ OutOfMemory, PartialMapping, EvidenceLimitExceeded }!void {
        if (builder.pcs >= rows_max) return error.EvidenceLimitExceeded;
        const row = try builder.getRow(scratch, path, line);
        row.* += @intFromBool(hit);
        builder.pcs += 1;
    }

    fn getRow(
        builder: *Builder,
        scratch: std.mem.Allocator,
        path: []const u8,
        line: u32,
    ) error{ OutOfMemory, PartialMapping, EvidenceLimitExceeded }!*u64 {
        if (line == 0 or !std.fs.path.isAbsolute(path)) return error.PartialMapping;
        if (builder.files.getPtr(path)) |file| {
            if (file.getPtr(line)) |row| return row;
        }
        if (builder.rows >= rows_max) return error.EvidenceLimitExceeded;
        const file = try builder.files.getOrPut(scratch, path);
        if (!file.found_existing) file.value_ptr.* = .empty;
        errdefer if (!file.found_existing) {
            file.value_ptr.deinit(scratch);
            const removed = builder.files.remove(path);
            std.debug.assert(removed);
        };
        const row = try file.value_ptr.getOrPut(scratch, line);
        std.debug.assert(!row.found_existing);
        row.value_ptr.* = 0;
        builder.rows += 1;
        return row.value_ptr;
    }

    /// Copies a deterministic report into `gpa`; result borrows nothing from this builder.
    /// On error, all output allocations are freed and the builder remains usable.
    pub fn finish(
        builder: *const Builder,
        gpa: std.mem.Allocator,
        blocks: Blocks,
    ) error{OutOfMemory}!Report {
        const tool = try gpa.dupe(u8, "ozai-zcov-raw");
        errdefer gpa.free(tool);
        const files = try gpa.alloc(File, builder.files.count());
        errdefer gpa.free(files);
        var initialized: usize = 0;
        errdefer freeFiles(gpa, files[0..initialized]);
        var summary: Summary = .{
            .lines_found = 0,
            .lines_hit = 0,
            .blocks_found = blocks.found,
            .blocks_hit = blocks.hit,
        };
        var iterator = builder.files.iterator();
        while (iterator.next()) |entry| {
            files[initialized] = try ownedFile(gpa, entry.key_ptr.*, entry.value_ptr);
            summary.lines_found += files[initialized].lines_found;
            summary.lines_hit += files[initialized].lines_hit;
            initialized += 1;
        }
        std.mem.sort(File, files, {}, fileLess);
        return .{ .version = 1, .tool = tool, .summary = summary, .files = files };
    }

    /// Releases grouping containers, but not the borrowed paths or any finished report.
    /// Invalidates the builder; call exactly once with its scratch allocator.
    pub fn deinit(builder: *Builder, scratch: std.mem.Allocator) void {
        var iterator = builder.files.valueIterator();
        while (iterator.next()) |rows| rows.deinit(scratch);
        builder.files.deinit(scratch);
        builder.* = undefined;
    }
};

fn ownedFile(
    gpa: std.mem.Allocator,
    input: []const u8,
    rows: *const Rows,
) std.mem.Allocator.Error!File {
    const path = try gpa.dupe(u8, input);
    errdefer gpa.free(path);
    const lines = try gpa.alloc(Line, rows.count());
    errdefer gpa.free(lines);
    var iterator = rows.iterator();
    var lines_hit: u64 = 0;
    var index: usize = 0;
    while (iterator.next()) |entry| {
        lines[index] = .{ .line = entry.key_ptr.*, .hits = entry.value_ptr.* };
        lines_hit += @intFromBool(entry.value_ptr.* != 0);
        index += 1;
    }
    std.mem.sort(Line, lines, {}, lineLess);
    return .{
        .path = path,
        .lines_found = lines.len,
        .lines_hit = lines_hit,
        .lines = lines,
    };
}

fn freeFiles(gpa: std.mem.Allocator, files: []const File) void {
    for (files) |file| {
        gpa.free(file.lines);
        gpa.free(file.path);
    }
}

fn lineLess(_: void, left: Line, right: Line) bool {
    return left.line < right.line;
}

fn fileLess(_: void, left: File, right: File) bool {
    return std.mem.lessThan(u8, left.path, right.path);
}

test "distinct unique PCs on a line sum hits with deterministic sorted grouping" {
    const gpa = std.testing.allocator;
    var builder: Builder = .empty;
    defer builder.deinit(gpa);
    try builder.add(gpa, "/project/src/b.zig", 9, false);
    try builder.add(gpa, "/project/src/a.zig", 8, true);
    try builder.add(gpa, "/project/src/a.zig", 3, false);
    try builder.add(gpa, "/project/src/a.zig", 8, true);
    try builder.add(gpa, "/project/src/a.zig", 8, false);
    const report = try builder.finish(gpa, .{ .found = 5, .hit = 2 });
    defer report.deinit(gpa);
    try std.testing.expectEqual(Summary{
        .lines_found = 3,
        .lines_hit = 1,
        .blocks_found = 5,
        .blocks_hit = 2,
    }, report.summary);
    try std.testing.expectEqualStrings("/project/src/a.zig", report.files[0].path);
    try std.testing.expectEqualStrings("/project/src/b.zig", report.files[1].path);
    try std.testing.expectEqual(@as(u64, 2), report.files[0].lines_found);
    try std.testing.expectEqual(@as(u64, 1), report.files[0].lines_hit);
    try std.testing.expectEqual(Line{ .line = 3, .hits = 0 }, report.files[0].lines[0]);
    try std.testing.expectEqual(Line{ .line = 8, .hits = 2 }, report.files[0].lines[1]);
}

test "empty numbered projection does not infer lines from block totals" {
    const gpa = std.testing.allocator;
    var builder: Builder = .empty;
    defer builder.deinit(gpa);
    const report = try builder.finish(gpa, .{ .found = 2, .hit = 1 });
    defer report.deinit(gpa);
    try std.testing.expectEqual(@as(usize, 0), report.files.len);
    try std.testing.expectEqual(@as(u64, 0), report.summary.lines_found);
    try std.testing.expectEqual(@as(u64, 2), report.summary.blocks_found);
}

test "projection owns paths after borrowed grouping and interned inputs are released" {
    const gpa = std.testing.allocator;
    const report = blk: {
        const path = try gpa.dupe(u8, "/project/src/a.zig");
        defer gpa.free(path);
        var paths: Paths = .empty;
        defer paths.deinit(gpa);
        const canonical = try paths.intern(gpa, path, "/project");
        var builder: Builder = .empty;
        defer builder.deinit(gpa);
        try builder.add(gpa, canonical, 4, true);
        break :blk try builder.finish(gpa, .{ .found = 1, .hit = 1 });
    };
    defer report.deinit(gpa);
    try std.testing.expectEqualStrings("/project/src/a.zig", report.files[0].path);
    try std.testing.expectEqual(Line{ .line = 4, .hits = 1 }, report.files[0].lines[0]);
}

test "projection frees partial construction after every allocation failure" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationFailure, .{});
}

fn allocationFailure(gpa: std.mem.Allocator) !void {
    var builder: Builder = .empty;
    defer builder.deinit(gpa);
    try builder.add(gpa, "/project/src/a.zig", 4, true);
    try builder.add(gpa, "/project/src/a.zig", 8, false);
    try builder.add(gpa, "/project/src/b.zig", 3, true);
    const report = try builder.finish(gpa, .{ .found = 3, .hit = 2 });
    defer report.deinit(gpa);
}

test "source paths intern once and normalize unique spellings without borrowing input" {
    const gpa = std.testing.allocator;
    var paths: Paths = .empty;
    defer paths.deinit(gpa);
    const first = blk: {
        const borrowed = try gpa.dupe(u8, "./src/../src/a.zig");
        defer gpa.free(borrowed);
        break :blk try paths.intern(gpa, borrowed, "/project");
    };
    const second = try paths.intern(gpa, "/project/src/a.zig", "/project");
    const third = try paths.intern(gpa, "./src/../src/a.zig", "/project");
    try std.testing.expectEqualStrings("/project/src/a.zig", first);
    try std.testing.expectEqual(first.ptr, second.ptr);
    try std.testing.expectEqual(first.ptr, third.ptr);
    try std.testing.expectEqual(@as(u32, 1), paths.canonical.count());
    try std.testing.expectEqual(@as(u32, 2), paths.spellings.count());
}

test "interned names are cleaned after every allocation failure" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, pathAllocationFailure, .{});
}

fn pathAllocationFailure(gpa: std.mem.Allocator) !void {
    var paths: Paths = .empty;
    defer paths.deinit(gpa);
    const first = try paths.intern(gpa, "./src/../src/a.zig", "/project");
    const second = try paths.intern(gpa, "/project/src/a.zig", "/project");
    try std.testing.expectEqual(first.ptr, second.ptr);
}

test "projection rejects zero and relative source rows and caps unique PC additions" {
    const gpa = std.testing.allocator;
    var builder: Builder = .empty;
    defer builder.deinit(gpa);
    try std.testing.expectError(
        error.PartialMapping,
        builder.add(gpa, "/project/src/a.zig", 0, true),
    );
    try std.testing.expectError(
        error.PartialMapping,
        builder.add(gpa, "src/a.zig", 4, true),
    );
    builder.pcs = rows_max;
    try std.testing.expectError(
        error.EvidenceLimitExceeded,
        builder.add(gpa, "/project/src/a.zig", 4, true),
    );
}

test "declared DWARF rows without direct PCs remain cold and count no blocks" {
    const gpa = std.testing.allocator;
    var builder: Builder = .empty;
    defer builder.deinit(gpa);
    try builder.declare(gpa, "/project/src/a.zig", 7);
    const report = try builder.finish(gpa, .{ .found = 0, .hit = 0 });
    defer report.deinit(gpa);
    try std.testing.expectEqual(Summary{
        .lines_found = 1,
        .lines_hit = 0,
        .blocks_found = 0,
        .blocks_hit = 0,
    }, report.summary);
    try std.testing.expectEqual(Line{ .line = 7, .hits = 0 }, report.files[0].lines[0]);
    try std.testing.expectEqual(@as(usize, 0), builder.pcs);
    try std.testing.expectEqual(@as(usize, 1), builder.rows);
}

test "duplicate declarations neither double count rows nor clear direct PC hits" {
    const gpa = std.testing.allocator;
    var builder: Builder = .empty;
    defer builder.deinit(gpa);
    try builder.declare(gpa, "/project/src/a.zig", 7);
    try builder.declare(gpa, "/project/src/a.zig", 7);
    try builder.add(gpa, "/project/src/a.zig", 7, true);
    try builder.declare(gpa, "/project/src/a.zig", 7);
    try builder.add(gpa, "/project/src/a.zig", 7, true);
    try builder.add(gpa, "/project/src/b.zig", 3, true);
    try builder.declare(gpa, "/project/src/b.zig", 3);
    const report = try builder.finish(gpa, .{ .found = 3, .hit = 3 });
    defer report.deinit(gpa);
    try std.testing.expectEqual(@as(u64, 2), report.summary.lines_found);
    try std.testing.expectEqual(@as(u64, 2), report.summary.lines_hit);
    try std.testing.expectEqual(Line{ .line = 7, .hits = 2 }, report.files[0].lines[0]);
    try std.testing.expectEqual(Line{ .line = 3, .hits = 1 }, report.files[1].lines[0]);
    try std.testing.expectEqual(@as(usize, 3), builder.pcs);
    try std.testing.expectEqual(@as(usize, 2), builder.rows);
}

test "declarations reject zero and relative rows and independently bound unique row storage" {
    const gpa = std.testing.allocator;
    var builder: Builder = .empty;
    defer builder.deinit(gpa);
    try std.testing.expectError(
        error.PartialMapping,
        builder.declare(gpa, "/project/src/a.zig", 0),
    );
    try std.testing.expectError(error.PartialMapping, builder.declare(gpa, "src/a.zig", 7));
    try builder.declare(gpa, "/project/src/a.zig", 7);
    builder.rows = rows_max;
    try builder.declare(gpa, "/project/src/a.zig", 7);
    try builder.add(gpa, "/project/src/a.zig", 7, true);
    try std.testing.expectError(
        error.EvidenceLimitExceeded,
        builder.declare(gpa, "/project/src/a.zig", 8),
    );
    try std.testing.expectError(
        error.EvidenceLimitExceeded,
        builder.declare(gpa, "/project/src/b.zig", 7),
    );
    try std.testing.expectError(
        error.EvidenceLimitExceeded,
        builder.add(gpa, "/project/src/a.zig", 8, true),
    );
    try std.testing.expectEqual(@as(u32, 1), builder.files.count());
    builder.pcs = rows_max;
    try builder.declare(gpa, "/project/src/a.zig", 7);
}

test "declaration storage and owned reports clean up after every allocation failure" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, declarationFailure, .{});
}

fn declarationFailure(gpa: std.mem.Allocator) !void {
    var builder: Builder = .empty;
    defer builder.deinit(gpa);
    try builder.declare(gpa, "/project/src/a.zig", 7);
    try builder.declare(gpa, "/project/src/a.zig", 8);
    try builder.declare(gpa, "/project/src/b.zig", 3);
    try builder.add(gpa, "/project/src/a.zig", 7, true);
    try builder.declare(gpa, "/project/src/a.zig", 7);
    const report = try builder.finish(gpa, .{ .found = 1, .hit = 1 });
    defer report.deinit(gpa);
    try std.testing.expectEqual(@as(u64, 3), report.summary.lines_found);
    try std.testing.expectEqual(@as(u64, 1), report.summary.lines_hit);
}
