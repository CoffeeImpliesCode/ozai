const std = @import("std");
const ev = @import("gate_evidence.zig");
const raw = @import("gate_raw.zig");
const policy = @import("coverage_policy.zig");
const limit = 16 * 1024 * 1024;

pub const Report = struct {
    version: u32, tool: []const u8,
    summary: struct { lines_found: u64, lines_hit: u64, blocks_found: u64, blocks_hit: u64 },
    files: []const struct {
        path: []const u8, lines_found: u64, lines_hit: u64,
        lines: []const struct { line: u32, hits: u64 },
    },
};
pub const ModeEvidence = struct {
    mode: []const u8,
    report: ev.Artifact,
    blocks_found: u64,
    blocks_hit: u64,
    lines_found: u64,
    lines_hit: u64,
};

// Report storage belongs to gpa, normally the measurement's arena.
pub fn parse(gpa: std.mem.Allocator, io: std.Io, path: []const u8) !Report {
    const bytes = try ev.readFile(gpa, io, path);
    defer gpa.free(bytes);
    const report = try std.json.parseFromSliceLeaky(Report, gpa, bytes,
        .{ .ignore_unknown_fields = true, .allocate = .alloc_always });
    try checkReport(report);
    return report;
}

fn checkReport(report: Report) !void {
    if (report.version != 2 or !std.mem.eql(u8, report.tool, "zig-cov") or
        report.summary.blocks_found == 0 or report.summary.lines_found == 0 or
        report.summary.blocks_hit > report.summary.blocks_found)
        return error.IncompleteReport;
    if (report.files.len > limit or report.summary.lines_found > limit)
        return error.EvidenceLimitExceeded;
    var found: u64 = 0;
    var hit: u64 = 0;
    for (report.files) |file| {
        if (file.lines.len == 0 or file.lines.len != file.lines_found)
            return error.PartialMapping;
        if (file.lines.len > limit - found) return error.EvidenceLimitExceeded;
        var file_hit: u64 = 0;
        var previous: u32 = 0;
        for (file.lines) |line| {
            if (line.line <= previous) return error.PartialMapping;
            previous = line.line;
            if (line.hits != 0) file_hit += 1;
        }
        if (file_hit != file.lines_hit) return error.PartialMapping;
        found += file.lines_found;
        hit += file_hit;
    }
    if (found != report.summary.lines_found or hit != report.summary.lines_hit)
        return error.PartialMapping;
}

pub fn checkCounters(report: Report, counters: raw.CounterSummary) !void {
    if (report.summary.blocks_found != counters.blocks_found or
        report.summary.blocks_hit != counters.blocks_hit) return error.PartialMapping;
}

pub fn collectItems(gpa: std.mem.Allocator, io: std.Io, report: Report, mode: []const u8,
    inventory: []const ev.Source, items: *std.ArrayList(policy.Item)) !void
{
    try checkReport(report);
    if (inventory.len > limit) return error.EvidenceLimitExceeded;
    var cwd_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const cwd = cwd_buffer[0..try std.Io.Dir.cwd().realPath(io, &cwd_buffer)];
    // Maps are temporary even when the item storage uses the caller's arena.
    var temporary = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer temporary.deinit();
    const scratch = temporary.allocator();
    var mapped: std.StringHashMapUnmanaged(void) = .empty;
    var source_map: std.StringHashMapUnmanaged(ev.Source) = .empty;
    for (inventory) |source| try source_map.put(scratch, source.path, source);
    for (report.files) |file| {
        const path = try relativePath(file.path, cwd);
        const source = source_map.get(path) orelse return error.UnexpectedSourceMapping;
        if (mapped.contains(path)) return error.PartialMapping;
        try mapped.put(scratch, path, {});
        for (file.lines) |line| {
            if (line.hits == 0) try items.append(gpa, .{
                .mode = mode, .path = source.path, .source_sha256 = source.sha256,
                .line = line.line, .unit = "inferred_line",
            });
        }
    }
    for (inventory) |source| {
        if (eligible(source.path) and !mapped.contains(source.path)) {
            try items.append(gpa, .{ .mode = mode, .path = source.path,
                .source_sha256 = source.sha256, .line = 0, .unit = "unattributed_file" });
        }
    }
}

fn relativePath(input: []const u8, cwd: []const u8) ![]const u8 {
    var path = input;
    if (std.fs.path.isAbsolute(path)) {
        if (!std.mem.startsWith(u8, path, cwd) or path.len <= cwd.len or
            path[cwd.len] != '/') return error.UnexpectedSourceMapping;
        path = path[cwd.len + 1 ..];
    }
    var remaining = path.len / 2;
    while (remaining > 0 and std.mem.startsWith(u8, path, "./")) : (remaining -= 1) {
        path = path[2..];
    }
    return path;
}

fn eligible(path: []const u8) bool {
    return std.mem.endsWith(u8, path, ".zig") and
        (std.mem.startsWith(u8, path, "src/") or
            std.mem.startsWith(u8, path, "vendor/quic/src/") or
            std.mem.startsWith(u8, path, "scripts/"));
}

test "plausible truncated JSON line mapping fails" {
    const report: Report = .{ .version = 2, .tool = "zig-cov",
        .summary = .{ .lines_found = 2, .lines_hit = 1, .blocks_found = 3, .blocks_hit = 2 },
        .files = &.{.{ .path = "src/a.zig", .lines_found = 2, .lines_hit = 1,
            .lines = &.{.{ .line = 4, .hits = 1 }} }} };
    try std.testing.expectError(error.PartialMapping, checkReport(report));
}

test "zero measured blocks is an incomplete report not a coverage percentage" {
    const report: Report = .{ .version = 2, .tool = "zig-cov",
        .summary = .{ .lines_found = 2, .lines_hit = 1, .blocks_found = 0, .blocks_hit = 0 },
        .files = &.{} };
    try std.testing.expectError(error.IncompleteReport, checkReport(report));
}

test "counter report cannot silently drop one measured block" {
    const report: Report = .{ .version = 2, .tool = "zig-cov",
        .summary = .{ .lines_found = 1, .lines_hit = 1, .blocks_found = 1, .blocks_hit = 1 },
        .files = &.{} };
    try std.testing.expectError(error.PartialMapping,
        checkCounters(report, .{ .blocks_found = 2, .blocks_hit = 1 }));
}

test "source paths require project boundaries and normalize dot prefixes" {
    try std.testing.expectEqualStrings("src/a.zig", try relativePath("././src/a.zig", "/root"));
    try std.testing.expectEqualStrings("src/a.zig", try relativePath("/root/src/a.zig", "/root"));
    try std.testing.expectError(error.UnexpectedSourceMapping, relativePath("/root2/a.zig", "/root"));
    try std.testing.expect(eligible("src/a.zig"));
    try std.testing.expect(eligible("vendor/quic/src/a.zig"));
    try std.testing.expect(eligible("scripts/gate_raw.zig"));
    try std.testing.expect(!eligible("vendor/other/a.zig"));
}
