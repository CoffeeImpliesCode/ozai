const std = @import("std");
const ev = @import("gate_evidence.zig");
const raw = @import("gate_raw.zig");
const projection = @import("gate_projection.zig");
const policy = @import("coverage_policy.zig");
const limit = 16 * 1024 * 1024;
const gate_files = @import("gate_files.zig");

pub const CheckError = error{
    IncompleteReport,
    EvidenceLimitExceeded,
    PartialMapping,
    UnexpectedSourceMapping,
};
pub const ParseError = gate_files.ReadFileError || std.json.ParseError(std.json.Scanner) || CheckError;
pub const CollectError = CheckError || std.mem.Allocator.Error || std.process.CurrentPathAllocError;

pub const ModeEvidence = struct {
    mode: []const u8,
    report: ev.Artifact,
    blocks_found: u64,
    blocks_hit: u64,
    lines_found: u64,
    lines_hit: u64,
    unmapped_project_blocks: u64,
    unmapped_project_hits: u64,
    unowned_blocks: u64,
    unowned_hits: u64,
};

/// Parses a retained projection; release its owned fields with Report.deinit(gpa).
pub fn parse(gpa: std.mem.Allocator, io: std.Io, path: []const u8) ParseError!projection.Report {
    const bytes = try ev.readFile(gpa, io, path);
    defer gpa.free(bytes);
    const report = try std.json.parseFromSliceLeaky(
        projection.Report,
        gpa,
        bytes,
        .{ .allocate = .alloc_always },
    );
    errdefer report.deinit(gpa);
    try checkReport(report);
    return report;
}

fn checkReport(report: projection.Report) CheckError!void {
    if (report.version != 1 or !std.mem.eql(u8, report.tool, "ozai-zcov-raw") or
        report.summary.blocks_found == 0 or
        report.summary.blocks_hit > report.summary.blocks_found)
        return error.IncompleteReport;
    if (report.files.len > limit or report.summary.lines_found > limit or
        report.summary.blocks_found > limit)
        return error.EvidenceLimitExceeded;
    var found: u64 = 0;
    var hit: u64 = 0;
    var previous_path: []const u8 = "";
    for (report.files) |file| {
        try canonicalPath(file.path);
        if (!std.mem.lessThan(u8, previous_path, file.path)) return error.PartialMapping;
        previous_path = file.path;
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

pub fn checkCounters(report: projection.Report, counters: raw.CounterSummary) CheckError!void {
    try checkReport(report);
    if (report.summary.blocks_found != counters.blocks_found or
        report.summary.blocks_hit != counters.blocks_hit or
        counters.unmapped_project_blocks > counters.blocks_found or
        counters.unmapped_project_hits > counters.unmapped_project_blocks or
        counters.unmapped_project_hits > counters.blocks_hit or
        counters.unowned_hits > counters.unowned_blocks)
        return error.PartialMapping;
    const mapped_hits = counters.blocks_hit - counters.unmapped_project_hits;
    var hits: u64 = 0;
    for (report.files) |file| {
        for (file.lines) |line| {
            if (line.hits > mapped_hits - hits) return error.PartialMapping;
            hits += line.hits;
        }
    }
    if (hits != mapped_hits) return error.PartialMapping;
}

/// Requires the retained report's exact ordered projection and recorded counters.
pub fn checkReplay(mode: ModeEvidence, report: projection.Report, audit: raw.Audit) CheckError!void {
    const counters = audit.counters;
    try checkCounters(report, counters);
    try checkCounters(audit.report, counters);
    if (mode.blocks_found != report.summary.blocks_found or
        mode.blocks_hit != report.summary.blocks_hit or
        mode.lines_found != report.summary.lines_found or
        mode.lines_hit != report.summary.lines_hit or
        mode.unmapped_project_blocks != counters.unmapped_project_blocks or
        mode.unmapped_project_hits != counters.unmapped_project_hits or
        mode.unowned_blocks != counters.unowned_blocks or
        mode.unowned_hits != counters.unowned_hits)
        return error.PartialMapping;
    if (!std.meta.eql(report.summary, audit.report.summary) or
        report.files.len != audit.report.files.len)
        return error.PartialMapping;
    for (report.files, audit.report.files) |retained, fresh| {
        if (!std.mem.eql(u8, retained.path, fresh.path) or
            retained.lines_found != fresh.lines_found or retained.lines_hit != fresh.lines_hit or
            retained.lines.len != fresh.lines.len)
            return error.PartialMapping;
        for (retained.lines, fresh.lines) |retained_line, fresh_line| {
            if (!std.meta.eql(retained_line, fresh_line)) return error.PartialMapping;
        }
    }
}

pub fn collectItems(
    gpa: std.mem.Allocator,
    io: std.Io,
    report: projection.Report,
    mode: []const u8,
    inventory: []const ev.Source,
    items: *std.ArrayList(policy.Item),
) CollectError!void {
    try checkReport(report);
    if (inventory.len > limit) return error.EvidenceLimitExceeded;
    const cwd = try std.process.currentPathAlloc(io, gpa);
    defer gpa.free(cwd);
    // Maps are temporary even when the item storage uses the caller's arena.
    var temporary = std.heap.ArenaAllocator.init(gpa);
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
                .mode = mode,
                .path = source.path,
                .source_sha256 = source.sha256,
                .line = line.line,
                .unit = "inferred_line",
            });
        }
    }
    for (inventory) |source| {
        if (eligible(source.path) and !mapped.contains(source.path)) {
            try items.append(gpa, .{
                .mode = mode,
                .path = source.path,
                .source_sha256 = source.sha256,
                .line = 0,
                .unit = "unattributed_file",
            });
        }
    }
}

fn canonicalPath(input: []const u8) error{UnexpectedSourceMapping}!void {
    if (!std.fs.path.isAbsolute(input) or input.len <= 1)
        return error.UnexpectedSourceMapping;
    var parts = std.mem.splitScalar(u8, input[1..], '/');
    while (parts.next()) |part| {
        if (part.len == 0 or std.mem.eql(u8, part, ".") or std.mem.eql(u8, part, ".."))
            return error.UnexpectedSourceMapping;
    }
}

// The returned slice borrows the canonical absolute report path.
fn relativePath(input: []const u8, cwd: []const u8) error{UnexpectedSourceMapping}![]const u8 {
    try canonicalPath(input);
    if (!std.mem.startsWith(u8, input, cwd) or input.len <= cwd.len or
        input[cwd.len] != '/') return error.UnexpectedSourceMapping;
    return input[cwd.len + 1 ..];
}

fn eligible(path: []const u8) bool {
    return std.mem.endsWith(u8, path, ".zig");
}

test "plausible truncated JSON line mapping fails" {
    const report: projection.Report = .{
        .version = 1,
        .tool = "ozai-zcov-raw",
        .summary = .{
            .lines_found = 2,
            .lines_hit = 1,
            .blocks_found = 3,
            .blocks_hit = 2,
        },
        .files = &.{
            .{
                .path = "/root/src/a.zig",
                .lines_found = 2,
                .lines_hit = 1,
                .lines = &.{
                    .{ .line = 4, .hits = 1 },
                },
            },
        },
    };
    try std.testing.expectError(error.PartialMapping, checkReport(report));
}

test "zero measured blocks is an incomplete report not a coverage percentage" {
    const report: projection.Report = .{
        .version = 1,
        .tool = "ozai-zcov-raw",
        .summary = .{
            .lines_found = 2,
            .lines_hit = 1,
            .blocks_found = 0,
            .blocks_hit = 0,
        },
        .files = &.{},
    };
    try std.testing.expectError(error.IncompleteReport, checkReport(report));
}

test "counter report cannot silently drop one measured block" {
    const report: projection.Report = .{
        .version = 1,
        .tool = "ozai-zcov-raw",
        .summary = .{
            .lines_found = 1,
            .lines_hit = 1,
            .blocks_found = 1,
            .blocks_hit = 1,
        },
        .files = &.{.{
            .path = "/root/src/a.zig",
            .lines_found = 1,
            .lines_hit = 1,
            .lines = &.{.{ .line = 4, .hits = 1 }},
        }},
    };
    try std.testing.expectError(
        error.PartialMapping,
        checkCounters(
            report,
            .{
                .blocks_found = 2,
                .blocks_hit = 1,
                .unmapped_project_blocks = 0,
                .unmapped_project_hits = 0,
                .unowned_blocks = 0,
                .unowned_hits = 0,
            },
        ),
    );
}

test "report source paths require canonical absolute project boundaries" {
    try std.testing.expectEqualStrings(
        "src/a.zig",
        try relativePath("/root/src/a.zig", "/root"),
    );
    const invalid = [_][]const u8{
        "././src/a.zig",          "src/../src//a.zig",
        "/root/src/../src/a.zig", "/root/src//a.zig",
        "../sysdeps/crti.S",      "/root/../sysdeps/start.S",
        "/root2/a.zig",           "/root/src/./a.zig",
        "/root/src/a.zig/",       "/root",
        ".",                      "",
    };
    for (invalid) |path| {
        try std.testing.expectError(
            error.UnexpectedSourceMapping,
            relativePath(path, "/root"),
        );
    }
}

test "replay requires exact unmapped and unowned counts independent of mapped totals" {
    const report: projection.Report = .{
        .version = 1,
        .tool = "ozai-zcov-raw",
        .summary = .{
            .lines_found = 1,
            .lines_hit = 1,
            .blocks_found = 3,
            .blocks_hit = 2,
        },
        .files = &.{.{
            .path = "/root/src/a.zig",
            .lines_found = 1,
            .lines_hit = 1,
            .lines = &.{.{ .line = 4, .hits = 1 }},
        }},
    };
    const counters: raw.CounterSummary = .{
        .blocks_found = 3,
        .blocks_hit = 2,
        .unmapped_project_blocks = 2,
        .unmapped_project_hits = 1,
        .unowned_blocks = 4,
        .unowned_hits = 2,
    };
    var mode: ModeEvidence = .{
        .mode = "Debug",
        .report = .{
            .path = "/scratch/report.json",
            .sha256 = "hash",
        },
        .blocks_found = 3,
        .blocks_hit = 2,
        .lines_found = 1,
        .lines_hit = 1,
        .unmapped_project_blocks = 2,
        .unmapped_project_hits = 1,
        .unowned_blocks = 4,
        .unowned_hits = 2,
    };
    const audit: raw.Audit = .{ .report = report, .counters = counters };
    try checkCounters(report, counters);
    try checkReplay(mode, report, audit);
    mode.unmapped_project_blocks = 1;
    try std.testing.expectError(error.PartialMapping, checkReplay(mode, report, audit));
    mode.unmapped_project_blocks = 2;
    mode.unmapped_project_hits = 0;
    try std.testing.expectError(error.PartialMapping, checkReplay(mode, report, audit));
    mode.unmapped_project_hits = 1;
    mode.unowned_blocks = 3;
    try std.testing.expectError(error.PartialMapping, checkReplay(mode, report, audit));
    mode.unowned_blocks = 4;
    mode.unowned_hits = 1;
    try std.testing.expectError(error.PartialMapping, checkReplay(mode, report, audit));
}

test "serialized mode evidence requires every unmapped and unowned count" {
    const missing = [_][]const u8{
        \\{"mode":"Debug","report":{"path":"report.json","sha256":"hash"},
        \\ "blocks_found":1,"blocks_hit":1,"lines_found":1,"lines_hit":1,
        \\ "unmapped_project_blocks":2,"unowned_blocks":4,"unowned_hits":2}
        ,
        \\{"mode":"Debug","report":{"path":"report.json","sha256":"hash"},
        \\ "blocks_found":1,"blocks_hit":1,"lines_found":1,"lines_hit":1,
        \\ "unmapped_project_hits":1,"unowned_blocks":4,"unowned_hits":2}
        ,
        \\{"mode":"Debug","report":{"path":"report.json","sha256":"hash"},
        \\ "blocks_found":1,"blocks_hit":1,"lines_found":1,"lines_hit":1,
        \\ "unmapped_project_blocks":2,"unmapped_project_hits":1,"unowned_hits":2}
        ,
        \\{"mode":"Debug","report":{"path":"report.json","sha256":"hash"},
        \\ "blocks_found":1,"blocks_hit":1,"lines_found":1,"lines_hit":1,
        \\ "unmapped_project_blocks":2,"unmapped_project_hits":1,"unowned_blocks":4}
        ,
    };
    for (missing) |json| {
        try std.testing.expectError(
            error.MissingField,
            std.json.parseFromSlice(
                ModeEvidence,
                std.testing.allocator,
                json,
                .{},
            ),
        );
    }
}

test "serialized mode evidence preserves unowned counts outside mapped totals" {
    const mode: ModeEvidence = .{
        .mode = "Debug",
        .report = .{ .path = "report.json", .sha256 = "hash" },
        .blocks_found = 1,
        .blocks_hit = 1,
        .lines_found = 1,
        .lines_hit = 1,
        .unmapped_project_blocks = 0,
        .unmapped_project_hits = 0,
        .unowned_blocks = 4,
        .unowned_hits = 2,
    };
    const json = try std.json.Stringify.valueAlloc(std.testing.allocator, mode, .{});
    defer std.testing.allocator.free(json);
    const parsed = try std.json.parseFromSlice(
        ModeEvidence,
        std.testing.allocator,
        json,
        .{},
    );
    defer parsed.deinit();
    try std.testing.expectEqual(mode.blocks_found, parsed.value.blocks_found);
    try std.testing.expectEqual(mode.blocks_hit, parsed.value.blocks_hit);
    try std.testing.expectEqual(mode.unowned_blocks, parsed.value.unowned_blocks);
    try std.testing.expectEqual(mode.unowned_hits, parsed.value.unowned_hits);
}

test "replay rejects same total line attribution and hit count forgeries" {
    const report: projection.Report = .{
        .version = 1,
        .tool = "ozai-zcov-raw",
        .summary = .{
            .lines_found = 3,
            .lines_hit = 2,
            .blocks_found = 4,
            .blocks_hit = 3,
        },
        .files = &.{
            .{
                .path = "/root/src/a.zig",
                .lines_found = 2,
                .lines_hit = 2,
                .lines = &.{ .{ .line = 4, .hits = 2 }, .{ .line = 6, .hits = 1 } },
            },
            .{
                .path = "/root/src/b.zig",
                .lines_found = 1,
                .lines_hit = 0,
                .lines = &.{.{ .line = 8, .hits = 0 }},
            },
        },
    };
    const audit: raw.Audit = .{
        .report = report,
        .counters = .{
            .blocks_found = 4,
            .blocks_hit = 3,
            .unmapped_project_blocks = 0,
            .unmapped_project_hits = 0,
            .unowned_blocks = 0,
            .unowned_hits = 0,
        },
    };
    const mode: ModeEvidence = .{
        .mode = "Debug",
        .report = .{ .path = "/scratch/report.json", .sha256 = "hash" },
        .blocks_found = 4,
        .blocks_hit = 3,
        .lines_found = 3,
        .lines_hit = 2,
        .unmapped_project_blocks = 0,
        .unmapped_project_hits = 0,
        .unowned_blocks = 0,
        .unowned_hits = 0,
    };
    try checkReplay(mode, report, audit);
    var files = [_]projection.File{ report.files[0], report.files[1] };
    var forged = report;
    forged.files = &files;
    files[0].path = "/root/src/aa.zig";
    try std.testing.expectError(error.PartialMapping, checkReplay(mode, forged, audit));
    files[0] = report.files[0];
    files[0].lines = &.{ .{ .line = 5, .hits = 2 }, .{ .line = 6, .hits = 1 } };
    try std.testing.expectError(error.PartialMapping, checkReplay(mode, forged, audit));
    files[0].lines = &.{ .{ .line = 4, .hits = 1 }, .{ .line = 6, .hits = 2 } };
    try std.testing.expectError(error.PartialMapping, checkReplay(mode, forged, audit));
    files[0] = report.files[0];
    files[0].lines_hit = 1;
    files[0].lines = &.{ .{ .line = 4, .hits = 0 }, .{ .line = 6, .hits = 1 } };
    files[1].lines_hit = 1;
    files[1].lines = &.{.{ .line = 8, .hits = 2 }};
    try std.testing.expectError(error.PartialMapping, checkReplay(mode, forged, audit));
}

test "replay cannot infer a numbered line for an unknown project block" {
    const report: projection.Report = .{
        .version = 1,
        .tool = "ozai-zcov-raw",
        .summary = .{
            .lines_found = 1,
            .lines_hit = 1,
            .blocks_found = 2,
            .blocks_hit = 1,
        },
        .files = &.{.{
            .path = "/root/src/a.zig",
            .lines_found = 1,
            .lines_hit = 1,
            .lines = &.{.{ .line = 4, .hits = 1 }},
        }},
    };
    const audit: raw.Audit = .{
        .report = report,
        .counters = .{
            .blocks_found = 2,
            .blocks_hit = 1,
            .unmapped_project_blocks = 1,
            .unmapped_project_hits = 0,
            .unowned_blocks = 0,
            .unowned_hits = 0,
        },
    };
    const mode: ModeEvidence = .{
        .mode = "Debug",
        .report = .{ .path = "/scratch/report.json", .sha256 = "hash" },
        .blocks_found = 2,
        .blocks_hit = 1,
        .lines_found = 2,
        .lines_hit = 1,
        .unmapped_project_blocks = 1,
        .unmapped_project_hits = 0,
        .unowned_blocks = 0,
        .unowned_hits = 0,
    };
    var forged = report;
    forged.summary.lines_found = 2;
    forged.files = &.{.{
        .path = "/root/src/a.zig",
        .lines_found = 2,
        .lines_hit = 1,
        .lines = &.{ .{ .line = 4, .hits = 1 }, .{ .line = 9, .hits = 0 } },
    }};
    try std.testing.expectError(error.PartialMapping, checkReplay(mode, forged, audit));
    forged.files = &.{.{
        .path = "/root/src/a.zig",
        .lines_found = 2,
        .lines_hit = 1,
        .lines = &.{ .{ .line = 0, .hits = 0 }, .{ .line = 4, .hits = 1 } },
    }};
    try std.testing.expectError(error.PartialMapping, checkReport(forged));
}

test "cold projection emits each numbered row and every unattributed eligible module" {
    const gpa = std.testing.allocator;
    const cwd = try std.process.currentPathAlloc(std.testing.io, gpa);
    defer gpa.free(cwd);
    const path = try std.fs.path.join(gpa, &.{ cwd, "src/a.zig" });
    defer gpa.free(path);
    const report: projection.Report = .{
        .version = 1,
        .tool = "ozai-zcov-raw",
        .summary = .{
            .lines_found = 3,
            .lines_hit = 1,
            .blocks_found = 4,
            .blocks_hit = 1,
        },
        .files = &.{.{
            .path = path,
            .lines_found = 3,
            .lines_hit = 1,
            .lines = &.{
                .{ .line = 4, .hits = 0 },
                .{ .line = 5, .hits = 1 },
                .{ .line = 9, .hits = 0 },
            },
        }},
    };
    const inventory = [_]ev.Source{
        .{ .path = "src/a.zig", .sha256 = "a" },
        .{ .path = "src/unknown.zig", .sha256 = "unknown" },
        .{ .path = "vendor/quic/src/unknown.zig", .sha256 = "vendor" },
        .{ .path = "scripts/unknown.zig", .sha256 = "script" },
        .{ .path = "vendor/other/unknown.zig", .sha256 = "external" },
    };
    var items: std.ArrayList(policy.Item) = .empty;
    defer items.deinit(gpa);
    try collectItems(gpa, std.testing.io, report, "Debug", &inventory, &items);
    try std.testing.expectEqual(@as(usize, 6), items.items.len);
    const expected_lines = [_]u32{ 4, 9, 0, 0, 0, 0 };
    const expected_sources = [_]usize{ 0, 0, 1, 2, 3, 4 };
    for (items.items, expected_lines, expected_sources) |item, line, source_index| {
        try std.testing.expectEqualStrings("Debug", item.mode);
        try std.testing.expectEqualStrings(inventory[source_index].path, item.path);
        try std.testing.expectEqualStrings(inventory[source_index].sha256, item.source_sha256);
        try std.testing.expectEqual(line, item.line);
        try std.testing.expectEqualStrings(
            if (line == 0) "unattributed_file" else "inferred_line",
            item.unit,
        );
    }
    var unexpected = inventory;
    unexpected[0].path = "src/b.zig";
    try std.testing.expectError(
        error.UnexpectedSourceMapping,
        collectItems(gpa, std.testing.io, report, "Debug", &unexpected, &items),
    );
    var unknown_only = report;
    unknown_only.summary = .{
        .lines_found = 0,
        .lines_hit = 0,
        .blocks_found = 1,
        .blocks_hit = 0,
    };
    unknown_only.files = &.{};
    try checkCounters(unknown_only, .{
        .blocks_found = 1,
        .blocks_hit = 0,
        .unmapped_project_blocks = 1,
        .unmapped_project_hits = 0,
        .unowned_blocks = 0,
        .unowned_hits = 0,
    });
    items.clearRetainingCapacity();
    try collectItems(gpa, std.testing.io, unknown_only, "Debug", &inventory, &items);
    try std.testing.expectEqual(@as(usize, 5), items.items.len);
    for (items.items, inventory) |item, source| {
        try std.testing.expectEqualStrings(source.path, item.path);
        try std.testing.expectEqual(@as(u32, 0), item.line);
        try std.testing.expectEqualStrings("unattributed_file", item.unit);
    }
}

test "root build helper absence requires both mode dispositions" {
    try expectAbsentSourceDisposition("vendored_file_list.zig");
}

test "opt in test module absence requires both mode dispositions" {
    try expectAbsentSourceDisposition("test/blobs_interop_test.zig");
}

fn expectAbsentSourceDisposition(path: []const u8) !void {
    const gpa = std.testing.allocator;
    const report: projection.Report = .{
        .version = 1,
        .tool = "ozai-zcov-raw",
        .summary = .{ .blocks_found = 1, .blocks_hit = 0, .lines_found = 0, .lines_hit = 0 },
        .files = &.{},
    };
    var items: std.ArrayList(policy.Item) = .empty;
    defer items.deinit(gpa);
    for (policy.modes) |mode| {
        try collectItems(gpa, std.testing.io, report, mode, &.{.{
            .path = path,
            .sha256 = &@as([64:0]u8, @splat('a')),
        }}, &items);
    }
    var ledger: policy.Ledger = .{
        .schema = policy.schema_version,
        .source_digest = "current",
        .compiler = "0.16.0",
        .measurement = .{ .path = "/retained/measurement.json", .sha256 = &@as([64:0]u8, @splat('b')) },
        .scope = policy.scope,
        .modes = policy.modes,
        .dispositions = &.{},
        .unmapped_project = &.{},
        .unowned = &.{},
    };
    try std.testing.expectError(
        error.MissingDisposition,
        policy.validate(gpa, ledger, "current", "0.16.0", items.items),
    );
    try std.testing.expectEqual(policy.modes.len, items.items.len);
    for (items.items, policy.modes) |item, mode| {
        try std.testing.expectEqualStrings(mode, item.mode);
        try std.testing.expectEqualStrings(path, item.path);
        try std.testing.expectEqualStrings(&@as([64:0]u8, @splat('a')), item.source_sha256);
        try std.testing.expectEqual(@as(u32, 0), item.line);
        try std.testing.expectEqualStrings("unattributed_file", item.unit);
    }
    var dispositions: [policy.modes.len]policy.Disposition = @splat(.{
        .mode = "",
        .path = path,
        .source_sha256 = &@as([64:0]u8, @splat('a')),
        .line = 0,
        .unit = "unattributed_file",
        .action = "accept",
        .reason = "Opt in source is outside the captured five target DWARF row universe.",
    });
    for (&dispositions, items.items) |*disposition, item| {
        disposition.* = .{
            .mode = item.mode,
            .path = item.path,
            .source_sha256 = item.source_sha256,
            .line = item.line,
            .unit = item.unit,
            .action = "accept",
            .reason = "Opt in source is outside the captured five target DWARF row universe.",
        };
    }
    ledger.dispositions = &dispositions;
    try policy.validate(gpa, ledger, "current", "0.16.0", items.items);
    for (&dispositions) |*disposition| {
        const reason = disposition.reason;
        disposition.reason = " \t\n";
        try std.testing.expectError(
            error.InvalidDisposition,
            policy.validate(gpa, ledger, "current", "0.16.0", items.items),
        );
        disposition.reason = reason;
    }
}

test "every inventory Zig source category survives unattributed accounting" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const inventory = try ev.sources(gpa, std.testing.io);
    const report: projection.Report = .{
        .version = 1,
        .tool = "ozai-zcov-raw",
        .summary = .{ .blocks_found = 1, .blocks_hit = 0, .lines_found = 0, .lines_hit = 0 },
        .files = &.{},
    };
    var items: std.ArrayList(policy.Item) = .empty;
    for (policy.modes) |mode| {
        items.clearRetainingCapacity();
        try collectItems(gpa, std.testing.io, report, mode, inventory, &items);
        var index: usize = 0;
        for (inventory) |source| {
            if (!std.mem.endsWith(u8, source.path, ".zig")) continue;
            try std.testing.expect(index < items.items.len);
            const item = items.items[index];
            try std.testing.expectEqualStrings(mode, item.mode);
            try std.testing.expectEqualStrings(source.path, item.path);
            try std.testing.expectEqualStrings(source.sha256, item.source_sha256);
            try std.testing.expectEqual(@as(u32, 0), item.line);
            try std.testing.expectEqualStrings("unattributed_file", item.unit);
            index += 1;
        }
        try std.testing.expectEqual(index, items.items.len);
    }
}

test "full DWARF row replay permits cold rows without instrumented PCs" {
    const gpa = std.testing.allocator;
    var builder: projection.Builder = .empty;
    defer builder.deinit(gpa);
    try builder.declare(gpa, "/root/src/a.zig", 4);
    try builder.declare(gpa, "/root/src/a.zig", 5);
    try builder.declare(gpa, "/root/src/a.zig", 9);
    try builder.add(gpa, "/root/src/a.zig", 4, true);
    const report = try builder.finish(gpa, .{ .found = 1, .hit = 1 });
    defer report.deinit(gpa);
    try std.testing.expectEqual(@as(u64, 3), report.summary.lines_found);
    try std.testing.expectEqual(@as(u64, 1), report.summary.blocks_found);
    const counters: raw.CounterSummary = .{
        .blocks_found = 1,
        .blocks_hit = 1,
        .unmapped_project_blocks = 0,
        .unmapped_project_hits = 0,
        .unowned_blocks = 0,
        .unowned_hits = 0,
    };
    const mode: ModeEvidence = .{
        .mode = "Debug",
        .report = .{ .path = "/scratch/report.json", .sha256 = "hash" },
        .blocks_found = 1,
        .blocks_hit = 1,
        .lines_found = 3,
        .lines_hit = 1,
        .unmapped_project_blocks = 0,
        .unmapped_project_hits = 0,
        .unowned_blocks = 0,
        .unowned_hits = 0,
    };
    try checkReplay(mode, report, .{ .report = report, .counters = counters });
    var forged = counters;
    forged.blocks_hit = 0;
    try std.testing.expectError(error.PartialMapping, checkCounters(report, forged));
    forged = counters;
    forged.unmapped_project_hits = 1;
    try std.testing.expectError(error.PartialMapping, checkCounters(report, forged));
    forged = counters;
    forged.unowned_hits = 1;
    try std.testing.expectError(error.PartialMapping, checkCounters(report, forged));
}
