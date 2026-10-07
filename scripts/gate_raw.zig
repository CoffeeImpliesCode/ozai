const std = @import("std");
const ev = @import("gate_evidence.zig");
const mapping = @import("gate_raw_mapping.zig");
const projection = @import("gate_projection.zig");
const dwarf_universe = @import("gate_dwarf_universe.zig");
const files = @import("gate_files.zig");

pub const AuditError = std.mem.Allocator.Error || std.process.CurrentPathAllocError ||
    files.ReadFileError || files.HashFileError || ev.RunError || dwarf_universe.Error ||
    mapping.Error || error{
    EvidenceLimitExceeded,
    IncompleteRaw,
    MissingArtifact,
    UnexpectedBinary,
    PartialMapping,
    InvalidCharacter,
    Overflow,
};
const BinaryIdentityError = std.mem.Allocator.Error || files.HashFileError ||
    ev.RunError || dwarf_universe.Error || error{ EvidenceLimitExceeded, UnexpectedBinary };
const MapError = std.mem.Allocator.Error || ev.RunError || mapping.Error ||
    error{ EvidenceLimitExceeded, PartialMapping, InvalidCharacter, Overflow };
const AuditFileError = files.ReadFileError || BinaryIdentityError || MapError ||
    error{IncompleteRaw};

pub const binary_names = [_][]const u8{
    "ozai-lib-test",          "ozai-integration-test", "ozai-loopback-test",
    "ozai-protocol-test",     "ozai-transfer-test",    "ozai-two-process-test",
    "ozai-relay-wire-test",   "ozai-portable-test",    "ozai-quic-test",
    "ozai-invariants-test",   "ozai-node",             "ozai-coverage-policy-test",
    "ozai-project-gate-test",
};
pub const CounterSummary = struct {
    blocks_found: u64,
    blocks_hit: u64,
    unmapped_project_blocks: u64,
    unmapped_project_hits: u64,
    unowned_blocks: u64,
    unowned_hits: u64,
};

/// Raw counter ownership and its authoritative source projection.
/// `report` belongs to `runner.gpa`; the caller releases it exactly once with `deinit`.
pub const Audit = struct { counters: CounterSummary, report: projection.Report };
const RawHeader = extern struct {
    magic: [4]u8,
    version: u32,
    slide: i64,
    num_pcs: u32,
    bin_path_len: u16,
};
const counters_max = 16 * 1024 * 1024;
const raws_max = 65536;
const Counter = struct {
    hit: bool = false,
    mapping: mapping.ParsedMapping = .{ .category = .project_line },
};
const Counters = std.AutoHashMapUnmanaged(u128, Counter);
const Cache = std.StringHashMapUnmanaged(usize);

/// Validates raw/binary/DWARF evidence and retains every positive project DWARF row.
/// OR-merged unique direct PCs supply hits; unknown project lines supply only block counts.
/// Returns deep-owned report storage in `runner.gpa`; private scratch is freed before return.
pub fn audit(
    runner: ev.Runner,
    raw_paths: []const []const u8,
    expected: []const ev.Artifact,
) AuditError!Audit {
    if (raw_paths.len > raws_max or expected.len > binary_names.len)
        return error.EvidenceLimitExceeded;
    // The caller commonly owns an arena; audit storage must not survive this call.
    var arena = std.heap.ArenaAllocator.init(runner.gpa);
    defer arena.deinit();
    const gpa = arena.allocator();
    const cwd = try std.process.currentPathAlloc(runner.io, gpa);
    var cache: Cache = .empty;
    var counters: Counters = .empty;
    var paths: projection.Paths = .empty;
    var builder: projection.Builder = .empty;
    const seen = try gpa.alloc(bool, expected.len);
    @memset(seen, false);
    for (raw_paths, 0..) |path, index| {
        try auditFile(
            gpa,
            runner,
            path,
            expected,
            seen,
            &cache,
            &counters,
            &paths,
            &builder,
            index,
            cwd,
        );
    }
    try requireArtifacts(seen, raw_paths.len);
    const summary = summarize(&counters);
    return .{
        .counters = summary,
        .report = try projectReport(runner.gpa, gpa, &builder, &counters, summary),
    };
}

fn auditFile(
    gpa: std.mem.Allocator,
    runner: ev.Runner,
    path: []const u8,
    expected: []const ev.Artifact,
    seen: []bool,
    cache: *Cache,
    counters: *Counters,
    paths: *projection.Paths,
    builder: *projection.Builder,
    index: usize,
    cwd: []const u8,
) AuditFileError!void {
    // Reset raw bytes, command output and argument strings after every raw file.
    var temporary = std.heap.ArenaAllocator.init(runner.gpa);
    defer temporary.deinit();
    var local = runner;
    local.gpa = temporary.allocator();
    const bytes = try ev.readFile(local.gpa, local.io, path);
    const header = try parseHeader(bytes);
    const path_end = @sizeOf(RawHeader) + @as(usize, header.bin_path_len);
    const binary = bytes[@sizeOf(RawHeader)..path_end];
    const identity = try binaryIdentity(
        gpa,
        local,
        binary,
        expected,
        seen,
        cache,
        paths,
        builder,
        cwd,
    );
    // Source ownership context comes from the verified binary, not a symbolizer label.
    const options: mapping.Options = .{
        .cwd = cwd,
        .binary_basename = std.fs.path.basename(binary),
    };
    try auditPCs(
        gpa,
        local,
        binary,
        header,
        bytes[path_end..],
        identity,
        index,
        counters,
        paths,
        options,
    );
}

fn parseHeader(bytes: []const u8) error{IncompleteRaw}!RawHeader {
    if (bytes.len < @sizeOf(RawHeader)) return error.IncompleteRaw;
    const header = std.mem.bytesToValue(RawHeader, bytes[0..@sizeOf(RawHeader)]);
    if (!std.mem.eql(u8, &header.magic, "ZCOV") or header.version != 2 or
        header.num_pcs == 0 or header.num_pcs > counters_max or header.bin_path_len == 0)
        return error.IncompleteRaw;
    const size = @sizeOf(RawHeader) + @as(u64, header.bin_path_len) +
        @as(u64, header.num_pcs) * 9;
    if (bytes.len != size) return error.IncompleteRaw;
    return header;
}

fn binaryIdentity(
    gpa: std.mem.Allocator,
    runner: ev.Runner,
    binary: []const u8,
    expected: []const ev.Artifact,
    seen: []bool,
    cache: *Cache,
    paths: *projection.Paths,
    builder: *projection.Builder,
    project_root: []const u8,
) BinaryIdentityError!usize {
    if (cache.get(binary)) |identity| return identity;
    if (cache.count() >= raws_max) return error.EvidenceLimitExceeded;
    const current = try ev.artifact(runner.gpa, runner.io, binary);
    var matched = false;
    for (expected, 0..) |wanted, i| {
        if (std.mem.eql(u8, current.sha256, wanted.sha256)) {
            seen[i] = true;
            matched = true;
        }
    }
    if (!matched) return error.UnexpectedBinary;
    const identity = cache.count();
    const result = try runner.run(
        try std.fmt.allocPrint(runner.gpa, "dwarf-{d}", .{identity}),
        &.{ "llvm-dwarfdump", "--verify", binary },
    );
    defer runner.gpa.free(result.stdout);
    defer runner.gpa.free(result.stderr);
    try dwarf_universe.collect(gpa, runner.io, .{
        .binary_path = binary,
        .project_root = project_root,
    }, paths, builder);
    const key = try gpa.dupe(u8, binary);
    errdefer gpa.free(key);
    try cache.put(gpa, key, identity);
    return identity;
}

fn auditPCs(
    gpa: std.mem.Allocator,
    runner: ev.Runner,
    binary: []const u8,
    header: RawHeader,
    data: []const u8,
    identity: usize,
    index: usize,
    counters: *Counters,
    paths: *projection.Paths,
    options: mapping.Options,
) MapError!void {
    const hits = data[@as(usize, header.num_pcs) * 8 ..];
    var argv: std.ArrayList([]const u8) = .empty;
    try argv.appendSlice(runner.gpa, &.{ "addr2line", "-e", binary });
    for (0..header.num_pcs) |i| {
        const pc = try adjustedPc(
            std.mem.readInt(u64, data[i * 8 ..][0..8], .little),
            header.slide,
        );
        if (try mergeCounter(gpa, counters, identity, pc, hits[i] != 0)) {
            try argv.append(runner.gpa, try std.fmt.allocPrint(runner.gpa, "0x{x}", .{pc}));
            if (argv.items.len == 259)
                try mapBatch(gpa, runner, &argv, index, i, identity, counters, paths, options);
        }
    }
    if (argv.items.len > 3)
        try mapBatch(
            gpa,
            runner,
            &argv,
            index,
            header.num_pcs,
            identity,
            counters,
            paths,
            options,
        );
}

fn mapBatch(
    gpa: std.mem.Allocator,
    runner: ev.Runner,
    argv: *std.ArrayList([]const u8),
    index: usize,
    offset: usize,
    identity: usize,
    counters: *Counters,
    paths: *projection.Paths,
    options: mapping.Options,
) MapError!void {
    const result = try runner.run(
        try std.fmt.allocPrint(runner.gpa, "map-{d}-{d}", .{ index, offset }),
        argv.items,
    );
    try mapping.checkMapping(result.stdout, argv.items.len - 3, options);
    var lines = std.mem.tokenizeScalar(u8, result.stdout, '\n');
    for (argv.items[3..]) |address| {
        const line = lines.next() orelse return error.PartialMapping;
        const pc = try std.fmt.parseInt(u64, address, 0);
        const counter = counters.getPtr((@as(u128, identity) << 64) | pc) orelse
            return error.PartialMapping;
        // Pure borrowed-string parsing has no allocator or command-argument storage to grow.
        // zbc-disable-next-line: slice-loop-reentrant-grow
        const parsed = try mapping.parseMapping(line, options);
        const source = if (parsed.path) |path| try paths.intern(gpa, path, options.cwd) else null;
        counter.mapping = .{
            .category = parsed.category,
            .path = source,
            .line = parsed.line,
        };
    }
    argv.shrinkRetainingCapacity(3);
}

fn adjustedPc(pc: u64, slide: i64) error{PartialMapping}!u64 {
    const adjusted: i128 = @as(i128, pc) - slide;
    if (adjusted < 0 or adjusted > std.math.maxInt(u64)) return error.PartialMapping;
    return @intCast(adjusted);
}

fn mergeCounter(
    gpa: std.mem.Allocator,
    counters: *Counters,
    identity: usize,
    pc: u64,
    hit: bool,
) (std.mem.Allocator.Error || error{EvidenceLimitExceeded})!bool {
    const key = (@as(u128, identity) << 64) | pc;
    if (!counters.contains(key) and counters.count() >= counters_max)
        return error.EvidenceLimitExceeded;
    const entry = try counters.getOrPut(gpa, key);
    if (!entry.found_existing) entry.value_ptr.* = .{};
    entry.value_ptr.hit = entry.value_ptr.hit or hit;
    return !entry.found_existing;
}

fn summarize(counters: *Counters) CounterSummary {
    var summary: CounterSummary = .{
        .blocks_found = 0,
        .blocks_hit = 0,
        .unmapped_project_blocks = 0,
        .unmapped_project_hits = 0,
        .unowned_blocks = 0,
        .unowned_hits = 0,
    };
    var iterator = counters.valueIterator();
    while (iterator.next()) |counter| {
        if (counter.mapping.category == .unowned) {
            summary.unowned_blocks += 1;
            if (counter.hit) summary.unowned_hits += 1;
            continue;
        }
        if (counter.mapping.category != .external) {
            summary.blocks_found += 1;
            if (counter.hit) summary.blocks_hit += 1;
        }
        if (counter.mapping.category == .project_unknown) {
            // Unknown project lines contribute blocks without any numbered source-line claim.
            summary.unmapped_project_blocks += 1;
            if (counter.hit) summary.unmapped_project_hits += 1;
        }
    }
    return summary;
}

fn projectReport(
    gpa: std.mem.Allocator,
    scratch: std.mem.Allocator,
    builder: *projection.Builder,
    counters: *const Counters,
    summary: CounterSummary,
) (std.mem.Allocator.Error || error{ EvidenceLimitExceeded, PartialMapping })!projection.Report {
    var iterator = counters.valueIterator();
    while (iterator.next()) |counter| {
        if (counter.mapping.category != .project_line) continue;
        const path = counter.mapping.path orelse return error.PartialMapping;
        const line = counter.mapping.line orelse return error.PartialMapping;
        try builder.add(scratch, path, line, counter.hit);
    }
    return builder.finish(gpa, .{ .found = summary.blocks_found, .hit = summary.blocks_hit });
}

fn requireArtifacts(seen: []const bool, raw_count: usize) error{MissingArtifact}!void {
    if (raw_count == 0) return error.MissingArtifact;
    for (seen) |present| {
        if (!present) return error.MissingArtifact;
    }
}

test "missing expected binary raw evidence fails" {
    try std.testing.expectError(
        error.MissingArtifact,
        requireArtifacts(&.{ true, false, true }, 12),
    );
    try std.testing.expectError(error.MissingArtifact, requireArtifacts(&.{ true, true }, 0));
}

test "binary cache uses actual path rather than shared content identity" {
    const gpa = std.testing.allocator;
    var cache: Cache = .empty;
    defer cache.deinit(gpa);
    try std.testing.expectEqual(@as(?usize, null), cache.get("/first/node"));
    try cache.put(gpa, "/first/node", 0);
    try std.testing.expectEqual(@as(?usize, 0), cache.get("/first/node"));
    try std.testing.expectEqual(@as(?usize, null), cache.get("/second/node"));
}

test "repeated slid PCs merge hits and map only unseen binary PCs" {
    const gpa = std.testing.allocator;
    var counters: Counters = .empty;
    defer counters.deinit(gpa);
    try std.testing.expect(
        try mergeCounter(
            gpa,
            &counters,
            0,
            try adjustedPc(0x1010, 0x1000),
            false,
        ),
    );
    try std.testing.expect(!try mergeCounter(
        gpa,
        &counters,
        0,
        try adjustedPc(0x2010, 0x2000),
        true,
    ));
    try std.testing.expect(!try mergeCounter(gpa, &counters, 0, 0x10, false));
    try std.testing.expect(try mergeCounter(gpa, &counters, 1, 0x10, false));
    try std.testing.expectEqual(CounterSummary{
        .blocks_found = 2,
        .blocks_hit = 1,
        .unmapped_project_blocks = 0,
        .unmapped_project_hits = 0,
        .unowned_blocks = 0,
        .unowned_hits = 0,
    }, summarize(&counters));
    try std.testing.expectError(error.PartialMapping, adjustedPc(0, 1));
    try std.testing.expectError(error.PartialMapping, adjustedPc(std.math.maxInt(u64), -1));
}

test "external blocks are audited but excluded from project summary" {
    const options: mapping.Options = .{ .cwd = "/project", .binary_basename = "ozai-test" };
    const gpa = std.testing.allocator;
    var counters: Counters = .empty;
    defer counters.deinit(gpa);
    try std.testing.expect(try mergeCounter(gpa, &counters, 0, 10, true));
    try std.testing.expect(try mergeCounter(gpa, &counters, 0, 20, false));
    const external = counters.getPtr(10) orelse return error.TestUnexpectedResult;
    external.mapping = try mapping.parseMapping("/opt/zig/lib/std/a.zig:4", options);
    const project = counters.getPtr(20) orelse return error.TestUnexpectedResult;
    project.mapping = try mapping.parseMapping("/project/src/a.zig:4", options);
    try std.testing.expect(!try mergeCounter(gpa, &counters, 0, 10, false));
    try std.testing.expectEqual(CounterSummary{
        .blocks_found = 1,
        .blocks_hit = 0,
        .unmapped_project_blocks = 0,
        .unmapped_project_hits = 0,
        .unowned_blocks = 0,
        .unowned_hits = 0,
    }, summarize(&counters));
}

test "unknown project source locations remain in block totals without line claims" {
    const options: mapping.Options = .{ .cwd = "/project", .binary_basename = "ozai-test" };
    const gpa = std.testing.allocator;
    var counters: Counters = .empty;
    defer counters.deinit(gpa);
    try std.testing.expect(try mergeCounter(gpa, &counters, 0, 10, false));
    const runner_counter = counters.getPtr(10) orelse return error.TestUnexpectedResult;
    runner_counter.mapping =
        try mapping.parseMapping("/project/test/expected_log_runner.zig:?", options);
    try std.testing.expect(!try mergeCounter(gpa, &counters, 0, 10, true));
    try std.testing.expect(!try mergeCounter(gpa, &counters, 0, 10, false));
    try std.testing.expect(try mergeCounter(gpa, &counters, 0, 20, false));
    const project = counters.getPtr(20) orelse return error.TestUnexpectedResult;
    project.mapping = try mapping.parseMapping("/project/src/a.zig:?", options);
    try std.testing.expect(try mergeCounter(gpa, &counters, 0, 30, true));
    const external = counters.getPtr(30) orelse return error.TestUnexpectedResult;
    external.mapping = try mapping.parseMapping("/opt/zig/std/a.zig:?", options);
    try std.testing.expect(try mergeCounter(gpa, &counters, 0, 40, true));
    const known_project = counters.getPtr(40) orelse return error.TestUnexpectedResult;
    known_project.mapping = try mapping.parseMapping("src/a.zig:4", options);
    try std.testing.expectEqual(CounterSummary{
        .blocks_found = 3,
        .blocks_hit = 2,
        .unmapped_project_blocks = 2,
        .unmapped_project_hits = 1,
        .unowned_blocks = 0,
        .unowned_hits = 0,
    }, summarize(&counters));
}

test "raw header truncation and unsupported versions fail closed" {
    try std.testing.expectError(error.IncompleteRaw, parseHeader("ZCOV"));
    const header: RawHeader = .{
        .magic = "ZCOV".*,
        .version = 3,
        .slide = 0,
        .num_pcs = 1,
        .bin_path_len = 1,
    };
    try std.testing.expectError(error.IncompleteRaw, parseHeader(std.mem.asBytes(&header)));
}

test "unowned PCs merge hits uniquely without inflating project block totals" {
    // Binary-CU unknown PCs retain unique hit bits only in source-unowned counters.
    const options: mapping.Options = .{ .cwd = "/project", .binary_basename = "ozai-test" };
    const gpa = std.testing.allocator;
    var counters: Counters = .empty;
    defer counters.deinit(gpa);
    try std.testing.expect(try mergeCounter(gpa, &counters, 0, 1, false));
    const unowned = counters.getPtr(1) orelse return error.TestUnexpectedResult;
    unowned.mapping = try mapping.parseMapping("??:0", options);
    try std.testing.expect(!try mergeCounter(gpa, &counters, 0, 1, true));
    try std.testing.expect(!try mergeCounter(gpa, &counters, 0, 1, false));
    try std.testing.expect(try mergeCounter(gpa, &counters, 1, 1, false));
    const second = counters.getPtr((@as(u128, 1) << 64) | 1) orelse
        return error.TestUnexpectedResult;
    second.mapping = try mapping.parseMapping("??:0", options);
    try std.testing.expect(try mergeCounter(gpa, &counters, 0, 2, false));
    const binary_unknown = counters.getPtr(2) orelse return error.TestUnexpectedResult;
    binary_unknown.mapping = try mapping.parseMapping("ozai-test:?", options);
    try std.testing.expect(!try mergeCounter(gpa, &counters, 0, 2, true));
    try std.testing.expect(!try mergeCounter(gpa, &counters, 0, 2, false));
    try std.testing.expect(try mergeCounter(gpa, &counters, 1, 2, false));
    const second_binary = counters.getPtr((@as(u128, 1) << 64) | 2) orelse
        return error.TestUnexpectedResult;
    second_binary.mapping = try mapping.parseMapping("other-test:?", .{
        .cwd = "/project",
        .binary_basename = "other-test",
    });
    try std.testing.expect(try mergeCounter(gpa, &counters, 0, 20, true));
    const project = counters.getPtr(20) orelse return error.TestUnexpectedResult;
    project.mapping = try mapping.parseMapping("src/a.zig:4", options);
    try std.testing.expect(try mergeCounter(gpa, &counters, 0, 30, true));
    const unknown_project = counters.getPtr(30) orelse return error.TestUnexpectedResult;
    unknown_project.mapping = try mapping.parseMapping("/project/src/b.zig:?", options);
    try std.testing.expectEqual(CounterSummary{
        .blocks_found = 2,
        .blocks_hit = 2,
        .unmapped_project_blocks = 1,
        .unmapped_project_hits = 1,
        .unowned_blocks = 4,
        .unowned_hits = 2,
    }, summarize(&counters));
}

test "raw counter count must exactly match complete PC and hit arrays" {
    var header: RawHeader = .{
        .magic = "ZCOV".*,
        .version = 2,
        .slide = 0,
        .num_pcs = 1,
        .bin_path_len = 1,
    };
    var bytes: [@sizeOf(RawHeader) + 1 + 9 + 1]u8 = @splat(0);
    @memcpy(bytes[0..@sizeOf(RawHeader)], std.mem.asBytes(&header));
    try std.testing.expectEqual(
        header.num_pcs,
        (try parseHeader(bytes[0 .. bytes.len - 1])).num_pcs,
    );
    try std.testing.expectError(error.IncompleteRaw, parseHeader(bytes[0 .. bytes.len - 2]));
    try std.testing.expectError(error.IncompleteRaw, parseHeader(&bytes));
    header.num_pcs = 2;
    @memcpy(bytes[0..@sizeOf(RawHeader)], std.mem.asBytes(&header));
    try std.testing.expectError(error.IncompleteRaw, parseHeader(bytes[0 .. bytes.len - 1]));
    header.num_pcs = 0;
    @memcpy(bytes[0..@sizeOf(RawHeader)], std.mem.asBytes(&header));
    try std.testing.expectError(error.IncompleteRaw, parseHeader(bytes[0 .. bytes.len - 1]));
}

test "projected hits observe final OR merge once for each binary PC" {
    const gpa = std.testing.allocator;
    var counters: Counters = .empty;
    defer counters.deinit(gpa);
    const options: mapping.Options = .{ .cwd = "/project", .binary_basename = "ozai-test" };
    try std.testing.expect(try mergeCounter(gpa, &counters, 0, 10, false));
    const first_pc = counters.getPtr(10) orelse return error.TestUnexpectedResult;
    first_pc.mapping = try mapping.parseMapping("/project/src/a.zig:4", options);
    try std.testing.expect(!try mergeCounter(gpa, &counters, 0, 10, true));
    try std.testing.expect(!try mergeCounter(gpa, &counters, 0, 10, true));
    try std.testing.expect(try mergeCounter(gpa, &counters, 0, 20, true));
    const second_pc = counters.getPtr(20) orelse return error.TestUnexpectedResult;
    second_pc.mapping = try mapping.parseMapping("/project/src/a.zig:4", options);
    try std.testing.expect(try mergeCounter(gpa, &counters, 1, 10, true));
    const other_binary_pc = counters.getPtr((@as(u128, 1) << 64) | 10) orelse
        return error.TestUnexpectedResult;
    other_binary_pc.mapping = try mapping.parseMapping("/project/src/a.zig:4", options);
    var builder: projection.Builder = .empty;
    defer builder.deinit(gpa);
    try builder.declare(gpa, "/project/src/a.zig", 4);
    try builder.declare(gpa, "/project/src/a.zig", 9);
    try builder.declare(gpa, "/project/src/a.zig", 9);
    const report = try projectReport(gpa, gpa, &builder, &counters, summarize(&counters));
    defer report.deinit(gpa);
    try std.testing.expectEqual(@as(u64, 3), report.summary.blocks_found);
    try std.testing.expectEqual(@as(u64, 3), report.summary.blocks_hit);
    try std.testing.expectEqual(@as(u64, 2), report.summary.lines_found);
    try std.testing.expectEqual(@as(u64, 1), report.summary.lines_hit);
    try std.testing.expectEqual(projection.Line{ .line = 4, .hits = 3 }, report.files[0].lines[0]);
    try std.testing.expectEqual(projection.Line{ .line = 9, .hits = 0 }, report.files[0].lines[1]);
    try std.testing.expectEqual(@as(usize, 3), builder.pcs);
}

test "unknown project blocks external and unowned PCs never claim numbered rows" {
    const gpa = std.testing.allocator;
    var counters: Counters = .empty;
    defer counters.deinit(gpa);
    const options: mapping.Options = .{ .cwd = "/project", .binary_basename = "ozai-test" };
    for ([_][]const u8{
        "/project/src/a.zig:?", "/opt/zig/std/a.zig:4", "??:0", "ozai-test:?",
    }, 0..) |row, pc| {
        try std.testing.expect(try mergeCounter(gpa, &counters, 0, pc, true));
        const counter = counters.getPtr(pc) orelse return error.TestUnexpectedResult;
        counter.mapping = try mapping.parseMapping(row, options);
    }
    const summary = summarize(&counters);
    var builder: projection.Builder = .empty;
    defer builder.deinit(gpa);
    const report = try projectReport(gpa, gpa, &builder, &counters, summary);
    defer report.deinit(gpa);
    try std.testing.expectEqual(@as(u64, 1), summary.blocks_found);
    try std.testing.expectEqual(@as(u64, 1), summary.unmapped_project_blocks);
    try std.testing.expectEqual(@as(u64, 2), summary.unowned_blocks);
    try std.testing.expectEqual(@as(usize, 0), report.files.len);
    try std.testing.expectEqual(@as(u64, 0), report.summary.lines_found);
}

test "merged unknown project PCs leave declared numeric DWARF rows cold" {
    const gpa = std.testing.allocator;
    var counters: Counters = .empty;
    defer counters.deinit(gpa);
    var builder: projection.Builder = .empty;
    defer builder.deinit(gpa);
    try builder.declare(gpa, "/project/src/a.zig", 4);
    try builder.declare(gpa, "/project/src/a.zig", 9);
    const options: mapping.Options = .{ .cwd = "/project", .binary_basename = "ozai-test" };
    try std.testing.expect(try mergeCounter(gpa, &counters, 0, 10, false));
    const unknown_project = counters.getPtr(10) orelse return error.TestUnexpectedResult;
    unknown_project.mapping = try mapping.parseMapping("/project/src/a.zig:?", options);
    try std.testing.expect(!try mergeCounter(gpa, &counters, 0, 10, true));
    try std.testing.expect(!try mergeCounter(gpa, &counters, 0, 10, false));
    try std.testing.expect(try mergeCounter(gpa, &counters, 0, 20, false));
    const known_project = counters.getPtr(20) orelse return error.TestUnexpectedResult;
    known_project.mapping = try mapping.parseMapping("/project/src/a.zig:4", options);
    const summary = summarize(&counters);
    try std.testing.expectEqual(CounterSummary{
        .blocks_found = 2,
        .blocks_hit = 1,
        .unmapped_project_blocks = 1,
        .unmapped_project_hits = 1,
        .unowned_blocks = 0,
        .unowned_hits = 0,
    }, summary);
    const report = try projectReport(gpa, gpa, &builder, &counters, summary);
    defer report.deinit(gpa);
    try std.testing.expectEqual(@as(u64, 2), report.summary.lines_found);
    try std.testing.expectEqual(@as(u64, 0), report.summary.lines_hit);
    try std.testing.expectEqual(@as(u64, 2), report.summary.blocks_found);
    try std.testing.expectEqual(@as(u64, 1), report.summary.blocks_hit);
    try std.testing.expectEqual(projection.Line{ .line = 4, .hits = 0 }, report.files[0].lines[0]);
    try std.testing.expectEqual(projection.Line{ .line = 9, .hits = 0 }, report.files[0].lines[1]);
    try std.testing.expectEqual(@as(usize, 1), builder.pcs);
}
