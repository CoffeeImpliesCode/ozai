const std = @import("std");
const ev = @import("gate_evidence.zig");

pub const binary_names = [_][]const u8{
    "ozai-lib-test", "ozai-integration-test", "ozai-loopback-test",
    "ozai-protocol-test", "ozai-transfer-test", "ozai-two-process-test",
    "ozai-relay-wire-test", "ozai-portable-test", "ozai-quic-test",
    "ozai-invariants-test", "ozai-node", "ozai-coverage-policy-test",
    "ozai-project-gate-test",
};
pub const CounterSummary = struct { blocks_found: u64, blocks_hit: u64 };
const RawHeader = extern struct {
    magic: [4]u8, version: u32, slide: i64, num_pcs: u32, bin_path_len: u16,
};
const counters_max = 16 * 1024 * 1024;
const raws_max = 65536;
const Counter = struct { hit: bool = false, included: bool = true };
const Counters = std.AutoHashMapUnmanaged(u128, Counter);
const Cache = std.StringHashMapUnmanaged(usize);

pub fn audit(runner: ev.Runner, raw_paths: []const []const u8,
    expected: []const ev.Artifact) !CounterSummary
{
    if (raw_paths.len > raws_max or expected.len > binary_names.len)
        return error.EvidenceLimitExceeded;
    // The caller commonly owns an arena; audit storage must not survive this call.
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    var cache: Cache = .empty;
    var counters: Counters = .empty;
    const seen = try gpa.alloc(bool, expected.len);
    @memset(seen, false);
    for (raw_paths, 0..) |path, index| {
        try auditFile(runner, gpa, path, expected, seen, &cache, &counters, index);
    }
    try requireArtifacts(seen, raw_paths.len);
    return summarize(&counters);
}

fn auditFile(runner: ev.Runner, gpa: std.mem.Allocator, path: []const u8,
    expected: []const ev.Artifact, seen: []bool, cache: *Cache,
    counters: *Counters, index: usize) !void
{
    // Reset raw bytes, command output and argument strings after every raw file.
    var temporary = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer temporary.deinit();
    var local = runner;
    local.gpa = temporary.allocator();
    const bytes = try ev.readFile(local.gpa, local.io, path);
    const header = try parseHeader(bytes);
    const path_end = @sizeOf(RawHeader) + @as(usize, header.bin_path_len);
    const binary = bytes[@sizeOf(RawHeader)..path_end];
    const identity = try binaryIdentity(local, gpa, binary, expected, seen, cache);
    try auditPCs(local, binary, header, bytes[path_end..], identity, index, gpa, counters);
}

fn parseHeader(bytes: []const u8) !RawHeader {
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

fn binaryIdentity(runner: ev.Runner, gpa: std.mem.Allocator, binary: []const u8,
    expected: []const ev.Artifact, seen: []bool, cache: *Cache) !usize
{
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
    const result = try runner.run(try std.fmt.allocPrint(runner.gpa,
        "dwarf-{d}", .{identity}), &.{ "llvm-dwarfdump", "--verify", binary });
    _ = result;
    try cache.put(gpa, try gpa.dupe(u8, binary), identity);
    return identity;
}

fn auditPCs(runner: ev.Runner, binary: []const u8, header: RawHeader, data: []const u8,
    identity: usize, index: usize, gpa: std.mem.Allocator, counters: *Counters) !void
{
    const hits = data[@as(usize, header.num_pcs) * 8 ..];
    var argv: std.ArrayList([]const u8) = .empty;
    try argv.appendSlice(runner.gpa, &.{ "addr2line", "-e", binary });
    var cwd_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const cwd = cwd_buffer[0..try std.Io.Dir.cwd().realPath(runner.io, &cwd_buffer)];
    for (0..header.num_pcs) |i| {
        const pc = try adjustedPC(std.mem.readInt(u64, data[i * 8 ..][0..8], .little),
            header.slide);
        if (try mergeCounter(gpa, counters, identity, pc, hits[i] != 0)) {
            try argv.append(runner.gpa, try std.fmt.allocPrint(runner.gpa, "0x{x}", .{pc}));
            if (argv.items.len == 259)
                try mapBatch(runner, &argv, index, i, identity, counters, cwd);
        }
    }
    if (argv.items.len > 3)
        try mapBatch(runner, &argv, index, header.num_pcs, identity, counters, cwd);
}

fn mapBatch(runner: ev.Runner, argv: *std.ArrayList([]const u8),
    index: usize, offset: usize, identity: usize, counters: *Counters, cwd: []const u8) !void
{
    const result = try runner.run(try std.fmt.allocPrint(runner.gpa,
        "map-{d}-{d}", .{ index, offset }), argv.items);
    try checkMapping(result.stdout, argv.items.len - 3);
    var lines = std.mem.tokenizeScalar(u8, result.stdout, '\n');
    for (argv.items[3..]) |address| {
        const line = lines.next().?;
        const separator = std.mem.lastIndexOfScalar(u8, line, ':').?;
        const pc = try std.fmt.parseInt(u64, address[2..], 16);
        counters.getPtr((@as(u128, identity) << 64) | pc).?.included =
            projectPath(line[0..separator], cwd);
    }
    argv.shrinkRetainingCapacity(3);
}

fn adjustedPC(pc: u64, slide: i64) !u64 {
    const adjusted: i128 = @as(i128, pc) - slide;
    if (adjusted < 0 or adjusted > std.math.maxInt(u64)) return error.PartialMapping;
    return @intCast(adjusted);
}

fn mergeCounter(gpa: std.mem.Allocator, counters: *Counters,
    identity: usize, pc: u64, hit: bool) !bool
{
    const key = (@as(u128, identity) << 64) | pc;
    if (!counters.contains(key) and counters.count() >= counters_max)
        return error.EvidenceLimitExceeded;
    const entry = try counters.getOrPut(gpa, key);
    if (!entry.found_existing) entry.value_ptr.* = .{};
    entry.value_ptr.hit = entry.value_ptr.hit or hit;
    return !entry.found_existing;
}

fn summarize(counters: *Counters) CounterSummary {
    var summary: CounterSummary = .{ .blocks_found = 0, .blocks_hit = 0 };
    var iterator = counters.valueIterator();
    for (0..counters.count()) |_| {
        const counter = iterator.next().?.*;
        if (counter.included) {
            summary.blocks_found += 1;
            if (counter.hit) summary.blocks_hit += 1;
        }
    }
    return summary;
}

fn projectPath(path: []const u8, cwd: []const u8) bool {
    if (!std.fs.path.isAbsolute(path)) return true;
    if (!std.mem.startsWith(u8, path, cwd)) return false;
    return path.len == cwd.len or path[cwd.len] == '/';
}

fn checkMapping(text: []const u8, expected: usize) !void {
    var count: usize = 0;
    var lines = std.mem.tokenizeScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (count >= expected or std.mem.indexOf(u8, line, "??") != null)
            return error.PartialMapping;
        const separator = std.mem.lastIndexOfScalar(u8, line, ':') orelse
            return error.PartialMapping;
        const number = std.mem.sliceTo(line[separator + 1 ..], ' ');
        if ((std.fmt.parseInt(u32, number, 10) catch return error.PartialMapping) == 0)
            return error.PartialMapping;
        count += 1;
    }
    if (count != expected) return error.PartialMapping;
}

fn requireArtifacts(seen: []const bool, raw_count: usize) !void {
    if (raw_count == 0) return error.MissingArtifact;
    for (seen) |present| {
        if (!present) return error.MissingArtifact;
    }
}

test "partial address mapping fails even with plausible known lines" {
    try std.testing.expectError(error.PartialMapping, checkMapping("src/a.zig:4\n??:0\n", 2));
    try std.testing.expectError(error.PartialMapping, checkMapping("src/a.zig:4\n", 2));
}

test "missing expected binary raw evidence fails" {
    try std.testing.expectError(error.MissingArtifact, requireArtifacts(&.{ true, false, true }, 12));
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
    try std.testing.expect(try mergeCounter(gpa, &counters, 0, try adjustedPC(0x1010, 0x1000), false));
    try std.testing.expect(!try mergeCounter(gpa, &counters, 0, try adjustedPC(0x2010, 0x2000), true));
    try std.testing.expect(!try mergeCounter(gpa, &counters, 0, 0x10, false));
    try std.testing.expect(try mergeCounter(gpa, &counters, 1, 0x10, false));
    try std.testing.expectEqual(CounterSummary{ .blocks_found = 2, .blocks_hit = 1 }, summarize(&counters));
    try std.testing.expectError(error.PartialMapping, adjustedPC(0, 1));
    try std.testing.expectError(error.PartialMapping, adjustedPC(std.math.maxInt(u64), -1));
}

test "external blocks are audited but excluded from project summary" {
    const gpa = std.testing.allocator;
    var counters: Counters = .empty;
    defer counters.deinit(gpa);
    try std.testing.expect(try mergeCounter(gpa, &counters, 0, 10, true));
    try std.testing.expect(try mergeCounter(gpa, &counters, 0, 20, false));
    counters.getPtr(10).?.included = projectPath("/opt/zig/lib/std/a.zig", "/project");
    counters.getPtr(20).?.included = projectPath("/project/src/a.zig", "/project");
    try std.testing.expect(!try mergeCounter(gpa, &counters, 0, 10, false));
    try std.testing.expectEqual(CounterSummary{
        .blocks_found = 1, .blocks_hit = 0,
    }, summarize(&counters));
    try std.testing.expect(!projectPath("/project2/src/a.zig", "/project"));
    try std.testing.expect(projectPath("src/a.zig", "/project"));
}

test "raw header truncation and unsupported versions fail closed" {
    try std.testing.expectError(error.IncompleteRaw, parseHeader("ZCOV"));
    const header: RawHeader = .{
        .magic = "ZCOV".*, .version = 3, .slide = 0, .num_pcs = 1, .bin_path_len = 1,
    };
    try std.testing.expectError(error.IncompleteRaw, parseHeader(std.mem.asBytes(&header)));
}
