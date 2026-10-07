const std = @import("std");
const ozai = @import("ozai");
const node_child = @import("two_process_child.zig");
const rust_child = @import("rust_interop_child.zig");
const t = std.testing;

// These cases compare actual production CLI output with upstream-captured payload bytes.
test "stock Rust blob provider serves whole cross-group and partial-tail Node gets" {
    for (cases) |case| try runCase(.rust_provider, case);
}

test "production Node blob provider serves whole cross-group and partial-tail Rust gets" {
    for (cases) |case| try runCase(.node_provider, case);
}

const Direction = enum { rust_provider, node_provider };
const Case = struct { range: []const u8, start: usize, end: usize };
const cases = [_]Case{
    .{ .range = "all", .start = 0, .end = 49_189 },
    .{ .range = "15:18", .start = 15_360, .end = 18_432 },
    .{ .range = "47:49", .start = 48_128, .end = 49_189 },
};

const data = @embedFile("fixtures/blobs/data49189.bin");
const root = @embedFile("fixtures/blobs/root32.bin");
const outboard = @embedFile("fixtures/blobs/outboard.bin");
const node_tag = 0x51;
const rust_tag = 0x6c;
const deadline_ms = 20_000;

fn runCase(direction: Direction, case: Case) !void {
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var temporary = t.tmpDir(.{});
    defer temporary.cleanup();
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const directory = path_buffer[0..try temporary.dir.realPath(t.io, &path_buffer)];
    try t.expectEqual(@as(usize, 49_189), data.len);
    try t.expectEqual(@as(usize, 32), root.len);
    for (data, 0..) |byte, i| {
        try t.expectEqual(@as(u8, @intCast((i * 31 + i / 1024) % 251)), byte);
    }
    const hash = hex(root);
    try temporary.dir.writeFile(t.io, .{
        .sub_path = try std.fmt.allocPrint(allocator, "{s}.data", .{hash}),
        .data = data,
    });
    try temporary.dir.writeFile(t.io, .{
        .sub_path = try std.fmt.allocPrint(allocator, "{s}.outboard", .{hash}),
        .data = outboard,
    });
    const output = try std.fmt.allocPrint(allocator, "{s}/download.bin", .{directory});
    var node_key = try ozai.SecretKey.fromSeed(@splat(node_tag));
    defer node_key.deinit();
    var rust_key = try ozai.SecretKey.fromSeed(@splat(rust_tag));
    defer rust_key.deinit();
    const node_hex = rust_child.hexId(node_key.nodeId());
    const rust_bytes = rust_key.nodeId().toBytes();
    const rust_z32 = ozai.base32.encode(ozai.base32.z32, 32, &rust_bytes);
    const summary = try std.fmt.allocPrint(
        allocator, "blob verified hash {s} size 49189 bytes {d}",
        .{ hash, case.end - case.start },
    );

    var node: *node_child.Process = undefined;
    var rust: *rust_child.Process = undefined;
    if (direction == .rust_provider) {
        rust = try startRust(allocator, &node_hex, case, null);
        errdefer rust.deinit(t.io);
        try awaitRustBanner(rust);
        const address = rust.value("listening") orelse return error.NoProviderAddress;
        const peer = try std.fmt.allocPrint(allocator, "{s}@{s}", .{ rust_z32, address });
        node = try node_child.Process.start(t.allocator, allocator, t.io, "Node blob getter", .{
            .tag = node_tag,
            .seed = 0x1111,
            .run_ms = deadline_ms,
            .peers = &.{peer},
            .extra = &.{
                "--blob-role", "getter", "--blob-dir", directory,
                "--blob-hash", &hash, "--blob-size", "49189",
                "--blob-range", case.range, "--blob-output", output,
            },
        });
    } else {
        node = try node_child.Process.start(t.allocator, allocator, t.io, "Node blob provider", .{
            .tag = node_tag,
            .seed = 0x1111,
            .run_ms = deadline_ms,
            .extra = &.{
                "--blob-role", "provider", "--blob-dir", directory,
                "--blob-hash", &hash, "--expect-peer", &rust_z32,
            },
        });
        errdefer node.deinit(t.io);
        try awaitNodeBanner(node);
        rust = try startRust(allocator, &node_hex, case, node.bound().?);
    }
    defer node.deinit(t.io);
    defer rust.deinit(t.io);
    errdefer {
        node.dump();
        std.debug.print("Rust stdout:\n{s}\nRust stderr:\n{s}\n", .{
            rust.out.items, rust.err_out.items,
        });
    }
    try awaitSummary(node, rust, direction, summary);
    if (direction == .rust_provider) {
        const downloaded = try temporary.dir.readFileAlloc(
            t.io, "download.bin", t.allocator, .limited(49_189),
        );
        defer t.allocator.free(downloaded);
        try t.expectEqualSlices(u8, data[case.start..case.end], downloaded);
    }
    try node.stop();
    try awaitFinished(node, rust);
    try t.expect(!(try rust.reportFailure(t.io)));
    const term = try node.child.wait(t.io);
    node.reaped = true;
    switch (term) {
        .exited => |code| try t.expectEqual(@as(u8, 0), code),
        else => return error.NodeFailed,
    }
    const observed = rust.progress() orelse return error.NoRustProgress;
    try t.expectEqual(@as(u64, 1), observed.finished);
    try t.expectEqual(@as(u64, 1), observed.established);
}

fn startRust(
    allocator: std.mem.Allocator,
    node_id_hex: []const u8,
    case: Case,
    connect: ?[]const u8,
) !*rust_child.Process {
    const seed = hex(&@as([32]u8, @splat(rust_tag)));
    var argv: std.ArrayList([]const u8) = .empty;
    try argv.appendSlice(allocator, &.{
        rust_child.peer_executable, "--tls", "iroh", "--protocol", "blobs",
        "--role", if (connect == null) "server" else "client",
        "--bind", "127.0.0.1:0", "--seed-hex", try allocator.dupe(u8, &seed),
        "--expect-peer", node_id_hex, "--for", "20000",
        "--blob-range", case.range, "--blob-size", "49189",
    });
    if (connect) |address| try argv.appendSlice(allocator, &.{ "--connect", address });
    const process = try t.allocator.create(rust_child.Process);
    errdefer t.allocator.destroy(process);
    process.* = .{
        .child = try std.process.spawn(t.io, .{
            .argv = argv.items, .stdin = .ignore, .stdout = .pipe, .stderr = .pipe,
        }),
        .gpa = t.allocator,
        .name = "stock Rust blobs",
    };
    return process;
}

fn hex(bytes: []const u8) [64]u8 {
    std.debug.assert(bytes.len == 32);
    var result: [64]u8 = undefined;
    const digits = "0123456789abcdef";
    for (bytes, 0..) |byte, i| {
        result[2 * i] = digits[byte >> 4];
        result[2 * i + 1] = digits[byte & 15];
    }
    return result;
}

fn awaitRustBanner(rust: *rust_child.Process) !void {
    for (0..1000) |_| {
        try rust.pump(t.io);
        if (rust.line("listening") != null) return;
        if (rust.finished()) return error.RustFailedBeforeBanner;
        try pause();
    }
    return error.RustBannerTimeout;
}

fn awaitNodeBanner(node: *node_child.Process) !void {
    for (0..1000) |_| {
        try node.pump(t.io);
        if (node.saidWhereItListens()) return;
        if (node.finished()) return error.NodeFailedBeforeBanner;
        try pause();
    }
    return error.NodeBannerTimeout;
}

fn awaitSummary(
    node: *node_child.Process, rust: *rust_child.Process,
    direction: Direction, summary: []const u8,
) !void {
    for (0..1000) |_| {
        try node.pump(t.io);
        try rust.pump(t.io);
        const found = if (direction == .rust_provider)
            node.line("blob verified hash ")
        else
            rust.line("blob verified hash ");
        if (found) |line| {
            if (!std.mem.startsWith(u8, line, summary)) return error.InvalidBlobSummary;
            if (line.len > summary.len and line[summary.len] != ' ')
                return error.InvalidBlobSummary;
            return;
        }
        if (node.finished() or rust.finished()) return error.GetterFailed;
        try pause();
    }
    return error.GetterTimeout;
}

fn awaitFinished(node: *node_child.Process, rust: *rust_child.Process) !void {
    for (0..1000) |_| {
        try node.pump(t.io);
        try rust.pump(t.io);
        if (node.finished() and rust.finished()) return;
        try pause();
    }
    return error.BlobProcessCloseTimeout;
}

fn pause() !void {
    try std.Io.sleep(t.io, .fromMilliseconds(20), .awake);
}
