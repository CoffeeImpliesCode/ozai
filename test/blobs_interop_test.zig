const std = @import("std");
const ozai = @import("ozai");
const node_child = @import("two_process_child.zig");
const rust_child = @import("rust_interop_child.zig");
const child_cleanup = @import("child_cleanup.zig");
const child_exit_probe = @import("child_exit_probe.zig");
const child_constructor_safety = @import("child_constructor_safety.zig");
const node_launch = @import("two_process_launch.zig");
const progress_ns = @import("two_process_progress.zig");
const test_scratch = @import("test_scratch");
const t = std.testing;

// These cases compare actual production CLI output with upstream-captured payload bytes.
test "stock Rust blob provider serves whole cross-group and partial-tail Node gets" {
    for (cases) |case| try runCase(.rust_provider, case);
}

test "production Node blob provider serves whole cross-group and partial-tail Rust gets" {
    for (cases) |case| try runCase(.node_provider, case);
}

const Direction = enum { rust_provider, node_provider };
const Case = struct {
    range: []const u8,
    start: usize,
    end: usize,
    request: []const u8,
    response: []const u8,
};
const cases = [_]Case{
    .{
        .range = "all",
        .start = 0,
        .end = 49_189,
        .request = @embedFile("fixtures/blobs/request-all.bin"),
        .response = @embedFile("fixtures/blobs/response-all.bin"),
    },
    .{
        .range = "15:18",
        .start = 15_360,
        .end = 18_432,
        .request = @embedFile("fixtures/blobs/request-15-18.bin"),
        .response = @embedFile("fixtures/blobs/response-15-18.bin"),
    },
    .{
        .range = "47:49",
        .start = 48_128,
        .end = 49_189,
        .request = @embedFile("fixtures/blobs/request-47-49.bin"),
        .response = @embedFile("fixtures/blobs/response-47-49.bin"),
    },
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
    var temporary = try test_scratch.tmpDir(.{});
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
        allocator,
        "blob verified hash {s} size 49189 bytes {d}",
        .{ hash, case.end - case.start },
    );

    var node: *node_child.Process = undefined;
    var node_started = false;
    defer if (node_started) node.deinit(t.io);
    var rust: *rust_child.Process = undefined;
    var rust_started = false;
    defer if (rust_started) rust.deinit(t.io);
    if (direction == .rust_provider) {
        const argv = try rustFlags(allocator, &node_hex, case, null);
        const started = try rust_child.Process.start(t.allocator, t.io, .{
            .name = "stock Rust blobs",
            .argv = argv,
            .final_argv = argv,
            .run_ms = deadline_ms,
        });
        rust = switch (started) {
            .ready => |value| value,
            .failed => |failure| {
                failure.process.deinit(t.io);
                return failure.cause;
            },
        };
        rust_started = true;
        try awaitRustBanner(rust);
        const address = rust.value("listening") orelse return error.NoProviderAddress;
        const peer = try std.fmt.allocPrint(allocator, "{s}@{s}", .{ rust_z32, address });
        const node_argv = try node_launch.flags(allocator, .{
            .tag = node_tag,
            .seed = 0x1111,
            .run_ms = deadline_ms,
            .peers = &.{peer},
            .extra = &.{
                "--blob-role",   "getter",
                "--blob-hash",   &hash,
                "--blob-size",   "49189",
                "--blob-range",  case.range,
                "--blob-output", output,
            },
        });
        const node_start = try node_child.Process.start(t.allocator, t.io, .{
            .name = "Node blob getter",
            .argv = node_argv,
            .final_argv = if (@import("node_test_options").node_executor != null)
                node_argv[1..]
            else
                node_argv,
            .run_ms = deadline_ms,
        });
        node = switch (node_start) {
            .ready => |value| value,
            .failed => |failure| {
                failure.process.deinit(t.io);
                return failure.cause;
            },
        };
        node_started = true;
    } else {
        const node_argv = try node_launch.flags(allocator, .{
            .tag = node_tag,
            .seed = 0x1111,
            .run_ms = deadline_ms,
            .extra = &.{
                "--blob-role", "provider", "--blob-dir",    directory,
                "--blob-hash", &hash,      "--expect-peer", &rust_z32,
            },
        });
        const node_start = try node_child.Process.start(t.allocator, t.io, .{
            .name = "Node blob provider",
            .argv = node_argv,
            .final_argv = if (@import("node_test_options").node_executor != null)
                node_argv[1..]
            else
                node_argv,
            .run_ms = deadline_ms,
        });
        node = switch (node_start) {
            .ready => |value| value,
            .failed => |failure| {
                failure.process.deinit(t.io);
                return failure.cause;
            },
        };
        node_started = true;
        try awaitNodeBanner(node);
        const bound = node.bound() orelse return error.TestUnexpectedResult;
        const argv = try rustFlags(allocator, &node_hex, case, bound);
        const started = try rust_child.Process.start(t.allocator, t.io, .{
            .name = "stock Rust blobs",
            .argv = argv,
            .final_argv = argv,
            .run_ms = deadline_ms,
        });
        rust = switch (started) {
            .ready => |value| value,
            .failed => |failure| {
                failure.process.deinit(t.io);
                return failure.cause;
            },
        };
        rust_started = true;
    }
    errdefer {
        node.dump();
        std.debug.print("Rust stdout:\n{s}\nRust stderr:\n{s}\n", .{
            rust.out.items, rust.err_out.items,
        });
    }
    try awaitSummary(node, rust, direction, summary);
    if (direction == .rust_provider) {
        const expected = data[case.start..case.end];
        const downloaded = try temporary.dir.readFileAlloc(
            t.io,
            "download.bin",
            t.allocator,
            .limited(expected.len + 1),
        );
        defer t.allocator.free(downloaded);
        try t.expectEqualSlices(u8, expected, downloaded);
    }
    try node.stop(t.io);
    try awaitFinished(node, rust);
    try t.expect(!(try rust.reportFailure(t.io)));
    const term = try node.child.wait(t.io);
    node.reaped = true;
    switch (term) {
        .exited => |code| try t.expectEqual(@as(u8, 0), code),
        else => return error.NodeFailed,
    }
    const observed = rust.progress() orelse return error.NoRustProgress;
    try expectProgressEqual(observed, "up", 1);
    const completed: u64 = if (direction == .node_provider) 1 else 0;
    try expectProgressEqual(observed, "blob transfers completed", completed);
    const sent = if (direction == .rust_provider) case.response.len else case.request.len;
    const received = if (direction == .rust_provider) case.request.len else case.response.len;
    try expectProgressEqual(observed, "blob sent bytes", sent);
    try expectProgressEqual(observed, "blob received bytes", received);
}

fn expectProgressEqual(observed: progress_ns.Progress, field: []const u8, expected: u64) !void {
    const lower: progress_ns.Need = .{ .field = field, .want = expected };
    const upper: progress_ns.Need = .{ .field = field, .want = expected, .at_most = true };
    try t.expect(lower.holds(observed));
    try t.expect(upper.holds(observed));
}

fn rustFlags(
    allocator: std.mem.Allocator,
    node_id_hex: []const u8,
    case: Case,
    connect: ?[]const u8,
) std.mem.Allocator.Error![]const []const u8 {
    const seed = hex(&@as([32]u8, @splat(rust_tag)));
    var argv: std.ArrayList([]const u8) = .empty;
    try argv.appendSlice(allocator, &.{
        rust_child.peer_executable,
        "--tls",
        "iroh",
        "--protocol",
        "blobs",
        "--role",
        if (connect == null) "server" else "client",
        "--bind",
        "127.0.0.1:0",
        "--seed-hex",
        try allocator.dupe(u8, &seed),
        "--expect-peer",
        node_id_hex,
        "--for",
        "20000",
        "--blob-range",
        case.range,
        "--blob-size",
        "49189",
    });
    if (connect) |address| try argv.appendSlice(allocator, &.{ "--connect", address });
    return argv.items;
}

fn hex(bytes: []const u8) [64]u8 {
    std.debug.assert(bytes.len == 32);
    var result: [64]u8 = undefined;
    const digits = "0123456789abcdef";
    for (bytes, 0..) |byte, i| {
        result[2 * i] = digits[byte >> 4];
        result[2 * i + 1] = digits[byte & 15];
    }
    // zbc misses the asserted 32-byte input and complete two-digit writes to result.
    // zbc-disable-next-line: use-undefined
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
    node: *node_child.Process,
    rust: *rust_child.Process,
    direction: Direction,
    summary: []const u8,
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

test "blob banner failure cleanup reaps only its prepared exact owned Rust child" {
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    var key = try ozai.SecretKey.fromSeed(@splat(node_tag));
    defer key.deinit();
    const node_id_hex = rust_child.hexId(key.nodeId());
    const argv = try rustFlags(arena.allocator(), &node_id_hex, cases[0], null);
    const started = try rust_child.Process.start(t.allocator, t.io, .{
        .name = "stock Rust blobs startup cleanup",
        .argv = argv,
        .final_argv = argv,
        .run_ms = deadline_ms,
    });
    const rust = switch (started) {
        .ready => |value| value,
        .failed => |failure| {
            failure.process.deinit(t.io);
            return failure.cause;
        },
    };
    defer rust.deinit(t.io);

    try awaitRustBanner(rust);
    // A consumer startup failure takes the same finish path used by deferred fixture disposal.
    try rust.finish(t.io);
    try t.expect(rust.reaped);
    try t.expectEqual(@as(?std.c.pid_t, null), rust.child.id);
    try t.expect(rust.guard.identity != null);
}

test {
    t.refAllDecls(child_cleanup);
    t.refAllDecls(child_exit_probe);
    t.refAllDecls(child_constructor_safety);
}
