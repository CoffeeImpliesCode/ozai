//! Process signals, monotonic clock, and the CLI's application output loop.
const std = @import("std");
const ozai = @import("ozai");
const cli_values = @import("cli_values.zig");
const cli_report = @import("cli_report.zig");
const Progress = @import("progress.zig").Snapshot;
const test_scratch = @import("test_scratch");
const Node = ozai.node.Node;
const Instant = ozai.transport_quic_bridge.Instant;

const BlobOutputError = std.Io.File.OpenError || std.Io.File.Writer.Error;
pub const DriveError = ozai.node.Error || cli_values.CliError ||
    std.Io.Writer.Error || BlobOutputError || error{BlobNotVerified};
pub const ShutError = ozai.node.Error || cli_values.CliError;

pub var stopped = ozai.node.Stop.init();
const stop_signals = [_]std.posix.SIG{ .INT, .TERM };

fn onSignal(sig: std.posix.SIG) callconv(.c) void {
    _ = sig;
    stopped.request();
}

pub fn watchForStop() void {
    const act: std.posix.Sigaction = .{
        .handler = .{ .handler = onSignal },
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    };
    for (stop_signals) |sig| std.posix.sigaction(sig, &act, null);
}

pub fn nowNs(io: std.Io) cli_values.CliError!ozai.transport_quic_bridge.Instant {
    const stamp = std.Io.Clock.awake.now(io);
    return std.math.cast(Instant, stamp.nanoseconds) orelse error.NoClock;
}

pub fn drive(
    io: std.Io,
    node: *Node,
    blob_output: ?[]const u8,
    evidence: *cli_report.GossipEvidence,
    progress: ?*std.Io.Writer,
) DriveError!void {
    var dialled = false;
    var exported = false;
    var previous: ?Progress = null;
    while (true) {
        const at = try nowNs(io);
        if (stopped.expired(at)) break;
        if (!dialled) {
            dialled = true;
            try node.start(at, node.generator());
        }
        _ = try node.step(io, at, node.generator());
        if (evidence.failure) |err| return err;
        if (!exported) {
            if (node.blobs.firstCompletedConnection()) |connection| {
                const payload = node.blobs.payload(connection) orelse
                    @panic("completed blob connection has no verified payload");
                if (blob_output) |path|
                    try writeBlobOutput(io, std.Io.Dir.cwd(), path, payload);
                const hash = node.blobs.last_hash orelse
                    @panic("completed blob transfer has no verified hash");
                if (node.blobs.last_size) |size| {
                    try evidence.writer.print(
                        "blob verified hash {x} size {d} bytes {d}\n",
                        .{ hash, size, payload.len },
                    );
                } else {
                    const claimed_size = node.blobs.last_claimed_size orelse
                        @panic("completed blob transfer has no size claim");
                    try evidence.writer.print(
                        "blob verified hash {x} unverified size claim {d} bytes {d}\n",
                        .{ hash, claimed_size, payload.len },
                    );
                }
                try evidence.writer.flush();
                exported = true;
            }
        }
        if (progress) |writer| {
            const current = Progress.capture(node);
            if (previous == null or !std.meta.eql(previous.?, current)) {
                try writer.print("{f}", .{&current});
                try writer.flush();
                previous = current;
            }
        }
        try node.wait(io, ozai.node.poll_interval_ms);
    }
    if (blob_output != null and !exported) return error.BlobNotVerified;
}

pub fn shut(io: std.Io, node: *Node, owed: usize) ShutError!cli_report.Close {
    const before = node.stats.datagrams_out;
    try node.close(io, try nowNs(io), node.generator());
    return .{ .connections = owed, .datagrams = node.stats.datagrams_out - before };
}

fn writeBlobOutput(
    io: std.Io,
    dir: std.Io.Dir,
    path: []const u8,
    payload: []const u8,
) BlobOutputError!void {
    const file = try dir.createFile(io, path, .{ .truncate = true });
    defer file.close(io);
    try file.writeStreamingAll(io, payload);
}

test "blob output truncates stale bytes and preserves the complete verified binary payload" {
    const t = std.testing;
    var tmp = try test_scratch.tmpDir(.{});
    defer tmp.cleanup();
    const stale = try tmp.dir.createFile(t.io, "blob", .{});
    try stale.writeStreamingAll(t.io, "stale bytes to truncate");
    stale.close(t.io);
    const payload = "\x00\xffabc\n";
    try writeBlobOutput(t.io, tmp.dir, "blob", payload);
    const file = try tmp.dir.openFile(t.io, "blob", .{});
    defer file.close(t.io);
    try t.expectEqual(@as(u64, payload.len), try file.length(t.io));
    var bytes: [payload.len]u8 = undefined;
    try t.expectEqual(payload.len, try file.readPositionalAll(t.io, &bytes, 0));
    try t.expectEqualSlices(u8, payload, &bytes);
}
