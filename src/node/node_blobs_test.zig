const std = @import("std");
const blobs = @import("node_blobs.zig");
const protocol = @import("../blobs/protocol.zig");
const store = @import("../blobs/store.zig");
const provider_mod = @import("../blobs/provider.zig");
const outboard_mod = @import("../blobs/bao_outboard.zig");
const range_spec = @import("../blobs/range_spec.zig");
const postcard = @import("../wire/postcard.zig");
const test_scratch = @import("test_scratch");
const t = std.testing;

// Real store answers must authenticate whole groups while exporting only requested chunks.
test "store backed node getter exports whole blob and clipped boundary ranges" {
    var data: [49189]u8 = undefined;
    for (&data, 0..) |*byte, i| byte.* = @intCast((i * 31 + @divFloor(i, 1024)) % 251);
    var tmp = try test_scratch.tmpDir(.{});
    defer tmp.cleanup();
    const hash = try putTestBlob(tmp.dir, &data);

    var names: store.NameStorage = undefined;
    var scratch: [1024]u8 = undefined;
    const provider = try provider_mod.Provider.init(tmp.dir, &names, hash, &scratch);
    const selections = [_]?protocol.ChunkRange{
        null,
        .{ .start = 15, .end = 18 },
        .{ .start = 47, .end = 49 },
    };
    for (selections) |range| {
        const options: blobs.Getter = .{ .hash = hash, .size = data.len, .range = range };
        var response: std.Io.Writer.Allocating = .init(t.allocator);
        defer response.deinit();
        try answerTestRequest(&provider, options, &response.writer);
        const wire = response.written();
        try t.expectEqual(@as(u64, data.len), std.mem.readInt(u64, wire[0..8], .little));

        const start: usize = if (range) |selected| @intCast(selected.start * 1024) else 0;
        const end: usize = if (range) |selected|
            @intCast(@min(selected.end * 1024, data.len))
        else
            data.len;
        const payload = try t.allocator.alloc(u8, end - start);
        defer t.allocator.free(payload);
        const decoded = try blobs.decodeResponse(options, wire, payload);
        try t.expectEqual(@as(u64, data.len), decoded.claimed_size);
        try t.expectEqual(@as(?u64, data.len), decoded.verified_size);
        try t.expectEqual(end - start, decoded.written);
        try t.expectEqualSlices(u8, data[start..end], payload[0..decoded.written]);
        const unknown = try blobs.decodeResponse(.{ .hash = hash, .range = range }, wire, payload);
        try t.expectEqual(@as(u64, data.len), unknown.claimed_size);
        const verified_size: ?u64 = if (range) |selected|
            if (selected.end == 49) data.len else null
        else
            data.len;
        try t.expectEqual(verified_size, unknown.verified_size);
        try t.expectEqualSlices(u8, data[start..end], payload[0..unknown.written]);
    }
}

// Mutate production answers only, and ensure failures leave consumer payload untouched.
test "store backed node getter refuses corrupt incomplete and mismatched answers" {
    var data: [49189]u8 = undefined;
    for (&data, 0..) |*byte, i| byte.* = @intCast((i * 31 + @divFloor(i, 1024)) % 251);
    var tmp = try test_scratch.tmpDir(.{});
    defer tmp.cleanup();
    const hash = try putTestBlob(tmp.dir, &data);
    var names: store.NameStorage = undefined;
    var scratch: [1024]u8 = undefined;
    const provider = try provider_mod.Provider.init(tmp.dir, &names, hash, &scratch);
    const options: blobs.Getter = .{ .hash = hash, .size = data.len };
    var response: std.Io.Writer.Allocating = .init(t.allocator);
    defer response.deinit();
    try answerTestRequest(&provider, options, &response.writer);
    const wire = response.written();
    var payload: [data.len]u8 = @splat(0xa5);
    const untouched: [data.len]u8 = @splat(0xa5);

    const corrupted = try t.allocator.dupe(u8, wire);
    defer t.allocator.free(corrupted);
    corrupted[8] ^= 1;
    try t.expectError(error.ChildMismatch, blobs.decodeResponse(options, corrupted, &payload));
    try t.expectEqualSlices(u8, &untouched, &payload);

    var wrong_root = hash;
    wrong_root[0] ^= 1;
    try t.expectError(
        error.RootMismatch,
        blobs.decodeResponse(.{ .hash = wrong_root, .size = data.len }, wire, &payload),
    );
    try t.expectEqualSlices(u8, &untouched, &payload);
    try t.expectError(
        error.ResponseTruncated,
        blobs.decodeResponse(options, wire[0 .. wire.len - 1], &payload),
    );
    try t.expectEqualSlices(u8, &untouched, &payload);
    var absent: std.Io.Writer.Allocating = .init(t.allocator);
    defer absent.deinit();
    try t.expectEqual(
        .absent,
        try provider.answer(t.io, &absent.writer, protocol.GetRequest.blob(wrong_root)),
    );
    try t.expectEqual(@as(usize, 0), absent.written().len);
    try t.expectError(
        error.ResponseTruncated,
        blobs.decodeResponse(.{ .hash = wrong_root, .size = data.len }, absent.written(), &payload),
    );
    try t.expectEqualSlices(u8, &untouched, &payload);
    try t.expectError(
        error.SizeMismatch,
        blobs.decodeResponse(.{ .hash = hash, .size = data.len + 1 }, wire, &payload),
    );
    try t.expectEqualSlices(u8, &untouched, &payload);
}

fn putTestBlob(dir: std.Io.Dir, data: []const u8) !store.Hash {
    const tree = outboard_mod.BaoTree.init(data.len);
    const hash = try tree.rootHash(data);
    const outboard = try t.allocator.alloc(u8, @intCast(outboard_mod.bytes(tree)));
    defer t.allocator.free(outboard);
    const written = try outboard_mod.encode(tree, data, outboard);
    try t.expectEqual(outboard.len, written);
    var names: store.NameStorage = undefined;
    const paths = store.names(&names, hash);
    {
        const partial = try store.createPartial(t.io, dir, paths);
        defer partial.close(t.io);
        try partial.data.writeStreamingAll(t.io, data);
        try partial.outboard.writeStreamingAll(t.io, outboard[0..written]);
    }
    try store.commit(t.io, dir, paths);
    return hash;
}

fn answerTestRequest(
    provider: *const provider_mod.Provider,
    options: blobs.Getter,
    writer: *std.Io.Writer,
) !void {
    var bytes: [128]u8 = undefined;
    const encoded = try blobs.encodeRequest(options, &bytes);
    var items: [2]range_spec.Item = undefined;
    var widths: [2]u64 = undefined;
    var storage: protocol.Storage = .{ .items = &items, .widths = &widths };
    var reader = postcard.Reader.init(encoded);
    const request = try protocol.Request.read(&reader, &storage);
    try t.expectEqual(.answered, try provider.answer(t.io, writer, request.to_eof.get));
}

test "getter sends upstream EOF request selecting boundary chunks" {
    const options: blobs.Getter = .{
        .hash = [_]u8{0x42} ** 32,
        .range = .{ .start = 15, .end = 18 },
    };
    var bytes: [128]u8 = undefined;
    const encoded = try blobs.encodeRequest(options, &bytes);
    var items: [2]range_spec.Item = undefined;
    var widths: [2]u64 = undefined;
    var storage: protocol.Storage = .{ .items = &items, .widths = &widths };
    var reader = postcard.Reader.init(encoded);
    const decoded = try protocol.Request.read(&reader, &storage);
    const selected = decoded.to_eof.get.selectedRange(49) orelse return error.TestUnexpectedResult;
    try t.expectEqual(@as(u64, 15), selected.start);
    try t.expectEqual(@as(u64, 18), selected.end);
}

test "getter never publishes truncated EOF as completion" {
    const options: blobs.Getter = .{ .hash = [_]u8{0x42} ** 32, .size = 49189 };
    var payload: [128]u8 = undefined;
    try t.expectError(error.ResponseTruncated, blobs.decodeResponse(options, &.{}, &payload));
    var size: [8]u8 = undefined;
    std.mem.writeInt(u64, &size, 49189, .little);
    try t.expectError(error.ProofIncomplete, blobs.decodeResponse(options, &size, &payload));
}

test "range request refuses empty or inverted chunk interval" {
    var bytes: [128]u8 = undefined;
    for ([_]protocol.ChunkRange{
        .{ .start = 18, .end = 18 },
        .{ .start = 18, .end = 15 },
    }) |range| {
        try t.expectError(
            error.InvalidRange,
            blobs.encodeRequest(.{ .hash = [_]u8{0} ** 32, .range = range }, &bytes),
        );
    }
}

test "expected size mismatch is consumer visible before export" {
    var size: [8]u8 = undefined;
    std.mem.writeInt(u64, &size, 49189, .little);
    var payload: [1]u8 = undefined;
    try t.expectError(
        error.SizeMismatch,
        blobs.decodeResponse(.{ .hash = [_]u8{0} ** 32, .size = 49190 }, &size, &payload),
    );
}
