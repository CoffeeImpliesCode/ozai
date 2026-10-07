//! Runtime consumers of captures from the pinned Noq private codecs.
//! Missing captures fail; tests never substitute locally generated vectors.
const std = @import("std");
const t = std.testing;
const quic = @import("quic");
const nat = @import("native_nat.zig");
const Frame = quic.frame.Frame;
const Address = quic.address.Address;
const sequences = [_]u64{ 0, 63, 64, 16383, 16384, 1073741823, 1073741824,
    4611686018427387903 };
const ipv6 = [_]u8{ 0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };

fn capture(name: []const u8) ![]u8 {
    const gpa = t.allocator;
    const path = try std.fs.path.join(gpa, &.{ "test/fixtures/native", name });
    defer gpa.free(path);
    return std.Io.Dir.cwd().readFileAlloc(t.io, path, gpa, .limited(1024 * 1024));
}

fn numberedCapture(prefix: []const u8, number: u64) ![]u8 {
    var name: [128]u8 = undefined;
    return capture(try std.fmt.bufPrint(&name, "{s}_{d}.bin", .{ prefix, number }));
}

fn goldenFrame(bytes: []u8, expected_tag: std.meta.Tag(Frame)) !Frame {
    var consumed: usize = 0;
    const frame = try Frame.parseSized(bytes, &consumed);
    try t.expectEqual(expected_tag, std.meta.activeTag(frame));
    try t.expectEqual(bytes.len, consumed);
    var output: [256]u8 = undefined;
    var writer = quic.io_compat.fixedBufferStream(&output);
    try frame.write(&writer);
    try t.expectEqualSlices(u8, bytes, writer.buffered());
    return frame;
}

fn provenance(name: []const u8) !void {
    const bytes = try capture(name);
    defer t.allocator.free(bytes);
    var lines = std.mem.tokenizeScalar(u8, bytes, '\n');
    var version: ?[]const u8 = null;
    var revision: ?[]const u8 = null;
    while (lines.next()) |line| {
        const separator = std.mem.indexOfScalar(u8, line, '=') orelse continue;
        const key = line[0..separator];
        const value = line[separator + 1 ..];
        if (std.mem.eql(u8, key, "noq-proto")) version = value;
        if (std.mem.eql(u8, key, "vcs")) revision = value;
    }
    try t.expectEqualStrings("1.3.0", version orelse return error.MissingVersion);
    try t.expectEqualStrings("c1f411562e6078852749b8bcf1190523096a107f",
        revision orelse return error.MissingRevision);
}

test "native observed frames match captured Noq addresses and every varint boundary" {
    try provenance("observed/observed_provenance.txt");
    const addresses = [_]Address{
        .initIpv4(.{ 203, 0, 113, 9 }, 443), .initIpv6(ipv6, 65535, 0),
    };
    for (addresses, 0..) |address, family| {
        const prefix = if (family == 0) "observed/observed_ipv4" else "observed/observed_ipv6";
        for (sequences) |sequence| {
            const bytes = try numberedCapture(prefix, sequence);
            defer t.allocator.free(bytes);
            const frame = try goldenFrame(bytes, .observed_address);
            try t.expectEqual(sequence, frame.observed_address.sequence);
            try t.expectEqualDeep(address, frame.observed_address.address);
        }
    }
    inline for (.{ .send_only, .receive_only, .both }) |tag| {
        const bytes = try capture("observed/observed_role_" ++ @tagName(tag) ++ ".bin");
        defer t.allocator.free(bytes);
        const role = try quic.observed_address.Role.decodeTransportValue(bytes);
        try t.expectEqual(@as(quic.observed_address.Role, tag), role);
        var output: [8]u8 = undefined;
        var writer = quic.io_compat.fixedBufferStream(&output);
        try quic.packet.writeVarInt(&writer, role.transportValue().?);
        try t.expectEqualSlices(u8, bytes, writer.buffered());
    }
}

test "native NAT captured ADD REMOVE REACH_OUT preserve variants addresses and sequences" {
    const addresses = [_]Address{
        .initIpv4(.{ 192, 0, 2, 1 }, 0x1234), .initIpv6(ipv6, 0x1234, 0),
    };
    for (addresses, 0..) |address, family| {
        for (sequences) |sequence| {
            inline for (.{ "add", "reach" }) |kind| {
                const prefix = if (family == 0) "nat/" ++ kind ++ "_v4" else "nat/" ++ kind ++ "_v6";
                const bytes = try numberedCapture(prefix, sequence);
                defer t.allocator.free(bytes);
                const tag: std.meta.Tag(Frame) = if (comptime std.mem.eql(u8, kind, "add"))
                    .add_address else .reach_address;
                const frame = try goldenFrame(bytes, tag);
                if (comptime std.mem.eql(u8, kind, "add")) {
                    try t.expectEqual(sequence, frame.add_address.sequence);
                    try t.expectEqualDeep(address, frame.add_address.address);
                } else {
                    try t.expectEqual(sequence, frame.reach_address.round);
                    try t.expectEqualDeep(address, frame.reach_address.address);
                }
            }
        }
    }
    for (sequences) |sequence| {
        const bytes = try numberedCapture("nat/remove", sequence);
        defer t.allocator.free(bytes);
        const frame = try goldenFrame(bytes, .remove_address);
        try t.expectEqual(sequence, frame.remove_address);
    }
    for ([_]u8{ 1, 32, 255 }) |capacity| {
        const bytes = try numberedCapture("nat/parameter", capacity);
        defer t.allocator.free(bytes);
        try t.expectEqual(capacity, try nat.decodeParameter(bytes));
        var output: [1]u8 = undefined;
        const length = try nat.encodeParameter(capacity, &output);
        try t.expectEqualSlices(u8, bytes, output[0..length]);
    }
}

fn expectAck(ack: anytype) !void {
    try t.expectEqual(@as(u64, 10), ack.largest_ack);
    try t.expectEqual(@as(u64, 0), ack.ack_delay);
    try t.expectEqual(@as(u64, 3), ack.first_ack_range);
    try t.expectEqual(@as(u8, 0), ack.ack_range_count);
}

fn expectMultipath(frame: Frame, path_id: u32) !void {
    switch (frame) {
        .path_ack => |value| {
            try t.expectEqual(path_id, value.path_id);
            try expectAck(value.ack);
        },
        .path_ack_ecn => |value| {
            try t.expectEqual(path_id, value.path_id);
            try expectAck(value.ack);
            try t.expectEqual(@as(u64, 1), value.ack.ecn_ect0);
            try t.expectEqual(@as(u64, 2), value.ack.ecn_ect1);
            try t.expectEqual(@as(u64, 3), value.ack.ecn_ce);
        },
        .path_abandon => |value| {
            try t.expectEqual(path_id, value.path_id);
            try t.expectEqual(@as(u64, 0), value.error_code);
        },
        inline .path_status_backup, .path_status_available => |value| {
            try t.expectEqual(path_id, value.path_id);
            try t.expectEqual(@as(u64, 2), value.status_seq_no);
        },
        .path_new_connection_id => |value| {
            try t.expectEqual(path_id, value.path_id);
            try t.expectEqual(@as(u64, 0), value.cid.seq_num);
            try t.expectEqual(@as(u64, 0), value.cid.retire_prior_to);
            try t.expectEqualSlices(u8, &.{0xab}, value.cid.conn_id);
            try t.expectEqualSlices(u8, &([_]u8{0xcd} ** 16), &value.cid.stateless_reset_token);
        },
        .path_retire_connection_id => |value| {
            try t.expectEqual(path_id, value.path_id);
            try t.expectEqual(@as(u64, 0), value.seq_num);
        },
        .max_path_id, .paths_blocked => |value| try t.expectEqual(path_id, value),
        .path_cids_blocked => |value| {
            try t.expectEqual(path_id, value.path_id);
            try t.expectEqual(@as(u64, 2), value.next_seq);
        },
        else => return error.UnexpectedMultipathFrame,
    }
}

fn expectInitialPathIdentity(params: quic.transport_params.TransportParams, golden: []const u8) !void {
    var output: [2048]u8 = undefined;
    var writer = quic.io_compat.fixedBufferStream(&output);
    var random = std.Random.DefaultPrng.init(0xc1f41156);
    try params.encode(&writer, random.random());
    var reader = quic.io_compat.fixedBufferStream(writer.buffered());
    while (reader.seek < writer.seek) {
        const start = reader.seek;
        const id = try quic.packet.readVarInt(&reader);
        const length = try quic.packet.readVarInt(&reader);
        reader.seek += @intCast(length);
        if (id == 0x3e) {
            try t.expectEqualSlices(u8, golden, output[start..reader.seek]);
            return;
        }
    }
    return error.MissingInitialPathParameter;
}

test "native multipath captured ten variants and initialMaxPath TLVs match Noq" {
    try provenance("multipath/multipath_provenance.txt");
    for ([_]u32{ 0, 1 }) |path_id| {
        inline for (.{ .path_ack, .path_ack_ecn, .path_abandon, .path_status_backup,
            .path_status_available, .path_new_connection_id, .path_retire_connection_id,
            .max_path_id, .paths_blocked, .path_cids_blocked }) |tag|
        {
            const bytes = try numberedCapture("multipath/" ++ @tagName(tag), path_id);
            defer t.allocator.free(bytes);
            try expectMultipath(try goldenFrame(bytes, tag), path_id);
        }
        inline for (.{ "initial_max_path_id", "multipath_params" }) |prefix| {
            const bytes = try numberedCapture("multipath/" ++ prefix, path_id);
            defer t.allocator.free(bytes);
            const params = try quic.transport_params.TransportParams.decode(bytes);
            try t.expectEqual(@as(?u32, path_id), params.initial_max_path_id);
            if (comptime std.mem.eql(u8, prefix, "initial_max_path_id")) {
                try expectInitialPathIdentity(params, bytes);
            }
        }
    }
}
