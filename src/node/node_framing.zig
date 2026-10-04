//! The existing private QUIC relay carrier: length prefix followed by frame bytes.
const std = @import("std");
const quic_stream = @import("../transport/quic_stream.zig");
const quic_error = @import("../transport/quic_error.zig");
const relay_frame = @import("../relay/frame_types.zig");
const relay_writer = @import("../relay/frame_writer.zig");
const relay_server = @import("../relay/server_queue.zig");

pub const Error = quic_error.Error || relay_frame.Error || error{FrameTooLarge};

/// Reserve the widest prefix before encoding, then close its unused gap.
pub fn writeRelay(
    stream: *quic_stream.Stream,
    out: []u8,
    message: relay_frame.Message,
) Error!void {
    const written = try relay_writer.encode(message, .v2, out[varint_max..]);
    const prefix = try writeVarint(out[0..varint_max], written.len);
    @memmove(out[prefix..][0..written.len], written);
    const framed = out[0 .. prefix + written.len];
    const sent = try stream.write(framed);
    // A partial write would leave bytes that the peer reads as another prefix.
    if (sent != framed.len) return error.CoreRefused;
}

/// Delimit without decoding, so even a refused message has a known end.
/// Scratch owns the borrow while the caller compacts the inbox once per walk.
///
/// **The declared width is judged before the frame is waited for.** A prefix
/// naming more than the frame room is refused on the strength of the prefix
/// alone, at the byte it was read, so the bytes it promises are never
/// buffered: the inbox grows with what a peer actually sent and not with what
/// it said it would send. Both width refusals — a varint that will not cast
/// and a length past the room — are `FrameTooLarge` and are decided here,
/// where a frame that has merely not all arrived is still null and is only
/// ever called truncated when `discardTail` sees the stream end under it.
pub fn peekFrame(
    bytes: []const u8,
    from: usize,
    scratch: []u8,
) Error!?struct { frame: []const u8, end: usize } {
    const head = readVarint(bytes[from..]) orelse return null;
    const whole = std.math.cast(usize, head.value) orelse return error.FrameTooLarge;
    if (whole > scratch.len) return error.FrameTooLarge;
    const end = from +| head.len +| whole;
    if (bytes.len < end) return null;
    @memcpy(scratch[0..whole], bytes[from + head.len ..][0..whole]);
    return .{ .frame = scratch[0..whole], .end = end };
}

pub fn dropInbox(inbox: *std.ArrayList(u8), used: usize) void {
    if (used == 0) return;
    const rest = inbox.items[used..];
    @memmove(inbox.items[0..rest.len], rest);
    inbox.shrinkRetainingCapacity(rest.len);
}

/// Called after whole frames are removed: a finished stream cannot fill its tail.
pub fn discardTail(inbox: *std.ArrayList(u8), finished: bool) bool {
    if (!finished or inbox.items.len == 0) return false;
    inbox.clearRetainingCapacity();
    return true;
}

pub fn controlFrame(control: relay_server.Control) relay_frame.Message {
    return switch (control) {
        .peer_gone => |node_id| .{ .endpoint_gone = node_id },
        .status => |status| .{ .status = status },
    };
}

pub const varint_max = 8;

pub const Varint = struct {
    value: u64,
    len: usize,
};

pub fn writeVarint(out: []u8, value: u64) Error!usize {
    if (value < 64) {
        if (out.len < 1) return error.NoRoom;
        out[0] = @intCast(value);
        return 1;
    }
    if (value < 16384) {
        if (out.len < 2) return error.NoRoom;
        putInt(u16, out[0..2], @intCast(value | (0b01 << 14)));
        return 2;
    }
    if (value < 1 << 30) {
        if (out.len < 4) return error.NoRoom;
        putInt(u32, out[0..4], @intCast(value | (0b10 << 30)));
        return 4;
    }
    if (out.len < varint_max) return error.NoRoom;
    putInt(u64, out[0..varint_max], value | (0b11 << 62));
    return varint_max;
}

pub fn readVarint(bytes: []const u8) ?Varint {
    if (bytes.len == 0) return null;
    const len = @as(usize, 1) << @as(u2, @truncate(bytes[0] >> 6));
    if (bytes.len < len) return null;
    const wide: u64 = switch (len) {
        1 => bytes[0],
        2 => getInt(u16, bytes[0..2]),
        4 => getInt(u32, bytes[0..4]),
        else => getInt(u64, bytes[0..varint_max]),
    };
    const bits: u6 = @intCast(@as(u32, @intCast(len)) * 8 - 2);
    return .{ .value = wide & ((@as(u64, 1) << bits) - 1), .len = len };
}

pub fn putInt(comptime T: type, out: []u8, value: T) void {
    std.mem.writeInt(T, @ptrCast(out.ptr), value, .big);
}

pub fn getInt(comptime T: type, bytes: []const u8) T {
    return std.mem.readInt(T, @ptrCast(bytes.ptr), .big);
}
