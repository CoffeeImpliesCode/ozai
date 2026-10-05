//! The message boundary a WebSocket would have carried, and the varint that
//! carries it.
//!
//! `relay/frame.zig` has no length prefix and says why twice: upstream's
//! carrier is a WebSocket, and one message *is* one frame. A QUIC stream is a
//! byte pipe with no boundary of its own, so this writes the one the WebSocket
//! was carrying, reads it back, and refuses a frame that does not fit rather
//! than truncating it. Both halves of the relay read through here, and neither
//! decodes: a frame's length says where it ends, and `decode` says what it
//! means, and the two answers are kept apart so a frame `decode` refuses has
//! still arrived whole.

const std = @import("std");

const node_config = @import("node_config.zig");
const node_transport = @import("node_transport.zig");
const bridge_mod = @import("../transport/quic_bridge.zig");
const relay_frame = @import("../relay/frame.zig");
const relay_server = @import("../relay/server.zig");

const Error = node_config.Error;
const max_datagram = node_transport.max_datagram;

/// Room for the largest message this node reads or writes on a relay stream:
/// a datagram's payload, the frame header around it, and a varint length in
/// front of that.
///
/// **This is a write bound, and `encode` refuses rather than truncates**, so a
/// frame that does not fit is `error.BufferFull` rather than a lie on the wire.
///
/// Eight is the widest a QUIC varint can be, and `DatagramFrame.header_length`
/// is the node id and the codepoint. That makes a datagram the widest frame
/// this node sends, and every other frame narrower — a serving relay writes a
/// challenge, a confirmation, a datagram, an `endpoint_gone`, a `status` and a
/// `pong`; a relay client writes a `client_auth`, a datagram and a `pong`. All
/// but one are bounded by a node id, by eight fixed bytes, or by the datagram.
///
/// **The eighth — `server_denies_auth`, whose payload is a reason string — was
/// the hole, and it is closed in the codec rather than here.** Its length is
/// the one in this protocol a peer can reach: upstream's access control is a
/// trait the operator implements (`handshake.rs:495`, `:524`), so the reason is
/// whatever that trait decided, and a buffer sized for whatever it said is not
/// a bound. `relay_frame.max_text_length` is, and
/// `relay_frame.encode` refuses past it as `error.TextTooLong` before writing a
/// byte. So the widest denial this node can be handed is a number —
/// `relay_frame.ServerDeniesAuth.max_frame_length` — and the assertion below is
/// what says it fits here. **Reserving worst-case room instead would have been
/// the wrong answer:** it is unbounded, so "worst case" is not a number, and
/// sizing a buffer for an unbounded string is the same mistake with a bigger
/// constant.
pub const relay_frame_room = relay_frame.DatagramFrame.header_length + max_datagram + 8;

comptime {
    // The reason a relay sends is bounded by the codec, so this is arithmetic
    // rather than a hope: if the bound or the datagram moves, this stops the
    // build instead of letting a relay discover at run time that it has no room
    // for the denial it just decided to send.
    if (relay_frame.ServerDeniesAuth.max_frame_length > relay_frame_room) {
        @compileError("the relay's frame room is narrower than the denial it may send");
    }
}

/// One relay frame onto a stream, with the message boundary a WebSocket would
/// have carried.
///
/// `relay/frame.zig` has no length prefix and says why twice: upstream's
/// carrier is a WebSocket, and one message *is* one frame. A QUIC stream is a
/// byte pipe with no boundary of its own, so this writes the one the WebSocket
/// was carrying — a QUIC varint length, then the frame — and the frame bytes
/// themselves are untouched, because `decode` is handed exactly the message
/// the length named.
pub fn writeRelay(
    stream: *bridge_mod.Stream,
    out: []u8,
    message: relay_frame.Message,
) Error!void {
    const written = try relay_frame.encode(message, .v2, out[varint_max..]);
    const prefix = try writeVarint(out[0..varint_max], written.len);
    // The frame was written at `varint_max` because the length had to go in
    // front of it and its own width is not known until it has been written.
    // It is moved down over the gap the length did not use, so what goes on the
    // wire is the length and then the frame and nothing between them.
    @memmove(out[prefix..][0..written.len], written);
    try stream.write(out[0 .. prefix + written.len]);
}

/// The next whole frame at or after `from` in `bytes`, copied into `scratch`,
/// and where it ended — or null when there is not one yet.
///
/// **This delimits a frame and does not decode one.** The length alone says
/// where the frame ends, and that end is a fact about the bytes rather than
/// about what they mean. How many bytes a frame was is therefore known before
/// anyone asks what it says, and the caller records that end before it asks:
/// a frame `decode` refuses has still arrived whole, so it has to be walked
/// over rather than met again on the next pass, and so has everything in
/// front of it. A helper that answered both questions in one return could not
/// hand back the end of a frame whose meaning turned out to be a fault.
///
/// **Copied into `scratch`, and that is the whole of what makes the borrow
/// sound.** `frame.decode` borrows its two variable-length payloads out of the
/// bytes it is handed, so those bytes must outlive the message. They cannot be
/// the inbox's, because taking a message off the inbox's front moves every byte
/// behind it — a borrow into a buffer that is compacted under it is a borrow of
/// nothing. One copy per message, into a buffer the caller owns, is the price
/// of a borrow that points at something.
///
/// **A walk, and the caller compacts once.** A take that shrank the inbox per
/// message moved everything behind that message every time, which is quadratic
/// in the inbox: cheap while a read buffer capped the inbox at one frame, which
/// is all it ever held, and a whole burst's worth of memmove now that a read
/// goes straight onto the inbox. So this hands back an end offset and leaves
/// the bytes where they are, and `dropInbox` moves what is left exactly once —
/// on the way out of the walk and on the fault that ends it alike, because the
/// two are one decision taken twice rather than two decisions.
///
/// `scratch` has to be as long as the largest frame this node admits, which is
/// `relay_frame_room`. One scratch serves a whole node because a pass takes at
/// most one direction of the protocol: a serving relay reads its clients, and a
/// client reads its relay.
pub fn peekFrame(
    bytes: []const u8,
    from: usize,
    scratch: []u8,
) Error!?struct { frame: []const u8, end: usize } {
    const head = readVarint(bytes[from..]) orelse return null;
    const whole = std.math.cast(usize, head.value) orelse return error.FrameTooLarge;
    const end = from +| head.len +| whole;
    if (bytes.len < end) return null;
    if (whole > scratch.len) return error.FrameTooLarge;
    @memcpy(scratch[0..whole], bytes[from + head.len ..][0..whole]);
    return .{ .frame = scratch[0..whole], .end = end };
}

/// Drop the first `used` bytes of `inbox`, in one move.
pub fn dropInbox(inbox: *std.ArrayList(u8), used: usize) void {
    if (used == 0) return;
    const rest = inbox.items[used..];
    @memmove(inbox.items[0..rest.len], rest);
    inbox.shrinkRetainingCapacity(rest.len);
}

/// Drop the frame a finished stream left half-written, and say whether it left
/// one.
///
/// **This is the half of `Stream.drain`'s answer its caller has to ask for.**
/// `drain` returns whether it appended bytes and says nothing about what came
/// before them, so a stream the peer ended on a frame boundary and one it ended
/// in the middle of a frame read the same, and only `Stream.finished` tells
/// them apart. What is left in `inbox` after that is a frame that will never
/// arrive, so it is dropped and counted rather than kept for a message that is
/// not coming.
///
/// Asked after `dropInbox`, never before: until the whole messages are taken,
/// an inbox with bytes in it is this node behind rather than a peer that
/// stopped early.
pub fn discardTail(inbox: *std.ArrayList(u8), finished: bool) bool {
    if (!finished or inbox.items.len == 0) return false;
    inbox.clearRetainingCapacity();
    return true;
}

/// A queued control message as the frame that carries it.
pub fn controlFrame(control: relay_server.Control) relay_frame.Message {
    return switch (control) {
        .peer_gone => |node_id| .{ .endpoint_gone = node_id },
        .status => |status| .{ .status = status },
    };
}

/// The widest a QUIC variable-length integer is, which is also the headroom a
/// message leaves in front of its frame. The same encoding `relay/frame.zig`
/// writes a frame type with, because that is what a peer will read it as.
pub const varint_max = 8;

/// A QUIC variable-length integer: two prefix bits say the width, and the
/// value is what is left of it.
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

/// Write `value` big-endian into the front of `out`, which the caller has
/// already sized for `T`'s width.
fn putInt(comptime T: type, out: []u8, value: T) void {
    std.mem.writeInt(T, @ptrCast(out.ptr), value, .big);
}

/// Read a big-endian `T` off the front of `bytes`, which the caller has
/// already checked is long enough.
fn getInt(comptime T: type, bytes: []const u8) T {
    return std.mem.readInt(T, @ptrCast(bytes.ptr), .big);
}
