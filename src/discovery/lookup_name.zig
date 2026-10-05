//! A DNS name in both its forms: presentation to wire, wire to presentation.
//!
//! `lookup_query.zig` encodes a question's name and `lookup_answer.zig` decodes
//! the names a reply carries, and both need the same rule about dots, the root
//! terminator and RFC 1035 §4.1.4's compression pointer. The pointer is why
//! this is one module rather than two: an encoder that skipped it and a decoder
//! that refused it would agree with each other and with no nameserver.

const std = @import("std");

const wire = @import("lookup_wire.zig");

/// A label, or the reserved encoding that is neither.
const name_label: u8 = 0x00;

/// A compression pointer. RFC 1035 §4.1.4 spells it `11` in the top two bits
/// and an offset in the low fourteen.
pub const name_pointer: u8 = 0xc0;

/// The wire form of a presentation name, written into `out`, and its length.
///
/// Every dot is a length octet and the name's own trailing dot is the root's
/// terminator, so `out` needs `name.len + 1` bytes.
pub fn writeName(name: []const u8, out: []u8) wire.WireError!usize {
    if (name.len == 0 or name[name.len - 1] != '.') return error.UnterminatedName;
    var rest = name[0 .. name.len - 1];
    if (rest.len == 0) {
        // The root: one zero octet and no labels.
        if (out.len == 0) return error.BufferTooSmall;
        out[0] = 0;
        return 1;
    }
    var at: usize = 0;
    while (true) {
        const dot = std.mem.indexOfScalar(u8, rest, '.') orelse rest.len;
        const label = rest[0..dot];
        if (label.len == 0) return error.EmptyLabel;
        if (label.len > wire.max_label_length) return error.LabelTooLong;
        if (at + 1 + label.len > out.len) return error.BufferTooSmall;
        out[at] = @intCast(label.len);
        @memcpy(out[at + 1 ..][0..label.len], label);
        at += 1 + label.len;
        if (dot == rest.len) break;
        rest = rest[dot + 1 ..];
    }
    if (at + 1 > out.len) return error.BufferTooSmall;
    out[at] = 0;
    return at + 1;
}

/// Where a decoded name ends in the message, and how much of it was written.
pub const Decoded = struct {
    /// Just past the name in the message, which is *not* where the walk
    /// finished when a pointer was taken: a pointer is two octets and the rest
    /// of the name is elsewhere, so this is the position after those two.
    end: usize,
    /// The presentation form written into the caller's buffer, trailing dot
    /// included. Zero when the caller asked for no name.
    written: usize,
};

/// Decode the name at `at` into `out`, in presentation form.
///
/// An `out` of length zero decodes without materialising, which is what walking
/// past a question is. The walk needs no step counter because RFC 1035 §4.1.4's
/// pointer names a *prior* occurrence: a target at or after the pointer's own
/// offset is `BadName`, so every jump moves strictly backwards while labels
/// move forwards, and neither can revisit a byte.
pub fn readName(message: []const u8, at: usize, out: []u8) wire.WireError!Decoded {
    const capture = out.len != 0;
    var cursor = at;
    var written: usize = 0;
    var end: ?usize = null;
    while (true) {
        if (cursor >= message.len) return error.ShortMessage;
        const lead = message[cursor];
        switch (lead & name_pointer) {
            name_pointer => {
                if (cursor + 1 >= message.len) return error.ShortMessage;
                const target = (@as(usize, lead & ~name_pointer) << 8) | message[cursor + 1];
                if (target >= message.len or target >= cursor) return error.BadName;
                if (end == null) end = cursor + 2;
                cursor = target;
            },
            name_label => {
                cursor += 1;
                if (lead == 0) {
                    // Every label already wrote the dot that follows it, so the
                    // root's terminator adds one only for a name that was the
                    // root all along — which is how `"."` comes out of a name
                    // with no labels rather than an empty string.
                    if (capture and written == 0) try writeByte(out, &written, '.');
                    // `end` is null only when no pointer was taken, and then it
                    // is this cursor: a name that ends at its own terminator
                    // ends one past it, which is where a record's `TYPE` is.
                    return .{ .end = end orelse cursor, .written = written };
                }
                if (cursor + lead > message.len) return error.ShortMessage;
                if (capture) {
                    try writeBytes(out, &written, message[cursor..][0..lead]);
                    try writeByte(out, &written, '.');
                }
                cursor += lead;
            },
            // `01` and `10` are reserved by §4.1.4 and there is no length to
            // read out of them, so a name using one is refused.
            else => return error.BadName,
        }
    }
}

fn writeByte(out: []u8, at: *usize, value: u8) wire.WireError!void {
    if (at.* >= out.len) return error.BufferTooSmall;
    out[at.*] = value;
    at.* += 1;
}

fn writeBytes(out: []u8, at: *usize, bytes: []const u8) wire.WireError!void {
    if (at.* + bytes.len > out.len) return error.BufferTooSmall;
    @memcpy(out[at.*..][0..bytes.len], bytes);
    at.* += bytes.len;
}