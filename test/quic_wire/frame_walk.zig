//! RFC 9000 §19's frame formats, read from the RFC rather than from the codec.
//!
//! This is the reference side of the frame target, split out from
//! `frame.zig` because the two are different responsibilities: this file says
//! what a type code means and how many octets §19 says its frame occupies,
//! and `frame.zig` asks `Frame.parseSized` whether it agrees. Keeping them
//! apart is what stops the comparison from collapsing into one function
//! checking itself — the walk here never calls the codec, and the checks there
//! never re-derive a length.
//!
//! §19 gives every frame type a wire format, and they are short enough to
//! state in full. A type code from a varint, then for each type the fields §19
//! lists, then the payload its length field declares. The two drafts the core
//! also speaks — `draft-ietf-quic-datagram` for 0x30/0x31 and
//! `draft-ietf-quic-ack-frequency` for 0x1f/0xaf — are named where they
//! appear, because §19's numbering stops at 0x1e and the codec does not.

const quic = @import("quic");
const frame = quic.frame;

/// Why this reading of the bytes stops. The codec's own refusals are
/// `FrameEncodingError` — a frame this module cannot decode — and
/// `EndOfStream` — a truncated varint or fixed-size field — and this walk has
/// to reach the same one for the same bytes. It is an error set because a
/// stop *is* the refusal `rfcWalk` hands back, and `none` is the value a
/// refusal this walk has no name for carries.
pub const Reason = error{ none, end_of_stream, frame_encoding_error };

/// §19.3.1's empty range: what every slot past `count` holds, and what the
/// array starts at. Named out here rather than written inline because an
/// anonymous struct literal in a field's own default is declared as a struct
/// of the enclosing declaration and never gets the array's element type as
/// its destination — the literal has to already be a `frame.AckRange` before
/// it reaches the `**`.
const empty_range: frame.AckRange = .{ .start = 0, .end = 0 };

/// §19.3.1's ACK ranges, recomputed from the wire.
pub const Acks = struct {
    present: bool = false,
    largest: u64 = 0,
    delay: u64 = 0,
    first_range: u64 = 0,
    count: usize = 0,
    ranges: [frame.MAX_ACK_RANGES]frame.AckRange = .{empty_range} ** frame.MAX_ACK_RANGES,
};

/// What §19 says one frame occupies: the span it took, the payload its length
/// field declared, and its type code.
pub const Walk = struct {
    code: u64 = 0,
    size: usize = 0,
    has_body: bool = false,
    body_at: usize = 0,
    body_len: usize = 0,
    acks: Acks = .{},
};

/// The frame type RFC 9000 §19's numbering gives a code, and null for a code
/// the section does not name. §12.4 makes such a frame a FRAME_ENCODING_ERROR
/// rather than something a receiver may skip.
pub fn rfcTag(code: u64) ?frame.FrameType {
    return switch (code) {
        0x00 => .padding,
        0x01 => .ping,
        0x02 => .ack,
        0x03 => .ack_ecn,
        0x04 => .reset_stream,
        0x05 => .stop_sending,
        0x06 => .crypto,
        0x07 => .new_token,
        0x08...0x0f => .stream,
        0x10 => .max_data,
        0x11 => .max_stream_data,
        0x12 => .max_streams_bidi,
        0x13 => .max_streams_uni,
        0x14 => .data_blocked,
        0x15 => .stream_data_blocked,
        0x16 => .streams_blocked_bidi,
        0x17 => .streams_blocked_uni,
        0x18 => .new_connection_id,
        0x19 => .retire_connection_id,
        0x1a => .path_challenge,
        0x1b => .path_response,
        0x1c => .connection_close,
        0x1d => .application_close,
        0x1e => .handshake_done,
        0x1f => .immediate_ack,
        0x30 => .datagram,
        0x31 => .datagram_with_length,
        0xaf => .ack_frequency,
        else => null,
    };
}

/// RFC 9000 §16: one varint at the cursor, read from the table.
fn varintAt(bytes: []const u8, cursor: *usize) Reason!u64 {
    const rest = bytes[cursor.*..];
    if (rest.len == 0) return error.end_of_stream;
    const width = @as(usize, 1) << @intCast(rest[0] >> 6);
    if (rest.len < width) return error.end_of_stream;
    var value: u64 = rest[0] & 0x3f;
    for (rest[1..width]) |b| value = (value << 8) | b;
    cursor.* += width;
    return value;
}

fn skipVars(bytes: []const u8, cursor: *usize, n: usize) Reason!void {
    for (0..n) |_| _ = try varintAt(bytes, cursor);
}

fn leadingZeros(bytes: []const u8) usize {
    var i: usize = 0;
    while (i < bytes.len and bytes[i] == 0) i += 1;
    return i;
}

/// A §19 length field: the payload must fit the datagram that carried it.
fn bodyWalk(bytes: []const u8, cursor: *usize, length: u64, out: *Walk) Reason!void {
    if (length > @as(u64, bytes.len - cursor.*)) return error.frame_encoding_error;
    out.has_body = true;
    out.body_at = cursor.*;
    out.body_len = @intCast(length);
    cursor.* += @intCast(length);
}

/// §19.3.1's descent: each additional range is a gap and a length below the
/// range before it, and a range reaching below packet number zero is a
/// FRAME_ENCODING_ERROR rather than something to clamp into range. Every
/// declared range is validated; only the first `MAX_ACK_RANGES` are kept, as
/// the type says, so a longer ACK is shortened and never silently misread.
fn ackWalk(bytes: []const u8, cursor: *usize, with_ecn: bool, out: *Acks) Reason!void {
    var at = cursor.*;
    const largest = try varintAt(bytes, &at);
    const delay = try varintAt(bytes, &at);
    const declared = try varintAt(bytes, &at);
    const first_range = try varintAt(bytes, &at);
    if (first_range > largest) return error.frame_encoding_error;

    var count: usize = 0;
    var smallest = largest - first_range;
    var i: u64 = 0;
    // Each remaining range spends at least two bytes, so a count past the
    // bytes left is a truncated frame, not a loop worth entering.
    while (i < declared and bytes.len - at >= 2) : (i += 1) {
        const gap = try varintAt(bytes, &at);
        const range_len = try varintAt(bytes, &at);
        if (smallest < gap +| 2) return error.frame_encoding_error;
        const range_largest = smallest - gap - 2;
        if (range_len > range_largest) return error.frame_encoding_error;
        if (count < frame.MAX_ACK_RANGES) {
            out.ranges[count] = .{ .start = range_largest - range_len, .end = range_largest };
            count += 1;
        }
        smallest = range_largest - range_len;
    }
    if (i < declared) return error.end_of_stream;
    if (with_ecn) try skipVars(bytes, &at, 3);

    out.present = true;
    out.largest = largest;
    out.delay = delay;
    out.first_range = first_range;
    out.count = count;
    cursor.* = at;
}

/// §19's formats, walked from the RFC's own description of each type.
pub fn rfcWalk(bytes: []const u8) Reason!Walk {
    var cursor: usize = 0;
    const code = try varintAt(bytes, &cursor);
    if (rfcTag(code) == null) return error.frame_encoding_error;
    var out: Walk = .{ .code = code };
    switch (code) {
        // §19.1: PADDING is a run of zero bytes with no length of its own, so
        // the frame is its type code followed by the whole run of zeros behind
        // it. The run starts where the type code ends and not at the type byte
        // itself, because §19's preamble lets a type be spelled wider than the
        // shortest encoding that carries it — "Frame Type values do not need to
        // be encoded on the shortest possible number of bytes necessary", which
        // is §16's own rule for every other varint on the wire. A four-octet
        // `80 00 00 00` is a type code reading as 0x00, and those four octets
        // are the frame's type code whether or not they are zero themselves.
        0x00 => {
            const run = leadingZeros(bytes[cursor..]);
            cursor += run;
        },
        // §19.2 PING, §19.20 HANDSHAKE_DONE, draft-ietf-quic-ack-frequency
        // IMMEDIATE_ACK: nothing follows the type code.
        0x01, 0x1e, 0x1f => {},
        // §19.3: Largest Acknowledged, ACK Delay, ACK Range Count, First ACK
        // Range, then a gap and a length per additional range, then the three
        // ECN counts when the type is the ECN one.
        0x02, 0x03 => try ackWalk(bytes, &cursor, code == 0x03, &out.acks),
        // §19.4 RESET_STREAM, §19.5 STOP_SENDING.
        0x04 => try skipVars(bytes, &cursor, 3),
        0x05 => try skipVars(bytes, &cursor, 2),
        // §19.6 CRYPTO: Offset, Length, Crypto Data.
        0x06 => {
            try skipVars(bytes, &cursor, 1);
            try bodyWalk(bytes, &cursor, try varintAt(bytes, &cursor), &out);
        },
        // §19.7 NEW_TOKEN: Length, Token.
        0x07 => try bodyWalk(bytes, &cursor, try varintAt(bytes, &cursor), &out),
        // §19.8: Stream Type, Stream ID, [Offset], [Length], Stream Data —
        // the optional fields are the type's own 0x04 and 0x02 bits.
        0x08...0x0f => {
            _ = try varintAt(bytes, &cursor);
            if (code & 0x04 != 0) try skipVars(bytes, &cursor, 1);
            if (code & 0x02 != 0) {
                try bodyWalk(bytes, &cursor, try varintAt(bytes, &cursor), &out);
            } else {
                // §19.8 without the length bit: the data is the remainder.
                out.has_body = true;
                out.body_at = cursor;
                out.body_len = bytes.len - cursor;
                cursor = bytes.len;
            }
        },
        // §19.10 through §19.17 and §19.16: one varint, plus the two that
        // carry a stream id alongside it.
        0x10, 0x12, 0x13, 0x14, 0x16, 0x17, 0x19 => try skipVars(bytes, &cursor, 1),
        0x11, 0x15 => try skipVars(bytes, &cursor, 2),
        // §19.15 NEW_CONNECTION_ID: Sequence Number, Retire Prior To, a
        // one-byte length the RFC bounds to 1..20, the ID, then a 16-byte
        // stateless reset token.
        0x18 => {
            try skipVars(bytes, &cursor, 2);
            if (cursor >= bytes.len) return error.end_of_stream;
            const cid_len = @as(usize, bytes[cursor]);
            cursor += 1;
            if (cid_len < 1 or cid_len > 20) return error.frame_encoding_error;
            try bodyWalk(bytes, &cursor, cid_len, &out);
            if (bytes.len - cursor < 16) return error.end_of_stream;
            cursor += 16;
        },
        // §19.18 PATH_CHALLENGE, §19.19 PATH_RESPONSE: eight fixed bytes.
        0x1a, 0x1b => {
            if (bytes.len - cursor < 8) return error.end_of_stream;
            cursor += 8;
        },
        // §19.19 CONNECTION_CLOSE: Error Code, Frame Type, Reason Phrase
        // Length, Reason Phrase.
        0x1c => {
            try skipVars(bytes, &cursor, 2);
            try bodyWalk(bytes, &cursor, try varintAt(bytes, &cursor), &out);
        },
        // §19.20 APPLICATION_CLOSE: Error Code, Reason Phrase Length, Phrase.
        0x1d => {
            try skipVars(bytes, &cursor, 1);
            try bodyWalk(bytes, &cursor, try varintAt(bytes, &cursor), &out);
        },
        // draft-ietf-quic-datagram: 0x30 carries no length of its own, so the
        // data is the rest of the packet and the frame ends with it — the same
        // implied remainder §19.8's STREAM frame without its length bit has,
        // and for the same reason the cursor moves to the end of the bytes.
        0x30 => {
            out.has_body = true;
            out.body_at = cursor;
            out.body_len = bytes.len - cursor;
            cursor = bytes.len;
        },
        0x31 => try bodyWalk(bytes, &cursor, try varintAt(bytes, &cursor), &out),
        // draft-ietf-quic-ack-frequency: four varints.
        0xaf => try skipVars(bytes, &cursor, 4),
        else => unreachable,
    }
    out.size = cursor;
    return out;
}
