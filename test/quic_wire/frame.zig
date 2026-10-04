//! RFC 9000 §19: the QUIC frame codec, over `vendor/quic/src/quic/frame.zig`'s
//! published `Frame.parseSized`.
//!
//! What this file does is ask the codec a question and check the answer
//! against `frame_walk.zig`, which reads the same bytes from §19 without ever
//! calling the codec. Four things are compared: the union tag the codec chose
//! against the type §19's numbering gives the code, the span it consumed
//! against the span §19 says that type occupies, every borrowed payload
//! against the offset and length §19's length field put it at, and every ACK
//! range against the absolute ranges §19.3.1's descent rule produces.
//!
//! What is not compared here, and why. `Frame.write` is not run over the
//! fuzzer's bytes: PADDING, a STREAM without its length bit and a DATAGRAM
//! without a length have no canonical encoding — the RFC gives them an implied
//! remainder — so a re-encode would only prove the codec agrees with itself.
//! The two refusals are told apart by the walk rather than merely accepted:
//! a body running past the datagram and a truncated varint are different
//! faults, and the walk reaches whichever the bytes make first.
//!
//! `parseSized` takes `[]u8` because a decoded `Frame` hands back mutable
//! borrowed slices, so the oracle copies into a stack buffer bounded at
//! `max_payload`. Nothing here writes through those slices.

const std = @import("std");
const quic = @import("quic");
const frame = quic.frame;
const walk_module = @import("frame_walk.zig");

/// RFC 9000 §14 keeps a packet inside one UDP datagram, and the vendored core
/// stages `packet.MAX_PACKET_LEN`, also 1536. A frame longer than this cannot
/// arrive, so an input past it is not a weaker test — it is not a frame.
const max_payload = 1536;

pub const Error = error{
    TestUnexpectedResult,
    TestExpectedEqual,
    TestExpectedError,
    TestUnexpectedError,
};

/// The refusal a walk reason stands for, as the codec names it. Both sets are
/// closed and two-armed, so this is a rename and not a judgement.
fn reasonOf(err: anyerror) walk_module.Reason {
    return switch (err) {
        error.EndOfStream => error.end_of_stream,
        error.FrameEncodingError => error.frame_encoding_error,
        else => error.none,
    };
}

/// The one place a walk refusal is not already answered. `rfcWalk` stops by
/// refusing, and the refusal reaching here means the codec *accepted* these
/// bytes: §19 read a different fact about them — a truncated varint
/// (`end_of_stream`), a body past the datagram or a type §12.4 condemns
/// (`frame_encoding_error`), or a stop with no RFC name (`none`) — and the
/// codec owes that refusal. Every stop is therefore the same defect, and the
/// one that fired is named on the way out rather than folded into the tag.
fn walked(walk: walk_module.Reason!walk_module.Walk) Error!walk_module.Walk {
    return walk catch |why| {
        std.debug.print("quic frame fuzz: accepted bytes the RFC walk refused: {s}\n", .{@errorName(why)});
        return error.TestUnexpectedError;
    };
}

/// Oracle: a payload is a view into the decode buffer at exactly the offset
/// §19's length field put it, not a copy of it and not a view past the end.
/// The frame type documents every such slice as borrowed, so a decoder that
/// copied, or pointed somewhere else, would break that promise silently.
fn expectBorrow(bytes: []const u8, walk: walk_module.Walk, data: []const u8) Error!void {
    if (!walk.has_body) return error.TestUnexpectedResult;
    if (data.len != walk.body_len) return error.TestExpectedEqual;
    if (data.len > bytes.len) return error.TestExpectedEqual;
    const base = @intFromPtr(bytes.ptr);
    const at = @intFromPtr(data.ptr);
    if (at < base or at - base != walk.body_at) return error.TestExpectedEqual;
}

fn checkAck(
    acks: walk_module.Acks,
    largest: u64,
    delay: u64,
    first_range: u64,
    count: u8,
    ranges: []const frame.AckRange,
) Error!void {
    if (!acks.present) return error.TestUnexpectedResult;
    if (largest != acks.largest) return error.TestExpectedEqual;
    if (delay != acks.delay) return error.TestExpectedEqual;
    if (first_range != acks.first_range) return error.TestExpectedEqual;
    if (@as(usize, count) != acks.count) return error.TestExpectedEqual;
    for (acks.ranges[0..acks.count], ranges[0..acks.count]) |want, got| {
        if (got.start != want.start or got.end != want.end) return error.TestExpectedEqual;
    }
}

/// Oracle: what an accepted parse produced — tag, span, payloads, ranges.
fn checkDecoded(bytes: []const u8, decoded: frame.Frame, walk: walk_module.Walk, size: usize) Error!void {
    const tag = walk_module.rfcTag(walk.code) orelse return error.TestUnexpectedResult;
    if (std.meta.activeTag(decoded) != tag) return error.TestExpectedEqual;
    // Oracle: the span. A packet holds several frames in one buffer, so where
    // this one ended is what says where the next one begins.
    if (size != walk.size) return error.TestExpectedEqual;

    switch (decoded) {
        .padding => |n| {
            // §19.1: one PADDING frame covers the run of zeros behind its type
            // code, and `write` emits that many zeros, so the count a decode
            // reports is the span the frame took — which the span oracle above
            // has already said is where the next frame begins. A frame takes
            // at least its type code, so there is no empty frame for this to
            // reject: the type code `80 00 00 00` is four octets of PADDING
            // type whatever follows it, and a decode reporting no octets at all
            // is the span oracle's finding, not one this count can add to.
            if (n != walk.size) return error.TestExpectedEqual;
        },
        .ack => |a| try checkAck(
            walk.acks,
            a.largest_ack,
            a.ack_delay,
            a.first_ack_range,
            a.ack_range_count,
            &a.ack_ranges,
        ),
        .ack_ecn => |a| try checkAck(
            walk.acks,
            a.largest_ack,
            a.ack_delay,
            a.first_ack_range,
            a.ack_range_count,
            &a.ack_ranges,
        ),
        .crypto => |c| try expectBorrow(bytes, walk, c.data),
        .new_token => |t| try expectBorrow(bytes, walk, t),
        .stream => |s| try expectBorrow(bytes, walk, s.data),
        .datagram => |d| try expectBorrow(bytes, walk, d.data),
        .datagram_with_length => |d| try expectBorrow(bytes, walk, d.data),
        .connection_close => |c| try expectBorrow(bytes, walk, c.reason),
        .application_close => |c| try expectBorrow(bytes, walk, c.reason),
        .new_connection_id => |c| {
            try expectBorrow(bytes, walk, c.conn_id);
            // §19.15 puts the stateless reset token immediately after the
            // connection id, so the frame's own span says which 16 bytes are
            // the token. Those bytes are copied out rather than borrowed, so
            // unlike the id they must be compared by value against the wire.
            const at = walk.body_at + walk.body_len;
            if (at + 16 != walk.size or at > bytes.len) return error.TestExpectedEqual;
            if (!std.mem.eql(u8, &c.stateless_reset_token, bytes[at..][0..16])) {
                return error.TestExpectedEqual;
            }
        },
        // The remaining types are fixed-width or varint fields with no
        // payload and no length of their own, so the span and the tag are the
        // whole of what §19 says about them.
        .ping,
        .handshake_done,
        .immediate_ack,
        .reset_stream,
        .stop_sending,
        .max_data,
        .max_stream_data,
        .max_streams_bidi,
        .max_streams_uni,
        .data_blocked,
        .stream_data_blocked,
        .streams_blocked_bidi,
        .streams_blocked_uni,
        .retire_connection_id,
        .path_challenge,
        .path_response,
        .ack_frequency,
        => {},
    }
}

pub fn check(input: []const u8) Error!void {
    if (input.len > max_payload) return;
    var scratch: [max_payload]u8 = undefined;
    @memcpy(scratch[0..input.len], input);
    const bytes = scratch[0..input.len];

    var size: usize = 0;
    const decoded = frame.Frame.parseSized(bytes, &size) catch |err| {
        if (walk_module.rfcWalk(bytes)) |_| {
            // §19 reads these bytes as a frame this codec declined to decode.
            return error.TestUnexpectedError;
        } else |why| {
            // A refusal is legal only where §19 condemns these bytes, and only
            // for the reason the independent walk reached first.
            if (reasonOf(err) != why) return error.TestExpectedEqual;
            return;
        }
    };

    try checkDecoded(bytes, decoded, try walked(walk_module.rfcWalk(bytes)), size);
}
