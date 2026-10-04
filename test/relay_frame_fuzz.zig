//! Fuzz target for the relay frame decoder.
//!
//! One target file and one corpus directory per decoder: `zig build fuzz` replays
//! the corpus, and `zig build fuzz --fuzz=<N>` hands the same corpus to Zig's
//! coverage-guided fuzzer and lets it mutate for N iterations. A frame is the
//! first thing a relay reads that it did not choose, every byte of it comes off
//! a peer's socket, and two of its rules — the batch invariant and the
//! v1/v2 split — are the ones the plan says fail silently.

const std = @import("std");
const ozai = @import("ozai");
const frame = ozai.relay_frame_types;
const writer = ozai.relay_frame_writer;
const codec = ozai.relay_frame_codec;
const t = std.testing;

/// Seeds are the bytes a relay would read out of one WebSocket message.
///
/// The two `captured_` seeds are the hexdumps upstream wrote in
/// `iroh-relay/src/protos/relay.rs` at commit 187f59e8, so a mutation starts
/// from something iroh actually sent. The rest are the shapes the codec has a
/// rule for: no header at all, a type past the table, a batch whose segment size
/// is wider than its payload, a header that names a varint it has not finished
/// sending, a segment size of zero, a payload longer than its type allows, a
/// postcard length that runs past the frame, a signature one byte short, and a
/// frame type spelled in the four-byte form for a value that fits in one.
/// `test/corpus/relay_frame/` is the record, and a file there is live only once
/// it is named here.
const corpus = [_][]const u8{
    @embedFile("corpus/relay_frame/empty"), // 0 bytes: no header at all
    @embedFile("corpus/relay_frame/ping"), // upstream: a whole `Ping` frame
    @embedFile("corpus/relay_frame/captured_batch"), // upstream: two datagrams of six
    @embedFile("corpus/relay_frame/captured_health"), // upstream: v1 only, and text
    @embedFile("corpus/relay_frame/unknown_type"), // 14, one past the table
    @embedFile("corpus/relay_frame/truncated_varint"), // a two-byte header, one byte sent
    @embedFile("corpus/relay_frame/batch_segment_wider_than_payload"), // 1024 over four
    @embedFile("corpus/relay_frame/batch_zero_segment"), // a segment size of zero
    @embedFile("corpus/relay_frame/status_trailing_byte"), // more payload than one byte
    @embedFile("corpus/relay_frame/denial_length_past_end"), // a length past the frame
    @embedFile("corpus/relay_frame/client_auth_short"), // a signature one byte short
    @embedFile("corpus/relay_frame/wide_varint_status"), // the four-byte spelling
};

/// Long enough to overrun every encoding above, so a mutated input can still
/// reach a length check it was not grown for, and long enough for the widest
/// frame a decode can produce from it: a denial whose reason is the whole
/// message needs its varint length on top.
const input_buffer_len = 128;

/// A decoded frame is at most `input_buffer_len` bytes long, and re-encoding one
/// never widens it, so this holds any canonical spelling the oracle compares.
const reencode_len = input_buffer_len + 32;

/// Both versions, in the order they are checked. The split is part of the frame
/// format and not a build flag, so a seed that only exercises `v1` leaves half
/// the table — `Status` — unread, and one that only exercises `v2` leaves
/// `Health` unread.
const versions = [_]frame.ProtocolVersion{ .v1, .v2 };

comptime {
    // A seed longer than the window the fuzzer reads into would be cut short on
    // its way to the oracle, and the length checks would never see the rest.
    for (corpus) |seed| std.debug.assert(seed.len <= input_buffer_len);
}

/// The fuzzer keeps one of these by pointer for the whole run, so it is empty by
/// design: everything the oracle needs is comptime.
const Context = struct {};

test "relay frame decode" {
    // A fuzz test is a plain test to a plain build. Without `-ffuzz` the runner
    // walks the corpus instead of handing it to the fuzzer, which is what makes
    // a bare `zig build fuzz` a bounded gate rather than an empty step.
    try t.fuzz(Context{}, testOne, .{ .corpus = &corpus });
}

fn testOne(_: Context, smith: *t.Smith) anyerror!void {
    var buffer: [input_buffer_len]u8 = undefined;
    // `in` is the corpus entry verbatim while the corpus is replayed, and null
    // when the fuzzer drives, in which case `slice` consumes its input.
    const bytes = if (smith.in) |replay| replay else buffer[0..smith.slice(&buffer)];
    for (versions) |version| try check(bytes, version);
}

fn check(bytes: []const u8, version: frame.ProtocolVersion) !void {
    const message = codec.decode(bytes, version) catch |err| {
        // Oracle: order. A frame type this version does not define is refused on
        // the type alone, before the payload is read, so the same bytes under the
        // version that does define it cannot fail the same way. Upstream checks
        // the version inside each payload arm (`relay.rs:441`), which means a
        // `Health` frame with a truncated payload answers `InvalidFrame` under v1
        // and `FrameNotAllowedInVersion` under v2; here the answer does not depend
        // on the payload at all. Everything else on this path is the no-panic
        // check upstream's `relay_client_frame_decode_no_panic` is
        // (`relay.rs:998`).
        if (err == error.FrameNotAllowedInVersion) {
            const other: frame.ProtocolVersion = if (version == .v1) .v2 else .v1;
            const other_refused = if (codec.decode(bytes, other)) |_|
                false
            else |other_err|
                other_err == error.FrameNotAllowedInVersion;
            try t.expect(!other_refused);
        }
        return;
    };
    const frame_type: frame.FrameType = std.meta.activeTag(message);

    // Oracle: version. A frame that decoded is a frame this version defines,
    // which is the v1/v2 split stated as a fact about the value rather than as
    // the check that produced it.
    try t.expect(frame_type.allowedIn(version));

    // Oracle: size. The length `encodedLen` claims is the length written, for
    // every variant. Upstream asserts this over a proptest
    // (`relay.rs:925`); here every decoded value goes through it.
    var out: [reencode_len]u8 = undefined;
    const written = try codec.encode(message, version, &out);
    try t.expectEqual(writer.encodedLen(message), written.len);

    // Oracle: the batch invariant, both halves, in both directions. A datagram
    // frame that decoded as a batch must carry a segment size and one that
    // decoded as a single datagram must not, and the type the value reports for
    // itself must be the type it arrived under. This is `docs/ARCHITECTURE.md`
    // rule 7, and it is the assertion the fuzzer exists to break.
    try checkBatchInvariant(message, frame_type);

    // Oracle: fidelity. The re-encoding of a decoded frame is the canonical
    // spelling, not the one that was sent — an ECN byte of four reads as none
    // and is written as zero — so the fixed point is taken from the second
    // decode, not the first. Upstream's own round-trip proptests
    // (`relay.rs:909`) have the same caveat and the same answer.
    const recoded = try codec.decode(written, version);
    try t.expect(codec.eql(message, recoded));
    try checkBatchInvariant(recoded, frame_type);

    var again: [reencode_len]u8 = undefined;
    try t.expectEqualSlices(u8, written, try codec.encode(recoded, version, &again));
}

/// `segment_size.is_some()` if and only if the frame is the batch type, in the
/// one place the fuzzer can ask it of every decoded value.
fn checkBatchInvariant(message: frame.Message, frame_type: frame.FrameType) !void {
    const datagram_frame = datagramFrameOf(message) orelse return;
    const is_batch = frame.FrameType.isDatagramBatch(frame_type);
    try t.expectEqual(is_batch, datagram_frame.datagrams.isBatch());

    // And the field the invariant is about, reached the other way round: ask the
    // value which frame type it belongs in and require the one it arrived under.
    const direction: frame.Direction = if (frame_type == .client_to_relay_datagram or
        frame_type == .client_to_relay_datagram_batch)
        .client_to_relay
    else
        .relay_to_client;
    try t.expectEqual(frame_type, datagram_frame.datagrams.frameType(direction));

    // A segment size that is set is a size a datagram can have. Zero is the
    // value that would make the two halves of the invariant disagree, and
    // `decode` refuses it; this is where a decoder that did not would show up.
    if (datagram_frame.datagrams.segment_size) |segment_size| {
        try t.expect(segment_size > 0);
    }
}

/// The payload of whichever of the four datagram frames this is, or null for the
/// other ten.
fn datagramFrameOf(message: frame.Message) ?frame.DatagramFrame {
    return switch (std.meta.activeTag(message)) {
        .client_to_relay_datagram => message.client_to_relay_datagram,
        .client_to_relay_datagram_batch => message.client_to_relay_datagram_batch,
        .relay_to_client_datagram => message.relay_to_client_datagram,
        .relay_to_client_datagram_batch => message.relay_to_client_datagram_batch,
        else => null,
    };
}
