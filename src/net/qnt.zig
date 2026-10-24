//! Quic Number-Time: the QNT frame and its negotiation, as pure bytes over a
//! caller's slice.
//! This standalone Number-Time model is not Noq's native NAT traversal wire.
//! Production uses vendor ADD_ADDRESS, REACH_ADDRESS and REMOVE_ADDRESS frames.
//! The pinned native Rust captures do not validate this codec.
//!
//! QNT is the frame that accompanies QAD and is not a variant of it. Where
//! QAD is a one-shot observation — one frame, one address, "here is where I saw
//! you" — QNT is a repeated exchange that answers a different question: not
//! *where* the peer is, but *how fast the peer's packet numbers advance*. A
//! sender answers with the packet numbers it has received and the instant it
//! wrote them down, so the requester can difference two answers and get a rate
//! for the path without putting bulk traffic on it. One exchange is a sequence
//! of rounds, each one asking and each one answering; the aggregation over
//! those rounds is `qnt_state.zig`, not this file.
//!
//! `qad.zig` is the sibling and this file is deliberately its dialect rather
//! than a second one. What follows is the whole of where the two agree and
//! where they cannot.
//!
//! # Where this matches `qad.zig`
//!
//! - **The frame type block.** Both frames live in the address-discovery
//!   codepoint range, and in both the least significant bit of the type is the
//!   address family, so `Family`, `familyOf` and `frameTypeOf` are the same
//!   three declarations with two constants changed. `Family` is not redeclared
//!   here: it is `qad.Family`, so a path's family has one type in this tree.
//! - **The varint.** One QUIC variable-length integer, RFC 9000 §16. The rule
//!   and the boundary table live in `wire/quic_varint.zig` and this file calls
//!   `put` and `get` there: the encoding is a transport specification's, it
//!   names no discovery or gossip concept, and `src/wire/` is the layer below
//!   every codec that spells bytes — so `qad.zig` and
//!   `node/node_relay_frame.zig` call the same three functions and the sweep
//!   that holds them to §16 exists once, in that module.
//! - **The refusals and their shape.** `NoRoom` before the bytes that did fit
//!   mean anything, `Truncated` for every prefix that ends inside a field, a
//!   closed `Error` with no arm a peer cannot provoke, a derived `Decoded`
//!   carrying the frame and the bytes it took, and an encode into the caller's
//!   buffer that refuses rather than grows.
//! - **The module doc's posture.** Sources are named, what the tests pin is
//!   listed, and what is unpinned is said plainly rather than left to be
//!   assumed.
//!
//! # Where the two genuinely differ, and why
//!
//! Four differences, each forced by the frame rather than chosen:
//!
//! 1. **QNT's body is variable-length and QAD's is not.** QAD is a type, a
//!    sequence number, an address and a port, so `qad.max_frame_length` is a
//!    bound on a body whose length is known. QNT ends in a list, and a QUIC
//!    packet holds several frames, so the frame has to say where its own list
//!    stops: a `Range Count` varint precedes the ranges. That is also why QNT
//!    has `TooManyRanges` and QAD has no arm for a length it cannot choose.
//! 2. **QNT has a time field and QAD has none.** QAD's frame is a fact about an
//!    address; QNT's is a fact about an interval, so it carries the sender's
//!    own timestamp. It is a varint of microseconds on the **sender's**
//!    monotonic clock and nothing more: 62 bits of microseconds is about a
//!    hundred and forty-six thousand years, so unlike a 32-bit microsecond
//!    field there is no wrap case to reason about at all. The clock is the
//!    sender's because two peers' clocks need not agree — `qnt_state.zig`
//!    differences arrivals on the *reader's* timeline and never differences
//!    two of these timestamps.
//! 3. **QNT carries an opaque challenge and QAD carries nothing to match a
//!    reply with.** QAD has no request, so it has no reply and needs no
//!    correlation. QNT is a request, and the sequence number cannot correlate
//!    it because the *responder* chooses that number. The challenge is eight
//!    fixed bytes — RFC 9000 §8.2.1's PATH_CHALLENGE data width, reused because
//!    it is already the width QUIC uses for "opaque bytes the peer echoes
//!    back", so no new width is introduced.
//! 4. **QNT refuses two shapes QAD cannot express.** A range whose `first` is
//!    above its `last`, and a range list that is not in canonical order. QAD's
//!    body has no list to be out of order in. Canonical means strictly
//!    increasing and never adjacent, which gives one list exactly one
//!    spelling; that is what makes `encode ∘ decode` a fixed point, and it is
//!    this module's rule rather than an upstream MUST, because no upstream text
//!    for QNT exists to carry one (below).
//!
//! # Where the bytes come from, and what is pinned
//!
//! **Read out of a source:** that the codepoints belong to the
//! address-discovery block and that the family is the type's least significant
//! bit — draft-ietf-quic-address-discovery §4.1 and `noq_proto`'s
//! `FrameType::ObservedIpv4Addr` / `ObservedIpv6Addr` at `0x9f81a6` /
//! `0x9f81a7`, both read on 2026-10-05, with the family rule and the field
//! order carried over unchanged.
//!
//! **Not read out of a source, and searched for on 2026-10-05:** the two QNT
//! constants. They are `0x9f81a8` and `0x9f81a9` — the next two in the same
//! block, differing in the same bit — because that is the only assignment the
//! block's own rule admits. It is **not** confirmed. Everything below was
//! read, and none of it carries a QNT frame holding packet numbers and a time:
//!
//! - draft-ietf-quic-address-discovery, its current text and `-00`. §4 defines
//!   OBSERVED_ADDRESS alone; QNT is not in either.
//! - draft-seemann-quic-nat-traversal `-00`, `-02` and its current text. `-02`
//!   defines ADD_ADDRESS, PUNCH_ME_NOW and REMOVE_ADDRESS, and the current
//!   revision has replaced PUNCH_ME_NOW with PUNCH_GRANT, MAX_PUNCH_GRANTS,
//!   PUNCH_REQUEST and PUNCH_DONE; `-00` defines one ICE frame.
//! - draft-bruynooghe-n0-quic-nat-traversal-00, whose title is "n0 QNT" and
//!   whose frames are ADD_ADDRESS, REACH_OUT and REMOVE_ADDRESS.
//! - draft-munizaga-quic-alternative-server-address-02, the ALTERNATIVE_ADDRESS
//!   draft the NAT-traversal draft normatively references. No occurrence of the
//!   string "QNT" in it.
//! - `noq-proto` 0.16.0, 0.17.0, 1.0.0, 1.2.0 and 1.3.0, unpacked from crates.io
//!   and grepped. `FrameType` has no QNT arm in any of them; the only hits for
//!   the string are comments in `connection/mod.rs` about *probing packets* and
//!   a `MAX_QNT_ADDRS` constant in `tests/proptests.rs`.
//! - `iroh-relay` 0.29.0 through 0.35.0, 0.90.0, 0.93.2, 0.95.1, 0.97.0, 0.98.0
//!   and 1.3.0, and `iroh-net` 0.9.0, 0.12.0, 0.16.0, 0.20.0, 0.24.0 and 0.28.0,
//!   the same way. No occurrence.
//!
//!
//! So the layout below rests on the QAD block's rule composed with the
//! measurement QNT is for, and on nothing else. **Pinned by the tests:** both
//! type constants as the exact bytes a QUIC variable-length integer spells
//! them; that they are QAD's two plus one and two, and that QAD's own two are
//! refused here so neither codec can read the other's frame; the field order
//! and the width of every field; every varint boundary in every field; the
//! canonical range rule and all three of its refusals; the truncation bound at
//! every prefix; the buffer bound at every length; and the round trip and its
//! fixed point for both families at every width.
//!
//! No captured Rust golden vector validates this Number-Time codec.
//! Its test vector is derived from the proposed field order and RFC 9000 §16.
//! The vendor-native Noq oracle captures validate a different protocol.
//!
//! **Not implemented here, and said here rather than left to be assumed:** the
//! rule that a frame whose challenge is not the one outstanding is not a reply.
//! That is per-round state, so it belongs to `qnt_state.zig`, by the same
//! argument `qad.zig` gives for the sequence rule it declines to own.
//!
//! # No socket, no clock, no allocator
//!
//! Every function is a function of its arguments and the caller's slice. A
//! decoded frame borrows nothing: the range list is an inline array of a
//! compile-time length, which is what lets it sit in a round record with no
//! lifetime attached. Encoding writes into the caller's buffer and refuses
//! rather than growing it.

const std = @import("std");
const qad = @import("qad.zig");
const quic_varint = @import("../wire/quic_varint.zig");

/// The address family a frame's path belongs to.
///
/// QAD's enum under QNT's name rather than a second one: the two frames select
/// the same two families with the same bit, and a path's family having two
/// types in this directory would be the second opinion `path_table.zig`
/// refuses to allow about anything else.
pub const Family = qad.Family;

const t = std.testing;

/// The QNT frame type for an IPv4 path. One above `qad.frame_type_ipv6`, the
/// last codepoint the address-discovery block is known to hold.
pub const frame_type_ipv4: u64 = 0x9f81a8;

/// The QNT frame type for an IPv6 path, and one more than the IPv4 type
/// because the least significant bit of the type is the family — the same rule
/// §4.1 states for OBSERVED_ADDRESS and the same bit these two differ in.
pub const frame_type_ipv6: u64 = 0x9f81a9;

/// The widest a QUIC variable-length integer is (RFC 9000 §16), so the widest
/// each of this frame's four varint fields can be.
pub const max_varint_length: usize = quic_varint.max_length;

/// The largest value a variable-length integer can carry, and so the largest a
/// sequence number, a timestamp or a range endpoint can be.
///
/// `quic_varint.max_value` under the name this file needs: QNT has three kinds
/// of varint value, and a name naming the first of them would be wrong for the
/// other two.
pub const max_value: u64 = quic_varint.max_value;

/// How many packet-number ranges one frame may carry.
///
/// Eight, and the reason is arithmetic rather than taste: a range costs at most
/// sixteen bytes, so eight of them is 128 bytes of the bound
/// `max_frame_length` states, which leaves a frame small enough to share a
/// 1200-byte datagram with the ACK, the PATH_CHALLENGE and the crypto a
/// probing packet already carries. Nine would cost sixteen bytes more for a
/// ninth run that a path whose loss is that fragmented is better described as
/// a slow path than as a fast one. A peer with more disjoint runs than this is
/// **refused rather than clipped**, because the runs are the measurement and
/// dropping one changes the answer without saying so.
pub const max_packet_ranges: usize = 8;

/// How many bytes of opaque value the challenge occupies, and why eight: it is
/// RFC 9000 §8.2.1's PATH_CHALLENGE data width, which is QUIC's existing
/// width for "bytes the peer echoes back".
pub const challenge_length: usize = 8;

/// The opaque value a reply must echo, so that a frame answering another round
/// is recognisable.
pub const Challenge = [challenge_length]u8;

/// The longest frame `encode` can write: four varints, the challenge, and one
/// `first`/`last` pair per range. Every type constant is a four-byte varint and
/// every count this module writes is a single byte, so this is a bound and not
/// a length.
///
/// 168 bytes, which is a small share of the roughly 1200-byte minimum QUIC
/// datagram (`vendor/quic/src/quic/mtu.zig`) and leaves room for the ACK, the
/// PATH_CHALLENGE and the crypto that share the packet.
pub const max_frame_length: usize =
    4 * max_varint_length + challenge_length + 2 * max_packet_ranges * max_varint_length;

/// Everything this codec can refuse, in one closed set. There is no `anyerror`
/// in this file and no arm a peer cannot provoke.
pub const Error = error{
    /// The caller's buffer cannot hold the frame. Raised before the bytes that
    /// did fit mean anything, so a caller that retries must discard what a
    /// failed `encode` wrote.
    NoRoom,
    /// The slice ended inside a field the frame's type promised.
    Truncated,
    /// The frame type is not one this build carries, so the path family behind
    /// it is one this build does not carry.
    ///
    /// **Refused by name, never skipped.** The family is the only thing this
    /// frame's type decides, so a type that is neither constant names a family
    /// with no arm here — `qad.zig` refuses QAD's own two constants for exactly
    /// this reason, and that refusal is the test that keeps the two codecs
    /// from reading each other's frames.
    UnknownAddressFamily,
    /// A varint field is past `max_value`, so it has no variable-length
    /// integer spelling and this frame cannot be written.
    ///
    /// One arm for three fields, where `qad.zig` has one arm for its one.
    /// Naming the field instead would be one arm per field guarding the same
    /// 62-bit ceiling.
    ValueTooLarge,
    /// The frame claims more ranges than `max_packet_ranges`. Refused, not
    /// truncated: the ranges are the measurement.
    TooManyRanges,
    /// A range's `first` is above its `last`, so it names no packet numbers.
    InvertedRange,
    /// The ranges are not in canonical form — a range that repeats, overlaps or
    /// abuts its predecessor. See the module doc's fourth difference.
    UnorderedRanges,
};

/// A closed run of packet numbers the sender has received, both ends included.
///
/// Inclusive at both ends because that is what makes two adjacent ranges one
/// range, which is what the canonical form requires and what
/// `error.UnorderedRanges` enforces.
pub const PacketRange = struct {
    first: u64,
    last: u64,
};

/// One QNT frame: what the sender had received when it wrote the frame down.
pub const Frame = struct {
    /// Which path family's packet numbers the ranges describe — the low bit of
    /// the frame type. Under QUIC Multipath each path has its own packet number
    /// space, so this is not redundant with the frame's own path: it says
    /// which space the numbers came from.
    family: Family,
    /// The sender's sequence number for this frame, monotonic per connection
    /// on the same rule QAD uses. Carried because it is the family's convention
    /// and it lets a peer order and log frames; **not** read by
    /// `qnt_state.zig`, because a reply is correlated by its challenge and the
    /// number is the responder's to choose.
    sequence: u64,
    /// The round this frame answers. A reply echoing anything else is not a
    /// reply to the round in flight.
    challenge: Challenge,
    /// Microseconds on the sender's own monotonic clock at the instant it wrote
    /// the frame. Not comparable across peers and never differenced against
    /// another frame's timestamp; it exists so a sender can show that its two
    /// samples describe a real interval.
    timestamp: u64,
    /// The runs of packet numbers received, canonical and at most
    /// `max_packet_ranges` of them.
    ranges: [max_packet_ranges]PacketRange,
    /// How many entries of `ranges` the frame carries. The rest of the array is
    /// zeroed, never undefined, so two frames compare with `==`.
    range_count: usize,

    /// The largest packet number the frame says was received, or zero when the
    /// frame carries no ranges.
    ///
    /// Zero for an empty list and not null, because for this exchange the two
    /// are the same measurement: no packet past the first has arrived, so the
    /// number advanced by nothing either way. What a caller must be able to
    /// tell apart is *nothing arrived* from *nothing was asked*, and that
    /// distinction lives in `qnt_state.zig`'s round results, not in a null
    /// here.
    pub fn covered(self: Frame) u64 {
        // Clamped rather than trusted: a frame assembled by hand can carry a
        // count this module would have refused to encode, and reading past the
        // array is a panic rather than an answer.
        const count = @min(self.range_count, max_packet_ranges);
        if (count == 0) return 0;
        return self.ranges[count - 1].last;
    }
};

/// A decoded frame and the bytes it occupied.
pub const Decoded = struct {
    frame: Frame,
    /// How many bytes of the input this frame took, type included. A QUIC
    /// packet holds several frames and the frame before this one has to be able
    /// to find where this one ends.
    length: usize,
};

/// The family a QNT frame type selects, or `error.UnknownAddressFamily`.
pub fn familyOf(frame_type: u64) Error!Family {
    return switch (frame_type) {
        frame_type_ipv4 => .v4,
        frame_type_ipv6 => .v6,
        else => error.UnknownAddressFamily,
    };
}

/// The frame type that carries `family`, the inverse of `familyOf`.
pub fn frameTypeOf(family: Family) u64 {
    return switch (family) {
        .v4 => frame_type_ipv4,
        .v6 => frame_type_ipv6,
    };
}

/// Write `frame` into the front of `out`, and say how many bytes it took.
///
/// The type is derived from `frame.family`, so a frame cannot be written with
/// a type that contradicts the path family behind it.
///
/// Refuses every shape refusal before writing a byte, and `error.NoRoom`
/// partway through, so a caller that retries with a bigger buffer must discard
/// what a failed call wrote.
pub fn encode(frame: Frame, out: []u8) Error!usize {
    try checkShape(frame);
    var offset: usize = 0;
    offset += try quic_varint.put(out[offset..], frameTypeOf(frame.family));
    offset += try quic_varint.put(out[offset..], frame.sequence);
    // The one fixed-width field, guarded the way `qad.zig` guards its address:
    // a buffer that ends inside the challenge is `NoRoom`, not a slice of a
    // slice that has run out. Every varint field is checked by
    // `quic_varint.put` itself, so without this a buffer one byte short of
    // this copy panicked where the rest of the frame answers.
    if (out[offset..].len < challenge_length) return error.NoRoom;
    @memcpy(out[offset..][0..challenge_length], frame.challenge[0..]);
    offset += challenge_length;
    offset += try quic_varint.put(out[offset..], frame.timestamp);
    offset += try quic_varint.put(out[offset..], frame.range_count);
    var index: usize = 0;
    while (index < frame.range_count) : (index += 1) {
        const range = frame.ranges[index];
        offset += try quic_varint.put(out[offset..], range.first);
        offset += try quic_varint.put(out[offset..], range.last);
    }
    return offset;
}

/// Read one QNT frame off the front of `bytes`.
///
/// The order of the reads is the order on the wire and the refusals are checked
/// as they are met, so a frame whose count is past the ceiling is refused
/// before its ranges are read rather than after `max_packet_ranges` of them
/// have been silently dropped.
pub fn decode(bytes: []const u8) Error!Decoded {
    var offset: usize = 0;
    const family = try familyOf(try quic_varint.get(bytes, &offset));
    const sequence = try quic_varint.get(bytes, &offset);
    if (bytes[offset..].len < challenge_length) return error.Truncated;
    var challenge: Challenge = undefined;
    @memcpy(challenge[0..], bytes[offset..][0..challenge_length]);
    offset += challenge_length;
    const timestamp = try quic_varint.get(bytes, &offset);
    const count = try quic_varint.get(bytes, &offset);
    if (count > max_packet_ranges) return error.TooManyRanges;
    const range_count: usize = @intCast(count);
    // Zeroed rather than undefined, so `Frame`'s equality is total: a decoded
    // frame compares equal to the frame it was encoded from, tail included.
    var ranges = @as([max_packet_ranges]PacketRange, @splat(.{ .first = 0, .last = 0 }));
    var index: usize = 0;
    while (index < range_count) : (index += 1) {
        const first = try quic_varint.get(bytes, &offset);
        const last = try quic_varint.get(bytes, &offset);
        try checkRange(first, last, if (index == 0) null else ranges[index - 1]);
        ranges[index] = .{ .first = first, .last = last };
    }
    // The guarded memcpy fills all eight challenge bytes before this aggregate return;
    // ZBC also reports the initialized field at the enclosing return expression.
    // zbc-disable-next-line: use-undefined
    return .{
        .frame = .{
            .family = family,
            .sequence = sequence,
            // Guard and memcpy fill Challenge; ZBC cannot prove its initialization.
            // zbc-disable-next-line: use-undefined
            .challenge = challenge,
            .timestamp = timestamp,
            .ranges = ranges,
            .range_count = range_count,
        },
        .length = offset,
    };
}

/// Everything about a frame's shape that is wrong before a byte is written.
fn checkShape(frame: Frame) Error!void {
    if (frame.range_count > max_packet_ranges) return error.TooManyRanges;
    if (frame.sequence > max_value) return error.ValueTooLarge;
    if (frame.timestamp > max_value) return error.ValueTooLarge;
    var index: usize = 0;
    while (index < frame.range_count) : (index += 1) {
        try checkRange(
            frame.ranges[index].first,
            frame.ranges[index].last,
            if (index == 0) null else frame.ranges[index - 1],
        );
    }
}

/// One range against its own ends and against the range before it.
///
/// The adjacency test is `first - previous.last == 1` rather than
/// `first == previous.last + 1` because the subtraction cannot wrap: the
/// strictly-increasing arm has already established `first > previous.last`.
fn checkRange(first: u64, last: u64, previous: ?PacketRange) Error!void {
    if (first > last) return error.InvertedRange;
    if (last > max_value) return error.ValueTooLarge;
    const before = previous orelse return;
    if (first <= before.last) return error.UnorderedRanges;
    if (first - before.last == 1) return error.UnorderedRanges;
}

comptime {
    // The bound above is a bound because of these facts, and a reader who
    // changes a constant should be told here rather than by a test that stops
    // holding.
    std.debug.assert(quic_varint.length(frame_type_ipv4) == 4);
    std.debug.assert(quic_varint.length(frame_type_ipv6) == 4);
    std.debug.assert(max_frame_length >= 4 + max_varint_length + challenge_length +
        1 + 2 * max_packet_ranges * max_varint_length);
}

// --- tests

/// The bytes `text` spells, spaces allowed between them, into `scratch`.
///
/// Written out for the reason `qad.zig` writes its own out: these are this
/// file's own golden vectors, and borrowing a fixture from another layer would
/// name types this module has no business knowing.
fn hex(text: []const u8, scratch: []u8) ![]const u8 {
    var length: usize = 0;
    var high: ?u8 = null;
    for (text) |character| {
        if (character == ' ') continue;
        const nibble = std.fmt.charToDigit(character, 16) catch return error.InvalidHex;
        if (high) |top| {
            scratch[length] = (top << 4) | nibble;
            length += 1;
            high = null;
        } else {
            high = nibble;
        }
    }
    // A half byte is a typo in a vector, not a byte on the wire.
    if (high != null) return error.InvalidHex;
    return scratch[0..length];
}

fn expectHex(text: []const u8, actual: []const u8) !void {
    var scratch: [64]u8 = undefined;
    const expected = try hex(text, &scratch);
    try t.expectEqualSlices(u8, expected, actual);
}

/// The variable-length integer `value` spells, compared against `text`.
fn expectVarint(text: []const u8, value: u64) !void {
    var scratch: [max_varint_length]u8 = undefined;
    const length = try quic_varint.put(&scratch, value);
    try expectHex(text, scratch[0..length]);
}

/// The varint boundaries RFC 9000 §16 draws, from the module that owns the
/// rule rather than restated here. A comptime array so a field added later is
/// swept without a test being edited.
const widths = quic_varint.boundaries;

/// The largest packet number the one canonical frame the tests build covers, so
/// two ranges can be placed without either being adjacent to its predecessor.
const sweep_ranges = [_]PacketRange{
    .{ .first = 0, .last = 42 },
    .{ .first = 63, .last = max_value },
};

fn frameWith(
    family: Family,
    sequence: u64,
    timestamp: u64,
    ranges: []const PacketRange,
) Frame {
    var built: Frame = .{
        .family = family,
        .sequence = sequence,
        .challenge = .{ 1, 2, 3, 4, 5, 6, 7, 8 },
        .timestamp = timestamp,
        .ranges = @as([max_packet_ranges]PacketRange, @splat(.{ .first = 0, .last = 0 })),
        .range_count = ranges.len,
    };
    for (ranges, 0..) |range, index| built.ranges[index] = range;
    return built;
}

test "the two QNT types are QAD's two plus one and two, and QAD's are not ours" {
    try expectVarint("80 9f 81 a8", frame_type_ipv4);
    try expectVarint("80 9f 81 a9", frame_type_ipv6);

    // The two differ only in the least significant bit, and that bit is the
    // family — so `familyOf` and `frameTypeOf` are inverses over both arms and
    // nothing else is a type.
    try t.expectEqual(frame_type_ipv6 - 1, frame_type_ipv4);
    inline for ([_]Family{ .v4, .v6 }) |family| {
        try t.expectEqual(family, try familyOf(frameTypeOf(family)));
    }

    // The block is QAD's, continued by two. QAD's own two constants sit below
    // ours and neither codec will read the other's frame, which is what keeps a
    // frame whose type is in the wrong half of the block from being parsed as
    // a plausible frame of the other kind.
    try t.expect(qad.frame_type_ipv4 < frame_type_ipv4);
    try t.expectError(error.UnknownAddressFamily, familyOf(qad.frame_type_ipv4));
    try t.expectError(error.UnknownAddressFamily, familyOf(qad.frame_type_ipv6));
}

test "one IPv4 frame, field by field, and it reads back" {
    const frame = frameWith(.v4, 42, 1000, &.{.{ .first = 5, .last = 9 }});
    var out: [max_frame_length]u8 = undefined;
    const length = try encode(frame, &out);
    //     type          seq  challenge            ts   n  first  last
    //   80 9f 81 a8     2a   01 02 03 04 05 06 07 08   43 e8  01  05  09
    try expectHex(
        "80 9f 81 a8 2a 01 02 03 04 05 06 07 08 43 e8 01 05 09",
        out[0..length],
    );
    try t.expectEqual(@as(usize, 18), length);

    const read = try decode(out[0..length]);
    try t.expectEqual(frame, read.frame);
    try t.expectEqual(length, read.length);
    try t.expectEqual(@as(u64, 9), read.frame.covered());
}

test "an IPv6 frame is the same frame with the type's other bit set" {
    const frame = frameWith(.v6, 42, 1000, &.{.{ .first = 5, .last = 9 }});
    var out: [max_frame_length]u8 = undefined;
    const length = try encode(frame, &out);
    // One byte differs from the IPv4 vector and it is the last bit of the type.
    try expectHex(
        "80 9f 81 a9 2a 01 02 03 04 05 06 07 08 43 e8 01 05 09",
        out[0..length],
    );
    try t.expectEqual(frame, (try decode(out[0..length])).frame);
}

test "every varint width round trips in the sequence and the timestamp" {
    var first: [max_frame_length]u8 = undefined;
    var second: [max_frame_length]u8 = undefined;
    inline for ([_]Family{ .v4, .v6 }) |family| {
        for (widths) |sequence| {
            for (widths) |timestamp| {
                const frame = frameWith(family, sequence, timestamp, &sweep_ranges);
                const length = try encode(frame, &first);
                const read = try decode(first[0..length]);
                // Equality is whole-struct, so this also proves the range tail
                // is zeroed rather than undefined on the way back.
                try t.expectEqual(frame, read.frame);
                try t.expectEqual(length, read.length);
                // The encoding is a fixed point: the value names the bytes, not
                // the spelling that happened to be chosen for them.
                const again = try encode(read.frame, &second);
                try t.expectEqual(length, again);
                try t.expectEqualSlices(u8, first[0..length], second[0..again]);
            }
        }
    }
}

test "range endpoints round trip at every width, and the empty list is a frame" {
    var out: [max_frame_length]u8 = undefined;
    for (widths) |first| {
        for (widths) |last| {
            if (first > last) continue;
            const frame = frameWith(.v4, 1, 1, &.{.{ .first = first, .last = last }});
            const length = try encode(frame, &out);
            const read = try decode(out[0..length]);
            try t.expectEqual(frame, read.frame);
            try t.expectEqual(last, read.frame.covered());
        }
    }

    // No ranges is a frame the peer wrote on purpose, and it says the most a
    // frame with nothing in it can say: nothing has arrived past the first
    // packet. It is a zero, not a refusal and not an absent frame.
    const empty = frameWith(.v4, 7, 7, &.{});
    const length = try encode(empty, &out);
    try expectHex("80 9f 81 a8 07 01 02 03 04 05 06 07 08 07 00", out[0..length]);
    const read = try decode(out[0..length]);
    try t.expectEqual(empty, read.frame);
    try t.expectEqual(@as(usize, 0), read.frame.range_count);
    try t.expectEqual(@as(u64, 0), read.frame.covered());
}

test "every prefix that ends inside the frame is Truncated" {
    var full: [max_frame_length]u8 = undefined;
    inline for ([_]Family{ .v4, .v6 }) |family| {
        const widest = frameWith(family, max_value, max_value, &sweep_ranges);
        const length = try encode(widest, &full);
        var cut: usize = 0;
        while (cut < length) : (cut += 1) {
            try t.expectError(error.Truncated, decode(full[0..cut]));
        }
        try t.expectEqual(length, (try decode(full[0..length])).length);
    }
}

test "a frame type this build does not carry is refused by name" {
    // QAD's two constants, one below this block and the pair a peer that has
    // the wrong codec would send; one above; and `0x1f`, which is a real QUIC
    // frame type, which is the point: this is a decoder for one frame, not a
    // packet walk.
    for ([_]u64{
        qad.frame_type_ipv4,
        qad.frame_type_ipv6,
        frame_type_ipv4 - 1,
        frame_type_ipv6 + 1,
        0x1f,
        0x00,
    }) |frame_type| {
        var scratch: [max_varint_length]u8 = undefined;
        const length = try quic_varint.put(&scratch, frame_type);
        try t.expectError(error.UnknownAddressFamily, decode(scratch[0..length]));
    }

    // And the refusal is not the truncation refusal: a type this build does
    // carry with no body behind it is Truncated, which is a different fault
    // with a different remedy.
    try t.expectError(error.Truncated, decode(&[_]u8{ 0x80, 0x9f, 0x81 }));
}

test "a range list past the ceiling is refused, never clipped" {
    // Two counts past the ceiling, written out rather than encoded: `encode`
    // will not produce either, and a test that built one by patching an
    // encoded frame would be pinning a byte offset instead of a rule.
    var scratch: [max_frame_length]u8 = undefined;
    //      type          seq  challenge            ts  count
    //    80 9f 81 a8     01   01 02 03 04 05 06 07 08   01   09
    try t.expectError(
        error.TooManyRanges,
        decode(try hex("80 9f 81 a8 01 01 02 03 04 05 06 07 08 01 09", &scratch)),
    );
    // The widest spelling a varint has — `max_value`, all eight bytes set — is
    // the same refusal and not a different one, so the check is on the value
    // and never on the width that spelled it.
    try t.expectError(
        error.TooManyRanges,
        decode(try hex(
            "80 9f 81 a8 01 01 02 03 04 05 06 07 08 01 ff ff ff ff ff ff ff ff",
            &scratch,
        )),
    );

    // And the same arm on the way out, for a hand-built frame whose count is
    // inside the array's bounds but outside the ceiling. `covered` answers
    // that frame rather than reading past the array, which is the only reason
    // the clamp in it exists.
    var out: [max_frame_length]u8 = undefined;
    var over: Frame = frameWith(.v4, 1, 1, &sweep_ranges);
    over.range_count = max_packet_ranges + 3;
    try t.expectError(error.TooManyRanges, encode(over, &out));
    try t.expectEqual(@as(u64, 0), over.covered());
}

test "an inverted range and a non-canonical list are three refusals" {
    var scratch: [max_frame_length]u8 = undefined;
    var out: [max_frame_length]u8 = @as([max_frame_length]u8, @splat(0));

    // 20 then 10: the range names no packet numbers at all.
    try t.expectError(
        error.InvertedRange,
        decode(try hex("80 9f 81 a8 01 01 02 03 04 05 06 07 08 01 01 14 0a", &scratch)),
    );

    // Two ranges, the second overlapping the first by six packets, then the
    // second abutting it. One arm for both, and the gaps are a negative number
    // and one — the same statement either way, that the list has a shorter
    // spelling and this frame is not it.
    try t.expectError(error.UnorderedRanges, decode(try hex(
        "80 9f 81 a8 01 01 02 03 04 05 06 07 08 01 02 0a 0a 04 14",
        &scratch,
    )));
    try t.expectError(error.UnorderedRanges, decode(try hex(
        "80 9f 81 a8 01 01 02 03 04 05 06 07 08 01 02 0a 0a 0b 14",
        &scratch,
    )));

    // The rule is the encoder's too, so a list one side refuses is refused by
    // the other: `encode` and `decode` cannot each admit a shape the other
    // rejects, which is what would break the fixed point.
    try t.expectError(
        error.UnorderedRanges,
        encode(frameWith(.v4, 1, 1, &.{
            .{ .first = 0, .last = 10 },
            .{ .first = 4, .last = 20 },
        }), &out),
    );
    try t.expectError(
        error.UnorderedRanges,
        encode(frameWith(.v4, 1, 1, &.{
            .{ .first = 0, .last = 10 },
            .{ .first = 11, .last = 20 },
        }), &out),
    );
    try t.expectError(
        error.InvertedRange,
        encode(frameWith(.v4, 1, 1, &.{.{ .first = 9, .last = 5 }}), &out),
    );
}

test "a value past the widest varint is refused before a byte is written" {
    const widest = frameWith(.v4, max_value, max_value, &sweep_ranges);
    var out: [max_frame_length]u8 = undefined;
    const length = try encode(widest, &out);
    try t.expectEqual(max_value, (try decode(out[0..length])).frame.timestamp);

    // Each varint field has its own ceiling and the same arm, and the check is
    // ahead of the write: the buffer is still the caller's own bytes afterwards.
    const untouched = @as([max_frame_length]u8, @splat(0xaa));
    var scratch = untouched;
    for ([_]Frame{
        frameWith(.v4, max_value + 1, 1, &sweep_ranges),
        frameWith(.v4, 1, max_value + 1, &sweep_ranges),
        frameWith(.v4, 1, 1, &.{.{ .first = 1, .last = max_value + 1 }}),
    }) |over| {
        try t.expectError(error.ValueTooLarge, encode(over, &scratch));
        try t.expectEqualSlices(u8, &untouched, &scratch);
    }
}

test "a buffer one byte short is NoRoom, and the widest frame fits" {
    const widest = frameWith(.v6, max_value, max_value, &sweep_ranges);
    var out: [max_frame_length]u8 = undefined;
    const length = try encode(widest, &out);
    var room: usize = 0;
    while (room < length) : (room += 1) {
        try t.expectError(error.NoRoom, encode(widest, out[0..room]));
    }
    // The bound is a bound and not a length, and it is what a caller sizes a
    // buffer from, so the widest frame must fit inside it.
    try t.expect(length <= max_frame_length);
}
