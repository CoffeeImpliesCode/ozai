//! The named refusals of the RFC 6455 carrier: which name each broken frame is
//! to be told, row for row.
//!
//! **This is the tables half of the pair.** `test/ws_frame_fuzz.zig` is the
//! entry `build.zig` names, and it owns the driver — the seed corpus, the fuzz
//! entry point, the oracles a mutation is walked through, and the test that
//! walks every row below. This file owns the fixed byte strings and what they
//! claim, and the split is by responsibility and not by size: a row here is a
//! *claim about a name*, and the half that holds the claims must not also hold
//! the fuzzer.
//!
//! The shape is `src/gossip/codec.zig`'s: the entry file imports this one by a
//! relative path and uses what it re-exports, so a reader of the entry point
//! never has to know how the split goes.
//!
//! # Why there are two tables and not one
//!
//! `ws.decode` takes a role and `ws.readHeader` does not, so the same bytes are
//! refusable with different names through the two. `decode` can answer with ten
//! of the eleven names in `ws_frame_types.Error` — the eight header rules and
//! the one role refusal the reading end is entitled to — while `readHeader`
//! cannot reach either role refusal at all, because it has nothing to compare
//! the mask bit against. That difference is the entire reason the second table
//! is not a copy of the first with the role dropped.
//!
//! # `Role` names the reading end, not the peer
//!
//! **This is where a row in this file goes wrong.** RFC 6455 section 5.1 puts
//! the mask obligation on the sender, so a frame read by a `.server` reader came
//! from a client and must be masked, and a frame read by a `.client` reader
//! came from a relay and must not be. `ws_frame_types.zig` says "the value
//! names this end, not the peer" in as many words, and a row written the other
//! way round asks a relay to refuse the one frame section 5.1 requires it to
//! accept — a mask bit set with a complete header is a legal frame and the only
//! thing that can be wrong with the bytes behind it is that there are none.
//!
//! Nothing here allocates, reads a clock, or reaches for a global.

const std = @import("std");
const ozai = @import("ozai");

const ws = ozai.relay_ws_frame;

/// One refusal: the bytes, the end reading them, and the one name they may be
/// refused with.
///
/// Each of these is a rule RFC 6455 states, so each is a name rather than a
/// limit this tree chose, and each is reached from a byte string short enough
/// to write out.
pub const DecodeCase = struct {
    bytes: []const u8,
    role: ws.Role,
    expected: ws.Error,
};

/// Every named refusal `ws.decode` is held to, in both roles.
pub const decode_cases = [_]DecodeCase{
    .{ .bytes = &.{ 0xc1, 0x00 }, .role = .server, .expected = error.ReservedBitSet },
    .{ .bytes = &.{ 0xf1, 0x00 }, .role = .client, .expected = error.ReservedBitSet },
    .{ .bytes = &.{ 0xa1, 0x00 }, .role = .server, .expected = error.ReservedBitSet },
    .{ .bytes = &.{ 0x91, 0x00 }, .role = .server, .expected = error.ReservedBitSet },
    .{ .bytes = &.{ 0x83, 0x00 }, .role = .server, .expected = error.UnknownOpcode },
    // The three reserved opcodes and the undefined ones above them. `0x83` is
    // opcode 3 and `0x8b` is 11, the first value past the six the RFC defines;
    // `0x87` is opcode 7, the last of the three the section reserves.
    .{ .bytes = &.{ 0x87, 0x00 }, .role = .server, .expected = error.UnknownOpcode },
    .{ .bytes = &.{ 0x8b, 0x00 }, .role = .server, .expected = error.UnknownOpcode },
    // One byte is shorter than the two a header minimally is, so the length
    // check answers before the opcode can be read at all:
    // `ws_frame_header.zig` returns `error.UnexpectedEnd` on the first line of
    // its body, ahead of the reserved bits and the opcode. There is no second
    // byte here to be the mask bit over a length, so `UnknownOpcode` is not
    // reachable from these bytes however the first byte is set.
    .{ .bytes = &.{0xfb}, .role = .server, .expected = error.UnexpectedEnd },
    .{ .bytes = &.{ 0x89, 0x7e }, .role = .server, .expected = error.ControlFrameTooLong },
    .{ .bytes = &.{ 0x8a, 0x7f }, .role = .server, .expected = error.ControlFrameTooLong },
    .{ .bytes = &.{ 0x09, 0x00 }, .role = .server, .expected = error.FragmentedControlFrame },
    .{ .bytes = &.{ 0x01, 0x7e, 0x00, 0x7d }, .role = .client, .expected = error.NonMinimalLength },
    .{
        .bytes = &.{ 0x01, 0x7f, 0, 0, 0, 0, 0, 0, 0, 0x01 },
        .role = .client,
        .expected = error.NonMinimalLength,
    },
    .{
        .bytes = &.{ 0x81, 0x7f, 0x80, 0, 0, 0, 0, 0, 0, 0 },
        .role = .server,
        .expected = error.ReservedLengthBit,
    },
    .{ .bytes = &.{0x81}, .role = .client, .expected = error.UnexpectedEnd },
    .{ .bytes = &.{ 0x81, 0x85 }, .role = .client, .expected = error.UnexpectedEnd },
    .{ .bytes = &.{ 0x81, 0x05 }, .role = .client, .expected = error.UnexpectedEnd },
    .{ .bytes = &.{ 0x81, 0x05 }, .role = .server, .expected = error.UnmaskedClientFrame },
    // The RFC 5.7 masked frame's key with none of its payload behind it, read
    // by a relay. **A masked frame is what a `.server` reader is required to
    // see** (RFC 6455 section 5.1), so the mask is not what is wrong here: the
    // header is whole — two bytes over four bytes of key — and the five payload
    // bytes it declares are absent, which is `decode`'s own
    // `bytes.len < header_length + payload_length`.
    .{
        .bytes = &.{ 0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d },
        .role = .server,
        .expected = error.UnexpectedEnd,
    },
    // And the same frame read by a node, which is the direction RFC 5.1
    // forbids: a server does not mask, so a `.client` reader refuses it.
    .{
        .bytes = &.{ 0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d },
        .role = .client,
        .expected = error.MaskedServerFrame,
    },
    // And an unmasked frame read by a relay, which is the same section's other
    // direction and its `UnmaskedClientFrame`.
    .{
        .bytes = &.{ 0x81, 0x05, 0x48 },
        .role = .server,
        .expected = error.UnmaskedClientFrame,
    },
    .{
        .bytes = &.{ 0x82, 0x7f, 0, 0, 0, 0, 0x10, 0, 0, 0 },
        .role = .client,
        .expected = error.FrameTooLarge,
    },
};

/// One header refusal: the bytes and the one name the header codec may answer
/// them with. `readHeader` has no role and so cannot reach either of the two
/// refusals about the end that sent the frame, which is what makes these a
/// different list from the one above.
pub const HeaderCase = struct {
    bytes: []const u8,
    expected: ws.Error,
};

/// Every named refusal `ws.readHeader` is held to, with no role to weigh.
pub const header_cases = [_]HeaderCase{
    .{ .bytes = &.{}, .expected = error.UnexpectedEnd },
    .{ .bytes = &.{0x81}, .expected = error.UnexpectedEnd },
    // `0x7e` says a sixteen-bit length follows and that length is zero, so the
    // header spells a length in a wider field than it needs. RFC 6455 section
    // 5.2 requires the minimal encoding and `ws_frame_header.zig` checks the
    // width rules before anything else may look at the value, so this is the
    // width rule's answer and not a header that stopped short.
    .{ .bytes = &.{ 0x81, 0x7e, 0x00, 0x00 }, .expected = error.NonMinimalLength },
    // A width the header stops inside, which is the other answer and not a
    // refinement of this one: two bytes for the `0x7e` and none of the eight.
    .{ .bytes = &.{ 0x81, 0x7e, 0x01 }, .expected = error.UnexpectedEnd },
    // And the sixty-four-bit width cut short the same way.
    .{ .bytes = &.{ 0x81, 0x7f, 0x00, 0x00 }, .expected = error.UnexpectedEnd },
    .{ .bytes = &.{ 0xc1, 0x00 }, .expected = error.ReservedBitSet },
    .{ .bytes = &.{ 0x83, 0x00 }, .expected = error.UnknownOpcode },
    .{ .bytes = &.{ 0x89, 0x7e }, .expected = error.ControlFrameTooLong },
    .{ .bytes = &.{ 0x09, 0x00 }, .expected = error.FragmentedControlFrame },
    .{ .bytes = &.{ 0x81, 0x7e, 0x00, 0x7d }, .expected = error.NonMinimalLength },
    .{ .bytes = &.{ 0x81, 0x7f, 0x80, 0, 0, 0, 0, 0, 0, 0 }, .expected = error.ReservedLengthBit },
    .{ .bytes = &.{ 0x82, 0x7f, 0, 0, 0, 0, 0x10, 0, 0, 0 }, .expected = error.FrameTooLarge },
};
