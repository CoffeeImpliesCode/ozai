//! Fuzz target for the vendored QUIC wire decoders: varints, the long and
//! short packet headers, frames, and transport parameters.
//!
//! One target file per decoder family group, and this is the file that owns
//! the Smith driver for the four of them. `zig build fuzz` replays the corpus
//! below; `zig build fuzz --fuzz=N` hands the same corpus to Zig's
//! coverage-guided fuzzer and lets it mutate for N iterations. A fuzz test is
//! a plain test to a plain build, so without `-ffuzz` the runner walks the
//! corpus instead — which is what makes a bare `zig build fuzz` a bounded gate
//! rather than an empty step.
//!
//! # Why the oracles live in four leaves and not here
//!
//! The four families are four decoders, each with a closed error set, an
//! independent RFC reference for *why* a given input is refused, invariants on
//! an accepted value, and — where the format defines one — an encode-decode
//! fixed point. That is four oracles' worth of reference decoder per family,
//! and none of it belongs in the file that owns the seed corpus and the driver
//! loop. So `quic_wire/varint.zig`, `quic_wire/header.zig`, `quic_wire/frame.zig`
//! and `quic_wire/transport_params.zig` each own one family, and this file owns
//! what they share: the seeds, the window the fuzzer fills, and the call that
//! hands the same bytes to all four.
//!
//! Every leaf here takes the bytes alone and owns its own error set, so no leaf
//! is handed an allocator it has nothing to do with. None of these four parsers
//! allocates; see the contract note below the imports.
//!
//! # The seeds are not captured vectors
//!
//! Every seed below is a shape written here byte for byte from RFC 9000
//! §14–§19 and RFC 9369 §5. None of them is a captured Rust vector, and none is
//! labelled as one: this repository has run no live exchange with a Rust peer,
//! so there is nothing captured to embed. What a mutation starts from is a
//! documented wire shape, and that is what these are.

const std = @import("std");

const varint = @import("quic_wire/varint.zig");
const header = @import("quic_wire/header.zig");
const frame = @import("quic_wire/frame.zig");
const transport_params = @import("quic_wire/transport_params.zig");

const t = std.testing;

// The leaves' failure set, as a contract rather than as a type this file
// declares. Each leaf owns its own: `std.testing.expect*` reports through
// `error{TestUnexpectedResult, TestExpectedEqual, TestExpectedError,
// TestUnexpectedError}`, and that is the whole vocabulary an oracle here needs,
// so a leaf that wanted its own names would be inventing a second one for no
// gain. This root does not declare the set because it does not consume one:
// `testOne` returns `anyerror!void` and the four `try`s below are the whole of
// the compatibility check — a leaf whose set this root cannot `try` fails to
// compile, which is the assertion worth having.
//
// `OutOfMemory` is absent everywhere in this family, and that is a fact about
// the parsers rather than a preference: `parseQuicHeader`, `readVarInt` /
// `writeVarInt`, `Frame.parse` / `parseSized` and `TransportParams.decode` all
// take borrowed slices, and the only cursor among them is
// `io_compat.FixedBufferStream`, which owns nothing. A leaf admitting
// `OutOfMemory` would advertise a path the production parser does not have. A
// refused varint, a malformed frame and a bad parameter list are closed
// production errors judged by the oracle that checks them, and none of them
// reaches a leaf's error set.

/// The seeds, one per shape the four decoders have a rule for.
///
/// The varints name a width in their top two bits and run out at each of the
/// four, plus the two spellings of 37 the RFC's own example gives. The headers
/// walk a long header's failures in the order the decoder reaches them — the
/// fixed bit clear, a destination id over 20 bytes, a source id over 20 bytes,
/// a length past the datagram — and then the four packet types, a version
/// negotiation packet, and two short headers whose destination id does and does
/// not fit. The frames are one frame of each kind of length: absent, a varint
/// truncated at every width, a type one past the table, a stream frame whose
/// length runs past the buffer, an ACK reaching below packet number zero, and a
/// DATAGRAM naming more bytes than it has. The parameters are the vacuous list,
/// a scalar whose declared length is not its varint width, a reset token one
/// byte short, a migration-disable flag with a value, a preferred address
/// carrying no connection id, and a version_information list that is not a
/// multiple of four.
const corpus = [_][]const u8{
    // varints: a width named by the top two bits, and nothing behind it
    &.{},
    &.{0xff},
    &.{0x40},
    &.{ 0x80, 0x00 },
    &.{ 0xc0, 0x00, 0x00, 0x00 },
    &.{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
    &.{ 0x7b, 0xbd },
    &.{0x25},
    // long headers
    &.{ 0x80, 0, 0, 0, 1, 0, 0 }, // the fixed bit clear (RFC 9000 §17.2)
    &.{ 0xc0, 0, 0, 0, 1, 21, 0, 0, 0, 0, 0 }, // a destination id over 20 bytes
    &.{ 0xc0, 0, 0, 0, 1, 0, 21, 0, 0, 0, 0 }, // a source id over 20 bytes
    &.{ 0xc0, 0, 0, 0, 1, 4, 1, 2, 3, 4, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }, // a length past the datagram
    &.{ 0xc0, 0, 0, 0, 1, 0, 0, 0x00 }, // an Initial with an empty token
    &.{ 0xc0, 0, 0, 0, 1, 0, 0, 0x40, 0x04, 1, 2, 3, 4 }, // an Initial with a token
    &.{ 0xe0, 0, 0, 0, 1, 0, 0, 0x01 }, // a Handshake
    &.{ 0xd0, 0, 0, 0, 1, 0, 0, 0x01 }, // 0-RTT
    &.{ 0xf0, 0, 0, 0, 1, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 }, // a Retry
    &.{ 0x80, 0, 0, 0, 0, 0, 0 }, // a version negotiation packet
    // short headers: a destination id that fits, and one that does not
    &.{0x40},
    &.{ 0x40, 0xde, 0xad, 0xbe, 0xef },
    // frames
    &.{0x01}, // PING
    &.{ 0x1a, 1, 2, 3, 4, 5, 6, 7, 8 }, // PATH_CHALLENGE, whole
    &.{ 0x08, 0x00 }, // STREAM with no length and no data
    &.{ 0x0a, 0x00, 0x05, 1, 2 }, // STREAM naming more bytes than it has
    &.{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 }, // an ACK reaching below packet zero
    &.{ 0xaf, 1, 2, 3, 4, 5 }, // ACK_FREQUENCY, one field short
    &.{0x20}, // one past the frame table
    &.{ 0x31, 0x40 }, // a DATAGRAM length wider than the buffer
    // The two shapes that only exist at the wider window. A bare
    // `zig build fuzz` replays the corpus and stops, so without these the long
    // paths would be reached only under `--fuzz=N` and a gate that never
    // mutates would report green without ever having decoded a frame whose
    // body exceeds a hundred bytes.
    &([_]u8{ 0x0a, 0x00, 0x43, 0xe8 } ++ ([_]u8{0xaa} ** 1000)), // STREAM, LEN set, a thousand-byte body
    &([_]u8{0} ** 1000), // a PADDING run that coalesces into one frame
    // transport parameters
    &.{},
    &.{ 0x01, 0x02, 0x00 }, // max_idle_timeout declared two bytes wide
    &.{ 0x02, 0x10, 1, 2, 3 }, // a stateless reset token of fifteen bytes
    &.{ 0x0c, 0x01, 0x00 }, // a migration-disable flag with a value behind it
    &([_]u8{ 0x0d, 0x2a } ++ ([_]u8{0} ** 41)), // a preferred address with no connection id
    &.{ 0x11, 0x06, 0, 0, 0, 1, 0, 0 }, // a version_information list of six bytes
    &.{ 0x11, 0x08, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0 },
};

/// The window the fuzzer fills. A seed longer than this would be cut short on
/// its way to an oracle, and the length checks would never see the rest of it.
///
/// It is RFC 9000 §14's maximum datagram size, which is also this core's
/// `packet.MAX_PACKET_LEN` and the width of the stack buffer the frame leaf
/// copies into. That is the natural ceiling for a QUIC wire target and not an
/// arbitrary one: a QUIC packet cannot be larger, so an input past it describes
/// no packet a peer could send. The frame family stops parsing above it rather
/// than truncating, so a window larger than this would leave the tail silently
/// uncovered while looking like more coverage; a window smaller than it would
/// refuse to generate the long frames that are the point of fuzzing a frame
/// decoder at all — a STREAM frame with a body of a thousand bytes, a DATAGRAM
/// carrying one, a PADDING run that coalesces. The varint, header and
/// transport-parameter families have no length bound of their own and lose
/// nothing here.
///
/// A leaf that re-encodes what it decoded sizes that buffer from this one, with
/// the argument written at its own use.
const input_buffer_len = 1536;

comptime {
    // A seed longer than the window the fuzzer reads into would be cut short,
    // and the length checks would never see the rest of it.
    for (corpus) |seed| std.debug.assert(seed.len <= input_buffer_len);
}

/// The fuzzer keeps one of these by pointer for the whole run, so it is empty
/// by design: everything the driver needs is comptime.
const Context = struct {};

test "quic wire decode" {
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
    // The same bytes to all four, in the order they sit on the wire: a length
    // is a varint before it is anything else.
    try varint.check(bytes);
    try header.check(bytes);
    try frame.check(bytes);
    try transport_params.check(bytes);
}
