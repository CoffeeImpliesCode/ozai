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
//! # One seed is recorded, the rest are shapes
//!
//! Every seed below but the last four is a shape written here byte for byte
//! from RFC 9000 §14–§19 and RFC 9369 §5. What a mutation starts from is a
//! documented wire shape, and that is what those are.
//!
//! The last is bytes rather than a shape: the datagram kept as hex in
//! `test/corpus/rust_wire/rust_client_initial.hex` and decoded once at compile
//! time by `rust_wire_initial.zig`'s decoder. It is 1200 bytes, which is
//! both the smallest datagram a client may open a connection with
//! (RFC 9000 §14.1) and the longest input this tree's consumers are ever
//! handed, so it is what the window below has to be wide enough for. The
//! reading that goes past the header lives in `rust_wire_initial.zig`, and
//! `rust_wire_initial_test.zig` is where that reading is held to the capture:
//! that its header is the one §17.2 lays out and the core reads the same one,
//! that the AEAD opens it under the keys its own destination id derives, and
//! that the CRYPTO frame behind the header is a TLS ClientHello. That root
//! asserts those. This driver requires no verdict of any kind from an
//! arbitrary mutation; it only asks that none of them crashes or trips the
//! disagreement oracle.

const std = @import("std");

const varint = @import("quic_wire/varint.zig");
const header = @import("quic_wire/header.zig");
const frame = @import("quic_wire/frame.zig");
const transport_params = @import("quic_wire/transport_params.zig");
const wire = @import("rust_wire_initial.zig");

const quic = @import("quic");

const connection_manager = quic.connection_manager;

const t = std.testing;

/// The recorded Rust client's first datagram, decoded out of the corpus file
/// once at compile time. The decoder is `wire`'s, the same one
/// `rust_wire_initial_test.zig` reads it with, so the two roots cannot drift
/// onto two different spellings of one capture.
///
/// An array at namespace scope, and not a slice handed out by the block below:
/// the corpus is replayed by the fuzz driver out of module initialization, so a
/// seed has to be data that outlives it, and a `const` slice at namespace
/// scope naming a `blk:` local is a reference to a comptime var, which Zig
/// refuses to build. The block holds only the buffer the decode writes into;
/// the array it hands back is this declaration's own value, and
/// `&recorded_bytes` is the pointer the corpus entry below names.
///
/// `decodeCapture` keeps the caller-provided buffer it already had, because
/// `rust_wire_initial_test.zig` decodes the same hex at run time into a buffer
/// it then mutates, and a decode that returned an array of its own could not be
/// that call. One decoder and two buffers is still one decode path; a second
/// spelling of the capture is not.
///
/// The quota below belongs to this one evaluation, and the reason is a fact
/// about the decode rather than about the capture: `decodeCapture` walks the
/// `wire.capture_len` bytes two characters at a time, each iteration of that
/// walk is one backwards branch, and a default of 1000 is spent part way
/// through a 1200-byte file. Four per captured byte covers the iterations and
/// the two character reads each of them makes, and deriving the number from
/// `wire.capture_len` takes the budget with the capture if the corpus file's
/// length ever moves.
///
/// Not done here, and deliberately: a decode of this input that does not branch
/// per byte. These bytes exist here only as hex, so such a formulation has to
/// be handed them some other way — a binary copy of the capture embedded beside
/// the hex, or 1200 bytes written out as a literal — and both of those are the
/// same datagram a second time, in a copy that no diff of
/// `corpus/rust_wire/rust_client_initial.hex` would ever reach, which is the
/// legibility the hex exists to keep. Trading a thousand-odd interpreter
/// iterations on one target's own build for a second undiffable spelling of
/// the capture would buy the wrong half of the cost, so the budget is raised at
/// the one call that spends it.
const recorded_bytes: [wire.capture_len]u8 = blk: {
    @setEvalBranchQuota(4 * wire.capture_len);
    var storage: [wire.capture_len]u8 = undefined;
    _ = wire.decodeCapture(&storage) catch unreachable;
    break :blk storage;
};

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
/// whose declared length runs past the buffer, two more that reach the
/// preferred address's own rules — a zero connection-id length and a length
/// that is not `41 + cid_len` — a preferred address carrying everything
/// §18.2 can name, and a version_information list that is not a multiple of
/// four.
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
    // A length past the datagram.
    &.{ 0xc0, 0, 0, 0, 1, 4, 1, 2, 3, 4, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
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
    // STREAM, LEN set, a thousand-byte body.
    &([_]u8{ 0x0a, 0x00, 0x43, 0xe8 } ++ ([_]u8{0xaa} ** 1000)),
    &([_]u8{0} ** 1000), // a PADDING run that coalesces into one frame
    // transport parameters
    &.{},
    &.{ 0x01, 0x02, 0x00 }, // max_idle_timeout declared two bytes wide
    &.{ 0x02, 0x10, 1, 2, 3 }, // a stateless reset token of fifteen bytes
    &.{ 0x0c, 0x01, 0x00 }, // a migration-disable flag with a value behind it
    &([_]u8{ 0x0d, 0x2a } ++ ([_]u8{0} ** 41)), // a preferred address with no connection id
    &.{ 0x11, 0x06, 0, 0, 0, 1, 0, 0 }, // a version_information list of six bytes
    &.{ 0x11, 0x08, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0 },
    // A preferred address carrying the whole of what §18.2 can name: an IPv4
    // and an IPv6 pair, a connection id, and the sixteen-byte stateless reset
    // token that has to be read out of the buffer rather than defaulted.
    &([_]u8{ 0x0d, 0x31, 192, 0, 2, 1, 0x11, 0x51 } ++
        [_]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01 } ++
        [_]u8{ 0x20, 0xfb, 0x08, 0xc1, 0x7a, 0x05, 0xbe, 0xef, 0x30, 0x9d, 0x4f } ++
        [_]u8{ 0x5e, 0xa1, 0x3c, 0x77, 0x0d, 0xe2, 0x46, 0x9b } ++
        [_]u8{ 0x18, 0xc4, 0x60, 0xaf, 0x32, 0x85, 0xeb, 0x11 }),
    // The same offer with the connection-id length zero. §18.2's rule is that
    // it is 1 to 20, so this is refused before the length arithmetic is read
    // at all — and the trailing octet is what makes the value 42 rather than
    // the 41 a zero-length id would otherwise sum to, because the decoder
    // refuses a shorter value first and this is meant to reach the rule.
    &([_]u8{ 0x0d, 0x2a, 192, 0, 2, 1, 0x11, 0x51 } ++
        [_]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01 } ++
        [_]u8{ 0x20, 0xfb, 0x00, 0x5e, 0xa1, 0x3c, 0x77, 0x0d, 0xe2, 0x46, 0x9b } ++
        [_]u8{ 0x18, 0xc4, 0x60, 0xaf, 0x32, 0x85, 0xeb, 0x11, 0x00 }),
    // And with it eight, over a value that still ends 42 octets in: §18.2
    // makes the value exactly `41 + cid_len` octets, so an id of eight is
    // legal and this value's length is not.
    &([_]u8{ 0x0d, 0x2a, 192, 0, 2, 1, 0x11, 0x51 } ++
        [_]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01 } ++
        [_]u8{ 0x20, 0xfb, 0x08, 0x5e, 0xa1, 0x3c, 0x77, 0x0d, 0xe2, 0x46, 0x9b } ++
        [_]u8{ 0x18, 0xc4, 0x60, 0xaf, 0x32, 0x85, 0xeb, 0x11, 0x00 }),
    // The recorded Rust client's first datagram, and the seed the window below
    // is sized for. `rust_wire_initial.zig` holds the reading and
    // `rust_wire_initial_test.zig` the claims about it; this entry is what
    // puts the same bytes through this driver's four leaves as well, which the
    // capture's own two-entry corpus never does.
    &recorded_bytes,
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
/// It also has to hold a whole client Initial. RFC 9000 §14.1 puts the
/// smallest datagram that may open a connection at 1200 bytes, the recorded
/// Rust peer's datagram is exactly that, and a window below it would cut the
/// corpus' longest seed short at the one place where the seed is a peer's
/// bytes rather than a shape. The assertion below ties the two together so a
/// future window that drops below the floor fails the build rather than
/// quietly shortening the seed.
///
/// A leaf that re-encodes what it decoded sizes that buffer from this one, with
/// the argument written at its own use.
const input_buffer_len = 1536;

comptime {
    // A seed longer than the window the fuzzer reads into would be cut short,
    // and the length checks would never see the rest of it.
    for (corpus) |seed| std.debug.assert(seed.len <= input_buffer_len);
    std.debug.assert(input_buffer_len >= connection_manager.MIN_INITIAL_DATAGRAM);
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
    // And then through the reading that goes past the header: protection comes
    // off, the payload is opened under the Initial keys its own destination
    // connection id derives, the CRYPTO stream is reassembled out of the
    // frames, and the flight is read by the vendored TLS parser and judged
    // against `tls_wire/hello.zig`'s independent RFC 8446 reference. Nothing
    // below the payload is reachable through the four leaves above, which stop
    // at the header. No verdict is required of an arbitrary mutation here:
    // every input reaches one, and this driver only asks that none of them
    // crashes or trips the disagreement oracle.
    try wire.fuzzOne(t.allocator, bytes);
}
