//! The relay frame's vocabulary: the frame type table, the payloads behind it,
//! the protocol version and how a connection settles on one, and every way a
//! frame may be refused.
//!
//! Captured from n0-computer/iroh at commit
//! 187f59e80afdae6bd9866002b33d3365c00b06d8, fetched 2026-09-30:
//!
//! - `iroh-relay/src/protos/common.rs` — `FrameType` 0 through 13.
//! - `iroh-relay/src/protos/relay.rs` — `Datagrams`, `Status`, the two message
//!   enums, and the two hexdump snapshots every captured vector below is copied
//!   from.
//! - `iroh-relay/src/protos/handshake.rs` — frames 0 through 3 and the payloads
//!   behind them.
//! - `iroh-relay/src/http.rs` — `ProtocolVersion` and its two wire names.
//! - `iroh-relay/src/server/http_server.rs:612` — the negotiation.
//! - `noq-proto` 1.3.0, `src/varint.rs` — the varint the frame type is written
//!   with, which `relay/frame_writer.zig` owns.
//! - `noq-proto` 1.3.0, `src/shared.rs:180` — `EcnCodepoint`.
//!
//! Nothing here reads the wire: the types are values, the version is an enum,
//! and `negotiate` answers a question about one header field. The codec that
//! turns these types into bytes is `relay/frame_encode.zig` and
//! `relay/frame_decode.zig`, and `relay/frame.zig` re-exports the lot.
//!
//! # The header is not a postcard varint
//!
//! The header is a QUIC variable-length integer: `noq_proto::VarInt::encode`,
//! called from `common.rs:83`. It is not a postcard varint. `frame_writer.zig`
//! says why that matters and in which direction the two part company.
//!
//! Everything after the header is raw bytes at a fixed width: `put_u8`, `put_u16`
//! and `put_u32` in `relay.rs:263`, all big-endian, and no length prefix
//! anywhere. A segment size of 6 is `00 06` and not a varint. postcard is used
//! for the one field upstream postcard-encodes, the denial reason in frame 3,
//! which `handshake.rs:561` hands to `postcard::to_io`.
//!
//! # What a frame is
//!
//! One WebSocket message is one frame: a type, then that type's payload to the end
//! of the message. There is no length prefix and no frame count, so a decoder that
//! read short truncated a payload and one that read long read a message that
//! cannot exist. `Health` is the one payload that is exactly the rest of the
//! message, because its payload is text and its length is being the rest of the
//! message.
//!
//! # A relay can always send what it decided to send
//!
//! Every frame here has either a length its own type fixes or a bound `encode`
//! enforces before it writes a byte. That is not upstream's rule, because
//! upstream cannot need it: `ServerDeniesAuth` is a bare `reason: String`
//! (`handshake.rs:106`) and `Health` a `problem: String` (`relay.rs:115`), both
//! serialised into a `BytesMut` that grows (`handshake.rs:558-561`,
//! `relay.rs:354-356`). A relay there decides how large its own denial is and
//! pays for it in memory.
//!
//! Here a relay writes into a buffer it was handed and never grows, and the
//! reason it writes is not only its own to choose: upstream's access control is
//! a trait the operator implements (`handshake.rs:495`, `:524`), so the text in
//! a denial is whatever that trait decided. **So the bound lives here, in
//! `max_text_length`, and the maximum a caller may write is a value in the type
//! it is writing — `ServerDeniesAuth.max_reason_length`, and the
//! `ServerDeniesAuth.max_frame_length` a buffer has to be sized for.** Past it
//! the answer is `error.TextTooLong` and nothing is written. The denial is
//! never shortened, because a reason missing its end is a sentence the relay
//! did not choose and the peer cannot tell it from one it did.
//!
//! One thing the length bound does not cover is whether the text is text, and
//! it is checked on the way out rather than left to the caller. Upstream's
//! reason is a `String` (`handshake.rs:106`) and cannot be anything else; here
//! it is `[]const u8`, so `encode` validates it with
//! `std.unicode.utf8ValidateSlice` and refuses `error.InvalidUtf8` — the name
//! `decode` already answers with, because postcard validates on the way in. A
//! codec that refuses a value on the way in and writes it on the way out is not
//! a codec, and the relay side of this protocol writes denials and health
//! problems that a peer reads as text.
//!
//! Nothing here reads a clock, the environment, or a global. `Restarting`
//! stores milliseconds as the `u32` the wire truncates them to rather than as a
//! duration, so a value that will not fit on the wire cannot be held in a struct
//! that claims to be a frame. See `docs/ARCHITECTURE.md`, "Wire codecs are pure
//! and separate from the transport".

const std = @import("std");

const key = @import("../base/key.zig");
const frame_writer = @import("frame_writer.zig");
const vectors = @import("frame_vectors.zig");

const NodeId = key.NodeId;
const Signature = key.Signature;

const std_testing = std.testing;

/// Every way a frame can fail to encode or decode.
///
/// The first five are `postcard.Error`'s, carried under the same names, because
/// one field in this frame is decoded with the postcard reader and a caller
/// should not have to learn a second name for the same rule. The rest are this
/// frame's own.
pub const Error = error{
    /// The frame ran out in the middle of a value.
    UnexpectedEnd,
    /// A varint kept its continuation bit set for every byte its width allows, so
    /// the value is longer than the width is wide.
    BadVarint,
    /// A varint's last byte carried more value bits than its width has left.
    ValueOutOfRange,
    /// A length prefix the remaining input cannot satisfy.
    BadLength,
    /// Bytes where a string was expected that are not UTF-8.
    InvalidUtf8,
    /// The frame type is not one of 0 through 13.
    ///
    /// A type outside the table is a peer speaking a protocol this build does not
    /// have, and it is named rather than defaulted: a decoder that invented an arm
    /// for it would read that peer as one it knows.
    UnknownFrameType,
    /// The frame type exists, but not in the negotiated protocol version.
    FrameNotAllowedInVersion,
    /// The payload does not have the shape its frame type names.
    InvalidFrame,
    /// The 32 bytes a frame carries for a node id are not a canonical ed25519
    /// point. See `base/key.zig` for why construction is the weaker check and
    /// `verifyStrict` is the strict one.
    InvalidNodeId,
    /// The payload is larger than `max_packet_size`.
    FrameTooLarge,
    /// A batch frame declaring a segment size of zero.
    ///
    /// A zero segment size names no datagram, so reading one as a single datagram
    /// would hand back a `Datagrams` with no segment size out of a batch frame, and
    /// the two halves of rule 7 in `docs/ARCHITECTURE.md` would stop being one
    /// fact.
    ZeroSegmentSize,
    /// Relay-authored text longer than `max_text_length`: a denial's reason,
    /// or a v1 health frame's problem.
    ///
    /// **Refused, never shortened.** A denial whose reason was cut short says
    /// something the relay did not decide to say, and the peer reading it has
    /// no way to tell it from the relay's real reason. A refusal the caller
    /// cannot mistake for a denial is the honest outcome; a truncated one is
    /// not.
    TextTooLong,
    /// A writer with no room left in the buffer it was handed.
    BufferFull,
};

/// The largest payload a frame may carry, excluding the frame type.
///
/// This counts only the bytes a socket sees, not the frame's own overhead, and it
/// is upstream's `MAX_PACKET_SIZE` (`relay.rs:23`).
///
/// **It is the ceiling of the whole codec, not only of the datagram arms.**
/// `decode` measures the payload alone and refuses over it whatever the frame
/// type is, so the largest frame this module reads is `max_packet_size + 1` bytes
/// — one header byte over 64 KiB. On the way out it binds the four datagram arms
/// and nothing else, and it binds the payload rather than the contents, which is
/// why those four are not bounded alike: 65503 bytes of contents in a single
/// datagram and 65501 in a batch, which spends two of the bound on its segment
/// size.
pub const max_packet_size: usize = 64 * 1024;

/// Upstream's `MAX_FRAME_SIZE` (`relay.rs:29`).
///
/// **Nothing in this module reads it, and this codec refuses sixteen times
/// less.** Upstream needs it where a frame is framed — the WebSocket read — and
/// `decode` here measures the payload alone against `max_packet_size`, so a
/// message a peer was willing to send as a megabyte arrives as
/// `error.FrameTooLarge`. A caller sizing a read buffer sizes it with this one; a
/// caller deciding how wide a message to admit decides it at the socket, and the
/// width that actually survives this decoder is `max_packet_size + 1`.
pub const max_frame_size: usize = 1024 * 1024;

/// The most bytes of text a relay writes into one frame: a `server_denies_auth`
/// reason, or a v1 `health` problem.
///
/// **Upstream bounds neither, and does not have to.** `ServerDeniesAuth` is a
/// bare `reason: String` (`handshake.rs:106`) and `write_frame` serialises it
/// into a `BytesMut` that grows (`handshake.rs:558-561`); `Health` is a
/// `problem: String` (`relay.rs:115`) put into one the same way
/// (`relay.rs:354-356`). Neither has a fixed buffer to miss, so there is
/// nothing to bound. This codec appends into a buffer the caller owns and
/// never grows, which is the whole difference between the two ports and the
/// whole reason there is a number here.
///
/// 255 is a sentence rather than a payload. A denial is prose a person reads in
/// a log line, and a health problem is the same, so neither has a use for more
/// than a paragraph. It also keeps the postcard length prefix at two bytes, so
/// the denial frame's length stops moving at
/// `ServerDeniesAuth.max_frame_length` however long the reason is.
///
/// `encode` refuses anything longer as `error.TextTooLong` and does not
/// shorten it. Truncation is the one answer worse than silence: a denial
/// missing the end of its reason is a different sentence from the one the relay
/// chose, and the peer reading it cannot tell.
///
/// **It bounds what `encode` writes, and nothing else.** `decode` applies only
/// `max_packet_size` to a whole payload, so a peer may send a denial reason or a
/// health problem of up to 65533 bytes: both are read, and a value that long
/// re-encodes as `error.TextTooLong`. Upstream is in the same position and has no
/// bound at all, so bounding the way in would refuse frames upstream emits.
pub const max_text_length: usize = 255;

/// The relay protocol version, as the `Sec-Websocket-Protocol` sub-protocol spells
/// it.
///
/// Upstream `ProtocolVersion` (`http.rs:50`), declared "with newest version last,
/// so that the `Ord` impl orders by latest version as max". The discriminants say
/// so here, so comparing two versions is comparing their order without anyone
/// having to remember which way round the list is.
pub const ProtocolVersion = enum(u8) {
    /// `iroh-relay-v1`: the only version before iroh 0.98.0.
    v1 = 1,
    /// `iroh-relay-v2`, added in iroh 0.98.0. Removed `Health`, added `Status`.
    v2 = 2,

    /// The sub-protocol name a client sends and a server answers with.
    ///
    /// A comptime literal with static lifetime, so it is never borrowed from the
    /// version and never freed. A caller that sends it must send it unchanged:
    /// `parse` is exact, so a peer that lower-cases this name is on no version.
    pub fn name(version: ProtocolVersion) []const u8 {
        return switch (version) {
            .v1 => "iroh-relay-v1",
            .v2 => "iroh-relay-v2",
        };
    }

    /// The version a sub-protocol name names, or null for a name this build does
    /// not speak.
    ///
    /// Exact and case-sensitive, as a sub-protocol token is: nothing is trimmed
    /// and no case is folded here, because this answers a name and `negotiate` is
    /// the half that handles a header field. Empty is not a name, and returns
    /// null.
    pub fn parse(text: []const u8) ?ProtocolVersion {
        if (std.mem.eql(u8, text, "iroh-relay-v1")) return .v1;
        if (std.mem.eql(u8, text, "iroh-relay-v2")) return .v2;
        return null;
    }
};

/// The version a `Sec-Websocket-Protocol` header value settles on, or null when it
/// names none this build speaks.
///
/// The server's half of the upgrade, `http_server.rs:612`: split on commas, trim
/// each token, drop the ones that do not parse, take the largest of what is left.
/// It is a `max()` and not a first match, and on the one header a client actually
/// sends the two disagree — iroh advertises newest first (`http.rs:68`), so
/// first-match would pin every connection to the oldest version both ends speak
/// and quietly keep `Health` alive forever.
///
/// `header_value` is the whole header field, a comma-separated list of tokens. It
/// is bytes rather than a parsed header map because this is the part of an HTTP
/// server that has to be right without one.
///
/// The result is the largest version named by any token, or null when the field
/// names none — an empty field and a field of nothing but unknown tokens are the
/// same answer, and the caller closes the connection rather than choosing. The
/// field is borrowed for the call and nothing in the result refers to it, so the
/// header buffer may be reused the moment this returns. **One connection
/// negotiates once**: the version it returns is the one every `decode` and every
/// `encode` on that connection is given, because a frame legal in one is not
/// legal in the other.
pub fn negotiate(header_value: []const u8) ?ProtocolVersion {
    var best: ?ProtocolVersion = null;
    var rest = header_value;
    while (true) {
        const comma = std.mem.findScalar(u8, rest, ',');
        const token = if (comma) |at| rest[0..at] else rest;
        if (ProtocolVersion.parse(std.mem.trim(u8, token, &std.ascii.whitespace))) |version| {
            if (best == null or @intFromEnum(version) > @intFromEnum(best.?)) best = version;
        }
        const at = comma orelse return best;
        rest = rest[at + 1 ..];
    }
}

/// Which end of a relay connection a frame belongs to.
///
/// Neither value is on the wire — the frame type already carries the direction,
/// and its four datagram arms are numbered by it. This names it locally so
/// `Datagrams.frameType` and a `Message`'s tag cannot disagree about which end a
/// datagram is going to.
pub const Direction = enum {
    /// A client to the relay. Upstream `ClientToRelayMsg`.
    client_to_relay,
    /// The relay to one client. Upstream `RelayToClientMsg`.
    relay_to_client,
};

/// Every frame type, and the number that names it on the wire.
///
/// `common.rs:18`. One shared numbering for two protocols: 0 through 3 are the
/// handshake a relay authenticates a client with, 4 through 13 are the send/recv
/// protocol. Neither reuses a number and neither may: the frame type is the only
/// thing that says what the rest of the message means.
pub const FrameType = enum(u8) {
    /// 16 bytes of challenge for the client to sign.
    server_challenge = 0,
    /// 32-byte node id, then a 64-byte signature over the derived challenge.
    client_auth = 1,
    /// Nothing. The client authenticated.
    server_confirms_auth = 2,
    /// A postcard string: why the client did not authenticate.
    server_denies_auth = 3,
    /// 32-byte destination id, ECN byte, one datagram.
    client_to_relay_datagram = 4,
    /// 32-byte destination id, ECN byte, segment size, datagrams.
    client_to_relay_datagram_batch = 5,
    /// 32-byte source id, ECN byte, one datagram.
    relay_to_client_datagram = 6,
    /// 32-byte source id, ECN byte, segment size, datagrams.
    relay_to_client_datagram_batch = 7,
    /// 32-byte id of a peer that has disconnected.
    endpoint_gone = 8,
    /// 8 bytes to be echoed in a `Pong`.
    ping = 9,
    /// The 8 bytes of the `Ping` being answered.
    pong = 10,
    /// UTF-8 text saying what is wrong. v1 only, removed in v2.
    health = 11,
    /// Two big-endian `u32` durations in milliseconds: reconnect after, give up
    /// after.
    restarting = 12,
    /// One byte of `Status`. v2 only, added in v2.
    status = 13,

    /// The frame type for a number, or null when the number is not one.
    ///
    /// `u32` and not `u8` because the header is read as a `u64` varint: `decode`
    /// narrows it before asking, so a peer spelling a frame type wider than `u32`
    /// is `error.UnknownFrameType` rather than a truncation. A number this build
    /// has no name for is a number it must not guess at.
    pub fn fromInt(value: u32) ?FrameType {
        return std.enums.fromInt(FrameType, value);
    }

    /// Whether a connection speaking `version` may carry this frame.
    ///
    /// Everything but two types is in both versions. `Health` is v1 only and
    /// `Status` is v2 only, and they are one semantic event in two encodings:
    /// upstream's `relay.rs:441` and `relay.rs:468` reject each in the version
    /// that replaced it, and a v2 server talks to a v1 client by translating.
    pub fn allowedIn(frame_type: FrameType, version: ProtocolVersion) bool {
        return switch (frame_type) {
            .health => version == .v1,
            .status => version == .v2,
            else => true,
        };
    }

    /// Whether this frame carries a `Datagrams` with a segment size.
    ///
    /// The one predicate the batch invariant is written in terms of, and the only
    /// place in the module that has to know which of the four datagram types are
    /// batches.
    pub fn isDatagramBatch(frame_type: FrameType) bool {
        return switch (frame_type) {
            .client_to_relay_datagram_batch, .relay_to_client_datagram_batch => true,
            else => false,
        };
    }

    /// How many bytes this frame type's header takes.
    ///
    /// Every value in the table is below 64, so this is always one. It is computed
    /// rather than written down because the rule is the one in
    /// `noq_proto::VarInt::size`, and a rule written down twice is a rule one table
    /// extension away from being wrong in two places.
    pub fn encodedLen(frame_type: FrameType) usize {
        return frame_writer.varIntLen(@intFromEnum(frame_type));
    }
};

/// Explicit congestion notification, as a datagram frame carries it.
///
/// `noq_proto::EcnCodepoint` (`shared.rs:180`) and the two-bit field it is read
/// from. Absent is not a codepoint here: it is the absence of one, and the wire
/// cannot tell "no ECN" from any other value that reduces to zero.
pub const Ecn = enum(u8) {
    ect1 = 0b01,
    ect0 = 0b10,
    ce = 0b11,

    /// The codepoint a byte reduces to, or null when it reduces to none.
    ///
    /// Only the low two bits are read, so `0x00` and `0x04` both reduce to none:
    /// upstream masks with `0b11` (`shared.rs:193`), and a byte above the field is
    /// not a fourth codepoint.
    pub fn fromBits(bits: u8) ?Ecn {
        return switch (bits & 0b11) {
            0b01 => .ect1,
            0b10 => .ect0,
            0b11 => .ce,
            else => null,
        };
    }

    /// The two-bit value, which is never zero: absence is a null
    /// `Datagrams.ecn`, and the codec spells that `0x00`.
    ///
    /// **So a decoded frame is not always a byte fixed point.** An ECN byte above
    /// `0b11` decodes to null here and re-encodes as `0x00`, and the canonical
    /// spelling of what it meant is the second decode's, which is the one a
    /// metamorphic check compares.
    pub fn toBits(self: Ecn) u8 {
        return @intFromEnum(self);
    }
};

/// One datagram, or several of a known size.
///
/// Upstream `Datagrams` (`relay.rs:198`), modelled on `noq_proto::Transmit`. A
/// QUIC socket hands a GSO send one segment size and the whole payload, and this
/// is the relay's copy of that: `segment_size` is set when the payload is more
/// than one datagram, and its absence is what says it is one datagram.
pub const Datagrams = struct {
    /// Explicit congestion notification for the datagrams, or null for none.
    ///
    /// Null is not a codepoint and cannot be spelled as one: the wire has two
    /// bits and `0b00` is what no codepoint reduces to, so a frame whose byte was
    /// `0x00` and a frame whose byte was `0x04` both read as null and both
    /// re-encodes as `0x00`.
    ecn: ?Ecn,
    /// The size of one datagram, or null when `contents` is one datagram.
    ///
    /// Set means several datagrams of this size; null means one datagram.
    /// A single-datagram frame tag with a set size is `error.InvalidFrame`,
    /// decided before encoding writes anything.
    ///
    /// A batch size of zero is `error.ZeroSegmentSize` on encode and decode.
    /// Encoding discovers it after writing the frame header, so that refusal
    /// leaves a partial frame in the caller's buffer.
    segment_size: ?u16,
    /// The datagram bytes, borrowed from whoever decoded or received them. In a
    /// batch, every `segment_size` bytes but the last datagram is one datagram.
    ///
    /// **Nothing here copies and nothing here frees.** `encode` writes these bytes
    /// into the caller's buffer and keeps no reference to them, so a payload
    /// buffer may be reused the instant `encode` returns; `decode` hands the same
    /// bytes on as a borrow of the message buffer, so they must stay put and
    /// unmutated until the frame built from them is done with.
    contents: []const u8,

    /// The ECN byte every datagram payload starts with.
    pub const ecn_length = 1;
    /// The big-endian segment size a batch payload carries after the ECN byte.
    pub const segment_size_length = 2;
    /// The number of bytes in a node id, which every datagram payload starts with.
    ///
    /// It is `key.NodeId.byte_length` and is written down rather than referred to
    /// so a caller can size a datagram payload from this file alone.
    pub const node_id_length = 32;

    /// Whether these are a batch. This is the left half of the invariant
    /// `docs/ARCHITECTURE.md` states as rule 7, and the frame type the value is
    /// encoded under is the right half.
    pub fn isBatch(self: Datagrams) bool {
        return self.segment_size != null;
    }

    /// The frame type these datagrams are carried in, given which way they are
    /// going.
    ///
    /// Upstream writes this test twice, once per message enum (`relay.rs:310` and
    /// `relay.rs:485`). It is one function here because both enums answer it from
    /// the same field.
    pub fn frameType(self: Datagrams, direction: Direction) FrameType {
        return switch (direction) {
            .client_to_relay => if (self.isBatch())
                .client_to_relay_datagram_batch
            else
                .client_to_relay_datagram,
            .relay_to_client => if (self.isBatch())
                .relay_to_client_datagram_batch
            else
                .relay_to_client_datagram,
        };
    }

    /// Splits off at most `num_segments` segments and leaves the rest here.
    ///
    /// Upstream `Datagrams::take_segments` (`relay.rs:232`). Two rules, and the
    /// second is the one that corrupts the GSO path when it is missed: the batch
    /// handed back keeps a segment size only if it really holds more than one
    /// segment, and this loses its segment size the moment one segment or less is
    /// left in it. **That is what keeps `isBatch` and `frameType` in step:** a
    /// value holding one datagram is carried as `*_datagram`, so a segment size
    /// left on one would make `frameType` pick the batch tag for a frame whose
    /// payload is a single datagram. Nothing else forbids that shape — a batch
    /// frame whose payload is narrower than its segment size decodes to exactly
    /// it, `readDatagrams` refusing only a zero segment size — so a caller
    /// draining a batch one segment at a time must expect the tail to come back
    /// as a non-batch.
    ///
    /// With a segment size, zero takes no bytes and one takes at most one
    /// segment; either result is a non-batch. Without a segment size, the whole
    /// payload is returned regardless of `num_segments`.
    ///
    /// The two values share one backing array: the batch handed back and the
    /// receiver both borrow the same bytes, the split moves no memory, and
    /// neither value frees anything. What the call changes is which bytes each
    /// one names — the receiver's `contents` is shortened and may lose its
    /// segment size — so a caller still holding the old slice sees the old
    /// datagrams while `self` no longer includes them.
    pub fn takeSegments(self: *Datagrams, num_segments: usize) Datagrams {
        const segment_size = self.segment_size orelse {
            const contents = self.contents;
            self.contents = &.{};
            return .{ .ecn = self.ecn, .segment_size = null, .contents = contents };
        };
        const size: usize = segment_size;
        // Saturating rather than checked: this runs on every datagram a relay
        // forwards, and a `num_segments` a caller can name is no reason for it to
        // trap. A saturated `wanted` is clamped to the contents anyway.
        const wanted = size *| num_segments;
        const taken = @min(wanted, self.contents.len);
        const contents = self.contents[0..taken];
        self.contents = self.contents[taken..];
        // Upstream's own comment: a batch left with a single datagram loses its
        // segment size, so a single datagram is never carried as a batch.
        if (self.contents.len <= size) self.segment_size = null;
        return .{
            .ecn = self.ecn,
            .segment_size = if (num_segments > 1 and size < taken) segment_size else null,
            .contents = contents,
        };
    }
};

/// The relay's one-way declaration of a connection's health: v2's answer to v1's
/// `Health`.
///
/// Upstream `Status` (`relay.rs:122`). The three named conditions are the ones a
/// relay can report. `unknown` is upstream's forward-compatibility arm: a
/// condition this build has no name for is kept rather than rejected, so a
/// relay that grows a fourth one does not break a client that is only reading.
///
/// **This module carries the value and decides nothing from it.** A status frame
/// arriving before admission is refused as an out-of-order frame by the client
/// handshake machine in `relay/client.zig`, because no handshake state names
/// it. A node past admission counts `.same_endpoint_id_connected` and drops
/// `.healthy`, `.rate_limited` and `.unknown` (`node.zig`, `converseMessage`),
/// so a relay that rate-limits a node is invisible to that node's counters and
/// its logs. That is a fact about the consumers, not about the wire, and a
/// consumer that wants to act on an arm has to write the arm for itself.
pub const Status = union(enum) {
    /// The connection is healthy, and has recovered from earlier trouble.
    healthy,
    /// Another endpoint connected with the same node id. Nothing more arrives.
    same_endpoint_id_connected,
    /// The relay is rate-limiting what this endpoint sends.
    rate_limited,
    /// A condition this build has no name for, kept as the byte the relay sent.
    unknown: u8,

    /// The condition a byte names, keeping a byte this build has no name for.
    ///
    /// The three named arms are 0, 1 and 2 and everything else is `.unknown`, so
    /// `toBits(fromBits(bits)) == bits` for all 256: the status frame is the one
    /// frame here whose re-encode is always the same byte.
    pub fn fromBits(bits: u8) Status {
        return switch (bits) {
            0 => .healthy,
            1 => .same_endpoint_id_connected,
            2 => .rate_limited,
            else => .{ .unknown = bits },
        };
    }

    /// The byte, which is the discriminant itself and not the arm's index.
    pub fn toBits(self: Status) u8 {
        return switch (self) {
            .healthy => 0,
            .same_endpoint_id_connected => 1,
            .rate_limited => 2,
            .unknown => |bits| bits,
        };
    }
};

/// The relay is restarting, and here is how long a client should wait.
///
/// Upstream `Restarting` (`relay.rs:87`), carrying two `Duration`s and writing
/// `as_millis() as u32`. The milliseconds are what is kept: a relay advertising a
/// wait longer than `u32.max` milliseconds has a value the wire truncates, and a
/// struct holding the untruncated one would be describing a frame that cannot
/// exist.
///
/// **Milliseconds, `u32`, big-endian, and nothing about the pair is checked.**
/// Zero is meaningful for both — no advisory wait, no budget — and this module
/// stores them and never compares them: `try_for_ms` is not required to exceed
/// `reconnect_in_ms`, and a relay that means one says so itself. The widest a
/// peer can be told is `std.math.maxInt(u32)` milliseconds, about 49.7 days, and
/// a client turning that into nanoseconds multiplies into `u64` without
/// overflowing.
///
/// **Nothing in this tree acts on either number.** They are decoded, sized,
/// compared for equality and encoded, and that is the whole of their life
/// here. A restarting frame that arrives before admission is refused as an
/// out-of-order frame by the client handshake machine in `relay/client.zig`,
/// because no handshake state names it. A node past admission drops it
/// (`node.zig`, `converseMessage`), and `Node` dials its relay once and does
/// not reconnect, so there is no loop here for either figure to govern or
/// spend. A consumer that wants a reconnect budget has to write one; nothing
/// in this module enforces it and nothing counts against it.
pub const Restarting = struct {
    /// An advisory wait before reconnecting. It may be zero: the relay is
    /// allowed to use it to smear reconnects out. No consumer in this tree
    /// waits for it.
    reconnect_in_ms: u32,
    /// An advisory total budget a client may spend reconnecting before it
    /// gives up and goes back to its own connection-failure logic. No consumer
    /// in this tree spends it, so nothing here gives up on it either.
    try_for_ms: u32,
};

/// The relay's challenge, frame 0.
///
/// Upstream `ServerChallenge` (`handshake.rs:77`). Which sixteen bytes they are
/// is the server's draw from a cryptographic RNG and not this module's: the codec
/// carries them, and the signer derives the message to sign from them.
///
/// The codec constrains the bytes by nothing but their length, and that is
/// deliberate: the whole of the challenge's force is that the client signs
/// something the relay could not have chosen, so the draw is a CSPRNG's and the
/// rest is `messageToSign`'s. The value is copied into the state and into the
/// frame that carries it, so nothing borrows it and nothing has to outlive the
/// caller.
pub const ServerChallenge = struct {
    /// Bytes of challenge, drawn by the server from a cryptographic RNG.
    pub const challenge_length = 16;
    challenge: [challenge_length]u8,
};

/// The client's answer to a challenge, frame 1.
///
/// Upstream `ClientAuth` (`handshake.rs:88`). Upstream's `public_key` is `NodeId`
/// here for the reason `docs/ARCHITECTURE.md` gives: the value is never used as a
/// key in this API, it addresses a node.
///
/// Self-contained and fixed width: `decode` copies both fields out of the message
/// buffer, so this is the one handshake payload that outlives the bytes it was
/// read from. A node id that is not a point at all is `error.InvalidNodeId` on
/// the way in; a value a caller builds by hand is not checked here, and the only
/// thing left that can fail with it is `verifyClientAuth`.
pub const ClientAuth = struct {
    /// The node id being claimed, and it must be a point on the curve: `decode`
    /// refuses the 32 bytes of a frame that are not one.
    node_id: NodeId,
    /// The signature over the derived message of the challenge that was issued
    /// (`relay/client.zig` is where that message is built). Sixty-four bytes
    /// rather than a 65-byte `r‖s` pair, because a fixed array is written as raw
    /// bytes by the one codec in this protocol that postcards anything.
    signature: Signature,
};

/// The relay's refusal, frame 3.
///
/// **This is the frame a peer can make unwritable.** Its reason is the one
/// payload in the relay half of this protocol whose length no field fixes: it
/// comes from whatever the relay's access control decided, and upstream's
/// access control is a trait the operator implements, so its text is not this
/// codec's to assume. The two numbers below are how a caller that has to build
/// one is told what it may write.
pub const ServerDeniesAuth = struct {
    /// The most bytes of reason `encode` will carry. Upstream has no such
    /// number and needs none; see `max_text_length` for why this one exists, and
    /// for why it is a bound on the way out only: a peer may send a longer
    /// reason, `decode` reads it, and a value over this bound re-encodes as
    /// `error.TextTooLong`.
    pub const max_reason_length: usize = max_text_length;
    /// The most bytes the whole denial frame may occupy: the frame type, the
    /// postcard length prefix over `max_reason_length`, and the reason.
    ///
    /// **A caller sizing a buffer for a denial uses this and not
    /// `max_reason_length`,** because the prefix and the frame type are the two
    /// bytes that turn a reason at the bound into a frame one byte longer than
    /// the reason the caller was handed. It is the ceiling a relay can be
    /// made to need, so it is what makes "the relay always has room for the
    /// denial it decided to send" a fact about a number rather than a hope.
    pub const max_frame_length: usize = FrameType.server_denies_auth.encodedLen() +
        frame_writer.postcardVarIntLen(max_reason_length) + max_reason_length;

    /// Why the client did not authenticate. postcard-encoded, so this is a varint
    /// length and then UTF-8.
    ///
    /// **Borrowed from whoever decided the text — access control, or one of the
    /// two constants above — and the frame borrows it too.** `encode` copies it
    /// into the caller's buffer, so a denial that has been written owes nothing
    /// further; the `Step` that carries it does not, so the text must stay put
    /// and unmutated from the decision until that write.
    ///
    /// **Longer than `max_reason_length` is refused by `encode` as
    /// `error.TextTooLong` and never shortened.** The denial is the one frame a
    /// peer is waiting to learn something from, so a truncated reason is worse
    /// than no denial: the peer is told something the relay did not decide to
    /// say, and a closed connection afterwards cannot be read as a correction.
    ///
    /// **It must also be UTF-8, and `encode` refuses it if it is not.** Upstream
    /// types the reason as a `String`, so it cannot be anything else; this port
    /// types it as bytes, and postcard validates on the way in while `encode`
    /// writes what it is given. Without the check, a relay could put a reason on
    /// the wire that this module's own decoder rejects and that no peer can read
    /// as a `String` either. So `encode` answers `error.InvalidUtf8` — the same
    /// name `decode` uses — and refuses before its writer exists, so `out` is
    /// left exactly as the caller handed it over.
    reason: []const u8,
};

/// A datagram frame's node id and its payload.
///
/// One type for both directions because the payload has the same shape in both;
/// the frame type says which end the id belongs to. Upstream spells the field
/// `remote_endpoint_id` on a relay-to-client frame (`relay.rs:80`) and
/// `dst_endpoint_id` on a client-to-relay one (`relay.rs:189`), and that
/// difference is the direction the frame type already carries.
///
/// The borrow is the datagram's, not the struct's: `node_id` is a value and
/// `datagrams.contents` is borrowed from the message buffer the frame was decoded
/// from, so a `DatagramFrame` handed out by `decode` is only as long-lived as that
/// buffer, while one built by a caller to be encoded is done with its payload as
/// soon as `encode` returns.
pub const DatagramFrame = struct {
    /// The node id plus the ECN byte, which every datagram payload starts with.
    pub const header_length = Datagrams.node_id_length + Datagrams.ecn_length;
    /// The other end of the datagram: its destination in one direction, its source
    /// in the other.
    node_id: NodeId,
    datagrams: Datagrams,
};

/// A frame, with its type as the tag.
///
/// The tag is the frame type, so the type is carried rather than returned
/// alongside, and a frame cannot be built whose payload does not match its type.
/// Which direction a frame belongs to is on the tag too: a connection that only
/// accepts one direction reads the tag and treats the rest as a named failure, the
/// way upstream's two enums make it a compile-time `InvalidFrameType`.
///
/// Every arm is emittable in the versions `FrameType.allowedIn` says, and `encode`
/// refuses the other combination rather than putting on the wire a frame the far
/// end has agreed not to understand.
///
/// **Six of the fourteen arms borrow and eight do not**, and the split is the one
/// `checkEncodable` draws: a denial's reason, a health problem and the four
/// datagram frames' contents are borrowed, and the other eight are fixed-width
/// values the codec copied. A `Message` is therefore exactly as long-lived as the
/// buffer it came from when it came from `decode`, and a caller that builds one
/// owns the bytes it put into it until `encode` returns.
///
/// `health` is the rest of the message rather than a length, so an empty health
/// frame is a valid frame carrying no text, and that text is bounded by
/// `max_packet_size` on the way in and by `max_text_length` on the way out.
pub const Message = union(FrameType) {
    server_challenge: ServerChallenge,
    client_auth: ClientAuth,
    server_confirms_auth: void,
    server_denies_auth: ServerDeniesAuth,
    client_to_relay_datagram: DatagramFrame,
    client_to_relay_datagram_batch: DatagramFrame,
    relay_to_client_datagram: DatagramFrame,
    relay_to_client_datagram_batch: DatagramFrame,
    endpoint_gone: NodeId,
    ping: [8]u8,
    pong: [8]u8,
    /// UTF-8 problem text, borrowed from the decode buffer or the caller.
    /// Encoding allows at most `max_text_length` bytes and refuses invalid
    /// UTF-8 as `error.InvalidUtf8` before writing anything.
    health: []const u8,
    restarting: Restarting,
    status: Status,
};

// --- tests

test "FrameType: 0 through 13, the numbers and no others" {
    // The numbering of `common.rs:18`, one assertion per value, so a change to
    // any one of them names itself.
    const table = [_]FrameType{
        .server_challenge,
        .client_auth,
        .server_confirms_auth,
        .server_denies_auth,
        .client_to_relay_datagram,
        .client_to_relay_datagram_batch,
        .relay_to_client_datagram,
        .relay_to_client_datagram_batch,
        .endpoint_gone,
        .ping,
        .pong,
        .health,
        .restarting,
        .status,
    };
    for (table, 0..) |frame_type, index| {
        try std_testing.expectEqual(@as(u8, @intCast(index)), @intFromEnum(frame_type));
        try std_testing.expectEqual(frame_type, FrameType.fromInt(@intCast(index)).?);
        // Every type in the table is below 64, so every header is one byte and
        // the header byte is the type. `Health` is `0b` in the captured vectors,
        // `Status` is `0d`, and this is why.
        try std_testing.expectEqual(@as(usize, 1), frame_type.encodedLen());
    }
    try std_testing.expectEqual(@as(usize, 14), table.len);

    // A type outside the table is malformed, not a default.
    try std_testing.expectEqual(@as(?FrameType, null), FrameType.fromInt(14));
    try std_testing.expectEqual(@as(?FrameType, null), FrameType.fromInt(63));
    try std_testing.expectEqual(@as(?FrameType, null), FrameType.fromInt(64));
    try std_testing.expectEqual(@as(?FrameType, null), FrameType.fromInt(0xffff_ffff));
}

test "negotiate: the largest version offered, not the first one" {
    // iroh advertises newest first (`http.rs:68`), which is the only order a
    // client sends. Under first-match that picks v1 and every connection stays on
    // v1 forever, so the first two cases are the whole test: one set, two orders,
    // and only a `max()` gives the same answer twice.
    try std_testing.expectEqual(
        @as(?ProtocolVersion, .v2),
        negotiate("iroh-relay-v2, iroh-relay-v1"),
    );
    try std_testing.expectEqual(
        @as(?ProtocolVersion, .v2),
        negotiate("iroh-relay-v1, iroh-relay-v2"),
    );
    try std_testing.expectEqual(@as(?ProtocolVersion, .v1), negotiate("iroh-relay-v1"));
    try std_testing.expectEqual(@as(?ProtocolVersion, .v2), negotiate("iroh-relay-v2"));

    // Whitespace around a token, and tokens this build does not speak, which
    // upstream's `filter_map` drops rather than failing on.
    try std_testing.expectEqual(
        @as(?ProtocolVersion, .v2),
        negotiate("  iroh-relay-v1 ,\troh-not-a-relay, iroh-relay-v2  "),
    );
    try std_testing.expectEqual(
        @as(?ProtocolVersion, .v1),
        negotiate("iroh-relay-v1,,iroh-relay-v1"),
    );

    // Nothing usable, which upstream reports as `UnsupportedRelayVersion`.
    try std_testing.expectEqual(@as(?ProtocolVersion, null), negotiate(""));
    try std_testing.expectEqual(@as(?ProtocolVersion, null), negotiate("iroh-relay-v3"));
    try std_testing.expectEqual(@as(?ProtocolVersion, null), negotiate("iroh-relay"));
    try std_testing.expectEqual(@as(?ProtocolVersion, null), negotiate(",,,"));

    // The name round-trips both ways, which is the whole of `http.rs:120`'s
    // `all_is_exhaustive` for a two-variant enum.
    for ([_]ProtocolVersion{ .v1, .v2 }) |version| {
        try std_testing.expectEqual(version, ProtocolVersion.parse(version.name()).?);
    }
}

test "batch invariant: draining to one datagram clears the segment size" {
    // Four datagrams of four bytes at a segment size of four, drained three at a
    // time. The first call hands back a real batch and leaves one datagram, and
    // the remainder is the asymmetry rule 7 names: one datagram left, so no
    // segment size, so it goes out as a single-datagram frame and not as a batch
    // of one.
    var batch: Datagrams = .{
        .ecn = .ce,
        .segment_size = 4,
        .contents = "abcdefghijklmnop",
    };
    try std_testing.expect(batch.isBatch());

    const first = batch.takeSegments(3);
    try std_testing.expectEqual(@as(?u16, 4), first.segment_size);
    try std_testing.expectEqualStrings("abcdefghijkl", first.contents);
    try std_testing.expectEqual(@as(usize, 3), vectors.datagramsIn(first.contents, 4));
    try std_testing.expectEqualStrings("mnop", batch.contents);
    try std_testing.expectEqual(@as(?u16, null), batch.segment_size);
    try std_testing.expect(!batch.isBatch());
    try std_testing.expectEqual(@as(usize, 1), vectors.datagramsIn(batch.contents, 4));

    // Draining the remainder returns it whole, as a non-batch, because a
    // `num_segments` of one cannot be a batch however much is left.
    var second = batch.takeSegments(1);
    try std_testing.expectEqual(@as(?u16, null), second.segment_size);
    try std_testing.expectEqualStrings("mnop", second.contents);
    try std_testing.expectEqual(@as(usize, 0), batch.contents.len);
    // And a drained non-batch is still a non-batch, however it is asked.
    try std_testing.expectEqual(@as(?u16, null), second.takeSegments(4).segment_size);
}

test "batch invariant: a non-batch never acquires a segment size" {
    var single: Datagrams = .{ .ecn = .ce, .segment_size = null, .contents = vectors.hello_world };
    const taken = single.takeSegments(8);
    try std_testing.expectEqual(@as(?u16, null), taken.segment_size);
    try std_testing.expectEqualStrings(vectors.hello_world, taken.contents);
    try std_testing.expectEqual(@as(usize, 0), single.contents.len);
    try std_testing.expectEqual(@as(?u16, null), single.segment_size);
    try std_testing.expect(!single.isBatch());
    try std_testing.expectEqual(@as(?u16, null), single.takeSegments(0).segment_size);
}

test "batch invariant: a segment size wider than the payload drains to one" {
    // The seed the fuzzer starts from, decided here. A batch frame declaring
    // 1024-byte segments and carrying four bytes holds one datagram and says it
    // holds more. Decoding keeps both, because a batch frame carrying one
    // datagram's worth is still a batch frame and the invariant is about the frame
    // type; draining it is where the claim collapses. Upstream's own
    // `is_datagram_batch` test (`relay.rs:248`) is the same strict less-than, so
    // the batch it hands back has no segment size either.
    var oversized: Datagrams = .{
        .ecn = .ce,
        .segment_size = 1024,
        .contents = "\xde\xad\xbe\xef",
    };
    const drained = oversized.takeSegments(1);
    try std_testing.expectEqual(@as(?u16, null), drained.segment_size);
    try std_testing.expectEqual(@as(?u16, null), oversized.segment_size);
    try std_testing.expectEqual(@as(usize, 0), oversized.contents.len);
    try std_testing.expectEqualStrings("\xde\xad\xbe\xef", drained.contents);
    try std_testing.expectEqual(@as(usize, 1), vectors.datagramsIn(drained.contents, 1024));
}
