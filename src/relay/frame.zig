//! The relay frame: what travels inside one relay WebSocket message.
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
//!   with, and `src/shared.rs:180` — `EcnCodepoint`.
//!
//! # This frame is not postcard
//!
//! The header is a QUIC variable-length integer: `noq_proto::VarInt::encode`,
//! called from `common.rs:83`. It is not a postcard varint. The two agree for
//! every value a `FrameType` can take — 0 through 13 is below 64, and below 64 a
//! QUIC varint is one raw byte, exactly as a postcard varint is — so every byte
//! this module emits is the same byte under either reading, and every captured
//! vector in this file is satisfied by both. They part company on the way in:
//! `40 00` is a two-byte QUIC varint spelling 0 and a two-byte postcard varint
//! spelling 64, and `80 00` is a QUIC varint that declares eight bytes against a
//! postcard varint spelling 0. A decoder that took the postcard spelling would
//! read a peer that has not sent a frame type at all.
//!
//! Everything after the header is raw bytes at a fixed width: `put_u8`, `put_u16`
//! and `put_u32` in `relay.rs:263`, all big-endian, and no length prefix
//! anywhere. A segment size of 6 is `00 06` and not a varint. postcard is used
//! here for the one field upstream postcard-encodes, the denial reason in frame
//! 3, which `handshake.rs:561` hands to `postcard::to_io`.
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
//! it is checked here rather than left to the caller. Upstream's reason is a
//! `String` (`handshake.rs:106`) and cannot be anything else; here it is
//! `[]const u8`, so `encode` validates it with
//! `std.unicode.utf8ValidateSlice` and refuses `error.InvalidUtf8` — the name
//! `decode` already answers with, because postcard validates on the way in. A
//! codec that refuses a value on the way in and writes it on the way out is not
//! a codec, and the relay side of this protocol writes denials and health
//! problems that a peer reads as text.
//!
//! Nothing here reads a clock, the environment, or a global, and nothing
//! allocates: `encode` appends into a buffer the caller owns, and `decode` borrows
//! the caller's bytes for the three kinds of payload it does not copy out — a
//! denial's reason, a health problem, and the contents of the four datagram
//! frames. Everything else it hands back is a value it copied first, so a
//! `Message` is as independent of its buffer as its tag allows. `Restarting`
//! stores milliseconds as the `u32` the wire truncates them to rather than as a
//! duration, so a value that will not fit on the wire cannot be held in a struct
//! that claims to be a frame. See `docs/ARCHITECTURE.md`, "Wire codecs are pure
//! and separate from the transport".

const std = @import("std");
const key = @import("../base/key.zig");
const postcard = @import("../wire/postcard.zig");

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
        return varIntLen(@intFromEnum(frame_type));
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
    /// re-encode as `0x00`.
    ecn: ?Ecn,
    /// The size of one datagram, or null when `contents` is one datagram.
    ///
    /// **Null is the whole of the batch invariant**: set means the payload is
    /// several datagrams of this size, absent means it is one, and the frame type
    /// this value is encoded under agrees or the codec refuses.
    ///
    /// Zero is what neither of them may hold. `decode` refuses a frame that
    /// declares one — zero names no datagram, and reading it as a single datagram
    /// would hand back a `Datagrams` with no segment size out of a batch frame —
    /// and `encode` refuses a value carrying one as `error.ZeroSegmentSize`. A
    /// value a caller builds by hand is therefore only caught on the way out.
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
    /// left in it. A `Datagrams` holding one datagram and a segment size is a value
    /// the decoder refuses to build, so leaving one here is not a smaller loss
    /// than it looks.
    ///
    /// A `num_segments` of zero or one returns everything as a non-batch and
    /// leaves nothing here, which is upstream's behaviour and the reason a
    /// single-datagram frame is a frame and not a batch of one.
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
/// discriminant this build has no name for is kept rather than rejected, so a
/// relay that grows a fourth one does not break a client that is only reading.
pub const Status = union(enum) {
    /// The connection is healthy, and has recovered from earlier trouble.
    healthy,
    /// Another endpoint connected with the same node id. Nothing more arrives.
    same_endpoint_id_connected,
    /// The relay is rate-limiting what this endpoint sends.
    rate_limited,
    /// A discriminant this build has no name for.
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
pub const Restarting = struct {
    /// An advisory wait before reconnecting. It may be zero: the relay is allowed
    /// to use it to smear reconnects out.
    reconnect_in_ms: u32,
    /// An advisory total budget for reconnecting before the client gives up and
    /// goes back to its own connection-failure logic.
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
        postcardVarIntLen(max_reason_length) + max_reason_length;

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
    health: []const u8,
    restarting: Restarting,
    status: Status,
};

/// The bytes `encode` will write for `message`, exactly.
///
/// Upstream keeps an `encoded_len` beside every `write_to` and asserts the two
/// agree. A size that is a guess is a size a caller sizes a buffer from.
///
/// **Six of this union's fourteen arms carry a length their type does not fix**,
/// and `encode` bounds each before it writes: a denial's reason and a health
/// problem by `max_text_length`, and the four datagram frames' payload by
/// `max_packet_size`. That payload is every byte after the frame type and not
/// the contents, so the four are not bounded alike — 65503 bytes of contents in
/// a single datagram, 65501 in a batch, which spends two of the bound on its
/// segment size. **A caller sizing one buffer for every frame it sends sizes it
/// for the frame and not for the contents, and takes
/// `max_packet_size + FrameType.client_to_relay_datagram_batch.encodedLen()`,
/// which `ServerDeniesAuth.max_frame_length` does not come near.** The other
/// eight arms are fixed by their own type, and `checkEncodable` is where both
/// halves of that statement are kept.
///
/// **It is what a buffer is sized from, and for every message `encode` accepts it
/// is exactly the byte count.** For one `encode` refuses it is what the frame
/// would have been: text over `max_text_length` still counts its bytes, and a
/// batch with no segment size or a zero one still counts the two that would have
/// carried it. So `encodedLen` never understates a frame that can be written, and
/// a caller may treat it as a lower bound on a buffer for a message it has not
/// checked.
pub fn encodedLen(message: Message) usize {
    const payload: usize = switch (message) {
        .server_challenge => ServerChallenge.challenge_length,
        .client_auth => NodeId.byte_length + Signature.byte_length,
        .server_confirms_auth => 0,
        .server_denies_auth => |denial| postcardVarIntLen(denial.reason.len) + denial.reason.len,
        .client_to_relay_datagram,
        .relay_to_client_datagram,
        => |frame| DatagramFrame.header_length + frame.datagrams.contents.len,
        .client_to_relay_datagram_batch,
        .relay_to_client_datagram_batch,
        => |frame| DatagramFrame.header_length + Datagrams.segment_size_length +
            frame.datagrams.contents.len,
        .endpoint_gone => NodeId.byte_length,
        .ping, .pong => 8,
        .health => |problem| problem.len,
        .restarting => 2 * @sizeOf(u32),
        .status => 1,
    };
    return std.meta.activeTag(message).encodedLen() + payload;
}

/// Writes `message` into `out` and hands back what it wrote.
///
/// `out` is the caller's buffer and is never grown: a frame that does not fit is
/// `error.BufferFull`, the same rule `wire/postcard.zig` follows and for the same
/// reason, that one scratch buffer can serve a whole connection.
///
/// `version` is what the connection negotiated, and a frame that version does not
/// define is `error.FrameNotAllowedInVersion` rather than bytes on the wire.
/// `Health` and `Status` are the two that differ, and refusing here is what keeps
/// both versions emittable without either one sending a frame the far end has
/// agreed not to understand.
///
/// **Which refusals leave what behind.** `error.FrameNotAllowedInVersion`,
/// `error.TextTooLong` and `error.FrameTooLarge` are all decided before the
/// writer exists, so `out` comes back exactly as the caller handed it over and a
/// caller cannot find a denial's first bytes in its buffer and mistake them for
/// one. A relay that cannot say why it refused has to say nothing rather than say
/// something it chose not to: the peer closing the connection is a different event
/// from the peer being told a truncated reason.
///
/// The two refusals the writer itself makes are different, and the difference is
/// what is in the buffer afterwards: **`error.BufferFull` and
/// `error.ZeroSegmentSize` leave a partial frame** — the frame type, and whatever
/// of the payload fitted before the writer ran out — because both are found once
/// bytes are down. Neither hands back a slice, so a caller must discard `out` on
/// any error rather than send what happens to be in it.
///
/// **What it borrows and what it keeps.** `message` is read and nothing in the
/// result refers to it: every arm is copied into `out`, so the payload buffers a
/// caller encoded from may be reused the moment this returns. The slice it returns
/// is `out[0..written]` — the same memory, not a copy of it — so it aliases the
/// caller's buffer and is invalidated by whatever the caller next writes there.
/// Nothing is allocated, nothing is read from a global, and no clock or I/O is
/// touched, so the call is reentrant over distinct buffers and needs no
/// synchronization beyond the caller's own.
pub fn encode(message: Message, version: ProtocolVersion, out: []u8) Error![]const u8 {
    const frame_type: FrameType = std.meta.activeTag(message);
    if (!frame_type.allowedIn(version)) return error.FrameNotAllowedInVersion;
    // Every bound this frame has to meet, before the writer exists. One pass
    // over the arms whose length the type does not fix, so a refusal leaves
    // `out` exactly as the caller handed it over rather than holding the frame
    // type and no payload.
    try checkEncodable(message);
    var writer = Writer.init(out);
    try writer.writeVarInt(@intFromEnum(frame_type));
    switch (message) {
        .server_challenge => |challenge| try writer.write(&challenge.challenge),
        .client_auth => |auth| {
            try writer.write(&auth.node_id.toBytes());
            try writer.write(&auth.signature.toBytes());
        },
        .server_confirms_auth => {},
        .server_denies_auth => |denial| {
            var text = postcard.Writer.init(writer.rest());
            text.writeStr(denial.reason) catch return error.BufferFull;
            writer.advance(text.finish().len);
        },
        .client_to_relay_datagram,
        .relay_to_client_datagram,
        => |frame| {
            try writeDatagramHeader(&writer, frame);
            try writer.write(frame.datagrams.contents);
        },
        .client_to_relay_datagram_batch,
        .relay_to_client_datagram_batch,
        => |frame| {
            // A batch frame is chosen because `segment_size` is set, so this
            // cannot be null. The check is here because a zero is a value the
            // invariant forbids and a named error beats a frame that lies.
            const segment_size = frame.datagrams.segment_size orelse return error.ZeroSegmentSize;
            if (segment_size == 0) return error.ZeroSegmentSize;
            try writeDatagramHeader(&writer, frame);
            try writer.writeU16Be(segment_size);
            try writer.write(frame.datagrams.contents);
        },
        .endpoint_gone => |node_id| try writer.write(&node_id.toBytes()),
        .ping => |data| try writer.write(&data),
        .pong => |data| try writer.write(&data),
        // v1 only, and the other of the two frames whose length no field fixes.
        // Its bound is `max_text_length` and `checkEncodable` has already had it,
        // together with the check that it is text at all.
        .health => |problem| try writer.write(problem),
        .restarting => |restarting| {
            try writer.writeU32Be(restarting.reconnect_in_ms);
            try writer.writeU32Be(restarting.try_for_ms);
        },
        .status => |status| try writer.writeU8(status.toBits()),
    }
    return writer.finish();
}

/// Reads one frame from the start of `bytes`.
///
/// `bytes` is one WebSocket message: a frame type and then that frame's payload to
/// the end. **What comes back is the caller's own storage, borrowed, on six of the
/// fourteen arms** — a denial's reason, a health problem, and the contents of the
/// four datagram frames are slices into `bytes`; the other eight arms are
/// fixed-width values copied out first, and the node ids and signatures among them
/// are independent of the buffer they were read from.
///
/// So the borrow lasts exactly as long as the message buffer, and freeing it is
/// the caller's: this function allocates nothing and retains nothing after it
/// returns. Writing any byte of `bytes` changes the frame borrowing it, and
/// reusing the buffer for the next message invalidates every `Message` still held
/// from the last one. See `base/addr.zig` on `RelayUrl.hostSlice` for the same
/// borrow, argued at greater length.
///
/// There is nothing to copy, nothing to free, and nothing to do with the message
/// but read it, so two threads may decode two messages out of two buffers at
/// once — and neither may decode from a buffer the other is writing.
///
/// `version` is what the connection negotiated, and it is checked before the
/// payload is read at all: a v2 connection sent a `Health` frame, the answer is
/// `error.FrameNotAllowedInVersion`, and nothing downstream learns what the
/// payload said.
pub fn decode(bytes: []const u8, version: ProtocolVersion) Error!Message {
    var offset: usize = 0;
    const tag = try readVarInt(bytes, &offset);
    const narrow = std.math.cast(u32, tag) orelse return error.UnknownFrameType;
    const frame_type = FrameType.fromInt(narrow) orelse return error.UnknownFrameType;
    if (!frame_type.allowedIn(version)) return error.FrameNotAllowedInVersion;
    const payload = bytes[offset..];
    if (payload.len > max_packet_size) return error.FrameTooLarge;
    return switch (frame_type) {
        .server_challenge => .{
            .server_challenge = .{
                .challenge = try readArray(ServerChallenge.challenge_length, payload),
            },
        },
        .client_auth => blk: {
            const node_id = try readNodeId(payload);
            const signature = Signature.fromBytes(
                try readExact(Signature.byte_length, payload[NodeId.byte_length..]),
            );
            break :blk .{ .client_auth = .{ .node_id = node_id, .signature = signature } };
        },
        .server_confirms_auth => if (payload.len == 0)
            .server_confirms_auth
        else
            error.InvalidFrame,
        .server_denies_auth => .{ .server_denies_auth = .{ .reason = try readStr(payload) } },
        .client_to_relay_datagram => try readDatagramFrame(payload, .client_to_relay_datagram),
        .client_to_relay_datagram_batch => try readDatagramFrame(
            payload,
            .client_to_relay_datagram_batch,
        ),
        .relay_to_client_datagram => try readDatagramFrame(payload, .relay_to_client_datagram),
        .relay_to_client_datagram_batch => try readDatagramFrame(
            payload,
            .relay_to_client_datagram_batch,
        ),
        .endpoint_gone => .{ .endpoint_gone = try readNodeIdExact(payload) },
        .ping => .{ .ping = try readExact(8, payload) },
        .pong => .{ .pong = try readExact(8, payload) },
        .health => .{ .health = payload },
        .restarting => blk: {
            if (payload.len != 2 * @sizeOf(u32)) return error.InvalidFrame;
            break :blk .{ .restarting = .{
                .reconnect_in_ms = std.mem.readInt(u32, payload[0..4], .big),
                .try_for_ms = std.mem.readInt(u32, payload[4..8], .big),
            } };
        },
        .status => if (payload.len == 1)
            .{ .status = Status.fromBits(payload[0]) }
        else
            error.InvalidFrame,
    };
}

/// Whether two frames are the same frame.
///
/// The comparison a round trip has to be a fixed point of, and the one place that
/// says what "the same" is for a borrowed payload: the bytes, not the buffer they
/// were read from.
pub fn eql(a: Message, b: Message) bool {
    const frame_type: FrameType = std.meta.activeTag(a);
    if (frame_type != std.meta.activeTag(b)) return false;
    return switch (a) {
        .server_challenge => |challenge| std.mem.eql(
            u8,
            &challenge.challenge,
            &b.server_challenge.challenge,
        ),
        .client_auth => |auth| nodeIdEql(auth.node_id, b.client_auth.node_id) and std.mem.eql(
            u8,
            &auth.signature.toBytes(),
            &b.client_auth.signature.toBytes(),
        ),
        .server_confirms_auth => true,
        .server_denies_auth => |denial| std.mem.eql(u8, denial.reason, b.server_denies_auth.reason),
        .client_to_relay_datagram => |frame| datagramFrameEql(frame, b.client_to_relay_datagram),
        .client_to_relay_datagram_batch => |frame| datagramFrameEql(
            frame,
            b.client_to_relay_datagram_batch,
        ),
        .relay_to_client_datagram => |frame| datagramFrameEql(frame, b.relay_to_client_datagram),
        .relay_to_client_datagram_batch => |frame| datagramFrameEql(
            frame,
            b.relay_to_client_datagram_batch,
        ),
        .endpoint_gone => |node_id| nodeIdEql(node_id, b.endpoint_gone),
        .ping => |data| std.mem.eql(u8, &data, &b.ping),
        .pong => |data| std.mem.eql(u8, &data, &b.pong),
        .health => |problem| std.mem.eql(u8, problem, b.health),
        .restarting => |restarting| restarting.reconnect_in_ms == b.restarting.reconnect_in_ms and
            restarting.try_for_ms == b.restarting.try_for_ms,
        // Compared by byte and not by arm: `Status` keeps a discriminant it has no
        // name for, and the name is the only thing that could differ.
        .status => |status| status.toBits() == b.status.toBits(),
    };
}

fn datagramFrameEql(a: DatagramFrame, b: DatagramFrame) bool {
    if (!nodeIdEql(a.node_id, b.node_id)) return false;
    if (a.datagrams.ecn != b.datagrams.ecn) return false;
    if (a.datagrams.segment_size != b.datagrams.segment_size) return false;
    return std.mem.eql(u8, a.datagrams.contents, b.datagrams.contents);
}

fn nodeIdEql(a: NodeId, b: NodeId) bool {
    return std.mem.eql(u8, &a.toBytes(), &b.toBytes());
}

fn writeDatagramHeader(writer: *Writer, frame: DatagramFrame) Error!void {
    try writer.write(&frame.node_id.toBytes());
    try writer.writeU8(if (frame.datagrams.ecn) |codepoint| codepoint.toBits() else 0);
}

/// Every bound `message` has to meet, checked before a byte of it is written.
///
/// **This is the sweep.** Six of the fourteen arms of `Message` carry a length
/// their own type does not fix, in three kinds, and each is refused here by
/// name: a `server_denies_auth` reason and a v1 `health` problem, both
/// relay-authored text, by `max_text_length`, and the four datagram frames'
/// payload by `max_packet_size`.
///
/// The other eight are the frame type's own width and cannot be anything else:
/// the challenge's sixteen bytes, the client auth's node id and signature, the
/// empty confirmation, the endpoint id, ping's and pong's eight bytes, the two
/// durations, and the status discriminant. **A fifteenth arm carrying a
/// peer-supplied length is the case this function exists to catch, and the
/// switch below is where it lands** — an arm with no bound here is an arm whose
/// length nothing checks.
///
/// The datagram bound is on the payload `decode` measures — every byte after the
/// frame type, and not the contents alone — so it is the rule `decode` already
/// applies to a payload it is handed (`relay.rs:404` and `:544`), now applied on
/// the way out too, and this module cannot emit a frame its own decoder refuses
/// for being too long. That is `max_packet_size` over a node id, an ECN byte and,
/// on a batch, a segment size: 65503 bytes of contents in a single datagram, 65501
/// in a batch. Upstream checks it on decode only, because its `write_to` writes
/// into a `BytesMut` that grows (`relay.rs:328`): a frame that is too large there
/// is a large allocation rather than a fault.
///
/// What is not a length is out of scope here, with one exception that is a real
/// hole: relay-authored text is written as it was handed, so a reason or a
/// problem that is not UTF-8 would be a frame this module emits and will not
/// read back. So this is the sweep that closes it — the two text arms check
/// `std.unicode.utf8ValidateSlice` and refuse `error.InvalidUtf8`, the name
/// `decode` already answers with, because a codec that refuses on the way in
/// and writes on the way out is not a codec.
///
/// It runs before the writer exists so that a refusal leaves `out` as the caller
/// handed it over. A caller that kept the frame type and lost the payload would
/// find a partial frame in its own buffer, and a partial denial is a denial
/// whose reason stops early.
fn checkEncodable(message: Message) Error!void {
    switch (message) {
        .server_denies_auth => |denial| {
            if (denial.reason.len > ServerDeniesAuth.max_reason_length) {
                return error.TextTooLong;
            }
            if (!std.unicode.utf8ValidateSlice(denial.reason)) return error.InvalidUtf8;
        },
        .health => |problem| {
            if (problem.len > max_text_length) return error.TextTooLong;
            if (!std.unicode.utf8ValidateSlice(problem)) return error.InvalidUtf8;
        },
        .client_to_relay_datagram,
        .relay_to_client_datagram,
        => |frame| {
            const contents_limit = max_packet_size - DatagramFrame.header_length;
            if (frame.datagrams.contents.len > contents_limit) return error.FrameTooLarge;
        },
        .client_to_relay_datagram_batch,
        .relay_to_client_datagram_batch,
        => |frame| {
            const contents_limit = max_packet_size - DatagramFrame.header_length -
                Datagrams.segment_size_length;
            if (frame.datagrams.contents.len > contents_limit) return error.FrameTooLarge;
        },
        .server_challenge,
        .client_auth,
        .server_confirms_auth,
        .endpoint_gone,
        .ping,
        .pong,
        .restarting,
        .status,
        => {},
    }
}

/// A node id and a datagram payload, under the length rules the four datagram
/// types name between them.
fn readDatagramFrame(payload: []const u8, frame_type: FrameType) Error!Message {
    if (payload.len < DatagramFrame.header_length) return error.InvalidFrame;
    // The slice starts after the node id and not after the whole header: the ECN
    // byte belongs to the datagram payload and `readDatagrams` is what reads it.
    const frame: DatagramFrame = .{
        .node_id = try readNodeId(payload),
        .datagrams = try readDatagrams(
            payload[NodeId.byte_length..],
            FrameType.isDatagramBatch(frame_type),
        ),
    };
    return switch (frame_type) {
        .client_to_relay_datagram => .{ .client_to_relay_datagram = frame },
        .client_to_relay_datagram_batch => .{ .client_to_relay_datagram_batch = frame },
        .relay_to_client_datagram => .{ .relay_to_client_datagram = frame },
        .relay_to_client_datagram_batch => .{ .relay_to_client_datagram_batch = frame },
        else => error.UnknownFrameType,
    };
}

fn readNodeId(payload: []const u8) Error!NodeId {
    return NodeId.fromBytes(try readArray(NodeId.byte_length, payload)) catch
        return error.InvalidNodeId;
}

fn readNodeIdExact(payload: []const u8) Error!NodeId {
    if (payload.len != NodeId.byte_length) return error.InvalidFrame;
    return readNodeId(payload);
}

/// The datagram payload, with or without the segment size.
fn readDatagrams(payload: []const u8, is_batch: bool) Error!Datagrams {
    if (is_batch) {
        // One ECN byte and a two-byte segment size, which `relay.rs:283` insists
        // on before it reads either.
        if (payload.len < Datagrams.ecn_length + Datagrams.segment_size_length) {
            return error.InvalidFrame;
        }
        const segment_size = std.mem.readInt(u16, payload[1..3], .big);
        // A zero segment size names no datagram, so reading one as a single
        // datagram would hand back a `Datagrams` with no segment size out of a
        // batch frame and the two halves of rule 7 would no longer be one fact.
        // The frame is refused instead. Upstream drops the `NonZeroU16` here and
        // returns exactly that inconsistent value (`relay.rs:293`).
        if (segment_size == 0) return error.ZeroSegmentSize;
        return .{
            .ecn = Ecn.fromBits(payload[0]),
            .segment_size = segment_size,
            .contents = payload[Datagrams.ecn_length + Datagrams.segment_size_length ..],
        };
    }
    if (payload.len < Datagrams.ecn_length) return error.InvalidFrame;
    return .{
        .ecn = Ecn.fromBits(payload[0]),
        .segment_size = null,
        .contents = payload[Datagrams.ecn_length..],
    };
}

/// The postcard string in a `ServerDeniesAuth`.
///
/// The one field in a relay frame that is postcard: `handshake.rs:561` hands the
/// whole struct to `postcard::to_io`, and a `String` is a varint length and then
/// UTF-8. Every failure keeps the name `postcard` gave it, except trailing bytes,
/// which mean this is not the frame it claims to be.
fn readStr(payload: []const u8) Error![]const u8 {
    var reader = postcard.Reader.init(payload);
    const reason = reader.readStr() catch |err| return fromPostcard(err);
    reader.finish() catch return error.InvalidFrame;
    return reason;
}

fn fromPostcard(err: postcard.Error) Error {
    return switch (err) {
        error.UnexpectedEnd => error.UnexpectedEnd,
        error.BadVarint => error.BadVarint,
        error.ValueOutOfRange => error.ValueOutOfRange,
        error.BadLength => error.BadLength,
        error.InvalidUtf8 => error.InvalidUtf8,
        // `readStr` reads a length and a UTF-8 run and nothing else, so these are
        // the arms that make the mapping total rather than the arms a denial can
        // reach.
        error.BufferFull,
        error.BadBool,
        error.BadOptionTag,
        error.UnknownVariant,
        error.TrailingBytes,
        => error.InvalidFrame,
    };
}

/// Exactly `length` bytes, or `InvalidFrame`.
///
/// Upstream writes this check the same way for every fixed-width payload
/// (`relay.rs:423`, `428`, `434`, `448`): a payload that is not the width its
/// type names is not that type.
fn readExact(comptime length: usize, payload: []const u8) Error![length]u8 {
    if (payload.len != length) return error.InvalidFrame;
    return payload[0..length].*;
}

fn readArray(comptime length: usize, payload: []const u8) Error![length]u8 {
    if (payload.len < length) return error.InvalidFrame;
    return payload[0..length].*;
}

/// How many bytes a QUIC varint of `value` takes.
///
/// `noq_proto::VarInt::size` (`noq-proto-1.3.0/src/varint.rs`). The two-bit
/// length lives in the top of the first byte, so the value is `1 << len` bits
/// narrower than the field it is stored in.
fn varIntLen(value: u64) usize {
    if (value < 1 << 6) return 1;
    if (value < 1 << 14) return 2;
    if (value < 1 << 30) return 4;
    return 8;
}

/// Reads a QUIC varint from `bytes[*offset..]`, leaving the offset after it.
///
/// `noq_proto::VarInt::decode` (`noq-proto-1.3.0/src/varint.rs`), loop for loop.
/// One rejection, and it is upstream's `UnexpectedEnd` at `relay.rs:105`: a first
/// byte naming a two-, four- or eight-byte varint with fewer bytes behind it.
/// There is no second rejection because a QUIC varint is self-describing — every
/// one of the 2^62 values has exactly one encoding, and unlike postcard there is
/// no over-long spelling to reject.
fn readVarInt(bytes: []const u8, offset: *usize) Error!u64 {
    const rest = bytes[offset.*..];
    if (rest.len == 0) return error.UnexpectedEnd;
    const length: usize = @as(usize, 1) << @intCast(rest[0] >> 6);
    if (rest.len < length) return error.UnexpectedEnd;
    var value: u64 = rest[0] & 0b0011_1111;
    for (rest[1..length]) |byte| value = (value << 8) | byte;
    offset.* += length;
    return value;
}

/// postcard's `varint(usize)`, which is a `varint(u64)` on a target that can hold
/// a length at all.
fn postcardVarIntLen(length: usize) usize {
    var rest: u64 = @intCast(length);
    var count: usize = 1;
    while (rest >= 0x80) {
        rest >>= 7;
        count += 1;
    }
    return count;
}

/// Appends frame bytes to a caller-owned buffer.
///
/// The same shape as `wire/postcard.zig`'s writer and for the same reason: it
/// grows nothing, so encoding into a buffer too small is `error.BufferFull` rather
/// than a resize the caller never agreed to. The widths are big-endian raw bytes
/// because this format's widths are big-endian raw bytes, and postcard's
/// `writeU16` would varint them into something a peer cannot read.
const Writer = struct {
    buffer: []u8,
    length: usize,

    fn init(buffer: []u8) Writer {
        return .{ .buffer = buffer, .length = 0 };
    }

    /// The part of the buffer not yet written, for a caller that has to hand it to
    /// another codec.
    fn rest(self: Writer) []u8 {
        return self.buffer[self.length..];
    }

    fn advance(self: *Writer, count: usize) void {
        self.length += count;
    }

    fn finish(self: Writer) []const u8 {
        return self.buffer[0..self.length];
    }

    fn write(self: *Writer, bytes: []const u8) Error!void {
        const free = self.rest();
        if (free.len < bytes.len) return error.BufferFull;
        @memcpy(free[0..bytes.len], bytes);
        self.length += bytes.len;
    }

    fn writeU8(self: *Writer, value: u8) Error!void {
        return self.write(&.{value});
    }

    fn writeU16Be(self: *Writer, value: u16) Error!void {
        var bytes: [2]u8 = undefined;
        std.mem.writeInt(u16, &bytes, value, .big);
        return self.write(&bytes);
    }

    fn writeU32Be(self: *Writer, value: u32) Error!void {
        var bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &bytes, value, .big);
        return self.write(&bytes);
    }

    /// `noq_proto::VarInt::encode` (`noq-proto-1.3.0/src/varint.rs`).
    fn writeVarInt(self: *Writer, value: u64) Error!void {
        const length = varIntLen(value);
        if (length == 1) return self.writeU8(@intCast(value));
        if (length == 2) return self.writeU16Be(0b01 << 14 | @as(u16, @intCast(value)));
        if (length == 4) return self.writeU32Be(0b10 << 30 | @as(u32, @intCast(value)));
        return self.writeU64Be(0b11 << 62 | value);
    }

    fn writeU64Be(self: *Writer, value: u64) Error!void {
        var bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &bytes, value, .big);
        return self.write(&bytes);
    }
};

// --- tests

/// The node id every captured vector carries.
///
/// Both snapshot tests build their frames from `SecretKey::from_bytes(&[42u8;
/// 32])` (`relay.rs:610` and `relay.rs:702`), and an ed25519 secret key is a
/// seed, so this is the same derivation. "golden: the captured node id is seed
/// [42]" is what holds that claim to the bytes.
fn captureKey() !key.SecretKey {
    return key.SecretKey.fromSeed([_]u8{42} ** key.SecretKey.seed_length);
}

fn captureId() !NodeId {
    var secret = try captureKey();
    defer secret.deinit();
    return secret.nodeId();
}

/// The contents of every captured datagram frame, and twelve bytes: two datagrams
/// at the six-byte segment size upstream chose.
const hello_world = "Hello World!";

/// The node id as upstream's hexdumps spell it, in two halves because 64 hex
/// digits do not fit on one line under a hundred columns.
const id_hex = "197f6b23e16c8532c6abc838" ++ "facd5ea789be0c76b2920334039bfa8b3d368d61";

/// 32 bytes of `ff`: a compressed ed25519 point whose `y` is `2^255 - 1`, past
/// the field modulus, so `NodeId.fromBytes` rejects it.
const non_canonical_id_hex = "ff" ** 32;

/// Covers the captured hexdumps and the largest authentication frame tested here:
/// ClientAuth is 97 bytes; ServerDeniesAuth.max_frame_length is 258.
const scratch_len = 512;

/// Every hexdump below is copied out of `iroh-relay/src/protos/relay.rs` at commit
/// 187f59e8, out of the two snapshot tests in its `mod tests`:
/// `test_relay_client_frames_snapshot` at `relay.rs:612` for the frames the relay
/// sends and `test_client_relay_frames_snapshot` at `relay.rs:704` for the
/// frames a client sends. Upstream strips the whitespace out of its own hexdumps
/// before decoding them (`relay.rs:592`), so the spacing here is ours and the
/// bytes are theirs.
const captured = [_]struct {
    /// The frame type this hexdump is a frame of.
    frame_type: FrameType,
    /// The only version this frame may be sent in.
    version: ProtocolVersion,
    /// Where upstream wrote it.
    source: []const u8,
    hex: []const u8,
}{
    // RelayToClientMsg::Health { problem: "Hello? Yes this is dog." }
    .{
        .frame_type = .health,
        .version = .v1,
        .source = "relay.rs:614",
        .hex = "0b 48656c6c6f3f20596573207468697320697320646f672e",
    },
    // RelayToClientMsg::EndpointGone(client_key.public())
    .{
        .frame_type = .endpoint_gone,
        .version = .v2,
        .source = "relay.rs:622",
        .hex = "08 " ++ id_hex,
    },
    // RelayToClientMsg::Ping([42u8; 8])
    .{
        .frame_type = .ping,
        .version = .v2,
        .source = "relay.rs:628",
        .hex = "09 2a2a2a2a2a2a2a2a",
    },
    // RelayToClientMsg::Pong([42u8; 8])
    .{
        .frame_type = .pong,
        .version = .v2,
        .source = "relay.rs:632",
        .hex = "0a 2a2a2a2a2a2a2a2a",
    },
    // RelayToClientMsg::Datagrams { segment_size: NonZeroU16::new(6) }
    .{
        .frame_type = .relay_to_client_datagram_batch,
        .version = .v2,
        .source = "relay.rs:636",
        .hex = "07 " ++ id_hex ++ " 03 0006 48656c6c6f20576f726c6421",
    },
    // RelayToClientMsg::Datagrams { segment_size: None }
    .{
        .frame_type = .relay_to_client_datagram,
        .version = .v2,
        .source = "relay.rs:658",
        .hex = "06 " ++ id_hex ++ " 03 48656c6c6f20576f726c6421",
    },
    // RelayToClientMsg::Restarting { 10ms, 20ms }
    .{
        .frame_type = .restarting,
        .version = .v2,
        .source = "relay.rs:679",
        .hex = "0c 0000000a 00000014",
    },
    // RelayToClientMsg::Status(Status::SameEndpointIdConnected)
    .{
        .frame_type = .status,
        .version = .v2,
        .source = "relay.rs:687",
        .hex = "0d 01",
    },
    // RelayToClientMsg::Status(Status::RateLimited)
    .{
        .frame_type = .status,
        .version = .v2,
        .source = "relay.rs:691",
        .hex = "0d 02",
    },
    // ClientToRelayMsg::Datagrams { segment_size: NonZeroU16::new(6) }
    .{
        .frame_type = .client_to_relay_datagram_batch,
        .version = .v2,
        .source = "relay.rs:714",
        .hex = "05 " ++ id_hex ++ " 03 0006 48656c6c6f20576f726c6421",
    },
    // ClientToRelayMsg::Datagrams { segment_size: None }
    .{
        .frame_type = .client_to_relay_datagram,
        .version = .v2,
        .source = "relay.rs:737",
        .hex = "04 " ++ id_hex ++ " 03 48656c6c6f20576f726c6421",
    },
};

test "golden: the captured node id is seed [42]" {
    const node_id = try captureId();
    try std_testing.expectEqualStrings(id_hex, &std.fmt.bytesToHex(&node_id.toBytes(), .lower));
}

test "golden: relay frame wire format, iroh-relay relay.rs" {
    var scratch: [scratch_len]u8 = undefined;
    var out: [scratch_len]u8 = undefined;
    for (captured) |vector| {
        const bytes = try parseHex(&scratch, vector.hex);
        const decoded = try decode(bytes, vector.version);
        const frame_type: FrameType = std.meta.activeTag(decoded);
        try std_testing.expectEqual(vector.frame_type, frame_type);

        // The captured bytes are the canonical spelling, so what came out goes
        // back in as what went in. That is the comparison a peer makes.
        const written = try encode(decoded, vector.version, &out);
        try expectHex(bytes, written);
        try std_testing.expectEqual(encodedLen(decoded), written.len);
    }
}

test "golden: the segment size is the whole difference between the pairs" {
    // Upstream's two datagram hexdumps in each direction differ by exactly the
    // frame type byte and the two segment-size bytes. Asserting the pairs against
    // each other is what says what the invariant is for: the type follows the
    // field, and the field is one optional `u16`.
    const node_id = try captureId();
    // Two buffers, because `decode` borrows the caller's bytes: parsing the
    // single frame into the same buffer would move the batch's contents under
    // the first decode's feet. `docs/ARCHITECTURE.md` rule 6 is about that.
    var batch_scratch: [scratch_len]u8 = undefined;
    var single_scratch: [scratch_len]u8 = undefined;
    var out: [scratch_len]u8 = undefined;
    const pairs = [_]struct { batch: []const u8, single: []const u8 }{
        .{
            .batch = "07 " ++ id_hex ++ " 03 0006 48656c6c6f20576f726c6421",
            .single = "06 " ++ id_hex ++ " 03 48656c6c6f20576f726c6421",
        },
        .{
            .batch = "05 " ++ id_hex ++ " 03 0006 48656c6c6f20576f726c6421",
            .single = "04 " ++ id_hex ++ " 03 48656c6c6f20576f726c6421",
        },
    };

    for (pairs) |pair| {
        const batch = try decode(try parseHex(&batch_scratch, pair.batch), .v2);
        const single = try decode(try parseHex(&single_scratch, pair.single), .v2);
        const batch_type: FrameType = std.meta.activeTag(batch);
        const single_type: FrameType = std.meta.activeTag(single);

        try std_testing.expect(FrameType.isDatagramBatch(batch_type));
        try std_testing.expect(!FrameType.isDatagramBatch(single_type));
        try std_testing.expectEqual(@as(?u16, 6), (try datagramsOf(batch)).segment_size);
        try std_testing.expectEqual(@as(?u16, null), (try datagramsOf(single)).segment_size);

        // Same id, same ECN, same contents, and the batch frame is two bytes
        // longer for the segment size and nothing else.
        try std_testing.expectEqual(node_id, try nodeOf(batch));
        try std_testing.expectEqual(@as(?Ecn, .ce), (try datagramsOf(batch)).ecn);
        try std_testing.expectEqual(@as(?Ecn, .ce), (try datagramsOf(single)).ecn);
        try std_testing.expectEqualStrings(hello_world, (try datagramsOf(batch)).contents);
        try std_testing.expectEqualStrings(hello_world, (try datagramsOf(single)).contents);
        const single_wire = try encode(single, .v2, &out);
        const batch_wire = try encode(batch, .v2, &out);
        try std_testing.expectEqual(single_wire.len + 2, batch_wire.len);
    }
}

test "golden: a captured batch is two datagrams of six bytes" {
    // relay.rs:636, and upstream's own reason for choosing six: "Hello World!" is
    // twelve bytes.
    var scratch: [scratch_len]u8 = undefined;
    const decoded = try decode(
        try parseHex(&scratch, "07 " ++ id_hex ++ " 03 0006 48656c6c6f20576f726c6421"),
        .v2,
    );
    const datagrams = try datagramsOf(decoded);
    try std_testing.expectEqual(@as(usize, 12), datagrams.contents.len);
    try std_testing.expectEqual(@as(usize, 2), datagramsIn(datagrams.contents, 6));
    try std_testing.expectEqual(
        @as(usize, 2),
        datagramsIn(datagrams.contents, datagrams.segment_size.?),
    );
}

test "golden: a captured restarting frame is two big-endian millisecond counts" {
    // relay.rs:679, written as `put_u32(reconnect_in.as_millis() as u32)`.
    var scratch: [16]u8 = undefined;
    var out: [scratch_len]u8 = undefined;
    const bytes = try parseHex(&scratch, "0c 0000000a 00000014");
    const decoded = try decode(bytes, .v2);
    try std_testing.expectEqual(
        Restarting{ .reconnect_in_ms = 10, .try_for_ms = 20 },
        decoded.restarting,
    );
    try expectHex(bytes, try encode(decoded, .v2, &out));
}

test "golden: a captured status frame is one byte" {
    for ([_]u8{ 1, 2 }) |bits| {
        const frame = [_]u8{ 0x0d, bits };
        const decoded = try decode(&frame, .v2);
        try std_testing.expectEqual(@as(FrameType, .status), std.meta.activeTag(decoded));
        try std_testing.expectEqual(bits, decoded.status.toBits());
        var out: [4]u8 = undefined;
        try expectHex(&frame, try encode(decoded, .v2, &out));
    }
}

test "golden: a captured health frame is its text" {
    // relay.rs:614. v1 only, so this is also the first half of the version test.
    var scratch: [64]u8 = undefined;
    var out: [64]u8 = undefined;
    const bytes = try parseHex(
        &scratch,
        "0b 48656c6c6f3f20596573207468697320697320646f672e",
    );
    const problem = try decode(bytes, .v1);
    try std_testing.expectEqual(@as(FrameType, .health), std.meta.activeTag(problem));
    try std_testing.expectEqualStrings("Hello? Yes this is dog.", problem.health);
    try expectHex(bytes, try encode(problem, .v1, &out));
}

test "golden: a captured ping and pong are the same eight bytes" {
    // relay.rs:628 and relay.rs:632: one payload, two frame types.
    var scratch: [16]u8 = undefined;
    var out: [16]u8 = undefined;
    const pairs = [_]struct { hex: []const u8, tag: FrameType }{
        .{ .hex = "09 2a2a2a2a2a2a2a2a", .tag = .ping },
        .{ .hex = "0a 2a2a2a2a2a2a2a2a", .tag = .pong },
    };
    for (pairs) |pair| {
        const bytes = try parseHex(&scratch, pair.hex);
        const message = try decode(bytes, .v2);
        try std_testing.expectEqual(pair.tag, std.meta.activeTag(message));
        try std_testing.expectEqual(@as([8]u8, [_]u8{42} ** 8), try payloadOf8(message));
        try expectHex(bytes, try encode(message, .v2, &out));
    }
}

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

test "version: Health is v1 only, Status is v2 only, both are emittable" {
    const health: Message = .{ .health = "the relay is full" };
    const status: Message = .{ .status = .rate_limited };
    var out: [scratch_len]u8 = undefined;

    try std_testing.expect(FrameType.health.allowedIn(.v1));
    try std_testing.expect(!FrameType.health.allowedIn(.v2));
    try std_testing.expect(FrameType.status.allowedIn(.v2));
    try std_testing.expect(!FrameType.status.allowedIn(.v1));
    // Every other type is in both, which is what makes "both versions must be
    // emittable" true for the twelve of thirteen that did not change.
    const shared = [_]FrameType{
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
        .restarting,
    };
    for (shared) |frame_type| {
        try std_testing.expect(frame_type.allowedIn(.v1));
        try std_testing.expect(frame_type.allowedIn(.v2));
    }

    // Both reach a decoder, and each is refused by the version that removed it.
    // Two output buffers, because a frame borrows the one it was written into and
    // `status_bytes` would otherwise be written over `health_bytes`.
    var v1_out: [scratch_len]u8 = undefined;
    var v2_out: [scratch_len]u8 = undefined;
    const health_bytes = try encode(health, .v1, &v1_out);
    try std_testing.expectEqual(
        @as(FrameType, .health),
        std.meta.activeTag(try decode(health_bytes, .v1)),
    );
    const status_bytes = try encode(status, .v2, &v2_out);
    try std_testing.expectEqual(
        @as(FrameType, .status),
        std.meta.activeTag(try decode(status_bytes, .v2)),
    );
    try std_testing.expectError(error.FrameNotAllowedInVersion, encode(health, .v2, &v2_out));
    try std_testing.expectError(error.FrameNotAllowedInVersion, encode(status, .v1, &v1_out));
    try std_testing.expectError(error.FrameNotAllowedInVersion, decode(health_bytes, .v2));
    try std_testing.expectError(error.FrameNotAllowedInVersion, decode(status_bytes, .v1));

    // And the decoder refuses before it looks at the payload: a `Health` frame
    // with no payload at all and a `Status` frame with none give the same answer
    // as well-formed ones, so the version rule is not the length rule.
    var header: [1]u8 = undefined;
    var header_writer = Writer.init(&header);
    try header_writer.writeVarInt(@intFromEnum(FrameType.health));
    try std_testing.expectError(error.FrameNotAllowedInVersion, decode(&header, .v2));
    try std_testing.expectError(
        error.FrameNotAllowedInVersion,
        decode(try parseHex(&out, "0d"), .v1),
    );
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

test "batch invariant: a segment size is there if and only if the type is a batch" {
    const node_id = try captureId();
    var out: [scratch_len]u8 = undefined;

    for ([_]Direction{ .client_to_relay, .relay_to_client }) |direction| {
        for ([_]?u16{ null, 1, 6, 1200, 65535 }) |segment_size| {
            const datagrams: Datagrams = .{
                .ecn = .ce,
                .segment_size = segment_size,
                .contents = hello_world,
            };
            const frame: DatagramFrame = .{ .node_id = node_id, .datagrams = datagrams };
            const tag = datagrams.frameType(direction);

            // The two halves of rule 7 as one fact about a frame that is about to
            // go on the wire.
            try std_testing.expectEqual(datagrams.isBatch(), FrameType.isDatagramBatch(tag));

            const bytes = try encode(try datagramMessage(tag, frame), .v2, &out);
            const decoded = try decode(bytes, .v2);
            try std_testing.expectEqual(tag, std.meta.activeTag(decoded));

            // And the half a decoder is trusted for: the payload agrees with the
            // type it arrived under, in both directions, every time.
            const back = try datagramsOf(decoded);
            try std_testing.expectEqual(back.isBatch(), FrameType.isDatagramBatch(tag));
            try std_testing.expectEqual(segment_size, back.segment_size);
            try std_testing.expectEqual(node_id, try nodeOf(decoded));
        }
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
    try std_testing.expectEqual(@as(usize, 3), datagramsIn(first.contents, 4));
    try std_testing.expectEqualStrings("mnop", batch.contents);
    try std_testing.expectEqual(@as(?u16, null), batch.segment_size);
    try std_testing.expect(!batch.isBatch());
    try std_testing.expectEqual(@as(usize, 1), datagramsIn(batch.contents, 4));

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
    var single: Datagrams = .{ .ecn = .ce, .segment_size = null, .contents = hello_world };
    const taken = single.takeSegments(8);
    try std_testing.expectEqual(@as(?u16, null), taken.segment_size);
    try std_testing.expectEqualStrings(hello_world, taken.contents);
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
    try std_testing.expectEqual(@as(usize, 1), datagramsIn(drained.contents, 1024));
}

test "codec: frames 0 through 3, derived from the handshake structs" {
    // Upstream writes no hexdump for the handshake frames, so there is no captured
    // vector to copy and this test does not claim one. The bytes follow from the
    // struct definitions and postcard's fixed-array rule, and the lines cited are
    // the definitions themselves.
    var secret = try captureKey();
    defer secret.deinit();
    const node_id = secret.nodeId();
    const signature = secret.sign("a message no peer has sent");
    var out: [scratch_len]u8 = undefined;

    // `ServerChallenge` (`handshake.rs:77`) is a `[u8; 16]`, and postcard writes a
    // fixed array inline with no length prefix, so a challenge is its header and
    // sixteen bytes.
    const challenge: ServerChallenge = .{ .challenge = [_]u8{0x01} ** 16 };
    const challenge_bytes = try encode(.{ .server_challenge = challenge }, .v2, &out);
    try std_testing.expectEqual(@as(usize, 17), challenge_bytes.len);
    try std_testing.expectEqual(@as(u8, 0), challenge_bytes[0]);
    try std_testing.expectEqualSlices(u8, &challenge.challenge, challenge_bytes[1..17]);
    try std_testing.expectEqual(challenge, (try decode(challenge_bytes, .v2)).server_challenge);
    try std_testing.expectError(error.InvalidFrame, decode(challenge_bytes[0..16], .v2));

    // `ClientAuth` (`handshake.rs:88`) is a 32-byte key and a 64-byte signature,
    // both fixed arrays, both inline: 96 bytes and a header.
    const auth: ClientAuth = .{ .node_id = node_id, .signature = signature };
    const auth_bytes = try encode(.{ .client_auth = auth }, .v2, &out);
    try std_testing.expectEqual(@as(usize, 97), auth_bytes.len);
    try std_testing.expectEqualSlices(u8, &node_id.toBytes(), auth_bytes[1..33]);
    try std_testing.expectEqualSlices(u8, &signature.toBytes(), auth_bytes[33..97]);
    try std_testing.expectEqual(auth, (try decode(auth_bytes, .v2)).client_auth);
    try std_testing.expectError(error.InvalidFrame, decode(auth_bytes[0..96], .v2));
    // One byte too long is still not the frame the type names: the width is the
    // type's own, in both directions.
    var over: [scratch_len]u8 = undefined;
    @memcpy(over[0..auth_bytes.len], auth_bytes);
    over[auth_bytes.len] = 0;
    try std_testing.expectError(
        error.InvalidFrame,
        decode(over[0 .. auth_bytes.len + 1], .v2),
    );

    // `ServerConfirmsAuth` (`handshake.rs:101`) is a unit struct, so the type is
    // the whole frame.
    const confirms = try encode(.{ .server_confirms_auth = {} }, .v2, &out);
    try expectHex(&.{0x02}, confirms);
    try std_testing.expectError(error.InvalidFrame, decode(try parseHex(&out, "02 00"), .v2));

    // `ServerDeniesAuth` (`handshake.rs:105`) is a `String`, so a varint length
    // and then UTF-8. Two bytes of reason is one length byte; two hundred is two,
    // which is the one case where a reader and a writer disagree about width.
    for ([_][]const u8{ "no", "x" ** 200 }) |reason| {
        const message: Message = .{ .server_denies_auth = .{ .reason = reason } };
        const denial = try encode(message, .v2, &out);
        try std_testing.expectEqual(@as(u8, 0x03), denial[0]);
        try std_testing.expectEqual(denial.len, encodedLen(message));
        var reader = postcard.Reader.init(denial[1..]);
        try std_testing.expectEqualStrings(reason, try reader.readStr());
        const decoded = try decode(denial, .v2);
        try std_testing.expectEqualStrings(reason, decoded.server_denies_auth.reason);
    }
}

test "codec: malformed frames are named errors" {
    var scratch: [scratch_len]u8 = undefined;
    var out: [scratch_len]u8 = undefined;

    // No bytes at all: no header, so no frame type.
    try std_testing.expectError(error.UnexpectedEnd, decode("", .v2));

    // A header naming a two-, four- or eight-byte varint with fewer bytes behind
    // it. This is upstream's `UnexpectedEnd` at `relay.rs:105`.
    for ([_][]const u8{ "40", "c0 00", "80 00 00" }) |hex| {
        try std_testing.expectError(
            error.UnexpectedEnd,
            decode(try parseHex(&scratch, hex), .v2),
        );
    }

    // A well-formed header naming a type this build has no arm for. `0e` is 14,
    // one past the table; `3f` is 63, the largest value a one-byte QUIC varint
    // can hold; `40 0e` is 14 in the two-byte form; the last is 14 in the
    // eight-byte form.
    const unknown = [_][]const u8{
        "0e 00",
        "3f",
        "40 0e",
        "c0 00 00 00 00 00 00 0e",
    };
    for (unknown) |hex| {
        try std_testing.expectError(
            error.UnknownFrameType,
            decode(try parseHex(&scratch, hex), .v2),
        );
    }

    // A type spelled in four bytes when one would do. The value is a real frame
    // type, so this is a valid header with an empty payload and the type's own
    // length rule rejects it. It is the case QUIC and postcard disagree on, and a
    // postcard reader would have called the whole four bytes a number far outside
    // 0 through 13.
    try std_testing.expectError(
        error.InvalidFrame,
        decode(try parseHex(&scratch, "80 00 00 09"), .v2),
    );

    // A ping or pong whose payload is not eight bytes, in both directions of
    // wrong.
    const short_payloads = [_][]const u8{
        "09",
        "09 2a2a2a2a2a2a2a2a2a",
        "0a 00",
        "0a 2a2a2a2a2a2a2a2a2a",
    };
    for (short_payloads) |hex| {
        try std_testing.expectError(
            error.InvalidFrame,
            decode(try parseHex(&scratch, hex), .v2),
        );
    }

    // A datagram frame with no room for a node id and a half. This is the
    // regression upstream wrote `regression_client_to_relay_undersized_datagram_rejected`
    // (`relay.rs:766`) for: a frame that is nothing but its type used to panic
    // while it sliced the id out.
    for ([_]FrameType{ .client_to_relay_datagram, .client_to_relay_datagram_batch }) |frame_type| {
        var header: [1]u8 = undefined;
        var header_writer = Writer.init(&header);
        try header_writer.writeVarInt(@intFromEnum(frame_type));
        try std_testing.expectError(error.InvalidFrame, decode(&header, .v2));
        var short: [DatagramFrame.header_length]u8 = undefined;
        @memset(&short, 0);
        short[0] = header[0];
        try std_testing.expectError(error.InvalidFrame, decode(&short, .v2));
    }

    // 32 bytes that are not a canonical ed25519 point. Upstream's
    // `InvalidPublicKey` (`relay.rs:411`), and a different rule from "too short",
    // so a different error. The datagram frame carries an ECN byte after the id,
    // so that its payload is long enough to reach the key at all.
    const bad_ids = [_][]const u8{
        "06 " ++ non_canonical_id_hex ++ " 03",
        "08 " ++ non_canonical_id_hex,
    };
    for (bad_ids) |hex| {
        try std_testing.expectError(
            error.InvalidNodeId,
            decode(try parseHex(&scratch, hex), .v2),
        );
    }

    // A batch frame with an ECN byte but not the two bytes of segment size after
    // it, which is upstream's `ensure!(bytes.len() >= 3)` at `relay.rs:283`.
    try std_testing.expectError(
        error.InvalidFrame,
        decode(try parseHex(&scratch, "07 " ++ id_hex ++ " 03 00"), .v2),
    );

    // A batch frame whose segment size is zero. Upstream drops the `NonZeroU16`
    // and hands back a `Datagrams` with no segment size out of a batch frame; rule
    // 7 says the two halves of the invariant are one fact, so the frame is refused
    // instead, on the way in and on the way out.
    try std_testing.expectError(
        error.ZeroSegmentSize,
        decode(try parseHex(&scratch, "07 " ++ id_hex ++ " 03 0000 00"), .v2),
    );
    try std_testing.expectError(
        error.ZeroSegmentSize,
        encode(.{ .relay_to_client_datagram_batch = .{
            .node_id = try captureId(),
            .datagrams = .{ .ecn = null, .segment_size = 0, .contents = hello_world },
        } }, .v2, &out),
    );

    // An endpoint-gone frame that is not exactly 32 bytes. Upstream is exact here
    // (`relay.rs:423`) where it is a lower bound for a datagram frame.
    try std_testing.expectError(
        error.InvalidFrame,
        decode(try parseHex(&scratch, "08 " ++ id_hex ++ " ff"), .v2),
    );

    // A status frame with anything other than one byte. Upstream reads the first
    // byte and ignores the rest, which lets two different messages share one
    // encoding; the length is the type's own.
    for ([_][]const u8{ "0d", "0d 01 ff", "0d 0000" }) |hex| {
        try std_testing.expectError(
            error.InvalidFrame,
            decode(try parseHex(&scratch, hex), .v2),
        );
    }

    // A restarting frame that is not two u32s.
    for ([_][]const u8{ "0c 0000000a", "0c 0000000a 00000014 00" }) |hex| {
        try std_testing.expectError(
            error.InvalidFrame,
            decode(try parseHex(&scratch, hex), .v2),
        );
    }

    // A denial whose postcard length runs past the frame, one whose length
    // varint never stops, one whose length varint is wider than a `u64` can
    // carry, and one whose text is not UTF-8. Each is `postcard.Error`'s own name,
    // carried across unchanged.
    const denials = [_]struct { hex: []const u8, expected: Error }{
        .{ .hex = "03 7f", .expected = error.BadLength },
        .{ .hex = "03 80808080808080808080 00", .expected = error.BadVarint },
        .{ .hex = "03 ffffffffffffffffff 7f", .expected = error.ValueOutOfRange },
        .{ .hex = "03 01 ff", .expected = error.InvalidUtf8 },
        .{ .hex = "03 04 6e6f6d65 ff", .expected = error.InvalidFrame },
    };
    for (denials) |denial| {
        try std_testing.expectError(
            denial.expected,
            decode(try parseHex(&scratch, denial.hex), .v2),
        );
    }
}

test "codec: a payload over max_packet_size is refused" {
    const alloc = std_testing.allocator;
    const bytes = try alloc.alloc(u8, max_packet_size + 2);
    defer alloc.free(bytes);
    @memset(bytes, 0xff);
    bytes[0] = @intFromEnum(FrameType.ping);
    // The frame type is read, the payload is measured, and only then is it refused:
    // upstream takes the same order at `relay.rs:402`.
    try std_testing.expectError(error.FrameTooLarge, decode(bytes, .v2));
    // One byte less and the same frame is a ping whose payload is not eight bytes,
    // so the size rule really is what stopped it.
    try std_testing.expectError(
        error.InvalidFrame,
        decode(bytes[0 .. max_packet_size + 1], .v2),
    );
}

test "codec: encodedLen is the length, for every variant" {
    var secret = try captureKey();
    defer secret.deinit();
    const node_id = secret.nodeId();
    var other = try key.SecretKey.fromSeed([_]u8{7} ** key.SecretKey.seed_length);
    defer other.deinit();
    const batched: DatagramFrame = .{
        .node_id = node_id,
        .datagrams = .{ .ecn = .ce, .segment_size = 6, .contents = hello_world },
    };
    const single: DatagramFrame = .{
        .node_id = node_id,
        .datagrams = .{ .ecn = .ce, .segment_size = null, .contents = hello_world },
    };

    const messages = [_]Message{
        .{ .server_challenge = .{ .challenge = [_]u8{7} ** 16 } },
        .{ .client_auth = .{ .node_id = node_id, .signature = secret.sign("m") } },
        .{ .server_confirms_auth = {} },
        .{ .server_denies_auth = .{ .reason = "no" } },
        // At the bound rather than above it, and still the case this entry is
        // here for: a reason long enough to need a two-byte postcard length
        // prefix, which is the one width where a reader and a writer disagree.
        // `encode` refuses a longer one, so 300 is no longer a value this codec
        // can write — see `max_text_length`.
        .{ .server_denies_auth = .{ .reason = "x" ** ServerDeniesAuth.max_reason_length } },
        .{ .client_to_relay_datagram = single },
        .{ .client_to_relay_datagram_batch = batched },
        .{ .relay_to_client_datagram = single },
        .{ .relay_to_client_datagram_batch = batched },
        .{ .endpoint_gone = node_id },
        .{ .endpoint_gone = other.nodeId() },
        .{ .ping = [_]u8{42} ** 8 },
        .{ .pong = [_]u8{0} ** 8 },
        .{ .health = "" },
        .{ .health = "a problem long enough to be worth a frame of its own" },
        .{ .restarting = .{ .reconnect_in_ms = 0, .try_for_ms = 0 } },
        .{ .status = .healthy },
        .{ .status = .same_endpoint_id_connected },
        .{ .status = .rate_limited },
        .{ .status = .{ .unknown = 200 } },
    };
    var out: [scratch_len]u8 = undefined;
    for (messages) |message| {
        const version: ProtocolVersion = if (std.meta.activeTag(message) == .health) .v1 else .v2;
        const bytes = try encode(message, version, &out);
        try std_testing.expectEqual(encodedLen(message), bytes.len);
        try std_testing.expect(eql(message, try decode(bytes, version)));
    }
}

test "codec: a reason at the bound round-trips, and one byte over is refused" {
    // The bound is a value in the type, and this is the two sides of it: the
    // longest reason the codec will write goes out whole and comes back whole,
    // and the next byte up is a named refusal rather than a shorter sentence.
    const at_bound: Message = .{
        .server_denies_auth = .{ .reason = "x" ** ServerDeniesAuth.max_reason_length },
    };
    var out: [scratch_len]u8 = undefined;
    const written = try encode(at_bound, .v2, &out);
    try std_testing.expectEqual(encodedLen(at_bound), written.len);
    // The frame a caller must make room for is the reason at its bound plus the
    // type byte and the prefix, which is what `max_frame_length` says it is.
    try std_testing.expectEqual(ServerDeniesAuth.max_frame_length, written.len);
    try std_testing.expect(eql(at_bound, try decode(written, .v2)));

    // One byte over, and refused rather than cut: the reason that goes on the
    // wire is never a prefix of the reason the caller chose.
    const over: Message = .{
        .server_denies_auth = .{ .reason = "x" ** (ServerDeniesAuth.max_reason_length + 1) },
    };
    var refusal: [scratch_len]u8 = undefined;
    @memset(&refusal, 0xff);
    try std_testing.expectError(error.TextTooLong, encode(over, .v2, &refusal));
    // Nothing was written, so a caller cannot find a partial denial in its own
    // buffer and mistake it for one.
    for (refusal) |byte| try std_testing.expectEqual(@as(u8, 0xff), byte);
    // And the refusal is the bound, not the buffer: a roomy buffer does not turn
    // an over-long reason back into an encodable one.
    var roomy: [ServerDeniesAuth.max_frame_length]u8 = undefined;
    try std_testing.expectError(error.TextTooLong, encode(over, .v2, &roomy));
}

test "codec: the health problem is bounded by the same number as the reason" {
    // v1's answer to the same question the denial answers, and the same rule:
    // relay-authored text with no field fixing its length. Both are refused
    // past `max_text_length` and neither is shortened.
    const at_bound: Message = .{ .health = "x" ** max_text_length };
    var out: [scratch_len]u8 = undefined;
    const written = try encode(at_bound, .v1, &out);
    try std_testing.expectEqual(encodedLen(at_bound), written.len);
    try std_testing.expect(eql(at_bound, try decode(written, .v1)));

    const over: Message = .{ .health = "x" ** (max_text_length + 1) };
    var refusal: [scratch_len]u8 = undefined;
    @memset(&refusal, 0xff);
    try std_testing.expectError(error.TextTooLong, encode(over, .v1, &refusal));
    for (refusal) |byte| try std_testing.expectEqual(@as(u8, 0xff), byte);
}

test "codec: text that is not UTF-8 is refused, because decode refuses it too" {
    // The one frame this module can write and cannot read back. Upstream's reason
    // is a `String`, so the bytes cannot be anything but text; here they are
    // `[]const u8` and `encode` writes what it is handed, while `decode` hands the
    // same bytes to postcard, which validates them and answers
    // `error.InvalidUtf8`. A relay that emits one has put a frame on the wire that
    // its own decoder refuses and that a peer cannot read as a `String` either.
    //
    // So `encode` refuses it under the name `decode` already uses, and it refuses
    // it in the sweep, before the writer exists, so the buffer is untouched the
    // way an over-long reason leaves it. `0xff` is never a UTF-8 byte, which is
    // what makes this the smallest input that says it.
    const not_text = [_]u8{ 0xff, 'n', 'o', ' ' };

    var out: [scratch_len]u8 = undefined;
    @memset(&out, 0xff);
    try std_testing.expectError(
        error.InvalidUtf8,
        encode(.{ .server_denies_auth = .{ .reason = &not_text } }, .v2, &out),
    );
    for (out) |byte| try std_testing.expectEqual(@as(u8, 0xff), byte);

    // v1's answer to the same question, over the same bytes and under the same
    // rule: both arms are relay-authored text with no field fixing its length.
    var v1_out: [scratch_len]u8 = undefined;
    @memset(&v1_out, 0xff);
    try std_testing.expectError(
        error.InvalidUtf8,
        encode(.{ .health = &not_text }, .v1, &v1_out),
    );
    for (v1_out) |byte| try std_testing.expectEqual(@as(u8, 0xff), byte);
}

test "codec: a datagram over max_packet_size is refused on the way out too" {
    // All four datagram arms go through the same check, so both directions and
    // both the batch and single form are covered by one case. These contents are
    // a whole packet over before the header they are written behind.
    const alloc = std_testing.allocator;
    const payload = try alloc.alloc(u8, max_packet_size + 1);
    defer alloc.free(payload);
    @memset(payload, 0x5a);
    const node_id = try captureId();
    const messages = [_]Message{
        .{ .client_to_relay_datagram = .{
            .node_id = node_id,
            .datagrams = .{ .ecn = null, .segment_size = null, .contents = payload },
        } },
        .{ .relay_to_client_datagram = .{
            .node_id = node_id,
            .datagrams = .{ .ecn = null, .segment_size = null, .contents = payload },
        } },
        .{ .client_to_relay_datagram_batch = .{
            .node_id = node_id,
            .datagrams = .{ .ecn = null, .segment_size = 6, .contents = payload },
        } },
        .{ .relay_to_client_datagram_batch = .{
            .node_id = node_id,
            .datagrams = .{ .ecn = null, .segment_size = 6, .contents = payload },
        } },
    };
    var out: [scratch_len]u8 = undefined;
    for (messages) |message| {
        try std_testing.expectError(error.FrameTooLarge, encode(message, .v2, &out));
    }
}

test "codec: a datagram at the payload bound round-trips, and one byte over is refused" {
    // The bound is on the payload, which is every byte after the frame type: the
    // node id and the ECN byte all four of these types carry, plus the two bytes
    // of segment size on a batch, and not the contents alone. 65536 bytes of
    // payload is 65503 bytes of contents in a single-datagram frame and 65501 in
    // a batch one.
    const single_limit = max_packet_size - DatagramFrame.header_length;
    const batch_limit = single_limit - Datagrams.segment_size_length;

    const alloc = std_testing.allocator;
    const contents = try alloc.alloc(u8, max_packet_size);
    defer alloc.free(contents);
    @memset(contents, 0x5a);
    const node_id = try captureId();
    // Room for the frame at the bound and not one byte more, so `BufferFull`
    // cannot be the answer to the round trip, and a byte to spare, so the
    // refusal below is the bound and not the buffer.
    const out = try alloc.alloc(u8, max_packet_size + 1);
    defer alloc.free(out);
    const roomy = try alloc.alloc(u8, max_packet_size + 2);
    defer alloc.free(roomy);

    for ([_]FrameType{
        .client_to_relay_datagram,
        .relay_to_client_datagram,
        .client_to_relay_datagram_batch,
        .relay_to_client_datagram_batch,
    }) |frame_type| {
        const is_batch = FrameType.isDatagramBatch(frame_type);
        const segment_size: ?u16 = if (is_batch) 6 else null;
        const limit = if (is_batch) batch_limit else single_limit;

        // At the bound: the payload is `max_packet_size` and not a byte over, so
        // the datagram goes out whole and comes back whole.
        const at_bound = try datagramMessage(frame_type, .{
            .node_id = node_id,
            .datagrams = .{
                .ecn = null,
                .segment_size = segment_size,
                .contents = contents[0..limit],
            },
        });
        const written = try encode(at_bound, .v2, out);
        try std_testing.expectEqual(max_packet_size + 1, written.len);
        try std_testing.expectEqual(encodedLen(at_bound), written.len);
        try std_testing.expect(eql(at_bound, try decode(written, .v2)));

        // One byte over, and refused before the writer exists: the buffer comes
        // back holding what the caller put in it.
        const over = try datagramMessage(frame_type, .{
            .node_id = node_id,
            .datagrams = .{
                .ecn = null,
                .segment_size = segment_size,
                .contents = contents[0 .. limit + 1],
            },
        });
        @memset(out, 0xff);
        try std_testing.expectError(error.FrameTooLarge, encode(over, .v2, out));
        for (out) |byte| try std_testing.expectEqual(@as(u8, 0xff), byte);
        // And with a byte of room to spare it is still refused, which is what
        // says the frame is too large and not the buffer too small.
        try std_testing.expectError(error.FrameTooLarge, encode(over, .v2, roomy));
    }
}

test "codec: a writer with no room is BufferFull, never a resize" {
    const ping: Message = .{ .ping = [_]u8{42} ** 8 };
    // Nine bytes: the header and the payload, exactly.
    var exact: [9]u8 = undefined;
    const written = try encode(ping, .v2, &exact);
    try std_testing.expectEqual(@as(usize, 9), written.len);
    try std_testing.expectEqual(@as(usize, 9), encodedLen(ping));

    var short: [8]u8 = undefined;
    try std_testing.expectError(error.BufferFull, encode(ping, .v2, &short));
    // A denial whose text does not fit takes the same path, through the postcard
    // writer it borrows.
    try std_testing.expectError(
        error.BufferFull,
        encode(.{ .server_denies_auth = .{ .reason = "too long for here" } }, .v2, &short),
    );
    // And a datagram frame whose header is one byte short of the node id it needs.
    try std_testing.expectError(
        error.BufferFull,
        encode(.{ .relay_to_client_datagram = .{
            .node_id = try captureId(),
            .datagrams = .{ .ecn = null, .segment_size = null, .contents = hello_world },
        } }, .v2, &short),
    );
}

test "codec: a health frame may be empty, and an unknown status is kept" {
    // `Health` is the rest of the message, so an empty one is a frame with no
    // problem text, which upstream's `Health { problem: String }` allows.
    var out: [4]u8 = undefined;
    try expectHex(&.{0x0b}, try encode(.{ .health = "" }, .v1, &out));

    // A status discriminant this build has no name for is kept, not rejected:
    // upstream's `Unknown(u8)` arm (`relay.rs:142`) exists so a relay that grows
    // a fourth condition does not break a client that is only reading it.
    for ([_]u8{ 3, 4, 200, 255 }) |bits| {
        const frame = [_]u8{ 0x0d, bits };
        const decoded = try decode(&frame, .v2);
        try std_testing.expectEqual(Status{ .unknown = bits }, decoded.status);
        var out_again: [4]u8 = undefined;
        try expectHex(&frame, try encode(decoded, .v2, &out_again));
    }
}

test "codec: an ECN byte of four is no ECN, and the re-encode says so" {
    // Upstream masks with `0b11` (`shared.rs:193`), so 4 reads as none, and writes
    // none as 0. A byte of 4 is therefore not a fixed point, and the canonical
    // spelling of what it meant is what a re-encode produces. The second decode is
    // the one compared, for the same reason the postcard fuzz target takes its
    // fixed point from the second decode.
    var scratch: [64]u8 = undefined;
    var out: [64]u8 = undefined;
    var again_out: [64]u8 = undefined;
    const decoded = try decode(try parseHex(&scratch, "06 " ++ id_hex ++ " 04 ff"), .v2);
    try std_testing.expectEqual(@as(?Ecn, null), (try datagramsOf(decoded)).ecn);

    const canonical = try encode(decoded, .v2, &out);
    const ecn_at = 1 + NodeId.byte_length;
    try std_testing.expectEqual(@as(u8, 0x00), canonical[ecn_at]);
    const again = try decode(canonical, .v2);
    try std_testing.expectEqual(@as(?Ecn, null), (try datagramsOf(again)).ecn);
    try expectEqualStringsSlices(
        canonical[ecn_at + 1 ..],
        (try encode(again, .v2, &again_out))[ecn_at + 1 ..],
    );
}

test "varint: the QUIC rules, at every width" {
    // `noq-proto-1.3.0/src/varint.rs` is the reference for all four widths, and the
    // frame type table only ever uses the first, so the other three are pinned here
    // against the encoder and the decoder agreeing on them.
    var scratch: [8]u8 = undefined;
    var out: [16]u8 = undefined;
    const widths = [_]struct { value: u64, hex: []const u8 }{
        .{ .value = 0, .hex = "00" },
        .{ .value = 13, .hex = "0d" },
        .{ .value = 63, .hex = "3f" },
        .{ .value = 64, .hex = "40 40" },
        .{ .value = 16383, .hex = "7f ff" },
        .{ .value = 16384, .hex = "80 00 40 00" },
        .{ .value = 1073741823, .hex = "bf ff ff ff" },
        .{ .value = 1073741824, .hex = "c0 00 00 00 40 00 00 00" },
    };
    for (widths) |width| {
        const expected = try parseHex(&scratch, width.hex);
        try std_testing.expectEqual(expected.len, varIntLen(width.value));
        var writer = Writer.init(&out);
        try writer.writeVarInt(width.value);
        try expectHex(expected, writer.finish());
        var offset: usize = 0;
        try std_testing.expectEqual(width.value, try readVarInt(&out, &offset));
        try std_testing.expectEqual(expected.len, offset);
    }
}

fn expectEqualStringsSlices(a: []const u8, b: []const u8) !void {
    if (std.mem.eql(u8, a, b)) return;
    return error.WireFormatMismatch;
}

/// The datagram payload of whichever of the four datagram frames this is.
fn datagramsOf(message: Message) error{NotADatagramFrame}!Datagrams {
    return switch (std.meta.activeTag(message)) {
        .client_to_relay_datagram => message.client_to_relay_datagram.datagrams,
        .client_to_relay_datagram_batch => message.client_to_relay_datagram_batch.datagrams,
        .relay_to_client_datagram => message.relay_to_client_datagram.datagrams,
        .relay_to_client_datagram_batch => message.relay_to_client_datagram_batch.datagrams,
        else => error.NotADatagramFrame,
    };
}

/// The `Message` for a datagram frame under a frame type chosen at runtime.
/// `@unionInit` needs a comptime field name, and the invariant test chooses the
/// tag from the direction it is looping over.
fn datagramMessage(frame_type: FrameType, frame: DatagramFrame) error{UnknownFrameType}!Message {
    return switch (frame_type) {
        .client_to_relay_datagram => .{ .client_to_relay_datagram = frame },
        .client_to_relay_datagram_batch => .{ .client_to_relay_datagram_batch = frame },
        .relay_to_client_datagram => .{ .relay_to_client_datagram = frame },
        .relay_to_client_datagram_batch => .{ .relay_to_client_datagram_batch = frame },
        else => error.UnknownFrameType,
    };
}

/// The node id of whichever of the four datagram frames this is.
fn nodeOf(message: Message) error{NotADatagramFrame}!NodeId {
    return switch (std.meta.activeTag(message)) {
        .client_to_relay_datagram => message.client_to_relay_datagram.node_id,
        .client_to_relay_datagram_batch => message.client_to_relay_datagram_batch.node_id,
        .relay_to_client_datagram => message.relay_to_client_datagram.node_id,
        .relay_to_client_datagram_batch => message.relay_to_client_datagram_batch.node_id,
        else => error.NotADatagramFrame,
    };
}

fn payloadOf8(message: Message) error{NotAnEightBytePayload}![8]u8 {
    return switch (std.meta.activeTag(message)) {
        .ping => message.ping,
        .pong => message.pong,
        else => error.NotAnEightBytePayload,
    };
}

/// How many datagrams `contents` holds at a segment size, for the tests that need
/// the number upstream never puts on the wire. A QUIC socket derives it the same
/// way: everything but the last datagram is exactly one segment.
fn datagramsIn(contents: []const u8, segment_size: usize) usize {
    if (segment_size == 0 or contents.len == 0) return 0;
    return 1 + @divFloor(contents.len - 1, segment_size);
}

/// The bytes a hexdump above stands for, decoded into `out`. A hexdump needs no
/// allocator: every one of them lands in a scratch buffer the test already has.
fn parseHex(out: []u8, hex: []const u8) ![]const u8 {
    var clean: [256]u8 = undefined;
    var length: usize = 0;
    for (hex) |c| {
        if (std.ascii.isWhitespace(c)) continue;
        if (length == clean.len) return error.HexdumpTooLong;
        clean[length] = c;
        length += 1;
    }
    if (length % 2 != 0) return error.OddHexLength;
    return std.fmt.hexToBytes(out, clean[0..length]);
}

/// Long enough for every hexdump a failure prints, and a diagnostic rather than a
/// general formatter: the bytes it prints are the ones written down in this file.
const max_dumped_bytes = 80;

fn expectHex(expected: []const u8, actual: []const u8) !void {
    if (std.mem.eql(u8, expected, actual)) return;
    std.debug.print("expected {d} bytes: {s}\n     got {d} bytes: {s}\n", .{
        expected.len, &hexdump(expected),
        actual.len,   &hexdump(actual),
    });
    return error.WireFormatMismatch;
}

fn hexdump(bytes: []const u8) [2 * max_dumped_bytes]u8 {
    var out: [2 * max_dumped_bytes]u8 = undefined;
    const digits = "0123456789abcdef";
    const shown = @min(bytes.len, max_dumped_bytes);
    for (bytes[0..shown], 0..) |byte, index| {
        out[index * 2] = digits[byte >> 4];
        out[index * 2 + 1] = digits[byte & 15];
    }
    @memset(out[shown * 2 ..], ' ');
    return out;
}
