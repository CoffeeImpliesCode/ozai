//! The vocabulary of the RFC 6455 carrier: every way an upgrade or a frame is
//! refused, what each refusal is counted under, and the three buffer limits.
//!
//! This is the layer `node/node_relay_carrier.zig` re-exports, and it is split
//! for the reason `relay/http_upgrade_types.zig` is: the vocabulary is what a
//! caller writes against, and it is worth reading without the implementation
//! behind it. Nothing here decides anything — every function in this file is a
//! constant or a size — so a reader who only needs to know what a refusal is
//! called never has to read the frame assembly that names it.

const http_upgrade = @import("../relay/http_upgrade.zig");
const ws_frame = @import("../relay/ws_frame.zig");

const Version = http_upgrade.Version;

/// Room for the `101`, at its largest.
///
/// `http_upgrade.responseLen` is exact for every version and for the
/// no-sub-protocol case, so this is the RFC's own arithmetic rather than a
/// number chosen here: one buffer, sized before the request is read, that holds
/// the response whatever version the request settles on.
pub const response_room: usize = http_upgrade.responseLen(.v2);

/// The most bytes one upgrade request may occupy.
///
/// `http_upgrade.max_header_length` is the parse's own ceiling and is what a
/// request is refused against as `error.HeaderTooLong`, so this is the codec's
/// number and not a second bound that could disagree with it.
pub const request_room: usize = http_upgrade.max_header_length;

/// The most bytes one WebSocket frame occupies here, header and payload.
///
/// `ws_frame.encode` writes header-then-payload into one buffer, so a caller
/// that never wants `error.BufferFull` sizes one at
/// `encodedLen(max_frame_size, .server)`. **A relay frame is far narrower than
/// that** — `relay_frame.max_packet_size` is what the codec measures a message
/// against, and `node_relay_frame.relay_frame_room` is the node's arithmetic on
/// it — so this is the carrier's ceiling rather than the one a relay frame meets.
pub const frame_room: usize = ws_frame.encodedLen(ws_frame.max_frame_size, .server);

/// Every way an upgrade or a frame is refused.
///
/// **An error set rather than an enum with a success arm**, because a refusal
/// here is a failure and nothing else: there is no "upgraded" value a caller
/// could get wrong by ignoring, and a `try` at the call site cannot drop it. An
/// explicit set rather than `anyerror` is `AGENTS.md` §1, and one arm per way
/// it can fail keeps the refusals named rather than merged — they are facts
/// about different halves. A caller that reads only the success path cannot tell
/// a peer that never asked to upgrade from a message this relay could not write.
pub const Outcome = error{
    /// The bytes are not an upgrade request this relay serves: not a `GET`, not
    /// this relay's path, no `Upgrade: websocket`, no `Connection: Upgrade`, a
    /// `Sec-WebSocket-Version` that is not `13`, a `Sec-WebSocket-Key` that is
    /// not base64 of sixteen bytes, a repeated singleton, or a header block over
    /// `request_room`. The parse's own arm is logged before this counter moves,
    /// so the reason behind a shared counter is never only a number.
    NotAnUpgrade,
    /// The sub-protocol field named no version both ends speak, so there is
    /// nothing to answer. The relay closes rather than choosing, which is
    /// `frame_types.zig:1070-1074`'s rule.
    NoCommonVersion,
    /// The `101` did not fit `response_room`. Nothing was written: a response
    /// with a missing accept field is a handshake that fails at the peer and
    /// names nothing.
    NoRoom,
    /// This connection already settled on a version. The first one stands —
    /// `conn_version.zig:22-29`'s rule, and a re-negotiation would admit a frame
    /// already promised to be refused.
    AlreadyBound,
    /// A frame this connection's version does not define, on the way out or on
    /// the way in. `Binding.encode`/`decode` refuse it, and a caller must send
    /// something else rather than believe something was sent.
    FrameNotAllowed,
    /// A frame that would not fit the caller's buffer. **Refused, never
    /// truncated.**
    NoFrameRoom,
    /// Bytes that arrived whole and this relay will not decode. They are spent
    /// either way, so this is counted once and not on every pass after it.
    Undecodable,
    /// A `Status` this build has no name for, on a v1 connection whose only
    /// spelling is text. `version_translate.toMessage`'s own refusal, and the
    /// one case where the protocol has no honest answer at all.
    StatusUnnameable,
};

/// How many times each refusal stopped. One field per `Outcome` arm, and a field
/// rather than a table indexed by an enum value so a reader does not have to
/// count arms to find the number it is reading.
pub const Refused = struct {
    /// See `Outcome.NotAnUpgrade`.
    not_an_upgrade: u64 = 0,
    /// See `Outcome.NoCommonVersion`.
    no_common_version: u64 = 0,
    /// See `Outcome.NoRoom`.
    no_room: u64 = 0,
    /// See `Outcome.AlreadyBound`.
    already_bound: u64 = 0,
    /// See `Outcome.FrameNotAllowed`.
    frame_not_allowed: u64 = 0,
    /// See `Outcome.NoFrameRoom`.
    no_frame_room: u64 = 0,
    /// See `Outcome.Undecodable`.
    undecodable: u64 = 0,
    /// See `Outcome.StatusUnnameable`.
    status_unnameable: u64 = 0,
};
