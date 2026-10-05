//! The relay frame: what travels inside one relay WebSocket message.
//!
//! This file is the facade every caller imports. It holds no logic of its own
//! and re-exports four siblings, which together are the whole codec:
//!
//! - `frame_types.zig` — the vocabulary: the frame type table, the payloads
//!   behind it, the protocol version and how a connection settles on one, and
//!   every way a frame may be refused.
//! - `frame_writer.zig` — the byte layer: the QUIC variable-length integer and
//!   a writer that appends into a buffer the caller owns and never grows.
//! - `frame_encode.zig` — the way out: `encodedLen`, `encode`, and the sweep
//!   that refuses a frame before a byte of it is written.
//! - `frame_decode.zig` — the way in: `decode` and the readers behind it.
//! - `frame_roundtrip.zig` — `eql`, and every suite that holds both directions
//!   to each other.
//!
//! # This frame is not postcard
//!
//! The header is a QUIC variable-length integer: `noq_proto::VarInt::encode`,
//! called from `common.rs:83`. It is not a postcard varint. The two agree for
//! every value a `FrameType` can take — 0 through 13 is below 64, and below 64 a
//! QUIC varint is one raw byte, exactly as a postcard varint is — so every byte
//! this module emits is the same byte under either reading, and every captured
//! vector behind `frame_roundtrip.zig` is satisfied by both. They part company on
//! the way in: `40 00` is a two-byte QUIC varint spelling 0 and a two-byte
//! postcard varint spelling 64, and `80 00` is a QUIC varint that declares eight
//! bytes against a postcard varint spelling 0. A decoder that took the postcard
//! spelling would read a peer that has not sent a frame type at all.
//!
//! postcard is used here for the one field upstream postcard-encodes, the denial
//! reason in frame 3, which `handshake.rs:561` hands to `postcard::to_io`.
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

const frame_types = @import("frame_types.zig");
const frame_encode = @import("frame_encode.zig");
const frame_decode = @import("frame_decode.zig");
const frame_roundtrip = @import("frame_roundtrip.zig");

// The frame vocabulary and the rules it is held to.

pub const Error = frame_types.Error;
pub const max_packet_size = frame_types.max_packet_size;
pub const max_frame_size = frame_types.max_frame_size;
pub const max_text_length = frame_types.max_text_length;
pub const ProtocolVersion = frame_types.ProtocolVersion;
pub const negotiate = frame_types.negotiate;
pub const Direction = frame_types.Direction;
pub const FrameType = frame_types.FrameType;
pub const Ecn = frame_types.Ecn;
pub const Datagrams = frame_types.Datagrams;
pub const Status = frame_types.Status;
pub const Restarting = frame_types.Restarting;
pub const ServerChallenge = frame_types.ServerChallenge;
pub const ClientAuth = frame_types.ClientAuth;
pub const ServerDeniesAuth = frame_types.ServerDeniesAuth;
pub const DatagramFrame = frame_types.DatagramFrame;
pub const Message = frame_types.Message;

// The codec itself.

pub const encodedLen = frame_encode.encodedLen;
pub const encode = frame_encode.encode;
pub const decode = frame_decode.decode;
pub const eql = frame_roundtrip.eql;