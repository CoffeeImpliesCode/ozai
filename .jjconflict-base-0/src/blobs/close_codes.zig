//! The QUIC codes that end a stream, and nothing else.
//!
//! These are sent *next to* a stream and never inside it, which is the whole
//! reason a provider that cannot answer a `get` has nothing to put in the
//! payload: a code is a fact about the stream and not bytes in it. That is why
//! this is its own module rather than an arm of the framing — `framing.zig`
//! spells how a request's bytes are read, and a close code is not a request and
//! is not read from the bytes a request was in.
//!
//! It is here rather than in `framing.zig` for a second reason, which is
//! budget: the framing holds the two framings, the discriminant and the length
//! prefixes, and its own tests, and a namespace of three QUIC codes is not one
//! more thing it should carry.

const std = @import("std");

/// Every way a stream close code this build does not have comes back.
///
/// `Closed` itself names the codes a peer can send; this names the one answer
/// a decoder owes for a code outside them.
pub const Error = error{
    /// A `Closed` code this build has no arm for.
    UnknownClose,
};

/// The reasons a stream is closed or stopped, as one namespace of error codes.
///
/// Upstream's `Closed` at `src/protocol.rs:667`, `#[repr(u16)]`, and the reason
/// strings are its own at `src/protocol.rs:690`. These are QUIC codes, sent
/// next to the stream and never inside it — which is the whole reason a
/// provider that cannot answer a `get` has nothing to put in the payload. All
/// three are below 64, and a QUIC varint of that size is a single byte holding
/// the value (`toVarInt`).
pub const Closed = enum(u16) {
    /// The receive stream was dropped. Upstream keeps this as documentation of
    /// what happened to `0` and says it is not used explicitly.
    stream_dropped = 0,
    /// The provider is terminating, and every stream with it.
    provider_terminating = 1,
    /// The provider has the request. Only one request is allowed per stream, so
    /// more data after it is what this code is for.
    request_received = 2,

    /// The close reason as bytes, which upstream requires to be valid UTF-8.
    pub fn reason(self: Closed) []const u8 {
        return switch (self) {
            .stream_dropped => "stream dropped",
            .provider_terminating => "provider terminating",
            .request_received => "request received",
        };
    }

    /// The QUIC varint a STOP_STREAM carries for this reason.
    ///
    /// Upstream's `impl From<Closed> for VarInt` is `VarInt::from(self as
    /// u16)`, and every arm is below 64, so each is one byte. The
    /// compression is a QUIC varint's length prefix in its first two bits
    /// (`RFC 9000` section 16), where `00` means one byte and the low six bits
    /// are the value — which is why the value comes back unchanged.
    pub fn toVarInt(self: Closed) u64 {
        return @intFromEnum(self);
    }

    /// The reason a code names, or `error.UnknownClose` for a code this build
    /// has no arm for. A decoder that invented a default arm would report a
    /// close nobody sent.
    pub fn fromVarInt(code: u64) Error!Closed {
        if (code > std.math.maxInt(u16)) return error.UnknownClose;
        return std.enums.fromInt(Closed, @as(u16, @intCast(code))) orelse error.UnknownClose;
    }
};
