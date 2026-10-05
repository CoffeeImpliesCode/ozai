//! The vocabulary of an RFC 6455 opening handshake: the request this relay
//! accepts, the response it answers, and every way a request is refused.
//!
//! This file is the layer `relay/http_upgrade.zig` re-exports. The request parse
//! is `relay/http_request.zig`, the response build and the accept computation are
//! `relay/http_response.zig`, and the RFC's own worked example lives in
//! `relay/ws_frame_vectors.zig` next to the frames it shares a section with.
//!
//! # What is verified here and what is not
//!
//! The `Sec-WebSocket-Key`/`Sec-WebSocket-Accept` pair in RFC 6455 section 1.3
//! is a golden this tree can hold, and `relay/http_upgrade.zig` holds it. **No
//! captured bytes from an iroh relay's own `101` exist to pin against**, because
//! upstream answers the upgrade through a library that writes the response line.
//! So what these tests establish is conformance to RFC 6455 and to RFC 9110's
//! grammar; the interop claim is not made.
//!
//! # Case is folded where the RFC says it is and nowhere else
//!
//! Three places in a handshake have a case rule and the three are different:
//!
//! - **Field names are case-insensitive** (RFC 9110 section 5.1), so
//!   `Sec-WebSocket-Key` and `sec-websocket-key` are one field.
//! - **The `Upgrade` and `Connection` tokens are case-insensitive**
//!   (RFC 6455 section 4.2.1), so `Upgrade: WebSocket` satisfies the check.
//! - **The method, the request target and the HTTP version are case-sensitive**
//!   (RFC 9110 sections 9.1, 7.1 and 2.3), so `get /relay HTTP/1.1` is a
//!   different request and not a spelling of this one.
//!
//! Nothing here reads a clock, opens a socket, or reaches for a global, and
//! nothing allocates: a request borrows the buffer it was parsed from and a
//! response is written into one the caller owns.

/// Every way a relay upgrade request is refused.
///
/// **Each arm names the first rule the request breaks, in the order RFC 6455
/// section 4.2.1 and RFC 9110 section 5 give them**, so a request that breaks
/// two is answered by the earlier one and a caller never has to guess which
/// rule took precedence.
pub const Error = error{
    /// The header block ended before its blank line. RFC 6455 section 4.1 makes
    /// the blank line the end of the request, so a request without one is
    /// incomplete rather than malformed.
    UnexpectedEnd,
    /// The request line is not `METHOD SP target SP HTTP-version`.
    MalformedRequestLine,
    /// The method is not `GET`. RFC 6455 section 4.1: "The request MUST be a GET
    /// request".
    MethodNotGet,
    /// The request target is not this relay's upgrade path. RFC 6455 section
    /// 4.1 requires a request to some resource and does not name it; the path
    /// is this relay's and not the RFC's.
    PathNotFound,
    /// The HTTP version is not `HTTP/1.1`. RFC 6455 section 4.2.1 requires
    /// 1.1 or higher, and this build speaks one of them.
    BadHttpVersion,
    /// A header field line is not `name ":" value`, or its name is not a token.
    MalformedField,
    /// More than `max_fields` fields, which is a bound this relay puts on a
    /// request rather than one the RFC has.
    TooManyFields,
    /// One field line is longer than `max_field_length`.
    FieldTooLong,
    /// A whole header block longer than `max_header_length`.
    HeaderTooLong,
    /// A field this relay reads as a singleton appeared more than once. RFC 9110
    /// section 5.3 lets a field repeat and be combined, and a value that means
    /// one thing cannot.
    DuplicateField,
    /// No `Upgrade` field on any of its occurrences names `websocket`. RFC 6455
    /// section 4.2.1 step 2.
    UpgradeNotWebsocket,
    /// No `Connection` field on any of its occurrences names `Upgrade`. RFC 6455
    /// section 4.2.1 step 5.
    ConnectionNotUpgrade,
    /// The `Sec-WebSocket-Version` field is not `13`. RFC 6455 section 4.2.1
    /// step 6, and 13 is the only version this build speaks.
    BadWebSocketVersion,
    /// The `Sec-WebSocket-Key` field is not base64 of exactly sixteen bytes.
    /// RFC 6455 section 4.1: "a base64-encoded value that, when decoded, is 16
    /// bytes in length".
    BadWebSocketKey,
    /// The `Sec-WebSocket-Protocol` field names no version this build speaks.
    /// RFC 6455 section 4.2.1 step 9, answered through `relay/frame.zig`'s
    /// `negotiate` rather than by a scan of its own.
    NoSupportedProtocol,
};

/// The path this relay answers its upgrade on.
///
/// **This relay's choice and not the RFC's.** RFC 6455 section 4.1 leaves the
/// request target to the server, and upstream iroh answers on `/relay`; the
/// constant is here because a caller building a request and a caller checking
/// one must not spell it twice.
pub const relay_path = "/relay";

/// The HTTP version a request must name and a response must answer with.
pub const http_version = "HTTP/1.1";

/// The one WebSocket version RFC 6455 section 4.2.1 step 6 accepts and this
/// build speaks: 13.
pub const websocket_version_token = "13";

/// The length the `Sec-WebSocket-Key` field must decode to. RFC 6455 section 4.1.
pub const key_length = 16;

/// The length of a `Sec-WebSocket-Accept` value: base64 of a twenty-byte digest.
pub const accept_length = 28;

/// The constant RFC 6455 sections 1.3 and 4.2.2 step 5 concatenate with the
/// client's key before hashing it.
///
/// **It is not secret and not a credential.** It is printed in the RFC and in
/// every RFC 6455 implementation's source, and its whole job is to keep a cache
/// or proxy that saw one handshake from replaying the answer for another. It is
/// a comptime literal with static lifetime so nothing borrows or frees it.
pub const websocket_guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// The most bytes of header block this relay reads, the terminating blank line
/// included.
///
/// A bound this relay puts on a request because the parse walks it with a fixed
/// table and a loop that must have an upper bound; RFC 6455 names none.
pub const max_header_length = 8192;

/// The most header fields this relay reads into its table.
pub const max_fields = 32;

/// The most bytes of one `name ":" value` line.
pub const max_field_length = 1024;

/// One parsed upgrade request, and everything the relay needs to answer it.
///
/// **The key is copied out and the text is borrowed.** `key` is the sixteen
/// decoded bytes, a value the caller may keep after the request buffer is
/// reused, and `key_text` is the base64 field value itself, which the response
/// has to hash because RFC 6455 section 4.2.2 step 5 concatenates the *field
/// value* rather than what it decodes to. Both facts in one struct are why the
/// two fields cannot be one.
pub const Request = struct {
    /// The `Sec-WebSocket-Key` field value exactly as it arrived, borrowed from
    /// the buffer `relay/http_request.zig` parsed.
    key_text: []const u8,
    /// The sixteen bytes `key_text` decodes to.
    key: [key_length]u8,
    /// The version the `Sec-WebSocket-Protocol` field settles on, or null when
    /// the field is absent.
    ///
    /// **Absent is not "the oldest version" and not a failure.** RFC 6455
    /// section 4.2.1 step 9 makes the sub-protocol optional, and section 4.2.2
    /// step 10 says a server that names one when the client sent none makes the
    /// client fail the connection — so a request without the field is answered
    /// without the response field, which is exactly the request and response
    /// RFC 6455 section 1.3 prints. A field that is present and names no version
    /// this build speaks is a different thing and is `error.NoSupportedProtocol`.
    version: ?Version,
    /// How many bytes of the buffer the header block occupied, its terminating
    /// blank line included, so a caller knows what a parse consumed.
    header_length: usize,
};

/// The relay protocol version, named here so `relay/http_upgrade.zig` does not
/// have to reach into `relay/frame.zig` for the type of one field.
pub const Version = @import("frame_types.zig").ProtocolVersion;
