//! The RFC 6455 carrier: the upgrade, the frame codec, and the one version a
//! connection speaks, bound to that connection.
//!
//! Six finished modules in `src/relay/` were called by nothing in `src/node/`:
//! `http_upgrade.zig` (which re-exports `http_request` and `http_response`),
//! `ws_frame.zig` (which re-exports five siblings), `conn_version.zig`,
//! `version_translate.zig`, and through them the relay's own opening handshake.
//! `node_relay_frame.zig` wrote a QUIC varint length in front of each relay
//! frame and read it back; that is a message boundary, and this file is the
//! carrier RFC 6455 names — an upgrade, then RFC 6455 frames on the stream that
//! upgrade settles.
//!
//! # What transport this runs on, and what it does not add
//!
//! **A QUIC stream, and nothing else.** `relay/carrier.zig:53-60` says it: "a
//! relay connection in this tree is a QUIC stream to a relay that speaks
//! `iroh-relay`, not a WebSocket over a TCP socket, so nothing here needs
//! TLS-over-TCP and nothing here provides one. That listener stays the declared
//! debt of `docs/DECISIONS/0001`." `DECISIONS/0001:31-32` gives the reason that
//! debt is real rather than deferred — "`std.crypto.tls` has a client-only
//! driver with no server and no raw-key certificate support" — and `:720-722`
//! records that the second TLS-over-TCP stack never entered this repository at
//! all.
//!
//! So the stream a relay connection runs on here is a QUIC stream
//! (`bridge_conn.Stream`), and the carrier rides that. Reaching for
//! `transport/tcp.zig` instead would compile, look right, and reach nothing:
//! `tcp.zig:67-73` records that it has no listener and no accept, and there is
//! no TLS server to put on one. **Nothing in this file opens a socket.** That is
//! a reading of `DECISIONS/0001`, not an omission.
//!
//! # Which end this node is, and why the upgrade has one caller
//!
//! **This node answers an upgrade; it never sends one.** `src/relay/` has no
//! request *builder* anywhere — `http_request.zig` parses, and nothing builds —
//! so a client half would mean writing a request encoder that no RFC 6455 text
//! in this tree pins. `relay/http_upgrade.zig:16-21` records the same stance for
//! the response half: "No bytes from an iroh relay's own `101` exist to pin
//! against". So `upgrade` is the relay's half, reached from a serving node's
//! admission path, and `node_relay_client.zig` keeps the stream it already
//! speaks. **A client request builder is a finding to report, not a gap to
//! fill**, and it is named as one.
//!
//! # Negotiation order is the offer list, and only a `max()` reads it
//!
//! **`Sec-WebSocket-Protocol` is an offer list, and first-match is the wrong
//! reader of one.** `frame_types.negotiate` takes the *largest* version any
//! token names, and the tree says why twice: iroh's client advertises newest
//! first (`http.rs:68`), so a first-match server "would pin every connection to
//! the oldest version both ends speak and quietly keep `Health` alive forever"
//! (`frame_types.zig:1075-1078`); and `conn_version.zig:80-92` builds the offer
//! newest-first for exactly that reason.
//!
//! That is the same shape as `router/alpn_table.zig`, and the two agree for one
//! reason: **an offer list is a preference list, and the order is the
//! preference.** `alpn_table.zig:231-235` calls registration order "the server's
//! preference order", and `qad_route.zig:35-42` separates "a property of the
//! offer list" from "negotiation" — the peer's list decides which name is taken.
//! `negotiate` reads the same list from the other end: the peer lists newest
//! first, and the server takes the best it can speak rather than the first it
//! recognises. **A tiebreak would read the order as an accident and pin every
//! connection to v1.** That is why `bind` is the only way a version enters the
//! `Connection` here: `Binding.bind` calls `negotiate` itself, so no call site
//! in this file can spell a version and get the order wrong.
//!
//! # Every refusal is named, and none of them truncates
//!
//! `Outcome` is exhaustive over the ways an upgrade or a frame fails, and
//! `Refused` counts each under its own name — `Wire.refused`'s shape in
//! `node_gossip_wire.zig:134-149`. **A frame too large for the buffer is
//! refused and never shortened**: a truncated frame is one the peer decodes as a
//! different message, and `ws_frame_encode.encode:123` answers
//! `error.BufferFull` for it rather than writing what fitted.
//!
//! One refusal is worth its own arm because it is why `version_translate.zig`
//! is reached at all: a `Status` this build cannot name is
//! `error.StatusNotExpressible` on a v1 connection rather than a sentence this
//! relay invented. `version_translate.zig:16-22` gives the reason — "any
//! sentence would be relay-authored prose that a v1 client cannot tell from a
//! decision the relay did make". It is counted separately rather than folded
//! into a generic codec refusal, because it is a decision about the protocol and
//! not about bytes.
//!
//! # Pure over bytes
//!
//! Every decision here is bytes in, state and actions out. `upgrade` reads a
//! request and produces the `101`; `writeFrame` takes a relay message and
//! produces one frame's bytes; `readFrame` takes one frame's bytes and produces
//! one relay message. None of them opens a socket, reads a clock, or allocates:
//! the caller owns every buffer, and `Connection` holds the binding and the
//! counters and nothing else.

const std = @import("std");

const carrier_types = @import("node_relay_carrier_types.zig");
const conn_version = @import("../relay/conn_version.zig");
const http_upgrade = @import("../relay/http_upgrade.zig");
const relay_frame = @import("../relay/frame.zig");
const version_translate = @import("../relay/version_translate.zig");
const ws_frame = @import("../relay/ws_frame.zig");

const std_testing = std.testing;

const Binding = conn_version.Binding;
const FrameType = conn_version.FrameType;
const Message = conn_version.Message;
const Opcode = ws_frame.Opcode;
const ProtocolVersion = conn_version.ProtocolVersion;
const Role = ws_frame.Role;
const Version = http_upgrade.Version;

// The vocabulary. Re-exported rather than spelled, so a caller has one place to
// import from and this file cannot drift from it.

pub const Outcome = carrier_types.Outcome;
pub const Refused = carrier_types.Refused;
pub const response_room = carrier_types.response_room;
pub const request_room = carrier_types.request_room;
pub const frame_room = carrier_types.frame_room;

/// One relay connection's carrier: the version it settled on, and what the
/// carrier has refused since.
///
/// **The binding is the connection's, not this build's.** Before `upgrade` has
/// run, `settled` is null and `Binding.version`, `encode` and `decode` all
/// answer `error.NotBound` rather than defaulting — `conn_version.zig:31-38`'s
/// rule, and the reason a connection whose upgrade never finished cannot be
/// read from by accident.
pub const Connection = struct {
    /// The version this connection speaks, or null until `upgrade` binds it.
    binding: Binding = .{ .settled = null },
    /// What the carrier refused, by name. See `Refused`.
    refused: Refused = .{},
    /// Connections answered with a `101`, and frames written and read since.
    upgraded: u64 = 0,
    frames_out: u64 = 0,
    frames_in: u64 = 0,

    /// Settle on the version the request names, and write the `101` into `out`.
    ///
    /// **Both halves come from `src/relay/`, and neither is re-implemented
    /// here.** `http_upgrade.parse` is the `GET` parse and `http_upgrade.build`
    /// is the response, including the accept value: this file computes no SHA-1
    /// and holds no copy of RFC 6455's GUID. The version is bound through
    /// `Binding.bind`, which calls `frame_types.negotiate`, so the order rule in
    /// the module doc is enforced by the module that owns it rather than by a
    /// scan written here.
    ///
    /// `request_bytes` is borrowed for the call and `out` is the caller's
    /// buffer; the returned slice aliases `out`, which is
    /// `http_response.build`'s contract. An `out` of less than `response_room`
    /// is `Outcome.no_room`.
    pub fn upgrade(self: *Connection, request_bytes: []const u8, out: []u8) Outcome![]const u8 {
        if (self.binding.settled != null) return refuse(self, error.AlreadyBound);
        const parsed = http_upgrade.parse(request_bytes) catch |err| {
            std.log.debug("relay carrier: the request was refused: {t}", .{err});
            return refuse(self, refused(err));
        };
        // A request that named no sub-protocol is refused rather than answered
        // with a version the client never offered. The parse succeeds on it —
        // RFC 6455 makes the field optional — and `Binding` has no way to
        // represent a connection with no version, so the two facts meet here and
        // the honest answer is to close rather than invent one.
        const chosen = parsed.version orelse return refuse(self, error.NoCommonVersion);
        // **The response is built before the version is bound, and the order is
        // load-bearing.** A `101` that did not fit writes nothing, and a
        // connection whose response was refused has answered nothing — binding
        // first would leave a connection reporting a version for a handshake no
        // peer ever saw, and `Binding.version` would hand it to the first frame
        // writer. So nothing is half-settled: a refused upgrade leaves this
        // connection unbound, not bound to nothing.
        const response = http_upgrade.build(out, chosen, parsed.key_text) catch
            return refuse(self, error.NoRoom);
        self.binding.settled = chosen;
        self.upgraded += 1;
        return response;
    }

    /// Write one relay message as one WebSocket frame.
    ///
    /// **Two buffers, and the split is load-bearing rather than tidiness.**
    /// `ws_frame.encode` copies the payload into the frame with `@memcpy`
    /// (`ws_frame_encode.zig:118`), and a `@memcpy` whose regions overlap has no
    /// answer the compiler will pick for it. Assembling in place — header at the
    /// front of one buffer, relay frame written behind it — would put the
    /// destination at `out[header_length..]` and the source at
    /// `out[max_header_length..]`, which overlap for any payload wider than the
    /// gap between them. So the relay frame is encoded into `relay` and the
    /// WebSocket frame is assembled in `out` from it: one copy, out of one
    /// buffer and into another, and no overlap to get wrong.
    ///
    /// `out` is the caller's buffer, never grown, and `ws_frame.encode`'s to
    /// refuse. **The version comes from the binding**, so a frame this
    /// connection's version forbids is refused here rather than written and
    /// refused by the peer.
    ///
    /// **A relay sends one message per frame, and it is unmasked.** RFC 6455
    /// section 5.1 makes the mask a client obligation, and `ws_frame.encode`
    /// takes the role from the connection rather than from the caller's key, so
    /// a relay cannot be talked into masking by being handed one. `Opcode.binary`
    /// is the opcode a relay message goes out under: the payload is postcard
    /// bytes and nothing in it is text.
    pub fn writeFrame(
        self: *Connection,
        message: Message,
        relay: []u8,
        out: []u8,
    ) Outcome![]const u8 {
        const written = self.binding.encode(message, relay) catch |err|
            return refuse(self, encoded(err));
        const framed = ws_frame.encode(
            out[0..ws_frame.encodedLen(written.len, .server)],
            .server,
            .{ .fin = true, .opcode = .binary, .key = @splat(0) },
            written,
        ) catch |err| return refuse(self, carrierFramed(err));
        self.frames_out += 1;
        return framed;
    }

    /// Read one relay message out of the bytes of exactly one frame.
    ///
    /// `bytes` is one frame and nothing of the next — the delimiter is the
    /// caller's, and `node_relay_frame.peekFrame` supplies it for a QUIC stream.
    ///
    /// **This reads what a *client* sends, so every frame is masked.** RFC 6455
    /// section 5.1 makes the mask a client obligation and section 5.3's transform
    /// the client's to apply, and `ws_frame.decode(bytes, .server)` refuses an
    /// unmasked frame before it measures the payload — so the mask bit is a
    /// fact here rather than a branch. The relay's own frames go the other way
    /// and are never masked, which is why `writeFrame` cannot be read back by
    /// this and that is the RFC and not a gap.
    ///
    /// **The unmask is this file's job and not the codec's**: `ws_frame.decode`
    /// hands its payload back still masked, because unmasking in place would
    /// change bytes another decoded frame borrows from the same message buffer
    /// (`ws_frame_decode.zig:74`). The plaintext therefore goes into `plain`,
    /// which the caller owns and must keep for as long as the returned message
    /// borrows from it.
    ///
    /// **`plain` is measured before it is written, not after.** The payload
    /// length is the peer's to declare and this end's to satisfy, and slicing
    /// `plain` to a length past its end would be a panic on a number a peer
    /// chose. So a frame whose payload will not fit is refused, which is also
    /// the only way this file honours "refused, never truncated" on the way in:
    /// a short plaintext is a frame the relay would decode as a different
    /// message.
    pub fn readFrame(self: *Connection, bytes: []const u8, plain: []u8) Outcome!?Message {
        const decoded = ws_frame.decode(bytes, .server) catch |err| {
            std.log.debug("relay carrier: the frame was refused: {t}", .{err});
            return refuse(self, carrierFramed(err));
        };
        // A continuation frame carries no opcode of its own (RFC 6455 section
        // 5.4) and this build reassembles nothing, so a fragment is the one
        // payload shape the carrier cannot turn into a message. It is refused by
        // name rather than decoded as the binary frame that began it.
        if (decoded.frame.opcode != .binary) return refuse(self, error.Undecodable);
        if (decoded.payload.len > plain.len) return refuse(self, error.NoFrameRoom);
        // A frame with no payload carries no relay message, and that is not a
        // refusal: `frame.decode` names it `error.UnexpectedEnd`, and a caller
        // asking again after a frame this end already spent would decide about
        // the same bytes twice.
        if (decoded.payload.len == 0) return null;
        // `maskCopy` answers `BufferFull` and this file answers it as a frame that
        // did not fit, which is what it is: the plaintext buffer was measured
        // against the payload two lines above, so the codec's own refusal is the
        // belt to that check's braces and not a second rule.
        const payload = ws_frame.maskCopy(
            decoded.frame.mask_key,
            decoded.payload,
            plain[0..decoded.payload.len],
        ) catch return refuse(self, error.NoFrameRoom);
        const message = self.binding.decode(payload) catch |err| {
            return refuse(self, encoded(err));
        };
        self.frames_in += 1;
        return message;
    }

    /// The message `control` becomes on this connection's version.
    ///
    /// **`version_translate.toMessage`, not a switch written here.** A `Status`
    /// is one byte on v2 and a sentence on v1, and a `Status` this build cannot
    /// name has no v1 spelling at all. The refusal is counted as
    /// `Outcome.status_unnameable` rather than folded into a codec error,
    /// because it is a decision about the protocol and not about bytes.
    pub fn controlMessage(
        self: *Connection,
        control: version_translate.Control,
    ) Outcome!Message {
        const version = self.binding.version() catch return refuse(self, error.NoCommonVersion);
        return version_translate.toMessage(control, version) catch |err|
            refuse(self, translated(err));
    }
};

/// What a refused parse is called here.
///
/// **Every arm of `http_upgrade.Error` is named by the arm that raised it, and
/// none of them is widened.** `NoCommonVersion` is kept apart because it is a
/// different fact: the rest are a request that is not an upgrade, and this one
/// is an upgrade whose sub-protocol this build cannot answer — which RFC 6455
/// section 4.2.2 answers by closing.
fn refused(err: http_upgrade.Error) Outcome {
    return switch (err) {
        error.NoSupportedProtocol => error.NoCommonVersion,
        error.UnexpectedEnd,
        error.MalformedRequestLine,
        error.MethodNotGet,
        error.PathNotFound,
        error.BadHttpVersion,
        error.MalformedField,
        error.TooManyFields,
        error.FieldTooLong,
        error.HeaderTooLong,
        error.DuplicateField,
        error.UpgradeNotWebsocket,
        error.ConnectionNotUpgrade,
        error.BadWebSocketVersion,
        error.BadWebSocketKey,
        => error.NotAnUpgrade,
    };
}

/// What a refused relay frame is called here.
///
/// **`conn_version.Error` is the set rather than `relay_frame.Error`,** because
/// `Binding` is what refuses and it adds the binding's refusals to the codec's.
/// `FrameNotAllowedInVersion` is the binding's and means this connection's
/// negotiated version does not define the frame — a fact about the negotiation
/// rather than about the bytes. Everything else this codec refused is a frame
/// that did not fit or did not have the shape its type names, and none of it is
/// truncated.
fn encoded(err: conn_version.Error) Outcome {
    return switch (err) {
        error.FrameNotAllowedInVersion => error.FrameNotAllowed,
        // The binding's own refusals are the version's *absence*, so they are
        // counted as such rather than as a frame that would not fit. An unbound
        // connection is the case a caller reaches by writing before its upgrade
        // ran, and `conn_version.zig:31-38` is what says it must not default.
        error.NotBound, error.NoCommonVersion, error.AlreadyBound => error.NoCommonVersion,
        else => error.NoFrameRoom,
    };
}

/// What a refused control-statement translation is called here.
///
/// **`StatusNotExpressible` is kept apart because it is the reason
/// `version_translate.zig` is reached at all**, and it is the one refusal here
/// that is a decision about the protocol rather than about bytes: this relay
/// has a `Status` it cannot name and the connection's version can only spell it
/// as text, so the honest answer is to send something else. The other two are
/// the statement not being one, and the frame not being in this version.
fn translated(err: version_translate.Error) Outcome {
    return switch (err) {
        error.StatusNotExpressible => error.StatusUnnameable,
        error.NotAControlStatement, error.FrameNotAllowedInVersion => error.FrameNotAllowed,
    };
}

/// What a refused WebSocket frame is called here.
///
/// **Both directions' refusals go through this one switch** because the same set
/// names them and a caller would otherwise get two switches over one vocabulary.
/// The mask arms are the ones a conforming peer never triggers — a relay never
/// masks and a relay's client always does — and they are counted as
/// `Undecodable` because that is what they are from here: bytes this end will
/// not act on. The two size arms are `NoFrameRoom` because a frame that does not
/// fit is refused and never shortened.
fn carrierFramed(err: ws_frame.Error) Outcome {
    return switch (err) {
        error.BufferFull, error.FrameTooLarge => error.NoFrameRoom,
        error.UnexpectedEnd,
        error.ReservedBitSet,
        error.UnknownOpcode,
        error.ControlFrameTooLong,
        error.FragmentedControlFrame,
        error.NonMinimalLength,
        error.ReservedLengthBit,
        error.UnmaskedClientFrame,
        error.MaskedServerFrame,
        => error.Undecodable,
    };
}

/// Count one refusal under its own name, and hand the name back.
fn refuse(self: *Connection, outcome: Outcome) Outcome {
    switch (outcome) {
        error.NotAnUpgrade => self.refused.not_an_upgrade += 1,
        error.NoCommonVersion => self.refused.no_common_version += 1,
        error.NoRoom => self.refused.no_room += 1,
        error.AlreadyBound => self.refused.already_bound += 1,
        error.FrameNotAllowed => self.refused.frame_not_allowed += 1,
        error.NoFrameRoom => self.refused.no_frame_room += 1,
        error.Undecodable => self.refused.undecodable += 1,
        error.StatusUnnameable => self.refused.status_unnameable += 1,
    }
    return outcome;
}

// --- tests

const relay_test_ids = @import("../relay/relay_test_ids.zig");
const http_request = @import("../relay/http_request.zig");

/// The four fields every well-formed request carries, over this relay's own
/// offer list. `http_request.base_fields` is the fixture the parse's own tests
/// are written against, so a request built from it is the same bytes and the
/// parse cannot pass against a spelling only this file's tests use.
const fields = http_request.base_fields ++
    "Sec-WebSocket-Protocol: " ++ conn_version.client_offer ++ "\r\n";

/// A whole request carrying `fields`, and nothing else.
fn request() []const u8 {
    return http_request.request(fields);
}

/// The accept value RFC 6455 section 1.3 prints for `vectors.handshake_key`.
///
/// **RFC 6455 section 1.3's own printed response**, which
/// `relay/http_upgrade.zig:97-102` holds as the golden for this half. Asserting
/// it here is what says the carrier wrote the RFC's response rather than a
/// response that agrees with itself.
const rfc_accept = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";

// **Stays here:** it crosses `http_upgrade.parse`, `http_upgrade.build`,
// `http_upgrade.accept`, `Binding.bind`, `Binding.encode` and `Binding.decode`,
// and no single module below this one can say that the six agree.
test "an upgrade answers with the accept key, and a frame survives both ways" {
    var conn: Connection = .{};
    var response: [response_room]u8 = undefined;
    const answered = try conn.upgrade(request(), &response);

    // The `101` is the RFC's own response, byte for byte, with this relay's
    // answer to the offer read back off it. The accept value is computed by
    // `http_response.accept`; this asserts the wire agrees with the RFC.
    try std_testing.expectEqualStrings(
        "HTTP/1.1 101 Switching Protocols\r\n" ++
            "Upgrade: websocket\r\n" ++
            "Connection: Upgrade\r\n" ++
            "Sec-WebSocket-Accept: " ++ rfc_accept ++ "\r\n" ++
            "Sec-WebSocket-Protocol: iroh-relay-v2\r\n" ++
            "\r\n",
        answered,
    );

    // The version is the connection's, and it is the largest the offer names.
    // `client_offer` is newest first, so this is the answer a `max()` gives and
    // the one a first-match would refuse.
    try std_testing.expectEqual(ProtocolVersion.v2, try conn.binding.version());
    try std_testing.expectEqual(@as(u64, 1), conn.upgraded);

    // **Both directions, each in its own role, because RFC 6455 does not let a
    // relay read its own frames.** A relay writes unmasked and a relay's client
    // writes masked, so the round trip is: the relay's frame read by a client,
    // and a client's frame read by the relay. Reading a relay's own output back
    // through `readFrame` would be refused as `UnmaskedClientFrame`, and that
    // refusal is the RFC and not a defect.
    const gone = try relay_test_ids.testNodeId(41);
    var relay: [frame_room]u8 = undefined;
    var out: [frame_room]u8 = undefined;
    const framed = try conn.writeFrame(.{ .endpoint_gone = gone }, &relay, &out);

    // What a relay writes is one binary frame with FIN set and no mask, which is
    // RFC 6455 section 5.1's rule and `ws_frame.encode`'s own choice of role.
    const on_the_wire = try ws_frame.decode(framed, .client);
    try std_testing.expectEqual(Opcode.binary, on_the_wire.frame.opcode);
    try std_testing.expect(on_the_wire.frame.fin);
    try std_testing.expect(!on_the_wire.frame.masked);
    // And the relay's own frame is refused by the relay's reader for the one
    // reason the RFC gives: a server frame is not masked.
    var plain: [frame_room]u8 = undefined;
    try std_testing.expectError(error.Undecodable, conn.readFrame(framed, &plain));

    // The other direction: a masked client frame, read back as the same relay
    // message. This is the path a relay's client actually takes.
    var client_out: [frame_room]u8 = undefined;
    const masked = try masked_frame(&conn, .{ .endpoint_gone = gone }, &relay, &client_out);
    const read = (try conn.readFrame(masked, &plain)).?;
    try std_testing.expectEqual(FrameType.endpoint_gone, std.meta.activeTag(read));
    try std_testing.expectEqual(gone, read.endpoint_gone);
    try std_testing.expectEqual(@as(u64, 1), conn.frames_out);
    try std_testing.expectEqual(@as(u64, 1), conn.frames_in);
}

// **Stays here:** it crosses `Binding.bind` and `frame_types.negotiate`, and the
// claim is about the order of an offer list rather than about either module
// alone. This is the test that says order is load-bearing.
test "the offer list settles on the newest, in either token order" {
    // A `101` buffer per connection: `upgrade` writes its response into a
    // caller-owned buffer, and the assertions here read only the version, so one
    // shared buffer would be a buffer two connections could write at once.
    var response: [response_room]u8 = undefined;

    // Newest first, which is what `conn_version.client_offer` sends and what
    // iroh's own client sends (`http.rs:68`).
    var newest: Connection = .{};
    _ = try newest.upgrade(with_offer("iroh-relay-v2, iroh-relay-v1"), &response);
    try std_testing.expectEqual(ProtocolVersion.v2, try newest.binding.version());

    // Oldest first is the same answer, and only a `max()` gives it twice. A
    // tiebreak reads the list as an ordering accident and pins this connection to
    // v1, which is what `frame_types.zig:1075-1078` says would keep `Health`
    // alive forever.
    var oldest: Connection = .{};
    _ = try oldest.upgrade(with_offer("iroh-relay-v1, iroh-relay-v2"), &response);
    try std_testing.expectEqual(ProtocolVersion.v2, try oldest.binding.version());

    // One version on its own, and a token this build does not speak dropped
    // rather than failed on — which is what lets a client advertise a version a
    // particular relay has never heard of.
    var one: Connection = .{};
    _ = try one.upgrade(with_offer("iroh-relay-v1"), &response);
    try std_testing.expectEqual(ProtocolVersion.v1, try one.binding.version());

    // And the two really are different, which is what makes the `max()` load
    // bearing: `Health` is v1 and `Status` is v2, so a connection that settled
    // wrongly refuses a frame it has already promised the peer it would take.
    try std_testing.expect(try one.binding.allows(.health));
    try std_testing.expect(!(try newest.binding.allows(.health)));
    try std_testing.expect(try newest.binding.allows(.status));

    // A second offer on a connection that has settled is refused and the first
    // answer stands, because a re-negotiation would admit a frame already
    // promised to be refused (`conn_version.zig:22-29`).
    try std_testing.expectError(error.AlreadyBound, newest.upgrade(request(), &response));
    try std_testing.expectEqual(ProtocolVersion.v2, try newest.binding.version());
    try std_testing.expectEqual(@as(u64, 1), newest.refused.already_bound);
}

// **Stays here:** each case is a decision this file makes about a refusal a
// module below it raised, and counting them is this file's whole job — no module
// below can count.
test "a refused upgrade is refused by name, and counted under that name" {
    // Every way a request is not an upgrade, each counted once. Eleven
    // distinct byte strings and one counter, and the counter says "not an
    // upgrade" rather than "a codec said no".
    for ([_][]const u8{
        "GET /relay\r\n\r\n",
        "POST /relay HTTP/1.1\r\n\r\n",
        "GET /elsewhere HTTP/1.1\r\n\r\n",
        "GET /relay HTTP/1.0\r\n\r\n",
        "GET /relay HTTP/1.1\r\nnocolon\r\n\r\n",
        "GET /relay HTTP/1.1\r\nbad name: value\r\n\r\n",
        // A field this relay reads as a singleton, twice.
        "GET /relay HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" ++
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
            "Sec-WebSocket-Version: 13\r\nSec-WebSocket-Version: 13\r\n\r\n",
        // The two upgrade tokens, each refused in turn.
        "GET /relay HTTP/1.1\r\nUpgrade: h2c\r\nConnection: Upgrade\r\n" ++
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
            "Sec-WebSocket-Version: 13\r\n\r\n",
        "GET /relay HTTP/1.1\r\nUpgrade: websocket\r\nConnection: keep-alive\r\n" ++
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
            "Sec-WebSocket-Version: 13\r\n\r\n",
        // The version token and the key, each refused in turn.
        "GET /relay HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" ++
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
            "Sec-WebSocket-Version: 14\r\n\r\n",
        "GET /relay HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" ++
            "Sec-WebSocket-Key: c2hvcnQ=\r\nSec-WebSocket-Version: 13\r\n\r\n",
        // A header block over the parse's own ceiling.
        "GET /relay HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" ++
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
            "Sec-WebSocket-Version: 13\r\n" ++
            "X-Pad: " ++ "p" ** (http_upgrade.max_field_length + 1) ++ "\r\n",
    }) |bad| {
        var conn: Connection = .{};
        var response: [response_room]u8 = undefined;
        try std_testing.expectError(error.NotAnUpgrade, conn.upgrade(bad, &response));
        try std_testing.expectEqual(@as(u64, 1), conn.refused.not_an_upgrade);
        // Nothing else moved: a refusal under one name is not also a refusal
        // under the others, which is what lets a reader trust the name.
        try std_testing.expectEqual(@as(u64, 0), conn.refused.no_common_version);
        try std_testing.expectEqual(@as(u64, 0), conn.upgraded);
    }

    // A sub-protocol this build cannot answer is a different fact, and it is
    // counted under its own name rather than the one above.
    var unknown: Connection = .{};
    var response: [response_room]u8 = undefined;
    try std_testing.expectError(error.NoCommonVersion, unknown.upgrade(
        with_offer("iroh-relay-v3"),
        &response,
    ));
    try std_testing.expectEqual(@as(u64, 1), unknown.refused.no_common_version);
    try std_testing.expectEqual(@as(u64, 0), unknown.refused.not_an_upgrade);

    // A request that named no sub-protocol at all is the same refusal, and it is
    // this file's decision rather than the parse's: the parse accepts the
    // request — RFC 6455 makes the field optional — and `Binding` cannot
    // represent a connection with no version.
    var nameless: Connection = .{};
    const bare = http_request.request(
        "Upgrade: websocket\r\nConnection: Upgrade\r\n" ++
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
            "Sec-WebSocket-Version: 13\r\n",
    );
    try std_testing.expectEqual(@as(?Version, null), (try http_upgrade.parse(bare)).version);
    try std_testing.expectError(error.NoCommonVersion, nameless.upgrade(bare, &response));
    try std_testing.expectEqual(@as(u64, 1), nameless.refused.no_common_version);

    // A response one byte short of what `responseLen` promises is refused and
    // writes nothing, which is `http_response.build`'s own rule: a response with
    // a missing accept field is a handshake that fails at the peer.
    var short: Connection = .{};
    var narrow: [response_room - 1]u8 = undefined;
    try std_testing.expectError(error.NoRoom, short.upgrade(request(), &narrow));
    try std_testing.expectEqual(@as(u64, 1), short.refused.no_room);
    // And nothing was half-settled: an unbound connection is not bound to
    // nothing.
    try std_testing.expectError(error.NotBound, short.binding.version());
}

// **Stays here:** the four refusals below are decisions about bytes on a stream,
// made across `ws_frame` and `Binding`, and no module below this one can say
// what a caller is expected to do with any of them.
test "a frame the connection cannot carry is refused by name" {
    // An unsettled connection refuses rather than defaulting to a version.
    var pending: Connection = .{};
    var plain: [frame_room]u8 = undefined;
    try std_testing.expectError(error.NoCommonVersion, pending.controlMessage(.{
        .peer_gone = try relay_test_ids.testNodeId(42),
    }));
    try std_testing.expectEqual(@as(u64, 1), pending.refused.no_common_version);

    // The v1 connection, which is where the refusals below are reachable:
    // `Status` is v2 and `Health` is v1, so the same frame is legal on one
    // connection and not on the other.
    var oldest: Connection = .{ .binding = .{ .settled = .v1 } };
    var scratch: [frame_room]u8 = undefined;
    var oldest_out: [frame_room]u8 = undefined;
    const health = try masked_frame(
        &oldest,
        .{ .health = "unwell" },
        &scratch,
        &oldest_out,
    );
    try std_testing.expectEqualStrings(
        "unwell",
        (try oldest.readFrame(health, &plain)).?.health,
    );

    // A `Status` this build cannot name has no v1 spelling, so the translation
    // is refused rather than answered with a sentence this relay invented. This
    // is `version_translate.zig:16-22`'s refusal, reached through the carrier.
    try std_testing.expectError(
        error.StatusUnnameable,
        oldest.controlMessage(.{ .status = .{ .unknown = 200 } }),
    );
    try std_testing.expectEqual(@as(u64, 1), oldest.refused.status_unnameable);

    // The same frame on a v2 connection is refused by the version and not by the
    // codec, which is what "carried on the connection" means.
    var newest: Connection = .{ .binding = .{ .settled = .v2 } };
    var newest_relay: [frame_room]u8 = undefined;
    var newest_out: [frame_room]u8 = undefined;
    try std_testing.expectError(
        error.FrameNotAllowed,
        newest.writeFrame(.{ .health = "unwell" }, &newest_relay, &newest_out),
    );
    try std_testing.expectEqual(@as(u64, 1), newest.refused.frame_not_allowed);

    // And the `Status` v1 could not carry is one byte on v2, written and read
    // back as itself rather than as a sentence.
    const status = try newest.controlMessage(.{ .status = .rate_limited });
    const framed = try masked_frame(&newest, status, &newest_relay, &newest_out);
    try std_testing.expectEqual(
        relay_frame.Status.rate_limited,
        (try newest.readFrame(framed, &plain)).?.status,
    );

    // A frame whose payload will not fit the plaintext buffer is refused and
    // **not shortened**: the counter moved under that name and the caller's
    // buffer is untouched, because a short plaintext is a frame the relay would
    // decode as a different message. The frame is a real masked client frame,
    // built by `ws_frame.encode` because that is the only encoder of one, so
    // this exercises the guard rather than a malformed header.
    //
    // **A hundred bytes, not the frame room.** The guard under test is the
    // plaintext buffer being eight bytes; a payload over `max_frame_size` would
    // be refused by `ws_frame` itself before this file saw it, which is a
    // different and already-covered refusal.
    var payload: [100]u8 = @splat(0xaa);
    var client_frame: [ws_frame.encodedLen(payload.len, .client)]u8 = undefined;
    const too_wide = try ws_frame.encode(
        &client_frame,
        .client,
        .{ .fin = true, .opcode = .binary, .key = ws_frame.fixedMaskKey() },
        &payload,
    );
    var narrow: [8]u8 = @splat(0xee);
    try std_testing.expectError(error.NoFrameRoom, newest.readFrame(too_wide, &narrow));
    try std_testing.expectEqual(@as(u64, 1), newest.refused.no_frame_room);
    var untouched: [8]u8 = @splat(0xee);
    try std_testing.expectEqualSlices(u8, &untouched, &narrow);
}

/// `message` as the masked frame a relay's *client* sends, over the connection's
/// own negotiated version.
///
/// **A relay cannot read its own frames.** RFC 6455 section 5.1 makes the mask a
/// client obligation, so `writeFrame`'s output is unmasked and `readFrame` —
/// which decodes as `.server` and so requires the mask — refuses it. Reading a
/// client is therefore a two-step shape: the relay message is encoded in the
/// connection's version, then framed with the section 5.3 transform applied. The
/// test client half is these few lines because there is no request builder in
/// `src/relay/` to build the other half with; see the module doc's "Which end
/// this node is".
fn masked_frame(
    conn: *const Connection,
    message: Message,
    relay: []u8,
    out: []u8,
) ![]const u8 {
    const written = conn.binding.encode(message, relay) catch unreachable;
    return ws_frame.encode(
        out[0..ws_frame.encodedLen(written.len, .client)],
        .client,
        .{ .fin = true, .opcode = .binary, .key = ws_frame.fixedMaskKey() },
        written,
    );
}

/// A whole request carrying `offer` as its sub-protocol field.
///
/// **Written here rather than through `http_request.request`** because that
/// helper takes its `fields` at comptime — its own note says a runtime
/// concatenation "would need a buffer this loop does not have" — and the offer
/// under test differs per case. The field spellings are this build's, which is
/// all a request builder has to be here: what is under test is which version
/// the offer settles on, and `http_upgrade.parse` is what reads the field.
fn with_offer(comptime offer: []const u8) []const u8 {
    return "GET /relay HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" ++
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n" ++
        "Sec-WebSocket-Protocol: " ++ offer ++ "\r\n\r\n";
}
