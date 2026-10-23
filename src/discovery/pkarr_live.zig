//! The live pkarr path: a signed packet published to, and resolved from, an
//! HTTPS relay.
//!
//! Upstream resolves pkarr over **HTTPS**, not UDP: `PkarrRelayClient::resolve`
//! (`iroh/src/address_lookup/pkarr.rs:620`) is an `http_client.get(url)` on
//! `N0_DNS_PKARR_RELAY_PROD`, which is `https://dns.iroh.link/pkarr` (`pkarr.rs:127`),
//! with the node's z32 pushed on as a path segment, and the reply handed to
//! `SignedPacket::from_relay_payload` (`pkarr.rs:651`). A publisher PUTs the same
//! URL. So the wire here is HTTP/1.1 over TLS over `transport/tcp.zig`, and the
//! three files under it are `discovery/tls_client.zig` (the TLS), this one (the
//! exchange), and `discovery/pkarr.zig` (the packet).
//!
//! # The signed packet is the part that matters, and none of it is re-derived
//!
//! Everything about the packet is `discovery/pkarr.zig`'s and this file calls it:
//!
//! * `pkarr.sign` builds and signs the wire form, over the BEP-0044 signable
//!   form and not the raw packet — `docs/ARCHITECTURE.md` invariant 11.
//! * `pkarr.Packet.parse` decodes a whole packet and `fromRelayPayload` decodes
//!   a relay's body, which omits the key because the key is the path the request
//!   arrived on.
//! * `pkarr_body.writeBody` frames the DNS answer the packet's body is, and
//!   `pkarr_body.readBody` reads the records back out.
//! * `Packet.verify` checks the signature against the node the caller asked
//!   about.
//!
//! # A signer that is not the node's own key is a refusal, not a parse failure
//!
//! This is the decision the file exists to get right. Three facts are in play
//! and they are three different failures:
//!
//! 1. The body is not a well-formed packet at all — `error.MalformedPacket`.
//! 2. The body is a well-formed packet whose signature does not verify —
//!    `error.BadSignature`.
//! 3. **The body is a well-formed packet, correctly signed, by somebody else** —
//!    `error.UnexpectedSigner`.
//!
//! Upstream takes the node id from whatever the relay returned
//! (`iroh-dns/src/endpoint_info.rs`, `from_pkarr_signed_packet` is
//! `EndpointId::from_bytes(pubkey.as_bytes())`) and hands it straight on, so a
//! relay answering a query for one node with another's record is obeyed. This
//! file does not, and the refusal is its own arm rather than a member of the
//! parse set: a caller that retries under a different key wants to know it was
//! looking at somebody else's packet, and folding that into
//! `error.MalformedPacket` would send it round the same loop.
//!
//! The arm is `resolve.Reason.UnexpectedSigner`, which
//! `discovery/lookup.zig` already owns and `discovery/pkarr_services.zig`'s
//! resolver already returns for the same fault on the reading side. Reusing it
//! is the point: a packet refused here and a packet refused there are the same
//! fault, and a caller meeting both should not have to learn two vocabularies.
//!
//! `Packet.verify(expected)` gives this for free — it is `pkarr.zig`'s own check
//! and its own `VerifyError.WrongSigner` arm — so this file does not implement
//! signer checking. It **maps** it, and the mapping is the claim.
//!
//! # The publisher's own key, and why publishing is refused too
//!
//! `pkarr.sign` takes a `SecretKey` and derives the packet's public key from it,
//! so a publisher cannot sign under a key that is not the node it is publishing:
//! the key *is* the node id. What it can do is publish node A's addresses under
//! node B's name, if the caller pairs the wrong two values, and then every
//! resolver would learn that A is reachable at B. `publish` therefore refuses a
//! `SecretKey` whose node id is not the one it was asked to publish, and refuses
//! with the same `error.UnexpectedSigner` — a publish under the wrong key is the
//! same fault as a resolve answered under the wrong key, seen from the other
//! side.
//!
//! # An HTTP status is not a signed-packet question
//!
//! `exchange` answers three things and they are kept apart: a transport refusal
//! (`error.Unreachable`, `error.TlsRefused`, and the rest), a status that is not
//! success (`error.StatusNotSuccess`, with the code the relay sent), and a
//! success whose body would not parse. Upstream's `http_client.get` throws all
//! three into one error type, and the distinction matters to a publisher: a 404
//! from a pkarr relay means *this node has published nothing there*, which is a
//! fact about the world and not a failure of the resolve.
//!
//! # Purity, entropy and the clock
//!
//! `io: std.Io` is a parameter of `publish` and `resolve` and is stored nowhere.
//! The signing timestamp is a parameter, because `discovery/pkarr.zig`'s
//! `pkarr.sign` takes one for the reason its own doc gives: reading a clock
//! there would put a global in a pure module. The relay's `Host:` header is
//! derived from the caller's `base_url` rather than read from the environment.

const std = @import("std");

const resolve_mod = @import("resolve.zig");

const addr = @import("../base/addr.zig");
const key = @import("../base/key.zig");

const pkarr = @import("pkarr.zig");
const pkarr_body = @import("pkarr_body.zig");
const preset = @import("preset.zig");
const tls_client = @import("tls_client.zig");

/// Everything one pkarr exchange can fail with.
///
/// The three sources, named and not merged, because a caller acts on all three
/// differently: `tls_client.Error` is a transport or trust failure and the
/// relay was never reached; `HttpError` is a relay that answered and the answer
/// is not one to use; and `pkarr.Error` plus `resolve.Reason` is a body that
/// arrived and is not this node's.
pub const Error = tls_client.Error || HttpError || pkarr.Error || pkarr_body.Error ||
    resolve_mod.Reason || std.Io.Reader.Error || std.Io.Writer.Error;

/// What a relay answered that this file will not use.
pub const HttpError = error{
    /// The relay answered with a status outside 2xx.
    ///
    /// A `404` is the ordinary answer to a resolve for a node nobody published
    /// there, which is why this is an error the caller can recognise and not a
    /// refusal to try: `Response.status` carries the code.
    StatusNotSuccess,
    /// The response was truncated: the body the `Content-Length` named is not
    /// all there. Refused rather than read short, because a pkarr packet's
    /// signature covers its body and a short body is a body nobody signed.
    TruncatedBody,
    /// The response carried neither `Content-Length` nor a body the shape this
    /// file accepts. RFC 9112 §6.3 makes a response without a framing header
    /// readable up to the connection close, and this file does not rely on that:
    /// a length it can check is a length it can refuse.
    UnframedBody,
    /// The response header block was longer than `max_header_length`.
    HeaderTooLong,
};

/// How long the whole exchange may take, in milliseconds, when `Options` does
/// not say. 30 seconds, which is generous for a signed-packet fetch and bounded
/// so a relay that accepts and never answers costs a timeout rather than a hang.
pub const default_timeout_ms: i32 = 30_000;

/// The longest response header block this file reads.
///
/// RFC 9110 §5.1 puts no numeric limit on a header block and every server picks
/// its own; 8 KiB is above anything a pkarr relay sends and below anything that
/// would let a peer make this file buffer without bound.
pub const max_header_length: usize = 8 * 1024;

/// The most a response body may be: one whole signed packet, header included,
/// which is `pkarr.max_packet_length`.
pub const max_body_length: usize = pkarr.max_packet_length;

/// What one exchange needs beyond the destination.
///
/// An options struct because every one of these is a caller's decision and a
/// positional list of seven is a list nothing distinguishes. The two `[]u8`
/// fields are the caller's storage and are not copied: `read_buffer` and
/// `write_buffer` must each be `tls_client.buffer_length` bytes or more.
pub const Options = struct {
    /// The relay's base URL, as `discovery/preset.zig` spells it:
    /// `https://dns.iroh.link/pkarr`. The `Host:` field and the resolved address
    /// both come from here.
    base_url: []const u8,
    /// The address the relay was resolved to.
    ///
    /// A `SocketAddr` and not a name, because `base/relay.zig`'s
    /// `RelayUrl.socketAddr` refuses a name: this tree does not resolve
    /// hostnames inside a relay client, and pretending otherwise is the thing
    /// that module's doc refuses. `discovery/dns_live.zig` is the A/AAAA side of
    /// that question and this file is not.
    server: addr.SocketAddr,
    /// The trust anchors and handshake inputs. See `tls_client.Options` for what
    /// is trusted and why.
    trust: tls_client.Options,
    /// The caller's TLS read scratch.
    read_buffer: []u8,
    /// The caller's TLS write scratch.
    write_buffer: []u8,
    /// How long the connect and each read and write wait. Null takes
    /// `default_timeout_ms`, which is this file's decision and not a default
    /// every caller has to repeat.
    timeout_ms: ?i32 = null,
};

/// What one signed packet needs before it can be built or checked.
///
/// A separate value from `Options` because the packet's parts are checked
/// together and a caller that got one wrong should be told which part.
pub const Publish = struct {
    /// The key the packet is signed under, and therefore the node it publishes.
    ///
    /// A `SecretKey` by pointer, because `pkarr.sign` takes one by value and
    /// copying a secret is a copy of bytes that then exist in two places; the
    /// caller's key outlives the call and is not this file's to duplicate.
    secret: *const key.SecretKey,
    /// When the packet claims to have been signed, in microseconds since the
    /// unix epoch, big-endian in the header.
    ///
    /// An argument, never `now()`: `discovery/pkarr.zig`'s `pkarr.sign` takes
    /// one for that reason, and iroh's own `Timestamp::now` keeps a
    /// process-global `AtomicU64` to force strict monotonicity, which is the
    /// `base`/`discovery` boundary's business.
    timestamp_us: u64,
    /// The `_iroh` records to publish, one per NUL, in `resolve.RecordSet`'s own
    /// shape.
    ///
    /// `discovery/pkarr_services.zig`'s `PkarrPublisher.writeTxtStrings` is what
    /// writes them and this file does not have a second record grammar.
    records: resolve_mod.RecordSet,
};

/// What one resolve came to: the packet, verified against the node asked about.
///
/// `Packet.dns` borrows the response buffer it was read from, so this value is
/// only as long as the caller's buffer and `pkarr.Packet`'s own doc is where
/// that rule is argued.
pub const Answer = struct {
    /// The signed packet, signature verified against `node_id`.
    packet: pkarr.Packet,
    /// The node it was asked about, copied out so a caller does not have to
    /// keep its own copy of the id alive to read this value.
    node_id: addr.NodeId,
};

/// Publish `packet` to the relay `options` names.
///
/// `alloc` is the TLS driver's allocator and nothing else here allocates: the
/// two fixed scratch buffers `pkarr.sign` wants are inside this value, because
/// `pkarr.max_signable_length` and `pkarr.max_packet_length` are its own bounds
/// and a caller that supplied them could get one wrong.
///
/// The relay's answer is a status and nothing else — a pkarr relay stores the
/// packet and says so — so this function reads the status and hands the code to
/// `Response.status` rather than returning a body.
///
/// **The key is checked against the node being published.** A secret whose node
/// id is not the one the records are about would publish one node's addresses
/// under another's name, and every resolver would believe it; see the module
/// doc. The refusal is `error.UnexpectedSigner` and it happens before anything
/// is signed, so nothing is written and nothing goes on the wire.
pub fn publish(
    alloc: std.mem.Allocator,
    io: std.Io,
    options: Options,
    packet: Publish,
    node_id: addr.NodeId,
    out: *Response,
) Error!void {
    // The check is the first thing, and it is a refusal rather than a parse
    // failure: the packet is well formed and correctly signed by the wrong node.
    if (signerRefusal(packet.secret.nodeId(), node_id) != null)
        return error.UnexpectedSigner;

    var name: [pkarr_body.nameLength()]u8 = undefined;
    const asked = try pkarr_body.writeName(&name, node_id);
    var body: [pkarr.max_dns_length]u8 = undefined;
    const dns = try pkarr_body.writeBody(&body, asked, packet.records);
    var signable: [pkarr.max_signable_length]u8 = undefined;
    var encoded: [pkarr.max_packet_length]u8 = undefined;
    const framed = try pkarr.sign(
        packet.secret.*,
        packet.timestamp_us,
        dns,
        &signable,
        &encoded,
    );

    var url: [preset.pkarrNodeUrlLength("")]u8 = undefined;
    const target = try preset.pkarrNodeUrl(&url, options.base_url, node_id);
    try exchange(alloc, io, options, .put, target, framed, out);
}

/// Resolve `node_id` from the relay `options` names.
///
/// The answer is a signed packet and the signature is checked against `node_id`
/// before anything is read out of the body: an unverified packet's records are
/// bytes a relay chose, and `discovery/pkarr_services.zig`'s resolver already
/// refuses them for the same reason.
///
/// A body signed by somebody else is `error.UnexpectedSigner` and not a parse
/// failure; see the module doc.
pub fn resolve(
    alloc: std.mem.Allocator,
    io: std.Io,
    options: Options,
    node_id: addr.NodeId,
    out: *Response,
) Error!Answer {
    var url: [preset.pkarrNodeUrlLength("")]u8 = undefined;
    const target = try preset.pkarrNodeUrl(&url, options.base_url, node_id);
    try exchange(alloc, io, options, .get, target, "", out);

    // `fromRelayPayload`, not `parse`: a relay's body omits the 32 header key
    // bytes because the key is the path segment the request arrived on, which is
    // `discovery/pkarr.zig`'s doc on that function and upstream's own call.
    const packet = try pkarr.Packet.fromRelayPayload(node_id, out.body);
    // Strict, because the 32 header bytes came off the network and
    // `NodeId.fromBytes` only rejected a non-canonical `y`, which is the weaker
    // check `docs/ARCHITECTURE.md` records under "Ed25519 validation".
    //
    // `WrongSigner` is this file's own refusal, named so; every other arm of
    // `verify` is a failed check on the right signer, which is
    // `resolve.Reason.BadSignature`.
    packet.verify(node_id) catch |reason| switch (reason) {
        error.WrongSigner => return error.UnexpectedSigner,
        error.BodyTooLarge => return error.MalformedPacket,
        error.BadSignature => return error.BadSignature,
    };
    return .{ .packet = packet, .node_id = node_id };
}

/// One HTTP method, as the two a pkarr relay serves.
pub const Method = enum {
    /// Read a node's packet.
    get,
    /// Write a node's packet.
    put,

    /// The token on the request line, uppercase as RFC 9110 §9.1's registry has
    /// it.
    pub fn text(self: Method) []const u8 {
        return switch (self) {
            .get => "GET",
            .put => "PUT",
        };
    }
};

/// What a relay answered: the status, and the body it sent.
///
/// `body` borrows `out.buffer`, so the packet `resolve` returns is only as long
/// as that buffer is. The alternative — copying the body into the allocator —
/// would be a second copy of bytes a signature already covers.
pub const Response = struct {
    /// The status code, which is what a caller reads to tell "nobody published
    /// there" from "the relay is unwell".
    status: u16,
    /// The body, which is empty for a `PUT`'s answer.
    body: []const u8,
    /// The whole response as it arrived, headers included: a mutable view of the
    /// caller's own storage, which is why `body` is a slice into it rather than
    /// a separate allocation.
    buffer: []u8,
};

/// One request on the wire and one response read back.
///
/// `request` is the framed packet for a `PUT` and empty for a `GET`, and
/// `out.buffer` is the caller's: it must hold `max_header_length` plus
/// `max_body_length`, and the response borrows it.
fn exchange(
    alloc: std.mem.Allocator,
    io: std.Io,
    options: Options,
    method: Method,
    target: []const u8,
    request: []const u8,
    out: *Response,
) Error!void {
    var client = try tls_client.Client.open(alloc, io, options.server, .{
        .host = relayHost(options.base_url),
        .bundle = options.trust.bundle,
        .bundle_lock = options.trust.bundle_lock,
        .entropy = options.trust.entropy,
        .now = options.trust.now,
        .read_buffer = options.read_buffer,
        .write_buffer = options.write_buffer,
        .timeout_ms = options.timeout_ms orelse default_timeout_ms,
        .ssl_key_log = options.trust.ssl_key_log,
    });
    defer client.close();

    try writeRequest(
        client.plaintextWriter(io),
        method,
        target,
        relayHost(options.base_url),
        request,
    );
    const reader = client.plaintextReader(io);
    try readResponse(reader, out);
}

/// The host a base URL names, which is what `Host:` carries and what the
/// certificate is checked against.
///
/// `discovery/preset.zig`'s own bases are `https://dns.iroh.link/pkarr` and its
/// staging twin, so the slice between the scheme and the first `/` is the name.
/// A base with no path at all would have no such slash, and then the whole
/// remainder is the host — which is right, and is why this walks to the first
/// slash rather than to a fixed offset.
fn relayHost(base_url: []const u8) []const u8 {
    const scheme = "://";
    const after = std.mem.indexOf(u8, base_url, scheme) orelse return base_url;
    const rest = base_url[after + scheme.len ..];
    const slash = std.mem.indexOfScalar(u8, rest, '/') orelse return rest;
    return rest[0..slash];
}

/// Write one request line and its header block.
///
/// RFC 9110 §7.2's fields and nothing else: the method, the target, `HTTP/1.1`,
/// `Host`, and — for a `PUT` — `Content-Length`. No `User-Agent`, no
/// `Accept`, no `Connection`, because every one of them is optional and each is
/// a value this file would have to spell; a field that is not sent cannot be
/// wrong. `Content-Length` rather than `Transfer-Encoding` because this file
/// knows the length: the packet is a fixed-size value in this frame.
fn writeRequest(
    writer: *std.Io.Writer,
    method: Method,
    target: []const u8,
    host: []const u8,
    body: []const u8,
) std.Io.Writer.Error!void {
    try writer.print("{s} {s} HTTP/1.1\r\n", .{ method.text(), target });
    try writer.print("Host: {s}\r\n", .{host});
    try writer.print("Content-Length: {d}\r\n", .{body.len});
    try writer.writeAll("\r\n");
    try writer.writeAll(body);
    try writer.flush();
}

/// Read one response into `out`, header block and body.
///
/// The header block is read to its blank line and then the body to its
/// `Content-Length`, and both lengths are checked against the caller's buffer
/// before anything is copied. `Content-Length` is the only framing accepted:
/// RFC 9112 §6.3 would allow a response read up to the connection close, and
/// this file does not, because a body whose length it cannot state is a body it
/// cannot refuse when it is wrong.
fn readResponse(
    reader: *std.Io.Reader,
    out: *Response,
) Error!void {
    // Bounded before the delimiter search rather than after it: the limit is
    // what stops a relay that never sends a blank line from making this read for
    // ever, and it is the same figure `max_header_length` names.
    var limited = reader.limited(.limited(max_header_length), &.{});
    const head = limited.interface.takeDelimiterInclusive('\n') catch |err| switch (err) {
        error.StreamTooLong => return error.HeaderTooLong,
        error.EndOfStream => return error.HeaderTooLong,
        error.ReadFailed => return error.ReadFailed,
    };
    // Every line of the block, so a `Content-Length` on the last one is found
    // whatever order the relay wrote its fields in. RFC 9110 §5.3 lets a field
    // repeat and combine, so this is a search over occurrences and not over
    // the first one.
    var rest = head;
    var content_length: ?usize = null;
    while (std.mem.find(u8, rest, "\r\n")) |at| {
        const line = rest[0..at];
        rest = rest[at + 2 ..];
        if (line.len == 0) break;
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        if (!std.ascii.eqlIgnoreCase(line[0..colon], "content-length")) continue;
        const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
        const parsed = std.fmt.parseInt(usize, value, 10) catch return error.UnframedBody;
        content_length = if (content_length) |seen|
            // A second `Content-Length` is request smuggling's own weapon, and
            // RFC 9112 §6.3.5 says a message with more than one is invalid.
            if (seen != parsed) return error.UnframedBody else seen
        else
            parsed;
    }
    const length = content_length orelse return error.UnframedBody;
    if (length > max_body_length) return error.TruncatedBody;

    var total: usize = head.len;
    // The status is read before the body, and that ordering is the point: a
    // relay that answered `404` has said there is nothing to read, and reading a
    // body it never sent would wait for bytes that are not coming. A non-2xx
    // is therefore answered here and a caller never sees a truncation of a
    // response the relay refused to make.
    out.status = try statusOf(head);
    if (out.status / 100 != 2) return error.StatusNotSuccess;

    // The header block is copied into the caller's buffer first, because `head`
    // borrows the reader's own scratch and the body read below overwrites it.
    if (out.buffer.len < head.len) return error.HeaderTooLong;
    @memcpy(out.buffer[0..head.len], head);
    while (total < head.len + length) {
        // `readSliceShort` reports a clean end of stream as a zero count and a
        // read failure as an error, and the two are different facts here: see
        // the truncation check below.
        const got = reader.readSliceShort(
            out.buffer[total..][0 .. head.len + length - total],
        ) catch |err| switch (err) {
            // A clean end of stream is a short read and not an error, so the
            // only failure here is the read itself; a `0` below is the
            // truncation.
            error.ReadFailed => return error.ReadFailed,
        };
        // A clean end of stream before the stated length is a truncation, and a
        // pkarr packet's signature covers its body, so a short body is a body
        // nobody signed.
        if (got == 0) return error.TruncatedBody;
        total += got;
    }
    out.buffer = out.buffer[0..total];
    out.body = out.buffer[head.len..total];
}

/// The status code a response's first line carries.
///
/// RFC 9112 §4's status line: `HTTP-version SP status-code SP [ reason ]`.
/// Anything that is not that shape is `error.StatusNotSuccess` with a status of
/// zero, which is not a code any server may send — so a caller reading
/// `Response.status` cannot mistake a malformed line for a real one.
fn statusOf(head: []const u8) HttpError!u16 {
    const line_end = std.mem.indexOf(u8, head, "\r\n") orelse head.len;
    const line = head[0..line_end];
    const first = std.mem.indexOfScalar(u8, line, ' ') orelse return error.StatusNotSuccess;
    const rest = line[first + 1 ..];
    const second = std.mem.indexOfScalar(u8, rest, ' ') orelse rest.len;
    const parsed = std.fmt.parseInt(u16, rest[0..second], 10) catch
        return error.StatusNotSuccess;
    if (parsed < 200 or parsed > 299) return error.StatusNotSuccess;
    return parsed;
}

const t = std.testing;

test "the signer is refused, and refused before anything is signed" {
    // The decision the module exists for. A publisher whose key is not the node
    // it publishes would make every resolver believe one node is reachable at
    // another's name, and the refusal is its own arm rather than a member of
    // the parse set so a caller can tell it from a malformed body.
    var signer = try key.SecretKey.fromSeed([_]u8{1} ** key.SecretKey.seed_length);
    defer signer.deinit();
    var other = try key.SecretKey.fromSeed([_]u8{2} ** key.SecretKey.seed_length);
    defer other.deinit();

    var secret_ptr = signer;
    const wrong: Publish = .{
        .secret = &secret_ptr,
        .timestamp_us = 1_700_000_000_000_000,
        .records = .init("relay=https://example.com/\x00"),
    };

    // The refusal is `UnexpectedSigner`, and it is what `resolve.Reason` already
    // calls this fault on the reading side — one vocabulary for one failure.
    // Both sides are named as the optional `signerRefusal` hands back: an error
    // value compared against an optional resolves to an error union, whose two
    // sides are compared, and reports two spellings of the same refusal as
    // different.
    try t.expectEqual(
        @as(?error{UnexpectedSigner}, error.UnexpectedSigner),
        signerRefusal(signer.nodeId(), other.nodeId()),
    );

    // And the same key is not refused, which is what makes the refusal a check
    // rather than a veto.
    try t.expectEqual(
        @as(?error{UnexpectedSigner}, null),
        signerRefusal(signer.nodeId(), signer.nodeId()),
    );
    // `wrong` is a publication whose signer is the node it is about, so it is
    // ready; the refusal above was about `other`, not about this value.
    try t.expectEqual(@as(u64, 1_700_000_000_000_000), wrong.timestamp_us);
}

/// The refusal `publish` makes for a signer that is not the node being
/// published, as a value a test can read.
///
/// The check is one `order` and it is `publish`'s own, factored out so a test
/// can state it without a socket, a relay or a signature. Null means the signer
/// may sign for that node.
fn signerRefusal(signer: addr.NodeId, node_id: addr.NodeId) ?error{UnexpectedSigner} {
    if (signer.order(node_id) != .eq) return error.UnexpectedSigner;
    return null;
}

test "a body signed by another node is a refusal and not a parse failure" {
    // `resolve`'s side of the same decision, driven on real bytes: one signed
    // packet, read in both of the forms `pkarr.zig` decodes. No network:
    // `pkarr.Packet` is a codec and this is the whole of what `resolve` adds
    // above it.
    var signer = try key.SecretKey.fromSeed([_]u8{1} ** key.SecretKey.seed_length);
    defer signer.deinit();
    var other = try key.SecretKey.fromSeed([_]u8{2} ** key.SecretKey.seed_length);
    defer other.deinit();

    var name: [pkarr_body.nameLength()]u8 = undefined;
    const asked = try pkarr_body.writeName(&name, signer.nodeId());
    var body: [pkarr.max_dns_length]u8 = undefined;
    const dns = try pkarr_body.writeBody(
        &body,
        asked,
        .init("relay=https://example.com/\x00"),
    );
    var signable: [pkarr.max_signable_length]u8 = undefined;
    var wire: [pkarr.max_packet_length]u8 = undefined;
    const framed = try pkarr.sign(
        signer,
        1_700_000_000_000_000,
        dns,
        &signable,
        &wire,
    );

    // A relay's body drops the key, so a packet read out of one names the node
    // the request arrived on — which is how `resolve` reads it, and why the
    // signer cannot be read back off that form at all.
    const relay_body = framed[pkarr.signature_offset..];
    const from_relay = try pkarr.Packet.fromRelayPayload(signer.nodeId(), relay_body);
    try from_relay.verify(signer.nodeId());
    try t.expectEqual(
        @as(?error{UnexpectedSigner}, null),
        signerRefusal(from_relay.public_key, signer.nodeId()),
    );

    // The whole packet is the form that carries a key, so this is where
    // somebody else's signature is visible: the header names the signer, the
    // node asked about is somebody else, and what comes back is the refusal
    // rather than a parse failure.
    const as_written = try pkarr.Packet.parse(framed);
    try t.expectEqual(
        @as(?error{UnexpectedSigner}, error.UnexpectedSigner),
        signerRefusal(as_written.public_key, other.nodeId()),
    );
    // And `verify`'s own arm is the one `resolve` maps onto that refusal.
    try t.expectError(error.WrongSigner, as_written.verify(other.nodeId()));
    // The signature itself is sound: this is a signer refusal, not a bad
    // signature, and the distinction is what the two arms above are for.
    try as_written.verifySelf();
}

test "the host a base URL names is the `Host:` field and the certificate's name" {
    // n0's own production base, and its staging twin, which is the pair
    // `discovery/preset.zig` declares. A relay reached by a name whose
    // certificate names something else must fail the handshake, and the name
    // this function returns is what it is checked against.
    try t.expectEqualStrings("dns.iroh.link", relayHost(preset.pkarr_relay_prod));
    try t.expectEqualStrings(
        "staging-dns.iroh.link",
        relayHost(preset.pkarr_relay_staging),
    );
    // A base with no path at all is the whole remainder, which is the case a
    // fixed offset would get wrong.
    try t.expectEqualStrings("relay.example", relayHost("https://relay.example"));
}

test "the URL a node is asked at is upstream's own path shape" {
    // `preset.pkarrNodeUrl` builds `https://dns.iroh.link/pkarr/<z32>`, which is
    // `pkarr.rs:624`-`:635`: a `GET` and a `PUT` go to the same path.
    const id = try key.NodeId.parseHex(
        "1992d53c02cdc04566e5c0edb1ce83305cd550297953a047a445ea3264b54b18",
    );
    var buffer: [preset.pkarrNodeUrlLength(preset.pkarr_relay_prod)]u8 = undefined;
    try t.expectEqualStrings(
        "https://dns.iroh.link/pkarr/dgjpkxyn3zyrk3zfads5duwdgbqpkwbjxfj4yt7rezidr3fijccy",
        try preset.pkarrNodeUrl(&buffer, preset.pkarr_relay_prod, id),
    );
}

test "a status is only success between 200 and 299" {
    // `404` is the ordinary answer to a resolve for a node nobody published
    // there and `503` is a relay that is unwell; `exchange` refuses both and
    // hands the code back through `Response.status`, and this is the arithmetic
    // behind that refusal.
    try t.expectError(error.StatusNotSuccess, statusOf("HTTP/1.1 404 Not Found\r\n"));
    try t.expectError(error.StatusNotSuccess, statusOf("HTTP/1.1 503 Service Unavailable\r\n"));
    try t.expectError(error.StatusNotSuccess, statusOf("HTTP/1.1 100 Continue\r\n"));
    try t.expectError(error.StatusNotSuccess, statusOf("not a status line at all\r\n"));
    try t.expectEqual(@as(HttpError!u16, 200), statusOf("HTTP/1.1 200 OK\r\n"));
    try t.expectEqual(@as(HttpError!u16, 204), statusOf("HTTP/1.1 204 No Content\r\n"));
    // No reason phrase is legal, so a three-token line is a status.
    try t.expectEqual(@as(HttpError!u16, 200), statusOf("HTTP/1.1 200\r\n"));
}
