//! An independent oracle for the two handshake messages that open a TLS 1.3
//! flight in QUIC: RFC 8446 §4.1.2's ClientHello and §4.1.3's ServerHello.
//!
//! **What is under test.** Both parsers are private (`serverProcessClientHello`
//! and `clientProcessServerHello` are `fn`, not `pub fn`), so neither can be
//! named from here and neither is named. What is public and is exercised
//! instead is the whole surface a peer reaches them through: `initServerInto`,
//! `initClientInto`, `provideData`, `step`, and the fields the parse leaves
//! behind. Every refusal and every accepted field is checked against the RFC
//! below, so the coverage is of the message grammar rather than of a symbol.
//!
//! **What "accepted" means here is exact, not "did not crash".** A ClientHello
//! that parses has to leave behind the cipher suite the offer selected in the
//! client's own order, the group its key share chose, the peer's
//! `legacy_session_id` byte for byte, the protocol `negotiatedAlpn` reports,
//! and a state of `server_send_server_hello` — which is not `connected`. A
//! ServerHello that parses has to leave the client waiting for
//! EncryptedExtensions with handshake keys pending. Anything else is a finding
//! even though nothing panics.
//!
//! **The two decisions borrowed from other decoders, and why that is not a
//! hole.** A `quic_transport_parameters` payload is settled by calling the
//! transport-parameter decoder itself and then requiring exactly what the TLS
//! parser owes for that verdict; `TransportParams.decode` is a different
//! decoder, fuzzed exhaustively on its own, and what is under test here is the
//! TLS parser's reaction to its answer. A `server_name` payload is settled the
//! same way, and `messages.zig` is where that grammar's own oracle lives.
//!
//! **The one branch no wire oracle can close.** RFC 8446 §7.4.2 makes a key
//! share that yields no shared secret a refusal, and whether a well-formed
//! P-256 point multiplies is curve arithmetic on a secret this file does not
//! hold. X25519 is decidable without it — an all-zero product is a property of
//! the point's order, not of the scalar, so one fixed probe scalar answers for
//! every small-order point there is — and the P-256 branch is closed on
//! everything short of the scalar multiply, which is named here rather than
//! left as a silent gap.
//!
//! **What else is in this file, and why here.** RFC 7250's two certificate-type
//! extensions are settled in a ClientHello and in an EncryptedExtensions, so
//! their refusals are hello refusals on one side and `EncryptedExtensions`
//! refusals on the other — and the `EncryptedExtensions` decoder is just as
//! private as the two hello decoders. The named vectors below drive both ends
//! of a real handshake and read the verdict off `step`, which is the same
//! seam `drive` uses, so a vector and a fuzz input are judged the same way.
//! `messages.zig` owns the grammar of the two extension payloads themselves
//! and compares those against the RFC; what cannot move there is a message
//! that arrives in the middle of a flight.
//!
//! **Lengths the stack reads leniently.** A ClientHello's extension block is
//! clamped to the message and its walk stops at a header that does not close
//! rather than refusing; the ServerHello side, whose block is the message's
//! last field, does refuse a length past the end (RFC 8446 §4.1.3) and the
//! reference does too. `client_shares_len` is likewise not checked against the
//! share list it introduces, so the reference walks the shares as they arrive.
//! Both are reported leniencies, not assertions.
//!
//! The allocator is the driver's own and is where the ~52 KB handshake lives;
//! nothing else here reaches for it, and `deinit` is owed on a handshake that
//! ends in a refusal exactly as on one that completes. Entropy is a seeded
//! generator with a stable lifetime and the clock is one frozen instant, so a
//! run is a function of its input and the seed and nothing else — no `std.Io`,
//! no clock read, no global.

const std = @import("std");
const tls = std.crypto.tls;
const quic = @import("quic");
const tls13 = quic.tls13;
const transport_params = quic.transport_params;
const err = @import("der.zig");

/// The four test tags and `OutOfMemory` are `der.zig`'s, and the handshake's
/// own refusals join them rather than being mapped onto them. Every `step`
/// whose refusal an oracle arm predicted is compared against that prediction
/// and reported as a test tag; the one that is not — `drive`'s `.wait` arm,
/// where the flight has not all arrived and the RFC owes `wait_for_data` and
/// no reason at all — has nothing to be compared against, so it is re-raised
/// under its own name instead. That keeps it tellable from a flight that
/// simply made no progress, which is a test tag, and it leaves the caller
/// holding the arm that fired rather than four tags to choose between.
pub const Error = err.Error || tls13.HandshakeError;

const aes: u16 = @intFromEnum(tls.CipherSuite.AES_128_GCM_SHA256);
const chacha: u16 = @intFromEnum(tls.CipherSuite.CHACHA20_POLY1305_SHA256);
const x25519: u16 = @intFromEnum(tls.NamedGroup.x25519);
const secp256r1: u16 = @intFromEnum(tls.NamedGroup.secp256r1);
const key_share: u16 = @intFromEnum(tls.ExtensionType.key_share);
const alpn_ext: u16 = @intFromEnum(tls.ExtensionType.application_layer_protocol_negotiation);
const client_cert_type: u16 = @intFromEnum(tls.ExtensionType.client_certificate_type);
const server_cert_type: u16 = @intFromEnum(tls.ExtensionType.server_certificate_type);
const raw_public_key: u8 = @intFromEnum(tls13.negotiated_certificate_type);

/// The ceiling on the bytes a parser can see: `provideData` copies what fits the
/// handshake's own inbound buffer and drops the rest. Read off that field rather
/// than written here, so it cannot drift from `limits.tls_handshake_in`.
const inbound_len = @typeInfo(@FieldType(tls13.Tls13Handshake, "in_buf")).array.len;

/// One frozen instant: `step` differences it against a ticket's age and stamps
/// a ticket with it, and nothing else reads it. A fixed value makes a run a
/// function of its input alone.
const now_s: i64 = 1_788_000_000;
/// The project's documented wire-fuzz seed, so a failing input replays.
const seed: u64 = 0xdec0de;
/// The one protocol both ends speak. A single entry keeps the ALPN arithmetic
/// exact: "did the client's offer name a protocol this server speaks" is one
/// comparison, and it is also the whole of what `negotiatedAlpn` can report.
const offered = [_][]const u8{"ozai"};

/// The key a peer whose identity is an Ed25519 node id signs its
/// CertificateVerify with. A hello parse never reads the certificate chain and
/// never signs, so the only field this fixture really has to state is the
/// algorithm `signatureSchemeFor` is asked about.
const server_key: [32]u8 = @splat(0x53);

/// A big-endian u16 off two bytes the reference has already bounds checked,
/// written out rather than reached for so the oracle does not depend on which
/// `std.mem` signature the toolchain has.
fn be16(b: []const u8) u16 {
    return @as(u16, b[0]) << 8 | b[1];
}

/// A big-endian u16 written into two bytes of a buffer the caller has already
/// bounds checked. The writer to `be16`'s reader, and its own function rather
/// than a `std.mem` call: the vectors below close a peer's own length fields,
/// and a length this file writes with one library call and reads with another
/// is a length that can disagree with itself.
fn put16(b: []u8, v: usize) void {
    b[0] = @intCast((v >> 8) & 0xff);
    b[1] = @intCast(v & 0xff);
}

/// A cursor over one handshake body, so the rule RFC 8446 §4.2 states once — a
/// field that does not fit inside the message is a `decode_error`, never a read
/// past its end — is written once instead of at every field.
const Walk = struct {
    b: []const u8,
    p: usize = 0,

    fn byte(self: *Walk) tls13.HandshakeError!u8 {
        return (try self.take(1))[0];
    }
    fn pair(self: *Walk) tls13.HandshakeError!u16 {
        return be16(try self.take(2));
    }
    fn take(self: *Walk, n: usize) tls13.HandshakeError![]const u8 {
        if (n > self.b.len - self.p) return error.DecodeError;
        defer self.p += n;
        return self.b[self.p..][0..n];
    }
};

/// What the RFC says a hello means when it parses: the fields the handshake is
/// obliged to hold afterwards, and nothing else. `session_id` borrows the input,
/// which is also the check that it is the peer's own bytes.
const Accepted = struct {
    suite: u16,
    group: u16,
    session_id: []const u8,
    alpn: []const u8,
    early: bool,
    tp: bool,
    psk: bool,
    /// What RFC 7250 settled, one field per direction. `.x509` is what a
    /// hello that has not reached EncryptedExtensions still reads, on either
    /// end, and that is what the decoder's own two fields say at the same
    /// point: a ServerHello names neither, and a ClientHello that parsed
    /// names both.
    server_certificate_type: tls13.CertificateType,
    client_certificate_type: tls13.CertificateType,
};

/// `wait` is the one outcome that is neither a refusal nor an acceptance: the
/// flight has not all arrived, so it is not yet a message and the parser owes
/// nothing but to keep waiting.
const Verdict = union(enum) {
    wait,
    refuse: tls13.HandshakeError,
    accept: Accepted,
};

/// The one call a fuzz driver makes: `input` is a peer flight, verbatim, read
/// as a ClientHello by a server and as a ServerHello by a client.
pub fn check(gpa: std.mem.Allocator, input: []const u8) Error!void {
    try drive(true, gpa, input);
    try drive(false, gpa, input);
}

/// RFC 9001 §4.1.3's framing for both: a handshake message is a one-byte type
/// and a 24-bit length, and a message that has not all arrived is not a message.
/// What does not fit the handshake's own inbound buffer is dropped rather than
/// refused, so a flight past it is a stall, never a read past the end.
fn frame(input: []const u8, kind: tls.HandshakeType) error{UnexpectedMessage}!?[]const u8 {
    const d = input[0..@min(input.len, inbound_len)];
    if (d.len < 4) return null;
    const body_len = (@as(usize, d[1]) << 16) | (@as(usize, d[2]) << 8) | d[3];
    if (d.len < 4 + body_len) return null;
    if (d[0] != @intFromEnum(kind)) return error.UnexpectedMessage;
    return d[4..][0..body_len];
}

fn drive(comptime is_server: bool, gpa: std.mem.Allocator, input: []const u8) Error!void {
    const hs = try gpa.create(tls13.Tls13Handshake);
    defer gpa.destroy(hs);
    defer hs.deinit();
    var prng = std.Random.DefaultPrng.init(seed);
    const random = prng.random();
    const cfg: tls13.TlsConfig = if (is_server) .{
        .cert_chain_der = &.{},
        .private_key_bytes = &server_key,
        .private_key_algorithm = .ed25519,
        .alpn = &offered,
    } else .{ .cert_chain_der = &.{}, .private_key_bytes = &.{}, .alpn = &offered };
    if (is_server) {
        tls13.Tls13Handshake.initServerInto(hs, cfg, .{}, random) catch return error.TestUnexpectedResult;
    } else {
        tls13.Tls13Handshake.initClientInto(hs, cfg, .{}, random) catch return error.TestUnexpectedResult;
        // The ClientHello is what a ServerHello answers, so the parse under test
        // only begins once this client has sent one.
        _ = hs.step(now_s, random) catch return error.TestUnexpectedResult;
    }
    const want = verdict(is_server, input);
    hs.provideData(input);
    switch (want) {
        .wait => {
            // `step` answers with an action or a refusal, so the verdict is
            // read off the payload. This is the one arm where a refusal has
            // no prediction to be compared against: a flight that has not
            // all arrived is owed `wait_for_data` and nothing else, so the
            // refusal leaves `drive` under its own name rather than as a tag
            // that would say only that one happened.
            switch (try hs.step(now_s, random)) {
                .wait_for_data => {},
                else => return error.TestUnexpectedResult,
            }
            const wanted: @TypeOf(hs.state) =
                if (is_server) .server_wait_client_hello else .client_wait_server_hello;
            const held = hs.state == wanted;
            if (!held) return error.TestExpectedEqual;
        },
        .refuse => |e| {
            // The parser owes the refusal the reference predicted, so a decode
            // that answers with that same arm is the agreement this arm exists
            // to record and the check passes. One that answers with a
            // different arm has read a different fact about these bytes
            // (`TestExpectedError`, the two refusals are not the same fact),
            // and one that accepts bytes the reference condemns is
            // `TestUnexpectedError` — the same two tags the `.wait` arm above
            // uses for the same reasons.
            _ = hs.step(now_s, random) catch |a| {
                if (a != e) return error.TestExpectedError;
                return;
            };
            return error.TestUnexpectedError;
        },
        .accept => |fields| {
            _ = hs.step(now_s, random) catch return error.TestUnexpectedError;
            try agreed(is_server, hs, fields);
        },
    }
}

/// The RFC's verdict on a complete hello, in the terms `drive` acts on.
fn verdict(comptime is_server: bool, input: []const u8) Verdict {
    const maybe = frame(input, if (is_server) .client_hello else .server_hello) catch |e| return .{ .refuse = e };
    const body = maybe orelse return .wait;
    const fields = (if (is_server) clientHello(body) else serverHello(body)) catch |e| return .{ .refuse = e };
    return .{ .accept = fields };
}

/// What a parse must have recorded, whichever hello it was parsing. The suite is
/// the first one both ends implement, in the peer's order; the group is the one
/// whose share was usable; the session id is echoed back byte for byte; and the
/// two flags say whether the extensions this connection requires were there.
fn agreed(comptime is_server: bool, hs: *const tls13.Tls13Handshake, want: Accepted) Error!void {
    if (want.suite != aes and want.suite != chacha) return error.TestUnexpectedResult;
    if (want.group != x25519 and want.group != secp256r1) return error.TestUnexpectedResult;
    const chosen = hs.negotiated_cipher_suite;
    const suite_ok = if (want.suite == aes) chosen == .aes_128_gcm_sha256 else chosen == .chacha20_poly1305_sha256;
    const group_ok = if (want.group == x25519) hs.negotiated_group == .x25519 else hs.negotiated_group == .secp256r1;
    if (!suite_ok or !group_ok) return error.TestExpectedEqual;
    const echoed = hs.peer_session_id[0..hs.peer_session_id_len];
    if (!std.mem.eql(u8, echoed, want.session_id)) return error.TestExpectedEqual;
    if (!std.mem.eql(u8, hs.negotiatedAlpn(), want.alpn)) return error.TestExpectedEqual;
    if (hs.early_data_offered != want.early) return error.TestExpectedEqual;
    if ((hs.peer_transport_params != null) != want.tp) return error.TestExpectedEqual;
    // RFC 7250: the two fields are what the parse left behind, so a decoder
    // that read the offers and dropped them — or defaulted them to X.509
    // rather than refusing — is caught here and not at the certificate.
    if (hs.negotiated_server_certificate_type != want.server_certificate_type) return error.TestExpectedEqual;
    if (hs.negotiated_client_certificate_type != want.client_certificate_type) return error.TestExpectedEqual;
    // A hello that parsed is a hello the server is answering, and answering it
    // is not finishing the handshake; a ServerHello that parsed is where the
    // client has handshake keys to install and waits for EncryptedExtensions.
    if (is_server and hs.state != .server_send_server_hello) return error.TestExpectedEqual;
    if (is_server) return;
    if (hs.using_psk != want.psk) return error.TestExpectedEqual;
    if (!hs.pending_install_handshake) return error.TestExpectedEqual;
    if (hs.state != .client_wait_encrypted_extensions) return error.TestExpectedEqual;
}

/// RFC 8446 §4.1.2's ClientHello in wire order, with the QUIC requirements of
/// RFC 9001 §8.2 folded in where they bind: `key_share` and
/// `quic_transport_parameters` are both mandatory in QUIC, and a full handshake
/// needs a `signature_algorithms` this server's certificate can be verified
/// with.
fn clientHello(body: []const u8) tls13.HandshakeError!Accepted {
    var w: Walk = .{ .b = body };
    _ = try w.take(34); // legacy_version(2) + random(32)
    const session_id = try w.take(try w.byte());
    if (session_id.len > 32) return error.DecodeError; // §4.1.2's own ceiling
    const suites = try w.take(try w.pair());
    if (suites.len % 2 != 0) return error.DecodeError;
    var suite: u16 = 0;
    // §4.1.2: the server picks from what was offered, in the client's order, so
    // the first suite both ends implement is the one that is chosen.
    for (0..suites.len / 2) |i| {
        const id = be16(suites[i * 2 ..]);
        if (id != aes and id != chacha) continue;
        suite = id;
        break;
    }
    if (suite == 0) return error.UnsupportedVersion;
    _ = try w.take(try w.byte()); // legacy_compression_methods, §4.1.2's {0}
    const ext_len = try w.pair();
    const ext = w.b[w.p..][0..@min(@as(usize, ext_len), w.b.len - w.p)];

    var group: u16 = 0;
    var algs: ?[]const u8 = null;
    var early = false;
    var tp = false;
    // RFC 7250 §3, kept per direction so a second copy is tellable from a
    // first: null until one has been read and agreed to.
    var server_type: ?u8 = null;
    var client_type: ?u8 = null;
    var p: usize = 0;
    while (p + 4 <= ext.len) {
        const kind = be16(ext[p..]);
        const len = be16(ext[p + 2 ..]);
        if (p + 4 + len > ext.len) break; // §4.2: the walk stops, it does not refuse
        const data = ext[p + 4 ..][0..len];
        // Widened before the addition, as every other length in this file is:
        // the sum is in bytes, not in the two bytes the length was written in.
        // The bound above is what keeps `4 + len` inside a `u16` today — it is
        // `ext.len` at most, and a block length is itself a `u16` — but a peer
        // writing `ff fc` owes this walk the check above, not a wrapped sum on
        // the way to it.
        p += 4 + @as(usize, len);
        if (kind == key_share and len >= 2) {
            var s: usize = 2; // client_shares, whose own length is not checked
            while (s + 4 <= len) {
                const named = be16(data[s..]);
                const klen = be16(data[s + 2 ..]);
                s += 4;
                if (named == x25519 and klen == 32 and s + 32 <= len) {
                    group = x25519;
                    break;
                }
                if (named == secp256r1 and klen == 65 and s + 65 <= len) group = secp256r1;
                s += klen;
            }
        } else if (kind == @intFromEnum(tls.ExtensionType.quic_transport_parameters)) {
            const decoded = transport_params.TransportParams.decode(data);
            if (decoded) |_| tp = true else |_| return error.TransportParameterError;
        } else if (kind == @intFromEnum(tls.ExtensionType.application_layer_protocol_negotiation)) {
            // RFC 7301 §3.1 gives the list a `u16` length of its own and every
            // entry a `ProtocolName` of `opaque <1..2^8-1>` — "Empty strings
            // MUST NOT be included" — so a body too short to hold the length
            // is a decode error rather than an offer with nothing in it, and
            // an entry of no length is a decode error rather than a name.
            if (len < 2) return error.DecodeError;
            // What is left is the one question §3.1 leaves this server: does
            // the client's list name the one protocol this server offers?
            // One that does not is RFC 7301's own `no_application_protocol`.
            if (!try namesProtocol(data, offered[0])) return error.NoApplicationProtocol;
        } else if (kind == @intFromEnum(tls.ExtensionType.signature_algorithms)) {
            // RFC 8446 §4.2.3's `SignatureScheme supported_signature_algorithms<2..2^16-1>`
            // is measured against a byte count, so the peer's length is read as
            // a `usize`: a peer that writes `ff ff` names a list longer than any
            // buffer, and adding two to it in a `u16` would overflow before the
            // comparison could answer that.
            if (len < 2 or @as(usize, be16(data)) + 2 != len or len % 2 != 0) return error.DecodeError;
            algs = data[2..];
        } else if (kind == @intFromEnum(tls.ExtensionType.server_name)) {
            // `messages.zig` owns that grammar's oracle; what is checked here is
            // only that a payload the parser calls malformed is a decode_error.
            if (tls13.parseServerNameExtension(data)) |_| {} else |_| return error.DecodeError;
        } else if (kind == @intFromEnum(tls.ExtensionType.early_data)) {
            early = true;
        } else if (kind == client_cert_type or kind == server_cert_type) {
            const to_server = kind == server_cert_type;
            if ((if (to_server) server_type else client_type) != null) return error.IllegalParameter;
            // §3: a one-byte count and that many one-byte types, the count
            // being the vector's own length.
            if (len < 2) return error.DecodeError;
            // Widened before the addition: at `u8` a peer writing `ff` would
            // overflow the count instead of earning the decode_error its
            // length does.
            const count: usize = data[0];
            if (count == 0 or count + 1 != len) return error.DecodeError;
            const offer = data[1..];
            const has_raw_key = std.mem.indexOfScalar(u8, offer, raw_public_key) != null;
            if (!has_raw_key) return error.UnsupportedCertificate;
            if (to_server) server_type = raw_public_key else client_type = raw_public_key;
        }
    }
    if (group == 0) return error.NoKeyShare;
    // §4.1 makes an absent extension an implicit X.509, and this server has
    // no X.509 to fall back to, so an absent offer is the refusal rather than
    // a default. It is settled where the decoder settles it — after the key
    // share — so a hello wrong in both ways is reported for the same one here
    // as there.
    _ = server_type orelse return error.MissingExtension;
    _ = client_type orelse return error.MissingExtension;
    if (!tp) return error.MissingExtension; // RFC 9001 §8.2
    const signer_algs = algs orelse return error.MissingExtension;
    if (tls13.signatureSchemeFor(.ed25519, signer_algs) == null) return error.HandshakeFailure;
    return .{
        .suite = suite,
        .group = group,
        .session_id = session_id,
        .alpn = offered[0],
        .early = early,
        .tp = tp,
        .psk = false,
        .server_certificate_type = .raw_public_key,
        .client_certificate_type = .raw_public_key,
    };
}

/// Whether an RFC 7301 §3.1 `ProtocolNameList` names `name`, walked as the
/// parser walks it: an entry that does not close ends the walk, and a walk
/// that ends without a match is a miss rather than a decode error. An entry
/// of no length is a different thing from both — it is not a name at all —
/// so it is refused where the walk meets it and refused before any match is
/// looked for, because the name this server would have matched it with is a
/// caller's own list and may be of no length too.
fn namesProtocol(data: []const u8, name: []const u8) tls13.HandshakeError!bool {
    // RFC 7301 §3.1 names the list's length in a `u16` and this walk measures
    // it against a cursor, so it is widened here: in `u16` the bound would
    // overflow on a peer that wrote `ff ff`, which is a list of 65535 entries
    // rather than the arithmetic a peer can reach.
    const list_len: usize = be16(data);
    var q: usize = 2;
    while (q < 2 + list_len and q < data.len) {
        const n = data[q];
        q += 1;
        if (n == 0) return error.DecodeError;
        if (q + n > data.len) return false;
        if (n == name.len and std.mem.eql(u8, data[q..][0..n], name)) return true;
        q += n;
    }
    return false;
}

/// RFC 8446 §4.1.3's ServerHello. The extension block is the message's last
/// field, so a length past the end is one this side cannot honour — a hostile
/// peer chooses it — and is a `decode_error` rather than a slice taken past the
/// message.
fn serverHello(body: []const u8) tls13.HandshakeError!Accepted {
    var w: Walk = .{ .b = body };
    _ = try w.take(34);
    _ = try w.take(try w.byte()); // the echo of the client's own legacy_session_id
    if (w.p + 3 > w.b.len) return error.DecodeError;
    const suite = be16(w.b[w.p..]);
    w.p += 3; // cipher_suite(2) + compression_method(1)
    if (suite != aes and suite != chacha) return error.UnsupportedVersion;
    const ext_len = try w.pair();
    if (ext_len > w.b.len - w.p) return error.DecodeError;
    const ext = w.b[w.p..][0..ext_len];

    var group: u16 = 0;
    var share: []const u8 = &.{};
    var psk = false;
    var p: usize = 0;
    while (p + 4 <= ext.len) {
        const kind = be16(ext[p..]);
        const len = be16(ext[p + 2 ..]);
        const at = p + 4;
        if (at + len > ext.len) return error.DecodeError;
        const data = ext[at..][0..len];
        p = at + len;
        if (kind == key_share) {
            if (len < 4) return error.DecodeError;
            const named = be16(data);
            const klen = be16(data[2..]);
            // The share is inside this extension and nothing else is. RFC 8446
            // §4.2.8 puts the `KeyShareEntry` in the `key_share` extension, so
            // the header and the share have to fit in `len` and not merely
            // somewhere in the block behind it. This is *stricter* than the
            // decoder, which spells the bound `ext_pos + 4 + 32 <= ext_data.len`
            // against the rest of the block and so accepts a `key_share` whose
            // own length is shorter than the share it read — the share then
            // comes out of the extension behind it, which is not bytes the peer
            // sent as a key share. The RFC settles it in favour of the bound
            // below, so the bound below stays and the leniency is a finding to
            // report against the decoder rather than one to mirror here.
            if (named == x25519 and klen == 32 and len >= 36) {
                group = x25519;
                share = data[4..][0..32];
            } else if (named == secp256r1 and klen == 65 and len >= 69) {
                group = secp256r1;
                share = data[4..][0..65];
            } else return error.NoKeyShare;
        } else if (kind == @intFromEnum(tls.ExtensionType.pre_shared_key) and len >= 2) {
            // RFC 8446 §4.2.11: selected_identity 0 is the first offer. This
            // client offered no ticket, so the flag records an intent to resume
            // that is checked against `using_psk` rather than trusted.
            if (be16(data) == 0) psk = true;
        }
    }
    if (group == 0) return error.NoKeyShare;
    try usable(group, share);
    return .{
        .suite = suite,
        .group = group,
        .session_id = &.{},
        .alpn = offered[0],
        .early = false,
        .tp = false,
        .psk = psk,
        // RFC 7250 §4.2 settles both types in EncryptedExtensions, which this
        // message is not: a client that has read a ServerHello has negotiated
        // nothing yet, and its two fields still read RFC 7250 §4.1's default.
        .server_certificate_type = .x509,
        .client_certificate_type = .x509,
    };
}

/// RFC 8446 §7.4.2: a key share that produces no shared secret is refused. For
/// X25519 that is decidable from the wire alone — the product is zero exactly
/// when the peer's u-coordinate has order dividing eight, a property of the
/// point and not of the scalar — so one fixed probe answers for every
/// small-order point. For P-256 the point is checked against the curve and the
/// remaining scalar multiply is the branch this file cannot close from bytes.
fn usable(group: u16, share: []const u8) tls13.HandshakeError!void {
    if (group != x25519) {
        // A P-256 share is a SEC-1 point or it is not a share at all, and
        // `fromSec1` refuses a point that is not on the curve rather than
        // answering with an optional.
        _ = std.crypto.ecc.P256.fromSec1(share) catch return error.KeyScheduleError;
        return;
    }
    const probe: [32]u8 = @splat(0x0a);
    var point: [32]u8 = undefined;
    @memcpy(&point, share);
    const shared = std.crypto.dh.X25519.scalarmult(probe, point) catch return error.KeyScheduleError;
    if (std.mem.eql(u8, &shared, &[_]u8{0} ** 32)) return error.KeyScheduleError;
}

// ── Wire vectors ──

/// Everything both ends wrote, copied. `Action.send_data.data` borrows the
/// handshake's own output buffer and the next `step` overwrites it, so a
/// vector that edits a flight has to own its bytes before it edits anything —
/// and the fixed sizes are the message ceilings this stack builds into, so a
/// flight that does not fit is a fixture that grew wrong rather than a
/// handshake that failed.
const Flight = struct {
    hello: [4096]u8 = undefined,
    hello_len: usize = 0,
    server_hello: [512]u8 = undefined,
    server_len: usize = 0,
    extensions: [1024]u8 = undefined,
    extensions_len: usize = 0,
};

/// A client and a server, each ~52 KB and so on the heap. They live together
/// because every vector below is about what one end wrote and what the other
/// end did with it, and `gpa` is the driver's own — the reason this leaf is
/// the one of the three that is handed an allocator.
const Pair = struct {
    client: *tls13.Tls13Handshake,
    server: *tls13.Tls13Handshake,

    fn create(gpa: std.mem.Allocator, random: std.Random) Error!Pair {
        return createWith(gpa, random, clientConfig(), serverConfig(false));
    }

    /// The same two handshakes from configs of the caller's, for a vector
    /// whose claim is about the policy either end was built with rather than
    /// about the wire. The two allocations and the deinit order are this
    /// struct's own, as they are above.
    fn createWith(
        gpa: std.mem.Allocator,
        random: std.Random,
        client_cfg: tls13.TlsConfig,
        server_cfg: tls13.TlsConfig,
    ) Error!Pair {
        const client = try gpa.create(tls13.Tls13Handshake);
        errdefer gpa.destroy(client);
        const server = try gpa.create(tls13.Tls13Handshake);
        errdefer gpa.destroy(server);
        tls13.Tls13Handshake.initClientInto(client, client_cfg, .{}, random) catch
            return error.TestUnexpectedResult;
        tls13.Tls13Handshake.initServerInto(server, server_cfg, .{}, random) catch
            return error.TestUnexpectedResult;
        return .{ .client = client, .server = server };
    }

    fn destroy(self: *const Pair, gpa: std.mem.Allocator) void {
        self.client.deinit();
        self.server.deinit();
        gpa.destroy(self.client);
        gpa.destroy(self.server);
    }

    /// Runs the handshake as far as the client waiting for EncryptedExtensions
    /// and keeps everything both ends wrote. The client is left there with the
    /// ServerHello consumed and its handshake keys taken, so what it is fed
    /// next — the real EncryptedExtensions or an edited copy — is answered by
    /// that message and not by the key install standing in front of it.
    fn toEncryptedExtensions(self: *Pair, random: std.Random, out: *Flight) Error!void {
        const hello = try sentData(self.client, random) orelse return error.TestUnexpectedResult;
        if (hello.len > out.hello.len) return error.TestUnexpectedResult;
        @memcpy(out.hello[0..hello.len], hello);
        out.hello_len = hello.len;

        self.server.provideData(out.hello[0..out.hello_len]);
        try serverFlight(self.server, random, out);
        self.client.provideData(out.server_hello[0..out.server_len]);
        try driveUntilWaiting(self.client, random);
    }
};

/// A server's first two messages, copied out of its own output buffer: the
/// ServerHello and the EncryptedExtensions that follows the handshake keys it
/// installs in between. Those keys are the one step that sends nothing, so the
/// walk is bounded rather than "until something arrives" — a server that never
/// reaches the second message is a fixture, not a vector.
fn serverFlight(server: *tls13.Tls13Handshake, random: std.Random, out: *Flight) Error!void {
    var steps: usize = 0;
    while (steps < 8) : (steps += 1) {
        const sent = try sentData(server, random) orelse continue;
        if (sent[0] == @intFromEnum(tls.HandshakeType.encrypted_extensions)) {
            if (sent.len > out.extensions.len) return error.TestUnexpectedResult;
            @memcpy(out.extensions[0..sent.len], sent);
            out.extensions_len = sent.len;
            return;
        }
        if (out.server_len == 0) {
            if (sent.len > out.server_hello.len) return error.TestUnexpectedResult;
            @memcpy(out.server_hello[0..sent.len], sent);
            out.server_len = sent.len;
        }
    }
    return error.TestUnexpectedResult;
}

/// Steps a handshake until it is waiting for more of the peer's flight, and
/// refuses one that never gets there.
///
/// RFC 8446 §7.1 makes `step` answer with derived keys before it does anything
/// else, and this stack owes them in two steps rather than one:
/// `clientProcessServerHello` returns the internal `_continue` and sets
/// `pending_install_handshake`, and the `step` after it is the one that answers
/// `install_keys`. A walk that stopped at the first action which was not
/// `install_keys` stopped one step early — `_continue` is an action the caller
/// is handed, not a loop of its own — and the message it fed next was answered
/// with those keys instead of with a verdict on the message.
///
/// `wait_for_data` is where the walk ends and it is the documented end: "call
/// repeatedly until it answers `wait_for_data` or `complete`". A `send_data`
/// on the way means the handshake moved past the message the caller meant to
/// test, and `complete` means there is nothing left to feed it.
fn driveUntilWaiting(hs: *tls13.Tls13Handshake, random: std.Random) Error!void {
    var steps: usize = 0;
    while (steps < 8) : (steps += 1) {
        const action = try hs.step(now_s, random);
        switch (action) {
            // Neither is a verdict on a message: one is the state machine
            // saying it consumed one and is going round again, the other is keys
            // it derived and owes the connection before it reads under them.
            ._continue, .install_keys => continue,
            .wait_for_data => return,
            .send_data, .complete => return error.TestUnexpectedResult,
        }
    }
    return error.TestUnexpectedResult;
}

/// The client this file's vectors connect from: one protocol, no SNI, and a
/// pin on a node id no fixture here owns, so a vector that reaches a
/// certificate is refused for the peer rather than for its certificate type.
fn clientConfig() tls13.TlsConfig {
    return .{
        .cert_chain_der = &.{},
        .private_key_bytes = &.{},
        .alpn = &offered,
        .expect_peer_node_id = pinned,
    };
}

/// The server: one protocol, an Ed25519 key to sign with, and — when
/// `ask_client_certificate` is set — the policy that makes it send a
/// CertificateRequest, which is what RFC 7250 §4.2 makes the condition on
/// naming `client_certificate_type`.
fn serverConfig(ask_client_certificate: bool) tls13.TlsConfig {
    return .{
        .cert_chain_der = &.{},
        .private_key_bytes = &server_key,
        .private_key_algorithm = .ed25519,
        .alpn = &offered,
        .client_auth = if (ask_client_certificate) &no_node else null,
    };
}

/// The node id the client vectors pin. Nobody presents it.
const pinned: [32]u8 = @splat(0x77);

/// The node id the wrong-peer vector wraps in a perfectly well-formed
/// `SubjectPublicKeyInfo`. It is not `pinned`: a certificate carrying the
/// pinned key is the one answer this stack accepts, and a vector built from
/// it would assert nothing.
const somebody_elses_node: [32]u8 = @splat(0x21);

/// A policy that wants a certificate from a client we do not name, so a
/// server built from it asks for one and RFC 7250 §4.2 has it name a type.
const no_node: tls13.ClientAuth = .{ .expect_node_id = null, .mode = .required };

/// A policy that names the node the client vectors pin and lets a client
/// that presents no certificate through anyway: `.optional` is the mode and
/// `expect_node_id` is the pin, and they are separate fields because they
/// say two different things about a client.
const pin_and_optional: tls13.ClientAuth = .{ .expect_node_id = pinned, .mode = .optional };

/// The same policy with no node named, which is the one case `.optional` is
/// written for: a client may have no certificate, and then nothing at all is
/// known about it.
const optional_and_no_pin: tls13.ClientAuth = .{ .expect_node_id = null, .mode = .optional };

/// The bytes one `step` sends, or null when it sent none — which is what the
/// handshake-key steps answer, and not a failure.
fn sentData(hs: *tls13.Tls13Handshake, random: std.Random) Error!?[]const u8 {
    const action = try hs.step(now_s, random);
    return switch (action) {
        .send_data => |sd| sd.data,
        else => null,
    };
}

/// The refusal one `step` answers with, against the one the vector expects.
/// A step that answers at all is `TestUnexpectedError`: the vector was built to
/// be refused, and completing is the finding it exists to catch.
fn expectRefusal(
    hs: *tls13.Tls13Handshake,
    want: tls13.HandshakeError,
    random: std.Random,
) Error!void {
    if (hs.step(now_s, random)) |_| {
        return error.TestUnexpectedError;
    } else |actual| {
        if (actual != want) return error.TestExpectedError;
    }
}

/// A server under `auth`, its own ClientHello answered and its whole first
/// flight written out, stopped where it waits for the client's Certificate.
///
/// The flight is not inspected beyond the one thing that has to be true of
/// it: it carried the CertificateRequest, which is the record this server
/// sends on its own and the thing that makes an answer owed at all. What the
/// walk expects is `send_data` — a handshake putting a flight on the wire is
/// not a verdict on a message — and `wait_for_data` is where it ends, which
/// is the end `driveUntilWaiting` documents for the other side of a flight.
fn serverAwaitingClientCertificate(
    gpa: std.mem.Allocator,
    random: std.Random,
    auth: *const tls13.ClientAuth,
) Error!Pair {
    var cfg = serverConfig(false);
    cfg.client_auth = auth;
    var pair = try Pair.createWith(gpa, random, clientConfig(), cfg);
    errdefer pair.destroy(gpa);
    // A policy in force needs somewhere to keep the certificate it accepts;
    // `serverProcessClientHello` refuses a policy it cannot honour rather
    // than asking for an allocator it was not given.
    pair.server.allocator = gpa;
    var flight: Flight = .{};
    const hello = try sentData(pair.client, random) orelse return error.TestUnexpectedResult;
    if (hello.len > flight.hello.len) return error.TestUnexpectedResult;
    @memcpy(flight.hello[0..hello.len], hello);
    flight.hello_len = hello.len;
    pair.server.provideData(flight.hello[0..flight.hello_len]);

    var steps: usize = 0;
    var asked = false;
    out: while (steps < 12) : (steps += 1) {
        switch (try pair.server.step(now_s, random)) {
            .send_data => |sd| asked = asked or
                (sd.data.len > 0 and sd.data[0] == @intFromEnum(tls.HandshakeType.certificate_request)),
            ._continue, .install_keys => {},
            .wait_for_data => break :out,
            .complete => return error.TestUnexpectedResult,
        }
    } else return error.TestUnexpectedResult;
    if (!asked) return error.TestUnexpectedResult;
    // The one writer of this state is the Finished that followed the request,
    // so this is a point where a Certificate is what the handshake waits for.
    if (pair.server.state != .server_wait_client_certificate) return error.TestExpectedEqual;
    return pair;
}

/// Where RFC 8446 §4.1.2's ClientHello body puts its `extensions<0..2^16-1>`:
/// legacy_version(2), random(32), legacy_session_id(1+n), cipher_suites(2+n),
/// legacy_compression_methods(1+n), and then the block, which is the message's
/// last field.
///
/// The index it answers with is the message's own — past the four-byte
/// handshake header, which is what `encryptedExtensionsBlockAt` does on the
/// other message — because every caller reads the block out of the message it
/// was handed and not out of a body window, and the four bytes between the two
/// are the difference between the block and the tail of the field before it.
/// Null when the message does not reach it, which is a vector built from the
/// wrong bytes rather than a verdict to assert.
fn clientHelloBlockAt(msg: []const u8) ?usize {
    // Hardening rather than a witnessed fix: every caller hands this the
    // handshake's own ClientHello, so the four handshake-header bytes are
    // there today and nothing reaches the slice below without them. The
    // promise above is a null for a message that does not reach the block, and
    // `msg[4..]` on a shorter message answers that with a slice panic rather
    // than with null — so the sibling's guard is repeated here in its shape,
    // and the per-field bounds below start after it.
    const body = if (msg.len < 4) {
        return null;
    } else msg[4..];
    // Every length is widened to a byte count before it is added to: the
    // session id and the compression list are each a `u8` count, and a peer
    // writing `ff` must answer with a null here and not a wrapped index.
    var p: usize = 34; // legacy_version + random
    if (body.len < p + 1) return null;
    p += 1 + @as(usize, body[p]); // legacy_session_id, empty over QUIC (RFC 9001 §4.1.2)
    if (p + 2 > body.len) return null;
    p += 2 + @as(usize, be16(body[p..])); // cipher_suites
    if (p + 1 > body.len) return null;
    p += 1 + @as(usize, body[p]); // legacy_compression_methods
    if (p + 2 > body.len) return null;
    return p + 4;
}

/// Where RFC 8446 §4.2.8's EncryptedExtensions body puts its block: the block
/// is the whole body, so its two-byte length is the first field after the
/// handshake header. That is the index `clientHelloBlockAt` answers for a
/// ClientHello — the length field, in the message's own coordinates — and it
/// is the index `extensionIn` and `editBlock` both take, so a block is read off
/// either message the same way rather than by remembering which one moved.
fn encryptedExtensionsBlockAt(msg: []const u8) ?usize {
    if (msg.len < 6) return null;
    return 4;
}

/// What `editBlock` does to the extension of type `kind`.
const Edit = enum {
    /// Take it out of the message, and close every length that closed it.
    drop,
    /// Put a second copy of it at the end of the block, so the message now
    /// carries two of the same extension — RFC 8446 §4.2's own prohibition.
    repeat,
};

/// `msg` with one extension edited, in `out`. `at` is the block's own index in
/// the message — what `clientHelloBlockAt` and `encryptedExtensionsBlockAt`
/// answer, both of which count from the message rather than from its body —
/// and `out` is the caller's buffer, which is longer than the message and is
/// written past the message's end when the edit grows the block. Every length
/// the edit moved is closed again: the block's own two bytes and the message's
/// three (RFC 9001 §4.1.2's framing). Both vectors need that three-step
/// arithmetic and a vector refused for a stale length would prove the length
/// checks rather than the rule it was built for, so it is written once.
fn editBlock(msg: []const u8, at: usize, kind: u16, edit: Edit, out: []u8) Error![]const u8 {
    if (msg.len > out.len) return error.TestUnexpectedResult;
    @memcpy(out[0..msg.len], msg);
    if (at + 2 > msg.len) return error.TestUnexpectedResult;
    // The block is the last field of both messages this touches, so its own
    // length has to close what is behind it — and what is behind it ends with
    // the message, not with the caller's buffer, which is longer and would make
    // every block look short by the difference. A message whose block does not
    // close is a fixture built wrong, and refusing to edit it says so instead
    // of producing a vector that proves nothing.
    const block_len = msg.len - at - 2;
    if (@as(usize, be16(out[at..])) != block_len) return error.TestUnexpectedResult;

    // Everything the walk touches is past the block's own two-byte length, so
    // `at` addresses that length and the first extension header is `base`.
    // Walking from `at` itself would read the length as a type and the first
    // header as a length.
    const base = at + 2;
    var q: usize = 0;
    var kept: usize = 0;
    var found: usize = 0;
    var found_len: usize = 0;
    var seen = false;
    while (q + 4 <= block_len) {
        const this = be16(out[base + q ..]);
        const len = be16(out[base + q + 2 ..]);
        if (q + 4 + len > block_len) return error.TestUnexpectedResult;
        if (this == kind) {
            found = q;
            found_len = len;
            seen = true;
        }
        const keep = switch (edit) {
            .drop => this != kind,
            .repeat => true,
        };
        if (keep) {
            // A kept extension that has not moved is already where it belongs,
            // and one that has — the first kept one after a dropped extension —
            // is written over bytes this walk has already read. Overlapping
            // copies are what `@memmove` is for; `@memcpy` is not one.
            if (kept != q) {
                @memmove(out[base + kept ..][0 .. 4 + len], out[base + q ..][0 .. 4 + len]);
            }
            kept += 4 + @as(usize, len);
        }
        q += 4 + @as(usize, len);
    }
    if (q != block_len or !seen) return error.TestUnexpectedResult;

    if (edit == .repeat) {
        // The second copy lands after everything kept, so the block grows and
        // the caller's buffer has to have room for it. `found` is counted from
        // the block like every other index here; the copy it reads is inside
        // the block and the copy it writes starts where the block ends, so
        // these two do not overlap.
        if (base + kept + 4 + found_len > out.len) return error.TestUnexpectedResult;
        @memcpy(out[base + kept ..][0 .. 4 + found_len], out[base + found ..][0 .. 4 + found_len]);
        kept += 4 + found_len;
    }

    put16(out[at..], kept);
    const body_len = at + 2 + kept - 4;
    out[1] = @intCast(body_len >> 16);
    out[2] = @intCast((body_len >> 8) & 0xff);
    out[3] = @intCast(body_len & 0xff);
    return out[0 .. 4 + body_len];
}

/// `msg` with the payload of its ALPN extension replaced by `payload`, in
/// `out`. `at` is the block's own index in the message, as
/// `clientHelloBlockAt` and `encryptedExtensionsBlockAt` answer it, and
/// `out` is the caller's buffer.
///
/// The one edit `editBlock` does not do: `drop` and `repeat` move whole
/// extensions and keep every payload, while the vectors here rewrite one
/// payload's bytes and so change its length — the offer grows by the entry
/// §3.1 forbids, the selection shrinks onto a name of no length. Every
/// length that moved is closed again (the extension's own two bytes, the
/// block's two, and the message's three), or the refusal these vectors read
/// would be a length check rather than the rule they were built for.
fn rewriteAlpn(msg: []const u8, at: usize, payload: []const u8, out: []u8) Error![]const u8 {
    if (msg.len > out.len) return error.TestUnexpectedResult;
    if (at + 2 > msg.len) return error.TestUnexpectedResult;
    @memcpy(out[0..msg.len], msg);
    // Both messages this touches close their block at the message's end —
    // see `editBlock`, which is where that is argued — so a block that does
    // not close here means a fixture built wrong, and refusing to edit it
    // says so instead of producing a vector that proves nothing.
    const block_len = msg.len - at - 2;
    if (@as(usize, be16(out[at..])) != block_len) return error.TestUnexpectedResult;

    const base = at + 2;
    var q: usize = 0;
    var old_len: usize = 0;
    var seen = false;
    while (q + 4 <= block_len) {
        const this = be16(out[base + q ..]);
        const len = be16(out[base + q + 2 ..]);
        if (q + 4 + len > block_len) return error.TestUnexpectedResult;
        if (this == alpn_ext) {
            old_len = len;
            seen = true;
            break;
        }
        q += 4 + @as(usize, len);
    }
    if (!seen) return error.TestUnexpectedResult;
    // Two of the lengths written below are `u16` — the extension's own and
    // the block's — and `put16` truncates rather than refusing, so a payload
    // with no encoding for them is a fixture built wrong and says so here
    // rather than as a refusal about a length.
    const kept = block_len - old_len + payload.len;
    if (payload.len > std.math.maxInt(u16) or kept > std.math.maxInt(u16)) {
        return error.TestUnexpectedResult;
    }
    // Everything behind this extension closes over it, so the copy that
    // shifts that tail overlaps what it writes and `@memcpy` is not what it
    // is for.
    const tail = block_len - q - 4 - old_len;
    @memmove(out[base + q + 4 + payload.len ..][0..tail], out[base + q + 4 + old_len ..][0..tail]);
    @memcpy(out[base + q + 4 ..][0..payload.len], payload);
    put16(out[base + q + 2 ..], payload.len);

    put16(out[at..], kept);
    const body_len = at + 2 + kept - 4;
    out[1] = @intCast(body_len >> 16);
    out[2] = @intCast((body_len >> 8) & 0xff);
    out[3] = @intCast(body_len & 0xff);
    return out[0 .. 4 + body_len];
}

/// The payload of the first extension of type `kind` in `block`. Generic over
/// the block's mutability, because a vector reads what the peer sent and then
/// rewrites a copy of it: handing a read-only window back for a rewrite would
/// mean a cast, and a cast is where a vector stops being the peer's bytes.
///
/// Null when the block carries no such extension, which in a vector asserting
/// that it does is a failure and not a skip.
fn extensionIn(comptime T: type, block: []T, kind: u16) ?[]T {
    var q: usize = 0;
    while (q + 4 <= block.len) {
        const this = be16(block[q..]);
        const len = be16(block[q + 2 ..]);
        if (q + 4 + len > block.len) return null;
        if (this == kind) return block[q + 4 ..][0..len];
        q += 4 + @as(usize, len);
    }
    return null;
}

/// RFC 8446 §4.4.2's Certificate carrying `der` as its one and only entry,
/// written out rather than reached for: under RFC 7250 §3 that entry is a
/// `SubjectPublicKeyInfo` and not a certificate, and it is exactly the bytes
/// this stack is refusing or accepting.
fn certificateMessage(out: []u8, der: []const u8) Error![]const u8 {
    const entry_len = 3 + der.len + 2;
    const body_len = 1 + 3 + entry_len;
    if (out.len < 4 + body_len) return error.TestUnexpectedResult;
    out[0] = @intFromEnum(tls.HandshakeType.certificate);
    out[1] = 0;
    out[2] = @intCast(body_len >> 8);
    out[3] = @intCast(body_len & 0xff);
    out[4] = 0; // certificate_request_context, empty
    out[5] = @intCast(entry_len >> 16);
    out[6] = @intCast((entry_len >> 8) & 0xff);
    out[7] = @intCast(entry_len & 0xff);
    out[8] = @intCast(der.len >> 16);
    out[9] = @intCast((der.len >> 8) & 0xff);
    out[10] = @intCast(der.len & 0xff);
    @memcpy(out[11..][0..der.len], der);
    put16(out[11 + der.len ..], 0); // the entry's own empty extensions
    return out[0 .. 4 + body_len];
}

/// RFC 8446 §4.4.2's answer to a CertificateRequest a client cannot meet: an
/// empty `certificate_list`, with no CertificateVerify after it. These are
/// the bytes this stack's own client writes when it holds no key the request
/// could use, so a server handed them is being handed its client's real
/// answer rather than a fixture of nobody's.
const empty_certificate = [_]u8{
    @intFromEnum(tls.HandshakeType.certificate),
    0,
    0,
    4, // body length
    0, // certificate_request_context, empty
    0,
    0,
    0, // certificate_list, empty
};

test "RFC 7250: both ends put both certificate-type extensions on the wire" {
    const gpa = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(seed);
    const random = prng.random();
    var pair = try Pair.create(gpa, random);
    defer pair.destroy(gpa);
    var flight: Flight = .{};
    try pair.toEncryptedExtensions(random, &flight);

    // The ClientHello carries both, each a single-entry list naming the raw
    // key. Asserted against the RFC's own bytes rather than against
    // `encodeCertificateTypeOffer`, so a builder that drifts from the RFC is
    // caught here and not agreed with by the check beside it.
    const block_at = clientHelloBlockAt(flight.hello[0..flight.hello_len]) orelse
        return error.TestUnexpectedResult;
    const hello_block = flight.hello[0..flight.hello_len];
    inline for (.{ client_cert_type, server_cert_type }) |kind| {
        const payload = extensionIn(u8, hello_block[block_at + 2 ..], kind) orelse
            return error.TestUnexpectedResult;
        if (!std.mem.eql(u8, payload, &[_]u8{ 1, raw_public_key })) return error.TestExpectedEqual;
    }

    // And the EncryptedExtensions settles `server_certificate_type` — always —
    // and `client_certificate_type` only where RFC 7250 §4.2 says to, which is
    // where a CertificateRequest follows.
    const extensions = flight.extensions[0..flight.extensions_len];
    const ee_block_at = encryptedExtensionsBlockAt(extensions) orelse
        return error.TestUnexpectedResult;
    const ee_block = extensions[ee_block_at + 2 ..];
    const selected = extensionIn(u8, ee_block, server_cert_type) orelse
        return error.TestUnexpectedResult;
    if (!std.mem.eql(u8, selected, &[_]u8{raw_public_key})) return error.TestExpectedEqual;
    if (extensionIn(u8, ee_block, client_cert_type) != null) return error.TestExpectedEqual;

    // With a policy in force the CertificateRequest follows, §4.2's condition
    // is met, and the client's own type is named too — against the same
    // ClientHello, so the difference between the two EncryptedExtensions is
    // the policy and not the fixture.
    var asking = try gpa.create(tls13.Tls13Handshake);
    defer {
        asking.deinit();
        gpa.destroy(asking);
    }
    tls13.Tls13Handshake.initServerInto(asking, serverConfig(true), .{}, random) catch
        return error.TestUnexpectedResult;
    // A policy in force needs somewhere to keep the certificate it accepts;
    // this handshake never reaches one, and `serverProcessClientHello` refuses
    // a policy it cannot honour rather than asking for an allocator it was
    // not given.
    asking.allocator = gpa;
    asking.provideData(flight.hello[0..flight.hello_len]);
    var asked: Flight = .{};
    try serverFlight(asking, random, &asked);
    const asked_at = encryptedExtensionsBlockAt(asked.extensions[0..asked.extensions_len]) orelse
        return error.TestUnexpectedResult;
    const asked_block = asked.extensions[0..asked.extensions_len][asked_at + 2 ..];
    const asked_client = extensionIn(u8, asked_block, client_cert_type) orelse
        return error.TestUnexpectedResult;
    if (!std.mem.eql(u8, asked_client, &[_]u8{raw_public_key})) return error.TestExpectedEqual;
    // ... and the server's own selection is unchanged by that policy.
    const asked_server = extensionIn(u8, asked_block, server_cert_type) orelse
        return error.TestUnexpectedResult;
    if (!std.mem.eql(u8, asked_server, &[_]u8{raw_public_key})) return error.TestExpectedEqual;
}

test "RFC 7250: a ClientHello without the offers is refused, not defaulted to X.509" {
    const gpa = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(seed);
    const random = prng.random();
    var pair = try Pair.create(gpa, random);
    defer pair.destroy(gpa);
    var flight: Flight = .{};
    try pair.toEncryptedExtensions(random, &flight);
    const at = clientHelloBlockAt(flight.hello[0..flight.hello_len]) orelse
        return error.TestUnexpectedResult;

    // Both, and then one at a time: §4.1's default is per extension, and a
    // check that dropped both at once could not tell which one the refusal
    // came from.
    inline for (.{ client_cert_type, server_cert_type }) |kind| {
        var edited: [4096]u8 = undefined;
        const msg = try editBlock(flight.hello[0..flight.hello_len], at, kind, .drop, &edited);
        var server = try gpa.create(tls13.Tls13Handshake);
        defer {
            server.deinit();
            gpa.destroy(server);
        }
        tls13.Tls13Handshake.initServerInto(server, serverConfig(false), .{}, random) catch
            return error.TestUnexpectedResult;
        server.provideData(msg);
        try expectRefusal(server, error.MissingExtension, random);
    }
}

test "RFC 7250: an offer that names X.509 is refused, and so is a second copy of one" {
    const gpa = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(seed);
    const random = prng.random();
    var pair = try Pair.create(gpa, random);
    defer pair.destroy(gpa);
    var flight: Flight = .{};
    try pair.toEncryptedExtensions(random, &flight);
    const at = clientHelloBlockAt(flight.hello[0..flight.hello_len]) orelse
        return error.TestUnexpectedResult;

    inline for (.{ client_cert_type, server_cert_type }) |kind| {
        // §4.2's outcome 2: the offer is there and names nothing in common.
        // Only the one byte changes, so every length stays right and the
        // refusal has to be about the type.
        var rewritten: [4096]u8 = undefined;
        @memcpy(rewritten[0..flight.hello_len], flight.hello[0..flight.hello_len]);
        const payload = extensionIn(u8, rewritten[at + 2 ..], kind) orelse
            return error.TestUnexpectedResult;
        payload[1] = @intFromEnum(tls13.CertificateType.x509);
        var server = try gpa.create(tls13.Tls13Handshake);
        defer {
            server.deinit();
            gpa.destroy(server);
        }
        tls13.Tls13Handshake.initServerInto(server, serverConfig(false), .{}, random) catch
            return error.TestUnexpectedResult;
        server.provideData(rewritten[0..flight.hello_len]);
        try expectRefusal(server, error.UnsupportedCertificate, random);

        // And RFC 8446 §4.2's one-copy rule, which is what stops the first
        // offer from being followed by one that says something else.
        var edited: [4096]u8 = undefined;
        const doubled = try editBlock(
            flight.hello[0..flight.hello_len],
            at,
            kind,
            .repeat,
            &edited,
        );
        var dup = try gpa.create(tls13.Tls13Handshake);
        defer {
            dup.deinit();
            gpa.destroy(dup);
        }
        tls13.Tls13Handshake.initServerInto(dup, serverConfig(false), .{}, random) catch
            return error.TestUnexpectedResult;
        dup.provideData(doubled);
        try expectRefusal(dup, error.IllegalParameter, random);
    }
}

test "a server that selects a certificate type this client never offered is refused" {
    const gpa = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(seed);
    const random = prng.random();
    var pair = try Pair.create(gpa, random);
    defer pair.destroy(gpa);
    var flight: Flight = .{};
    try pair.toEncryptedExtensions(random, &flight);
    const at = encryptedExtensionsBlockAt(flight.extensions[0..flight.extensions_len]) orelse
        return error.TestUnexpectedResult;

    // One byte changes, so every enclosing length stays right and the refusal
    // cannot be a length check. RFC 7250 §4.2 makes a type the client never
    // offered an illegal parameter, and it is the receiving half of a
    // downgrade to a certificate this client cannot read a key out of.
    var rewritten: [1024]u8 = undefined;
    @memcpy(rewritten[0..flight.extensions_len], flight.extensions[0..flight.extensions_len]);
    const selection = extensionIn(u8, rewritten[at + 2 ..], server_cert_type) orelse
        return error.TestUnexpectedResult;
    selection[0] = @intFromEnum(tls13.CertificateType.x509);
    pair.client.provideData(rewritten[0..flight.extensions_len]);
    try expectRefusal(pair.client, error.IllegalParameter, random);
}

test "a server that names no certificate type is refused, not read as X.509" {
    const gpa = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(seed);
    const random = prng.random();
    var pair = try Pair.create(gpa, random);
    defer pair.destroy(gpa);
    var flight: Flight = .{};
    try pair.toEncryptedExtensions(random, &flight);
    const at = encryptedExtensionsBlockAt(flight.extensions[0..flight.extensions_len]) orelse
        return error.TestUnexpectedResult;

    // RFC 7250 §4.1: an absent extension is an implicit X.509, and this
    // client has no X.509 verifier — so the handshake ends here, before any
    // certificate is read at all. Dropping the extension is the whole of the
    // vector: the lengths behind it are closed again, so what is refused is
    // the missing selection and not a truncated message.
    var edited: [1024]u8 = undefined;
    const without = try editBlock(
        flight.extensions[0..flight.extensions_len],
        at,
        server_cert_type,
        .drop,
        &edited,
    );
    pair.client.provideData(without);
    try expectRefusal(pair.client, error.MissingExtension, random);
}

test "a server that selects a protocol this client never offered is refused" {
    const gpa = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(seed);
    const random = prng.random();
    var pair = try Pair.create(gpa, random);
    defer pair.destroy(gpa);
    var flight: Flight = .{};
    try pair.toEncryptedExtensions(random, &flight);
    const at = encryptedExtensionsBlockAt(flight.extensions[0..flight.extensions_len]) orelse
        return error.TestUnexpectedResult;

    // RFC 7301 §3.1: exactly one protocol, and it has to be one this client
    // offered. The name is rewritten in place — same length, so no enclosing
    // length moves — which is what makes this the client's own check and not a
    // mismatch between two fixtures that never agreed in the first place.
    var rewritten: [1024]u8 = undefined;
    @memcpy(rewritten[0..flight.extensions_len], flight.extensions[0..flight.extensions_len]);
    const payload = extensionIn(
        u8,
        rewritten[at + 2 ..],
        @intFromEnum(tls.ExtensionType.application_layer_protocol_negotiation),
    ) orelse return error.TestUnexpectedResult;
    const name = payload[3..];
    if (!std.mem.eql(u8, name, offered[0])) return error.TestUnexpectedResult;
    @memcpy(name, "evil");
    pair.client.provideData(rewritten[0..flight.extensions_len]);
    try expectRefusal(pair.client, error.IllegalParameter, random);
}

test "RFC 7301: a server offering no protocol at all refuses the ClientHello that named one" {
    const gpa = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(seed);
    const random = prng.random();
    // The client's own first flight, taken here and not out of a driven pair:
    // `sentData` borrows the handshake's own output buffer and the next `step`
    // overwrites it, so this is the one point at which the bytes are whole,
    // and nothing has run on the server side of them yet. `clientConfig`
    // offers `offered`, so this hello names the one protocol below.
    var offering = try gpa.create(tls13.Tls13Handshake);
    defer {
        offering.deinit();
        gpa.destroy(offering);
    }
    tls13.Tls13Handshake.initClientInto(offering, clientConfig(), .{}, random) catch
        return error.TestUnexpectedResult;
    var flight: Flight = .{};
    const hello = try sentData(offering, random) orelse return error.TestUnexpectedResult;
    if (hello.len > flight.hello.len) return error.TestUnexpectedResult;
    @memcpy(flight.hello[0..hello.len], hello);
    flight.hello_len = hello.len;
    const at = clientHelloBlockAt(flight.hello[0..flight.hello_len]) orelse
        return error.TestUnexpectedResult;

    // The offer is on the wire, and it names the one protocol this file's
    // client speaks. That is what makes this the case §3.2's rule is about:
    // an extension present and a list in it, rather than a ClientHello that
    // named no protocol at all and so never advertised anything to answer.
    const payload = extensionIn(u8, flight.hello[at + 2 ..], alpn_ext) orelse
        return error.TestUnexpectedResult;
    if (!try namesProtocol(payload, offered[0])) return error.TestUnexpectedResult;

    // The last lane retired: this file's own server with its offer list
    // emptied, which is the state `quic_bridge`'s withdrawal leaves a node in
    // once every protocol has been withdrawn. RFC 7301 §3.2 is explicit about
    // that case — "In the event that the server supports no protocols that the
    // client advertises, then the server SHALL respond with a fatal
    // no_application_protocol alert" — and an empty list supports none.
    var serving_nothing = serverConfig(false);
    serving_nothing.alpn = &.{};
    var server = try gpa.create(tls13.Tls13Handshake);
    defer {
        server.deinit();
        gpa.destroy(server);
    }
    tls13.Tls13Handshake.initServerInto(server, serving_nothing, .{}, random) catch
        return error.TestUnexpectedResult;

    // The real ClientHello, the bytes above, handed to it whole. The refusal
    // has to be the answer to that message rather than something this side
    // does once the connection is up: `expectRefusal` fails on any action, and
    // the first action a server has for a parsed ClientHello is the ServerHello
    // this vector is saying it must not write.
    server.provideData(flight.hello[0..flight.hello_len]);
    try expectRefusal(server, error.NoApplicationProtocol, random);
}

test "RFC 7301: a ClientHello that names no protocol is answered without one" {
    const gpa = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(seed);
    const random = prng.random();

    // The other half of the rule above, and the one a fix for it must not take
    // with it: §3.2 conditions the alert on a client that *advertises*, and a
    // ClientHello carrying no ALPN extension advertises nothing. Both ends
    // here offer no protocol, which is agreement rather than a disagreement.
    var offering_nothing = clientConfig();
    offering_nothing.alpn = &.{};
    var serving_nothing = serverConfig(false);
    serving_nothing.alpn = &.{};
    var client = try gpa.create(tls13.Tls13Handshake);
    defer {
        client.deinit();
        gpa.destroy(client);
    }
    var server = try gpa.create(tls13.Tls13Handshake);
    defer {
        server.deinit();
        gpa.destroy(server);
    }
    tls13.Tls13Handshake.initClientInto(client, offering_nothing, .{}, random) catch
        return error.TestUnexpectedResult;
    tls13.Tls13Handshake.initServerInto(server, serving_nothing, .{}, random) catch
        return error.TestUnexpectedResult;

    var flight: Flight = .{};
    const hello = try sentData(client, random) orelse return error.TestUnexpectedResult;
    if (hello.len > flight.hello.len) return error.TestUnexpectedResult;
    @memcpy(flight.hello[0..hello.len], hello);
    flight.hello_len = hello.len;
    const at = clientHelloBlockAt(flight.hello[0..flight.hello_len]) orelse
        return error.TestUnexpectedResult;

    // Read off the wire rather than off the config: a client with an empty
    // offer list has to leave the extension out entirely, because a present
    // extension with no entry in it is a list no peer wrote.
    const asked = flight.hello[at + 2 ..];
    if (extensionIn(u8, asked, alpn_ext) != null) return error.TestExpectedEqual;

    // And so the server answers, rather than refusing a hello that asked for
    // nothing: the flight is produced, and its EncryptedExtensions selects no
    // protocol either.
    server.provideData(flight.hello[0..flight.hello_len]);
    try serverFlight(server, random, &flight);
    const ee = encryptedExtensionsBlockAt(flight.extensions[0..flight.extensions_len]) orelse
        return error.TestUnexpectedResult;
    if (flight.extensions_len < ee + 2) return error.TestUnexpectedResult;
    const selected = flight.extensions[0..flight.extensions_len][ee + 2 ..];
    if (extensionIn(u8, selected, alpn_ext) != null) return error.TestExpectedEqual;
}

test "RFC 7301: an offered protocol name of no length is refused" {
    const gpa = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(seed);
    const random = prng.random();

    // The client's own first flight, taken here rather than out of a driven
    // pair for the reason the vector above gives: `sentData` borrows the
    // handshake's own output buffer and the next `step` overwrites it.
    // `clientConfig` offers `offered`, so this hello names one protocol and
    // is otherwise a ClientHello a server here would answer.
    var offering = try gpa.create(tls13.Tls13Handshake);
    defer {
        offering.deinit();
        gpa.destroy(offering);
    }
    tls13.Tls13Handshake.initClientInto(offering, clientConfig(), .{}, random) catch
        return error.TestUnexpectedResult;
    var flight: Flight = .{};
    const hello = try sentData(offering, random) orelse return error.TestUnexpectedResult;
    if (hello.len > flight.hello.len) return error.TestUnexpectedResult;
    @memcpy(flight.hello[0..hello.len], hello);
    flight.hello_len = hello.len;
    const at = clientHelloBlockAt(flight.hello[0..flight.hello_len]) orelse
        return error.TestUnexpectedResult;
    const original = extensionIn(u8, flight.hello[at + 2 ..], alpn_ext) orelse
        return error.TestUnexpectedResult;
    if (original.len < 3) return error.TestUnexpectedResult;
    const name = original[3..];
    if (original[2] != name.len or !std.mem.eql(u8, name, offered[0])) {
        return error.TestUnexpectedResult;
    }

    // RFC 7301 §3.1 spells an offer as a `u16` list of `ProtocolName`s, each
    // `opaque <1..2^8-1>`, and says "Empty strings MUST NOT be included". This
    // list breaks that rule: an entry of no length first, then the one
    // protocol the rest of this hello is about. The order is the point — a
    // decoder that hunted for a match without reading the list would find
    // `offered[0]` and answer about that, so what is refused here has to be
    // the empty entry and not a protocol this server could have selected.
    // Every length the rewrite moved is closed again by `rewriteAlpn`.
    var payload: [4 + offered[0].len]u8 = undefined;
    payload[0] = 0;
    payload[1] = @intCast(2 + offered[0].len); // the list's own length
    payload[2] = 0; // the entry §3.1 forbids
    payload[3] = @intCast(offered[0].len);
    @memcpy(payload[4..], offered[0]);
    var edited: [4096]u8 = undefined;
    const msg = try rewriteAlpn(flight.hello[0..flight.hello_len], at, &payload, &edited);

    // Two servers, and the second is why this is a vector rather than a
    // check of one decoder: `TlsConfig` is a public struct a caller can fill
    // with a name of no length, and this stack is built with one wherever
    // the transport above it chooses to check. An entry like that pairs with
    // the peer's empty entry byte for byte, so a selection walk that looks
    // for a match before it reads the list records no protocol at all and
    // this handshake goes on to write a ServerHello.
    const alpn_configs = [_][]const []const u8{ offered[0..], &.{""} };
    for (alpn_configs) |alpn| {
        var cfg = serverConfig(false);
        cfg.alpn = alpn;
        var server = try gpa.create(tls13.Tls13Handshake);
        defer {
            server.deinit();
            gpa.destroy(server);
        }
        tls13.Tls13Handshake.initServerInto(server, cfg, .{}, random) catch
            return error.TestUnexpectedResult;
        server.provideData(msg);
        try expectRefusal(server, error.DecodeError, random);
    }
}

test "RFC 7301: a server that selects a protocol of no length is refused" {
    const gpa = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(seed);
    const random = prng.random();
    var pair = try Pair.create(gpa, random);
    defer pair.destroy(gpa);
    var flight: Flight = .{};
    try pair.toEncryptedExtensions(random, &flight);
    const at = encryptedExtensionsBlockAt(flight.extensions[0..flight.extensions_len]) orelse
        return error.TestUnexpectedResult;

    // RFC 7301 §3.1 types the selection's one name as `opaque <1..2^8-1>`
    // and says empty strings must not be included, so `{0, 1, 0}` — a list
    // of one byte naming nothing at all — is not a selection of the empty
    // protocol. Those three bytes are the whole payload: a `u16` list length
    // of one, and a name length of none.
    var rewritten: [1024]u8 = undefined;
    const msg = try rewriteAlpn(
        flight.extensions[0..flight.extensions_len],
        at,
        &[_]u8{ 0, 1, 0 },
        &rewritten,
    );

    // The refusal is about those bytes and not about this client's list: the
    // same payload naming a protocol this client did not offer is
    // `illegal_parameter`, which is the check the membership loop below the
    // decode makes. A selection of no length has no spelling to be wrong
    // about, so it must never reach that loop — and it must not, because a
    // caller's own list may hold an empty name for it to match, and a match
    // there would leave `selected_alpn_len` at zero, which is what
    // `negotiatedAlpn` reads as "nothing was selected" and falls back from.
    pair.client.provideData(msg);
    try expectRefusal(pair.client, error.DecodeError, random);
    if (pair.client.selected_alpn_len != 0) return error.TestExpectedEqual;
}

test "a peer whose key is not the node this client pinned is refused" {
    const gpa = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(seed);
    const random = prng.random();
    var pair = try Pair.create(gpa, random);
    defer pair.destroy(gpa);
    var flight: Flight = .{};
    try pair.toEncryptedExtensions(random, &flight);

    // The real EncryptedExtensions first: the walk has to get past it and on
    // to the Certificate, or this vector would be proving the extension check
    // it already has a vector for. What it does not do is compare the client's
    // state here — the claim is the refusal below, and it can only be this one
    // if the EncryptedExtensions was accepted and the walk really did reach the
    // certificate, so a premise that did not hold fails on the claim.
    pair.client.provideData(flight.extensions[0..flight.extensions_len]);
    try driveUntilWaiting(pair.client, random);

    // A well-formed `SubjectPublicKeyInfo` around somebody else's node id.
    // Under RFC 7250 this is a legal certificate — the grammar is not what is
    // wrong with it — so it is the pin that refuses it, which is the whole of
    // the identity model and the reason it is a separate vector from the ones
    // above.
    const foreign = tls13.ed25519Spki(&somebody_elses_node);
    var buf: [256]u8 = undefined;
    const msg = try certificateMessage(&buf, &foreign);
    pair.client.provideData(msg);
    try expectRefusal(pair.client, error.BadCertificate, random);
}

test "a policy that pins a node does not let a client through with no certificate" {
    const gpa = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(seed);
    const random = prng.random();
    var pair = try serverAwaitingClientCertificate(gpa, random, &pin_and_optional);
    defer pair.destroy(gpa);

    // This server asked, and this is its client's real answer to that ask.
    // Letting it through completes a connection this server authenticated
    // only as the server: `.optional` is about what to do with a client that
    // has no certificate, and `expect_node_id` is about which node has to be
    // the one on the other end. The policy carries both, and the pin is not
    // waived by the mode.
    pair.server.provideData(&empty_certificate);
    try expectRefusal(pair.server, error.CertificateRequired, random);
}

test "a policy that pins no node lets a client through with no certificate" {
    const gpa = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(seed);
    const random = prng.random();
    var pair = try serverAwaitingClientCertificate(gpa, random, &optional_and_no_pin);
    defer pair.destroy(gpa);

    // The same server, the same request and the same eight bytes, one field
    // of the policy apart. This is the half of the rule a pin must not take
    // with it: `.optional` means a client with no certificate is let through,
    // and the handshake then waits for that client's Finished — a flight that
    // carries on, not a connection this server said anything about its peer.
    pair.server.provideData(&empty_certificate);
    switch (try pair.server.step(now_s, random)) {
        // One message consumed and a state machine going round again.
        ._continue => {},
        else => return error.TestUnexpectedResult,
    }
    switch (try pair.server.step(now_s, random)) {
        .wait_for_data => {},
        else => return error.TestUnexpectedResult,
    }
    if (pair.server.state != .server_wait_client_finished) return error.TestExpectedEqual;
}
