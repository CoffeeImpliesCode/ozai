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
    var p: usize = 0;
    while (p + 4 <= ext.len) {
        const kind = be16(ext[p..]);
        const len = be16(ext[p + 2 ..]);
        if (p + 4 + len > ext.len) break; // §4.2: the walk stops, it does not refuse
        const data = ext[p + 4 ..][0..len];
        p += 4 + len;
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
        } else if (kind == @intFromEnum(tls.ExtensionType.application_layer_protocol_negotiation) and len >= 2) {
            // This server offers one protocol, so the only question RFC 7301
            // §3.1 leaves is whether the client's list names it; one that does
            // not is RFC 7301's own `no_application_protocol`.
            if (!namesProtocol(data, offered[0])) return error.NoApplicationProtocol;
        } else if (kind == @intFromEnum(tls.ExtensionType.signature_algorithms)) {
            if (len < 2 or be16(data) + 2 != len or len % 2 != 0) return error.DecodeError;
            algs = data[2..];
        } else if (kind == @intFromEnum(tls.ExtensionType.server_name)) {
            // `messages.zig` owns that grammar's oracle; what is checked here is
            // only that a payload the parser calls malformed is a decode_error.
            if (tls13.parseServerNameExtension(data)) |_| {} else |_| return error.DecodeError;
        } else if (kind == @intFromEnum(tls.ExtensionType.early_data)) early = true;
    }
    if (group == 0) return error.NoKeyShare;
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
    };
}

/// Whether an RFC 7301 §3.1 `ProtocolNameList` names `name`, walked as the
/// parser walks it: an entry that does not close ends the walk, and a walk that
/// ends without a match is a miss rather than a decode error.
fn namesProtocol(data: []const u8, name: []const u8) bool {
    // RFC 7301 §3.1 names the list's length in a `u16` and this walk measures
    // it against a cursor, so it is widened here: in `u16` the bound would
    // overflow on a peer that wrote `ff ff`, which is a list of 65535 entries
    // rather than the arithmetic a peer can reach.
    const list_len: usize = be16(data);
    var q: usize = 2;
    while (q < 2 + list_len and q < data.len) {
        const n = data[q];
        q += 1;
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
