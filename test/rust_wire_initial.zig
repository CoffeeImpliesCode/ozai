//! A captured QUIC v1 Initial from the Rust partner, read end to end: the
//! long header, the Initial keys it derives, header protection, the AEAD, a
//! bounded walk of the CRYPTO frames, and the TLS 1.3 server that answers the
//! ClientHello inside them.
//!
//! **What is captured.** `corpus/rust_wire/rust_client_initial.hex` is the
//! 1200-byte `peer-inbound` datagram at sequence 0 of
//! `evidence/capture-w1-native-listener-after-role-predicate-fix`, byte for
//! byte and hex-encoded so a diff of the corpus is legible.
//! `corpus/rust_wire/provenance.json` says which run produced it, what ran,
//! and which of the vectors built on it are that capture and which are edits
//! derived from it. Nothing in this file synthesises a datagram.
//!
//! **What is under test.** The four layers a stranger's UDP datagram crosses
//! before it is a handshake. `PacketNumSpace.setupInitial` — which is
//! `crypto.deriveInitialKeyMaterial` and nothing else, deriving from the
//! destination connection id that is on the wire, with no clock, no entropy
//! and no allocation. `packet.parseQuicHeader` and `packet.decrypt`, which
//! borrow the caller's buffer and unprotect it in place. A walk of the
//! payload's frames that is bounded by the CRYPTO offsets they declare. And
//! `tls13.Tls13Handshake` on what that walk reassembled.
//!
//! **What is asserted.** The things a peer has no freedom about: the protocol
//! RFC 7301 §3.2 makes both ends agree on, the certificate types RFC 7250 §3
//! settles in the hello, the group the client's own key share named, and
//! whether the server answered at all — read off the bytes it emitted, since
//! the name RFC 7301 requires it to echo is in them, and not off `state`,
//! which is a transition this file has no business naming. The independent
//! RFC 8446 reference in `tls_wire/hello.zig` then judges the same handshake
//! bytes and has to reach the same conclusion.
//!
//! **What is derived, not captured.** The certificate-type negatives edit the
//! *decrypted* hello, and the key-domain negative names a different
//! connection id. All three are mutations this file makes and nothing else,
//! and `provenance.json` classifies them that way wherever they appear.

const std = @import("std");
const tls = std.crypto.tls;
const quic = @import("quic");
const frame = quic.frame;
const hello = @import("tls_wire/hello.zig");
const packet = quic.packet;
const tls13 = quic.tls13;

/// The capture, in hex. See `corpus/rust_wire/provenance.json`.
pub const capture_hex = @embedFile("corpus/rust_wire/rust_client_initial.hex");

/// The length the capture is pinned at, which is also RFC 9000 §14's floor
/// for a client's first datagram and this core's `packet.MAX_PACKET_LEN`'s
/// neighbour. It is the only thing `decodeCapture` takes on faith: the hex
/// must spell this many bytes, so a corpus file that is not this capture is
/// refused rather than half-decoded.
pub const capture_len = 1200;

/// The one protocol the capture's ALPN extension offers, and the one the run
/// it came from had both ends speaking.
pub const fixture_alpn = "/ozai/w1-fixture";

/// RFC 7250 §3's two certificate-type extensions, as `tls.ExtensionType`
/// numbers them. Written out rather than read through `std`, for the reason
/// `tls13.zig` writes its own comptime check of them: a peer's dispatch is
/// keyed on these two values.
pub const client_certificate_type_ext: u16 = 19;
pub const server_certificate_type_ext: u16 = 20;

/// RFC 9001 §5.4.2: the header-protection sample begins four bytes after the
/// packet number. Fixed by the RFC, so it is a constant here rather than
/// something read off a packet.
pub const sample_offset = 4;

/// One frozen instant and one seed, so a run is a function of its input and
/// the seed and nothing else — no `std.Io`, no clock read, no global.
const now_s: i64 = 1_788_000_000;
const seed: u64 = 0xdec0de;

/// The key this fixture signs with. A hello parse never reads a certificate
/// chain and never signs, so the one field the config really has to state is
/// the algorithm `signatureSchemeFor` is asked about — and the capture's own
/// `signature_algorithms` names Ed25519, which is what settles that scheme.
const server_key: [32]u8 = @splat(0x53);

/// The one protocol the server offers. A single entry keeps RFC 7301 §3.2's
/// selection exact: whether the client's list names a protocol this side
/// speaks is one comparison.
const offered = [_][]const u8{fixture_alpn};

/// What this file's own decoding can refuse. Every arm is a name one of the
/// four layers above already produces, so a caller can tell a wire refusal
/// from one of this file's bounds without consulting a decoder. The four
/// after `InvalidVersion` are this file's own: the corpus file, the
/// reassembly bound, the derived offer edit, and the output buffer.
pub const WireError = error{
    // `packet.parseQuicHeader`
    BufferTooShort,
    EndOfStream,
    InvalidPacket,
    NoSpaceLeft,
    PacketError,
    VarIntTooLarge,
    // `packet.PacketNumSpace.setupInitial`
    InvalidVersion,
    // `packet.decrypt`
    UndecryptablePacket,
    AuthenticationFailed,
    // `frame.Frame.parseSized`
    FrameEncodingError,
    // this file's own bounds
    CaptureNotHex,
    CaptureLength,
    CryptoDataOutOfRange,
    CertificateOfferMalformed,
    AlpnTooLong,
};

/// What `serverVerdict` can refuse: the handshake's own set, plus the two it
/// adds — the caller's output buffer for the negotiated name, and the
/// allocator the handshake's own buffers live in.
pub const VerdictError = error{ OutOfMemory, AlpnTooLong } || tls13.HandshakeError;

/// What `fuzzOne` reports: a defect in this file's reading, or a
/// disagreement between the vendored TLS parser and the independent RFC 8446
/// reference in `hello.zig` about the same handshake bytes.
pub const Error = WireError || hello.Error;

/// The captured datagram, out of its hex spelling and into `out`.
///
/// Two hex digits are one byte and no other character is accepted: a corpus
/// file that is not this capture is refused here rather than decoded as
/// whatever it happens to be. The newline that ends the file is checked
/// rather than forgiven, for the same reason.
pub fn decodeCapture(out: []u8) WireError![]u8 {
    const digits = 2 * capture_len;
    if (capture_hex.len != digits + 1 or capture_hex[digits] != '\n') return error.CaptureLength;
    var i: usize = 0;
    while (i < digits) : (i += 2) {
        const high = try hexDigit(capture_hex[i]);
        const low = try hexDigit(capture_hex[i + 1]);
        out[i / 2] = high * 16 + low;
    }
    return out[0..capture_len];
}

/// One hex digit, or the refusal a corpus file earns by holding anything else.
fn hexDigit(c: u8) WireError!u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => error.CaptureNotHex,
    };
}

/// What opening a datagram learned about it. Every slice borrows `datagram`,
/// which the caller still owns: nothing here copied a byte or allocated.
pub const Opened = struct {
    header: packet.Header,
    /// Where the packet number field began. The header does not record it and
    /// the payload's own bound does depend on it, so it is read off the
    /// cursor between the parse and the decrypt.
    packet_number_offset: usize,
    /// The frames, in the memory the ciphertext was in.
    plaintext: []u8,
};

/// Derive the Initial keys for `key_dcid` and open the datagram in place.
///
/// `key_dcid` is the destination connection id RFC 9001 §5.2 derives the keys
/// from, which is the one this packet's own header carries. `null` means take
/// it from there, which is what a server does; a caller that names a
/// different one is asking what these same bytes look like under a domain they
/// are not from, and that is one of the negatives this file exists to run.
/// Nothing about `key_dcid` is invented — a caller supplies an id that is
/// somewhere in the capture or nowhere at all.
///
/// `datagram` is damaged by the call: header protection is removed, the
/// ciphertext is overwritten with the plaintext and the tag consumed. That is
/// what `packet.decrypt` does, and this file borrows rather than copies, so a
/// datagram a caller means to keep must be copied by that caller.
pub fn decryptInitial(datagram: []u8, key_dcid: ?[]const u8) WireError!Opened {
    var reader = quic.io_compat.fixedBufferStream(datagram);
    // The short-header connection id length is connection state a long header
    // does not carry, and a long header is the only header this file reads.
    var header = try packet.parseQuicHeader(&reader, 0);
    const packet_number_offset = reader.seek;
    var space: packet.PacketNumSpace = .{};
    // A server opens the client's Initial keys and seals its own.
    try space.setupInitial(key_dcid orelse header.dcid, header.version, true);
    const plaintext = try packet.decrypt(&header, &reader, &space);
    return .{
        .header = header,
        .packet_number_offset = packet_number_offset,
        .plaintext = plaintext,
    };
}

/// What the frame walk found, so a caller can say how the stream was
/// assembled and not only what came out of it. One CRYPTO frame at offset
/// zero and one frame at an offset are both "a CRYPTO stream", and only the
/// count and the declared offset tell them apart.
pub const Stream = struct {
    /// The reassembled CRYPTO stream, in the caller's own buffer.
    bytes: []u8,
    /// How many CRYPTO frames carried it.
    frames: usize,
    /// The offset the first of them declared (RFC 9000 §19.6).
    first_offset: u64,
};

/// Reassemble the CRYPTO stream the frames in `payload` carry, into `out`.
///
/// Bounded twice over, and both bounds matter. `out` is one: a frame whose
/// declared offset and length do not both fit inside it is refused rather
/// than clipped, because a clipped hello is a hello nobody sent. And the walk
/// ends where the payload does — every frame's size comes from
/// `frame.Frame.parseSized`, which refuses a body running past its buffer, so
/// there is no length here that this file has to check for itself.
pub fn cryptoStream(payload: []u8, out: []u8) WireError!Stream {
    var rest = payload;
    var end: usize = 0;
    var frames: usize = 0;
    var first_offset: u64 = 0;
    while (rest.len > 0) {
        var size: usize = 0;
        const parsed = try frame.Frame.parseSized(rest, &size);
        // Every frame this table knows spends at least its own type byte, so
        // `size` is never zero. The check is the walk's termination argument
        // — a driver mutates these bytes, and a zero here would spin forever —
        // not a second opinion on the parser.
        if (size == 0) return error.FrameEncodingError;
        switch (parsed) {
            .crypto => |c| {
                const at = std.math.cast(usize, c.offset) orelse return error.CryptoDataOutOfRange;
                if (at > out.len or c.data.len > out.len - at) return error.CryptoDataOutOfRange;
                @memcpy(out[at..][0..c.data.len], c.data);
                if (at + c.data.len > end) end = at + c.data.len;
                if (frames == 0) first_offset = c.offset;
                frames += 1;
            },
            else => {},
        }
        rest = rest[size..];
    }
    return .{ .bytes = out[0..end], .frames = frames, .first_offset = first_offset };
}

/// RFC 7250's certificate-type extension inside a ClientHello flight, found
/// by walking RFC 8446 §4.1.2 rather than by an offset written down here.
///
/// The capture's own extension block says where its two certificate-type
/// extensions are, and a capture from a peer that ordered them differently
/// would move this walk with it. `kind` is 19 or 20. The slice borrows
/// `flight` and is mutable, which is what makes the derived edit below a
/// two-byte change rather than a re-encoding of the hello.
pub fn certificateTypeExtension(flight: []u8, kind: u16) ?[]u8 {
    // §4.1.2: a ClientHello is a one-byte type and a 24-bit length.
    if (flight.len < 4 or flight[0] != 0x01) return null;
    const body_len = (@as(usize, flight[1]) << 16) | (@as(usize, flight[2]) << 8) | flight[3];
    if (body_len > flight.len - 4) return null;
    const body = flight[4..][0..body_len];
    var p: usize = 2 + 32; // legacy_version, random
    if (p + 1 > body.len) return null;
    p += 1 + body[p]; // legacy_session_id
    if (p + 2 > body.len) return null;
    p += 2 + be16(body[p..]); // cipher_suites
    if (p + 1 > body.len) return null;
    p += 1 + body[p]; // legacy_compression_methods
    if (p + 2 > body.len) return null;
    const extensions_len = be16(body[p..]);
    p += 2;
    // §4.2: the block's own length is clamped to the message, and a header
    // that does not close ends the walk rather than refusing — the same two
    // rules `tls_wire/hello.zig`'s reference applies.
    const end = @min(p + extensions_len, body.len);
    while (p + 4 <= end) {
        const wanted = be16(body[p..]) == kind;
        const len = be16(body[p + 2 ..]);
        if (p + 4 + len > end) return null;
        if (wanted) return body[p + 4 ..][0..len];
        p += 4 + len;
    }
    return null;
}

/// RFC 7250 §3's offer, rewritten to name X.509 alone.
///
/// Length-preserving on purpose: nothing after the edit moves, so the one
/// thing a derived mutation changes is the certificate type the server is
/// asked to use. `error.CertificateOfferMalformed` is an offer this file
/// cannot rewrite in place — one whose count is not its own length — rather
/// than an edit that would have to shift the rest of the hello behind it.
pub fn offerX509Only(extension: []u8) WireError!void {
    if (extension.len != 2 or extension[0] != 1) return error.CertificateOfferMalformed;
    extension[1] = 0;
}

fn be16(b: []const u8) u16 {
    return @as(u16, b[0]) << 8 | b[1];
}

/// What the vendored TLS 1.3 server settled on this hello.
///
/// `alpn` is the caller's own slice rather than the handshake's: the
/// handshake is released before `serverVerdict` returns, so the name cannot
/// borrow it.
pub const Verdict = struct {
    alpn: []const u8,
    /// The group the client's own key share named.
    group: tls.NamedGroup,
    /// RFC 7250 §3's two selections, as the parse left them.
    client_certificate_type: tls13.CertificateType,
    server_certificate_type: tls13.CertificateType,
    /// Whether the hello was answered rather than stalled, read off the bytes
    /// the server emitted: RFC 7301 §3.2 makes a server echo the protocol it
    /// selected, so a flight carrying the name is the proof.
    answered: bool,
};

/// Run `flight` through the vendored TLS 1.3 server, offering the one
/// protocol the capture's ALPN extension names.
///
/// `alpn_out` receives the protocol the server selected and must be wide
/// enough for it; `error.AlpnTooLong` says it was not, rather than the name
/// being cut to fit. `alloc` is where the handshake's own buffers live and
/// where they are released. Nothing else here allocates: the config, the
/// transport parameters and the output buffer are this function's.
pub fn serverVerdict(
    alloc: std.mem.Allocator,
    flight: []const u8,
    alpn_out: []u8,
) VerdictError!Verdict {
    const hs = try alloc.create(tls13.Tls13Handshake);
    defer alloc.destroy(hs);
    defer hs.deinit();
    var prng = std.Random.DefaultPrng.init(seed);
    const random = prng.random();
    const config: tls13.TlsConfig = .{
        .cert_chain_der = &.{},
        .private_key_bytes = &server_key,
        .private_key_algorithm = .ed25519,
        .alpn = &offered,
    };
    try tls13.Tls13Handshake.initServerInto(hs, config, .{}, random);
    hs.provideData(flight);
    // One step is the parse: every field below is what that parse left behind,
    // and a refusal it raises is this caller's to hand back rather than a
    // verdict to report. The answer itself is further along, which is what
    // `answeredFlight` is for.
    _ = try hs.step(now_s, random);
    const selected = hs.negotiatedAlpn();
    if (selected.len > alpn_out.len) return error.AlpnTooLong;
    @memcpy(alpn_out[0..selected.len], selected);
    return .{
        .alpn = alpn_out[0..selected.len],
        .group = hs.negotiated_group,
        .client_certificate_type = hs.negotiated_client_certificate_type,
        .server_certificate_type = hs.negotiated_server_certificate_type,
        .answered = try answeredFlight(hs, random, selected),
    };
}

/// How many `step`s this server is driven before its answer is read as absent.
/// `tls_wire/hello.zig` drives the same handshake under the same bound, and
/// this path needs four of them: the parse, the ServerHello, the handshake keys
/// that flight asks for, and the EncryptedExtensions.
const answer_steps: usize = 8;

/// Whether the server emits a flight carrying `selected` before it runs out of
/// steps. RFC 7301 §3.2 makes a server echo the protocol it chose, so that
/// flight is the proof the hello was answered rather than stalled.
///
/// No single action can show it. `serverProcessClientHello` consumes the hello
/// and answers `._continue` — the state machine's own "call me again", which
/// `Action` documents as not a caller-visible outcome — the ServerHello it
/// reaches next carries no protocol, and the name is in the
/// EncryptedExtensions one `install_keys` action later. So the flights are read
/// across the steps rather than off one, which is what every other driver of
/// this handshake does: `connection.advanceHandshake` loops on it and so does
/// this repository's own RFC 8446 oracle. What those callers do with the keys
/// is not done here, because a reading reads the bytes a flight carries and
/// not what they are sealed under.
fn answeredFlight(
    hs: *tls13.Tls13Handshake,
    random: std.Random,
    selected: []const u8,
) tls13.HandshakeError!bool {
    var steps: usize = 0;
    while (steps < answer_steps) : (steps += 1) {
        switch (try hs.step(now_s, random)) {
            .send_data => |sent| {
                if (std.mem.indexOf(u8, sent.data, selected) != null) return true;
            },
            .install_keys => {},
            ._continue, .wait_for_data => {},
            .complete => return false,
        }
    }
    return false;
}

/// The one call a fuzz driver makes: `input` is a datagram, verbatim.
///
/// Nothing here asks `input` to be the capture. Every refusal the four layers
/// own — a header that does not parse, a tag that does not verify, a frame
/// that does not close — is an outcome, and swallowing it is what lets a
/// driver mutate freely rather than replay one vector. What comes back as an
/// error is a defect in this file's reading, or a disagreement between the
/// vendored TLS parser and the independent RFC 8446 reference `hello.zig`
/// applies to the same handshake bytes.
///
/// The TLS half is reached whenever the layers above recover a flight, which
/// for arbitrary bytes is rare and is the point: a mutation that does decrypt
/// and reassemble is then judged against a second reading of itself instead of
/// being trusted.
pub fn fuzzOne(alloc: std.mem.Allocator, input: []const u8) Error!void {
    // RFC 9000 §14's maximum datagram size, which is also this core's
    // `packet.MAX_PACKET_LEN`. An input past it describes no packet a peer
    // could send, and truncating it would leave the tail uncovered while
    // looking like more coverage.
    if (input.len > packet.MAX_PACKET_LEN) return;
    // `decrypt` unprotects the header and overwrites the payload in place, so
    // the driver's own copy is the one it is allowed to damage.
    var storage: [packet.MAX_PACKET_LEN]u8 = undefined;
    @memcpy(storage[0..input.len], input);
    const opened = decryptInitial(storage[0..input.len], null) catch return;
    // A CRYPTO stream cannot be longer than the datagram it arrived in, so
    // this window is that datagram's size rather than a second guess at it.
    var flight: [packet.MAX_PACKET_LEN]u8 = undefined;
    const reassembled = cryptoStream(opened.plaintext, &flight) catch return;
    try hello.check(alloc, reassembled.bytes);
}
