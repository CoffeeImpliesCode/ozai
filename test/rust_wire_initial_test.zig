//! The captured Rust client's first datagram, read the way a server reads it.
//!
//! `rust_wire_initial.zig` is the reading; this file is what says the reading
//! is right. It holds the capture's own claims — that the header is the one
//! RFC 9000 §17.2 lays out and the core parses the same one, that the
//! datagram is a full-size client Initial under §14.1 and §7.2, that its
//! Length field closes the datagram exactly, that the AEAD *opens* it under
//! the Initial keys its own destination connection id derives, and that the
//! CRYPTO frame behind the header is a TLS ClientHello at offset zero — and
//! the negatives that keep each of those from being a coincidence.
//!
//! The header is read twice, from the RFC's field order and by the core, and
//! the two are compared. A walk that borrowed the first reader's decoder
//! would prove only that two calls into the same code agree.
//!
//! Three tests below read the capture's own bytes through. They are three
//! reads of one datagram, not three witnesses, and `provenance.json` says so
//! The five after them each change something first — one re-keys the datagram,
//! two damage it, and two rewrite the certificate types in the *decrypted*
//! hello — and are derived mutations rather than captures, which the same
//! record classifies beside the vector each comes from. One more runs
//! the same reading over a datagram this core builds and seals itself, because
//! without it every other test here would be a claim about a single vector.
//! The last is the fuzz root, and it asserts nothing: its first seed is the
//! capture decoded unchanged, which is why that record calls it a capture too,
//! and it hands every input to `wire.fuzzOne`.

const hello = @import("tls_wire/hello.zig");
const std = @import("std");
const quic = @import("quic");
const wire = @import("rust_wire_initial.zig");

const connection = quic.connection;
const connection_manager = quic.connection_manager;
const packet = quic.packet;

const t = std.testing;

/// A fixed instant on a monotonic clock. The core takes time as a parameter
/// and reads none, so this only has to be a plausible one.
const now: i64 = 1_000 * std.time.ns_per_s;

/// Seeded entropy, so the connection built below draws the same connection ids
/// on every run. `std.Random` is an interface over a pointer to its engine, so
/// the engine outlives every value handed out from it.
const TestRandom = std.Random.DefaultPrng;

/// The digest `provenance.json` records for the capture. The corpus file is
/// hex so a diff of it is legible, which means nothing downstream has seen the
/// bytes it decoded unless they hash to this.
const capture_sha256 = "473b53b1926dce2f9841718684b76792059ab02ba2fd7770f6b53e7315876f7d";

/// RFC 9001 §5.4.2: the header-protection sample is `crypto.SAMPLE_LEN` bytes
/// and begins `wire.sample_offset` bytes after the packet number, so a
/// datagram shorter than the two together cannot be unprotected at all.
const sample_bytes = wire.sample_offset + quic.crypto.SAMPLE_LEN;

/// Wider than RFC 7301 §3.1's own 255-byte ceiling on a protocol name, so
/// `serverVerdict` can never be handed a buffer too narrow for one.
const alpn_len = 256;

/// The short-header destination-id length. A long header carries none
/// (RFC 9000 §17.2), so this is the core's own default and only an input whose
/// first byte has been mutated from long to short ever reads it.
const local_cid_len: u8 = 8;

/// The one protocol this dial offers, and so the one name inside the
/// ClientHello `connectInto` builds from the configuration below.
/// `connectInto` copies that configuration and the handshake borrows the names
/// out of it for the connection's whole life, so this list has to outlive the
/// call; it is in this frame, and the connection is torn down inside this test.
const offered_alpn = [_][]const u8{wire.fixture_alpn};

/// One field at a time out of the recorded header, by RFC 9000 §17.2's order
/// and not by anything the code under test does.
const Walked = struct {
    first_byte: u8,
    version: u32,
    dcid: []const u8,
    scid: []const u8,
    token_len: u64,
    /// The Length field: the packet number and everything behind it.
    length: u64,
    /// Where the packet number starts, which is where Length is counted from.
    packet_number_offset: usize,
};

/// A varint read off the wire (RFC 9000 §16), written here rather than taken
/// from `packet.readVarInt`, for the reason the struct above names.
fn readVarInt(bytes: []const u8, at: usize) !struct { value: u64, width: usize } {
    if (at >= bytes.len) return error.Truncated;
    const first = bytes[at];
    const width: usize = @as(usize, 1) << @intCast(first >> 6);
    if (at + width > bytes.len) return error.Truncated;
    var value: u64 = first & 0x3f;
    for (bytes[at + 1 .. at + width]) |octet| {
        value = value << 8;
        value = value + octet;
    }
    return .{ .value = value, .width = width };
}

/// The header of a long-header datagram, read from the RFC's field order: first
/// byte, Version, DCID Length, DCID, SCID Length, SCID, then the per-type
/// fields, of which an Initial has the token and then Length.
fn walkHeader(bytes: []const u8) !Walked {
    if (bytes.len < 6) return error.Truncated;
    const first_byte = bytes[0];
    if ((first_byte & 0x80) == 0) return error.NotLongHeader;
    const version = std.mem.readInt(u32, bytes[1..5], .big);

    const dcid_len = bytes[5];
    if (dcid_len > 20) return error.ConnectionIdTooLong;
    var at: usize = 6;
    if (at + dcid_len > bytes.len) return error.Truncated;
    const dcid = bytes[at..][0..dcid_len];
    at += dcid_len;

    if (at >= bytes.len) return error.Truncated;
    const scid_len = bytes[at];
    if (scid_len > 20) return error.ConnectionIdTooLong;
    at += 1;
    if (at + scid_len > bytes.len) return error.Truncated;
    const scid = bytes[at..][0..scid_len];
    at += scid_len;

    // §17.2.2: an Initial's token is a varint length and those bytes.
    const token = try readVarInt(bytes, at);
    at += token.width;
    if (token.value > bytes.len - at) return error.Truncated;
    at += @intCast(token.value);

    // §17.2: Length is a varint covering the packet number and the payload.
    const length = try readVarInt(bytes, at);
    at += length.width;

    return .{
        .first_byte = first_byte,
        .version = version,
        .dcid = dcid,
        .scid = scid,
        .token_len = token.value,
        .length = length.value,
        .packet_number_offset = at,
    };
}

/// The capture as the corpus file spells it. A copy rather than the file's own
/// bytes, because `packet.decrypt` unprotects the header and overwrites the
/// payload where it stands, and every negative here opens its own copy.
///
/// A corpus file that does not decode is a finding about the capture and not a
/// reason to skip the assertion, so the refusal is handed to the caller.
fn captureBytes() wire.WireError![wire.capture_len]u8 {
    var out: [wire.capture_len]u8 = undefined;
    _ = try wire.decodeCapture(&out);
    return out;
}

/// One RFC 7250 certificate-type offer out of a ClientHello flight.
fn offer(flight: []u8, kind: u16) wire.WireError![]u8 {
    return wire.certificateTypeExtension(flight, kind) orelse error.CertificateOfferMalformed;
}

test "the recorded datagram is the client Initial RFC 9000 17.2 lays out" {
    const datagram = try captureBytes();

    // The bytes are the ones the capture is, before anything reads them as a
    // packet: `provenance.json` records this digest over the datagram.
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&datagram, &digest, .{});
    try t.expectEqualStrings(capture_sha256, &std.fmt.bytesToHex(&digest, .lower));

    const walk = try walkHeader(&datagram);
    // §17.2: long form, the fixed bit set, and long packet type 0b00, which
    // under a version of 1 is an Initial.
    try t.expect((walk.first_byte & 0x80) != 0);
    try t.expect((walk.first_byte & 0x40) != 0);
    try t.expect((walk.first_byte & 0x30) == 0);
    try t.expectEqual(@as(u32, 1), walk.version);
    try t.expectEqual(@as(u64, 0), walk.token_len);

    // §14.1: a client pads its Initial to the smallest datagram a server may
    // open a connection from. §7.2: the destination id is one the client
    // invented, so it is long enough to be unpredictable. Both are the two
    // conditions `connection_manager.route` refuses below, before it spends a
    // connection's state on anything.
    try t.expect(datagram.len >= connection_manager.MIN_INITIAL_DATAGRAM);
    try t.expect(walk.dcid.len >= connection_manager.MIN_INITIAL_DCID_LEN);

    // §17.2: Length counts the packet number and everything behind it, so the
    // datagram closes on exactly that and no second packet is coalesced in it.
    try t.expectEqual(datagram.len, walk.packet_number_offset + @as(usize, @intCast(walk.length)));

    // And the core reads the same header out of the same bytes.
    var scratch = try captureBytes();
    var reader = quic.io_compat.fixedBufferStream(&scratch);
    const header = try packet.parseQuicHeader(&reader, local_cid_len);
    try t.expectEqual(walk.version, header.version);
    try t.expectEqual(packet.PacketType.initial, header.packet_type);
    try t.expectEqualSlices(u8, walk.dcid, header.dcid);
    try t.expectEqualSlices(u8, walk.scid, header.scid);
    try t.expectEqual(@as(usize, @intCast(walk.length)), header.remainder_len);
    // The cursor is left on the packet number, which is where header
    // protection's sample is measured from.
    try t.expectEqual(walk.packet_number_offset, reader.seek);
}

test "the recorded datagram opens, and its CRYPTO frame is a ClientHello" {
    const cap = try captureBytes();
    const walked = try walkHeader(&cap);
    var scratch = cap;
    // RFC 9001 §5.2: the keys are derived from the destination connection id
    // this packet carries, and §5.3: the packet is sealed over the unprotected
    // header and that packet number. Nothing here supplies a key, so the open
    // is the AEAD's own verdict on bytes it was not built for.
    const opened = try wire.decryptInitial(&scratch, null);
    try t.expectEqual(packet.PacketType.initial, opened.header.packet_type);
    try t.expectEqual(@as(u32, 1), opened.header.version);
    try t.expectEqual(walked.packet_number_offset, opened.packet_number_offset);
    // RFC 9001 §5.4.1 takes the protection off the reserved bits before the
    // payload is touched, and this is where that shows: a peer that set them
    // would have been refused rather than opened.
    try t.expect(!opened.header.reserved_bits_set);
    // The first packet a client sends, at the number its own header protection
    // was hiding until `packet.decrypt` took the mask off.
    try t.expectEqual(@as(u64, 0), opened.header.packet_number);

    var flight: [wire.capture_len]u8 = undefined;
    const stream = try wire.cryptoStream(opened.plaintext, &flight);
    // RFC 9000 §19.6: one CRYPTO frame, at the offset it declares, which is
    // zero — so what came out is the whole stream and not a piece of it. The
    // rest of the payload is the padding §14.1 asks for.
    try t.expectEqual(@as(usize, 1), stream.frames);
    try t.expectEqual(@as(u64, 0), stream.first_offset);
    // RFC 8446 §4.1.2: a handshake message is a one-byte type and a 24-bit
    // length, and the first message a client sends is ClientHello. Bounded
    // first, so the subtraction below is a length and not a wrap.
    try t.expect(stream.bytes.len >= 4);
    try t.expectEqual(@as(u8, 0x01), stream.bytes[0]);
    try t.expectEqual(stream.bytes.len - 4, (@as(usize, stream.bytes[1]) << 16) |
        (@as(usize, stream.bytes[2]) << 8) | stream.bytes[3]);
}

test "the vendored TLS server negotiates the captured hello" {
    var scratch = try captureBytes();
    const opened = try wire.decryptInitial(&scratch, null);
    var flight: [wire.capture_len]u8 = undefined;
    const stream = try wire.cryptoStream(opened.plaintext, &flight);

    // RFC 7250 §3's two offers, found by walking §4.1.2 rather than at an
    // offset written down here, and both naming RawPublicKey — the only
    // certificate type this stack has.
    const raw_public_key = [_]u8{ 1, @intFromEnum(quic.tls13.negotiated_certificate_type) };
    try t.expectEqualSlices(u8, &raw_public_key, try offer(stream.bytes, wire.client_certificate_type_ext));
    try t.expectEqualSlices(u8, &raw_public_key, try offer(stream.bytes, wire.server_certificate_type_ext));

    var alpn: [alpn_len]u8 = undefined;
    const verdict = try wire.serverVerdict(t.allocator, stream.bytes, &alpn);
    // RFC 7301 §3.2: the selection is an intersection, and this run's two ends
    // were both speaking the protocol the capture carries. The group is the one
    // the client's own key share named, and `answered` is the protocol coming
    // back inside the flight the server emitted.
    try t.expectEqualStrings(wire.fixture_alpn, verdict.alpn);
    try t.expectEqual(std.crypto.tls.NamedGroup.x25519, verdict.group);
    try t.expectEqual(quic.tls13.negotiated_certificate_type, verdict.client_certificate_type);
    try t.expectEqual(quic.tls13.negotiated_certificate_type, verdict.server_certificate_type);
    try t.expect(verdict.answered);

    // The independent RFC 8446 reference in `tls_wire/hello.zig`, on the same
    // bytes. Its fixture offers only `"ozai"` where this capture offered
    // `/ozai/w1-fixture`, and its reference models RFC 7301 §3.2's
    // `no_application_protocol` for an empty intersection — so what it demands
    // here is that refusal, and the vendored parser has to refuse the same way.
    try hello.check(t.allocator, stream.bytes);
}

test "the recorded datagram does not open under its own source connection id" {
    var scratch = try captureBytes();
    var reader = quic.io_compat.fixedBufferStream(&scratch);
    const header = try packet.parseQuicHeader(&reader, local_cid_len);
    // The source id is on the wire and in the capture, and it is the wrong
    // answer to RFC 9001 §5.2 for this packet, which derives from the
    // destination id. §5.3 is what says why the tag cannot verify under it.
    try t.expect(!std.mem.eql(u8, header.scid, header.dcid));
    try t.expectError(error.AuthenticationFailed, wire.decryptInitial(&scratch, header.scid));
}

test "a single flipped ciphertext byte stops the recorded datagram opening" {
    const cap = try captureBytes();
    var probe = cap;
    const opened = try wire.decryptInitial(&probe, null);
    // The ciphertext starts past the packet number, and the packet number is
    // the last field of the associated data, so a byte this far in is inside
    // the AEAD's own input and outside the header it authenticates: nothing
    // about the header is wrong, only the payload. The flip lands on a pristine
    // copy, because the one `decrypt` opened now holds plaintext there.
    const ciphertext = opened.packet_number_offset + opened.header.packet_number_len;
    try t.expect(ciphertext + 4 < cap.len);
    var damaged = cap;
    damaged[ciphertext + 4] ^= 0x01;
    try t.expectError(error.AuthenticationFailed, wire.decryptInitial(&damaged, null));
}

test "a datagram cut inside the header protection sample refuses" {
    const cap = try captureBytes();
    var probe = cap;
    const opened = try wire.decryptInitial(&probe, null);
    // One byte short of the sample RFC 9001 §5.4.2 reads four bytes after the
    // packet number, cut out of the capture itself. The header still parses —
    // its own Length field is inside the cut — so this is `packet.decrypt`'s
    // sample bound and nothing else.
    var cut = cap;
    try t.expectError(
        error.InvalidPacket,
        wire.decryptInitial(cut[0 .. opened.packet_number_offset + sample_bytes - 1], null),
    );
}

test "a derived server certificate type edit refuses the hello" {
    var scratch = try captureBytes();
    const opened = try wire.decryptInitial(&scratch, null);
    var flight: [wire.capture_len]u8 = undefined;
    const stream = try wire.cryptoStream(opened.plaintext, &flight);
    // A derived mutation, not a capture: the decrypted capture's own
    // `server_certificate_type` offer, rewritten to name X.509 alone. Nothing
    // a peer emitted produced these bytes.
    try wire.offerX509Only(try offer(stream.bytes, wire.server_certificate_type_ext));
    var alpn: [alpn_len]u8 = undefined;
    // RFC 7250 §4.2's outcome 2: this server has one certificate type to give
    // and the client did not offer it.
    try t.expectError(error.UnsupportedCertificate, wire.serverVerdict(t.allocator, stream.bytes, &alpn));
}

test "a derived client certificate type edit refuses the hello" {
    var scratch = try captureBytes();
    const opened = try wire.decryptInitial(&scratch, null);
    var flight: [wire.capture_len]u8 = undefined;
    const stream = try wire.cryptoStream(opened.plaintext, &flight);
    // The same derived edit on the other direction's extension, which is a
    // separate refusal: RFC 7250 settles each end's type in its own
    // extension, so a server that could not be given a certificate it would
    // have to verify says so before it says anything about its own.
    try wire.offerX509Only(try offer(stream.bytes, wire.client_certificate_type_ext));
    var alpn: [alpn_len]u8 = undefined;
    try t.expectError(error.UnsupportedCertificate, wire.serverVerdict(t.allocator, stream.bytes, &alpn));
}

test "the same reading opens a client Initial this core builds" {
    var entropy = TestRandom.init(0);
    const random = entropy.random();
    // The other end of the exchange the capture is one half of: this core
    // builds the client's first flight and seals it under its own Initial
    // keys, and the same reading has to open it. Nothing here is on the wire,
    // so what this proves is that the reading is not tailored to one capture.
    //
    // The flight is a ClientHello because of the configuration below, not in
    // spite of it: handed no `tls_config`, `connectInto` queues this
    // connection's encoded transport parameters into the Initial's CRYPTO
    // stream in its place (`connection.zig:5459`), and a parameter block is
    // not a handshake message. Its first bytes are a parameter id and that
    // parameter's length, where RFC 8446 §4.1.2 puts a 24-bit message length
    // — so this datagram had the reading compare the length of one against the
    // length of the other.
    const tls_config: quic.tls13.TlsConfig = .{
        // A client presents nothing here; the empty pair is what "not a
        // server" is, and it is the pair `Dialer.tlsConfigFor` hands the core.
        .cert_chain_der = &.{},
        .private_key_bytes = &.{},
        .private_key_algorithm = .ed25519,
        .alpn = &offered_alpn,
    };
    const conn = try t.allocator.create(connection.Connection);
    defer {
        conn.deinit();
        t.allocator.destroy(conn);
    }
    try connection.connectInto(conn, t.allocator, "ozai.example", .{}, tls_config, null, now, random);

    var out: [packet.MAX_PACKET_LEN]u8 = undefined;
    const len = try conn.sendAt(&out, now, random);
    try t.expect(len >= connection_manager.MIN_INITIAL_DATAGRAM);

    const opened = try wire.decryptInitial(out[0..len], null);
    var flight: [packet.MAX_PACKET_LEN]u8 = undefined;
    const stream = try wire.cryptoStream(opened.plaintext, &flight);
    // RFC 9000 §19.6 and RFC 8446 §4.1.2: what this core puts at offset zero
    // is the ClientHello, and the 24-bit length closes it. Bounded first, so
    // the subtraction below is a length and not a wrap.
    try t.expect(stream.bytes.len >= 4);
    try t.expectEqual(@as(u64, 0), stream.first_offset);
    try t.expectEqual(@as(u8, 0x01), stream.bytes[0]);
    try t.expectEqual(stream.bytes.len - 4, (@as(usize, stream.bytes[1]) << 16) |
        (@as(usize, stream.bytes[2]) << 8) | stream.bytes[3]);
}

/// The window a fuzz driver fills, and the size of the corpus it replays before
/// it starts mutating: the capture, and the same bytes cut inside their own
/// version field, so a bare `zig build fuzz` reaches the header parser's first
/// refusal as well as the whole decode.
const corpus_len = 2;
const input_buffer_len = 1536;

/// The fuzzer keeps one of these by pointer for the whole run, so it is empty
/// by design: everything the driver needs is built from the input.
const Context = struct {};

test "rust initial decode" {
    var storage: [corpus_len][input_buffer_len]u8 = undefined;
    var lengths: [corpus_len]usize = undefined;
    // A corpus file that does not decode fails this gate rather than leaving
    // the corpus holding whatever it happens to spell.
    lengths[0] = (try wire.decodeCapture(&storage[0])).len;
    @memcpy(storage[1][0..3], storage[0][0..3]);
    lengths[1] = 3;
    var corpus: [corpus_len][]const u8 = undefined;
    for (0..corpus_len) |i| corpus[i] = storage[i][0..lengths[i]];

    // A fuzz test is a plain test to a plain build. Without `-ffuzz` the runner
    // walks this corpus and stops, which is what makes a bare `zig build fuzz`
    // a bounded gate rather than an empty step.
    try t.fuzz(Context{}, testOne, .{ .corpus = &corpus });
}

fn testOne(_: Context, smith: *t.Smith) anyerror!void {
    var buffer: [input_buffer_len]u8 = undefined;
    // `in` is the corpus entry verbatim while the corpus is replayed, and null
    // when the fuzzer drives, in which case `slice` consumes its input.
    const bytes = if (smith.in) |replay| replay else buffer[0..smith.slice(&buffer)];
    try wire.fuzzOne(t.allocator, bytes);
}
