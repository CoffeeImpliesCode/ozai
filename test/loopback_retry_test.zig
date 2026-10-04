//! Retry token validation: from the moment one is sealed to the moment a second
//! use of the same bytes is refused.
//!
//! # Why this file has no socket in most of it
//!
//! A Retry token exists to be checked *before* a connection exists — that is the
//! whole of source-address validation (RFC 9000 §8.1.1). Anything that needs a
//! peer to have connected first has already missed the point, so the four
//! verdicts are driven against a bridge on its own, with no datagram and no
//! listener, and only the last test puts the token on a real socket.
//!
//! # One test that does need a peer first
//!
//! The last test here is the exception, and it is the one a single Initial
//! cannot express. A Retry token is presented in *every* Initial a client
//! sends until its ClientHello is out (`packet_packer.zig:656`), and a
//! ClientHello longer than one datagram does not fit in one — so the second
//! packet of the first flight carries a token this node has already recorded,
//! and whether that datagram is a replay or the rest of a handshake is a
//! question about the connection it is addressed to. That cannot be asked of a
//! bridge on its own, so that test drives a real client through a real Retry
//! over a real socket and asks whether the session comes up.
//!
//! **Where the length comes from, now that the offer cannot.** A protocol
//! name past `quic_config.max_alpn_name_len` could never be the protocol a
//! connection runs on, so `Dialer.create` refuses such an offer by name,
//! before it allocates (`dial.zig:406`) — the padding this file used to
//! offer is no longer an offer at all. The ClientHello is still made longer
//! than one datagram, by the one field with no ceiling: RFC 6066 puts none on
//! a server name, and the core writes what that name's length field encodes
//! (`vendor/quic/src/quic/tls13.zig:4320-4336`). See `pad_server_name`.
//!
//! That split is also what keeps the file honest about cost: `check` answers
//! from a record it already holds without opening a cipher at all
//! (`retry.zig:303-311`), and the tests below are arranged so the *first* answer
//! is the free one and only the forged cases reach the AEAD.
//!
//! # The four verdicts, and what each one is for
//!
//! * **`unknown`** — the bytes are not a token this format can carry: their
//!   length is outside `[min_token_length, max_token_length]`, so they are
//!   somebody else's and the core is the only thing entitled to an opinion. A
//!   NEW_TOKEN answers here too, and must: it is reusable, and refusing the
//!   second connection that presents it would be a filter dressed up as a
//!   correctness check.
//! * **`recorded`** — opened just now (or recognised from a record this gate
//!   sealed), and written down so the *next* copy is free.
//! * **`spent`** — this node already answered those exact bytes for that exact
//!   address. A replay is not a token any more.
//! * **`invalid`** — did not open: forged, sealed for another address, or past
//!   its age. Nothing is recorded, so the core still gets to answer it and the
//!   address is validated the slow way.
//!
//! # Time is virtual
//!
//! The age check is part of the verdict, so these tests move the instant rather
//! than waiting. A token is refused once it is older than `token_max_age`, and
//! a test that only checked a fresh token would pass against a gate that never
//! expired anything.

const std = @import("std");
const ozai = @import("ozai");

const t = std.testing;

const link_mod = @import("loopback_link.zig");
const bridge_mod = ozai.transport_quic_bridge;

/// The retry module owns the Initial parser and token gate.
const transport_retry = ozai.transport_retry;

const Bridge = bridge_mod.Bridge;
const Link = link_mod.Link;
const RetryVerdict = transport_retry.Verdict;
const bothUp = link_mod.bothUp;
const link_alpn = link_mod.alpn;
const link_start = link_mod.start;

const Instant = link_mod.Instant;
const SecretKey = ozai.SecretKey;
const SocketAddr = ozai.SocketAddr;

/// Fixed seeds, as in `loopback_test.zig`.
const client_seed: [SecretKey.seed_length]u8 = @splat(0xc1);
const server_seed: [SecretKey.seed_length]u8 = @splat(0x53);

/// The key the bridges in this file seal under. The harness's own bridges use
/// `@splat(0x11)`; this is the same value written out so a test that depends on
/// *a* key rather than on that one is visible as depending on it.
const token_key: [16]u8 = @splat(0x11);

/// A second key, for the one assertion that needs a token sealed under a
/// different secret. Without it there is no way to say "invalid" about a token
/// this node itself issued.
const other_key: [16]u8 = @splat(0x77);

/// How long a token stays valid, from `src/transport/retry.zig`'s `max_age`
/// (60 s). Written out rather than imported because the value under test is the
/// age *check*, and a test that read the same constant it is being measured
/// against would pass if both moved together.
const token_max_age: Instant = 60 * std.time.ns_per_s;

/// A stable address to seal tokens for. Port is fixed rather than ephemeral
/// because no socket is involved: the token is bound to the address, not to a
/// listener, and a token bound to a port nobody is listening on is the case
/// source-address validation exists for.
const client_addr: SocketAddr = .{ .ip = .{ .v4 = .{ 127, 0, 0, 1 } }, .port = 40000 };

/// The same address on a different port — the same host, and a different path.
const other_addr: SocketAddr = .{ .ip = .{ .v4 = .{ 127, 0, 0, 1 } }, .port = 40001 };

/// The two connection ids a Retry packet's header carries, per RFC 9000 §17.2.5.
const original_dcid = [_]u8{ 0xde, 0xad, 0xbe, 0xef, 0, 0, 0, 0 };
const retry_scid = [_]u8{ 0xfe, 0xed, 0xfa, 0xce, 0, 0, 0, 0 };

/// One bridge that seals under `key`, with nothing else configured.
///
/// The seeds are fixed and the ALPN is the harness's own, so two runs present
/// the same certificate and the same token key and a failure reproduces from
/// the test name alone.
fn sealedBridge(key: [16]u8, secret: SecretKey, engine_seed: u64) !*Bridge {
    var engine = link_mod.Prng.init(engine_seed);
    return Bridge.create(t.allocator, t.io, .{
        .secret = secret,
        .alpns = &.{link_alpn},
        .retry_token_key = key,
    }, engine.random());
}

test "a token this node sealed comes back recorded, and the same bytes again are spent" {
    var secret = try SecretKey.fromSeed(server_seed);
    defer secret.deinit();
    var engine = link_mod.Prng.init(31);

    const node = try sealedBridge(token_key, secret, 32);
    defer node.destroy();

    // The key the bridge actually seals with is the one it was configured with,
    // so the tokens below are this node's and not a sibling's. Asserted because
    // a bridge that fell back to a drawn key would still pass every verdict
    // assertion below against itself.
    try t.expectEqualSlices(u8, &token_key, &node.manager.retry_token_key);

    const token = try node.issueRetryToken(
        &original_dcid,
        &retry_scid,
        client_addr,
        link_start,
        engine.random(),
    );

    // The window between issuing a token and the client echoing it back: the
    // gate already holds these bytes for this address, and answering `spent`
    // now would drop the one connection the token exists to let in. False here
    // is the assertion — a gate that recorded on the way out would refuse a
    // legitimate client.
    try t.expect(!node.checkRetryTokenIsSpent(token.slice(), client_addr, link_start));

    // First presentation: it opens, and it is written down.
    try t.expectEqual(
        RetryVerdict.recorded,
        node.checkRetryToken(token.slice(), client_addr, link_start),
    );

    // And now it is spent, read without the cipher. The flag is what the second
    // verdict below is computed from, so it is asserted on its own rather than
    // only through it.
    try t.expect(node.checkRetryTokenIsSpent(token.slice(), client_addr, link_start));

    // Second presentation of the same bytes for the same address: the cipher's
    // answer is on file and cannot have changed, so this costs no AEAD open and
    // says the token is spent.
    try t.expectEqual(
        RetryVerdict.spent,
        node.checkRetryToken(token.slice(), client_addr, link_start),
    );

    // And a third time is still spent rather than recorded: a replay that
    // oscillated between the two would be a filter that lets a second use
    // through every other attempt.
    try t.expectEqual(
        RetryVerdict.spent,
        node.checkRetryToken(token.slice(), client_addr, link_start),
    );
}

test "a token sealed for another address, another key, or too long ago is refused" {
    var secret = try SecretKey.fromSeed(server_seed);
    defer secret.deinit();
    var other_secret = try SecretKey.fromSeed(client_seed);
    defer other_secret.deinit();
    var engine = link_mod.Prng.init(41);

    const node = try sealedBridge(token_key, secret, 42);
    defer node.destroy();
    // A sibling that shares nothing but the address. Built because "invalid" is
    // only meaningful against a token this node did not seal under its own key.
    const sibling = try sealedBridge(other_key, other_secret, 43);
    defer sibling.destroy();

    const token = try node.issueRetryToken(
        &original_dcid,
        &retry_scid,
        client_addr,
        link_start,
        engine.random(),
    );
    const issued = token.slice();

    // Bound to an address. The same host on a different port is a different
    // path, and a token that validated across it would be a token a spoofed
    // source could use — the whole of what source-address validation prevents.
    try t.expectEqual(
        RetryVerdict.invalid,
        node.checkRetryToken(issued, other_addr, link_start),
    );

    // Sealed under a different key. Nothing is recorded, so the core still gets
    // to answer this datagram and the address is validated the slow way.
    try t.expectEqual(
        RetryVerdict.invalid,
        sibling.checkRetryToken(issued, client_addr, link_start),
    );

    // Past its age. The check is on the issuer's clock epoch, so this moves the
    // instant rather than waiting, and it is the assertion that would fail
    // against a gate which never expired anything.
    try t.expectEqual(
        RetryVerdict.invalid,
        node.checkRetryToken(issued, client_addr, link_start + token_max_age + 1),
    );

    // A token stamped in the future is refused too: an age check that only
    // tested "old" would accept a clock an attacker chose.
    const future = try node.issueRetryToken(
        &original_dcid,
        &retry_scid,
        client_addr,
        link_start + 2 * token_max_age,
        engine.random(),
    );
    try t.expectEqual(
        RetryVerdict.invalid,
        node.checkRetryToken(future.slice(), client_addr, link_start),
    );

    // Bytes that are not a token at all are `unknown`, not `invalid`. The
    // distinction is the whole of the contract with the core: an unknown token
    // is somebody else's bytes and the core is the only thing entitled to an
    // opinion about it, so the gate must not claim it failed to open.
    try t.expectEqual(
        RetryVerdict.unknown,
        node.checkRetryToken("ab", client_addr, link_start),
    );
    const roomy = try t.allocator.alloc(u8, transport_retry.max_token_length + 1);
    defer t.allocator.free(roomy);
    @memset(roomy, 0x5a);
    try t.expectEqual(
        RetryVerdict.unknown,
        node.checkRetryToken(roomy, client_addr, link_start),
    );

    // In-range random bytes are `invalid`: they are the right *shape* and did
    // not open, which is a different answer from being the wrong shape.
    const shapely = try t.allocator.alloc(u8, transport_retry.min_token_length + 8);
    defer t.allocator.free(shapely);
    @memset(shapely, 0x33);
    try t.expectEqual(
        RetryVerdict.invalid,
        node.checkRetryToken(shapely, client_addr, link_start),
    );
}

test "the token field is read out of an Initial, and only out of an Initial" {
    var secret = try SecretKey.fromSeed(server_seed);
    defer secret.deinit();
    var engine = link_mod.Prng.init(51);

    const node = try sealedBridge(token_key, secret, 52);
    defer node.destroy();
    const token = try node.issueRetryToken(
        &original_dcid,
        &retry_scid,
        client_addr,
        link_start,
        engine.random(),
    );
    const issued = token.slice();

    // A hand-built Initial: long header, fixed bit, packet type `Initial`, the
    // version, both connection ids, then the token length as a varint and the
    // token. Built here rather than captured off a wire so that every byte the
    // parser skips is a byte this test chose.
    //
    // The token's room is the format's own bound rather than this run's
    // `issued.len`: an array's length has to be known before anything runs and
    // a slice's length is not. `max_token_length` is the bound itself rather
    // than a guess at one — `RetryToken`'s storage is a `[max_token_length]u8`,
    // so no slice of one is longer — and the assertion after the build says
    // this datagram still fits the room it was given.
    const token_room = transport_retry.max_token_length;
    // The length and packet number behind the token, which nothing here reads.
    // Two one-byte varints would do; the room is generous so the test is not
    // about the width of a varint it never parses.
    const tail_room = 16;
    // The token's length goes on the wire as a varint (RFC 9000 §16), and this
    // token is past 63 bytes, so it takes the two-byte form and the room is
    // for two.
    const varint_room = 2;
    var datagram: [1 + 4 + 1 + 8 + 1 + 8 + varint_room + token_room + tail_room]u8 = undefined;
    var at: usize = 0;
    datagram[at] = 0xc0; // long header (0x80) | fixed bit (0x40) | Initial (0b00)
    at += 1;
    std.mem.writeInt(u32, datagram[at..][0..4], 1, .big); // QUIC v1
    at += 4;
    datagram[at] = original_dcid.len;
    at += 1;
    @memcpy(datagram[at..][0..original_dcid.len], &original_dcid);
    at += original_dcid.len;
    datagram[at] = retry_scid.len;
    at += 1;
    @memcpy(datagram[at..][0..retry_scid.len], &retry_scid);
    at += retry_scid.len;
    // A varint of one byte carries any length below 64, and a token is longer
    // than that in general — so the width is chosen by the value, not assumed.
    // RFC 9000 §16: the top two bits of the first byte are the width and its
    // low six bits are the top of the value, so a length of `n` below 16384 is
    // `0b01 << 6 | n >> 8` followed by `n & 0xff`. The bare length on its own
    // is not that: its own top bits are the width, so a token past 63 written
    // as its length reads as a two-byte varint whose second byte is the
    // token's own first byte, and the parser answers null for a packet that
    // carried one.
    std.debug.assert(issued.len < 1 << 14);
    datagram[at] = 0x40 | @as(u8, @intCast(issued.len >> 8));
    datagram[at + 1] = @truncate(issued.len);
    at += varint_room;
    // The whole datagram fits the buffer it was given: the header so far, this
    // token and the two fields behind it. Checked before the copy rather than
    // after it, so a `token_room` too small for this token says so here
    // instead of running off the end of the datagram.
    try t.expect(at + issued.len + tail_room <= datagram.len);
    @memcpy(datagram[at..][0..issued.len], issued);
    at += issued.len;
    @memset(datagram[at..], 0); // length and packet number, which nothing here reads

    try t.expectEqualSlices(u8, issued, transport_retry.initialHeader(datagram[0..at]).?.token.?);
    // **The destination id out of the same walk, and the whole of it.** This
    // is the field a caller matches a connection on before acting on a token,
    // so a reader that returned a prefix of it would ask the routing table
    // about an id nobody sent.
    try t.expectEqualSlices(u8, &original_dcid, transport_retry.initialHeader(datagram[0..at]).?.dcid);

    // A zero-length token is an Initial that asked for none, which is every
    // first flight a client sends. It is not a token to have an opinion about,
    // so it is null rather than an empty slice — and the header still parses,
    // because who the datagram is addressed to is a question a caller has about
    // a first flight too: that id is what the core opens a connection on.
    const no_token = [_]u8{ 0xc0, 0, 0, 0, 1, 0, 0, 0 };
    try t.expect(transport_retry.initialHeader(&no_token).?.token == null);
    try t.expectEqual(@as(usize, 0), transport_retry.initialHeader(&no_token).?.dcid.len);

    // A short header carries no token field at all — and no destination id to
    // match a connection on either, so there is no Initial here to read.
    const short_header = [_]u8{ 0x40, 0x11, 0x22, 0x33 };
    try t.expect(transport_retry.initialHeader(&short_header) == null);

    // A long header without the fixed bit is not a QUIC packet.
    const no_fixed_bit = [_]u8{ 0x80, 0, 0, 0, 1, 0, 0, 0 };
    try t.expect(transport_retry.initialHeader(&no_fixed_bit) == null);

    // A long header that is not an Initial — 0b01 is 0-RTT — has no token field
    // either, and reading one out of it would hand a caller bytes that are
    // something else's.
    const not_initial = [_]u8{ 0xd0, 0, 0, 0, 1, 0, 0, 0 };
    try t.expect(transport_retry.initialHeader(&not_initial) == null);

    // The token-length varint starts at byte 7 after the two empty connection
    // ids. Its 0x40 prefix requires a second byte that this datagram lacks.
    // Putting a zero before it would complete a zero-token prefix instead,
    // leaving 0x40 in the later packet-length field that this reader does not own.
    const truncated_length = [_]u8{ 0xc0, 0, 0, 0, 1, 0, 0, 0x40 };
    try t.expect(transport_retry.initialHeader(&truncated_length) == null);

    // The issued token's declared length stays intact, but its last byte is
    // missing. The pre-accept caller must never receive a partial token.
    try t.expect(transport_retry.initialHeader(datagram[0 .. at - 1]) == null);

    // A declared connection id must also fit before any token can be read.
    const truncated_destination = [_]u8{ 0xc0, 0, 0, 0, 1, 2, 0xaa };
    try t.expect(transport_retry.initialHeader(&truncated_destination) == null);
    const truncated_source = [_]u8{ 0xc0, 0, 0, 0, 1, 0, 2, 0xaa };
    try t.expect(transport_retry.initialHeader(&truncated_source) == null);
}

test "a handshake on a real socket leaves the client holding the NEW_TOKEN the server issued" {
    var client_secret = try SecretKey.fromSeed(client_seed);
    defer client_secret.deinit();
    var server_secret = try SecretKey.fromSeed(server_seed);
    defer server_secret.deinit();

    var link: Link = undefined;
    try link.init(client_secret, server_secret, server_secret.nodeId(), 61, .{});
    defer link.deinit();
    try link.drive(link_start, 32, bothUp);

    // The core issues a NEW_TOKEN once the handshake is confirmed, and only
    // when a token key is set: `connectionConfig` always supplies one, so this
    // is the harness's configuration showing up on the wire rather than a
    // default that happened to be there.
    try t.expectEqualSlices(u8, &token_key, &link.server.bridge.manager.retry_token_key);

    const token = link.client.live().?.entry.conn.getNewToken() orelse {
        link.report("retry", "the client holds no NEW_TOKEN after a completed handshake");
        return error.NoNewTokenIssued;
    };

    // The bytes came off a real socket, out of a real handshake, and they are a
    // token and not some other frame the connection was carrying: the length is
    // the one the core's format produces, and it is not zero.
    try t.expectEqual(transport_retry.new_token_length, token.len);
    try t.expect(token.len >= transport_retry.min_token_length);

    // Both ends sealed and read under the same key, which is the whole reason
    // `transport_quic_config.Config.retry_token_key` is one value on both bridges: a token sealed
    // under a key the reader does not hold would never validate, and the peer's
    // address would be re-validated the slow way on every connection for ever.
    try t.expectEqualSlices(u8, &token_key, &link.client.bridge.manager.retry_token_key);

    // The token is bound to the address the datagram actually came from, which
    // is the only claim source-address validation makes. A NEW_TOKEN answers
    // `unknown` even when it opens, because it is reusable: recording it would
    // drop the *second* connection that presents it, which is a filter dressed
    // up as a correctness check (`retry.zig:290-292`). The core is what
    // validates it, so the gate's whole job here was to decline to have an
    // opinion.
    try t.expectEqual(
        RetryVerdict.unknown,
        link.server.bridge.checkRetryToken(token, link.client.socket.address, link_start),
    );

    // And it is bound tightly enough to be worth binding: the same bytes
    // presented for any other address are `invalid` rather than `unknown`, so
    // the core knows this peer has not been proven yet.
    try t.expectEqual(
        RetryVerdict.invalid,
        link.server.bridge.checkRetryToken(token, link.server.socket.address, link_start),
    );
    try t.expectEqual(
        RetryVerdict.invalid,
        link.server.bridge.checkRetryToken(token, client_addr, link_start),
    );
}

/// What the client writes once the session is up, so that "the handshake
/// completed" is not the end of the claim.
const session_bytes = "bytes that crossed a Retry split across packets";

/// One protocol name at the bound: `max_alpn_name_len` bytes, the longest a
/// selection can hold whole — the server's walk skips an entry it cannot
/// (`tls13.zig:3149-3154`) — and so the longest `quic_config.validateAlpns` will
/// let `Dialer.create` offer. Its job is to fill the offer: seven of these
/// beside one real name is the largest list this stack sends, and none of it
/// is a protocol a peer could ever answer with.
const pad_alpn: [ozai.transport_quic_config.max_alpn_name_len]u8 = @splat('p');

/// What puts that ClientHello past a single datagram.
///
/// RFC 6066 puts no ceiling on a server name and nothing upstream bounds
/// one, so the core writes whatever the name's two-byte length field encodes
/// (`vendor/quic/src/quic/tls13.zig:4320-4336`) into the 4 KiB staging buffer
/// the builder is handed (`tls13.zig:2571-2573`), and nothing resolves this
/// name or checks it against anything (`quic_bridge.zig:661-663`): its length
/// is the message's length and nothing else.
///
/// 1008 bytes puts the whole message in the window that splits it across
/// exactly two Initial packets, for every transport parameter encoding the
/// core can produce:
///
/// * One Initial carries 1137 bytes of ClientHello on the flight that has no
///   token in it. The datagram is `min(max_packet_size, out_buf.len)`, and
///   `max_packet_size` is the 1200 of RFC 9000 §14.1 by default — the field's
///   own default `DEFAULT_MAX_PACKET_SIZE` (`packet_packer.zig:394`, `:227`,
///   `:88`) — which is what a client that has discovered no path MTU still
///   has, so the staging budget is 1184 once the AEAD tag is outside it
///   (`:583`).
///   `remaining_space` takes the 27-byte long header — the first byte, the
///   version, both ids, a zero token length, the length placeholder and a
///   one-byte packet number — the tag and the four bytes the header-protection
///   sample is reserved against off that (`:722`), and the CRYPTO frame's own
///   four-byte header fits in what is left of the staging buffer.
/// * The datagram is padded back to 1200 whatever that turned out to carry
///   (`:997`), which is what makes the second packet a 1200-byte one too.
/// * After a Retry every packet of the flight carries the token in that same
///   header, so the message has to clear the smaller of the two budgets to
///   still be two packets — which 1008 bytes of name does, at either end of
///   the range below.
/// * The transport parameters are whatever this connection encodes, at most
///   the core's own derived `encode_len_max` of 324 bytes
///   (`transport_params.zig:648`), which a maximal set costs 321 to 324 of
///   (`tls13.zig:7823-7824`), and this length has room for all of them.
///
/// None of which is left to be believed: the test counts the datagrams the
/// client's first flight is actually received as.
///
/// **And why both fragments come out the same size**, which is a property of
/// this length and not an accident to tune away: the message is ≈1535 bytes,
/// so the first Initial carries ≈1130 of it and packs to ≈1180 before the
/// §14.1 pad, and the tail carries ≈400 and packs to ≈450. Both are padded to
/// 1200, and two datagrams of one size are one segmented run
/// (`quic_conn.zig:122-128`), so this flight leaves the socket in a single
/// `sendmsg` — which is why the assertion below reads the datagrams the
/// *server* received rather than the runs the client wrote: one `sendmsg` is
/// not one datagram. Both numbers are arithmetic derived from the packet sizes
/// above, not measurements; so is the ≈1226 the padding ALPN names this
/// replaced gave for the tail fragment, which cleared the 1200 floor by only
/// ≈25 bytes and so came out a different size — that flight left the client
/// as two runs rather than one, and a run is not a unit a reader can count
/// datagrams in.
const pad_server_name: []const u8 = "ozai-retry-padding" ** 56;
comptime {
    std.debug.assert(pad_server_name.len == 1008);
}

/// How many rounds a phase may take. Generous, because a round is a few
/// syscalls over a loopback socket and nothing here blocks.
const max_rounds: usize = 32;

test "a ClientHello split across Initial packets after a Retry completes the session" {
    var client_secret = try SecretKey.fromSeed(client_seed);
    defer client_secret.deinit();
    var server_secret = try SecretKey.fromSeed(server_seed);
    defer server_secret.deinit();

    // **The offer this client sends.** The dialer is where a peer's own list
    // is chosen (`loopback_link.zig:319`), so this is the only place the
    // protocols are set — and what does not grow is the server's own list,
    // which is the one that decides what a connection runs on. This is the
    // largest offer the stack will send: the one real name, and seven at the
    // bound. It is not what makes the ClientHello long; `pad_server_name` is.
    var offers: [ozai.transport_quic_config.max_alpns][]const u8 = undefined;
    offers[0] = link_alpn;
    @memset(offers[1..], pad_alpn[0..]);

    // A server that answers an Initial with a Retry rather than with a
    // connection, which is the pre-accept path and the only place a Retry
    // token exists at all. Nothing else in this file's link asks for it.
    var link: Link = undefined;
    try link.init(client_secret, server_secret, server_secret.nodeId(), 71, .{
        .dial_alpns = &offers,
        .dial_server_name = pad_server_name,
        .server_require_retry = true,
    });
    defer link.deinit();
    // **That the ClientHello really is split**, counted where it arrives
    // rather than read back off the length of a padding constant: this round
    // moves the client's whole first flight onto the server's socket and the
    // same round's `take` reads it back, so `received[1]` is that flight's
    // datagram count, and one round is the only place it can be read at all.
    // Two is the number everything below is about, so a length that quietly
    // fitted the message into a single datagram fails here — the server would
    // have read one — rather than passing as the weaker claim it has become.
    //
    // **The receiver's count, not the sender's**, because the two were not
    // always the same unit and the claim is about the wire. Both fragments
    // carry the RFC 9000 §14.1 padding to 1200, so they are the same size and
    // leave the client as one segmented run (`loopback_link.zig:122-128`),
    // which is the shape this message was built to produce. `sent` is a
    // conversion off that: it adds `datagramCount()` per egress run
    // (`loopback_link.zig:574-586`), so it agrees with this one today, but
    // what it reports is a fact about how the client handed the packets over
    // rather than about how many crossed the wire. `received` is the server's
    // own `Recv.datagramCount` (`loopback_link.zig:630`) — a datagram count
    // whatever `UDP_GRO` did to the read — so the number asserted here is what
    // arrived at the far end, which is what this test is about.
    //
    // `step`'s answer is asserted rather than dropped, which is the one thing
    // this call site does that the `_ =` on `exchange` further down does not:
    // that round is the only one in the test whose whole job is to move the
    // client's first flight, so whether it moved anything is the claim, and
    // `drive` below is what treats a quiet round as a stall.
    try t.expect(try link.step(0, 1, link_start));
    try t.expectEqual(@as(usize, 2), link.received[1]);

    // The whole of the regression, in one line: a real client, a real Retry,
    // a real socket, and a ClientHello that arrives in two Initial packets
    // both carrying the one token. The second packet is addressed to the
    // connection the first one opened, so it is that connection's datagram —
    // and a filter standing in front of admission has no say over it. Dropped
    // there, this stalls with the ClientHello half-read, and `drive` says so.
    try link.drive(link_start, max_rounds, bothUp);

    // A Retry token really was issued and really was presented back: the
    // server's gate holds a record only for a token it was shown, and the
    // manager seals Retry tokens itself without going through the gate, so
    // one record here is one echo that arrived. Two would be a second
    // connection this node cannot account for.
    try t.expectEqual(@as(usize, 1), link.server.bridge.retryTokensTracked());

    const client = link.client.live().?;
    const server = link.server.live().?;
    // The padded names are padding: the protocol that came out is the one both
    // ends spoke, chosen by the server's own first match rather than by
    // whichever name happened to be longest.
    try t.expectEqualStrings(link_alpn, server.entry.conn.negotiatedAlpn());

    // **And application bytes cross it**, which is what a session is. A
    // unidirectional stream, written after the handshake and drained at the
    // far end, so what is proved is a connection carrying data rather than a
    // core that reached a state.
    var uni = try client.openUni();
    try t.expectEqual(session_bytes.len, try uni.write(session_bytes));
    uni.close();

    // The peer finds the stream only once its STREAM frame has arrived, and
    // the data is drained in a loop because one pass moves at most 64 runs.
    var received: ?ozai.transport_quic_stream.RecvUni = null;
    var round: usize = 0;
    while (round < max_rounds) : (round += 1) {
        _ = try link.exchange(link_start);
        if (server.acceptUni(0)) |taken| {
            received = taken;
            break;
        }
    }
    var incoming = received orelse {
        link.report("retry", "the peer never saw the unidirectional stream");
        return error.UniStreamMissing;
    };
    try t.expectEqual(uni.id(), incoming.id());
    var sink: std.ArrayList(u8) = .empty;
    defer sink.deinit(t.allocator);
    round = 0;
    while (round < max_rounds) : (round += 1) {
        _ = try link.exchange(link_start);
        _ = try incoming.drain(t.allocator, &sink);
        if (incoming.finished() and sink.items.len == session_bytes.len) break;
    }
    try t.expect(incoming.finished());
    try t.expectEqualStrings(session_bytes, sink.items);
}
