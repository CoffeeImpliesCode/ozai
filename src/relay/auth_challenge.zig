//! The relay's half of proving a peer: one challenge, belonging to one
//! connection, good for a bounded while, with the connection named inside the
//! bytes the peer signs.
//!
//! Upstream `iroh-relay` draws sixteen bytes and checks the signature that comes
//! back (`handshake.rs:77`, `:234-247`); `relay/client.zig` reproduces the bytes
//! and the derivation. What upstream does not have, and this module does, is a
//! *binding*. Upstream's binding is the draw itself: the relay verifies an
//! answer against the challenge it issued on this connection, so a credential
//! captured on one connection fails on another for exactly as long as no CSPRNG
//! ever repeats sixteen bytes. That is a 2^-128 argument, and `AGENTS.md` §2
//! holds that a 2^-128 argument about a security property is an assumption, not
//! a property.
//!
//! So the connection id and the instant the challenge was issued go **into the
//! message that is signed**. Two connections then ask for different signatures
//! even when both drew the same sixteen bytes, and a replay is refused because
//! the message does not match rather than because the draw differed.
//!
//! # The divergence, said rather than buried
//!
//! An upstream iroh client signs `client.messageToSign` and this relay verifies
//! `messageToSign` below, so **an upstream client and this relay do not
//! authenticate each other**. The derivation here is upstream's with two fields
//! appended, so the two differ by a suffix rather than by a design, but they
//! differ, and nothing in this tree is a test that says otherwise.
//!
//! Nothing in this tree can close that today, and the next section says why.
//! What would close it: a relay on the upstream listener, with a captured
//! upstream challenge transcript to compare against. No such transcript exists
//! on this machine.
//!
//! # Which authentication path exists here
//!
//! Only the signed challenge. `Mechanism.signed_key_material` needs
//! `server_handshake.Offer.material`, which is a TLS exporter's export
//! (RFC 5705), and nothing in this tree produces one: `vendor/quic/` holds no
//! occurrence of `export_keying_material`, `exporter` or `exported_keying`, and
//! `client.KeyMaterial` appears in no module but `relay/client.zig` and the
//! tests that synthesise one out of a number. `relay/carrier.zig` says the same
//! about why and names the debt — a relay connection here is a QUIC stream
//! rather than a WebSocket over a TCP socket, and the TCP listener stays
//! `docs/DECISIONS/0001`'s open item because `std.crypto.tls` has a client-only
//! driver with no server. So `Offer.material` is null, `KeyMaterialAuth.verify`
//! answers `error.NoKeyingMaterial`, and `server_handshake.admit` takes this
//! path for every client this relay will ever admit.
//!
//! # Challenge first, access second
//!
//! The challenge is issued **before** access control is asked, and this module
//! cannot be used the other way round: `issue` takes no node id, because at that
//! point there is no proven one, and `server_handshake.step` takes `.access`
//! only from `.authenticated`, so a policy is never asked about an unproven
//! claim.
//!
//! The order costs one ed25519 verification on a peer the operator may go on to
//! refuse. Asking first costs an oracle: a stranger who sent any signature at
//! all would learn whether their node id is on this relay's list, and that is
//! the one answer access control must not give to a peer nobody has
//! authenticated. A peer that proves who it is and is then refused is refused
//! *by name*, which is what `access_policy.Reason` exists to carry.
//! Authenticate, then admit.

const std = @import("std");

const client = @import("client.zig");
const frame = @import("frame.zig");
const registry = @import("server_registry.zig");

/// Nanoseconds on a monotonic timeline the caller owns. See `client.Nanos`.
pub const Nanos = client.Nanos;

/// Which connection is asking. See `server_registry.ConnectionId`.
pub const ConnectionId = registry.ConnectionId;

/// The sixteen bytes that go on the wire. See `frame.ServerChallenge`.
pub const ServerChallenge = frame.ServerChallenge;

/// How long an answer stays good when the caller names no other number.
///
/// Ten seconds: an answer is one round trip and a relay round trip is
/// milliseconds, so this is slack measured in orders of magnitude rather than a
/// figure anybody tuned. Upstream has no number here at all — a challenge is
/// good until the connection dies, and in this tree a connection is a QUIC
/// stream that may idle indefinitely while the relay holds the record — so the
/// bound is this module's and is published rather than left to each caller to
/// invent.
pub const default_lifetime: Nanos = 10 * std.time.ns_per_s;

/// Why a challenge could not be issued.
pub const IssueError = error{
    /// A zero lifetime mints a challenge that is already dead, which is a
    /// challenge no answer could ever satisfy and a record that fails every
    /// check made of it.
    ZeroLifetime,
    /// The window would end past the end of the timeline. A saturating sum
    /// would instead mint an expiry that never arrives, which is the one record
    /// this module exists to prevent.
    LifetimeTooLong,
};

/// Why a challenge is not worth answering.
pub const LivenessError = error{
    /// `now` is at or past the instant the challenge stopped being good.
    Expired,
    /// `now` is before the challenge was issued. That is a caller that mixed two
    /// timelines rather than a peer that did anything, and it is refused anyway.
    NotYetValid,
};

/// One challenge, issued on one connection at one instant.
///
/// **A value, and the whole of what binds a credential to a connection.** Every
/// field is a value, so the relay keeps one beside the
/// `server_handshake.State.challenged` that carries the same sixteen bytes, and
/// the two are for the same connection: `challenge` is what goes on the wire and
/// `connection_id` is part of what the peer is asked to sign over.
///
/// `issue` mints one. A caller that builds this struct itself has asserted
/// nothing about the window, and `checkLive` is the only thing that reads it.
pub const Issued = struct {
    /// The connection this challenge belongs to. A credential signed for
    /// another one names a different message and does not verify.
    connection_id: ConnectionId,
    /// The sixteen bytes on the wire, drawn by the caller from a CSPRNG. This
    /// module draws nothing and reads no clock.
    challenge: ServerChallenge,
    /// When it went out, on the caller's timeline.
    issued_at: Nanos,
    /// When it stopped being good. The window is half-open, so this is the first
    /// instant that is too late rather than the last that is all right.
    expires_at: Nanos,
};

/// Domain separation for the answer's signature.
///
/// **This string is ozai's and not upstream's.** Upstream's is
/// `DOMAIN_SEP_CHALLENGE` (`handshake.rs:52`), reproduced privately by
/// `relay/client.zig`, and a derivation under it cannot carry a connection id.
/// The two agree on nothing but the shape of the idea, and a peer signing under
/// one is not answering the other.
const answer_domain = "ozai relay handshake v1 bound challenge answer";

comptime {
    // The connection id and the instant both reach the derivation as fixed
    // eight-byte big-endian values, so their widths and their byte order are
    // part of the protocol rather than a property of the machine that ran it.
    std.debug.assert(@sizeOf(ConnectionId) == 8);
    std.debug.assert(@sizeOf(Nanos) == 8);
}

/// Mint a challenge for one connection, good from `now` for `lifetime`.
///
/// Pure, and free of every hidden input: the randomness is the caller's
/// argument and so is the instant, so the same four arguments produce the same
/// record on any machine and in any interleaving of threads. Nothing is
/// allocated, nothing is retained, and no clock is read.
///
/// **The window is half-open.** `now` is inside it and `now + lifetime` is the
/// first instant outside it, so a peer has one whole lifetime and not a
/// nanosecond more.
pub fn issue(
    connection_id: ConnectionId,
    challenge: ServerChallenge,
    now: Nanos,
    lifetime: Nanos,
) IssueError!Issued {
    if (lifetime == 0) return error.ZeroLifetime;
    const expires_at = std.math.add(Nanos, now, lifetime) catch return error.LifetimeTooLong;
    return .{
        .connection_id = connection_id,
        .challenge = challenge,
        .issued_at = now,
        .expires_at = expires_at,
    };
}

/// Whether a challenge is still worth answering at `now`.
///
/// The only clock a connection has here is the one its caller measured, so
/// `now` is an argument and not a read. Two instants are comparable only when
/// they came from the same timeline: a `now` from another one lands on the wrong
/// side of one of these comparisons, and both answers are refusals.
pub fn checkLive(issued: Issued, now: Nanos) LivenessError!void {
    if (now < issued.issued_at) return error.NotYetValid;
    if (now >= issued.expires_at) return error.Expired;
}

/// The message a peer signs to answer this challenge: upstream's derived
/// challenge message with the connection id and the instant appended.
///
/// **The connection binding is the whole point of this function.** Upstream
/// derives from the sixteen bytes alone (`client.messageToSign`), so two
/// challenges carrying the same bytes ask for the same signature; this one
/// derives from the bytes and from who issued them and when, so two connections
/// ask for different signatures and a credential captured on one is refused on
/// the other by anyone who does not hold that peer's key.
///
/// The result is a value: the signer may drop it the moment the signature
/// exists, and the record it came from may be released immediately after.
pub fn messageToSign(issued: Issued) [32]u8 {
    var hasher = std.crypto.hash.Blake3.initKdf(answer_domain, .{});
    hasher.update(&client.messageToSign(issued.challenge));
    var binding: [@sizeOf(ConnectionId) + @sizeOf(Nanos)]u8 = undefined;
    std.mem.writeInt(ConnectionId, binding[0..8], issued.connection_id, .big);
    std.mem.writeInt(Nanos, binding[8..16], issued.issued_at, .big);
    hasher.update(&binding);
    var message: [32]u8 = undefined;
    hasher.final(&message);
    return message;
}

// --- tests

const t = std.testing;

/// A challenge from a fixed pattern, which is what `server_handshake.zig` does
/// for the same reason: a module that draws randomness is not one a test can
/// drive, and the draw is not what is under test.
const test_challenge: ServerChallenge = .{ .challenge = @splat(0x5a) };

/// An instant far enough from zero that `issued_at - 1` does not underflow.
const start: Nanos = 1_000_000_000;

test "a challenge names the connection that issued it and the instant it went out" {
    // Two connections that drew the *same* sixteen bytes at the *same* instant,
    // which is the case upstream's derivation cannot tell apart at all.
    const first = try issue(1, test_challenge, start, default_lifetime);
    const second = try issue(2, test_challenge, start, default_lifetime);
    try t.expectEqualSlices(u8, &first.challenge.challenge, &second.challenge.challenge);
    try t.expect(first.issued_at == second.issued_at);
    try t.expect(!std.meta.eql(messageToSign(first), messageToSign(second)));

    // The instant is bound as well, so an answer cannot be carried from one draw
    // of the same sixteen bytes to a later draw of them.
    const later = try issue(1, test_challenge, start + 1, default_lifetime);
    try t.expect(!std.meta.eql(messageToSign(first), messageToSign(later)));

    // And the derivation is a function of the record alone, which is what lets
    // the relay hold the record while the peer holds only its answer.
    const again = try issue(1, test_challenge, start, default_lifetime);
    try t.expectEqual(messageToSign(first), messageToSign(again));

    // Upstream's derivation is the counterfactual this test exists for: from the
    // same sixteen bytes it produces the same message, so a credential captured
    // under it would verify on the second connection.
    const upstream_first = client.messageToSign(first.challenge);
    const upstream_second = client.messageToSign(second.challenge);
    try t.expectEqual(upstream_first, upstream_second);
}

test "a lifetime that cannot be a window is refused rather than clamped" {
    // Zero mints a challenge no answer could ever satisfy, which is a challenge
    // with no purpose and a record that fails every check made of it.
    try t.expectError(error.ZeroLifetime, issue(1, test_challenge, start, 0));

    // The far end of the timeline. Clamping here would mint the one record this
    // module exists to refuse: an expiry that never arrives.
    const at_end: Nanos = std.math.maxInt(Nanos);
    try t.expectError(error.LifetimeTooLong, issue(1, test_challenge, at_end, 1));
    try t.expectError(error.LifetimeTooLong, issue(1, test_challenge, at_end, default_lifetime));

    // The largest window that is still a window is accepted, and it ends on the
    // last representable instant rather than past it.
    const widest = try issue(1, test_challenge, start, std.math.maxInt(Nanos) - start);
    try t.expectEqual(std.math.maxInt(Nanos), widest.expires_at);
}

test "the window is half-open and holds exactly the instants inside it" {
    const issued = try issue(1, test_challenge, start, default_lifetime);
    try t.expectEqual(start + default_lifetime, issued.expires_at);

    // The first instant inside it is the one it went out at.
    try t.expectError(error.NotYetValid, checkLive(issued, start - 1));
    try checkLive(issued, start);
    try checkLive(issued, issued.expires_at - 1);

    // And the first instant outside is the one it ends at, not one past it, so
    // a peer gets one whole lifetime and no more.
    try t.expectError(error.Expired, checkLive(issued, issued.expires_at));
    try t.expectError(error.Expired, checkLive(issued, issued.expires_at + 1));
}

test "every liveness failure has an instant that produces it" {
    // A sweep over the error set rather than two assertions, so an arm added to
    // `LivenessError` with no way to reach it fails this test instead of
    // sitting in the set uncovered.
    const issued = try issue(1, test_challenge, start, default_lifetime);
    const outside_instant: Outside = .{
        .Expired = issued.expires_at,
        .NotYetValid = issued.issued_at - 1,
    };
    inline for (@typeInfo(LivenessError).error_set.?) |member| {
        const failure: LivenessError = @field(LivenessError, member.name);
        try t.expectError(failure, checkLive(issued, @field(outside_instant, member.name)));
    }

    // The third outcome is not a failure, and the sweep would have named it if
    // it had been one.
    try checkLive(issued, issued.issued_at);
}

/// An instant that is outside a window, named by the failure it produces.
///
/// The mapping is a struct rather than a switch so that an arm added to
/// `LivenessError` fails the test above for having no instant, rather than
/// failing the build with an inexhaustive switch.
const Outside = struct {
    Expired: Nanos,
    NotYetValid: Nanos,
};
