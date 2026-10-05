//! The peer's half of a relay's proof: the credential it sends back, and the
//! one check that turns a credential into an identity.
//!
//! Upstream `handshake.rs:225-247` is two functions over a bare
//! `ClientAuth { public_key, signature }` and the sixteen bytes the relay sent;
//! `relay/client.zig` reproduces both. What this module adds is the connection
//! the credential was issued on and the window it is good for, both carried by
//! `relay/auth_challenge.zig`'s `Issued` — the record the relay holds and the
//! peer never sees.
//!
//! # The identity this returns
//!
//! `verify` answers with the `NodeId` whose key verified, and that is the only
//! identity in this tree worth anything: a node id nobody signed for is a claim.
//! The caller builds `access_policy.Identity` out of it, the same record's
//! `connection_id` and `Mechanism.signed_challenge`; that module already
//! defines all three fields, so nothing here has to know it exists.
//!
//! # Pure, and drivable to its edges
//!
//! `now` is an argument because a relay that read a clock would be undrivable
//! and its expiry untestable. Nothing is allocated, nothing is retained, and both
//! functions are total over their arguments, so two relays verifying two answers
//! at the same instant may run on any thread.
//!
//! # What is not claimed
//!
//! No interoperability, and none is testable here: `relay/auth_challenge.zig`
//! gives the divergence from upstream's derivation and the reason for it, and
//! the two reasons there — an exporter this relay cannot take and a TCP listener
//! `docs/DECISIONS/0001` still owes — mean there is no upstream peer on the far
//! end of a challenge to pin a transcript to.

const std = @import("std");

const key = @import("../base/key.zig");
const frame = @import("frame.zig");
const challenge = @import("auth_challenge.zig");

/// The node id a credential is about.
pub const NodeId = key.NodeId;

/// The peer's key, and the only thing that answers a challenge.
pub const SecretKey = key.SecretKey;

/// The record of the challenge this credential answers.
pub const Issued = challenge.Issued;

/// Nanoseconds on a monotonic timeline the caller owns. See `challenge.Nanos`.
pub const Nanos = challenge.Nanos;

/// The credential, in the shape it has on the wire.
///
/// Upstream `ClientAuth` (`handshake.rs:88`), which `relay/frame.zig` already
/// carries, so this is a name and not a second representation: the same bytes go
/// into the frame and in front of `verify`, and there is no conversion between
/// the two that could disagree with itself.
pub const Credential = frame.ClientAuth;

/// Why a credential was refused.
///
/// Composed rather than restated, because the window's failures are the
/// credential's failures and a caller handling `LivenessError` has to handle
/// both of them anyway.
pub const VerifyError = challenge.LivenessError || error{
    /// The signature does not verify under the node id the credential claims,
    /// over the message this connection's record derives. One arm for every
    /// cause — another key, another connection, another instant, a truncated
    /// signature — because the peer learns the same thing from all of them, and
    /// a relay that named them would tell a prober which one to fix.
    SignatureInvalid,
};

/// The credential this peer sends to answer a challenge on this connection.
///
/// The secret is borrowed for the call and never copied or retained: the node id
/// and the signature come out by value, so the caller may zero its key the moment
/// this returns. The message is derived here rather than taken, so a caller
/// cannot answer with the wrong binding by accident — and cannot answer anything
/// except a challenge this record describes.
///
/// Upstream `ClientAuth::new` (`handshake.rs:225-230`) with the one difference
/// the binding is: upstream signs `client.messageToSign`, and this signs
/// `challenge.messageToSign`.
pub fn answer(secret: *const SecretKey, issued: Issued) Credential {
    return .{
        .node_id = secret.nodeId(),
        .signature = secret.*.sign(&challenge.messageToSign(issued)),
    };
}

/// Check an answer against the record of the challenge it claims to answer.
///
/// `issued` is the relay's own record for **this** connection and not one that
/// arrived with the credential. There is no field in the credential that names
/// a connection, so the only way an answer can be about this one is that it
/// signs the message this record derives — which is the whole binding, and the
/// reason a credential captured on another connection is refused here even when
/// the two challenges carry the same sixteen bytes.
///
/// **The window is checked first, and that order is the answer.** An answer to a
/// challenge that is no longer live is refused as too late whatever it is signed
/// with, and refusing it before the verification is both cheaper and more
/// honest: a lapsed challenge has exactly one answer, and the signature is not
/// the reason.
///
/// The check is `Signature.verifyStrict` rather than `Signature.verify`, because
/// the node id arrived from a peer rather than from `NodeId.fromBytes`, and
/// `base/key.zig` calls the strict form the right one on any key off the network:
/// it rejects small-order and non-canonical keys, as iroh's strict form does.
///
/// The `NodeId` that comes back is the one the signature verified under, so it
/// is the peer's identity and not the claim it made.
pub fn verify(credential: Credential, issued: Issued, now: Nanos) VerifyError!NodeId {
    try challenge.checkLive(issued, now);
    const message = challenge.messageToSign(issued);
    credential.signature.verifyStrict(&message, credential.node_id) catch
        return error.SignatureInvalid;
    return credential.node_id;
}

// --- tests

const t = std.testing;

const relay_test_ids = @import("relay_test_ids.zig");

/// A challenge from a fixed pattern, for the reason `auth_challenge.zig` gives:
/// a module that draws randomness is not one a test can drive.
const test_challenge: challenge.ServerChallenge = .{ .challenge = @splat(0x5a) };

/// An instant far enough from zero that `issued_at - 1` does not underflow.
const start: challenge.Nanos = 1_000_000_000;

/// A record for one connection: the same sixteen bytes at the same instant every
/// time, so a test about the binding cannot pass on a differing draw.
fn issuedFor(connection_id: challenge.ConnectionId) !Issued {
    return challenge.issue(connection_id, test_challenge, start, challenge.default_lifetime);
}

test "a correct answer proves the peer that signed it at every instant it is live" {
    const secret = try relay_test_ids.testSecret(40);
    const issued = try issuedFor(1);
    const credential = answer(&secret, issued);

    // The credential is the frame, so the bytes on the wire are what is checked
    // and the identity that comes back is the signer's own.
    try t.expectEqual(secret.nodeId(), credential.node_id);
    try t.expectEqual(secret.nodeId(), try verify(credential, issued, issued.issued_at));
    const last_good = issued.expires_at - 1;
    try t.expectEqual(secret.nodeId(), try verify(credential, issued, last_good));

    // And the answer really is a signature of this record's message rather than
    // of something else the caller happened to sign, which is what makes the id
    // above an identity and not a field read back. Deterministic ed25519 lets
    // that be asserted exactly rather than approximately.
    const signed = secret.sign(&challenge.messageToSign(issued));
    const expected: Credential = .{ .node_id = secret.nodeId(), .signature = signed };
    try t.expectEqual(expected, answer(&secret, issued));
}

test "an answer signed by a key that does not own the id it claims is refused" {
    const owner = try relay_test_ids.testSecret(41);
    const impostor = try relay_test_ids.testSecret(42);
    const issued = try issuedFor(1);

    // The only shape of a wrong signature: one node id claimed and a different
    // key signing for it, which is what upstream's `ClientAuth::verify` rejects
    // and what `server_handshake` turns into `invalid_signature_reason`.
    const forged: Credential = .{
        .node_id = owner.nodeId(),
        .signature = impostor.sign(&challenge.messageToSign(issued)),
    };
    try t.expectError(error.SignatureInvalid, verify(forged, issued, issued.issued_at));

    // The honest answer from the same record at the same instant is not refused,
    // so what refused the other was the key rather than the record.
    const honest = answer(&owner, issued);
    try t.expectEqual(owner.nodeId(), try verify(honest, issued, issued.issued_at));
}

test "an answer captured on one connection does not verify on another" {
    const secret = try relay_test_ids.testSecret(43);

    // Two connections that drew the same sixteen bytes at the same instant, so
    // the binding is the only thing that could tell the two apart.
    const first = try issuedFor(1);
    const second = try issuedFor(2);
    try t.expectEqualSlices(u8, &first.challenge.challenge, &second.challenge.challenge);
    try t.expect(first.issued_at == second.issued_at);

    // A credential lifted off the first connection and replayed on the second is
    // refused, which is the case upstream's derivation leaves to a CSPRNG that
    // never repeats sixteen bytes.
    const captured = answer(&secret, first);
    try t.expectError(error.SignatureInvalid, verify(captured, second, second.issued_at));

    // And it is refused for being about the wrong connection, not for being bad:
    // the same bytes still verify where they were issued, inside the window.
    try t.expectEqual(secret.nodeId(), try verify(captured, first, first.issued_at));
}

test "an answer to a challenge that is no longer live is refused as too late" {
    const secret = try relay_test_ids.testSecret(44);
    const issued = try issuedFor(1);
    const credential = answer(&secret, issued);

    // The last instant it is good, and the first that is too late: the window is
    // half-open, so a peer gets one whole lifetime and not a nanosecond more.
    const last_good = issued.expires_at - 1;
    try t.expectEqual(secret.nodeId(), try verify(credential, issued, last_good));
    try t.expectError(error.Expired, verify(credential, issued, issued.expires_at));
    try t.expectError(error.Expired, verify(credential, issued, issued.expires_at + 1));
    try t.expectError(error.NotYetValid, verify(credential, issued, issued.issued_at - 1));

    // A window decides before a signature does. An answer that is both late and
    // signed by the wrong key is reported late, because that is the whole reason
    // it was going to be refused and the signature was never going to be read.
    const wrong_key = try relay_test_ids.testSecret(45);
    const forged: Credential = .{
        .node_id = secret.nodeId(),
        .signature = wrong_key.sign(&challenge.messageToSign(issued)),
    };
    try t.expectError(error.Expired, verify(forged, issued, issued.expires_at));
}