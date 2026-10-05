//! Issuing a challenge and reading its answer: the two halves of the handshake
//! that `relay/server_handshake.zig` deliberately does not bind to a
//! connection.
//!
//! # Why this file exists when the machine already has a challenge path
//!
//! `server_handshake.State.challenged` carries sixteen bytes and nothing else,
//! and its `.client_auth` arm verifies them with `client.verifyClientAuth` —
//! upstream's derivation (`handshake.rs:234-247`), which is a function of the
//! sixteen bytes alone. `relay/auth_challenge.zig` gives an `Issued` record that
//! also names the connection it was issued on and the instant it went out, and
//! `relay/auth_credential.zig` verifies against that record.
//!
//! **The two verifications cannot both run, and the consequence is a name this
//! file has to refuse.** A credential signed over
//! `auth_challenge.messageToSign` does **not** verify under
//! `client.messageToSign`, so a peer that has satisfied this module's binding
//! has failed `server_handshake`'s own check, and one that has satisfied that
//! check proves no connection binding at all. There is no credential that
//! satisfies both. A relay therefore chooses, and this file is the half that
//! does not verify: it builds the `.authenticated` state itself and hands the
//! caller a value to step from. Routing the answer through
//! `server_handshake.step` instead would be a way to write a bound credential
//! that the relay then refuses for being bound.
//!
//! That is the same divergence `auth_challenge.zig` states against upstream's
//! `client.messageToSign`, carried one step further: this file's own answer does
//! not satisfy the machine this tree already has. Nothing here is testable
//! against a captured upstream transcript, because no such transcript exists on
//! this machine.
//!
//! # A refusal is named, and the name is uniform on the wire
//!
//! **Every failed proof is written as `server_denies_auth`, never dropped.**
//! A silent close is indistinguishable from a network fault to the peer, which
//! then retries forever against a relay that will never answer it, and it tells
//! the operator nothing at all: no counter, no sentence, no way to tell a
//! prober from a client with a stale clock. `frame.ServerDeniesAuth` exists on
//! the wire for exactly this, and upstream writes it (`handshake.rs:458-466`).
//!
//! **The wire sentence is the same for all four failures, and that is the
//! point.** `auth_credential.zig` says why: the peer learns the same thing from
//! all of them, and a relay that named which one would tell a prober which
//! field to fix. So `Failure` is an operator's code and `refusal_sentence` is
//! one comptime literal, upstream's own, which is both bounded well inside
//! `max_reason_length` and byte-identical to what `server_handshake` writes for
//! a failed challenge. The operator's counters read `Failure`; the peer reads
//! upstream's sentence.
//!
//! # The connection binding, and the check beside it
//!
//! The binding is inside the signed message: `auth_challenge.messageToSign`
//! folds the `ConnectionId` and the instant into what the peer signs, so a
//! credential captured on one connection names a different message on another
//! and is refused there by anyone who does not hold the peer's key.
//!
//! **That binding cannot see a relay filing its own records wrongly.** A relay
//! that kept one `Issued` per connection and handed the wrong one to `verify`
//! would be asking about a connection the peer never saw, and the record would
//! be entirely self-consistent. So `verify` takes the connection the frame
//! arrived on *as a separate argument* and compares it with the record's own
//! before it reads the window or the signature. That comparison is first,
//! because it is about the relay rather than about the peer, and a peer that
//! did nothing must not be reported as having failed.

const std = @import("std");

const access_policy = @import("access_policy.zig");
const auth_challenge = @import("auth_challenge.zig");
const auth_credential = @import("auth_credential.zig");
const frame = @import("frame.zig");
const handshake = @import("server_handshake.zig");

/// Which connection is asking. See `server_registry.ConnectionId`.
pub const ConnectionId = auth_challenge.ConnectionId;

/// Nanoseconds on a monotonic timeline the caller owns. See `client.Nanos`.
pub const Nanos = auth_challenge.Nanos;

/// The sixteen bytes that go on the wire. See `frame.ServerChallenge`.
pub const ServerChallenge = auth_challenge.ServerChallenge;

/// The answer a peer sends back. See `frame.ClientAuth`.
pub const Credential = auth_credential.Credential;

/// The identity a verified credential proves. See `base/key.NodeId`.
pub const NodeId = auth_credential.NodeId;

/// The relay's own record of a challenge: connection, bytes, window.
pub const Issued = auth_challenge.Issued;

/// Why a challenge could not be issued. See `auth_challenge.IssueError`.
pub const IssueError = auth_challenge.IssueError;

/// How long an answer stays good when the caller names no other number.
pub const default_lifetime = auth_challenge.default_lifetime;

/// How a peer proved it owns the node id it claimed.
pub const Mechanism = handshake.Mechanism;

/// The sentence every failed proof is written with, on the wire.
///
/// **Upstream's own, and identical to `server_handshake`'s.** One literal for
/// every arm of `Failure`, because the four failures are four different things
/// to go and look at and are one thing to the peer: a named refusal that
/// distinguishes them would be an oracle saying which field to correct. A
/// comptime literal has static lifetime, so nothing here allocates and the
/// denial a caller holds borrows no buffer of its own.
pub const refusal_sentence = handshake.invalid_signature_reason;

/// Why a proof was refused, for the operator's counters and log.
///
/// **Not what the peer reads.** `refusal_sentence` is that, and it is the same
/// for every arm here. An operator's counter aggregates these; a sentence
/// cannot be aggregated by, which is the whole of the distinction and the whole
/// of why this is an enum rather than a string.
pub const Failure = enum {
    /// The signature does not verify under the node id the credential claims.
    /// Another key, another connection, another instant, a truncated signature:
    /// one arm, because the peer learns the same thing from all of them.
    signature_invalid,
    /// The challenge stopped being good before the answer arrived. The peer's
    /// latency, a busy relay, or an operator's clock; not the peer's fault.
    challenge_expired,
    /// `now` is before the challenge went out, which is a relay mixing two
    /// timelines rather than a peer doing anything.
    clock_mismatch,
    /// The relay handed `verify` a record belonging to another connection. A
    /// relay's own filing mistake, and the one arm here no peer can cause.
    connection_mismatch,
};

/// The operator's name for a verification failure.
///
/// Exhaustive over `auth_credential.VerifyError` by construction: a new arm
/// there fails to compile here rather than being swept into a refusal with no
/// name.
pub fn failureFor(failure: auth_credential.VerifyError) Failure {
    return switch (failure) {
        error.SignatureInvalid => .signature_invalid,
        error.Expired => .challenge_expired,
        error.NotYetValid => .clock_mismatch,
    };
}

/// A challenge that has gone out, and the frame that put it there.
///
/// Both halves come from one call because the relay cannot do the second
/// without the first: the record names the connection and the window, and the
/// sixteen bytes on the wire are what that record is about.
pub const Challenge = struct {
    /// What the relay keeps for this connection until the answer arrives.
    issued: Issued,
    /// The one frame to write, and the action `server_handshake.step` produces
    /// for the same challenge. A bare action rather than a `Step`: a challenge
    /// always owes one, so there is no null for a caller to handle.
    action: handshake.Action,
};

/// Issue one connection's challenge.
///
/// Pure, and free of every hidden input: the sixteen bytes are the caller's
/// argument and so is the instant, so the same four produce the same record on
/// any machine and in any interleaving of threads. Nothing is allocated,
/// nothing is retained, and no clock is read.
///
/// `lifetime` is half-open. `default_lifetime` is the figure this module
/// publishes for a caller with no other opinion, not a default: `IssueError`
/// refuses the two windows that could not be one.
pub fn issue(
    connection_id: ConnectionId,
    challenge: ServerChallenge,
    now: Nanos,
    lifetime: Nanos,
) IssueError!Challenge {
    return .{
        .issued = try auth_challenge.issue(connection_id, challenge, now, lifetime),
        .action = .{ .write = .{ .server_challenge = challenge } },
    };
}

/// A peer that has proved it owns `node_id`, and the state a relay keeps.
///
/// Both fields, because both are needed and neither is derived from the other
/// at the call site: the registry files a peer by node id and the handshake
/// machine stores the state, and a caller that built one from the other by hand
/// would have given them a second place to disagree.
pub const Proof = struct {
    /// The node id the signature verified under, which is the peer's identity
    /// and not the claim it made.
    node_id: NodeId,
    /// `.{ .authenticated = proof }`, ready for an `Event.access`. It carries
    /// no access decision, because that is the caller's and this module owns
    /// none.
    state: handshake.State,

    /// What `access_policy` is asked about this peer.
    ///
    /// The mechanism is `.signed_challenge` and not a field, because this file
    /// only ever verifies a challenge. A relay that did verify key material
    /// would not come through here at all, and `relay/relay_auth_policy.zig` is
    /// where that asymmetry is named.
    pub fn identity(self: Proof, connection_id: ConnectionId) access_policy.Identity {
        return .{
            .node_id = self.node_id,
            .connection_id = connection_id,
            .mechanism = .signed_challenge,
        };
    }
};

/// A proof that was refused: what failed, the state to keep, and the frame to
/// write.
///
/// Terminal, like every `server_handshake.State.denied`: a caller that keeps
/// stepping it is told nothing new rather than handed a second outcome.
pub const Refusal = struct {
    /// The operator's name for what failed. Never reaches the wire.
    failure: Failure,
    /// The state to store. Holds `refusal_sentence`, which has static lifetime.
    state: handshake.State,
    /// The one action, and it is a frame. **There is no arm in which a failed
    /// proof closes the connection without writing**, and that is the decision
    /// this type exists to make unrepresentable rather than merely documented.
    action: handshake.Action,
};

/// What one answer came to.
pub const Answer = union(enum) {
    /// The peer proved it. Step an `Event.access` into `Proof.state`.
    proved: Proof,
    /// The peer is refused by name.
    refused: Refusal,
};

/// Check one answer against the record of the challenge it claims to answer.
///
/// `on` is the connection the frame arrived on, and it is a separate argument
/// on purpose. Nothing in `Credential` names a connection — upstream's
/// `ClientAuth` is a public key and a signature — so the only way an answer can
/// be about this connection is that it signs the message this record derives,
/// and the record is the relay's own. A relay that files records wrongly is
/// therefore invisible to the derivation, and `on` is what makes it visible.
///
/// The order is the argument: the connection before the window, and the window
/// before the signature, cheapest and most-relay-our-own first. A relay's
/// filing mistake is then never reported as a peer's expired challenge, and a
/// lapsed challenge is never reported as a bad signature.
///
/// Pure and total over its arguments. Nothing is retained and no clock is read;
/// `now` is an argument because a relay that read one would be undrivable.
pub fn verify(
    issued: Issued,
    on: ConnectionId,
    presented: Credential,
    now: Nanos,
) Answer {
    if (on != issued.connection_id) return .{ .refused = refuse(.connection_mismatch) };
    const node_id = auth_credential.verify(presented, issued, now) catch |failure|
        return .{ .refused = refuse(failureFor(failure)) };
    return .{ .proved = .{
        .node_id = node_id,
        .state = .{ .authenticated = .{ .node_id = node_id, .mechanism = .signed_challenge } },
    } };
}

/// The one refusal, built once so its state and its frame cannot disagree.
fn refuse(failure: Failure) Refusal {
    return .{
        .failure = failure,
        .state = .{ .denied = .{ .reason = refusal_sentence } },
        .action = .{ .write = .{ .server_denies_auth = .{ .reason = refusal_sentence } } },
    };
}

// --- tests

const t = std.testing;

const relay_test_ids = @import("relay_test_ids.zig");

/// A challenge from a fixed pattern. A module that drew its own randomness
/// would not be one a test can drive, and the draw is not what is under test.
const test_challenge: ServerChallenge = .{ .challenge = @splat(0x5a) };

/// An instant far enough from zero that `issued_at - 1` does not underflow.
const start: Nanos = 1_000_000_000;

/// One challenge issued for `connection_id`, at `start`, with the same sixteen
/// bytes every time — so a test about the binding cannot pass on a differing
/// draw.
fn issuedFor(connection_id: ConnectionId) !Challenge {
    return issue(connection_id, test_challenge, start, default_lifetime);
}

test "a challenge goes out as sixteen bytes and the answer names the signer" {
    const secret = try relay_test_ids.testSecret(60);
    const issued = try issuedFor(1);

    // The action is the upstream challenge frame, and its bytes survive the
    // real codec unchanged. This is the claim that the binding added nothing to
    // the wire: the same sixteen bytes an upstream peer reads are the ones read
    // here, and only the thing the peer signs differs.
    var out: [64]u8 = undefined;
    const written = try frame.encode(issued.action.write, .v2, &out);
    const read = try frame.decode(written, .v2);
    try t.expectEqualSlices(u8, &test_challenge.challenge, &read.server_challenge.challenge);

    // A correct answer proves the peer that signed it, and lands in the state
    // the machine's access arm is stepped from.
    const answered = auth_credential.answer(&secret, issued.issued);
    const proof = verify(issued.issued, 1, answered, issued.issued.issued_at).proved;
    try t.expectEqual(secret.nodeId(), proof.node_id);
    try t.expectEqual(
        handshake.State{ .authenticated = .{
            .node_id = secret.nodeId(),
            .mechanism = .signed_challenge,
        } },
        proof.state,
    );

    // And the record a policy is asked about is the same identity, on the same
    // connection, with the mechanism this module can actually verify.
    try t.expectEqual(
        access_policy.Identity{
            .node_id = secret.nodeId(),
            .connection_id = 1,
            .mechanism = .signed_challenge,
        },
        proof.identity(1),
    );
}

test "an answer captured on one connection is refused on another" {
    const secret = try relay_test_ids.testSecret(61);

    // Two connections that drew the same sixteen bytes at the same instant, so
    // the binding is the only thing that could tell them apart.
    const first = try issuedFor(1);
    const second = try issuedFor(2);
    try t.expectEqualSlices(
        u8,
        &first.issued.challenge.challenge,
        &second.issued.challenge.challenge,
    );
    try t.expect(first.issued.issued_at == second.issued.issued_at);

    // A credential lifted off the first connection and replayed on the second
    // is refused. This is the case upstream's derivation leaves to a CSPRNG
    // that never repeats sixteen bytes.
    const captured = auth_credential.answer(&secret, first.issued);
    const replayed = verify(second.issued, 2, captured, second.issued.issued_at);
    try t.expectEqual(Failure.signature_invalid, replayed.refused.failure);

    // And refused for being about the wrong connection rather than for being
    // bad: the same bytes still prove where they were issued, inside the
    // window.
    const home = verify(first.issued, 1, captured, first.issued.issued_at);
    try t.expectEqual(secret.nodeId(), home.proved.node_id);
}

test "a record kept for one connection cannot be spent on another" {
    const secret = try relay_test_ids.testSecret(62);
    const issued = try issuedFor(1);
    const answered = auth_credential.answer(&secret, issued.issued);

    // A relay filing its own records wrongly is invisible to the derivation —
    // the record is self-consistent — so `on` is a separate argument and the
    // mismatch is caught before the window is read.
    const misfiled = verify(issued.issued, 99, answered, issued.issued.issued_at);
    try t.expectEqual(Failure.connection_mismatch, misfiled.refused.failure);

    // The comparison comes first even when the window would have refused it
    // too, because a peer that did nothing must not be told its challenge
    // expired when the relay handed over the wrong record.
    const expired = verify(issued.issued, 99, answered, issued.issued.expires_at);
    try t.expectEqual(Failure.connection_mismatch, expired.refused.failure);

    // And the same answer on the connection the record names is not a mismatch,
    // so what refused the two above was the filing and not the credential.
    const home = verify(issued.issued, 1, answered, issued.issued.issued_at);
    try t.expectEqual(secret.nodeId(), home.proved.node_id);
}

test "every way a proof fails is refused by name, and the name is not the sentence" {
    const honest = try relay_test_ids.testSecret(63);
    const impostor = try relay_test_ids.testSecret(64);
    const issued = try issuedFor(1);
    const good = auth_credential.answer(&honest, issued.issued);
    const forged: Credential = .{
        .node_id = honest.nodeId(),
        .signature = impostor.sign(&auth_challenge.messageToSign(issued.issued)),
    };

    // Each arm of `Failure`, with a connection, a credential and an instant
    // that produce it and nothing else.
    const refusals = [_]Refusal{
        verify(issued.issued, 1, forged, issued.issued.issued_at).refused,
        verify(issued.issued, 1, good, issued.issued.expires_at).refused,
        verify(issued.issued, 1, good, issued.issued.issued_at - 1).refused,
        verify(issued.issued, 99, good, issued.issued.issued_at).refused,
    };
    try t.expectEqual(@as(usize, 4), refusals.len);
    const expected = [_]Failure{
        .signature_invalid,
        .challenge_expired,
        .clock_mismatch,
        .connection_mismatch,
    };

    for (refusals, expected) |refusal, failure| {
        // The operator's code says which, so a counter separates a prober from
        // a stale clock from a relay bug.
        try t.expectEqual(failure, refusal.failure);
        // The peer reads one sentence for all four, which is the other half: a
        // refusal that said which field to correct would be an oracle.
        try t.expectEqualStrings(refusal_sentence, refusal.state.denied.reason);
        // **No arm closes without writing.** A denial frame is what makes a
        // failed proof distinguishable to the peer from a network fault, and it
        // is byte-identical to what `server_handshake` writes for this failure.
        try t.expectEqual(
            handshake.Action{ .write = .{ .server_denies_auth = .{
                .reason = handshake.invalid_signature_reason,
            } } },
            refusal.action,
        );
    }
}

test "the set of failures a proof can have is swept, not restated" {
    // A sweep over `Failure` rather than a restatement of it, so an arm added
    // with no way to reach it fails this test instead of sitting in the enum
    // uncovered.
    const reachable: Reachable = .{
        .signature_invalid = .signature_invalid,
        .challenge_expired = .challenge_expired,
        .clock_mismatch = .clock_mismatch,
        .connection_mismatch = .connection_mismatch,
    };
    try t.expectEqual(@as(usize, 4), @typeInfo(Failure).@"enum".fields.len);
    inline for (@typeInfo(Failure).@"enum".fields) |field| {
        const failure: Failure = @field(reachable, field.name);
        const refusal = refuse(failure);
        try t.expectEqual(failure, refusal.failure);
        try t.expectEqualStrings(refusal_sentence, refusal.state.denied.reason);
        try t.expectEqualStrings(refusal_sentence, refusal.action.write.server_denies_auth.reason);
    }

    // And the mapping from the verifier's own errors onto those names is
    // exhaustive, so a new verification failure cannot arrive unnamed.
    const named: Named = .{
        .SignatureInvalid = .signature_invalid,
        .Expired = .challenge_expired,
        .NotYetValid = .clock_mismatch,
    };
    inline for (@typeInfo(auth_credential.VerifyError).error_set.?) |member| {
        const failure: auth_credential.VerifyError = @field(
            auth_credential.VerifyError,
            member.name,
        );
        try t.expectEqual(@field(named, member.name), failureFor(failure));
    }
}

/// One value of every `Failure` arm, so a sweep can reach each.
const Reachable = struct {
    signature_invalid: Failure,
    challenge_expired: Failure,
    clock_mismatch: Failure,
    connection_mismatch: Failure,
};

/// One member of every arm of the verifier's error set.
const Named = struct {
    SignatureInvalid: Failure,
    Expired: Failure,
    NotYetValid: Failure,
};
