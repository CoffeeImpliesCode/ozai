//! When a relay must authenticate a peer, what it accepts when it does not,
//! and what it says when the mechanism it wanted was never here.
//!
//! `relay/auth_challenge.zig` and `relay/auth_credential.zig` prove who a peer
//! is; `relay/access_policy.zig` decides whether to serve one that has proved
//! itself; `relay/relay_auth_wiring.zig` issues the challenge and reads the
//! answer. None of the four decides whether a proof is demanded at all, and
//! that decision is an operator's rather than a protocol's. This file is where
//! the operator makes it, once, before a listener exists.
//!
//! # Required and optional, and who decides
//!
//! **The caller decides, by naming it, and the name is checked before the
//! listener opens.** `Config` cannot be left unset and `plan` refuses the one
//! configuration this relay cannot serve. There is no third reading, so "I did
//! not configure it" is not a policy that admits everybody by accident.
//!
//! # What a relay that does not require authentication accepts
//!
//! **A peer that can sign, whatever node id it signs with — and nothing else.**
//! `Admission.open` does not make authentication optional; it makes the peer's
//! identity uninteresting. The peer still signs a challenge bound to its own
//! connection, `relay_auth_wiring.verify` still checks it with `verifyStrict`,
//! and the node id that comes back is still what the peer is filed under in
//! `server_registry`, because that table is keyed by `NodeId` and a peer with
//! no identity has nowhere to be filed. **An open relay here is not a relay that
//! skips authentication; it is a relay whose access decision is
//! `access_policy.accept_all`**, and this tree has no configuration in which a
//! peer is served without having signed.
//!
//! **The public good and the public cost, in that order.** The good is that
//! anyone may relay through it without an account, which is the property
//! `iroh`'s relays have and much of the reason this protocol exists. The cost is
//! that every peer on it is attributable to a key and to nothing else: the
//! operator cannot say which of its peers is causing trouble, cannot rate-limit
//! one of them alone, and cannot tell an abusive client from a client on a bad
//! network except by watching bytes move. Both halves of that sentence are why
//! the choice is the caller's and is made in one place — a relay that wants an
//! open door writes `.open`, a relay that wants a list writes `.governed`, and
//! neither gets the other's behaviour by omitting a field.
//!
//! # The two mechanisms, and whether a refusal can tell them apart
//!
//! `server_handshake.Mechanism` has two arms and **one of them can never fire
//! in this tree.** `signed_key_material` needs `Offer.material`, a TLS
//! exporter's export (RFC 5705), and nothing here produces one: a relay
//! connection is a QUIC stream rather than a WebSocket over a TCP socket, and
//! that TCP listener stays `docs/DECISIONS/0001`'s open item ("`std.crypto.tls`
//! has a client-only driver with no server"). `vendor/quic/` holds no
//! occurrence of `export_keying_material`, `exporter` or `exported_keying`.
//! So `Offer.material` is null, `KeyMaterialAuth.verify` answers
//! `error.NoKeyingMaterial`, and `server_handshake.admit` takes the challenge
//! path for every client this relay will ever admit.
//!
//! **So `plan` refuses `signed_key_material` up front, and that is the answer
//! to whether the two mechanisms are distinguishable in a refusal.** They are
//! not, and the reason is that there is only ever one: `AvailableMechanism` is
//! a one-armed enum, so a relay holding a `Plan` holds a mechanism it can
//! actually perform, and nothing downstream of `plan` has a `signed_key_material`
//! arm to write. What a caller must never do is the opposite — accept such a
//! `Config` and then report each peer as `proof_failed`, which tells the
//! operator its clients are forging signatures when the truth is that the relay
//! has no exporter. That is why the unavailability is **stated and refused at
//! configuration time**, named by `error.KeyingMaterialUnavailable`, and never
//! left to be discovered per connection.
//!
//! The peer reads the same thing either way, because `ServerDeniesAuth` is a
//! bare postcard string and no code reaches the wire. The operator's counters
//! are the only place a mechanism is told from another, and with one live arm
//! there is nothing to tell — which is why `Cause.not_configured` exists at all
//! rather than being folded into the authentication arm.

const std = @import("std");

const access_policy = @import("access_policy.zig");
const frame = @import("frame.zig");
const relay_auth_wiring = @import("relay_auth_wiring.zig");
const server_handshake = @import("server_handshake.zig");

/// The identity an access decision is about.
pub const Identity = access_policy.Identity;

/// The node id a decision is about.
pub const NodeId = access_policy.NodeId;

/// The decision as `access_policy.Policy` returns it.
pub const Decision = access_policy.Decision;

/// The reason a relay sends when it denies without a reason of its own.
pub const default_denial = server_handshake.default_denial;

/// How a client proved who it is. See `server_handshake.Mechanism`.
pub const Mechanism = server_handshake.Mechanism;

/// What a relay does with a peer that has proved itself.
///
/// **Named rather than defaulted, and a union so the two answers cannot be
/// confused.** `.open` is not a `Policy` that happens to admit everybody; it is
/// the absence of a policy, and a `.governed` relay cannot be built without
/// one. An operator who wants an open door and an operator who wants a list
/// write different code, and neither is the other by omission.
pub const Admission = union(enum) {
    /// Every peer that proved a node id is served, and none is refused by this
    /// file. **This is the open relay**, and its cost is written down above
    /// rather than left to be discovered: its peers are attributable to a key
    /// and to nothing else.
    open,
    /// Ask this policy about every peer that has proved itself, and serve what
    /// it accepts. `access_policy.Policy` is a function pointer and a caller
    /// pointer, so the relay stores the operator's own code and calls into it
    /// exactly once per connection.
    governed: access_policy.Policy,
};

/// A relay's configuration, before it is checked.
///
/// `Config` cannot be left unset, so "I did not configure it" is not a reading;
/// a caller writes the `Admission` it means.
pub const Config = struct {
    /// What to do with a peer that has proved itself.
    admission: Admission,
    /// Which mechanism the relay means to verify with. `plan` refuses the arm
    /// this relay cannot perform, so naming it is a configuration mistake
    /// caught at startup rather than a per-connection mystery.
    mechanism: Mechanism = .signed_challenge,
};

/// The mechanism a relay can actually verify with.
///
/// **One arm, and the width of this enum is the claim.** A `Plan` cannot hold
/// `signed_key_material`, so nothing downstream of `plan` holds a mechanism arm
/// that cannot fire. When an exporter exists — the TCP listener
/// `docs/DECISIONS/0001` still owes — this grows an arm, and every caller that
/// switches on it becomes exhaustive at that point rather than at some later
/// runtime surprise.
pub const AvailableMechanism = enum {
    /// A signature over a challenge the relay sent, bound to the connection it
    /// was issued on. The only path `relay_auth_wiring` verifies, and the only
    /// one available here.
    signed_challenge,
};

/// Why a configuration cannot be served by this relay.
pub const PlanError = error{
    /// The configuration named `Mechanism.signed_key_material`, and this relay
    /// has no TLS exporter to verify it against: no `export_keying_material`
    /// anywhere in `vendor/quic/`, and no TCP listener to take one from
    /// (`docs/DECISIONS/0001`). **Refused here rather than discovered per
    /// connection**, because the alternative reports every peer as a failed
    /// proof when the truth is that the relay was never configured to ask one.
    KeyingMaterialUnavailable,
};

/// A configuration that has been checked and can be served.
///
/// `plan` is the only way to hold one, and `AvailableMechanism` is what makes
/// the check mean something downstream rather than being a promise in a doc
/// comment.
pub const Plan = struct {
    /// What to do with a peer that has proved itself, carried through
    /// unchanged: checking a configuration does not edit it.
    admission: Admission,
    /// The mechanism, narrowed to what this relay can perform.
    mechanism: AvailableMechanism,

    /// What this plan does with one peer that has proved itself.
    ///
    /// **One indirect call for `.governed` and none at all for `.open`.** No
    /// clock, no allocator, no I/O, and no promise about how long the call
    /// takes, because that is the operator's code and `access_policy.Policy`
    /// says so of itself. It is asked once, here, and this function's whole
    /// output is its answer; nothing downstream re-asks it.
    ///
    /// **This is not `access_policy.Policy.event` with a different name.**
    /// That drops `Reason.code` because no frame carries one; this keeps it,
    /// because the operator's counter is the only place the two causes this
    /// file names — a peer's failed proof and a relay with no exporter — can be
    /// told apart.
    pub fn admit(self: Plan, identity: Identity) Outcome {
        return switch (self.admission) {
            .open => .{ .serve = identity },
            .governed => |policy| switch (policy.evaluate(identity)) {
                .accept => .{ .serve = identity },
                // An operator who wrote no sentence of their own reads as the
                // relay's default, which is `sentence(.policy_refused)` and
                // which upstream's `default_denial` already bounds for the same
                // reason. One who did is quoted verbatim.
                .refuse => |reason| if (reason.text) |text| .{ .refuse = .{
                    .cause = .{ .policy_refused = reason.code },
                    .text = text,
                } } else .{ .refuse = report(.{ .policy_refused = reason.code }) },
            },
        };
    }
};

/// Check a configuration before any peer arrives.
///
/// The one refusal is the point of the function, and it happens here rather
/// than per connection for the reason `PlanError.KeyingMaterialUnavailable`
/// gives. Returns the configuration narrowed to a mechanism that can run, so
/// the narrowing is a property of the value rather than a rule the caller has
/// to remember.
pub fn plan(config: Config) PlanError!Plan {
    return switch (config.mechanism) {
        .signed_challenge => .{
            .admission = config.admission,
            .mechanism = .signed_challenge,
        },
        .signed_key_material => error.KeyingMaterialUnavailable,
    };
}

/// Why a relay refused a peer, for the operator's counters and log.
///
/// **A union rather than a flat enum, because two of these carry another
/// module's own taxonomy** and flattening them would lose the difference
/// between "this peer is not on the list" and "this relay has no exporter".
/// Nothing here reaches the wire: `server_denies_auth` is a bare postcard
/// string (`handshake.rs:106`), so these are for counters and a log line.
pub const Cause = union(enum) {
    /// The peer did not prove who it is, and
    /// `relay_auth_wiring.Failure` says which of the four ways. The sentence
    /// that module chose is the one the peer reads.
    proof_failed: relay_auth_wiring.Failure,
    /// The peer proved who it is and the operator's own rule refused it.
    /// `access_policy.Code` is the label that policy already chose, kept whole.
    policy_refused: access_policy.Code,
    /// **This relay cannot perform the authentication it was configured for.**
    /// Not a peer's fault, and not something a peer could fix by answering
    /// differently — which is why it is an arm here and not a `proof_failed`.
    /// `plan` refuses a key-material configuration before a peer can reach it,
    /// so this is what a caller that skipped `plan` would report, and it is the
    /// arm that stops such a relay calling its own misconfiguration a forgery.
    not_configured,
};

/// Why a relay refused a peer: a name for the operator, a sentence for the peer.
///
/// The sentence is this file's and is a comptime literal: no allocation, no
/// borrow of the caller's, and no possibility of one that is over
/// `ServerDeniesAuth.max_reason_length` and refused by the codec after the
/// relay has decided what to say.
pub const Refusal = struct {
    /// What the operator records.
    cause: Cause,
    /// What the peer reads.
    text: []const u8,
};

/// What a relay decided about one peer that has proved itself.
pub const Outcome = union(enum) {
    /// Serve it, and this is who it is. The caller writes the confirmation and
    /// takes the guard, which are `server_registry.admit`'s to take.
    serve: Identity,
    /// Refuse it, and write this sentence. Named, never dropped: a silent close
    /// is indistinguishable from a network fault to the peer, which then retries
    /// against a relay that will never answer, and it leaves the operator with
    /// nothing to count.
    refuse: Refusal,
};

/// The sentence a cause is written with on the wire.
///
/// **One sentence per cause, and the causes are not interchangeable.** Every
/// authentication failure reads as the same sentence, so a peer cannot use a
/// refusal to work out which field to correct; `not_configured` reads
/// differently precisely because it is the one cause no amount of correct
/// answering would have prevented. Nothing about this list is a discovery: a
/// peer learns a reason, an operator learns a code, and the wire never says
/// which mechanism this relay holds.
pub fn sentence(cause: Cause) []const u8 {
    return switch (cause) {
        // Upstream's own sentence, for every arm of the failure, so the four
        // ways stay in the operator's counter rather than in the peer's hands.
        .proof_failed => relay_auth_wiring.refusal_sentence,
        // The operator's sentence is used when they wrote one; this is what a
        // caller reads from here when they did not, and `Plan.admit` prefers
        // theirs.
        .policy_refused => default_denial,
        .not_configured => "relay has no authentication configured here",
    };
}

comptime {
    // The two sentences this file speaks for itself are both inside what the
    // codec will carry, checked here rather than at the `encode` that would
    // refuse one: a refusal cut short, or refused outright, says something the
    // relay did not decide to say. The third is `default_denial`, which
    // `server_handshake` already holds to the same bound for the same reason.
    const missing: Cause = .not_configured;
    if (sentence(missing).len > frame.ServerDeniesAuth.max_reason_length)
        @compileError("the not-configured sentence does not fit a denial frame");
    const failed: Cause = .{ .proof_failed = .signature_invalid };
    if (sentence(failed).len > frame.ServerDeniesAuth.max_reason_length)
        @compileError("the proof-failed sentence does not fit a denial frame");
}

/// The refusal a cause is reported with, built once so the name and the
/// sentence cannot disagree.
///
/// **This is the constructor a caller needs for the two causes `Plan.admit`
/// never produces**, and it is why `Cause.not_configured` is reachable from
/// outside: a relay that skipped `plan` has a cause to report and no
/// sentence for it, and inventing one there is how "authentication failed"
/// ends up being said about a relay with no exporter.
pub fn report(cause: Cause) Refusal {
    return .{ .cause = cause, .text = sentence(cause) };
}

// --- tests

const t = std.testing;

const auth_challenge = @import("auth_challenge.zig");
const auth_credential = @import("auth_credential.zig");
const relay_test_ids = @import("relay_test_ids.zig");

/// A policy that admits exactly one node id and counts how often it was asked,
/// both in the caller's own storage. The counting is the point: a relay that
/// asked twice per connection would have a policy whose answer could change
/// under it.
const Allowlist = struct {
    allowed: NodeId,
    asked: u32 = 0,

    fn decide(context: ?*anyopaque, identity: Identity) Decision {
        const self: *Allowlist = @ptrCast(@alignCast(context.?));
        self.asked += 1;
        if (self.allowed.order(identity.node_id) == .eq) return .accept;
        return .{ .refuse = .{ .code = .unknown_peer, .text = "this relay serves nobody else" } };
    }
};

/// An instant far enough from zero that nothing here underflows it.
const start: relay_auth_wiring.Nanos = 1_000_000_000;

/// The challenge bytes both connections below draw. A module that drew its own
/// randomness would not be one a test can drive, and the draw is not what is
/// under test.
const test_challenge: relay_auth_wiring.ServerChallenge = .{ .challenge = @splat(0x5a) };

/// A challenge issued for one connection, with the same sixteen bytes and the
/// same instant every time, so a test about the binding cannot pass on a
/// differing draw.
fn issuedFor(connection_id: relay_auth_wiring.ConnectionId) !relay_auth_wiring.Issued {
    return (try relay_auth_wiring.issue(
        connection_id,
        test_challenge,
        start,
        relay_auth_wiring.default_lifetime,
    )).issued;
}

test "an open relay serves every peer that can sign, and no peer that cannot" {
    const stranger = try relay_test_ids.testNodeId(70);
    const another = try relay_test_ids.testNodeId(71);
    const open = try plan(.{ .admission = .open });
    try t.expectEqual(AvailableMechanism.signed_challenge, open.mechanism);

    // Two peers this relay has never heard of. Neither is on any list, because
    // there is no list: both are served, each under the node id its own
    // signature proved.
    for ([_]NodeId{ stranger, another }) |node_id| {
        const identity: Identity = .{
            .node_id = node_id,
            .connection_id = 40,
            .mechanism = .signed_challenge,
        };
        try t.expectEqual(identity, open.admit(identity).serve);
    }

    // **And the open relay still authenticates.** An open admission is asked
    // about an `Identity`, and an `Identity` exists only once a signature has
    // verified: a forged answer produces a refusal in
    // `relay_auth_wiring` and never reaches `admit` at all, so `.open` is an
    // open door and not an absent lock. This is the check the open policy
    // never gets to make and must never be the only one there is.
    const honest = try relay_test_ids.testSecret(72);
    const impostor = try relay_test_ids.testSecret(73);
    const issued = try issuedFor(1);
    const forged: relay_auth_wiring.Credential = .{
        .node_id = honest.nodeId(),
        .signature = impostor.sign(&auth_challenge.messageToSign(issued)),
    };
    const refused = relay_auth_wiring.verify(issued, 1, forged, start);
    try t.expectEqual(
        relay_auth_wiring.Failure.signature_invalid,
        refused.refused.failure,
    );

    // The honest answer to the same record does become an identity, and that
    // identity — a node id this relay has never heard of — is served. So the
    // two are told apart by the signature and nothing else, and `.open` is the
    // only reason the second is admitted at all.
    const accepted = relay_auth_wiring.verify(
        issued,
        1,
        auth_credential.answer(&honest, issued),
        start,
    );
    try t.expectEqual(
        honest.nodeId(),
        open.admit(accepted.proved.identity(1)).serve.node_id,
    );
}

test "a governed relay asks its policy once, and the refusal keeps the operator's code" {
    const allowed = try relay_test_ids.testNodeId(74);
    const stranger = try relay_test_ids.testNodeId(75);
    var list: Allowlist = .{ .allowed = allowed };
    const governed = try plan(.{
        .admission = .{ .governed = .{ .context = &list, .decide = Allowlist.decide } },
    });

    // The peer on the list is served, and the peer that is not is refused with
    // the operator's own sentence — and with the operator's own code, which
    // this file carries rather than flattening into a taxonomy of its own.
    const welcome: Identity = .{
        .node_id = allowed,
        .connection_id = 42,
        .mechanism = .signed_challenge,
    };
    try t.expectEqual(welcome, governed.admit(welcome).serve);

    const closed = governed.admit(.{
        .node_id = stranger,
        .connection_id = 43,
        .mechanism = .signed_challenge,
    });
    try t.expectEqual(
        Refusal{
            .cause = .{ .policy_refused = .unknown_peer },
            .text = "this relay serves nobody else",
        },
        closed.refuse,
    );

    // Asked once each. A relay that re-asked would have a policy whose answer
    // could change between the two asks, and a load-dependent policy is one
    // that changes between connections rather than one that races with its own
    // handshake.
    try t.expectEqual(@as(u32, 2), list.asked);

    // The same refusal without a sentence of the operator's own reads as the
    // relay's default, which is upstream's arrangement (`handshake.rs:543`) and
    // is not the same as having chosen those words.
    var quiet: Allowlist = .{ .allowed = allowed };
    const silent = try plan(.{
        .admission = .{ .governed = .{ .context = &quiet, .decide = Allowlist.decide } },
    });
    try t.expectEqualStrings(
        default_denial,
        silent.admit(.{
            .node_id = stranger,
            .connection_id = 44,
            .mechanism = .signed_challenge,
        }).refuse.text,
    );
}

test "a mechanism this relay cannot perform is refused before a peer arrives" {
    // The whole of the distinguishability question, as a value: the only
    // mechanism a `Plan` can name is the one this relay performs.
    try t.expectEqual(@as(usize, 1), @typeInfo(AvailableMechanism).@"enum".fields.len);

    // Naming the path that needs a TLS exporter is refused with its own error,
    // at configuration time, before any listener exists to accept a peer. The
    // alternative is a relay that takes the configuration and then reports
    // every client as a forged signature.
    try t.expectError(
        error.KeyingMaterialUnavailable,
        plan(.{ .admission = .open, .mechanism = .signed_key_material }),
    );

    // The arm that does run is accepted, and the admission shape survives the
    // check unchanged: checking a configuration does not edit it.
    const open = try plan(.{ .admission = .open, .mechanism = .signed_challenge });
    try t.expectEqual(std.meta.activeTag(@as(Admission, .open)), std.meta.activeTag(open.admission));
    try t.expectEqual(AvailableMechanism.signed_challenge, open.mechanism);
}

test "a relay with no exporter says so, and does not say the peer failed" {
    // What `plan` refuses is named as its own cause rather than folded into
    // `proof_failed`, because no peer can fix it by answering differently. The
    // operator's counter separates the two and the peer reads two sentences.
    const missing = report(.not_configured);
    const failed = report(.{ .proof_failed = .signature_invalid });

    try t.expect(std.meta.activeTag(missing.cause) != std.meta.activeTag(failed.cause));
    try t.expect(!std.mem.eql(u8, missing.text, failed.text));
    try t.expectEqualStrings(relay_auth_wiring.refusal_sentence, failed.text);

    // Both sentences are inside what the codec will carry, so a refusal is
    // never itself refused by the codec after the relay has decided what to
    // say. And the one that says "not configured" is short enough to be a
    // comptime literal of the kind this file promises.
    for ([_][]const u8{ missing.text, failed.text, default_denial }) |text| {
        try t.expect(text.len > 0);
        try t.expect(text.len <= frame.ServerDeniesAuth.max_reason_length);
    }
}

test "every cause has a sentence, and the set of causes is swept" {
    // A sweep over the arms of `Cause` rather than a restatement of them, so an
    // arm added with no sentence fails this test rather than producing a
    // refusal whose text is `error{UnionTagNotFound}` at run time. The arms
    // are keyed by name because a union's payload is what this file is about,
    // and a payload-less arm has none to carry.
    const by_name = struct {
        const proof_failed: Cause = .{ .proof_failed = .connection_mismatch };
        const policy_refused: Cause = .{ .policy_refused = access_policy.Code.at_capacity };
        const not_configured: Cause = .not_configured;
    };
    inline for (@typeInfo(Cause).@"union".fields) |field| {
        const cause: Cause = @field(by_name, field.name);
        // Every arm is reachable, and each names a sentence a peer can read.
        try t.expectEqualStrings(sentence(cause), report(cause).text);
        try t.expect(report(cause).text.len > 0);
        try t.expect(report(cause).text.len <= frame.ServerDeniesAuth.max_reason_length);
    }

    // The two crossings keep both taxonomies whole: a relay filing its own
    // records wrongly is still distinguishable from a peer absent from the
    // operator's list, and both from a relay with no exporter. Three tags, so
    // nothing collapses into "the peer failed" by accident.
    const filing = report(.{ .proof_failed = .connection_mismatch });
    const listed = report(.{ .policy_refused = .unknown_peer });
    const missing = report(.not_configured);
    const tags = [_]std.meta.Tag(Cause){
        std.meta.activeTag(filing.cause),
        std.meta.activeTag(listed.cause),
        std.meta.activeTag(missing.cause),
    };
    for (tags, 0..) |tag, index| {
        for (tags[0..index]) |earlier| try t.expect(tag != earlier);
    }
}
