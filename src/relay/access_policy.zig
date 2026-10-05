//! The seam a relay's operator closes: who may be relayed for, decided by the
//! caller and by nobody else.
//!
//! `relay/server_handshake.zig` already has the seam's inner half — `Event.access`
//! carries an `Access` decision in, `step` writes the confirmation or the denial,
//! and no state anywhere in this tree can produce one on its own. What was
//! missing is the other half: a way for an operator to *have* a policy and hand
//! it to the machine. This file is that, and it is a function pointer and a
//! context rather than a trait, a vtable or a callback the handshake calls.
//!
//! # Why a seam and not a built-in rule
//!
//! **Upstream's access control is a trait the operator implements**
//! (`handshake.rs:495`, `:524`) — `AccessControl::on_connect` and
//! `on_disconnect` — and everything downstream of that decision is written as
//! though the answer were arbitrary: `frame_types.zig` bounds the denial's text
//! because the text is whatever that trait decided, and `server_handshake.zig`
//! stores the reason *borrowed* from the caller because the caller owns the
//! buffer it names. A rule written into the handshake would have to pick one of
//! the policies that exist — an allowlist of node ids, a subscription check, a
//! metered quota, a closed relay — and every operator whose policy is not that
//! one would have to fork the protocol to get it.
//!
//! Three further things follow from it being a seam, and each is a property a
//! caller can rely on:
//!
//! - **The decision is the caller's, evaluated at the moment it is asked.** The
//!   handshake never caches it and never re-asks it; a policy that is time- or
//!   load-dependent is one that changes between connections, not one that races
//!   with its own handshake.
//! - **The context is the caller's own data, not a global.** `context` is an
//!   opaque pointer the caller supplies, so an allowlist, a quota counter and a
//!   log line all live wherever that caller keeps them. There is no process-wide
//!   "the access control" for two relays in one process to fight over.
//! - **A refusal names itself and carries a sentence.** `Reason.code` is a
//!   closed enum, so a counter can be read across a set somebody enumerated;
//!   `Reason.text` is the caller's own bytes and is the only part of the decision
//!   that reaches the wire. The two are separate because no frame carries a
//!   code: `ServerDeniesAuth` is a bare `reason: String` (`handshake.rs:106`),
//!   so `Policy.event` drops the code and the caller keeps it for its own log.
//!
//! # A refusal with no sentence
//!
//! `Reason.text` is nullable and null is not a different decision — it is the
//! same refusal with the relay speaking for itself, and `handshake.default_denial`
//! is what the peer reads. That is upstream's own arrangement
//! (`handshake.rs:543`) and it is deliberately *not* the same as choosing those
//! words: nothing on the wire tells the two apart, and a caller that wants the
//! difference has to keep it in `code`.
//!
//! A text over `frame.ServerDeniesAuth.max_reason_length` is refused by the codec
//! as `error.TextTooLong` with nothing written, and this module does not
//! shorten it first: a denial whose reason was cut short says something the relay
//! did not decide to say, and a peer cannot tell it from the relay's real reason.
//!
//! Nothing here reads a clock, opens a socket or allocates. `evaluate` is one
//! indirect call and `event` is a switch over its answer, so a relay with no
//! access control at all passes `accept_all` and pays one pointer chase per
//! client.

const std = @import("std");
const key = @import("../base/key.zig");
const frame = @import("frame.zig");
const handshake = @import("server_handshake.zig");
const registry = @import("server_registry.zig");

const std_testing = std.testing;

/// The node id a decision is about.
pub const NodeId = key.NodeId;

/// Which connection is asking. Upstream passes it so an implementation can pair
/// `on_connect` with `on_disconnect` (`server.rs:302`); it is a `u64` the caller
/// draws, because a process-global counter would hand two relays in one process
/// the same one.
pub const ConnectionId = registry.ConnectionId;

/// How the client proved who it is. Recorded, never branched on: which mechanism
/// let a client in is the operator's business and the handshake records it
/// (`handshake.rs:399-404`).
pub const Mechanism = handshake.Mechanism;

/// The decision as `server_handshake.step` receives it.
pub const Event = handshake.Event;

/// The decision as the handshake names it: `allow`, or `deny` with the text.
pub const Access = handshake.Access;

/// The reason a relay sends when it denies without a reason of its own.
pub const default_denial = handshake.default_denial;

/// Who is asking, as far as the policy is concerned.
///
/// **All three fields are values**, so the caller may build one, keep it in a
/// log line and compare two of them, and nothing here borrows.
pub const Identity = struct {
    /// The node id the handshake proved. It was verified by the time a policy is
    /// asked: the handshake reaches `.authenticated` first and nothing else can
    /// produce an access event (`handshake.rs:495`), so a policy is never asked
    /// about an unproven claim.
    node_id: NodeId,
    /// Which connection is asking, which is what tells two connections of one
    /// node id apart.
    connection_id: ConnectionId,
    /// How it proved it.
    mechanism: Mechanism,
};

/// The named reason a refusal carries.
///
/// **It is a label and not a rule.** Nothing in this tree produces any of these
/// but a caller, and a caller whose own taxonomy is finer keeps `text` for the
/// difference: the enum exists so `relay_node.zig`'s counters and an operator's
/// log can aggregate refusals across a set somebody enumerated, which a sentence
/// cannot be aggregated by.
pub const Code = enum {
    /// The operator's own rule refused this peer, and `text` is its sentence.
    by_policy,
    /// This relay does not serve the peer that connected.
    unknown_peer,
    /// The relay has no room for one more connection. Upstream refuses rather
    /// than drops for the same reason (`server/clients.rs:218-224`).
    at_capacity,
    /// The peer already has a connection here. Upstream admits this and displaces
    /// the older one (`server/clients.rs:81-101`); the code exists for an
    /// operator who would rather refuse, and this tree never produces it.
    duplicate,
};

/// Why a peer was refused: a name for the caller's own records, and a sentence
/// for the peer.
///
/// **The text is borrowed and outlives the call.** The `Step` this decision
/// produces holds it twice — in `State.denied.reason` and in
/// `Action.write.server_denies_auth.reason` — and `frame.encode` reads it after
/// that, so it must stay alive and unmutated until the denial has been written.
/// A buffer the caller is about to reuse for the next connection's decision must
/// not be the one this denial names.
pub const Reason = struct {
    /// The name, for the caller's counters and log.
    code: Code,
    /// The sentence the peer reads, or null for `default_denial`.
    text: ?[]const u8,
};

/// What a policy decided.
pub const Decision = union(enum) {
    /// Let the client in. Nothing further is asked and nothing is cached.
    accept,
    /// Refuse, and say why.
    refuse: Reason,
};

/// The seam: a caller-supplied decision about a peer.
///
/// **`decide` is a plain function pointer and `context` is the caller's own
/// pointer.** There is no interface to implement, no vtable to build and no
/// registration to be done, so an operator's policy is one function in their own
/// code and adding one to a relay is adding one function to a relay. The
/// alternative — a trait object, or a callback the handshake stores and calls
/// whenever it likes — would put the operator's data inside the protocol machine
/// and make the handshake's purity (`server_handshake.zig`'s own rule: no clock,
/// no allocator, no global, no call back into the caller) a thing to be careful
/// about rather than a thing the type system holds.
pub const Policy = struct {
    /// Whatever the caller's decision reads. Never dereferenced here.
    context: ?*anyopaque,
    /// The decision itself. Not optional: a `Policy` cannot be built without one,
    /// so there is no null to check at the one call site that would have to.
    decide: *const fn (?*anyopaque, Identity) Decision,

    /// What this policy says about one peer.
    ///
    /// One indirect call and nothing else: no clock, no allocator, no I/O, and no
    /// guarantee about how long it takes, because that is the caller's code. The
    /// handshake calls it once, between proving a client and answering it.
    pub fn evaluate(self: Policy, identity: Identity) Decision {
        return self.decide(self.context, identity);
    }

    /// The decision as the event `server_handshake.step` takes.
    ///
    /// **The code is dropped here and only here**, because no frame carries one:
    /// `server_denies_auth` is a bare postcard string (`handshake.rs:106`). A
    /// caller that wants `Reason.code` in a log reads it from `evaluate`'s own
    /// answer; this is the half that reaches the wire.
    ///
    /// `Access` is only meaningful in the `.authenticated` state, and the
    /// handshake enforces that: the same event anywhere else is
    /// `Failure.out_of_order` (`handshake.zig`), so a decision cannot be applied
    /// before the proof it is about.
    pub fn event(self: Policy, identity: Identity) Event {
        return .{ .access = switch (self.evaluate(identity)) {
            .accept => .allow,
            .refuse => |reason| .{ .deny = reason.text },
        } };
    }
};

/// The policy a relay with no access control runs: every client in.
///
/// **Named rather than defaulted.** A struct field of type `Policy` cannot be
/// left unset, so a relay that wants no filtering says so by writing this and a
/// relay that wants filtering says so by writing its own. There is no third
/// reading of an uninitialised decision.
pub const accept_all: Policy = .{ .context = null, .decide = allowEveryClient };

fn allowEveryClient(context: ?*anyopaque, identity: Identity) Decision {
    _ = context;
    _ = identity;
    return .accept;
}

// --- tests

const relay_test_ids = @import("relay_test_ids.zig");

/// One policy for the tests: an allowlist of node ids and a count of how often
/// it was asked, both in the caller's own storage.
const Scripted = struct {
    allowed: NodeId,
    asked: u32 = 0,
    reason: ?[]const u8,

    fn decide(context: ?*anyopaque, identity: Identity) Decision {
        const self: *Scripted = @ptrCast(@alignCast(context.?));
        self.asked += 1;
        if (self.allowed.order(identity.node_id) == .eq) return .accept;
        return .{ .refuse = .{ .code = .unknown_peer, .text = self.reason } };
    }
};

test "a policy refuses with a named reason and the handshake carries it" {
    const allowed = try relay_test_ids.testNodeId(21);
    const stranger = try relay_test_ids.testNodeId(22);
    var script: Scripted = .{ .allowed = allowed, .reason = "this relay serves nobody else" };
    const policy: Policy = .{ .context = &script, .decide = Scripted.decide };

    // The peer on the list is let in, and the handshake writes the confirmation.
    const welcome = handshake.step(
        .{ .authenticated = .{ .node_id = allowed, .mechanism = .signed_challenge } },
        policy.event(.{
            .node_id = allowed,
            .connection_id = 7,
            .mechanism = .signed_challenge,
        }),
    );
    try std_testing.expectEqual(
        @as(?handshake.Action, .{ .write = .server_confirms_auth }),
        welcome.action,
    );
    try std_testing.expectEqual(
        handshake.State{ .admitted = .{ .node_id = allowed, .mechanism = .signed_challenge } },
        welcome.state,
    );

    // The one that is not is refused, with the operator's own sentence, and the
    // refusal names itself.
    const refused = policy.evaluate(.{
        .node_id = stranger,
        .connection_id = 8,
        .mechanism = .signed_key_material,
    });
    try std_testing.expectEqual(
        Decision{ .refuse = .{ .code = .unknown_peer, .text = script.reason } },
        refused,
    );

    const denial = handshake.step(
        .{ .authenticated = .{ .node_id = stranger, .mechanism = .signed_key_material } },
        policy.event(.{
            .node_id = stranger,
            .connection_id = 8,
        .mechanism = .signed_key_material,
        }),
    );
    try std_testing.expectEqualStrings("this relay serves nobody else", denial.state.denied.reason);
    // The relay writes the denial rather than closing: the client is waiting to
    // learn why, and upstream returns `ServerDeniedAuth` for the caller to
    // write (`handshake.rs:458-466`).
    try std_testing.expectEqualStrings(
        "this relay serves nobody else",
        denial.action.?.write.server_denies_auth.reason,
    );
}

// The context is the caller's own storage, so two policies with different
// contexts decide differently and the caller's counter moves.
test "the context is what makes it a policy, and it reaches the decision" {
    const first = try relay_test_ids.testNodeId(23);
    const second = try relay_test_ids.testNodeId(24);
    var open: Scripted = .{ .allowed = first, .reason = "closed" };
    var shut: Scripted = .{ .allowed = second, .reason = "closed" };
    const identity: Identity = .{
        .node_id = first,
        .connection_id = 9,
        .mechanism = .signed_key_material,
    };

    const permissive: Policy = .{ .context = &open, .decide = Scripted.decide };
    const restrictive: Policy = .{ .context = &shut, .decide = Scripted.decide };
    try std_testing.expectEqual(Decision.accept, permissive.evaluate(identity));
    try std_testing.expectEqual(
        Decision{ .refuse = .{ .code = .unknown_peer, .text = "closed" } },
        restrictive.evaluate(identity),
    );

    // Both were asked, each once, in the caller's own counters.
    try std_testing.expectEqual(@as(u32, 1), open.asked);
    try std_testing.expectEqual(@as(u32, 1), shut.asked);
}

// A refusal with no sentence of its own is the relay's default, and one that is
// too long for the wire is refused rather than shortened.
test "no sentence means the default denial, and a long one is refused not cut" {
    const peer = try relay_test_ids.testNodeId(25);
    // The peer below is on neither allowlist, which is what puts the handshake
    // on its denial arm at all: a list naming the peer asked about admits it.
    const served = try relay_test_ids.testNodeId(27);
    var quiet: Scripted = .{ .allowed = served, .reason = null };
    const policy: Policy = .{ .context = &quiet, .decide = Scripted.decide };

    // The same refusal with no text: the peer reads the relay's own words, and
    // nothing distinguishes them from a text the relay chose to be that sentence.
    const denial = handshake.step(
        .{ .authenticated = .{ .node_id = peer, .mechanism = .signed_challenge } },
        policy.event(.{ .node_id = peer, .connection_id = 10, .mechanism = .signed_challenge }),
    );
    try std_testing.expectEqualStrings(default_denial, denial.state.denied.reason);

    // A reason the codec cannot carry is refused with nothing written, because a
    // shortened one is a sentence the relay did not decide to say.
    const too_long_text = "x" ** (frame.ServerDeniesAuth.max_reason_length + 1);
    var long: Scripted = .{ .allowed = served, .reason = too_long_text };
    const verbose: Policy = .{ .context = &long, .decide = Scripted.decide };
    const too_long = handshake.step(
        .{ .authenticated = .{ .node_id = peer, .mechanism = .signed_challenge } },
        verbose.event(.{ .node_id = peer, .connection_id = 11, .mechanism = .signed_challenge }),
    );
    var out: [frame.ServerDeniesAuth.max_frame_length + 1]u8 = @splat(0xa5);
    try std_testing.expectError(
        error.TextTooLong,
        frame.encode(too_long.action.?.write, .v2, &out),
    );
    for (out) |byte| {
        try std_testing.expectEqual(@as(u8, 0xa5), byte);
    }
}

// A relay with no access control says so by naming the one that admits
// everyone, and it is a policy like any other rather than a missing one.
test "accept_all is a policy and not an absent decision" {
    const peer = try relay_test_ids.testNodeId(26);
    const stepped = handshake.step(
        .{ .authenticated = .{ .node_id = peer, .mechanism = .signed_key_material } },
        accept_all.event(.{
            .node_id = peer,
            .connection_id = 12,
        .mechanism = .signed_key_material,
        }),
    );
    try std_testing.expectEqual(
        @as(?handshake.Action, .{ .write = .server_confirms_auth }),
        stepped.action,
    );
}