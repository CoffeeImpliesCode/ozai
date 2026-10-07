//! Which protocols this node registers, and the ceiling it will not be talked
//! past.
//!
//! `router/alpn_table.zig` owns what a registration is and what it refuses;
//! `node/node_accept.zig:45` owns the number of protocols this node registers.
//! This file is the **plan**: the ALPNs a configuration names, checked against
//! that number once, before the router is built — so that a protocol which
//! cannot be registered is refused to the operator who wrote it down rather
//! than to a peer at the moment it is first wanted.
//!
//! **The bound is read off the wire, not written here.** `max_alpns` is the
//! length of the ALPN list this tree's bridge hands the QUIC core
//! (`transport/bridge_manager.zig:189,194`, where `alpn_list: [1][]const u8`
//! becomes `TlsConfig.alpn`). That is the whole of the constraint: a node whose
//! router dispatched a second protocol while its transport offered one would
//! have a table and a wire that disagree, which is the failure
//! `node/node_accept.zig:41-44` names and refuses to fix by widening either
//! side. So the number is derived, and `transport/dial_client.zig:82` — the
//! dialling half, same width — is the second place a future second protocol has
//! to reach before this module will let a node hold one.
//!
//! **A budget wider than `max_alpns` does not compile.** That is what makes the
//! number load-bearing rather than a comment: the ceiling is a property of the
//! transport, and a lane table past it would be offering the core a list it
//! cannot carry.
//!
//! **It allocates nothing, so there is no allocator to pass.** A lane is an
//! ALPN slice borrowed from the configuration, and the lanes are a fixed array
//! sized by the ceiling — so the whole plan is a value a caller holds in its
//! own struct beside `Node.entries` (`node/node.zig:359`), which is sized by
//! the same number.
//!
//! # The refusal is at startup, and it is the whole plan or none of it
//!
//! **A protocol registers or it does not; there is no registering later.** Three
//! reasons, in the order they bite:
//!
//! 1. **A registration after the freeze reaches nobody.** `router.Builder.build`
//!    freezes the table and `spawn` hands the offer list to the endpoint once
//!    (`router/alpn_table.zig:213-216`). A protocol registered at first use
//!    would sit in the table and never be offered, and a peer proposing it would
//!    be dropped by `negotiatingStep` — a drop the peer cannot tell from a
//!    firewall. That is not a late registration; it is an invisible one.
//! 2. **A first use that fits is the worse failure.** If the lane is free at the
//!    moment a peer first asks, the registration succeeds — once, quietly, under
//!    no load — and fails under load when it is not free. The same configuration
//!    then passes its own smoke test and fails in production, and the failure is
//!    a function of traffic rather than of configuration, so reproducing it
//!    means reproducing the traffic.
//! 3. **A first-use refusal arrives where it cannot be read.** It would come
//!    back on the accept path as one more entry in `node_stats.refusals`
//!    (`node/node_stats.zig:32`) alongside every other reject, so the operator
//!    sees refusals rise with nothing naming the protocol or the ceiling.
//!
//! So there is one call, over the whole configured list, before `build` — and
//! **a plan that does not fit claims nothing.** There is no partial plan and no
//! per-protocol retry: a node that came up offering the subset of its
//! configuration that fitted would be a node whose offer list and whose
//! configuration disagree, which is the same defect as (1) reached by a
//! different road. A refusal refuses the node, not the protocol, and it does so
//! where the configuration is still in front of the author.
//!
//! # The reserved protocol is not a lane
//!
//! **`qad_alpn` is `acceptInternal`'s, and `accept` refuses it**
//! (`router/alpn_table.zig:237`). Nothing under `src/` calls `acceptInternal`,
//! so a table built in this tree never offers `/iroh-qad/0`
//! (`router/qad_route.zig`, "Nothing calls this, and that is the decision").
//! Two consequences, and both are enforced rather than described:
//!
//! - `plan` refuses the reserved ALPN by name. A node's own configuration cannot
//!   claim it, and the refusal is a different name from a full table because the
//!   two answer different questions: one is "you may not have this", the other
//!   is "there is no room".
//! - There is no way to plan an internal lane. Not a parameter, not a method.
//!   The internal route is the router's business and it is deliberately not
//!   registered: `router/qad_route.zig` records the decision and the two
//!   vendored-core features it waits on. A second bridge field is what brings
//!   the lane, exactly as `node/node_accept.zig:41-44` says — and it is the
//!   last of the three, not the first.
//!
//! **A repeated ALPN is not refused here.** `Builder.push` reproduces upstream
//! and pushes a second entry, offering the name twice and dispatching to the
//! newer (`router/alpn_table.zig:264-275`), so a name given twice is two
//! registrations and this table counts two lanes for it. Deciding that is wrong
//! would be a policy the router does not have; storing what it is given is what
//! `node/topic_table.zig` does with a peer it is handed twice.

const std = @import("std");
// The bridge is read for its types only, at comptime: the width below is a
// field's array length, so nothing here is compiled against the vendored core
// and nothing here runs it. The facade is imported rather than
// `bridge_manager.zig` because the facade is the boundary this tree holds
// (`node/node_accept.zig:18`), and re-pointing the read at a moved `Bridge` is
// then one edit here rather than one per importer.
const bridge = @import("../transport/quic_bridge.zig");
const alpn_table = @import("../router/alpn_table.zig");

/// How many protocols this node registers, read from the transport.
///
/// **One, and that is not a policy this tree chose.** The core's TLS stack takes
/// a list because it is a general TLS stack; this bridge builds a one-element
/// one (`transport/bridge_manager.zig:82,189`) because a node speaks one
/// protocol. Reading the width out of the bridge rather than writing `1` here
/// is what makes the ceiling and the wire one number: raise this and the read
/// fails, rather than a node offering two protocols over a list of one.
///
/// The comptime read fails loudly, and not silently at zero, if `Bridge` ever
/// loses the field or its type: that is a `@compileError` at the point where the
/// bound would otherwise have become a number nobody checked.
pub const max_alpns: usize = blk: {
    for (@typeInfo(bridge.Bridge).@"struct".fields) |field| {
        if (std.mem.eql(u8, field.name, "alpn_list")) {
            break :blk @typeInfo(field.type).array.len;
        }
    }
    @compileError("bridge.Bridge has no `alpn_list` field to size a lane budget from");
};

/// The one ALPN an application registration cannot claim. See
/// `router/alpn_table.qad_alpn`.
///
/// Named here rather than left for a caller to reach into the router for, so
/// that "is this protocol mine to register" is one comparison against a value
/// from this layer rather than a second thing to remember.
pub const reserved_alpn: []const u8 = alpn_table.qad_alpn;

/// Every way a lane plan is refused.
pub const PlanError = error{
    /// The budget already holds a plan.
    ///
    /// **Nothing is overwritten and nothing is claimed.** A plan is decided
    /// once, at startup; a second one means the registration path ran twice,
    /// and answering it by replacing the first would make the lane table a
    /// runtime thing whose contents depend on who called it last.
    AlreadyPlanned,
    /// `protocols` names `reserved_alpn`, which `acceptInternal` owns.
    ///
    /// **Not a full table.** This protocol is not the application's to have at
    /// any occupancy, and reporting it as a capacity problem would send an
    /// operator to raise a ceiling that was never what stopped them.
    ReservedProtocol,
    /// More protocols were named than the budget has lanes.
    ///
    /// **Nothing is claimed, not even the ones that fitted.** A plan that took
    /// the first protocol and refused the second would leave a node offering a
    /// subset of what it was configured for; see the module doc.
    NoFreeLane,
};

/// The protocols this node will register, and the lanes they claim.
///
/// `LaneBudget(max_alpns)` is the one a node builds. Nothing grows: a plan past
/// the ceiling is `error.NoFreeLane`, and a plan is written once by `plan` and
/// read by `offers` until the caller drops the budget.
pub fn LaneBudget(comptime lanes: usize) type {
    return struct {
        const Self = @This();

        comptime {
            // A node that registers no protocol cannot be dialled, which is a
            // caller mistake rather than a shape to represent — and it is
            // refused here, where the mistake is, not on a run that shipped.
            std.debug.assert(lanes > 0);
            // The ceiling is the transport's, so a budget past it is refused
            // at build time rather than discovered by a peer that negotiates a
            // protocol the core was never offered.
            if (lanes > max_alpns) {
                @compileError("a lane budget wider than the transport's ALPN list");
            }
        }

        /// The ALPNs claimed, in the order the configuration named them. Only
        /// `[0..len]` is ever read, so a lane past `len` is `undefined` rather
        /// than empty.
        alpn: [lanes][]const u8 = undefined,
        /// How many lanes are claimed, never a capacity: a plan of one in a
        /// budget of one is `len == 1`.
        len: usize = 0,

        /// An unplanned budget. Nothing to release — see the module doc — so
        /// there is no `deinit` and no allocator to hand one.
        pub fn init() Self {
            return .{};
        }

        /// How many protocols this node will register.
        pub fn count(self: *const Self) usize {
            return self.len;
        }

        /// The offer list, in registration order.
        ///
        /// **Order is preference, not bookkeeping.** The first ALPN a peer
        /// offers that this node also offers is the one negotiated
        /// (`router/alpn_table.zig:227-231`), so the order a plan is written in
        /// is the order the caller chose, read straight back. Borrowed: the
        /// ALPN bytes are the configuration's and outlive the budget.
        pub fn offers(self: *const Self) []const []const u8 {
            return self.alpn[0..self.len];
        }

        /// Claim a lane for every protocol named, or for none of them.
        ///
        /// Every check runs before the first write, so a refused plan leaves the
        /// budget exactly as it was — including the budget that had never been
        /// planned.
        ///
        /// **An empty list is not refused.** It claims no lane and offers
        /// nothing, which is a node no peer can reach — but `node_config.zig:160`
        /// gives `Config.alpn` a default and the node passes the one ALPN it
        /// holds, so this tree has no path that produces an empty list. Refusing
        /// a value a caller cannot construct would be a check for a guaranteed
        /// value, and `AGENTS.md` §9 asks for it to be deleted instead.
        pub fn plan(self: *Self, protocols: []const []const u8) PlanError!void {
            // This budget's own state first: a second plan means the startup
            // path ran twice, and that is the diagnosis worth giving ahead of
            // anything about the protocols in it.
            if (self.len != 0) return error.AlreadyPlanned;
            // The reservation next, because it is a property of one protocol
            // and holds at any occupancy — and a caller who named it deserves
            // that answer rather than a ceiling they could have raised.
            for (protocols) |protocol| {
                if (std.mem.eql(u8, protocol, reserved_alpn)) {
                    return error.ReservedProtocol;
                }
            }
            // The ceiling last, once every protocol has cleared the two checks
            // that are about the protocol rather than about room.
            if (protocols.len > lanes) return error.NoFreeLane;
            @memcpy(self.alpn[0..protocols.len], protocols);
            self.len = protocols.len;
        }
    };
}

// --- tests

const t = std.testing;

/// The protocol a configuration names, typed as a slice rather than left as a
/// string literal's pointer, so a plan reads as the list of names it is and not
/// as a cast the reader has to make. `relay_alpn` is the second name, used only
/// to put a configuration one protocol past the ceiling.
const gossip_alpn: []const u8 = "ozai";
const relay_alpn: []const u8 = "iroh-relay";

test "a protocol the configuration names is registered, and the ceiling is the wire's" {
    // The production width, so the ceiling under test is the one the transport
    // offers and not a number written here. It is pinned because it is the
    // answer to "how many protocols does this node speak", and that answer must
    // not drift from `Bridge.alpn_list` without a build failure.
    try t.expectEqual(@as(usize, 1), max_alpns);
    // zwanzig-disable-next-line: identifier-style
    const Budget = LaneBudget(max_alpns);
    var budget = Budget.init();

    // Unplanned, and saying so with a count rather than with an empty offer
    // list a caller could mistake for a protocol that refuses everything.
    try t.expectEqual(@as(usize, 0), budget.count());
    try t.expectEqual(@as(usize, 0), budget.offers().len);

    try budget.plan(&.{gossip_alpn});
    try t.expectEqual(@as(usize, 1), budget.count());
    try t.expectEqualStrings(gossip_alpn, budget.offers()[0]);

    // The one protocol named is the one registered, and it is offered under the
    // name the configuration wrote rather than a copy of it.
    try t.expectEqual(@as(usize, 1), budget.offers().len);
}

test "a configuration one protocol past the ceiling is refused whole" {
    // zwanzig-disable-next-line: identifier-style
    const Budget = LaneBudget(max_alpns);
    var budget = Budget.init();

    // The ceiling refuses at the ceiling, and the refusal is all or nothing:
    // the first protocol would have fitted, and it is not claimed either. A
    // node that came up offering one of two configured protocols would be a
    // node whose offer list disagrees with its configuration.
    try t.expectError(error.NoFreeLane, budget.plan(&.{ gossip_alpn, relay_alpn }));
    try t.expectEqual(@as(usize, 0), budget.count());
    try t.expectEqual(@as(usize, 0), budget.offers().len);

    // And the node that did fit is still plannable afterwards, so a refusal
    // cost the configuration nothing and the budget nothing but the call.
    try budget.plan(&.{gossip_alpn});
    try t.expectEqual(@as(usize, 1), budget.count());
}

test "the reserved protocol is refused as a reservation and not as a full table" {
    // The ceiling is one and the budget is empty, so there is room here: a
    // refusal at this occupancy cannot be about room, and the name it carries
    // has to be the one that says the protocol is not the application's to
    // have at any occupancy.
    // zwanzig-disable-next-line: identifier-style
    const Budget = LaneBudget(max_alpns);
    var budget = Budget.init();
    try t.expectEqual(@as(usize, 0), budget.count());

    try t.expectError(error.ReservedProtocol, budget.plan(&.{reserved_alpn}));
    try t.expectEqual(@as(usize, 0), budget.count());

    // Refused by name and not by a misspelling of it: the comparison is the
    // reserved ALPN and the router's own bytes.
    try t.expectEqualStrings("/iroh-qad/0", reserved_alpn);

    // A different protocol at the same budget is admitted, which is what makes
    // the two refusals different facts rather than one fact reported twice.
    try budget.plan(&.{gossip_alpn});
    try t.expectEqual(@as(usize, 1), budget.count());
}

test "a plan is decided once and a second one is refused rather than replacing it" {
    // This is the refusal that makes "at startup" a property of the type and
    // not only of a doc comment: there is no path here that adds a lane after
    // the plan, so a protocol can never register on first use — and therefore
    // can never succeed once and fail under load.
    // zwanzig-disable-next-line: identifier-style
    const Budget = LaneBudget(max_alpns);
    var budget = Budget.init();
    try budget.plan(&.{gossip_alpn});

    try t.expectError(error.AlreadyPlanned, budget.plan(&.{relay_alpn}));
    try t.expectEqual(@as(usize, 1), budget.count());
    try t.expectEqualStrings(gossip_alpn, budget.offers()[0]);

    // The second plan is refused even when it is the reserved protocol, because
    // the budget's own state is the first fact and the one that must be loud.
    try t.expectError(error.AlreadyPlanned, budget.plan(&.{reserved_alpn}));
    try t.expectEqualStrings(gossip_alpn, budget.offers()[0]);
}
