//! What must happen before what on the way down, and what may be skipped.
//!
//! **The order here is read out of the code, not proposed to it.** Every step
//! below is work the wind-down already performs, at the line the citation
//! names, and `order` is those places in the sequence they occur in. An order
//! invented here would be a description of a shutdown nobody runs, which is the
//! one thing this file must not be.
//!
//! Two functions perform the wind-down and they are not alternatives.
//! `Node.close` runs the first four steps and `Node.deinit` runs the rest, and
//! `node_loop.run` closes on its way out precisely so that a caller reaches
//! `deinit` with the first half already run (`node_build.zig:332-336`). So
//! `order` is one sequence over both, and `descriptor` appearing in it once is
//! a fact rather than a smoothing: two call sites reach it
//! (`node_close.zig:218`, `node_build.zig:398`) and one flag decides which of
//! them does the work (`node_transport.zig:205-209`).
//!
//! # What is released exactly once
//!
//! **A release is given up once, and what makes it once is a latch rather than
//! the order.** The two the code reaches twice are named by `latched`: the
//! relay's clients, which the handler's shutdown releases and `freeRelay`
//! releases again as its backstop (`node_accept.zig:331`,
//! `node_relay_table.zig:231`), and the descriptor, which `close_endpoint` and
//! `deinit` both shut. Both survive the second reach the same way, and each
//! latch *takes* what it guards rather than leaving a flag for a second call to
//! read: the relay guard is deinited and the slot overwritten with `.{}`
//! (`node_relay_release.zig:47-51`), and `socket_open` is cleared before the
//! `close` rather than after it (`node_transport.zig:206-207`). There is then
//! no second call left to make, which is stronger than a flag that answers
//! "already done".
//!
//! **The order alone does not give this, and `Ledger` says so.** Walking
//! `order` twice gives `relay_clients` twice, and `giveUp` refuses the second.
//! So the exactly-once property is carried by those latches and by nothing
//! else, and a caller that wants to know it holds has somewhere to ask.
//!
//! # What is safe to skip
//!
//! **One step: the connection close, and only where the caller has nothing to
//! stamp one with.** `dispose` is a shutdown with no runtime and no instant and
//! it performs every phase but that one (`node_close.zig:117-139`,
//! `:213-216`); the connections it did not close are then released with the
//! bridge, which is why `releases` puts `connections` under `.bridge` as well.
//! So the disposal path leaks nothing. What it loses is not a resource but the
//! announcement — the peers are not told, and each waits out its own idle
//! timeout. Every other step runs on every path, including the one a budget
//! would most like to skip; `shutdown_budget.zig` decides that one.

const std = @import("std");

/// One unit of work a wind-down performs, named as the code performing it names
/// it.
pub const Step = enum {
    /// `shutdown_handlers`: every registered handler's own `shutdown`, and
    /// through the node's handler the relay's clients (`node_close.zig:165-175`,
    /// `node_accept.zig:323-332`).
    handlers,
    /// `cancel_accepts`: every live accept task reaped as `.cancelled`
    /// (`node_close.zig:182-199`).
    accepts,
    /// `close_endpoint`'s first half — `conn.close` stamped on every connection
    /// the core holds, drained and sent (`node_close.zig:232-240`).
    connections,
    /// `close_endpoint`'s second half, and `deinit`'s last line
    /// (`node_close.zig:218`, `node_build.zig:398`).
    descriptor,
    /// `Lease.deinit`, given up first inside `deinit` (`node_build.zig:346`).
    lease,
    /// Every dialled connection out of the manager, then `bridge.sweep`
    /// (`node_build.zig:360-366`).
    dialled,
    /// `node_relay_table.freeRelay` (`node_build.zig:372`).
    ///
    /// **Its own doc claims the opposite of what the code does.**
    /// `node_build.zig:367-371` says the relay is given up *before* the
    /// dialer's connections leave, and `:360-366` has already taken them. The
    /// order the code runs is the one that survives, and it is safe for a
    /// reason the comment does not give: `release` reads the slot's guard and
    /// its inbox and never the connection (`node_relay_release.zig:47-51`), so
    /// nothing here dereferences a connection the core has already freed.
    relayed,
    /// `Dialer.destroy` (`node_build.zig:383`).
    dialer,
    /// `Bridge.destroy`, which takes the core's remaining connections with it
    /// (`node_build.zig:389`).
    bridge,
    /// `egress`, `out`, `scratch` and `buf` (`node_build.zig:390-393`).
    buffers,
    /// The address map and the three bookkeeping tables
    /// (`node_build.zig:394-397`).
    bookkeeping,
    /// The node's own copy of the secret (`node_build.zig:399`).
    secret,
    /// The node itself (`node_build.zig:400`).
    node,
};

/// Every step, in the order the wind-down performs them.
///
/// `descriptor` is one step with two entrances, and this is the single
/// sequence that both `close` and `deinit` walk.
pub const order: []const Step = &.{
    .handlers,
    .accepts,
    .connections,
    .descriptor,
    .lease,
    .dialled,
    .relayed,
    .dialer,
    .bridge,
    .buffers,
    .bookkeeping,
    .secret,
    .node,
};

/// Where `step` falls in `order`, and null for a step `order` does not carry.
///
/// Null rather than a sentinel: a step missing from the order is a step this
/// file has failed to record, and a caller has to be able to hear that rather
/// than be handed a position that orders it last.
pub fn position(step: Step) ?usize {
    for (order, 0..) |candidate, index| {
        if (candidate == step) return index;
    }
    return null;
}

/// Whether `a` is performed before `b`.
///
/// A step the order does not carry precedes nothing, because there is no
/// sequence to read the order out of.
pub fn precedes(a: Step, b: Step) bool {
    const first = position(a) orelse return false;
    const second = position(b) orelse return false;
    return first < second;
}

/// What `step` cannot be performed before.
///
/// **A subset of the order, not the whole of it.** A step with no entry here is
/// not free of the sequence — it is waiting on nothing, and the reason the code
/// puts it where it is is at the line its own field cites. `relayed` is the
/// clearest case: it follows `dialled` in the sequence and depends on nothing,
/// because the work it does never touches a connection.
///
/// The dependencies that are here are the ones a violation of which is a use
/// after free rather than a surprise: a cancel issued while a handler is still
/// draining (`node_close.zig:141-147`), the endpoint close the machine will not
/// emit before the cancel landed (`router.zig:631-639`), a guard that reaches
/// into this struct's own registry (`node_build.zig:367-371`), the manager that
/// has to outlive the dialer walking it (`node_build.zig:354-359`), and the
/// allocator that is a field of the node every one of those frees with.
pub fn blockedBy(step: Step) []const Step {
    return switch (step) {
        .handlers, .lease, .dialled, .relayed, .buffers, .bookkeeping, .secret => &.{},
        .accepts => &.{.handlers},
        .connections => &.{ .handlers, .accepts },
        // `close_endpoint` is one machine action, so the descriptor goes no
        // earlier than the cancel even on the path that closes no connections.
        .descriptor => &.{.accepts},
        .dialer => &.{.relayed},
        .bridge => &.{ .relayed, .dialer },
        .node => &.{ .relayed, .dialer, .bridge, .buffers, .bookkeeping, .secret },
    };
}

/// One thing a wind-down gives up.
///
/// Two steps reach `relay_clients` and two reach `connections`, which is the
/// whole of what makes this a separate list from `Step`: what is given up is a
/// question the order cannot answer, because it is answered by a latch.
pub const Release = enum {
    /// The handler's own state, which for this node is its timer table:
    /// `clearRetainingCapacity` empties it in this phase (`node_accept.zig:325`)
    /// and the capacity itself goes back with the bookkeeping step.
    handler_state,
    /// Every relay client's guard reported, its inbox freed and its slot left
    /// holding nothing (`node_relay_release.zig:47-51`).
    relay_clients,
    /// Every live accept task, reaped as `.cancelled` and counted
    /// (`node_close.zig:182-199`).
    accept_tasks,
    /// The connections the core holds: closed and announced by
    /// `closeConnections`, or taken with the bridge when nothing announced
    /// them.
    connections,
    /// The socket descriptor (`node_transport.zig:205-209`).
    descriptor,
    /// The endpoint lease (`node_build.zig:346`).
    lease,
    /// Every dialled connection out of the core's manager
    /// (`node_build.zig:360-366`).
    dialled,
    /// The relay's storage: the registry, the client slots, the queues and the
    /// two frame buffers (`node_relay_table.zig:230-243`).
    relay_storage,
    /// The dialer's own seed and its borrowed copy of the secret, both erased
    /// (`dial_client.zig:131-132`). It refuses while a dialled connection is
    /// live, so this release is only reached once there is none.
    dialer_seed,
    /// The core's table and the seed it signs with (`bridge_manager.zig:142-145`),
    /// and with them whatever connections are still in that table.
    bridge_state,
    /// The four heap buffers: egress, send, scratch and receive.
    buffers,
    /// The address map, the offered set, the dialled set and the timer table
    /// (`node_build.zig:394-397`).
    bookkeeping,
    /// The node's own copy of the secret (`node_build.zig:399`).
    secret,
    /// The node itself, and with it the allocator every step above freed with.
    node,
};

/// What `step` gives up.
///
/// `relay_clients` and `connections` appear under two steps each. That is the
/// code, not a slip: `freeRelay` releases the clients again as its backstop
/// (`node_relay_table.zig:231`) and the core's teardown takes the connections
/// a disposal path never closed (`node_close.zig:209-211`). `latched` is what
/// keeps the second client reach from being a double free; the connections are
/// kept once by *which* of the two ran rather than by a latch, because the
/// bridge takes only what `closeConnections` did not already close.
pub fn releases(step: Step) []const Release {
    return switch (step) {
        .handlers => &.{ .handler_state, .relay_clients },
        .accepts => &.{.accept_tasks},
        .connections => &.{.connections},
        .descriptor => &.{.descriptor},
        .lease => &.{.lease},
        .dialled => &.{.dialled},
        .relayed => &.{ .relay_clients, .relay_storage },
        .dialer => &.{.dialer_seed},
        .bridge => &.{ .connections, .bridge_state },
        .buffers => &.{.buffers},
        .bookkeeping => &.{.bookkeeping},
        .secret => &.{.secret},
        .node => &.{.node},
    };
}

/// Whether a step may reach `release` a second time behind a latch of its own.
///
/// **These two, and the reason is the same for both: the latch takes rather
/// than counts.** The relay guard is deinited and the slot overwritten with
/// `.{}`, so there is no handle left for a second call to report through, and
/// `socket_open` is cleared before `Socket.close` rather than after it. Every
/// other release is reached once because the machine emits its action once,
/// which is a stronger guarantee than a latch and costs nothing to state.
pub fn latched(release: Release) bool {
    return release == .relay_clients or release == .descriptor;
}

/// Whether performing `step` is something a peer can observe.
///
/// One step, and it is the one the budget decides about: the connection close
/// writes to the wire, and nothing else on the way down does. The descriptor
/// release stops this node answering, which a peer learns from a timeout rather
/// than from a packet.
pub fn announced(step: Step) bool {
    return step == .connections;
}

/// What a caller handed the close.
///
/// `dispose` is the one caller that hands it neither, and that is the whole of
/// what the connection close needs: a runtime to write through and an instant
/// to stamp the close with (`node_close.zig:213-216`).
pub const Have = struct {
    /// Whether the close has a `std.Io` to send through.
    runtime: bool = false,
    /// Whether the close has an instant to stamp a connection close with.
    instant: bool = false,
};

/// Whether `step` is the kind of step a caller may skip at all.
///
/// One of them, and the reason is not that it is cheap: it is that every other
/// step is local, and a skipped local step is a resource this node still holds
/// when it is gone.
pub fn skippable(step: Step) bool {
    return step == .connections;
}

/// Whether `step` is skipped given what the caller handed the close.
///
/// Both halves are required, because the code requires both: `close_endpoint`
/// closes the connections only under an `io` *and* an `at`
/// (`node_close.zig:213-216`), so a runtime without an instant skips as much as
/// an instant without one.
pub fn skipped(step: Step, have: Have) bool {
    if (!skippable(step)) return false;
    return !(have.runtime and have.instant);
}

/// Which releases have been given up. Fourteen releases fit a `u16`, and the
/// fit is proved below against the enum's own field count rather than written
/// as a number.
pub const Mask = u16;

/// One release's bit.
pub fn maskOf(release: Release) Mask {
    return @as(Mask, 1) << @intCast(@intFromEnum(release));
}

/// Every release, as a mask: what a finished wind-down has made of it is `every`
/// with all of these set.
pub const every: Mask = blk: {
    var mask: Mask = 0;
    for (@typeInfo(Release).@"enum".fields, 0..) |_, index| {
        mask |= @as(Mask, 1) << @intCast(index);
    }
    break :blk mask;
};

const step_count = @typeInfo(Step).@"enum".fields.len;

comptime {
    if (@typeInfo(Release).@"enum".fields.len > @bitSizeOf(Mask)) {
        @compileError("a release no longer fits this ledger's mask");
    }
}

/// What a ledger refuses. All three are a caller's finding rather than a
/// failure the wind-down itself can hit: `OutOfOrder` is the use after free
/// `node_close.zig:141-147` names, `ReleasedTwice` is the double free the two
/// latches exist to prevent, and `NotRun` is a latch reporting "already done"
/// for a step that never started.
pub const Error = error{
    OutOfOrder,
    ReleasedTwice,
    NotRun,
};

/// Which steps have run and which releases have been given up.
///
/// **Two words, because the wind-down asks two different questions and they have
/// different answers.** A step may be reached more than once — the code reaches
/// `close_endpoint` twice on a resumed close and `descriptor` from two call
/// sites — and a release may not. A ledger that conflated the two would refuse
/// the resume `node_close.zig:96-109` exists to support, so `advance` is
/// idempotent and `giveUp` is not.
pub const Ledger = struct {
    ran: [step_count]bool = @splat(false),
    given: Mask = 0,

    /// Record that `step` was performed.
    ///
    /// `OutOfOrder` when something `step` depends on has not run. A step that
    /// was skipped does not block: it is a step nobody performed and nothing
    /// waits for it, which is what lets the disposal path reach `.descriptor`.
    pub fn advance(self: *Ledger, step: Step) Error!void {
        for (blockedBy(step)) |needed| {
            if (!self.hasRun(needed)) return error.OutOfOrder;
        }
        self.ran[@intFromEnum(step)] = true;
    }

    /// Record that `release` is given up, and refuse the second time.
    pub fn giveUp(self: *Ledger, release: Release) Error!void {
        const bit = maskOf(release);
        if (self.given & bit != 0) return error.ReleasedTwice;
        self.given |= bit;
    }

    /// A step reached again behind its own latch, which gives nothing up.
    ///
    /// `NotRun` when it has not run: there is no latch to have reported
    /// anything, and a caller treating this as a re-entry has found a latch
    /// that says "already done" about work that never began.
    pub fn reentered(self: *Ledger, step: Step) Error!void {
        if (!self.hasRun(step)) return error.NotRun;
    }

    /// Whether `step` has been performed.
    pub fn hasRun(self: Ledger, step: Step) bool {
        return self.ran[@intFromEnum(step)];
    }

    /// Whether `release` has been given up.
    pub fn hasGiven(self: Ledger, release: Release) bool {
        return self.given & maskOf(release) != 0;
    }

    /// Every release nothing has given up yet. Zero at the end of a wind-down
    /// is what says no resource leaks at exit; anything else at the end is a
    /// leak, or a step the caller has not reached yet.
    pub fn outstanding(self: Ledger) Mask {
        return every & ~self.given;
    }
};

// --- tests

const t = std.testing;

/// The wind-down the code performs: every step, with the releases each gives
/// up, a latched release left alone on the reach that would give it twice, and
/// the connections given up by whichever of the two steps that reach them
/// actually ran.
fn windDown(ledger: *Ledger, have: Have) Error!void {
    // Whether the close announced the connections, which is what decides which
    // of the two steps that release them reaches any work.
    var close_announced = false;
    for (order) |step| {
        if (skipped(step, have)) continue;
        try ledger.advance(step);
        for (releases(step)) |release| {
            // `connections` is reached twice and latched zero times.
            // `closeConnections` stamps and writes every connection the core
            // holds (`node_close.zig:232-240`) and `Bridge.destroy` takes only
            // what is left in the table (`node_build.zig:389`), so on any one
            // path the second of the two reaches finds nothing to release.
            if (release == .connections and close_announced) continue;
            if (latched(release) and ledger.hasGiven(release)) continue;
            try ledger.giveUp(release);
        }
        if (step == .connections) close_announced = true;
    }
}

test "every step the wind-down performs is in the order, and in it once" {
    try t.expectEqual(@as(usize, step_count), order.len);
    // Every step has a place, so `position` is never the answer a caller gets
    // for a step this file names.
    inline for (@typeInfo(Step).@"enum".fields) |field| {
        const step: Step = @enumFromInt(field.value);
        try t.expect(position(step) != null);
    }
    // And the sequence is a strict order: nothing precedes itself, and for two
    // distinct steps exactly one direction holds.
    inline for (@typeInfo(Step).@"enum".fields, 0..) |field, index| {
        const a: Step = @enumFromInt(field.value);
        try t.expect(!precedes(a, a));
        inline for (@typeInfo(Step).@"enum".fields, 0..) |other, other_index| {
            const b: Step = @enumFromInt(other.value);
            try t.expectEqual(index != other_index, precedes(a, b) != precedes(b, a));
        }
    }
}

test "no step waits on a step the order performs after it" {
    var edges: usize = 0;
    for (order) |step| {
        const at = position(step) orelse return error.TestUnexpectedResult;
        for (blockedBy(step)) |needed| {
            edges += 1;
            const needed_at = position(needed) orelse return error.TestUnexpectedResult;
            try t.expect(needed_at < at);
        }
    }
    // A vacuous pass is a pass over no dependencies, so the sweep above would
    // have proved nothing at all; the table is not empty.
    try t.expect(edges > 0);
}

test "a wind-down that runs the whole order gives every release up once" {
    var ledger: Ledger = .{};
    try windDown(&ledger, .{ .runtime = true, .instant = true });
    // Nothing is left over, which is the leak-at-exit half of the question.
    try t.expectEqual(@as(Mask, 0), ledger.outstanding());
    // And nothing was given up twice: `giveUp` refuses the second reach, and
    // this walk reached every release and came back.
    inline for (@typeInfo(Release).@"enum".fields) |field| {
        try t.expect(ledger.hasGiven(@enumFromInt(field.value)));
    }
}

test "the disposal path skips the close and still leaks nothing" {
    var ledger: Ledger = .{};
    try windDown(&ledger, .{});
    // The connection close is the one step a caller with no runtime and no
    // instant cannot perform, and `advance` refused nothing on the way past it:
    // a skipped step blocks nobody, which is what the descriptor release needs.
    try t.expect(!ledger.hasRun(.connections));
    try t.expect(ledger.hasRun(.descriptor));
    // What it lost is the announcement rather than the release. The connections
    // are gone with the bridge, which is what `node_close.zig:209-211` says
    // the disposal path leaves them to.
    try t.expect(ledger.hasGiven(.connections));
    try t.expectEqual(@as(Mask, 0), ledger.outstanding());
}

test "a step that runs before what it depends on is refused" {
    var ledger: Ledger = .{};
    // The accept cancel waits for the handlers, and the endpoint close waits
    // for the cancel: `node_close.zig:141-147` and `router.zig:631-639`.
    try t.expectError(error.OutOfOrder, ledger.advance(.accepts));
    try t.expectError(error.OutOfOrder, ledger.advance(.connections));
    try t.expectError(error.OutOfOrder, ledger.advance(.descriptor));
    // The dialer waits for the relay's guards, which reach into this struct.
    try t.expectError(error.OutOfOrder, ledger.advance(.dialer));
    // And nothing is freed with the node's own allocator before the node is.
    try t.expectError(error.OutOfOrder, ledger.advance(.node));
    // None of those left a mark, so the wind-down still runs in order.
    try t.expectEqual(every, ledger.outstanding());
    try windDown(&ledger, .{ .runtime = true, .instant = true });
    try t.expectEqual(@as(Mask, 0), ledger.outstanding());
}

test "a release given up twice is refused, and a latch is how it is given once" {
    var ledger: Ledger = .{};
    try windDown(&ledger, .{ .runtime = true, .instant = true });
    // The walk reached `.relay_clients` at the handlers and again at `freeRelay`,
    // and gave it up once: the latch is what the second reach came through.
    try t.expect(ledger.hasGiven(.relay_clients));
    // Anything but the latch and this is a double free.
    try t.expectError(error.ReleasedTwice, ledger.giveUp(.relay_clients));
    try t.expectError(error.ReleasedTwice, ledger.giveUp(.descriptor));
    try t.expectError(error.ReleasedTwice, ledger.giveUp(.secret));
    // A step reached again behind its latch is not a second wind-down, and a
    // latch claiming that about a step that never ran is a latch lying.
    try ledger.reentered(.descriptor);
    var fresh: Ledger = .{};
    try t.expectError(error.NotRun, fresh.reentered(.descriptor));
}

test "the only step a caller may skip is the close, and only without a stamp" {
    inline for (@typeInfo(Step).@"enum".fields) |field| {
        const step: Step = @enumFromInt(field.value);
        const only_close = step == .connections;
        try t.expectEqual(only_close, skippable(step));
        try t.expectEqual(only_close, skipped(step, .{}));
        // One half of what the close needs is not enough: `close_endpoint`
        // closes connections under an `io` *and* an `at`.
        try t.expectEqual(only_close, skipped(step, .{ .runtime = true }));
        try t.expectEqual(only_close, skipped(step, .{ .instant = true }));
        try t.expect(!skipped(step, .{ .runtime = true, .instant = true }));
    }
}
