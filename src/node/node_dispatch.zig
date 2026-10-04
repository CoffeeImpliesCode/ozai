//! Endpoint event reports, concrete actions, and ordered shutdown work.
//! I/O and time stay explicit; disposal can omit both without retaining a runtime.

const std = @import("std");
const node_mod = @import("node.zig");
const node_error = @import("node_error.zig");
const node_protocol = @import("node_protocol.zig");
const node_lane = @import("node_lane.zig");
const quic_conn = @import("../transport/quic_conn.zig");
const endpoint = @import("../endpoint/endpoint.zig");
const incoming_filter = @import("../endpoint/incoming_filter.zig");
const node_connection_close = @import("node_connection_close.zig");
const base_ula = @import("../base/ula.zig");

pub fn feed(
    self: *node_mod.Node,
    io: ?std.Io,
    first: endpoint.Event,
    at: ?quic_conn.Instant,
    random: std.Random,
) node_error.Error!void {
    // A shutdown action can owe one identical report per handler.
    var pending: [node_protocol.max_pending_events]endpoint.Event = undefined;
    var count: usize = 1;
    var head: usize = 0;
    pending[0] = first;
    while (head < count) : (head += 1) {
        const stepped = self.accept.step(pending[head]);
        self.accept = stepped.loop;
        const owed = (try perform(self, io, stepped.action, at, random)) orelse continue;
        var index: usize = 0;
        while (index < owed.count) : (index += 1) {
            std.debug.assert(count < pending.len);
            pending[count] = owed.event;
            count += 1;
        }
    }
}

/// The admission filter this node registers: let a flow in once the address it
/// arrived from has been proved, and ask it to prove itself first when it has
/// not.
///
/// **Proved means both of the core's proved states, and neither records what
/// proved it.** `.validated` is the core's validated bit on a path that is not
/// a relay, carrying the address the attempt came from; `.cooperated` is that
/// same bit on a relay, where the relay vouched for the origin before this
/// endpoint saw the datagram. The bit names no token this node can point at: at
/// the pre-accept hook it stands for a Retry token *or* a NEW_TOKEN that
/// validated against this flow's address
/// (`vendor/quic/src/quic/connection_manager.zig:806-813`), and the accept walk
/// reads a bit the core also lifts for a Handshake packet from the peer
/// (`vendor/quic/src/quic/connection.zig:2104-2106`, read through
/// `quic_conn.Conn.isValidated`). Both are read here as *proved* and not as an
/// identity they cannot back. Either is a state a second Retry is forbidden in,
/// which is why `incoming_filter.admit` refuses a retry there rather than
/// answering it. Answering `.retry` for either would ask for a token that
/// cannot exist, and the attempt would end in a refusal instead of a
/// connection.
///
/// Only `.unvalidated` is asked back, and the answer is `.retry`: source
/// address validation on a direct path, and the cost of the extra round trip on
/// a relayed one. That is upstream's own filter (`protocol.rs:574-596`), and it
/// is why an inbound flow now costs one Retry round trip.
fn proveAddress(_: *anyopaque, incoming: incoming_filter.Incoming) incoming_filter.Answer {
    return switch (incoming.validation) {
        .validated, .cooperated => .accept,
        .unvalidated => .retry,
    };
}

/// The filter `endpoint.Loop.init` is given, and the one the pre-accept hook
/// asks: one registration, both call sites.
///
/// The context is the node, which is heap-stable and outlives the loop, so it
/// stays valid for as long as `IncomingFilter` requires. `proveAddress` reads no
/// state from it; the pointer is what that contract asks for, not a channel.
pub fn filterer(self: *node_mod.Node) incoming_filter.IncomingFilter {
    return .{ .ptr = @ptrCast(self), .filter = proveAddress };
}

/// The core's pre-accept hook: the registered filter, asked at the one point
/// where its answer can still reach the peer.
///
/// A `retry` verdict here is a Retry packet on the wire rather than a refusal,
/// because nothing has been committed for the flow and the Initial is still in
/// hand (`vendor/quic/src/quic/connection_manager.zig`). That is why the node
/// runs this at all: `endpoint.zig` records at length that a retry verdict
/// reached after the connection exists can only be refused.
pub fn admission(ptr: *anyopaque, offered: quic_conn.Admission) quic_conn.AdmissionVerdict {
    const self: *node_mod.Node = @ptrCast(@alignCast(ptr));
    return admit(self.accept.incoming_filter, offered);
}

/// One attempt, and the verdict the endpoint layer reaches for it: the
/// registered filter's answer put through the endpoint's own `decide`, which
/// attaches what a retry is worth on this path and refuses a retry that a flow
/// which has already proved itself cannot be given.
///
/// The core offers no refusal verb, so `reject` and `ignore` both arrive as
/// `drop`: neither sends anything, which is what `ignore` is, and a
/// peer-visible refusal stays the loop's own `Action.refuse` for an attempt it
/// already holds. Both are reachable only from a filter some caller registers;
/// the one registered here answers accept or retry.
pub fn admit(
    present: ?incoming_filter.IncomingFilter,
    offered: quic_conn.Admission,
) quic_conn.AdmissionVerdict {
    // An address the core cannot name is not an attempt this endpoint can act
    // on, and a filter handed a fabricated address would be answering about
    // something that was never received.
    const remote = quic_conn.fromCoreAddress(&offered.remote) orelse return .drop;
    const local = quic_conn.fromCoreAddress(&offered.local) orelse return .drop;
    const classification = base_ula.classify(remote);
    const incoming: incoming_filter.Incoming = .{
        .id = offered.id,
        .remote = remote,
        .local = local,
        .classification = classification,
        // The core's own answer about this flow, read the way every other
        // attempt reads it: a bit that is false is `.unvalidated` on every
        // path, not the identity that path would otherwise have earned.
        .validation = incoming_filter.proved(classification, remote, offered.validated),
    };
    return switch (incoming_filter.decide(incoming_filter.ask(present, incoming), incoming)) {
        .accept => .accept,
        .retry => .retry,
        .reject, .ignore => .drop,
    };
}

pub fn perform(
    self: *node_mod.Node,
    io: ?std.Io,
    action: endpoint.Action,
    at: ?quic_conn.Instant,
    random: std.Random,
) node_error.Error!?node_mod.Answer {
    switch (action) {
        .offer => |incoming| {
            // The filter the loop was registered with, not a null one. `Loop`
            // holds the registration and only names the call, so ignoring it
            // here is what made every attempt accepted regardless of policy.
            return .{ .event = .{
                .filtered = incoming_filter.ask(self.accept.incoming_filter, incoming),
            } };
        },
        .spawn => |task| {
            self.stats.spawned += 1;
            std.debug.assert(self.accept.task(task.id) != null);
            return null;
        },
        .refuse => {
            self.stats.refusals += 1;
            return null;
        },
        .ignore => {
            self.stats.ignores += 1;
            return null;
        },
        .shutdown => |owed| return try performShutdown(self, io, owed, at, random),
        .none => return null,
    }
}

pub fn performShutdown(
    self: *node_mod.Node,
    io: ?std.Io,
    owed: endpoint.ShutdownStep,
    at: ?quic_conn.Instant,
    random: std.Random,
) node_error.Error!?node_mod.Answer {
    if (owed.panicked) |reaped| std.log.err(
        "node: accept task {d} failed and started the shutdown",
        .{reaped.id},
    );
    switch (owed.action) {
        .shutdown_handlers => |count| {
            // **Both sides count the same set, and the assertion survives.**
            // `endpoint.handlerCount` is the number of *distinct* ALPNs
            // (`Router.protocolCount`), because a handler registered twice is
            // shut down once, as the newer one — the older entry is unreachable
            // (`router.zig`'s `Registered.replaced`). `table.configured()` is
            // the number of *registrations*, so walking it shut a displaced lane
            // down as well and then asserted equality against a count that
            // could not match it: a table with a duplicated ALPN panicked at
            // close. The walk now counts what it shuts down rather than
            // comparing two different sets, and the assertion below still
            // catches a machine that owes a different number than this performs.
            //
            // `shutdownLane` skips a lane already shut down by retirement, so
            // what is counted is what the close owes and not what this pass
            // happened to call.
            var shut: usize = 0;
            var index: usize = 0;
            while (index < self.table.configured()) : (index += 1) {
                // Whether this registration is the one a peer reaches for its
                // ALPN is asked of the router rather than decided here:
                // `dispatch` resolves an ALPN to its newest entry, so this is
                // the table's own answer and not a second comparison of ALPN
                // bytes that could drift from it.
                switch (self.table.dispatch(self.lanes[index].alpn)) {
                    .protocol => |claim| {
                        if (claim.index != index) continue;
                        node_lane.shutdownLane(self, index);
                        shut += 1;
                    },
                    // An entry's own ALPN is always claimed by the table, so
                    // this arm is unreachable for an index read out of that
                    // table. It is named rather than folded into a wildcard
                    // because an ALPN nothing claims is not this lane's.
                    .refused => {},
                }
            }
            std.debug.assert(shut == count);
            return .{ .event = .handler_finished, .count = count };
        },
        .cancel_accepts => {
            // Reap backwards because the endpoint swaps its final task into each hole.
            var index = self.accept.live;
            while (index > 0) {
                index -= 1;
                const id = self.accept.tasks[index].id;
                const stepped = self.accept.step(.{
                    .reaped = .{ .id = id, .ended = .cancelled },
                });
                self.accept = stepped.loop;
                std.debug.assert(stepped.action == .none);
                // The removal is the work; only its result is asserted. A call
                // inside `std.debug.assert` is not evaluated in ReleaseFast or
                // ReleaseSmall, which would leave this task in the map.
                const removed = self.offered.remove(id);
                std.debug.assert(removed);
                self.stats.accepts_cancelled += 1;
            }
            return .{ .event = .accepts_cancelled };
        },
        .close_endpoint => {
            // A failed send leaves the descriptor open for the next shutdown attempt.
            if (io) |runtime| {
                if (at) |stamp| {
                    try node_connection_close.closeConnections(runtime, self, stamp, random);
                }
            }
            self.endpoint_closed = true;
            shutdownSocket(self);
            return .{ .event = .endpoint_closed };
        },
        .none => return null,
    }
}

pub fn shutdownSocket(self: *node_mod.Node) void {
    // A second close could release a descriptor reused by an unrelated owner.
    if (!self.socket_open) return;
    self.socket_open = false;
    self.socket.close();
}

const t = std.testing;
const SocketAddr = @import("../base/addr.zig").SocketAddr;
const Verdict = quic_conn.AdmissionVerdict;

/// One attempt as the core hands it over, over addresses a test can name.
fn attempt(remote: SocketAddr, validated: bool) quic_conn.Admission {
    return .{
        .id = 7,
        .remote = quic_conn.toCoreAddress(remote),
        .local = quic_conn.toCoreAddress(remote),
        .validated = validated,
    };
}

/// The filter this node registers, asked directly. `proveAddress` reads no
/// state, so the context is a real object that is never dereferenced.
fn registered(context: *anyopaque) incoming_filter.IncomingFilter {
    return .{ .ptr = context, .filter = proveAddress };
}

/// A direct peer, and a relayed one, as the two paths an attempt arrives on.
const direct_peer: SocketAddr = .{ .ip = .{ .v4 = .{ 203, 0, 113, 9 } }, .port = 443 };

fn relayPeer(host: u8) SocketAddr {
    return base_ula.socketAddrFor(.relay, .{ 0, 0, 0, 0, 0, 0, 0, host });
}

test "an unvalidated flow is retried and a validated one is admitted without a Retry" {
    var context: u8 = 0;
    const filter = registered(@ptrCast(&context));

    // The negative space, and the reason the core's bit is a parameter and not
    // a guess: nothing proved means the flow is asked to prove itself, not let
    // in. This is the verdict that becomes a Retry packet on the wire.
    try t.expectEqual(Verdict.retry, admit(filter, attempt(direct_peer, false)));
    try t.expectEqual(Verdict.retry, admit(filter, attempt(relayPeer(9), false)));

    // Proved means accepted, on both paths, and a Retry is not asked for a
    // second time: QUIC permits one per flow, so a validated address bypasses
    // Retry rather than earning another one.
    try t.expectEqual(Verdict.accept, admit(filter, attempt(direct_peer, true)));
    try t.expectEqual(Verdict.accept, admit(filter, attempt(relayPeer(9), true)));
}

test "a filter's refusal reaches the core as silence, and an unnamed address is never offered" {
    var context: u8 = 0;

    // A filter that refuses or ignores sends nothing at either seam, and the
    // core hook has no third answer for it: neither is a token and neither is a
    // connection.
    const rejecting: incoming_filter.IncomingFilter = .{
        .ptr = @ptrCast(&context),
        .filter = struct {
            fn refuse(_: *anyopaque, _: incoming_filter.Incoming) incoming_filter.Answer {
                return .reject;
            }
        }.refuse,
    };
    try t.expectEqual(Verdict.drop, admit(rejecting, attempt(direct_peer, false)));

    // A retry on a flow that has already proved itself is refused by the
    // endpoint's own rule, so it never becomes a second Retry token either.
    const always_retry: incoming_filter.IncomingFilter = .{
        .ptr = @ptrCast(&context),
        .filter = struct {
            fn again(_: *anyopaque, _: incoming_filter.Incoming) incoming_filter.Answer {
                return .retry;
            }
        }.again,
    };
    try t.expectEqual(Verdict.retry, admit(always_retry, attempt(direct_peer, false)));
    try t.expectEqual(Verdict.drop, admit(always_retry, attempt(direct_peer, true)));

    // An address the core cannot name is not an attempt: nothing is accepted on
    // the strength of an address that was never received.
    const unnamed: quic_conn.Admission = .{
        .id = 7,
        .remote = quic_conn.unset_address,
        .local = quic_conn.unset_address,
        .validated = false,
    };
    try t.expectEqual(Verdict.drop, admit(registered(@ptrCast(&context)), unnamed));

    // And no filter at all is upstream's default: every attempt accepted.
    try t.expectEqual(Verdict.accept, admit(null, attempt(direct_peer, false)));
}
