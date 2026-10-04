//! One protocol retired part way, and the accept tasks it left behind.
//!
//! # Why this file exists
//!
//! `node_close.retire` withdraws an ALPN, runs that handler's own shutdown, and
//! only then cancels that protocol's accepts — and its own note says a
//! socket-send error propagates *after the state changes already performed*.
//! The second half of that sentence is the whole subject here: when the first
//! `closeOne` inside `cancelLane` fails, the handler has been given its
//! shutdown and the lane has stopped claiming, while the rest of that
//! protocol's accept tasks are still held, still `.handling`, and still
//! carrying a connection their handler is no longer there to serve.
//!
//! `test/runtime_handlers_test.zig` retires a lane with a connection under it
//! and watches that connection get cancelled, which is the other branch: its
//! retirement reaches `cancelLane` with nothing left to fail on. This file is
//! the branch that stops half way.
//!
//! # How the failure is produced
//!
//! **At the socket, on the real close path.** `Socket.send` asks its `std.Io`
//! whether it is cancelled before it writes a byte, so a runtime that answers
//! `error.Canceled` fails the first CONNECTION_CLOSE `cancelLane` tries to
//! send — a refused write, on the production code, at the point where a busy or
//! half-closed runtime really refuses one. The `swapCancelProtection` slot is
//! overridden alongside it so the double is a runtime that can still block
//! cancellation, like the one in `node_tests.zig` and not a function that
//! simply always says no.
//!
//! Everything else is the production loop: a `Node` with two registered
//! protocols, real sockets, real peers that finish real QUIC handshakes over
//! real UDP, and handlers that answer `.more` so their accept tasks stay in
//! `.handling` — the state only a long-lived `accept` reaches, and the state a
//! retirement has to interrupt.

const std = @import("std");
const node_mod = @import("node.zig");
const lifecycle = @import("node_lifecycle.zig");
const runtime = @import("node_runtime.zig");
const closing = @import("node_close.zig");
const protocol = @import("node_protocol.zig");
const config = @import("node_config.zig");
const base_key = @import("../base/key.zig");
const router = @import("../router/router.zig");

const t = std.testing;

const SecretKey = base_key.SecretKey;
const SocketAddr = @import("../base/addr.zig").SocketAddr;
const Instant = @import("../transport/quic_conn.zig").Instant;
const Connection = protocol.Connection;
const Turn = protocol.Turn;
const Handler = protocol.Handler;

/// Where a node binds, with port zero: the kernel picks it.
const loopback: SocketAddr = .{
    .ip = .{ .v4 = .{ 127, 0, 0, 1 } },
    .port = 0,
};

/// Where virtual time starts, and how far it moves per pass. A pass is a
/// handful of syscalls, so this is a clock and not a delay.
const start_ns: Instant = 1_000 * std.time.ns_per_s;
const time_quantum: Instant = 1_000_000;

/// A backstop against a run that never converges, not a timer.
const max_passes = 256;

/// The retired protocol, and the one that must keep being served.
const alpha_alpn = "/iroh-retired-alpha/1";
const beta_alpn = "/iroh-retired-beta/1";

/// A fixed identity per node, so a failure reproduces rather than has to be
/// re-diagnosed.
fn identityOf(tag: u8) base_key.KeyError!SecretKey {
    return SecretKey.fromSeed(@splat(tag));
}

/// One registered protocol's handler, counting what it was given.
///
/// **`.more` every time is the point, and it is the only interesting answer
/// here.** A handler that answers `.finished` has its accept task reaped in the
/// very pass that ran it, so a retirement that failed half way would find
/// nothing left to continue and this file would prove nothing. A task that is
/// still held is a task whose handler is still owed a turn on a later pass.
const Recorder = struct {
    turns: u64 = 0,
    shutdowns: u64 = 0,

    fn accept(ptr: *anyopaque, connection: Connection) router.AcceptError!Turn {
        _ = connection;
        const self: *Recorder = @ptrCast(@alignCast(ptr));
        self.turns += 1;
        return .more;
    }

    fn shutdown(ptr: *anyopaque) void {
        const self: *Recorder = @ptrCast(@alignCast(ptr));
        self.shutdowns += 1;
    }

    fn asHandler(self: *Recorder) Handler {
        return .{ .ptr = @ptrCast(self), .accept = accept, .shutdown = shutdown };
    }
};

/// Close before release even when an assertion fails: `deinit` on a node that
/// was never closed gives up its lease and logs at error level.
fn closeOnExit(node: *node_mod.Node, at: Instant) void {
    defer lifecycle.deinit(node);
    closing.close(t.io, node, at, node_mod.generator(node)) catch |err| std.debug.panic(
        "a node did not close during test teardown: {t}",
        .{err},
    );
}

/// A peer node, and the bootstrap slice its configuration borrows.
///
/// **A whole `Node` rather than a socket and a bridge**, because the claim under
/// test is about this node's own accept loop answering `node_runtime.step`
/// after a retirement, and a peer that was half the production runtime would be
/// a claim about a loop this file did not run. What the peer registers is
/// therefore never reached: a dialled connection is not an accept
/// (`node_accept.admit` walks server-side connections only), so its handler is
/// here because a protocol with no named handler is refused at registration,
/// and not because anything calls it.
///
/// **The peer list is on the heap because the node borrows it.** `Config.peers`
/// is a slice and this struct is returned by value, so an array inside it would
/// leave the node pointing at a frame that has already been popped — which is
/// the same rule `Config.protocols` states for ALPN bytes, for the one storage
/// a caller has to own rather than this file's stack.
const Dialer = struct {
    peers: []config.Peer,
    node: *node_mod.Node,

    fn init(server: *node_mod.Node, seed: u8, alpn: []const u8, silent: *Recorder) !Dialer {
        const peers = try t.allocator.alloc(config.Peer, 1);
        errdefer t.allocator.free(peers);
        peers[0] = .{
            .id = node_mod.nodeId(server),
            .addr = .{ .ip = node_mod.address(server) },
        };
        const node = try lifecycle.create(t.allocator, t.io, .{
            .secret = try identityOf(seed),
            .listen = loopback,
            .peers = peers,
            .protocols = &.{.{ .alpn = alpn, .handler = .{ .custom = silent.asHandler() } }},
        });
        errdefer {
            closing.close(t.io, node, start_ns, node_mod.generator(node)) catch {};
            lifecycle.deinit(node);
        }
        try runtime.start(node, start_ns, node_mod.generator(node));
        return .{ .peers = peers, .node = node };
    }

    fn step(self: *Dialer, at: Instant) !void {
        _ = try runtime.step(t.io, self.node, at, node_mod.generator(self.node));
    }

    /// The node's own close before its release, and its borrowed peer list
    /// after both: the list is still the configuration's until `deinit` returns.
    fn deinit(self: *Dialer, at: Instant) void {
        const peers = self.peers;
        const node = self.node;
        self.* = undefined;
        defer t.allocator.free(peers);
        defer lifecycle.deinit(node);
        closing.close(t.io, node, at, node_mod.generator(node)) catch |err|
            std.debug.panic("a dialled peer did not close during teardown: {t}", .{err});
    }
};

/// A runtime that is cancelled the way a real backend is: it answers
/// `checkCancel` with `error.Canceled` until the task blocks cancellation, and
/// it honours `swapCancelProtection` to know when that is.
///
/// Two vtable fields and one double, so every other answer stays the live
/// backend's. Kept on the thread that asked for it: the vtable slot receives
/// only the backend's `userdata`, and taking the protection out of the copied
/// vtable's userdata would put one slot's state behind every other slot's
/// backend.
threadlocal var cancel_protection: std.Io.CancelProtection = .unblocked;

fn cancelledCheck(userdata: ?*anyopaque) std.Io.Cancelable!void {
    _ = userdata;
    if (cancel_protection == .blocked) return;
    return error.Canceled;
}

fn cancelledSwap(userdata: ?*anyopaque, new: std.Io.CancelProtection) std.Io.CancelProtection {
    _ = userdata;
    const previous = cancel_protection;
    cancel_protection = new;
    return previous;
}

/// Two connections held under `index 0` and one under `index 1`, every one of
/// them in `.handling`: a task is counted by its lane from the moment it is
/// routed, `live` is the count `cancelLane` reads, and a handler that answered
/// `.finished` would have taken its task out of that count already.
fn held(server: *node_mod.Node, alpha: *const Recorder, beta: *const Recorder) bool {
    const retiring = closing.laneStats(server, 0) orelse return false;
    const other = closing.laneStats(server, 1) orelse return false;
    return retiring.live == 2 and other.live == 1 and alpha.turns != 0 and beta.turns != 0;
}

test "a retirement that failed half way gives the retired handler no further turn" {
    var at: Instant = start_ns;

    var alpha: Recorder = .{};
    var beta: Recorder = .{};
    // Never reached: see `Dialer`.
    var silent: Recorder = .{};

    const server = try lifecycle.create(t.allocator, t.io, .{
        .secret = try identityOf(0x51),
        .listen = loopback,
        .protocols = &.{
            .{ .alpn = alpha_alpn, .handler = .{ .custom = alpha.asHandler() } },
            .{ .alpn = beta_alpn, .handler = .{ .custom = beta.asHandler() } },
        },
    });
    defer closeOnExit(server, at);

    // **Two peers on the retired protocol and one on the other**, because the
    // retirement cancels this protocol's tasks one at a time and only a failure
    // on the *first* of two leaves one behind: the task whose connection was
    // being closed is gone by then, and a single task per lane would leave
    // nothing for the next pass to get wrong.
    var first = try Dialer.init(server, 0x61, alpha_alpn, &silent);
    defer first.deinit(at);
    var second = try Dialer.init(server, 0x62, alpha_alpn, &silent);
    defer second.deinit(at);
    var third = try Dialer.init(server, 0x63, beta_alpn, &silent);
    defer third.deinit(at);

    var passes: usize = 0;
    while (passes < max_passes and !held(server, &alpha, &beta)) : (passes += 1) {
        at += time_quantum;
        _ = try runtime.step(t.io, server, at, node_mod.generator(server));
        try first.step(at);
        try second.step(at);
        try third.step(at);
    }
    if (!held(server, &alpha, &beta)) std.debug.print(
        "\nstalled after {d} passes: attempts {d} routed {d}\n" ++
            "  alpha live {d} turns {d}   beta live {d} turns {d}\n",
        .{
            passes,
            server.stats.attempts,
            server.stats.tasks_routed,
            closing.laneStats(server, 0).?.live,
            alpha.turns,
            closing.laneStats(server, 1).?.live,
            beta.turns,
        },
    );
    try t.expect(held(server, &alpha, &beta));

    // The retirement, interrupted. Its first three steps are the ones
    // `lifetime.Lifetime` orders: withdraw the offer, shut the handler down,
    // then cancel this protocol's accepts — and the cancellation's first close
    // is refused by a runtime that was cancelled mid-close.
    var vtable = t.io.vtable.*;
    vtable.checkCancel = cancelledCheck;
    vtable.swapCancelProtection = cancelledSwap;
    const cancelled: std.Io = .{ .userdata = t.io.userdata, .vtable = &vtable };
    defer cancel_protection = .unblocked;

    try t.expectError(
        error.Canceled,
        closing.retire(cancelled, server, alpha_alpn, at),
    );

    // **The state the failure leaves behind, read off the same lane.** The
    // handler was given its shutdown and the lane stopped claiming, which is
    // the ordering `retire` reached before its cancellation failed; one of the
    // two connections it was going to cancel is gone and one is still held.
    const interrupted = closing.laneStats(server, 0).?;
    try t.expect(!interrupted.serving);
    try t.expectEqual(@as(u64, 1), interrupted.shutdowns);
    try t.expectEqual(@as(u64, 1), alpha.shutdowns);
    try t.expectEqual(@as(usize, 1), interrupted.live);
    // And the other lane is untouched by any of it.
    try t.expect(closing.laneStats(server, 1).?.serving);

    const alpha_turns = alpha.turns;
    const beta_turns = beta.turns;

    // The next ordinary pass. Nothing about it is special: the same
    // `node_runtime.step` any caller runs, with the live backend behind it.
    at += time_quantum;
    _ = try runtime.step(t.io, server, at, node_mod.generator(server));

    // **The claim.** A task whose lane is no longer serving is not handed to a
    // handler that has already been shut down, and it is not handed back on a
    // later pass either: it is completed here, so the pass that owes it a turn
    // owes nothing and the lane's remaining live count is zero.
    try t.expectEqual(alpha_turns, alpha.turns);
    try t.expectEqual(@as(usize, 0), closing.laneStats(server, 0).?.live);

    // **And the other lane is still driven.** One pass, one task in `.handling`,
    // one turn — which is what retiring one protocol is not: this node's close.
    try t.expectEqual(beta_turns + 1, beta.turns);
    try t.expectEqual(@as(usize, 1), closing.laneStats(server, 1).?.live);
    // The retired handler's shutdown still ran exactly once, and running it
    // again would be the other half of the same ordering mistake.
    try t.expectEqual(@as(u64, 1), alpha.shutdowns);
}
