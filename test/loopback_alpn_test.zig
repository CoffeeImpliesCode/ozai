//! Which protocol a loopback connection ends up speaking, and what happens to
//! a peer that asks for one this node does not serve.
//!
//! # Why this file exists
//!
//! `docs/PLAN.md` put "ALPN selection and refusal" in wave 1, and the runtime
//! restriction it removed was `src/node/node.zig`'s `max_alpns = 1`: a node
//! could be configured with exactly one protocol, so "which protocol is this
//! connection?" had an answer that was true before the handshake and could not
//! be wrong. With several protocols configured it is a real question with two
//! distinct failure modes, and they fail in different places:
//!
//! * **No intersection.** The peer names a protocol this node does not offer.
//!   The TLS handshake refuses it — RFC 8446 alert 120,
//!   `no_application_protocol` — and no connection is ever established. The
//!   peer is told, and told early.
//! * **A configured protocol exists but nobody claims it.** The router is
//!   asked to dispatch an ALPN its table does not hold, and the attempt is
//!   dropped with `Drop.refused_protocol`. Nobody is told.
//!
//! The first is a wire fact and the second is a table fact, so they are two
//! tests rather than one with a union at the end, and the boundary between them
//! is itself asserted: a refusal over a real socket must not be reported as a
//! router drop, or a test that only checked "it did not connect" would pass
//! against a stack that connected and then hung up.
//!
//! # Selection, over a socket and in a table
//!
//! Two protocols configured on one endpoint is the case that was unreachable
//! before `Config.alpns` became a list: with a single ALPN per side there is
//! nothing to choose between, so a server that ignored the peer's offer and
//! picked its own first entry would pass every other test in this file. The two
//! socket tests at the end therefore cover the thing the rest cannot:
//!
//! * A server offering `[blobs, gossip]` against a dialer naming only `gossip`
//!   negotiates **gossip** — the one protocol both ends speak, so a server
//!   that answered its own first entry regardless would have said `blobs`.
//! * With both ends offering both in opposite orders, the **server's** order
//!   wins, which is RFC 7301 §3.2: the selection is made among the protocols
//!   both ends speak and `Config.alpns` is this side's preference order over
//!   them, so the dialer's order does not decide it. This is the arm that
//!   fails if either side is consulted in the wrong order.
//!
//! Both assert the negotiated name on *both* ends and the handshake's recorded
//! selection length, so neither can pass on the config fallback
//! (`Tls13Handshake.negotiatedAlpn` answers the first configured entry when
//! nothing was chosen).
//!
//! # What is asserted
//!
//! 1. Several handlers registered under different protocols each claim their
//!    own ALPN, and an ALPN none of them claims earns a refusal that names what
//!    *is* configured. Two registrations under one ALPN are one protocol, which
//!    is what makes `protocolCount` different from `configured`.
//! 2. Over a real socket: a dial that offers a protocol the other end does not
//!    speak never establishes on either side, and the end that refused holds no
//!    negotiated protocol — the handshake died before it could pick one.
//! 3. The refusal is not a router drop, because no established connection
//!    reached the router. That is asserted by driving the same
//!    refusal through `dispatchStep` and showing the table's own answer is a
//!    drop, while the socket's is a connection that never came up.
//!
//! # The refusal logs at error level
//!
//! The vendored core reports a failed handshake step with
//! `std.log.err("TLS 1.3 handshake error: {}", .{err})`
//! (`vendor/quic/src/quic/connection.zig:3178`), and the error here is
//! `error.NoApplicationProtocol`. That message is at error level, so this
//! artifact — which runs under `test/expected_log_runner.zig` and fails on any
//! error-level log it was not told about — needs a second `--expect-log` row in
//! `build.zig`, beside the certificate refusal the wrong-peer test provokes.
//! The row is a claim that the message arrives *once*, and the runner spends it
//! on the first match and fails on a second copy, which is what makes two
//! deliberate refusals in one artifact accountable separately rather than one
//! of them silently tolerated.

const std = @import("std");
const ozai = @import("ozai");

const t = std.testing;

const link_mod = @import("loopback_link.zig");
const router = ozai.router;
const router_dispatch = ozai.router_dispatch;

const Link = link_mod.Link;
const bothUp = link_mod.bothUp;
const link_start = link_mod.start;

const SecretKey = ozai.SecretKey;

/// Fixed seeds, as in `loopback_test.zig`. Two links in this file present the
/// same certificates, so a failure reproduces from its test name alone.
const client_seed: [SecretKey.seed_length]u8 = @splat(0xc1);
const server_seed: [SecretKey.seed_length]u8 = @splat(0x53);

/// How many rounds the handshake may take. Generous, because a round is a few
/// syscalls and nothing here blocks.
const max_rounds = 32;

/// The protocols this file configures. Three, so that "several" is several
/// rather than two, and so that the refusal in the table test names an ALPN
/// that is a near-miss of a real one (`/ozai/blobs`) as well as one that is
/// not (`/nonexistent`): a test that only refuses a wholly unrelated string
/// would pass against a table comparing prefixes.
const blobs_alpn = "/ozai/blobs";
const gossip_alpn = "/ozai/gossip";
const echo_alpn = "/ozai/echo";
const absent_alpn = "/nonexistent";
const near_miss_alpn = "/ozai/blob";

/// A handler that counts the calls it was given, so "this protocol claimed
/// this connection" is an observation rather than an inference from which
/// function pointer was stored.
///
/// `ptr` is borrowed and never dereferenced by the router, so the counters live
/// behind `@ptrCast` and the handler cannot be told apart from any other with
/// the same shape — which is why every assertion below pairs the count with
/// the ALPN that was dispatched.
const Recorder = struct {
    alpn: []const u8,
    accepting_calls: usize = 0,
    accept_calls: usize = 0,
    shutdown_calls: usize = 0,

    fn onAccepting(ptr: *anyopaque, _: router.Accepting) router.AcceptError!router.Connection {
        const self: *Recorder = @ptrCast(@alignCast(ptr));
        self.accepting_calls += 1;
        return .{ .ptr = ptr };
    }

    fn accept(ptr: *anyopaque, _: router.Connection) router.AcceptError!void {
        const self: *Recorder = @ptrCast(@alignCast(ptr));
        self.accept_calls += 1;
    }

    /// The third of the handler's three calls, on the same context as the
    /// other two. A close owes one `shutdown` per registered ALPN, so a
    /// recorder that answered only the first two could not say *which* handler
    /// a close reached — which is the question the replaced registration below
    /// turns on.
    fn shutdown(ptr: *anyopaque) void {
        const self: *Recorder = @ptrCast(@alignCast(ptr));
        self.shutdown_calls += 1;
    }

    fn handler(self: *Recorder) router.ProtocolHandler {
        return .{
            .ptr = @ptrCast(self),
            .on_accepting = onAccepting,
            .accept = accept,
            .shutdown = shutdown,
        };
    }
};

/// What `quietHandler` names as its context. The router hands `ptr` back
/// unchanged and never dereferences it, and both optional calls this handler
/// leaves null are run by the router itself, so nothing ever reads through
/// here. It is a named value rather than a pointer to nothing because
/// `ProtocolHandler` requires a context, and a requirement with nothing behind
/// it would be a hole rather than a discipline.
var quiet_context: u8 = 0;

/// A handler that does nothing, for the one assertion in this file that is
/// about the table and not about a handler being called. Declared beside the
/// ones that count calls because it is the only one never dispatched to, and a
/// handler defined at the bottom of a file reads as an afterthought rather
/// than as a fixture.
fn quietAccept(_: *anyopaque, _: router.Connection) router.AcceptError!void {}

/// `quietAccept` as the router registers a handler, which is what
/// `Builder.accept` takes rather than a bare function pointer.
///
/// Both optional calls are null — upstream's default for each, and the same
/// shape `router.zig`'s own `bare()` fixture registers. The router awaits the
/// handshake itself and owes a shutdown this handler does nothing about, so
/// the test that registers it is asking the table a question rather than
/// watching a handler work.
fn quietHandler() router.ProtocolHandler {
    return .{
        .ptr = @ptrCast(&quiet_context),
        .on_accepting = null,
        .accept = quietAccept,
        .shutdown = null,
    };
}

test "each configured protocol claims its own ALPN, and an unclaimed one earns a refusal" {
    var entries: [3]router.Entry = undefined;
    var blobs: Recorder = .{ .alpn = blobs_alpn };
    var gossip: Recorder = .{ .alpn = gossip_alpn };
    var echo: Recorder = .{ .alpn = echo_alpn };

    var builder = router.Builder.init(&entries);
    _ = try builder.accept(blobs_alpn, blobs.handler());
    _ = try builder.accept(gossip_alpn, gossip.handler());
    _ = try builder.accept(echo_alpn, echo.handler());
    const table = builder.build();

    // Three registrations, three protocols, and three offers — in registration
    // order, because that is the order they go on the wire in and a caller
    // filling a bounded array needs to know which order it will get.
    try t.expectEqual(@as(usize, 3), table.configured());
    try t.expectEqual(@as(usize, 3), table.protocolCount());
    var offered: [4][]const u8 = undefined;
    try t.expectEqual(@as(usize, 3), table.offers(&offered));
    try t.expectEqualStrings(blobs_alpn, offered[0]);
    try t.expectEqualStrings(gossip_alpn, offered[1]);
    try t.expectEqualStrings(echo_alpn, offered[2]);
    // A bounded write into a short array is a count short of the list, not an
    // index panic: `offers` is what fills the transport's own array.
    var narrow: [2][]const u8 = undefined;
    try t.expectEqual(@as(usize, 2), table.offers(&narrow));

    // Each ALPN dispatches to its own registration, by index, and to nobody
    // else's. The index is what a caller addresses a protocol's lifetime by,
    // so it is asserted rather than inferred from the entry pointer.
    const blobs_claim = switch (table.dispatch(blobs_alpn)) {
        .protocol => |claim| claim,
        .refused => return error.BlobProtocolRefused,
    };
    try t.expectEqual(@as(usize, 0), blobs_claim.index);
    try t.expectEqualStrings(blobs_alpn, blobs_claim.entry.alpn);

    const gossip_claim = switch (table.dispatch(gossip_alpn)) {
        .protocol => |claim| claim,
        .refused => return error.GossipProtocolRefused,
    };
    try t.expectEqual(@as(usize, 1), gossip_claim.index);

    const echo_claim = switch (table.dispatch(echo_alpn)) {
        .protocol => |claim| claim,
        .refused => return error.EchoProtocolRefused,
    };
    try t.expectEqual(@as(usize, 2), echo_claim.index);

    // Two refusals, and they are not the same refusal. A wholly unrelated name
    // and a near-miss of a configured one are the two ways a peer can be
    // wrong, and a table that compared ALPN bytes by prefix would claim the
    // near-miss.
    for ([_][]const u8{ absent_alpn, near_miss_alpn }) |asked| {
        const refusal = switch (table.dispatch(asked)) {
            .protocol => return error.NearMissClaimed,
            .refused => |refusal| refusal,
        };
        try t.expectEqualStrings(asked, refusal.alpn);
        // The count of what *is* served is in the refusal, so a caller can say
        // whether the peer named something this endpoint does not serve at all
        // or something it does not serve here.
        try t.expectEqual(@as(usize, 3), refusal.configured);
    }

    // No handler was called: `dispatch` is a lookup and the router runs a
    // handler only when the accept loop steps the connection.
    try t.expectEqual(@as(usize, 0), blobs.accepting_calls);
    try t.expectEqual(@as(usize, 0), gossip.accepting_calls);
    try t.expectEqual(@as(usize, 0), echo.accepting_calls);
}

test "a handler registered twice is one protocol, so a close owes it one shutdown" {
    var entries: [2]router.Entry = undefined;
    var older: Recorder = .{ .alpn = blobs_alpn };
    var newer: Recorder = .{ .alpn = blobs_alpn };

    var builder = router.Builder.init(&entries);
    // The second registration replaces the first rather than adding to the
    // table, so the table grows by one entry and the older handler is
    // unreachable.
    try t.expectEqual(router.Registered.fresh, try builder.accept(blobs_alpn, older.handler()));
    try t.expectEqual(
        router.Registered{ .replaced = 0 },
        try builder.accept(blobs_alpn, newer.handler()),
    );
    const table = builder.build();

    try t.expectEqual(@as(usize, 2), table.configured());
    // Two registrations, one protocol. This is the difference that makes
    // `Shutdown` terminate: a close owed a `handler_finished` per registration
    // would wait for one that a single-protocol endpoint never sends.
    try t.expectEqual(@as(usize, 1), table.protocolCount());

    // The newest registration wins, which is what upstream's `HashMap::insert`
    // leaves behind.
    const claim = switch (table.dispatch(blobs_alpn)) {
        .protocol => |claim| claim,
        .refused => return error.ReplacedProtocolRefused,
    };
    try t.expectEqual(@as(usize, 1), claim.index);

    // And the single `shutdown` a close owes reaches the newer registration
    // and not the one it replaced. The call goes through `claim.entry.handler`
    // — the handler the table holds for this ALPN — with that entry's own
    // context, so what is observed is the table's choice of handler rather
    // than a restatement of which recorder was registered second.
    const reached = claim.entry.handler.shutdown orelse return error.ShutdownNotRegistered;
    reached(claim.entry.handler.ptr);
    try t.expectEqual(@as(usize, 1), newer.shutdown_calls);
    try t.expectEqual(@as(usize, 0), older.shutdown_calls);
}

test "a table with no protocol refuses every ALPN, and says it has none" {
    var entries: [1]router.Entry = undefined;
    var builder = router.Builder.init(&entries);
    const table = builder.build();

    try t.expectEqual(@as(usize, 0), table.configured());
    try t.expectEqual(@as(usize, 0), table.protocolCount());
    // Zero offers out of storage that had room to hold them. `offers` fills a
    // caller-owned list of ALPNs rather than the table's own storage, so the
    // array is the test's to supply — sized to the one entry this table was
    // built with, which an empty table fills none of.
    var offered: [entries.len][]const u8 = undefined;
    try t.expectEqual(@as(usize, 0), table.offers(&offered));

    // Zero configured is a real answer rather than an empty one: an endpoint
    // with no protocol serves nothing, and this is the `endpoint.Loop.init`
    // configuration rather than a failure.
    const refusal = switch (table.dispatch(echo_alpn)) {
        .protocol => return error.UnconfiguredProtocolClaimed,
        .refused => |refusal| refusal,
    };
    try t.expectEqualStrings(echo_alpn, refusal.alpn);
    try t.expectEqual(@as(usize, 0), refusal.configured);
}

test "the router drops an ALPN it does not hold, and tells the peer nothing" {
    var entries: [2]router.Entry = undefined;
    var blobs: Recorder = .{ .alpn = blobs_alpn };
    var gossip: Recorder = .{ .alpn = gossip_alpn };

    var builder = router.Builder.init(&entries);
    _ = try builder.accept(blobs_alpn, blobs.handler());
    _ = try builder.accept(gossip_alpn, gossip.handler());
    const table = builder.build();

    // The offered protocol reaches the handler registered for it, and the
    // router owes that handler the handshake it declared.
    const served = router_dispatch.dispatchStep(&table, .negotiating, .{
        .outcome = .{ .alpn = gossip_alpn },
    });
    try t.expectEqual(router.ConnState{ .accepting = gossip.handler() }, served.state);
    try t.expectEqual(router.DispatchAction{ .on_accepting = gossip.handler() }, served.action);

    // A protocol no registration holds is a drop, and `PeerOutcome.nothing` is
    // what says the peer was told nothing: upstream warns and returns
    // (`protocol.rs:653-656`).
    const refused = router_dispatch.dispatchStep(&table, .negotiating, .{
        .outcome = .{ .alpn = absent_alpn },
    });
    const refusal: router.Refusal = .{ .alpn = absent_alpn, .configured = 2 };
    try t.expectEqual(router.ConnState{ .dropped = .{ .refused_protocol = refusal } }, refused.state);
    try t.expectEqual(router.DispatchAction{ .drop = .{ .refused_protocol = refusal } }, refused.action);
    try t.expectEqual(router.PeerOutcome.nothing, refused.action.peerOutcome());

    // Neither handler was called, and the one that was not the offered protocol
    // was not called either — a drop is not a misroute.
    try t.expectEqual(@as(usize, 0), gossip.accepting_calls);
    try t.expectEqual(@as(usize, 0), blobs.accepting_calls);

    // And the served one goes all the way: the handler `accept` names is the
    // one registered for that ALPN and not its neighbour. Dispatching to the
    // right *state* is not the same claim as dispatching to the right
    // *handler*, and with several protocols configured only the second one says
    // the table is really keyed by protocol name.
    const connected = router_dispatch.dispatchStep(&table, served.state, .{
        .outcome = .{ .connection = .{ .ptr = &entries } },
    });
    try t.expectEqual(router.ConnState{ .handling = gossip.handler() }, connected.state);
    try t.expectEqual(router.DispatchAction{ .accept = gossip.handler() }, connected.action);

    // Running it is what calls the handler, and only the one that was dispatched.
    try gossip.handler().accept(@ptrCast(&gossip), .{ .ptr = &entries });
    try t.expectEqual(@as(usize, 1), gossip.accept_calls);
    try t.expectEqual(@as(usize, 0), blobs.accept_calls);
}

test "a dial offering a protocol the peer does not speak never establishes" {
    var client_secret = try SecretKey.fromSeed(client_seed);
    defer client_secret.deinit();
    var server_secret = try SecretKey.fromSeed(server_seed);
    defer server_secret.deinit();

    var link: Link = undefined;
    // The server speaks `blobs_alpn`; the dialer offers `absent_alpn`. Both
    // ends are otherwise identical to the handshake test in
    // `loopback_test.zig`, so the only thing that differs is the ALPN.
    try link.init(client_secret, server_secret, server_secret.nodeId(), 7, .{
        .server_alpns = &.{blobs_alpn},
        .dial_alpns = &.{absent_alpn},
    });
    defer link.deinit();

    // Keep the original round/time bound: refusal may leave managed entries
    // draining for three PTOs, but neither endpoint may ever establish.
    // exchange ends with the client's receive, before its next tick; inspect
    // that fresh table entry, never the borrowed dialled handle after driving.
    const dialled_id = link.dialled.id();
    var round: usize = 0;
    var handshake_observed = false;
    var refusal_observed = false;
    while (round < max_rounds) : (round += 1) {
        _ = try link.exchange(link_start);
        try t.expect(link.client.live() == null);
        try t.expect(link.server.live() == null);
        var index: usize = 0;
        while (link.client.bridge.connectionAt(index)) |conn| : (index += 1) {
            if (conn.id() != dialled_id) continue;
            if (conn.entry.conn.isDraining()) {
                const closed = conn.entry.conn.local_err orelse return error.PeerCloseMissing;
                try t.expect(!closed.is_app);
                try t.expectEqual(@as(u64, 0x100 + 120), closed.code);
                refusal_observed = true;
            }
            const hs = conn.entry.conn.tls13_hs orelse continue;
            // The refused end holds no negotiated protocol, and that is the
            // part with teeth. `negotiatedAlpn` falls back to "the config's
            // first entry" when nothing was selected, so a test that only
            // compared it against the *dialer's* configured ALPN would see
            // the fallback and call it a negotiation. The selected length is
            // what says a protocol was chosen, and on this dialer nothing
            // ever is: the server refuses in the ClientHello, so no
            // EncryptedExtensions arrives to name one.
            try t.expectEqual(@as(usize, 0), hs.selected_alpn_len);
            handshake_observed = true;
        }
    }
    try t.expect(handshake_observed);
    // A wire-decoded transport close proves refusal, rather than a silent
    // handshake stall or an application hangup after successful negotiation.
    try t.expect(refusal_observed);
    try t.expect(link.client.live() == null);
    try t.expect(link.server.live() == null);

    // And the two halves of this file do not overlap: the router would have
    // dropped this ALPN too, but it was never asked, because the handshake
    // refused the protocol before an established connection could dispatch.
    // The table half is asserted separately, over `dispatchStep`.
    var entries: [1]router.Entry = undefined;
    const served_alpn = blobs_alpn;
    var builder = router.Builder.init(&entries);
    _ = try builder.accept(served_alpn, quietHandler());
    const table = builder.build();
    try t.expectEqual(
        router.Refusal{ .alpn = absent_alpn, .configured = 1 },
        switch (table.dispatch(absent_alpn)) {
            .protocol => return error.AbsentProtocolClaimed,
            .refused => |refusal| refusal,
        },
    );
}

test "a dial for a protocol the peer does speak establishes and negotiates exactly it" {
    var client_secret = try SecretKey.fromSeed(client_seed);
    defer client_secret.deinit();
    var server_secret = try SecretKey.fromSeed(server_seed);
    defer server_secret.deinit();

    var link: Link = undefined;
    // The negative space for the test above, on the same two sockets and the
    // same loop: the server speaks `blobs_alpn`, the dialer offers the same
    // name, and the only difference is one string.
    try link.init(client_secret, server_secret, server_secret.nodeId(), 8, .{
        .server_alpns = &.{blobs_alpn},
        .dial_alpns = &.{blobs_alpn},
    });
    defer link.deinit();

    try link.drive(link_start, max_rounds, bothUp);

    // Both ends agree on the protocol, and both agree it is the configured one
    // rather than a prefix or a fallback: a server offering one protocol has
    // nothing else it could have selected, so the value that would catch a
    // broken negotiation is the *dialer's* — it offered a list and the server
    // picked from it.
    const client = link.client.live().?;
    const server = link.server.live().?;
    try t.expectEqualStrings(blobs_alpn, client.entry.conn.negotiatedAlpn());
    try t.expectEqualStrings(blobs_alpn, server.entry.conn.negotiatedAlpn());

    // The selection is a selection, not the config's fallback: a real match
    // records its length in the handshake.
    try t.expectEqual(blobs_alpn.len, client.entry.conn.tls13_hs.?.selected_alpn_len);
    try t.expectEqual(blobs_alpn.len, server.entry.conn.tls13_hs.?.selected_alpn_len);
}

test "a server offering several protocols takes the one the peer named, not the first it has" {
    var client_secret = try SecretKey.fromSeed(client_seed);
    defer client_secret.deinit();
    var server_secret = try SecretKey.fromSeed(server_seed);
    defer server_secret.deinit();

    var link: Link = undefined;
    // The server offers two protocols and the dialer names only the *second*.
    // This is the claim every test above this one could not make: with one
    // protocol per side there is nothing to choose between, so a server that
    // ignored the peer's list and picked its own first entry would pass all of
    // them.
    try link.init(client_secret, server_secret, server_secret.nodeId(), 9, .{
        .server_alpns = &.{ blobs_alpn, gossip_alpn },
        .dial_alpns = &.{gossip_alpn},
    });
    defer link.deinit();

    try link.drive(link_start, max_rounds, bothUp);

    const client = link.client.live().?;
    const server = link.server.live().?;
    // The peer's list leaves the server one candidate, and this assertion is
    // what would catch a server that answered its own first entry anyway: the
    // server's list leads with `blobs_alpn`, which the dialer never named, so
    // naming it would be selecting a protocol the peer did not offer, which
    // RFC 7301 §3.2 forbids: the server's selection is one the client
    // advertised, and it is what both ends then treat as the negotiated one.
    try t.expectEqualStrings(gossip_alpn, client.entry.conn.negotiatedAlpn());
    try t.expectEqualStrings(gossip_alpn, server.entry.conn.negotiatedAlpn());

    // Both ends hold the *same* bytes, at the same length, and neither is
    // holding its own first entry or the config fallback.
    try t.expectEqual(gossip_alpn.len, client.entry.conn.tls13_hs.?.selected_alpn_len);
    try t.expectEqual(gossip_alpn.len, server.entry.conn.tls13_hs.?.selected_alpn_len);
    try t.expect(!std.mem.eql(u8, client.entry.conn.negotiatedAlpn(), blobs_alpn));
}

test "a server taking the peer's protocol still prefers its own when both are offered" {
    var client_secret = try SecretKey.fromSeed(client_seed);
    defer client_secret.deinit();
    var server_secret = try SecretKey.fromSeed(server_seed);
    defer server_secret.deinit();

    var link: Link = undefined;
    // Both ends offer both protocols, in opposite orders. RFC 7301 §3.2: the
    // server "SHOULD select the most highly preferred protocol that it
    // supports and that is also advertised by the client", so the selection
    // runs over the server's own list and the dialer's order does not decide
    // it. The server's first entry wins here even though the dialer listed the
    // other one first — and this is the test that fails if either side is
    // consulted in the wrong order.
    try link.init(client_secret, server_secret, server_secret.nodeId(), 10, .{
        .client_alpns = &.{ gossip_alpn, blobs_alpn },
        .server_alpns = &.{ blobs_alpn, gossip_alpn },
    });
    defer link.deinit();

    try link.drive(link_start, max_rounds, bothUp);

    const client = link.client.live().?;
    const server = link.server.live().?;
    try t.expectEqualStrings(blobs_alpn, client.entry.conn.negotiatedAlpn());
    try t.expectEqualStrings(blobs_alpn, server.entry.conn.negotiatedAlpn());
}
