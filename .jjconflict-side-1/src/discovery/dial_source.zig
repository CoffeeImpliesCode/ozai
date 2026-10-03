//! Ask every address lookup this node is configured with, and dial what the
//! network said.
//!
//! This is the fan-in `discovery/resolve.zig`'s module doc names as the one
//! thing deliberately absent: upstream's `AddressLookupServices`
//! (`iroh/src/address_lookup.rs:565`), a list of services and a merge over
//! whatever they answer. The list is a `[]const resolve.AddressLookup` here,
//! and the merge is `item.merge` and `item.winner` — both built and tested in
//! `discovery/item.zig` before anything ran them. What was missing was the
//! thing that *runs* them and hands the answer to `transport/dial.zig`, and
//! that is this file.
//!
//! # The order is the whole of the answer
//!
//! Every source that will answer is asked, every answer is merged, and the
//! winner under `item.Item.order` is the one that is dialled. Two
//! consequences, and neither is a detail:
//!
//! * The order the caller listed its sources in is not consulted. The *set*
//!   decides, which is what `docs/PLAN.md` M5's "a total order or zones flap"
//!   asks for; a second comparator here would be a second answer to a
//!   question `item.zig` has already answered, and the two would disagree the
//!   first time a service reported a stale address.
//! * No source is skipped because an earlier one produced a usable address.
//!   A walk that stopped at the first answer would make the dial depend on
//!   the order the configuration happens to be written in, which is a
//!   configuration detail wearing the clothes of a preference.
//!
//! # Four answers, and none of them is another one
//!
//! `item.Resolution` keeps "cannot resolve at all" and "resolved to nothing"
//! apart, and `docs/ARCHITECTURE.md` invariant 13 says they must not be
//! confused. That distinction has to survive the merge, so it is a property
//! of the run and not only of one service's answer:
//!
//! * A service that answers `null` **stops the walk**. It has said it will
//!   not answer for this node at all — `resolve.AddressLookup.refuse_resolve`,
//!   which `PkarrPublisher` takes, so this is upstream's production case and
//!   not a shape invented here. That is a claim about what this configuration
//!   can do, and walking past it to report an absence no service claimed is
//!   the defect the milestone exists to prevent. The only way to prevent it
//!   is to end the run where the claim was made.
//! * A service that answered and had nothing to say **does not stop it**. The
//!   next source is asked, and the run ends on `.nothing` only once every
//!   source that could answer has had nothing. `PkarrResolver` over an empty
//!   answer set is that, and it is a fact about the world.
//! * A source that named the node and gave no path to it is `.no_address`.
//!   `DnsAddressLookup` over an answer set with no records produces exactly
//!   this: one item, the node, no addresses — `discovery/dns.zig`'s own "an
//!   empty answer is a node that published nothing". The node exists and
//!   there is nowhere to send a packet, which is a third fact and not an
//!   absence of one.
//! * A connection is open is `.dialed`, and it names the service the winning
//!   item came from, because a dial that cannot be traced to a service is a
//!   dial nobody can blame for a wrong address.
//!
//! # Every stream this run starts, it closes
//!
//! Invariant 13 is a rule about callers remembering to `deinit`. A caller of
//! this function has nothing to remember, because it never holds a stream:
//! the one `defer` in `dialFromSources` closes every stream the walk
//! started — on the success path, on the refusal that ends it early, on the
//! error that escapes, and on the winner that turns out to carry no path. So
//! a run that finds an address and dials it has also stopped the retrievals
//! behind the other services, which is what keeps a resolve that has already
//! been answered from leaving a relay query in flight.
//!
//! The consequence is a lifetime: the items are the streams' own, so they are
//! dead when this function returns, and `Dialed` holds a `dial.Dial` that
//! owns everything it points at. The `Route` a dialled connection carries
//! holds its relay URL by value and its custom address' bytes in the map's own
//! key, so nothing in the result is a slice into an arena this function
//! emptied. That is invariant 6 read from the other end.
//!
//! # The seam: the retrieval, and what it costs that the type does not say
//!
//! `discovery/resolve.zig` takes its answers as a parameter and never fetches
//! one, and neither does this file. Everything a real lookup needs that the
//! type does not say is in that one gap, and it is all I/O this milestone
//! does not build:
//!
//! * a query written to a socket and the answer read back, so a `std.Io`, a
//!   write buffer and a deadline — a pkarr query is a signed packet of the
//!   layout `docs/PLAN.md` M3 gives, posted to a relay, and a DNS lookup
//!   builds a query for `_iroh.<z32>.<origin>` (`iroh-dns/src/dns.rs:1062`)
//!   and waits on a transaction id;
//! * an abort handle for that wait, which is `resolve.Cancellation` and the
//!   only reason a stream here can be told to stop;
//! * entropy for what a lookup signs or numbers with, the way a dial draws
//!   one (`transport/dial.zig`);
//! * a copy of the answer set, because the buffer an `Io` read fills does not
//!   outlive the call and a service holds its answers as values.
//!
//! Those four are what a real `resolve.PacketSource` and a real
//! `dns.DnsAddressLookup` are built with, and this milestone does not build
//! them: a relay client, a UDP socket and a DNS transaction manager are
//! transport work, and `transport/socket.zig` is the seam they come through.
//! Until they exist the answers are the caller's, and this file cannot tell
//! the difference — which is the whole point of handing them in as values.
//!
//! # What is not on this path
//!
//! No clock, no spawn, and no `std.Io` at all, for the reason
//! `transport/dial.zig`'s module doc gives: a parameter with no work is a
//! parameter a caller has to thread for a fiction. The instant the dial
//! happens at is `Request.at`, and a test drives a whole resolve at a
//! constant one with no runtime stood up and no socket opened.
//!
//! The instant is deliberately *not* stamped onto the items. Both services
//! publish `last_updated` as null — upstream passes `None` to
//! `AddressLookupItem::new` on both, as `discovery/resolve.zig` records — and a
//! stamp invented here would be the same value on every item, which is a key
//! that orders nothing while looking like freshness. `item.Item.order` falls
//! through to the encoded address, and this file does not touch it.

const std = @import("std");
const addr = @import("../base/addr.zig");
const item = @import("item.zig");
const resolve = @import("resolve.zig");
const addr_map = @import("../transport/addr_map.zig");
const dial = @import("../transport/dial.zig");

/// What this file refuses.
///
/// Both vocabularies whole rather than restated, for `transport/dial.zig`'s
/// reason: a second copy of a set is a list that goes stale when the file it
/// came from grows an arm. A run that resolves nothing and dials nothing
/// refuses nothing, and a run that dialled a refused connection gives back
/// exactly what the dial gave back.
pub const Error = resolve.ResolveError || dial.Error;

/// One run's inputs, as a value.
///
/// The run needs six of them and a positional list that long is a list
/// nothing distinguishes, so they are named here once. `at` and `random` are
/// the caller's for the reason the module doc gives.
///
/// Nothing here is copied and nothing here is owned except what the run puts
/// into `map`: `map` is written to and has to outlive the `Outcome`, and the
/// `Selector` is called into, so both have to outlive the call.
pub const Request = struct {
    /// The node being dialled: what every source is asked about, the pin the
    /// connection carries, and the node half of every synthetic map key.
    node_id: addr.NodeId,
    /// The address the caller's own socket is bound to, which the peer will
    /// see and which only the caller knows.
    local: addr.SocketAddr,
    /// Where a synthetic address is allocated from and looked up in. The one
    /// target an address is turned into an address by.
    map: *addr_map.MappedAddrs,
    /// Which of the winner's addresses this node is willing to dial.
    select: Selector,
    /// The instant to dial at.
    at: dial.Instant,
    /// The generator the dial draws its transport nonces and host bits from.
    random: std.Random,
};

/// Which of a winning item's addresses this node dials.
///
/// A vtable, for `resolve.AddressLookup`'s reason: the policy is the caller's
/// and a switch in this file would be a second opinion about paths written by
/// a module whose module doc says the caller owns it — one target is one
/// connection, and a peer reachable over a relay and over a direct address is
/// two dials.
///
/// Two dials rather than one dial carrying two paths, and the second half of
/// that is measured rather than assumed: the core holds two `NetworkPath`s and
/// indexes one as active (`transport/dial.zig`), and driving `Connection`
/// directly over two hand-built addresses on 2026-10-01 found the second one
/// *replaces* the first — the active index flips and the old address goes dark
/// rather than carrying anything beside it. So a winner's other addresses are
/// not spare capacity for this dial; they are the next one, and a policy that
/// wants them runs this again. The measurement left no artefact, so its numbers
/// are in that worker's report rather than in the tree.
///
/// The choice is made before the dial because it cannot be made after. The core
/// never discovers an address that has not spoken: only a 1-RTT packet, after
/// the handshake is confirmed, carrying at least one non-probing frame starts a
/// migration (`connection.zig:1540`), so padding, a PATH_CHALLENGE, a
/// PATH_RESPONSE or a NEW_CONNECTION_ID from an address the connection has
/// never heard of does not reach the migration check at all. The candidate slot is
/// never filled for a silent address, and an address that has spoken costs a
/// migration on every change, with the congestion window thrown away each
/// time. Nothing in a winner's address list can therefore be called cheap or
/// expensive in advance, and a connection left to try both is already
/// oscillating rather than carrying twice the load. Pick once, dial once, run
/// again for the rest.
pub const Selector = struct {
    /// The policy's own value, borrowed and reached by `pick`. It has to stay
    /// alive for the whole run, which reaches it exactly once.
    ctx: *anyopaque,
    /// The one address to dial, or null when this node will take none of them.
    ///
    /// Handed a list that is never empty: a winner with no address is settled
    /// before the policy is asked, because there is nothing in it to choose
    /// from. `addr.TransportAddr.order` is the caller's to sort with.
    ///
    /// Called once per run, synchronously, on the thread that called
    /// `dialFromSources` and before anything is dialled. `endpoint` points at
    /// the winning item, which belongs to a stream this call closes before it
    /// returns: the pointer and every slice read out of it are good for this
    /// call and not after it, and an address to keep is one to copy here.
    /// Nothing reenters the run from this callback.
    pick: *const fn (ctx: *anyopaque, endpoint: *const addr.NodeAddr) ?addr.TransportAddr,
};

/// What a run of the sources came to.
///
/// The result and the failure are separate fields because they are separate
/// facts: a source that answered with a packet that would not decode has still
/// been asked, whatever the run went on to do, and a run that dialled after one
/// is not the same run as one that did not.
pub const Outcome = struct {
    /// Which of the four answers this was.
    result: Result,
    /// The first answer that was not an item, or null when every answer was
    /// one. The first, because the sources are asked in order and a stream's
    /// answers come in packet order, so this is a value and not a sample; it
    /// is not a summary and a second failure does not overwrite it.
    first_failure: ?resolve.Failure,
};

/// The four answers. `docs/ARCHITECTURE.md` invariant 13 is why the first two
/// are different arms; the module doc is why the third is.
pub const Result = union(enum) {
    /// A service will not resolve for this node at all, so the walk stopped
    /// there: no later source was asked and nothing looked for past it.
    cannot_resolve,
    /// Every source that could answer was asked and every one had nothing to
    /// say. Not the same as a service declining to answer, which is the arm
    /// above.
    nothing,
    /// A winner was found and there is no path to it: the item carries no
    /// address, or the caller's policy took none of the ones it carries.
    no_address,
    /// A connection is open to the address the merge chose.
    dialed: Dialed,
};

/// The connection a run opened, and where its address came from.
pub const Dialed = struct {
    /// Owned by the caller's bridge, which drives it with the same `recv`,
    /// `tick` and `sweep` an accepted connection is driven by. It outlives
    /// this run and borrows nothing from it.
    dial: dial.Dial,
    /// The service the winning item came from, which is a fact about how the
    /// address was learned and the only thing that makes a wrong address
    /// traceable.
    provenance: item.Provenance,
};

/// Ask every source, merge what they answered, and dial the winner.
///
/// `alloc` may be an arena: every allocation this function makes is the list
/// of items, the list of streams and `item.merge`'s output, and all three die
/// before it returns. The items themselves are the streams' own, allocated
/// when the streams were started.
///
/// `sources` are borrowed for the length of the call, in the order they are
/// asked; the order decides which refusal stops the walk first and which
/// failure is reported first, and nothing else.
///
/// The dialer is borrowed for one call. A run that resolves to nothing never
/// touches it, and one that dials hands back a connection the dialer's bridge
/// owns.
///
/// Every path out closes every stream the walk started and tells the retrieval
/// behind each one to stop, including the paths that end in an `Outcome` and
/// the path that returns an error. So an error here leaves nothing running and
/// nothing for the caller to release but the `Outcome`, and the items the run
/// read are already gone by the time it returns — which is why no field of
/// `Outcome` borrows them.
pub fn dialFromSources(
    alloc: std.mem.Allocator,
    sources: []const resolve.AddressLookup,
    dialer: *dial.Dialer,
    request: Request,
) Error!Outcome {
    // Every stream the walk starts, and the one `defer` that closes them all.
    // This is the module doc's cancellation rule in one place: the walk can
    // leave on the success path, on a refusal, on an error, or on a winner
    // with no path, and on all four the streams that were started are closed
    // and the retrievals behind them told to stop.
    var open: std.ArrayList(resolve.Stream) = .empty;
    defer {
        for (open.items) |*stream| stream.deinit();
        open.deinit(alloc);
    }

    // The items of every stream, side by side, because `item.merge` is handed
    // one set. They are borrows: each stream's own arena owns its own, and
    // the streams are still open because the winner is read after the last
    // source has been asked and dialled before they are closed.
    var found: std.ArrayList(item.Item) = .empty;
    defer found.deinit(alloc);
    var first_failure: ?resolve.Failure = null;

    for (sources) |source| {
        // Before the service is asked rather than after it answered: a stream
        // can only be cancelled through the handle that started it, so the
        // room for that handle has to exist before the handle does.
        try open.ensureUnusedCapacity(alloc, 1);
        const started = (try source.resolve(alloc, request.node_id)) orelse
            return .{
                .result = .cannot_resolve,
                .first_failure = first_failure,
            };
        // From here the stream is in the list above, and every path out of
        // this function closes it. `addOneAssumeCapacity` cannot fail and
        // `ensureUnusedCapacity` above is the only fallible step left, and it
        // hands back the slot it filled, so the walk drives the stream it just
        // appended. Naming that slot `items.len - 1` is a claim about the list
        // that only the append makes true; taking the pointer the append hands
        // back is a claim the append makes itself.
        const stream: *resolve.Stream = open.addOneAssumeCapacity();
        stream.* = started;

        // Driven to the end whatever is in it. A failure is recorded and the
        // walk carries on, which is `discovery/resolve.zig`'s own rule read
        // from above: one answer that is not an item must not hide the answers
        // of the sources still to come.
        while (stream.next()) |event| switch (event) {
            .item => {},
            .failed => |failure| if (first_failure == null) {
                first_failure = failure;
            },
        };
        // Read before `deinit` and owned by the arena `deinit` empties, which
        // is `resolve.Stream`'s contract and the reason nothing here closes a
        // stream at the end of an iteration.
        switch (stream.finish()) {
            .cannot_resolve => return .{
                .result = .cannot_resolve,
                .first_failure = first_failure,
            },
            .resolved => |items| for (items) |value| try found.append(alloc, value),
        }
    }

    // The one merge, from the one place that knows how items compare. Sorted
    // and deduplicated, so two services reporting one address is agreement
    // rather than a conflict, and so the answer does not depend on which
    // source spoke first.
    const merged = try item.merge(alloc, found.items);
    defer alloc.free(merged);
    // `item.winner`, and not `merged[0]`. `merge` documents that its output
    // reads best-first, and reading index zero is a second statement of that
    // which stops holding the moment the sort direction does. One place asks
    // which of two results wins; this is that caller.
    const best = item.winner(merged) orelse return .{
        .result = .nothing,
        .first_failure = first_failure,
    };
    // A winner with no address is not a service that resolved to nothing, and
    // either way there is no path to dial, so the policy is not asked about a
    // list it cannot choose from.
    const target: ?addr.TransportAddr = if (best.endpoint.addrs.len == 0)
        null
    else
        request.select.pick(request.select.ctx, &best.endpoint);
    if (target == null) return .{
        .result = .no_address,
        .first_failure = first_failure,
    };

    // Pinned and keyed on the node that was asked about rather than on the one
    // the winner carries. They are the same value — a service only ever
    // produces an item for the node it was handed, and `resolve` reports
    // `UnexpectedSigner` for a pkarr answer about anybody else — and the id
    // that was asked about is the one the caller meant to reach.
    const opened = try dialer.dial(
        target.?,
        request.node_id,
        request.local,
        request.map,
        request.at,
        request.random,
    );
    return .{
        .result = .{ .dialed = .{
            .dial = opened,
            .provenance = best.provenance,
        } },
        .first_failure = first_failure,
    };
}

const t = std.testing;
const key = @import("../base/key.zig");
const ula = @import("../base/ula.zig");
const dns = @import("dns.zig");
const batch = @import("../transport/batch.zig");
const quic_bridge = @import("../transport/quic_bridge.zig");
const quic = @import("quic");

/// Fixed seeds, so a run draws the same connection ids, the same nonces and
/// the same synthetic host bits every time.
const client_seed: [key.SecretKey.seed_length]u8 = @splat(0xc1);
const server_seed: [key.SecretKey.seed_length]u8 = @splat(0x53);

/// The one ALPN both ends speak.
const alpn = "ozai";

/// Where virtual time starts: a second past zero, so every deadline a core
/// computes is a plain offset. It is a constant, and a run is driven entirely
/// at it, which is what `docs/DECISIONS/0002` bought.
const at_instant: dial.Instant = 1_000 * std.time.ns_per_s;

/// A seeded generator's engine. `std.Random` is an interface over a pointer to
/// an engine, so the engine outlives every value handed out from it.
const Prng = std.Random.DefaultPrng;

/// The largest datagram a socket read is expected to hold.
const max_datagram = 1500;

/// How many socket writes one drain may hand back before the room is too small.
const max_egress = 32;

/// The address this node's socket is bound to, so the address the peer sees
/// the dialled connection come from. A direct one, which is why the receiving
/// end needs no map entry to attribute it.
const local_addr: addr.SocketAddr = .{ .ip = .{ .v4 = .{ 127, 0, 0, 1 } }, .port = 40001 };

/// Two bridges, one dialer and the map they share: the smallest thing a run
/// can be observed against.
///
/// One map for both ends, as `transport/dial.zig`'s own harness does it, so a
/// synthetic address the dialler allocated is one the receiving end can name.
/// The rest is duplicated rather than borrowed because that harness is private
/// to a file this milestone does not change.
const Harness = struct {
    client: *quic_bridge.Bridge,
    server: *quic_bridge.Bridge,
    dialer: *dial.Dialer,
    map: addr_map.MappedAddrs,
    client_secret: key.SecretKey,
    server_secret: key.SecretKey,

    fn init(self: *Harness, engine: *Prng) !void {
        self.* = .{
            .client = undefined,
            .server = undefined,
            .dialer = undefined,
            .map = addr_map.MappedAddrs.init(),
            .client_secret = try key.SecretKey.fromSeed(client_seed),
            .server_secret = try key.SecretKey.fromSeed(server_seed),
        };
        errdefer self.client_secret.deinit();
        errdefer self.server_secret.deinit();
        errdefer self.map.deinit(t.allocator);
        // The server pins the client, so a handshake this run opens is
        // verified against a peer that exists rather than against nothing.
        self.client = try quic_bridge.Bridge.create(t.allocator, t.io, .{
            .secret = self.client_secret,
            .expect_peer = null,
            .alpn = alpn,
        }, engine.random());
        errdefer self.client.destroy();
        self.server = try quic_bridge.Bridge.create(t.allocator, t.io, .{
            .secret = self.server_secret,
            .expect_peer = self.client_secret.nodeId(),
            .alpn = alpn,
        }, engine.random());
        errdefer self.server.destroy();
        self.dialer = try dial.Dialer.create(t.allocator, self.client, .{
            .secret = self.client_secret,
            .alpn = alpn,
        });
    }

    /// Take every dialled connection out of the table and free it, then the
    /// dialer, then the bridges.
    ///
    /// `Dialer.destroy` refuses while a connection it opened is still in the
    /// table. The walk below takes every client entry out of it first, so a
    /// refusal is not a path this expects — but that is a claim about a live
    /// table rather than about a constant, and a table that disagreed would
    /// leave the dialer's seed, chain and ALPN freed under a connection still
    /// reading them. `defer` has nowhere to send an error and `deinit` has no
    /// caller that could act, so the refusal is named here: a teardown that
    /// carried on would report success over a dialer freed too early.
    fn deinit(self: *Harness) void {
        // Backwards: `removeConnection` swap-removes from the list being
        // walked, so a forward walk skips an entry and leaves a freed one in
        // the table for `Dialer.destroy` to refuse.
        var index = self.client.manager.entries.items.len;
        while (index > 0) {
            index -= 1;
            const entry = self.client.manager.entries.items[index];
            if (!entry.conn.is_server) self.client.manager.removeConnection(entry);
        }
        self.client.sweep();
        self.dialer.destroy() catch |err| switch (err) {
            error.DialedConnectionsLive => std.debug.panic(
                "a dialled connection outlived the dialer that opened it",
                .{},
            ),
        };
        self.client.destroy();
        self.server.destroy();
        self.map.deinit(t.allocator);
        self.client_secret.deinit();
        self.server_secret.deinit();
        // Invalid rather than merely freed. The harness is a test's whole
        // world, and a second teardown over bridges that are already gone
        // would be a use-after-free reported as a mystery rather than as the
        // mistake it is. `secureZero` above has already run, so this erases
        // nothing it was there to erase.
        self.* = undefined;
    }
};

/// A run's request, with the policy this test does not care about: the first
/// address of a sorted list, which is a choice and not a rule.
fn requestAt(harness: *Harness, engine: *Prng) Request {
    return .{
        .node_id = harness.server_secret.nodeId(),
        .local = local_addr,
        .map = &harness.map,
        // The harness outlives the call and the policy reads none of it, so it
        // is the one pointer there is always in hand.
        .select = .{ .ctx = @ptrCast(@alignCast(harness)), .pick = firstAddress },
        .at = at_instant,
        .random = engine.random(),
    };
}

fn firstAddress(_: *anyopaque, endpoint: *const addr.NodeAddr) ?addr.TransportAddr {
    return if (endpoint.addrs.len == 0) null else endpoint.addrs[0];
}

/// The retrieval `discovery/resolve.zig` deliberately does not build, as a
/// value: signed-packet bytes in, a `Packet` out.
///
/// `answers` is NUL-separated because each answer is a whole signed packet,
/// which is `resolve.PacketSource`'s own contract and the reason the two
/// services can share a buffer shape.
const FakeRelay = struct {
    answers: []const u8,
    packets: []const resolve.Packet,
    /// Which answer is being decoded, so a second resolve against one relay
    /// walks the same answer set from its start the way a fresh retrieval
    /// would.
    cursor: usize = 0,
    /// The only bytes this relay knows. Anything else is a malformed packet,
    /// which is how a decode failure is reached.
    good: []const u8 = "signed",

    fn decode(ctx: *anyopaque, packet: []const u8) resolve.DecodeError!resolve.Packet {
        const self: *FakeRelay = @ptrCast(@alignCast(ctx));
        if (!std.mem.eql(u8, packet, self.good)) return error.MalformedPacket;
        const at = self.cursor;
        self.cursor += 1;
        if (at >= self.packets.len) return error.MalformedPacket;
        return self.packets[at];
    }

    fn source(self: *FakeRelay, cancellation: ?resolve.Cancellation) resolve.PacketSource {
        return .{
            .ctx = @ptrCast(@alignCast(self)),
            .decode = decode,
            .answers = .init(self.answers),
            .cancellation = cancellation,
        };
    }
};

/// A retrieval handle that only counts, which is the whole of what a test can
/// observe about a cancellation. The count lives outside the service on
/// purpose: a service that counted its own stops would be asserting that it
/// asked itself to stop.
const Counter = struct {
    stops: u32 = 0,

    fn stop(ctx: *anyopaque) void {
        const self: *Counter = @ptrCast(@alignCast(ctx));
        self.stops += 1;
    }

    fn cancellation(self: *Counter) resolve.Cancellation {
        return .{ .ctx = @ptrCast(@alignCast(self)), .stop = stop };
    }
};

/// A service with a counter in front of it, so "was this one asked" is
/// something a test reads rather than something it infers from what came back.
const Counted = struct {
    inner: resolve.AddressLookup,
    asked: u32 = 0,
    vtable: resolve.AddressLookup.VTable = counted_vtable,

    fn init(inner: resolve.AddressLookup) Counted {
        return .{ .inner = inner };
    }

    fn lookup(self: *Counted) resolve.AddressLookup {
        return .{ .vtable = &self.vtable, .ctx = @ptrCast(@alignCast(self)) };
    }
};

const counted_vtable: resolve.AddressLookup.VTable = .{
    .publish = resolve.AddressLookup.ignore_publish,
    .resolve = countedResolve,
};

fn countedResolve(
    ctx: *anyopaque,
    // The order is `AddressLookup.VTable.resolve`'s own, and a vtable entry's
    // signature is the interface's to fix: moving the allocator first would
    // change the type every service in the tree implements.
    // ziglint-ignore: Z023
    alloc: std.mem.Allocator,
    node_id: addr.NodeId,
) resolve.ResolveError!?resolve.Stream {
    const self: *Counted = @ptrCast(@alignCast(ctx));
    self.asked += 1;
    return self.inner.resolve(alloc, node_id);
}

/// A service whose work never starts. `resolve.ResolveError` has one arm, and
/// this is how a caller meets it: a real service's `OutOfMemory` arrives
/// exactly this way, with the sources before it already holding streams.
const Unstartable = struct {
    asked: u32 = 0,
    vtable: resolve.AddressLookup.VTable,

    fn init() Unstartable {
        var self: Unstartable = .{ .asked = 0, .vtable = undefined };
        self.vtable = .{
            .publish = resolve.AddressLookup.ignore_publish,
            .resolve = refuseStart,
        };
        return self;
    }

    fn lookup(self: *Unstartable) resolve.AddressLookup {
        return .{ .vtable = &self.vtable, .ctx = @ptrCast(@alignCast(self)) };
    }
};

fn refuseStart(
    ctx: *anyopaque,
    // `AddressLookup.VTable.resolve`'s parameter order, for the reason
    // `countedResolve` above gives. Only the answer is this file's.
    // ziglint-ignore: Z023
    _: std.mem.Allocator,
    _: addr.NodeId,
) resolve.ResolveError!?resolve.Stream {
    const self: *Unstartable = @ptrCast(@alignCast(ctx));
    self.asked += 1;
    return error.OutOfMemory;
}

/// Hand one round of a connection's datagrams to a bridge and say whether it
/// produced any.
///
/// No socket is opened and none is needed: the datagrams are handed straight
/// over, which is what makes a dialled connection testable at all. A relay
/// path's datagram would go to a relay client first, which is the work this
/// milestone does not build, so it is handed to the peer instead — the same
/// shortcut `transport/dial.zig`'s own harness takes.
fn forward(
    conn: quic_bridge.Conn,
    into: *quic_bridge.Bridge,
    map: *const addr_map.MappedAddrs,
    engine: *Prng,
) quic_bridge.Error!bool {
    var scratch: [2 * max_datagram]u8 = undefined;
    var egress: [max_egress]quic_bridge.Egress = undefined;
    var out: [max_egress * max_datagram]u8 = undefined;
    const from = conn.local() orelse return error.NoPathAddress;
    const sends = try conn.drain(&egress, &out, at_instant, engine.random());
    for (sends) |send| {
        var runs = try batch.Runs.init(send.send, batch.Capability.none);
        while (runs.next()) |run| {
            _ = try into.recv(map, .{
                .bytes = run.contents,
                .from = from,
                .local = send.to,
                .ecn = run.ecn,
            }, &scratch, at_instant, engine.random());
        }
    }
    return sends.len != 0;
}

test "the merge chooses the address and the dial opens on it" {
    var engine: Prng = Prng.init(1);
    var harness: Harness = undefined;
    try harness.init(&engine);
    defer harness.deinit();
    const peer = harness.server_secret.nodeId();

    // The DNS service is asked first and names one relay; the relay service is
    // asked second and names another. `item.Item.order` compares the canonical
    // encoding, and the two records agree on everything down to the host, so
    // the second source's relay is the greater and the winner is *not* the
    // first source's answer. The hosts are the same length on purpose, so the
    // order is decided by the bytes a reader can see rather than by a length
    // prefix that would decide it first. A run that took the first usable
    // address instead of the merge would dial `one.example.` and the key
    // assertion below would fail on its first line.
    var stops: Counter = .{};
    var relay: FakeRelay = .{
        .answers = "signed\x00",
        .packets = &.{.{ .node_id = peer, .txt = .init("relay=https://two.example./\x00") }},
    };
    var resolver = resolve.PkarrResolver.init(relay.source(stops.cancellation()));
    var service = dns.DnsAddressLookup.init(
        .init("relay=https://one.example./\x00"),
        null,
    );
    var named_one = Counted.init(service.lookup());
    var named_two = Counted.init(resolver.lookup());
    const sources = [_]resolve.AddressLookup{ named_one.lookup(), named_two.lookup() };

    const outcome = try dialFromSources(
        t.allocator,
        &sources,
        harness.dialer,
        requestAt(&harness, &engine),
    );

    // Both were asked, and the later one won. The counts are the assertion
    // that the walk does not stop at the first answer.
    try t.expectEqual(@as(u32, 1), named_one.asked);
    try t.expectEqual(@as(u32, 1), named_two.asked);
    try t.expect(outcome.first_failure == null);

    const dialled = switch (outcome.result) {
        .dialed => |value| value,
        else => return error.ExpectedADial,
    };
    try t.expectEqual(item.Provenance.pkarr, dialled.provenance);
    // Three separate answers from one target, which is what `resolveRoute`
    // exists to give: the address the core is told, the key that owns it, and
    // the subnet it sits in. The key is the *second* source's relay, and the
    // map is what says so — the winning address, not the first one asked for.
    try t.expectEqual(ula.Path.relay, dialled.dial.route.subnet.?);
    const expected: addr_map.Key = .{ .relay = .{
        .relay = try addr.RelayUrl.parse("https://two.example./"),
        .node = peer,
    } };
    try t.expectEqual(expected, dialled.dial.route.key.?);
    try t.expectEqual(expected, dial.ownerOf(&harness.map, dialled.dial.route.socket).?);
    // One key for one target: the relay the other service named was never a
    // target, so no address was allocated for it.
    try t.expectEqual(@as(usize, 1), harness.map.by_key.count());

    // The stream the answer came out of is closed before the run returns, so
    // nothing in the result is a slice into an arena that has just been
    // emptied.
    try t.expectEqual(@as(u32, 1), stops.stops);

    // The first flight leaves for the address the merge chose and a peer
    // accepts it: the whole distance from "cannot be found" to "a connection
    // exists", with no socket open and no clock read.
    try t.expectEqual(@as(usize, 1), harness.client.manager.entries.items.len);
    const client = harness.client.connectionAt(0) orelse
        return error.TestUnexpectedResult;
    try t.expect(try forward(client, harness.server, &harness.map, &engine));
    const accepted = harness.server.connectionAt(0) orelse return error.NoAcceptedConnection;
    try t.expectEqual(quic.connection.State.handshake, accepted.entry.conn.state);
}

test "a service that will not resolve stops the walk where it made its claim" {
    var engine: Prng = Prng.init(2);
    var harness: Harness = undefined;
    try harness.init(&engine);
    defer harness.deinit();
    const peer = harness.server_secret.nodeId();

    // Upstream's publisher implements no `resolve`
    // (`iroh/src/address_lookup/pkarr.rs:357`), so this is a service in
    // ordinary production and not a double invented to make this test pass.
    var publisher = resolve.PkarrPublisher.init();
    defer publisher.deinit();
    var refusing = Counted.init(publisher.lookup());

    // A relay that would have answered with an address, so the refusal is
    // shown to cost an answer rather than to describe a node nobody has.
    var first_stops: Counter = .{};
    var first_relay: FakeRelay = .{
        .answers = "signed\x00",
        .packets = &.{.{ .node_id = peer, .txt = .init("addr=192.0.2.9:9999\x00") }},
    };
    var first_resolver = resolve.PkarrResolver.init(
        first_relay.source(first_stops.cancellation()),
    );
    var answering = Counted.init(first_resolver.lookup());

    // The refusal first: the walk ends there, and the service behind it is
    // never asked, so there is no retrieval to cancel and no answer to lose.
    const refused = [_]resolve.AddressLookup{ refusing.lookup(), answering.lookup() };
    const stopped = try dialFromSources(
        t.allocator,
        &refused,
        harness.dialer,
        requestAt(&harness, &engine),
    );
    try t.expect(stopped.result == .cannot_resolve);
    try t.expectEqual(@as(u32, 1), refusing.asked);
    try t.expectEqual(@as(u32, 0), answering.asked);
    try t.expectEqual(@as(u32, 0), first_stops.stops);

    // The same two services the other way round: the walk reads the answering
    // one to the end and *then* stops on the claim, and the retrieval behind
    // the read one is stopped. Two different orders, one answer, and the
    // difference between them is which service was asked.
    const after = [_]resolve.AddressLookup{ answering.lookup(), refusing.lookup() };
    const stopped_after = try dialFromSources(
        t.allocator,
        &after,
        harness.dialer,
        requestAt(&harness, &engine),
    );
    try t.expect(stopped_after.result == .cannot_resolve);
    try t.expectEqual(@as(u32, 1), answering.asked);
    try t.expectEqual(@as(u32, 1), first_stops.stops);

    // And that the stream behind it was *read*, not only closed: the relay
    // behind the answering service gave up its one answer. A walk that named
    // the wrong slot of the open list would close both streams just the same
    // and leave this at zero, so the count is what says the walk drove the
    // stream the first source produced.
    try t.expectEqual(@as(usize, 1), first_relay.cursor);
}

test "an answer with nothing in it does not stop the walk" {
    var engine: Prng = Prng.init(3);
    var harness: Harness = undefined;
    try harness.init(&engine);
    defer harness.deinit();
    const peer = harness.server_secret.nodeId();

    // A node that exists and has nowhere to be sent a packet, from the one
    // service that can say so: an answer set with no records is one item, the
    // node, and no addresses.
    var service = dns.DnsAddressLookup.init(.init(""), null);
    var published_nothing = Counted.init(service.lookup());

    var stops: Counter = .{};
    var relay: FakeRelay = .{
        .answers = "signed\x00",
        .packets = &.{.{ .node_id = peer, .txt = .init("relay=https://relay.example./\x00") }},
    };
    var resolver = resolve.PkarrResolver.init(relay.source(stops.cancellation()));
    var relayed = Counted.init(resolver.lookup());
    const sources = [_]resolve.AddressLookup{ published_nothing.lookup(), relayed.lookup() };

    const outcome = try dialFromSources(
        t.allocator,
        &sources,
        harness.dialer,
        requestAt(&harness, &engine),
    );

    // The empty answer did not end the run, and the item it did produce lost
    // the merge to an item with an address, so it never reached the policy.
    try t.expectEqual(@as(u32, 1), published_nothing.asked);
    try t.expectEqual(@as(u32, 1), relayed.asked);
    try t.expectEqual(@as(u32, 1), stops.stops);
    const dialled = switch (outcome.result) {
        .dialed => |value| value,
        else => return error.ExpectedADial,
    };
    try t.expectEqual(item.Provenance.pkarr, dialled.provenance);
    try t.expectEqual(ula.Path.relay, dialled.dial.route.subnet.?);
}

test "an empty result, an empty address list and a refused path are told apart" {
    var engine: Prng = Prng.init(4);
    var harness: Harness = undefined;
    try harness.init(&engine);
    defer harness.deinit();
    const peer = harness.server_secret.nodeId();

    // A relay that answered with no packets. It was asked, it ran, and the
    // world had nothing in it: no items at all, which is
    // `item.Resolution.isEmptyResult` and not the absence of a service.
    var quiet: FakeRelay = .{ .answers = "", .packets = &.{} };
    var quiet_resolver = resolve.PkarrResolver.init(quiet.source(null));
    var silent = Counted.init(quiet_resolver.lookup());
    const only_quiet = [_]resolve.AddressLookup{silent.lookup()};
    const nothing = try dialFromSources(
        t.allocator,
        &only_quiet,
        harness.dialer,
        requestAt(&harness, &engine),
    );
    try t.expect(nothing.result == .nothing);
    try t.expectEqual(@as(u32, 1), silent.asked);

    // The same absence of addresses said by the other service, which is a
    // different fact: the node was found and it has no path.
    var service = dns.DnsAddressLookup.init(.init(""), null);
    var nameless = Counted.init(service.lookup());
    const only_nameless = [_]resolve.AddressLookup{nameless.lookup()};
    const no_path = try dialFromSources(
        t.allocator,
        &only_nameless,
        harness.dialer,
        requestAt(&harness, &engine),
    );
    try t.expect(no_path.result == .no_address);

    // And a winner this node's policy will not take, which is a fourth thing
    // again: the network named a path and the caller declined it. The run
    // reports it beside the two above rather than as one of them, and no
    // connection is opened.
    var stops: Counter = .{};
    var relay: FakeRelay = .{
        .answers = "signed\x00",
        .packets = &.{.{ .node_id = peer, .txt = .init("relay=https://relay.example./\x00") }},
    };
    var resolver = resolve.PkarrResolver.init(relay.source(stops.cancellation()));
    var answered = Counted.init(resolver.lookup());
    const only_answered = [_]resolve.AddressLookup{answered.lookup()};
    var declined = requestAt(&harness, &engine);
    declined.select = .{ .ctx = @ptrCast(@alignCast(&harness)), .pick = refuseEvery };
    const refused = try dialFromSources(
        t.allocator,
        &only_answered,
        harness.dialer,
        declined,
    );
    try t.expect(refused.result == .no_address);
    try t.expectEqual(@as(u32, 1), answered.asked);
    try t.expectEqual(@as(u32, 1), stops.stops);
    try t.expectEqual(@as(usize, 0), harness.client.manager.entries.items.len);
}

fn refuseEvery(_: *anyopaque, _: *const addr.NodeAddr) ?addr.TransportAddr {
    return null;
}

test "a run that gives up mid-walk still stops every retrieval it started" {
    var engine: Prng = Prng.init(5);
    var harness: Harness = undefined;
    try harness.init(&engine);
    defer harness.deinit();
    const peer = harness.server_secret.nodeId();

    // The error path. A service that cannot start leaves the streams of the
    // services before it open, and the error escapes; a run that returned
    // before closing them would have cancelled nothing, and the resolve behind
    // a stream nobody holds any more would keep running.
    var stops: Counter = .{};
    var relay: FakeRelay = .{
        .answers = "signed\x00",
        .packets = &.{.{ .node_id = peer, .txt = .init("addr=192.0.2.9:9999\x00") }},
    };
    var resolver = resolve.PkarrResolver.init(relay.source(stops.cancellation()));
    var answering = Counted.init(resolver.lookup());
    var unstartable = Unstartable.init();
    const failing = [_]resolve.AddressLookup{ answering.lookup(), unstartable.lookup() };
    try t.expectError(
        error.OutOfMemory,
        dialFromSources(
            t.allocator,
            &failing,
            harness.dialer,
            requestAt(&harness, &engine),
        ),
    );
    try t.expectEqual(@as(u32, 1), answering.asked);
    try t.expectEqual(@as(u32, 1), unstartable.asked);
    try t.expectEqual(@as(u32, 1), stops.stops);
    // Nothing was dialled, so nothing is in the manager to leak.
    try t.expectEqual(@as(usize, 0), harness.client.manager.entries.items.len);

    // And the path where the walk is cut short by a claim rather than by an
    // error: two sources read to the end, then a service that will not
    // resolve. All three are closed, and the two that produced nothing had a
    // retrieval cancelled as well, because a finished resolve has nothing
    // left to cancel and says so rather than skipping the call.
    var quiet_stops: Counter = .{};
    var quiet: FakeRelay = .{ .answers = "", .packets = &.{} };
    var quiet_resolver = resolve.PkarrResolver.init(quiet.source(quiet_stops.cancellation()));
    var silent = Counted.init(quiet_resolver.lookup());
    var publisher = resolve.PkarrPublisher.init();
    defer publisher.deinit();
    const cut_short = [_]resolve.AddressLookup{
        answering.lookup(),
        silent.lookup(),
        publisher.lookup(),
    };
    const outcome = try dialFromSources(
        t.allocator,
        &cut_short,
        harness.dialer,
        requestAt(&harness, &engine),
    );
    try t.expect(outcome.result == .cannot_resolve);
    try t.expectEqual(@as(u32, 2), answering.asked);
    try t.expectEqual(@as(u32, 1), silent.asked);
    try t.expectEqual(@as(u32, 2), stops.stops);
    try t.expectEqual(@as(u32, 1), quiet_stops.stops);
}
