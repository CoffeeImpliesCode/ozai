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
//! that is this module.
//!
//! # The order is the whole of the answer
//!
//! Every source that will answer is asked, every answer is merged, and the
//! winner under `item.Item.order` is the one that is dialled. Two
//! consequences, and neither is a detail:
//!
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
//! one, and neither does this module. Everything a real lookup needs that the
//! type does not say is in that one gap, and it is all I/O this milestone
//! does not build:
//!
//!
//! Those four are what a real `resolve.PacketSource` and a real
//! `dns.DnsAddressLookup` are built with, and this milestone does not build
//! them: a relay client, a UDP socket and a DNS transaction manager are
//! transport work, and `transport/socket.zig` is the seam they come through.
//! Until they exist the answers are the caller's, and this module cannot tell
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
//! through to the address value order, and this module does not touch it.

const std = @import("std");
const addr = @import("../base/addr.zig");
const item = @import("item.zig");
const resolve = @import("resolve.zig");
const addr_map = @import("../transport/addr_map.zig");
const dial = @import("../transport/dial.zig");

/// What this module refuses.
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
/// and a switch in this module would be a second opinion about paths written by
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
