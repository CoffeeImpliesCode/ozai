//! The two pkarr services: `PkarrPublisher`, which publishes this node and
//! cannot resolve, and `PkarrResolver`, which resolves and does not publish.
//! `discovery/pkarr.zig` is the signed-packet codec underneath them and this
//! file is what is left once the bytes have been read: the two services that
//! hold a slot or an answer set.
//!
//! Captured from n0-computer/iroh, `iroh/src/address_lookup/pkarr.rs`, commit
//! 187f59e80afdae6bd9866002b33d3365c00b06d8 — the `iroh` 1.3.0 crate as
//! published, fetched 2026-09-30: `PkarrPublisher` at line 357 and
//! `PkarrResolver` at `:536`, upstream's `watchable.set(Some(info))` in
//! `update_endpoint_data`, and the `BTreeMap` order `to_txt_strings` writes
//! records in.
//!
//! Upstream these two are two impls of one trait, and the trait is somewhere
//! else. ozai keeps that shape rather than inventing one: this file holds the
//! services and `discovery/lookup.zig` holds the interface, and the two take
//! opposite defaults — the publisher takes `AddressLookup.refuse_resolve`, the
//! resolver takes `AddressLookup.ignore_publish` — so "cannot resolve at all"
//! and "publishes nothing" are each a real service here and neither is a trait
//! default nobody uses.
//!
//! # Why this is the third file
//!
//! Take the interface out and take the grammar out and what is left is the
//! implementation: `Packet` and `PacketSource` are the seams a resolver reads
//! through, `PkarrState` is the one state the pull-based stream in
//! `discovery/lookup.zig` runs on, and `discovery/resolve.zig` re-exports the
//! whole surface, so a caller names that file and never this one by hand.

const std = @import("std");
const addr = @import("../base/addr.zig");
const item = @import("item.zig");
const lookup_mod = @import("lookup.zig");
const txt = @import("txt.zig");

/// One signed pkarr packet, as a resolver needs it.
///
/// A value: `node_id` is fixed-size and `txt` is a position in somebody else's
/// buffer. Nothing here is released, and a `Packet` is valid for as long as the
/// bytes `PacketSource.decode` read it out of — which is why that callback may
/// not decode into scratch it reuses before the pull that asked for it ends.
pub const Packet = struct {
    /// Who signed it, which *is* the node being published: upstream reads the
    /// id out of the packet's own public key (`iroh-dns/src/endpoint_info.rs`,
    /// `from_pkarr_signed_packet`).
    node_id: addr.NodeId,
    /// The `_iroh` records, in whatever order the packet listed them. The
    /// `_iroh` name filter is already applied and the character strings of one
    /// record are already concatenated: upstream reads them with
    /// `packet.txt_records(IROH_TXT_NAME)`, and a pkarr packet's records are
    /// DNS records, whose multiple character strings are one value
    /// (`iroh/src/address_lookup/dns.rs:35`: "If a TXT record contains multiple
    /// character strings, they are concatenated first"). The concatenation is a
    /// DNS-layer fact and the same one `discovery/dns.zig` relies on, so neither
    /// service does it.
    ///
    /// Borrowed from the packet bytes, positioned at its first record; a copy is
    /// how two readers share one buffer without stepping on each other.
    txt: txt.RecordSet,
};

/// What a pkarr resolver reads: signed packet bytes, and the retrieval to stop.
///
/// Nothing here fetches. A resolver is handed an answer set that something else
/// already retrieved, together with a handle to that retrieval, which is how a
/// caller cancels without the resolver ever learning what a socket is.
///
/// Nothing here is owned: the answers are borrowed and the two callables are
/// the caller's own, so all of it has to outlive every stream started against
/// it. One source may serve several streams, and `decode` is then called from
/// whichever thread is pulling — the seam carries no synchronisation of its own,
/// and a source shared across threads has to be safe to call that way.
pub const PacketSource = struct {
    /// The source's own value, borrowed and reached by `decode`. It has to stay
    /// alive until every stream reading this source is closed.
    ctx: *anyopaque,
    /// Signed-packet bytes to what they say. This function is
    /// `discovery/pkarr.zig`'s and nothing in this file is; a resolver calls it
    /// and turns its answer into either a `Packet` or a `DecodeError`, and that
    /// mapping is the whole of the coupling between the two files.
    ///
    /// Called once per answer, synchronously, inside the `Stream.next` that
    /// walks to it and on that call's thread. `packet` borrows `answers` and is
    /// live for the call only; the returned `Packet.txt` may borrow it, so a
    /// source that decodes out of a scratch buffer cannot hand one back that
    /// outlives the pull. Nothing here reenters the stream being pulled, and
    /// `error.MalformedPacket` and `error.BadSignature` lose that one answer
    /// rather than the stream.
    decode: *const fn (ctx: *anyopaque, packet: []const u8) lookup_mod.DecodeError!Packet,
    /// The answers, already retrieved, concatenated and NUL-separated. The
    /// first NUL ends one packet and the second starts the next, which is why
    /// each answer is a whole signed packet and a packet may hold several
    /// `_iroh` records of its own.
    ///
    /// Borrowed, and read from the position this value holds: a resolver copies
    /// it per resolve so two streams cannot tread on each other's place in the
    /// buffer, but both copies point at the same bytes, which therefore have to
    /// stay valid and unchanged until the last of those streams is closed.
    answers: txt.RecordSet,
    /// How to stop the retrieval. Null when there was none — an answer set read
    /// out of a file has nothing to cancel — and a stream with a null one still
    /// runs and still frees; it simply tells nobody to stop. Non-null is fired
    /// exactly once per stream, from `Stream.deinit`, so the handle it points at
    /// has to outlive every stream started here.
    cancellation: ?lookup_mod.Cancellation,
};

/// `PkarrPublisher`: the service that only publishes.
///
/// Upstream's `PkarrPublisher` implements `publish` and not `resolve`
/// (`iroh/src/address_lookup/pkarr.rs:357`), so it takes
/// `AddressLookup.refuse_resolve` and a resolve asked of it comes back `None`.
/// That is the production case for the distinction invariant 13 is about, and
/// not only a trait default nobody uses.
///
/// One slot, so the last publication is readable, and `deinit` for the one that
/// is still in it. The slot holds the whole `Published`, allocator included, so
/// a value this publisher did not build is released with the allocator that did
/// build it — see `Published`.
pub const PkarrPublisher = struct {
    /// The last data handed to `publish`, owned whole so the caller is free the
    /// moment `publish` returns. Upstream's is `self.watchable.set(Some(info))`
    /// (`iroh/src/address_lookup/pkarr.rs`, `update_endpoint_data`): the same
    /// take-ownership swap, into the same one slot, read by a background task
    /// that republishes on a timer.
    ///
    /// Null is the empty state: nothing published, and `published` says so
    /// rather than answering with an item that has no address.
    stored: ?lookup_mod.Published,
    /// Borrowed by every `AddressLookup` handed out of `lookup`.
    vtable: lookup_mod.AddressLookup.VTable = publisher_vtable,

    /// A publisher with nothing in its slot.
    pub fn init() PkarrPublisher {
        return .{ .stored = null };
    }

    // The slot is given back and then nulled, and null is the terminal state:
    // `published` answers null, a second `deinit` frees nothing, and the next
    // `publish` starts a fresh slot. Z030 recognises a fixed list of terminal
    // field names and `stored` is not on it, so the `= null` it cannot see is
    // here to be read.
    // ziglint-ignore: Z030
    /// Releases the slot, with the allocator that slot arrived with, and leaves
    /// the publisher empty. Not a vtable entry, because the vtable is a
    /// borrowed view: see `AddressLookup`. A second call frees nothing, and a
    /// `Published` published afterwards is released by the next `publish` or by
    /// this call.
    pub fn deinit(self: *PkarrPublisher) void {
        if (self.stored) |data| lookup_mod.releaseTransfer(data);
        self.stored = null;
    }

    /// A handle onto this publisher. Borrowed, so the publisher has to outlive
    /// every handle taken of it and every publish made through one.
    pub fn lookup(self: *PkarrPublisher) lookup_mod.AddressLookup {
        return .{ .vtable = &self.vtable, .ctx = @ptrCast(@alignCast(self)) };
    }

    /// What was published last, or null when `publish` has not been called.
    ///
    /// Borrows the publisher's own storage, so the address list is dead after
    /// the next `publish` and after `deinit` — invariant 6's reason. The
    /// provenance is `.pkarr` and the stamp is the one the caller published,
    /// because a publisher is only ever a pkarr one.
    pub fn published(self: *const PkarrPublisher) ?item.Item {
        const data = self.stored orelse return null;
        return item.Item.init(data.endpoint, .pkarr, data.last_updated);
    }

    /// The records a signed packet for the published data would carry, as a
    /// `RecordSet` written into caller storage. Records are NUL-separated
    /// because that is what a DNS record set is; whoever builds the packet puts
    /// each one in a character string of its own and does not send the
    /// separators.
    ///
    /// The order is upstream's — every `relay=`, then every `addr=`, then
    /// `user-data=` — because a `BTreeMap` over `IrohAttr` iterates in
    /// declaration order however the packet listed them (`iroh-dns/src/attrs.rs`,
    /// `to_txt_strings`). It falls out of one loop here because
    /// `TransportAddr`'s declaration order is the same three families and
    /// `NodeAddr` is sorted by `TransportAddr.order`, so the sorted list is
    /// already grouped. `user-data=` is never written, because there is no user
    /// data to write: see `Attribute.user_data`.
    ///
    /// The order *within* the relays and the addresses is not upstream's.
    /// Upstream's `EndpointData` is insertion-ordered and says so — "The
    /// address order is preserved, so it can encode priority for address lookup
    /// services, should they not fit into e.g. a single DNS packet otherwise".
    /// Invariant 2 makes an address list a set, so ozai cannot encode a
    /// publication priority. That is a divergence, not an oversight.
    ///
    /// The relay URL text is upstream's: `url::Url`'s `Display` is scheme, host,
    /// a non-default port and a `/` path, which is exactly the canonical form
    /// invariant 4 pins.
    pub fn writeTxtStrings(self: *const PkarrPublisher, out: []u8) txt.EncodeError![]const u8 {
        const stored = self.stored orelse return error.NothingPublished;
        var writer = std.Io.Writer.fixed(out);
        for (stored.endpoint.addrs) |value| {
            try writeTxtRecord(value, &writer);
        }
        return writer.buffered();
    }
};

fn writeTxtRecord(value: addr.TransportAddr, writer: *std.Io.Writer) txt.EncodeError!void {
    // One record at a time, into a scratch buffer, and copied out with
    // its separator. Keeping the record boundary here makes
    // `max_record_length` a bound each write actually relies on.
    var scratch: [txt.max_record_length]u8 = undefined;
    var line = std.Io.Writer.fixed(&scratch);
    try writeTxtValue(value, &line);
    writer.writeAll(line.buffered()) catch return error.BufferTooSmall;
    writer.writeAll("\x00") catch return error.BufferTooSmall;
}

fn writeTxtValue(value: addr.TransportAddr, line: *std.Io.Writer) txt.EncodeError!void {
    switch (value) {
        .relay => |url| {
            line.writeAll("relay=") catch return error.BufferTooSmall;
            url.format(line) catch return error.BufferTooSmall;
        },
        .ip => |socket| {
            line.writeAll("addr=") catch return error.BufferTooSmall;
            txt.writeSocketAddr(socket, line) catch return error.BufferTooSmall;
        },
        .custom => |custom| {
            line.writeAll("addr=") catch return error.BufferTooSmall;
            custom.format(line) catch return error.BufferTooSmall;
        },
    }
}

const publisher_vtable: lookup_mod.AddressLookup.VTable = .{
    .publish = publisherPublish,
    .resolve = lookup_mod.AddressLookup.refuse_resolve,
};

fn publisherPublish(ctx: *anyopaque, data: lookup_mod.Published) void {
    const self: *PkarrPublisher = @ptrCast(@alignCast(ctx));
    // The slot is replaced, not appended to, which is upstream's
    // `watchable.set`: a publisher's job is to say what this node is reachable
    // at *now*, and an address the endpoint has since stopped using is not a
    // second opinion, it is stale.
    // Released with the allocator that slot arrived with, not with one of this
    // publisher's: whoever published last built that list, and a publisher has
    // no allocator of its own to release it with.
    if (self.stored) |previous| lookup_mod.releaseTransfer(previous);
    self.stored = data;
}

/// `PkarrResolver`: the service that only resolves.
///
/// Upstream's `PkarrResolver` implements `resolve` and not `publish`
/// (`iroh/src/address_lookup/pkarr.rs:536`), so it takes
/// `AddressLookup.ignore_publish`. Publishing is somebody else's job, and a
/// resolver that also published would make "what this node is reachable at" and
/// "what the network says about that node" the same value.
///
/// Copying the service copies the borrowed source and the vtable, so a copy is
/// a second handle onto one answer set and not a second retrieval.
pub const PkarrResolver = struct {
    /// The answers and the handle to the retrieval behind them, both borrowed.
    /// Every stream started against this resolver reads them, so they have to
    /// outlive all of those streams.
    source: PacketSource,
    /// Borrowed by every `AddressLookup` handed out of `lookup`.
    vtable: lookup_mod.AddressLookup.VTable = resolver_vtable,

    /// A resolver over one already-retrieved answer set.
    pub fn init(source: PacketSource) PkarrResolver {
        return .{ .source = source };
    }

    /// A handle onto this resolver. Borrowed, so the resolver has to outlive
    /// every stream started through the handle.
    pub fn lookup(self: *PkarrResolver) lookup_mod.AddressLookup {
        return .{ .vtable = &self.vtable, .ctx = @ptrCast(@alignCast(self)) };
    }
};

const resolver_vtable: lookup_mod.AddressLookup.VTable = .{
    .publish = lookup_mod.AddressLookup.ignore_publish,
    .resolve = resolverResolve,
};

const PkarrState = struct {
    parent: *const PkarrResolver,
    /// The arena every item this stream produces lives in. See `parseTxt` on
    /// why a resolver needs one: an item owns a `NodeAddr` *and* the bytes
    /// behind any custom address in it, and a `NodeAddr` has nowhere to keep
    /// the second. One arena for the whole stream means `destroy` is one call
    /// and no item can outlive it by accident.
    arena: std.heap.ArenaAllocator,
    /// `arena.allocator()`, taken after the state reached its final address:
    /// the allocator hands back the arena's own address, and that address must
    /// not move while the allocator is in use.
    alloc: std.mem.Allocator,
    /// The node the caller asked about, held because a packet is only an answer
    /// if it was signed by it. See `Reason.UnexpectedSigner`.
    node_id: addr.NodeId,
    /// The service's answer set, by value: two resolves against one service
    /// each get their own position in the buffer.
    answers: txt.RecordSet,
    /// The item being handed over. It walks forward one at a time, so a caller
    /// that abandons the stream leaves the rest of the answers undecoded — which
    /// is what "cancel the work" has to mean for a resolver whose work is the
    /// decode.
    cursor: usize,
    /// Every item this stream has produced, in packet order. `finish` hands the
    /// whole slice back, so it has to outlive the last pull, and the pull that
    /// produces an item is the pull that appends it.
    items: std.ArrayList(item.Item),
};

fn resolverResolve(
    ctx: *anyopaque,
    // `AddressLookup.VTable.resolve`'s parameter order: a vtable entry takes
    // its context first and the allocator second, and the type every service
    // in the tree implements is fixed on `AddressLookup`.
    // ziglint-ignore: Z023
    alloc: std.mem.Allocator,
    node_id: addr.NodeId,
) lookup_mod.ResolveError!?lookup_mod.Stream {
    const self: *PkarrResolver = @ptrCast(@alignCast(ctx));
    const state = try alloc.create(PkarrState);
    errdefer alloc.destroy(state);
    state.* = .{
        .parent = self,
        .arena = .init(alloc),
        .alloc = undefined,
        .node_id = node_id,
        .answers = self.source.answers,
        .cursor = 0,
        .items = .empty,
    };
    state.alloc = state.arena.allocator();
    return .{
        .state = @ptrCast(@alignCast(state)),
        .vtable = &pkarr_stream_vtable,
        .alloc = alloc,
        .status = .live,
    };
}

const pkarr_stream_vtable: lookup_mod.Stream.VTable = .{
    .next = pkarrNext,
    .finish = pkarrFinish,
    .cancel = pkarrCancel,
    .destroy = pkarrDestroy,
};

/// One pull: hand over the item already decoded, or decode the next answer.
///
/// Decoding and delivering are interleaved rather than separated on purpose.
/// Doing every decode up front would make `finish` simpler and would mean a
/// caller that abandons the stream had already paid for all of it, which is the
/// opposite of what a cancellation is for.
fn pkarrNext(state: *anyopaque) ?lookup_mod.Event {
    const self: *PkarrState = @ptrCast(@alignCast(state));
    if (self.cursor < self.items.items.len) {
        const value = self.items.items[self.cursor];
        self.cursor += 1;
        return .{ .item = value };
    }
    const bytes = self.answers.next() orelse return null;
    const packet = self.parent.source.decode(self.parent.source.ctx, bytes) catch |reason| {
        return failed(.pkarr, reason);
    };
    if (self.node_id.order(packet.node_id) != .eq) {
        return failed(.pkarr, error.UnexpectedSigner);
    }
    const value = txt.parseTxt(self.alloc, packet.node_id, packet.txt, .pkarr) catch |reason| {
        return failed(.pkarr, reason);
    };
    self.items.append(self.alloc, value) catch {
        // The item is built and owned by nothing, so its address list is freed
        // here: `destroy` walks `items` and this one is not in it.
        value.endpoint.deinit(self.alloc);
        return failed(.pkarr, error.OutOfMemory);
    };
    // The item just appended is the one being handed over, so the cursor moves
    // with it. Without this the next pull would find `cursor < items.len` and
    // hand the same item over a second time.
    self.cursor += 1;
    return .{ .item = value };
}

fn pkarrFinish(state: *anyopaque) item.Resolution {
    const self: *PkarrState = @ptrCast(@alignCast(state));
    return .{ .resolved = self.items.items };
}

fn pkarrCancel(state: *anyopaque) void {
    const self: *PkarrState = @ptrCast(@alignCast(state));
    if (self.parent.source.cancellation) |cancellation| cancellation.fire();
}

// `Stream.VTable.destroy`'s parameter order, for the reason `resolverResolve`
// above gives: the state being released, then the allocator the stream was
// started with.
// ziglint-ignore: Z023
fn pkarrDestroy(state: *anyopaque, alloc: std.mem.Allocator) void {
    const self: *PkarrState = @ptrCast(@alignCast(state));
    // The arena owns every item, their address lists and the bytes behind any
    // custom address, so there is nothing to walk and nothing to free
    // individually — and therefore no way for one of those to be missed.
    self.arena.deinit();
    alloc.destroy(self);
}

fn failed(provenance: item.Provenance, reason: lookup_mod.Reason) lookup_mod.Event {
    return .{ .failed = .{ .provenance = provenance, .reason = reason } };
}
