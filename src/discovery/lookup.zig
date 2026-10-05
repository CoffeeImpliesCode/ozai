//! What a lookup service *is*: the address-lookup vtable, the pull-based stream
//! a resolve hands back, and the vocabulary one failure is spoken in.
//!
//! Captured from n0-computer/iroh, `iroh/src/address_lookup.rs`, commit
//! 187f59e80afdae6bd9866002b33d3365c00b06d8 — the `iroh` 1.3.0 crate as
//! published, fetched 2026-09-30: the `AddressLookup` trait at line 335 with its
//! two default bodies at `:343` and `:349`, and the rule at `:584` that one
//! failing service must not hide results from others still in flight.
//!
//! Two things differ from upstream, and each is one rule applied rather than
//! two decisions made.
//!
//! * The trait is a vtable, as `docs/ARCHITECTURE.md` records for
//!   `ProtocolHandler`. A vtable has no default method bodies, so upstream's two
//!   defaults are two function pointers any vtable may take:
//!   `AddressLookup.ignore_publish` and `AddressLookup.refuse_resolve`. The
//!   second is where "cannot resolve at all" comes from, and
//!   `discovery/pkarr.zig`'s publisher takes it — upstream's publisher
//!   implements no `resolve`, so asking one to resolve is answered with `None`
//!   and not with an empty stream.
//! * The stream is pulled. See `Stream`.
//!
//! Nothing here opens a socket. A service is handed the bytes an answer consists
//! of, and a handle to the retrieval they came from, and the retrieval is the
//! transport's business and is injected at construction. mDNS and the Mainline
//! DHT are external crates upstream and are not in that tree; in ozai they are
//! two more `VTable` values and nothing else, and nothing here would change to
//! add either.
//!
//! One thing is deliberately absent: `AddressLookupServices`, upstream's fan-in
//! over many services (`iroh/src/address_lookup.rs:565`). M5 asks for three
//! implementations of one interface, and the merge that would sit on top of it
//! is `discovery/item.zig`'s `merge` and `order`, which are already total.
//!
//! # Why this is half a file
//!
//! Three things are here because each is named by the other two. `Published` is
//! what `AddressLookup.VTable.publish` takes and what `discovery/pkarr.zig`'s
//! publisher stores; `Stream` is what `AddressLookup.VTable.resolve` returns and
//! what every `Failure` travels over; and `Reason` is the union of the arms a
//! record grammar and a packet decoder each produce, so it belongs where a
//! caller of a *stream* reads it rather than in either module that produces one
//! of its arms. That is why `discovery/txt.zig`'s `ParseError` lives there and
//! is named here across a module boundary.
//!
//! `discovery/pkarr.zig` is the other half and `discovery/resolve.zig` is the
//! facade: every name below is still reachable through that file, so a caller
//! that names it never has to learn that the split happened.

const std = @import("std");
const addr = @import("../base/addr.zig");
const item = @import("item.zig");
const txt = @import("txt.zig");

/// What a service is asked to publish, and what it takes on the duty of
/// releasing.
///
/// Upstream's `publish(&self, data: &EndpointData)`
/// (`iroh/src/address_lookup.rs:343`) takes the *data* and not the endpoint, so
/// the trait never names the node it is publishing for. ozai's `NodeAddr` is
/// upstream's `EndpointInfo` — the id and the data already joined — so the two
/// arrive together and a publisher cannot be handed addresses for a node it is
/// not publishing. `discovery/item.zig`'s `Item` is the same join on the
/// reading side.
///
/// # The address is transferred, and the allocator travels with it
///
/// `publish` *consumes* this value: from the moment it returns the caller owns
/// nothing here and the callee owns all of it, releasing included. Nothing is
/// copied, because a Zig move is free and making `publish` copy would be an
/// allocation every publication paid for.
///
/// A `NodeAddr` carries no allocator of its own, so the one that built
/// `endpoint` arrives beside it, and that is what the field is for. Both of the
/// services that take this value need it:
///
/// * `AddressLookup.ignore_publish` releases the address list and returns.
///   Handed a `NodeAddr` alone it could only have leaked, and a leak a service
///   causes by being a resolver is not a fact the caller can act on — the
///   caller gave the value away.
/// * `PkarrPublisher` releases the slot a later publication replaces, and the
///   slot it still holds, each with the allocator that slot arrived with. One
///   allocator of the publisher's own cannot do that: the previous publication
///   was built by whoever called `publish` last, and freeing it with any other
///   is a double free or a leak depending on which that was.
///
/// So `alloc` must still be valid when the callee releases the value, which for
/// a publisher that stores it means until its `deinit`.
///
/// # What the transfer does not carry
///
/// Only the outer list. A `.custom` address borrows its `data`, and
/// `base/addr.zig` owns that rule, so the bytes behind one stay the caller's
/// to keep alive for as long as the callee holds the endpoint — until the
/// publisher's `deinit`, in the case that stores it. `parseTxt` is where the
/// reading side pays for that.
pub const Published = struct {
    /// The allocator `endpoint`'s address list came from, and the only one it
    /// may be released with. A value rather than a pointer: whatever it
    /// addresses must be alive at the release above.
    alloc: std.mem.Allocator,
    /// The address to publish, consumed by the call that takes this value. Its
    /// list is sorted, unique and owned; the caller must not read it again.
    endpoint: addr.NodeAddr,
    /// When this address was learned, or null when the caller cannot say. Null
    /// sorts before every known timestamp in `Item.order`. Equal timestamps
    /// fall through to node id, address value order, and provenance.
    ///
    /// Upstream's publisher stores no timestamp at all — it republishes on a
    /// timer and on change. The field is here because `Item` has one and the
    /// endpoint knows when it last republished; a caller with nothing to say
    /// passes null, which is what upstream means.
    last_updated: ?u64,
};

/// Why `resolve` could not start.
///
/// One arm, and it is the allocator's. Starting the work is a small state
/// block; a service that could not start has not started, which is what `null`
/// says, so a caller has two distinct answers to handle rather than three.
pub const ResolveError = error{OutOfMemory};

/// Two methods, upstream's method set, as a vtable.
///
/// A vtable is a borrowed view. The service behind it is a value the caller owns
/// and releases with its own `deinit` — `PkarrPublisher.deinit`, say — so there
/// is no third entry here for a destructor. Adding one would be Zig's `Drop`
/// wearing a trait method's name, and the method set is the part worth keeping
/// recognisable.
///
/// Copying a handle is free and every copy names the same service; nothing in
/// it is owned, and the service has to outlive every handle taken of it.
pub const AddressLookup = struct {
    /// The service's own vtable, borrowed: a field of the service value, and
    /// dead with it.
    vtable: *const VTable,
    /// The service value behind this handle, borrowed and reinterpreted. It
    /// must stay alive and unmoved for every call made through the handle.
    ctx: *anyopaque,

    /// The two methods every service implements, and the two defaults it may
    /// take instead.
    ///
    /// Each entry runs synchronously on the thread that called through
    /// `AddressLookup` and returns before that call does, so a service whose
    /// own work is off-thread takes its own handle rather than being called
    /// from one. `ctx` is the service value and is live for the call.
    pub const VTable = struct {
        /// Takes over `data`: the callee owns the address list from this call
        /// onwards and releases it with `data.alloc`, on this call or on a
        /// later one. Fire and forget, as upstream's is: "This is fire and
        /// forget, since the `Endpoint` can not wait for successful publishing"
        /// (`iroh/src/address_lookup.rs:337`). `AddressLookup.ignore_publish`
        /// is the slot for a service that publishes nothing, and it releases
        /// there and then; `PkarrPublisher` keeps the value and releases the
        /// one a later publication replaces.
        publish: *const fn (ctx: *anyopaque, data: Published) void,
        /// Begin a resolve, or answer null for a service that does not resolve
        /// at all. The caller owns what comes back and must `deinit` it, and
        /// `error.OutOfMemory` means nothing was started and there is nothing
        /// to release. Every allocation the stream makes comes from `alloc`,
        /// so that allocator has to outlive the stream.
        resolve: *const fn (
            ctx: *anyopaque,
            alloc: std.mem.Allocator,
            node_id: addr.NodeId,
        ) ResolveError!?Stream,
    };

    /// Hands `data` to the service and gives up ownership of it: the address
    /// list is released with `data.alloc` here or by the service later, and
    /// either way the caller must not read `data.endpoint` again.
    pub fn publish(self: AddressLookup, data: Published) void {
        self.vtable.publish(self.ctx, data);
    }

    /// Starts a resolve for `node_id`, allocating the stream out of `alloc`, or
    /// answers null for a service that will not answer for that node at all.
    ///
    /// Null means "cannot resolve at all", which is not "resolved to nothing".
    /// The second is a stream that ran and came back with no items; see
    /// `Stream` and `item.Resolution`. A returned stream reads the service on
    /// every pull, so the service outlives it even though the stream borrows
    /// nothing from it.
    pub fn resolve(
        self: AddressLookup,
        alloc: std.mem.Allocator,
        node_id: addr.NodeId,
    ) ResolveError!?Stream {
        return self.vtable.resolve(self.ctx, alloc, node_id);
    }

    /// Upstream's default `publish`: do nothing
    /// (`iroh/src/address_lookup.rs:343`). A pointer rather than a private
    /// function so that a service which publishes nothing says so by taking the
    /// default instead of restating it, and so a reader can tell at the vtable
    /// which services are publishers and which only resolve.
    ///
    /// "Nothing" is about the publication and not about the value: `data` was
    /// transferred, so the address list is released here with `data.alloc` and
    /// the caller is left with nothing of its own to release.
    pub const ignore_publish: *const fn (*anyopaque, Published) void = ignorePublish;

    /// Upstream's default `resolve`: `None`
    /// (`iroh/src/address_lookup.rs:349`), which its doc reads as "this service
    /// will not answer for this node id at all".
    pub const refuse_resolve: *const fn (
        *anyopaque,
        std.mem.Allocator,
        addr.NodeId,
    ) ResolveError!?Stream = refuseResolve;
};

fn ignorePublish(_: *anyopaque, data: Published) void {
    releaseTransfer(data);
}

/// Release one transferred publication: its address list, with the allocator
/// that list came from.
///
/// There is no check for the empty list `NodeAddr.init` hands back: `deinit`
/// frees the outer list and nothing else, and freeing a zero-length slice is a
/// no-op.
pub fn releaseTransfer(data: Published) void {
    data.endpoint.deinit(data.alloc);
}

fn refuseResolve(
    _: *anyopaque,
    // `AddressLookup.refuse_resolve`'s parameter order: the vtable entry takes
    // its context first and the allocator second, and the type is declared on
    // the public `AddressLookup` rather than here.
    // ziglint-ignore: Z023
    _: std.mem.Allocator,
    _: addr.NodeId,
) ResolveError!?Stream {
    return null;
}

/// One pull's worth of answer.
pub const Event = union(enum) {
    /// A result. Its address list, and the payload bytes behind any custom
    /// address in it, belong to the stream and die with `Stream.deinit`; a
    /// caller that keeps one past that copies what it needs, since copying an
    /// `Item` shares that storage rather than duplicating it.
    item: item.Item,
    /// One answer could not be turned into an item.
    ///
    /// The stream carries on, which is upstream's rule and not a convenience:
    /// `iroh/src/address_lookup.rs:584` says a single failing service must not
    /// hide results from others still in flight, and one truncated packet in a
    /// four-packet answer set is that same situation one level down. Upstream
    /// models it as a `Result` inside the stream rather than as the end of it,
    /// and so does this.
    failed: Failure,
};

/// One answer that was not an item.
pub const Failure = struct {
    /// Which service produced it, so a caller reading a merged stream knows
    /// which resolver to blame without keeping a handle per service.
    provenance: item.Provenance,
    /// What went wrong with that one answer. Nothing partial survives it: this
    /// answer is gone and the stream carries on.
    reason: Reason,
};

/// Why injected packet bytes are not a signed packet.
///
/// Deliberately two arms, and the whole of the coupling between this file and
/// `discovery/pkarr.zig`. Upstream's failure is a source-chained error enum
/// whose variant names are that module's business; what a caller of a *stream*
/// does about a failure is not, and the answer is the same for both — this one
/// answer is gone and the rest of the stream is not. A wider set would be wide
/// enough to be mistaken for a decision the caller has to make.
pub const DecodeError = error{
    /// Not a DNS packet, or a truncated one.
    MalformedPacket,
    /// A well-formed packet whose signature does not verify under the public key
    /// it carries. Upstream rejects these before anything downstream sees them,
    /// and so does this.
    BadSignature,
};

/// Why a set of records is not an `Item`.
///
/// `DecodeError`, plus the one way a *record* can be wrong and the one way this
/// code can run out of memory. A value that is well formed but unusable — a
/// relay URL that will not parse, an address of no known shape — is not in here:
/// upstream drops those and `parseTxt` drops them, because a resolver that
/// failed instead would lose the good records behind the bad one.
pub const ParseError = error{
    /// A record that is not `key=value`, or whose key is not one of the three
    /// `iroh` attributes. Upstream fails the whole lookup on either
    /// (`ParseError::UnexpectedFormat`, `ParseError::AttrFromString`, both in
    /// `iroh-dns/src/attrs.rs`).
    MalformedRecord,
    OutOfMemory,
};

/// Everything one answer can fail with.
pub const Reason = DecodeError || txt.ParseError || error{
    /// A packet that was not signed by the node the caller asked about.
    ///
    /// Upstream takes the node id from whatever the relay returned
    /// (`iroh-dns/src/endpoint_info.rs`, `from_pkarr_signed_packet` is
    /// `EndpointId::from_bytes(pubkey.as_bytes())`) and hands it straight on, so
    /// a relay that answers a query for one node with another's record is
    /// obeyed. ozai reports it: a `resolve` for one node handing back another
    /// node's address is worse than handing back none, and reporting it keeps
    /// the answer distinguishable from "this node has published nothing".
    UnexpectedSigner,
};

/// The producer's own "stop what you are doing" handle.
///
/// This is invariant 13 seen from the other side, and it points at something
/// the *producer* owns — a relay request's abort handle, a DNS transaction's
/// cancellation — and never at the stream's own state. A stream that cancelled
/// only itself would satisfy every assertion written about it while the fetch
/// behind it kept running, which is exactly the failure the invariant names.
pub const Cancellation = struct {
    /// The producer's own value, borrowed and reached by `stop`. It has to stay
    /// alive until `fire` runs, which is `Stream.deinit` and not the end of the
    /// resolve.
    ctx: *anyopaque,
    /// Runs synchronously on the calling thread and returns before `fire` does,
    /// with everything it needs reachable from `ctx`: a producer whose work is
    /// off-thread is told to stop here, not joined here. Nothing reenters the
    /// stream from it — the state is still live, but a pull from inside a
    /// cancel is not a call this contract allows.
    stop: *const fn (ctx: *anyopaque) void,

    /// Tells the producer to stop. Called exactly once per stream, from
    /// `Stream.deinit`, on every path out of a resolve — drained, abandoned, or
    /// never pulled at all — so a producer may treat it as one request and a
    /// second one as a no-op.
    ///
    /// It does not join the producer's work: a resolve that already finished is
    /// told to stop anyway, because a `cancel` that does nothing then is cheaper
    /// than a status check that could be got wrong.
    pub fn fire(self: Cancellation) void {
        self.stop(self.ctx);
    }
};

/// A resolve in progress, pulled by whoever asked for it.
///
/// Upstream's `BoxStream<Result<Item, Error>>` is driven by the runtime: the
/// service's future makes progress whether or not anyone is reading, and
/// dropping the box is what stops it. This one is pulled, and that is the whole
/// reason it is testable. `docs/ARCHITECTURE.md` says a state machine that needs
/// a runtime stood up in order to be tested has found a boundary in the wrong
/// place; a pull-based stream is `(state, input) -> (state, actions)` with the
/// caller supplying the input, so every transition below is a function call a
/// test makes directly.
///
/// The lifetime is the contract, invariant 13: **every** `resolve` that returns
/// a stream is followed by a `Stream.deinit`, on every path out of the caller.
/// That is how a caller cancels. Zig has no implicit destructor, so `deinit` is
/// the drop, and a caller that abandons a resolve without reaching it leaks the
/// retrieval rather than cancelling it — the rule "one `deinit` per stream, on
/// every path" is the only thing standing between the two, which is why it is
/// stated here and not left for a reader to infer. A stream that has already
/// finished still needs `deinit`: its items are heap.
///
/// The `Resolution` from `finish` borrows that same heap, so it is read before
/// `deinit` and not after. `item.Resolution` says so; this is where the borrow
/// comes from.
///
/// # What the stream owns, and what a copy of one is
///
/// The state is allocated from the allocator the resolve was started with and
/// released by `deinit` with that same allocator, so the allocator has to
/// outlive the stream. Every item a pull hands out lives in that state — a
/// pkarr stream's are in an arena inside it — so an `Event` stays valid until
/// `deinit` and not one instant past it, and a later pull does not invalidate
/// an earlier one. `item.Item` is where copying one of those is described.
///
/// A `Stream` is a handle and not a move: copying one copies the state pointer
/// and each copy keeps its own `status`, so `deinit` reached through two copies
/// tells the producer to stop twice and frees the state twice. One `deinit` per
/// returned stream, on one handle.
pub const Stream = struct {
    /// The service's state, owned by this stream and released by `deinit`. It
    /// is not moved while the stream is live, because every pull reads it.
    state: *anyopaque,
    /// How to pull, finish, cancel and release that state, borrowed. Both
    /// services here point this at a file-scope constant, so it outlives every
    /// stream; an implementation whose vtable is a field would have to keep the
    /// service alive instead.
    vtable: *const VTable,
    /// The allocator the state came from. Held rather than taken again by
    /// `deinit`, because an owning handle that takes the allocator once more is
    /// a handle that can be freed with the wrong one.
    alloc: std.mem.Allocator,
    /// Which of the three states this handle is in. `.live` is the only one a
    /// caller may pull in, and only `deinit` moves a handle out of it.
    status: Status,

    /// Why `finish` may and may not be read.
    ///
    /// Three states rather than one flag, because two different questions are
    /// being asked: a stream that has run out of items is not a stream that has
    /// been released, and `deinit` has to be answerable in both cases and in
    /// neither twice.
    pub const Status = enum {
        /// Still has answers.
        live,
        /// Ran out. `finish` is readable; `deinit` is still owed.
        finished,
        /// Released. Every pull answers as if finished and `deinit` is a no-op,
        /// so a second `deinit` is a mistake that costs nothing.
        closed,
    };

    /// The four calls a service implements behind a stream, in the order
    /// `deinit` makes them.
    ///
    /// Each runs synchronously on the thread that called through `Stream` and
    /// returns before that call does; none of them runs after its own call has
    /// returned, so a service does not keep a pointer into them.
    pub const VTable = struct {
        /// One pull: the next answer, or null when the service has nothing
        /// more. Null moves the handle to `.finished`, which is what makes
        /// `finish` readable and what stops a second pull reaching the service.
        next: *const fn (state: *anyopaque) ?Event,
        /// How the service came to be finished, read once `next` has answered
        /// null. The items it hands back belong to the state and die with
        /// `deinit`.
        finish: *const fn (state: *anyopaque) item.Resolution,
        /// Tell the producer to stop. Called exactly once, by `deinit`, whether
        /// the stream was drained or abandoned.
        cancel: *const fn (state: *anyopaque) void,
        /// Release the state, with the `alloc` it was started with. Called
        /// exactly once, after `cancel`.
        destroy: *const fn (state: *anyopaque, alloc: std.mem.Allocator) void,
    };

    /// The next answer, or null when the service is finished, in which case this
    /// handle is `.finished` and `finish` may be read.
    ///
    /// A returned `Event.item` is the stream's own and is valid until `deinit`;
    /// a later pull does not disturb it. After `.finished` or `.closed` this
    /// answers null without reaching the service at all.
    pub fn next(self: *Stream) ?Event {
        if (self.status != .live) return null;
        const event = self.vtable.next(self.state);
        if (event == null) self.status = .finished;
        return event;
    }

    /// What the service came to, which is the only way a caller learns whether
    /// it resolved to nothing or had nothing to say for another reason.
    ///
    /// Readable only once `next` has answered null. The `Resolution.resolved`
    /// slice borrows the state, so it is read before `deinit` and is dead after
    /// it; a caller that needs it to outlive the stream has to copy it out.
    pub fn finish(self: *const Stream) item.Resolution {
        std.debug.assert(self.status == .finished);
        return self.vtable.finish(self.state);
    }

    // `.closed` is this stream's terminal state, and it is what `next` reads to
    // answer as finished after a close; the guard that skips an already-closed
    // stream is what makes a second `deinit` a no-op rather than a second
    // cancel of a retrieval that is already gone. Z030 recognises a fixed list
    // of terminal field names and `status` is not on it, so the write it cannot
    // see is here to be read.
    // ziglint-ignore: Z030
    /// Stop the work and release the state. Idempotent.
    ///
    /// The producer is told to stop exactly once, on every path, and a stream
    /// that already finished is told anyway: a service that has finished has
    /// nothing left to stop, and a `cancel` that is a no-op then is cheaper than
    /// a status check that could be got wrong.
    ///
    /// The state and every item in it are released here, so a `Resolution` read
    /// from `finish` and an `Event.item` from a pull are both dead afterwards.
    pub fn deinit(self: *Stream) void {
        if (self.status == .closed) return;
        self.status = .closed;
        self.vtable.cancel(self.state);
        self.vtable.destroy(self.state, self.alloc);
    }
};
