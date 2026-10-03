//! The address-lookup interface, the pull-based stream `resolve` hands back,
//! and the two pkarr services.
//!
//! Upstream, captured 2026-09-30 at n0-computer/iroh commit
//! 187f59e80afdae6bd9866002b33d3365c00b06d8 (`iroh` 1.3.0 as published): the
//! `AddressLookup` trait at `iroh/src/address_lookup.rs:335` with its two
//! default bodies at `:343` and `:349`, `PkarrPublisher` and `PkarrResolver` at
//! `iroh/src/address_lookup/pkarr.rs:357` and `:536`, and the `key=value` record
//! grammar at `iroh-dns/src/attrs.rs` and `iroh-dns/src/endpoint_info.rs`.
//!
//! Three things differ from upstream and each is one rule applied rather than
//! three decisions made.
//!
//! * The trait is a vtable, as `docs/ARCHITECTURE.md` records for
//!   `ProtocolHandler`. A vtable has no default method bodies, so upstream's two
//!   defaults are two function pointers any vtable may take:
//!   `AddressLookup.ignore_publish` and `AddressLookup.refuse_resolve`. The
//!   second is where "cannot resolve at all" comes from, and `PkarrPublisher`
//!   takes it — upstream's publisher implements no `resolve`, so asking one to
//!   resolve is answered with `None` and not with an empty stream.
//! * The stream is pulled. See `Stream`.
//! * Nothing here opens a socket. A service is handed the bytes an answer
//!   consists of, and a handle to the retrieval they came from, and the
//!   retrieval is the transport's business and is injected at construction.
//!   mDNS and the Mainline DHT are external crates upstream and are not in that
//!   tree; in ozai they are two more `VTable` values and nothing else, and
//!   nothing here would change to add either.
//!
//! One thing is deliberately absent: `AddressLookupServices`, upstream's fan-in
//! over many services (`iroh/src/address_lookup.rs:565`). M5 asks for three
//! implementations of one interface, and the merge that would sit on top of it
//! is `discovery/item.zig`'s `merge` and `order`, which are already total.

const std = @import("std");
const addr = @import("../base/addr.zig");
const item = @import("item.zig");

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
    /// is infinitely old to `Item.order`, so a publisher that declines to vouch
    /// loses every tie rather than winning one by accident.
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
/// The length is the test because an endpoint that never grew a list holds
/// `NodeAddr.init`'s empty literal rather than an allocation, and `free` of a
/// zero-length slice is not a call `std` accepts. `base/addr.zig` owns
/// `NodeAddr.deinit`; this is the one place in discovery that reaches past it,
/// and the empty list is a supported state rather than a mistake — a node that
/// published nothing is one of the answers `item.Resolution` names.
fn releaseTransfer(data: Published) void {
    if (data.endpoint.addrs.len == 0) return;
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
pub const Reason = DecodeError || ParseError || error{
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

/// The record name both services write under: `_iroh`.
///
/// `iroh-dns/src/attrs.rs`, `pub const IROH_TXT_NAME: &str = "_iroh";`. It is
/// here and not in `discovery/dns.zig` because it is the one thing a pkarr
/// packet and a DNS query have in common, and a publisher needs it too:
/// upstream's `TxtAttrs::to_pkarr_signed_packet` hands `IROH_TXT_NAME` to
/// `pkarr::SignedPacket::from_txt_strings`, same file.
pub const iroh_txt_name = "_iroh";

/// The three `iroh` TXT attributes.
///
/// Upstream's `IrohAttr` (`iroh-dns/src/attrs.rs`) declares `Relay`, `Addr`,
/// `UserData` with `#[strum(serialize_all = "kebab-case")]`, derives `Ord`, and
/// collects into a `BTreeMap`, so records come back out grouped in declaration
/// order however the packet or the answer listed them. The spellings are
/// upstream's: lower case, and `user-data` with a hyphen — "The resource record
/// uses the lower-case names", and `strum`'s generated match is exact.
pub const Attribute = enum {
    /// `relay=<url>`: the home relay.
    relay,
    /// `addr=<addr>`: an IP socket, or a custom transport address.
    addr,
    /// `user-data=<text>`.
    ///
    /// Read and discarded. Upstream keeps it on `EndpointData`; `item.Item` has
    /// nowhere to put it. Discarding is what keeps a real published record
    /// readable: refusing `user-data=` would fail every endpoint that publishes
    /// one, and an endpoint that cannot be found is worse than one whose note
    /// is lost.
    user_data,

    /// Every arm, for iteration. A test holds this against the enum, so an arm
    /// cannot be added without a spelling.
    pub const all = [_]Attribute{ .relay, .addr, .user_data };

    /// The attribute whose record key is `key_text`, or null when the key is not
    /// one of the three. The match is exact — `strum`'s generated `FromStr` is
    /// too — so a case-folded or hyphen-less key is an unknown key rather than
    /// a spelling of one of these.
    pub fn parse(key_text: []const u8) ?Attribute {
        inline for (all) |attribute| {
            if (std.mem.eql(u8, key_text, attribute.text())) return attribute;
        }
        return null;
    }

    /// The key this attribute is written under in a `key=value` record. A slice
    /// of a string literal, so it is valid for the life of the program.
    pub fn text(self: Attribute) []const u8 {
        return switch (self) {
            .relay => "relay",
            .addr => "addr",
            .user_data => "user-data",
        };
    }
};

/// A set of `key=value` records, in one borrowed buffer, separated by NUL.
///
/// Upstream takes `impl Iterator<Item = impl Display>`
/// (`iroh-dns/src/attrs.rs`, `from_txt_lookup` and `from_pkarr_signed_packet`),
/// because a DNS answer and a pkarr packet are different iterators over one
/// shape. A NUL-separated buffer is that shape with no allocation and no length
/// prefix, and it is the shape DNS already has: a TXT record's character strings
/// are NUL-free by construction, so a block of them is exactly this. A
/// publisher's output and a resolver's input are then the same value, which is
/// what makes a round trip a test rather than a conversion.
///
/// A `RecordSet` is a value with a position in it, so it is copied into whatever
/// reads it and never shared: two resolves against one service each get their
/// own, and neither can tread on the other's place in the buffer.
pub const RecordSet = struct {
    /// The NUL-separated records, borrowed from whoever holds the answer. A
    /// `RecordSet` owns none of them and has no `deinit`: the buffer has to
    /// outlive every read made through any copy of this set.
    bytes: []const u8,
    /// How far this copy has read, zero for a set nothing has read from. It is
    /// per-copy state rather than a property of the buffer, which is what lets
    /// two sets read one buffer from its start at the same time.
    at: usize = 0,

    /// A set over `bytes`, positioned at its first record.
    pub fn init(bytes: []const u8) RecordSet {
        return .{ .bytes = bytes };
    }

    /// The next record, or null at the end. A trailing NUL is not a record: the
    /// block is a list and not a counted sequence, so it may end with one or
    /// without.
    pub fn next(self: *RecordSet) ?[]const u8 {
        if (self.at >= self.bytes.len) return null;
        const end = std.mem.indexOfScalar(u8, self.bytes[self.at..], 0) orelse {
            const record = self.bytes[self.at..];
            self.at = self.bytes.len;
            return record;
        };
        const record = self.bytes[self.at..][0..end];
        self.at += end + 1;
        return record;
    }
};

/// Turn a set of records into the one `Item` they describe.
///
/// The node id arrives as an argument because upstream takes it from two
/// different places — a DNS name's second label for TXT, the packet's public key
/// for pkarr — and both call the same `TxtAttrs::from_strings` at the bottom of
/// `iroh-dns/src/attrs.rs`. This is that bottom, and it is the only place in the
/// tree that reads a record.
///
/// `last_updated` is null because it is null upstream: `AddressLookupItem::new`
/// is called with `None` by both services (`iroh/src/address_lookup/dns.rs`,
/// `iroh/src/address_lookup/pkarr.rs:546`). A timestamp would be something the
/// publisher knew and the reader did not, and inventing one on the reading side
/// would put a value into the order that no two services could ever agree on.
///
/// # What the result owns, and what a caller has to release
///
/// Everything the result owns comes from `alloc`: the address list, and the
/// bytes behind every `addr=<custom>` value. The second one is not optional.
/// `addr.CustomAddr.data` borrows — `CustomAddr.parse` needs storage for the
/// inline data and `NodeAddr.insert` copies the slice header, not the bytes it
/// points at — so the bytes are copied out here, and that copy has to outlive
/// the item.
///
/// So `alloc` has to outlive the item, and `NodeAddr.deinit` releases the
/// address list and nothing else, because a `NodeAddr` has no field for the
/// payloads. On the success path the item owns both: a caller that holds it in
/// an arena gets both back from one `arena.deinit`, which is what both
/// resolvers below do, and a caller that does not has to walk `addrs` and free
/// each custom address's `data` itself. This is invariant 6 read from the
/// other end: the value never carries a slice into storage it does not own, and
/// where it cannot own it, the owner is named.
///
/// On either error nothing survives: the address list and every payload copied
/// before the failing record are released before the error leaves, and no
/// record after it is read. There is no partial item to clean up, and `alloc` is
/// back to what it was on entry.
///
/// Upstream's three rules, all three load-bearing:
///
/// * `s.split('=')` and take the first two pieces, so a value runs from the
///   first `=` to the *second* and everything after the second is dropped. A
///   relay URL carrying a query does not survive it. That is upstream's
///   behaviour and not something to fix here, because a fix would make ozai's
///   reader disagree with every other one.
/// * A record that does not split, or a key that is not one of the three, fails
///   the whole lookup. Upstream returns `Err` and the resolve yields an error
///   rather than a partial answer.
/// * A value that does not parse is dropped and the rest of the set is kept, by
///   `filter_map` in `endpoint_info_from_attrs`. Upstream loses a bad address
///   and keeps the good ones, and a reader that failed instead would hand back
///   nothing at all, which is the one outcome a caller cannot act on.
pub fn parseTxt(
    alloc: std.mem.Allocator,
    node_id: addr.NodeId,
    records: RecordSet,
    provenance: item.Provenance,
) ParseError!item.Item {
    var set = records;
    var endpoint = addr.NodeAddr.init(node_id);
    // The address list, when there is one to release: `NodeAddr.init` hands back
    // an empty literal rather than an allocation, and `free` of a zero-length
    // slice is not a call `std` accepts. `releaseTransfer` says the same about
    // the publishing side, for the same reason.
    errdefer if (endpoint.addrs.len != 0) endpoint.deinit(alloc);
    // Every custom address data buffer copied out so far, so the error path can
    // hand them all back. `NodeAddr.deinit` frees the address list and nothing
    // else, so a buffer that only an earlier record allocated has no owner left
    // to free it once the item is discarded. On the success path the list is
    // dropped without freeing, because by then the buffers belong to the item.
    var owned: std.ArrayList([]u8) = .empty;
    errdefer {
        for (owned.items) |bytes| alloc.free(bytes);
        owned.deinit(alloc);
    }
    while (set.next()) |record| {
        const separator = std.mem.indexOfScalar(u8, record, '=') orelse
            return error.MalformedRecord;
        const key_text = record[0..separator];
        const after = record[separator + 1 ..];
        const value_end = std.mem.indexOfScalar(u8, after, '=') orelse after.len;
        const attribute = Attribute.parse(key_text) orelse return error.MalformedRecord;
        const value = after[0..value_end];
        switch (attribute) {
            .relay => {
                const url = addr.RelayUrl.parse(value) catch continue;
                // A duplicate is not a failure: `insert` reports one by
                // returning null and upstream dedups too, in
                // `EndpointData::new`. Only the error is an error.
                endpoint = (try endpoint.insert(alloc, .{ .relay = url })) orelse endpoint;
            },
            .addr => {
                // Upstream tries `SocketAddr::from_str` and then
                // `CustomAddr::from_str`, dropping the record if neither takes
                // it. The socket parse is `std`'s, because a socket address on
                // a wire is Rust's `SocketAddr` text and nothing else — see
                // `writeSocketAddr` for the other direction.
                if (std.Io.net.IpAddress.parseLiteral(value)) |literal| {
                    const grown = try endpoint.insert(alloc, .{ .ip = socketOf(literal) });
                    endpoint = grown orelse endpoint;
                } else |_| {
                    var storage: [addr.max_inline_length]u8 = undefined;
                    const custom = addr.CustomAddr.parse(value, &storage) catch continue;
                    // `CustomAddr.data` borrows `storage`, which dies at the end
                    // of this block, and `NodeAddr.insert` copies the slice
                    // header rather than the bytes it points at. So the bytes
                    // are copied out here, from `alloc`, and that copy has to
                    // outlive the item — which is the rule `parseTxt` states
                    // about its allocator.
                    const data = try alloc.dupe(u8, custom.data);
                    // Recorded before the address is inserted, and not after,
                    // because recording it can fail and the insert is what makes
                    // the item refer to the copy. Appending first means every
                    // later path out of here frees the copy through `owned`,
                    // where the error path walks it; the other order handed back
                    // an item holding a buffer that nothing owned as soon as
                    // this append failed. The one path the tracker cannot cover
                    // is this one, and it frees the copy itself.
                    owned.append(alloc, data) catch {
                        alloc.free(data);
                        return error.OutOfMemory;
                    };
                    const grown = endpoint.insert(alloc, .{
                        .custom = .{ .id = custom.id, .data = data },
                    }) catch return error.OutOfMemory;
                    if (grown) |next| {
                        endpoint = next;
                    } else {
                        // Already present, so nothing refers to the copy, and it
                        // is the last thing `owned` recorded: popping it is the
                        // whole of taking it back.
                        alloc.free(owned.pop().?);
                    }
                }
            },
            .user_data => {},
        }
    }
    owned.deinit(alloc);
    return item.Item.init(endpoint, provenance, null);
}

/// `std.Io.net.IpAddress` to `addr.SocketAddr`.
fn socketOf(literal: std.Io.net.IpAddress) addr.SocketAddr {
    return switch (literal) {
        .ip4 => |address| .{ .ip = .{ .v4 = address.bytes }, .port = address.port },
        .ip6 => |address| .{ .ip = .{ .v6 = address.bytes }, .port = address.port },
    };
}

/// `addr.SocketAddr` to the text an `addr=` record carries.
///
/// `std`'s, and not `addr.SocketAddr.format`, and the reason is worth writing
/// down because the two differ: `base/addr.zig` renders an IPv6 address as bare
/// lower-case hex, which is this project's own canonical display form for logs
/// and tickets, and it is *not* what a peer or a DNS record carries. Upstream
/// writes `addr.to_string()` on a `std::net::SocketAddr` and reads it with
/// `SocketAddr::from_str` (`iroh-dns/src/endpoint_info.rs`), and `std`'s
/// `IpAddress` parser and formatter are the same text on both sides of that
/// pair — brackets, `::` compression, `::ffff:` for a mapped address and all.
pub fn writeSocketAddr(socket: addr.SocketAddr, writer: *std.Io.Writer) std.Io.Writer.Error!void {
    const literal: std.Io.net.IpAddress = switch (socket.ip) {
        .v4 => |bytes| .{ .ip4 = .{ .bytes = bytes, .port = socket.port } },
        .v6 => |bytes| .{ .ip6 = .{ .bytes = bytes, .port = socket.port } },
    };
    return literal.format(writer);
}

/// Why a publisher could not write its records.
pub const EncodeError = error{
    /// `out` is smaller than `maxTxtStringsLength` for the address list. The
    /// only way a fixed writer fails is a full buffer, so a write failure and a
    /// buffer the caller sized too small are one event.
    BufferTooSmall,
    /// `publish` has not been called, so there is nothing to write.
    NothingPublished,
};

/// Longest single `key=value` record, being the relay arm: `relay=`, the
/// longest scheme `https://`, a 253-byte host, a five-digit port, and the
/// trailing `/` invariant 4 requires. The other two arms are far shorter —
/// `addr=` with either 21 bytes of IPv4 or 39 of IPv6, or 77 bytes of custom id
/// and data — and the relay arm is the one that has to be right.
pub const max_record_length = 6 + 8 + addr.RelayUrl.max_host_length + 1 + 5 + 1;

/// Buffer size `PkarrPublisher.writeTxtStrings` needs for this many addresses,
/// separators included. The encoding has no fixed length, because the address
/// list has none, so the caller sizes the buffer and owns it.
pub fn maxTxtStringsLength(addrs: usize) usize {
    return addrs * (max_record_length + 1);
}

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
    txt: RecordSet,
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
    decode: *const fn (ctx: *anyopaque, packet: []const u8) DecodeError!Packet,
    /// The answers, already retrieved, concatenated and NUL-separated. The
    /// first NUL ends one packet and the second starts the next, which is why
    /// each answer is a whole signed packet and a packet may hold several
    /// `_iroh` records of its own.
    ///
    /// Borrowed, and read from the position this value holds: a resolver copies
    /// it per resolve so two streams cannot tread on each other's place in the
    /// buffer, but both copies point at the same bytes, which therefore have to
    /// stay valid and unchanged until the last of those streams is closed.
    answers: RecordSet,
    /// How to stop the retrieval. Null when there was none — an answer set read
    /// out of a file has nothing to cancel — and a stream with a null one still
    /// runs and still frees; it simply tells nobody to stop. Non-null is fired
    /// exactly once per stream, from `Stream.deinit`, so the handle it points at
    /// has to outlive every stream started here.
    cancellation: ?Cancellation,
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
    stored: ?Published,
    /// Borrowed by every `AddressLookup` handed out of `lookup`.
    vtable: AddressLookup.VTable = publisher_vtable,

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
        if (self.stored) |data| releaseTransfer(data);
        self.stored = null;
    }

    /// A handle onto this publisher. Borrowed, so the publisher has to outlive
    /// every handle taken of it and every publish made through one.
    pub fn lookup(self: *PkarrPublisher) AddressLookup {
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
    pub fn writeTxtStrings(self: *const PkarrPublisher, out: []u8) EncodeError![]const u8 {
        const stored = self.stored orelse return error.NothingPublished;
        var writer = std.Io.Writer.fixed(out);
        for (stored.endpoint.addrs) |value| {
            // One record at a time, into a scratch buffer, and copied out with
            // its separator. The separator goes *between* records, and a `for`
            // body is the only place that knows where one record ends; writing
            // it here also means `max_record_length` is a bound this loop
            // actually relies on rather than one it hopes for.
            var scratch: [max_record_length]u8 = undefined;
            var line = std.Io.Writer.fixed(&scratch);
            switch (value) {
                .relay => |url| {
                    line.writeAll("relay=") catch return error.BufferTooSmall;
                    url.format(&line) catch return error.BufferTooSmall;
                },
                .ip => |socket| {
                    line.writeAll("addr=") catch return error.BufferTooSmall;
                    writeSocketAddr(socket, &line) catch return error.BufferTooSmall;
                },
                .custom => |custom| {
                    line.writeAll("addr=") catch return error.BufferTooSmall;
                    custom.format(&line) catch return error.BufferTooSmall;
                },
            }
            writer.writeAll(line.buffered()) catch return error.BufferTooSmall;
            writer.writeAll("\x00") catch return error.BufferTooSmall;
        }
        return writer.buffered();
    }
};

const publisher_vtable: AddressLookup.VTable = .{
    .publish = publisherPublish,
    .resolve = AddressLookup.refuse_resolve,
};

fn publisherPublish(ctx: *anyopaque, data: Published) void {
    const self: *PkarrPublisher = @ptrCast(@alignCast(ctx));
    // The slot is replaced, not appended to, which is upstream's
    // `watchable.set`: a publisher's job is to say what this node is reachable
    // at *now*, and an address the endpoint has since stopped using is not a
    // second opinion, it is stale.
    // Released with the allocator that slot arrived with, not with one of this
    // publisher's: whoever published last built that list, and a publisher has
    // no allocator of its own to release it with.
    if (self.stored) |previous| releaseTransfer(previous);
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
    vtable: AddressLookup.VTable = resolver_vtable,

    /// A resolver over one already-retrieved answer set.
    pub fn init(source: PacketSource) PkarrResolver {
        return .{ .source = source };
    }

    /// A handle onto this resolver. Borrowed, so the resolver has to outlive
    /// every stream started through the handle.
    pub fn lookup(self: *PkarrResolver) AddressLookup {
        return .{ .vtable = &self.vtable, .ctx = @ptrCast(@alignCast(self)) };
    }
};

const resolver_vtable: AddressLookup.VTable = .{
    .publish = AddressLookup.ignore_publish,
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
    answers: RecordSet,
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
) ResolveError!?Stream {
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

const pkarr_stream_vtable: Stream.VTable = .{
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
fn pkarrNext(state: *anyopaque) ?Event {
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
    const value = parseTxt(self.alloc, packet.node_id, packet.txt, .pkarr) catch |reason| {
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

fn failed(provenance: item.Provenance, reason: Reason) Event {
    return .{ .failed = .{ .provenance = provenance, .reason = reason } };
}

const t = std.testing;
const key = @import("../base/key.zig");

/// A node id from a fixed seed. A resolver hands out real keys and a `NodeId`
/// cannot be made from arbitrary bytes, so a corpus draws from seeds.
fn corpusId(seed: u8) !addr.NodeId {
    var bytes: [key.SecretKey.seed_length]u8 = undefined;
    @memset(&bytes, seed);
    return (try key.SecretKey.fromSeed(bytes)).nodeId();
}

/// The three record strings and the node id of upstream's own
/// `test_from_txt_lookup`, copied from `iroh-dns/src/endpoint_info.rs` at
/// 187f59e80afdae6bd9866002b33d3365c00b06d8. Captured bytes and not invented:
/// all three strings and the 64-character id are that test's own literals.
const upstream_records = "addr=192.168.96.145:60165\x00" ++
    "addr=213.208.157.87:60165\x00" ++
    "relay=https://euw1-1.relay.iroh.network./\x00";
const upstream_id = "1992d53c02cdc04566e5c0edb1ce83305cd550297953a047a445ea3264b54b18";

/// A stand-in for `discovery/pkarr.zig`: signed bytes to a `Packet`, in answer
/// order, and a counter standing in for the retrieval. Those are exactly the
/// two seams `PacketSource` names, so a resolver wired to this exercises the
/// same interface a real one does, and the counter is what makes a cancellation
/// observable rather than merely asserted.
const FakeRelay = struct {
    /// NUL-separated, because each answer is a whole signed packet and a
    /// packet may hold several `_iroh` records of its own.
    answers: []const u8,
    packets: []const Packet,
    /// Which answer is being decoded, so a second call gets the next packet the
    /// way a real source reading a fresh answer set does.
    cursor: usize = 0,
    /// Fired once per `Stream.deinit`. This is the assertion invariant 13 is
    /// really about, and it lives outside the resolver on purpose.
    cancels: u32 = 0,
    /// The only bytes this fake accepts. Anything else is a malformed packet,
    /// which is how a resolver's decode-failure path gets exercised.
    good: []const u8 = "signed",

    fn decode(ctx: *anyopaque, packet: []const u8) DecodeError!Packet {
        const self: *FakeRelay = @ptrCast(@alignCast(ctx));
        if (!std.mem.eql(u8, packet, self.good)) return error.MalformedPacket;
        const at = self.cursor;
        self.cursor += 1;
        if (at >= self.packets.len) return error.MalformedPacket;
        return self.packets[at];
    }

    fn stop(ctx: *anyopaque) void {
        const self: *FakeRelay = @ptrCast(@alignCast(ctx));
        self.cancels += 1;
    }

    fn source(self: *FakeRelay) PacketSource {
        return .{
            .ctx = @ptrCast(@alignCast(self)),
            .decode = decode,
            .answers = .init(self.answers),
            .cancellation = .{ .ctx = @ptrCast(@alignCast(self)), .stop = stop },
        };
    }
};

test "a publisher cannot resolve, which is not a failure" {
    var publisher = PkarrPublisher.init();
    defer publisher.deinit();
    // Upstream's publisher implements `publish` and no `resolve`
    // (`iroh/src/address_lookup/pkarr.rs:357`), so a resolve is the trait
    // default's `None`: the service will not answer, as against a service that
    // answered and had nothing. No work was started, so there is nothing to
    // cancel either, and no error to log.
    try t.expect((try publisher.lookup().resolve(t.allocator, try corpusId(1))) == null);
}

test "a publisher that has published nothing writes nothing" {
    var publisher = PkarrPublisher.init();
    defer publisher.deinit();
    // `published` is null and `writeTxtStrings` says so rather than handing
    // back an empty record set, which a reader would take for a node that has
    // published nothing. One slot, two answers, and the second one is not
    // "there is nothing here yet".
    try t.expect(publisher.published() == null);
    var buffer: [maxTxtStringsLength(1)]u8 = undefined;
    try t.expectError(error.NothingPublished, publisher.writeTxtStrings(&buffer));
}

test "a publish nobody wanted still released what it was handed" {
    // The other end of the transfer. Every resolver in the tree takes
    // `ignore_publish`, so this is the shape a caller publishes into when the
    // service it chose does not publish: nothing was published, and nothing is
    // left over for the caller to release either, because the address list
    // arrived with the allocator that built it. `t.allocator` names the leak at
    // the end of the test, so a `publish` that dropped the value on the floor
    // fails here without needing an assertion of its own.
    const id = try corpusId(3);
    var relay: FakeRelay = .{ .answers = "", .packets = &.{} };
    var resolver = PkarrResolver.init(relay.source(null));

    resolver.lookup().publish(.{
        .alloc = t.allocator,
        .endpoint = try addr.NodeAddr.withRelay(
            t.allocator,
            id,
            try addr.RelayUrl.parse("https://relay.example./"),
        ),
        .last_updated = null,
    });
    // The publication changed nothing about the service: it resolves as it did,
    // which is the whole of what publishing into a resolver means.
    var stream = (try resolver.lookup().resolve(t.allocator, id)) orelse
        return error.TestUnexpectedResult;
    try t.expect(stream.next() == null);
    try t.expect(stream.finish().isEmptyResult());
    stream.deinit();
}

test "a publisher releases the slot it replaces with the allocator that made it" {
    // Two publications, two allocators, and the second replaces the first. A
    // publisher holds no allocator of its own, so this is only correct because
    // each `Published` carries the one its list came from: releasing the first
    // slot with the second's would hand an arena's bytes to a testing allocator
    // that never allocated them, and the run would stop inside `free` rather
    // than at an assertion here.
    const id = try corpusId(4);
    // Declared before the publisher, so `deinit` empties the slot while the
    // arena is still there. That order is the obligation `Published` states for
    // a caller, and a test that got it wrong would free into a dead arena.
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    var publisher = PkarrPublisher.init();
    defer publisher.deinit();

    publisher.lookup().publish(.{
        .alloc = arena.allocator(),
        .endpoint = try addr.NodeAddr.withRelay(
            arena.allocator(),
            id,
            try addr.RelayUrl.parse("https://one.example./"),
        ),
        .last_updated = 1,
    });
    publisher.lookup().publish(.{
        .alloc = t.allocator,
        .endpoint = try addr.NodeAddr.withRelay(
            t.allocator,
            id,
            try addr.RelayUrl.parse("https://two.example./"),
        ),
        .last_updated = 2,
    });

    // The slot is the second publication and the first is gone: an address the
    // endpoint has since stopped using is stale, not a second opinion.
    const stored = publisher.published() orelse return error.TestUnexpectedResult;
    try t.expectEqual(@as(?u64, 2), stored.last_updated);
    try t.expectEqual(@as(usize, 1), stored.endpoint.addrs.len);
    try t.expectEqual(
        try addr.RelayUrl.parse("https://two.example./"),
        stored.endpoint.addrs[0].relay,
    );

    // A third publication replaces that one, and `deinit` releases this one on
    // the way out — the release a replaced slot never gets to make.
    publisher.lookup().publish(.{
        .alloc = t.allocator,
        .endpoint = try addr.NodeAddr.withRelay(
            t.allocator,
            id,
            try addr.RelayUrl.parse("https://three.example./"),
        ),
        .last_updated = 3,
    });
}

test "cannot resolve and resolved to nothing are different answers" {
    const id = try corpusId(1);

    // A service that will not answer at all. There is no `Resolution` in hand
    // afterwards, and the absence is the whole point: there is no value a caller
    // could mistake for an empty one.
    var publisher = PkarrPublisher.init();
    defer publisher.deinit();
    try t.expect((try publisher.lookup().resolve(t.allocator, id)) == null);

    // A service that was asked, ran, and had nothing to say. The answer set is
    // empty because the relay answered with no packets, which is a real state of
    // the world: a node that has published nothing.
    var relay: FakeRelay = .{
        .answers = "",
        .packets = &.{},
    };
    var resolver = PkarrResolver.init(relay.source());
    var stream = (try resolver.lookup().resolve(t.allocator, id)) orelse
        return error.TestUnexpectedResult;
    defer stream.deinit();
    try t.expect(stream.next() == null);

    const nothing = stream.finish();
    try t.expectEqual(@as(?usize, 0), nothing.itemCount());
    try t.expect(nothing.isEmptyResult());
    // `Resolution.cannot_resolve` as a value and not as an enum member: a
    // tagged union has no member to name on the type.
    const cannot: item.Resolution = .cannot_resolve;
    try t.expectEqual(@as(?usize, null), cannot.itemCount());
    try t.expect(!cannot.isEmptyResult());
}

test "dropping a stream stops the work behind it" {
    const id = try corpusId(3);
    var relay: FakeRelay = .{
        .answers = "signed\x00signed\x00",
        .packets = &.{
            .{ .node_id = id, .txt = .init("relay=https://relay.example./\x00") },
            .{ .node_id = id, .txt = .init("addr=127.0.0.1:1234\x00") },
        },
    };
    var resolver = PkarrResolver.init(relay.source());

    // Abandoned part-drained, with a second answer still waiting: the case a
    // future-driven stream gets wrong, because nothing in the caller's control
    // has to happen for the work behind it to keep going.
    var stream = (try resolver.lookup().resolve(t.allocator, id)) orelse
        return error.TestUnexpectedResult;
    try t.expect(stream.next() != null);
    // Nothing has been told to stop yet, and saying so is the half of the
    // assertion that makes the other half mean anything.
    try t.expectEqual(@as(u32, 0), relay.cancels);
    stream.deinit();
    try t.expectEqual(@as(u32, 1), relay.cancels);
}

test "a drained stream is cancelled exactly once too" {
    const id = try corpusId(3);
    var relay: FakeRelay = .{
        .answers = "signed\x00",
        .packets = &.{.{ .node_id = id, .txt = .init("relay=https://relay.example./\x00") }},
    };
    var resolver = PkarrResolver.init(relay.source());
    var stream = (try resolver.lookup().resolve(t.allocator, id)) orelse
        return error.TestUnexpectedResult;
    try t.expect(stream.next() != null);
    try t.expect(stream.next() == null);
    try t.expectEqual(@as(?usize, 1), stream.finish().itemCount());
    // A finished service has nothing left to stop, so a `cancel` that is a
    // no-op now is what makes "on every path" true rather than aspirational.
    stream.deinit();
    try t.expectEqual(@as(u32, 1), relay.cancels);
    // Idempotent, because a second `deinit` is a caller mistake that must not
    // also be a double free.
    stream.deinit();
    try t.expectEqual(@as(u32, 1), relay.cancels);
}

test "a resolver with no retrieval in flight still runs and still frees" {
    // `cancellation` is null when the answers were not fetched here. Upstream's
    // pkarr and DNS lookups are both in-flight fetches, so null is a
    // stored-answer-set shape rather than the production one, and it has to
    // work because that is how a cache is read back.
    const id = try corpusId(4);
    var relay: FakeRelay = .{
        .answers = "signed\x00",
        .packets = &.{.{ .node_id = id, .txt = .init("addr=127.0.0.1:1234\x00") }},
    };
    var resolver = PkarrResolver.init(.{
        .ctx = @ptrCast(@alignCast(&relay)),
        .decode = FakeRelay.decode,
        .answers = .init("signed\x00"),
        .cancellation = null,
    });
    var stream = (try resolver.lookup().resolve(t.allocator, id)) orelse
        return error.TestUnexpectedResult;
    try t.expect(stream.next() != null);
    try t.expect(stream.next() == null);
    try t.expectEqual(@as(?usize, 1), stream.finish().itemCount());
    stream.deinit();
    // Nothing was told to stop, because there was nothing to stop. The counter
    // belongs to the fake and the fake's handle is null, so this is the
    // complement of the cancellation tests rather than a repeat of them.
    try t.expectEqual(@as(u32, 0), relay.cancels);
}

test "the attribute set is upstream's three, spelled upstream's way" {
    // `IrohAttr` in `iroh-dns/src/attrs.rs`: three arms, `kebab-case`, and
    // "The resource record uses the lower-case names".
    try t.expectEqual(@as(usize, 3), Attribute.all.len);
    // `all` is what `parse` iterates. An arm missing from it would be
    // unreadable and unwritable, so the list is held to the enum here.
    try t.expectEqual(Attribute.all.len, @typeInfo(Attribute).@"enum".fields.len);
    try t.expectEqualStrings("relay", Attribute.relay.text());
    try t.expectEqualStrings("addr", Attribute.addr.text());
    try t.expectEqualStrings("user-data", Attribute.user_data.text());
    // Every arm round trips through its own spelling, which is the only thing
    // `parse` has to get right: a spelling that did not would make a record
    // some other client wrote unreadable here.
    inline for (Attribute.all) |attribute| {
        try t.expectEqual(attribute, Attribute.parse(attribute.text()).?);
    }
    // The match is exact. `strum`'s generated `FromStr` is exact too, so a
    // case-folded record is a failed record and not a read one — and
    // `userdata` is not `user-data`, which is the mistake worth pinning.
    try t.expect(Attribute.parse("RELAY") == null);
    try t.expect(Attribute.parse("userdata") == null);
    try t.expect(Attribute.parse("") == null);
}

test "upstream's own records parse to the endpoint upstream says" {
    const id = try key.NodeId.parseHex(upstream_id);
    const value = try parseTxt(t.allocator, id, .init(upstream_records), .dns);
    defer value.endpoint.deinit(t.allocator);

    // Upstream's expected `EndpointInfo` from the same test: one relay URL and
    // two sockets, no user data. `NodeAddr` is sorted, and the sorted order is
    // relay, then IPv4 by address, which is the order the test lists them in.
    try t.expectEqual(@as(usize, 3), value.endpoint.addrs.len);
    try t.expectEqual(
        try addr.RelayUrl.parse("https://euw1-1.relay.iroh.network./"),
        value.endpoint.addrs[0].relay,
    );
    try t.expectEqual(
        addr.SocketAddr{ .ip = .{ .v4 = .{ 192, 168, 96, 145 } }, .port = 60165 },
        value.endpoint.addrs[1].ip,
    );
    try t.expectEqual(
        addr.SocketAddr{ .ip = .{ .v4 = .{ 213, 208, 157, 87 } }, .port = 60165 },
        value.endpoint.addrs[2].ip,
    );
    // Upstream passes `None` for the timestamp on both services, so a reader
    // never stamps one and the order falls through to the encoded bytes.
    try t.expectEqual(@as(?u64, null), value.last_updated);
    try t.expectEqual(item.Provenance.dns, value.provenance);
}

test "a value ends at the second equals sign, as upstream's split does" {
    // `iroh-dns/src/attrs.rs`, `from_strings`: `let mut parts = s.split('=')`
    // and then the first two pieces, so the value of `a=b=c` is `b` and `c` is
    // gone. The records below are built to exercise that rule; they are not
    // captured ones, and nothing here claims they are.
    const value = try parseTxt(
        t.allocator,
        try corpusId(5),
        .init("addr=127.0.0.1:1234=9\x00user-data=a=b\x00"),
        .pkarr,
    );
    defer value.endpoint.deinit(t.allocator);
    try t.expectEqual(@as(usize, 1), value.endpoint.addrs.len);
    try t.expectEqual(
        addr.SocketAddr{ .ip = .{ .v4 = .{ 127, 0, 0, 1 } }, .port = 1234 },
        value.endpoint.addrs[0].ip,
    );
}

test "an unknown key fails the whole record set" {
    // `ParseError::AttrFromString` upstream: `T::from_str(key).map_err(..)`
    // returns `Err`, so one key that is not one of the three takes the good
    // records with it. That is what makes a typo in a publisher visible instead
    // of silent.
    const id = try corpusId(5);
    try t.expectError(error.MalformedRecord, parseTxt(
        t.allocator,
        id,
        .init("relay=https://relay.example./\x00hostname=x\x00"),
        .dns,
    ));
    // A record with no `=` is `ParseError::UnexpectedFormat`, and an empty key
    // is the same arm of it.
    try t.expectError(error.MalformedRecord, parseTxt(
        t.allocator,
        id,
        .init("relay=https://relay.example./\x00nonsense\x00"),
        .dns,
    ));
}

test "a value that will not parse is dropped and the rest is kept" {
    // `filter_map(|s| Url::parse(s).ok())` upstream: a relay URL that is not a
    // URL is a dropped record, not a failed lookup. Same for an address of no
    // known shape.
    const value = try parseTxt(
        t.allocator,
        try corpusId(5),
        .init("relay=not a url\x00addr=999.1.1.1:1\x00relay=https://relay.example./\x00"),
        .dns,
    );
    defer value.endpoint.deinit(t.allocator);
    try t.expectEqual(@as(usize, 1), value.endpoint.addrs.len);
    try t.expectEqual(
        try addr.RelayUrl.parse("https://relay.example./"),
        value.endpoint.addrs[0].relay,
    );
}

test "a custom payload is released however the record fails" {
    // Three allocations stand between this record and the item: the payload
    // copy, the tracker that records it, and the growth of the address list.
    // The middle one is the one that used to be missed — the copy went into the
    // address list first and was recorded afterwards, so a failure in the
    // recording handed back an item holding a buffer no path owned. Each probe
    // fails one of the two later allocations by index, and `t.allocator` names
    // the leak at the end of the test, so both are green only when the copy is
    // released on each of those paths.
    const id = try corpusId(6);
    const records: RecordSet = .init("addr=1_a1b2c3\x00");

    var recording = t.FailingAllocator.init(t.allocator, .{ .fail_index = 1 });
    try t.expectError(error.OutOfMemory, parseTxt(recording.allocator(), id, records, .pkarr));

    var growing = t.FailingAllocator.init(t.allocator, .{ .fail_index = 2 });
    try t.expectError(error.OutOfMemory, parseTxt(growing.allocator(), id, records, .pkarr));

    // The success path still owns what the contract says it does: the payload is
    // the caller's to release, because `NodeAddr.deinit` frees the address list
    // and nothing else. Reading it here is the other half of that sentence — an
    // item that copied the bytes out and then lost track of them would fail on
    // the leak check above and never reach this.
    const value = try parseTxt(t.allocator, id, records, .pkarr);
    try t.expectEqual(@as(usize, 1), value.endpoint.addrs.len);
    for (value.endpoint.addrs) |one| {
        if (one == .custom) t.allocator.free(one.custom.data);
    }
    value.endpoint.deinit(t.allocator);
}

test "a packet signed for another node is reported, not returned" {
    // Upstream takes the id from the packet and hands it on
    // (`from_pkarr_signed_packet`), so a relay answering a query for one node
    // with another's record is obeyed. ozai reports it instead.
    const id = try corpusId(7);
    const other = try corpusId(8);
    var relay: FakeRelay = .{
        .answers = "signed\x00signed\x00",
        .packets = &.{
            .{ .node_id = other, .txt = .init("relay=https://elsewhere.example./\x00") },
            .{ .node_id = id, .txt = .init("relay=https://relay.example./\x00") },
        },
    };
    var resolver = PkarrResolver.init(relay.source());
    var stream = (try resolver.lookup().resolve(t.allocator, id)) orelse
        return error.TestUnexpectedResult;
    defer stream.deinit();

    const first = stream.next() orelse
        return error.TestUnexpectedResult;
    try t.expectEqual(error.UnexpectedSigner, first.failed.reason);
    try t.expectEqual(item.Provenance.pkarr, first.failed.provenance);
    // The failure did not end the stream, so the packet that *was* signed for
    // this node still arrives behind it.
    const second = stream.next() orelse
        return error.TestUnexpectedResult;
    try t.expectEqual(id, second.item.endpoint.node_id);
    try t.expect(stream.next() == null);
    try t.expectEqual(@as(?usize, 1), stream.finish().itemCount());
}

test "a packet that will not decode fails one answer and not the stream" {
    const id = try corpusId(7);
    var relay: FakeRelay = .{
        .answers = "garbage\x00signed\x00",
        .packets = &.{.{ .node_id = id, .txt = .init("relay=https://relay.example./\x00") }},
    };
    var resolver = PkarrResolver.init(relay.source());
    var stream = (try resolver.lookup().resolve(t.allocator, id)) orelse
        return error.TestUnexpectedResult;
    defer stream.deinit();

    const first = stream.next() orelse
        return error.TestUnexpectedResult;
    try t.expectEqual(error.MalformedPacket, first.failed.reason);
    const second = stream.next() orelse
        return error.TestUnexpectedResult;
    try t.expectEqual(id, second.item.endpoint.node_id);
    try t.expect(stream.next() == null);
}

test "published records read back as the address that was published" {
    const id = try corpusId(7);
    var publisher = PkarrPublisher.init();
    defer publisher.deinit();

    // Three families, so the loop that writes one record per address is walked
    // in all three, and the v6 and custom arms are the ones whose text form is
    // not this project's own display form.
    var endpoint = addr.NodeAddr.init(id);
    for ([_]addr.TransportAddr{
        .{ .relay = try addr.RelayUrl.parse("https://relay.example./") },
        .{ .ip = .{ .ip = .{ .v4 = .{ 192, 0, 2, 7 } }, .port = 7842 } },
        .{ .ip = .{ .ip = .{ .v6 = .{
            0xfd, 0x15, 0x07, 0x0a, 0x51, 0x0b, 0, 0,
            0,    0,    0,    0,    0,    0,    0, 1,
        } }, .port = 12345 } },
        .{ .custom = .{ .id = 1, .data = &.{ 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6 } } },
    }) |value| {
        if (try endpoint.insert(t.allocator, value)) |grown| endpoint = grown;
    }
    publisher.lookup().publish(.{
        .alloc = t.allocator,
        .endpoint = endpoint,
        .last_updated = 7,
    });

    var buffer: [maxTxtStringsLength(4)]u8 = undefined;
    const records = try publisher.writeTxtStrings(&buffer);

    // The custom address is upstream's `txt_attr_roundtrip_with_custom_addr`
    // `bt_addr`, whose text form `iroh-base/src/endpoint_addr.rs` writes as
    // `write!(f, "{:x}_{}", self.id, HEXLOWER.encode(self.data.as_bytes()))`.
    try t.expect(std.mem.indexOf(u8, records, "addr=1_a1b2c3d4e5f6\x00") != null);
    // The relay text is `url::Url`'s `Display`: scheme, host, no port for the
    // default, and a `/` path. That is the shape invariant 4 pins, so the two
    // rules agree and a published relay is readable by any other client.
    try t.expect(std.mem.indexOf(u8, records, "relay=https://relay.example./\x00") != null);
    // The reader's copy of the custom address data has to outlive the item, so
    // the read side gets the arena `parseTxt` asks for. The published side
    // borrows, because the data here is a string literal in the test.
    var arena = std.heap.ArenaAllocator.init(t.allocator);
    defer arena.deinit();
    const read = try parseTxt(arena.allocator(), id, .init(records), .pkarr);
    defer read.endpoint.deinit(arena.allocator());
    const stored = publisher.published() orelse
        return error.TestUnexpectedResult;
    try t.expectEqual(stored.endpoint.node_id, read.endpoint.node_id);
    try t.expectEqual(stored.endpoint.addrs.len, read.endpoint.addrs.len);
    for (stored.endpoint.addrs, read.endpoint.addrs) |left, right| {
        // `order` and not `==`: a `TransportAddr` holds a slice, and the two
        // were built from two different buffers.
        try t.expectEqual(std.math.Order.eq, left.order(right));
    }
    // A published record carries no timestamp, so the reader cannot recover the
    // one the publisher held. That is upstream's shape too, and it is why
    // `Item.order` falls through to the encoded bytes for every item any
    // resolver produces.
    try t.expectEqual(@as(?u64, null), read.last_updated);
}

test "resolver output is what merge and order are for" {
    // Two services and three items, none of which a test built for the purpose
    // of being ordered: two come out of the pkarr resolver's stream and one out
    // of upstream's captured records. The total order is exercised through what
    // the services produced.
    const dns_id = try key.NodeId.parseHex(upstream_id);
    const pkarr_id = try corpusId(9);
    const records = "relay=https://use1-1.relay.iroh.network./\x00addr=192.0.2.9:9999\x00";
    var relay: FakeRelay = .{
        .answers = "signed\x00",
        .packets = &.{.{ .node_id = pkarr_id, .txt = .init(records) }},
    };
    var resolver = PkarrResolver.init(relay.source());

    var pulled: [1]item.Item = undefined;
    {
        var stream = (try resolver.lookup().resolve(t.allocator, pkarr_id)) orelse
            return error.TestUnexpectedResult;
        defer stream.deinit();
        var count: usize = 0;
        var failed_count: usize = 0;
        while (stream.next()) |event| switch (event) {
            .item => |value| {
                pulled[count] = value;
                count += 1;
            },
            .failed => failed_count += 1,
        };
        try t.expectEqual(@as(usize, 0), failed_count);
        try t.expectEqual(@as(usize, 1), count);
        try t.expectEqual(@as(?usize, 1), stream.finish().itemCount());

        // Everything below reads items the stream owns, so all of it happens
        // before `deinit` hands the heap back. That ordering is `Stream`'s
        // contract, and a test that got it wrong would read freed memory and
        // pass or fail at random.
        const same_by_dns = try parseTxt(t.allocator, pkarr_id, .init(records), .dns);
        defer same_by_dns.endpoint.deinit(t.allocator);
        const other = try parseTxt(t.allocator, dns_id, .init(upstream_records), .dns);
        defer other.endpoint.deinit(t.allocator);

        const found = [_]item.Item{ pulled[0], same_by_dns, other };
        const merged = try item.merge(t.allocator, &found);
        defer t.allocator.free(merged);
        // Three services' answers, three distinct facts, and the two that agree
        // on one endpoint are *not* the same item: provenance is a tiebreak and
        // not a dedup key, because two services reporting one address is
        // agreement rather than a conflict.
        try t.expectEqual(@as(usize, 3), merged.len);
        try t.expect(merged[0].eql(item.winner(&found).?));
        var at: usize = 1;
        while (at < merged.len) : (at += 1) {
            try t.expectEqual(std.math.Order.gt, merged[at - 1].order(merged[at]));
        }
        // And the pair that differs in nothing at all but which service said it
        // has an order, and it is the one `Provenance.rank` names rather than
        // the one the answers happened to arrive in.
        try t.expectEqual(std.math.Order.lt, same_by_dns.order(pulled[0]));
        try t.expectEqual(std.math.Order.gt, pulled[0].order(same_by_dns));
    }
}
