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

/// What a service is asked to publish.
///
/// Upstream's `publish(&self, data: &EndpointData)`
/// (`iroh/src/address_lookup.rs:343`) takes the *data* and not the endpoint, so
/// the trait never names the node it is publishing for. ozai's `NodeAddr` is
/// upstream's `EndpointInfo` — the id and the data already joined — so the two
/// arrive together and a publisher cannot be handed addresses for a node it is
/// not publishing. `discovery/item.zig`'s `Item` is the same join on the
/// reading side.
///
/// The address is *moved*, not borrowed. Upstream copies, because a Rust
/// `EndpointData` behind a `Cow` is one the caller wants to keep reading; a Zig
/// move is free, and making `publish` copy would be an allocation the caller
/// could have avoided. The caller must not read `endpoint` again afterwards,
/// which is the ordinary convention for a parameter that is consumed.
pub const Published = struct {
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
pub const AddressLookup = struct {
    vtable: *const VTable,
    ctx: *anyopaque,

    pub const VTable = struct {
        /// Publish, taking ownership of the address. Fire and forget, as
        /// upstream's is: "This is fire and forget, since the `Endpoint` can
        /// not wait for successful publishing"
        /// (`iroh/src/address_lookup.rs:337`).
        publish: *const fn (ctx: *anyopaque, data: Published) void,
        /// Begin a resolve, or answer null for a service that does not resolve
        /// at all. The caller owns what comes back and must `deinit` it.
        resolve: *const fn (
            ctx: *anyopaque,
            alloc: std.mem.Allocator,
            node_id: addr.NodeId,
        ) ResolveError!?Stream,
    };

    pub fn publish(self: AddressLookup, data: Published) void {
        self.vtable.publish(self.ctx, data);
    }

    /// Null means "cannot resolve at all", which is not "resolved to nothing".
    /// The second is a stream that ran and came back with no items; see
    /// `Stream` and `item.Resolution`.
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

fn ignorePublish(_: *anyopaque, _: Published) void {}

fn refuseResolve(
    _: *anyopaque,
    _: std.mem.Allocator,
    _: addr.NodeId,
) ResolveError!?Stream {
    return null;
}

/// One pull's worth of answer.
pub const Event = union(enum) {
    /// A result. Its `NodeAddr` belongs to the stream and dies with
    /// `Stream.deinit`; a caller that keeps one must copy it.
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
    ctx: *anyopaque,
    stop: *const fn (ctx: *anyopaque) void,

    /// Tell the producer to stop. Called at most once per resolve, on every
    /// path out of the stream.
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
pub const Stream = struct {
    /// The service's own state, laid out by whoever started the work.
    state: *anyopaque,
    vtable: *const VTable,
    /// The allocator the work was started with, held rather than passed to
    /// `deinit` because an owning handle that takes the allocator again is a
    /// handle that can be freed with the wrong one.
    alloc: std.mem.Allocator,
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

    pub const VTable = struct {
        /// One pull. Null when the service has nothing more, and `finish` is
        /// the answer from then on.
        next: *const fn (state: *anyopaque) ?Event,
        /// How the service came to be finished. Readable only after `next`
        /// answered null, and the items it hands back are the stream's own.
        finish: *const fn (state: *anyopaque) item.Resolution,
        /// Tell the producer to stop. Called exactly once per resolve, by
        /// `deinit`, whether the stream was drained or abandoned.
        cancel: *const fn (state: *anyopaque) void,
        /// Release the state. Called exactly once, after `cancel`.
        destroy: *const fn (state: *anyopaque, alloc: std.mem.Allocator) void,
    };

    /// The next answer, or null when the service is finished.
    pub fn next(self: *Stream) ?Event {
        if (self.status != .live) return null;
        const event = self.vtable.next(self.state);
        if (event == null) self.status = .finished;
        return event;
    }

    /// What the service came to. Meaningful only once `next` has answered null,
    /// and the only way a caller learns whether the service resolved to nothing
    /// or had nothing to say for a different reason.
    pub fn finish(self: *const Stream) item.Resolution {
        std.debug.assert(self.status == .finished);
        return self.vtable.finish(self.state);
    }

    /// Stop the work and release the state. Idempotent.
    ///
    /// The producer is told to stop exactly once, on every path, and a stream
    /// that already finished is told anyway: a service that has finished has
    /// nothing left to stop, and a `cancel` that is a no-op then is cheaper than
    /// a status check that could be got wrong.
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

    pub fn parse(key_text: []const u8) ?Attribute {
        inline for (all) |attribute| {
            if (std.mem.eql(u8, key_text, attribute.text())) return attribute;
        }
        return null;
    }

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
    bytes: []const u8,
    at: usize = 0,

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
/// Everything the result owns comes from `alloc`: the address list, and the
/// bytes behind every `addr=<custom>` value. The second one is not optional.
/// `addr.CustomAddr.data` borrows — `CustomAddr.parse` needs storage for the
/// inline data and `NodeAddr.insert` copies the slice header, not the bytes it
/// points at — so the bytes are copied out here, and the copy has to outlive
/// the item. `NodeAddr.deinit(alloc)` does not free them, because a `NodeAddr`
/// has no field for them. A caller that wants the item to outlive the allocator
/// it passed wants an arena, and both resolvers below hold one for exactly that
/// reason. This is invariant 6 read from the other end: the value never carries
/// a slice into storage it does not own, and where it cannot own it, the owner
/// is named.
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
    errdefer endpoint.deinit(alloc);
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
                    const grown = endpoint.insert(alloc, .{
                        .custom = .{ .id = custom.id, .data = data },
                    }) catch {
                        alloc.free(data);
                        return error.OutOfMemory;
                    };
                    if (grown) |next| {
                        endpoint = next;
                        // Only now does anything refer to the copy, so it
                        // leaves this record's hands and joins the list the
                        // error path frees.
                        try owned.append(alloc, data);
                    } else {
                        // Already present, so nothing refers to the copy.
                        alloc.free(data);
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
    txt: RecordSet,
};

/// What a pkarr resolver reads: signed packet bytes, and the retrieval to stop.
///
/// Nothing here fetches. A resolver is handed an answer set that something else
/// already retrieved, together with a handle to that retrieval, which is how a
/// caller cancels without the resolver ever learning what a socket is.
pub const PacketSource = struct {
    ctx: *anyopaque,
    /// Signed-packet bytes to what they say. This function is
    /// `discovery/pkarr.zig`'s and nothing in this file is; a resolver calls it
    /// and turns its answer into either a `Packet` or a `DecodeError`, and that
    /// mapping is the whole of the coupling between the two files.
    decode: *const fn (ctx: *anyopaque, packet: []const u8) DecodeError!Packet,
    /// The answers, already retrieved, concatenated and NUL-separated. The
    /// first NUL ends one packet and the second starts the next, which is why
    /// each answer is a whole signed packet and a packet may hold several
    /// `_iroh` records of its own.
    answers: RecordSet,
    /// How to stop the retrieval. Null when there was none — an answer set read
    /// out of a file has nothing to cancel, and saying so is different from
    /// having a cancellation that nobody fired.
    cancellation: ?Cancellation,
};

/// `PkarrPublisher`: the service that only publishes.
///
/// Upstream's `PkarrPublisher` implements `publish` and not `resolve`
/// (`iroh/src/address_lookup/pkarr.rs:357`), so it takes
/// `AddressLookup.refuse_resolve` and a resolve asked of it comes back `None`.
/// That is the production case for the distinction invariant 13 is about, and
/// not only a trait default nobody uses.
pub const PkarrPublisher = struct {
    alloc: std.mem.Allocator,
    /// The last data handed to `publish`, owned so the caller is free the moment
    /// `publish` returns. Upstream's is `self.watchable.set(Some(info))`
    /// (`iroh/src/address_lookup/pkarr.rs`, `update_endpoint_data`): the same
    /// take-ownership swap, into the same one slot, read by a background task
    /// that republishes on a timer.
    stored: ?item.Item,
    vtable: AddressLookup.VTable = publisherVTable,

    /// The allocator is taken here and held rather than taken per call, because
    /// the one slot has to be given back on the next `publish` and on `deinit`
    /// and those are the only two moments it exists.
    pub fn init(alloc: std.mem.Allocator) PkarrPublisher {
        return .{ .alloc = alloc, .stored = null };
    }

    /// The one slot has to be given back. Not a vtable entry, because the
    /// vtable is a borrowed view: see `AddressLookup`.
    pub fn deinit(self: *PkarrPublisher) void {
        if (self.stored) |value| value.endpoint.deinit(self.alloc);
        self.stored = null;
    }

    pub fn lookup(self: *PkarrPublisher) AddressLookup {
        return .{ .vtable = &self.vtable, .ctx = @ptrCast(@alignCast(self)) };
    }

    /// What was published last, or null when `publish` has not been called.
    /// Borrows the publisher's own storage, so the slice is dead after the next
    /// `publish` — invariant 6's reason.
    pub fn published(self: *const PkarrPublisher) ?item.Item {
        return self.stored;
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

const publisherVTable: AddressLookup.VTable = .{
    .publish = publisherPublish,
    .resolve = AddressLookup.refuse_resolve,
};

fn publisherPublish(ctx: *anyopaque, data: Published) void {
    const self: *PkarrPublisher = @ptrCast(@alignCast(ctx));
    // The slot is replaced, not appended to, which is upstream's
    // `watchable.set`: a publisher's job is to say what this node is reachable
    // at *now*, and an address the endpoint has since stopped using is not a
    // second opinion, it is stale.
    if (self.stored) |previous| previous.endpoint.deinit(self.alloc);
    self.stored = item.Item.init(data.endpoint, .pkarr, data.last_updated);
}

/// `PkarrResolver`: the service that only resolves.
///
/// Upstream's `PkarrResolver` implements `resolve` and not `publish`
/// (`iroh/src/address_lookup/pkarr.rs:536`), so it takes
/// `AddressLookup.ignore_publish`. Publishing is somebody else's job, and a
/// resolver that also published would make "what this node is reachable at" and
/// "what the network says about that node" the same value.
pub const PkarrResolver = struct {
    source: PacketSource,
    vtable: AddressLookup.VTable = resolverVTable,

    pub fn init(source: PacketSource) PkarrResolver {
        return .{ .source = source };
    }

    pub fn lookup(self: *PkarrResolver) AddressLookup {
        return .{ .vtable = &self.vtable, .ctx = @ptrCast(@alignCast(self)) };
    }
};

const resolverVTable: AddressLookup.VTable = .{
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
        .vtable = &pkarrStreamVTable,
        .alloc = alloc,
        .status = .live,
    };
}

const pkarrStreamVTable: Stream.VTable = .{
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
    var publisher = PkarrPublisher.init(t.allocator);
    defer publisher.deinit();
    // Upstream's publisher implements `publish` and no `resolve`
    // (`iroh/src/address_lookup/pkarr.rs:357`), so a resolve is the trait
    // default's `None`: the service will not answer, as against a service that
    // answered and had nothing. No work was started, so there is nothing to
    // cancel either, and no error to log.
    try t.expect((try publisher.lookup().resolve(t.allocator, try corpusId(1))) == null);
}

test "a publisher that has published nothing writes nothing" {
    var publisher = PkarrPublisher.init(t.allocator);
    defer publisher.deinit();
    // `published` is null and `writeTxtStrings` says so rather than handing
    // back an empty record set, which a reader would take for a node that has
    // published nothing. One slot, two answers, and the second one is not
    // "there is nothing here yet".
    try t.expect(publisher.published() == null);
    var buffer: [maxTxtStringsLength(1)]u8 = undefined;
    try t.expectError(error.NothingPublished, publisher.writeTxtStrings(&buffer));
}

test "cannot resolve and resolved to nothing are different answers" {
    const id = try corpusId(1);

    // A service that will not answer at all. There is no `Resolution` in hand
    // afterwards, and the absence is the whole point: there is no value a caller
    // could mistake for an empty one.
    var publisher = PkarrPublisher.init(t.allocator);
    defer publisher.deinit();
    try t.expect((try publisher.lookup().resolve(t.allocator, id)) == null);

    // A service that was asked, ran, and had nothing to say. The answer set is
    // empty because the relay answered with no packets, which is a real state of
    // the world: a node that has published nothing.
    var relay = FakeRelay{
        .answers = "",
        .packets = &.{},
    };
    var resolver = PkarrResolver.init(relay.source());
    var stream = (try resolver.lookup().resolve(t.allocator, id)).?;
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
    var relay = FakeRelay{
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
    var stream = (try resolver.lookup().resolve(t.allocator, id)).?;
    try t.expect(stream.next() != null);
    // Nothing has been told to stop yet, and saying so is the half of the
    // assertion that makes the other half mean anything.
    try t.expectEqual(@as(u32, 0), relay.cancels);
    stream.deinit();
    try t.expectEqual(@as(u32, 1), relay.cancels);
}

test "a drained stream is cancelled exactly once too" {
    const id = try corpusId(3);
    var relay = FakeRelay{
        .answers = "signed\x00",
        .packets = &.{.{ .node_id = id, .txt = .init("relay=https://relay.example./\x00") }},
    };
    var resolver = PkarrResolver.init(relay.source());
    var stream = (try resolver.lookup().resolve(t.allocator, id)).?;
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
    var relay = FakeRelay{
        .answers = "signed\x00",
        .packets = &.{.{ .node_id = id, .txt = .init("addr=127.0.0.1:1234\x00") }},
    };
    var resolver = PkarrResolver.init(.{
        .ctx = @ptrCast(@alignCast(&relay)),
        .decode = FakeRelay.decode,
        .answers = .init("signed\x00"),
        .cancellation = null,
    });
    var stream = (try resolver.lookup().resolve(t.allocator, id)).?;
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

test "a packet signed for another node is reported, not returned" {
    // Upstream takes the id from the packet and hands it on
    // (`from_pkarr_signed_packet`), so a relay answering a query for one node
    // with another's record is obeyed. ozai reports it instead.
    const id = try corpusId(7);
    const other = try corpusId(8);
    var relay = FakeRelay{
        .answers = "signed\x00signed\x00",
        .packets = &.{
            .{ .node_id = other, .txt = .init("relay=https://elsewhere.example./\x00") },
            .{ .node_id = id, .txt = .init("relay=https://relay.example./\x00") },
        },
    };
    var resolver = PkarrResolver.init(relay.source());
    var stream = (try resolver.lookup().resolve(t.allocator, id)).?;
    defer stream.deinit();

    const first = stream.next().?;
    try t.expectEqual(error.UnexpectedSigner, first.failed.reason);
    try t.expectEqual(item.Provenance.pkarr, first.failed.provenance);
    // The failure did not end the stream, so the packet that *was* signed for
    // this node still arrives behind it.
    const second = stream.next().?;
    try t.expectEqual(id, second.item.endpoint.node_id);
    try t.expect(stream.next() == null);
    try t.expectEqual(@as(?usize, 1), stream.finish().itemCount());
}

test "a packet that will not decode fails one answer and not the stream" {
    const id = try corpusId(7);
    var relay = FakeRelay{
        .answers = "garbage\x00signed\x00",
        .packets = &.{.{ .node_id = id, .txt = .init("relay=https://relay.example./\x00") }},
    };
    var resolver = PkarrResolver.init(relay.source());
    var stream = (try resolver.lookup().resolve(t.allocator, id)).?;
    defer stream.deinit();

    const first = stream.next().?;
    try t.expectEqual(error.MalformedPacket, first.failed.reason);
    const second = stream.next().?;
    try t.expectEqual(id, second.item.endpoint.node_id);
    try t.expect(stream.next() == null);
}

test "published records read back as the address that was published" {
    const id = try corpusId(7);
    var publisher = PkarrPublisher.init(t.allocator);
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
    publisher.lookup().publish(.{ .endpoint = endpoint, .last_updated = 7 });

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
    const stored = publisher.published().?;
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
    var relay = FakeRelay{
        .answers = "signed\x00",
        .packets = &.{.{ .node_id = pkarr_id, .txt = .init(records) }},
    };
    var resolver = PkarrResolver.init(relay.source());

    var pulled: [1]item.Item = undefined;
    {
        var stream = (try resolver.lookup().resolve(t.allocator, pkarr_id)).?;
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
