//! Discovery as a pass of the node's loop: the live lookup, the fan-in that
//! dials what it found, and the timer both of them run on.
//!
//! `TODO.md` names the gap this file fills: "No production driver performs a
//! live lookup. `lookup_live.zig` proves the seam against real sockets and the
//! only callers of its `Datagram` are its own tests; `src/node/` never reaches
//! for it". `discovery/dial_source.zig` is the fan-in that was built and never
//! run, and `discovery/lookup_io.zig`'s `Retrieval` is the question that goes
//! out on a socket. This file drives both: it asks for `_iroh.<z32>.<origin>`,
//! hands the answer to `dns.DnsAddressLookup`, and dials whatever the merge
//! chose.
//!
//! # The lookup gets a socket of its own
//!
//! The node's socket carries gossip and every peer datagram, and a lookup
//! cannot be taken out on it. Two facts, and both are in the types:
//!
//! 1. **A lookup eats what it finds.** `Retrieval.ask` takes the next datagram
//!    off the descriptor and refuses anything that did not come from the
//!    nameserver (`error.ForeignSource`), so a peer datagram that arrived first
//!    would be consumed and thrown away by a question about a name — silently,
//!    once per republish.
//! 2. **A lookup stops the socket it went out on.** `Stream.deinit` fires the
//!    cancellation its service was built with (`dns.zig`'s `dnsCancel`), and a
//!    handle from `Retrieval.cancellation` names the descriptor the retrieval
//!    used. `Socket.stop` empties the queue and leaves the socket refusing to
//!    serve until the next send, which on the node's own socket is every
//!    datagram that arrived while nobody was listening.
//!
//! So `State` owns a socket of its own: the wildcard address of the family the
//! nameserver is in, on an ephemeral port, because nothing outside this file
//! has to find it. The only thing ever queued on it is an answer to a question
//! this file asked.
//!
//! # The cancellation this file does not pass
//!
//! `dns.DnsAddressLookup.init` takes a `resolve.Cancellation` and this file
//! passes null, which is a decision rather than an omission. The answer is
//! already in hand when the stream closes — the question went out and came back
//! inside `fanIn`, before the service was built — so there is nothing in flight
//! for a stop to end. The retrieval's own handle is refused rather than left
//! unused because it would latch `lookup_live.Datagram.stopped` on the first
//! pass, and that latch is final: `lookup_live.zig`'s module doc has it "set
//! once and never cleared", so the second lookup this node ever made would be
//! refused before it left the socket.
//!
//! # What a pass costs
//!
//! `pass` runs its question inline, on the thread that drives the node's loop,
//! where upstream runs the same work on a background task this tree does not
//! have (`docs/DECISIONS/0002-async-substrate.md` is why there are none). Two
//! bounds keep that honest: one question per pass, so a pass costs at most
//! `query_deadline_ms`, and one peer per pass, so a node with many peers pays
//! the deadline once each instead of `n` times over.
//!
//! # The timer
//!
//! One interval, two legs: what this node last said about itself, and what the
//! network last said about a peer. They are one question asked twice — what the
//! world believes about a node — and the first leg costs nothing until
//! something sends it, so the interval is set by the second. A `due` of zero
//! makes the first pass publish and look up, because a node that has said
//! nothing yet has nothing to correct.
//!
//! # What is not here
//!
//! * **No pkarr source.** `resolve_pkarr.PkarrResolver` reads answers something
//!   already retrieved, and upstream retrieves over HTTPS from a relay.
//!   `docs/ARCHITECTURE.md` records that this tree has no HTTP client and no TLS
//!   client outside the vendored QUIC core, and a `PacketSource` answering out
//!   of an empty buffer would make the fan-in merge a fiction.
//! * **No sender for the publication.** `resolve_publish.PkarrPublisher` keeps
//!   what it is given and writes the records it would carry; putting those on
//!   the wire is the same HTTPS request as above. What this file publishes is
//!   therefore held rather than sent, and `published` is how a caller reads it.
//! * **No netcheck.** A node publishes the address its own socket is bound to,
//!   which is the only external address it has — the `net/` probe seam is still
//!   a test fake, for the reason `lookup_live.zig`'s module doc gives. A node
//!   behind NAT therefore publishes something nobody outside can dial, which is
//!   recorded here rather than replaced by an address nobody measured.
//!
//! # Ownership
//!
//! `State` is a `Node` field and nothing is copied out of it: the seam holds the
//! address of the `Datagram` inside it, so the value must not move once a pass
//! has run. `create` fills it in place for that reason, and `deinit` releases
//! the descriptor and the publication. Everything else here is borrowed from
//! the `Node` it is passed, and every allocation a pass makes is an arena that
//! dies before the pass returns.

const std = @import("std");
const node_mod = @import("node.zig");
const socket_mod = @import("../transport/socket.zig");
const base_addr = @import("../base/addr.zig");
const base_key = @import("../base/key.zig");
const item = @import("../discovery/item.zig");
const node_addr = @import("../base/node_addr.zig");
const transport_addr = @import("../base/transport_addr.zig");
const dns = @import("../discovery/dns.zig");
const lookup_io = @import("../discovery/lookup_io.zig");
const lookup_live = @import("../discovery/lookup_live.zig");
const resolve = @import("../discovery/resolve.zig");
const resolve_publish = @import("../discovery/resolve_publish.zig");
const dial_source = @import("../discovery/dial_source.zig");
const Instant = @import("../transport/quic_conn.zig").Instant;

/// What this file refuses.
///
/// `lookup_io`'s and `dial_source`'s own sets, whole rather than restated:
/// this file adds no failure of its own, and a second copy of either set is a
/// list that goes stale when the file it came from grows an arm.
pub const Error = socket_mod.OpenError || lookup_io.Error || dial_source.Error;

/// One question's whole budget, in milliseconds.
///
/// Upstream's own figure, which `lookup_io.Request.deadline_ms` already quotes
/// from `iroh/src/address_lookup/dns.rs:19`, and the whole cost of a pass: a
/// pass asks one question. It is not a retry count — `Retrieval.ask` is one
/// datagram out and one in — so a peer the network cannot answer for is found
/// on the next pass instead.
pub const query_deadline_ms: i32 = 3_000;

/// How long this node's own publication and its peers' answers are left alone
/// before they are asked for again, in milliseconds.
///
/// The number is this file's: nothing above it configures one, and what it
/// bounds is a peer's address going stale rather than a record going stale, so
/// it is set by the slower half of a pass and not by the publication.
pub const republish_interval_ms: i64 = 30_000;

/// The one interval in nanoseconds, so the timer below is one addition.
const republish_interval_ns: i64 = republish_interval_ms * std.time.ns_per_ms;

/// Who the question goes to when the caller names none.
///
/// Upstream's two nameservers are both DNS-over-HTTPS endpoints
/// (`iroh/src/address_lookup/dns.rs`), which this tree cannot speak, and a
/// nameserver is a policy rather than a fact about a node — so this is a
/// default and `create` takes the address, not the other way round.
pub const default_server: base_addr.SocketAddr = .{
    .ip = .{ .v4 = .{ 1, 1, 1, 1 } },
    .port = 53,
};

/// The origin every question is asked under.
///
/// Upstream's default origin (`discovery/dns.zig` quotes both), and fixed here
/// because it is a property of the deployment rather than of a node: naming a
/// different one is configuration, and `node_config.Config` has no field for
/// it.
const origin = dns.prod_origin;

/// The name a question is framed under: `_iroh.<z32>.<origin>`.
const name_room = dns.queryNameLength(origin);

/// The query bytes that name is framed into.
const wire_room = lookup_io.queryLength("x" ** name_room);

/// This node's discovery: the socket, the live seam over it, the scratch one
/// question is written and read with, and the timer that paces both legs.
///
/// A `Node` field, and the one value here that must not move: the seam
/// `fanIn` takes is `&self.datagram`, so a pass reads a seam that points at
/// wherever this value was when the pass began. See "Ownership".
pub const State = struct {
    /// The descriptor every question goes out on. Owned here and not the
    /// node's: see "The lookup gets a socket of its own".
    socket: socket_mod.Socket,
    /// The live `lookup_io.Datagram` over it: the query, the answer, and the
    /// handle that stops both. Its latch is never set by this file, which is
    /// what lets one value serve every pass — see "The cancellation this file
    /// does not pass".
    datagram: lookup_live.Datagram,
    /// Who is asked. The caller's, so a node can name its own resolver.
    server: base_addr.SocketAddr,
    /// The name, the query and the answer of one question, all rebuilt per
    /// question. Fields rather than per-pass locals because a pass is not the
    /// only thing that writes them and a buffer nobody reinitialises is a
    /// question carrying the last peer's bytes.
    name: [name_room]u8 = undefined,
    wire: [wire_room]u8 = undefined,
    reply: [lookup_io.reply_length]u8 = undefined,
    /// When the next republish is due, in the same instants the pass is
    /// driven with. Zero so the first pass publishes and looks up.
    due: Instant = 0,
    /// Which peer of the join's list the next due pass starts from. A pass
    /// asks about one peer, and this is what makes the next one a different
    /// peer rather than the same one again.
    cursor: usize = 0,
    /// What this node last said about itself, kept whole so the address list
    /// is the publisher's to release.
    publisher: resolve_publish.PkarrPublisher = resolve_publish.PkarrPublisher.init(),

    /// Open the descriptor and point the seam at it.
    ///
    /// In place, and not by value, because the seam holds the address of the
    /// socket inside this value: a `State` returned by a constructor would
    /// carry a pointer to the copy it was built in, and the copy would be gone
    /// before the first question went out. The caller places this value where
    /// it will live — a `Node` field — and keeps it there.
    pub fn create(self: *State, server: base_addr.SocketAddr) socket_mod.OpenError!void {
        // The wildcard address of the nameserver's own family, so the
        // descriptor this file sends from can reach the one place it sends to,
        // and an ephemeral port because nothing else has to find it.
        const bind: base_addr.SocketAddr = .{
            .ip = switch (server.ip) {
                .v4 => .{ .v4 = @splat(0) },
                .v6 => .{ .v6 = @splat(0) },
            },
            .port = 0,
        };
        self.socket = try socket_mod.Socket.create(bind, .{});
        errdefer self.socket.close();
        self.* = .{
            .socket = self.socket,
            .datagram = lookup_live.Datagram.init(&self.socket),
            .server = server,
        };
    }

    /// Release the publication and the descriptor. Once, after which the value
    /// is dead; a question that is still in flight is not one this file can
    /// still answer for, because a pass does not outlive the loop.
    pub fn deinit(self: *State) void {
        self.publisher.deinit();
        self.socket.close();
    }

    /// What this node last published, or null before the first republish.
    ///
    /// Borrows the publisher's own storage, so the answer dies with the next
    /// `publish` and with `deinit` — invariant 6's reason, and the reason a
    /// caller copies an address it wants to keep.
    pub fn published(self: *const State) ?item.Item {
        return self.publisher.published();
    }

    /// One pass of the timer: republish, then look up one peer and dial what
    /// the merge chose.
    ///
    /// Returns whether a connection was opened, which is the only thing here a
    /// caller can act on. Everything else — a publication replaced, a peer
    /// that was already named, a nameserver that said nothing — is a fact
    /// this pass records and nobody waits for.
    pub fn pass(
        self: *State,
        io: std.Io,
        node: *node_mod.Node,
        at: Instant,
        random: std.Random,
    ) Error!bool {
        if (at < self.due) return false;
        self.due = at + republish_interval_ns;
        try self.publish(node);
        return self.refresh(io, node, at, random);
    }

    /// Look `target` up over the live socket and dial what the fan-in chose.
    ///
    /// A named connection to `target` is not dialled again: `conn_index`'s
    /// `put` re-points the slot rather than adding one, so a second dial would
    /// leave the first connection unreachable instead of spare. Returns
    /// whether a connection was opened.
    pub fn reach(
        self: *State,
        io: std.Io,
        node: *node_mod.Node,
        target: base_key.NodeId,
        at: Instant,
        random: std.Random,
    ) Error!bool {
        // Every allocation below dies before this function returns: the items
        // the streams produced and the answer they read. `Dialed` holds a
        // connection and a route that own their own storage, which is what
        // `dial_source` guarantees about its result.
        var arena = std.heap.ArenaAllocator.init(node.gpa);
        defer arena.deinit();
        const outcome = self.fanIn(arena.allocator(), io, node, target, at, random) catch |err| switch (err) {
            // Two arms are this pass's own rather than the network's, and
            // `node_runtime.step` closes a node that returns an error rather
            // than replaying the pass that did.
            error.OutOfMemory, error.Canceled => return err,
            // Everything else is a dial this peer refused. `start` counts and
            // warns about those rather than failing, and a pass that ended the
            // node's loop over one unreachable peer would make every other
            // peer unreachable too.
            else => {
                node.stats.dials_refused += 1;
                std.log.warn("node: {f} was not reached: {t}", .{ target, err });
                return false;
            },
        };
        const reached = switch (outcome.result) {
            .dialed => |opened| opened,
            .cannot_resolve, .nothing, .no_address => {
                node.stats.dials_refused += 1;
                if (outcome.first_failure) |failure| {
                    std.log.warn("node: {f} was not resolved: {f}: {t}", .{
                        target,
                        @tagName(failure.provenance),
                        failure.reason,
                    });
                } else {
                    // No failure and no address is what the network said, not
                    // something that went wrong, and it recurs every interval.
                    std.log.info("node: {f} published no address", .{target});
                }
                return false;
            },
        };
        node.stats.dials += 1;
        // The peer id a gossip request names is the one this dial was pinned
        // to, so naming it here is what makes the connection reachable by
        // gossip. An index that is full has refused a peer that is really
        // there, which `start` reports the same way.
        node.connections.put(target, reached.dial.conn) catch |err| switch (err) {
            error.ConnectionIndexFull => std.log.warn(
                "node: {f} was dialled and cannot be named by gossip: {t}",
                .{ target, err },
            ),
        };
        // The service the address came from, which is the only thing that makes
        // a wrong address traceable — and `dial_source` hands back the service
        // rather than the address, so this is the only place the run names it.
        std.log.info("node: {f} was reached over {f}", .{ target, @tagName(reached.provenance) });
        return true;
    }

    /// One peer of the join's own bootstrap list, and the first this node has
    /// no named connection to.
    ///
    /// `config.peers` is the list `node_runtime.start` joins gossip with, so
    /// these are the peers a node has to reach before its membership means
    /// anything. One per pass, round-robin by `cursor`, so the pass costs one
    /// deadline however many peers there are.
    fn refresh(
        self: *State,
        io: std.Io,
        node: *node_mod.Node,
        at: Instant,
        random: std.Random,
    ) Error!bool {
        const peers = node.config.peers;
        var left: usize = peers.len;
        while (left > 0) : (left -= 1) {
            if (self.cursor >= peers.len) self.cursor = 0;
            const peer = peers[self.cursor];
            self.cursor += 1;
            if (node.connections.connFor(peer.id) != null) continue;
            return self.reach(io, node, peer.id, at, random);
        }
        return false;
    }

    /// The one live question and the fan-in that dials what it answered.
    ///
    /// The sources are this node's own: what the network said about `target`,
    /// fetched here and handed over as values. `resolve.AddressLookup` is a
    /// borrowed view of a service, so the service is a local of this function
    /// and outlives the streams `dialFromSources` takes from it — which it does
    /// not, because that function closes every stream it starts before it
    /// returns.
    fn fanIn(
        self: *State,
        alloc: std.mem.Allocator,
        io: std.Io,
        node: *node_mod.Node,
        target: base_key.NodeId,
        at: Instant,
        random: std.Random,
    ) Error!dial_source.Outcome {
        const name = dns.queryName(self.name[0..], target, origin);
        // The transaction id is drawn here, once: a second ask of this
        // retrieval would ask the same question and read the first one's late
        // answer, which is why the value is per question.
        var retrieval = lookup_io.Retrieval.begin(self.datagram.seam(), self.server, random);
        const answer = retrieval.ask(alloc, io, .{
            .name = name,
            .wire = self.wire[0..],
            .reply = self.reply[0..],
            .deadline_ms = query_deadline_ms,
        }) catch |err| switch (err) {
            error.OutOfMemory, error.Canceled => return err,
            // The deadline arriving is the one refusal `resolve.Reason` names,
            // and it is a fact about the exchange rather than about the peer.
            error.Empty => return .{
                .result = .nothing,
                .first_failure = .{ .provenance = .dns, .reason = .TimedOut },
            },
            // Everything else is the exchange itself failing: a socket that
            // would not send, an answer to somebody else's question, a
            // datagram from a source that is not the nameserver. None of them
            // is a statement about the peer and `Reason` names none of them,
            // so the log carries what happened and the outcome carries what
            // the node learned.
            else => {
                std.log.warn("node: {f} was not looked up: {t}", .{ target, err });
                return .{ .result = .nothing, .first_failure = null };
            },
        };
        defer answer.deinit(alloc);

        // An answer with no records is a name that exists and carries nothing
        // this question asked for: a fact about the world, and `nothing` is
        // the arm `dial_source` already keeps apart from a refusal to resolve.
        if (!answer.hasRecords()) return .{ .result = .nothing, .first_failure = null };

        // Null cancellation: see the module doc's own section. The answer is
        // already copied out of `reply` by `ask`, so nothing is in flight and
        // a handle here would only stop the socket every later pass needs.
        var service = dns.DnsAddressLookup.init(answer.records, null);
        const sources = [_]resolve.AddressLookup{service.lookup()};
        return dial_source.dialFromSources(alloc, &sources, node.dialer, .{
            .node_id = target,
            .local = node_mod.address(node),
            .map = &node.map,
            .select = .{ .ctx = @ptrCast(node), .pick = preferDirect },
            .at = at,
            .random = random,
        });
    }

    /// Rebuild what this node says about itself and hand it to the publisher.
    ///
    /// Fire and forget, which is what `AddressLookup.publish` is: the publisher
    /// takes the address list over and releases the previous one with the
    /// allocator that built it, so nothing here is left to free on any path.
    fn publish(self: *State, node: *node_mod.Node) std.mem.Allocator.Error!void {
        const alloc = node.gpa;
        var endpoint = node_addr.NodeAddr.init(node_mod.nodeId(node));
        // The relay this node converses with is a path to it that does not
        // depend on this host being reachable directly, so it is published
        // when the configuration names one.
        switch (node.config.relay.role) {
            .client => |peer| {
                endpoint = (try endpoint.insert(alloc, peer.addr)) orelse endpoint;
            },
            .off, .serve => {},
        }
        // The address the kernel bound this node's own socket to, which is the
        // only external address it has. `insert` answers null for an address
        // the list already carries and re-points the list otherwise, so the
        // receiver is adopted from the answer either way.
        endpoint = (try endpoint.insert(alloc, .{ .ip = node_mod.address(node) })) orelse endpoint;
        // No timestamp: upstream's publisher stores none — it republishes on a
        // timer and on change — and a stamp invented here would be the same
        // value on every republication, which orders nothing.
        self.publisher.lookup().publish(.{
            .alloc = alloc,
            .endpoint = endpoint,
            .last_updated = null,
        });
    }
};

/// Which of a winning item's addresses this node dials: a direct one when the
/// item carries any, and the lowest-ordered address when it does not.
///
/// Upstream's order, and not this file's opinion: iroh separates a peer's
/// direct addresses from its relays and tries the direct ones first
/// (`iroh/src/endpoint.rs`), and a node behind a relay would rather spend the
/// holepunch than the relay's bandwidth. `TransportAddr.order` sorts relays
/// first, so "the first address" and "a direct address" are not the same
/// answer and only one of them is what upstream does.
///
/// The list is never empty: `dial_source` settles a winner with no address
/// before it asks, so the fallback here is a relay or a custom address and not
/// an absent one.
fn preferDirect(
    _: *anyopaque,
    endpoint: *const node_addr.NodeAddr,
) ?transport_addr.TransportAddr {
    for (endpoint.addrs) |value| {
        if (value == .ip) return value;
    }
    return endpoint.addrs[0];
}