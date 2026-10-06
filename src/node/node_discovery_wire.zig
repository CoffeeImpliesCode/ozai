//! The two transports the node's discovery pass puts bytes on: a signed packet
//! to a pkarr relay, and a TXT question to a nameserver.
//!
//! `node_discovery.zig` is the state machine beside this one and asks; this
//! file does the I/O and names every refusal, in the shape
//! `node_gossip_wire.zig` sets for the gossip send path. The precedent is the
//! whole of the rule here: a state machine over decoded input, and a wire that
//! turns one into bytes and one refusal into a counter that has a name.
//!
//! # Why both arms are here rather than in the state machine
//!
//! **A question and a packet are different facts with different hazards.** A
//! TXT answer carries no signature, so the datagram seam is injected and the
//! source address is checked against the server the question was asked of
//! (`lookup_io.Datagram`'s own doc). A signed packet carries one, so the arm
//! that writes it refuses on `error.UnexpectedSigner` *before* anything is
//! signed (`discovery/pkarr_live.zig`'s doc says the same). One node pass
//! carries both; this file is where they stop looking alike.
//!
//! # The clock is read here and nowhere else in the pass
//!
//! `pkarr_live.Publish.timestamp_us` and `tls_client.Options.now` are both
//! wall-clock facts about *this* packet and *this* certificate, and both
//! modules name them as parameters they must not discover themselves. So the
//! one read happens here, once per publish attempt, which
//! `discovery/publisher.zig`'s republish interval bounds to once a minute by
//! default. The publisher's own timer takes its `now_ms` from the caller's
//! instant and is not affected: see `node_discovery.discovery`.
//!
//! # Entropy comes from the caller
//!
//! The RFC 1035 §4.1.1 transaction id is drawn from the pass's `random`, and
//! the TLS driver's 240 bytes of key share and randoms are filled from the
//! same one, into storage this node owns. Nothing here reaches for a global
//! generator, which is what `AGENTS.md` §2 forbids by name.

const std = @import("std");

const node_mod = @import("node.zig");
const node_config = @import("node_config.zig");

const dns_live = @import("../discovery/dns_live.zig");
const dns = @import("../discovery/dns.zig");
const pkarr_live = @import("../discovery/pkarr_live.zig");
const resolve = @import("../discovery/resolve.zig");
const txt = @import("../discovery/txt.zig");
const tls_client = @import("../discovery/tls_client.zig");

const base_key = @import("../base/key.zig");

const Node = node_mod.Node;
const NodeId = base_key.NodeId;

/// How many publishes did not happen, by name.
///
/// One field per non-success outcome, and a field rather than an array indexed
/// by `@intFromEnum` so a reader does not have to count enum arms to find the
/// number it is reading. **The publish arm and the lookup arm are counted
/// apart**, because the two are facts about different networks: a relay that is
/// down says nothing about a nameserver, and a lookup that timed out says
/// nothing about whether this node's own record is stored.
///
/// `timed_out` and `nothing` are the pair `discovery/lookup_io.zig` refuses to
/// let anybody merge, and they are two fields here for the same reason. A peer
/// that published nothing under its name is a fact about the world; a nameserver
/// that did not answer in time is a fact about a clock, and mapping either onto
/// the other hides every source still in flight.
pub const Refused = struct {
    // -- the publish arm --------------------------------------------------
    /// The record this node would publish had no address in it, so `tick`'s
    /// publish had nothing to sign. Nothing went out, so the timer is left
    /// alone: this is a fact about the node's own configuration, not an
    /// attempt that failed.
    nothing_to_publish: u64 = 0,
    /// The preset names more relays than `max_relays`, so the record would not
    /// fit the address list this node is built with. Refused at arm time,
    /// once, rather than silently publishing the first `max_relays` of them.
    too_many_relays: u64 = 0,
    /// The key that would sign is not this node's own, so the packet would be
    /// one node's addresses published under another's name. Nothing was signed.
    signer_refused: u64 = 0,
    /// The relay answered and refused: a status outside 2xx. A `404` and a
    /// `503` are the same arm here, and `pkarr_live.relayStatus` is what tells
    /// them apart for a caller that cares.
    relay_refused: u64 = 0,
    /// The relay was never reached, or the answer was not one this file will
    /// use: TLS, the connect, the framing. The reason is logged by name before
    /// the counter moves, so it is never only a number.
    unaccepted: u64 = 0,
    /// A tick that skipped because the previous attempt is unconfirmed. Not a
    /// failure of this pass — `publisher.State`'s own decision — and counted
    /// because a publisher that defers for ever is a failure nobody would see.
    deferred: u64 = 0,
    /// A tick that gave up on the record after `publisher.skip_unconfirmed`
    /// deferrals. This node's own contact data is now treated as not published,
    /// which is what a caller needs to hear.
    stale: u64 = 0,

    // -- the lookup arm ---------------------------------------------------
    /// No nameserver seam is configured, so no question could go out. Reached
    /// only when a caller takes the seam away from a node that was driving a
    /// lookup: a node configured without one is `Refused.no_peer`'s neighbour
    /// rather than this, because it has nobody to ask about either.
    no_source: u64 = 0,
    /// The configured origin's question name does not fit the buffer this node
    /// is built with, so the name could not be framed. Refused rather than
    /// asserted: `dns.queryName` asserts its own bound, and a caller that names
    /// a very long origin gets a counter instead of a panic in a pass.
    origin_too_long: u64 = 0,
    /// The seam would not put the question out, or would not give back a
    /// datagram that was one datagram.
    query_refused: u64 = 0,
    /// The datagram was not this question's answer: a foreign transaction id or
    /// a source that is not the server it was asked of. A TXT answer is
    /// unsigned, so this is the only thing standing between a lookup and a
    /// forged one.
    foreign: u64 = 0,
    /// The `TC` bit was set: the answer did not fit one datagram. The retry
    /// RFC 1035 §4.2.2 asks for is a TCP stream, and
    /// `discovery/host_io.streamRetry` is what would have to go out on it; a
    /// node whose transport is a datagram socket has no stream to retry on, so
    /// this is a refusal by name rather than a silent short answer.
    truncated: u64 = 0,
    /// The bytes were not an answer at all: a name that does not exist, an
    /// `RCODE` this decoder refuses, a name that runs past the message.
    undecodable: u64 = 0,
    /// **Nothing answered inside the deadline.** A fact about a clock, and not
    /// `nothing` and not `cannot_resolve`: a slow nameserver must not end the
    /// pass, because ending it hides every source still in flight.
    timed_out: u64 = 0,
    /// **An answer arrived and carried nothing under the name asked about.**
    /// A fact about the world: the name exists and this peer published nothing
    /// under it.
    nothing: u64 = 0,
    /// The resolver would not resolve at all for this node id, which is
    /// `item.Resolution.cannot_resolve` and neither of the two above.
    cannot_resolve: u64 = 0,
    /// The stream ran and carried no item. Reached only with records in hand,
    /// so it is a third fact again rather than either of the two.
    no_item: u64 = 0,
    /// One answer in the stream was a failure rather than an item, and the
    /// stream carried on. The provenance and the reason are logged by name.
    unreadable: u64 = 0,
    /// The allocator ran out inside the question or the resolve.
    out_of_memory: u64 = 0,
    /// The caller's `Io` was cancelled mid-question.
    canceled: u64 = 0,

    // -- the pass itself --------------------------------------------------
    /// The node was configured with no peers, so there was nobody to look up.
    /// Counted once per due tick rather than left as a pass that silently does
    /// nothing: a node that will have no peers on its next tick either is a
    /// configuration, and a number is how a reader sees it.
    no_peer: u64 = 0,
    /// The caller's instant cannot be expressed in the unit the discovery
    /// timers are in, so no tick could be asked. Reachable only at a clock
    /// before this node's epoch, and refused by name rather than asserted:
    /// `node_config.Error.InstantOutOfRange` is what the same conversion is
    /// called one layer up.
    clock_unusable: u64 = 0,
};

/// What one operation came to, as a name the counters can be read against.
///
/// One arm per non-success outcome and one for the success, and every refusal
/// arm is the name of the `Refused` field that counts it: a caller switching on
/// this value and a reader of `Refused` are reading the same facts in the same
/// spelling, which is what makes a refusal countable rather than merely
/// reportable. The shape is `node_gossip_wire.Outcome`'s and for its reason.
pub const Outcome = enum {
    /// The relay took the packet, or the answer carried records this node
    /// could act on. The only arm with no counter.
    accepted,
    /// See `Refused.nothing_to_publish`.
    nothing_to_publish,
    /// See `Refused.too_many_relays`.
    too_many_relays,
    /// See `Refused.signer_refused`.
    signer_refused,
    /// See `Refused.relay_refused`.
    relay_refused,
    /// See `Refused.unaccepted`.
    unaccepted,
    /// See `Refused.deferred`.
    deferred,
    /// See `Refused.stale`.
    stale,
    /// See `Refused.no_source`.
    no_source,
    /// See `Refused.origin_too_long`.
    origin_too_long,
    /// See `Refused.query_refused`.
    query_refused,
    /// See `Refused.foreign`.
    foreign,
    /// See `Refused.truncated`.
    truncated,
    /// See `Refused.undecodable`.
    undecodable,
    /// See `Refused.timed_out`.
    timed_out,
    /// See `Refused.nothing`.
    nothing,
    /// See `Refused.no_peer`.
    no_peer,
    /// See `Refused.clock_unusable`.
    clock_unusable,
    /// See `Refused.cannot_resolve`.
    cannot_resolve,
    /// See `Refused.no_item`.
    no_item,
    /// See `Refused.unreadable`.
    unreadable,
    /// See `Refused.out_of_memory`.
    out_of_memory,
    /// See `Refused.canceled`.
    canceled,
};

/// Put this node's own record at the relay, and say whether it was stored.
///
/// The record is `records` — the `_iroh` strings
/// `discovery/pkarr_services.PkarrPublisher.writeTxtStrings` wrote — and the
/// key is this node's own, so `pkarr_live.publish`'s signer check is the thing
/// standing between one node's addresses and another's name.
///
/// **Nothing is raised.** Every refusal is a counter and a log line, because a
/// relay that is down is a fact about the relay and not a fault of the node:
/// `Node.step` would then have to be answered with `error.OutOfMemory` for a
/// relay that happened to be unreachable, and `node.zig`'s own rule is that a
/// failed pass is a node to be closed rather than a pass to be replayed.
///
/// The caller records the attempt and the outcome on `publisher.State`; see
/// `node_discovery.republish`.
pub fn publish(
    self: *Node,
    io: std.Io,
    records: txt.RecordSet,
    random: std.Random,
) bool {
    const relay = self.config.discovery.relay orelse {
        // A node that was not given a pkarr relay has nothing to publish, and
        // `discovery/preset.zig`'s `Publication.relay_only` is exactly that
        // answer: this node is reachable through the relays it already dials
        // and publishes nothing anywhere else. No slot was armed, so this arm
        // is not reached; the counter is here for a caller that armed one and
        // then took the relay away.
        self.discovery.refused.nothing_to_publish += 1;
        return false;
    };
    // Read once per attempt, and used only for the two values that must be
    // wall-clock: the packet's own claim about when it was signed and the
    // trust store's window. See the module doc.
    const now = std.Io.Clock.real.now(io);
    const timestamp_us = std.math.cast(u64, @divTrunc(now.nanoseconds, std.time.ns_per_us)) orelse {
        self.discovery.refused.unaccepted += 1;
        std.log.warn(
            "node {f}: a clock this node cannot date a packet with",
            .{self.nodeId()},
        );
        return false;
    };
    random.bytes(&self.discovery.entropy);
    var out: pkarr_live.Response = .{
        .status = 0,
        .body = &.{},
        .buffer = relay.response,
    };
    pkarr_live.publish(self.gpa, io, .{
        .base_url = relay.base_url,
        .server = relay.server,
        .trust = .{
            // `pkarr_live.exchange` reads the host out of `base_url` itself and
            // never looks at this field, which is here because
            // `tls_client.Options.host` has no default and no
            // `no_verification` alternative. See `node_config.Relay`.
            .host = relay.certificate_host,
            .bundle = relay.bundle,
            .bundle_lock = relay.bundle_lock,
            .entropy = &self.discovery.entropy,
            .now = now,
            .read_buffer = relay.read_buffer,
            .write_buffer = relay.write_buffer,
            .timeout_ms = relay.timeout_ms,
        },
        .read_buffer = relay.read_buffer,
        .write_buffer = relay.write_buffer,
        .timeout_ms = relay.timeout_ms,
    }, .{
        .secret = &self.config.secret,
        .timestamp_us = timestamp_us,
        .records = records,
    }, self.nodeId(), &out) catch |err| {
        count(self, publishFailed(err));
        return false;
    };
    self.stats.discovery_publishes += 1;
    return true;
}

/// Ask the nameserver about `peer` and take whatever comes back to the node's
/// own resolution path.
///
/// **The question is a real `_iroh.<z32>.<origin>` TXT question, framed by
/// `discovery/dns_live.zig` and decoded by it.** Only the socket is injected:
/// `Config.discovery.lookup`'s `datagram` is the seam `discovery/lookup_io.zig`
/// was built around, and in production it is a `dns_live.Resolver`'s own
/// `seam()`. So the transaction id really is drawn from `random` and really has
/// to be echoed, the `QR` and `TC` bits really are checked, and the answer
/// really is walked record by record — this is the module's path, not a
/// stand-in for it.
///
/// `dns_live.Retrieval.ask` maps a datagram that never arrived onto
/// `Answer.timeout`, so a timeout is a *different arm* here from an answer that
/// arrived carrying nothing, and the two reach two different counters. That is
/// the distinction `discovery/lookup_io.zig` argues for at length and the
/// reason this function switches on the answer rather than on a bool.
pub fn ask(self: *Node, io: std.Io, peer: NodeId, random: std.Random) void {
    const source = self.config.discovery.lookup orelse {
        self.discovery.refused.no_source += 1;
        return;
    };
    const origin = self.config.discovery.origin;
    if (dns.queryNameLength(origin) > self.discovery.name.len) {
        self.discovery.refused.origin_too_long += 1;
        return;
    }
    const name = dns.queryName(&self.discovery.name, peer, origin);
    // A fresh retrieval per pass: the transaction id is drawn here and a second
    // ask through one retrieval would ask the same question again and read the
    // first one's late answer (`lookup_retrieval.Retrieval.ask`'s own rule).
    var retrieval: dns_live.Retrieval = .{
        .datagram = source.datagram,
        .server = source.server,
        .id = random.int(u16),
    };
    self.stats.discovery_lookups += 1;
    const answer = retrieval.ask(self.gpa, io, .{
        .name = name,
        .wire = &self.discovery.question,
        .reply = &self.discovery.reply,
        .deadline_ms = self.config.discovery.deadline_ms,
    }) catch |err| {
        count(self, lookupFailed(err));
        return;
    };
    // The records are copied out of `alloc` by `ask`, so the answer owns them
    // until this returns and `records` below is only a borrow of that copy.
    defer answer.deinit(self.gpa);
    switch (answer) {
        // The third arm, and not an error: the clock ran out, not the world.
        .timeout => self.discovery.refused.timed_out += 1,
        // The name exists and nothing was published under it. Also not an
        // error, and not the same fact.
        .nothing => self.discovery.refused.nothing += 1,
        .records => |records| resolveThrough(self, peer, records),
    }
}

/// Hand the records to the resolver that already exists and take what it finds.
///
/// This is the node's own resolution path: `dns_live.Resolver.service` builds
/// `discovery/dns.zig`'s `DnsAddressLookup` over the records and the items come
/// off a `resolve.Stream` exactly as `discovery/dial_source.zig` would read
/// them. The stream, the service and the records all die with this call, which
/// is why nothing here keeps an address: this node has no use for a resolved
/// peer yet, and keeping one would be a second answer list beside
/// `Node.map`'s.
///
/// **A stream that ends with no item is counted apart from both `timed_out` and
/// `nothing`.** Records arrived, the resolver ran, and it produced none: a
/// third fact, and the one that says the records did not parse into an
/// address.
fn resolveThrough(
    self: *Node,
    peer: NodeId,
    records: txt.RecordSet,
) void {
    self.stats.discovery_answers += 1;
    var service = dns_live.Resolver.service(records, null);
    var stream = service.lookup().resolve(self.gpa, peer) catch {
        self.discovery.refused.out_of_memory += 1;
        return;
    } orelse {
        self.discovery.refused.cannot_resolve += 1;
        return;
    };
    defer stream.deinit();
    var items: usize = 0;
    while (stream.next()) |event| switch (event) {
        .item => |found| {
            items += 1;
            self.stats.discovery_addresses += found.endpoint.addrs.len;
        },
        .failed => |failure| {
            self.discovery.refused.unreadable += 1;
            // `Provenance` is an enum with a `rank` and no `format`, and the
            // rank is its declaration order — `.dns` first, `.pkarr` second,
            // `.memory_lookup` third — which is the ordering a log reader wants
            // and the one `item_record.Provenance` publishes for it.
            std.log.warn("node {f}: a discovery answer of rank {d} could not be read: {t}", .{
                self.nodeId(),
                failure.provenance.rank(),
                failure.reason,
            });
        },
    };
    if (items == 0) {
        self.discovery.refused.no_item += 1;
        return;
    }
    self.stats.discovery_items += items;
}

/// Which counter one refused publish moves.
///
/// `error.UnexpectedSigner` and `error.StatusNotSuccess` are the two the tree
/// names and a caller acts on differently, so they are arms of their own.
/// Everything else this module can fail with is a relay that was not reached
/// or an answer that was not usable, and it is logged by name on the way —
/// which is `node_gossip_wire.encoded`'s rule: a reason is never only a number.
fn publishFailed(err: pkarr_live.Error) Outcome {
    return switch (err) {
        error.UnexpectedSigner => .signer_refused,
        error.StatusNotSuccess => .relay_refused,
        else => blk: {
            std.log.warn("a pkarr relay refused a publish: {t}", .{err});
            break :blk .unaccepted;
        },
    };
}

/// Which counter one refused question moves.
///
/// The three the pass must keep apart are three arms: a `TC` bit is
/// `truncated` because the retry needs a stream this node has none of, a
/// foreign transaction or a foreign source is `foreign`, and an `RCODE` or a
/// malformed message is `undecodable`. `error.Empty` never arrives here:
/// `dns_live.Retrieval.ask` has already turned it into `Answer.timeout`.
fn lookupFailed(err: dns_live.Error) Outcome {
    return switch (err) {
        error.Truncated => .truncated,
        error.ForeignTransaction, error.ForeignSource => .foreign,
        error.Refused => .query_refused,
        error.OutOfMemory => .out_of_memory,
        error.Canceled => .canceled,
        else => blk: {
            std.log.warn("a DNS question was refused: {t}", .{err});
            break :blk .undecodable;
        },
    };
}

/// Move one refusal under its own name.
///
/// Public because `node_discovery.zig`'s state machine reaches the counters for
/// the arms only this file's two arms can produce — a deferred tick, a stale
/// record, a node with no peers, a clock it cannot use — and a refusal named in
/// two files must still be one counter.
pub fn count(self: *Node, refused: Outcome) void {
    const counts = &self.discovery.refused;
    switch (refused) {
        .accepted => return,
        .nothing_to_publish => counts.nothing_to_publish += 1,
        .too_many_relays => counts.too_many_relays += 1,
        .signer_refused => counts.signer_refused += 1,
        .relay_refused => counts.relay_refused += 1,
        .unaccepted => counts.unaccepted += 1,
        .deferred => counts.deferred += 1,
        .stale => counts.stale += 1,
        .no_peer => counts.no_peer += 1,
        .clock_unusable => counts.clock_unusable += 1,
        .no_source => counts.no_source += 1,
        .origin_too_long => counts.origin_too_long += 1,
        .query_refused => counts.query_refused += 1,
        .foreign => counts.foreign += 1,
        .truncated => counts.truncated += 1,
        .undecodable => counts.undecodable += 1,
        .timed_out => counts.timed_out += 1,
        .nothing => counts.nothing += 1,
        .cannot_resolve => counts.cannot_resolve += 1,
        .no_item => counts.no_item += 1,
        .unreadable => counts.unreadable += 1,
        .out_of_memory => counts.out_of_memory += 1,
        .canceled => counts.canceled += 1,
    }
}
