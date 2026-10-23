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

const dns_live = @import("../discovery/dns_live.zig");
const dns = @import("../discovery/dns.zig");
const pkarr_live = @import("../discovery/pkarr_live.zig");
const resolve = @import("../discovery/resolve.zig");
const txt = @import("../discovery/txt.zig");
const lookup_io = @import("../discovery/lookup_io.zig");
const lookup_wire = @import("../discovery/lookup_wire.zig");
const dial_source_walk = @import("../discovery/dial_source_walk.zig");
const pkarr_body = @import("../discovery/pkarr_body.zig");
const discovery_item = @import("../discovery/item.zig");
const addr = @import("../base/addr.zig");
const Instant = @import("../transport/dial.zig").Instant;

const base_key = @import("../base/key.zig");

const Self = node_mod.Node;
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
    /// `503` are the same arm here, and `pkarr_live.Response.status` is what tells
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
    /// The validated UDP answer requested TCP fallback, but the bounded
    /// stream answer was itself truncated. UDP truncation alone is not a
    /// refusal: `dns_live.Retrieval.ask` performs the real TCP retry.
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
    /// The relay took the published packet. The only arm with no counter.
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
    self: *Self,
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

/// Resolve and initiate one pinned dial for a requested identity.
/// Static attempts and earlier lookup attempts share the deliberate one-shot latch.
/// DNS failure never hides an explicitly enabled PKARR source.
pub fn ask(self: *Self, io: std.Io, peer: NodeId, at: Instant, random: std.Random) void {
    if (self.dialled.contains(peer)) return;
    self.dialled.put(self.gpa, peer, {}) catch {
        count(self, .out_of_memory);
        return;
    };
    self.stats.discovery_lookups += 1;
    const dns_answer = fetchDns(self, io, peer, random);
    defer if (dns_answer) |answer| answer.deinit(self.gpa);
    var sources: [2]resolve.AddressLookup = undefined;
    var source_count: usize = 0;
    var dns_service = dns_live.Resolver.service(.init(""), null);
    if (answerRecords(self, dns_answer)) |records| {
        dns_service = dns_live.Resolver.service(records, null);
        sources[source_count] = dns_service.lookup();
        source_count += 1;
    }
    var pkarr_records: ?lookup_io.Answer = null;
    defer if (pkarr_records) |answer| answer.deinit(self.gpa);
    var pkarr_service: VerifiedRecords = .{ .service = dns_live.Resolver.service(.init(""), null) };
    if (self.config.discovery.resolve_pkarr) {
        pkarr_records = fetchPkarr(self, io, peer, random);
        if (answerRecords(self, pkarr_records)) |records| {
            pkarr_service.service = dns_live.Resolver.service(records, null);
            sources[source_count] = pkarr_service.lookup();
            source_count += 1;
        }
    }
    if (source_count == 0) {
        if (self.config.discovery.lookup == null and !self.config.discovery.resolve_pkarr)
            count(self, .no_source);
        return;
    }
    dialSources(self, sources[0..source_count], peer, at, random);
}

fn dialSources(
    self: *Self,
    sources: []resolve.AddressLookup,
    peer: NodeId,
    at: Instant,
    random: std.Random,
) void {
    const outcome = dial_source_walk.dialFromSources(self.gpa, sources, self.dialer, .{
        .node_id = peer,
        .local = self.socket.address,
        .map = &self.map,
        .select = .{ .ctx = self, .pick = selectAddress },
        .at = at,
        .random = random,
    }) catch |err| {
        if (err == error.OutOfMemory) count(self, .out_of_memory);
        self.stats.dials_refused += 1;
        std.log.warn("node {f}: discovery dial to {f} refused: {t}", .{ self.nodeId(), peer, err });
        return;
    };
    if (outcome.first_failure) |failure| {
        count(self, .unreadable);
        std.log.warn(
            "node {f}: discovery source rank {d} refused: {t}",
            .{ self.nodeId(), failure.provenance.rank(), failure.reason },
        );
    }
    switch (outcome.result) {
        .cannot_resolve => count(self, .cannot_resolve),
        .nothing => count(self, .no_item),
        .no_address => count(self, .no_item),
        // Initiated, not authenticated success: Node.step drives the handshake.
        .dialed => self.stats.dials += 1,
    }
}

fn answerRecords(self: *Self, answer: ?lookup_io.Answer) ?resolve.RecordSet {
    const received = answer orelse return null;
    switch (received) {
        .timeout => count(self, .timed_out),
        .nothing => count(self, .nothing),
        .records => |records| {
            self.stats.discovery_answers += 1;
            return records;
        },
    }
    return null;
}

fn fetchDns(self: *Self, io: std.Io, peer: NodeId, random: std.Random) ?dns_live.Answer {
    if (self.config.discovery.lookup) |source| {
        const origin = self.config.discovery.origin;
        if (dns.queryNameLength(origin) > self.discovery.name.len) {
            count(self, .origin_too_long);
        } else {
            var retrieval: dns_live.Retrieval = .{
                .datagram = source.datagram,
                .server = source.server,
                .id = random.int(u16),
                .resolver_stopped = source.resolver_stopped,
                .stream_execution = source.stream_execution,
            };
            return retrieval.ask(self.gpa, io, .{
                .name = dns.queryName(&self.discovery.name, peer, origin),
                .wire = &self.discovery.question,
                .reply = &self.discovery.reply,
                .deadline_ms = self.config.discovery.deadline_ms,
            }) catch |err| {
                count(self, lookupFailed(err));
                return null;
            };
        }
    }
    return null;
}

fn selectAddress(ctx: *anyopaque, endpoint: *const addr.NodeAddr) ?addr.TransportAddr {
    const self: *Self = @ptrCast(@alignCast(ctx));
    self.stats.discovery_items += 1;
    self.stats.discovery_addresses += endpoint.addrs.len;
    // The node's UDP socket can send direct IP candidates. Relay candidates
    // require the relay carrier; do not pretend an unmapped relay is reachable.
    for (endpoint.addrs) |candidate| switch (candidate) {
        .ip => return candidate,
        .relay, .custom => {},
    };
    return null;
}

/// A verified PKARR packet has already supplied these records. Reuse the TXT
/// parser and stream ownership, retaining the signed source's provenance.
const VerifiedRecords = struct {
    service: dns.DnsAddressLookup,
    const vtable: resolve.AddressLookup.VTable = .{
        .publish = resolve.AddressLookup.ignore_publish,
        .resolve = start,
    };

    fn lookup(self: *VerifiedRecords) resolve.AddressLookup {
        return .{ .ctx = self, .vtable = &vtable };
    }

    fn start(
        ctx: *anyopaque,
        // AddressLookup.VTable.resolve requires context first; reordering changes its ABI.
        // ziglint-ignore: Z023
        alloc: std.mem.Allocator,
        peer: NodeId,
    ) resolve.ResolveError!?resolve.Stream {
        const self: *VerifiedRecords = @ptrCast(@alignCast(ctx));
        var inner = (try self.service.lookup().resolve(alloc, peer)) orelse return null;
        errdefer inner.deinit();
        const state = try alloc.create(SignedStream);
        state.* = .{ .inner = inner };
        return .{ .state = state, .vtable = &SignedStream.vtable, .alloc = alloc, .status = .live };
    }
};

const SignedStream = struct {
    inner: resolve.Stream,
    slot: [1]discovery_item.Item = undefined,
    has_item: bool = false,
    const vtable: resolve.Stream.VTable = .{
        .next = next,
        .finish = finish,
        .cancel = cancel,
        .destroy = destroy,
    };

    fn next(ctx: *anyopaque) ?resolve.Event {
        const self: *SignedStream = @ptrCast(@alignCast(ctx));
        var event = self.inner.next() orelse return null;
        switch (event) {
            .item => |*found| {
                found.provenance = .pkarr;
                self.slot[0] = found.*;
                self.has_item = true;
            },
            .failed => |*failure| failure.provenance = .pkarr,
        }
        return event;
    }

    fn finish(ctx: *anyopaque) discovery_item.Resolution {
        const self: *SignedStream = @ptrCast(@alignCast(ctx));
        return switch (self.inner.finish()) {
            .cannot_resolve => .cannot_resolve,
            .resolved => .{ .resolved = if (self.has_item) &self.slot else &.{} },
        };
    }

    fn cancel(_: *anyopaque) void {
        // The synchronous TLS retrieval is closed before the stream starts.
    }

    fn destroy(
        ctx: *anyopaque,
        // Stream.VTable.destroy requires context first; reordering changes its ABI.
        // ziglint-ignore: Z023
        alloc: std.mem.Allocator,
    ) void {
        const self: *SignedStream = @ptrCast(@alignCast(ctx));
        self.inner.deinit();
        alloc.destroy(self);
    }
};

fn fetchPkarr(self: *Self, io: std.Io, peer: NodeId, random: std.Random) ?lookup_io.Answer {
    const relay = self.config.discovery.relay orelse {
        count(self, .no_source);
        return null;
    };
    random.bytes(&self.discovery.entropy);
    const now = std.Io.Clock.real.now(io);
    var out: pkarr_live.Response = .{ .status = 0, .body = &.{}, .buffer = relay.response };
    const answer = pkarr_live.resolve(self.gpa, io, .{
        .base_url = relay.base_url,
        .server = relay.server,
        .trust = .{
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
        .timeout_ms = @min(
            relay.timeout_ms orelse self.config.discovery.deadline_ms,
            self.config.discovery.deadline_ms,
        ),
    }, peer, &out) catch |err| {
        count(self, if (err == error.OutOfMemory) .out_of_memory else .unreadable);
        std.log.warn("node {f}: PKARR lookup for {f} refused: {t}", .{ self.nodeId(), peer, err });
        return null;
    };
    var name: [pkarr_body.nameLength()]u8 = undefined;
    var owner: [lookup_wire.max_name_length]u8 = undefined;
    return pkarr_body.readBody(self.gpa, answer.packet.dns, peer, &name, &owner) catch |err| {
        count(self, lookupFailed(err));
        return null;
    };
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
/// A truncated TCP fallback stays apart from a foreign transaction/source and
/// an undecodable answer. UDP truncation is handled by `Retrieval.ask`, not
/// translated into success or discarded here. An empty deadline becomes
/// `Answer.timeout`, which remains distinct from an empty answer.
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
pub fn count(self: *Self, refused: Outcome) void {
    if (refusalCounter(&self.discovery.refused, refused)) |counter| counter.* += 1;
}

fn refusalCounter(counts: *Refused, refused: Outcome) ?*u64 {
    return switch (refused) {
        .accepted => null,
        .nothing_to_publish => &counts.nothing_to_publish,
        .too_many_relays => &counts.too_many_relays,
        .signer_refused => &counts.signer_refused,
        .relay_refused => &counts.relay_refused,
        .unaccepted => &counts.unaccepted,
        .deferred => &counts.deferred,
        .stale => &counts.stale,
        .no_peer => &counts.no_peer,
        .clock_unusable => &counts.clock_unusable,
        .no_source => &counts.no_source,
        .origin_too_long => &counts.origin_too_long,
        .query_refused => &counts.query_refused,
        .foreign => &counts.foreign,
        .truncated => &counts.truncated,
        .undecodable => &counts.undecodable,
        .timed_out => &counts.timed_out,
        .nothing => &counts.nothing,
        .cannot_resolve => &counts.cannot_resolve,
        .no_item => &counts.no_item,
        .unreadable => &counts.unreadable,
        .out_of_memory => &counts.out_of_memory,
        .canceled => &counts.canceled,
    };
}

test {
    _ = @import("node_discovery_lookup_test.zig");
}

test "verified PKARR records keep signed provenance in the fan-in finish set" {
    const t = std.testing;
    const id = (try base_key.SecretKey.fromSeed(@splat(0x51))).nodeId();
    var service: VerifiedRecords = .{
        .service = dns_live.Resolver.service(.init("addr=127.0.0.1:4242\x00"), null),
    };
    var stream = (try service.lookup().resolve(t.allocator, id)) orelse
        return error.ExpectedResolvedStream;
    defer stream.deinit();
    const event = stream.next() orelse return error.ExpectedResolvedItem;
    try t.expectEqual(discovery_item.Provenance.pkarr, event.item.provenance);
    try t.expect(stream.next() == null);
    const result = stream.finish().resolved;
    try t.expectEqual(@as(usize, 1), result.len);
    try t.expectEqual(discovery_item.Provenance.pkarr, result[0].provenance);
    try t.expectEqual(id, result[0].endpoint.node_id);
}

test "a DNS source canceled at UDP truncation remains canceled in the node" {
    // Stop the actual source after TC, before the node enters TCP fallback.
    const t = std.testing;
    var resolver = try dns_live.Resolver.open(
        .{ .ip = .{ .v4 = .{ 127, 0, 0, 1 } }, .port = 0 },
        .{ .ip = .{ .v4 = .{ 127, 0, 0, 1 } }, .port = 0 },
        .{},
    );
    defer resolver.close();
    var script: CancelAtTruncation = .{ .resolver = &resolver };
    const node = try Self.create(t.allocator, t.io, .{
        .secret = try base_key.SecretKey.fromSeed(@splat(0x71)),
        .listen = .{ .ip = .{ .v4 = .{ 127, 0, 0, 1 } }, .port = 0 },
        .discovery = .{
            .lookup = .{
                .datagram = script.datagram(),
                .server = resolver.server,
                .resolver_stopped = &resolver.stopped,
                .stream_execution = resolver.stream_execution,
            },
            .deadline_ms = 100,
        },
    }, 0x51eed);
    defer node.deinit();
    defer node.close(t.io, 0, node.generator()) catch |err| {
        std.debug.panic("DNS cancellation fixture teardown failed: {t}", .{err});
    };
    var secret = try base_key.SecretKey.fromSeed(@splat(0x72));
    defer secret.deinit();
    var prng = std.Random.DefaultPrng.init(0x51eed);
    const result = fetchDns(node, t.io, secret.nodeId(), prng.random());
    defer if (result) |answer| answer.deinit(t.allocator);
    try t.expect(script.received);
    try t.expect(resolver.stopped.load(.acquire));
    try t.expect(result == null);
    try t.expectEqual(@as(u64, 1), node.discovery.refused.canceled);
    try t.expectEqual(@as(u64, 0), node.discovery.refused.query_refused);
}

const CancelAtTruncation = struct {
    resolver: *dns_live.Resolver,
    transaction: u16 = 0,
    received: bool = false,

    fn datagram(self: *CancelAtTruncation) lookup_io.Datagram {
        return .{ .ctx = self, .send = send, .receive = receive, .stop = stop };
    }

    fn send(
        ctx: *anyopaque,
        io: std.Io,
        to: addr.SocketAddr,
        bytes: []const u8,
    ) lookup_io.SocketError!void {
        _ = io;
        const self: *CancelAtTruncation = @ptrCast(@alignCast(ctx));
        if (to.order(self.resolver.server) != .eq) return error.Refused;
        self.transaction = lookup_wire.be16(bytes, 0);
    }

    fn receive(
        ctx: *anyopaque,
        io: std.Io,
        into: []u8,
        deadline_ms: ?i32,
    ) lookup_io.SocketError!lookup_io.Datagram.Reply {
        _ = io;
        _ = deadline_ms;
        const self: *CancelAtTruncation = @ptrCast(@alignCast(ctx));
        if (into.len < lookup_wire.header_length) return error.Refused;
        const reply = into[0..lookup_wire.header_length];
        @memset(reply, 0);
        lookup_wire.put16(reply, 0, self.transaction);
        lookup_wire.put16(reply, 2, lookup_wire.flag_response | lookup_wire.flag_truncated);
        self.received = true;
        self.resolver.cancellation().fire();
        return .{ .from = self.resolver.server, .bytes = reply };
    }

    fn stop(ctx: *anyopaque) void {
        const self: *CancelAtTruncation = @ptrCast(@alignCast(ctx));
        self.resolver.cancellation().fire();
    }
};
