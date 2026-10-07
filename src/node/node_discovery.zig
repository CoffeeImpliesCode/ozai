//! The node's discovery pass: republish what this node is reachable at, and
//! look one peer up, each on a timer of its own.
//!
//! `node.zig`'s module doc named this as the second thing the node's loop did
//! not do. `discovery/publisher.zig` already models the republish timer and the
//! fan-in over several sources, `discovery/dns_live.zig` already puts a
//! `_iroh.<z32>.<origin>` TXT question on a datagram socket of its own, and
//! `discovery/pkarr_live.zig` already signs a packet and hands it to a relay
//! over TLS — and nothing under `src/node/` reached any of them. A node could
//! dial a peer it had been handed and could not find one.
//!
//! # The shape, and why it is a state machine beside a wire
//!
//! `publisher.State.tick` is the whole of the decision: pure over this node's
//! own state and the caller's instant, no clock and no socket (`publisher.zig`
//! says so of itself). This file owns that state, asks the question, and hands
//! the answer to `node_discovery_wire.zig`, which does the I/O and counts every
//! refusal by name. The split is `node_gossip.zig` and `node_gossip_wire.zig`'s
//! and for its reason: a pass that both decides and writes cannot be driven at
//! a fixed clock, and a node that cannot be driven at a fixed clock cannot be
//! tested.
//!
//! # What the pass publishes, and what it does not
//!
//! **This node's own record, and nothing else.** The address list is the node's
//! listen address plus whatever relays the configuration named, merged by
//! `publisher.mergePublished` — one fan-in for every source, so a rule about
//! what may be published under one node's key exists once (`publisher.zig`
//! refuses `error.MixedNodeIds` for exactly this).
//!
//! **Publication is relay-only, which is `discovery/preset.zig`'s own default
//! and is kept.** `Publication.relay_only` says the node "is reachable through
//! the relays in `Preset.relays` and publishes nothing anywhere else: no DNS
//! TXT record, no pkarr packet, no direct address handed to a third party", and
//! `Preset.n0` is the value this node takes. So a node with no relay configured
//! has nothing to publish: `arm` refuses it by name
//! (`Refused.nothing_to_publish`) rather than arming a slot nothing would ever
//! fill, and the republish timer then never comes due. **A lookup is not a
//! publication**: asking a nameserver about a peer puts a question on the wire
//! and publishes nothing, and the two arms are counted apart throughout.
//!
//! # The clock and the entropy are the caller's, and so is the socket
//!
//! `pass` takes `at` and derives the publisher's `now_ms` from it, so a test
//! drives this node at a counter and not at a clock. `random` supplies the DNS
//! transaction id and the TLS driver's key share. The one wall-clock read lives
//! in `node_discovery_wire.publish`, because `pkarr_live.Publish.timestamp_us`
//! and `tls_client.Options.now` are both wall-clock facts the modules below
//! refuse to discover for themselves.
//!
//! # Which peer, and when
//!
//! One peer per lookup tick, round-robin over `Config.peers`, because a pass
//! that resolved every configured peer would put `max_bootstrap` questions on
//! the wire between two timer fires and answer none of them before the next.
//! `lookup_interval_ms` is the gap, and it is this project's value for the same
//! reason `publisher.default_republish_interval_ms` is: nothing upstream's is
//! quoted from memory here.

const std = @import("std");

const node_mod = @import("node.zig");
const node_config = @import("node_config.zig");
const node_discovery_record = @import("node_discovery_record.zig");
const node_discovery_wire = @import("node_discovery_wire.zig");

const lookup_wire = @import("../discovery/lookup_wire.zig");
const pkarr_live = @import("../discovery/pkarr_live.zig");
const host_io = @import("../discovery/host_io.zig");
const lookup_io = @import("../discovery/lookup_io.zig");
const preset = @import("../discovery/preset.zig");
const publisher = @import("../discovery/publisher.zig");
const tls_client = @import("../discovery/tls_client.zig");

const base_addr = @import("../base/addr.zig");
const base_key = @import("../base/key.zig");
const bridge_mod = @import("../transport/quic_bridge.zig");

const Node = node_mod.Node;
const Instant = bridge_mod.Instant;
const NodeId = base_key.NodeId;

/// How many relays one record may carry, and the room their records need. Both
/// are `node_discovery_record`'s: what this node publishes is that module's
/// subject, and a reader of the pass should not have to open a second file to
/// learn a buffer size.
pub const max_relays = node_discovery_record.max_relays;
/// See `max_relays`.
pub const record_room = node_discovery_record.record_room;

/// How long the pass waits between lookups when the caller names no interval.
///
/// Two minutes, and it is this project's choice rather than a value quoted from
/// a file that is not on this machine — the same reason
/// `publisher.default_republish_interval_ms` carries its own. A node's own
/// record goes stale at the relay on the order of an hour, so looking a peer up
/// twice inside that is looking it up twice for the same answer; and the
/// question is a datagram on somebody else's nameserver, which is a cost this
/// project should not pay by default.
pub const default_lookup_interval_ms: u64 = 120_000;

/// What one node publishes about itself, where, and whom it looks up.
///
/// **`Config{}` — the default — is a node that publishes nothing and looks
/// nobody up**, which is `discovery/preset.zig`'s `Publication.relay_only`
/// reached through configuration: the node is reachable through the relays it
/// already dials and hands no address to a third party. A caller that wants a
/// pkarr packet names `relay`; a caller that wants its peers resolved names
/// `lookup` and at least one peer id in `Config.peers`.
///
/// **Every slice and pointer is the caller's and outlives the node**, which is
/// `node_config.Config`'s own rule for its borrowed fields applied to this one.
/// Nothing here is copied at `create`: `Config` is taken by value and the
/// storage it names is borrowed.
pub const Config = struct {
    /// The relay URLs this node is reachable at, and the only addresses it
    /// publishes. At most `max_relays`; more is `Refused.too_many_relays`.
    ///
    /// **A direct address is never in this list**, and that is a decision:
    /// see `arm`.
    relays: []const []const u8 = &.{},
    /// The pkarr relay to publish to and the trust that goes with it. Null for
    /// a node that publishes nothing, which is the default and needs no relay
    /// to be named.
    relay: ?node_config.DiscoveryRelay = null,
    /// Where a `_iroh` TXT question goes, and the seam it goes out on. Null for
    /// a node that looks nobody up, which is the default.
    ///
    /// **The seam is injected, and in production it is a `dns_live.Resolver`'s
    /// own** — `Resolver.seam()` is what a caller hands here, and `dns_live.zig`'s
    /// module doc is why it is a vtable and not a socket. A resolver of its own
    /// per subsystem is that module's whole subject, and a node that shared its
    /// gossip socket with a lookup would consume a datagram meant for gossip.
    lookup: ?Source = null,
    /// Identity-only peers resolved and dialled once. No physical endpoint is required.
    peer_ids: []const NodeId = &.{},
    /// Resolve through the configured PKARR relay as well as the DNS source.
    resolve_pkarr: bool = false,
    /// The origin `_iroh.<z32>` is asked under, borrowed. `preset.dns_origin_prod`
    /// and its staging twin are the two values this tree's presets name.
    origin: []const u8 = preset.dns_origin_prod,
    /// How long one question waits. `discovery/host_io.query_timeout_ms` is
    /// upstream's own per-query figure — `iroh/src/address_lookup/dns.rs:19`
    /// restates it as "Each query has its own timeout of 3s" — and the default
    /// here for that reason. Reached rather than restated, so the two modules
    /// cannot drift apart unnoticed.
    deadline_ms: i32 = host_io.query_timeout_ms,
    /// How long the pass waits between lookups. `default_lookup_interval_ms`
    /// when the caller names none.
    interval_ms: u64 = default_lookup_interval_ms,
};

/// A datagram a question goes out on, and the server that answers it.
///
/// A group of its own rather than two `Config` fields because they travel
/// together and neither means anything without the other: a seam with no server
/// names no destination, and a server with no seam has nothing to send it on.
pub const Source = struct {
    /// The datagram, borrowed. `dns_live.Resolver.seam()` in production; a
    /// scripted socket's `datagram()` in a test. Whatever its `ctx` reaches
    /// must outlive every pass this node makes.
    datagram: lookup_io.Datagram,
    /// Who questions go to, by value. RFC 1035 §7.2's "the client should try
    /// other servers before repeating a query" is a policy and needs an instant
    /// this node deliberately does not keep, so one source asks one server.
    server: base_addr.SocketAddr,
};

/// What one node's discovery pass owns, and what it has refused.
///
/// **A value and not a service, so `create` writes nothing and `deinit` has one
/// answer to give.** Everything here is fixed storage — the publisher's slot
/// pointer, the two DNS buffers, the name, the TLS entropy — and the counters.
/// The one thing this node owns that is not fixed storage is the
/// `publisher.State` slot, a `Published` transferred into it and released by
/// `releaseSlot`; see `disarm`.
pub const State = struct {
    /// The republish timer and the record it republishes. `publisher.State`
    /// unchanged: its `tick` is the decision and this file only acts on the
    /// answer, so the interval, the deferral bound and the stale bound are
    /// `publisher`'s own and not restated here.
    publisher: publisher.State = .init(),

    /// The question this node asks about one peer, in presentation form:
    /// `_iroh.<z32>.<origin>`. Bounded by RFC 1035 §2.3.4's 255-octet name,
    /// which is `lookup_wire.max_name_length`, and a longer configured origin is
    /// refused by name rather than asserted.
    name: [lookup_wire.max_name_length]u8 = undefined,

    /// Where a question is framed. `lookup_wire.reply_length` is the same
    /// figure for both directions and a query for the longest name this node
    /// can frame is shorter than it, so one bound covers both and the two
    /// buffers cannot be sized apart by accident.
    question: [lookup_wire.reply_length]u8 = undefined,
    /// Where an answer is read. Same bound, same reason.
    reply: [lookup_wire.reply_length]u8 = undefined,

    /// Where this node's own `_iroh` records are written before they are
    /// signed. `record_room` is `txt.maxTxtStringsLength(max_relays)`, which is
    /// the writer's own arithmetic for a list this node cannot exceed, so the
    /// buffer cannot be too small for a record built here.
    records: [record_room]u8 = undefined,

    /// The TLS driver's key share and randoms, 240 bytes filled from the
    /// caller's `random` on each attempt. Held here rather than in
    /// `node_config.DiscoveryRelay` because it is *this node's* entropy and a
    /// caller's configuration must not carry a value that changes under it.
    entropy: [tls_client.entropy_length]u8 = undefined,

    /// When the next lookup is due, in the caller's `now_ms` scale, or null when
    /// none has been scheduled.
    next_lookup_ms: ?u64 = null,
    /// Which peer the next lookup asks about: an index into `Config.peers`, and
    /// taken modulo the list's length so a node whose peer list shrank still
    /// asks a peer that exists.
    peer_cursor: usize = 0,

    /// Everything the pass refused, by name. See `node_discovery_wire.Refused`.
    refused: node_discovery_wire.Refused = .{},

    /// Give back the record the publisher holds, and leave it empty.
    ///
    /// The one allocation this pass owns. `publisher.State.set` took the
    /// `Published` and `releaseSlot` gives it back with the allocator it
    /// arrived with, which is this node's `gpa` for every record `arm` builds —
    /// so a caller that handed in a record of its own must release that one
    /// itself, and `deinit` must not free what it did not take.
    ///
    /// Idempotent, because `publisher.State.releaseSlot` is.
    pub fn release(self: *State) void {
        self.publisher.releaseSlot();
    }
};

/// One discovery pass: republish this node's record if it is due, and ask about
/// one peer if a lookup is due.
///
/// **No clock is read here and none is stored.** `now_ms` is `at` in the unit
/// `publisher.tick` and `next_lookup_ms` are in, which is `publisher`'s own
/// requirement ("`tick` takes `now_ms` as an argument") and the reason this
/// pass is drivable at a counter. `io` is threaded per operation and reaches
/// neither a field nor a decision, which is `docs/DECISIONS/0002`'s rule.
///
/// Returns whether anything moved, so `Node.step`'s caller can tell an idle
/// pass from a busy one — the same `bool` every other pass in that step
/// returns, and read for the same reason.
///
/// **Neither arm can fail the pass.** Every refusal is counted and logged by
/// name in `node_discovery_wire`; a node whose relay is down and whose
/// nameserver is slow keeps gossiping. `Node.step`'s own rule is that a failed
/// pass is a node to be closed rather than a pass to be replayed, and a
/// discovery failure is the worst possible reason to close one.
pub fn pass(self: *Node, io: std.Io, at: Instant, random: std.Random) bool {
    var moved = republish(self, io, at, random);
    moved = lookup(self, io, at, random) or moved;
    return moved;
}

/// What one tick of the republish timer decided, done.
///
/// **The decision is `publisher.State.tick`'s and this function only acts on
/// it.** Four arms, in `publisher.zig`'s own order of questions, and each one
/// does the one thing that arm is for:
///
/// * `.wait_until` — nothing is due, and the value names the instant the next
///   tick is. Not an action and not a refusal: the common case, and a counter
///   here would be a number that means nothing.
/// * `.publish` — the record goes out now, and `attempted` is recorded
///   **whether or not the relay took it**, because the deadline runs from the
///   attempt (`publisher.zig`'s own rule) and a relay that accepts a connection
///   and drops the body would otherwise be asked again on the next tick.
/// * `.deferred` — the previous attempt is unconfirmed, so a second packet
///   could land first and publish the older of the two. `deferred` is
///   recorded so `publisher.skip_unconfirmed` has something to count.
/// * `.stale` — the record is reported as not published. Counted and nothing
///   else: `publisher.abandon` is the way back and it is a caller's decision,
///   not this pass's.
fn republish(self: *Node, io: std.Io, at: Instant, random: std.Random) bool {
    const now_ms = millisOf(at) orelse {
        // A clock before this node's epoch cannot be expressed in the timers'
        // unit, so no tick can be asked. Named rather than asserted, and
        // nothing is recorded on the publisher: no tick happened.
        node_discovery_wire.count(self, .clock_unusable);
        return false;
    };
    switch (self.discovery.publisher.tick(now_ms)) {
        .wait_until => return false,
        .deferred => {
            self.discovery.publisher.deferred();
            node_discovery_wire.count(self, .deferred);
            return true;
        },
        .stale => {
            node_discovery_wire.count(self, .stale);
            return true;
        },
        .publish => {},
    }
    const held = self.discovery.publisher.published() orelse {
        // `tick` answered `publish` with a slot it must have, so this arm is a
        // caller that released the slot out from under a timer. Named rather
        // than asserted, and nothing is recorded on the publisher: no attempt
        // went out, so the next tick asks again.
        node_discovery_wire.count(self, .nothing_to_publish);
        return true;
    };
    // The record the publisher holds is this node's own, borrowed for the
    // length of this call: `writeTxtStrings` reads the address list and the
    // `Published` it writes into is a temporary this function never gives up,
    // so the publisher's own slot is untouched and still released by
    // `State.release`.
    const records = node_discovery_record.recordsOf(
        self.gpa,
        held.endpoint,
        &self.discovery.records,
    ) catch |err| {
        std.log.warn("node {f} could not write its own records: {t}", .{ self.nodeId(), err });
        node_discovery_wire.count(self, .nothing_to_publish);
        return true;
    };
    const stored = node_discovery_wire.publish(self, io, records, random);
    self.discovery.publisher.attempted(now_ms);
    if (stored) {
        self.discovery.publisher.recordConfirmed();
    } else {
        self.discovery.publisher.refused();
    }
    return true;
}

/// Ask about one peer if a lookup is due.
///
/// **Round-robin over `Config.peers`, one per due tick.** The cursor advances
/// past the peer just asked, so two peers configured and two ticks due is two
/// questions about two peers rather than two questions about one.
///
/// A peer list that is empty is `Refused.no_peer` and schedules the next lookup
/// anyway: a node configured with no peers is a node that will have none by the
/// next tick too, and the counter is what says so once rather than a pass that
/// silently does nothing for ever.
fn lookup(self: *Node, io: std.Io, at: Instant, random: std.Random) bool {
    const now_ms = millisOf(at) orelse {
        node_discovery_wire.count(self, .clock_unusable);
        return false;
    };
    if (self.discovery.next_lookup_ms) |due| {
        if (now_ms < due) return false;
    }
    self.discovery.next_lookup_ms = now_ms + self.config.discovery.interval_ms;
    const explicit = self.config.discovery.peer_ids;
    const peers = self.config.peers;
    const count = if (explicit.len != 0) explicit.len else peers.len;
    if (count == 0) {
        node_discovery_wire.count(self, .no_peer);
        return false;
    }
    const cursor = self.discovery.peer_cursor % count;
    const peer = if (explicit.len != 0) explicit[cursor] else peers[cursor].id;
    self.discovery.peer_cursor += 1;
    node_discovery_wire.ask(self, io, peer, at, random);
    return true;
}

/// This node's instant in the unit the discovery timers are in, or null when
/// it cannot be expressed as one.
///
/// `at` is `bridge_config.Instant`, a signed 64-bit nanosecond count, and the
/// timers are `u64` milliseconds. A clock before this node's epoch has no such
/// value and is null rather than `@intCast`ed to a huge one or truncated to
/// zero: `node_config.Error.InstantOutOfRange` is what a caller would have to
/// handle for the same conversion one layer up, and a discovery pass has
/// refused arms of its own to say it in.
fn millisOf(at: Instant) ?u64 {
    return std.math.cast(u64, @divTrunc(at, std.time.ns_per_ms));
}
const t = std.testing;

const dns = @import("../discovery/dns.zig");
const txt = @import("../discovery/txt.zig");
const lookup_name = @import("../discovery/lookup_name.zig");
const lookup_query = @import("../discovery/lookup_query.zig");
const pkarr_body = @import("../discovery/pkarr_body.zig");

const SecretKey = base_key.SecretKey;

/// Where a test node binds, with port zero so two nodes in one process both
/// bind and a socket left over from the last run cannot collide.
const loopback: base_addr.SocketAddr = .{
    .ip = .{ .v4 = .{ 127, 0, 0, 1 } },
    .port = 0,
};

/// The nameserver a scripted answer comes from. `127.0.0.1` and not a name,
/// because a test that resolves a name is a test that can fail on a machine's
/// hosts file.
const nameserver: base_addr.SocketAddr = .{
    .ip = .{ .v4 = .{ 127, 0, 0, 1 } },
    .port = 53,
};

/// Where virtual time starts, and how far it moves per pass. A pass is a
/// handful of syscalls, so this is a clock and not a delay: nothing here waits
/// for it to elapse.
const start_ns: Instant = 1_000 * std.time.ns_per_s;
const time_quantum: Instant = std.time.ns_per_ms;

/// How many passes the loop below runs. Generous, because a pass cannot block —
/// the scripted seam answers immediately — and a backstop rather than a timer.
const max_passes = 8;

/// The offset a question's `QTYPE` sits at: past the header, the name, and the
/// root label's zero octet.
fn wire_question_length(asked: []const u8) usize {
    return lookup_wire.header_length + asked.len + 1;
}

/// One `_iroh` record, in `resolve.RecordSet`'s own shape.
const one_record = "relay=https://example.com/\x00";

/// A nameserver that answers from a script, and echoes the transaction.
///
/// **The only thing substituted here is the socket**, and it is the seam
/// `discovery/lookup_io.zig` was built around: `dns_live.Resolver.seam()` is
/// the production value of `Config.discovery.lookup.datagram` and this is the
/// test's. Everything above it — the question `dns_live` frames, the
/// transaction id the node drew from its own generator, the `QR` and `TC`
/// checks, the record walk, the `Error.Empty` to `Answer.timeout` mapping and
/// the `dns.DnsAddressLookup` the answer is handed to — is the module's own
/// path.
///
/// The echo is why this is not `discovery/lookup_test_support.zig`'s `Scripted`:
/// that one hands back a fixed reply, and a fixed reply cannot answer a
/// question whose transaction id this node drew for itself. A nameserver
/// copies the `ID` into its reply (RFC 1035 §4.1.1) and so does this.
const Scripted = struct {
    /// Who the answer comes from. Must be the server the question went to, or
    /// `dns_live.Retrieval.ask` refuses it as a `ForeignSource` — which is the
    /// point of that check and why this field is not optional.
    from: base_addr.SocketAddr,
    /// The name the answer carries, which is the name the node is asked about.
    asked: []const u8,
    /// What the next receive hands back.
    mode: Mode = .records,
    /// What the last send put on the wire, and where it went.
    sent: [lookup_wire.reply_length]u8 = undefined,
    sent_len: usize = 0,
    sent_to: base_addr.SocketAddr = undefined,
    sends: u32 = 0,
    /// The transaction the last question carried, read back off the wire.
    id: u16 = 0,
    stops: u32 = 0,

    const Mode = enum {
        /// An answer carrying one `_iroh` record, built by
        /// `discovery/pkarr_body.zig`'s own writer.
        records,
        /// A `NOERROR` answer that echoes the question and carries no answer at
        /// all: the name exists and this peer published nothing under it.
        nothing,
        /// No datagram at all, whatever the deadline.
        timeout,
    };

    fn datagram(self: *Scripted) lookup_io.Datagram {
        return .{
            .ctx = @ptrCast(@alignCast(self)),
            .send = send,
            .receive = receive,
            .stop = stop,
        };
    }

    fn send(
        ctx: *anyopaque,
        // The vtable slot, so a reordered parameter is a different type. Z023
        // reads `*anyopaque` as a plain runtime value.
        // ziglint-ignore: Z023
        _: std.Io,
        to: base_addr.SocketAddr,
        bytes: []const u8,
    ) lookup_io.SocketError!void {
        const self: *Scripted = @ptrCast(@alignCast(ctx));
        if (bytes.len > self.sent.len) return error.Refused;
        @memcpy(self.sent[0..bytes.len], bytes);
        self.sent_len = bytes.len;
        self.sent_to = to;
        self.sends += 1;
        self.id = lookup_wire.be16(bytes, 0);
    }

    fn receive(
        ctx: *anyopaque,
        // The vtable slot. See `send`.
        // ziglint-ignore: Z023
        _: std.Io,
        into: []u8,
        _: ?i32,
    ) lookup_io.SocketError!lookup_io.Datagram.Reply {
        const self: *Scripted = @ptrCast(@alignCast(ctx));
        if (self.mode == .timeout) return error.Empty;
        // The writers below fail with `WireError`; the seam has three arms and
        // a message this scripted nameserver cannot frame is a socket that
        // would not answer, which is the same refusal by name.
        const written = switch (self.mode) {
            .records => answerWithRecord(self, into) catch return error.Refused,
            .nothing, .timeout => answerWithoutRecords(self, into) catch return error.Refused,
        };
        return .{ .bytes = into[0..written], .from = self.from };
    }

    fn stop(ctx: *anyopaque) void {
        const self: *Scripted = @ptrCast(@alignCast(ctx));
        self.stops += 1;
    }
};

/// The answer a nameserver sends for a peer that published one relay.
///
/// Written by `discovery/pkarr_body.zig`, which is the only writer of a pkarr
/// body in the tree, and then given the transaction the question was asked
/// under — the one field a captured body cannot carry, because a body is a
/// reply to no question and a TXT answer is a reply to this one.
fn answerWithRecord(self: *const Scripted, into: []u8) !usize {
    const written = try pkarr_body.writeBody(
        into,
        self.asked,
        txt.RecordSet.init(one_record),
    );
    lookup_wire.put16(into[0..written.len], 0, self.id);
    return written.len;
}

/// The answer a nameserver sends for a peer that published nothing.
///
/// `QR` set on the very question `discovery/lookup_query.writeQuery` framed,
/// which is RFC 1035's `NOERROR` with an empty answer section. A header
/// claiming a question it does not carry would be a malformed message rather
/// than an empty answer, and this is why the question is written rather than
/// only a header synthesised.
fn answerWithoutRecords(self: *const Scripted, into: []u8) !usize {
    const written = try lookup_query.writeQuery(self.asked, .{ .id = self.id }, into);
    lookup_wire.put16(into[0..written.len], 2, lookup_wire.flag_response);
    return written.len;
}

/// One node, one configured peer, and a scripted nameserver behind it.
///
/// Everything the pass needs is named here so a test that changes one of them
/// says so at the call site rather than in a helper four frames away.
fn nodeOver(script: *Scripted, peers: []const node_config.Peer) !*Node {
    return Node.create(t.allocator, t.io, .{
        .secret = try SecretKey.fromSeed(@splat(0xa7)),
        .listen = loopback,
        .peers = peers,
        .discovery = .{ .lookup = .{ .datagram = script.datagram(), .server = nameserver } },
    }, 0x5eed);
}

/// The name this pass asks about for `peer_id`, and the question's own length.
fn askedNameFor(peer_id: NodeId, out: []u8) ![]const u8 {
    return dns.queryName(out, peer_id, preset.dns_origin_prod);
}

/// Drive passes until `reached` reads true, or give up.
///
/// A bound rather than a timer, and generous: a pass here cannot block because
/// the scripted seam answers or refuses immediately, so a lookup that has not
/// happened by the bound is not going to happen at all.
fn driveUntil(node: *Node, at: *Instant, reached: *const fn (*Node) bool) !void {
    var passes: usize = 0;
    while (passes < max_passes and !reached(node)) : (passes += 1) {
        at.* += time_quantum;
        _ = try node.step(t.io, at.*, node.generator());
    }
    std.debug.assert(reached(node));
}

fn oneLookupHappened(node: *Node) bool {
    return node.stats.discovery_lookups > 0;
}


test "a lookup the node's own pass asks reaches the node's resolution path" {
    // The whole of the wiring, through `Node.step`: the pass's timer asks,
    // `dns_live` frames the question, the answer comes back, and the records
    // reach `dns.DnsAddressLookup` and come out of it as an item.
    var peer_key = try SecretKey.fromSeed(@splat(0xa1));
    defer peer_key.deinit();
    const peer_id = peer_key.nodeId();

    var name: [dns.queryNameLength(preset.dns_origin_prod)]u8 = undefined;
    var script: Scripted = .{
        .from = nameserver,
        .asked = try askedNameFor(peer_id, &name),
    };
    const peers = [_]node_config.Peer{.{
        .id = peer_id,
        .addr = .{ .ip = loopback },
    }};
    const node = try nodeOver(&script, &peers);
    defer node.deinit();
    var at: Instant = start_ns;
    try driveUntil(node, &at, oneLookupHappened);

    // One question went out, to the server it was asked of, and it is the
    // question this pass is supposed to ask: a TXT question for
    // `_iroh.<z32>.dns.iroh.link.` under the transaction the node drew.
    try t.expectEqual(@as(u32, 1), script.sends);
    try t.expectEqual(std.math.Order.eq, nameserver.order(script.sent_to));
    try t.expectEqual(lookup_io.queryLength(script.asked), script.sent_len);
    try t.expectEqual(
        lookup_io.type_txt,
        lookup_wire.be16(&script.sent, wire_question_length(script.asked)),
    );
    // The name on the wire is read back with `discovery/lookup_name.zig`, the
    // decoder the answer path itself uses, and compared to the presentation
    // name this pass built. Encoder and decoder both being the project's own is
    // the point: it is not a string this test searched for, it is the bytes
    // `_iroh.<z32>.<origin>` became.
    var decoded: [lookup_wire.max_name_length]u8 = undefined;
    const owner = try lookup_name.readName(&script.sent, lookup_wire.header_length, &decoded);
    try t.expect(std.mem.eql(u8, script.asked, decoded[0..owner.written]));

    // And the answer came back through the node's own resolver rather than
    // stopping at the counter: one answer carried records, and the resolution
    // path turned it into one item with one address — the relay the record
    // named. `dns_live`'s `Resolver.service` is what produced it, so this is
    // `discovery/dns.zig`'s `DnsAddressLookup` running over the node's pass.
    try t.expectEqual(@as(u64, 1), node.stats.discovery_answers);
    try t.expectEqual(@as(u64, 1), node.stats.discovery_items);
    try t.expectEqual(@as(u64, 1), node.stats.discovery_addresses);
    try t.expectEqual(@as(u64, 0), node.discovery.refused.nothing);
    try t.expectEqual(@as(u64, 0), node.discovery.refused.timed_out);
    try t.expectEqual(@as(u64, 0), node.discovery.refused.undecodable);
    try t.expectEqual(@as(u64, 0), node.discovery.refused.foreign);

    // The second pass asks nothing: `default_lookup_interval_ms` has not run
    // out, so the timer is a timer and not a loop.
    at += time_quantum;
    _ = try node.step(t.io, at, node.generator());
    try t.expectEqual(@as(u32, 1), script.sends);

    try node.close(t.io, at, node.generator());
}

test "a lookup that timed out and one that came back empty stay two facts" {
    // The distinction `discovery/lookup_io.zig` argues for at length, held all
    // the way up through the node's own pass: nothing answered in time is a
    // fact about a clock, and an answer that arrived carrying nothing is a fact
    // about the world. Collapsing either onto the other would end the walk on a
    // slow nameserver and hide every source still in flight.
    var peer_key = try SecretKey.fromSeed(@splat(0xb1));
    defer peer_key.deinit();
    const peer_id = peer_key.nodeId();

    var name: [dns.queryNameLength(preset.dns_origin_prod)]u8 = undefined;
    var script: Scripted = .{
        .from = nameserver,
        .asked = try askedNameFor(peer_id, &name),
        // A node that looks nobody up is the default, and this is a node that
        // was told to look one peer up, so the counter a default node would
        // show is not part of what is being asserted here.
        .mode = .timeout,
    };
    const peers = [_]node_config.Peer{.{
        .id = peer_id,
        .addr = .{ .ip = loopback },
    }};
    const node = try nodeOver(&script, &peers);
    defer node.deinit();
    var at: Instant = start_ns;
    try driveUntil(node, &at, oneLookupHappened);

    // Nothing came back. The pass counted it as a timeout and carried on: the
    // answer never reached the resolver, so nothing was resolved.
    try t.expectEqual(@as(u64, 1), node.discovery.refused.timed_out);
    try t.expectEqual(@as(u64, 0), node.discovery.refused.nothing);
    try t.expectEqual(@as(u64, 0), node.stats.discovery_answers);
    try t.expectEqual(@as(u64, 0), node.stats.discovery_items);

    // A requested peer is deliberately attempted only once, even after the
    // lookup interval expires. A different node can observe the empty answer.
    script.mode = .nothing;
    at += @as(Instant, default_lookup_interval_ms + 1) * std.time.ns_per_ms;
    _ = try node.step(t.io, at, node.generator());
    try t.expectEqual(@as(u32, 1), script.sends);
    const empty = try nodeOver(&script, &peers);
    defer empty.deinit();
    try driveUntil(empty, &at, oneLookupHappened);
    try t.expectEqual(@as(u32, 2), script.sends);
    try t.expectEqual(@as(u64, 1), node.discovery.refused.timed_out);
    try t.expectEqual(@as(u64, 0), node.discovery.refused.nothing);
    try t.expectEqual(@as(u64, 0), empty.discovery.refused.timed_out);
    try t.expectEqual(@as(u64, 1), empty.discovery.refused.nothing);
    try t.expectEqual(@as(u64, 0), empty.stats.discovery_answers);
    try t.expectEqual(@as(u64, 0), empty.stats.dials);
    try t.expectEqual(@as(u64, 0), empty.discovery.refused.cannot_resolve);
    try empty.close(t.io, at, empty.generator());

    try node.close(t.io, at, node.generator());
}

test "a node with no relay and no lookup publishes nothing and asks nobody" {
    // `discovery/preset.zig`'s `Publication.relay_only` reached through
    // configuration: the default `Config.discovery` is a node that hands no
    // address to a third party. Asserted rather than assumed, because the
    // alternative — a slot armed with an empty record — would put a publisher
    // timer that came due for ever over a packet nobody wanted.
    const node = try Node.create(t.allocator, t.io, .{
        .secret = try SecretKey.fromSeed(@splat(0xc3)),
        .listen = loopback,
    }, 0xfeed);
    defer node.deinit();

    var at: Instant = start_ns;
    var passes: usize = 0;
    while (passes < max_passes) : (passes += 1) {
        at += time_quantum;
        _ = try node.step(t.io, at, node.generator());
    }

    // The record was refused by name once, at arm time, and no publish has
    // been attempted since: `publisher.tick` answers `wait_until` for ever on
    // an empty slot.
    try t.expectEqual(@as(u64, 1), node.discovery.refused.nothing_to_publish);
    try t.expectEqual(@as(u64, 0), node.stats.discovery_publishes);
    try t.expectEqual(@as(u64, 0), node.stats.discovery_lookups);
    // And no peer to ask about either, which is the other half of the default:
    // one lookup was due across `max_passes` passes and the rest of the passes
    // found the interval had not run out, so the refusal was counted once
    // rather than once per pass.
    try t.expectEqual(@as(u64, 1), node.discovery.refused.no_peer);
    try t.expectEqual(@as(u64, 0), node.discovery.refused.no_source);

    try node.close(t.io, at, node.generator());
}

test "lookup configuration refuses unbounded deadlines before opening a node" {
    try t.expectError(error.InvalidDiscoveryConfig, Node.create(t.allocator, t.io, .{
        .secret = try SecretKey.fromSeed(@splat(0xd4)),
        .discovery = .{ .deadline_ms = 0 },
    }, 42));
    try t.expectError(error.InvalidDiscoveryConfig, Node.create(t.allocator, t.io, .{
        .secret = try SecretKey.fromSeed(@splat(0xd4)),
        .discovery = .{ .interval_ms = 0 },
    }, 42));
}
