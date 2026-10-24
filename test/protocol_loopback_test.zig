//! The first application protocol over a real connection: gossip between ozai
//! endpoints, and the plan's blob property over the same socket.
//!
//!
//! # What is asserted, and what is not
//!
//! The bar is the plan's own — "two Zig nodes must agree with the reference on
//! membership convergence, not merely exchange bytes" — and the reference bar
//! is the one `src/gossip/hyparview.zig` already holds itself to in
//! "a bootstrapped swarm converges". So the assertions here are:
//!
//! 1. **Nobody is left out.** Every node's active view is non-empty, and
//!    every count is inside the configured capacity. A node left with no
//!    neighbour is named by index, with the peers it *is* adjacent to.
//! 2. **The disagreement stops.** `asymmetricLinks` — a link one end believes
//!    in and the other has no record of — is measured once the swarm has
//!    settled and again at the end, and the two must be equal. It is not
//!    required to be zero, because the simulator's own doc says it is not
//!    always zero and that the cause is upstream rather than a port defect.
//! 3. **The broadcast reaches everybody, once.** One PlumTree broadcast from
//!    one node arrives at every other node exactly once, with no duplicate,
//!    and leaves the membership it was built on untouched.
//! 4. **The transport really is six sockets.** Every link is a completed TLS
//!    handshake, every node's peer identity was proved by the pin the dialer
//!    carried, and the six ports are six distinct ephemeral ports.
//!
//! No message count is an assertion. `frames_read` and `frames_written` are
//! printed by the stall report and never checked: a protocol that delivered every
//! message to a machine that disagreed about membership would fail above.
//!
//! # The codec is the test's own
//!
//! `src/gossip/hyparview.zig` says so itself: "this module has no wire codec".
//! A protocol message cannot cross a socket without bytes, so this file
//! supplies them — `test/protocol_codec.zig` is where they live — and they are
//! **not** the project's wire format. They are one plausible encoding, chosen
//! so the state machines' own types can be exercised unchanged. Nothing under
//! `src/` depends on them and no golden vector claims otherwise. A real codec
//! belongs to the milestone that ships the protocol; what is under test here
//! is the *stack*, not the encoding.
//!
//! Two things about it are deliberate rather than accidental. Every
//! discriminant is an explicit tag byte rather than a union's declaration
//! order, so reordering an arm in `src/gossip/` cannot silently change these
//! bytes. And every slice a decoded message carries is borrowed out of the
//! frame it was decoded from and consumed inside the same call, which is the
//! borrow rule both gossip layers document — so the harness copies every
//! outgoing message into a queue before the next `handle` on the same state.
//!
//! # The transport under the protocol
//!
//! Four nodes, each with its own socket, its own `Bridge` and its own
//! `Dialer`. Node `i` dials node `j` for every `j > i`, so every pair has
//! exactly one connection with the lower index as the client: six connections,
//! six ephemeral ports, and a link whose two ends agree on who opened what
//! without either being told.
//!
//! A connection carries exactly two bidirectional streams, one per direction:
//! stream `0` is the client's, stream `1` is the server's. That is not a
//! convention this file invented — RFC 9000 §2.1 numbers a client-initiated
//! bidirectional stream `4n` and a server-initiated one `4n + 1`, so with one
//! stream opened per side the ids are determined by role alone. Each side
//! writes only its own and reads only its peer's, which is what makes a
//! length-prefixed frame on a byte stream the whole of the framing.
//!
//! # Time is virtual and moves only when the test says so
//!
//! Every call into the QUIC core takes an `Instant` and every call into the
//! gossip state machines takes a `now`. This file owns one counter and
//! advances it by one millisecond per round. No clock is ever read and nothing
//! sleeps anywhere in this file. The bound is on rounds, so a run that never
//! converges ends by saying where it stopped rather than by hanging. The total
//! virtual time stays far below the core's 30 s idle timeout, so a connection
//! is never reaped by the clock — a reaped connection would be a finding about
//! time and not about gossip.
//!
//! # `disconnect_peer`, and the one thing this harness does differently
//!
//! Membership asks the application to close a connection in three places. The
//! reference simulator (`sim.Network::tick`) answers with `killConnection`,
//! which does two things: it removes the pair from a bookkeeping table, and it
//! delivers `peer_disconnected` to the far end. Its *message* path never
//! consults that table — `send_message` enqueues whether or not the pair is in
//! it.
//!
//! So the faithful port here keeps the descriptor and delivers the event, and
//! that is what `handleOut` does. Tearing the QUIC connection down as well
//! would be *less* faithful to the reference than keeping it, because the
//! reference keeps sending. The count of teardowns asked for is printed by
//! the stall report so a reader can see how often it happened.
//!
//! # Ordering, and why it is not the simulator's ordering
//!
//! The simulator's queue is ordered by `(time, insertion order)`. This file's
//! is ordered by round, and a `disconnect_peer` is delivered at the end of the
//! round that produced it rather than one microsecond later. The two are not
//! event-for-event comparable, and `src/gossip/hyparview.zig` says why: the
//! reference seeds `ChaCha12` and this port seeds `xoshiro256`, so "the same
//! bits" was never on offer. What is on offer, and what is asserted, is the
//! outcome — the same neighbour sets, the same delivery counts, the same
//! synchrony. That is the claim the module makes, and this file holds the port
//! to it against a kernel instead of against itself.
//!
//! # Blobs, and what is deliberately not proved here
//!
//! The plan's property for blobs is "**missing data is EOF, not an error
//! frame**". This file proves the transport half: a `get` runs to the end of
//! its stream, the provider that has nothing closes the stream without writing
//! a byte, and the getter sees zero bytes with its FIN set and no reset — and a
//! reset is what an error would have cost this layer, because
//! `src/blobs/protocol.zig` has no error frame and says so in its own doc. A
//! second stream, answered with bytes, shows the getter's read path is not
//! vacuously empty.
//!
//! What is **not** proved: that those bytes are valid bao data. This project
//! has no bao encoder, so the provider's answer is opaque bytes and only the
//! framing is under test. `src/blobs/protocol.zig`'s own tests cover the
//! request codecs, and this file adds the socket they had never met.
//! # Where the parts live
//!
//! Six modules, one responsibility each, and this file is the artifact that
//! runs them:
//!
//! * `test/protocol_codec.zig` — the wire encoding above, and nothing else.
//! * `test/protocol_wire.zig` — one endpoint's transport and the virtual clock.
//! * `test/protocol_node.zig` — one mesh endpoint and the framing on one link.
//! * `test/protocol_swarm.zig` — the swarm, its round and its dialling.
//! * `test/protocol_properties.zig` — the properties the assertions are about,
//!   and the stall report.
//! * `test/protocol_blobs_link.zig` — the blobs pair and its round.
//!
//! Every `test` block is in this file, so every one of them runs under the one
//! `addTest` in `build.zig` that has always named this artifact.

const std = @import("std");
const ozai = @import("ozai");

const t = std.testing;

const gossip = ozai.gossip_hyparview;
const postcard = ozai.postcard;
const blobs = ozai.blobs_protocol;
const bridge_mod = ozai.transport_quic_bridge;
const NodeId = ozai.NodeId;

const codec = @import("protocol_codec.zig");
const node_ns = @import("protocol_node.zig");
const swarm = @import("protocol_swarm.zig");
const props = @import("protocol_properties.zig");
const blobs_link = @import("protocol_blobs_link.zig");
const wire = @import("protocol_wire.zig");

/// Every node holds every other, and holds no link the other end denies.
///
/// The full mesh is what four nodes and a capacity of five converge to — the
/// note on `node_count` says so — and it is a stronger bar than "nobody is
/// alone", which a half-built swarm passes. A membership that is merely
/// non-empty is still growing, and the broadcast below is built on one
/// membership and compared against it afterwards, so capturing a moving one
/// compares it against itself a few rounds later. Nothing can be added past
/// the full mesh either: three peers under a capacity of five is all there is.
fn settled(mesh: *swarm.Mesh) bool {
    if (props.asymmetricLinks(mesh) != 0) return false;
    for (&mesh.nodes) |*node| {
        if (node.topic.swarm.activeView().len < node_ns.node_count - 1) return false;
    }
    return true;
}

/// The same, one round later: membership has stopped changing.
fn stable(mesh: *swarm.Mesh) bool {
    return settled(mesh);
}

/// Every link on every node has a completed handshake.
fn allUp(mesh: *swarm.Mesh) bool {
    for (0..node_ns.max_nodes) |index| {
        for (0..node_ns.max_nodes) |peer| {
            if (peer == index) continue;
            if (!mesh.nodes[index].up(peer, mesh.ports)) return false;
        }
    }
    return true;
}

/// Run rounds until `goal` holds, or until the bound is reached.
fn driveTo(mesh: *swarm.Mesh, phase: []const u8, goal: fn (*swarm.Mesh) bool) !void {
    var round: usize = 0;
    while (round < wire.max_rounds) : (round += 1) {
        if (goal(mesh)) return;
        _ = try mesh.round();
    }
    if (goal(mesh)) return;
    props.report(mesh, phase);
    return error.Stalled;
}

/// The DER `SubjectPublicKeyInfo` an ed25519 key is presented as: a fixed
/// twelve-byte header and then the 32 bytes of public key.
///
/// The header is the encoding itself — a 42-byte SEQUENCE, a 5-byte
/// `AlgorithmIdentifier` naming OID 1.3.101.112, and a BIT STRING of 33 bytes
/// with no unused bits — written out here rather than read off the peer's own
/// certificate. A test that compares a value against the thing that produced it
/// proves nothing: this is the same 44 bytes `tls13.ed25519Spki` builds, built
/// a second time so the comparison has two sides.
fn spkiOf(node: NodeId) [bridge_mod.spki_length]u8 {
    const header = [_]u8{
        0x30, 0x2a, // SEQUENCE, 42 bytes
        0x30, 0x05, //   SEQUENCE, 5 bytes
        0x06, 0x03, 0x2b, 0x65, 0x70, //   OID 1.3.101.112, id-Ed25519
        0x03, 0x21, 0x00, //   BIT STRING, 33 bytes, no padding
    };
    var out: [bridge_mod.spki_length]u8 = undefined;
    @memcpy(out[0..header.len], &header);
    @memcpy(out[header.len..], &node.toBytes());
    // zbc does not resolve spki_length to 44 and the adjacent copies that fill it.
    // zbc-disable-next-line: use-undefined
    return out;
}

test "a swarm of ozai endpoints converges on one membership over real sockets" {
    var mesh: swarm.Mesh = undefined;
    try mesh.init(0x5eed);
    defer mesh.deinit();
    try mesh.dialAll();

    // Every peer answered with a distinct ephemeral port, so the six links
    // cannot have collapsed into fewer.
    var ports = mesh.ports;
    std.mem.sort(u16, &ports, {}, std.sort.asc(u16));
    for (ports) |port| try t.expect(port != 0);
    for (ports[1..], 1..) |port, position| {
        try t.expect(port != ports[position - 1]);
    }

    // Node 0 is the contact node and starts ready to be asked; the other three
    // each ask it for an introduction. This is the shape `BootstrapMode.single`
    // brings up in the simulator, and the shape that makes the convergence
    // below non-trivial: nobody is adjacent to anybody at the start.
    for (1..node_ns.max_nodes) |index| {
        var bootstrap: [gossip.max_bootstrap]NodeId = undefined;
        bootstrap[0] = mesh.nodes[0].wire.id;
        try swarm.feed(&mesh, &mesh.nodes[index], .{
            .command = .{ .join = try gossip.Peers.init(bootstrap[0..1]) },
        }, index);
    }
    try swarm.feed(&mesh, &mesh.nodes[0], .{
        .command = .{ .join = try gossip.Peers.init(&.{}) },
    }, 0);

    // The handshakes have to finish before any of this means anything, and one
    // that does not is a transport finding rather than a gossip one.
    try driveTo(&mesh, "every gossip link completed its handshake", allUp);

    // And then the membership has to settle. The bound is rounds; nothing here
    // sleeps and the clock moves only because a round moved it.
    try driveTo(&mesh, "the swarm never reached a membership", settled);

    // The disagreement is measured once the swarm has settled, and again at the
    // end: what has to hold is that it does not grow.
    const early = props.asymmetricLinks(&mesh);

    // ── the transport, which the protocol runs on ──
    //
    // Six links, all established, and every one of them proved the peer it
    // reached. The pin is the dialer's, because `Bridge.Config.expect_peer` is
    // one node id and this mesh has three peers per bridge; the handshake's
    // `peerNodeId` is where the pin a dial carried comes back out.
    for (0..node_ns.max_nodes) |index| {
        for (index + 1..node_ns.max_nodes) |peer| {
            const dialed = mesh.nodes[index].dialled[peer] orelse return error.NoConnection;
            try t.expect(dialed.established());
            const carried = dialed.entry.conn.tls13_hs orelse return error.NoHandshakeState;
            try t.expectEqual(
                mesh.nodes[peer].wire.id.toBytes(),
                carried.peerNodeId().?,
            );
            try t.expectEqual(
                mesh.nodes[peer].wire.id.toBytes(),
                carried.config.expect_peer_node_id.?,
            );
            // The accept side read the dialler's certificate off the wire and
            // compared it against an SPKI built here from the DER encoding,
            // rather than against the configuration that produced it.
            const accepted = mesh.nodes[peer].connTo(index, mesh.ports) orelse
                return error.NoConnection;
            try t.expectEqualSlices(
                u8,
                &spkiOf(mesh.nodes[index].wire.id),
                accepted.entry.conn.peerCertificate().?,
            );
            try t.expectEqualStrings(swarm.gossip_alpn, dialed.entry.conn.negotiatedAlpn());
        }
    }

    // ── nobody is left out ──
    //
    // The property is membership and not message delivery: no frame count is
    // asserted anywhere above. `frames_read` is printed by `report` and never
    // checked.
    for (0..node_ns.max_nodes) |index| {
        const node = &mesh.nodes[index];
        var found: [node_ns.max_nodes]usize = undefined;
        const count = props.neighbours(&mesh, index, &found);
        if (count == 0) {
            props.report(&mesh, "a node ended the run with no neighbour at all");
            std.debug.print("  {s} is the node left out\n", .{node.wire.name});
            return error.LeftOut;
        }
        // Every count is inside the capacity the config asked for: a view that
        // grew past it would mean the state machine ignored its own bound.
        try t.expect(count <= node.topic.swarm.config.active_view_capacity);
        try t.expect(count <= node.topic.swarm.passiveView().len + count);
        // And each node knows at least one peer by contact data that crossed
        // the socket: the peer view and the contact table cannot disagree
        // about who this node is talking to.
        try t.expect(node.peer_data_seen >= count);
    }
    try t.expectEqual(@as(usize, 0), props.peersWithoutNeighbors(&mesh));

    // Every node's copy of every peer's contact data matched what the peer
    // advertised. A mismatch is a codec that lost or reordered bytes, and it is
    // counted rather than tolerated.
    if (mesh.peer_data_mismatch != 0) {
        props.report(&mesh, "contact data crossed the socket and did not match");
        return error.ContactDataMismatch;
    }

    // ── one broadcast, over the same sockets ──
    //
    // Membership that agrees is the plan's bar for gossip. A broadcast is what
    // the membership is *for*, and it is the second protocol layer's turn: a
    // `plumtree.Message` crosses the same framed streams, so this is what
    // proves the codec's other arm is live rather than merely present.
    const before = blk: {
        var extent: [node_ns.max_nodes]usize = undefined;
        for (0..node_ns.max_nodes) |index| {
            var found: [node_ns.max_nodes]usize = undefined;
            extent[index] = props.neighbours(&mesh, index, &found);
        }
        break :blk extent;
    };
    for (&mesh.nodes) |*node| {
        node.delivered = 0;
        node.duplicated = 0;
        node.delivered_len = 0;
    }

    try swarm.feed(&mesh, &mesh.nodes[0], .{
        .command = .{ .broadcast = .{
            .content = "ozai, over a socket, on a real descriptor",
            .scope = .swarm,
        } },
    }, 0);

    var round: usize = 0;
    while (round < wire.max_rounds) : (round += 1) {
        var complete = true;
        for (1..node_ns.max_nodes) |index| {
            if (mesh.nodes[index].delivered == 0) complete = false;
        }
        if (complete) break;
        _ = try mesh.round();
    }

    for (1..node_ns.max_nodes) |index| {
        if (mesh.nodes[index].delivered == 0) {
            props.report(&mesh, "a broadcast never reached a node");
            std.debug.print(
                "  {s} received nothing broadcast by {s}\n",
                .{ mesh.nodes[index].wire.name, mesh.nodes[0].wire.name },
            );
            return error.BroadcastStalled;
        }
        // Delivered once. `duplicated` counts a second arrival of the same
        // payload, which the payload cache's id table exists to prevent, and a
        // different payload arriving at all — the only other thing that can
        // land here — is counted as the same kind of failure.
        try t.expectEqual(@as(usize, 0), mesh.nodes[index].duplicated);
    }
    // The origin delivered to nobody: a broadcast is not an echo.
    try t.expectEqual(@as(usize, 0), mesh.nodes[0].delivered);

    // And the broadcast left the membership it was built on untouched.
    for (0..node_ns.max_nodes) |index| {
        var found: [node_ns.max_nodes]usize = undefined;
        try t.expectEqual(before[index], props.neighbours(&mesh, index, &found));
    }

    // ── the disagreement did not grow ──
    //
    // Settled, broadcast, and still the same count. Upstream's position is
    // written down in `sim.Network.asymmetricLinks`: `check_synchronicity` is
    // a helper and not a property it claims, and its own convergence test
    // asserts only that the count stops growing.
    try driveTo(&mesh, "membership did not settle after the broadcast", stable);
    try t.expectEqual(early, props.asymmetricLinks(&mesh));
    try t.expectEqual(@as(usize, 0), props.peersWithoutNeighbors(&mesh));
}

test "a node that refuses its topic config releases the wire it had built" {
    var node: node_ns.Node = undefined;
    const refused: gossip.TopicConfig = .{
        .membership = .{ .shuffle_active_view_count = 0 },
    };
    try t.expectError(
        error.ShuffleNodeListTooLong,
        node.init(0, swarm.gossip_alpn, gossip.Rng.init(1), refused, 7),
    );
}

test "a blob the provider does not have is EOF on the wire, not an error frame" {
    var link: blobs_link.BlobLink = undefined;
    try link.init(t.allocator);
    defer link.deinit();

    var round: usize = 0;
    while (round < wire.max_rounds) : (round += 1) {
        const accepted = link.provider.bridge.connectionAt(0);
        if (link.dialled.established() and
            accepted != null and accepted.?.established()) break;
        _ = try link.round();
    }
    const getter_conn = link.dialled;
    const provider_conn = link.provider.bridge.connectionAt(0) orelse {
        link.report("the provider never saw a connection");
        return error.NoConnection;
    };
    if (!getter_conn.established() or !provider_conn.established()) {
        link.report("the blobs handshake did not finish");
        return error.Stalled;
    }
    // The pin both ends carried, proved by the handshake rather than by the
    // configuration: the getter's pin names the provider, and the provider's
    // `client_auth` pin names the getter.
    try t.expectEqual(
        link.provider.id.toBytes(),
        getter_conn.entry.conn.tls13_hs.?.peerNodeId().?,
    );
    try t.expectEqual(
        link.getter.id.toBytes(),
        provider_conn.entry.conn.clientAuth().?.expect_node_id.?,
    );
    try t.expectEqualStrings(blobs.alpn, getter_conn.entry.conn.negotiatedAlpn());

    // The getter asks for two hashes the provider has never heard of, on two
    // streams. Two rather than one because "EOF" and "some bytes" have to be
    // told apart, and one stream can only show one of them.
    const wanted = [_][32]u8{ @splat(0x5a), @splat(0x5b) };
    var requests: [2]u64 = undefined;
    for (wanted, 0..) |hash, position| {
        const frame = try link.writeRequest(.{
            .to_eof = .{ .get = blobs.GetRequest.blob(hash) },
        });
        const stream = try getter_conn.entry.conn.openStream();
        try stream.send.writeData(frame);
        // The `to_eof` framing is the whole stream: a `get` is closed by a FIN
        // and not by a length, which is what `EofFraming` documents.
        stream.send.close();
        requests[position] = stream.stream_id;
    }

    // The provider reads each request to the end of its stream and decodes it
    // with the one reader `Request.read` dispatches to.
    var answered: [2]bool = .{ false, false };
    var decoded: [2]blobs.Request = undefined;
    // One storage per request, and both outlive the loop that fills them. A
    // decoded `GetRequest` borrows its range sequence out of the `Storage` it
    // was read into, and `RangeSpecSeq.parse` writes into `items[0..count]` —
    // so one slot reused per iteration leaves request 0 pointing at request
    // 1's ranges, and a slot scoped to the iteration leaves both pointing at a
    // frame that ended with it. Debug hands back the bytes that frame happened
    // to keep; a release build has already reused the slot, and the assertion
    // below then reads a range the wire never carried. See the module doc: a
    // decoded message is borrowed out of the frame it was decoded from, and
    // here the frame has to be the one that outlives the comparison.
    var storages = @as([requests.len]blobs_link.DecodeStorage, @splat(.{}));
    for (&storages) |*storage| storage.init();
    round = 0;
    while (round < wire.max_rounds) : (round += 1) {
        _ = try link.round();
        var position: usize = 0;
        while (position < requests.len) : (position += 1) {
            if (answered[position]) continue;
            if (!link.finished(&link.provider_fin, requests[position])) continue;
            const queued = link.provider_bytes.get(requests[position]) orelse
                return error.NoStream;
            var reader = postcard.Reader.init(queued.items);
            decoded[position] = try blobs.Request.read(&reader, &storages[position].inner);
            // The reader has to end at the end of it: a byte after a `get` is a
            // stream that carried something else, and `finish` is what makes
            // that different from a request read two ways.
            try reader.finish();
            answered[position] = true;

            const stream = provider_conn.entry.conn.streams.getStream(requests[position]) orelse
                return error.NoStream;
            // The first request is answered with bytes, the second has no
            // answer at all. `Closed.request_received` is upstream's own reason
            // for stopping: one request per stream.
            if (position == 0) try stream.send.writeData(blobs_link.answer_bytes);
            stream.send.close();
        }
        if (answered[0] and answered[1]) break;
    }
    if (!answered[0] or !answered[1]) {
        link.report("a blobs request never arrived whole");
        return error.RequestStalled;
    }

    // The requests survived the socket: the hash the getter wrote is the hash
    // the provider read, on both streams, byte for byte.
    for (decoded, 0..) |request, position| {
        try t.expect(request.discriminant() == .get);
        // The ranges the provider read live in the storage it read them into.
        // That is a claim about an address, so it is checked as one: a decode
        // through a `Storage` that was copied out of its own struct reads
        // whatever is in that dead frame now, and a debug build is the only
        // reason that can look like it worked.
        try t.expectEqual(
            @intFromPtr(&storages[position].items[0]),
            @intFromPtr(request.to_eof.get.ranges.items.ptr),
        );
        const want = try link.writeRequest(.{
            .to_eof = .{ .get = blobs.GetRequest.blob(wanted[position]) },
        });
        // `want` and `got` are both slices of one scratch buffer, and the
        // second `writeRequest` overwrites the first before the comparison
        // reads it: two encodings of the same length compared the buffer
        // against itself and checked nothing but the length. One side is
        // copied out first, so the comparison has two.
        var held: [codec.max_frame]u8 = undefined;
        @memcpy(held[0..want.len], want);
        const got = try link.writeRequest(request);
        try t.expectEqualSlices(u8, held[0..want.len], got);
    }

    // The getter reads both answers to their ends.
    var fin: [2]bool = .{ false, false };
    round = 0;
    while (round < wire.max_rounds) : (round += 1) {
        _ = try link.round();
        for (requests, 0..) |id, position| {
            fin[position] = link.finished(&link.getter_fin, id);
        }
        if (fin[0] and fin[1]) break;
    }
    if (!fin[0] or !fin[1]) {
        link.report("a blobs answer never reached the end of its stream");
        return error.AnswerStalled;
    }

    // ── missing data is EOF ──
    //
    // The stream the provider had nothing for arrived as zero bytes with its
    // FIN set and no reset — and a reset is what an error would have cost this
    // layer, because `protocol.zig` has no error frame and says so in its own
    // doc: a provider that does not have the data stops writing.
    const missing_stream = getter_conn.entry.conn.streams.getStream(requests[1]) orelse
        return error.NoStream;
    const missing_bytes = link.getter_bytes.get(requests[1]) orelse
        return error.NoStream;
    var missing_reader = postcard.Reader.init(missing_bytes.items);
    const missing = blobs.BaoResponse.read(&missing_reader);
    try t.expect(missing.isEof());
    try t.expectEqual(@as(usize, 0), missing.bytes.len);
    try t.expect(missing_stream.recv.fin_received);
    try t.expectEqual(@as(?u64, null), missing_stream.recv.reset_err);

    // And the getter's read path is not vacuously empty: the stream that was
    // answered carried bytes, and they are the ones the provider wrote.
    const present_bytes = link.getter_bytes.get(requests[0]) orelse
        return error.NoStream;
    var present_reader = postcard.Reader.init(present_bytes.items);
    const present = blobs.BaoResponse.read(&present_reader);
    try t.expect(!present.isEof());
    try t.expectEqualSlices(u8, blobs_link.answer_bytes, present.bytes);

    // The `to_eof` rule, checked on bytes that came off a socket: one byte
    // after the request and it is not a request any more. This is what makes
    // "read to EOF" mean what it says, and it is the difference between a
    // missing answer and a truncated request.
    const first = try link.writeRequest(.{
        .to_eof = .{ .get = blobs.GetRequest.blob(wanted[0]) },
    });
    var trailing: [codec.codec_room]u8 = undefined;
    @memcpy(trailing[0..first.len], first);
    trailing[first.len] = 0;
    var trailing_reader = postcard.Reader.init(trailing[0 .. first.len + 1]);
    var storage: blobs_link.DecodeStorage = .{};
    storage.init();
    try t.expectError(
        error.TrailingBytes,
        blobs.Request.read(&trailing_reader, &storage.inner),
    );
    // Without that byte the same reader returns the request, so the byte is
    // what made the difference rather than the buffer being wrong.
    var clean_reader = postcard.Reader.init(first);
    var clean_storage: blobs_link.DecodeStorage = .{};
    clean_storage.init();
    const clean = try blobs.Request.read(&clean_reader, &clean_storage.inner);
    try t.expectEqual(blobs.RequestType.get, clean.discriminant());
}

test "the blobs link releases both wires when its first buffer is refused" {
    var failing: t.FailingAllocator = .init(t.allocator, .{ .fail_index = 0 });
    var link: blobs_link.BlobLink = undefined;
    try t.expectError(error.OutOfMemory, link.init(failing.allocator()));
}

// One step further in, so the unwind has a buffer of its own to give back
// before it reaches the wires.
test "the blobs link releases both wires when its second buffer is refused" {
    var failing: t.FailingAllocator = .init(t.allocator, .{ .fail_index = 1 });
    var link: blobs_link.BlobLink = undefined;
    try t.expectError(error.OutOfMemory, link.init(failing.allocator()));
}
