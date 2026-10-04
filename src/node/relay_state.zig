//! The storage a node's relay owns, and the lifetime of every byte in it.
//!
//! `node.zig` holds this by value and drives it; it does not own it. The
//! registry of the clients a relay has admitted, a slot with two queues and a
//! datagram ring behind each of them, the relay this node spoke to when it is a
//! client of one, and the two buffers a frame passes through are all taken in
//! `State.init` from an allocator the caller named and given back in
//! `State.deinit`.
//!
//! **Two rules the relay is built on are properties of this struct rather than
//! of the node holding it, which is why they are stated here.**
//!
//! * **Only a serving relay builds a registry, slots and queues.** `init`
//!   returns before it reaches them for every other role, so those fields are
//!   not "empty" elsewhere, they are unwritten — and a read out of them would
//!   answer from bytes nobody wrote. Every reader is gated on the role for that
//!   reason and not out of caution.
//! * **The two frame buffers belong to every role.** They are taken before the
//!   role is read at all and freed whatever it was, so a node that is not a
//!   relay holds and returns two allocations it never writes a byte into. An
//!   ownership audit that reads this group as "no relay storage off a relay
//!   node" misses both, on every gossip node in the tree.
//!
//! **Nothing here allocates that `deinit` does not give back, and nothing here
//! reads the node.** A relay pass needs the bridge, the dialer and a set of
//! counters, so it stays where it is and reaches in here for the storage;
//! everything below is storage arithmetic, a cut out of storage, or the
//! registry's own report — which is returned rather than counted, because the
//! counters a caller publishes are the caller's vocabulary.

const std = @import("std");

const base_key = @import("../base/key.zig");
const quic_stream = @import("../transport/quic_stream.zig");
const relay_frame = @import("../relay/frame_types.zig");
const relay_client = @import("../relay/client.zig");
const relay_handshake = @import("../relay/server_handshake.zig");
const relay_queue = @import("../relay/server_queue.zig");
const relay_registry = @import("../relay/server_registry.zig");

const NodeId = base_key.NodeId;
const Allocator = std.mem.Allocator;

/// One datagram a relay handed this node, and the node it came from.
///
/// `data` is a copy taken from the caller's allocator, not a view of the bytes
/// the relay frame was read from: a relay frame borrows its datagrams out of
/// its inbox and that inbox is reused by the next read, so a payload handed
/// out has to be a copy or it is a view of a buffer that has moved on.
///
/// **Two lifetimes, and they are not the same one.** The payload is owned until
/// the node's `node_relay_client.clearDelivered` gives it back — or until
/// `deinit`, which frees whatever is still listed — and that allocator is the
/// one that frees it. The list it sits in does not survive the next delivery:
/// appending to it may move it. `node_relay_client.delivered` says which is
/// which from the outside.
pub const Delivered = struct {
    /// The node id the relay says this datagram came from. Copied, and so
    /// independent of the payload and of every other item on the list.
    src: NodeId,
    /// The datagram bytes this node copied. Empty is a datagram of no bytes,
    /// which the relay protocol permits and which is not an absence.
    data: []u8,
};

/// How many clients a serving relay admits, how deep their queues are, and how
/// long a datagram may be. Null is every other role, and is what `State.init`
/// reads as "the two frame buffers and nothing else".
///
/// **These are the values the storage is cut from and never re-cut from.** A
/// later depth re-points or overruns storage that was never resized, so the
/// caller is the only one who may decide them and does it once.
pub const Sizing = struct {
    /// How many client slots, and how much queue storage behind each of them.
    clients: usize,
    /// How many datagrams one client's queue holds, and one fixed byte slot per
    /// position behind it.
    queue_depth: usize,
    /// The largest datagram one ring slot holds. This and the frame bound are
    /// two different bounds and both are needed: one sizes a frame, the other
    /// the datagram inside one.
    datagram: usize,
};

/// What releasing a client reported, so the caller can count it without this
/// file knowing what a counter is.
///
/// **The registry reports at most once per connection and only for one it still
/// holds.** The arms are kept apart rather than folded into one number because
/// they answer different questions: `.disconnected` is the first report,
/// `.duplicate` and `.promoted` are connections something else had already
/// taken over, and `.already_gone` is a second exit finding nothing.
pub const Reported = struct {
    /// The connection ended and nothing took its place.
    disconnects: u64 = 0,
    /// The connection was one a later connection for the same node id had
    /// already displaced.
    duplicates: u64 = 0,
    /// The active connection ended and the newest displaced one took over.
    promoted: u64 = 0,
    /// A control message for the promoted client was dropped because its queue
    /// was full. Saturation drops the notification, not the promoted client.
    queue_full: u64 = 0,
    /// A report for a connection the registry no longer holds.
    double_reports: u64 = 0,

    /// Add one report into an accumulating one, which is what a release over a
    /// whole table is.
    pub fn add(self: *Reported, other: Reported) void {
        self.disconnects += other.disconnects;
        self.duplicates += other.duplicates;
        self.promoted += other.promoted;
        self.queue_full += other.queue_full;
        self.double_reports += other.double_reports;
    }
};

/// The relay this node spoke to, and what it has handed back.
pub const Spoke = struct {
    /// The core connection the relay is on.
    conn: u64,
    /// The stream the relay protocol runs on, once there is one.
    ///
    /// **Not at the dial.** `StreamsMap.openBidiStream` refuses while the
    /// peer's stream limit is still zero (`stream.zig:1385-1389`), and a dialled
    /// connection has not read a peer's transport parameters until its
    /// handshake is through. So the stream is opened on the first pass where the
    /// connection is established, which is also the first pass where anything
    /// could be written on it.
    stream: ?quic_stream.Stream,
    /// The client half of the handshake, from the dial.
    handshake: relay_client.State,
    /// What has been read and is not yet a whole message.
    inbox: std.ArrayList(u8),
    /// Everything the relay has handed this node, owned until cleared.
    delivered: std.ArrayList(Delivered),

    /// Retain one datagram the relay handed this node.
    ///
    /// **The copy is taken from `gpa`, and the guard for it is taken before the
    /// list is.** `relay/frame_codec.zig`'s `decode` borrows a frame's datagrams out of the
    /// bytes that frame was read from, and those bytes are reused by the next
    /// read, so a payload handed to a caller has to be copied rather than
    /// pointed at. Copying makes it an allocation the caller owns from that
    /// line on, and the append that publishes it can still fail — so the
    /// `errdefer` sits between the two: an append that cannot be given the copy
    /// releases it rather than leaving one payload behind for every frame refused
    /// on the way to the list.
    ///
    /// Nothing bounds the list. The caller takes what is on it and gives the
    /// payloads back, so a relay that keeps answering grows it until then.
    pub fn retain(
        self: *Spoke,
        gpa: Allocator,
        frame: relay_frame.DatagramFrame,
    ) Allocator.Error!void {
        const owned = try gpa.dupe(u8, frame.datagrams.contents);
        errdefer gpa.free(owned);
        try self.delivered.append(gpa, .{
            .src = frame.node_id,
            .data = owned,
        });
    }

    /// Forget everything the relay has handed back, and free the payloads.
    ///
    /// Each `data` is freed here and nowhere else, and the list is emptied in the
    /// same pass, so a second call finds nothing to free and `State.deinit`
    /// finds nothing to give back. A caller holding a slice from before holds
    /// freed memory afterwards; a caller holding one `data` holds it until this
    /// call and not one pass longer.
    ///
    /// The list's capacity is kept, so a caller that clears every pass pays for
    /// one growth rather than one per pass.
    pub fn clearDelivered(self: *Spoke, gpa: Allocator) void {
        for (self.delivered.items) |item| gpa.free(item.data);
        self.delivered.clearRetainingCapacity();
    }

    /// Whether this relay client has nothing more to say.
    ///
    /// **The machine's terminal outcome, read rather than remembered.**
    /// `relay_client.step` reaches a terminal state in exactly two ways:
    /// `.denied` for a refusal, and `.failed` for a frame out of order or a
    /// stream that ended (`client.zig:465,515`). Both arrive with the `.close`
    /// action `node_relay_client.converseClose` carries out, and a terminal
    /// state folds itself into every later step and answers no action, so a
    /// second close is already impossible, and a flag to prevent one would only
    /// restate the state it reads.
    ///
    /// **`.established` is terminal too and is deliberately not named.** An
    /// admitted handshake has said everything it will say, but the stream this
    /// node writes on is the one it opened to answer, and the relay reads that
    /// one whatever it has done with the stream it opened to send on. Only a
    /// refusal, and a handshake its stream ended before it finished, take the
    /// stream away from this node.
    ///
    /// **Not the transport's `finished`,** which is the relay's FIN on the
    /// stream it sends on: that is a fact about the wire, read by whoever holds
    /// the stream. This is what the relay said about this client.
    pub fn ended(self: *const Spoke) bool {
        return switch (self.handshake) {
            .denied, .failed => true,
            else => false,
        };
    }
};

/// One client a serving relay holds.
///
/// The registry holds connection ids and not these, because a registry that held
/// queues would allocate and `relay/server.zig`'s does not — it is a table over
/// storage the caller owns, and this is where the caller put the rest.
fn ClientSlot(comptime displaced: usize) type {
    return struct {
        /// Whether this slot holds a client.
        live: bool = false,
        /// The core connection this client is spoken on, which is the id the
        /// registry holds for it.
        conn: u64 = 0,
        /// The relay half of the handshake, from the moment the connection is
        /// established. `.admitted` is where a client stops being a handshake
        /// and starts being a client.
        handshake: relay_handshake.State = .opened,
        /// The handle that ends this client, and the only way out of the
        /// registry. Null is a client that has not been admitted, and must not
        /// be reported as gone: `Registry.unregister` is not public, so a client
        /// with no handle has no exit at all.
        guard: ?relay_registry.Registry(displaced).OnDisconnectGuard = null,
        /// The node id the handshake proved, or null until it has.
        node_id: ?NodeId = null,
        /// The two queues, over storage this struct owns.
        queues: relay_queue.Connection = undefined,
        /// The bytes a queued datagram borrows: one fixed slot per queue
        /// position, so a `Packet` points at the slot its own ring position
        /// names and the slot is free the moment it is popped.
        ///
        /// Fixed rather than an arena that grows, because a growing arena moves
        /// the bytes every queued `Packet` points at.
        ring: []u8 = &.{},
        /// The stream this relay writes to the client on: one it opened itself.
        ///
        /// **Two streams per client, and they are not interchangeable.** A QUIC
        /// stream is read by whichever end opened it, so the client's half of
        /// the protocol can only be read from the stream the *client* opened —
        /// which this connection does not hold until the client has written
        /// something. That is why the relay opens one of its own to speak on: a
        /// relay that waited for the client's stream could not send the challenge
        /// that makes the client write on it. The serving pass finds the other
        /// half each time it reads.
        out: quic_stream.Stream = undefined,
        /// What has been read off that stream and is not yet a whole message.
        inbox: std.ArrayList(u8) = .empty,
    };
}

/// One client's two queues, cut out of storage every client shares.
fn cutQueues(
    packets: []relay_queue.Packet,
    messages: []relay_queue.Control,
    depth: usize,
    index: usize,
) relay_queue.Connection {
    const base = index * depth;
    return relay_queue.Connection.init(
        packets[base..][0..depth],
        messages[base..][0..depth],
    );
}

/// One client's datagram ring: a fixed slot per queue position.
fn cutRing(ring: []u8, depth: usize, datagram: usize, index: usize) []u8 {
    const room = depth * datagram;
    return ring[index * room ..][0..room];
}

/// The relay's storage, sized once for the role this node was built as.
///
/// `table_slots` is the open-addressed table the registry probes, built so it is
/// never more than half full; `displaced` is how many connections one node id's
/// later connections may hold behind its active one. Both are comptime because
/// both are a fixed array somewhere: the registry's own comptime parameter is
/// the inactive list it keeps per entry.
pub fn State(comptime table_slots: usize, comptime displaced: usize) type {
    return struct {
        const Self = @This();
        const registry_type = relay_registry.Registry(displaced);

        /// One client a serving relay holds, and the type the slot array holds.
        pub const client_type = ClientSlot(displaced);

        /// The registry's slots and the table over them. Both are built for a
        /// serving relay and left unwritten for every other role.
        slots: [table_slots]registry_type.Slot,
        registry: registry_type,
        /// One slot per client a serving relay admits, in the order it admits
        /// them.
        clients: []client_type,
        /// The two queues' storage for every client, laid out back to back and
        /// cut into one client's depth apiece. One allocation for all of them,
        /// because a per-client allocation is a pointer chase on the hot path
        /// and the sizes are all the same.
        packets: []relay_queue.Packet,
        messages: []relay_queue.Control,
        /// One fixed datagram slot per queue position of every client, laid out
        /// the same way.
        ring: []u8,
        /// The relay this node spoke to, when it is a client of one.
        spoke: ?Spoke,
        /// Whether that dial has been attempted, whatever it answered. A relay
        /// that was not there is a fact about the network and not a reason to
        /// retry, which is the same rule `start` applies to a peer.
        dialled: bool,
        /// Where a relay frame is encoded — the varint length first, then the
        /// frame behind it. **The only buffer here sized by the frame bound.** A
        /// read used to have one too, and that conflation was the defect: a read
        /// is a run of whatever arrived, not a frame, so sizing it by the frame
        /// bound refused the run after the core had already handed the bytes
        /// over.
        out: []u8,
        /// What a decoded relay frame borrows out of. Sized by the same bound,
        /// but for the opposite reason: `decode` borrows two variable-length
        /// payloads out of the bytes it is handed, and those bytes must outlive
        /// the message.
        scratch: []u8,

        /// Build the storage, once, from the role this node was built as.
        ///
        /// `out_room` and `scratch_room` are the two frame buffers, taken before
        /// `sizing` is read at all — which is what makes them every role's and
        /// what `deinit` frees whatever the role was. `sizing` is a serving
        /// relay's own numbers and null for every other role: a client needs no
        /// registry and no queues, and the two buffers are all it allocates.
        ///
        /// **Initialised in place, and never returned by value.** `registry_type.init`
        /// hands back a registry that points at the caller's slot array, so a
        /// `Self` returned from here would carry a pointer into a stack frame
        /// that is gone by the time the caller has it. `node_lifecycle.create`
        /// therefore calls this on the node's own field, which is heap-allocated
        /// and never moves.
        ///
        /// **The operator's numbers are the caller's to validate**, against
        /// the bound that sizes `table_slots`, so a refusal is the node's own
        /// error rather than one this file invented. Everything here can only
        /// fail for want of memory.
        pub fn init(
            self: *Self,
            gpa: Allocator,
            out_room: usize,
            scratch_room: usize,
            sizing: ?Sizing,
        ) Allocator.Error!void {
            self.* = .{
                .slots = undefined,
                .registry = undefined,
                .clients = &.{},
                .packets = &.{},
                .messages = &.{},
                .ring = &.{},
                .spoke = null,
                .dialled = false,
                .out = &.{},
                .scratch = &.{},
            };
            errdefer self.deinit(gpa);
            self.out = try gpa.alloc(u8, out_room);
            self.scratch = try gpa.alloc(u8, scratch_room);
            const size = sizing orelse return;
            const per_client = size.clients * size.queue_depth;
            const clients = try gpa.alloc(client_type, size.clients);
            errdefer gpa.free(clients);
            const packets = try gpa.alloc(relay_queue.Packet, per_client);
            errdefer gpa.free(packets);
            const messages = try gpa.alloc(relay_queue.Control, per_client);
            errdefer gpa.free(messages);
            const ring = try gpa.alloc(u8, per_client * size.datagram);
            errdefer gpa.free(ring);
            // Every slot is written before the list is published, so a `deinit`
            // reached from one of the `errdefer`s above walks nothing that was
            // never written.
            for (clients, 0..) |*client, index| {
                client.* = .{
                    .queues = cutQueues(packets, messages, size.queue_depth, index),
                    .ring = cutRing(ring, size.queue_depth, size.datagram, index),
                };
            }
            self.registry = registry_type.init(&self.slots);
            self.clients = clients;
            self.packets = packets;
            self.messages = messages;
            self.ring = ring;
        }

        /// Give back everything the relay took, for whatever role it took it
        /// for.
        ///
        /// Every client is released first, and that is not tidiness: a guard
        /// reaches into this struct's own registry and a client slot points at
        /// storage that is about to be freed. An orderly shutdown has already
        /// released every client, so this is the backstop for the node that was
        /// dropped without one — and the report it makes belongs to the caller,
        /// which is why it is discarded here rather than counted.
        pub fn deinit(self: *Self, gpa: Allocator) void {
            _ = self.releaseAll(gpa);
            if (self.spoke) |*spoke| {
                spoke.inbox.deinit(gpa);
                spoke.clearDelivered(gpa);
                spoke.delivered.deinit(gpa);
            }
            self.spoke = null;
            gpa.free(self.out);
            gpa.free(self.scratch);
            gpa.free(self.ring);
            gpa.free(self.messages);
            gpa.free(self.packets);
            gpa.free(self.clients);
        }

        /// End every client, at once, and report each departure once.
        pub fn releaseAll(self: *Self, gpa: Allocator) Reported {
            var reported = Reported{};
            for (self.clients) |*slot| {
                if (!slot.live) continue;
                reported.add(self.release(gpa, slot));
            }
            return reported;
        }

        /// End one client, reporting it exactly once.
        ///
        /// The guard is *taken* and not merely deinited, so nothing is left on
        /// the slot for a second call. That spends the type's own guarantee
        /// rather than relying on it: a second `deinit` answers `.already_gone`
        /// without reaching the registry, and taking the handle means there is
        /// no second call to make.
        ///
        /// Nothing is written to the client here. Either its connection is gone,
        /// which is the case that got here, or the whole endpoint is closing and
        /// the endpoint's own close covers it — and a stream written to after the
        /// core's sweep would be a write into freed memory.
        pub fn release(self: *Self, gpa: Allocator, slot: *client_type) Reported {
            var reported = Reported{};
            if (slot.guard) |*guard| reported = self.report(guard);
            slot.inbox.deinit(gpa);
            slot.* = .{};
            return reported;
        }

        /// Tell access control, once, that a client has gone, and act on
        /// whatever the registry did about it.
        fn report(self: *Self, guard: *registry_type.OnDisconnectGuard) Reported {
            var reported = Reported{};
            switch (guard.deinit()) {
                .disconnected => reported.disconnects += 1,
                // A connection that had already been displaced ends too, and
                // the entry survives with its active connection untouched.
                .duplicate => reported.duplicates += 1,
                .promoted => |promotion| {
                    reported.disconnects += 1;
                    reported.promoted += 1;
                    // Upstream tells the connection that took over that it is
                    // healthy (`server/clients.rs:122-129`), and it goes on that
                    // client's control queue like every other control message.
                    const took_over = self.servedFor(promotion.took_over) orelse return reported;
                    // Queue saturation drops the notification, not the promoted
                    // client.
                    took_over.queues.control.push(.{ .status = .healthy }) catch |err| switch (err) {
                        error.QueueFull => reported.queue_full += 1,
                    };
                },
                // The registry holds no such connection, which is what a second
                // exit finds. Counting it is how a double report would show up.
                .already_gone => reported.double_reports += 1,
            }
            return reported;
        }

        /// One client's two queues, cut out of this storage.
        ///
        /// **The cut is redone from the live configuration on every call rather
        /// than kept beside the storage it describes**, so `depth` is the value
        /// the field holds now and not the one `init` sized these allocations
        /// from. That is the whole of the rule the node's `Config` states: the
        /// relay's sizing is fixed at construction because this call re-reads it,
        /// not because anything here copied it.
        pub fn queuesOf(
            self: *const Self,
            depth: usize,
            index: usize,
        ) relay_queue.Connection {
            return cutQueues(self.packets, self.messages, depth, index);
        }

        /// One client's datagram ring: a fixed slot per queue position.
        pub fn ringOf(self: *const Self, depth: usize, datagram: usize, index: usize) []u8 {
            return cutRing(self.ring, depth, datagram, index);
        }

        /// The client on connection `conn`, or null when there is none.
        pub fn servedFor(self: *const Self, conn: u64) ?*client_type {
            for (self.clients) |*slot| {
                if (slot.live and slot.conn == conn) return slot;
            }
            return null;
        }

        /// A free client slot, or null when every one holds a client.
        pub fn freeClient(self: *const Self) ?*client_type {
            for (self.clients) |*slot| {
                if (!slot.live) return slot;
            }
            return null;
        }

        /// Which slot this is, for the storage cuts `queuesOf` and `ringOf` make.
        pub fn indexOf(self: *const Self, slot: *const client_type) usize {
            const at = @intFromPtr(slot) - @intFromPtr(self.clients.ptr);
            return at / @sizeOf(client_type);
        }
    };
}
