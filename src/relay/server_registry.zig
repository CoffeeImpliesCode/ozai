//! The relay server's registry: the clients one relay has admitted, the
//! connection ids they are known by, and the one exit each admitted connection
//! has.
//!
//! Captured 2026-09-30 from n0-computer/iroh commit
//! 187f59e80afdae6bd9866002b33d3365c00b06d8: `OnDisconnectGuard`, `Access` and
//! `ConnectionId` from `iroh-relay/src/server.rs`; `Clients::register` and
//! `Clients::unregister` from `iroh-relay/src/server/clients.rs`. Each is named
//! where it is reproduced.
//!
//! Nothing here opens a socket, reads a clock, or allocates: the table is an
//! open-addressed map over slots the caller owns, and the guard's `deinit` is the
//! only exit a connection has. The handshake a client runs before it is admitted
//! is `relay/server_handshake.zig`, and the two queues an admitted connection
//! writes from are `relay/server_queue.zig`. `relay/server.zig` re-exports the
//! lot.

const std = @import("std");

const key = @import("../base/key.zig");
const relay_queue = @import("server_queue.zig");
const relay_test_ids = @import("relay_test_ids.zig");

const NodeId = key.NodeId;

/// A process-unique identifier for one relay client connection.
///
/// Upstream `ConnectionId(u64)` (`server.rs:175`), drawn from a process-global
/// atomic (`server.rs:179-182`). The value is an argument here: a
/// process-global counter is what `base` forbids, and a per-registry counter
/// would hand two relays in one process the same id, which is the one thing
/// upstream says the id must not do — it exists so an access-control
/// implementation can pair `on_connect` with `on_disconnect`.
///
/// **Uniqueness is the caller's, and that is why the value is an argument rather
/// than a counter in here.** Two live connections of one process must not share
/// one, because `OnDisconnectGuard.deinit` tells a departure from a displacement
/// by comparing it against the entry's active connection
/// (`server/clients.rs:110-121`), and a clash turns one of them into a silent
/// double report. The value is copied into the entry and into the handle, so
/// nothing borrows it and a number may be reused once `deinit` has answered.
pub const ConnectionId = u64;

/// A connection's departure, as access control is told of it. Upstream
/// `AccessControl::on_disconnect(endpoint_id, connection_id)`
/// (`server.rs:302`).
///
/// **It is reported at most once per connection, and only by the registry.** It
/// comes back from `OnDisconnectGuard.deinit` in exactly the arms that mean the
/// connection really ended — `Unregister.disconnected`, `.duplicate` and
/// `.promoted` — and never from `.already_gone`. It is the one value access
/// control is told about, so a relay running none counts it instead of dropping
/// it; nothing in this module reads it.
pub const Disconnection = struct {
    /// The node id the connection proved, and the first thing access control is
    /// told: it is the entry's key, so one node id's connections are told apart by
    /// `connection_id` and not by this.
    node_id: NodeId,
    /// Which connection it was, which is the whole of what told a departure from
    /// a displacement when the entry was left with another connection in it.
    connection_id: ConnectionId,
};

/// A connection's departure, or its replacement by another.
///
/// Upstream `Clients::unregister` (`server/clients.rs:109-170`) has exactly
/// these arms, and the connection id it requires is what tells them apart:
/// `remove_if_mut` compares it against the entry's active connection, and a
/// mismatch means this connection is one of the displaced ones.
///
/// **This is what `OnDisconnectGuard.deinit` answers, and it is the only source of
/// a `Disconnection`.** Two arms report and two do not: `.disconnected` and
/// `.duplicate` are a connection that ended, and `.promoted` is one that ended
/// *and* handed its node id to another, so the caller reports the `ended` in it
/// and then tells the connection named by `took_over` that it is healthy — a frame
/// on that connection's control queue, which is the caller's. `.already_gone` is
/// the second `deinit`, and it is what keeps that from being a double report.
pub const Unregister = union(enum) {
    /// No connection with this id is in the table, so there is nothing to
    /// report. This is the arm a second exit reaches, and it is the reason a
    /// disconnect is reported exactly once: the report is the registry's, and
    /// the registry reports only for a connection it still holds.
    already_gone,
    /// The connection ended and nothing took its place, so the entry goes
    /// with it. Upstream's last arm, without the peer-gone fanout: that is a
    /// second index keyed by sender, and it belongs with the forwarding path
    /// rather than with the lifecycle this milestone is about.
    disconnected: Disconnection,
    /// The connection was one this node id's later connections had displaced.
    /// It ends and access control is told, and the entry survives with its
    /// active connection untouched. Upstream's `retain` arm
    /// (`server/clients.rs:136-144`).
    duplicate: Disconnection,
    /// The active connection ended and the newest displaced one took over.
    /// Upstream pops the last inactive, promotes it, and tells it
    /// `Status::Healthy` (`server/clients.rs:122-129`).
    promoted: struct { ended: Disconnection, took_over: ConnectionId },
};

/// A registry of the clients one relay has admitted.
///
/// Upstream is a `DashMap<EndpointId, ClientState>` behind an `Arc`
/// (`server/clients.rs:29-43`); this is the same map with the concurrency
/// taken out, as an open-addressed table over storage the caller owns.
/// Admitting a client allocates nothing, which is what lets a relay's whole
/// client set be a value a test can hold on the stack.
///
/// There is one entry per node id, and there is always exactly one entry per
/// node id with a connection in it. A second connection from a node id that
/// already has one does not make a second entry: it takes the entry, and the
/// connection it displaced is remembered so that a departure can hand the node
/// id back. That is upstream's behaviour (`server/clients.rs:81-101`) and it
/// is the same fact as invariant 10's "admit once".
///
/// `inactive_depth` is how many displaced connections a node id may
/// accumulate. Upstream's `Vec` grows without bound, and a bound has to be
/// somewhere; the caller is the only one who knows what a relay should shed
/// first. A connection past the depth is refused rather than silently dropped,
/// so the caller can log it.
///
/// **The caller owns the slots and the registry borrows them**: `init` writes
/// `.empty` over every one and nothing grows the array afterwards, so the storage
/// must outlive the registry and the registry needs no `deinit`.
///
/// **Two bounds, and both are refusals that leave the table as it was.** The slot
/// count is the caller's, and a table with no free slot is `error.NoFreeSlot`.
/// `inactive_depth` is how many displaced connections one node id may hold, and
/// the next is `error.TooManyDuplicateConnections` — checked before the active id
/// moves, so the entry keeps its active connection and its displaced list. **A
/// refused `admit` admits nothing**: that connection has no handle, is not in the
/// table, and is the caller's to close.
///
/// The table rehashes itself at three quarters full, tombstones included, so a
/// relay that churns connections does not probe through its own history; the
/// rebuild keeps every entry and clears the tombstones.
///
/// **No synchronization.** Every method takes `*Self` over a plain table, so two
/// threads sharing one registry are a race; the relay's loop is the only writer,
/// which is the discipline `Connection`'s queues are under too.
pub fn Registry(comptime inactive_depth: usize) type {
    return struct {
        const Self = @This();

        /// One cell of the table. The caller owns the array of them and never
        /// reads it: `init` writes every one, so nothing here is ever `undefined`
        /// and a slot the caller never filled is not a slot with no valid tag.
        pub const Slot = union(enum) {
            /// Never used, and never held a neighbour's entry.
            empty,
            /// Held an entry that has gone. Probing walks past it, so a
            /// removal cannot hide the entry behind it, and `rehash` is what
            /// stops a long-lived relay from spending its whole table on
            /// them.
            tombstone,
            occupied: Entry,
        };

        /// What the registry knows about one node id. Upstream `ClientState`
        /// (`server/clients.rs:40-43`).
        pub const Entry = struct {
            /// The node id, which is also the table key.
            node_id: NodeId,
            /// The connection datagrams are forwarded to. Upstream `active`.
            active: ConnectionId,
            /// Connections this node id opened that a later one displaced,
            /// newest last. Upstream `inactive: Vec<Client>`.
            inactive: struct {
                // Registry already defines Self; that alias is ambiguous here.
                // ziglint-ignore: Z022
                const Inactive = @This();

                /// The displaced connections, newest last, up to the depth the
                /// caller's `Registry(inactive_depth)` bound the list at. Only
                /// `[0..len]` is ever read — `admit` leaves the rest `undefined`
                /// — so nothing outside this file may look at them, and a caller
                /// that kept more displaced connections than this holds has lost
                /// them to a bound it chose rather than to a write it can see.
                ids: [inactive_depth]ConnectionId,
                /// How many of `ids` are in use, and never a capacity: a list of
                /// depth four holding one is `len == 1`.
                len: usize,

                fn pop(self: *Inactive) ?ConnectionId {
                    if (self.len == 0) return null;
                    self.len -= 1;
                    return self.ids[self.len];
                }

                fn push(self: *Inactive, id: ConnectionId) error{TooManyDuplicateConnections}!void {
                    if (self.len == self.ids.len) return error.TooManyDuplicateConnections;
                    self.ids[self.len] = id;
                    self.len += 1;
                }

                fn holds(self: Inactive, id: ConnectionId) bool {
                    for (self.ids[0..self.len]) |candidate| {
                        if (candidate == id) return true;
                    }
                    return false;
                }

                fn forget(self: *Inactive, id: ConnectionId) void {
                    for (self.ids[0..self.len], 0..) |*candidate, offset| {
                        if (candidate.* != id) continue;
                        // Newest last, and the order is what decides which
                        // one is promoted next.
                        std.mem.copyForwards(
                            ConnectionId,
                            self.ids[offset..self.len],
                            self.ids[offset + 1 .. self.len],
                        );
                        self.len -= 1;
                        return;
                    }
                }
            },
        };

        slots: []Slot,
        /// How many slots hold an entry.
        len: usize,
        /// How many hold one that has gone.
        tombstones: usize,

        pub const AdmitError = error{
            /// The table has no slot left. The operator sized it, and a relay
            /// that fills it has to shed connections; this is where it finds
            /// out.
            NoFreeSlot,
            /// This node id already has `inactive_depth` displaced
            /// connections.
            ///
            /// **The table is unchanged**: the entry keeps its active connection
            /// and its displaced list, and the connection that was refused has no
            /// handle and is not in it. Nothing is evicted to make room, so a
            /// caller sees the refusal rather than a client it did not choose to
            /// lose.
            TooManyDuplicateConnections,
        };

        /// What admitting a connection did.
        pub const Admit = union(enum) {
            /// The node id was free and this connection owns it.
            fresh,
            /// Another connection owned it. Upstream deactivates that one,
            /// tells it `Status::SameEndpointIdConnected` over its control
            /// queue, and remembers it as inactive.
            ///
            /// **The value is the connection that was displaced, not the one
            /// that was admitted.** It is the id of the connection that lost the
            /// node id, so it is what the caller still owes a
            /// `Status::SameEndpointIdConnected` over, on that connection's own
            /// control queue, which is the caller's queue and not this file's.
            /// A `fresh` admitted into nothing and owes nothing.
            ///
            /// The displaced id is also what the entry remembers, so a departure
            /// can tell the two apart (`server/clients.rs:110-121`) and the id
            /// this arm carries is the one the caller may act on.
            replaced: ConnectionId,
        };

        /// A connection that has been admitted, and the handle that ends it.
        ///
        /// The two fields are read once, together: the handle ends the connection
        /// and the outcome says what is still owed. Copying it copies the handle,
        /// which is safe because `deinit` reports once, and the handle points
        /// into the registry that handed it out.
        pub const Admitted = struct {
            guard: OnDisconnectGuard,
            admit: Admit,
        };

        /// The handle that ends a connection, and the only way to remove it.
        ///
        /// Upstream `OnDisconnectGuard` (`server.rs:375-425`) reports in
        /// `Drop`, and holds an `Option<Arc<dyn DynAccessControl>>` so a guard
        /// with no access control attached reports nothing. Zig has no `Drop`,
        /// so the report moves to `deinit` and every guarantee the move was
        /// carrying is restated in Zig terms:
        ///
        /// - `admit` is the only way into the table and it hands the handle
        ///   back, so no connection is ever admitted without one and no
        ///   caller can forget to take it.
        /// - `deinit` marks the handle before it reports, so a second call on
        ///   the same handle does nothing.
        /// - The report is the registry's, and the registry reports only for a
        ///   connection it still holds, so even a handle that was copied
        ///   before it was deinited reports once.
        ///
        /// The registry must outlive every handle, because `deinit` reaches
        /// into it. That is the half of "the connection actor must never
        /// outlive the guard" a type can carry; the other half is a discipline,
        /// and it is recorded in `docs/ARCHITECTURE.md` rather than pretended
        /// away — Zig has no move semantics, so a struct can always be copied.
        ///
        /// **`deinit` reports by returning and calls nothing.** It frees no
        /// memory, closes no socket, and does not reach the caller's access
        /// control; the caller receives an `Unregister` and acts on it. It is the
        /// only exit, so a connection dropped without it stays in the table until
        /// the registry itself is discarded — which is how a relay that tears its
        /// table down early loses exactly those connections' reports.
        pub const OnDisconnectGuard = struct {
            registry: *Self,
            node_id: NodeId,
            connection_id: ConnectionId,
            reported: bool,

            /// The single exit path.
            ///
            /// It hands back what the registry did, because the caller still
            /// has to act on a promotion. Upstream's `unregister` sends the
            /// `Status::Healthy` itself; here that is a frame the caller
            /// writes, because the queue it goes on is the caller's.
            pub fn deinit(self: *OnDisconnectGuard) Unregister {
                if (self.reported) return .already_gone;
                self.reported = true;
                return self.registry.unregister(self.node_id, self.connection_id);
            }
        };

        /// Builds a registry over storage the caller owns. `slots` is sized
        /// by the caller and is never grown. A power of two is faster to
        /// probe, and any size is correct.
        ///
        /// `slots` is marked empty in place and never read otherwise, so it may
        /// be `undefined` on the way in and must outlive the registry. Zero slots
        /// is degenerate rather than broken — every `admit` is
        /// `error.NoFreeSlot` and every lookup is null — and it is why the probing
        /// and the insertion both answer before dividing by `slots.len`.
        pub fn init(slots: []Slot) Self {
            for (slots) |*slot| slot.* = .empty;
            return .{ .slots = slots, .len = 0, .tombstones = 0 };
        }

        /// Upstream `Clients::register`, gated on upstream's access check:
        /// nothing is admitted before access control has allowed it, and the
        /// handle comes back with the entry.
        ///
        /// **The handle comes back only on success**, so a refused `admit` leaves
        /// the caller with a connection it has not admitted and must close; that
        /// error is also the only place a relay learns to log
        /// `TooManyDuplicateConnections` instead of dropping a client silently.
        ///
        /// `connection_id` is the caller's number and is unique across the
        /// process rather than across this registry, because the table compares it
        /// against an entry that another registry may also hold.
        pub fn admit(
            self: *Self,
            node_id: NodeId,
            connection_id: ConnectionId,
        ) AdmitError!Admitted {
            if (self.find(node_id)) |index| {
                // The node id already has an owner. Upstream replaces the
                // active connection, tells the old one it has been
                // superseded, and pushes it onto the inactive list
                // (`server/clients.rs:82-94`).
                const entry = self.entryAt(index);
                const displaced = entry.active;
                // Checked before the active id moves, so a refusal leaves
                // the entry exactly as it was.
                try entry.inactive.push(displaced);
                entry.active = connection_id;
                return .{
                    .guard = .{
                        .registry = self,
                        .node_id = node_id,
                        .connection_id = connection_id,
                        .reported = false,
                    },
                    .admit = .{ .replaced = displaced },
                };
            }
            try self.insert(.{
                .node_id = node_id,
                .active = connection_id,
                .inactive = .{ .ids = undefined, .len = 0 },
            });
            return .{
                .guard = .{
                    .registry = self,
                    .node_id = node_id,
                    .connection_id = connection_id,
                    .reported = false,
                },
                .admit = .fresh,
            };
        }

        /// The connection datagrams for this node id are forwarded to.
        ///
        /// Null means no entry holds this node id, which is what a relay answers
        /// with `Control.peer_gone` — this is only the lookup, and the frame is the
        /// caller's to send. The id is a value, so nothing here borrows and a
        /// lookup keeps no connection alive.
        pub fn activeConnectionId(self: *const Self, node_id: NodeId) ?ConnectionId {
            const index = self.find(node_id) orelse return null;
            return self.slots[index].occupied.active;
        }

        /// How many node ids the registry holds, which is the number of
        /// entries and not the number of connections.
        ///
        /// One node id is one entry however many of its connections are
        /// displaced, so this is a count of clients the relay can reach and not
        /// of connections it is holding.
        pub fn nodeCount(self: *const Self) usize {
            return self.len;
        }

        /// Upstream `Clients::unregister`. Not public: the guard's `deinit`
        /// is the only exit, which is invariant 10 restated as a visibility
        /// rule.
        fn unregister(
            self: *Self,
            node_id: NodeId,
            connection_id: ConnectionId,
        ) Unregister {
            const index = self.find(node_id) orelse return .already_gone;
            const entry = self.entryAt(index);
            const ended: Disconnection = .{ .node_id = node_id, .connection_id = connection_id };

            // The connection id is what tells the three cases apart, and it is
            // why upstream passes one (`server/clients.rs:110-121`).
            if (entry.active == connection_id) {
                if (entry.inactive.pop()) |promoted| {
                    entry.active = promoted;
                    return .{ .promoted = .{ .ended = ended, .took_over = promoted } };
                }
                self.slots[index] = .tombstone;
                self.len -= 1;
                self.tombstones += 1;
                return .{ .disconnected = ended };
            }
            if (entry.inactive.holds(connection_id)) {
                // The displaced connection is forgotten; the entry and its
                // active connection are untouched.
                entry.inactive.forget(connection_id);
                return .{ .duplicate = ended };
            }
            // The registry holds no such connection, which is what a second
            // exit finds. Reporting here would be the double report.
            return .already_gone;
        }

        fn entryAt(self: *Self, index: usize) *Entry {
            return &self.slots[index].occupied;
        }

        /// Where this node id's probe starts.
        fn start(self: *const Self, node_id: NodeId) usize {
            return @intCast(std.hash.Wyhash.hash(0, &node_id.toBytes()) % self.slots.len);
        }

        fn find(self: *const Self, node_id: NodeId) ?usize {
            if (self.slots.len == 0) return null;
            var probes: usize = 0;
            while (probes < self.slots.len) : (probes += 1) {
                const index = (self.start(node_id) + probes) % self.slots.len;
                switch (self.slots[index]) {
                    .empty => return null,
                    .tombstone => continue,
                    .occupied => |entry| {
                        if (node_id.order(entry.node_id) == .eq) return index;
                    },
                }
            }
            // A full table of entries with no `empty` in it: every probe
            // landed on an entry, so this node id is not in any of them.
            return null;
        }

        fn insert(self: *Self, entry: Entry) AdmitError!void {
            if (self.len == self.slots.len) return error.NoFreeSlot;
            // Three quarters full, tombstones included: a relay that churns
            // connections would otherwise probe through its own history.
            if ((self.len + self.tombstones + 1) * 4 > self.slots.len * 3) {
                self.rehash();
            }
            try self.place(entry);
            self.len += 1;
        }

        /// Probes for a slot and writes the entry there, with no load
        /// bookkeeping of its own: `insert` has already decided whether the
        /// table needed rebuilding before it got here.
        fn place(self: *Self, entry: Entry) AdmitError!void {
            var probes: usize = 0;
            while (probes < self.slots.len) : (probes += 1) {
                const index = (self.start(entry.node_id) + probes) % self.slots.len;
                switch (self.slots[index]) {
                    .occupied => continue,
                    .tombstone => self.tombstones -= 1,
                    .empty => {},
                }
                self.slots[index] = .{ .occupied = entry };
                return;
            }
            // Not reachable: `insert` establishes that `len < slots.len`
            // first, which is an `empty` to find. It is here so the function
            // has no exit that is not accounted for.
            return error.NoFreeSlot;
        }

        /// Puts every entry back, clearing the tombstones.
        ///
        /// A tombstone cannot simply become an `empty` slot: probing stops at
        /// one, so every entry whose path crosses it has to move first, and
        /// where it moves to is the first free slot on its own path. Each hole
        /// is therefore closed by taking the entries that depend on it, one
        /// after the other, with the hole walking on to the slot each of them
        /// stood in; the hole it reaches last is one that nothing depends on,
        /// and that is the `empty` the table then measures against.
        ///
        /// The walk goes round the whole table rather than forward from the
        /// hole, because an entry whose probe wrapped past the end of the
        /// array depends on slots on both sides of it. Nothing is written
        /// outside the caller's slots, and a move only ever shortens the path
        /// its entry was probed along, so no entry is lost and none is left
        /// unreachable.
        fn rehash(self: *Self) void {
            var scan: usize = 0;
            while (scan < self.slots.len) : (scan += 1) {
                switch (self.slots[scan]) {
                    .occupied, .empty => continue,
                    .tombstone => {},
                }
                var hole = scan;
                var probe = scan;
                var walked: usize = 0;
                while (walked + 1 < self.slots.len) : (walked += 1) {
                    probe = (probe + 1) % self.slots.len;
                    switch (self.slots[probe]) {
                        // Nothing is probed past an `empty` slot, so nothing
                        // beyond this one can depend on the hole.
                        .empty => break,
                        .occupied => |entry| {
                            // The hole is on this entry's path when it is no
                            // further from the home than its own slot is.
                            const home = self.start(entry.node_id);
                            const to_hole = (hole + self.slots.len - home) % self.slots.len;
                            const to_entry = (probe + self.slots.len - home) % self.slots.len;
                            if (to_hole > to_entry) continue;
                            self.slots[hole] = .{ .occupied = entry };
                            self.slots[probe] = .empty;
                            hole = probe;
                        },
                        .tombstone => {},
                    }
                }
                self.slots[hole] = .empty;
            }
            self.tombstones = 0;
        }
    };
}

// --- tests

const t = std.testing;
const Connection = relay_queue.Connection;
const Control = relay_queue.Control;
const Packet = relay_queue.Packet;

test "a second connection takes the node id and does not make a second entry" {
    // `Registry` is a generic factory: the binding holds the struct type it
    // returns, and a type binding is PascalCase rather than a value.
    // zwanzig-disable-next-line: identifier-style
    const Reg = Registry(4);
    var slots: [4]Reg.Slot = undefined;
    var registry = Reg.init(&slots);
    const node_id = try relay_test_ids.testNodeId(1);

    const first = try registry.admit(node_id, 1);
    try t.expectEqual(Reg.Admit.fresh, first.admit);
    try t.expectEqual(@as(usize, 1), registry.nodeCount());
    try t.expectEqual(@as(?ConnectionId, 1), registry.activeConnectionId(node_id));

    const second = try registry.admit(node_id, 2);
    try t.expectEqual(Reg.Admit{ .replaced = 1 }, second.admit);
    // One entry, and the new connection owns it. The displaced one is
    // remembered rather than dropped, which is what lets a departure hand the
    // node id back.
    try t.expectEqual(@as(usize, 1), registry.nodeCount());
    try t.expectEqual(@as(?ConnectionId, 2), registry.activeConnectionId(node_id));

    // A different node id is a different entry, and the table holds both.
    const other = try registry.admit(try relay_test_ids.testNodeId(2), 3);
    try t.expectEqual(Reg.Admit.fresh, other.admit);
    try t.expectEqual(@as(usize, 2), registry.nodeCount());
    try t.expectEqual(@as(?ConnectionId, 2), registry.activeConnectionId(node_id));
    try t.expectEqual(
        @as(?ConnectionId, 3),
        registry.activeConnectionId(try relay_test_ids.testNodeId(2)),
    );
    try t.expectEqual(
        @as(?ConnectionId, null),
        registry.activeConnectionId(try relay_test_ids.testNodeId(3)),
    );
}

test "a departing connection hands its node id to the newest one it displaced" {
    // `Registry` is a generic factory: the binding holds the struct type it
    // returns, and a type binding is PascalCase rather than a value.
    // zwanzig-disable-next-line: identifier-style
    const Reg = Registry(4);
    var slots: [4]Reg.Slot = undefined;
    var registry = Reg.init(&slots);
    const node_id = try relay_test_ids.testNodeId(4);

    var first = (try registry.admit(node_id, 1)).guard;
    var second = (try registry.admit(node_id, 2)).guard;
    var third = (try registry.admit(node_id, 3)).guard;
    try t.expectEqual(@as(usize, 1), registry.nodeCount());

    // The newest displaced connection takes over, and is told it is healthy.
    switch (third.deinit()) {
        .promoted => |promotion| try t.expectEqual(@as(ConnectionId, 2), promotion.took_over),
        else => return error.TestUnexpectedResult,
    }
    try t.expectEqual(@as(?ConnectionId, 2), registry.activeConnectionId(node_id));
    try t.expectEqual(@as(usize, 1), registry.nodeCount());

    // And then the one before it.
    switch (second.deinit()) {
        .promoted => |promotion| try t.expectEqual(@as(ConnectionId, 1), promotion.took_over),
        else => return error.TestUnexpectedResult,
    }
    try t.expectEqual(@as(?ConnectionId, 1), registry.activeConnectionId(node_id));

    // The last one leaves and the entry goes with it, because a node id with
    // no connection in it is not a client.
    switch (first.deinit()) {
        .disconnected => |ended| try t.expectEqual(@as(ConnectionId, 1), ended.connection_id),
        else => return error.TestUnexpectedResult,
    }
    try t.expectEqual(@as(usize, 0), registry.nodeCount());
    try t.expectEqual(@as(?ConnectionId, null), registry.activeConnectionId(node_id));
}

test "a displaced connection's own departure leaves the active one alone" {
    // `Registry` is a generic factory: the binding holds the struct type it
    // returns, and a type binding is PascalCase rather than a value.
    // zwanzig-disable-next-line: identifier-style
    const Reg = Registry(4);
    var slots: [4]Reg.Slot = undefined;
    var registry = Reg.init(&slots);
    const node_id = try relay_test_ids.testNodeId(5);

    // The second connection takes the node id, so the first is the displaced
    // one and the second is the one that owns it.
    var displaced = (try registry.admit(node_id, 1)).guard;
    var active = (try registry.admit(node_id, 2)).guard;

    // The displaced connection ends. Upstream retains the entry and leaves
    // the active connection alone (`server/clients.rs:136-144`), so the
    // connection that still owns the node id is still the one that owns it.
    switch (displaced.deinit()) {
        .duplicate => |ended| try t.expectEqual(@as(ConnectionId, 1), ended.connection_id),
        else => return error.TestUnexpectedResult,
    }
    try t.expectEqual(@as(?ConnectionId, 2), registry.activeConnectionId(node_id));
    try t.expectEqual(@as(usize, 1), registry.nodeCount());

    switch (active.deinit()) {
        .disconnected => |ended| try t.expectEqual(@as(ConnectionId, 2), ended.connection_id),
        else => return error.TestUnexpectedResult,
    }
    try t.expectEqual(@as(?ConnectionId, null), registry.activeConnectionId(node_id));
}

test "a disconnect is reported once, whichever way the connection ends" {
    // `Registry` is a generic factory: the binding holds the struct type it
    // returns, and a type binding is PascalCase rather than a value.
    // zwanzig-disable-next-line: identifier-style
    const Reg = Registry(4);
    var slots: [4]Reg.Slot = undefined;
    var registry = Reg.init(&slots);
    const node_id = try relay_test_ids.testNodeId(6);

    var admitted = try registry.admit(node_id, 1);

    // The path that could double-report: a handle is a plain struct, so it
    // can be copied, where upstream's guard is moved into the connection
    // actor so that it cannot be. Both copies are deinited, and only the one
    // the registry still holds reports.
    var copy = admitted.guard;
    try t.expect(admitted.guard.deinit() == .disconnected);
    try t.expectEqual(Unregister.already_gone, copy.deinit());
    try t.expectEqual(@as(usize, 0), registry.nodeCount());

    // The other half: one handle, deinited twice. The mark is set before the
    // report, so the second call finds nothing to do.
    var guard = (try registry.admit(node_id, 2)).guard;
    try t.expect(guard.deinit() == .disconnected);
    try t.expectEqual(Unregister.already_gone, guard.deinit());

    // And a handle for a connection that was never admitted.
    var stranger: Reg.OnDisconnectGuard = .{
        .registry = &registry,
        .node_id = node_id,
        .connection_id = 99,
        .reported = false,
    };
    try t.expectEqual(Unregister.already_gone, stranger.deinit());
}

test "a registry refuses what the caller sized it for" {
    // One slot and one displaced connection: neither is generous.
    // `Registry` is a generic factory: the binding holds the struct type it
    // returns, and a type binding is PascalCase rather than a value.
    // zwanzig-disable-next-line: identifier-style
    const Reg = Registry(1);
    var slots: [1]Reg.Slot = undefined;
    var registry = Reg.init(&slots);
    var first = try registry.admit(try relay_test_ids.testNodeId(7), 1);
    try t.expectError(error.NoFreeSlot, registry.admit(try relay_test_ids.testNodeId(8), 2));
    // One displaced connection fits; the second does not.
    try t.expectEqual(
        Reg.Admit{ .replaced = 1 },
        (try registry.admit(try relay_test_ids.testNodeId(7), 3)).admit,
    );
    try t.expectError(
        error.TooManyDuplicateConnections,
        registry.admit(try relay_test_ids.testNodeId(7), 4),
    );
    // The two refusals changed nothing, which is the other half of a refusal
    // being safe. Connection 3 is the one that did get in.
    try t.expectEqual(@as(usize, 1), registry.nodeCount());
    try t.expectEqual(
        @as(?ConnectionId, 3),
        registry.activeConnectionId(try relay_test_ids.testNodeId(7)),
    );
    try t.expect(first.guard.deinit() == .duplicate);
}

test "an empty registry holds nothing and refuses everything" {
    // Zero slots is degenerate rather than broken: every admission is refused
    // and every lookup is empty, with no indexing anywhere.
    // `Registry` is a generic factory: the binding holds the struct type it
    // returns, and a type binding is PascalCase rather than a value.
    // zwanzig-disable-next-line: identifier-style
    const Reg = Registry(1);
    var registry = Reg.init(&.{});
    try t.expectError(error.NoFreeSlot, registry.admit(try relay_test_ids.testNodeId(9), 1));
    try t.expectEqual(
        @as(?ConnectionId, null),
        registry.activeConnectionId(try relay_test_ids.testNodeId(9)),
    );
    try t.expectEqual(@as(usize, 0), registry.nodeCount());
}

test "a removed entry does not hide the one behind it" {
    // A table with room for two, and two node ids in it. Whether their
    // probes collide is up to the hash; what must hold either way is that a
    // removal leaves the other findable, which is what a tombstone is for.
    // `Registry` is a generic factory: the binding holds the struct type it
    // returns, and a type binding is PascalCase rather than a value.
    // zwanzig-disable-next-line: identifier-style
    const Reg = Registry(2);
    var slots: [2]Reg.Slot = undefined;
    var registry = Reg.init(&slots);
    const first_node = try relay_test_ids.testNodeId(10);
    const second_node = try relay_test_ids.testNodeId(11);

    var first = try registry.admit(first_node, 1);
    var second = try registry.admit(second_node, 2);
    try t.expectEqual(@as(?ConnectionId, 1), registry.activeConnectionId(first_node));
    try t.expectEqual(@as(?ConnectionId, 2), registry.activeConnectionId(second_node));

    try t.expect(first.guard.deinit() == .disconnected);
    try t.expectEqual(@as(?ConnectionId, null), registry.activeConnectionId(first_node));
    try t.expectEqual(@as(?ConnectionId, 2), registry.activeConnectionId(second_node));
    try t.expect(second.guard.deinit() == .disconnected);
    try t.expectEqual(@as(usize, 0), registry.nodeCount());
    // And the table is reusable after the tombstones, which is what `rehash`
    // is for.
    try t.expect((try registry.admit(first_node, 3)).admit == .fresh);
    try t.expectEqual(@as(?ConnectionId, 3), registry.activeConnectionId(first_node));
}

test "a rebuild keeps every connection and hands the table its empty slots back" {
    // Churn, with a collision the hash decides: seeds 4, 5 and 6 all probe
    // from the same slot in an eight-slot table, so two of them wrap past the
    // end of it and the rebuild has to move entries whose probe path crosses
    // the tombstones rather than the ones that only pass them.
    // `Registry` is a generic factory: the binding holds the struct type it
    // returns, and a type binding is PascalCase rather than a value.
    // zwanzig-disable-next-line: identifier-style
    const Reg = Registry(4);
    var slots: [8]Reg.Slot = undefined;
    var registry = Reg.init(&slots);

    const wrapped_a = try relay_test_ids.testNodeId(4);
    const wrapped_b = try relay_test_ids.testNodeId(5);
    const wrapped_c = try relay_test_ids.testNodeId(6);
    const churned = try relay_test_ids.testNodeId(9);
    const churned_too = try relay_test_ids.testNodeId(16);
    const held = try relay_test_ids.testNodeId(14);

    // Six node ids, one per slot, and then a second connection that takes one
    // of them away from the first: the table holds a displaced connection as
    // well as the live ones, and the rebuild has to keep both.
    var first = try registry.admit(wrapped_a, 1);
    var displaced = try registry.admit(wrapped_b, 2);
    try t.expect((try registry.admit(wrapped_c, 3)).admit == .fresh);
    var gone = try registry.admit(churned, 4);
    var also_gone = try registry.admit(churned_too, 5);
    var kept = try registry.admit(held, 6);
    var newest = try registry.admit(wrapped_b, 7);
    // The displaced connection is the one that lost the node id, not the one
    // that took it.
    try t.expectEqual(Reg.Admit{ .replaced = 2 }, newest.admit);
    try t.expectEqual(@as(usize, 6), registry.nodeCount());

    // Three of them leave, which spends six of the eight slots, so the next
    // admission is over three quarters full and rebuilds.
    try t.expect(gone.guard.deinit() == .disconnected);
    try t.expect(also_gone.guard.deinit() == .disconnected);
    try t.expect(first.guard.deinit() == .disconnected);
    try t.expectEqual(@as(usize, 3), registry.nodeCount());
    try t.expectEqual(@as(usize, 3), registry.tombstones);

    var rebuilt = try registry.admit(try relay_test_ids.testNodeId(24), 8);
    try t.expectEqual(Reg.Admit.fresh, rebuilt.admit);

    // Every entry survived the rebuild: the three that stayed, the node id the
    // newest connection owns, and the ones that left, which stay gone.
    try t.expectEqual(@as(?ConnectionId, 7), registry.activeConnectionId(wrapped_b));
    try t.expectEqual(@as(?ConnectionId, 3), registry.activeConnectionId(wrapped_c));
    try t.expectEqual(@as(?ConnectionId, 6), registry.activeConnectionId(held));
    try t.expectEqual(
        @as(?ConnectionId, 8),
        registry.activeConnectionId(try relay_test_ids.testNodeId(24)),
    );
    try t.expectEqual(@as(?ConnectionId, null), registry.activeConnectionId(wrapped_a));
    try t.expectEqual(@as(?ConnectionId, null), registry.activeConnectionId(churned));
    try t.expectEqual(@as(?ConnectionId, null), registry.activeConnectionId(churned_too));
    try t.expectEqual(@as(usize, 4), registry.nodeCount());

    // The rebuild cleared the tombstones, in the caller's slots and not only
    // in the count: what the table measures afterwards is its entries, so the
    // next rebuild is that many admissions away rather than one admission away.
    try t.expectEqual(@as(usize, 0), registry.tombstones);
    for (registry.slots) |slot| try t.expect(std.meta.activeTag(slot) != .tombstone);

    // The displaced connection is still remembered, and still the one the node
    // id goes back to.
    switch (newest.guard.deinit()) {
        .promoted => |promotion| try t.expectEqual(@as(ConnectionId, 2), promotion.took_over),
        else => return error.TestUnexpectedResult,
    }
    try t.expectEqual(@as(?ConnectionId, 2), registry.activeConnectionId(wrapped_b));
    try t.expect(displaced.guard.deinit() == .disconnected);
    try t.expectEqual(@as(?ConnectionId, null), registry.activeConnectionId(wrapped_b));

    // A connection displaced after the rebuild is the duplicate when it goes,
    // and leaves the live one holding the node id.
    var replaces = try registry.admit(held, 9);
    try t.expectEqual(Reg.Admit{ .replaced = 6 }, replaces.admit);
    try t.expect(kept.guard.deinit() == .duplicate);
    try t.expectEqual(@as(?ConnectionId, 9), registry.activeConnectionId(held));
    try t.expect(replaces.guard.deinit() == .disconnected);

    // And the table keeps taking connections afterwards, right up to a second
    // rebuild, which leaves every one of them where the caller put it.
    try t.expect((try registry.admit(try relay_test_ids.testNodeId(1), 10)).admit == .fresh);
    try t.expect((try registry.admit(try relay_test_ids.testNodeId(2), 11)).admit == .fresh);
    try t.expect((try registry.admit(try relay_test_ids.testNodeId(3), 12)).admit == .fresh);
    try t.expect((try registry.admit(try relay_test_ids.testNodeId(7), 13)).admit == .fresh);
    try t.expect((try registry.admit(try relay_test_ids.testNodeId(10), 14)).admit == .fresh);
    var again = try registry.admit(try relay_test_ids.testNodeId(11), 15);
    try t.expectEqual(Reg.Admit.fresh, again.admit);
    try t.expectEqual(@as(usize, 8), registry.nodeCount());
    try t.expectEqual(@as(usize, 0), registry.tombstones);
    for (registry.slots) |slot| try t.expect(std.meta.activeTag(slot) != .tombstone);
    try t.expectEqual(@as(?ConnectionId, 3), registry.activeConnectionId(wrapped_c));
    try t.expectEqual(
        @as(?ConnectionId, 8),
        registry.activeConnectionId(try relay_test_ids.testNodeId(24)),
    );
    try t.expectEqual(
        @as(?ConnectionId, 10),
        registry.activeConnectionId(try relay_test_ids.testNodeId(1)),
    );
    try t.expectEqual(
        @as(?ConnectionId, 11),
        registry.activeConnectionId(try relay_test_ids.testNodeId(2)),
    );
    try t.expectEqual(
        @as(?ConnectionId, 12),
        registry.activeConnectionId(try relay_test_ids.testNodeId(3)),
    );
    try t.expectEqual(
        @as(?ConnectionId, 13),
        registry.activeConnectionId(try relay_test_ids.testNodeId(7)),
    );
    try t.expectEqual(
        @as(?ConnectionId, 14),
        registry.activeConnectionId(try relay_test_ids.testNodeId(10)),
    );
    try t.expectEqual(
        @as(?ConnectionId, 15),
        registry.activeConnectionId(try relay_test_ids.testNodeId(11)),
    );
    try t.expect(rebuilt.guard.deinit() == .disconnected);
    try t.expect(again.guard.deinit() == .disconnected);
}

test "a registry action lands on a saturated connection's control queue" {
    // The two halves together, which is the shape invariant 9 is really
    // about: a second connection arrives for a node id whose first connection
    // has a full datagram backlog.
    // `Registry` is a generic factory: the binding holds the struct type it
    // returns, and a type binding is PascalCase rather than a value.
    // zwanzig-disable-next-line: identifier-style
    const Reg = Registry(2);
    var slots: [2]Reg.Slot = undefined;
    var registry = Reg.init(&slots);
    const node_id = try relay_test_ids.testNodeId(14);

    var data_storage: [1]Packet = undefined;
    var control_storage: [1]Control = undefined;
    var connection = Connection.init(&data_storage, &control_storage);
    try connection.data.push(.{ .src = node_id, .data = "ozai" });

    var first = try registry.admit(node_id, 1);
    var second = try registry.admit(node_id, 2);
    try t.expectEqual(Reg.Admit{ .replaced = 1 }, second.admit);

    // Upstream's `old_client.try_send_health(Status::SameEndpointIdConnected)`
    // (`server/clients.rs:90-91`), over the control queue, which is not full.
    try connection.control.push(.{ .status = .same_endpoint_id_connected });
    try t.expectEqual(
        Control{ .status = .same_endpoint_id_connected },
        connection.control.pop().?,
    );
    // The datagram queue is still refusing, which is what the second queue is
    // for.
    try t.expectError(
        error.QueueFull,
        connection.data.push(.{ .src = node_id, .data = "ozai" }),
    );
    try t.expect(first.guard.deinit() == .duplicate);
    try t.expect(second.guard.deinit() == .disconnected);
}