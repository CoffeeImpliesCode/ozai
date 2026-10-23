//! Which connection a peer is spoken on.
//!
//! The gossip layer names peers and never addresses connections: every message
//! it asks to be sent ends in a `NodeId` (`gossip/hyparview.zig`), and nothing
//! in this project can turn that id into a socket. This is that turn, and it is
//! the whole of it — a bounded directory from a peer to the connection
//! carrying it, held by the node and asked once per send.
//!
//! **Nothing here is reproduced from the Rust tree, so no upstream line is
//! cited and no interoperability claim is made.** A peer-to-connection pairing
//! is the one lookup every send needs, and this is it as a value: bounded,
//! owned, and drivable without a socket.
//!
//! **It allocates nothing, so there is no allocator to pass.** Every entry is
//! inline storage sized by the bound, which is a stronger answer than
//! parameterising one: there is no failure path for a caller to inject into and
//! none for it to forget. A node's whole directory is a value a test holds on
//! the stack, which is what `relay/server_registry.zig` does with a relay's
//! clients.

const std = @import("std");
const base_key = @import("../base/key.zig");

const NodeId = base_key.NodeId;

/// The core's number for one connection, and the value
/// `transport/bridge_conn.zig` reads back out of a `Conn`.
///
/// **A number and not a pointer.** `Conn.entry` is a `*Entry` into memory the
/// core heap-allocates and frees in `Bridge.sweep`, so a pointer kept here
/// would read freed bytes the moment that connection was swept — a fault with
/// no test able to see it, because the test would have to run the sweeper. A
/// `u64` cannot dangle, it compares with `==`, and the core already promises it
/// is unique per bridge and never reused, so a stale entry is a wrong number
/// rather than a wrong dereference. An index into a pool is not used either:
/// it would be a second way for a connection to be renamed, and the core's
/// number is the one a log line already carries.
pub const ConnId = u64;

/// How many peers this node speaks to at once.
///
/// **A bound is a refusal, and a growing directory would be a directory whose
/// memory a remote peer sizes.** This is the number an operator picks by
/// naming the peers the node has, and it is the only reason `bind` has an
/// error at all. Thirty-two is the ceiling HyParView already puts on one
/// neighbour list (`gossip/hyparview/bounds.zig`, `max_active`), so a full
/// directory is a node at the width its own protocol already allows.
pub const max_peers = 32;

/// Every way the directory refuses a bind.
pub const BindError = error{
    /// The directory holds its bound already and `peer` is not one of them.
    ///
    /// **Nothing is evicted.** The caller holds the connections and knows
    /// which of them the node can do without; shedding one is a decision about
    /// a peer somebody is relying on. A directory that dropped a live peer to
    /// admit a new one would then route a name to a connection it had already
    /// closed, and the count of peers it reports would disagree with the count
    /// it can actually answer for. A refusal the caller can count is the only
    /// honest version of "the table is full".
    NoFreeSlot,
};

/// What a bind did.
pub const Bind = union(enum) {
    /// The peer had no connection in here and owns this one now.
    fresh,
    /// The peer was already bound and has moved to the connection that was
    /// passed in; the connection it was on is what this carries.
    ///
    /// **The value is the connection that lost the peer, not the one that took
    /// it.** This directory does not own the transport and cannot tell a
    /// displaced connection that is the same socket re-advertised from one that
    /// is closed, so it reports rather than closes: the caller is the only one
    /// that knows, and it is the one that owes the peer a message.
    replaced: ConnId,
};

/// One peer and the connection its messages go out on.
///
/// Fixed-size and owned: nothing here borrows, so copying an entry copies the
/// route rather than a handle to it, and the directory outliving a stale copy
/// of one is not a dangling read.
pub const Entry = struct {
    /// The peer, which is also the key.
    peer: NodeId,
    /// The connection its messages are written to.
    conn: ConnId,
};

/// A bounded directory from peer to connection.
///
/// `capacity` is how many peers this one holds, and `ConnIndex(max_peers)` is
/// the one a node builds. Nothing grows: `bind` past `capacity` is
/// `error.NoFreeSlot`, and a peer leaves only through `remove`.
///
/// **A peer is bound at most once, and the second bind replaces rather than
/// refuses.** A peer that reconnects is the same peer, and refusing would
/// leave the directory pointing at the connection it had before — one this node
/// has already stopped using — which is the failure `remove` exists to make
/// impossible. `Bind.replaced` carries the connection that was displaced so the
/// caller can finish with it.
///
/// **A full directory refuses only peers it does not hold.** A rebind is an
/// update of an entry that exists and needs no slot, so `NoFreeSlot` means
/// exactly what it says and never turns into an eviction.
///
/// **A peer's position is not its identity.** Entries are held in the order
/// they were first bound and `remove` moves the last entry into the gap, so
/// two directories holding the same peers need not list them the same way.
pub fn ConnIndex(comptime capacity: usize) type {
    return struct {
        const Self = @This();

        // A zero-capacity directory holds nothing and can never hold anything,
        // which is a caller mistake rather than a state to represent. Refused
        // here, where the mistake is, and not at the first `bind` on a run
        // that already shipped.
        comptime {
            std.debug.assert(capacity > 0);
        }

        /// The peers held, first bound first. Only `[0..len]` is ever read, so
        /// an entry past `len` is `undefined` rather than empty: nothing walks
        /// past `len` to find it.
        entries: [capacity]Entry = undefined,
        /// How many of `entries` are in use, never a capacity: a directory of
        /// two holding one is `len == 1`.
        len: usize = 0,

        /// An empty directory. Nothing to release — see the module doc — so
        /// there is no `deinit` and no allocator to hand one.
        pub fn init() Self {
            return .{};
        }

        /// How many peers are bound. A count of routes and not of connections:
        /// a peer that rebound is still one, and that is the difference between
        /// a node holding four peers and a node holding five sockets.
        pub fn count(self: *const Self) usize {
            return self.len;
        }

        /// The connection `peer` is spoken on, or null for a peer this node has
        /// no connection to.
        ///
        /// The connection is a value and not a borrow, so answering does not
        /// keep a connection alive and cannot outlive one.
        pub fn connFor(self: *const Self, peer: NodeId) ?ConnId {
            const index = self.indexOf(peer) orelse return null;
            return self.entries[index].conn;
        }

        /// Route `peer` to `conn`, or report the connection it was on.
        ///
        /// A refused bind leaves the directory exactly as it was, and the peer
        /// that was refused is still routed where it was.
        pub fn bind(self: *Self, peer: NodeId, conn: ConnId) BindError!Bind {
            const index = self.indexOf(peer) orelse return self.openSlot(peer, conn);
            const displaced = self.entries[index].conn;
            self.entries[index].conn = conn;
            return Bind{ .replaced = displaced };
        }

        /// Forget `peer`, and answer with the connection it was on so the
        /// caller can act on it. Null for a peer this directory does not hold.
        ///
        /// **Removal is explicit and names what it removes.** A directory that
        /// dropped a peer on its own — to make room, to stay under a bound —
        /// would be a peer that stops receiving gossip with nothing reporting
        /// it. Here a peer leaves because the caller said so, and the caller
        /// learns which connection it has to close. A second `remove` of the
        /// same peer is `null` and evicts nobody, which is what makes a
        /// disconnect path that runs twice harmless.
        pub fn remove(self: *Self, peer: NodeId) ?ConnId {
            const index = self.indexOf(peer) orelse return null;
            const conn = self.entries[index].conn;
            // ZBC cannot carry `indexOf`'s nonempty-prefix proof into this subtraction.
            // zbc-disable-next-line: index-minus-one-without-zero-guard
            self.entries[index] = self.entries[self.len - 1];
            self.len -= 1;
            return conn;
        }

        /// Where `peer` is, or null for a peer this directory does not hold.
        ///
        /// A scan and not a hash: the whole directory is `capacity` entries,
        /// a lookup is a handful of 32-byte comparisons, and the work it saves
        /// is dwarfed by the datagram the answer is for. The loop is bounded
        /// by the storage it walks, so it cannot run away. The bound on
        /// probing iterations `relay/server_registry.zig` needs is this
        /// table's `len`, which is why this one has no tombstone either.
        fn indexOf(self: *const Self, peer: NodeId) ?usize {
            for (self.entries[0..self.len], 0..) |entry, index| {
                if (entry.peer.order(peer) == .eq) return index;
            }
            return null;
        }

        /// Give a peer that is not held the one free slot there is.
        fn openSlot(self: *Self, peer: NodeId, conn: ConnId) BindError!Bind {
            if (self.len == capacity) return error.NoFreeSlot;
            self.entries[self.len] = .{ .peer = peer, .conn = conn };
            self.len += 1;
            return Bind.fresh;
        }
    };
}

// --- tests

const t = std.testing;
const node_test_ids = @import("node_test_ids.zig");

test "a bound peer is found by the id it is known by" {
    // `ConnIndex` is a generic factory: the binding holds the struct type it
    // returns, and a type binding is PascalCase rather than a value.
    // zwanzig-disable-next-line: identifier-style
    const Index = ConnIndex(2);
    var index = Index.init();

    // Nothing is bound yet, and the two names below are different peers.
    try t.expectEqual(@as(usize, 0), index.count());
    const first = try node_test_ids.testNodeId(1);
    const second = try node_test_ids.testNodeId(2);
    try t.expectEqual(@as(?ConnId, null), index.connFor(first));

    try t.expectEqual(Bind.fresh, try index.bind(first, 10));
    try t.expectEqual(Bind.fresh, try index.bind(second, 20));
    try t.expectEqual(@as(usize, 2), index.count());
    // Each peer answers with its own connection and not with its neighbour's,
    // which is what proves the key is the id rather than the slot.
    try t.expectEqual(@as(?ConnId, 10), index.connFor(first));
    try t.expectEqual(@as(?ConnId, 20), index.connFor(second));
}

test "binding a peer a second time displaces the connection it was on" {
    // zwanzig-disable-next-line: identifier-style
    const Index = ConnIndex(2);
    var index = Index.init();
    const peer = try node_test_ids.testNodeId(3);
    const bystander = try node_test_ids.testNodeId(4);
    _ = try index.bind(bystander, 7);

    try t.expectEqual(Bind.fresh, try index.bind(peer, 10));
    // One entry however many connections the peer has been on, and the bind
    // says which connection lost it: the caller cannot close what it is not
    // told about.
    try t.expectEqual(Bind{ .replaced = 10 }, try index.bind(peer, 11));
    try t.expectEqual(@as(usize, 2), index.count());
    try t.expectEqual(@as(?ConnId, 11), index.connFor(peer));
    // The peer nobody touched still routes where it did.
    try t.expectEqual(@as(?ConnId, 7), index.connFor(bystander));

    // A third bind displaces the second and not the first: the value carried
    // is what the entry holds now.
    try t.expectEqual(Bind{ .replaced = 11 }, try index.bind(peer, 12));
    try t.expectEqual(@as(usize, 2), index.count());
    try t.expectEqual(@as(?ConnId, 12), index.connFor(peer));
    try t.expectEqual(@as(?ConnId, 7), index.connFor(bystander));
}

test "a removed peer is gone and the peers around it are not" {
    // zwanzig-disable-next-line: identifier-style
    const Index = ConnIndex(3);
    var index = Index.init();
    const first = try node_test_ids.testNodeId(5);
    const second = try node_test_ids.testNodeId(6);
    const third = try node_test_ids.testNodeId(7);
    _ = try index.bind(first, 10);
    _ = try index.bind(second, 20);
    _ = try index.bind(third, 30);

    // The removed peer answers with the connection it was on, because the
    // caller closing it is the whole point of a removal.
    try t.expectEqual(@as(?ConnId, 20), index.remove(second));
    try t.expectEqual(@as(usize, 2), index.count());
    try t.expectEqual(@as(?ConnId, null), index.connFor(second));
    // The peers on either side of the gap it left are untouched: a removal
    // moves the last entry into the gap and drops nothing else.
    try t.expectEqual(@as(?ConnId, 10), index.connFor(first));
    try t.expectEqual(@as(?ConnId, 30), index.connFor(third));

    // A peer that was never held is a null removal and evicts nobody, which
    // is what makes a disconnect path that runs twice harmless.
    try t.expectEqual(@as(?ConnId, null), index.remove(second));
    try t.expectEqual(@as(usize, 2), index.count());
    try t.expectEqual(@as(?ConnId, 10), index.connFor(first));
    try t.expectEqual(@as(?ConnId, 30), index.connFor(third));
}

test "a full directory refuses a peer it does not hold and keeps every peer it had" {
    // The production bound, so the number the operator picks is the one under
    // test and not a smaller one that behaves the same way. The number itself
    // is pinned because it is the answer to "how many peers does this node
    // speak to", and that answer must not drift silently.
    // zwanzig-disable-next-line: identifier-style
    const Index = ConnIndex(max_peers);
    var index = Index.init();
    try t.expectEqual(@as(usize, 32), max_peers);

    for (0..max_peers) |offset| {
        const seed: u8 = @intCast(offset + 1);
        try t.expectEqual(Bind.fresh, try index.bind(
            try node_test_ids.testNodeId(seed),
            @intCast(offset),
        ));
    }
    try t.expectEqual(@as(usize, max_peers), index.count());

    // One peer past the bound is refused, and the refusal is an error the
    // caller can count rather than an eviction it has to detect.
    const stranger = try node_test_ids.testNodeId(200);
    try t.expectError(error.NoFreeSlot, index.bind(stranger, 999));
    try t.expectEqual(@as(usize, max_peers), index.count());
    try t.expectEqual(@as(?ConnId, null), index.connFor(stranger));

    // Every peer the directory already held still answers with its own
    // connection. This is the whole of what "never evicts" means: the refusal
    // cost the directory nothing and the newcomer nothing but its bind.
    for (0..max_peers) |offset| {
        const seed: u8 = @intCast(offset + 1);
        const conn: ConnId = @intCast(offset);
        try t.expectEqual(@as(?ConnId, conn), index.connFor(
            try node_test_ids.testNodeId(seed),
        ));
    }

    // A rebind needs no slot, so a full directory refuses only peers it does
    // not hold: the peer moves and the count does not change.
    try t.expectEqual(
        Bind{ .replaced = 0 },
        try index.bind(try node_test_ids.testNodeId(1), 500),
    );
    try t.expectEqual(@as(usize, max_peers), index.count());
    try t.expectEqual(@as(?ConnId, 500), index.connFor(try node_test_ids.testNodeId(1)));

    // One departure frees exactly one slot, for exactly one arrival: the
    // refusal above was not a queue.
    try t.expectEqual(@as(?ConnId, 500), index.remove(try node_test_ids.testNodeId(1)));
    try t.expectEqual(Bind.fresh, try index.bind(stranger, 999));
    try t.expectEqual(@as(usize, max_peers), index.count());
    try t.expectEqual(@as(?ConnId, 999), index.connFor(stranger));
}
