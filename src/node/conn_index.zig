//! Peer id → connection: the one table that turns a request naming a node into
//! a stream the bytes can be written on.
//!
//! **The key is a node id because nothing else knows one.** `quic_conn.Conn`
//! answers a socket address, and `addr_map` answers the *key* an address was
//! allocated for — which is `null` for a direct path, because a dialled peer
//! gets its own real address and enters no map. A gossip state machine names a
//! node and nothing else: `OutEvent.send_message` is `{ to: NodeId, message }`
//! and `disconnect_peer` is a bare `NodeId`. This table is therefore the whole
//! of the translation, and it is here rather than in `gossip_state` because it
//! is about connections rather than about swarms.
//!
//! **Fixed storage, and a full table refuses rather than evicts.** Every slot
//! is inline, so a node's whole peer set is one allocation it already owns and
//! no look-up can fail for want of memory. `put` on a full table answers
//! `error.ConnectionIndexFull` and leaves every entry alone — evicting a peer
//! to make room would turn that peer's next send into a silent no-op, and a
//! no-op here is indistinguishable on the wire from a peer that is merely
//! unreachable, which is the one failure this table exists to rule out.
//!
//! No clock, no allocator, no I/O: an entry is a `NodeId` and a borrowed
//! connection, and both outlive the index only as long as the bridge entry does.

const std = @import("std");
const base_key = @import("../base/key.zig");
const quic_conn = @import("../transport/quic_conn.zig");
const config = @import("node_config.zig");

const NodeId = base_key.NodeId;

pub const Error = error{ConnectionIndexFull};

/// One peer and the connection carrying it.
const Entry = struct {
    peer: NodeId,
    conn: quic_conn.Conn,
};

pub const Index = struct {
    /// Uninitialised past `len`, which is the only prefix anything reads.
    entries: [config.max_connections]Entry = undefined,
    len: usize = 0,

    pub fn count(self: *const Index) usize {
        return self.len;
    }

    /// Name a peer, or re-point one already named.
    ///
    /// A peer already held is rewritten rather than appended, so a peer whose
    /// connection was replaced — a later dial for the same node id — keeps one
    /// entry and the old, now finished, connection is never reachable again.
    pub fn put(self: *Index, peer: NodeId, conn: quic_conn.Conn) Error!void {
        if (self.slotOf(peer)) |slot| {
            self.entries[slot].conn = conn;
            return;
        }
        if (self.len == config.max_connections) return error.ConnectionIndexFull;
        self.entries[self.len] = .{ .peer = peer, .conn = conn };
        self.len += 1;
    }

    /// The connection a peer is reached on, or null for a peer this node has
    /// no connection to — which is a fact about the peer, not a failure.
    pub fn connFor(self: *const Index, peer: NodeId) ?quic_conn.Conn {
        const slot = self.slotOf(peer) orelse return null;
        return self.entries[slot].conn;
    }

    /// The peer a finished connection was carrying, by the core's own id.
    ///
    /// `expire` holds a connection the core has already finished with and needs
    /// the node id the membership layer knows that peer by; the core's id is
    /// the only handle it has left, because a direct path's address is not in
    /// any map.
    pub fn forget(self: *Index, connection: u64) ?NodeId {
        var index: usize = 0;
        while (index < self.len) : (index += 1) {
            if (self.entries[index].conn.id() != connection) continue;
            const peer = self.entries[index].peer;
            self.swapRemove(index);
            return peer;
        }
        return null;
    }

    /// The connection held for a peer, dropped from the table.
    ///
    /// Asked by a `disconnect_peer` action, which names a node and nothing
    /// else: the entry is the connection, so taking it answers both questions
    /// at once and leaves no route to a peer this node has just refused.
    pub fn forgetPeer(self: *Index, peer: NodeId) ?quic_conn.Conn {
        const slot = self.slotOf(peer) orelse return null;
        const conn = self.entries[slot].conn;
        self.swapRemove(slot);
        return conn;
    }

    fn slotOf(self: *const Index, peer: NodeId) ?usize {
        for (self.entries[0..self.len], 0..) |*entry, index| {
            // The repository's own id comparison; `NodeId` has no `eql`, and
            // this is the idiom every other table here uses.
            if (entry.peer.order(peer) == .eq) return index;
        }
        return null;
    }

    /// Order is not this table's contract: the caller that walks `forget` and
    /// `put` in one pass has already read whatever it needed, and a swap costs
    /// one copy of a 40-byte entry where a shift would cost a scan.
    fn swapRemove(self: *Index, index: usize) void {
        std.debug.assert(index < self.len);
        self.entries[index] = self.entries[self.len - 1];
        self.len -= 1;
    }
};
