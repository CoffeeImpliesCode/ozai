//! The two bounded queues each relay connection writes from, and the item
//! types behind them.
//!
//! Captured 2026-09-30 from n0-computer/iroh commit
//! 187f59e80afdae6bd9866002b33d3365c00b06d8: the two channels and the `biased`
//! select that drains them from `iroh-relay/src/server/client.rs`, and
//! `PER_CLIENT_SEND_QUEUE_DEPTH` from `iroh-relay/src/protos/relay.rs`.
//!
//! Nothing here allocates: every queue is a bounded FIFO over storage the caller
//! owns, so there is no `deinit` and what the caller owns, `init` says. The
//! handshake a connection runs before anything is queued is
//! `relay/server_handshake.zig`, and the registry of the connections these
//! queues belong to is `relay/server_registry.zig`. `relay/server.zig`
//! re-exports the lot.

const std = @import("std");

const key = @import("../base/key.zig");
const frame = @import("frame.zig");
const relay_test_ids = @import("relay_test_ids.zig");

const NodeId = key.NodeId;

/// A datagram queued for one client. Upstream `server::client::Packet`
/// (`server/client.rs:41-46`).
///
/// **The storage contract is the whole of this type.** `src` is a value and
/// `data` is borrowed from whoever copied the datagram out of its read buffer —
/// a ring slot of the caller's own in this repo's relay, a `Bytes` upstream's —
/// and the queue copies nothing:
///
/// - the bytes must stay alive and unmutated from the `push` until the item is
///   popped, which is the whole of "the relay has room for what it forwarded";
/// - **a popped `Packet` is a copy of the item and not of its bytes, and it owns
///   nothing.** The `pop` released the ring slot and the queue promises nothing
///   past that: the bytes are still the caller's own storage, but the ring writes
///   that slot again `capacity() - len()` pushes later, with `len()` read just
///   after the `pop` — the very next `push` when the queue was full at it. A
///   caller that needs a datagram beyond that has to copy it out first;
/// - `peek` removes nothing, so the bytes it names are still the queue's own.
pub const Packet = struct {
    /// The node the datagram came from. Upstream `src`.
    src: NodeId,
    /// The datagram, borrowed from whoever decoded it. The queue's storage is
    /// the caller's, so the bytes have to outlive their time in the queue,
    /// which is the same rule as any other borrow and a good deal cheaper
    /// than a copy per datagram per hop on the relay's hottest path.
    data: []const u8,
};

/// A message queued for one client that is not a datagram.
///
/// Upstream calls these "messages" and the other kind "packets"
/// (`server/client.rs:108-111`). Both arms are values the registry's own
/// actions produce, which is what makes the two queues worth having: they are
/// written to from the same few places and they are drained under different
/// rules.
///
/// **Nothing here borrows**, which is the difference from `Packet` and the reason
/// one of the two queues can be a bounded table of values: a queued `Control` is
/// self-contained, outlives whatever buffer the event that produced it was read
/// from, and needs no ring slot to live in.
pub const Control = union(enum) {
    /// `FrameType::EndpointGone` (8): a peer this client has sent to is gone.
    /// Upstream `RelayToClientMsg::EndpointGone`.
    peer_gone: NodeId,
    /// The relay's one-way declaration of the connection's health. Upstream's
    /// `Status` for a v2 client and `Health` for a v1 one — the same event in
    /// two encodings, and which encoding goes on the wire is the negotiated
    /// version's business (`server/client.rs:214-225`).
    status: frame.Status,
};

/// A bounded FIFO over storage the caller owns.
///
/// Upstream's `mpsc::channel(channel_capacity)`, with the two properties that
/// matter kept: bounded, so one slow client cannot grow the relay's heap, and
/// non-blocking on push, so a full queue refuses rather than stalling the
/// relay behind a client that will never read. Capacity is the length of the
/// storage, so there is no second number to keep in step with the first.
///
/// **The consumer supplies two things and the queue calls out to neither**: the
/// item type, and the `storage` slice this is instantiated over. Everything it
/// stores is the item's own value, so the queue is exactly as pure as its items
/// are — a queue of `Packet` inherits `Packet`'s borrow and a queue of `Control`
/// inherits nothing.
///
/// **The bound is `storage.len`, and reaching it is a refusal and not an
/// eviction.** A `push` into a full queue is `error.QueueFull`, leaves the queue
/// exactly as it was, and writes the item nowhere, so nothing the caller still
/// believes it holds has been overwritten. Zero-length storage is a queue that
/// refuses every push and is never indexed, which is what makes the arithmetic
/// below total rather than a division by zero.
///
/// **Where an item sits, and when its bytes move.** Item *n* of the queue lives
/// in `storage[(head + n) % storage.len]` and is not written again until it is
/// popped, so an item that borrows points at storage that stays put while it is
/// queued. `pop` releases that slot, and the ring reaches it again only after
/// every other slot has been filled once. `storage`, `head` and `count` are public
/// because a caller that places borrowed bytes per queue position has to compute
/// the same index this will — and that arithmetic is only valid while nothing
/// pushes between the two steps, which is the caller's discipline to keep.
///
/// Nothing here is synchronized, so two threads sharing one queue are a race the
/// caller has to prevent, and there is no `deinit` because there is nothing to
/// free: the storage is the caller's from the first instruction to the last.
pub fn Queue(comptime Item: type) type {
    return struct {
        const Self = @This();

        /// The caller's storage. Its length is the queue's capacity.
        storage: []Item,
        /// Index of the front item.
        head: usize,
        /// How many items are queued.
        count: usize,

        pub const PushError = error{
            /// The queue is at capacity and the item was dropped.
            ///
            /// Upstream's `TrySendError::Full`, and the relay drops the
            /// datagram on it (`server/clients.rs:218-224`).
            ///
            /// **The queue is unchanged and the item is dropped**, which is the
            /// caller's cue to count it: the datagram that did not fit is not
            /// waiting behind the ones that did, so a relay cannot report a
            /// backlog it is not holding.
            QueueFull,
        };

        /// Takes the caller's storage and borrows it: nothing is read from it,
        /// nothing is written to it here, and it is not freed here either, so a
        /// zeroed or otherwise undefined buffer is a valid one to hand over and
        /// the buffer must outlive this queue.
        ///
        /// The length is the capacity, so a queue with no storage is not a
        /// malformed one — it is the one that refuses everything.
        pub fn init(storage: []Item) Self {
            return .{ .storage = storage, .head = 0, .count = 0 };
        }

        /// Adds an item at the back, or refuses.
        ///
        /// The refusal is `error.QueueFull` and it is decided before anything is
        /// written, so the queue and every item in it are exactly as they were.
        /// The item is a value: a caller holding the only copy of something the
        /// item borrows is the one who has to keep it alive until the pop.
        pub fn push(self: *Self, item: Item) PushError!void {
            // This check is also what makes the modulo below safe: a queue
            // with no storage is always full and never indexes.
            if (self.count == self.storage.len) return error.QueueFull;
            self.storage[(self.head + self.count) % self.storage.len] = item;
            self.count += 1;
        }

        /// The front item, removed, or null when the queue is empty.
        ///
        /// **The item is a copy of what was stored, and not of what that item
        /// borrows.** For a `Packet` the datagram bytes belong to the caller's
        /// storage, this queue has released the slot, and the ring overwrites
        /// those bytes only when it wraps back around to that slot — which is the
        /// next `push` if the queue was full and `capacity()` pushes later if it
        /// was not.
        pub fn pop(self: *Self) ?Item {
            if (self.count == 0) return null;
            const item = self.storage[self.head];
            self.head = (self.head + 1) % self.storage.len;
            self.count -= 1;
            return item;
        }

        /// The next item, without removing it.
        ///
        /// It removes nothing, so the item stays at the front and the storage an
        /// item borrows cannot be overwritten until it is popped.
        pub fn peek(self: Self) ?Item {
            if (self.count == 0) return null;
            return self.storage[self.head];
        }

        /// How many items are queued, which is `count` and never the capacity:
        /// a queue of capacity two holding one is `len() == 1`.
        pub fn len(self: Self) usize {
            return self.count;
        }

        /// How many pushes this queue accepts before it refuses.
        ///
        /// This is the bound `push` refuses at, and it is the length of the
        /// caller's storage rather than a number of this file's own, so the two
        /// cannot disagree.
        pub fn capacity(self: Self) usize {
            return self.storage.len;
        }

        /// Whether the next `push` is a refusal, which is a stronger statement
        /// than `len() == capacity()` only because it is the answer to the
        /// question a caller actually asks.
        pub fn isFull(self: Self) bool {
            return self.count == self.storage.len;
        }
    };
}

/// How many datagrams and control messages one connection may have queued.
///
/// Upstream's default `channel_capacity` is
/// `PER_CLIENT_SEND_QUEUE_DEPTH = 512` (`relay.rs:40`), and both channels
/// get it (`server/client.rs:139-140`). The 512 is the number invariant 9 is
/// about: merged, a `Status` sits behind 512 datagrams for a client that has
/// stopped reading, which is a client that most needs to be told.
///
/// **It is a default, not a limit anything here enforces.** Nothing in this
/// module sizes a queue — the caller owns the storage — so the depth is the
/// caller's number and this one is upstream's to start from. A caller that picks
/// a smaller depth refuses sooner and holds fewer bytes per client; one that
/// picks a larger one holds more datagrams for as long as a client stops reading.
/// At whatever depth it picks, reaching it is `error.QueueFull` and the datagram
/// is dropped (`server/clients.rs:218-224`), which is why the control queue is a
/// second queue rather than a longer first one.
pub const per_client_send_queue_depth = 512;

/// The two queues one connection writes from.
///
/// Upstream's `Client` (`server/client.rs:99-114`) holds exactly these two
/// senders, and the connection actor drains them with a `biased` select that
/// takes packets first (`server/client.rs:381-423`). Keeping them apart is
/// what lets a control message be accepted while the datagram queue is full,
/// which is the whole of `docs/ARCHITECTURE.md` invariant 9.
///
/// **The two queues have separate storage and separate bounds, so one of them
/// being full never refuses the other.** That is invariant 9, and it is what lets
/// a `Status` reach a client whose datagram backlog is exhausted. Nothing here
/// allocates and there is no `deinit`; what the caller owns, `init` says.
pub const Connection = struct {
    data: Queue(Packet),
    control: Queue(Control),

    /// Both buffers are the caller's, are borrowed rather than copied, and must
    /// outlive the `Connection`. Their lengths are the capacities, so a caller
    /// that wants a smaller depth passes shorter slices rather than setting a
    /// field — and a caller that passes an empty one has built a connection that
    /// can be said nothing to.
    pub fn init(data_storage: []Packet, control_storage: []Control) Connection {
        return .{
            .data = Queue(Packet).init(data_storage),
            .control = Queue(Control).init(control_storage),
        };
    }

    /// Whether both queues are full, which is the state in which a control
    /// message is the only thing that can still be said to this client.
    ///
    /// **Both full is the state a control message cannot escape**, and one full is
    /// a slow client rather than a lost one: `peer_gone` and every `status` still
    /// fit while the datagram queue refuses.
    pub fn isSaturated(self: Connection) bool {
        return self.data.isFull() and self.control.isFull();
    }
};

// --- tests
const t = std.testing;

test "a status is not refused by a full datagram backlog" {
    // A connection with room for two datagrams and two control messages.
    var data_storage: [2]Packet = undefined;
    var control_storage: [2]Control = undefined;
    var connection = Connection.init(&data_storage, &control_storage);
    const node_id = try relay_test_ids.testNodeId(12);
    const datagram: Packet = .{ .src = node_id, .data = "ozai" };

    // Fill the datagram queue, which is what a client that has stopped
    // reading looks like from here.
    try connection.data.push(datagram);
    try connection.data.push(datagram);
    try connection.control.push(.{ .peer_gone = node_id });
    try connection.control.push(.{ .status = .same_endpoint_id_connected });
    try t.expect(connection.control.isFull());
    try t.expect(connection.data.isFull());
    try t.expect(connection.isSaturated());
    try t.expectError(error.QueueFull, connection.data.push(datagram));

    // Both queues are full and the two of them still answer separately: the
    // control queue hands over what it holds while the datagram queue is
    // exactly as full as it was.
    try t.expectEqual(Control{ .peer_gone = node_id }, connection.control.pop().?);
    try t.expect(connection.data.isFull());
    try t.expectEqual(@as(usize, 2), connection.data.len());

    // And one freed control slot is all it takes to say the thing that
    // matters, without the datagram queue ever having moved.
    try connection.control.push(.{ .status = .rate_limited });
    try t.expectEqual(
        Control{ .status = .same_endpoint_id_connected },
        connection.control.peek().?,
    );
    try t.expectEqual(@as(usize, 2), connection.data.len());
    try t.expectError(error.QueueFull, connection.data.push(datagram));
    try t.expectEqual(
        Control{ .status = .same_endpoint_id_connected },
        connection.control.pop().?,
    );
    try t.expectEqual(Control{ .status = .rate_limited }, connection.control.pop().?);
    try t.expectEqual(@as(?Control, null), connection.control.pop());
}

test "merging the two queues loses the status, which is the point of them" {
    // The same two datagrams, at the same capacity, in one queue. This is the
    // merged shape invariant 9 rules out, and it is worth running rather than
    // describing: the control message is refused, and a client that is being
    // superseded is a client that never hears it.
    var merged_storage: [2]Packet = undefined;
    var merged = Queue(Packet).init(&merged_storage);
    const datagram: Packet = .{ .src = try relay_test_ids.testNodeId(13), .data = "ozai" };
    try merged.push(datagram);
    try merged.push(datagram);
    try t.expectError(error.QueueFull, merged.push(datagram));
    try t.expectEqual(@as(usize, 2), merged.capacity());
}