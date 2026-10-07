//! Acknowledgement, loss detection and the three packet number spaces.
//!
//! `PacketHandler` is the whole surface a connection drives, through
//! `Connection.pkt_handler`; `SentPacketTracker`, `ReceivedPacketTracker`,
//! `SentPacket` and `AckResult` are the state behind it and are reached
//! through the handler's fields and the result it fills.
//!
//! Every tracker retains the allocator it was given, and `PacketHandler`
//! hands the same one to all six of them. Loss detection is driven by the
//! caller's `now`; the only entropy in this file is the injected
//! `std.Random` `nextPacketNumber` is given, and it is drawn from only when
//! a packet number is skipped.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const testing = std.testing;

const ranges = @import("ranges.zig");
const RangeSet = ranges.RangeSet;
const rtt_mod = @import("rtt.zig");
const RttStats = rtt_mod.RttStats;
const frame_mod = @import("frame.zig");
const Frame = frame_mod.Frame;
const AckRange = frame_mod.AckRange;
const MAX_ACK_RANGES = frame_mod.MAX_ACK_RANGES;

/// Encryption level / packet number space.
///
/// One per QUIC packet number space, and the tag value is the index into
/// `PacketHandler.sent` and `PacketHandler.recv`, so `initial` is 0,
/// `handshake` is 1 and `application` is 2. The backing type is `u2`, so
/// three is representable and has no tag: `@enumFromInt` on it is illegal
/// behaviour, not a fourth space that falls back to anything.
pub const EncLevel = enum(u2) {
    initial = 0,
    handshake = 1,
    application = 2,
};

/// Application packet numbers between skips, at first and at most.
const SKIP_INITIAL_PERIOD: u64 = 24;
const SKIP_MAX_PERIOD: u64 = 10_000;

/// The number of packet-reordering threshold for declaring loss (RFC 9002).
const PACKET_THRESHOLD: u64 = 3;

/// Maximum number of ACK-eliciting packets before forcing an ACK.
const ACK_ELICITING_THRESHOLD: u32 = 2;

/// Default max ACK delay (25ms in nanoseconds).
const DEFAULT_MAX_ACK_DELAY: i64 = 25_000_000;

/// Maximum PTO (60 seconds in nanoseconds).
const MAX_PTO: i64 = 60_000_000_000;

/// Maximum PTO for Initial/Handshake spaces (3 seconds in nanoseconds).
/// Caps backoff to ensure timely retransmission under extreme packet loss.
const MAX_HANDSHAKE_PTO: i64 = 3_000_000_000;

/// Maximum number of stream frame records per sent packet.
/// Must be large enough to track all stream frames in a packet (e.g., many small 0-RTT streams).
/// Cap inline stream-frame records per sent packet. Each is 32 bytes and lives
/// inside SentPacket (one per in-flight packet). A 1200-byte MTU can't fit many
/// usefully-sized stream frames anyway — 12 is generous for real traffic and
/// keeps SentPacket at ~432 bytes instead of ~1.6KB.
///
/// The bound is on records, not on frames sent: `SentPacket.addStreamFrame`
/// silently ignores the thirteenth, so the sender must not pack a stream
/// frame it will not be able to retransmit. The packet packer therefore
/// leaves a frame it cannot record for the next packet.
pub const MAX_STREAM_FRAMES_PER_PACKET: usize = 12;

/// Retransmittable control frames recorded per sent packet. A packet that
/// has used them all takes no more such frames; they wait for the next one.
///
/// Same shape as the stream cap: a frame beyond it is not recorded and so is
/// not repeated on loss, which is why the packer re-queues it instead of
/// sending it untracked.
pub const MAX_CONTROL_FRAMES_PER_PACKET: usize = 4;

/// A control frame RFC 9000 13.3 has us repeat when its packet is lost. Flow
/// control credit is recorded by kind only: on loss the current value is sent,
/// never the stale one. RESET_STREAM keeps everything, because a reset uni
/// stream is freed as soon as the frame is queued.
///
/// Each payload is what the retransmission needs to find the frame again, not
/// the bytes to put on the wire: a credit kind names the window or the stream
/// whose current value is read at loss time, so a limit that moved while the
/// packet was in flight is re-sent at its new value. The two kinds that carry
/// their values — `reset_stream` and `stop_sending` — are the two whose
/// streams may already be gone.
///
/// The value is a plain union with no allocator and no pointer, so it is
/// copyable and outlives the `SentPacket` it was copied into.
pub const SentControlFrame = union(enum) {
    /// A MAX_DATA. Re-sent with the connection's current receive window.
    max_data: void,
    /// A MAX_STREAM_DATA, carrying the stream it was for. Re-sent with that
    /// stream's current window, or dropped if the stream has since finished.
    max_stream_data: u64,
    /// A MAX_STREAMS for bidirectional streams, re-sent with the current
    /// limit rather than the one that was in flight.
    max_streams_bidi: void,
    /// A MAX_STREAMS for unidirectional streams, on the same terms as
    /// `max_streams_bidi`.
    max_streams_uni: void,
    /// A DATA_BLOCKED, carrying the limit that was blocked at. Re-sent only
    /// while the connection is still blocked at that same limit.
    data_blocked: u64,
    /// A STREAM_DATA_BLOCKED for one stream, carrying the limit it was
    /// blocked at, and repeated only while that stream is still blocked
    /// there.
    stream_data_blocked: struct { stream_id: u64, limit: u64 },
    /// A STREAMS_BLOCKED for bidirectional streams, carrying the limit; it
    /// is repeated only while that limit still stands.
    streams_blocked_bidi: u64,
    /// A STREAMS_BLOCKED for unidirectional streams, on the same terms as
    /// `streams_blocked_bidi`.
    streams_blocked_uni: u64,
    /// A RESET_STREAM with its whole payload. Repeated verbatim, because
    /// the stream it names may already have been freed when the frame was
    /// queued.
    reset_stream: struct { stream_id: u64, error_code: u64, final_size: u64 },
    /// A STOP_SENDING with its payload, repeated verbatim for the same
    /// reason as `reset_stream`.
    stop_sending: struct { stream_id: u64, error_code: u64 },
    /// A NEW_CONNECTION_ID, carrying the sequence number. The frame is
    /// rebuilt from the local pool entry it named, so a sequence number that
    /// has since been retired is dropped instead of repeated.
    new_connection_id: u64,
    /// A RETIRE_CONNECTION_ID, carrying the sequence number, repeated only
    /// while that retire is still outstanding.
    retire_connection_id: u64,
    /// A NEW_TOKEN. Carries nothing: the token is minted fresh on each
    /// retransmission, because a token this peer never accepted is not one
    /// it needs again.
    new_token: void,
    /// Re-arm reporting on the actual sending path; never replay old address bytes.
    observed_address: u32,
    add_address: @FieldType(frame_mod.PendingControlFrame, "add_address"),
    reach_address: @FieldType(frame_mod.PendingControlFrame, "reach_address"),
    remove_address: u64,
    path_abandon: @FieldType(frame_mod.PendingControlFrame, "path_abandon"),
    /// Rebuild the current status and sequence for this path.
    path_status: u32,
    path_new_connection_id: struct { path_id: u32, seq_num: u64 },
    path_retire_connection_id: @FieldType(frame_mod.PendingControlFrame, "path_retire_connection_id"),
    /// Rebuild the current advertised path limit.
    max_path_id: void,
    /// Blocked notifications preserve the historical limit, like Noq.
    paths_blocked: u32,
    path_cids_blocked: @FieldType(frame_mod.PendingControlFrame, "path_cids_blocked"),

    /// The record for a queued frame, or null for one that is never repeated
    /// (PING, PATH_CHALLENGE/RESPONSE, CONNECTION_CLOSE, ACK_FREQUENCY, IMMEDIATE_ACK).
    /// OBSERVED_ADDRESS also returns null here: the packer must supply its
    /// actual sending path, which the queued wire payload does not contain.
    ///
    /// Except for that context-dependent report, `null` means fire-and-forget,
    /// not an invalid frame.
    pub fn from(pcf: frame_mod.PendingControlFrame) ?SentControlFrame {
        return switch (pcf) {
            .max_data => .max_data,
            .max_stream_data => |m| .{ .max_stream_data = m.stream_id },
            .max_streams_bidi => .max_streams_bidi,
            .max_streams_uni => .max_streams_uni,
            .data_blocked => |l| .{ .data_blocked = l },
            .stream_data_blocked => |b| .{ .stream_data_blocked = .{ .stream_id = b.stream_id, .limit = b.limit } },
            .streams_blocked_bidi => |l| .{ .streams_blocked_bidi = l },
            .streams_blocked_uni => |l| .{ .streams_blocked_uni = l },
            .reset_stream => |r| .{ .reset_stream = .{ .stream_id = r.stream_id, .error_code = r.error_code, .final_size = r.final_size } },
            .stop_sending => |ss| .{ .stop_sending = .{ .stream_id = ss.stream_id, .error_code = ss.error_code } },
            .new_connection_id => |n| .{ .new_connection_id = n.seq_num },
            .retire_connection_id => |seq| .{ .retire_connection_id = seq },
            .new_token => .new_token,
            .add_address => |value| .{ .add_address = value },
            .reach_address => |value| .{ .reach_address = value },
            .remove_address => |value| .{ .remove_address = value },
            .path_abandon => |value| .{ .path_abandon = value },
            .path_status_backup => |value| .{ .path_status = value.path_id },
            .path_status_available => |value| .{ .path_status = value.path_id },
            .path_new_connection_id => |value| .{ .path_new_connection_id = .{
                .path_id = value.path_id, .seq_num = value.cid.seq_num,
            } },
            .path_retire_connection_id => |value| .{ .path_retire_connection_id = value },
            .max_path_id => .max_path_id,
            .paths_blocked => |value| .{ .paths_blocked = value },
            .path_cids_blocked => |value| .{ .path_cids_blocked = value },
            .observed_address => null,
            .ping, .path_challenge, .path_response, .connection_close, .ack_frequency, .immediate_ack => null,
        };
    }
};

/// Tracks which stream data was carried in a sent packet for retransmission on loss.
///
/// An offset and a length, not a copy: the bytes stay in the stream's send
/// buffer and are re-offered from there on loss, which is why a record this
/// small is worth keeping inline in `SentPacket`.
pub const StreamFrameInfo = struct {
    /// Stream the data went on. It is not the packet number space — a
    /// `SentPacket` is in exactly one space, and the stream id alone does not
    /// say which.
    stream_id: u64,
    /// Byte offset within that stream's send space where the frame's data
    /// began.
    offset: u64,
    /// Bytes the frame carried. Re-offering offers these again, so a length
    /// that no longer matches the stream's buffered data is a retransmission
    /// this record cannot satisfy.
    length: u64,
    /// Whether the frame carried the stream's FIN. A packet whose only loss
    /// was the FIN is re-offered as a FIN-only frame, which is why this is
    /// tracked separately from the byte range.
    fin: bool,
};

/// Metadata stored for each sent packet.
///
/// A `SentPacket` handed to `SentPacketTracker.onPacketSent` is a copy: the
/// tracker takes one into its pool and the caller's value is theirs again. It
/// owns no memory and borrows none, so it may be built on the stack and
/// passed by value — which is what the packet packer does.
///
/// The two arrays are fixed-size slots, not slices: entries past the matching
/// count are `undefined` and must never be read. Read them through
/// `getStreamFrames` and `getControlFrames`, which bound by the count.
pub const SentPacket = struct {
    /// Packet number within `enc_level`'s space. The tracker's map key, so two
    /// packets with the same number in different spaces are tracked apart.
    pn: u64,
    /// The instant the packet was handed to the sender, on the connection's
    /// clock. Loss detection compares it against `now`, and the PTO is
    /// measured from it, so it must come from the same clock as every later
    /// `now` the connection passes.
    time_sent: i64,
    /// Bytes on the wire, header and AEAD tag included. This is what is
    /// charged to and credited from `bytes_in_flight`, so it is the whole
    /// packet and not the payload length.
    size: u64,
    /// Whether the packet carries a frame that demands an acknowledgement.
    /// Only these advance `ack_eliciting_in_flight` and only these are timed
    /// out by the PTO; a packet of pure ACKs is still tracked but does not
    /// hold the PTO open.
    ack_eliciting: bool,
    /// Whether the packet counts against the congestion window. The packer
    /// sets this equal to `ack_eliciting`; a caller that separates them must
    /// know that only an `in_flight` packet's size is added to and removed
    /// from `bytes_in_flight`.
    in_flight: bool,
    /// Which packet number space this packet belongs to, and which tracker's
    /// map it goes into.
    enc_level: EncLevel,
    /// The largest packet number the ACK frame this packet carried covers,
    /// or null when it carried no ACK. On acknowledgement of this packet the
    /// receiver-side ranges below that number are pruned, so an ACK that
    /// acknowledges nothing by number but carried ranges is still worth
    /// recording.
    largest_acked: ?u64 = null,
    /// Whether the packet was marked ECT(0). Recorded so a CE report can be
    /// charged against what was actually marked.
    ecn_marked: bool = false,

    /// Stream frames carried by this packet (for retransmission on loss).
    /// Only the first `stream_frame_count` entries are valid.
    stream_frames: [MAX_STREAM_FRAMES_PER_PACKET]StreamFrameInfo = undefined,
    /// How many `stream_frames` entries are live, at most
    /// `MAX_STREAM_FRAMES_PER_PACKET`.
    stream_frame_count: u8 = 0,

    /// Whether this packet contains CRYPTO frame data (for retransmission on loss).
    has_crypto_data: bool = false,

    /// Whether this packet contains HANDSHAKE_DONE (for retransmission on loss).
    has_handshake_done: bool = false,

    /// Whether this packet contains DATAGRAM frames (for stats tracking on loss).
    /// Datagram bytes are not retransmitted, so this only feeds the loss
    /// statistics; the packet's size still counts against the window.
    has_datagram: bool = false,

    /// Control frames to repeat if this packet is lost. Only the first
    /// `control_frame_count` entries are valid.
    control_frames: [MAX_CONTROL_FRAMES_PER_PACKET]SentControlFrame = undefined,
    /// How many `control_frames` entries are live, at most
    /// `MAX_CONTROL_FRAMES_PER_PACKET`.
    control_frame_count: u8 = 0,

    /// The recorded control frames, bounded by `control_frame_count`. The
    /// slice points into this struct and is invalidated by anything that
    /// moves the struct, so a caller holding one across a tracker call must
    /// re-take it.
    pub fn getControlFrames(self: *const SentPacket) []const SentControlFrame {
        return self.control_frames[0..self.control_frame_count];
    }

    /// Record a stream frame carried by this packet.
    ///
    /// A thirteenth frame is dropped silently rather than growing the packet
    /// or reporting an error: the packet's inline capacity is the bound, and
    /// a frame it cannot hold must not go on the wire expecting a
    /// retransmission nothing will make.
    pub fn addStreamFrame(self: *SentPacket, info: StreamFrameInfo) void {
        if (self.stream_frame_count < MAX_STREAM_FRAMES_PER_PACKET) {
            self.stream_frames[self.stream_frame_count] = info;
            self.stream_frame_count += 1;
        }
    }

    /// Get the recorded stream frames.
    ///
    /// Bounded by `stream_frame_count`; the entries past it are `undefined`
    /// and are not returned. Same aliasing as `getControlFrames`.
    pub fn getStreamFrames(self: *const SentPacket) []const StreamFrameInfo {
        return self.stream_frames[0..self.stream_frame_count];
    }
};

/// Heap-backed list of SentPackets for ACK results.
///
/// Bulk benchmark rows can acknowledge or declare lost thousands of packets in
/// a single ACK/loss pass after ACK compression or loss bursts. A fixed small
/// result buffer silently dropped the excess packets, which left
/// bytes_in_flight and stream ack_offset accounting stale even though packets
/// had been removed from the sent-packet map.
///
/// The list owns its array and borrows every packet in it: the pointers stay
/// the caller's responsibility, and `deinit` releases the array without
/// touching them.
pub const SentPacketList = struct {
    /// Owned by the list. Empty and unallocated until the first `append`.
    items: std.ArrayListUnmanaged(*SentPacket) = .empty,

    /// Releases the array. Does not destroy the packets it pointed at — that
    /// is the tracker's pool, reached through `AckResult.reset`.
    pub fn deinit(self: *SentPacketList, allocator: Allocator) void {
        self.items.deinit(allocator);
    }

    /// Empties the list while keeping its capacity, so the next `append`
    /// does not allocate again. The packets are not returned to their pool.
    pub fn clearRetainingCapacity(self: *SentPacketList) void {
        self.items.clearRetainingCapacity();
    }

    /// Adds one packet. `error.OutOfMemory` leaves the list exactly as it
    /// was, so the caller still owns every packet it had already appended.
    pub fn append(self: *SentPacketList, allocator: Allocator, item: *SentPacket) !void {
        try self.items.append(allocator, item);
    }

    /// Reserve `additional_count` slots. Allocation failure preserves entries;
    /// success may reallocate and invalidate views into the list.
    pub fn ensureUnusedCapacity(
        self: *SentPacketList,
        allocator: Allocator,
        additional_count: usize,
    ) !void {
        try self.items.ensureUnusedCapacity(allocator, additional_count);
    }

    /// Append without allocation. Requires unused capacity reserved beforehand.
    /// This precondition is asserted only in safety-checked builds.
    pub fn appendAssumeCapacity(self: *SentPacketList, item: *SentPacket) void {
        self.items.appendAssumeCapacity(item);
    }

    /// The packets, in the order they were appended — acknowledged ones in
    /// map order, not by packet number. Borrows the list until capacity changes,
    /// entries are overwritten/cleared, or the list is released.
    pub fn constSlice(self: *const SentPacketList) []const *SentPacket {
        return self.items.items;
    }

    /// How many packets the list holds.
    pub fn count(self: *const SentPacketList) usize {
        return self.items.items.len;
    }
};

/// Result of processing an ACK frame.
/// The packets an ACK or a loss pass took out of a tracker. They belong to
/// that tracker's pool until `release`, which the caller runs once done.
///
/// This is a lease, not a copy: the packets named in `acked` and `lost` have
/// already been removed from the tracker's map and are owned by whoever
/// holds this value until `reset` or `release` hands them back. The caller
/// must not read them after that, and must not treat the result as valid
/// across a second ACK or loss pass — every entry point here begins by
/// resetting it, which is what makes one result reusable for the life of a
/// connection. One at a time: two results cannot both hold packets from the
/// same tracker.
pub const AckResult = struct {
    /// Packets the peer acknowledged. Their stream frames and control frames
    /// are the caller's to retire: the data is delivered and the credit
    /// frames are moot, while a RESET_STREAM record may still have work.
    acked: SentPacketList = .{},
    /// Packets declared lost, which RFC 9002 §7 says to retransmit. A packet
    /// can appear here only, never in both lists, because it leaves the map
    /// once.
    lost: SentPacketList = .{},
    /// Whether the lost packets' send times spanned more than the persistent
    /// congestion threshold (RFC 9002 §7.6.2), which is the connection's
    /// signal to cut its window to the minimum. Set only by a loss pass that
    /// found at least one lost ack-eliciting packet.
    persistent_congestion: bool = false,
    /// The tracker whose pool the listed packets came from, set by every call
    /// that fills this result and cleared by `reset`. It is what lets `reset`
    /// return the packets without the caller naming a tracker; while it is
    /// null the lists are treated as holding nothing.
    owner: ?*SentPacketTracker = null,

    /// `reset`, then releases both arrays. Does not free the allocator.
    /// Running it on a result that still holds packets returns them first,
    /// so it is safe on a result a caller abandoned mid-pass; running it
    /// twice is a double free.
    pub fn deinit(self: *AckResult, allocator: Allocator) void {
        self.reset();
        self.acked.deinit(allocator);
        self.lost.deinit(allocator);
    }

    /// Return the packets to their tracker and empty the lists.
    ///
    /// Destroys each packet back into the owning tracker's pool, so a caller
    /// holding a `*SentPacket` from `acked` or `lost` is left with a freed
    /// pointer. Idempotent: a second call finds `owner` null and only clears
    /// what is already empty. Keeping the arrays' capacity means the next
    /// pass over a typical ACK does not allocate.
    pub fn reset(self: *AckResult) void {
        if (self.owner) |t| {
            for (self.acked.constSlice()) |pkt| t.pool.destroy(pkt);
            for (self.lost.constSlice()) |pkt| t.pool.destroy(pkt);
            t.live -= self.acked.count() + self.lost.count();
        }
        self.owner = null;
        self.acked.clearRetainingCapacity();
        self.lost.clearRetainingCapacity();
        self.persistent_congestion = false;
    }

    /// `reset`, keeping room for a typical ACK and freeing what a burst grew.
    ///
    /// The caller runs this once it is done with a result and before the next
    /// ACK or loss pass takes it again. Capacity above sixty-four entries is
    /// released, so a result that once carried a burst does not hold that
    /// memory for the life of the connection. In runtime-safety builds the
    /// call also checks the tracker's own accounting and panics if packets
    /// are outstanding — a caller that skipped a `reset` trips it here
    /// rather than corrupting the pool silently.
    pub fn release(self: *AckResult, allocator: Allocator) void {
        const owner = self.owner;
        self.reset();
        // Callers release before the next result is taken: nothing else holds any.
        if (std.debug.runtime_safety) if (owner) |t| {
            if (t.live != t.sent_packets.count()) std.debug.panic("{d} SentPackets outstanding", .{t.live - t.sent_packets.count()});
        };
        const keep = 64;
        inline for (.{ &self.acked, &self.lost }) |list| {
            if (list.items.capacity > keep) {
                list.deinit(allocator);
                list.* = .{};
            }
        }
    }
};

/// Tracks sent packets and handles loss detection for a single packet number space.
///
/// One of these per `EncLevel`, owned by `PacketHandler`. It retains the
/// allocator it was given and owns every `SentPacket` it hands out: a packet
/// moves between the tracker's map and an `AckResult` and is destroyed back
/// into `pool` by the result's `reset`. It borrows nothing and reads no
/// clock — `now` arrives on the calls that need it — so a copy of the struct
/// is a second tracker over the same allocator, not a second view of one.
pub const SentPacketTracker = struct {
    /// Retained at `init` for the map and the pool, and used again by
    /// `deinit`. Every packet in `sent_packets` and in any `AckResult` this
    /// tracker owns came from it.
    allocator: Allocator,
    /// Dense array-backed map: no tombstones on removal, so iterator() is always
    /// O(count) not O(capacity). Critical for detectLostPackets() which iterates
    /// on every ACK — with AutoHashMap, tombstone bloat after thousands of
    /// insert/remove cycles caused progressive latency degradation.
    /// Values point into `pool`: removal moves a pointer, not a 568-byte record.
    ///
    /// Keyed by packet number, so it holds at most one entry per packet in
    /// this space. A packet leaves it when it is acknowledged or declared
    /// lost, and never returns.
    sent_packets: std.AutoArrayHashMapUnmanaged(u64, *SentPacket),
    /// Where the packets are allocated. Owned by the tracker; `deinit`
    /// releases it, and `clear` deliberately keeps it.
    pool: std.heap.MemoryPool(SentPacket) = .empty,
    /// Packets taken from `pool` and not yet returned, in the map or a result.
    ///
    /// The pool's own accounting would give the same number, but a result
    /// still holding packets is invisible to the pool, and `AckResult.release`
    /// compares the two to catch a result the caller forgot to reset.
    live: usize = 0,
    /// Highest packet number ever handed to `onPacketSent` here, whether or
    /// not it is still in the map. Null before anything is sent, and it never
    /// falls, so a peer cannot make it go backwards.
    largest_sent: ?u64 = null,
    /// Highest packet number the peer has acknowledged in this space. Null
    /// until the first ACK, and never decreases — it is the anchor both loss
    /// tests are measured from, so a stale ACK that names a smaller number
    /// cannot trigger a spurious loss.
    largest_acked: ?u64 = null,
    /// When the earliest un-lost packet's loss timer expires, on the
    /// connection's clock, or null when nothing is pending. A loss timer
    /// takes priority over the PTO for the whole space: while it is set,
    /// `PacketHandler.getPtoSpace` skips that space.
    loss_time: ?i64 = null,
    /// Ack-eliciting packets sent and not yet acknowledged or declared
    /// lost. This, not `sent_packets.count()`, is what the PTO arms on: a
    /// packet of pure ACKs is tracked and does not hold the timer open.
    ack_eliciting_in_flight: u32 = 0,
    /// Time of the most recent ack-eliciting packet sent in this space.
    /// Used as PTO baseline when ack_eliciting_in_flight drops to 0 during handshake.
    ///
    /// Null until one is sent. Survives the packet leaving the map, which is
    /// what lets the PTO fall back to it when `largest_sent` names a packet
    /// loss detection has already taken.
    last_ack_eliciting_sent_time: ?i64 = null,
    /// Per-space PTO count (exponential backoff). Reset when ACK is received
    /// for this space. Separate from other spaces to allow independent backoff.
    ///
    /// Shifts the PTO duration left by this many bits, capped at thirty, so
    /// a space that never acknowledges saturates rather than overflowing.
    pto_count: u32 = 0,

    /// An empty tracker with an allocated-nothing map and pool. Nothing is
    /// owed by a tracker that never sent, and `deinit` is safe whether or
    /// not it grew.
    pub fn init(allocator: Allocator) SentPacketTracker {
        return .{
            .allocator = allocator,
            .sent_packets = .{},
        };
    }

    /// Releases the map and every packet still in the pool. Does not free the
    /// allocator. Packets an `AckResult` is still holding are destroyed by
    /// that result, not here, so calling this while one is outstanding leaves
    /// `live` packets pointing at freed memory — reset the results first.
    pub fn deinit(self: *SentPacketTracker) void {
        self.sent_packets.deinit(self.allocator);
        self.pool.deinit(self.allocator);
    }

    /// Forget every packet, keeping the pool: an AckResult may still hold some.
    ///
    /// Every field except `live` returns to its value from `init`, and
    /// `live` drops only by what the map held — so packets a result still
    /// owns stay counted, and `AckResult.release` still balances. That is the
    /// whole reason this keeps the pool instead of freeing it: a result
    /// outliving this call would otherwise destroy into a released pool.
    pub fn clear(self: *SentPacketTracker) void {
        for (self.sent_packets.values()) |pkt| self.pool.destroy(pkt);
        const live = self.live - self.sent_packets.count();
        self.sent_packets.clearAndFree(self.allocator);
        const allocator = self.allocator;
        const pool = self.pool;
        self.* = .{ .allocator = allocator, .sent_packets = .{}, .pool = pool, .live = live };
    }

    /// Records a sent packet: copies it into the pool and keys it by packet
    /// number. The caller's `pkt` is theirs again; the copy in the pool is
    /// the tracker's until an ACK or a loss pass takes it.
    ///
    /// `error.OutOfMemory` changes nothing. The pool copy and the map entry
    /// are the only allocations, and every counter moves after both of them
    /// succeed, so a space is never left counting a packet it does not hold
    /// and a caller whose send was refused may send the same number again.
    ///
    /// `pkt.pn` must be a number this tracker is not already holding. A
    /// packet number is spent when it is handed out and never reused, so a
    /// repeat is a caller error: it trips an assertion here, rather than
    /// replacing the earlier packet and stranding the allocation behind it.
    pub fn onPacketSent(self: *SentPacketTracker, pkt: SentPacket) !void {
        assert(!self.sent_packets.contains(pkt.pn));
        const p = try self.pool.create(self.allocator);
        errdefer self.pool.destroy(p);
        p.* = pkt;
        try self.sent_packets.put(self.allocator, pkt.pn, p);

        self.live += 1;
        if (self.largest_sent == null or pkt.pn > self.largest_sent.?) {
            self.largest_sent = pkt.pn;
        }
        if (pkt.ack_eliciting) {
            self.ack_eliciting_in_flight += 1;
            self.last_ack_eliciting_sent_time = pkt.time_sent;
        }
    }

    /// Takes out of the tracker every packet an ACK covers, then runs loss
    /// detection, and reports both through `result`.
    ///
    /// `largest_ack` with `first_ack_range` covering `[largest_ack -
    /// first_ack_range, largest_ack]`, plus `ack_ranges` for the gaps; the
    /// whole span is matched against the packets still tracked rather than
    /// walked number by number, so an ACK compressed over hundreds of
    /// thousands of numbers costs one pass over what is in flight. Only the
    /// packet whose number equals `largest_ack` feeds the RTT sample.
    ///
    /// `result` is reset first and adopted by this tracker, so whatever it
    /// held is returned before this pass starts. The caller must run
    /// `AckResult.release` or `reset` on it before the next ACK.
    ///
    /// `ack_delay_ns` is already decoded from the frame's delay field and
    /// exponent by the caller; `rtt_stats` is borrowed for the call and
    /// updated, not retained. `now` is on the same clock as every
    /// `SentPacket.time_sent`.
    ///
    /// `error.OutOfMemory` changes nothing. What the ACK covers and what the
    /// loss test then takes are counted before a packet moves, and `result`
    /// is given room for exactly those, so a refused pass leaves the map, the
    /// counters, `largest_acked` and the RTT sample as they were and the same
    /// ACK can be run again. The sample is read from the packet the ACK names
    /// while that packet is still in the map, because the loss delay below it
    /// is what the same pass measures against.
    pub fn onAckReceived(
        self: *SentPacketTracker,
        largest_ack: u64,
        ack_delay_ns: i64,
        ack_ranges: []const AckRange,
        first_ack_range: u64,
        rtt_stats: *RttStats,
        now: i64,
        result: *AckResult,
    ) !void {
        result.reset();

        const first_range_start = largest_ack -| first_ack_range;
        const largest_acked = @max(self.largest_acked orelse 0, largest_ack);
        var acked_count: usize = 0;
        for (self.sent_packets.values()) |pkt| {
            if (ackCovers(pkt.pn, first_range_start, largest_ack, ack_ranges)) acked_count += 1;
        }
        // Noq updates the ACK watermark, then stops if no recovery packet was
        // newly acknowledged (connection/mod.rs:2960,2993-2995). Off-path PNs
        // are valid ACK targets but cannot trigger on-path loss or recovery.
        if (acked_count == 0) {
            self.largest_acked = largest_acked;
            result.owner = self;
            return;
        }
        var next_rtt = rtt_stats.*;
        if (self.sent_packets.get(largest_ack)) |pkt| {
            next_rtt.updateRtt(now - pkt.time_sent, ack_delay_ns, true);
        }
        const lost_send_time = now - next_rtt.lossDelay();

        var lost_count: usize = 0;
        for (self.sent_packets.values()) |pkt| {
            if (!ackCovers(pkt.pn, first_range_start, largest_ack, ack_ranges) and
                isLost(pkt, largest_acked, lost_send_time))
            {
                lost_count += 1;
            }
        }
        try result.acked.ensureUnusedCapacity(self.allocator, acked_count);
        try result.lost.ensureUnusedCapacity(self.allocator, lost_count);
        result.owner = self;

        self.largest_acked = largest_acked;
        rtt_stats.* = next_rtt;

        var i: usize = 0;
        while (i < self.sent_packets.count()) {
            const pkt = self.sent_packets.values()[i];
            if (!ackCovers(pkt.pn, first_range_start, largest_ack, ack_ranges)) {
                i += 1;
                continue;
            }
            result.acked.appendAssumeCapacity(pkt);
            if (pkt.ack_eliciting) self.ack_eliciting_in_flight -|= 1;
            // A swap removal leaves the last entry in the hole, so the next
            // packet to read is the one that took this one's place.
            self.sent_packets.swapRemoveAt(i);
        }

        self.applyLosses(largest_acked, &next_rtt, now, result);
    }

    /// Declares lost every packet in the map that RFC 9002 §6.1.1 covers:
    /// sent more than one loss delay before `now`, or numbered three or more
    /// below `largest_acked`. Recomputes `loss_time` from what survives, and
    /// sets `result.persistent_congestion` when the lost ack-eliciting
    /// packets span more than the persistent-congestion threshold.
    ///
    /// `result.owner` must be null or this tracker; it is set here, so a
    /// caller may pass a fresh result. `rtt_stats` is borrowed.
    ///
    /// `error.OutOfMemory` changes nothing. `result.lost` is given room for
    /// exactly the packets this pass declares lost, before the first of them
    /// leaves the map, so a refused pass leaves the space, its timer and the
    /// result as they were and this call can be run again. A packet is never
    /// in the map and in the result at once, so `AckResult.reset` is always
    /// safe against this tracker.
    fn detectLostPackets(self: *SentPacketTracker, rtt_stats: *RttStats, now: i64, result: *AckResult) !void {
        assert(result.owner == null or result.owner == self);
        const largest_acked = self.largest_acked orelse {
            result.owner = self;
            return;
        };
        try result.lost.ensureUnusedCapacity(
            self.allocator,
            self.countLosses(largest_acked, now - rtt_stats.lossDelay()),
        );
        self.applyLosses(largest_acked, rtt_stats, now, result);
        result.owner = self;
    }

    /// How many packets a loss pass under these thresholds would declare
    /// lost, so the caller can size the result before moving any of them.
    fn countLosses(self: *const SentPacketTracker, largest_acked: u64, lost_send_time: i64) usize {
        var lost: usize = 0;
        for (self.sent_packets.values()) |pkt| {
            if (isLost(pkt, largest_acked, lost_send_time)) lost += 1;
        }
        return lost;
    }

    /// Commits a loss pass: every packet it covers leaves the map for
    /// `result.lost` and stops holding the PTO open, `loss_time` becomes the
    /// earliest timer of what survives, and the span the lost ack-eliciting
    /// packets cover is compared against the persistent-congestion
    /// threshold.
    ///
    /// `result.lost` must already hold `countLosses` entries of room under
    /// these thresholds. This allocates nothing and cannot fail, so no packet
    /// is ever left named in one place and held in the other.
    fn applyLosses(
        self: *SentPacketTracker,
        largest_acked: u64,
        rtt_stats: *const RttStats,
        now: i64,
        result: *AckResult,
    ) void {
        const loss_delay = rtt_stats.lossDelay();
        const lost_send_time = now - loss_delay;
        var loss_time: ?i64 = null;
        // Span of the lost ack-eliciting packets (RFC 9002 §7.6.2).
        var earliest_lost_time: ?i64 = null;
        var latest_lost_time: ?i64 = null;

        var i: usize = 0;
        while (i < self.sent_packets.count()) {
            const pkt = self.sent_packets.values()[i];
            // Above `largest_acked` the peer has said nothing: not lost, and
            // no timer armed until an ACK or the loss delay covers it.
            if (pkt.pn > largest_acked) {
                i += 1;
                continue;
            }
            if (!isLost(pkt, largest_acked, lost_send_time)) {
                const loss_time_for_pkt = pkt.time_sent + loss_delay;
                if (loss_time == null or loss_time_for_pkt < loss_time.?) loss_time = loss_time_for_pkt;
                i += 1;
                continue;
            }

            result.lost.appendAssumeCapacity(pkt);
            if (pkt.ack_eliciting) {
                self.ack_eliciting_in_flight -|= 1;
                if (earliest_lost_time == null or pkt.time_sent < earliest_lost_time.?) {
                    earliest_lost_time = pkt.time_sent;
                }
                if (latest_lost_time == null or pkt.time_sent > latest_lost_time.?) {
                    latest_lost_time = pkt.time_sent;
                }
            }
            self.sent_packets.swapRemoveAt(i);
        }

        self.loss_time = loss_time;
        if (earliest_lost_time) |earliest| {
            const span = latest_lost_time.? - earliest;
            if (span > rtt_stats.persistentCongestionThreshold()) result.persistent_congestion = true;
        }
    }

    /// Whether an ACK naming `largest_ack` over `[first_range_start,
    /// largest_ack]` and `ack_ranges` covers `pn`.
    fn ackCovers(pn: u64, first_range_start: u64, largest_ack: u64, ack_ranges: []const AckRange) bool {
        if (pn >= first_range_start and pn <= largest_ack) return true;
        for (ack_ranges) |range| {
            if (pn >= range.start and pn <= range.end) return true;
        }
        return false;
    }

    /// Whether RFC 9002 §6.1.1 declares this packet lost at `now`: sent
    /// more than one loss delay ago, or numbered `PACKET_THRESHOLD` or more
    /// below what the peer has acknowledged.
    fn isLost(pkt: *const SentPacket, largest_acked: u64, lost_send_time: i64) bool {
        if (pkt.pn > largest_acked) return false;
        if (pkt.time_sent <= lost_send_time) return true;
        return largest_acked >= PACKET_THRESHOLD and pkt.pn <= largest_acked - PACKET_THRESHOLD;
    }
};

/// Received-packet ranges kept per space; the oldest go first. An ACK frame
/// carries at most `MAX_ACK_RANGES` + 1 of them anyway.
///
/// This bounds what the set between them holds, not what an ACK encodes: it
/// is the count at which the tracker prunes its own history, while
/// `getAckFrame` caps the encoded ranges at `frame_mod.MAX_ACK_RANGES`.
/// Pruning is silent, and a packet number below the pruned line is then
/// answered as a duplicate — a peer that skips packet numbers pays for its
/// own ACK with the ability to be told it already sent something.
pub const MAX_RECEIVED_RANGES: usize = 64;

/// Tracks received packets for generating ACK frames.
///
/// One of these per `EncLevel`, owned by `PacketHandler`. It retains the
/// allocator and owns the `RangeSet` behind `received`; `deinit` releases
/// the set and not the allocator. It reads no clock of its own — `now`
/// arrives on `onPacketReceived` and the `getAckFrame` pair — so a
/// simulation drives it by the instants it passes in.
pub const ReceivedPacketTracker = struct {
    /// Retained at `init` for the range set's array. Never used for anything
    /// else, so the tracker allocates only when a range is added.
    allocator: Allocator,
    /// Which packet numbers have arrived, descending and merged. This is
    /// what an ACK frame is built from, and it is bounded by
    /// `MAX_RECEIVED_RANGES`: `onPacketReceived` prunes the oldest ranges
    /// once that is exceeded.
    received: RangeSet,
    /// Highest packet number seen, and the anchor every ACK frame reports as
    /// `largest_ack`. Null until the first packet; a packet below it is a
    /// reorder, not a new high, and does not move it.
    largest_received: ?u64 = null,
    /// When `largest_received` was set, on the caller's clock. The ACK delay
    /// a frame encodes is measured from here, so a second packet with a
    /// higher number moves both and every delay is measured from the newest.
    largest_received_time: i64 = 0,
    /// Ack-eliciting packets received since the last ACK was handed out.
    /// Zeroed by `getAckFrame`, so a caller that asks for an ACK frame and
    /// then drops it has spent the credit it was counting.
    ack_eliciting_since_last_ack: u32 = 0,
    /// An ACK is owed now, whatever the threshold and the alarm say. Set by
    /// reaching `ack_eliciting_threshold`, by a reorder past
    /// `reordering_threshold`, and by `triggerImmediateAck`; cleared only by
    /// handing out an ACK frame.
    ack_queued: bool = false,
    /// When the delayed ACK is due, on the caller's clock, or null when none
    /// is armed. Set when an ack-eliciting packet arrives without reaching
    /// the threshold, and cleared by `ack_queued` taking priority or by an
    /// ACK being handed out. A `getAckFrame` before this instant returns
    /// null.
    ack_alarm: ?i64 = null,
    /// Packets received with each ECN codepoint, cumulative for the life of
    /// the space and never reset — RFC 9000 §13.4.2 has ACK_ECN report
    /// connection totals, so a later frame restates what the earlier ones
    /// said rather than the delta since them. These are the counts an
    /// ACK_ECN reports; a zero in all three makes the tracker emit a plain
    /// ACK instead, because §13.4.2 reserves ACK_ECN for a path where
    /// marking is in use.
    ecn_ect0: u64 = 0,
    /// Packets received marked ECT(1). This stack never sends ECT(1), so a
    /// non-zero value here is the peer's doing and is reported as such.
    ecn_ect1: u64 = 0,
    /// Packets received that the network marked CE. The peer is expected to
    /// report at most as many as it marked, and `ecn.EcnValidator` is what
    /// turns a report that exceeds that into a failed path.
    ecn_ce: u64 = 0,
    /// Highest PN that was pruned — any PN at or below this is a duplicate
    ///
    /// Null until the first prune, and it only rises. It is what lets
    /// `isDuplicate` keep answering for numbers the set has forgotten.
    largest_pruned: ?u64 = null,

    // draft-ietf-quic-ack-frequency: configurable ACK generation parameters
    /// Ack-eliciting packets after which an ACK is due immediately. Two from
    /// `init`; an ACK_FREQUENCY frame may raise or lower it within one to
    /// 256.
    ack_eliciting_threshold: u32 = ACK_ELICITING_THRESHOLD,
    /// Longest the tracker will sit on an ACK after the first
    /// ack-eliciting packet, in nanoseconds on the caller's clock. 25 ms from
    /// `init`; ACK_FREQUENCY replaces it, capped at the signed duration limit.
    max_ack_delay_ns: i64 = DEFAULT_MAX_ACK_DELAY,
    /// How far below `largest_received` a packet may arrive and still force
    /// an immediate ACK. One from `init`; zero disables reorder-triggered
    /// ACKs entirely, so a reordering peer stops costing an ACK each.
    reordering_threshold: u64 = 1, // 0 = no reorder-triggered ACKs
    /// Highest received ACK_FREQUENCY sequence number, plus one. Zero from
    /// `init` means "none applied yet". Sequence numbers are QUIC varints;
    /// equal or older sequence numbers do not apply a second time.
    ack_frequency_seq: u64 = 0,

    /// A tracker that has seen no packets, holds no ranges and arms no
    /// timer. The allocator is retained immediately; one `deinit` is owed
    /// whether or not any packet arrives.
    pub fn init(allocator: Allocator) ReceivedPacketTracker {
        return .{
            .allocator = allocator,
            .received = RangeSet.init(allocator),
        };
    }

    /// Releases the range set. Does not free the allocator. The tracker is
    /// unusable afterwards, and a second call frees the same bytes twice.
    pub fn deinit(self: *ReceivedPacketTracker) void {
        self.received.deinit();
    }

    /// Records one received packet: adds `pn` to the ranges, updates the high
    /// water mark and the ECN counters, and decides whether an ACK is now
    /// due. `ecn` is the two-bit codepoint from the packet's header.
    ///
    /// A `pn` already in the ranges is ignored outright — no counter moves
    /// and no ACK is scheduled — so a retransmission is free.
    ///
    /// `error.OutOfMemory` comes from the range insertion, which runs before
    /// anything else: on that path the tracker is exactly as it was and the
    /// packet is simply not recorded, so nothing can be acknowledged for it
    /// later and the peer must send it again.
    ///
    /// Adding the sixty-fifth range prunes the oldest ones on this same call,
    /// which is what bounds the memory a peer that skips packet numbers can
    /// make this tracker hold.
    /// Delayed deadlines beyond the signed clock range saturate at `maxInt(i64)`.
    pub fn onPacketReceived(self: *ReceivedPacketTracker, pn: u64, ack_eliciting: bool, now: i64, ecn: u2) !void {
        if (self.received.contains(pn)) return;
        try self.received.add(pn);
        // A peer skipping every other PN would otherwise grow this without
        // bound. Packets in the gaps we forget read as duplicates from here on.
        const tracked = self.received.getRanges();
        if (tracked.len > MAX_RECEIVED_RANGES) {
            self.pruneAckedRanges(tracked[MAX_RECEIVED_RANGES - 1].start);
        }

        if (self.largest_received == null or pn > self.largest_received.?) {
            self.largest_received = pn;
            self.largest_received_time = now;
        }

        // Increment ECN counters (RFC 9000 §13.4.2)
        switch (ecn) {
            0b10 => self.ecn_ect0 += 1, // ECT(0)
            0b01 => self.ecn_ect1 += 1, // ECT(1)
            0b11 => self.ecn_ce += 1, // CE
            0b00 => {}, // Not-ECT
        }

        if (ack_eliciting) {
            self.ack_eliciting_since_last_ack += 1;

            // Reordering-based immediate ACK (draft-ietf-quic-ack-frequency)
            if (self.largest_received != null and pn < self.largest_received.?) {
                if (self.reordering_threshold > 0) {
                    const gap = self.largest_received.? - pn;
                    if (gap >= self.reordering_threshold) {
                        self.ack_queued = true;
                        self.ack_alarm = null;
                    }
                }
                // If reordering_threshold == 0, don't trigger immediate ACK on reorder
            } else if (self.ack_eliciting_since_last_ack >= self.ack_eliciting_threshold) {
                self.ack_queued = true;
                self.ack_alarm = null;
            } else {
                if (self.ack_alarm == null) {
                    self.ack_alarm = now +| self.max_ack_delay_ns;
                }
            }
        }
    }

    /// Apply ACK_FREQUENCY frame parameters (draft-ietf-quic-ack-frequency).
    /// Ignores frames with sequence numbers not greater than the last applied.
    ///
    /// Returns whether the frame was applied. Equal or older sequence numbers
    /// return false without changing any state. `seq` must fit a QUIC varint.
    ///
    /// `threshold` is clamped to 1..256; one requests an ACK every packet.
    /// `max_delay_us` converts to nanoseconds and saturates at `maxInt(i64)`;
    /// arming a delayed ACK also saturates at that clock boundary.
    /// `reorder_threshold` is taken as given; zero disables reorder-triggered ACKs.
    pub fn applyAckFrequency(self: *ReceivedPacketTracker, seq: u64, threshold: u64, max_delay_us: u64, reorder_threshold: u64) bool {
        std.debug.assert(seq < (@as(u64, 1) << 62));
        if (self.ack_frequency_seq > 0 and seq < self.ack_frequency_seq) return false;
        self.ack_frequency_seq = seq + 1;
        self.ack_eliciting_threshold = @intCast(@max(1, @min(threshold, 256)));
        self.max_ack_delay_ns = @intCast(@min(max_delay_us *| 1000, std.math.maxInt(i64)));
        self.reordering_threshold = reorder_threshold;
        return true;
    }

    /// Force immediate ACK transmission (IMMEDIATE_ACK frame, draft-ietf-quic-ack-frequency).
    ///
    /// Queues an ACK now and cancels the delayed one. Does nothing before
    /// the first packet has been recorded, since there is nothing to
    /// acknowledge.
    pub fn triggerImmediateAck(self: *ReceivedPacketTracker) void {
        if (self.largest_received != null) {
            self.ack_queued = true;
            self.ack_alarm = null;
        }
    }

    /// Whether `pn` has already been seen. True for a number in the ranges
    /// and for any number at or below `largest_pruned`, so pruning does not
    /// make an old packet look new — and a peer that skips packet numbers
    /// can therefore be told its own skips were duplicates.
    pub fn isDuplicate(self: *const ReceivedPacketTracker, pn: u64) bool {
        // Any PN at or below the largest pruned value is a duplicate
        // (we already ACKed it and the peer confirmed receipt).
        if (self.largest_pruned) |lp| {
            if (pn <= lp) return true;
        }
        return self.received.contains(pn);
    }

    /// Prune received ranges below the given packet number (RFC 9000 §13.2.4).
    /// Called when the peer ACKs a packet that contained our ACK for ranges up to this value.
    ///
    /// `below` is exclusive: the range containing it is trimmed to start at
    /// it, and everything lower is forgotten. `largest_pruned` moves to
    /// `below - 1`, or stays put when `below` is zero, and only ever rises —
    /// so `isDuplicate` keeps answering for the forgotten numbers.
    pub fn pruneAckedRanges(self: *ReceivedPacketTracker, below: u64) void {
        self.received.removeBelow(below);
        if (below > 0) {
            const pruned = below - 1;
            if (self.largest_pruned == null or pruned > self.largest_pruned.?) {
                self.largest_pruned = pruned;
            }
        }
    }

    /// Check if there are any unacknowledged ack-eliciting packets.
    /// Used by the packet packer to piggyback ACKs on outgoing data packets.
    ///
    /// The packer's question, not the tracker's alarm: true means an ACK is
    /// owed whether or not its timer has fired, so a packet carrying data
    /// can take one along. It goes false only when an ACK frame is actually
    /// handed out.
    pub fn hasUnackedAckEliciting(self: *const ReceivedPacketTracker) bool {
        return self.ack_eliciting_since_last_ack > 0;
    }

    /// The ACK frame to send now, or null when none is due: no ACK is queued,
    /// no alarm has fired, or nothing has been received at all.
    ///
    /// The frame copies the ranges into its own fixed array, so it borrows
    /// nothing and stays valid after the tracker moves. Handing one out
    /// commits: `ack_queued`, `ack_alarm` and
    /// `ack_eliciting_since_last_ack` are cleared, so a caller that asks and
    /// then discards the frame has spent the ACK.
    ///
    /// Delay is `max(0, (now - largest_received_time) / 1000)` microseconds,
    /// shifted right by `ack_delay_exponent`; the peer multiplies by that power.
    /// The exponent must be in 0..20, the QUIC transport-parameter range.
    pub fn getAckFrame(self: *ReceivedPacketTracker, now: i64, ack_delay_exponent: u64) ?Frame {
        return self.getAckFrameImpl(now, ack_delay_exponent, false);
    }

    /// Generate an ACK frame regardless of threshold/alarm timers.
    /// Used to piggyback ACKs on outgoing data packets (RFC 9000 §13.2.1).
    ///
    /// As `getAckFrame`, and committing in the same way, except that it also
    /// answers when the threshold has not been reached and the alarm has not
    /// fired. It still returns null before the first packet, so "forced"
    /// does not mean "always".
    pub fn getAckFrameForced(self: *ReceivedPacketTracker, now: i64, ack_delay_exponent: u64) ?Frame {
        return self.getAckFrameImpl(now, ack_delay_exponent, true);
    }

    /// The shared body of the two `getAckFrame` entry points; `force` is what
    /// separates them. `ack_delay_exponent` is shifted by at most 63.
    ///
    /// At most `frame_mod.MAX_ACK_RANGES` of the extra ranges fit in the
    /// frame's fixed array and the rest are dropped, so the ACK names the
    /// largest range and the thirty-two most recent gaps; the tracker's own
    /// `received` set is unchanged by the omission and a later frame can
    /// still report what this one could not.
    fn getAckFrameImpl(self: *ReceivedPacketTracker, now: i64, ack_delay_exponent: u64, force: bool) ?Frame {
        if (!force and !self.ack_queued) {
            if (self.ack_alarm) |alarm| {
                if (now < alarm) return null;
            } else {
                return null;
            }
        }

        const largest = self.largest_received orelse return null;
        const recv_ranges = self.received.getRanges();
        if (recv_ranges.len == 0) return null;

        const first_range = recv_ranges[0];
        const first_ack_range = largest - first_range.start;

        const ack_delay_ns = now - self.largest_received_time;
        const ack_delay_us: u64 = @intCast(@max(0, @divTrunc(ack_delay_ns, 1000)));
        const ack_delay_encoded = ack_delay_us >> @intCast(ack_delay_exponent);

        self.ack_queued = false;
        self.ack_alarm = null;
        self.ack_eliciting_since_last_ack = 0;

        // Populate additional ACK ranges from received range set
        var ack_ranges: [MAX_ACK_RANGES]AckRange = undefined;
        var ack_range_count: u8 = 0;
        if (recv_ranges.len > 1) {
            for (recv_ranges[1..]) |r| {
                if (ack_range_count >= MAX_ACK_RANGES) break;
                ack_ranges[ack_range_count] = .{ .start = r.start, .end = r.end };
                ack_range_count += 1;
            }
        }

        // Use ACK_ECN when any ECN counter is non-zero (RFC 9000 §13.4.2)
        if (self.ecn_ect0 > 0 or self.ecn_ect1 > 0 or self.ecn_ce > 0) {
            return Frame{
                .ack_ecn = .{
                    .largest_ack = largest,
                    .ack_delay = ack_delay_encoded,
                    .first_ack_range = first_ack_range,
                    .ack_range_count = ack_range_count,
                    .ack_ranges = ack_ranges,
                    .ecn_ect0 = self.ecn_ect0,
                    .ecn_ect1 = self.ecn_ect1,
                    .ecn_ce = self.ecn_ce,
                },
            };
        }

        return Frame{
            .ack = .{
                .largest_ack = largest,
                .ack_delay = ack_delay_encoded,
                .first_ack_range = first_ack_range,
                .ack_range_count = ack_range_count,
                .ack_ranges = ack_ranges,
            },
        };
    }
};

/// Top-level packet handler that manages all three packet number spaces.
///
/// The whole acknowledgement and loss surface a connection drives, reached
/// through `Connection.pkt_handler`. It retains one allocator, hands it to
/// all six trackers, and owns them: `deinit` releases every one and nothing
/// else. It reads no clock — `now` is an argument on every call that needs
/// one — and draws no entropy of its own; the only randomness is the
/// injected `std.Random` `nextPacketNumber` is given, so a test can pin the
/// packet-number schedule a seed produces.
///
/// Not thread-safe: every field below is unsynchronized mutable state and
/// the handler is meant to be driven from the one thread owning the
/// connection.
pub const PacketHandler = struct {
    /// The allocator handed to all six trackers at `init` and used again by
    /// `deinit`. The handler allocates nothing itself.
    allocator: Allocator,
    /// One sent-packet tracker per packet number space, indexed by
    /// `@intFromEnum(EncLevel)`: 0 initial, 1 handshake, 2 application.
    /// `ack_handler.EncLevel` is the index, so no space can be named that
    /// does not have a tracker.
    sent: [3]SentPacketTracker,
    /// One received-packet tracker per space, indexed the same way. These
    /// build the ACK frames and hold the ECN counters the peer will be told
    /// about.
    recv: [3]ReceivedPacketTracker,
    /// The RTT sample and the PTO and loss delays derived from it. Shared by
    /// all three spaces on purpose: RFC 9002 measures one path. Mutated by
    /// `onAckReceived` from the largest acknowledged packet only.
    rtt_stats: RttStats = .{},
    /// Bytes of ack-eliciting packets sent and not yet acknowledged or
    /// declared lost, summed over all three spaces. This is the figure the
    /// congestion window is compared against, and it is decremented on
    /// acknowledgement, on loss, and by `dropSpace`.
    bytes_in_flight: u64 = 0,
    /// Connection-wide PTO backoff count, zeroed by any ACK in any space.
    /// Each space also keeps its own `SentPacketTracker.pto_count`, which is
    /// what `spacePtoDeadline` actually reads; this one is the connection's
    /// summary and does not drive the timers.
    pto_count: u32 = 0,
    /// Next packet number to hand out per space. A packet number consumed by
    /// `nextPacketNumber` is spent even if no packet is sent, unless the
    /// caller decrements this back — which is what the packet packer does
    /// when it built nothing. Nothing resets it: `dropSpace` drops the
    /// packets but not the numbering.
    next_pn: [3]u64 = .{ 0, 0, 0 },

    /// RFC 9000 21.4: the application space leaves the odd packet number
    /// unsent, so a peer acking what it never received (to inflate our
    /// window) names one of these and is caught. The gap between skips
    /// doubles, as quic-go's does, so the cost fades on long connections.
    /// Which number in the gap goes unsent is drawn from the generator
    /// `nextPacketNumber` is handed: predictability is the bug this defends
    /// against, so the value stays random, but injected: a test can pin the
    /// schedule a given seed produces.
    ///
    /// The packet number that will be skipped next, in the application space
    /// only. Every twenty-four packets at first, doubling each time up to one
    /// per ten thousand, and the two most recent skips are kept so an ACK
    /// naming a stale one is still caught.
    skip_pn: u64 = SKIP_INITIAL_PERIOD,
    /// How far ahead the next skip is scheduled, doubling on every skip and
    /// capped at ten thousand.
    skip_period: u64 = SKIP_INITIAL_PERIOD,
    /// The two most recently skipped packet numbers, newest first, or null
    /// before the first skip. Only the application space skips, so
    /// `acksUnsentPacket` checks them only there.
    skipped_pns: [2]?u64 = .{ null, null },

    /// A handler with three empty spaces, no RTT sample and no packet sent.
    /// The allocator is retained immediately; one `deinit` is owed whether or
    /// not the handler ever grows.
    pub fn init(allocator: Allocator) PacketHandler {
        return .{
            .allocator = allocator,
            .sent = .{
                SentPacketTracker.init(allocator),
                SentPacketTracker.init(allocator),
                SentPacketTracker.init(allocator),
            },
            .recv = .{
                ReceivedPacketTracker.init(allocator),
                ReceivedPacketTracker.init(allocator),
                ReceivedPacketTracker.init(allocator),
            },
        };
    }

    /// Releases all six trackers. Does not free the allocator. An `AckResult`
    /// still holding packets from one of them must be reset first, or its
    /// packets point into a released pool.
    pub fn deinit(self: *PacketHandler) void {
        for (&self.sent) |*s| s.deinit();
        for (&self.recv) |*r| r.deinit();
    }

    /// Take the next packet number in `level`, leaving one unsent in the
    /// application space on the schedule above. `random` is drawn from
    /// only when a packet number is skipped.
    ///
    /// The number is spent whether or not a packet is actually sent, so a
    /// caller that builds nothing must decrement `next_pn[idx]` itself to
    /// give the number back. That rollback undoes only the number returned
    /// here: a skip that happened during this call has already been recorded
    /// in `skipped_pns` and `skip_pn`, and must not be undone with it.
    ///
    /// `random` is the caller's generator, borrowed for the call and never
    /// retained; it is drawn from only on the branches that skip, so two
    /// handlers driven with one generator still produce independent
    /// schedules.
    pub fn nextPacketNumber(self: *PacketHandler, level: EncLevel, random: std.Random) u64 {
        const idx = @intFromEnum(level);
        if (level == .application and self.next_pn[idx] == self.skip_pn) {
            self.skipped_pns = .{ self.skip_pn, self.skipped_pns[0] };
            self.next_pn[idx] += 1;
            self.skip_period = @min(self.skip_period * 2, SKIP_MAX_PERIOD);
            const half = self.skip_period / 2;
            self.skip_pn = self.next_pn[idx] + half + random.int(u64) % half;
        }
        const pn = self.next_pn[idx];
        self.next_pn[idx] += 1;
        return pn;
    }

    /// Whether an ACK claims a packet we never sent: one past the last we
    /// numbered, or one we skipped. RFC 9000 13.1 makes either a
    /// PROTOCOL_VIOLATION.
    ///
    /// A pure check — the caller decides what to do with the answer, and
    /// `Connection` closes the connection on true. Only the application space
    /// checks skipped numbers; other spaces check `largest_ack >= next_pn` alone.
    pub fn acksUnsentPacket(
        self: *const PacketHandler,
        level: EncLevel,
        largest_ack: u64,
        first_ack_range: u64,
        ack_ranges: []const AckRange,
    ) bool {
        if (largest_ack >= self.next_pn[@intFromEnum(level)]) return true;
        if (level != .application) return false;
        for (self.skipped_pns) |maybe| {
            const skipped = maybe orelse continue;
            if (skipped <= largest_ack and skipped >= largest_ack -| first_ack_range) return true;
            for (ack_ranges) |r| {
                if (skipped >= r.start and skipped <= r.end) return true;
            }
        }
        return false;
    }

    /// Return the largest packet number acknowledged by the peer for this level.
    ///
    /// Null until the space has been acknowledged at all. This is what the
    /// packet number encoder measures against when it chooses how many bytes
    /// to spend, so a null makes it encode the full four bytes.
    pub fn getLargestAcked(self: *const PacketHandler, level: EncLevel) ?u64 {
        const idx = @intFromEnum(level);
        return self.sent[idx].largest_acked;
    }

    /// Records a sent packet in the space `pkt.enc_level` names, and charges
    /// its size to `bytes_in_flight` when it was in flight.
    ///
    /// The packet number is the map key, so it must come from
    /// `nextPacketNumber` and must not be reused within its space; the
    /// tracker's assertion is what says so.
    ///
    /// `error.OutOfMemory` changes nothing: the tracker keeps the packet
    /// only if it stored it, and the charge follows that, so `bytes_in_flight`
    /// counts what the space actually holds and the same packet can be sent
    /// again.
    pub fn onPacketSent(self: *PacketHandler, pkt: SentPacket) !void {
        const idx = @intFromEnum(pkt.enc_level);
        try self.sent[idx].onPacketSent(pkt);
        if (pkt.in_flight) {
            self.bytes_in_flight += pkt.size;
        }
    }

    /// Off-path NAT probes consume real path-zero numbers and can be ACKed,
    /// but are not recovery packets on the working path. Retain the sent
    /// watermark; next_pn and skipped_pns already validate their ACKs. Do not
    /// allocate a recovery record, arm PTO, sample RTT or return these bytes
    /// through ACK/loss results to the on-path congestion controller.
    pub fn onOffPathPacketSent(self: *PacketHandler, pn: u64) void {
        const idx = @intFromEnum(EncLevel.application);
        assert(pn < self.next_pn[idx]);
        assert(!self.sent[idx].sent_packets.contains(pn));
        if (self.sent[idx].largest_sent) |largest| assert(pn > largest);
        self.sent[idx].largest_sent = pn;
    }

    /// Records a received packet against `level`, which is the space its
    /// header said, not the one the caller would have guessed. `ecn` is the
    /// two-bit codepoint from that header.
    ///
    /// `error.OutOfMemory` leaves the tracker exactly as it was — nothing is
    /// recorded and no ACK is scheduled — so the packet has to arrive again.
    pub fn onPacketReceived(self: *PacketHandler, level: EncLevel, pn: u64, ack_eliciting: bool, now: i64, ecn: u2) !void {
        const idx = @intFromEnum(level);
        try self.recv[idx].onPacketReceived(pn, ack_eliciting, now, ecn);
    }

    /// Processes an ACK frame in `level`: takes out the acknowledged and lost
    /// packets, updates the RTT, prunes the received ranges the acknowledged
    /// packets' own ACKs made redundant, and clears both PTO counters.
    ///
    /// `ack_delay_encoded` is the wire delay in units of
    /// `2^ack_delay_exponent` microseconds. The delay is capped at the peer's
    /// `rtt_stats.max_ack_delay` before scaling, so even the largest wire value
    /// cannot overflow. That ceiling must be nonnegative.
    /// `ack_ranges` is the gap list; `first_ack_range` the width below `largest_ack`.
    ///
    /// `result` is reset first, so it must be released after the previous
    /// pass. Its `acked` and `lost` packets are owned by it until then, and
    /// `bytes_in_flight` has already been credited back for each.
    ///
    /// `error.OutOfMemory` from the tracker changes nothing, so the pruning
    /// and the credits below never run on a pass that took nothing: every byte
    /// `result` names is credited exactly once, and a retried ACK is safe.
    pub fn onAckReceived(
        self: *PacketHandler,
        level: EncLevel,
        largest_ack: u64,
        ack_delay_encoded: u64,
        ack_delay_exponent: u6,
        ack_ranges: []const AckRange,
        first_ack_range: u64,
        now: i64,
        result: *AckResult,
    ) !void {
        const idx = @intFromEnum(level);

        const max_delay_ns = self.rtt_stats.max_ack_delay;
        std.debug.assert(max_delay_ns >= 0);
        const max_delay_us: u64 = @intCast(@divFloor(max_delay_ns, 1000));
        const max_encoded = max_delay_us >> ack_delay_exponent;
        const ack_delay_ns: i64 = if (ack_delay_encoded > max_encoded)
            max_delay_ns
        else
            @intCast((ack_delay_encoded << ack_delay_exponent) * 1000);

        try self.sent[idx].onAckReceived(
            largest_ack,
            ack_delay_ns,
            ack_ranges,
            first_ack_range,
            &self.rtt_stats,
            now,
            result,
        );
        if (result.acked.count() == 0) return;

        // ACK-of-ACK pruning (RFC 9000 §13.2.4): when an acked packet contained
        // our ACK frame, prune received ranges below that ACK's largest_ack
        var max_ack_of_ack: ?u64 = null;
        for (result.acked.constSlice()) |pkt| {
            if (pkt.in_flight) {
                self.bytes_in_flight -|= pkt.size;
            }
            if (pkt.largest_acked) |la| {
                if (max_ack_of_ack == null or la > max_ack_of_ack.?) {
                    max_ack_of_ack = la;
                }
            }
        }
        if (max_ack_of_ack) |prune_below| {
            self.recv[idx].pruneAckedRanges(prune_below);
        }

        for (result.lost.constSlice()) |pkt| {
            if (pkt.in_flight) {
                self.bytes_in_flight -|= pkt.size;
            }
        }

        self.pto_count = 0;
        self.sent[idx].pto_count = 0;
    }

    /// The ACK frame `level` owes now, or null. Committing, as on the
    /// tracker: an ACK handed out clears that space's queue and alarm, so a
    /// caller that asks and drops the frame has spent it. `now` and the
    /// exponent are this connection's own clock and transport parameter.
    pub fn getAckFrame(self: *PacketHandler, level: EncLevel, now: i64, ack_delay_exponent: u64) ?Frame {
        const idx = @intFromEnum(level);
        return self.recv[idx].getAckFrame(now, ack_delay_exponent);
    }

    /// Generate an ACK frame regardless of threshold/alarm timers.
    /// Used to piggyback ACKs when the packet already carries data.
    ///
    /// Committing in the same way as `getAckFrame`, and the packer's choice
    /// of when: forcing on every congestion-limited poll could build an
    /// ACK-only send loop that never drains `bytes_in_flight`, so this is
    /// used only when the packet being built carries something else.
    pub fn getAckFrameForced(self: *PacketHandler, level: EncLevel, now: i64, ack_delay_exponent: u64) ?Frame {
        const idx = @intFromEnum(level);
        return self.recv[idx].getAckFrameForced(now, ack_delay_exponent);
    }

    /// Check if there are unacked ack-eliciting packets at the given level.
    ///
    /// What the packet packer asks before forcing an ACK onto a data packet.
    /// It says an ACK is owed, not that one is due now.
    pub fn hasUnackedAckEliciting(self: *const PacketHandler, level: EncLevel) bool {
        const idx = @intFromEnum(level);
        return self.recv[idx].hasUnackedAckEliciting();
    }

    /// Compute PTO deadline for a single packet number space.
    /// Returns null if the space should not arm PTO (no data, application space idle).
    /// RFC 9002 §6.2.2.1: handshake spaces arm PTO even with no packets in flight.
    ///
    /// The deadline, on the caller's clock, or null when this space should
    /// not hold a timer. A handshake space with nothing in flight still arms
    /// one, from its last ack-eliciting send time, because RFC 9002 §6.2.2.1
    /// wants the handshake to time out rather than hang; the application space
    /// with nothing outstanding does not.
    ///
    /// `tracker` and `idx` must be the same space: `idx` is the index into
    /// `sent`, and `tracker` is read for that tracker's own counters, so a
    /// mismatched pair computes a deadline from one space's state and treats
    /// it as another's. `tracker` is taken by value and only read, so the
    /// copy costs nothing and nothing it holds is retained.
    ///
    /// The duration is the space's PTO duration shifted left by its own
    /// `pto_count`, capped at thirty bits of shift and at sixty seconds for
    /// the application space or three for the handshake spaces.
    pub fn spacePtoDeadline(self: *const PacketHandler, tracker: SentPacketTracker, idx: usize) ?i64 {
        const is_handshake_space = (idx != @intFromEnum(EncLevel.application));
        if (tracker.ack_eliciting_in_flight == 0) {
            if (!(is_handshake_space and tracker.last_ack_eliciting_sent_time != null)) {
                return null;
            }
        }

        const base_time = if (tracker.ack_eliciting_in_flight > 0) blk: {
            const largest_sent = tracker.largest_sent orelse return null;
            // Packet may have been removed from sent_packets after loss detection.
            // Fall back to last_ack_eliciting_sent_time which is always maintained.
            const sent_pkt = tracker.sent_packets.get(largest_sent) orelse
                break :blk tracker.last_ack_eliciting_sent_time orelse return null;
            break :blk sent_pkt.time_sent;
        } else blk: {
            break :blk tracker.last_ack_eliciting_sent_time.?;
        };

        var pto_duration = if (idx == @intFromEnum(EncLevel.application))
            self.rtt_stats.pto()
        else
            self.rtt_stats.ptoNoAckDelay();

        // Use per-space PTO count for independent backoff per encryption level
        const shift: u6 = @intCast(@min(tracker.pto_count, 30));
        pto_duration = pto_duration << shift;
        const max_pto = if (idx == @intFromEnum(EncLevel.application)) MAX_PTO else MAX_HANDSHAKE_PTO;
        pto_duration = @min(pto_duration, max_pto);

        return base_time + pto_duration;
    }

    /// The earliest instant at which anything should happen on this
    /// connection, on the caller's clock, or null when nothing is pending.
    ///
    /// Loss timers are considered before PTOs and a space's loss timer
    /// replaces its own PTO entirely, matching `getPtoSpace`'s skip: the
    /// two never disagree about which fires first. The caller schedules a
    /// timer for this value and re-asks afterwards; nothing here is armed by
    /// this call.
    pub fn getPtoTimeout(self: *const PacketHandler) ?i64 {
        var earliest: ?i64 = null;

        for (self.sent, 0..) |tracker, idx| {
            if (tracker.loss_time) |lt| {
                if (earliest == null or lt < earliest.?) {
                    earliest = lt;
                }
                continue;
            }

            const timeout = self.spacePtoDeadline(tracker, idx) orelse continue;
            if (earliest == null or timeout < earliest.?) {
                earliest = timeout;
            }
        }

        return earliest;
    }

    /// Check if any loss_time has expired. Returns the enc level if so.
    /// RFC 9002 §6.2.1: loss timers fire before PTO and should run loss
    /// detection without incrementing pto_count.
    ///
    /// The space with the earliest expired loss timer, or null when none has
    /// expired at `now`. A pure read: running the loss detection it points
    /// at is the caller's next step, through `detectLossesForSpace`, and
    /// until then the same space answers again.
    pub fn getExpiredLossTime(self: *PacketHandler, now: i64) ?EncLevel {
        var earliest: ?i64 = null;
        var result: ?EncLevel = null;
        for (self.sent, 0..) |tracker, idx| {
            if (tracker.loss_time) |lt| {
                if (lt <= now and (earliest == null or lt < earliest.?)) {
                    earliest = lt;
                    result = @enumFromInt(idx);
                }
            }
        }
        return result;
    }

    /// Run loss detection for a specific packet number space (called when loss_time fires).
    /// Returns the lost packets for congestion control processing.
    ///
    /// `result` is reset first and filled with the lost packets, whose sizes
    /// are credited back to `bytes_in_flight` before this returns. The space's
    /// `loss_time` is recomputed from what survives, so the caller can ask
    /// `getExpiredLossTime` again for the next one.
    ///
    /// `error.OutOfMemory` from the tracker changes nothing, so the credits
    /// below never run on a pass that declared nothing lost. The space keeps
    /// its armed `loss_time` and the same call can be run again.
    pub fn detectLossesForSpace(self: *PacketHandler, level: EncLevel, now: i64, result: *AckResult) !void {
        const idx = @intFromEnum(level);
        result.reset();
        try self.sent[idx].detectLostPackets(&self.rtt_stats, now, result);
        for (result.lost.constSlice()) |pkt| {
            if (pkt.in_flight) {
                self.bytes_in_flight -|= pkt.size;
            }
        }
    }

    /// Get the encryption level where PTO should fire (the one with earliest timeout).
    ///
    /// The space whose PTO deadline is earliest, or null when no space arms
    /// one. A space with a pending loss timer is skipped, because
    /// `getExpiredLossTime` answers for it first and RFC 9002 §6.2.1 has the
    /// loss timer win. Pure read — the caller still has to send the probe.
    pub fn getPtoSpace(self: *PacketHandler) ?EncLevel {
        var earliest: ?i64 = null;
        var result: ?EncLevel = null;

        for (self.sent, 0..) |tracker, idx| {
            if (tracker.loss_time != null) continue;
            const timeout = self.spacePtoDeadline(tracker, idx) orelse continue;
            if (earliest == null or timeout < earliest.?) {
                earliest = timeout;
                result = @enumFromInt(idx);
            }
        }

        return result;
    }

    /// Discards one packet number space: every packet it was tracking is
    /// dropped and its in-flight bytes credited back, and its received
    /// tracker is released and rebuilt empty.
    ///
    /// What survives is deliberate — the RTT sample, `bytes_in_flight` for
    /// the other spaces, and `next_pn` for this one, which keeps counting so
    /// the peer cannot tell the space was reset by a replayed packet number.
    /// What goes includes every loss timer and PTO state for the space, and
    /// the ECN counts it would have reported.
    ///
    /// An `AckResult` still holding packets from this space must be reset
    /// first: `clear` keeps the pool alive for exactly that case, but a
    /// result released afterwards would destroy into a pool whose map no
    /// longer names them.
    pub fn dropSpace(self: *PacketHandler, level: EncLevel) void {
        const idx = @intFromEnum(level);

        var it = self.sent[idx].sent_packets.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.*.in_flight) {
                self.bytes_in_flight -|= entry.value_ptr.*.size;
            }
        }

        self.sent[idx].clear();
        self.recv[idx].deinit();
        self.recv[idx] = ReceivedPacketTracker.init(self.allocator);
    }
};

// Tests

test "SentPacketTracker: basic send and ack" {
    var tracker = SentPacketTracker.init(testing.allocator);
    defer tracker.deinit();

    var rtt_stats = RttStats{};
    const now: i64 = 1_000_000_000;

    try tracker.onPacketSent(.{
        .pn = 0,
        .time_sent = now,
        .size = 1200,
        .ack_eliciting = true,
        .in_flight = true,
        .enc_level = .initial,
    });

    try testing.expectEqual(@as(u32, 1), tracker.ack_eliciting_in_flight);

    const ack_time = now + 50_000_000;
    var result: AckResult = .{};
    defer result.deinit(testing.allocator);
    try tracker.onAckReceived(0, 0, &.{}, 0, &rtt_stats, ack_time, &result);

    try testing.expectEqual(@as(usize, 1), result.acked.count());
    try testing.expectEqual(@as(u64, 0), result.acked.constSlice()[0].pn);
    try testing.expectEqual(@as(u32, 0), tracker.ack_eliciting_in_flight);
    try testing.expect(rtt_stats.has_measurement);
}

test "ReceivedPacketTracker: immediate ACK on reorder" {
    var tracker = ReceivedPacketTracker.init(testing.allocator);
    defer tracker.deinit();

    const now: i64 = 1_000_000_000;

    try tracker.onPacketReceived(0, true, now, 0);
    try tracker.onPacketReceived(1, true, now + 1_000_000, 0);

    try testing.expect(tracker.ack_queued);
}

test "SentPacketTracker: large ACK range scans in-flight packets" {
    var tracker = SentPacketTracker.init(testing.allocator);
    defer tracker.deinit();

    var rtt_stats = RttStats{};
    const now: i64 = 1_000_000_000;

    try tracker.onPacketSent(.{
        .pn = 10,
        .time_sent = now,
        .size = 1200,
        .ack_eliciting = true,
        .in_flight = true,
        .enc_level = .application,
    });
    try tracker.onPacketSent(.{
        .pn = 1_000_000,
        .time_sent = now + 1_000,
        .size = 1200,
        .ack_eliciting = true,
        .in_flight = true,
        .enc_level = .application,
    });

    var result: AckResult = .{};
    defer result.deinit(testing.allocator);
    try tracker.onAckReceived(1_000_000, 0, &.{}, 999_990, &rtt_stats, now + 50_000_000, &result);

    try testing.expectEqual(@as(usize, 2), result.acked.count());
    try testing.expectEqual(@as(usize, 0), tracker.sent_packets.count());
    try testing.expectEqual(@as(u32, 0), tracker.ack_eliciting_in_flight);
}

test "PacketHandler: integration" {
    var handler = PacketHandler.init(testing.allocator);
    defer handler.deinit();

    const now: i64 = 1_000_000_000;

    var prng = std.Random.DefaultPrng.init(0x6a697474);
    const random = prng.random();
    const pn = handler.nextPacketNumber(.initial, random);
    try handler.onPacketSent(.{
        .pn = pn,
        .time_sent = now,
        .size = 1200,
        .ack_eliciting = true,
        .in_flight = true,
        .enc_level = .initial,
    });

    try testing.expectEqual(@as(u64, 1200), handler.bytes_in_flight);

    try handler.onPacketReceived(.initial, 0, true, now, 0);

    const ack_time = now + 50_000_000;
    var result: AckResult = .{};
    defer result.deinit(testing.allocator);
    try handler.onAckReceived(.initial, 0, 0, 3, &.{}, 0, ack_time, &result);

    try testing.expectEqual(@as(u64, 0), handler.bytes_in_flight);
}

test "ReceivedPacketTracker: ECN counters and ACK_ECN generation" {
    var tracker = ReceivedPacketTracker.init(testing.allocator);
    defer tracker.deinit();

    const now: i64 = 1_000_000_000;

    // Receive packets with ECN marks
    try tracker.onPacketReceived(0, true, now, 0b10); // ECT(0)
    try tracker.onPacketReceived(1, true, now + 1_000_000, 0b10); // ECT(0)
    try tracker.onPacketReceived(2, true, now + 2_000_000, 0b11); // CE

    try testing.expectEqual(@as(u64, 2), tracker.ecn_ect0);
    try testing.expectEqual(@as(u64, 0), tracker.ecn_ect1);
    try testing.expectEqual(@as(u64, 1), tracker.ecn_ce);

    // getAckFrame should return ACK_ECN when ECN counters are non-zero
    const frame = tracker.getAckFrame(now + 3_000_000, 3);
    try testing.expect(frame != null);
    switch (frame.?) {
        .ack_ecn => |ack_ecn| {
            try testing.expectEqual(@as(u64, 2), ack_ecn.largest_ack);
            try testing.expectEqual(@as(u64, 2), ack_ecn.ecn_ect0);
            try testing.expectEqual(@as(u64, 0), ack_ecn.ecn_ect1);
            try testing.expectEqual(@as(u64, 1), ack_ecn.ecn_ce);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "ReceivedPacketTracker: no ECN returns plain ACK" {
    var tracker = ReceivedPacketTracker.init(testing.allocator);
    defer tracker.deinit();

    const now: i64 = 1_000_000_000;

    // Receive packets without ECN marks
    try tracker.onPacketReceived(0, true, now, 0); // Not-ECT
    try tracker.onPacketReceived(1, true, now + 1_000_000, 0); // Not-ECT

    // getAckFrame should return plain ACK
    const frame = tracker.getAckFrame(now + 2_000_000, 3);
    try testing.expect(frame != null);
    switch (frame.?) {
        .ack => {},
        else => return error.TestUnexpectedResult,
    }
}

test "SentPacket: stream frame tracking" {
    var pkt = SentPacket{
        .pn = 0,
        .time_sent = 0,
        .size = 1200,
        .ack_eliciting = true,
        .in_flight = true,
        .enc_level = .application,
    };

    pkt.addStreamFrame(.{ .stream_id = 0, .offset = 0, .length = 100, .fin = false });
    pkt.addStreamFrame(.{ .stream_id = 4, .offset = 50, .length = 200, .fin = true });

    try testing.expectEqual(@as(u8, 2), pkt.stream_frame_count);
    const frames = pkt.getStreamFrames();
    try testing.expectEqual(@as(usize, 2), frames.len);
    try testing.expectEqual(@as(u64, 0), frames[0].stream_id);
    try testing.expectEqual(@as(u64, 0), frames[0].offset);
    try testing.expectEqual(@as(u64, 100), frames[0].length);
    try testing.expect(!frames[0].fin);
    try testing.expectEqual(@as(u64, 4), frames[1].stream_id);
    try testing.expectEqual(@as(u64, 50), frames[1].offset);
    try testing.expectEqual(@as(u64, 200), frames[1].length);
    try testing.expect(frames[1].fin);
}

test "SentPacket: stream frame capacity limit" {
    var pkt = SentPacket{
        .pn = 0,
        .time_sent = 0,
        .size = 1200,
        .ack_eliciting = true,
        .in_flight = true,
        .enc_level = .application,
    };

    // Add MAX_STREAM_FRAMES_PER_PACKET frames
    var i: u64 = 0;
    while (i < MAX_STREAM_FRAMES_PER_PACKET) : (i += 1) {
        pkt.addStreamFrame(.{ .stream_id = i * 4, .offset = 0, .length = 10, .fin = false });
    }

    // Adding one more should be silently ignored (no crash)
    pkt.addStreamFrame(.{ .stream_id = 100, .offset = 0, .length = 10, .fin = false });
    try testing.expectEqual(@as(u8, MAX_STREAM_FRAMES_PER_PACKET), pkt.stream_frame_count);
}

// ACK-of-ACK pruning (RFC 9000 §13.2.4)
test "PacketHandler: skipped application packet numbers are never sent, and an ACK naming one is caught" {
    var handler = PacketHandler.init(testing.allocator);
    defer handler.deinit();
    var prng = std.Random.DefaultPrng.init(0x6a697474);
    const random = prng.random();

    var last: u64 = 0;
    var gaps: usize = 0;
    var i: usize = 0;
    while (i < 200) : (i += 1) {
        const pn = handler.nextPacketNumber(.application, random);
        if (i > 0 and pn != last + 1) {
            gaps += 1;
            try testing.expectEqual(last + 2, pn);
            try testing.expect(handler.acksUnsentPacket(.application, pn, 1, &.{}));
            try testing.expect(!handler.acksUnsentPacket(.application, pn, 0, &.{}));
            try testing.expect(handler.acksUnsentPacket(.application, pn, 0, &.{.{ .start = last + 1, .end = last + 1 }}));
        }
        last = pn;
    }
    try testing.expect(gaps >= 2);
    // Handshake spaces number densely: the peer's ACKs there come too early
    // to matter, and those spaces are short-lived.
    try testing.expectEqual(@as(u64, 0), handler.nextPacketNumber(.initial, random));
    try testing.expectEqual(@as(u64, 1), handler.nextPacketNumber(.initial, random));
}

test "ReceivedPacketTracker: range count is capped, oldest dropped" {
    var tracker = ReceivedPacketTracker.init(testing.allocator);
    defer tracker.deinit();

    // Every other PN: one range per packet.
    var pn: u64 = 0;
    while (pn < 4 * MAX_RECEIVED_RANGES) : (pn += 2) {
        try tracker.onPacketReceived(pn, true, 0, 0);
    }
    try testing.expectEqual(MAX_RECEIVED_RANGES, tracker.received.len());
    // The newest survive; a forgotten gap now reads as a duplicate.
    try testing.expect(tracker.received.contains(pn - 2));
    try testing.expect(tracker.isDuplicate(1));
    try testing.expect(!tracker.isDuplicate(pn - 1));
}

test "ReceivedPacketTracker: pruneAckedRanges removes old ranges" {
    var tracker = ReceivedPacketTracker.init(testing.allocator);
    defer tracker.deinit();

    // Receive packets 0..9
    var i: u64 = 0;
    while (i < 10) : (i += 1) {
        try tracker.onPacketReceived(i, true, 1000 + @as(i64, @intCast(i)), 0);
    }

    // Ranges should cover 0..9
    try testing.expectEqual(@as(usize, 1), tracker.received.getRanges().len);
    try testing.expectEqual(@as(u64, 0), tracker.received.getRanges()[0].start);

    // Prune below 5 — ranges should now start at 5
    tracker.pruneAckedRanges(5);
    try testing.expectEqual(@as(usize, 1), tracker.received.getRanges().len);
    try testing.expectEqual(@as(u64, 5), tracker.received.getRanges()[0].start);
    try testing.expectEqual(@as(u64, 9), tracker.received.getRanges()[0].end);
}

// App-limited cwnd suppression (RFC 9002 §7.8)
test "NewReno: app_limited suppresses cwnd growth" {
    const cc_mod = @import("congestion.zig");
    var cc = cc_mod.NewReno.init();

    // Normal growth in slow start
    const initial = cc.congestion_window;
    cc.onPacketAcked(1200, 100);
    try testing.expect(cc.congestion_window > initial);

    // Set app_limited — no further growth
    const after_ack = cc.congestion_window;
    cc.app_limited = true;
    cc.onPacketAcked(1200, 200);
    try testing.expectEqual(after_ack, cc.congestion_window);

    // Clear app_limited — growth resumes
    cc.app_limited = false;
    cc.onPacketAcked(1200, 300);
    try testing.expect(cc.congestion_window > after_ack);
}

test "AckResult.release keeps a typical ACK's room and frees a burst's" {
    var result: AckResult = .{};
    defer result.deinit(testing.allocator);
    var pkt: SentPacket = .{ .pn = 0, .time_sent = 0, .size = 1200, .ack_eliciting = true, .in_flight = true, .enc_level = .application };
    for (0..8) |_| try result.acked.append(testing.allocator, &pkt);
    result.release(testing.allocator);
    try testing.expect(result.acked.items.capacity >= 8);

    for (0..1000) |_| try result.lost.append(testing.allocator, &pkt);
    result.release(testing.allocator);
    try testing.expectEqual(@as(usize, 0), result.lost.items.capacity);
    try testing.expect(result.acked.items.capacity >= 8);
}

test "SentPacketTracker: every packet taken from the pool goes back" {
    var ph = PacketHandler.init(testing.allocator);
    defer ph.deinit();
    var result: AckResult = .{};
    defer result.deinit(testing.allocator);
    const app = &ph.sent[@intFromEnum(EncLevel.application)];

    var pn: u64 = 0;
    var now: i64 = 1_000_000;
    for (0..50) |round| {
        // Ten packets; the peer acks all but the first two, which go lost.
        const first = pn;
        for (0..10) |_| {
            try ph.onPacketSent(.{ .pn = pn, .time_sent = now, .size = 1200, .ack_eliciting = true, .in_flight = true, .enc_level = .application });
            pn += 1;
        }
        now += 10_000_000;
        try ph.onAckReceived(.application, pn - 1, 0, 3, &.{}, pn - 1 - (first + 2), now, &result);
        try testing.expectEqual(@as(usize, 8), result.acked.count());
        result.release(testing.allocator);
        // The two left behind are declared lost by the timer, or already were.
        now += 1_000_000_000;
        try ph.detectLossesForSpace(.application, now, &result);
        result.release(testing.allocator);
        try testing.expectEqual(@as(usize, 0), app.sent_packets.count());
        try testing.expectEqual(@as(usize, 0), app.live);
        _ = round;
    }

    // A space dropped while a result still holds its packets.
    try ph.onPacketSent(.{ .pn = pn, .time_sent = now, .size = 1200, .ack_eliciting = true, .in_flight = true, .enc_level = .handshake });
    try ph.onPacketSent(.{ .pn = pn + 1, .time_sent = now, .size = 1200, .ack_eliciting = true, .in_flight = true, .enc_level = .handshake });
    try ph.onAckReceived(.handshake, pn, 0, 3, &.{}, 0, now + 1000, &result);
    ph.dropSpace(.handshake);
    try testing.expectEqual(@as(u64, pn), result.acked.constSlice()[0].pn); // still readable
    result.release(testing.allocator);
    try testing.expectEqual(@as(usize, 0), ph.sent[@intFromEnum(EncLevel.handshake)].live);
}

/// The application packet numbers a handler leaves unsent over `packets`
/// sends. `random` is seeded with `seed`, so the answer is the same every
/// run.
fn skipSequence(seed: u64, packets: usize, out: []u64) !usize {
    var prng = std.Random.DefaultPrng.init(seed);
    const random = prng.random();
    var handler = PacketHandler.init(testing.allocator);
    defer handler.deinit();

    var skipped: usize = 0;
    var before = handler.skipped_pns[0];
    for (0..packets) |_| {
        const pn = handler.nextPacketNumber(.application, random);
        const current = handler.skipped_pns[0];
        if (current == before) continue;
        before = current;

        if (skipped == out.len) return error.SkipBufferTooSmall;
        const gap = current.?;
        out[skipped] = gap;
        skipped += 1;

        // The number handed out after a gap is the one after the skipped.
        try testing.expectEqual(gap + 1, pn);
        // Only the window is pinned. The offset inside it is the part that
        // has to stay unpredictable to a peer, so it is drawn, not asserted.
        const half = handler.skip_period / 2;
        try testing.expect(gap + half <= handler.skip_pn);
        try testing.expect(handler.skip_pn < gap + 2 * half);
    }
    return skipped;
}

// RFC 9000 21.4 needs the skip unpredictable, so no value is pinned here.
// Injecting the generator buys what this can now see: the same seed leaves
// the same numbers unsent twice, and a different seed leaves others, so the
// skip is drawn from the source the caller handed in rather than fixed.
test "PacketHandler: the skipped packet number is drawn from the injected generator" {
    var first: [16]u64 = undefined;
    var again: [16]u64 = undefined;
    var other: [16]u64 = undefined;

    const n = try skipSequence(0x6a697474, 400, &first);
    const m = try skipSequence(0x6a697474, 400, &again);
    const o = try skipSequence(0x6a697475, 400, &other);

    try testing.expect(n >= 2);
    try testing.expectEqual(n, m);
    try testing.expectEqualSlices(u64, first[0..n], again[0..m]);
    try testing.expect(!std.mem.eql(u64, first[0..n], other[0..o]));
}

test "PacketHandler: excessive encoded ACK delay is capped before scaling" {
    const Delay = struct { encoded: u64, exponent: u6 };
    for ([_]Delay{
        .{ .encoded = 25_000, .exponent = 0 },
        .{ .encoded = 1 << 35, .exponent = 20 },
        .{ .encoded = (1 << 62) - 1, .exponent = 20 },
    }) |delay| {
        var handler = PacketHandler.init(testing.allocator);
        defer handler.deinit();
        handler.rtt_stats = .{
            .min_rtt = 10_000_000,
            .smoothed_rtt = 50_000_000,
            .rtt_var = 1_000_000,
            .has_measurement = true,
        };
        var result: AckResult = .{};
        defer result.deinit(testing.allocator);
        try handler.onPacketSent(.{
            .pn = 0,
            .time_sent = 100_000_000,
            .size = 1200,
            .ack_eliciting = true,
            .in_flight = true,
            .enc_level = .application,
        });
        try handler.onAckReceived(
            .application,
            0,
            delay.encoded,
            delay.exponent,
            &.{},
            0,
            180_000_000,
            &result,
        );
        try testing.expectEqual(@as(usize, 1), result.acked.count());
        try testing.expectEqual(@as(u64, 0), result.acked.constSlice()[0].pn);
        try testing.expectEqual(@as(i64, 80_000_000), handler.rtt_stats.latest_rtt);
        try testing.expectEqual(@as(i64, 50_625_000), handler.rtt_stats.smoothed_rtt);
        try testing.expectEqual(@as(u64, 0), handler.bytes_in_flight);
    }
}

test "ReceivedPacketTracker: an unrepresentable ACK frequency delay is bounded" {
    var tracker = ReceivedPacketTracker.init(testing.allocator);
    defer tracker.deinit();
    try testing.expect(tracker.applyAckFrequency(0, 256, (1 << 62) - 1, 0));
    try testing.expectEqual(std.math.maxInt(i64), tracker.max_ack_delay_ns);
    try testing.expect(!tracker.applyAckFrequency(0, 1, 1, 1));
    try testing.expectEqual(@as(u32, 256), tracker.ack_eliciting_threshold);
    try testing.expectEqual(std.math.maxInt(i64), tracker.max_ack_delay_ns);
}

test "ReceivedPacketTracker: an ACK deadline beyond the clock range is bounded" {
    var tracker = ReceivedPacketTracker.init(testing.allocator);
    defer tracker.deinit();
    const delay_us: u64 = @intCast(@divFloor(std.math.maxInt(i64), 1000));
    try testing.expect(tracker.applyAckFrequency(0, 256, delay_us, 0));
    try tracker.onPacketReceived(0, true, 1_000_000, 0);
    try testing.expectEqual(@as(?i64, std.math.maxInt(i64)), tracker.ack_alarm);
    try testing.expectEqual(@as(?Frame, null), tracker.getAckFrame(std.math.maxInt(i64) - 1, 0));
    const ack = tracker.getAckFrame(std.math.maxInt(i64), 0) orelse
        return error.TestUnexpectedResult;
    try testing.expectEqual(@as(u64, 0), ack.ack.largest_ack);
}

// Fail-N: every allocation an ACK or a loss pass makes is a point at which it
// can be refused, and each of those refusals has to leave the space whole.

/// A refused send cannot leave a counter that counted a packet the space does
/// not hold: the caller has already reported that packet and cannot un-spend
/// its number.
fn sendUnderAnyRefusal(gpa: Allocator) !void {
    var tracker = SentPacketTracker.init(gpa);
    defer tracker.deinit();
    var rtt_stats = RttStats{};
    var result: AckResult = .{};
    defer result.deinit(gpa);

    const now: i64 = 1_000_000_000;
    try tracker.onPacketSent(.{
        .pn = 0,
        .time_sent = now,
        .size = 1200,
        .ack_eliciting = true,
        .in_flight = true,
        .enc_level = .application,
    });

    if (tracker.onPacketSent(.{
        .pn = 1,
        .time_sent = now + 1,
        .size = 1200,
        .ack_eliciting = true,
        .in_flight = true,
        .enc_level = .application,
    })) |_| {} else |err| {
        try testing.expectEqual(error.OutOfMemory, err);
        try testing.expectEqual(@as(usize, 1), tracker.sent_packets.count());
        try testing.expectEqual(@as(usize, 1), tracker.live);
        try testing.expectEqual(@as(u32, 1), tracker.ack_eliciting_in_flight);
        try testing.expectEqual(@as(?u64, 0), tracker.largest_sent);
        try testing.expectEqual(@as(?i64, now), tracker.last_ack_eliciting_sent_time);
        // Handed back so the sweep reads this as the refusal it induced, and
        // its leak accounting covers whatever the call had already taken.
        return error.OutOfMemory;
    }

    try testing.expectEqual(@as(usize, 2), tracker.sent_packets.count());
    try testing.expectEqual(@as(usize, 2), tracker.live);
    try testing.expectEqual(@as(u32, 2), tracker.ack_eliciting_in_flight);
    try testing.expectEqual(@as(?u64, 1), tracker.largest_sent);
    try testing.expectEqual(@as(?i64, now + 1), tracker.last_ack_eliciting_sent_time);

    try tracker.onAckReceived(1, 0, &.{}, 1, &rtt_stats, now + 50_000_000, &result);
    try testing.expectEqual(@as(usize, 2), result.acked.count());
    try testing.expectEqual(@as(usize, 0), tracker.sent_packets.count());
    try testing.expectEqual(@as(u32, 0), tracker.ack_eliciting_in_flight);
    result.release(gpa);
    try testing.expectEqual(@as(usize, 0), tracker.live);
}

/// A pass refused part-way through has to have removed nothing: packets taken
/// out of the map but never handed to the result are credits that never reach
/// `bytes_in_flight`, and a window charged for packets nobody holds does not
/// open again on its own.
fn ackPassUnderAnyRefusal(gpa: Allocator) !void {
    var handler = PacketHandler.init(gpa);
    defer handler.deinit();
    var result: AckResult = .{};
    defer result.deinit(gpa);
    const app = &handler.sent[@intFromEnum(EncLevel.application)];

    const now: i64 = 1_000_000_000;
    for (0..8) |i| {
        try handler.onPacketSent(.{
            .pn = @intCast(i),
            .time_sent = now,
            .size = 1200,
            .ack_eliciting = true,
            .in_flight = true,
            .enc_level = .application,
        });
    }
    const in_flight: u64 = 8 * 1200;

    // Acknowledges packets 1..6; the threshold takes packet 0 and packet 7
    // is too recent to be lost.
    if (handler.onAckReceived(.application, 6, 0, 3, &.{}, 5, now + 50_000_000, &result)) |_| {} else |err| {
        try testing.expectEqual(error.OutOfMemory, err);
        try testing.expectEqual(in_flight, handler.bytes_in_flight);
        try testing.expectEqual(@as(usize, 8), app.sent_packets.count());
        try testing.expectEqual(@as(usize, 8), app.live);
        try testing.expectEqual(@as(u32, 8), app.ack_eliciting_in_flight);
        try testing.expectEqual(@as(?u64, null), app.largest_acked);
        try testing.expectEqual(@as(?i64, null), app.loss_time);
        try testing.expect(!handler.rtt_stats.has_measurement);
        try testing.expectEqual(@as(usize, 0), result.acked.count());
        try testing.expectEqual(@as(usize, 0), result.lost.count());
        return error.OutOfMemory;
    }

    try testing.expectEqual(@as(usize, 6), result.acked.count());
    try testing.expectEqual(@as(usize, 1), result.lost.count());
    try testing.expectEqual(@as(usize, 1), app.sent_packets.count());
    try testing.expectEqual(@as(usize, 8), app.live);
    try testing.expectEqual(@as(u32, 1), app.ack_eliciting_in_flight);
    try testing.expectEqual(@as(u64, 1200), handler.bytes_in_flight);
    try testing.expectEqual(@as(u64, 6), app.largest_acked.?);
    try testing.expectEqual(@as(i64, 50_000_000), handler.rtt_stats.latest_rtt);
    // Where the tracker and its result are checked against each other.
    result.release(gpa);
    try testing.expectEqual(@as(usize, 1), app.live);
    try testing.expectEqual(@as(usize, 1), app.sent_packets.count());
}

test "SentPacketTracker: a refused send leaves the space exactly as it was" {
    // Each run either completes the send or hands back the refusal, and the
    // sweep fails on a packet that was taken and then lost.
    try std.testing.checkAllAllocationFailures(testing.allocator, sendUnderAnyRefusal, .{});
}

test "PacketHandler: a refused ACK pass takes nothing out of the space" {
    try std.testing.checkAllAllocationFailures(testing.allocator, ackPassUnderAnyRefusal, .{});
}

test "PacketHandler: an ACK pass refused once is safe to repeat, and to drop" {
    // The connection re-raises a frame it could not hand over, so running the
    // same ACK again is a supported call and not a caller that got it wrong.
    var failing = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    var handler = PacketHandler.init(testing.allocator);
    defer handler.deinit();
    var result: AckResult = .{};
    defer result.deinit(testing.allocator);
    const app = &handler.sent[@intFromEnum(EncLevel.application)];

    const now: i64 = 1_000_000_000;
    for (0..8) |i| {
        try handler.onPacketSent(.{
            .pn = @intCast(i),
            .time_sent = now,
            .size = 1200,
            .ack_eliciting = true,
            .in_flight = true,
            .enc_level = .application,
        });
    }

    app.allocator = failing.allocator();
    try testing.expectError(
        error.OutOfMemory,
        handler.onAckReceived(.application, 6, 0, 3, &.{}, 5, now + 50_000_000, &result),
    );
    app.allocator = testing.allocator;

    try testing.expectEqual(@as(u64, 8 * 1200), handler.bytes_in_flight);
    try testing.expectEqual(@as(usize, 8), app.sent_packets.count());
    try testing.expectEqual(@as(usize, 0), result.acked.count());
    try testing.expectEqual(@as(usize, 0), result.lost.count());

    try handler.onAckReceived(.application, 6, 0, 3, &.{}, 5, now + 50_000_000, &result);
    try testing.expectEqual(@as(usize, 6), result.acked.count());
    try testing.expectEqual(@as(usize, 1), result.lost.count());
    try testing.expectEqual(@as(u64, 1200), handler.bytes_in_flight);
    try testing.expectEqual(@as(i64, 50_000_000), handler.rtt_stats.latest_rtt);
    result.release(testing.allocator);
    try testing.expectEqual(@as(usize, 1), app.live);

    // Dropping the space returns the packet it was still holding.
    handler.dropSpace(.application);
    try testing.expectEqual(@as(u64, 0), handler.bytes_in_flight);
    try testing.expectEqual(@as(usize, 0), app.live);
    try testing.expectEqual(@as(usize, 0), app.sent_packets.count());
}

test "PacketHandler: a refused loss pass leaves the loss timer armed and is safe to repeat" {
    // The timer-driven pass gets a fresh result, as the connection gives it
    // one: the room the previous pass left behind is not this pass's to use.
    var failing = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    var handler = PacketHandler.init(testing.allocator);
    defer handler.deinit();
    var result: AckResult = .{};
    defer result.deinit(testing.allocator);
    var loss_result: AckResult = .{};
    defer loss_result.deinit(testing.allocator);
    const app = &handler.sent[@intFromEnum(EncLevel.application)];

    const now: i64 = 1_000_000_000;
    for (0..6) |i| {
        try handler.onPacketSent(.{
            .pn = @intCast(i),
            .time_sent = now,
            .size = 1200,
            .ack_eliciting = true,
            .in_flight = true,
            .enc_level = .application,
        });
    }
    // Acknowledges the top two; the threshold takes the bottom three and the
    // fourth is left with a loss timer armed.
    try handler.onAckReceived(.application, 5, 0, 3, &.{}, 1, now + 50_000_000, &result);
    try testing.expectEqual(@as(usize, 2), result.acked.count());
    try testing.expectEqual(@as(usize, 3), result.lost.count());
    try testing.expectEqual(@as(u32, 1), app.ack_eliciting_in_flight);
    result.release(testing.allocator);
    const armed_loss_time = app.loss_time.?;
    try testing.expectEqual(@as(u64, 1200), handler.bytes_in_flight);

    app.allocator = failing.allocator();
    try testing.expectError(
        error.OutOfMemory,
        handler.detectLossesForSpace(.application, now + 10_000_000_000, &loss_result),
    );
    app.allocator = testing.allocator;

    try testing.expectEqual(@as(u64, 1200), handler.bytes_in_flight);
    try testing.expectEqual(@as(usize, 1), app.sent_packets.count());
    try testing.expectEqual(@as(usize, 1), app.live);
    try testing.expectEqual(@as(u32, 1), app.ack_eliciting_in_flight);
    try testing.expectEqual(armed_loss_time, app.loss_time.?);
    try testing.expectEqual(@as(usize, 0), loss_result.lost.count());

    try handler.detectLossesForSpace(.application, now + 10_000_000_000, &loss_result);
    try testing.expectEqual(@as(usize, 1), loss_result.lost.count());
    try testing.expectEqual(@as(usize, 0), app.sent_packets.count());
    try testing.expectEqual(@as(u32, 0), app.ack_eliciting_in_flight);
    try testing.expectEqual(@as(u64, 0), handler.bytes_in_flight);
    try testing.expectEqual(@as(?i64, null), app.loss_time);
}

test "native control records survive packet-threshold loss with owned payloads" {
    const address = @import("../address.zig").Address.initIpv4(.{ 192, 0, 2, 7 }, 443);
    const pending = [_]frame_mod.PendingControlFrame{
        .{ .add_address = .{ .sequence = 9, .address = address } },
        .{ .reach_address = .{ .round = 4, .address = address } },
        .{ .remove_address = 9 },
        .{ .path_abandon = .{ .path_id = 2, .error_code = 17 } },
        .{ .path_status_backup = .{ .path_id = 2, .status_seq_no = 6 } },
        .{ .path_status_available = .{ .path_id = 2, .status_seq_no = 7 } },
        .{ .path_new_connection_id = .{ .path_id = 2, .cid = .{
            .seq_num = 8, .retire_prior_to = 3, .cid_buf = [_]u8{0xab} ** 20,
            .cid_len = 1, .stateless_reset_token = [_]u8{0xcd} ** 16,
        } } },
        .{ .path_retire_connection_id = .{ .path_id = 2, .seq_num = 8 } },
        .{ .max_path_id = 12 },
        .{ .paths_blocked = 11 },
        .{ .path_cids_blocked = .{ .path_id = 2, .next_seq = 10 } },
    };
    const expected = [_]SentControlFrame{
        .{ .add_address = .{ .sequence = 9, .address = address } },
        .{ .reach_address = .{ .round = 4, .address = address } },
        .{ .remove_address = 9 },
        .{ .path_abandon = .{ .path_id = 2, .error_code = 17 } },
        .{ .path_status = 2 },
        .{ .path_status = 2 },
        .{ .path_new_connection_id = .{ .path_id = 2, .seq_num = 8 } },
        .{ .path_retire_connection_id = .{ .path_id = 2, .seq_num = 8 } },
        .max_path_id,
        .{ .paths_blocked = 11 },
        .{ .path_cids_blocked = .{ .path_id = 2, .next_seq = 10 } },
    };
    for (pending, expected) |frame, expected_record| {
        var handler = PacketHandler.init(testing.allocator);
        defer handler.deinit();
        var result = AckResult{};
        defer result.deinit(testing.allocator);
        const record = SentControlFrame.from(frame) orelse return error.UntrackedNativeControl;
        try testing.expectEqualDeep(expected_record, record);
        var lost: SentPacket = .{
            .pn = 0, .time_sent = 1_000_000_000, .size = 1200,
            .ack_eliciting = true, .in_flight = true, .enc_level = .application,
        };
        lost.control_frames[0] = record;
        lost.control_frame_count = 1;
        try handler.onPacketSent(lost);
        try handler.onPacketSent(.{
            .pn = 3, .time_sent = 1_000_000_001, .size = 1200,
            .ack_eliciting = true, .in_flight = true, .enc_level = .application,
        });
        try handler.onAckReceived(.application, 3, 0, 3, &.{}, 0, 1_050_000_000, &result);
        try testing.expectEqual(@as(usize, 1), result.lost.count());
        try testing.expectEqualDeep(record, result.lost.constSlice()[0].getControlFrames()[0]);
    }
}

test "ACK on another path cannot clear an observed report loss record" {
    var first = PacketHandler.init(testing.allocator);
    defer first.deinit();
    var second = PacketHandler.init(testing.allocator);
    defer second.deinit();
    var result = AckResult{};
    defer result.deinit(testing.allocator);
    var sent: SentPacket = .{
        .pn = 0, .time_sent = 1_000_000_000, .size = 1200,
        .ack_eliciting = true, .in_flight = true, .enc_level = .application,
    };
    sent.control_frame_count = 1;
    sent.control_frames[0] = .{ .observed_address = 1 };
    try first.onPacketSent(sent);
    sent.control_frames[0] = .{ .observed_address = 2 };
    try second.onPacketSent(sent);
    try first.onAckReceived(.application, 0, 0, 3, &.{}, 0, 1_050_000_000, &result);
    try testing.expectEqual(@as(u32, 1), result.acked.constSlice()[0].getControlFrames()[0].observed_address);
    try testing.expectEqual(@as(usize, 1), second.sent[2].sent_packets.count());
    result.release(testing.allocator);
    try second.onPacketSent(.{
        .pn = 3, .time_sent = 1_050_000_001, .size = 1200,
        .ack_eliciting = true, .in_flight = true, .enc_level = .application,
    });
    try second.onAckReceived(.application, 3, 0, 3, &.{}, 0, 1_100_000_000, &result);
    try testing.expectEqual(@as(usize, 1), result.lost.count());
    try testing.expectEqual(@as(u32, 2), result.lost.constSlice()[0].getControlFrames()[0].observed_address);
}

test "PacketHandler: off-path numbering leaves fallback recovery unchanged after timeout" {
    var handler = PacketHandler.init(testing.allocator);
    defer handler.deinit();
    var prng = std.Random.DefaultPrng.init(42);
    const random = prng.random();
    const normal_pn = handler.nextPacketNumber(.application, random);
    try handler.onPacketSent(.{
        .pn = normal_pn, .time_sent = 1000, .size = 1200,
        .ack_eliciting = true, .in_flight = true, .enc_level = .application,
    });
    const deadline = handler.spacePtoDeadline(handler.sent[2], 2);
    const probe_pn = handler.nextPacketNumber(.application, random);
    handler.onOffPathPacketSent(probe_pn);
    try testing.expectEqual(@as(?u64, probe_pn), handler.sent[2].largest_sent);
    try testing.expect(!handler.acksUnsentPacket(.application, probe_pn, 0, &.{}));
    try testing.expect(handler.acksUnsentPacket(.application, probe_pn + 1, 0, &.{}));
    try testing.expectEqual(deadline, handler.spacePtoDeadline(handler.sent[2], 2));
    var result: AckResult = .{};
    defer result.deinit(testing.allocator);
    try handler.detectLossesForSpace(.application, 10_000_000_000, &result);
    try testing.expectEqual(@as(usize, 0), result.lost.count());
    try testing.expectEqual(@as(u64, 1200), handler.bytes_in_flight);
    try testing.expectEqual(@as(u32, 1), handler.sent[2].ack_eliciting_in_flight);
}

test "PacketHandler: acknowledging off-path probe returns no on-path recovery credit" {
    var handler = PacketHandler.init(testing.allocator);
    defer handler.deinit();
    var prng = std.Random.DefaultPrng.init(42);
    const pn = handler.nextPacketNumber(.application, prng.random());
    handler.onOffPathPacketSent(pn);
    var result: AckResult = .{};
    defer result.deinit(testing.allocator);
    try handler.onAckReceived(.application, pn, 0, 3, &.{}, 0, 1001, &result);
    try testing.expectEqual(@as(usize, 0), result.acked.count());
    try testing.expectEqual(@as(usize, 0), result.lost.count());
    try testing.expect(!handler.rtt_stats.has_measurement);
    try testing.expectEqual(@as(u64, 0), handler.bytes_in_flight);
    try testing.expectEqual(@as(u32, 0), handler.sent[2].ack_eliciting_in_flight);
    try testing.expectEqual(@as(?i64, null), handler.spacePtoDeadline(handler.sent[2], 2));
}

test "PacketHandler: ACK only off-path probes cannot lose outstanding fallback packet" {
    var handler = PacketHandler.init(testing.allocator);
    defer handler.deinit();
    var prng = std.Random.DefaultPrng.init(42);
    const random = prng.random();
    const normal_pn = handler.nextPacketNumber(.application, random);
    try handler.onPacketSent(.{
        .pn = normal_pn, .time_sent = 1000, .size = 1200,
        .ack_eliciting = true, .in_flight = true, .enc_level = .application,
    });
    for (0..3) |_| {
        handler.onOffPathPacketSent(handler.nextPacketNumber(.application, random));
    }
    handler.pto_count = 2;
    handler.sent[2].pto_count = 2;
    const deadline = handler.spacePtoDeadline(handler.sent[2], 2);
    var result: AckResult = .{};
    defer result.deinit(testing.allocator);
    // Both the packet threshold and elapsed loss delay would otherwise lose PN 0.
    try handler.onAckReceived(.application, 3, 0, 3, &.{}, 0, 10_000_000_000, &result);
    try testing.expectEqual(@as(?u64, 3), handler.sent[2].largest_acked);
    try testing.expectEqual(@as(usize, 0), result.acked.count());
    try testing.expectEqual(@as(usize, 0), result.lost.count());
    try testing.expect(handler.sent[2].sent_packets.contains(normal_pn));
    try testing.expectEqual(@as(u64, 1200), handler.bytes_in_flight);
    try testing.expectEqual(@as(u32, 1), handler.sent[2].ack_eliciting_in_flight);
    try testing.expectEqual(@as(u32, 2), handler.pto_count);
    try testing.expectEqual(@as(u32, 2), handler.sent[2].pto_count);
    try testing.expectEqual(deadline, handler.spacePtoDeadline(handler.sent[2], 2));
    try testing.expectEqual(@as(?i64, null), handler.sent[2].loss_time);
    try testing.expect(!handler.rtt_stats.has_measurement);
    try testing.expect(!result.persistent_congestion);
}
