//! Assembling outgoing QUIC packets: header, frame selection, AEAD
//! encryption, header protection and coalescing into one datagram.
//!
//! `PacketPacker` is reached through `Connection.packer` and is that
//! connection's send state, not a general encoder: the connection owns the
//! congestion window, the pacer and the anti-amplification budget, and only
//! `Connection.sendAt` applies them. The packer owns its two connection-id
//! buffers and borrows everything else — the streams, the crypto streams,
//! the frame queue and the flow controller are all the caller's and must
//! outlive the call.

const std = @import("std");
const testing = std.testing;
const io = @import("../io_compat.zig");

const packet_mod = @import("packet.zig");
const crypto_mod = @import("crypto.zig");
const frame_mod = @import("frame.zig");
const Frame = frame_mod.Frame;
const ack_handler = @import("ack_handler.zig");
const crypto_stream = @import("crypto_stream.zig");
const stream_mod = @import("stream.zig");
const conn_mod = @import("connection.zig");
const protocol = @import("protocol.zig");
const flow_control = @import("flow_control.zig");

/// A bounded off-path payload, never a view of the normal send queues.
pub const OffPathOptions = struct {
    challenge: ?[8]u8 = null,
    response: ?[8]u8 = null,
};

/// Calculate the overhead of a STREAM frame header (type + stream_id + offset + length varints).
/// This accounts for the LEN flag always being set.
fn streamFrameHeaderOverhead(stream_id: u64, offset: u64, max_data_len: u64) usize {
    return 1 // type byte (always 1 byte, value 0x08-0x0F)
    + packet_mod.varIntLength(stream_id) + (if (offset > 0) packet_mod.varIntLength(offset) else 0) + packet_mod.varIntLength(max_data_len); // length field (always present with LEN flag)
}

/// The room the Handshake level is guaranteed before the Initial may take it,
/// so a level that shares a datagram's 1200-byte floor can always reach it.
///
/// Its long header with this connection's two ids, the length field, the
/// longest packet number, the CRYPTO frame it is sharing for — whose offset and
/// length are varints, and so widest at eight bytes each — one byte of that
/// frame's data, the four plaintext bytes the header-protection sample starts
/// in, and the AEAD tag twice over: the packet's own length and the budget
/// that CRYPTO frame is measured against each take one off.
fn laterLevelRoom(dcid_len: u8, scid_len: u8) usize {
    const dcid: usize = dcid_len;
    const scid: usize = scid_len;
    return 1 + 4 + (1 + dcid) + (1 + scid) + 2 + 4 + (1 + 8 + 8 + 1) + 4 +
        AEAD_TAG_LEN + AEAD_TAG_LEN + 1;
}

/// Whether the Initial packet a call packs carries a frame of its own —
/// CRYPTO data at that level, or a PING or CONNECTION_CLOSE its own control
/// loop writes — rather than being in the datagram only because an ACK
/// happens to be due.
///
/// A CONNECTION_CLOSE is not what makes a packet ack-eliciting (RFC 9000
/// §13.2.1, which `Frame.isAckEliciting` agrees with), so this is not a
/// question about ack-eliciting packets: it counts a queued close anyway, and
/// `closeQueued` says why the levels above keep one queued.
fn initialCarriesOwnFrames(
    crypto_mgr: *crypto_stream.CryptoStreamManager,
    pending_frames: *frame_mod.PendingFrameQueue,
) bool {
    if (crypto_mgr.getStream(0).hasData()) return true;
    for (pending_frames.items[0..pending_frames.len]) |frame| switch (frame) {
        .ping, .connection_close => return true,
        else => {},
    };
    return false;
}

/// Whether a CONNECTION_CLOSE is queued for the levels above. RFC 9000 §10.2.3
/// sends one at every level the peer may still be reading, so the Initial's
/// control loop writes it and requeues it for the rest. That is why a
/// Handshake level with nothing but that close to say still counts as a
/// flight the floor is shared with: an Initial that spends the whole floor on
/// its own requeues the close again, so the Handshake packet meant to carry
/// it is deferred on every pass, and a deferral that repeats forever is not a
/// close that goes out later.
fn closeQueued(pending_frames: *frame_mod.PendingFrameQueue) bool {
    for (pending_frames.items[0..pending_frames.len]) |frame| switch (frame) {
        .connection_close => return true,
        else => {},
    };
    return false;
}

/// Default QUIC packet size (UDP payload).
const DEFAULT_MAX_PACKET_SIZE: usize = 1200;

/// Absolute maximum packet size we ever assemble (probes included).
///
/// The ceiling on `PacketPacker.max_packet_size` and on the staging buffer:
/// a caller asking for more is truncated to this rather than refused, so a
/// probe for a path MTU above it silently probes 1500.
const ABSOLUTE_MAX_PACKET_SIZE: usize = 1500;

/// Minimum Initial packet size for client.
const MIN_INITIAL_PACKET_SIZE: usize = 1200;

/// AEAD tag length (AES-128-GCM).
const AEAD_TAG_LEN: usize = crypto_mod.Aead.tag_length;

/// The packet packer assembles outgoing QUIC packets.
///
/// It handles:
/// - Coalescing multiple encryption levels into one UDP datagram
/// - Collecting frames (ACK, CRYPTO, STREAM, control)
/// - Applying payload encryption and header protection
/// - Padding Initial packets to minimum 1200 bytes
///
/// It owns the two connection-id buffers and holds no allocator: there is no
/// `deinit`, because every buffer it writes through is a fixed-size stack
/// array and the connection ids are inline, so it allocates nothing whose
/// lifetime outlives a call. A packer may be moved freely; what it must not
/// do is move while a caller holds a slice from `getScid` or `getDcid`.
///
/// The fields below are the connection's send state rather than parameters
/// of a call, and `Connection` writes most of them directly: `max_packet_size`
/// after path MTU discovery, `key_phase` on a key update, `spin_bit` for
/// passive RTT measurement, `ecn_mark` from the ECN validator before each
/// send, and `initial_token` after a Retry.
pub const PacketPacker = struct {
    /// Whether this side is the server. Decides who spends a coalesced
    /// datagram's 1200-byte floor — see `packCoalesced`, which pads an Initial
    /// itself unless a Handshake level with CRYPTO to seal shares the datagram
    /// with it — and whether an Initial this packer emits is subject to that
    /// floor at all, which for a server means only when it carries a frame of
    /// its own (`initialCarriesOwnFrames`).
    is_server: bool,

    /// Source connection ID (owned buffer to avoid dangling slices).
    ///
    /// A copy, not a borrow: it is here so the packer keeps working after
    /// the connection it was built from has moved or released the caller's
    /// original. `init` copies without a length check, so a source id longer
    /// than twenty bytes overflows here — the bound is RFC 9000 §17.2's
    /// twenty, and the caller is what enforces it.
    scid_buf: [20]u8 = @splat(0),
    /// Bytes of `scid_buf` in use, at most twenty.
    scid_len: u8 = 0,

    /// Destination connection ID (owned buffer to avoid dangling slices).
    ///
    /// Same copy and same unchecked twenty-byte bound as `scid_buf`. Written
    /// by `init` and by `updateDcid`, and read for every packet header, so
    /// changing it changes where the next packet goes.
    dcid_buf: [20]u8 = @splat(0),
    /// Bytes of `dcid_buf` in use, at most twenty.
    dcid_len: u8 = 0,
    /// The QUIC version written into every long header but a 0-RTT one, and,
    /// with `quic_version` on the TLS config, the version the Handshake and
    /// 1-RTT keys are labelled for. The two must agree: a version negotiation
    /// that moves this without moving the config produces packets whose keys
    /// do not match their labels.
    ///
    /// This is the connection's negotiated version once it has one. It starts
    /// as the version the first flight was built with and moves only when
    /// `Connection.switchVersion` says the connection adopted another.
    version: u32,

    /// The QUIC version this connection's first flight was built with, which is
    /// what every 0-RTT packet keeps using.
    ///
    /// RFC 9369 §4.1: "The client MUST NOT send 0-RTT packets using the
    /// negotiated version, even after processing a packet of that version from
    /// the server." A 0-RTT packet carries its version in its long header, so
    /// one written after the negotiation would be a packet the server reads
    /// under a version it has no 0-RTT keys for. Set by `init` from the same
    /// version as `version` and never changed.
    original_version: u32,

    /// Token for Initial packets (from Retry).
    ///
    /// Borrowed from the connection's own token buffer, not copied, so that
    /// buffer must stay alive and unmodified for as long as this points into
    /// it. Nothing here clears the field: once the connection sets it, every
    /// later Initial carries the token, so the connection is what decides when
    /// the token stops being sent — by overwriting the buffer, or by setting
    /// this to null itself. `null` sends a zero-length token, which is what a
    /// first Initial does.
    initial_token: ?[]const u8 = null,

    /// Whether to send HANDSHAKE_DONE frame in the next 1-RTT packet (server only).
    ///
    /// One-shot: packing consumes it, so the connection re-arms it after a
    /// PTO or a loss rather than leaving it set. Cleared by the caller at
    /// the same time it queues the retransmission.
    send_handshake_done: bool = false,

    /// Current key phase bit for 1-RTT packets (toggled on key update).
    ///
    /// Set into the short header on every 1-RTT packet, so it must match the
    /// seal actually used: writing it without rolling the keys produces
    /// packets the peer will decrypt with the wrong key.
    key_phase: bool = false,

    /// Null keeps legacy 1-RTT protection and ACKs. A negotiated multipath
    /// connection sets this even for path zero and supplies that path's handler
    /// to every packing call; the handler owns its independent packet numbers.
    /// Initial, Handshake and 0-RTT protection never use this path nonce.
    application_path_id: ?u32 = null,

    /// Whole-packet minimum for a 1-RTT path-validation challenge. The caller
    /// sets zero for ordinary traffic and NAT probes, which need no expansion.
    application_padding_min: usize = 0,

    /// Spin bit for passive RTT measurement (RFC 9000 §17.4).
    ///
    /// A peer that echoes it proves it received the packet, so it is set to
    /// the connection's own answer to the last ACK and is not a local
    /// decision at pack time.
    spin_bit: bool = false,

    /// Maximum size of one outgoing datagram, for regular (non-probe) sends.
    ///
    /// 1200 from `init`, raised as path MTU discovery succeeds. It is a
    /// whole-UDP-payload number because `Connection` writes it from the path
    /// MTU, and the datagram is what a path carries: `packCoalesced` spends it
    /// once, as `min(max_packet_size, out_buf.len)`, and offers every level
    /// what is left of that one budget rather than a copy of it each. So the
    /// bytes of an Initial and the Handshake packet riding behind it are one
    /// budget between them, not one each. A value above 1500 buys nothing —
    /// the staging buffer is 1500 — and a short caller buffer shrinks the
    /// datagram the same way.
    ///
    /// Below `MIN_INITIAL_PACKET_SIZE` this is a budget and not a floor, so
    /// `packCoalesced` stops sharing one with a Handshake level and puts the
    /// whole of it on the Initial. Every packet then handed a target it cannot
    /// reach is refused whole by `packSinglePacket`, before a packet number is
    /// taken and before a frame leaves its queue: that flight goes out whole
    /// on the first send with the room for it, which is what RFC 9000 §14.1
    /// asks for and all a lowering achieves. What is given no target is still
    /// built to this size — a server's Initial that would be in the datagram
    /// only because an ACK is due, and a Handshake packet that reaches the
    /// packer with nothing written ahead of it — which is why this stays a
    /// budget rather than a preguard that refuses the call.
    max_packet_size: usize = DEFAULT_MAX_PACKET_SIZE,

    /// Whether outgoing 1-RTT packets should be marked as ECN (ECT(0)).
    /// Set by connection before packing based on ECN validator state.
    ///
    /// Only 1-RTT packets are marked; Initial and Handshake packets never
    /// are. The connection sets it from `ecn.EcnValidator.shouldMark` before
    /// each send, and the value is recorded on the resulting `SentPacket` so
    /// a CE report can be charged against what was marked.
    ecn_mark: bool = false,

    /// Connection-level flow controller (for send-side limit enforcement).
    ///
    /// Borrowed from `Connection.conn_flow_ctrl` and set before each send;
    /// `null` means no connection-level limit is applied here and stream bytes
    /// are packed against the per-stream window alone. Whether this packer
    /// runs at all — the congestion window, and the anti-amplification budget
    /// that shortens the caller's output buffer — is the caller's decision and
    /// is not read from here. Bytes packed are charged straight to
    /// `base.bytes_sent` rather than through the stream's own controller, so
    /// this pointer and the streams must describe the same connection.
    conn_flow_ctrl: ?*flow_control.ConnectionFlowController = null,

    /// A packer for one connection, with its connection ids copied in.
    ///
    /// `scid` and `dcid` are borrowed for the call and copied, so the caller
    /// may release them immediately. Neither length is checked: anything
    /// longer than twenty bytes overflows the inline buffers, and the
    /// twenty-byte bound of RFC 9000 §17.2 is the caller's to enforce.
    /// `version` is what goes in the long header from the first packet.
    ///
    /// Everything else is at its default: no token, 1200-byte packets, no
    /// ECN marking and no flow control, so a packer built here sends until
    /// the connection fills in the rest.
    pub fn init(
        is_server: bool,
        scid: []const u8,
        dcid: []const u8,
        version: u32,
    ) PacketPacker {
        var packer = PacketPacker{
            .is_server = is_server,
            .scid_len = @intCast(scid.len),
            .dcid_len = @intCast(dcid.len),
            .version = version,
            .original_version = version,
        };
        @memcpy(packer.scid_buf[0..scid.len], scid);
        @memcpy(packer.dcid_buf[0..dcid.len], dcid);
        return packer;
    }

    /// The source connection id, as a slice of the packer's own buffer. It
    /// stays valid until the packer moves, and is not invalidated by any
    /// method here — the source id is written once, at `init`.
    pub fn getScid(self: *const PacketPacker) []const u8 {
        return self.scid_buf[0..self.scid_len];
    }

    /// The destination connection id, as a slice of the packer's own
    /// buffer. Invalidated by `updateDcid` and by moving the packer.
    pub fn getDcid(self: *const PacketPacker) []const u8 {
        return self.dcid_buf[0..self.dcid_len];
    }

    /// Points the next packets at a different destination connection id.
    ///
    /// `new_dcid` is copied, so the caller may release it immediately, and
    /// its length is not checked against the twenty-byte buffer — a longer id
    /// overflows here. Does not touch the source id, and does not revisit
    /// packets already built: a packet number spent under the old id stays
    /// spent, which is why a peer migration is also a protocol event.
    pub fn updateDcid(self: *PacketPacker, new_dcid: []const u8) void {
        @memcpy(self.dcid_buf[0..new_dcid.len], new_dcid);
        self.dcid_len = @intCast(new_dcid.len);
    }

    /// Seal one off-path NAT probe in the real path-zero application PN space.
    /// Noq's NAT sender emits probing frames only and excludes the datagram
    /// from recovery/congestion accounting (connection/mod.rs:2157-2168).
    /// Unlike regular path validation, this packet has no 1200-byte floor.
    /// Empty or undersized calls allocate no PN. The normal queues and this
    /// packer's send flags are untouched.
    pub fn packOffPath(
        self: *const PacketPacker,
        buf: []u8,
        pkt_handler: *ack_handler.PacketHandler,
        seal: *const crypto_mod.Seal,
        options: OffPathOptions,
        random: std.Random,
    ) !usize {
        const max_payload = 9 + 9;
        var payload: [max_payload]u8 = undefined;
        var writer = io.fixedBufferStream(&payload);
        if (options.challenge) |challenge| {
            try (Frame{ .path_challenge = challenge }).write(&writer);
        }
        if (options.response) |response| {
            try (Frame{ .path_response = response }).write(&writer);
        }
        if (writer.seek == 0) return 0;

        // Reserve the largest PN before numbering, so every subsequent write
        // is guaranteed to fit. Nine-byte path frames exceed the HP sample
        // minimum without padding.
        const required = 1 + @as(usize, self.dcid_len) + 4 + writer.seek + AEAD_TAG_LEN;
        if (@min(self.max_packet_size, buf.len) < required) return 0;
        const pn = pkt_handler.nextPacketNumber(.application, random);
        var pn_buf: [4]u8 = undefined;
        const pn_len = crypto_mod.encodePacketNumber(
            pn,
            pkt_handler.getLargestAcked(.application),
            &pn_buf,
        );
        var first_byte: u8 = packet_mod.FIXED_BIT;
        if (self.key_phase) first_byte |= packet_mod.KEY_PHASE_BIT;
        if (self.spin_bit) first_byte |= packet_mod.PACKET_SPIN_BIT;
        first_byte |= @as(u8, @intCast(pn_len - 1));
        buf[0] = first_byte;
        const pn_offset = 1 + @as(usize, self.dcid_len);
        @memcpy(buf[1..pn_offset], self.getDcid());
        @memcpy(buf[pn_offset..][0..pn_len], pn_buf[0..pn_len]);
        const header_len = pn_offset + pn_len;
        // Path zero's nonce is independent of whichever application path the
        // regular packer currently targets. Legacy protection is identical.
        const encrypted_len = seal.encryptPayloadForPath(
            0,
            pn,
            buf[0..header_len],
            payload[0..writer.seek],
            buf[header_len..],
        );
        const total_len = header_len + encrypted_len;
        seal.applyHeaderProtection(buf[0..total_len], pn_offset, pn_len);
        pkt_handler.onOffPathPacketSent(pn);
        return total_len;
    }

    /// Pack a coalesced packet (Initial + 0-RTT + Handshake + 1-RTT).
    /// Returns the number of bytes written to out_buf.
    /// When ack_only is true, only ACK/CRYPTO/HANDSHAKE_DONE/control frames are packed (no stream/datagram data).
    /// `random` draws the packet numbers a level skips; the caller owns it, so a
    /// test pins the skip schedule with a seed instead of a process CSPRNG.
    ///
    /// The datagram to send is `out_buf[0..returned]`: every byte the packer
    /// took — stream data, CRYPTO data, datagrams, control frames — is inside
    /// that prefix and is gone from the queues that held it. Nothing may be
    /// taken from `out_buf` beyond the returned count, and a caller that
    /// writes fewer bytes than were returned has silently discarded frames
    /// the queues will not offer again.
    ///
    /// Zero means nothing was packed and no packet was recorded: the packet
    /// number each level took is given back, the caller's queues are
    /// untouched, and nothing has to be sent. A caller must treat it as
    /// "nothing to do", not as "an empty datagram".
    ///
    /// Each level present in the seals is offered a packet in turn, and each
    /// is skipped when it has nothing to say — no seal, no room left in the
    /// datagram budget, or an empty payload at that level. Nothing is dropped
    /// to make room: the frames a level packed stay in the prefix this returns.
    ///
    /// The 1200-byte floor of RFC 9000 §14.1 is a whole-datagram rule, and
    /// which level spends it is decided per call: a Handshake level with
    /// something to seal under its key — CRYPTO of its own, or a
    /// CONNECTION_CLOSE queued for it — fills what the Initial leaves, with the
    /// Initial kept back from the room that level needs, and otherwise the
    /// Initial pads itself to the floor. Either way a datagram that carries an
    /// Initial ends up at 1200 bytes or is not sent at all — the guard in
    /// `packSinglePacket` answers a packet that cannot reach its own target
    /// with nothing, before a packet number is taken, so a caller whose buffer
    /// is short of the floor keeps its flight whole. A datagram with no Initial
    /// in it has no floor to share, but that is conditional on the seal: with
    /// the Initial seal retained and nothing to send at that level, the
    /// Handshake behind it goes out as short as the flight needs it to, whereas
    /// a client whose Initial keys are gone has no such seal and its standalone
    /// Handshake keeps the whole 1200 target.
    ///
    /// The floor is the one rule that can stop a level that otherwise would go
    /// out: a budget short of 1200 leaves `packSinglePacket` refusing the
    /// Initial whole, so the levels above it are held rather than sent in a
    /// datagram that stays under the floor while the Initial CRYPTO they
    /// follow is still queued. At a budget that reaches the floor nothing is
    /// held, and a congestion-limited pass with Initial CRYPTO still queued
    /// makes progress at both levels.
    ///
    /// A server is held to the floor for the ack-eliciting Initial packets
    /// §14.1 names, and what this call can tell is what that Initial would
    /// carry (`initialCarriesOwnFrames`); one that would only be there because
    /// an ACK happens to be due is left as short as it has always been.
    ///
    /// Two errors are reachable, and on either the return carries no count,
    /// so the prefix of `out_buf` that is valid is unspecified and must be
    /// discarded. `error.OutOfMemory` comes from recording a packet that has
    /// already been written and encrypted: that packet's number is spent,
    /// its bytes are in the buffer nobody is told about, and its frames are
    /// gone from the queues. `error.NoSpaceLeft` comes from a write into a
    /// level's staging buffer that the per-frame size checks did not
    /// anticipate — the frames already packed at that level are lost the same
    /// way. `Connection` closes the connection on both, which is the only
    /// reason the frames are tolerable to lose.
    ///
    /// Everything else is borrowed for the duration of the call: the seals,
    /// the stream and crypto-stream maps, the frame queue, the datagram queue
    /// and the flow controller. `random` is the caller's generator and is
    /// never retained.
    pub fn packCoalesced(
        self: *PacketPacker,
        out_buf: []u8,
        pkt_handler: *ack_handler.PacketHandler,
        crypto_mgr: *crypto_stream.CryptoStreamManager,
        streams: *stream_mod.StreamsMap,
        pending_frames: *frame_mod.PendingFrameQueue,
        initial_seal: ?*const crypto_mod.Seal,
        early_seal: ?*const crypto_mod.Seal,
        handshake_seal: ?*const crypto_mod.Seal,
        app_seal: ?*const crypto_mod.Seal,
        now: i64,
        datagram_queue: ?*conn_mod.DatagramQueue,
        ack_only: bool,
        random: std.Random,
    ) !usize {
        // The whole datagram is one UDP payload, and `max_packet_size` is the
        // path's MTU — a number about datagrams, not about each packet in one.
        // So it is spent once, here, and every level below is offered what is
        // left of that one budget instead of a copy of it each. A level that
        // cannot reach the floor inside what is left writes nothing and leaves
        // its flight queued for a pass with the room, exactly as it already
        // does for a caller buffer that is short.
        const budget: usize = @min(self.max_packet_size, out_buf.len);
        const datagram = out_buf[0..budget];

        var offset: usize = 0;

        if (initial_seal != null) {
            // Which level spends this datagram's 1200-byte floor. The Handshake
            // level fills what the Initial leaves, and only a level with
            // something to seal under its own key will: an ACK it owes is
            // alarm-gated and may not be due this pass, and a queued PING is
            // the Initial's own control loop to write. A queued
            // CONNECTION_CLOSE is different — the Initial writes it and
            // requeues it for the levels above, so without it counted here an
            // Initial that spends the whole floor alone defers that close on
            // every pass, and a deferral that repeats forever is not a close
            // that goes out later.
            const later_flight = handshake_seal != null and
                (crypto_mgr.getStream(2).hasData() or closeQueued(pending_frames));
            // While the two share the floor, the room that level needs to be
            // sure of packing a CRYPTO frame is kept back from the Initial, so
            // the padding has somewhere to land whatever the Initial's own
            // length turns out to be.
            const later_room = laterLevelRoom(self.dcid_len, self.scid_len);
            // `max_packet_size` is not named in this call: `datagram` is
            // already capped by it, so a budget under the floor is settled
            // before the question is asked. The level that spends the floor
            // still has to be able to reach it.
            const share_floor = later_flight and datagram.len >= MIN_INITIAL_PACKET_SIZE and
                datagram.len > later_room;
            // A server's floor is on the ack-eliciting Initial packets
            // RFC 9000 §14.1 names, and what this call can tell is what that
            // Initial would carry; an Initial that would only be there
            // because an ACK happens to be due is left as short as it has
            // always been, and so is a datagram of nothing but it.
            const floor_obliged = !self.is_server or
                initialCarriesOwnFrames(crypto_mgr, pending_frames);
            const pad_target: usize = if (share_floor or !floor_obliged)
                0
            else
                MIN_INITIAL_PACKET_SIZE;
            const initial_len = try self.packSinglePacket(
                if (share_floor) datagram[0 .. datagram.len - later_room] else datagram,
                .initial,
                pkt_handler,
                crypto_mgr,
                streams,
                pending_frames,
                initial_seal.?,
                now,
                pad_target,
                null,
                false,
                ack_only,
                random,
            );
            offset += initial_len;
        }

        // The floor is what holds the levels above an Initial back, and only
        // when this datagram's budget cannot reach it: there
        // `packSinglePacket` refuses the Initial whole, so a Handshake packet
        // sent now would go out alone, in a datagram under the floor and with
        // the Initial CRYPTO it follows still queued. At a budget that reaches
        // the floor the Initial goes out, so nothing is held. Nothing is spent
        // while this holds: no packet number, no frame.
        const floor_short = datagram.len < MIN_INITIAL_PACKET_SIZE;
        const initial_owed = initial_seal != null and
            initialCarriesOwnFrames(crypto_mgr, pending_frames);
        const hold_later_levels = floor_short and initial_owed;

        // Try packing 0-RTT packet (Long Header, type 0x10)
        // If coalesced after a padded Initial, no extra padding needed (already >= 1200)
        if (!hold_later_levels and early_seal != null and offset < datagram.len and !ack_only) {
            const pad_target: usize = if (initial_seal != null and offset > 0)
                MIN_INITIAL_PACKET_SIZE -| offset
            else
                0;
            const early_len = try self.packSinglePacket(
                datagram[offset..],
                .application,
                pkt_handler,
                crypto_mgr,
                streams,
                pending_frames,
                early_seal.?,
                now,
                pad_target,
                datagram_queue,
                true, // zero_rtt = true
                false,
                random,
            );
            offset += early_len;
        }

        // Try packing Handshake packet
        // Padding logic: the coalesced datagram (Initial+Handshake) must reach 1200 bytes.
        // Both client and server pad the Handshake portion to fill the remainder.
        if (!hold_later_levels and handshake_seal != null and offset < datagram.len) {
            const hs_pad: usize = if (offset > 0)
                MIN_INITIAL_PACKET_SIZE -| offset // Coalesced after Initial: pad remainder
            else if (!self.is_server and initial_seal == null)
                MIN_INITIAL_PACKET_SIZE // Standalone client Handshake: full pad
            else
                0;
            const hs_len = try self.packSinglePacket(
                datagram[offset..],
                .handshake,
                pkt_handler,
                crypto_mgr,
                streams,
                pending_frames,
                handshake_seal.?,
                now,
                hs_pad,
                null,
                false,
                ack_only,
                random,
            );
            offset += hs_len;
        }

        // Try packing 1-RTT packet
        if (app_seal != null and offset < datagram.len) {
            const app_len = try self.packSinglePacket(
                datagram[offset..],
                .application,
                pkt_handler,
                crypto_mgr,
                streams,
                pending_frames,
                app_seal.?,
                now,
                0,
                datagram_queue,
                false,
                ack_only,
                random,
            );
            offset += app_len;
        }

        return offset;
    }

    /// Pack a single packet at the given encryption level.
    /// Returns the total packet size including header, encrypted payload, and AEAD tag.
    /// When zero_rtt=true, packs a 0-RTT Long Header packet (type 0x10) with only STREAM/DATAGRAM frames.
    /// When ack_only=true, skips stream and datagram frames (used when congestion-limited).
    ///
    /// Writes one packet at `offset` in `buf` and returns its length, or zero
    /// when the level had nothing to say. Zero gives back the packet number
    /// this level took and records nothing, so an empty poll costs no packet
    /// number and does not push the PTO out.
    ///
    /// A frame it cannot record or cannot fit is re-queued rather than sent
    /// untracked, and the packet is built in a fixed 1500-byte staging buffer
    /// so the plaintext never lands in `buf`. `pad_target` pads this packet
    /// toward a size — RFC 9000 §14.1's 1200 for the Initial and Handshake
    /// levels — and is ignored at 1-RTT, where a short packet is short.
    ///
    /// Every write into the staging buffer, padding included, is bounded by
    /// `effective_max`: the smaller of `max_packet_size`, the staging array,
    /// and `buf` less one AEAD tag — the tag lands after the last plaintext
    /// byte, which is what keeps the encrypted result inside `buf`. A
    /// `pad_target` that budget cannot reach is not a shorter packet: the
    /// guard above answers zero instead, before a packet number is taken and
    /// before a frame leaves its queue, so that flight stays whole rather than
    /// going out under the floor.
    fn packSinglePacket(
        self: *PacketPacker,
        buf: []u8,
        level: ack_handler.EncLevel,
        pkt_handler: *ack_handler.PacketHandler,
        crypto_mgr: *crypto_stream.CryptoStreamManager,
        streams: *stream_mod.StreamsMap,
        pending_frames: *frame_mod.PendingFrameQueue,
        seal: *const crypto_mod.Seal,
        now: i64,
        pad_target: usize, // 0 = no padding, >0 = target packet size for this packet
        datagram_queue: ?*conn_mod.DatagramQueue,
        zero_rtt: bool,
        ack_only: bool,
        random: std.Random,
    ) !usize {
        // We build the packet in a temporary buffer, then encrypt into buf
        var tmp: [ABSOLUTE_MAX_PACKET_SIZE]u8 = undefined;
        // Account for output buffer size: encrypted output = fbs.seek + AEAD_TAG_LEN
        const effective_max = @min(self.max_packet_size, @min(tmp.len, buf.len -| AEAD_TAG_LEN));

        const pkt_type = if (zero_rtt)
            packet_mod.PacketType.zero_rtt
        else switch (level) {
            .initial => packet_mod.PacketType.initial,
            .handshake => packet_mod.PacketType.handshake,
            .application => packet_mod.PacketType.one_rtt,
        };

        // Check the staging budget before spending a packet number or frame.
        // RFC 9001 §5.4.2 places the 16-byte protection sample four bytes past
        // the packet-number offset. Reserve the longest encoded packet number
        // and four plaintext bytes, with the AEAD tag outside effective_max.
        const header_len = switch (pkt_type) {
            .one_rtt => 1 + self.dcid_len,
            else => 1 + 4 + (1 + self.dcid_len) + (1 + self.scid_len) +
                if (pkt_type == .initial)
                    if (self.initial_token) |t| packet_mod.varIntLength(t.len) + t.len else 1
                else
                    0,
        };
        const length_len: usize = if (pkt_type == .one_rtt) 0 else 2;
        const min_packet_plaintext = header_len + length_len + 4 + 4;
        if (buf.len < 64 or effective_max < min_packet_plaintext) return 0;
        const packet_pad_target = if (pkt_type == .one_rtt)
            @max(pad_target, self.application_padding_min)
        else
            pad_target;

        // RFC 9000 §14.1: a datagram carrying a client's Initial is expanded to
        // 1200 bytes, so a buffer that cannot reach the target this packet
        // exists to reach holds no datagram a peer is obliged to accept.
        // Padding toward a target the budget cannot reach is not a shorter
        // valid datagram; it is one every peer may drop, carrying a ClientHello
        // that then goes nowhere.
        if (packet_pad_target > 0 and effective_max + AEAD_TAG_LEN < packet_pad_target) return 0;

        var fbs = io.fixedBufferStream(tmp[0..effective_max]);
        const writer = &fbs;

        // Get packet number and encode it
        const pn = pkt_handler.nextPacketNumber(level, random);
        const largest_acked = pkt_handler.getLargestAcked(level);
        var pn_buf: [4]u8 = undefined;
        const pn_len = crypto_mod.encodePacketNumber(pn, largest_acked, &pn_buf);

        // Write header
        const header_start: usize = 0;

        var length_offset: usize = 0; // where the payload length field is (long headers only)

        if (pkt_type == .one_rtt) {
            // Short header: 1 byte + DCID
            var first_byte: u8 = packet_mod.FIXED_BIT;
            if (self.key_phase) first_byte |= packet_mod.KEY_PHASE_BIT;
            if (self.spin_bit) first_byte |= packet_mod.PACKET_SPIN_BIT;
            first_byte |= @as(u8, @intCast(pn_len - 1));
            try writer.writeByte(first_byte);
            try writer.writeAll(self.getDcid());
        } else {
            // Long header. A 0-RTT packet keeps the version of the first
            // flight: RFC 9369 §4.1 forbids sending it under the negotiated
            // version even after the client has learned one, and the version
            // field here is what the server reads those packets under.
            const header_version = if (zero_rtt) self.original_version else self.version;
            var first_byte: u8 = packet_mod.encodeLongHeaderTypeBits(pkt_type, header_version);
            first_byte |= @as(u8, @intCast(pn_len - 1));
            try writer.writeByte(first_byte);
            try writer.writeInt(u32, header_version, .big);

            try writer.writeByte(@intCast(self.getDcid().len));
            try writer.writeAll(self.getDcid());
            try writer.writeByte(@intCast(self.getScid().len));
            try writer.writeAll(self.getScid());

            // Token (Initial only)
            if (pkt_type == .initial) {
                if (self.initial_token) |token| {
                    try packet_mod.writeVarInt(writer, token.len);
                    try writer.writeAll(token);
                } else {
                    try packet_mod.writeVarInt(writer, 0);
                }
            }

            // Payload length placeholder - use 2-byte varint (can hold up to 16383)
            length_offset = fbs.seek;
            try writer.writeInt(u16, 0, .big); // placeholder
        }

        // Write packet number
        const pn_offset = fbs.seek;
        try writer.writeAll(pn_buf[0..pn_len]);

        // Record where the plaintext payload starts
        const payload_start = fbs.seek;

        // Collect frames
        var ack_eliciting = false;
        var has_crypto_data = false;
        var has_handshake_done = false;

        // Track the largest_ack we send in this packet's ACK frame (for ACK-of-ACK pruning)
        var ack_largest_sent: ?u64 = null;

        // Control frames to repeat if this packet is lost (RFC 9000 13.3).
        var control_frames: [ack_handler.MAX_CONTROL_FRAMES_PER_PACKET]ack_handler.SentControlFrame = undefined;
        var control_frame_count: u8 = 0;

        // 0-RTT packets only contain STREAM and DATAGRAM frames — skip ACK, CRYPTO, control
        if (!zero_rtt) {
            // 1. ACK frame (always first if pending)
            // Force ACK generation only when it can piggyback on non-ACK data.
            // ACK-only packets bypass congestion control; forcing one on every
            // congestion-limited poll can create an ACK-only send loop that
            // never drains bytes_in_flight or returns quiescent state to the
            // application. In ack_only mode, honor the normal ACK queue/alarm.
            const ack_delay_exp: u64 = 3;
            const ack_frame_opt: ?Frame = if (!ack_only and pkt_handler.hasUnackedAckEliciting(level))
                pkt_handler.getAckFrameForced(level, now, ack_delay_exp)
            else
                pkt_handler.getAckFrame(level, now, ack_delay_exp);
            if (ack_frame_opt) |ack_frame| {
                // Record the largest_ack for ACK-of-ACK pruning (RFC 9000 §13.2.4)
                switch (ack_frame) {
                    .ack => |a| ack_largest_sent = a.largest_ack,
                    .ack_ecn => |a| ack_largest_sent = a.largest_ack,
                    else => {},
                }
                const wire_ack: Frame = if (pkt_type == .one_rtt)
                    if (self.application_path_id) |path_id|
                        switch (ack_frame) {
                            .ack => |a| .{ .path_ack = .{ .path_id = path_id, .ack = a } },
                            .ack_ecn => |a| .{ .path_ack_ecn = .{ .path_id = path_id, .ack = a } },
                            else => ack_frame,
                        }
                    else
                        ack_frame
                else
                    ack_frame;
                try wire_ack.write(writer);
            }

            // 2. CRYPTO frames
            const crypto_level_idx: u8 = switch (level) {
                .initial => 0,
                .handshake => 2,
                .application => 3,
            };
            const cs = crypto_mgr.getStream(crypto_level_idx);
            // Saturating: a level whose staging room is under a tag plus the
            // write headroom has none, and subtracting must not wrap into a
            // large budget the room check below would then believe.
            const remaining_space = effective_max -| (fbs.seek + AEAD_TAG_LEN + 4);
            // Checked first: past the handshake there is never any, and building
            // the 576-byte ?Frame to say so cost 5.6% of the 10 KB HTTP/3 row.
            if (remaining_space > 0 and cs.hasData()) {
                if (cs.popCryptoFrame(remaining_space)) |crypto_frame| {
                    try crypto_frame.write(writer);
                    ack_eliciting = true;
                    has_crypto_data = true;
                }
            }

            // 2b. PING and CONNECTION_CLOSE for Initial/Handshake packets
            // PING: PTO probes need ack-eliciting frames (RFC 9002 §6.2.4)
            // CONNECTION_CLOSE: valid at all levels (RFC 9000 §10.2.3)
            //
            // Scratch-encoded and room-checked like the 1-RTT loop below: a
            // frame this packet cannot hold waits for the next one rather than
            // being written past the packet's own budget — or lost with the
            // packet when the staging buffer has no room left for it.
            if (level == .initial or level == .handshake) {
                var remaining_pf = pending_frames.len;
                while (remaining_pf > 0) : (remaining_pf -= 1) {
                    const pcf = pending_frames.pop() orelse break;
                    const wanted_here = switch (pcf) {
                        // A packet that is already ack-eliciting needs no
                        // second PING to say so.
                        .ping => !ack_eliciting,
                        .connection_close => true,
                        // Other control frames go in 1-RTT.
                        else => false,
                    };
                    if (!wanted_here) {
                        pending_frames.requeue(pcf);
                        continue;
                    }
                    var scratch: [256]u8 = undefined;
                    var scratch_fbs = io.fixedBufferStream(&scratch);
                    pcf.write(&scratch_fbs) catch {
                        pending_frames.requeue(pcf);
                        continue;
                    };
                    const encoded = scratch_fbs.buffered();
                    if (fbs.seek + encoded.len + AEAD_TAG_LEN > effective_max) {
                        pending_frames.requeue(pcf);
                        continue;
                    }
                    try writer.writeAll(encoded);
                    switch (pcf) {
                        // Keep CONNECTION_CLOSE for the higher encryption levels
                        // too (RFC 9000 §10.2.3: send at all available levels).
                        // And leave the packet's accounting alone: a close is
                        // not what makes a packet ack-eliciting (RFC 9000
                        // §13.2.1, which `Frame.isAckEliciting` says the same
                        // way) — CRYPTO or a PING above already has.
                        .connection_close => pending_frames.requeue(pcf),
                        else => ack_eliciting = true,
                    }
                }
            }

            // 3. HANDSHAKE_DONE frame (server only, 1-RTT)
            // Sent once per trigger (initial handshake completion or PTO/loss re-arm).
            // Connection clears send_handshake_done after packing to prevent flooding
            // the CC window with HANDSHAKE_DONE-only packets in burst loops.
            // Skip when ack_only (congestion-limited).
            if (level == .application and self.send_handshake_done and !ack_only) {
                try writer.writeByte(0x1e); // HANDSHAKE_DONE frame type
                has_handshake_done = true;
                ack_eliciting = true;
                self.send_handshake_done = false; // One-shot: PTO/loss will re-arm
            }

            // 4. Pending control frames (only in 1-RTT)
            // PATH_CHALLENGE/PATH_RESPONSE are always sent (path probing is exempt from CC).
            // Receiver-credit frames must also be allowed through the congestion-limited
            // path: otherwise a small control packet can fill cwnd and prevent MAX_DATA
            // from unblocking a peer that is already stuck at the connection window.
            if (level == .application) {
                var remaining = pending_frames.len;
                while (remaining > 0) : (remaining -= 1) {
                    const pcf = pending_frames.pop() orelse break;
                    const is_urgent_control = switch (pcf) {
                        .path_challenge, .path_response => true,
                        .max_data, .max_stream_data, .max_streams_bidi, .max_streams_uni => true,
                        else => false,
                    };
                    if (!is_urgent_control and ack_only) {
                        // Re-queue non-probing frames when congestion-limited
                        pending_frames.requeue(pcf);
                        continue;
                    }
                    // A frame this packet cannot record, or has no room for,
                    // waits for the next one rather than going out untracked.
                    const record: ?ack_handler.SentControlFrame = switch (pcf) {
                        // Null selects legacy protection; multipath supplies
                        // the carrying path ID, including an explicit path zero.
                        .observed_address => .{ .observed_address = self.application_path_id orelse 0 },
                        else => ack_handler.SentControlFrame.from(pcf),
                    };
                    if (record != null and control_frame_count == control_frames.len) {
                        pending_frames.requeue(pcf);
                        continue;
                    }
                    var scratch: [256]u8 = undefined;
                    var scratch_fbs = io.fixedBufferStream(&scratch);
                    // Requeued, not dropped: the frame is already out of the
                    // queue, and every variant encodes below this scratch
                    // today, so the write is not expected to fail — but a
                    // frame this packet cannot encode must still wait for the
                    // next one rather than vanish from the connection.
                    pcf.write(&scratch_fbs) catch {
                        pending_frames.requeue(pcf);
                        continue;
                    };
                    const encoded = scratch_fbs.buffered();
                    if (fbs.seek + encoded.len + AEAD_TAG_LEN > effective_max) {
                        pending_frames.requeue(pcf);
                        continue;
                    }
                    try writer.writeAll(encoded);
                    // RFC 9000 §13.2.1: what is in the packet decides. ACK,
                    // PADDING and CONNECTION_CLOSE are the only exclusions,
                    // and this loop writes neither of the first two, so the
                    // close — in either form — is the one frame here that
                    // leaves the packet non-ack-eliciting. The Initial and
                    // Handshake loop above keeps it out of the accounting for
                    // the same reason. Everything else here still owes the
                    // peer an ACK, NEW_TOKEN included: Table 3's Spec column
                    // for 0x07 is empty, and `Frame.isAckEliciting` answers
                    // the same way.
                    switch (pcf) {
                        .connection_close => {},
                        else => ack_eliciting = true,
                    }
                    if (record) |r| {
                        control_frames[control_frame_count] = r;
                        control_frame_count += 1;
                    }
                }
            }
        }

        // 5. Stream frames (only in 1-RTT or 0-RTT, skip when ack_only)
        // Track stream frames for retransmission on loss
        var stream_frame_infos: [ack_handler.MAX_STREAM_FRAMES_PER_PACKET]ack_handler.StreamFrameInfo = undefined;
        var stream_frame_info_count: u8 = 0;

        if (level == .application and !ack_only) {
            // Connection-level flow control budget for this packet
            var conn_budget: u64 = if (self.conn_flow_ctrl) |cfc| cfc.sendWindowSize() else std.math.maxInt(u64);

            // Bidirectional streams — scheduled by RFC 9218 priority
            var sched_buf: [stream_mod.StreamsMap.MAX_SCHEDULABLE]*stream_mod.Stream = undefined;
            const sched_count = streams.getScheduledStreams(&sched_buf);
            for (sched_buf[0..sched_count]) |s| {
                if (fbs.seek + AEAD_TAG_LEN + 16 >= effective_max) break;
                const retransmitting = s.send.hasRetransmitData();
                if (conn_budget == 0 and !retransmitting) continue;
                if (stream_frame_info_count >= ack_handler.MAX_STREAM_FRAMES_PER_PACKET) break;
                const remaining = effective_max - fbs.seek - AEAD_TAG_LEN;
                const header_overhead = streamFrameHeaderOverhead(s.send.stream_id, s.send.send_offset, remaining);
                if (remaining <= header_overhead) break;
                const max_stream_data = if (retransmitting)
                    remaining - header_overhead
                else
                    @min(remaining - header_overhead, conn_budget);
                const prev_send_offset = s.send.send_offset;
                if (s.send.popStreamFrame(max_stream_data)) |stream_frame| {
                    try stream_frame.write(writer);
                    ack_eliciting = true;
                    if (stream_frame.stream.fin) streams.closeIfDone(s);
                    // Only count NEW data against connection flow control (not retransmissions)
                    const new_bytes = s.send.send_offset - prev_send_offset;
                    if (new_bytes > 0) {
                        conn_budget -= @min(conn_budget, new_bytes);
                        if (self.conn_flow_ctrl) |cfc| cfc.base.addBytesSent(new_bytes);
                    }
                    // Record for retransmission tracking
                    stream_frame_infos[stream_frame_info_count] = .{
                        .stream_id = stream_frame.stream.stream_id,
                        .offset = stream_frame.stream.offset,
                        .length = stream_frame.stream.length,
                        .fin = stream_frame.stream.fin,
                    };
                    stream_frame_info_count += 1;
                }
            }

            // Unidirectional send streams (priority-scheduled)
            var uni_sched_buf: [stream_mod.StreamsMap.MAX_SCHEDULABLE]*stream_mod.SendStream = undefined;
            const uni_sched_count = streams.getScheduledUniStreams(&uni_sched_buf);
            if (uni_sched_count > 0) {
                for (uni_sched_buf[0..uni_sched_count]) |s| {
                    if (fbs.seek + AEAD_TAG_LEN + 16 >= effective_max) break;
                    const retransmitting = s.hasRetransmitData();
                    if (conn_budget == 0 and !retransmitting) continue;
                    if (stream_frame_info_count >= ack_handler.MAX_STREAM_FRAMES_PER_PACKET) break;
                    const remaining_uni = effective_max - fbs.seek - AEAD_TAG_LEN;
                    const uni_header_overhead = streamFrameHeaderOverhead(s.stream_id, s.send_offset, remaining_uni);
                    if (remaining_uni <= uni_header_overhead) break;
                    const max_stream_data = if (retransmitting)
                        remaining_uni - uni_header_overhead
                    else
                        @min(remaining_uni - uni_header_overhead, conn_budget);
                    const prev_uni_offset = s.send_offset;
                    if (s.popStreamFrame(max_stream_data)) |stream_frame| {
                        try stream_frame.write(writer);
                        ack_eliciting = true;
                        // Only count NEW data against connection flow control
                        const new_bytes_uni = s.send_offset - prev_uni_offset;
                        if (new_bytes_uni > 0) {
                            conn_budget -= @min(conn_budget, new_bytes_uni);
                            if (self.conn_flow_ctrl) |cfc| cfc.base.addBytesSent(new_bytes_uni);
                        }
                        // Record for retransmission tracking
                        stream_frame_infos[stream_frame_info_count] = .{
                            .stream_id = stream_frame.stream.stream_id,
                            .offset = stream_frame.stream.offset,
                            .length = stream_frame.stream.length,
                            .fin = stream_frame.stream.fin,
                        };
                        stream_frame_info_count += 1;
                    }
                }
            } // send_streams.count() > 0

        }

        // 6. DATAGRAM frames (RFC 9221) — subject to congestion control (RFC 9221 §5)
        // Only pack datagrams when CC allows (i.e. not in ack_only mode).
        var has_datagram = false;
        if (level == .application and !ack_only) {
            if (datagram_queue) |dq| {
                while (true) {
                    // Zero-copy peek: read directly from ring buffer without
                    // copying to an intermediate stack buffer.
                    const dgram_data = dq.peekDataSkipExpired(now) orelse break;
                    // DATAGRAM_WITH_LENGTH frame: type(1) + varint(len) + payload
                    const varint_overhead: usize = if (dgram_data.len <= 63) 1 else 2;
                    const frame_size = 1 + varint_overhead + dgram_data.len;
                    if (fbs.seek + frame_size + AEAD_TAG_LEN > effective_max) break;
                    const dgram_frame = Frame{ .datagram_with_length = .{
                        .data = dgram_data,
                    } };
                    try dgram_frame.write(writer);
                    dq.consume();
                    ack_eliciting = true;
                    has_datagram = true;
                }
            }
        }

        // Note: RFC 9002 loss detection deadlock prevention is handled by the PTO
        // mechanism in ack_handler.zig, which sends PING probes when the PTO timer
        // fires. No need to inject PINGs into every ACK-only packet here — doing so
        // creates an ACK amplification loop (ACK+PING → server ACKs → client ACK+PING → ...).

        // Check if we have any payload
        const payload_len = fbs.seek - payload_start;
        if (payload_len == 0) {
            // Roll back the packet number we consumed — no packet will be sent.
            // This applies even with pad_target > 0: sending a padded Initial with
            // no ACK/CRYPTO content just wastes PNs and pushes the PTO forward.
            const idx = @backingInt(level);
            pkt_handler.next_pn[idx] -= 1;
            return 0; // Nothing to send
        }

        // RFC 9001 §5.4.2: the header protection sample starts 4 bytes after
        // the PN offset, so the plaintext carries at least 4 bytes whatever
        // the packet number's encoded length. Bounded by `effective_max`
        // like every other write into the staging buffer, so a short
        // `out_buf` cannot turn the minimum into an overrun.
        const min_plaintext: usize = 4;
        if (payload_len < min_plaintext) {
            const min_pad = @min(min_plaintext - payload_len, effective_max - fbs.seek);
            @memset(tmp[fbs.seek..][0..min_pad], 0x00);
            fbs.seek += min_pad;
        }

        // Validation challenges carry the same full-datagram minimum as the
        // long-header targets. The guard above refuses an unreachable target
        // before consuming either a packet number or the challenge frame.
        if (packet_pad_target > 0) {
            const current_total = fbs.seek - header_start + AEAD_TAG_LEN;
            if (current_total < packet_pad_target) {
                const pad_needed = packet_pad_target - current_total;
                @memset(tmp[fbs.seek..][0..pad_needed], 0x00);
                fbs.seek += pad_needed;
            }
        }

        // The plaintext payload is tmp[payload_start..fbs.seek]
        const plaintext_payload = tmp[payload_start..fbs.seek];
        const header_bytes = tmp[header_start..payload_start];

        // Fill in the payload length field for long headers
        // Length = pn_len + plaintext_payload.len + AEAD_TAG_LEN
        if (pkt_type != .one_rtt) {
            const total_payload_len: u16 = @intCast(pn_len + plaintext_payload.len + AEAD_TAG_LEN);
            // Encode as 2-byte varint (set high 2 bits to 01)
            std.mem.writeInt(u16, tmp[length_offset..][0..2], total_payload_len | (0x40 << 8), .big);
        }

        // Copy header to output buffer
        const out_header = buf[header_start..][0..header_bytes.len];
        @memcpy(out_header, header_bytes);

        // Copy packet number to output buffer
        @memcpy(buf[pn_offset..][0..pn_len], pn_buf[0..pn_len]);

        // Encrypt payload into output buffer (after pn)
        const encrypted_start = pn_offset + pn_len;
        // RFC 9001 Section 5.2: AD is the header up to and including the packet number field
        const ad = buf[header_start..][0..(pn_offset - header_start + pn_len)];
        const encrypted_len = if (pkt_type == .one_rtt)
            if (self.application_path_id) |path_id|
                seal.encryptPayloadForPath(path_id, pn, ad, plaintext_payload, buf[encrypted_start..])
            else
                seal.encryptPayload(pn, ad, plaintext_payload, buf[encrypted_start..])
        else
            seal.encryptPayload(pn, ad, plaintext_payload, buf[encrypted_start..]);

        const total_packet_len = encrypted_start + encrypted_len;

        // Apply header protection (uses cached AES HP context when available)
        seal.applyHeaderProtection(
            buf[header_start..total_packet_len],
            pn_offset - header_start,
            pn_len,
        );

        // Record the packet as sent, including stream frame info for retransmission
        var sent_pkt = ack_handler.SentPacket{
            .pn = pn,
            .time_sent = now,
            .size = @intCast(total_packet_len),
            .ack_eliciting = ack_eliciting,
            .in_flight = ack_eliciting,
            .enc_level = level,
            .has_crypto_data = has_crypto_data,
            .has_handshake_done = has_handshake_done,
            .has_datagram = has_datagram,
            .ecn_marked = level == .application and self.ecn_mark,
            .largest_acked = ack_largest_sent,
        };
        // Copy stream frame records into the SentPacket
        for (stream_frame_infos[0..stream_frame_info_count]) |info| {
            sent_pkt.addStreamFrame(info);
        }
        @memcpy(sent_pkt.control_frames[0..control_frame_count], control_frames[0..control_frame_count]);
        sent_pkt.control_frame_count = control_frame_count;
        try pkt_handler.onPacketSent(sent_pkt);

        return total_packet_len;
    }

    /// Pack an MTU probe packet (1-RTT PING + PADDING to target size).
    /// Returns the total bytes written and the packet number used.
    /// `random` is the same generator the coalesced path draws from, so a probe
    /// and the data packets around it share one skip schedule.
    ///
    /// `target_size` is the datagram size being probed for, in bytes, and is
    /// clamped to 1500 — the staging buffer's own length — so a target above
    /// that probes 1500, writes 1500 and reports 1500 in `bytes_written`,
    /// rather than failing. `buf` is checked against the clamped size, not
    /// the requested one: a 1500-byte buffer serves a 1600-byte request.
    ///
    /// The short answer: when `buf` cannot hold the clamped size, or that
    /// size is under 64, the result is `{ 0, 0 }`. That path takes no packet
    /// number, records no packet, and writes nothing — a caller that treats a
    /// zero `pn` as a real one would probe packet number zero.
    ///
    /// On success the packet is a 1-RTT PING padded to the clamped size, is
    /// recorded as sent and in flight, and `pn` is the number it used. A lost
    /// probe is handled by the ordinary loss path, so the caller does not
    /// have to distinguish it. A caller that learns the path MTU from the
    /// return must use `bytes_written`, which is the clamped size, rather than
    /// the `target_size` it asked for.
    ///
    /// `error.NoSpaceLeft` from a header write the sizing did not anticipate,
    /// which happens before anything is encrypted. `error.OutOfMemory` comes
    /// from recording the probe, and that one comes after the packet is fully
    /// written into `buf`: the bytes are there, the packet is not recorded,
    /// and the caller has no count to find them by.
    pub fn packMtuProbe(
        self: *PacketPacker,
        buf: []u8,
        target_size: usize,
        pkt_handler: *ack_handler.PacketHandler,
        seal: *const crypto_mod.Seal,
        now: i64,
        random: std.Random,
    ) !struct { bytes_written: usize, pn: u64 } {
        // Clamped first, then checked against `buf`, so the bound the caller
        // has to satisfy and the size actually probed are the same number.
        const probe_size = @min(target_size, ABSOLUTE_MAX_PACKET_SIZE);
        if (buf.len < probe_size or probe_size < 64) return .{ .bytes_written = 0, .pn = 0 };

        var tmp: [ABSOLUTE_MAX_PACKET_SIZE]u8 = undefined;
        const effective_max = probe_size;
        var fbs = io.fixedBufferStream(tmp[0..effective_max]);
        const writer = &fbs;

        const pn = pkt_handler.nextPacketNumber(.application, random);
        const largest_acked = pkt_handler.getLargestAcked(.application);
        var pn_buf: [4]u8 = undefined;
        const pn_len = crypto_mod.encodePacketNumber(pn, largest_acked, &pn_buf);

        // Short header (1-RTT)
        var first_byte: u8 = packet_mod.FIXED_BIT;
        if (self.key_phase) first_byte |= packet_mod.KEY_PHASE_BIT;
        if (self.spin_bit) first_byte |= packet_mod.PACKET_SPIN_BIT;
        first_byte |= @as(u8, @intCast(pn_len - 1));
        try writer.writeByte(first_byte);
        try writer.writeAll(self.getDcid());

        const pn_offset = fbs.seek;
        try writer.writeAll(pn_buf[0..pn_len]);

        const payload_start = fbs.seek;

        // PING frame (makes it ACK-eliciting)
        try packet_mod.writeVarInt(writer, 0x01);

        // Fill remaining space with PADDING to reach the clamped probe size,
        // which is what makes `bytes_written` the size actually sent.
        const overhead = payload_start + AEAD_TAG_LEN;
        if (probe_size > overhead) {
            const pad_needed = probe_size - overhead - (fbs.seek - payload_start);
            @memset(tmp[fbs.seek..][0..pad_needed], 0x00);
            fbs.seek += pad_needed;
        }

        const plaintext_payload = tmp[payload_start..fbs.seek];
        const header_bytes = tmp[0..payload_start];

        // Copy header
        @memcpy(buf[0..header_bytes.len], header_bytes);
        @memcpy(buf[pn_offset..][0..pn_len], pn_buf[0..pn_len]);

        // Encrypt
        const encrypted_start = pn_offset + pn_len;
        const ad = buf[0..(pn_offset + pn_len)];
        const encrypted_len = if (self.application_path_id) |path_id|
            seal.encryptPayloadForPath(path_id, pn, ad, plaintext_payload, buf[encrypted_start..])
        else
            seal.encryptPayload(pn, ad, plaintext_payload, buf[encrypted_start..]);
        const total_len = encrypted_start + encrypted_len;

        // Apply header protection (uses cached AES HP context when available)
        seal.applyHeaderProtection(buf[0..total_len], pn_offset, pn_len);

        // Record as sent (in_flight but special — caller handles probe loss separately)
        try pkt_handler.onPacketSent(.{
            .pn = pn,
            .time_sent = now,
            .size = @intCast(total_len),
            .ack_eliciting = true,
            .in_flight = true,
            .enc_level = .application,
        });

        return .{ .bytes_written = total_len, .pn = pn };
    }
};

// Tests

/// A generator a test owns, seeded so the packet-number skip schedule a run
/// produces is the same twice. Nothing here reaches for the process CSPRNG.
const TestRandom = struct {
    prng: std.Random.DefaultPrng = .init(0x7061636b),

    fn random(self: *@This()) std.Random {
        return self.prng.random();
    }
};

test "PacketPacker: basic init" {
    const scid = &[_]u8{ 0x01, 0x02, 0x03, 0x04 };
    const dcid = &[_]u8{ 0x05, 0x06, 0x07, 0x08 };
    const packer = PacketPacker.init(
        false,
        scid,
        dcid,
        0x00000001,
    );
    try testing.expectEqualSlices(u8, scid, packer.getScid());
    try testing.expectEqualSlices(u8, dcid, packer.getDcid());
}

test "PacketPacker: updateDcid" {
    const scid = &[_]u8{ 0x01, 0x02, 0x03, 0x04 };
    const dcid = &[_]u8{ 0x05, 0x06, 0x07, 0x08 };
    var packer = PacketPacker.init(false, scid, dcid, 0x00000001);
    const new_dcid = &[_]u8{ 0xAA, 0xBB, 0xCC };
    packer.updateDcid(new_dcid);
    try testing.expectEqualSlices(u8, new_dcid, packer.getDcid());
}

// Helper: derive Initial crypto keys for packer tests (client side)
fn testClientKeys() !struct { seal: crypto_mod.Seal, open: crypto_mod.Open } {
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const keys = try crypto_mod.deriveInitialKeyMaterial(&dcid, 0x00000001, false);
    return .{ .seal = keys[1], .open = keys[0] };
}

// Helper: derive Initial crypto keys for packer tests (server side)
fn testServerKeys() !struct { seal: crypto_mod.Seal, open: crypto_mod.Open } {
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const keys = try crypto_mod.deriveInitialKeyMaterial(&dcid, 0x00000001, true);
    return .{ .seal = keys[1], .open = keys[0] };
}

test "PacketPacker: pack Initial with CRYPTO data" {
    var rng = TestRandom{};
    // Setup: client packer with Initial keys and CRYPTO data to send
    const scid = &[_]u8{0x01};
    const dcid = &[_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    var packer = PacketPacker.init(false, scid, dcid, 0x00000001);

    var pkt_handler = ack_handler.PacketHandler.init(testing.allocator);
    defer pkt_handler.deinit();

    var crypto_mgr = crypto_stream.CryptoStreamManager.init(testing.allocator);
    defer crypto_mgr.deinit();

    var streams = stream_mod.StreamsMap.init(testing.allocator, false);
    defer streams.deinit();

    var pending_frames = frame_mod.PendingFrameQueue{};

    // Write some CRYPTO data (simulates ClientHello)
    const crypto_data = "test ClientHello data for packer";
    try crypto_mgr.getStream(0).writeData(crypto_data);

    const keys = try testClientKeys();

    var out_buf: [1500]u8 = undefined;
    const written = try packer.packCoalesced(
        &out_buf,
        &pkt_handler,
        &crypto_mgr,
        &streams,
        &pending_frames,
        &keys.seal, // initial_seal
        null, // early_seal
        null, // handshake_seal
        null, // app_seal
        1000,
        null, // datagram_queue
        false, // ack_only
        rng.random(),
    );

    // Client Initial packets MUST be >= 1200 bytes (RFC 9000 §14.1)
    try testing.expect(written >= MIN_INITIAL_PACKET_SIZE);

    // Verify it's a Long Header Initial packet (high bit set, form bit set)
    try testing.expect(out_buf[0] & 0x80 != 0); // Long header

    // Verify packet was tracked
    try testing.expectEqual(@as(u64, 1), pkt_handler.next_pn[0]); // Used PN 0

    // Verify sent packet was recorded
    try testing.expectEqual(@as(usize, 1), pkt_handler.sent[0].sent_packets.count());
}

test "PacketPacker: pack 1-RTT with stream data" {
    var rng = TestRandom{};
    const scid = &[_]u8{0x01};
    const dcid = &[_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    var packer = PacketPacker.init(false, scid, dcid, 0x00000001);

    var pkt_handler = ack_handler.PacketHandler.init(testing.allocator);
    defer pkt_handler.deinit();

    var crypto_mgr = crypto_stream.CryptoStreamManager.init(testing.allocator);
    defer crypto_mgr.deinit();

    var streams = stream_mod.StreamsMap.init(testing.allocator, false);
    defer streams.deinit();

    var pending_frames = frame_mod.PendingFrameQueue{};

    // Create a stream and write data
    streams.setMaxStreams(10, 10);
    streams.setPeerInitialMaxStreamData(65536, 65536, 65536);
    const s = try streams.openBidiStream();
    try s.send.writeData("Hello from stream");

    const keys = try testClientKeys();

    var out_buf: [1500]u8 = undefined;
    const written = try packer.packCoalesced(
        &out_buf,
        &pkt_handler,
        &crypto_mgr,
        &streams,
        &pending_frames,
        null, // no initial
        null, // no early
        null, // no handshake
        &keys.seal, // app_seal
        1000,
        null,
        false,
        rng.random(),
    );

    // Should have produced a packet with stream data
    try testing.expect(written > 0);

    // Verify it's a Short Header (1-RTT) packet (high bit clear)
    try testing.expect(out_buf[0] & 0x80 == 0);

    // Verify sent packet tracking
    const app_idx = @backingInt(ack_handler.EncLevel.application);
    try testing.expectEqual(@as(usize, 1), pkt_handler.sent[app_idx].sent_packets.count());
}

test "PacketPacker: no data produces no packet" {
    var rng = TestRandom{};
    const scid = &[_]u8{0x01};
    const dcid = &[_]u8{0x02};
    var packer = PacketPacker.init(false, scid, dcid, 0x00000001);

    var pkt_handler = ack_handler.PacketHandler.init(testing.allocator);
    defer pkt_handler.deinit();

    var crypto_mgr = crypto_stream.CryptoStreamManager.init(testing.allocator);
    defer crypto_mgr.deinit();

    var streams = stream_mod.StreamsMap.init(testing.allocator, false);
    defer streams.deinit();

    var pending_frames = frame_mod.PendingFrameQueue{};

    const keys = try testClientKeys();

    var out_buf: [1500]u8 = undefined;
    // No crypto data, no stream data, no ACKs — should produce nothing
    const written = try packer.packCoalesced(
        &out_buf,
        &pkt_handler,
        &crypto_mgr,
        &streams,
        &pending_frames,
        &keys.seal, // initial_seal
        null,
        null,
        null,
        1000,
        null,
        false,
        rng.random(),
    );

    try testing.expectEqual(@as(usize, 0), written);
}

test "PacketPacker: ack_only skips stream data but sends receiver credit" {
    var rng = TestRandom{};
    const scid = &[_]u8{0x01};
    const dcid = &[_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    var packer = PacketPacker.init(false, scid, dcid, 0x00000001);

    var pkt_handler = ack_handler.PacketHandler.init(testing.allocator);
    defer pkt_handler.deinit();

    var crypto_mgr = crypto_stream.CryptoStreamManager.init(testing.allocator);
    defer crypto_mgr.deinit();

    var streams = stream_mod.StreamsMap.init(testing.allocator, false);
    defer streams.deinit();

    var pending_frames = frame_mod.PendingFrameQueue{};
    pending_frames.push(.{ .max_data = 12345 });

    // Create a stream with data
    streams.setMaxStreams(10, 10);
    streams.setPeerInitialMaxStreamData(65536, 65536, 65536);
    const s = try streams.openBidiStream();
    try s.send.writeData("This data should be skipped");

    // Register 2 received packets to trigger immediate ACK (ACK_ELICITING_THRESHOLD=2)
    try pkt_handler.recv[2].onPacketReceived(0, true, 1000, 0);
    try pkt_handler.recv[2].onPacketReceived(1, true, 1000, 0);

    const keys = try testClientKeys();

    var out_buf: [1500]u8 = undefined;
    const written = try packer.packCoalesced(
        &out_buf,
        &pkt_handler,
        &crypto_mgr,
        &streams,
        &pending_frames,
        null,
        null,
        null,
        &keys.seal, // app_seal
        1000,
        null,
        true, // ack_only = true
        rng.random(),
    );

    // Should produce a packet carrying ACK plus receiver-credit control.
    try testing.expect(written > 0);
    try testing.expectEqual(@as(u8, 0), pending_frames.len);

    // Stream data should still be waiting (not consumed)
    try testing.expect(s.send.hasData());
}

test "PacketPacker: ack_only does not force sub-threshold ACKs" {
    var rng = TestRandom{};
    const scid = &[_]u8{0x01};
    const dcid = &[_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    var packer = PacketPacker.init(false, scid, dcid, 0x00000001);

    var pkt_handler = ack_handler.PacketHandler.init(testing.allocator);
    defer pkt_handler.deinit();

    var crypto_mgr = crypto_stream.CryptoStreamManager.init(testing.allocator);
    defer crypto_mgr.deinit();

    var streams = stream_mod.StreamsMap.init(testing.allocator, false);
    defer streams.deinit();

    var pending_frames = frame_mod.PendingFrameQueue{};

    // One ack-eliciting packet arms a delayed ACK, but it is below the immediate
    // ACK threshold. ACK-only packing must not force an immediate packet.
    try pkt_handler.recv[2].onPacketReceived(0, true, 1000, 0);

    const keys = try testClientKeys();

    var out_buf: [1500]u8 = undefined;
    const written = try packer.packCoalesced(
        &out_buf,
        &pkt_handler,
        &crypto_mgr,
        &streams,
        &pending_frames,
        null,
        null,
        null,
        &keys.seal,
        1000,
        null,
        true,
        rng.random(),
    );

    try testing.expectEqual(@as(usize, 0), written);
    try testing.expectEqual(@as(u64, 0), pkt_handler.next_pn[2]);
}

test "PacketPacker: coalesced Initial + Handshake" {
    var rng = TestRandom{};
    const scid = &[_]u8{0x01};
    const dcid = &[_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    var packer = PacketPacker.init(true, scid, dcid, 0x00000001); // server

    var pkt_handler = ack_handler.PacketHandler.init(testing.allocator);
    defer pkt_handler.deinit();

    var crypto_mgr = crypto_stream.CryptoStreamManager.init(testing.allocator);
    defer crypto_mgr.deinit();

    var streams = stream_mod.StreamsMap.init(testing.allocator, true);
    defer streams.deinit();

    var pending_frames = frame_mod.PendingFrameQueue{};

    // Write CRYPTO data for Initial and Handshake levels
    try crypto_mgr.getStream(0).writeData("Initial crypto");
    try crypto_mgr.getStream(2).writeData("Handshake crypto"); // handshake = index 2

    const keys = try testServerKeys();

    var out_buf: [1500]u8 = undefined;
    const written = try packer.packCoalesced(
        &out_buf,
        &pkt_handler,
        &crypto_mgr,
        &streams,
        &pending_frames,
        &keys.seal, // initial_seal
        null, // no early
        &keys.seal, // handshake_seal (reuse same keys for test)
        null, // no app
        1000,
        null,
        false,
        rng.random(),
    );

    // Should have coalesced both levels
    try testing.expect(written > 0);

    // Both Initial and Handshake packet numbers should have been used
    try testing.expectEqual(@as(u64, 1), pkt_handler.next_pn[0]); // Initial PN 0 used
    try testing.expectEqual(@as(u64, 1), pkt_handler.next_pn[1]); // Handshake PN 0 used
}

test "PacketPacker: HANDSHAKE_DONE frame packed in 1-RTT" {
    var rng = TestRandom{};
    const scid = &[_]u8{0x01};
    const dcid = &[_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    var packer = PacketPacker.init(true, scid, dcid, 0x00000001);
    packer.send_handshake_done = true;

    var pkt_handler = ack_handler.PacketHandler.init(testing.allocator);
    defer pkt_handler.deinit();

    var crypto_mgr = crypto_stream.CryptoStreamManager.init(testing.allocator);
    defer crypto_mgr.deinit();

    var streams = stream_mod.StreamsMap.init(testing.allocator, true);
    defer streams.deinit();

    var pending_frames = frame_mod.PendingFrameQueue{};
    const keys = try testServerKeys();

    var out_buf: [1500]u8 = undefined;
    const written = try packer.packCoalesced(
        &out_buf,
        &pkt_handler,
        &crypto_mgr,
        &streams,
        &pending_frames,
        null,
        null,
        null,
        &keys.seal, // app_seal
        1000,
        null,
        false,
        rng.random(),
    );

    try testing.expect(written > 0);

    // HANDSHAKE_DONE is one-shot: cleared by packer after writing, re-armed by PTO/loss
    try testing.expect(!packer.send_handshake_done);

    // Sent packet should be tracked as ack-eliciting with handshake_done
    const app_idx = @backingInt(ack_handler.EncLevel.application);
    try testing.expectEqual(@as(usize, 1), pkt_handler.sent[app_idx].sent_packets.count());
    var it = pkt_handler.sent[app_idx].sent_packets.iterator();
    const pkt = it.next().?.value_ptr.*;
    try testing.expect(pkt.ack_eliciting);
    try testing.expect(pkt.has_handshake_done);
}

test "PacketPacker: ecn_mark propagates to SentPacket" {
    var rng = TestRandom{};
    const scid = &[_]u8{0x01};
    const dcid = &[_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    var packer = PacketPacker.init(false, scid, dcid, 0x00000001);
    packer.ecn_mark = true;

    var pkt_handler = ack_handler.PacketHandler.init(testing.allocator);
    defer pkt_handler.deinit();

    var crypto_mgr = crypto_stream.CryptoStreamManager.init(testing.allocator);
    defer crypto_mgr.deinit();

    var streams = stream_mod.StreamsMap.init(testing.allocator, false);
    defer streams.deinit();

    var pending_frames = frame_mod.PendingFrameQueue{};

    // Need ack-eliciting content — add stream data
    streams.setMaxStreams(10, 10);
    streams.setPeerInitialMaxStreamData(65536, 65536, 65536);
    const s = try streams.openBidiStream();
    try s.send.writeData("ecn test data");

    const keys = try testClientKeys();

    var out_buf: [1500]u8 = undefined;
    const written = try packer.packCoalesced(
        &out_buf,
        &pkt_handler,
        &crypto_mgr,
        &streams,
        &pending_frames,
        null,
        null,
        null,
        &keys.seal,
        1000,
        null,
        false,
        rng.random(),
    );

    try testing.expect(written > 0);

    // Check the sent packet has ecn_marked set
    const app_idx = @backingInt(ack_handler.EncLevel.application);
    var it = pkt_handler.sent[app_idx].sent_packets.iterator();
    const pkt = it.next().?.value_ptr.*;
    try testing.expect(pkt.ecn_marked);
    try testing.expect(pkt.ack_eliciting);
}

test "PacketPacker: key_phase bit in short header" {
    var rng = TestRandom{};
    const scid = &[_]u8{0x01};
    const dcid = &[_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    var packer = PacketPacker.init(false, scid, dcid, 0x00000001);

    var pkt_handler = ack_handler.PacketHandler.init(testing.allocator);
    defer pkt_handler.deinit();

    var crypto_mgr = crypto_stream.CryptoStreamManager.init(testing.allocator);
    defer crypto_mgr.deinit();

    var streams = stream_mod.StreamsMap.init(testing.allocator, false);
    defer streams.deinit();

    var pending_frames = frame_mod.PendingFrameQueue{};

    // Add stream data so we produce a packet
    streams.setMaxStreams(10, 10);
    streams.setPeerInitialMaxStreamData(65536, 65536, 65536);
    const s = try streams.openBidiStream();
    try s.send.writeData("test data");

    const keys = try testClientKeys();

    // Pack with key_phase = false
    packer.key_phase = false;
    var out1: [1500]u8 = undefined;
    _ = try packer.packCoalesced(&out1, &pkt_handler, &crypto_mgr, &streams, &pending_frames, null, null, null, &keys.seal, 1000, null, false, rng.random());

    // Write more data and pack with key_phase = true
    try s.send.writeData("more data");
    packer.key_phase = true;
    var out2: [1500]u8 = undefined;
    _ = try packer.packCoalesced(&out2, &pkt_handler, &crypto_mgr, &streams, &pending_frames, null, null, null, &keys.seal, 1000, null, false, rng.random());

    // After header protection is applied, the key_phase bit is masked.
    // But the two packets should differ (different key phase + different content).
    // Just verify both produced output and used different PNs.
    const app_idx = @backingInt(ack_handler.EncLevel.application);
    try testing.expectEqual(@as(u64, 2), pkt_handler.next_pn[app_idx]);
}

test "PacketPacker: pending control frames in 1-RTT" {
    var rng = TestRandom{};
    const scid = &[_]u8{0x01};
    const dcid = &[_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    var packer = PacketPacker.init(false, scid, dcid, 0x00000001);

    var pkt_handler = ack_handler.PacketHandler.init(testing.allocator);
    defer pkt_handler.deinit();

    var crypto_mgr = crypto_stream.CryptoStreamManager.init(testing.allocator);
    defer crypto_mgr.deinit();

    var streams = stream_mod.StreamsMap.init(testing.allocator, false);
    defer streams.deinit();

    var pending_frames = frame_mod.PendingFrameQueue{};

    // Queue a PATH_CHALLENGE control frame
    const challenge = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE };
    pending_frames.push(.{ .path_challenge = challenge });

    const keys = try testClientKeys();

    var out_buf: [1500]u8 = undefined;
    const written = try packer.packCoalesced(
        &out_buf,
        &pkt_handler,
        &crypto_mgr,
        &streams,
        &pending_frames,
        null,
        null,
        null,
        &keys.seal,
        1000,
        null,
        false,
        rng.random(),
    );

    try testing.expect(written > 0);

    // Control frame should be consumed from the queue
    try testing.expectEqual(@as(?frame_mod.PendingControlFrame, null), pending_frames.pop());

    // Sent packet should be ack-eliciting
    const app_idx = @backingInt(ack_handler.EncLevel.application);
    var it = pkt_handler.sent[app_idx].sent_packets.iterator();
    const pkt = it.next().?.value_ptr.*;
    try testing.expect(pkt.ack_eliciting);
}

test "PacketPacker: stream frame info tracked in SentPacket" {
    var rng = TestRandom{};
    const scid = &[_]u8{0x01};
    const dcid = &[_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    var packer = PacketPacker.init(false, scid, dcid, 0x00000001);

    var pkt_handler = ack_handler.PacketHandler.init(testing.allocator);
    defer pkt_handler.deinit();

    var crypto_mgr = crypto_stream.CryptoStreamManager.init(testing.allocator);
    defer crypto_mgr.deinit();

    var streams = stream_mod.StreamsMap.init(testing.allocator, false);
    defer streams.deinit();

    var pending_frames = frame_mod.PendingFrameQueue{};

    streams.setMaxStreams(10, 10);
    streams.setPeerInitialMaxStreamData(65536, 65536, 65536);
    const s = try streams.openBidiStream();
    try s.send.writeData("stream data for tracking");

    const keys = try testClientKeys();

    var out_buf: [1500]u8 = undefined;
    _ = try packer.packCoalesced(
        &out_buf,
        &pkt_handler,
        &crypto_mgr,
        &streams,
        &pending_frames,
        null,
        null,
        null,
        &keys.seal,
        1000,
        null,
        false,
        rng.random(),
    );

    // Verify stream frame info was recorded in SentPacket
    const app_idx = @backingInt(ack_handler.EncLevel.application);
    var it = pkt_handler.sent[app_idx].sent_packets.iterator();
    const pkt = it.next().?.value_ptr.*;
    const sf = pkt.getStreamFrames();
    try testing.expect(sf.len > 0);
    try testing.expectEqual(@as(u64, 0), sf[0].stream_id);
    try testing.expectEqual(@as(u64, 0), sf[0].offset);
    try testing.expect(sf[0].length > 0);
}

fn packAppOnly(
    packer: *PacketPacker,
    pkt_handler: *ack_handler.PacketHandler,
    crypto_mgr: *crypto_stream.CryptoStreamManager,
    streams: *stream_mod.StreamsMap,
    pending_frames: *frame_mod.PendingFrameQueue,
    out_buf: []u8,
    random: std.Random,
) !usize {
    const keys = try testClientKeys();
    return packer.packCoalesced(out_buf, pkt_handler, crypto_mgr, streams, pending_frames, null, null, null, &keys.seal, 1000, null, false, random);
}

test "PacketPacker: packing our FIN closes a stream whose peer finished first" {
    var rng = TestRandom{};
    const dcid = &[_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    var packer = PacketPacker.init(true, &[_]u8{0x01}, dcid, 0x00000001);
    var pkt_handler = ack_handler.PacketHandler.init(testing.allocator);
    defer pkt_handler.deinit();
    var crypto_mgr = crypto_stream.CryptoStreamManager.init(testing.allocator);
    defer crypto_mgr.deinit();
    var streams = stream_mod.StreamsMap.init(testing.allocator, true);
    defer streams.deinit();
    var pending_frames = frame_mod.PendingFrameQueue{};
    streams.setMaxStreams(10, 10);
    streams.setPeerInitialMaxStreamData(65536, 65536, 65536);

    // The request arrives whole; the response is not written yet.
    const s = try streams.getOrCreateStream(0);
    try s.recv.handleStreamFrame(0, "GET /", true);
    streams.collectClosedStreams();
    try testing.expect(!s.closed_for_gc);
    try testing.expect(!streams.needs_gc_scan); // no scan left armed to notice later

    try s.send.writeData("200 OK");
    s.send.close();
    var out: [1500]u8 = undefined;
    _ = try packAppOnly(&packer, &pkt_handler, &crypto_mgr, &streams, &pending_frames, &out, rng.random());
    try testing.expect(s.send.fin_sent);
    try testing.expect(s.closed_for_gc);
    try testing.expectEqual(@as(u64, 1), streams.consumed_bidi_streams);
}

test "PacketPacker: a sent packet records the control frames to repeat on loss" {
    var rng = TestRandom{};
    const dcid = &[_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    var packer = PacketPacker.init(false, &[_]u8{0x01}, dcid, 0x00000001);
    var pkt_handler = ack_handler.PacketHandler.init(testing.allocator);
    defer pkt_handler.deinit();
    var crypto_mgr = crypto_stream.CryptoStreamManager.init(testing.allocator);
    defer crypto_mgr.deinit();
    var streams = stream_mod.StreamsMap.init(testing.allocator, false);
    defer streams.deinit();

    var pending_frames = frame_mod.PendingFrameQueue{};
    pending_frames.push(.{ .ping = {} });
    pending_frames.push(.{ .max_stream_data = .{ .stream_id = 3, .max = 9000 } });
    pending_frames.push(.{ .reset_stream = .{ .stream_id = 7, .error_code = 1, .final_size = 40 } });

    var out_buf: [1500]u8 = undefined;
    try testing.expect(try packAppOnly(&packer, &pkt_handler, &crypto_mgr, &streams, &pending_frames, &out_buf, rng.random()) > 0);

    const sent = pkt_handler.sent[2].sent_packets.values()[0];
    const records = sent.getControlFrames();
    // PING is never repeated, so it is not recorded.
    try testing.expectEqual(@as(usize, 2), records.len);
    try testing.expectEqual(@as(u64, 3), records[0].max_stream_data);
    try testing.expectEqual(@as(u64, 40), records[1].reset_stream.final_size);
}

test "PacketPacker: control frames past one packet wait for the next" {
    var rng = TestRandom{};
    const dcid = &[_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    var packer = PacketPacker.init(false, &[_]u8{0x01}, dcid, 0x00000001);
    var pkt_handler = ack_handler.PacketHandler.init(testing.allocator);
    defer pkt_handler.deinit();
    var crypto_mgr = crypto_stream.CryptoStreamManager.init(testing.allocator);
    defer crypto_mgr.deinit();
    var streams = stream_mod.StreamsMap.init(testing.allocator, false);
    defer streams.deinit();

    // More RESET_STREAMs than one packet may record, and more NEW_TOKENs
    // than one packet can hold: none may be lost to a full packet.
    var pending_frames = frame_mod.PendingFrameQueue{};
    var id: u64 = 0;
    while (id < 10) : (id += 1) {
        try testing.expect(pending_frames.tryPush(.{ .reset_stream = .{ .stream_id = id * 4 + 2, .error_code = 0, .final_size = 0 } }));
    }
    var tok: frame_mod.PendingControlFrame = .{ .new_token = .{} };
    tok.new_token.token_len = 92;
    var n: usize = 0;
    while (n < 20) : (n += 1) try testing.expect(pending_frames.tryPush(tok));

    var out_buf: [1500]u8 = undefined;
    var packets: usize = 0;
    var resets: usize = 0;
    var tokens: usize = 0;
    while (pending_frames.len > 0) : (packets += 1) {
        if (packets > 30) return error.TestUnexpectedResult;
        const written = try packAppOnly(&packer, &pkt_handler, &crypto_mgr, &streams, &pending_frames, &out_buf, rng.random());
        try testing.expect(written > 0 and written <= packer.max_packet_size);
    }
    for (pkt_handler.sent[2].sent_packets.values()) |p| {
        try testing.expect(p.control_frame_count <= ack_handler.MAX_CONTROL_FRAMES_PER_PACKET);
        for (p.getControlFrames()) |cf| switch (cf) {
            .reset_stream => resets += 1,
            .new_token => tokens += 1,
            else => {},
        };
    }
    try testing.expectEqual(@as(usize, 10), resets);
    try testing.expectEqual(@as(usize, 20), tokens);
}

test "PacketPacker: an Initial control frame with no room waits for the next packet" {
    // The 1-RTT loop scratch-encodes a queued frame and requeues it when the
    // packet has no room for it. The Initial and Handshake loop wrote into the
    // staging buffer straight from the queue instead, so a CONNECTION_CLOSE
    // that did not fit was dequeued and written past the packet's own budget —
    // and where the staging buffer really was full, lost along with the frames
    // the packet already held, with the error closing the connection. What the
    // requeue contract says is that it waits for a packet that can carry it.
    var rng = TestRandom{};
    const dcid = &[_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    var packer = PacketPacker.init(true, &[_]u8{0x01}, dcid, 0x00000001);
    // Enough CRYPTO data to fill a whole packet's budget, so the packets
    // before the close leaves are filled to the same edge it does not fit past.
    const crypto_bytes: usize = 4000;
    var pkt_handler = ack_handler.PacketHandler.init(testing.allocator);
    defer pkt_handler.deinit();
    var crypto_mgr = crypto_stream.CryptoStreamManager.init(testing.allocator);
    defer crypto_mgr.deinit();
    var streams = stream_mod.StreamsMap.init(testing.allocator, true);
    defer streams.deinit();
    var pending_frames = frame_mod.PendingFrameQueue{};
    try testing.expect(pending_frames.tryPush(.{
        .connection_close = .{
            .error_code = std.math.maxInt(u62),
            .frame_type = std.math.maxInt(u62),
            .is_app = false,
        },
    }));
    try crypto_mgr.getStream(0).writeData(&@as([crypto_bytes:0]u8, @splat('c')));
    const keys = try testServerKeys();

    var out_buf: [1500]u8 = undefined;
    var passes: usize = 0;
    while (crypto_mgr.getStream(0).hasData()) : (passes += 1) {
        try testing.expect(passes < 32);
        const written = try packer.packCoalesced(
            &out_buf,
            &pkt_handler,
            &crypto_mgr,
            &streams,
            &pending_frames,
            &keys.seal,
            null,
            null,
            null,
            1000,
            null,
            false,
            rng.random(),
        );
        // The packet that went out carried CRYPTO data and stayed inside the
        // budget, and the close is still queued for one that can hold it.
        try testing.expect(written > 0);
        try testing.expect(written <= packer.max_packet_size);
        try testing.expectEqual(@as(usize, 1), pending_frames.len);
        try testing.expect(pending_frames.items[0] == .connection_close);
    }
    try testing.expect(passes > 0);

    // What the close costs on the wire, measured the way the packer measures
    // it: the frame encoded into scratch. It is wider than the room a
    // full packet has left.
    var close_scratch: [64]u8 = undefined;
    var close_fbs = io.fixedBufferStream(&close_scratch);
    try pending_frames.items[0].write(&close_fbs);
    const close_len = close_fbs.buffered().len;

    // The CRYPTO data is drained, so the close is all this pass has to say and
    // the packet it leaves in is one that reaches the floor — nothing else
    // could have produced a packet at all, so this is the pass the close went
    // out in. It stays queued after that: RFC 9000 §10.2.3 sends a close at
    // every level the peer may be reading.
    const written = try packer.packCoalesced(
        &out_buf,
        &pkt_handler,
        &crypto_mgr,
        &streams,
        &pending_frames,
        &keys.seal,
        null,
        null,
        null,
        1000,
        null,
        false,
        rng.random(),
    );
    // The premise, and it is a tight one: a CRYPTO frame filled to the budget
    // leaves exactly one tag plus a byte, and the close is wider than that.
    try testing.expect(close_len > AEAD_TAG_LEN + 1);
    try testing.expectEqual(@as(usize, MIN_INITIAL_PACKET_SIZE), written);
    try testing.expectEqual(@as(usize, 1), pending_frames.len);
    try testing.expect(pending_frames.items[0] == .connection_close);
}

test "PacketPacker: a 1-RTT packet carrying only a CONNECTION_CLOSE is not ack-eliciting" {
    // RFC 9000 §13.2.1: an ack-eliciting packet is one that "contains frames
    // other than ACK, PADDING, and CONNECTION_CLOSE", and Table 3's Spec
    // column marks CONNECTION_CLOSE — both forms — `N`, for "packets
    // containing only frames with this marking are not ack-eliciting". A
    // packet holding only a close provokes no ACK and counts for nothing in
    // flight. The Initial and Handshake loop already keeps a close out of
    // this accounting; the 1-RTT loop set the flag for every control frame it
    // wrote, so a connection going out under a CONNECTION_CLOSE claimed the
    // peer owed it an ACK.
    var rng = TestRandom{};
    const dcid = &[_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    var packer = PacketPacker.init(true, &[_]u8{0x01}, dcid, 0x00000001);
    var pkt_handler = ack_handler.PacketHandler.init(testing.allocator);
    defer pkt_handler.deinit();
    var crypto_mgr = crypto_stream.CryptoStreamManager.init(testing.allocator);
    defer crypto_mgr.deinit();
    var streams = stream_mod.StreamsMap.init(testing.allocator, true);
    defer streams.deinit();
    var pending_frames = frame_mod.PendingFrameQueue{};
    pending_frames.push(.{ .connection_close = .{ .error_code = 7, .frame_type = 0, .is_app = false } });

    var out_buf: [1500]u8 = undefined;
    try testing.expect(try packAppOnly(&packer, &pkt_handler, &crypto_mgr, &streams, &pending_frames, &out_buf, rng.random()) > 0);

    const app = pkt_handler.sent[@backingInt(ack_handler.EncLevel.application)].sent_packets;
    try testing.expectEqual(@as(usize, 1), app.count());
    const sent = app.values()[0];
    try testing.expect(!sent.ack_eliciting);
    try testing.expect(!sent.in_flight);
}

test "PacketPacker: a 1-RTT packet carrying only a NEW_TOKEN is ack-eliciting" {
    // The counterpart to the close-only packet, and the one that catches the
    // over-reach: §13.2.1 excludes ACK, PADDING and CONNECTION_CLOSE and
    // nothing else, and Table 3's Spec column for 0x07 is empty — NEW_TOKEN is
    // not marked `N`. A packet carrying only one still owes the peer an ACK,
    // and calling it a non-ack-eliciting packet takes a token the peer never
    // acknowledged out of congestion and loss accounting.
    var rng = TestRandom{};
    const dcid = &[_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    var packer = PacketPacker.init(true, &[_]u8{0x01}, dcid, 0x00000001);
    var pkt_handler = ack_handler.PacketHandler.init(testing.allocator);
    defer pkt_handler.deinit();
    var crypto_mgr = crypto_stream.CryptoStreamManager.init(testing.allocator);
    defer crypto_mgr.deinit();
    var streams = stream_mod.StreamsMap.init(testing.allocator, true);
    defer streams.deinit();
    var pending_frames = frame_mod.PendingFrameQueue{};
    var token: frame_mod.PendingControlFrame = .{ .new_token = .{} };
    token.new_token.token_len = 8;
    try testing.expect(pending_frames.tryPush(token));

    var out_buf: [1500]u8 = undefined;
    try testing.expect(try packAppOnly(&packer, &pkt_handler, &crypto_mgr, &streams, &pending_frames, &out_buf, rng.random()) > 0);

    const app = pkt_handler.sent[@backingInt(ack_handler.EncLevel.application)].sent_packets;
    try testing.expectEqual(@as(usize, 1), app.count());
    const sent = app.values()[0];
    try testing.expect(sent.ack_eliciting);
    try testing.expect(sent.in_flight);
}

test "PacketPacker: a coalesced datagram that reaches the Initial floor stays within the budget" {
    // A datagram carrying an ack-eliciting Initial owes 1200 bytes of RFC 9000
    // §14.1 before anything else is added to it, and `max_packet_size` is
    // copied from the path MTU — a whole-UDP-payload number, not a per-packet
    // one, so the Handshake packet riding behind an Initial shares that one
    // budget rather than having one of its own.
    //
    // The Handshake level here has no CRYPTO to seal, only the CONNECTION_CLOSE
    // this connection is closing with, which the Initial's own control loop
    // writes and then requeues for the levels above. Counting that close as
    // something to share the floor with is what keeps the level reachable:
    // without it the Initial takes all 1200 on its own, requeues the close
    // again, and does the same on the next pass — a Handshake packet starved
    // on every pass is a close that is never sent at that level at all, not
    // one sent later.
    //
    // Per packet the budget already holds on the wire: every writer in
    // `packSinglePacket` subtracts `AEAD_TAG_LEN` before it takes bytes, so a
    // packet lands on `effective_max` and never past it. The datagram around
    // them is the half that needed covering.
    var rng = TestRandom{};
    const dcid = &[_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    var packer = PacketPacker.init(false, &[_]u8{0x01}, dcid, 0x00000001);
    var pkt_handler = ack_handler.PacketHandler.init(testing.allocator);
    defer pkt_handler.deinit();
    var crypto_mgr = crypto_stream.CryptoStreamManager.init(testing.allocator);
    defer crypto_mgr.deinit();
    var streams = stream_mod.StreamsMap.init(testing.allocator, false);
    defer streams.deinit();
    var pending_frames = frame_mod.PendingFrameQueue{};
    pending_frames.push(.{ .connection_close = .{ .error_code = 0, .frame_type = 0, .is_app = false } });
    try crypto_mgr.getStream(0).writeData("a ClientHello");
    // Two seals of the same material. Nothing here decrypts, and what matters
    // is that both levels have a seal to write under.
    const init_keys = try testClientKeys();
    const hs_keys = try testClientKeys();

    var out_buf: [1500]u8 = undefined;
    const written = try packer.packCoalesced(
        &out_buf,
        &pkt_handler,
        &crypto_mgr,
        &streams,
        &pending_frames,
        &init_keys.seal,
        null,
        &hs_keys.seal,
        null,
        1000,
        null,
        false,
        rng.random(),
    );

    // The Initial still reached the floor and still carried its CRYPTO out.
    try testing.expect(written >= MIN_INITIAL_PACKET_SIZE);
    try testing.expect(!crypto_mgr.getStream(0).hasData());
    // Both levels advanced a packet number, so neither packet was rolled back
    // and the flight is spent rather than half-sent.
    try testing.expectEqual(@as(u64, 1), pkt_handler.next_pn[0]);
    try testing.expectEqual(@as(u64, 1), pkt_handler.next_pn[1]);
    // And both levels recorded a packet, which is the whole point: RFC 9000
    // §10.2.3 sends a close at every level the peer may be reading, so a level
    // the Initial starves is a level the close never reaches.
    try testing.expectEqual(@as(usize, 1), pkt_handler.sent[0].sent_packets.count());
    try testing.expectEqual(@as(usize, 1), pkt_handler.sent[1].sent_packets.count());
    // It stays queued for the levels above these two, which is what the
    // requeue is for.
    try testing.expectEqual(@as(usize, 1), pending_frames.len);
    try testing.expect(pending_frames.items[0] == .connection_close);
    // And the datagram as a whole fits the budget the path MTU set.
    try testing.expect(written <= packer.max_packet_size);
}

test "PacketPacker: a client Initial waits for a datagram that can reach 1200" {
    // RFC 9000 §14.1: a datagram carrying a client's Initial is expanded to
    // 1200 bytes, so a buffer that cannot hold one has no valid datagram in it
    // to write. Padding toward a target the buffer cannot reach produced a
    // 600-byte Initial instead — shorter than the minimum every peer is
    // entitled to drop, carrying a ClientHello that then goes nowhere — so a
    // datagram this short is not written at all: the CRYPTO data stays queued,
    // takes no packet number, and goes out whole on the first send that has
    // room.
    var rng = TestRandom{};
    const dcid = &[_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    var packer = PacketPacker.init(false, &[_]u8{0x01}, dcid, 0x00000001);
    var pkt_handler = ack_handler.PacketHandler.init(testing.allocator);
    defer pkt_handler.deinit();
    var crypto_mgr = crypto_stream.CryptoStreamManager.init(testing.allocator);
    defer crypto_mgr.deinit();
    var streams = stream_mod.StreamsMap.init(testing.allocator, false);
    defer streams.deinit();
    var pending_frames = frame_mod.PendingFrameQueue{};
    try crypto_mgr.getStream(0).writeData("a ClientHello long enough to fill part of a packet");
    const keys = try testClientKeys();

    // A server's anti-amplification budget, or an MTU below the minimum, can
    // leave the caller far under 1200 bytes.
    var short_buf: [600]u8 = undefined;
    try testing.expectEqual(@as(usize, 0), try packer.packCoalesced(
        &short_buf,
        &pkt_handler,
        &crypto_mgr,
        &streams,
        &pending_frames,
        &keys.seal,
        null,
        null,
        null,
        1000,
        null,
        false,
        rng.random(),
    ));
    try testing.expectEqual(@as(u64, 0), pkt_handler.next_pn[0]);
    try testing.expectEqual(@as(usize, 0), pkt_handler.sent[0].sent_packets.count());
    try testing.expect(crypto_mgr.getStream(0).hasData());

    // One byte under the minimum is still a datagram nothing may send.
    var tight_buf: [MIN_INITIAL_PACKET_SIZE - 1]u8 = undefined;
    try testing.expectEqual(@as(usize, 0), try packer.packCoalesced(
        &tight_buf,
        &pkt_handler,
        &crypto_mgr,
        &streams,
        &pending_frames,
        &keys.seal,
        null,
        null,
        null,
        1000,
        null,
        false,
        rng.random(),
    ));
    try testing.expectEqual(@as(u64, 0), pkt_handler.next_pn[0]);

    // The minimum itself, and the packet the first flight actually left with.
    var full_buf: [MIN_INITIAL_PACKET_SIZE]u8 = undefined;
    try testing.expectEqual(MIN_INITIAL_PACKET_SIZE, try packer.packCoalesced(
        &full_buf,
        &pkt_handler,
        &crypto_mgr,
        &streams,
        &pending_frames,
        &keys.seal,
        null,
        null,
        null,
        1000,
        null,
        false,
        rng.random(),
    ));
    try testing.expectEqual(@as(u64, 1), pkt_handler.next_pn[0]);
    try testing.expectEqual(@as(usize, 1), pkt_handler.sent[0].sent_packets.count());
    try testing.expect(!crypto_mgr.getStream(0).hasData());
}

test "PacketPacker: a coalesced client Initial waits for a datagram that can reach 1200" {
    // RFC 9000 §14.1 asks for 1200 bytes of every datagram that carries a
    // client's Initial, and handshake keys change who does the padding rather
    // than whether there is any: the Initial and the Handshake packet that
    // follows share one datagram's budget. A buffer too short for that budget
    // holds no datagram a peer is obliged to accept, so it is offered no
    // packet at all and nothing is spent for the refusal — no packet number at
    // either level, no CRYPTO data off either stream, nothing recorded.
    var rng = TestRandom{};
    const dcid = &[_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    var packer = PacketPacker.init(false, &[_]u8{0x01}, dcid, 0x00000001);
    var pkt_handler = ack_handler.PacketHandler.init(testing.allocator);
    defer pkt_handler.deinit();
    var crypto_mgr = crypto_stream.CryptoStreamManager.init(testing.allocator);
    defer crypto_mgr.deinit();
    var streams = stream_mod.StreamsMap.init(testing.allocator, false);
    defer streams.deinit();
    var pending_frames = frame_mod.PendingFrameQueue{};
    // The ClientHello, and the Finished that shares its datagram.
    try crypto_mgr.getStream(0).writeData(&@as([600:0]u8, @splat('a')));
    try crypto_mgr.getStream(2).writeData(&@as([40:0]u8, @splat('b')));
    // One seal at both levels: the packer takes it as given, and what is under
    // test is how the two levels share the datagram's padding.
    const keys = try testClientKeys();

    var short_buf: [MIN_INITIAL_PACKET_SIZE - 1]u8 = undefined;
    try testing.expectEqual(@as(usize, 0), try packer.packCoalesced(
        &short_buf,
        &pkt_handler,
        &crypto_mgr,
        &streams,
        &pending_frames,
        &keys.seal,
        null,
        &keys.seal,
        null,
        1000,
        null,
        false,
        rng.random(),
    ));
    try testing.expectEqual(@as(u64, 0), pkt_handler.next_pn[0]);
    try testing.expectEqual(@as(u64, 0), pkt_handler.next_pn[1]);
    try testing.expectEqual(@as(usize, 0), pkt_handler.sent[0].sent_packets.count());
    try testing.expectEqual(@as(usize, 0), pkt_handler.sent[1].sent_packets.count());
    try testing.expect(crypto_mgr.getStream(0).hasData());
    try testing.expect(crypto_mgr.getStream(2).hasData());

    // A buffer that can hold it: both levels go out as one datagram, and it is
    // 1200 bytes, the Initial's share plus the padding the Handshake level
    // adds to reach the same floor.
    var full_buf: [1500]u8 = undefined;
    try testing.expectEqual(@as(usize, MIN_INITIAL_PACKET_SIZE), try packer.packCoalesced(
        &full_buf,
        &pkt_handler,
        &crypto_mgr,
        &streams,
        &pending_frames,
        &keys.seal,
        null,
        &keys.seal,
        null,
        1000,
        null,
        false,
        rng.random(),
    ));
    try testing.expectEqual(@as(u64, 1), pkt_handler.next_pn[0]);
    try testing.expectEqual(@as(u64, 1), pkt_handler.next_pn[1]);
    try testing.expectEqual(@as(usize, 1), pkt_handler.sent[0].sent_packets.count());
    try testing.expectEqual(@as(usize, 1), pkt_handler.sent[1].sent_packets.count());
    try testing.expect(!crypto_mgr.getStream(0).hasData());
    try testing.expect(!crypto_mgr.getStream(2).hasData());
}

test "PacketPacker: an Initial with a silent Handshake level pads itself" {
    // RFC 9000 §14.1 asks for 1200 bytes of every datagram carrying an Initial,
    // and the padding that reaches it belongs to the Handshake packet only
    // while that level has a flight of its own to add. A handshake seal with
    // nothing queued at that level leaves the floor to the Initial, whose own
    // padding reaches it: the alternative is a datagram short of the minimum
    // every peer may drop, carrying a ClientHello that then goes nowhere.
    // Both roles are held to it — the rule is the datagram's, not the
    // sender's.
    var rng = TestRandom{};
    const dcid = &[_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const keys = try testClientKeys();

    for ([_]bool{ false, true }) |is_server| {
        var packer = PacketPacker.init(is_server, &[_]u8{0x01}, dcid, 0x00000001);
        var pkt_handler = ack_handler.PacketHandler.init(testing.allocator);
        defer pkt_handler.deinit();
        var crypto_mgr = crypto_stream.CryptoStreamManager.init(testing.allocator);
        defer crypto_mgr.deinit();
        var streams = stream_mod.StreamsMap.init(testing.allocator, is_server);
        defer streams.deinit();
        var pending_frames = frame_mod.PendingFrameQueue{};
        try crypto_mgr.getStream(0).writeData(&@as([600:0]u8, @splat('a')));

        var out_buf: [1500]u8 = undefined;
        const written = try packer.packCoalesced(
            &out_buf,
            &pkt_handler,
            &crypto_mgr,
            &streams,
            &pending_frames,
            &keys.seal,
            null,
            &keys.seal,
            null,
            1000,
            null,
            false,
            rng.random(),
        );

        try testing.expectEqual(@as(usize, MIN_INITIAL_PACKET_SIZE), written);
        try testing.expectEqual(@as(u64, 1), pkt_handler.next_pn[0]);
        try testing.expectEqual(@as(u64, 0), pkt_handler.next_pn[1]);
        try testing.expectEqual(@as(usize, 1), pkt_handler.sent[0].sent_packets.count());
        try testing.expectEqual(@as(usize, 0), pkt_handler.sent[1].sent_packets.count());

        // A legal packet: the long header's Length field covers everything
        // after it, so the peer reads one whole packet, not a short one.
        const length_at = 1 + 4 + (1 + dcid.len) + (1 + 1) + 1;
        const declared = std.mem.readInt(u16, out_buf[length_at..][0..2], .big) & 0x3fff;
        try testing.expectEqual(written, @as(usize, declared) + length_at + 2);
    }
}

test "PacketPacker: a pass that shares the floor with nothing still reaches 1200" {
    // An ACK the Handshake level owes is not a flight to share the floor with:
    // it is owed under an alarm this pass may not have reached, and a
    // congestion-limited pass asks for it only if the alarm has. CRYPTO is:
    // `packSinglePacket` packs it at every level whether or not the pass is
    // congestion-limited, so a Handshake level with data in it is the level the
    // datagram's padding is shared with either way. What is left is the Initial
    // carrying the floor on its own — the first two cases — and the Handshake
    // packet riding after it in the same datagram, which is the third.
    var rng = TestRandom{};
    const dcid = &[_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const keys = try testClientKeys();

    const cases = [_]struct { ack_only: bool, handshake_crypto: usize }{
        .{ .ack_only = true, .handshake_crypto = 0 },
        .{ .ack_only = false, .handshake_crypto = 0 },
        .{ .ack_only = true, .handshake_crypto = 40 },
    };
    for (cases) |case| {
        var packer = PacketPacker.init(false, &[_]u8{0x01}, dcid, 0x00000001);
        var pkt_handler = ack_handler.PacketHandler.init(testing.allocator);
        defer pkt_handler.deinit();
        var crypto_mgr = crypto_stream.CryptoStreamManager.init(testing.allocator);
        defer crypto_mgr.deinit();
        var streams = stream_mod.StreamsMap.init(testing.allocator, false);
        defer streams.deinit();
        var pending_frames = frame_mod.PendingFrameQueue{};
        try crypto_mgr.getStream(0).writeData(&@as([600:0]u8, @splat('a')));
        if (case.handshake_crypto > 0) {
            // `case.handshake_crypto` is a case value, not a comptime one, so
            // `**` cannot spell this repeat — the CRYPTO is filled at runtime
            // into a buffer as wide as the largest case asks for. No case is
            // dropped to make it fit.
            var hs_data: [64]u8 = undefined;
            @memset(hs_data[0..case.handshake_crypto], 'b');
            try crypto_mgr.getStream(2).writeData(hs_data[0..case.handshake_crypto]);
        }
        // One ack-eliciting handshake packet received, below the threshold, so
        // the alarm that would make its ACK due has not fired.
        try pkt_handler.onPacketReceived(.handshake, 0, true, 1000, 0);

        var out_buf: [1500]u8 = undefined;
        const written = try packer.packCoalesced(
            &out_buf,
            &pkt_handler,
            &crypto_mgr,
            &streams,
            &pending_frames,
            &keys.seal,
            null,
            &keys.seal,
            null,
            1000,
            null,
            case.ack_only,
            rng.random(),
        );

        try testing.expect(written >= MIN_INITIAL_PACKET_SIZE);
        try testing.expectEqual(@as(usize, 1), pkt_handler.sent[0].sent_packets.count());
        // The first packet is whole: its Length field covers it and no more, so
        // whatever rides after it starts exactly where that packet ends.
        const length_at = 1 + 4 + (1 + dcid.len) + (1 + 1) + 1;
        const first_len = @as(usize, std.mem.readInt(u16, out_buf[length_at..][0..2], .big) & 0x3fff) +
            length_at + 2;
        try testing.expect(first_len <= written);

        if (case.handshake_crypto == 0) {
            // Nothing to share with: the Initial is the whole floor, and with
            // it the whole datagram budget — `max_packet_size` is spent once,
            // on the datagram, not once per packet in it. So the ACK the
            // Handshake level owes has no room left to ride after it and waits
            // for the next pass, whatever this pass was allowed to ask for.
            // Nothing is lost by the wait: an ACK is regenerated on demand,
            // not spent once.
            try testing.expectEqual(@as(usize, MIN_INITIAL_PACKET_SIZE), first_len);
            try testing.expectEqual(@as(u64, 0), pkt_handler.next_pn[1]);
        } else {
            // Something to share with: one datagram of 1200 carrying both
            // levels, congestion-limited or not.
            try testing.expectEqual(@as(usize, MIN_INITIAL_PACKET_SIZE), written);
            try testing.expectEqual(@as(u64, 1), pkt_handler.next_pn[1]);
            try testing.expect(!crypto_mgr.getStream(2).hasData());
        }
    }
}

test "PacketPacker: a congestion-limited pass still makes Handshake progress" {
    // Two things that look alike and are not: a pass that is congestion-limited,
    // and an Initial whose CRYPTO is still queued afterwards. This is what the
    // implementation does with the two: `packSinglePacket` packs CRYPTO at
    // every level whether or not the pass is congestion-limited, so a bounded
    // Initial takes what fits its share of the datagram and leaves the rest
    // queued for a later pass.
    //
    // The Initial here is bounded because a Handshake flight is there to share
    // the floor with, so it gets `datagram[0..datagram.len - later_room]` and
    // no padding — and the flight is far larger than that share, so a thousand
    // bytes or so of ClientHello are still waiting when this pass ends. That
    // is the state the stall happens in: nothing is waiting on a floor, the
    // Initial went out, there is room inside the one datagram budget for the
    // Handshake level to carry part of its own flight and the ACK it owes, and
    // holding the Handshake packet back loses that progress for no reason.
    // It also strands the datagram short of the 1200 bytes RFC 9000 §14.1
    // asks of any datagram carrying an ack-eliciting Initial, because the
    // padding that reaches it is the Handshake packet's to write.
    var rng = TestRandom{};
    const dcid = &[_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    var packer = PacketPacker.init(false, &[_]u8{0x01}, dcid, 0x00000001);
    var pkt_handler = ack_handler.PacketHandler.init(testing.allocator);
    defer pkt_handler.deinit();
    var crypto_mgr = crypto_stream.CryptoStreamManager.init(testing.allocator);
    defer crypto_mgr.deinit();
    var streams = stream_mod.StreamsMap.init(testing.allocator, false);
    defer streams.deinit();
    var pending_frames = frame_mod.PendingFrameQueue{};
    // Larger than one bounded Initial can carry, so data remains queued.
    try crypto_mgr.getStream(0).writeData(&@as([2048:0]u8, @splat('c')));
    // The Handshake flight, bytes that differ by position so that what a pass
    // handed over and what it kept is checkable as data and not as a count
    // alone. It is larger than what one pass carries out of the room kept back
    // for this level: `later_room` is a worst-case reservation, for the widest
    // CRYPTO frame and the longest packet number, shared with the ACK the
    // level below owes, and it is not widened to fit a flight of any one size.
    // So the first pass takes a prefix of this flight and keeps the rest.
    const flight = "0123456789abcdefghijklmnopqrstuvwxyz0123";
    try crypto_mgr.getStream(2).writeData(flight);
    // One ack-eliciting Handshake packet received; the pass is a second later,
    // well past the ACK alarm, so that ACK rides in the reserved room too.
    const keys = try testClientKeys();
    // Both sends below are the same instant: the second is the datagram the
    // first could not spend, not a later flight of this connection's.
    const now = 1000 + std.time.ns_per_s;

    var out_buf: [1500]u8 = undefined;
    const written = try packer.packCoalesced(
        &out_buf,
        &pkt_handler,
        &crypto_mgr,
        &streams,
        &pending_frames,
        &keys.seal,
        null,
        &keys.seal,
        null,
        now,
        null,
        true,
        rng.random(),
    );

    // The Initial went out, whole.
    try testing.expectEqual(@as(u64, 1), pkt_handler.next_pn[0]);
    // The premise this stall needs, asserted before the boundary assertions
    // that follow: unsent Initial CRYPTO really is still queued, so a fail is
    // a hold-back of a level that could have progressed, not a level with
    // nothing to say.
    try testing.expect(crypto_mgr.getStream(0).hasData());
    // A datagram carrying an ack-eliciting Initial reached the floor…
    try testing.expect(written >= MIN_INITIAL_PACKET_SIZE);
    // …and stayed inside the budget.
    try testing.expect(written <= packer.max_packet_size);
    // And the Handshake level made its progress in this same pass: a packet of
    // its own went out behind the bounded Initial, and it carried CRYPTO
    // rather than reaching the floor on padding alone.
    try testing.expectEqual(@as(u64, 1), pkt_handler.next_pn[1]);
    const hs_sent = pkt_handler.sent[1].sent_packets;
    try testing.expectEqual(@as(usize, 1), hs_sent.count());
    try testing.expect(hs_sent.get(0).?.has_crypto_data);

    // Which is a prefix of the flight and not all of it: what the level kept
    // is the exact unsent tail of the same bytes, so the next CRYPTO frame
    // carries them at the offset this one stopped short of and a peer given
    // both packets has the whole flight with no gap in it.
    const hs_crypto = crypto_mgr.getStream(2);
    const carried: usize = @intCast(hs_crypto.send_offset);
    try testing.expect(carried > 0);
    try testing.expect(hs_crypto.hasData());
    const unsent = hs_crypto.send_buffer.items[carried..flight.len];
    try testing.expectEqualSlices(u8, flight[carried..flight.len], unsent);

    // The next bounded send spends the same one datagram budget again. The
    // Initial's own flight is nearer its end now, so more of the datagram is
    // left for the Handshake level, and the remainder of the flight goes out
    // in one piece.
    const written_next = try packer.packCoalesced(
        &out_buf,
        &pkt_handler,
        &crypto_mgr,
        &streams,
        &pending_frames,
        &keys.seal,
        null,
        &keys.seal,
        null,
        now,
        null,
        true,
        rng.random(),
    );

    try testing.expectEqual(@as(u64, flight.len), hs_crypto.send_offset);
    try testing.expectEqual(@as(u64, flight.len), hs_crypto.write_offset);
    try testing.expect(!hs_crypto.hasData());
    // Nothing rewrote the buffer behind it: the bytes both passes drew from
    // are the flight this test queued, first byte to last.
    const queued_flight = hs_crypto.send_buffer.items[0..flight.len];
    try testing.expectEqualSlices(u8, flight[0..flight.len], queued_flight);
    // Two Handshake packets went out, and the one that finished the flight
    // carried the rest of it rather than padding to the floor, in a datagram
    // that still reached that floor.
    const hs_sent_next = pkt_handler.sent[1].sent_packets;
    try testing.expectEqual(@as(usize, 2), hs_sent_next.count());
    try testing.expect(hs_sent_next.get(1).?.has_crypto_data);
    try testing.expectEqual(@as(u64, 2), pkt_handler.next_pn[1]);
    try testing.expectEqual(@as(usize, MIN_INITIAL_PACKET_SIZE), written_next);
}

test "PacketPacker: an MTU probe above the ceiling reports the clamped size" {
    var rng = TestRandom{};
    const dcid = &[_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    var packer = PacketPacker.init(false, &[_]u8{0x01}, dcid, 0x00000001);
    var pkt_handler = ack_handler.PacketHandler.init(testing.allocator);
    defer pkt_handler.deinit();
    const keys = try testClientKeys();

    var out_buf: [1600]u8 = undefined;
    const probe = try packer.packMtuProbe(&out_buf, 1510, &pkt_handler, &keys.seal, 1000, rng.random());

    // The staging buffer is 1500 bytes, so that is what a larger request
    // probes, writes and reports.
    try testing.expectEqual(@as(usize, 1500), probe.bytes_written);
    try testing.expectEqual(@as(usize, 1), pkt_handler.sent[2].sent_packets.count());
}

test "PacketPacker: a buffer that cannot hold a protectable packet packs none" {
    // RFC 9001 §5.4.2: the header-protection sample starts four bytes past the
    // packet number offset and is sixteen bytes long, so a packet shorter than
    // that cannot be protected at all — and a packet whose header protection
    // was skipped is a packet the peer cannot read. The longest long header
    // this packer writes is an Initial carrying a Retry token, so that is what
    // the sweep packs, and it walks every buffer size across the boundary where
    // the padding that makes the sample reachable stops fitting.
    var rng = TestRandom{};
    const dcid = &[_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const scid = &[_]u8{0x01};
    const token: [29]u8 = @splat(0x5c);
    const keys = try testServerKeys();

    // The shortest packet this connection can send at all: the long header
    // (first byte, version, both connection ids, the token's length and bytes
    // and the payload length), a one-byte packet number — nothing is acked yet,
    // so packet number zero is one byte — the four plaintext bytes the sample
    // starts in, and the AEAD tag.
    const min_protectable = 1 + 4 + (1 + dcid.len) + (1 + scid.len) +
        (1 + token.len) + 2 + 1 + 4 + AEAD_TAG_LEN;

    for (0..200) |buf_len| {
        var packer = PacketPacker.init(true, scid, dcid, 0x00000001);
        packer.initial_token = &token;
        var pkt_handler = ack_handler.PacketHandler.init(testing.allocator);
        defer pkt_handler.deinit();
        var crypto_mgr = crypto_stream.CryptoStreamManager.init(testing.allocator);
        defer crypto_mgr.deinit();
        var streams = stream_mod.StreamsMap.init(testing.allocator, true);
        defer streams.deinit();
        // One byte of payload: the case where the plaintext padding that
        // carries the sample is the only thing standing between a packet and
        // an unprotectable one.
        var pending_frames = frame_mod.PendingFrameQueue{};
        try testing.expect(pending_frames.tryPush(.{ .ping = {} }));

        var out_buf: [200]u8 = undefined;
        const written = try packer.packCoalesced(
            out_buf[0..buf_len],
            &pkt_handler,
            &crypto_mgr,
            &streams,
            &pending_frames,
            &keys.seal,
            null,
            null,
            null,
            1000,
            null,
            false,
            rng.random(),
        );

        if (written == 0) {
            // Nothing written means nothing spent: no packet number taken, no
            // packet recorded, and the PING still queued for the next send.
            try testing.expectEqual(@as(u64, 0), pkt_handler.next_pn[0]);
            try testing.expectEqual(@as(usize, 0), pkt_handler.sent[0].sent_packets.count());
            try testing.expectEqual(@as(usize, 1), pending_frames.len);
            continue;
        }
        try testing.expect(written <= buf_len);
        try testing.expect(written >= min_protectable);
        try testing.expectEqual(@as(u64, 1), pkt_handler.next_pn[0]);
        try testing.expectEqual(@as(usize, 1), pkt_handler.sent[0].sent_packets.count());
    }
}

test "PacketPacker: an Initial header beyond the staging budget leaves its flight pending" {
    // Retry tokens come from the peer. A larger output buffer does not grow
    // the packer's staging budget, so an oversized header must consume nothing.
    var rng = TestRandom{};
    const dcid = &[_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    var packer = PacketPacker.init(false, &.{0x01}, dcid, protocol.QUIC_V1);
    const token: [1400]u8 = @splat(0x5c);
    packer.initial_token = &token;
    var pkt_handler = ack_handler.PacketHandler.init(testing.allocator);
    defer pkt_handler.deinit();
    var crypto_mgr = crypto_stream.CryptoStreamManager.init(testing.allocator);
    defer crypto_mgr.deinit();
    var streams = stream_mod.StreamsMap.init(testing.allocator, false);
    defer streams.deinit();
    var pending_frames = frame_mod.PendingFrameQueue{};
    try testing.expect(pending_frames.tryPush(.{ .ping = {} }));
    const keys = try testClientKeys();
    var output: [2048]u8 = undefined;

    const written = try packer.packCoalesced(
        &output,
        &pkt_handler,
        &crypto_mgr,
        &streams,
        &pending_frames,
        &keys.seal,
        null,
        null,
        null,
        1000,
        null,
        false,
        rng.random(),
    );
    try testing.expectEqual(@as(usize, 0), written);
    try testing.expectEqual(@as(u64, 0), pkt_handler.next_pn[0]);
    try testing.expectEqual(@as(usize, 0), pkt_handler.sent[0].sent_packets.count());
    try testing.expectEqual(@as(usize, 1), pending_frames.len);
}

test "PacketPacker: a 0-RTT packet keeps the first flight's version" {
    // RFC 9369 §4.1: "The client MUST NOT send 0-RTT packets using the
    // negotiated version, even after processing a packet of that version from
    // the server." The long header's Version field is what a server reads a
    // 0-RTT packet under, so this is a version-1 packet on a connection that
    // has already negotiated version 2 — and the Handshake packet sent from
    // the same packer is the version-2 one.
    var rng = TestRandom{};
    const dcid = &[_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    var packer = PacketPacker.init(false, &[_]u8{0x01}, dcid, protocol.QUIC_V1);
    // What `Connection.switchVersion` does once the client has read the
    // negotiated version off a long header.
    packer.version = protocol.QUIC_V2;

    var pkt_handler = ack_handler.PacketHandler.init(testing.allocator);
    defer pkt_handler.deinit();
    var crypto_mgr = crypto_stream.CryptoStreamManager.init(testing.allocator);
    defer crypto_mgr.deinit();
    var streams = stream_mod.StreamsMap.init(testing.allocator, false);
    defer streams.deinit();
    var pending_frames = frame_mod.PendingFrameQueue{};
    streams.setMaxStreams(10, 10);
    streams.setPeerInitialMaxStreamData(65536, 65536, 65536);
    const stream = try streams.openBidiStream();
    try stream.send.writeData("data the peer will not read twice");
    const keys = try testClientKeys();

    var out_buf: [1500]u8 = undefined;
    const zero_rtt_len = try packer.packCoalesced(
        &out_buf,
        &pkt_handler,
        &crypto_mgr,
        &streams,
        &pending_frames,
        null,
        &keys.seal,
        null,
        null,
        1000,
        null,
        false,
        rng.random(),
    );
    try testing.expect(zero_rtt_len > 0);
    try testing.expectEqual(protocol.QUIC_V1, std.mem.readInt(u32, out_buf[1..5], .big));

    try crypto_mgr.getStream(2).writeData("handshake flight");
    const handshake_len = try packer.packCoalesced(
        &out_buf,
        &pkt_handler,
        &crypto_mgr,
        &streams,
        &pending_frames,
        null,
        null,
        &keys.seal,
        null,
        1000,
        null,
        false,
        rng.random(),
    );
    try testing.expect(handshake_len > 0);
    try testing.expectEqual(protocol.QUIC_V2, std.mem.readInt(u32, out_buf[1..5], .big));
}

fn expectPathPacket(
    packet: []u8,
    dcid: []const u8,
    path_id: u32,
    pn: u64,
) !void {
    const keys = try testServerKeys();
    const pn_offset = 1 + dcid.len;
    const pn_len = crypto_mod.removeHeaderProtection(
        packet,
        pn_offset,
        keys.open.hp_key,
        keys.open.cipher_suite,
    );
    try testing.expect(pn_len > 0);
    try testing.expectEqual(packet_mod.FIXED_BIT, packet[0] & 0xc0);
    try testing.expectEqual(@as(u8, 0), packet[0] & 0x18);
    try testing.expectEqualSlices(u8, dcid, packet[1..pn_offset]);
    var truncated_pn: u64 = 0;
    for (packet[pn_offset..][0..pn_len]) |byte| {
        truncated_pn = (truncated_pn << 8) | byte;
    }
    try testing.expectEqual(pn, truncated_pn);
    const header_len = pn_offset + pn_len;
    var wrong_path: [1500]u8 = undefined;
    @memcpy(wrong_path[0..packet.len], packet);
    try testing.expectError(error.AuthenticationFailed, keys.open.decryptPayloadForPath(
        path_id ^ 1,
        pn,
        wrong_path[0..header_len],
        wrong_path[header_len..packet.len],
    ));
    const plaintext = try keys.open.decryptPayloadForPath(
        path_id,
        pn,
        packet[0..header_len],
        packet[header_len..],
    );
    try testing.expectEqual(@as(u8, 0x01), plaintext[0]);
}

test "PacketPacker: path probes separate nonces and retain independent packet numbers" {
    // A path switch selects connection-owned state, never resets a shared counter.
    var rng = TestRandom{};
    const dcid = &[_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    var packer = PacketPacker.init(false, &.{0x01}, dcid, protocol.QUIC_V1);
    var path0 = ack_handler.PacketHandler.init(testing.allocator);
    defer path0.deinit();
    var path1 = ack_handler.PacketHandler.init(testing.allocator);
    defer path1.deinit();
    const keys = try testClientKeys();
    var packet0: [1500]u8 = undefined;
    var packet1: [1500]u8 = undefined;
    packer.application_path_id = 0;
    const first0 = try packer.packMtuProbe(&packet0, 1200, &path0, &keys.seal, 1000, rng.random());
    packer.application_path_id = 1;
    const first1 = try packer.packMtuProbe(&packet1, 1200, &path1, &keys.seal, 1000, rng.random());
    try testing.expectEqual(@as(u64, 0), first0.pn);
    try testing.expectEqual(first0.pn, first1.pn);
    try testing.expectEqual(first0.bytes_written, first1.bytes_written);
    try testing.expect(!std.mem.eql(
        u8,
        packet0[0..first0.bytes_written],
        packet1[0..first1.bytes_written],
    ));
    try expectPathPacket(packet0[0..first0.bytes_written], dcid, 0, first0.pn);
    try expectPathPacket(packet1[0..first1.bytes_written], dcid, 1, first1.pn);
    packer.application_path_id = 0;
    const next0 = try packer.packMtuProbe(&packet0, 1200, &path0, &keys.seal, 1001, rng.random());
    try testing.expect(next0.pn > first0.pn);
    try expectPathPacket(packet0[0..next0.bytes_written], dcid, 0, next0.pn);
    try testing.expectEqual(@as(usize, 2), path0.sent[2].sent_packets.count());
    try testing.expectEqual(@as(usize, 1), path1.sent[2].sent_packets.count());
}

test "PacketPacker: application data uses selected path handler and nonce" {
    var rng = TestRandom{};
    const dcid = &[_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    var packer = PacketPacker.init(false, &.{0x01}, dcid, protocol.QUIC_V1);
    var path0 = ack_handler.PacketHandler.init(testing.allocator);
    defer path0.deinit();
    var path1 = ack_handler.PacketHandler.init(testing.allocator);
    defer path1.deinit();
    var crypto_mgr = crypto_stream.CryptoStreamManager.init(testing.allocator);
    defer crypto_mgr.deinit();
    var streams = stream_mod.StreamsMap.init(testing.allocator, false);
    defer streams.deinit();
    var pending_frames = frame_mod.PendingFrameQueue{};
    var packet: [1500]u8 = undefined;
    for ([_]u32{ 0, 1, 0 }) |path_id| {
        packer.application_path_id = path_id;
        const handler = if (path_id == 0) &path0 else &path1;
        pending_frames.push(.{ .ping = {} });
        const written = try packAppOnly(
            &packer,
            handler,
            &crypto_mgr,
            &streams,
            &pending_frames,
            &packet,
            rng.random(),
        );
        try testing.expect(written > 0);
        const sent = handler.sent[2].sent_packets.values();
        try expectPathPacket(packet[0..written], dcid, path_id, sent[sent.len - 1].pn);
    }
    try testing.expectEqual(@as(usize, 2), path0.sent[2].sent_packets.count());
    try testing.expectEqual(@as(usize, 1), path1.sent[2].sent_packets.count());
    try testing.expectEqual(@as(u64, 0), path1.sent[2].sent_packets.values()[0].pn);
    try testing.expect(path0.sent[2].sent_packets.values()[1].pn > 0);
}

test "PacketPacker: negotiated path zero emits PATH_ACK and legacy emits ACK" {
    // Null and zero are distinct configurations even when the path's PN is identical.
    var rng = TestRandom{};
    const dcid = &[_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const path_ids = [_]?u32{ null, 0, 1 };
    for (path_ids) |path_id| {
        var packer = PacketPacker.init(false, &.{0x01}, dcid, protocol.QUIC_V1);
        packer.application_path_id = path_id;
        var handler = ack_handler.PacketHandler.init(testing.allocator);
        defer handler.deinit();
        try handler.recv[2].onPacketReceived(0, true, 1000, 0);
        try handler.recv[2].onPacketReceived(1, true, 1000, 0);
        var crypto_mgr = crypto_stream.CryptoStreamManager.init(testing.allocator);
        defer crypto_mgr.deinit();
        var streams = stream_mod.StreamsMap.init(testing.allocator, false);
        defer streams.deinit();
        var pending_frames = frame_mod.PendingFrameQueue{};
        var packet: [1500]u8 = undefined;
        const written = try packAppOnly(
            &packer,
            &handler,
            &crypto_mgr,
            &streams,
            &pending_frames,
            &packet,
            rng.random(),
        );
        try testing.expect(written > 0);
        const keys = try testServerKeys();
        const pn_offset = 1 + dcid.len;
        const pn_len = crypto_mod.removeHeaderProtection(
            packet[0..written],
            pn_offset,
            keys.open.hp_key,
            keys.open.cipher_suite,
        );
        try testing.expect(pn_len > 0);
        const header_len = pn_offset + pn_len;
        const plaintext = if (path_id) |id|
            try keys.open.decryptPayloadForPath(
                id,
                0,
                packet[0..header_len],
                packet[header_len..written],
            )
        else
            try keys.open.decryptPayload(0, packet[0..header_len], packet[header_len..written]);
        const ack = try Frame.parse(plaintext);
        if (path_id) |id| {
            switch (ack) {
                .path_ack => |a| {
                    try testing.expectEqual(id, a.path_id);
                    try testing.expectEqual(@as(u64, 1), a.ack.largest_ack);
                },
                .path_ack_ecn => |a| {
                    try testing.expectEqual(id, a.path_id);
                    try testing.expectEqual(@as(u64, 1), a.ack.largest_ack);
                },
                else => return error.TestUnexpectedResult,
            }
        } else {
            switch (ack) {
                .ack => |a| try testing.expectEqual(@as(u64, 1), a.largest_ack),
                .ack_ecn => |a| try testing.expectEqual(@as(u64, 1), a.largest_ack),
                else => return error.TestUnexpectedResult,
            }
        }
    }
}

test "PacketPacker: application path configuration never changes long header protection" {
    // Initial and Handshake remain on path zero; 0-RTT retains legacy protection too.
    const cases = [_]struct { level: ack_handler.EncLevel, zero_rtt: bool }{
        .{ .level = .initial, .zero_rtt = false },
        .{ .level = .handshake, .zero_rtt = false },
        .{ .level = .application, .zero_rtt = true },
    };
    const dcid = &[_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    const keys = try testClientKeys();
    for (cases) |case| {
        var packets: [2][1500]u8 = undefined;
        var lengths: [2]usize = undefined;
        for ([_]?u32{ null, 1 }, 0..) |path_id, i| {
            var rng = TestRandom{};
            var packer = PacketPacker.init(false, &.{0x01}, dcid, protocol.QUIC_V1);
            packer.application_path_id = path_id;
            var handler = ack_handler.PacketHandler.init(testing.allocator);
            defer handler.deinit();
            var crypto_mgr = crypto_stream.CryptoStreamManager.init(testing.allocator);
            defer crypto_mgr.deinit();
            var streams = stream_mod.StreamsMap.init(testing.allocator, false);
            defer streams.deinit();
            var pending_frames = frame_mod.PendingFrameQueue{};
            if (case.zero_rtt) {
                streams.setMaxStreams(10, 10);
                streams.setPeerInitialMaxStreamData(65536, 65536, 65536);
                const stream = try streams.openBidiStream();
                try stream.send.writeData("early path zero");
            } else {
                pending_frames.push(.{ .ping = {} });
            }
            lengths[i] = try packer.packSinglePacket(
                &packets[i],
                case.level,
                &handler,
                &crypto_mgr,
                &streams,
                &pending_frames,
                &keys.seal,
                1000,
                1200,
                null,
                case.zero_rtt,
                false,
                rng.random(),
            );
            try testing.expectEqual(@as(usize, 1200), lengths[i]);
            try testing.expect(packets[i][0] & 0x80 != 0);
        }
        try testing.expectEqualSlices(u8, packets[0][0..lengths[0]], packets[1][0..lengths[1]]);
    }
}

test "PacketPacker: application validation padding preserves challenge and refuses short buffer" {
    var rng = TestRandom{};
    const dcid = &[_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    var packer = PacketPacker.init(false, &.{0x01}, dcid, protocol.QUIC_V1);
    packer.application_path_id = 1;
    packer.application_padding_min = 1200;
    var handler = ack_handler.PacketHandler.init(testing.allocator);
    defer handler.deinit();
    var crypto_mgr = crypto_stream.CryptoStreamManager.init(testing.allocator);
    defer crypto_mgr.deinit();
    var streams = stream_mod.StreamsMap.init(testing.allocator, false);
    defer streams.deinit();
    var pending_frames = frame_mod.PendingFrameQueue{};
    const challenge = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    pending_frames.push(.{ .path_challenge = challenge });
    var packet: [1500]u8 = undefined;
    try testing.expectEqual(@as(usize, 0), try packAppOnly(
        &packer,
        &handler,
        &crypto_mgr,
        &streams,
        &pending_frames,
        packet[0..1199],
        rng.random(),
    ));
    try testing.expectEqual(@as(u64, 0), handler.next_pn[2]);
    try testing.expectEqual(@as(usize, 1), pending_frames.len);
    const written = try packAppOnly(
        &packer,
        &handler,
        &crypto_mgr,
        &streams,
        &pending_frames,
        &packet,
        rng.random(),
    );
    try testing.expectEqual(@as(usize, 1200), written);
    const keys = try testServerKeys();
    const pn_offset = 1 + dcid.len;
    const pn_len = crypto_mod.removeHeaderProtection(
        packet[0..written],
        pn_offset,
        keys.open.hp_key,
        keys.open.cipher_suite,
    );
    try testing.expect(pn_len > 0);
    const header_len = pn_offset + pn_len;
    const plaintext = try keys.open.decryptPayloadForPath(
        1,
        0,
        packet[0..header_len],
        packet[header_len..written],
    );
    var frame_len: usize = undefined;
    const decoded = try Frame.parseSized(plaintext, &frame_len);
    try testing.expectEqualSlices(u8, &challenge, &decoded.path_challenge);
    for (plaintext[frame_len..]) |byte| try testing.expectEqual(@as(u8, 0), byte);
}

test "PacketPacker: off-path probes preserve pending ACK crypto streams and controls" {
    var rng = TestRandom{};
    const dcid = &[_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    var packer = PacketPacker.init(false, &.{0x01}, dcid, protocol.QUIC_V1);
    packer.application_path_id = 0;
    packer.send_handshake_done = true;
    var handler = ack_handler.PacketHandler.init(testing.allocator);
    defer handler.deinit();
    try handler.onPacketReceived(.application, 0, true, 1000, 0);
    try handler.onPacketReceived(.application, 1, true, 1000, 0);
    var crypto_mgr = crypto_stream.CryptoStreamManager.init(testing.allocator);
    defer crypto_mgr.deinit();
    try crypto_mgr.getStream(3).writeData("pending crypto");
    var streams = stream_mod.StreamsMap.init(testing.allocator, false);
    defer streams.deinit();
    streams.setMaxStreams(10, 10);
    streams.setPeerInitialMaxStreamData(65536, 65536, 65536);
    const stream = try streams.openBidiStream();
    try stream.send.writeData("pending stream");
    var pending_frames = frame_mod.PendingFrameQueue{};
    pending_frames.push(.{ .max_data = 12345 });
    const challenge = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    const response = [_]u8{ 8, 7, 6, 5, 4, 3, 2, 1 };
    const keys = try testClientKeys();
    const receiver = try testServerKeys();
    var packet: [1500]u8 = undefined;
    for (0..2) |pn| {
        const written = try packer.packOffPath(
            &packet,
            &handler,
            &keys.seal,
            .{ .challenge = challenge, .response = response },
            rng.random(),
        );
        try testing.expect(written > 0 and written < 1200);
        const pn_offset = 1 + dcid.len;
        const pn_len = crypto_mod.removeHeaderProtection(
            packet[0..written],
            pn_offset,
            receiver.open.hp_key,
            receiver.open.cipher_suite,
        );
        try testing.expect(pn_len > 0);
        const header_len = pn_offset + pn_len;
        const plaintext = try receiver.open.decryptPayloadForPath(
            0,
            @intCast(pn),
            packet[0..header_len],
            packet[header_len..written],
        );
        var consumed: usize = undefined;
        var offset: usize = 0;
        const decoded_challenge = try Frame.parseSized(plaintext[offset..], &consumed);
        try testing.expectEqualSlices(u8, &challenge, &decoded_challenge.path_challenge);
        offset += consumed;
        const decoded_response = try Frame.parseSized(plaintext[offset..], &consumed);
        try testing.expectEqualSlices(u8, &response, &decoded_response.path_response);
        offset += consumed;
        try testing.expectEqual(plaintext.len, offset);
        try testing.expect(handler.recv[2].ack_queued);
        try testing.expect(crypto_mgr.getStream(3).hasData());
        try testing.expect(stream.send.hasData());
        try testing.expectEqual(@as(usize, 1), pending_frames.len);
        try testing.expect(packer.send_handshake_done);
        try testing.expectEqual(@as(u64, pn + 1), handler.next_pn[2]);
        try testing.expect(!handler.acksUnsentPacket(.application, @intCast(pn), 0, &.{}));
        try testing.expectEqual(@as(u64, 0), handler.bytes_in_flight);
        try testing.expectEqual(@as(usize, 0), handler.sent[2].sent_packets.count());
    }
    const normal_written = try packer.packCoalesced(
        &packet,
        &handler,
        &crypto_mgr,
        &streams,
        &pending_frames,
        null,
        null,
        null,
        &keys.seal,
        1000,
        null,
        false,
        rng.random(),
    );
    try testing.expect(normal_written > 0);
    try testing.expectEqual(@as(u64, normal_written), handler.bytes_in_flight);
    try testing.expectEqual(@as(u64, 3), handler.next_pn[2]);
    try testing.expect(!handler.recv[2].ack_queued);
    try testing.expectEqual(@as(usize, 0), pending_frames.len);
}

test "PacketPacker: empty and short off-path calls consume no packet number" {
    var rng = TestRandom{};
    var packer = PacketPacker.init(false, &.{1}, &.{2}, protocol.QUIC_V1);
    var handler = ack_handler.PacketHandler.init(testing.allocator);
    defer handler.deinit();
    const keys = try testClientKeys();
    var packet: [64]u8 = undefined;
    try testing.expectEqual(@as(usize, 0), try packer.packOffPath(
        &packet,
        &handler,
        &keys.seal,
        .{},
        rng.random(),
    ));
    try testing.expectEqual(@as(usize, 0), try packer.packOffPath(
        packet[0..20],
        &handler,
        &keys.seal,
        .{ .challenge = @splat(1) },
        rng.random(),
    ));
    try testing.expectEqual(@as(u64, 0), handler.next_pn[2]);
    try testing.expectEqual(@as(?u64, null), handler.skipped_pns[0]);
}
