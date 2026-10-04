//! The DATAGRAM seam: RFC 9221's unreliable messages, bounded and owned.
//!
//! # What this is and what it is not
//!
//! A QUIC DATAGRAM frame is not a UDP datagram. It rides inside a packet on a
//! connection, it is flow-controlled by nothing at all, and it is **not
//! retransmitted** — RFC 9221 §5.2 makes loss the peer's problem and this
//! node's congestion controller's. The UDP datagram this project sends on the
//! wire is `batch.Send`, and `Batch` is the seam for it; this is the seam for
//! the other thing, one layer up, and the two never meet.
//!
//! # Off by default, and the knob that turns it on
//!
//! Support is negotiated, not asserted: RFC 9221 §3 has each end advertise
//! `max_datagram_frame_size` in its transport parameters, and the core enables
//! the extension only when **both** did (`connection.zig:3382`). A null value
//! is not "unlimited" — its absence is what tells the peer this endpoint has no
//! DATAGRAM at all — so `Config.max_datagram_frame_size` defaults to null and a
//! node that wants none says nothing. A caller that wants them states the
//! frame size on **both** ends of the connection, and each end has its own
//! configuration surface for that: a bridge's `Config` for a connection it
//! accepts, and a dialer's `Config` for one it originates (`dial.zig:302`) —
//! a dialled connection is built by `Dialer` and never reads the bridge's
//! configuration. One end configured and the other not is the same as neither,
//! and every send on that connection is `error.DatagramsNotEnabled` for as long
//! as it lives.
//!
//! # Bounded, in both directions, by two different numbers
//!
//! `max_payload` is the format's ceiling: what the core's queue will hold in
//! one entry, and the largest payload a frame can carry however much the peer
//! says. `maxDatagramPayloadSize` is the smaller of what the peer's transport
//! parameter allows and what one packet can hold. A send is refused against
//! **both**, before the core is asked, so an over-long payload is a named
//! refusal rather than a queue entry the packer cannot place.
//!
//! # Who owns which buffer
//!
//! **The send queue is the core's, and it copies.** `DatagramQueue.push`
//! (`connection.zig:695`) copies into its own ring, so `bytes` may be released
//! the moment `send` returns. The queue is bounded — a fixed ring, a high
//! water mark, no growth — so a send past it is `error.DatagramQueueFull`
//! rather than a stall, and the queue length is readable through
//! `datagramQueued` so a caller can decide before it writes rather than after.
//!
//! **The receive buffer is the caller's**, and this is the one direction with a
//! trap worth naming: the core copies the head entry into it *and drops it*, so
//! a buffer too small leaves the entry where it was and answers null
//! (`connection.zig:705-720`). Nothing is lost and nothing is truncated — a
//! caller that gets null has to ask whether the queue was empty or whether its
//! buffer was short, and `max_payload` is the width that makes the second
//! answer impossible to hit by accident.
//!
//! **The tests are on the other side of this one.** Every value here is a
//! function of a `Connection` whose peer has answered a handshake, and the only
//! honest way to have one is to drive that handshake — which is
//! `quic_bridge.zig`'s `Client` fixture and its test section, where the round
//! trip, both refusals and the short-buffer receive are pinned. This file
//! holds no fixture of its own, because a hand-built `Connection` literal
//! would be testing a core that no peer ever agreed with.

const quic = @import("quic");

const Connection = quic.connection.Connection;
const Queue = quic.connection.DatagramQueue;

/// The most bytes one DATAGRAM frame's payload may be, whatever any peer
/// says: what the core's queue holds in one entry, and the smallest of what
/// the peer's transport parameter, one packet's budget and this figure allow
/// (`connection.zig:4872`).
pub const max_payload: usize = Queue.MAX_DATAGRAM_SIZE;

/// What a datagram operation refuses.
///
/// Its own set and not `quic_bridge.Error`, because nothing else on this path
/// can raise any of it: a stream cannot be too long and a packet cannot be too
/// big for a datagram.
pub const Error = error{
    /// The peer never advertised `max_datagram_frame_size`, so there is no
    /// DATAGRAM extension on this connection and no payload size that would
    /// change that. Recoverable: a connection whose handshake has not finished
    /// looks exactly like this.
    DatagramsNotEnabled,
    /// The payload is larger than the peer's parameter allows, larger than one
    /// packet can hold, or larger than `max_payload`. Refused before the core
    /// is asked, so nothing is queued and nothing is drawn.
    DatagramTooLarge,
    /// The core's fixed send queue is at its high water mark. Transient by
    /// design: the queue drains as the packer places frames, so a caller that
    /// can wait should and one that cannot should not send a datagram.
    DatagramQueueFull,
};

/// Whether both ends of this connection advertised the extension.
pub fn enabled(conn: *const Connection) bool {
    return conn.datagrams_enabled;
}

/// The most bytes one datagram may carry here, or null when there is no
/// extension on this connection.
///
/// The smaller of the peer's `max_datagram_frame_size` less its frame
/// overhead, one packet's payload budget, and `max_payload`. A caller that
/// wants to send a fixed size checks this once and sizes its messages from it,
/// which is why it is exposed rather than folded into `send`.
pub fn maxPayload(conn: *const Connection) ?usize {
    return conn.maxDatagramPayloadSize();
}

/// How many datagrams are waiting to be placed in a packet. Zero to the core's
/// high water mark.
pub fn queued(conn: *const Connection) usize {
    return conn.datagramSendQueueLen();
}

/// Queue `bytes` as one datagram, to be carried at `at`.
///
/// **Nothing is retained.** The core copies into its own ring, so `bytes` may
/// be released when this returns, and `queued` is the only handle on it.
///
/// Both size checks run before the core is asked, which is what makes the
/// refusals free: an oversized payload costs no queue entry and no entropy.
/// The core's own answers are mapped onto the same names rather than wrapped,
/// because a caller has to act on "too large" and "the queue is full" very
/// differently, and only the second of them is worth retrying.
pub fn send(conn: *Connection, bytes: []const u8, at: i64) Error!void {
    if (!conn.datagrams_enabled) return error.DatagramsNotEnabled;
    if (bytes.len > max_payload) return error.DatagramTooLarge;
    if (conn.maxDatagramPayloadSize()) |limit| {
        if (bytes.len > limit) return error.DatagramTooLarge;
    }
    conn.sendDatagram(bytes, at) catch |err| switch (err) {
        error.DatagramsNotEnabled => return error.DatagramsNotEnabled,
        error.DatagramTooLarge => return error.DatagramTooLarge,
        error.DatagramQueueFull => return error.DatagramQueueFull,
    };
}

/// Take the next datagram into `buffer`, or null when there is none to take.
///
/// **The bytes are copied into the caller's buffer and the queue entry is
/// dropped**, so the result borrows `buffer` and is good until the next call
/// overwrites it. Nothing is allocated and nothing is retained.
///
/// **Null is two answers and the caller owns the difference.** The queue was
/// empty, or the entry at its head was longer than `buffer` — in which case it
/// is still queued and a second call with a wider buffer takes it. A buffer of
/// `max_payload` cannot hit the second: no entry is ever longer, so null from
/// one is the first answer and nothing else.
pub fn recv(conn: *Connection, buffer: []u8, at: i64) ?[]const u8 {
    const length = conn.recvDatagram(buffer, at) orelse return null;
    return buffer[0..length];
}
