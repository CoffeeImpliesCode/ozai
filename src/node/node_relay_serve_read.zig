//! The read a serving relay makes of every client slot it holds, and the rules
//! that decide what a byte off that stream still means.
//!
//! **Split from the admission half on what a pass walks.** That file walks the
//! connections this node accepted and spends slots on the ones that negotiated
//! the relay ALPN; this one walks the slots that walk handed out. The two meet
//! at a single call, so nothing here can run before there is a slot to read,
//! and no slot is admitted without this file coming next in the pass.
//!
//! `handshakeEnded` is public because the datagram half asks the same question
//! of the same slot on the same pass: the read's gate and the frame's gate are
//! two checks that have to agree, and they are one function here so that they
//! cannot drift apart.

const node_mod = @import("node.zig");
const Error = @import("node_error.zig").Error;
const framing = @import("node_framing.zig");
const relay_admit = @import("node_relay_serve_admit.zig");
const relay_serve = @import("node_relay_serve.zig");

const Instant = @import("../transport/quic_conn.zig").Instant;

const Client = relay_admit.Client;

/// Read every live client, then tell each handshake what its stream said.
pub fn serveRead(self: *node_mod.Node, at: Instant) Error!bool {
    var moved = false;
    for (self.relay_state.clients) |*slot| {
        if (!slot.live) continue;
        // **A slot outlives the handshake that ended it, and this is the read
        // that kept serving it.** `serveRelease` hands a slot back only once
        // the core has let go of its connection, which is passes after the
        // answer that ended the handshake — and a denial is a write rather
        // than a close, so the connection stays and the slot stays `live` and
        // reachable for the whole of it. Draining such a slot is serving a
        // client this relay has already refused.
        if (handshakeEnded(slot)) continue;
        const conn = node_mod.connFor(self, slot.conn) orelse continue;
        // **No cursor, every pass, and that is what "the client's stream"
        // means.** `serveRead` re-derives this handle each tick rather than
        // retaining one, so it has nothing to pass as a cursor: a stream id
        // would be a cursor past the stream on the next pass and answer null
        // and stop the drain. The relay protocol has one peer-opened stream
        // per connection, so the lowest one is the stream there is.
        //
        // **And the lowest one is id zero here.** This end accepted the
        // connection, so the peer's first bidirectional stream is the one
        // RFC 9000 §2.1 numbers `0x00` (`quic_conn.Conn.peerStream`). A `0`
        // cursor would skip it — the challenge is written, the client answers
        // on exactly that stream, and nothing this node counts moves: no
        // admission and no refusal either.
        var incoming = conn.peerStream(null) orelse continue;
        moved = try incoming.drain(self.gpa, &slot.inbox) or moved;
        moved = try relay_serve.serveMessages(self, at, slot) or moved;
        // Whole frames are served before the end is believed, so a client that
        // authenticates and FINs in one flight is still admitted.
        const finished = incoming.finished();
        if (framing.discardTail(&slot.inbox, finished)) {
            self.stats.relay_stream_truncated += 1;
        }
        moved = try serveEnded(self, at, slot, finished) or moved;
    }
    return moved;
}

/// The machine's own end-of-stream event, for a handshake still running.
///
/// **A FIN mid-handshake is the refusal the stream is asking for, and this is
/// where it is said out loud.** `incoming.finished()` alone only clears the
/// inbox; nothing stepped the machine, so a peer that opened the stream and
/// ended it before authenticating held its slot until its QUIC connection
/// died — four of those and `serveAdmit` refuses every client for the node's
/// lifetime. `relay_server.step` already answers `Failure.stream_ended` with
/// `Action.close` from each of the three states that can still move.
///
/// **Once, because the machine absorbs it.** `step` folds a terminal state
/// into itself and answers no action (server.zig:365-370), so the close
/// happens on the pass that first sees the FIN and never again; and it is the
/// same `.close` arm every other refusal takes, so a slot that never proved
/// itself is ended on the same timeline as one that did — stamped with this
/// pass's own instant, because a close stamped with zero leaves the core's
/// `closing_start_time` at zero, never arms the 3-PTO drain, and the slot is
/// never handed back at all.
///
/// Only `.opened` and `.challenged` are fed, which is exactly the set
/// `serveMessage` feeds a frame to. A client that proved itself has left the
/// handshake, and its stream ending is the connection's business, not the
/// machine's.
fn serveEnded(self: *node_mod.Node, at: Instant, slot: *Client, finished: bool) Error!bool {
    if (!finished) return false;
    switch (slot.handshake) {
        .opened, .challenged => return relay_admit.serveHandshake(self, at, slot, .stream_ended),
        else => {},
    }
    return false;
}

/// Whether this slot's handshake has ended and nothing can move it again.
///
/// **`.denied` and `.failed`, with the other four named so this cannot be read
/// as a wildcard.** `relay_server.step` folds every later event into either of
/// them and answers no action (`server.zig:369-370`), so they are what a slot
/// rests in between the answer that ended its handshake and the close
/// `serveRelease` waits out.
///
/// **`.authenticated` is not one of them, and a gate that named it would skip
/// every slot on every pass.** It exists only between the proof and the access
/// answer inside one `serveHandshake` call, which stores that answer over it
/// before anything else can fail, so it is never what a slot holds between two
/// frames. `.admitted` is the resting state that is not an ending: it is a
/// client this relay took, and its datagrams are the work the relay is for.
pub fn handshakeEnded(slot: *const Client) bool {
    return switch (slot.handshake) {
        .denied, .failed => true,
        .opened, .challenged, .authenticated, .admitted => false,
    };
}
