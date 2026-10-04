//! Borrowed QUIC connection operations over caller-provided bytes and time.
//! Connection ownership and reaping remain with the bridge; socket I/O stays
//! with the caller. No handle or stream may outlive its connection entry.

const std = @import("std");
const quic = @import("quic");
const batch = @import("batch.zig");
const SocketAddr = @import("../base/addr.zig").SocketAddr;
const Error = @import("quic_error.zig").Error;
const stream_mod = @import("quic_stream.zig");
const datagram_mod = @import("quic_datagram.zig");
const core_stream = quic.stream;

/// Nanoseconds on the caller's monotonic timeline, as expected by the core.
pub const Instant = i64;
/// Minimum room checked before asking the core to consume outgoing frames.
pub const min_datagram = quic.connection_manager.MIN_INITIAL_DATAGRAM;

/// The core's "no address" value. `fromCoreAddress` answers null for it and
/// `toCoreAddress` has no spelling for it, because `SocketAddr` cannot name an
/// absent address — so a caller that has to recognise a nameless core address
/// rather than translate one names it here.
pub const unset_address: quic.address.Address = .unset;

/// The core's pre-accept admission vocabulary, re-exported so first-party code
/// implements the hook without naming the vendored module itself. The hook runs
/// on `ConnectionManager.recvDatagram`'s thread, before a connection exists, and
/// its `retry` verdict is the only application verdict that reaches the peer as
/// a token: `endpoint.zig` records at length why a verdict made afterwards is a
/// refusal instead.
pub const Admission = quic.connection_manager.Admission;
pub const AdmissionVerdict = quic.connection_manager.AdmissionVerdict;
pub const AdmissionHook = quic.connection_manager.AdmissionHook;

/// One socket write, borrowing its payload from the caller's drain buffer.
pub const Egress = struct {
    /// Peer address on the active path when the payload was built.
    to: SocketAddr,
    /// Feed to `batch.Runs.init` with the socket's capability.
    send: batch.Send,
};

/// A borrowed connection entry. Copies refer to the same core connection;
/// reaping the entry invalidates every copy and every stream borrowed from it.
pub const Conn = struct {
    /// Read connection state off the owner's entry; do not write the entry.
    entry: *quic.connection_manager.ConnEntry,

    /// Core id, unique per bridge and never reused.
    pub fn id(self: Conn) u64 {
        return self.entry.id;
    }

    /// Peer address on the active path, or null while it has no address.
    pub fn peer(self: Conn) ?SocketAddr {
        return fromCoreAddress(self.entry.conn.peerAddress());
    }

    /// Local address on the active path, or null while it has no address.
    pub fn local(self: Conn) ?SocketAddr {
        return fromCoreAddress(self.entry.conn.localAddress());
    }

    /// Whether the core has proved the address this flow arrived from: it
    /// opened with a valid Retry or NEW_TOKEN, or the peer has since sent a
    /// Handshake packet. One bit read from the core, never a second copy of it.
    ///
    /// Read before the handshake completes, this is what tells an admission
    /// filter whether asking the peer to come back with a Retry token is still
    /// worth anything: QUIC permits one Retry per flow.
    pub fn isValidated(self: *const Conn) bool {
        return self.entry.conn.isPathValidated();
    }

    /// Whether the handshake is done and the connection carries stream data.
    pub fn established(self: Conn) bool {
        return self.entry.conn.isEstablished();
    }

    /// The protocol this connection's handshake negotiated, or null when it
    /// negotiated none.
    ///
    /// **`Connection.negotiatedAlpn` cannot answer that question, which is why
    /// this exists.** It answers `config.alpn[0]` whenever the handshake
    /// selected nothing (`vendor/quic/src/quic/tls13.zig:2060-2063`), and its
    /// own note says that fallback "is not a negotiated protocol and nothing
    /// treats it as one" — so on a server it is that endpoint's own first
    /// configured protocol standing in for an answer the peer never gave. A
    /// peer that advertised no ALPN at all selects nothing, and asking the
    /// core that question returns that first configured protocol instead: the
    /// answer would be the same for every such peer and for every connection
    /// whose handshake has not been read, which is two answers to one question
    /// wearing one value.
    ///
    /// `selected_alpn[0..selected_alpn_len]` is the handshake's own record. The
    /// selection walk writes both fields and nothing else does
    /// (`tls13.zig:3163-3164`), a zero length is "no protocol was selected"
    /// (`tls13.zig:1991-1996`), and the core's own writers that record a ticket
    /// read this same slice rather than the fallback for exactly this reason
    /// (`tls13.zig:3672-3676`, `tls13.zig:3997-4001`). Read after
    /// `established`, so it is a finished handshake's selection and not a
    /// pending one.
    pub fn negotiatedAlpn(self: Conn) ?[]const u8 {
        const handshake = self.entry.conn.tls13_hs orelse return null;
        if (handshake.selected_alpn_len == 0) return null;
        return handshake.selected_alpn[0..handshake.selected_alpn_len];
    }

    /// Whether the core has finished; drain before the owner sweeps the entry.
    pub fn closed(self: Conn) bool {
        return self.entry.conn.isClosed();
    }

    /// Queue an application close at `at`; this does not reap the entry.
    /// `reason` is borrowed, not copied, and must stay alive and unchanged until
    /// the owner reaps the connection. Drain queued close packets before sweep;
    /// after reap neither this handle nor its borrowed streams may be used.
    pub fn close(self: Conn, application_error: u64, reason: []const u8, at: Instant) void {
        self.entry.conn.close(application_error, reason, at);
    }

    /// Build a bounded prefix of outgoing datagrams into the caller's buffers.
    /// The result borrows `out`; each send borrows `buffer` until overwritten.
    /// Bytes and order are exactly those of core `sendAt`, grouped into runs
    /// split at size changes. Single datagrams carry no segment size; socket
    /// capability and splitting a run into writes remain the caller's concern.
    ///
    /// `NoPathAddress` and initial `NoRoom` build nothing. Mid-flight exhaustion
    /// returns the completed prefix; drain again until the result is empty.
    /// `CoreRefused` logs the core error but cannot return datagrams already
    /// consumed in this pass. Room is checked before `sendAt` consumes frames.
    pub fn drain(
        self: Conn,
        out: []Egress,
        buffer: []u8,
        at: Instant,
        random: std.Random,
    ) Error![]Egress {
        const conn = self.entry.conn;
        const ecn: ?batch.Ecn = batch.Recv.ecnFromBits(conn.getEcnMark());
        const core_peer = conn.peerAddress().*;
        if (core_peer == .unset) return error.NoPathAddress;
        const to = fromCoreAddress(&core_peer) orelse return error.NoPathAddress;
        if (out.len == 0 or buffer.len < min_datagram) return error.NoRoom;

        var filled: usize = 0;
        var used: usize = 0;
        var run_start: usize = 0;
        var run_size: usize = 0;
        while (true) {
            // Reserve a slot for the current run and any size-change run before
            // building a datagram, so stopping always leaves room to close it.
            const slots = out.len - used;
            if (slots == 0 or (run_size != 0 and slots < 2)) break;
            if (buffer.len - filled < min_datagram) break;

            const len = conn.sendAt(buffer[filled..], at, random) catch |err| {
                std.log.warn("quic bridge: the core refused to build a packet: {t}", .{err});
                return error.CoreRefused;
            };
            if (len == 0) break;
            if (run_size == 0) {
                run_size = len;
            } else if (len != run_size) {
                used = try closeRun(out, used, buffer, run_start, filled, run_size, ecn, to);
                run_start = filled;
                run_size = len;
            }
            filled += len;
        }
        if (run_size != 0) {
            used = try closeRun(out, used, buffer, run_start, filled, run_size, ecn, to);
        }
        return out[0..used];
    }

    /// The peer's next bidirectional stream after `after`, or null when there
    /// is none. The returned stream borrows the connection's stream entry.
    ///
    /// **It is a scan, and the scan is the whole of the contract.** The core
    /// keeps both ends' bidirectional streams in one map with no order of its
    /// own (`stream.zig:1518`), so "the next one" has to be defined against
    /// something the caller holds: the id of the stream it last took. A caller
    /// holding the stream it is reading passes the same `after` every pass and
    /// is handed that same stream back, which is what makes this a poll and
    /// not a take; a caller walking a set of them passes the last id it took
    /// and gets the next in stream order.
    ///
    /// **`after` is optional because zero is a stream id.** RFC 9000 §2.1
    /// numbers a client-initiated bidirectional stream from **zero** (`0b00`)
    /// and a server-initiated one from one (`0b01`), and the core allocates
    /// from the same bases (`stream.zig:1636-1639`), so on a connection this
    /// end accepted the peer's first bidirectional stream **is** id zero. A
    /// caller that had nothing to pass has no cursor to pass, and `null` says
    /// so; a `0` cursor would say "everything up to and including the
    /// peer's first stream" and skip the one stream a serving relay has to
    /// read — the client opens it and every frame after the challenge arrives
    /// on it, so the relay writes its challenge, the client answers, and the
    /// relay's read never finds the answer.
    ///
    /// `acceptUni` keeps a plain cursor for the same walk, and the difference
    /// is not an oversight: a unidirectional stream is numbered from two
    /// (`0b10`, `0b11`), so no unidirectional id is ever zero and a plain
    /// zero needs no second meaning there.
    ///
    /// The map is scanned whole and the smallest id the cursor admits wins, so
    /// the answer is stream order rather than whatever the hash table happened
    /// to yield first. The scan is bounded by the connection's live
    /// bidirectional stream count, and running off the end of it is the
    /// explicit null: nothing the cursor admits is the answer, and not a
    /// failure.
    pub fn peerStream(self: Conn, after: ?u64) ?stream_mod.Stream {
        var taken: ?*core_stream.Stream = null;
        var it = self.entry.conn.streams.streams.iterator();
        while (it.next()) |entry| {
            // The core's own key for this stream, which is what `after` is
            // compared against; the entry beside it is the same id as a
            // field, and the map key is the one the loop has to read.
            const mapped_id = entry.key_ptr.*;
            if (after) |cursor| {
                if (mapped_id <= cursor) continue;
            }
            // One this end opened is this caller's own stream to write on, and
            // `openBidi` already handed it out; the same filter `acceptUni`
            // applies on the storage these two maps share.
            if (core_stream.isLocal(mapped_id, self.entry.conn.is_server)) continue;
            const candidate = entry.value_ptr.*;
            if (taken == null or candidate.stream_id < taken.?.stream_id) taken = candidate;
        }
        const found = taken orelse return null;
        return .{ .entry = found };
    }

    /// Open a borrowed send-only stream; writes past peer credit are refused.
    pub fn openUni(self: Conn) Error!stream_mod.UniStream {
        return stream_mod.openUni(self.entry.conn);
    }

    /// Borrow the peer's next receive-only stream after `after`, or null.
    /// Pass 0 first; core stream storage is unordered, not an acceptance queue.
    pub fn acceptUni(self: Conn, after: u64) ?stream_mod.RecvUni {
        return stream_mod.acceptUni(self.entry.conn, after);
    }

    /// Whether both ends advertised RFC 9221 DATAGRAM support.
    pub fn datagramsEnabled(self: Conn) bool {
        return datagram_mod.enabled(self.entry.conn);
    }

    /// Maximum datagram payload, or null when the extension is not enabled.
    pub fn datagramMaxPayload(self: Conn) ?usize {
        return datagram_mod.maxPayload(self.entry.conn);
    }

    /// Datagrams queued for packetization, up to the core's high water mark.
    pub fn datagramQueued(self: Conn) usize {
        return datagram_mod.queued(self.entry.conn);
    }

    /// Copy `bytes` into the core's datagram queue at `at`.
    /// The caller may release them on return; a refusal queues no message.
    /// DATAGRAM frames are not retransmitted.
    pub fn sendDatagram(self: Conn, bytes: []const u8, at: Instant) Error!void {
        return datagram_mod.send(self.entry.conn, bytes, at);
    }

    /// Copy the next datagram into `buffer`, or null when none fits or exists.
    /// A short buffer leaves the head queued. The result borrows `buffer` until
    /// overwritten; `quic_datagram.max_payload` always holds the head.
    pub fn recvDatagram(self: Conn, buffer: []u8, at: Instant) ?[]const u8 {
        return datagram_mod.recv(self.entry.conn, buffer, at);
    }
};

fn group(contents: []const u8, size: usize, ecn: ?batch.Ecn) batch.Error!batch.Send {
    if (contents.len == size) return batch.Send.single(contents, ecn);
    return batch.Send.batch(contents, size, ecn);
}

fn closeRun(
    out: []Egress,
    used: usize,
    buffer: []u8,
    begin: usize,
    end: usize,
    size: usize,
    ecn: ?batch.Ecn,
    to: SocketAddr,
) Error!usize {
    if (used == out.len) return error.NoRoom;
    out[used] = .{
        .to = to,
        .send = try group(buffer[begin..end], size, ecn),
    };
    return used + 1;
}

/// Translate bytes and port by value; SocketAddr has no IPv6 scope, so it is 0.
pub fn toCoreAddress(socket: SocketAddr) quic.address.Address {
    return switch (socket.ip) {
        .v4 => |octets| quic.address.Address.initIpv4(octets, socket.port),
        .v6 => |octets| quic.address.Address.initIpv6(octets, socket.port, 0),
    };
}

/// Translate a borrowed core address by value; unset has no SocketAddr spelling.
pub fn fromCoreAddress(core: *const quic.address.Address) ?SocketAddr {
    return switch (core.*) {
        .unset => null,
        .ipv4 => |v4| .{ .ip = .{ .v4 = v4.bytes }, .port = v4.port },
        .ipv6 => |v6| .{ .ip = .{ .v6 = v6.bytes }, .port = v6.port },
    };
}
