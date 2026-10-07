//! The two endpoints, the dial between them, and the round that moves datagrams.
//!
//! `Link` owns both `Side`s and the `Dialer` the client used, and `drive` is
//! what a test asks to move bytes until a state holds. Nothing here reads a
//! clock: `at` is one instant for the whole run, so nothing but the state
//! machines or the round bound can end a loop — which is the property the pure
//! layers were built for, and also the reason a stall here is a finding about
//! the stack rather than a flake about a loaded machine.
//!
//! `bothUp` is here because it is `drive`'s goal: the handshake phase's own
//! question, asked of the two sides rather than of anything this file holds.

const std = @import("std");
const ozai = @import("ozai");

const t = std.testing;

const batch = ozai.transport_batch;
const bridge_mod = ozai.transport_quic_bridge;
const dial_mod = ozai.transport_dial;

const Side = @import("loopback_side.zig").Side;
const alpn = @import("loopback_side.zig").alpn;
const start = @import("loopback_side.zig").start;
const max_rounds = @import("loopback_side.zig").max_rounds;

const Conn = bridge_mod.Conn;
const Instant = bridge_mod.Instant;
const Dialer = dial_mod.Dialer;
const NodeId = ozai.NodeId;
const SecretKey = ozai.SecretKey;

/// The codepoint's own name, or `none` for a datagram that carried no
/// control message. `Ecn` has no not-ECT tag, so "zero" is an absence here.
fn ecnName(ecn: ?batch.Ecn) []const u8 {
    const set = ecn orelse return "none";
    return @tagName(set);
}

/// Whether `side` holds a connection the core says is established.
pub fn established(side: *Side) bool {
    var index: usize = 0;
    while (side.bridge.connectionAt(index)) |conn| : (index += 1) {
        if (conn.established()) return true;
    }
    return false;
}

/// The handshake phase's goal: both ends agree the connection is up, neither
/// because it was told so and neither before the other.
pub fn bothUp(client: *Side, server: *Side) bool {
    return established(client) and established(server);
}

/// The two endpoints and the bookkeeping that makes a stall readable.
///
/// Index 0 is the dialling side and index 1 the accepting one, everywhere in
/// this struct.
pub const Link = struct {
    client: Side,
    server: Side,
    dialer: *Dialer,
    /// The connection `Dialer.dial` handed back, kept only to prove that the
    /// bridge finds the same one by index. It is a borrowed handle: `deinit`
    /// frees it, and nothing may read it afterwards.
    dialled: Conn,
    sent: [2]usize = .{ 0, 0 },
    received: [2]usize = .{ 0, 0 },
    /// Connections the core declared finished, which leaves the table but
    /// keeps its memory until `sweep`.
    finished: [2]usize = .{ 0, 0 },
    ecn: [2]Cods = .{ .{}, .{} },

    /// What each side marked on the wire and what each side read off the
    /// wire.
    ///
    /// Counts rather than a single remembered value, because a handshake is
    /// sent not-ECT — which is `Ecn`'s null, not a fourth codepoint — and the
    /// core only starts marking once the handshake confirms. The counts are
    /// what say the marking ever happened.
    const Cods = struct {
        marked: usize = 0,
        saw: usize = 0,
        lost: usize = 0,
        last_sent: ?batch.Ecn = null,
        last_seen: ?batch.Ecn = null,
    };

    /// Both ends up, with a bridge each and a dialer on the client.
    ///
    /// `pub` because `loopback_test.zig` calls it across the file boundary
    /// the split that gave this module its own name introduced.
    pub fn init(
        self: *Link,
        client_secret: SecretKey,
        server_secret: SecretKey,
        pinned: NodeId,
        engine_seed: u64,
    ) !void {
        self.* = .{
            .client = undefined,
            .server = undefined,
            .dialer = undefined,
            .dialled = undefined,
        };
        // Unwound in the one order `Dialer.destroy` refuses to invert: a
        // dialled connection's handshake points at the dialer's own seed, so
        // the dialer goes before the bridges. Errdefers run in reverse of
        // declaration, so the dialer is named last.
        // Both paths go through `closeDialed`, so the teardown an unwinding
        // `init` performs is the teardown a finished test performs and the two
        // cannot drift apart.
        var client_live = false;
        var server_live = false;
        var dialer_live = false;
        errdefer if (client_live) self.client.deinit();
        errdefer if (server_live) self.server.deinit();
        errdefer if (dialer_live) self.closeDialed();

        // The client first: the dial below is handed the address this socket
        // came back bound to, and it cannot be dialled without one.
        try self.client.init("client", client_secret, null, engine_seed);
        client_live = true;
        try self.server.init("server", server_secret, client_secret.nodeId(), engine_seed + 1);
        server_live = true;
        self.dialer = try Dialer.create(t.allocator, self.client.bridge, .{
            .secret = client_secret,
            .alpn = alpn,
        });
        dialer_live = true;
        // A direct target, so the address the core is told is the server's
        // real one and no synthetic subnet is involved: this file is about the
        // socket, and a relay path would test the map instead.
        self.dialled = (try self.dialer.dial(
            .{ .ip = self.server.socket.address },
            pinned,
            self.client.socket.address,
            &self.client.map,
            start,
            self.client.random(),
        )).conn;
    }

    /// Take the link down: the dialled connection, then both ends in turn.
    ///
    /// `pub` because `loopback_test.zig` calls it across the file boundary the
    /// split that gave this module its own name introduced.
    pub fn deinit(self: *Link) void {
        self.closeDialed();
        self.client.deinit();
        self.server.deinit();
        self.* = undefined;
    }

    /// Take the dialled connections out of the client's bridge, then free the
    /// dialer that opened them.
    ///
    /// `Dialer.destroy` refuses while one is still in the table, so the
    /// removal is what makes the call that follows it possible. It walks
    /// backwards because `removeConnection` swap-removes and a forward walk
    /// would skip an entry and leave a freed one behind, and `sweep` frees
    /// what the core declared finished.
    ///
    /// A refusal is not returned, because neither caller can return one: the
    /// normal teardown is a `defer` and the unwinding one an `errdefer`, and
    /// neither may `return`. So it is reported the way a stall is reported —
    /// the counts and both ends' connection states are exactly what says
    /// whether a connection outlived the dialer or arrived after this walk —
    /// and then logged at error level, which is the one thing this artifact's
    /// runner turns into a failed run beyond the message `build.zig` names.
    /// `destroy` returns before it frees, so a refusal has left the dialer
    /// allocated and the leak checker says so in this run; the log is what
    /// stops the step passing with the teardown named only in a leak trace.
    fn closeDialed(self: *Link) void {
        var index = self.client.bridge.manager.entries.items.len;
        while (index > 0) {
            index -= 1;
            const entry = self.client.bridge.manager.entries.items[index];
            if (!entry.conn.is_server) self.client.bridge.manager.removeConnection(entry);
        }
        self.client.bridge.sweep();
        self.dialer.destroy() catch |err| {
            self.report("teardown", "a dialled connection outlived its dialer");
            std.log.err("loopback teardown: the dialer was not freed: {t}", .{err});
        };
    }

    /// The side at `which`: 0 is the dialling end, 1 the accepting one.
    fn of(self: *Link, which: usize) *Side {
        return if (which == 0) &self.client else &self.server;
    }

    /// Drain everything on one side's connections and write each datagram to
    /// the peer's real socket, then take whatever is waiting on the other.
    ///
    /// Both directions go through `Socket.send` and `Socket.tryReceive`, so a
    /// datagram is a `sendmsg` and a `recvmsg` here exactly as it would be in
    /// production — including the traffic-class and segment control messages
    /// `batch.zig` models, which is the only reason the codepoint assertions
    /// below mean anything.
    fn step(self: *Link, from: usize, into: usize, at: Instant) !bool {
        const sender = self.of(from);
        var moved = false;
        var index: usize = 0;
        // Found by index, never by a handle the caller was handed: an accepted
        // connection has no other way in, and the dialled one has to be found
        // the same way or the dial path is a second implementation.
        while (sender.bridge.connectionAt(index)) |conn| : (index += 1) {
            for (try conn.drain(sender.egress, sender.out, at, sender.random())) |egress| {
                const went = try sender.socket.send(t.io, egress.to, egress.send);
                if (!went.ecnSurvived()) self.ecn[from].lost += 1;
                if (went.carried) |set| {
                    self.ecn[from].marked += 1;
                    self.ecn[from].last_sent = set;
                }
                self.sent[from] += 1;
                moved = true;
            }
        }
        // Timers after the sends, so a connection that owes a retransmission
        // gets the chance to produce one in this round rather than the next.
        // `tick` may take a finished connection out of the table, which shifts
        // what the index walk sees; every round walks it again and the count
        // is in the stall report, so a skipped tick costs a round and not a
        // correctness answer.
        var scan: usize = 0;
        while (sender.bridge.connectionAt(scan)) |conn| : (scan += 1) {
            if (sender.bridge.tick(conn, at, sender.random()) == .finished) {
                self.finished[from] += 1;
            }
        }
        return if (try self.take(into, at)) true else moved;
    }

    /// Take everything queued on one side's socket and hand it to that side's
    /// bridge.
    ///
    /// A read is not one datagram: `UDP_GRO` may have coalesced a burst into
    /// one buffer, so the stride is what says how many packets there are and
    /// the bridge is handed them one at a time — which is what `Datagram`
    /// documents, since two packets sharing one buffer would leave the core
    /// with two replies pointing at the same bytes.
    fn take(self: *Link, which: usize, at: Instant) !bool {
        const side = self.of(which);
        var moved = false;
        while (true) {
            const sock = &side.socket;
            const got = sock.tryReceive(t.io, side.buf, &side.control) catch |err| switch (err) {
                // The socket is non-blocking from the moment it was created,
                // and an empty queue is a fact the loop acts on rather than a
                // failure.
                error.WouldBlock => break,
                else => return err,
            };
            const recv = try got.toRecv();
            self.received[which] += recv.datagramCount();
            if (recv.ecn) |set| {
                self.ecn[which].saw += recv.datagramCount();
                self.ecn[which].last_seen = set;
            }
            var position: usize = 0;
            while (position < recv.datagramCount()) : (position += 1) {
                const ingress = try side.bridge.recv(&side.map, .{
                    // The loop's bound is `recv.datagramCount()`, and
                    // `Recv.datagram` answers null only past that count.
                    // zwanzig-disable-next-line: optional-unwrap
                    .bytes = recv.datagram(position).?,
                    .from = got.from,
                    .local = side.socket.address,
                    .ecn = recv.ecn,
                }, side.scratch, at, side.random());
                moved = true;
                switch (ingress.outcome) {
                    // Nothing to do here: the connection this datagram belongs
                    // to is drained by the next `step`, which finds it by
                    // index.
                    .processed => {},
                    // A stateless reply is a send, so it goes back out of the
                    // same socket to the address the datagram came from.
                    .reply => |reply| {
                        self.sent[which] += 1;
                        _ = try side.socket.send(t.io, ingress.source.socket, reply);
                    },
                    .dropped, .foreign => {},
                }
            }
        }
        return moved;
    }

    /// One pass of the whole link: everything the client has, then everything
    /// the server has. A round is one flight in each direction.
    ///
    /// `pub` because `loopback_test.zig` calls it across the file boundary the
    /// split that gave this module its own name introduced.
    pub fn exchange(self: *Link, at: Instant) !bool {
        const moved = try self.step(0, 1, at);
        return (try self.step(1, 0, at)) or moved;
    }

    /// Move datagrams both ways until `goal` holds, or until the bound is
    /// reached.
    ///
    /// There is no timer in here. `at` is one instant for the whole run, so
    /// nothing but the state machines or the bound can end this loop — which
    /// is the property the pure layers were built for, and also the reason a
    /// stall here is a finding about the stack rather than a flake about a
    /// loaded machine.
    ///
    /// `pub` because `loopback_test.zig` calls it across the file boundary the
    /// split that gave this module its own name introduced.
    pub fn drive(self: *Link, at: Instant, goal: fn (*Side, *Side) bool) !void {
        var round: usize = 0;
        while (round < max_rounds) : (round += 1) {
            if (goal(&self.client, &self.server)) return;
            if (!try self.exchange(at)) {
                self.report("stalled", "a whole round moved no datagram in either direction");
                return error.Stalled;
            }
        }
        if (goal(&self.client, &self.server)) return;
        self.report("stalled", "the round bound was reached before both ends were there");
        return error.Stalled;
    }

    /// Print what a failure looks like from the inside: what kind of failure
    /// it is, the datagrams each side moved, the codepoints it marked and
    /// read, and the state of every connection on it.
    ///
    /// "Handshake failed" on a pair that never exchanged a datagram is not a
    /// diagnosis. This is: a side that sent two datagrams and received none
    /// is a different finding from one that moved traffic both ways and never
    /// settled, and only the counts say which.
    /// `pub` because `loopback_test.zig` calls it across the file boundary the
    /// split that gave this module its own name introduced.
    pub fn report(self: *Link, what: []const u8, reason: []const u8) void {
        std.debug.print("\nloopback {s}: {s}\n", .{ what, reason });
        for (0..2) |which| {
            const side = self.of(which);
            std.debug.print(
                "  {s} at {f}: {d} sent, {d} received, ecn {d} marked, {d} seen, {d} lost\n",
                .{
                    side.name,
                    side.socket.address,
                    self.sent[which],
                    self.received[which],
                    self.ecn[which].marked,
                    self.ecn[which].saw,
                    self.ecn[which].lost,
                },
            );
            std.debug.print("    last codepoint: {s} out, {s} in\n", .{
                ecnName(self.ecn[which].last_sent),
                ecnName(self.ecn[which].last_seen),
            });
            var index: usize = 0;
            while (side.bridge.connectionAt(index)) |conn| : (index += 1) {
                std.debug.print(
                    "    conn {d}: state {t}, established {}, closed {}, peer {f}\n",
                    .{
                        conn.id(),
                        conn.entry.conn.state,
                        conn.established(),
                        conn.closed(),
                        conn.peer() orelse side.socket.address,
                    },
                );
            }
            const held = side.bridge.manager.connectionCount();
            std.debug.print("    connections held: {d}\n", .{held});
        }
        const out_total = self.sent[0] + self.sent[1];
        const in_total = self.received[0] + self.received[1];
        std.debug.print(
            "  the exchange stopped at datagram {d}: {d} written, {d} read back\n",
            .{ out_total, out_total, in_total },
        );
        std.debug.print(
            "  connections the core declared finished: {d}\n",
            .{self.finished[0] + self.finished[1]},
        );
    }
};
