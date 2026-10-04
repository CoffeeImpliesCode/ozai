//! Borrowed protocol registrations and the connection contract handed to handlers.
//! This module owns no node state, allocation, clock, or callback execution.
const std = @import("std");
const base_addr = @import("../base/addr.zig");
const quic_conn = @import("../transport/quic_conn.zig");
const quic_stream = @import("../transport/quic_stream.zig");
const router = @import("../router/router.zig");
const quic_config = @import("../transport/quic_config.zig");
const Error = @import("node_error.zig").Error;

/// Registrations are bounded before their storage is allocated.
///
/// node's protocol set can be is an array in this struct. The transport's own
/// `quic_config.max_alpns` is eight and looser — a general TLS stack rather
/// than a node — so this number is the one that decides, and a node configured
/// past it is refused by `create` as `error.TooManyProtocols` rather than
/// truncated into a table that offers fewer protocols than it dispatches.
pub const max_alpns = 2;
comptime {
    // The bound above is the deciding one, and a caller that raises it past
    // the transport's would otherwise find the refusal moved rather than
    // removed: `create` allocates the node and its socket first, so a
    // configuration mistake would be reported late, as a failure after
    // allocation, instead of here where it costs nothing.
    if (max_alpns > quic_config.max_alpns) {
        @compileError("the node's ALPN bound exceeds the transport's");
    }
}
/// Room for the deepest endpoint-event chain queued by one feed.
pub const max_pending_events = 8;
pub const gossip_alpn = "/iroh-gossip/1";
pub const relay_alpn = "/iroh-relay/1";

/// A standard selection resolves from its registration's ALPN, not from a tag.
pub const Standard = enum {
    gossip,
    relay,
};

/// A custom handler is the only way to serve an ALPN without a built-in handler.
pub const Selection = union(enum) {
    standard,
    custom: Handler,
};

/// The ALPN bytes and custom handler state must outlive the node.
/// Offer order is registration order; the server's order decides negotiation.
pub const Protocol = struct {
    alpn: []const u8,
    handler: Selection = .standard,
};

/// A protocol owns its accept work and receives shutdown exactly once.
pub const Handler = struct {
    /// Caller-owned state, passed unchanged and never dereferenced by the node.
    ptr: *anyopaque,
    /// Runs inside a bounded step pass. Re-entering or closing the node is invalid.
    /// A more result retains the task for a later pass, but closing or draining
    /// ends the task before another turn, without waiting for core reclamation.
    accept: *const fn (ptr: *anyopaque, connection: Connection) router.AcceptError!Turn,
    /// Runs before cancellation of this protocol's live accepts.
    shutdown: ?*const fn (ptr: *anyopaque) void = null,
};

pub const Turn = union(enum) {
    /// Ends the accept task and returns the connection to the endpoint.
    finished,
    /// Requests a later turn with this connection.
    more,
};

/// The core owns this connection. This handle borrows it for one handler turn
/// only: a later sweep can free it, and the next pass reconstructs the handle.
pub const Connection = struct {
    conn: quic_conn.Conn,
    /// Registration index, shared by router claims and lane statistics.
    protocol: usize,

    pub fn id(self: Connection) u64 {
        return self.conn.id();
    }

    pub fn peer(self: Connection) ?base_addr.SocketAddr {
        return self.conn.peer();
    }

    pub fn local(self: Connection) ?base_addr.SocketAddr {
        return self.conn.local();
    }

    /// Handlers receive only connections whose handshake has completed.
    pub fn established(self: Connection) bool {
        return self.conn.established();
    }

    /// Closing or draining ends an accept before terminal state is reached.
    pub fn closed(self: Connection) bool {
        return self.conn.closed();
    }

    /// Configuration grants neither unidirectional streams nor DATAGRAMs.
    /// NoStreamRoom means the peer has not yet granted bidirectional credit.
    pub fn openStream(self: Connection) Error!quic_stream.Stream {
        return quic_stream.openBidi(self.conn.entry.conn);
    }

    /// Borrow the peer's next bidirectional stream after `after`, or null.
    /// Pass null before anything has been taken: a peer's first bidirectional
    /// stream can be id zero, so there is no cursor that means "from the
    /// start". Core stream storage is unordered, not an acceptance queue.
    pub fn peerStream(self: Connection, after: ?u64) ?quic_stream.Stream {
        return self.conn.peerStream(after);
    }
};

/// Read-only counters addressed by the registration index.
pub const LaneStats = struct {
    /// Borrowed from the registration's ALPN bytes.
    alpn: []const u8,
    standard: ?Standard,
    turns: u64,
    finished: u64,
    /// A retired protocol is not shut down again during endpoint-wide close.
    shutdowns: u64,
    /// Retirement withdraws the ALPN before cancellation of its live tasks.
    serving: bool,
    live: usize,
};

/// Refuses displacement, reserved router ALPNs, and unsupported standard handlers
/// before the lifecycle owner allocates registration storage.
/// `node_lifecycle.create` is the only path to the registration storage, and its
/// `register` is private to that call, so the precondition above is structural.
pub fn validateProtocols(registrations: []const Protocol) Error!void {
    if (registrations.len > max_alpns) return error.TooManyProtocols;
    for (registrations, 0..) |registration, index| {
        for (registrations[0..index]) |earlier| {
            if (std.mem.eql(u8, earlier.alpn, registration.alpn)) {
                return error.DuplicateProtocol;
            }
        }
        if (std.mem.eql(u8, registration.alpn, router.qad_alpn)) return error.reserved_alpn;
        switch (registration.handler) {
            .standard => if (standardOf(registration.alpn) == null) {
                return error.NoStandardProtocol;
            },
            .custom => {},
        }
    }
}

pub fn standardOf(alpn: []const u8) ?Standard {
    if (std.mem.eql(u8, alpn, gossip_alpn)) return .gossip;
    if (std.mem.eql(u8, alpn, relay_alpn)) return .relay;
    return null;
}
