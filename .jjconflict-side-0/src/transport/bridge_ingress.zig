//! One datagram as it arrived, and what the core did with it.
//!
//! Split out of `transport/quic_bridge.zig`, which is now the facade over it
//! and five other named modules. The boundary is the direction of travel: this
//! is everything `Bridge.recv` reads and the whole of the answer it returns,
//! and nothing a caller drives forward. The two borrows inside `Outcome` are
//! what keep it apart — a processed datagram hands back a `Conn` the caller
//! already holds, and a stateless reply borrows the caller's own `scratch` —
//! so the read side is one shape with two borrows rather than half a
//! connection.

const batch = @import("batch.zig");
const base_addr = @import("../base/addr.zig");
const base_ula = @import("../base/ula.zig");
const addr_map = @import("addr_map.zig");

const SocketAddr = base_addr.SocketAddr;
const Conn = @import("bridge_conn.zig").Conn;

/// One datagram as it arrived, in this project's vocabulary.
///
/// The read side's own shape is `batch.Recv`, which may be a coalesced
/// buffer holding several datagrams. This is one of them: `recv` takes a
/// single datagram because the core's reply borrows the buffer it was
/// written into, and two datagrams sharing one buffer would have two
/// answers pointing at the same bytes. A caller reading a coalesced read
/// asks it for one datagram at a time, with `batch.Recv.datagram`.
pub const Datagram = struct {
    /// The bytes, one datagram and no more.
    bytes: []const u8,
    /// Where it came from.
    from: SocketAddr,
    /// Where it was sent to.
    local: SocketAddr,
    /// The codepoint it carried, or null for not-ECT.
    ecn: ?batch.Ecn,
};

/// Where a received datagram came from, in this project's terms.
pub const Source = struct {
    /// The address itself.
    socket: SocketAddr,
    /// What `base/ula.zig`'s `classify` made of it: one of the three
    /// synthetic subnets, or a direct path. Note that this looks at eight
    /// octets and ignores the port — see the module doc.
    classification: base_ula.Classification,
    /// The key that owns the address in `addr_map`, or null when this node's
    /// map never handed it out: a direct path, or a synthetic address that
    /// belongs to somebody else's map. Null is not a failure — it is the
    /// answer for every packet on a direct path.
    owner: ?addr_map.Key,
};

/// What the core did with a received datagram.
pub const Outcome = union(enum) {
    /// The core owns the datagram now and has a connection for it.
    processed: Conn,
    /// The core wrote a stateless reply — Version Negotiation, Retry, or a
    /// stateless reset — and it goes back to `Ingress.source.socket` through
    /// the same send seam an egress uses, because it is a send. It borrows
    /// the caller's `scratch` and is good until the next `recv`.
    reply: batch.Send,
    /// Unroutable or invalid. Nothing to do and nothing to report.
    dropped: void,
    /// The DCID named another server under the same QUIC-LB config id, and
    /// this is its server id. It borrows the core's own scratch and is good
    /// until the next `recv`.
    ///
    /// A bridge built from `Config` never returns it: the core only reports
    /// a foreign DCID when `ConnectionManager.steer_foreign` is set
    /// (`connection_manager.zig:234`, default false) and `Config` has no QUIC
    /// load-balancing field to set it with. The arm is here because `recv`
    /// forwards what the core says rather than dropping an arm it does not
    /// expect, and a caller adding QUIC-LB to `Config` gets it without
    /// coming back here.
    foreign: []const u8,
};

/// One datagram through the core and back out as an answer.
pub const Ingress = struct {
    source: Source,
    outcome: Outcome,
};

/// What one pass of the timers did to a connection.
pub const Tick = enum {
    /// Still live. Keep draining it.
    live,
    /// The core has finished with it and taken it out of its table. The
    /// memory stands until `Bridge.sweep`, so a drain after this still reads
    /// a closed connection rather than freed memory.
    finished,
};

/// The two bits the core reads off an `IP_TOS` or `IPV6_TCLASS`, or zero.
///
/// Zero is `IP_TOS_NOT_ECT`, so "no codepoint" and "not-ECT" are the same
/// value on this side too, which is what `batch.Recv.ecnFromBits` says from
/// the other end.
pub fn ecnBits(codepoint: ?batch.Ecn) u2 {
    const set = codepoint orelse return 0;
    return @truncate(set.toBits());
}
