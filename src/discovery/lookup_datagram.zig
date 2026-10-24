//! The socket a lookup goes out on: two calls and a stop, as a vtable.
//!
//! Nothing here is a socket. `lookup_io.zig` gives the reason — the layering
//! puts `ozai.transport` above `ozai.discovery`, so a file under `discovery/`
//! that reached for a transport socket would invert the tree — and
//! `lookup_live.zig` is the arm that supplies a real one. What this file fixes
//! is the *shape*: what a lookup needs to be able to say about the thing its
//! datagram travels on, which is a small and closed vocabulary.

const std = @import("std");

const addr = @import("../base/addr.zig");

/// Everything an injected datagram can fail with here, in three arms, because a
/// lookup acts on exactly three things.
///
/// A real socket names thirteen — `transport/socket.zig`'s `SendError` and
/// `ReceiveError` — and a lookup cannot act differently on any two of them, so
/// a seam passing thirteen arms through would be a second vocabulary for one
/// fact. The mapping a binding performs is all three arms:
///
/// * `ReceiveError.WouldBlock` is `Empty`. `transport/socket.zig`'s `poll`
///   reports a zero as the deadline, and the `MSG_DONTWAIT` read that follows
///   reports `EAGAIN` for the same fact, so this arm is what a deadline looks
///   like on the way in and `Answer.timeout` is what it looks like on the way
///   out.
/// * `ReceiveError.Canceled` is `Canceled`.
/// * Everything else in both sets is `Refused`.
pub const SocketError = error{
    /// The datagram did not go out, or the read failed for a reason that is
    /// neither the clock nor the abort handle.
    Refused,
    /// Nothing arrived inside the deadline. Not an absence and not `Refused`:
    /// the deadline is the question being asked and not getting an answer.
    Empty,
    /// The caller gave up on this retrieval.
    Canceled,
};

/// The socket a lookup goes out on: two calls and a stop, as a vtable.
///
///
/// Nothing here is owned: `ctx` is the socket's own value and the three
/// functions are the caller's, so all of it has to outlive every `Retrieval`
/// begun with it. Each call runs synchronously, on the thread that asked, and
/// returns before `Retrieval.ask` does — this seam retains neither a datagram
/// nor a reply — and none of them is reentered from another: a `send` or
/// `receive` that called back into the retrieval asking it would be reading a
/// `Request` that call is in the middle of writing.
pub const Datagram = struct {
    /// Borrowed backend state. Its address must remain stable until all asks
    /// and cancellation callbacks return. Synchronize state shared by them.
    ctx: *anyopaque,
    /// Put one datagram on the wire, whole or not at all: a query truncated in
    /// transit is a question nobody can answer.
    ///
    /// `bytes` is the framed query, borrowed for the call, and `to` is
    /// `Retrieval.server` by value. Called synchronously, on the thread that
    /// asked, with `io` borrowed for the call and stored nowhere. Nothing
    /// survives it.
    send: *const fn (
        ctx: *anyopaque,
        io: std.Io,
        to: addr.SocketAddr,
        bytes: []const u8,
    ) SocketError!void,
    /// Take one datagram into `into`, waiting at most `deadline_ms`.
    ///
    /// On success `Reply.bytes` borrows `into` until that buffer is overwritten
    /// or released. A short receive only overwrites its prefix; an error or
    /// timeout need not write any bytes. `deadline_ms` is null for no deadline.
    /// A finite wait with no datagram returns `error.Empty`.
    ///
    /// Called synchronously on the asking thread; `io` is borrowed for the
    /// call. Concurrent `stop` must wake this call without racing its state.
    receive: *const fn (
        ctx: *anyopaque,
        io: std.Io,
        into: []u8,
        deadline_ms: ?i32,
    ) SocketError!Reply,
    /// Stop whatever is in flight.
    ///
    /// Reached from `resolve.Cancellation` and from nothing else, and it is why
    /// `stop` is here rather than on `Retrieval`: a flag on a struct nobody
    /// reads would satisfy every assertion written about cancellation while the
    /// query sat in the socket's queue, which is the failure invariant 13 names.
    /// May run on a concurrent thread. Synchronize shared callback state and
    /// unblock a pending receive. This is a request, not a join or disposal.
    stop: *const fn (ctx: *anyopaque) void,

    /// One datagram, and who sent it.
    pub const Reply = struct {
        /// Borrows the receive buffer until it is overwritten or released.
        bytes: []const u8,
        /// Who sent it, by value, and the only thing standing between a lookup
        /// and a forged answer: a TXT answer carries no signature.
        from: addr.SocketAddr,
    };
};
