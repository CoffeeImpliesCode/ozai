//! The ALPN table: what a registration is, the one ALPN iroh reserves for
//! itself, and the lookup and offer list a frozen table answers.
//!
//! Split out of `router/router.zig`, which is now the facade over this and two
//! other named modules. The boundary is registration: everything below is what
//! an application may claim and what it may not, over the caller's own entry
//! slice, and not one of these declarations knows a connection exists. The
//! handler vtable lives here rather than in the connection machine because a
//! handler is what a registration *is* — `ConnState` holds one and
//! `dispatchStep` copies it — and a type that is half a registration and half a
//! state would be a type both machines have to agree on.

const std = @import("std");

/// A handler for one ALPN: a context pointer and three calls.
///
/// Upstream `ProtocolHandler` is a trait with a default `on_accepting` and a
/// default `shutdown`. A vtable has nowhere to keep a default, so both fields
/// are optional and a null one *is* the default. A null is not a stub: the
/// router runs the default itself, and the two defaults are the ones upstream
/// writes as bodies — `on_accepting` awaits the handshake
/// (`protocol.rs:252-255`) and `shutdown` does nothing (`protocol.rs:284-286`).
/// `PacketSource` in `discovery/resolve.zig` gives its default as a named
/// function pointer instead, which works there because "publish nothing" is a
/// body. Here a default would have to be a function of the handler's context
/// in a module that never drives a handshake, so null says what the router
/// does instead.
///
/// `accept` is the only non-optional field, and that is upstream's shape too:
/// it is the whole of a handler, so there is nothing to default it to.
///
/// **All three calls are made synchronously, by the thread stepping the
/// router**, and that thread is the caller's own: the accept loop's pass, or a
/// caller driving `dispatchStep` itself. Nothing here spawns, defers, or moves
/// a call onto a thread of its own. Upstream runs each `accept` on a freshly
/// spawned task (`protocol.rs:258-261`) and a vtable has nowhere to put a join
/// set, so the caller is what runs the body — a handler that blocks blocks the
/// pass, and there is no thread here for it to move to.
///
/// **Every argument is borrowed for the duration of the call.** `ptr` comes
/// back unchanged and is never dereferenced here. `Accepting` and `Connection`
/// are opaque handles the endpoint layer minted and the router never looks
/// inside, so a handler has nothing of its own to keep: what a handle means,
/// and how long it stays valid, belongs to the layer that minted it.
///
/// **`ptr` must stay valid and unchanged from registration until the router is
/// dropped.** That outlives every individual call, and it is the handler's own
/// discipline rather than the router's: a handler torn down before its
/// registration is gone leaves a dangling context, and nothing here can see it
/// coming.
///
/// **None of the three may re-enter the router**, and `shutdown` is the one
/// that most needs saying. It runs from inside the close, before the machine
/// has advanced past the handlers, and the ordering the whole shutdown exists
/// for is that a handler's state is released *while* the accepts that might
/// still be using it are running and never after (`protocol.rs:284-286`,
/// `:609-611`). A `shutdown` that closed the endpoint or stepped the accept
/// loop from inside that call cuts the graceful close in half; `Node`'s own
/// `shutdownHandler` is the discipline to copy — it gives up the handler's own
/// state and touches nothing else.
pub const ProtocolHandler = struct {
    /// The handler's own state, handed to every call unchanged and never
    /// dereferenced here. A handler that needs nothing still has to name
    /// something; upstream's `&self` is a real borrow and this is the thinnest
    /// honest equivalent. It must outlive every registration that names it,
    /// and it is not the router's job to say when: see this struct's note.
    ptr: *anyopaque,
    /// Take the connection over before the handshake finishes. Upstream
    /// `ProtocolHandler::on_accepting`.
    ///
    /// Called at most once per connection, on the thread stepping the router,
    /// with the pre-handshake handle borrowed for the call and not to be
    /// stored. Returning a `Connection` means the handshake is done and `accept`
    /// is owed; returning an error drops the connection with a warning and no
    /// error code (`protocol.rs:657-670`).
    ///
    /// It may be the whole protocol: upstream notes that 0-RTT means a handler
    /// can implement everything here and have `accept` return immediately
    /// (`protocol.rs:239-247`).
    ///
    /// Null is upstream's default body, and it is not a stub that skips the
    /// handshake: the router awaits it itself and reports the same two outcomes
    /// under the same log line.
    on_accepting: ?*const fn (ptr: *anyopaque, accepting: Accepting) AcceptError!Connection,
    /// Handle one connection. Upstream `ProtocolHandler::accept`.
    ///
    /// This is the long-lived one, and it is what makes the shutdown ordering
    /// load-bearing: upstream's returned future runs on a freshly spawned task,
    /// so it outlives the handshake and can outlive the connection. A handler's
    /// `shutdown` closes connections its own `accept` is still using, so the
    /// router may not cancel the accepts until every handler has been given its
    /// `shutdown` — which is why `Shutdown` counts running accepts rather than
    /// remembering that some exist. Here the caller runs the body inside its own
    /// pass, so "long-lived" means "for as many passes as it takes": a handler
    /// that wants a connection past this call has to be re-entered by the loop
    /// driving it, not left running.
    ///
    /// Called once per connection that got past the handshake, on the thread
    /// stepping the router, with the handle borrowed for the call. An error
    /// drops the connection and sends nothing: see `Failure.accept`. What the
    /// router does *not* do is close or drop anything itself — it never
    /// dereferences the handle, so what becomes of the connection when this
    /// returns is the endpoint layer's business.
    accept: *const fn (ptr: *anyopaque, connection: Connection) AcceptError!void,
    /// Called once per shutdown, on every registered handler, before any accept
    /// is cancelled, on the thread stepping the router. Upstream
    /// `ProtocolHandler::shutdown`, whose future is awaited for all of them
    /// before the cancel (`protocol.rs:284-286`, `:609-611`).
    ///
    /// Null is upstream's default body: nothing to do, and nothing owed.
    shutdown: ?*const fn (ptr: *anyopaque) void,
};

/// A connection attempt whose handshake is still under way. Upstream
/// `Accepting`.
///
/// The router never looks inside: the endpoint layer mints the handle and
/// `on_accepting` interprets it. What the router needs is that this is a
/// different type from `Connection`, so a pre-handshake handle cannot be handed
/// to a handler that is about to call `accept_bi` on it.
pub const Accepting = struct {
    /// The endpoint's own value, never dereferenced here and borrowed for the
    /// call that carries it. What it *is* — and how long it stays usable — is
    /// the minting layer's rule: for this project's endpoint, as long as the
    /// accept task it was handed to is held.
    ptr: *anyopaque,
};

/// A connection whose handshake finished. Upstream `Connection`.
///
/// The same handle as `Accepting` with the other half of the handshake done,
/// and the same rule about who owns its lifetime: the endpoint layer mints it,
/// the router lends it for the call, and nothing in this file closes, drops or
/// keeps it.
pub const Connection = struct {
    /// The endpoint's own value. Never dereferenced here.
    ptr: *anyopaque,
};

/// What a stage can fail with.
///
/// The closed form of upstream's `AcceptError` (`protocol.rs:113-131`): the
/// same cases minus `User { source: AnyError }`, which is `anyerror` and which
/// this project does not put in a public API. The endpoint maps its own
/// `ConnectingError` and `ConnectionError` onto `Connecting` and `Connection`,
/// which is what upstream's `From` impls do. A handler with a failure of its
/// own either maps it here or adds a variant to this file on purpose.
pub const AcceptError = error{
    /// Upstream `AcceptError::Connecting`: the connection never completed.
    Connecting,
    /// Upstream `AcceptError::Connection`: the connection failed.
    Connection,
    /// Upstream `AcceptError::MissingRemoteEndpointId`: the peer finished a
    /// handshake without an endpoint id.
    MissingRemoteEndpointId,
    /// Upstream `AcceptError::NotAllowed`.
    NotAllowed,
};

/// The one ALPN iroh reserves for itself: QUIC address discovery, spoken to
/// the relay and by address lookup. Captured from `ALPN_QUIC_ADDR_DISC` at
/// `iroh-relay/src/quic.rs:10`.
///
/// No application registration reaches it: `Builder.accept` refuses this ALPN
/// with `error.reserved_alpn`. `Builder.acceptInternal` is the only way in, and
/// it takes no ALPN at all so there is no string to pass wrongly.
///
/// **Nothing under `src/` calls `acceptInternal`, and that is a decision
/// rather than a gap.** This is a reservation: a table built in this tree
/// never offers `/iroh-qad/0`, and a peer that negotiates it is dropped rather
/// than served (`conn_dispatch.zig:303-304`). `router/qad_route.zig` holds the
/// one way past this refusal and explains, with line numbers, why it is not
/// called: the vendored core carries neither the OBSERVED_ADDRESS frame nor
/// the `address_discovery` transport parameter, so a registered route could
/// negotiate this ALPN and then report nothing. The codec over those two
/// halves is `net/qad.zig`, tested and unwired.
pub const qad_alpn: []const u8 = "/iroh-qad/0";

/// One registration: an ALPN and the handler that claims it.
pub const Entry = struct {
    /// The ALPN as the application-chosen bytes upstream keeps in a
    /// `Vec<Vec<u8>>` (`protocol.rs:379`). Borrowed, not copied: the storage is
    /// the caller's and must outlive the router, which is the rule
    /// `Clients.init` takes its slots under too.
    alpn: []const u8,
    /// The handler this ALPN dispatches to.
    handler: ProtocolHandler,
};

/// What a registration did.
///
/// Upstream's `ProtocolMap::insert` (`protocol.rs:391-394`) pushes the ALPN
/// onto the offer list unconditionally and then overwrites the map entry, so an
/// ALPN registered twice is offered to the peer twice while dispatching goes to
/// the newer handler. Both halves are reproduced, because either alone would be
/// a different API: deduplicating the offer list is the endpoint's business,
/// and resolving to the older handler would contradict the map upstream keeps.
pub const Registered = union(enum) {
    /// The ALPN was not registered before.
    fresh,
    /// The ALPN was already registered at this index. It is now on the offer
    /// list twice, and the entry at this index is unreachable.
    replaced: usize,
};

/// What a registration can be refused for. Sized by the caller and never grown,
/// like every other store in this project.
pub const RegisterError = error{
    /// The caller's entry slice is full.
    no_space,
    /// The ALPN is `qad_alpn`, which `acceptInternal` owns.
    reserved_alpn,
};

/// Registrations, in the order they were made, over storage the caller owns.
///
/// Upstream `RouterBuilder` (`protocol.rs:105-111`). It is a separate type from
/// `Router` because `spawn` freezes: it hands the offer list to the endpoint
/// once (`protocol.rs:513-522`) and a registration made after that reaches no
/// peer, so `build` is the line and `Router` has no way past it.
pub const Builder = struct {
    entries: []Entry,
    len: usize,

    /// Over storage the caller owns, which must outlive every `Router` built
    /// from it.
    pub fn init(entries: []Entry) Builder {
        return .{ .entries = entries, .len = 0 };
    }

    /// Upstream `RouterBuilder::accept`. Registration order is the server's
    /// preference order: the offer list goes to the endpoint in this order and
    /// the first ALPN a peer offers that the server also offers is the one
    /// negotiated (`iroh/src/endpoint.rs:973-977`, `protocol.rs:489-492`), so
    /// the preferred protocol goes first.
    pub fn accept(
        self: *Builder,
        alpn: []const u8,
        handler: ProtocolHandler,
    ) RegisterError!Registered {
        if (std.mem.eql(u8, alpn, qad_alpn)) return error.reserved_alpn;
        return self.push(alpn, handler);
    }

    /// Registers `qad_alpn`. No ALPN argument on purpose: the one internal
    /// ALPN is not reachable by passing a different string, and a call site
    /// that says `acceptInternal` says which ALPN it meant.
    ///
    /// Nothing under `src/` calls this: see `qad_alpn`.
    pub fn acceptInternal(
        self: *Builder,
        handler: ProtocolHandler,
    ) RegisterError!Registered {
        return self.push(qad_alpn, handler);
    }

    /// The frozen table. Everything after this is a lookup.
    pub fn build(self: *const Builder) Router {
        return .{ .entries = self.entries[0..self.len] };
    }

    /// The last match wins, so the search for a duplicate runs to the end
    /// rather than stopping at the first: a caller that stops early resolves
    /// the older handler and the `Registered` it gets back names the wrong
    /// entry.
    fn push(
        self: *Builder,
        alpn: []const u8,
        handler: ProtocolHandler,
    ) RegisterError!Registered {
        var displaced: ?usize = null;
        for (self.entries[0..self.len], 0..) |entry, index| {
            if (std.mem.eql(u8, entry.alpn, alpn)) displaced = index;
        }
        // Refused before the write, so a full table is left as it was.
        if (self.len == self.entries.len) return error.no_space;
        self.entries[self.len] = .{ .alpn = alpn, .handler = handler };
        self.len += 1;
        return if (displaced) |index| .{ .replaced = index } else .fresh;
    }
};

/// An ALPN to handler table.
///
/// `docs/ARCHITECTURE.md`: the router owns ALPN dispatch and nothing else. It
/// turns a negotiated ALPN into a handler call and knows nothing about what any
/// protocol does.
pub const Router = struct {
    /// The registrations, in registration order. Only `Builder.build` makes one,
    /// and the entries are the caller's.
    entries: []const Entry,

    /// The ALPNs to offer a peer, in registration order. Upstream
    /// `ProtocolMap::alpns` (`protocol.rs:397-399`) into `spawn`'s `set_alpns`
    /// (`protocol.rs:515-522`).
    ///
    /// A repeated ALPN comes out twice, because that is what upstream offers.
    pub fn alpns(self: *const Router) AlpnIterator {
        return .{ .entries = self.entries, .index = 0 };
    }

    /// The registration an ALPN dispatches to: the newest one for it, which is
    /// the entry upstream's `HashMap::insert` leaves behind
    /// (`protocol.rs:391-394`).
    pub fn lookup(self: *const Router, alpn: []const u8) ?*const Entry {
        var index = self.entries.len;
        while (index > 0) {
            index -= 1;
            if (std.mem.eql(u8, self.entries[index].alpn, alpn)) return &self.entries[index];
        }
        return null;
    }
};

/// The offer list, one ALPN at a time.
///
/// An iterator rather than a slice because the ALPNs live in the entries, and a
/// `[]const []const u8` over them would be a second copy of the registration
/// order kept for nothing.
pub const AlpnIterator = struct {
    entries: []const Entry,
    index: usize,

    /// Bounded by the entries, so the loop cannot outrun the table.
    pub fn next(self: *AlpnIterator) ?[]const u8 {
        if (self.index == self.entries.len) return null;
        defer self.index += 1;
        return self.entries[self.index].alpn;
    }
};
