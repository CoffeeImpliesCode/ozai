//! The router: the ALPN table, the handler vtable it dispatches through, and
//! the two machines the router is — one per connection, one per endpoint.
//!
//! Captured 2026-09-30 from n0-computer/iroh commit
//! 187f59e80afdae6bd9866002b33d3365c00b06d8: `ProtocolHandler` at
//! `iroh/src/protocol.rs:228-287`; `ProtocolMap` at `protocol.rs:375-408`;
//! `RouterBuilder::accept` at `protocol.rs:495-503`; the accept loop and
//! `handle_connection` at `protocol.rs:531-672`; the shutdown order at
//! `protocol.rs:608-623`; `IncomingFilterOutcome` at `protocol.rs:164-209`;
//! `Incoming::{accept, refuse, retry, ignore, remote_addr_validated}` at
//! `iroh/src/endpoint/connection.rs:138-230`; the ALPN preference order at
//! `iroh/src/endpoint.rs:973-993`; `/iroh-qad/0` at `iroh-relay/src/quic.rs:10`.
//! Each is named where it is reproduced.
//!
//! Nothing here opens a socket, reads a clock, or allocates: the ALPN bytes
//! and the entries that hold them are the caller's, a handler is a context
//! pointer and three function pointers, and every step is a value. The router's
//! whole job is one line of `docs/ARCHITECTURE.md` — it turns a negotiated
//! ALPN into a handler call — and what is worth a machine is what surrounds
//! the call: the accepts may not be cancelled until every handler has finished
//! shutting down, and an `accept` that fails tells the peer nothing.

const std = @import("std");
const ula = @import("../base/ula.zig");

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
/// **Nothing under `src/` calls `acceptInternal` today**, so this is a
/// reservation and not a wired route: a table built in this tree never offers
/// `/iroh-qad/0`, and a peer that negotiates it is dropped rather than served
/// (`negotiatingStep`, `router.zig:616-617`). Registering the handler that
/// would answer it is the endpoint layer's job and it has not been done.
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

/// What a `retry` verdict means, which upstream's single `Retry` variant does
/// not say. The verb is the same and the two meanings are not, and collapsing
/// them into one tag is how a relayed connection ends up paying for address
/// validation that cannot exist.
pub const Retry = union(enum) {
    /// QUIC source-address validation, on a direct path. The token is bound to
    /// the peer's source address: a spoofed initial packet has the retry sent
    /// to the spoofed address and the attacker is never heard from again, and
    /// a real client comes back with the token, after which the next attempt
    /// for that flow reports its address as validated
    /// (`protocol.rs:177-183`).
    source_validation,
    /// Cost imposition, on a relayed path. The relay already vouches for the
    /// packet origin, so there is no address to validate and the retry carries
    /// no security meaning; what it buys is an extra round trip through the
    /// relay and a fresh ClientHello, which filters out clients that do not
    /// handle tokens and delays the expensive part of the handshake
    /// (`protocol.rs:185-195`).
    cost_imposition,
};

/// The meaning a bare `Retry` has on a path. The filter decides *whether* to
/// retry; the path decides what that is worth, and the router is the first
/// place both are known.
pub fn retryMeaning(path: ula.Path) Retry {
    return switch (path) {
        // The relay vouched for the origin, so there is nothing to validate.
        .relay => .cost_imposition,
        // `any_path` is the peer before a path is chosen, which is a direct
        // path until something says otherwise.
        .any_path, .custom => .source_validation,
    };
}

/// What the filter decided about an incoming attempt, and what the router
/// passes on.
///
/// Upstream `IncomingFilterOutcome` (`protocol.rs:164-209`) has these same four
/// verdicts. The `Retry` arm is split here because upstream's one variant has
/// two meanings and the path, which decides between them, is known here and
/// nowhere earlier.
pub const Verdict = union(enum) {
    /// Carry on with the handshake. Upstream `Accept`.
    accept,
    /// Answer with a retry token. Upstream `Retry`, with the meaning made
    /// explicit.
    retry: Retry,
    /// Refuse, and say so. Upstream `Reject`: "The remote will receive a
    /// CONNECTION_REFUSED error immediately" (`protocol.rs:203-205`). The one
    /// filter verdict a peer learns about.
    reject,
    /// Send nothing and say nothing. Upstream `Ignore`
    /// (`connection.rs:191-194`), and the one verdict upstream does not log.
    ignore,
};

/// Why a stage could not finish.
pub const Failure = union(enum) {
    /// The handshake did not produce an ALPN. Upstream `accepting.alpn().await`
    /// failing (`protocol.rs:644-650`).
    handshake: AcceptError,
    /// `on_accepting` returned an error, or the router's default await did.
    /// Upstream logs one line for both (`protocol.rs:657`, `:668-670`), so
    /// there is one arm.
    accepting: AcceptError,
    /// `accept` returned an error.
    ///
    /// **The peer is told nothing, and that is upstream's choice, not an
    /// oversight.** `protocol.rs:262-268`: returning an error drops the
    /// connection and logs a warning, "but no dedicated error code will be
    /// sent to the peer, so it's recommended to explicitly close the
    /// connection within your accept handler". A handler that wants the peer to
    /// know calls `Connection::close(code, reason)` itself, before returning
    /// the error; this module never sends a code on a handler's behalf, which
    /// is why `DispatchAction` has no field a code could live in and why
    /// `peerOutcome` answers for every arm of it.
    accept: AcceptError,
};

/// Where a connection attempt ended, when it ended by going away.
pub const Drop = union(enum) {
    /// A stage failed. The peer is told nothing.
    failed: Failure,
    /// The peer negotiated an ALPN no handler is registered for. Upstream
    /// warns and returns (`protocol.rs:653-656`).
    unsupported_alpn: []const u8,
    /// An event this state cannot accept. ozai's own arm, with no upstream
    /// counterpart: upstream's accept loop is a `select!` and cannot be fed an
    /// event out of order, but a machine can, and the router is the last place
    /// a stage can be caught before a handler is handed a pre-handshake handle.
    out_of_order: ConnEvent,
};

/// What the peer learns from an action.
///
/// The router sends two things to a peer and no more: a retry token, and a
/// refusal. Every local ending — invariant 19's accept failure, a connection a
/// handler dropped on purpose, an ALPN nobody registered — leaves the peer with
/// nothing, and upstream's five warnings are all of that kind.
pub const PeerOutcome = enum {
    /// No error code and no packet. The peer learns from the transport timing
    /// out, which is exactly what upstream's failed `accept` leaves behind.
    nothing,
    /// A refusal: CONNECTION_REFUSED, from `Incoming::refuse`.
    refused,
};

/// What the router does about a step.
pub const DispatchAction = union(enum) {
    /// Drive the handshake until the ALPN is known. Upstream
    /// `accepting.alpn().await` (`protocol.rs:644`).
    negotiate_alpn,
    /// Answer the filter's retry verdict with a token. The payload is what the
    /// retry is worth on this path, and it rides along because this is the last
    /// place the two meanings are still distinguishable.
    send_retry: Retry,
    /// Refuse. The peer is told at once.
    refuse,
    /// Send nothing. Upstream `incoming.ignore()`.
    ignore,
    /// Let the handshake finish without the handler's help: upstream's default
    /// `on_accepting` body, run by the router because the field is null.
    await_handshake,
    /// Call the handler's `on_accepting`.
    on_accepting: ProtocolHandler,
    /// Call the handler's `accept`. May be long-lived.
    accept: ProtocolHandler,
    /// The handler is done. The connection goes back to the endpoint, which
    /// closes it unless the handler kept a clone.
    release,
    /// The connection is gone. Nothing is sent.
    drop: Drop,
    /// Nothing: this state owes no step, or the step is already done.
    none,

    /// The peer outcome of an action.
    ///
    /// Exhaustive on purpose. A new arm that has not decided what the peer
    /// learns does not compile, which is the only way "sends no error code"
    /// stays a fact about the value rather than a comment about a code path.
    pub fn peerOutcome(self: DispatchAction) PeerOutcome {
        return switch (self) {
            .refuse => .refused,
            .negotiate_alpn,
            .send_retry,
            .ignore,
            .await_handshake,
            .on_accepting,
            .accept,
            .release,
            .drop,
            .none,
            => .nothing,
        };
    }
};

/// One connection attempt, as the router sees it.
///
/// The four live arms are upstream's four awaits in `handle_connection`
/// (`protocol.rs:637-671`) in order: the filter rules, the handshake produces
/// an ALPN, the handler takes the connection, the handler runs on it. Every
/// other arm is terminal.
pub const ConnState = union(enum) {
    /// An attempt has arrived and nothing has been read of it. The filter rules
    /// on this, which is what an `Incoming` is for: it exists so a connection
    /// can be judged before the handshake does any work
    /// (`connection.rs:130-137`).
    incoming,
    /// The filter let it through and the handshake is owed. No payload, because
    /// nothing is known yet: the ALPN is what finds the handler, so there is no
    /// handler to hold yet.
    negotiating,
    /// The ALPN is known and the handler's `on_accepting` is owed. The handler
    /// is held because finding it is part of this step, and a caller that has
    /// to report which protocol a connection landed on reads it here.
    accepting: ProtocolHandler,
    /// The handler's `accept` has been called and has not come back. There is no
    /// task here: the caller ran it inside the pass that reached this state and
    /// is holding the state until it reports an outcome, which may be several
    /// passes later. This is the arm the shutdown ordering protects — see
    /// `ProtocolHandler`'s note on what a long-lived `accept` means without a
    /// thread.
    handling: ProtocolHandler,
    ///
    /// The filter answered with a retry token. Terminal: the client comes back
    /// as a new attempt carrying the token.
    retried: Retry,
    /// The filter refused. Terminal, and the peer was told.
    refused,
    /// The filter ignored it. Terminal, and nobody was told.
    ignored,
    /// The handler's `accept` returned. Terminal: the connection goes back to
    /// the endpoint.
    released,
    /// The connection is gone. Terminal, and nobody was told.
    dropped: Drop,
};

/// One thing that happened to a connection attempt.
pub const ConnEvent = union(enum) {
    /// The filter ruled. Legal only while the attempt is `incoming`.
    filtered: Verdict,
    /// A stage reported. Which stage the state is waiting for says which
    /// success arm is legal, so a connection reported where an ALPN was owed
    /// is an out-of-order drop rather than a silent pass.
    outcome: Outcome,
};

/// What a stage came back with.
///
/// The success arm carries what that stage produces. The failure arm is shared
/// because upstream logs one line per failure and sends nothing for any of
/// them, and which stage failed is in the `Failure`.
pub const Outcome = union(enum) {
    /// The ALPN the peer negotiated.
    alpn: []const u8,
    /// `on_accepting` produced a connection, or the router's default await did.
    connection: Connection,
    /// `accept` returned. It produces nothing: upstream drops the connection
    /// when the future returns (`protocol.rs:262-265`).
    finished,
    /// The stage failed.
    failed: Failure,
};

/// One step: the next state and the one thing to do about it.
pub const DispatchStep = struct {
    state: ConnState,
    action: DispatchAction,
};

/// One step of a connection attempt.
///
/// `router` is a parameter, not state: which handler an ALPN resolves to is a
/// question about the table, and the table is the caller's, so nothing about
/// the answer is captured where a copy of it could go stale. Pure — the same
/// table, state and event always give the same step, which is what lets a test
/// drive a whole connection without a socket or a scheduler.
pub fn dispatchStep(
    router: *const Router,
    state: ConnState,
    event: ConnEvent,
) DispatchStep {
    return switch (state) {
        .incoming => incomingStep(event),
        .negotiating => negotiatingStep(router, event),
        .accepting => |handler| acceptingStep(handler, event),
        .handling => handledStep(event),
        // A terminal state absorbs everything. The first ending is the ending,
        // and a later event claiming otherwise is reported by the state the
        // caller already has, not by a second verdict written over the first.
        .retried, .refused, .ignored, .released, .dropped => .{
            .state = state,
            .action = .none,
        },
    };
}

fn incomingStep(event: ConnEvent) DispatchStep {
    const verdict = switch (event) {
        .filtered => |verdict| verdict,
        .outcome => return dropped(.{ .out_of_order = event }),
    };
    return switch (verdict) {
        .accept => .{ .state = .negotiating, .action = .negotiate_alpn },
        .retry => |retry| .{
            .state = .{ .retried = retry },
            .action = .{ .send_retry = retry },
        },
        .reject => .{ .state = .refused, .action = .refuse },
        .ignore => .{ .state = .ignored, .action = .ignore },
    };
}

fn negotiatingStep(router: *const Router, event: ConnEvent) DispatchStep {
    const outcome = switch (event) {
        .outcome => |outcome| outcome,
        .filtered => return dropped(.{ .out_of_order = event }),
    };
    return switch (outcome) {
        .alpn => |alpn| blk: {
            // No handler is a drop and not a refusal: upstream warns and
            // returns, and the peer is told nothing (`protocol.rs:653-656`).
            const entry = router.lookup(alpn) orelse
                break :blk dropped(.{ .unsupported_alpn = alpn });
            const handler = entry.handler;
            break :blk .{
                .state = .{ .accepting = handler },
                // Upstream's default `on_accepting` is the router's await, so
                // a handler that has no `on_accepting` is not called at all.
                .action = if (handler.on_accepting == null)
                    .await_handshake
                else
                    .{ .on_accepting = handler },
            };
        },
        .failed => |failure| switch (failure) {
            .handshake => |err| dropped(.{ .failed = .{ .handshake = err } }),
            // The other two belong to the two stages after this one.
            .accepting, .accept => dropped(.{ .out_of_order = event }),
        },
        .connection, .finished => dropped(.{ .out_of_order = event }),
    };
}

fn acceptingStep(handler: ProtocolHandler, event: ConnEvent) DispatchStep {
    const outcome = switch (event) {
        .outcome => |outcome| outcome,
        .filtered => return dropped(.{ .out_of_order = event }),
    };
    return switch (outcome) {
        .connection => .{
            .state = .{ .handling = handler },
            .action = .{ .accept = handler },
        },
        .failed => |failure| switch (failure) {
            .accepting => |err| dropped(.{ .failed = .{ .accepting = err } }),
            .handshake, .accept => dropped(.{ .out_of_order = event }),
        },
        .alpn, .finished => dropped(.{ .out_of_order = event }),
    };
}

fn handledStep(event: ConnEvent) DispatchStep {
    const outcome = switch (event) {
        .outcome => |outcome| outcome,
        .filtered => return dropped(.{ .out_of_order = event }),
    };
    return switch (outcome) {
        // Upstream drops the connection when the future returns; the handler
        // kept a clone if it wanted the connection to live
        // (`protocol.rs:262-265`).
        .finished => .{ .state = .released, .action = .release },
        .failed => |failure| switch (failure) {
            // The headline: a drop, and nothing sent to the peer. See
            // `Failure.accept`.
            .accept => |err| dropped(.{ .failed = .{ .accept = err } }),
            .handshake, .accepting => dropped(.{ .out_of_order = event }),
        },
        .alpn, .connection => dropped(.{ .out_of_order = event }),
    };
}

/// The terminal step for a connection that is gone. The state and the action
/// carry the same reason, because the caller has to act on one and the next
/// step has to remember the other.
fn dropped(reason: Drop) DispatchStep {
    return .{ .state = .{ .dropped = reason }, .action = .{ .drop = reason } };
}

/// The router's shutdown, as a value.
///
/// Upstream runs these steps at the bottom of the accept loop once the loop
/// stops (`protocol.rs:608-613`), in this order:
///
/// 1. `protocols.shutdown().await` — every handler's `shutdown`, awaited, so a
///    handler gets to close its connections gracefully.
/// 2. `handler_cancel_token.cancel()` — the `accept` futures stop.
/// 3. `endpoint.close().await` — the endpoint closes, which force-closes
///    whatever is left.
///
/// The order is the point, and an ordering bug here is a use-after-free. A
/// handler's `shutdown` closes connections that its own `accept` is still
/// using, so cancelling the accepts first cuts a graceful close in half;
/// closing the endpoint force-closes live connections, so closing before the
/// accepts are cancelled does the same damage a step later and without a
/// warning. Upstream says as much in the other direction, on the tail after the
/// close: the accepts are cancelled so that the `abort_all` which follows is
/// "a noop" (`protocol.rs:614-615`).
///
/// That tail is not a fourth step here. It exists to clean up tasks the cancel
/// already stopped, and the three steps above are where the order lives.
pub const Shutdown = struct {
    /// Which step is owed. Each phase owes exactly one action, and a phase
    /// only advances when the step before it has been reported done, so the
    /// cancel cannot be emitted while a handler is still shutting down and the
    /// close cannot be emitted before the cancel.
    phase: Phase = .serving,
    /// Registered handlers, which become running when the shutdown starts and
    /// reach zero when the last of them has returned. The count is not in the
    /// phase because the table is the caller's and the machine holds no table.
    ///
    /// **Zero means the close owes no report at all**, and the machine takes
    /// that as a fact on the first step rather than as a phase to wait in.
    handlers: usize = 0,
    /// `accept` futures still running. This is what a cancel has to account
    /// for, and it is why the state is more than the phase: a router with three
    /// accepts running and one that has been told they are gone are the same
    /// phase and a different fact.
    ///
    /// **`accepts` does not gate anything.** The cancel is one step whatever
    /// the count is, exactly as `cancel()` is one call upstream
    /// (`protocol.rs:611`); the count is what a caller reads to know how many
    /// accept futures its own cancel has to account for, and it saturates at
    /// zero rather than wrapping.
    accepts: usize = 0,

    pub const Phase = enum {
        /// The accept loop is taking connections. Upstream's `select!` body
        /// before the cancel token fires.
        ///
        /// Nothing waits here, and a close taken with no handler registered
        /// passes straight through this phase to the cancel rather than resting
        /// in the drain (`beginShutdown`). Upstream's `protocols.shutdown().await`
        /// over an empty map returns at once and the cancel follows it
        /// (`protocol.rs:609-611`), so the two agree on what happens and only
        /// the representation differs.
        serving,
        /// Intake has stopped and the handlers are draining. Upstream
        /// `protocols.shutdown().await`.
        draining_handlers,
        /// Every handler has returned. The accepts are still running and are
        /// owed their cancellation. Upstream `handler_cancel_token.cancel()`.
        cancelling_accepts,
        /// The accepts are cancelled. The endpoint is owed its close. Upstream
        /// `endpoint.close().await`.
        closing_endpoint,
        /// Closed. Terminal.
        closed,
    };

    /// One thing that happened to the shutdown.
    pub const Event = union(enum) {
        /// The application asked to close, or the accept loop stopped because
        /// the endpoint closed under it. Upstream `Router::shutdown` cancels
        /// the run token and awaits the task (`protocol.rs:435-452`), and the
        /// loop also breaks when `endpoint.accept()` returns nothing
        /// (`protocol.rs:569-571`).
        close_requested,
        /// A handler's `shutdown` returned.
        handler_finished,
        /// An `accept` returned, finished or was cancelled. This is the live
        /// count going down, and it never advances the shutdown: upstream's
        /// loop takes a finished task from the join set and goes back to
        /// `select!` (`protocol.rs:545-565`).
        accept_finished,
        /// The cancellation landed: every `accept` future is gone.
        ///
        /// Upstream does not wait for this separately — `cancel()` is
        /// synchronous and `endpoint.close()` follows it — but a machine that
        /// is to be checkable without a scheduler has to be *told* the step
        /// happened. Otherwise the close is emitted in the same breath as the
        /// cancel and the ordering stops being observable at all.
        accepts_cancelled,
        /// `endpoint.close()` returned.
        endpoint_closed,
    };

    /// The one thing the shutdown owes.
    pub const Action = union(enum) {
        /// Call `shutdown` on every registered handler and await all of them,
        /// concurrently (`protocol.rs:404-407`).
        shutdown_handlers: usize,
        /// Cancel the `accept` futures.
        cancel_accepts,
        /// Close the endpoint.
        close_endpoint,
        /// Nothing: this event is not this phase's business, or the step is
        /// already done. Upstream's `trace!` arms (`protocol.rs:559-565`).
        none,
    };

    pub const Step = struct {
        shutdown: Shutdown,
        action: Action,
    };

    /// A router that has not been asked to close, with `handlers` registered and
    /// `accepts` running. The counts are the caller's to know and the machine's
    /// to keep.
    ///
    /// **`handlers == 0` is a legitimate answer, not an empty one.** It is what
    /// an endpoint over a table with no registrations hands here, and it makes
    /// the first close step emit the cancel directly — see `beginShutdown`. A
    /// caller that reads it as "drain nothing, then wait" has read it wrong:
    /// there is no report to wait for and the machine will not invent one.
    pub fn init(handlers: usize, accepts: usize) Shutdown {
        return .{ .handlers = handlers, .accepts = accepts };
    }

    /// One step. Pure, and the whole of the ordering.
    ///
    /// Every event is named in every phase and nothing falls through, so an
    /// event added later has to be classified here rather than being absorbed
    /// by a wildcard and never reaching the phase that owed it.
    pub fn step(self: Shutdown, event: Event) Step {
        return switch (self.phase) {
            .serving => switch (event) {
                .close_requested => beginShutdown(self),
                .accept_finished => .{ .shutdown = self.fewerAccepts(), .action = .none },
                // Nothing has been asked for yet, and a report from a phase
                // that has not been entered is not this one's business.
                .handler_finished, .accepts_cancelled, .endpoint_closed => self.hold(),
            },
            .draining_handlers => switch (event) {
                .handler_finished => handlerFinished(self),
                .accept_finished => .{ .shutdown = self.fewerAccepts(), .action = .none },
                // The whole ordering is this arm: the cancel waits for the
                // handlers and the close waits for the cancel, so neither of
                // these can begin early.
                .close_requested, .accepts_cancelled, .endpoint_closed => self.hold(),
            },
            .cancelling_accepts => switch (event) {
                .accepts_cancelled => .{
                    .shutdown = .{ .phase = .closing_endpoint, .accepts = 0 },
                    .action = .close_endpoint,
                },
                .accept_finished => .{ .shutdown = self.fewerAccepts(), .action = .none },
                .close_requested, .handler_finished, .endpoint_closed => self.hold(),
            },
            .closing_endpoint => switch (event) {
                .endpoint_closed => .{
                    .shutdown = .{ .phase = .closed },
                    .action = .none,
                },
                .accept_finished, .close_requested, .handler_finished, .accepts_cancelled => {
                    return self.hold();
                },
            },
            .closed => self.hold(),
        };
    }

    /// No step. Absorbing an event that does not apply here is the point: the
    /// ordering lives in which event advances which phase, and an event that
    /// advances nothing is the ordering holding.
    fn hold(self: Shutdown) Step {
        return .{ .shutdown = self, .action = .none };
    }

    /// One handler returned, and either there are others still draining or
    /// every handler is done and the accepts are owed their cancellation.
    ///
    /// The count goes down on *every* report, not only on the last: an arm that
    /// held the state unchanged until the end would never reach zero, the
    /// cancel would never be emitted, and the endpoint would never close.
    fn handlerFinished(self: Shutdown) Step {
        // A report past zero is a handler the count never had, and holding is
        // the only honest answer: there is nothing left to drain. `beginShutdown`
        // is why that arm is unreachable on the way in — a close taken with no
        // handler registered never enters the phase this runs in.
        if (self.handlers == 0) return self.hold();
        var next = self;
        next.handlers -= 1;
        if (next.handlers > 0) return .{ .shutdown = next, .action = .none };
        return .{
            .shutdown = .{ .phase = .cancelling_accepts, .accepts = self.accepts },
            .action = .cancel_accepts,
        };
    }

    /// A close, and the first thing it owes.
    ///
    /// **The counts decide the phase, and the phase is settled before the
    /// action is named.** A close with a handler registered owes
    /// `shutdown_handlers` and then one `handler_finished` per handler, and it
    /// cannot leave `.draining_handlers` until every one of those has been
    /// reported. A close with *no* handler registered owes no report at all, so
    /// entering that phase with a `shutdown_handlers` of zero would be a phase
    /// nothing can leave: `handler_finished` past zero is held, because there
    /// is nothing left to drain, and the cancel this close owes is never
    /// emitted — the endpoint stays open for ever.
    ///
    /// So the zero case is decided here, on the counts, rather than left to a
    /// caller to notice: no handler means the cancel is owed the moment the
    /// close is asked for, and the machine says so in one step. `accepts`
    /// crosses either way, because the cancel has to account for them whatever
    /// the handlers did.
    ///
    /// Upstream cannot reach the shape this avoids. `protocols.shutdown()`
    /// awaits one future per *map value* (`protocol.rs:404-407`), and a map
    /// with no values has nothing to await, so the cancel at `:611` is the very
    /// next statement to run. `handlerCount` is what makes the count knowable
    /// on this side, and it is the same count the phase it feeds would have
    /// waited for.
    fn beginShutdown(self: Shutdown) Step {
        if (self.handlers == 0) return .{
            .shutdown = .{ .phase = .cancelling_accepts, .accepts = self.accepts },
            .action = .cancel_accepts,
        };
        return .{
            .shutdown = .{
                .phase = .draining_handlers,
                .handlers = self.handlers,
                .accepts = self.accepts,
            },
            .action = .{ .shutdown_handlers = self.handlers },
        };
    }

    /// One `accept` returned. Saturating: a report past zero is a task the count
    /// never had, and a wrapped count would read as "an enormous number of
    /// accepts is still running".
    fn fewerAccepts(self: Shutdown) Shutdown {
        var next = self;
        next.accepts = if (self.accepts == 0) 0 else self.accepts - 1;
        return next;
    }
};

/// The endpoint lease, which has to be given up by closing.
///
/// Upstream logs an error from `EndpointInner`'s `Drop` when `close()` was
/// never called: dropping an endpoint without closing is a misuse, not a
/// cleanup. Zig has no `Drop`, so the report moves to `deinit` and the guarantee
/// is carried by a type rather than by discipline:
///
/// - `acquire` is the only way to hold a lease, so nothing is bound to an
///   endpoint without one.
/// - `deinit` is the only way to give it up, and it reads the answer out of the
///   shutdown the lease watches rather than out of an argument, so a caller
///   cannot talk its way out of it. `.abandoned` is upstream's drop error, with
///   the phase it was dropped in.
/// - the mark is set before the report, so a second `deinit` finds nothing to
///   do — the same discipline as `OnDisconnectGuard` in `relay/server.zig`.
///
/// The shutdown must outlive the lease, because `deinit` reads it. That is the
/// half of "the endpoint must never outlive its guard" a type can carry; the
/// other half stays a discipline, because Zig has no move semantics and both
/// `phase` and the lease's own fields are readable and writable by anyone
/// holding the struct.
pub const Lease = struct {
    shutdown: *Shutdown,
    reported: bool,

    /// The only way to hold a lease.
    pub fn acquire(shutdown: *Shutdown) Lease {
        return .{ .shutdown = shutdown, .reported = false };
    }

    /// The single exit. `.closed` is the one good answer, and the only way to
    /// reach it is to have driven the shutdown to `closed` — which is the only
    /// way the endpoint is closed.
    // `reported` is the readable report-once tombstone; Z030 only recognizes
    // its fixed vocabulary of lifecycle field names, not this marker.
    // ziglint-ignore: Z030
    pub fn deinit(self: *Lease) Release {
        const already = self.reported;
        self.reported = true;
        if (already) return .already_gone;
        if (self.shutdown.phase == .closed) return .closed;
        return .{ .abandoned = self.shutdown.phase };
    }
};

/// What giving up a lease found.
pub const Release = union(enum) {
    /// The endpoint was closed. The one good exit.
    closed,
    /// The lease was given up with the endpoint still open, in this phase.
    /// This is the drop upstream logs an error for, and the phase is in the
    /// answer because "you forgot to close" and "you closed in the wrong
    /// order" are different bugs.
    abandoned: Shutdown.Phase,
    /// Already reported. A lease is a plain struct and can be copied, so a
    /// second copy can be deinited; the mark is set before the report, exactly
    /// as `OnDisconnectGuard::deinit` does it.
    already_gone,
};

const t = std.testing;

/// A handler that records what the router called it for. Every test owns one,
/// so the context pointer is the observable "which handler won".
const Recorder = struct {
    on_accepting_calls: usize = 0,
    accept_calls: usize = 0,
    shutdown_calls: usize = 0,
    accept_error: ?AcceptError = null,

    fn onAccepting(ctx: *anyopaque, accepting: Accepting) AcceptError!Connection {
        const self: *Recorder = @ptrCast(@alignCast(ctx));
        _ = accepting;
        self.on_accepting_calls += 1;
        return .{ .ptr = ctx };
    }

    fn accept(ctx: *anyopaque, connection: Connection) AcceptError!void {
        const self: *Recorder = @ptrCast(@alignCast(ctx));
        _ = connection;
        self.accept_calls += 1;
        if (self.accept_error) |err| return err;
    }

    fn shutdown(ctx: *anyopaque) void {
        const self: *Recorder = @ptrCast(@alignCast(ctx));
        self.shutdown_calls += 1;
    }

    fn handler(self: *Recorder) ProtocolHandler {
        return .{
            .ptr = self,
            .on_accepting = Recorder.onAccepting,
            .accept = Recorder.accept,
            .shutdown = Recorder.shutdown,
        };
    }

    /// A handler that implements `accept` and nothing else, which is the shape
    /// upstream's default methods are for: the router runs both defaults and
    /// this one is never called for them.
    fn bare(self: *Recorder) ProtocolHandler {
        return .{
            .ptr = self,
            .on_accepting = null,
            .accept = Recorder.accept,
            .shutdown = null,
        };
    }
};

/// The offer list, into storage the test owns. Bounded by `out` so an
/// under-sized buffer shows up as a wrong count rather than an index panic.
fn offered(router: *const Router, out: [][]const u8) usize {
    var alpns = router.alpns();
    var count: usize = 0;
    while (count < out.len) {
        const alpn = alpns.next() orelse break;
        out[count] = alpn;
        count += 1;
    }
    return count;
}

/// A router with one handler for `alpn`, and the recorder behind it.
fn oneHandler(
    alpn: []const u8,
    entries: []Entry,
    recorder: *Recorder,
) RegisterError!Router {
    var builder = Builder.init(entries);
    _ = try builder.accept(alpn, recorder.handler());
    return builder.build();
}

/// Which handler a lookup found. `*anyopaque` does not compare with a typed
/// pointer, so a test names the handler it expects through this.
fn isContext(handler: ProtocolHandler, context: *Recorder) bool {
    return handler.ptr == @as(*anyopaque, context);
}

test "the handler vtable is four fields and no more" {
    // The plan names the four. A fifth would be a trait method wearing a
    // vtable's name, which is what `AddressLookup` refuses in
    // `discovery/resolve.zig`.
    const fields = @typeInfo(ProtocolHandler).@"struct".fields;
    try t.expectEqual(@as(usize, 4), fields.len);
    const names = [_][]const u8{ "ptr", "on_accepting", "accept", "shutdown" };
    inline for (fields, names) |field, name| {
        try t.expectEqualStrings(name, field.name);
    }
}

test "every callback gets the handler's own context back" {
    var recorder: Recorder = .{};
    const handler = recorder.handler();

    const on_accepting = handler.on_accepting orelse return error.TestUnexpectedResult;
    const shutdown = handler.shutdown orelse return error.TestUnexpectedResult;
    const connection = try on_accepting(handler.ptr, .{ .ptr = &recorder });
    try t.expectEqual(handler.ptr, connection.ptr);
    try handler.accept(handler.ptr, connection);
    shutdown(handler.ptr);

    // The context is not copied or replaced, and each entry is called once.
    try t.expectEqual(@as(usize, 1), recorder.on_accepting_calls);
    try t.expectEqual(@as(usize, 1), recorder.accept_calls);
    try t.expectEqual(@as(usize, 1), recorder.shutdown_calls);
}

test "registration order is the offer order" {
    var first: Recorder = .{};
    var second: Recorder = .{};
    var third: Recorder = .{};
    var entries: [3]Entry = undefined;
    var builder = Builder.init(&entries);

    try t.expectEqual(Registered.fresh, try builder.accept("/echo", first.handler()));
    try t.expectEqual(Registered.fresh, try builder.accept("/blob", second.handler()));
    try t.expectEqual(Registered.fresh, try builder.accept("/qad-probe", third.handler()));

    // The order the ALPNs were registered in, which is the order the peer is
    // offered them in, which is the order a server's preference runs.
    var list: [3][]const u8 = undefined;
    const router = builder.build();
    try t.expectEqual(@as(usize, 3), offered(&router, &list));
    try t.expectEqualStrings("/echo", list[0]);
    try t.expectEqualStrings("/blob", list[1]);
    try t.expectEqualStrings("/qad-probe", list[2]);

    // And each one dispatches to the handler it was registered with.
    try t.expect(isContext(router.lookup("/echo").?.handler, &first));
    try t.expect(isContext(router.lookup("/blob").?.handler, &second));
    try t.expect(isContext(router.lookup("/qad-probe").?.handler, &third));
    try t.expectEqual(@as(?*const Entry, null), router.lookup("/nope"));
}

test "an ALPN registered twice is offered twice and dispatches to the newer handler" {
    var older: Recorder = .{};
    var newer: Recorder = .{};
    // Three slots for three registrations: a repeated ALPN takes a second slot
    // rather than replacing the first, because it is offered twice.
    var entries: [3]Entry = undefined;
    var builder = Builder.init(&entries);

    try t.expectEqual(Registered.fresh, try builder.accept("/echo", older.handler()));
    // The second registration names the entry it displaces, so the caller can
    // see that the first one is now unreachable instead of finding out from a
    // peer.
    try t.expectEqual(
        Registered{ .replaced = 0 },
        try builder.accept("/echo", newer.handler()),
    );
    try t.expectEqual(Registered.fresh, try builder.accept("/blob", older.handler()));

    // Both halves of upstream's overwrite, and they disagree on purpose: the
    // peer is offered the ALPN twice, and only the newer handler can be picked.
    var list: [3][]const u8 = undefined;
    const router = builder.build();
    try t.expectEqual(@as(usize, 3), offered(&router, &list));
    try t.expectEqualStrings("/echo", list[0]);
    try t.expectEqualStrings("/echo", list[1]);
    try t.expectEqualStrings("/blob", list[2]);

    try t.expect(isContext(router.lookup("/echo").?.handler, &newer));
    try t.expect(isContext(router.lookup("/blob").?.handler, &older));
    // The displaced entry is still there, holding the ALPN, because upstream
    // pushes onto the offer list unconditionally.
    try t.expect(isContext(router.entries[0].handler, &older));
}

test "the internal ALPN is one constant an application cannot register" {
    var recorder: Recorder = .{};
    var entries: [1]Entry = undefined;
    var builder = Builder.init(&entries);

    // Captured from `iroh-relay/src/quic.rs:10`; the bytes are the contract
    // with every iroh peer that speaks address discovery.
    try t.expectEqualStrings("/iroh-qad/0", qad_alpn);
    try t.expectEqual(@as(usize, 11), qad_alpn.len);

    try t.expectError(error.reserved_alpn, builder.accept(qad_alpn, recorder.handler()));
    // And the refusal changed nothing: no entry, no offer.
    var list: [1][]const u8 = undefined;
    const refused = builder.build();
    try t.expectEqual(@as(usize, 0), offered(&refused, &list));

    // The one way in takes no ALPN, so there is no string to pass wrongly.
    try t.expectEqual(Registered.fresh, try builder.acceptInternal(recorder.handler()));
    const router = builder.build();
    try t.expectEqual(@as(usize, 1), offered(&router, &list));
    try t.expectEqualStrings(qad_alpn, list[0]);
    try t.expect(isContext(router.lookup(qad_alpn).?.handler, &recorder));
}

test "a full table refuses a registration and changes nothing" {
    var recorder: Recorder = .{};
    var entries: [1]Entry = undefined;
    var builder = Builder.init(&entries);

    try t.expectEqual(Registered.fresh, try builder.accept("/echo", recorder.handler()));
    try t.expectError(error.no_space, builder.accept("/blob", recorder.handler()));

    var list: [1][]const u8 = undefined;
    const router = builder.build();
    try t.expectEqual(@as(usize, 1), offered(&router, &list));
    try t.expectEqualStrings("/echo", list[0]);
    try t.expectEqual(@as(?*const Entry, null), router.lookup("/blob"));
}

test "a retry is address validation on a direct path and a cost on a relay" {
    // Same verb, two meanings, and the path is what tells them apart. One type
    // with two values, so a verdict that lost its meaning on the way through
    // the router stops comparing equal to what the path says it should be.
    try t.expectEqual(Retry.source_validation, retryMeaning(.any_path));
    try t.expectEqual(Retry.source_validation, retryMeaning(.custom));
    try t.expectEqual(Retry.cost_imposition, retryMeaning(.relay));
}

test "the filter's four verdicts, and only a refusal reaches the peer" {
    var recorder: Recorder = .{};
    var entries: [1]Entry = undefined;
    const router = try oneHandler("/echo", &entries, &recorder);

    // Carry on: the handshake is owed and nothing is sent.
    const accept = dispatchStep(&router, .incoming, .{ .filtered = .accept });
    try t.expectEqual(ConnState.negotiating, accept.state);
    try t.expectEqual(DispatchAction.negotiate_alpn, accept.action);
    try t.expectEqual(PeerOutcome.nothing, accept.action.peerOutcome());

    // Retry: the token is sent and the attempt ends. The meaning rides along.
    const direct = dispatchStep(&router, .incoming, .{
        .filtered = .{ .retry = retryMeaning(.custom) },
    });
    try t.expectEqual(ConnState{ .retried = .source_validation }, direct.state);
    try t.expectEqual(
        DispatchAction{ .send_retry = .source_validation },
        direct.action,
    );
    try t.expectEqual(PeerOutcome.nothing, direct.action.peerOutcome());

    // The same verdict on a relayed path is a different value and a different
    // state, which is the whole point of carrying the meaning.
    const relayed = dispatchStep(&router, .incoming, .{
        .filtered = .{ .retry = retryMeaning(.relay) },
    });
    try t.expectEqual(ConnState{ .retried = .cost_imposition }, relayed.state);

    // Reject: the one thing the peer is told.
    const reject = dispatchStep(&router, .incoming, .{ .filtered = .reject });
    try t.expectEqual(ConnState.refused, reject.state);
    try t.expectEqual(DispatchAction.refuse, reject.action);
    try t.expectEqual(PeerOutcome.refused, reject.action.peerOutcome());

    // Ignore: no packet, and unlike every other ending here, no warning.
    const ignore = dispatchStep(&router, .incoming, .{ .filtered = .ignore });
    try t.expectEqual(ConnState.ignored, ignore.state);
    try t.expectEqual(DispatchAction.ignore, ignore.action);
    try t.expectEqual(PeerOutcome.nothing, ignore.action.peerOutcome());
}

test "an ALPN nobody registered is dropped, not refused" {
    var recorder: Recorder = .{};
    var entries: [1]Entry = undefined;
    const router = try oneHandler("/echo", &entries, &recorder);

    const step = dispatchStep(&router, .negotiating, .{
        .outcome = .{ .alpn = "/unknown" },
    });
    // Upstream warns and returns: the peer is told nothing, so this is a drop
    // and not a refusal even though the router does know the ALPN.
    try t.expectEqual(
        ConnState{ .dropped = .{ .unsupported_alpn = "/unknown" } },
        step.state,
    );
    try t.expectEqual(
        DispatchAction{ .drop = .{ .unsupported_alpn = "/unknown" } },
        step.action,
    );
    try t.expectEqual(PeerOutcome.nothing, step.action.peerOutcome());
    try t.expectEqual(@as(usize, 0), recorder.accept_calls);
}

test "the two accepting routes converge on the same call" {
    var with_default: Recorder = .{};
    var with_own: Recorder = .{};
    var entries: [2]Entry = undefined;
    var builder = Builder.init(&entries);
    _ = try builder.accept("/bare", with_default.bare());
    _ = try builder.accept("/own", with_own.handler());
    const router = builder.build();

    // No `on_accepting`: the router awaits the handshake itself, which is
    // upstream's default body.
    const awaited = dispatchStep(&router, .negotiating, .{
        .outcome = .{ .alpn = "/bare" },
    });
    try t.expectEqual(ConnState{ .accepting = with_default.bare() }, awaited.state);
    try t.expectEqual(DispatchAction.await_handshake, awaited.action);
    try t.expectEqual(@as(usize, 0), with_default.on_accepting_calls);

    // With one: the handler is called, and the action names the call rather
    // than the router having made it. Calling it here is what makes the action
    // checkable without a scheduler.
    const called = dispatchStep(&router, .negotiating, .{
        .outcome = .{ .alpn = "/own" },
    });
    switch (called.action) {
        .on_accepting => |handler| {
            const on_accepting = handler.on_accepting orelse return error.TestUnexpectedResult;
            const connection = try on_accepting(handler.ptr, .{ .ptr = &with_own });
            // The handle comes back unchanged, which is the whole of what a
            // pre-handshake handle is allowed to be here.
            try t.expect(connection.ptr == @as(*anyopaque, &with_own));
            try t.expectEqual(@as(usize, 1), with_own.on_accepting_calls);

            // Both routes now owe the same call, on the same kind of state.
            const next = dispatchStep(&router, called.state, .{
                .outcome = .{ .connection = connection },
            });
            try t.expectEqual(ConnState{ .handling = handler }, next.state);
            try t.expectEqual(DispatchAction{ .accept = handler }, next.action);
        },
        else => return error.TestUnexpectedResult,
    }
    try t.expectEqual(@as(usize, 0), with_default.on_accepting_calls);
}

test "an accept failure drops the connection and sends no error code" {
    var recorder: Recorder = .{ .accept_error = error.NotAllowed };
    var entries: [1]Entry = undefined;
    const router = try oneHandler("/echo", &entries, &recorder);

    // All the way to a running accept.
    const offered_alpn = dispatchStep(&router, .negotiating, .{
        .outcome = .{ .alpn = "/echo" },
    });
    const handling = dispatchStep(&router, offered_alpn.state, .{
        .outcome = .{ .connection = .{ .ptr = &entries } },
    });
    try t.expectEqual(ConnState{ .handling = recorder.handler() }, handling.state);
    try t.expectEqual(DispatchAction{ .accept = recorder.handler() }, handling.action);

    // And now it fails.
    const failed = dispatchStep(&router, handling.state, .{
        .outcome = .{ .failed = .{ .accept = error.NotAllowed } },
    });
    const drop: Drop = .{ .failed = .{ .accept = error.NotAllowed } };
    try t.expectEqual(ConnState{ .dropped = drop }, failed.state);
    try t.expectEqual(DispatchAction{ .drop = drop }, failed.action);
    // Invariant 19. The connection is dropped, nothing is sent, and the only
    // trace of it is the warning the caller logs for a `.drop`. A handler that
    // wants the peer to know closes the connection itself, before it returns
    // the error — and if someone "fixes" this path into an error code, the two
    // lines below are what fails.
    try t.expectEqual(PeerOutcome.nothing, failed.action.peerOutcome());
    // The refusal is still the one thing that reaches a peer, so the assertion
    // above is not the assertion that every action is silent.
    try t.expectEqual(
        PeerOutcome.refused,
        dispatchStep(&router, .incoming, .{ .filtered = .reject }).action.peerOutcome(),
    );
}

test "a handler that returns cleanly releases the connection" {
    var recorder: Recorder = .{};
    var entries: [1]Entry = undefined;
    const router = try oneHandler("/echo", &entries, &recorder);

    const step = dispatchStep(&router, .{ .handling = recorder.handler() }, .{
        .outcome = .finished,
    });
    try t.expectEqual(ConnState.released, step.state);
    // Released is also a drop of the connection — upstream drops it when the
    // future returns — but not a failure, so it is a different action and no
    // warning goes with it.
    try t.expectEqual(DispatchAction.release, step.action);
    try t.expectEqual(PeerOutcome.nothing, step.action.peerOutcome());
}

test "a failed handshake or a failed on_accepting is a drop with a warning" {
    var recorder: Recorder = .{};
    var entries: [1]Entry = undefined;
    const router = try oneHandler("/echo", &entries, &recorder);

    // The handshake never produced an ALPN.
    const handshake = dispatchStep(&router, .negotiating, .{
        .outcome = .{ .failed = .{ .handshake = error.Connecting } },
    });
    try t.expectEqual(ConnState{ .dropped = .{
        .failed = .{ .handshake = error.Connecting },
    } }, handshake.state);
    try t.expectEqual(PeerOutcome.nothing, handshake.action.peerOutcome());

    // The handler's `on_accepting` failed, which upstream logs under the same
    // line as the default await.
    const accepting = dispatchStep(&router, .{ .accepting = recorder.handler() }, .{
        .outcome = .{ .failed = .{ .accepting = error.MissingRemoteEndpointId } },
    });
    try t.expectEqual(ConnState{ .dropped = .{
        .failed = .{ .accepting = error.MissingRemoteEndpointId },
    } }, accepting.state);
    try t.expectEqual(PeerOutcome.nothing, accepting.action.peerOutcome());
    try t.expectEqual(@as(usize, 0), recorder.accept_calls);
}

test "each live state accepts only the outcome its own stage produces" {
    var recorder: Recorder = .{};
    var entries: [1]Entry = undefined;
    const router = try oneHandler("/echo", &entries, &recorder);

    // `ConnState` order, and the one `Outcome` success arm each state is
    // waiting for. `incoming` owes the filter, not a stage.
    const live = [_]ConnState{
        .incoming,
        .negotiating,
        .{ .accepting = recorder.handler() },
        .{ .handling = recorder.handler() },
    };
    const successes = [_]Outcome{
        .{ .alpn = "/echo" },
        .{ .connection = .{ .ptr = &recorder } },
        .finished,
    };
    // The one failure each state can produce. The other two are out of order
    // for it, which is what stops a handler failure being reported one stage
    // early.
    const failures = [_]Failure{
        .{ .handshake = error.Connecting },
        .{ .accepting = error.NotAllowed },
        .{ .accept = error.Connection },
    };

    for (live, 0..) |state, stage| {
        for (successes, 0..) |outcome, arm| {
            const step = dispatchStep(&router, state, .{ .outcome = outcome });
            // The one stage this state is waiting for moves it on; every other
            // report is a drop that names the event it could not accept.
            if (stage == arm + 1) {
                try t.expect(std.meta.activeTag(step.state) != .dropped);
            } else {
                try t.expectEqual(
                    Drop{ .out_of_order = .{ .outcome = outcome } },
                    step.state.dropped,
                );
            }
        }
        for (failures) |failure| {
            const step = dispatchStep(&router, state, .{
                .outcome = .{ .failed = failure },
            });
            // `failures` is in `ConnState` order minus the state that owes no
            // stage, so the state's own failure is one below its index.
            if (stage > 0 and
                std.meta.activeTag(failure) == std.meta.activeTag(failures[stage - 1]))
            {
                try t.expectEqual(Drop{ .failed = failure }, step.state.dropped);
            } else {
                try t.expectEqual(
                    Drop{ .out_of_order = .{ .outcome = .{ .failed = failure } } },
                    step.state.dropped,
                );
            }
        }
    }
}

test "a terminal connection state absorbs every event" {
    var recorder: Recorder = .{};
    var entries: [1]Entry = undefined;
    const router = try oneHandler("/echo", &entries, &recorder);

    // The first ending is the ending, and a later event does not overwrite the
    // record of it.
    const terminal = [_]ConnState{
        .{ .retried = .cost_imposition },
        .refused,
        .ignored,
        .released,
        .{ .dropped = .{ .failed = .{ .accept = error.NotAllowed } } },
    };
    const events = [_]ConnEvent{
        .{ .filtered = .accept },
        .{ .filtered = .reject },
        .{ .outcome = .finished },
        .{ .outcome = .{ .failed = .{ .accept = error.NotAllowed } } },
    };
    for (terminal) |state| {
        for (events) |event| {
            const step = dispatchStep(&router, state, event);
            try t.expectEqual(state, step.state);
            try t.expectEqual(DispatchAction.none, step.action);
        }
    }
}

test "the shutdown order is handlers, then cancel, then close" {
    var shutdown = Shutdown.init(2, 3);
    try t.expectEqual(Shutdown.Phase.serving, shutdown.phase);

    // Intake stops, and every handler is told at once.
    const first = shutdown.step(.close_requested);
    try t.expectEqual(Shutdown.Action{ .shutdown_handlers = 2 }, first.action);
    try t.expectEqual(Shutdown.Phase.draining_handlers, first.shutdown.phase);
    shutdown = first.shutdown;

    // The cancel cannot begin while a handler is still shutting down, and
    // neither can the close. These three are the ordering, and each is fed the
    // event that would jump the queue.
    for ([_]Shutdown.Event{ .accepts_cancelled, .endpoint_closed, .close_requested }) |event| {
        const early = shutdown.step(event);
        try t.expectEqual(Shutdown.Action.none, early.action);
        try t.expectEqual(Shutdown.Phase.draining_handlers, early.shutdown.phase);
    }
    // One handler back out of two: still nothing.
    const one = shutdown.step(.handler_finished);
    try t.expectEqual(Shutdown.Action.none, one.action);
    try t.expectEqual(Shutdown.Phase.draining_handlers, one.shutdown.phase);
    try t.expectEqual(@as(usize, 1), one.shutdown.handlers);

    // The last handler, and now the accepts are cancelled.
    const cancel = one.shutdown.step(.handler_finished);
    try t.expectEqual(Shutdown.Action.cancel_accepts, cancel.action);
    try t.expectEqual(Shutdown.Phase.cancelling_accepts, cancel.shutdown.phase);
    try t.expectEqual(@as(usize, 0), cancel.shutdown.handlers);
    // A handler report that arrives after the cancel has nothing to do: there
    // are none left.
    const late = cancel.shutdown.step(.handler_finished);
    try t.expectEqual(Shutdown.Action.none, late.action);
    try t.expectEqual(Shutdown.Phase.cancelling_accepts, late.shutdown.phase);

    // The close cannot begin before the cancellation has landed.
    const too_early = late.shutdown.step(.endpoint_closed);
    try t.expectEqual(Shutdown.Action.none, too_early.action);
    try t.expectEqual(Shutdown.Phase.cancelling_accepts, too_early.shutdown.phase);

    // The cancellation lands, and only now is the endpoint closed.
    const close = late.shutdown.step(.accepts_cancelled);
    try t.expectEqual(Shutdown.Action.close_endpoint, close.action);
    try t.expectEqual(Shutdown.Phase.closing_endpoint, close.shutdown.phase);

    // And the close is what finishes it.
    const closed = close.shutdown.step(.endpoint_closed);
    try t.expectEqual(Shutdown.Action.none, closed.action);
    try t.expectEqual(Shutdown.Phase.closed, closed.shutdown.phase);

    // A second close request is upstream's `Router::shutdown` returning `Ok`
    // when already shut down, not a second shutdown.
    for ([_]Shutdown.Event{
        .close_requested,
        .handler_finished,
        .accept_finished,
        .accepts_cancelled,
        .endpoint_closed,
    }) |event| {
        const again = closed.shutdown.step(event);
        try t.expectEqual(Shutdown.Action.none, again.action);
        try t.expectEqual(Shutdown.Phase.closed, again.shutdown.phase);
    }
}

test "a close with nothing registered still cancels the accepts and closes" {
    // The shape an endpoint over a table with no registrations hands this
    // machine, and the one place the counts have to be read before the phase is
    // chosen. A close that entered `draining_handlers` here would owe a
    // `handler_finished` that nobody can send, and every later event is held
    // while it waits: the accepts are never cancelled and the endpoint is never
    // closed.
    const first = Shutdown.init(0, 0).step(.close_requested);
    try t.expectEqual(Shutdown.Action.cancel_accepts, first.action);
    try t.expectEqual(Shutdown.Phase.cancelling_accepts, first.shutdown.phase);
    try t.expectEqual(@as(usize, 0), first.shutdown.handlers);

    // So the order is reached by the two reports the close still owes, with no
    // handler drain in between to stall in.
    const cancelled = first.shutdown.step(.accepts_cancelled);
    try t.expectEqual(Shutdown.Action.close_endpoint, cancelled.action);
    try t.expectEqual(Shutdown.Phase.closing_endpoint, cancelled.shutdown.phase);
    const closed = cancelled.shutdown.step(.endpoint_closed);
    try t.expectEqual(Shutdown.Phase.closed, closed.shutdown.phase);

    // And accepts that were running are still counted across the cancel, so a
    // caller knows what its cancellation has to account for even though no
    // handler ever reported and the close never waited for one.
    const running = Shutdown.init(0, 2).step(.close_requested);
    try t.expectEqual(Shutdown.Action.cancel_accepts, running.action);
    try t.expectEqual(@as(usize, 2), running.shutdown.accepts);
    try t.expectEqual(@as(usize, 1), running.shutdown.step(.accept_finished).shutdown.accepts);
    try t.expectEqual(@as(usize, 0), running.shutdown.step(.accepts_cancelled).shutdown.accepts);
}

test "an accept finishing counts down and never advances the shutdown" {
    var shutdown = Shutdown.init(1, 2);

    // An accept can finish at any time, including before the shutdown is asked
    // for, and it never moves the machine: upstream's loop takes the finished
    // task from the join set and goes back to its `select!`.
    var step = shutdown.step(.accept_finished);
    try t.expectEqual(Shutdown.Action.none, step.action);
    try t.expectEqual(Shutdown.Phase.serving, step.shutdown.phase);
    try t.expectEqual(@as(usize, 1), step.shutdown.accepts);
    shutdown = step.shutdown;

    step = shutdown.step(.accept_finished);
    try t.expectEqual(@as(usize, 0), step.shutdown.accepts);
    try t.expectEqual(Shutdown.Phase.serving, step.shutdown.phase);
    shutdown = step.shutdown;

    // And after the cancel, including reports past zero: a count that wrapped
    // would read as an enormous number of accepts still running.
    shutdown = shutdown.step(.close_requested).shutdown;
    shutdown = shutdown.step(.handler_finished).shutdown;
    try t.expectEqual(Shutdown.Phase.cancelling_accepts, shutdown.phase);
    for (0..3) |_| {
        const late = shutdown.step(.accept_finished);
        try t.expectEqual(@as(usize, 0), late.shutdown.accepts);
        try t.expectEqual(Shutdown.Phase.cancelling_accepts, late.shutdown.phase);
        shutdown = late.shutdown;
    }
}

test "a lease given up with the endpoint open is reported" {
    // Every phase but the last one is an endpoint nobody closed, and each is
    // reported in the phase it was dropped in, because "you forgot to close"
    // and "you closed in the wrong order" are different bugs.
    const phases = [_]Shutdown.Phase{
        .serving,
        .draining_handlers,
        .cancelling_accepts,
        .closing_endpoint,
    };
    var shutdown = Shutdown.init(1, 1);
    for (phases[0 .. phases.len - 1], phases[1..]) |phase, next_phase| {
        var lease = Lease.acquire(&shutdown);
        try t.expectEqual(Release{ .abandoned = phase }, lease.deinit());
        // On to the next phase by driving the machine, so these are the phases a
        // caller can actually be holding.
        shutdown = switch (next_phase) {
            .draining_handlers => shutdown.step(.close_requested).shutdown,
            .cancelling_accepts => shutdown.step(.close_requested).shutdown
                .step(.handler_finished).shutdown,
            .closing_endpoint => shutdown.step(.close_requested).shutdown
                .step(.handler_finished).shutdown.step(.accepts_cancelled).shutdown,
            // `next_phase` is `phases[1..]`, which holds neither of these.
            .serving, .closed => unreachable,
        };
        try t.expectEqual(next_phase, shutdown.phase);
    }
}

test "a lease given up after the close reports the close, once" {
    var shutdown = Shutdown.init(1, 1);
    var lease = Lease.acquire(&shutdown);

    // The whole shutdown, driven the way the caller has to drive it.
    var step = shutdown.step(.close_requested);
    try t.expectEqual(Shutdown.Action{ .shutdown_handlers = 1 }, step.action);
    step = step.shutdown.step(.handler_finished);
    try t.expectEqual(Shutdown.Action.cancel_accepts, step.action);
    step = step.shutdown.step(.accepts_cancelled);
    try t.expectEqual(Shutdown.Action.close_endpoint, step.action);
    step = step.shutdown.step(.endpoint_closed);
    try t.expectEqual(Shutdown.Phase.closed, step.shutdown.phase);
    shutdown = step.shutdown;

    try t.expectEqual(Release.closed, lease.deinit());
    // The mark is set before the report, so a second exit finds nothing to do
    // and a copy deinited after the original reports the same thing once.
    try t.expectEqual(Release.already_gone, lease.deinit());
    var copy = lease;
    try t.expectEqual(Release.already_gone, copy.deinit());
    // And the copy could not have reported anything else even if it tried: the
    // answer comes out of the shutdown, not out of an argument.
    try t.expectEqual(Shutdown.Phase.closed, shutdown.phase);
}
