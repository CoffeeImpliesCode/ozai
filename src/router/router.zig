//! The router's protocol set: the ALPN table, the handler vtable it dispatches
//! through, and the value types a connection attempt is carried in.
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
//!
//! **What this file owns, and what its siblings own.** Everything a caller
//! needs in order to *hold* a connection attempt is a type here: the bounded
//! configured protocol set (`Builder`, `Router`, `Entry`, and the
//! `Claim`/`Route`/`Refusal` a dispatch answers with), the handler vtable, and
//! the handshake and dispatch values (`Verdict`, `Failure`, `Drop`,
//! `ConnState`, `ConnEvent`, `Outcome`, `DispatchStep`). The three machines
//! that move those values are sibling files, each owning one and importing this
//! one — never the other way round:
//!
//! - `dispatch.zig` — one connection attempt, `dispatchStep`.
//! - `shutdown.zig` — the whole endpoint's close, `Shutdown` and its `Lease`.
//! - `lifetime.zig` — one configured protocol's own close, `Lifetime`, `Lanes`.
//!
//! **Why the split rather than three sections of one file.** None of the
//! machines needs a runtime and each of them is a decision a caller has to be
//! able to check without one, but they have three different owners, three
//! different callers and three different reasons to change. Keeping them here
//! meant a caller that only registers handlers and reads a `Claim` — the common
//! case, and what `Node`'s table build is — carried a connection machine, an
//! endpoint close and a per-protocol close with it, and every reader of a
//! registration had to page past all three to reach it.
//!
//! **Nothing here performs anything that would need a socket.** A handler call
//! is *named* (`DispatchAction.on_accepting`, `DispatchAction.accept`) and a
//! close step is *named* (`Shutdown.Action` in `shutdown.zig`, `Lifetime.Action`
//! in `lifetime.zig`); the layer that performs them owns the runtime —
//! `src/node/node_runtime.zig` for a node, and `src/endpoint/endpoint.zig`
//! for the accept loop that hands them over. That split is the reason those
//! files can be a value and the other one cannot.

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
    /// `shutdown` — which is why `shutdown.Shutdown` counts running accepts
    /// rather than remembering that some exist. Here the caller runs the body
    /// inside its own pass, so "long-lived" means "for as many passes as it
    /// takes": a handler that wants a connection past this call has to be
    /// re-entered by the loop driving it, not left running.
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
/// (`negotiatingStep` in `dispatch.zig`). Registering the handler that
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
    /// preference order, and it is the server that decides: the offer list goes
    /// to the endpoint in this order, and the negotiated protocol is the first
    /// ALPN in *this* list that the peer also offers, not the first one the peer
    /// happened to name (RFC 7301 §3.2 — the server chooses from the
    /// intersection, a client preference does not reorder it; `iroh`'s
    /// `set_alpns` hands this order over unchanged,
    /// `iroh/src/endpoint.rs:973-977`, `protocol.rs:489-492`). So the preferred
    /// protocol goes first.
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

/// The configured protocol set: the bounded list of supported ALPNs and the
/// handler each of them dispatches to.
///
/// `docs/ARCHITECTURE.md`: the router owns ALPN dispatch and nothing else. It
/// turns a negotiated ALPN into a handler call and knows nothing about what any
/// protocol does.
///
/// **How many protocols an endpoint serves is the caller's choice, bounded by
/// the slice it sized `Builder` with.** There is no single protocol anywhere in
/// this file: one is a table of length one, which is what `Node` still builds
/// (`max_alpns` in `src/node/node_protocol.zig`), and several is the same
/// table read the same way.
pub const Router = struct {
    /// The registrations, in registration order. Only `Builder.build` makes one,
    /// and the entries are the caller's.
    entries: []const Entry,

    /// How many protocols this endpoint is configured with: the bounded length
    /// of the caller's slice. Upstream's bound is the heap (`Vec<Entry>`,
    /// `protocol.rs:379`); here it is the array the caller sized `Builder`
    /// with, so it is a property of the storage rather than of a check.
    ///
    /// **Zero is a real answer, not an empty one.** An endpoint configured with
    /// no protocol serves nothing and refuses every ALPN, and both halves of
    /// that fall out of this number rather than out of a special case.
    pub fn configured(self: *const Router) usize {
        return self.entries.len;
    }

    /// How many `shutdown` calls a close owes: the number of *distinct* ALPNs
    /// in the table.
    ///
    /// Upstream awaits one future per *map value* (`protocol.rs:404-407`), and a
    /// map holds one value per ALPN, so a handler registered twice is shut down
    /// once, as the newer one, because the older one is unreachable
    /// (`protocol.rs:385-394`, which `Builder.push` reproduces). A count of
    /// registrations would wait for a `handler_finished` that never comes.
    ///
    /// It is counted here and not by the caller because it is a fact about the
    /// table, and two answers for one count is how a close waits for a report
    /// that is never sent.
    pub fn protocolCount(self: *const Router) usize {
        var distinct: usize = 0;
        for (self.entries, 0..) |entry, index| {
            var first = true;
            for (self.entries[0..index]) |earlier| {
                if (std.mem.eql(u8, earlier.alpn, entry.alpn)) {
                    first = false;
                    break;
                }
            }
            if (first) distinct += 1;
        }
        return distinct;
    }

    /// The ALPNs to offer a peer, in registration order, into storage the
    /// caller sizes. Upstream `ProtocolMap::alpns` (`protocol.rs:397-399`) into
    /// `spawn`'s `set_alpns` (`protocol.rs:515-522`).
    ///
    /// A repeated ALPN comes out twice, because that is what upstream offers,
    /// and an under-sized `out` is a count short of the list rather than an
    /// index panic: this is the function that fills a transport's own bounded
    /// array, and the caller is the one that sized it.
    ///
    /// **This list and `dispatch` read the same bounded set, and that is what
    /// makes a wrong-protocol refusal clean.** A peer that asks for an ALPN
    /// this list does not name never reaches a connection at all: the handshake
    /// fails on the empty intersection (TLS `no_application_protocol`) and the
    /// router is never asked. `Route.refused` is what is left for the case the
    /// two halves were configured apart, and it is a refusal the caller reads
    /// rather than a connection it has to diagnose.
    ///
    /// This is the list every lane still serving gets into: `Lanes.offers` in
    /// `lifetime.zig` is this function with retirement applied.
    pub fn offers(self: *const Router, out: [][]const u8) usize {
        var count: usize = 0;
        while (count < out.len and count < self.entries.len) : (count += 1) {
            out[count] = self.entries[count].alpn;
        }
        return count;
    }

    /// The protocol an ALPN dispatches to, or the refusal it earns.
    ///
    /// The newest registration wins, which is the entry upstream's
    /// `HashMap::insert` leaves behind (`protocol.rs:391-394`), and the claim
    /// carries that entry's index so the caller can address this one protocol's
    /// lifetime lane and its tasks by number rather than comparing ALPN bytes
    /// a second time.
    pub fn dispatch(self: *const Router, alpn: []const u8) Route {
        var index = self.entries.len;
        while (index > 0) {
            index -= 1;
            if (!std.mem.eql(u8, self.entries[index].alpn, alpn)) continue;
            return .{ .protocol = .{ .index = index, .entry = &self.entries[index] } };
        }
        return .{ .refused = .{ .alpn = alpn, .configured = self.entries.len } };
    }
};

/// The protocol one ALPN was dispatched to, and where it lives.
///
/// The index is the whole point of carrying the entry: it is the address of
/// that protocol's `Lifetime` lane in `Lanes` (`lifetime.zig`) and of the
/// `protocol` field on every accept task routed to it, so routing a connection
/// and retiring its protocol are both a number rather than a second comparison
/// of ALPN bytes.
pub const Claim = struct {
    /// Which registration claimed it — the index into `Router.entries`.
    index: usize,
    /// The registration itself, borrowed for as long as the table is. Its
    /// handler is the one the caller calls and the one `shutdown` reaches.
    entry: *const Entry,
};

/// What a dispatch to the table produced: a protocol, or a refusal.
///
/// Exhaustive on purpose, like `DispatchAction.peerOutcome`: a new arm that has
/// not decided what happens to an ALPN nobody configured does not compile.
pub const Route = union(enum) {
    /// A configured protocol claims this ALPN.
    protocol: Claim,
    /// No configured protocol claims it, and this is why.
    refused: Refusal,
};

/// Why an ALPN reached no protocol.
///
/// `Drop.refused_protocol` carries the same value, so the reason a connection
/// went away and the reason a table declined to claim it are one type rather
/// than two spellings of one fact.
pub const Refusal = struct {
    /// The ALPN that was asked for, borrowed from the peer and never stored.
    alpn: []const u8,
    /// How many protocols *are* configured, so a log line says whether the
    /// peer named something this endpoint does not serve at all or something
    /// it does not serve *here*. **Zero is a real answer**: an endpoint
    /// configured with no protocol refuses every ALPN, and that is the
    /// endpoint `Loop.init` documents, not a failure.
    configured: usize,
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
    /// The peer negotiated an ALPN no configured protocol claims, and the
    /// refusal says which one and how many are configured. Upstream warns and
    /// returns (`protocol.rs:653-656`), which is the same ending — see
    /// `negotiatingStep` in `dispatch.zig`.
    refused_protocol: Refusal,
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
/// other arm is terminal. `dispatch.zig` is what moves between them.
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
///
/// The machine that produces one of these is `dispatchStep` in `dispatch.zig`.
pub const DispatchStep = struct {
    state: ConnState,
    action: DispatchAction,
};

const t = std.testing;

/// A handler that records what the router called it for. Every test here owns
/// one, so the context pointer is the observable "which handler won".
const Recorder = struct {
    on_accepting_calls: usize = 0,
    accept_calls: usize = 0,
    shutdown_calls: usize = 0,

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
};

/// Which handler a dispatch found. `*anyopaque` does not compare with a typed
/// pointer, so a test names the handler it expects through this.
fn isContext(handler: ProtocolHandler, context: *Recorder) bool {
    return handler.ptr == @as(*anyopaque, context);
}

/// The claim a dispatch found, or null when nothing claimed it. A test names
/// the handler it expects through the claim rather than through a bare entry,
/// so the index is one assertion away.
fn claim(router: *const Router, alpn: []const u8) ?Claim {
    return switch (router.dispatch(alpn)) {
        .protocol => |found| found,
        .refused => null,
    };
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
    try t.expectEqual(@as(usize, 3), router.configured());
    try t.expectEqual(@as(usize, 3), router.protocolCount());
    try t.expectEqual(@as(usize, 3), router.offers(&list));
    try t.expectEqualStrings("/echo", list[0]);
    try t.expectEqualStrings("/blob", list[1]);
    try t.expectEqualStrings("/qad-probe", list[2]);

    // And each one dispatches to the handler it was registered with, at the
    // index the offer order gave it: a claim's index is what a lifetime lane
    // and an accept task are addressed by, so it is the registration order and
    // not an accident of where the entry sits.
    try t.expect(isContext(claim(&router, "/echo").?.entry.handler, &first));
    try t.expectEqual(@as(usize, 0), claim(&router, "/echo").?.index);
    try t.expect(isContext(claim(&router, "/blob").?.entry.handler, &second));
    try t.expectEqual(@as(usize, 1), claim(&router, "/blob").?.index);
    try t.expect(isContext(claim(&router, "/qad-probe").?.entry.handler, &third));
    try t.expectEqual(@as(usize, 2), claim(&router, "/qad-probe").?.index);
    // And an ALPN nobody configured is refused, and the refusal says what *is*
    // configured rather than only what is not.
    try t.expectEqual(@as(?Claim, null), claim(&router, "/nope"));
    try t.expectEqual(
        Refusal{ .alpn = "/nope", .configured = 3 },
        router.dispatch("/nope").refused,
    );

    // An under-sized offer buffer is a short count and not an index panic: the
    // caller sizes the transport's own array, and one entry into a three-entry
    // list is a caller that wanted a shorter list.
    var narrow: [1][]const u8 = undefined;
    try t.expectEqual(@as(usize, 1), router.offers(&narrow));
    try t.expectEqualStrings("/echo", narrow[0]);
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
    try t.expectEqual(@as(usize, 3), router.offers(&list));
    try t.expectEqualStrings("/echo", list[0]);
    try t.expectEqualStrings("/echo", list[1]);
    try t.expectEqualStrings("/blob", list[2]);

    try t.expect(isContext(claim(&router, "/echo").?.entry.handler, &newer));
    try t.expect(isContext(claim(&router, "/blob").?.entry.handler, &older));
    // The claim names the *newest* registration, so the lane it indexes is the
    // one the newer handler's lifetime lives in — which is why `Lanes` has one
    // lane per registration rather than one per distinct ALPN.
    try t.expectEqual(@as(usize, 1), claim(&router, "/echo").?.index);
    // The displaced entry is still there, holding the ALPN, because upstream
    // pushes onto the offer list unconditionally.
    try t.expect(isContext(router.entries[0].handler, &older));
    // And the close owes one `shutdown` for the ALPN, not one per registration.
    try t.expectEqual(@as(usize, 2), router.protocolCount());
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
    try t.expectEqual(@as(usize, 0), refused.offers(&list));

    // The one way in takes no ALPN, so there is no string to pass wrongly.
    try t.expectEqual(Registered.fresh, try builder.acceptInternal(recorder.handler()));
    const router = builder.build();
    try t.expectEqual(@as(usize, 1), router.offers(&list));
    try t.expectEqualStrings(qad_alpn, list[0]);
    try t.expect(isContext(claim(&router, qad_alpn).?.entry.handler, &recorder));
}

test "a full table refuses a registration and changes nothing" {
    var recorder: Recorder = .{};
    var entries: [1]Entry = undefined;
    var builder = Builder.init(&entries);

    try t.expectEqual(Registered.fresh, try builder.accept("/echo", recorder.handler()));
    try t.expectError(error.no_space, builder.accept("/blob", recorder.handler()));

    var list: [1][]const u8 = undefined;
    const router = builder.build();
    try t.expectEqual(@as(usize, 1), router.offers(&list));
    try t.expectEqualStrings("/echo", list[0]);
    try t.expectEqual(@as(?Claim, null), claim(&router, "/blob"));
}

test "a retry is address validation on a direct path and a cost on a relay" {
    // Same verb, two meanings, and the path is what tells them apart. One type
    // with two values, so a verdict that lost its meaning on the way through
    // the router stops comparing equal to what the path says it should be.
    try t.expectEqual(Retry.source_validation, retryMeaning(.any_path));
    try t.expectEqual(Retry.source_validation, retryMeaning(.custom));
    try t.expectEqual(Retry.cost_imposition, retryMeaning(.relay));
}
