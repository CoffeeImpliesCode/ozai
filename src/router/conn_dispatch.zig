//! One connection attempt, as a machine: the states it can be in, the two
//! things that can happen to it, and the one step each pairing owes.
//!
//! Split out of `router/router.zig`, which is now the facade over this and two
//! other named modules. The boundary is the connection, and it is a pure
//! function of the caller's table: `router` is a parameter and not state, so
//! the same table, state and event always give the same step. That is what lets
//! a test drive a whole connection with no socket and no scheduler, and it is
//! why nothing here closes, keeps or dereferences a handle.

const ula = @import("../base/ula.zig");
const alpn_table = @import("alpn_table.zig");

const AcceptError = alpn_table.AcceptError;
const Connection = alpn_table.Connection;
const ProtocolHandler = alpn_table.ProtocolHandler;
const Router = alpn_table.Router;

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
