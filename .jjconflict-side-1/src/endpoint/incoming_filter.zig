//! The incoming filter as a predicate that runs: the vtable an application
//! fills in, the attempt it is asked about, and the two things a filter cannot
//! know by itself — what a `retry` is worth on the path the attempt arrived on,
//! and whether that path's flow has already answered one.
//!
//! Captured 2026-09-30 from n0-computer/iroh commit
//! 187f59e80afdae6bd9866002b33d3365c00b06d8: `IncomingFilterOutcome` at
//! `iroh/src/protocol.rs:170-211`; `IncomingFilter` at `:214-216`;
//! `RouterBuilder::incoming_filter` at `:478-481`; the filter block in the
//! accept loop at `:573-596`; `Incoming` and its four answers at
//! `iroh/src/endpoint/connection.rs:133-229`; `RetryError::into_incoming` at
//! `connection.rs:248-262`. Each is named where it is reproduced.
//!
//! Upstream's filter is a boxed closure over `&Incoming`, held by the router
//! builder and called once per connection attempt before the handshake does any
//! work. It is a vtable here for the reason `ProtocolHandler` is one: no heap,
//! no `anyerror` in the type, and one idiom for "the application supplies this
//! call" rather than two. A filter answers `Answer` — four values, with a
//! `retry` that means only "ask again", which is upstream's own shape — and
//! `decide` turns an answer into the `router.Verdict` the router dispatches on,
//! attaching what the path says a retry is worth. Upstream gets both of those
//! facts from `noq` for free; the closure never sees either of them.

const std = @import("std");
const router = @import("../router/router.zig");
const base_addr = @import("../base/addr.zig");
const ula = @import("../base/ula.zig");

const Verdict = router.Verdict;
const Retry = router.Retry;

/// A filter for incoming attempts, run before the handshake does any work.
///
/// Upstream `IncomingFilter` (`protocol.rs:214-216`) is
/// `Arc<dyn Fn(&Incoming) -> IncomingFilterOutcome + Send + Sync>`, held by the
/// router builder and called once per attempt. A vtable is the same thing with
/// no allocation and no `anyerror` in its type, and `ProtocolHandler`
/// (`router.zig:42-84`) is already one, so a project that made that a vtable
/// does not invent a second idiom for the other.
///
/// The filter is *not* optional here; the absence of one is
/// `?IncomingFilter = null`, which is upstream's `Option<IncomingFilter>` on
/// the builder (`protocol.rs:106-111`, `:478-481`). `ask` then runs the same
/// default the `if let Some(filter)` upstream runs: no filter, every attempt
/// accepted.
///
/// **The call is synchronous and happens on the thread stepping the loop** —
/// the endpoint's own pass, or a caller driving `Loop.step` itself. Upstream's
/// closure is awaited inside the loop body (`protocol.rs:574`) and this is
/// that await made into an `Action`, so a filter that blocks blocks the pass
/// and there is no thread here for it to move to.
///
/// **`incoming` is borrowed for the call and is not to be stored.** The accept
/// loop holds one attempt while the filter runs and clears the slot when the
/// answer arrives, so an attempt is acted on exactly once; a filter that kept
/// the value would be keeping a copy of a struct that names a connection the
/// core may already have finished with.
///
/// **`ptr` must stay valid from `Loop.init` until the loop is dropped**, for
/// the same reason a handler's context must outlive its registration: a filter
/// torn down first leaves a dangling context and nothing here can see it
/// coming.
///
/// **A filter may not step the loop from inside its own call.** It is holding
/// the one attempt the loop is waiting on, so re-entering is what turns one
/// verdict into two.
pub const IncomingFilter = struct {
    /// The filter's own state, handed to every call unchanged and never
    /// dereferenced here. The same field `ProtocolHandler.ptr` is, for the same
    /// reason: upstream's `&self` is a real borrow and this is the thinnest
    /// honest equivalent. It must stay valid and unchanged from `Loop.init`
    /// until the loop is dropped — see this struct's note.
    ptr: *anyopaque,
    /// The call. Upstream's closure, and its four answers are `Answer`.
    ///
    /// Called at most once per attempt, on the thread stepping the loop, with
    /// the attempt borrowed for the call and not to be stored. The answer is
    /// the filter's own: nothing is done to it before the loop sees it except
    /// `decide`, which attaches what the path says a `retry` is worth and
    /// refuses one this flow cannot be given.
    filter: *const fn (ptr: *anyopaque, incoming: Incoming) Answer,
};

/// What a filter answers, in upstream's own shape: four values, and a `retry`
/// that means only "ask the peer to come back".
///
/// Upstream's `IncomingFilterOutcome` (`protocol.rs:170-211`) is an enum, so
/// its `Retry` carries nothing and the two meanings live in the doc comment
/// above it. `router.Verdict` is the union those two meanings turned into, and
/// it is what the router dispatches on. So the filter answers this and
/// `decide` turns the answer into a verdict: a filter that returned a
/// `router.Verdict` would have to name a meaning for a path it cannot see, and
/// one that guessed would be silently corrected here.
///
/// `accept`, `retry`, `reject` and `ignore` are upstream's `Accept`, `Retry`,
/// `Reject` and `Ignore` under the names the router already uses. `refuse` is
/// not one of them: it is what `incoming.refuse()` does about a `Reject`, and
/// the router already calls that action `refuse`.
pub const Answer = enum {
    /// Carry on with the handshake. Upstream `Accept`.
    accept,
    /// Answer with a retry token. Upstream `Retry`, and which of the two
    /// meanings that is depends on the path the attempt arrived on.
    retry,
    /// Refuse, and say so. Upstream `Reject`: the peer is told at once.
    reject,
    /// Send nothing and say nothing. Upstream `Ignore`, and the one verdict
    /// upstream does not even log.
    ignore,
};

/// The answer the filter gives for one attempt.
///
/// Upstream calls this closure itself, in the loop body (`protocol.rs:574`).
/// It is called by whoever is driving the loop here — `endpoint.zig`'s
/// `Action.offer` is the step that says to — because a function that calls
/// application code cannot be stepped twice and get the same answer, and
/// `docs/ARCHITECTURE.md` asks for that of every machine. `router.dispatchStep`
/// makes the same move: `DispatchAction.on_accepting` names the call rather
/// than making it.
///
/// The answer is the filter's own; nothing has been done to it yet.
///
/// A null filter is upstream's `if let Some(filter)` (`protocol.rs:573-596`):
/// no filter, every attempt accepted, and no call made at all. The thread is
/// the caller's own and the attempt is borrowed, so a filter is a predicate and
/// not a worker — see `IncomingFilter`'s note for the rest.
pub fn ask(filter: ?IncomingFilter, incoming: Incoming) Answer {
    const present = filter orelse return .accept;
    return present.filter(present.ptr, incoming);
}

/// The endpoint's answer to a filter's answer: the meaning the path gives a
/// `retry`, and the refusal a flow that has already proved itself cannot avoid.
/// Everything the loop does to an answer, it does here.
///
/// Upstream's filter returns a bare `Retry` (`protocol.rs:177`) and leaves the
/// two meanings in the doc comment above it (`:178-196`), because only the
/// caller of `Incoming::retry` can see whether the path is direct. Here the
/// attempt is in hand and the path is a field of it, so the meaning is attached
/// here rather than left for a reader to remember.
///
/// The three other answers pass through the path untouched, including `reject`:
/// a filter that refuses an attempt is the endpoint's business and is already
/// the answer.
pub fn decide(answer: Answer, incoming: Incoming) Verdict {
    return admit(switch (answer) {
        .accept => Verdict.accept,
        .retry => .{ .retry = retryMeaning(incoming.classification) },
        .reject => .reject,
        .ignore => .ignore,
    }, incoming);
}

/// What a `retry` verdict is worth on the path an attempt arrived on.
///
/// `router.retryMeaning` takes a `ula.Path`, which is the mapped-address half
/// of a classification. A datagram that arrived at a real socket address is a
/// direct path and has no synthetic address of its own, so it is asked about as
/// the peer's own — which is what `any_path` is (`base/ula.zig:55-57`) and what
/// `retryMeaning` already treats as direct (`router.zig:309-317`).
fn retryMeaning(classification: ula.Classification) Retry {
    return router.retryMeaning(switch (classification) {
        .relay => .relay,
        .custom => .custom,
        .any_path, .ip => .any_path,
    });
}

/// What the endpoint knows about the address an attempt came from.
///
/// Upstream has one bit for this — `Incoming::remote_addr_validated`
/// (`connection.rs:219-223`) — and two facts behind it, and the difference
/// between them is the whole content of `IncomingFilterOutcome::Retry`
/// (`protocol.rs:178-196`). Reporting both as one bit is what lets a filter
/// that collapses the two look as though it works: it is right on a direct
/// path and it can never be right on a relay.
pub const Validation = union(enum) {
    /// Nothing is proved. The first attempt on a flow.
    unvalidated,
    /// The flow proved the address it came from, and it is this one.
    ///
    /// A direct path only. The token is bound to the address it was issued to
    /// (`vendor/quic/src/quic/packet.zig:825-830`), so a flow that comes back
    /// with one proved that this address can receive, which is what a
    /// spoofed initial cannot do.
    validated: base_addr.SocketAddr,
    /// The flow proved its own cooperation and nothing else.
    ///
    /// A relay only. The relay vouched for the packet origin before the
    /// endpoint saw the datagram (`protocol.rs:186-191`), so the same core
    /// bit here means the client sent the token and nothing more. Upstream
    /// reports `remote_addr_validated() == true` on this path too, in the same
    /// words: "that just means the client cooperated with the retry".
    cooperated,
};

/// What a core that says a flow's address is proved means on each path.
///
/// The core keeps one bit for this too — `NetworkPath.is_validated`, set when a
/// connection opens with a valid Retry token
/// (`vendor/quic/src/quic/connection.zig:825-829`) — and it is worth the same
/// two things. This is where the core's one bit becomes one of the two facts,
/// and it is the only place in the project that decides it.
///
/// An attempt the core proved nothing about is `.unvalidated`, which the caller
/// writes itself: there is nothing to decide in that direction.
///
/// One gap is worth naming here, because it is where this fact comes from.
/// `quic_bridge.Conn` exposes `id`, `peer`, `local`, `established`, `closed` and
/// `drain`, and nothing that reports the path's validated bit
/// (`transport/quic_bridge.zig:226-320`), so upstream's
/// `Incoming::remote_addr_validated()` has no ozai counterpart yet. Until it
/// does, this function is how a caller turns what the core told it into the
/// fact a filter reads, and a caller with nothing to report must write
/// `.unvalidated` — which is the conservative answer, because a token the
/// endpoint never saw being validated buys it nothing.
pub fn proved(
    classification: ula.Classification,
    remote: base_addr.SocketAddr,
) Validation {
    return switch (classification) {
        // The relay vouched for the origin already, so a token bought a round
        // trip and a client that obeyed it.
        .relay => .cooperated,
        .any_path, .custom, .ip => .{ .validated = remote },
    };
}

/// The attempt a filter is asked about. Upstream `Incoming`
/// (`connection.rs:133-141`).
///
/// Upstream's is a handle, and each of its four answers consumes it
/// (`connection.rs:148`, `:175`, `:185`, `:192`). Here it is a value, and the
/// guarantee is carried by the accept loop instead: the loop holds one attempt
/// while the filter is running and clears the slot when the answer arrives, so
/// an attempt is acted on once. `endpoint.zig`'s `Loop` is where that lives.
pub const Incoming = struct {
    /// The core's connection id: unique per bridge, never reused
    /// (`transport/quic_bridge.zig:230-233`), and the name a reaped accept
    /// task is reported under.
    id: u64,
    /// Where the datagram came from. Upstream `Incoming::remote_addr`
    /// (`connection.rs:204-210`).
    remote: base_addr.SocketAddr,
    /// The local address that received it. Upstream `Incoming::local_addr`
    /// (`connection.rs:197-202`).
    local: base_addr.SocketAddr,
    /// How it reached here, and so what a retry is worth on it.
    classification: ula.Classification,
    /// What is already proved about the address it came from: the fact
    /// upstream's `remote_addr_validated` reports, and the one a `retry` verdict
    /// on this flow cannot be granted on.
    validation: Validation,
};

/// The endpoint's answer to a filter's answer, before the router sees it.
///
/// Upstream's block is `if let Err(err) = incoming.retry() { err.into_incoming()
/// .refuse() }` (`protocol.rs:583-586`). QUIC allows one Retry per flow, so a
/// `Retry` verdict on a flow that has already proved its address cannot be
/// answered with a token; the attempt is **refused** instead, and that is the
/// one ending a filter can cause which the peer is told about.
/// `RetryError` exists to hand the attempt back for exactly that
/// (`connection.rs:248-262`).
///
/// So the rewrite happens here, at the layer that knows the flow's state, and
/// the router is handed a verdict it already understands. It is the one place a
/// filter's answer is not the answer.
pub fn admit(verdict: Verdict, incoming: Incoming) Verdict {
    return switch (verdict) {
        .retry => switch (incoming.validation) {
            .unvalidated => verdict,
            // Both proved states are refused, and for upstream's one reason:
            // the flow is already proved, and a second Retry is not a thing
            // QUIC has. Which of the two it is — an address, or a client that
            // cooperated — is the difference the two meanings make, and it is
            // the filter's to read on the *next* attempt. Refusing one and
            // retrying the other would be a policy invented here.
            .validated, .cooperated => .reject,
        },
        .accept, .reject, .ignore => verdict,
    };
}

const t = std.testing;

/// A filter that answers a fixed way and remembers what it was asked.
const Recorder = struct {
    answer: Answer,
    calls: usize = 0,
    asked: ?Incoming = null,

    fn decide(ctx: *anyopaque, incoming: Incoming) Answer {
        const self: *Recorder = @ptrCast(@alignCast(ctx));
        self.calls += 1;
        self.asked = incoming;
        return self.answer;
    }

    fn filterer(self: *Recorder) IncomingFilter {
        return .{ .ptr = self, .filter = Recorder.decide };
    }
};

/// A handler that counts the calls the router makes on it, so a table can be
/// built without a protocol behind it. `endpoint.zig` has its own, because a
/// handler that fails on demand is the only one worth having over there.
const Handler = struct {
    accept_calls: usize = 0,

    fn accept(ctx: *anyopaque, connection: router.Connection) router.AcceptError!void {
        _ = connection;
        const self: *Handler = @ptrCast(@alignCast(ctx));
        self.accept_calls += 1;
    }

    fn handler(self: *Handler) router.ProtocolHandler {
        return .{
            .ptr = self,
            .on_accepting = null,
            .accept = Handler.accept,
            .shutdown = null,
        };
    }
};

/// A table with one handler for `alpn`, and the handler behind it.
fn oneHandler(
    alpn: []const u8,
    entries: []router.Entry,
    handler: *Handler,
) !router.Router {
    var builder = router.Builder.init(entries);
    _ = try builder.accept(alpn, handler.handler());
    return builder.build();
}

/// A direct-path attempt: a real socket address, nothing proved.
fn direct(id: u64) Incoming {
    const remote: base_addr.SocketAddr = .{
        .ip = .{ .v4 = .{ 192, 0, 2, @intCast(id) } },
        .port = 443,
    };
    return .{
        .id = id,
        .remote = remote,
        .local = ula.socketAddrFor(.any_path, host(id)),
        .classification = ula.classify(remote),
        .validation = .unvalidated,
    };
}

/// The same attempt one hop away, through a relay.
fn relayed(id: u64) Incoming {
    const remote = ula.socketAddrFor(.relay, host(id));
    return .{
        .id = id,
        .remote = remote,
        .local = ula.socketAddrFor(.any_path, host(id)),
        .classification = ula.classify(remote),
        .validation = .unvalidated,
    };
}

/// The eight host bits a test attempt's address is built from, so the address
/// carries the attempt's id and two attempts are two addresses.
fn host(id: u64) ula.HostBits {
    return .{ 0, 0, 0, 0, 0, 0, 0, @intCast(id) };
}

/// Run a filter over one attempt the way a caller does, and turn the answer
/// into a decision: the two halves of what the endpoint layer does to a
/// verdict, in the order it does them.
fn answered(present: ?IncomingFilter, incoming: Incoming) Verdict {
    return decide(ask(present, incoming), incoming);
}

test "the filter vtable is a context pointer and one call" {
    // The plan names one call, and `ProtocolHandler` names three. A filter that
    // grew a second call would be a trait wearing a vtable's name, which is
    // what `AddressLookup` refuses in `discovery/resolve.zig`.
    const fields = @typeInfo(IncomingFilter).@"struct".fields;
    try t.expectEqual(@as(usize, 2), fields.len);
    const names = [_][]const u8{ "ptr", "filter" };
    inline for (fields, names) |field, name| {
        try t.expectEqualStrings(name, field.name);
    }
}

test "every callback gets the filter's own context and the whole attempt" {
    var recorder: Recorder = .{ .answer = .accept };
    const filter = recorder.filterer();
    const incoming = direct(1);

    try t.expectEqual(Answer.accept, ask(filter, incoming));

    // The context is not copied or replaced, and the attempt arrives whole: a
    // filter that reads the path and the validation is a filter that can tell
    // the two retry meanings apart.
    try t.expectEqual(@as(usize, 1), recorder.calls);
    try t.expectEqual(incoming, recorder.asked.?);
    try t.expect(filter.ptr == @as(*anyopaque, &recorder));
}

test "no filter is upstream's default: every attempt is accepted" {
    // `if let Some(filter) = &incoming_filter` (`protocol.rs:573`) — an absent
    // filter falls through to the spawn, so the answer is the accept one and the
    // endpoint never refuses a peer on its own.
    try t.expectEqual(Answer.accept, ask(null, direct(1)));
    try t.expectEqual(Answer.accept, ask(null, relayed(1)));
    try t.expectEqual(Verdict.accept, answered(null, relayed(1)));
}

test "the filter's four answers, and only a refusal reaches the peer" {
    // Upstream's four, by the names the router already uses
    // (`protocol.rs:172-210`). `refuse` is not an answer: it is what
    // `incoming.refuse()` does about a `Reject`.
    const answers = [_]Answer{ .accept, .retry, .reject, .ignore };
    try t.expectEqual(@as(usize, 4), answers.len);
    for (answers) |answer| {
        var recorder: Recorder = .{ .answer = answer };
        const decided = answered(recorder.filterer(), direct(1));
        // Three of the four reach the router as themselves, and a `retry`
        // reaches it carrying the meaning the path gives it.
        const want: Verdict = switch (answer) {
            .accept => .accept,
            .retry => .{ .retry = .source_validation },
            .reject => .reject,
            .ignore => .ignore,
        };
        try t.expectEqual(want, decided);
        try t.expectEqual(answer, recorder.answer);
        try t.expectEqual(@as(usize, 1), recorder.calls);

        // And the router's own machine gives each of them a different next
        // step, which is what the loop acts on.
        var handler: Handler = .{};
        var entries: [1]router.Entry = undefined;
        const table = try oneHandler("/echo", &entries, &handler);
        const step = router.dispatchStep(&table, .incoming, .{ .filtered = decided });
        switch (answer) {
            .accept => try t.expectEqual(router.DispatchAction.negotiate_alpn, step.action),
            .retry => try t.expectEqual(
                router.DispatchAction{ .send_retry = .source_validation },
                step.action,
            ),
            .reject => try t.expectEqual(router.DispatchAction.refuse, step.action),
            .ignore => try t.expectEqual(router.DispatchAction.ignore, step.action),
        }
        // The one answer a peer learns about is a refusal, and the retry token
        // is not an ending.
        try t.expectEqual(
            if (answer == .reject) router.PeerOutcome.refused else router.PeerOutcome.nothing,
            step.action.peerOutcome(),
        );
        // Nothing was dispatched: an answer is not a connection.
        try t.expectEqual(@as(usize, 0), handler.accept_calls);
    }
}

test "a retry is source validation on a direct path and a cost on a relay" {
    // Same verb, one function, and the path is what tells them apart. The
    // filter's answer is bare in both cases; only the meaning differs, and it
    // differs in the action the endpoint owes the peer.
    var through: Recorder = .{ .answer = .retry };
    try t.expectEqual(Retry.source_validation, answered(through.filterer(), direct(1)).retry);
    try t.expectEqual(Retry.cost_imposition, answered(through.filterer(), relayed(1)).retry);

    // And a relayed flow's second attempt is a different *state* from a direct
    // flow's, which is the half of this that a filter reads.
    const peer: base_addr.SocketAddr = .{
        .ip = .{ .v4 = .{ 203, 0, 113, 9 } },
        .port = 443,
    };
    try t.expectEqual(Validation{ .validated = peer }, proved(.{ .ip = peer }, peer));
    try t.expectEqual(
        Validation{ .validated = peer },
        proved(ula.classify(peer), peer),
    );
    try t.expectEqual(
        Validation.cooperated,
        proved(ula.classify(ula.socketAddrFor(.relay, host(9))), peer),
    );
}

test "a filter cannot retry a flow that has already proved itself" {
    // Upstream's `incoming.retry()` errors when `remote_address_validated()`
    // and the loop refuses the attempt instead (`protocol.rs:583-586`), so a
    // filter that always says retry ends in a refusal rather than a loop. Both
    // proved states are refused, and each is refused for the same reason — the
    // flow is proved — even though only one of them is an address.
    const direct_in = direct(1);
    try t.expectEqual(Verdict.accept, admit(.accept, direct_in));
    try t.expectEqual(Verdict.reject, admit(.reject, direct_in));
    try t.expectEqual(Verdict.ignore, admit(.ignore, direct_in));
    try t.expectEqual(
        Verdict{ .retry = .source_validation },
        admit(.{ .retry = .source_validation }, direct_in),
    );

    var proved_direct = direct(2);
    proved_direct.validation = .{ .validated = proved_direct.remote };
    try t.expectEqual(
        Verdict.reject,
        admit(.{ .retry = .source_validation }, proved_direct),
    );

    var proved_relay = relayed(2);
    proved_relay.validation = .cooperated;
    try t.expectEqual(
        Verdict.reject,
        admit(.{ .retry = .cost_imposition }, proved_relay),
    );

    // Nothing else is rewritten: a proved flow that is refused stays refused,
    // and one that is ignored stays ignored, because the rule is about a token
    // and not about the flow.
    try t.expectEqual(Verdict.accept, admit(.accept, proved_direct));
    try t.expectEqual(Verdict.ignore, admit(.ignore, proved_relay));
}
