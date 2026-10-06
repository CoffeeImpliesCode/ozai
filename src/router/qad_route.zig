//! The route that would make the reserved QAD ALPN reachable, and nothing else.
//!
//! `router/alpn_table.zig` reserves `/iroh-qad/0` for iroh's own address
//! discovery and refuses it through the public registration path. This file is
//! the one place allowed past that refusal: `registerLast` is the only caller
//! of `Builder.acceptInternal` under `src/`, and it is what turns the
//! reservation into a served route — a peer that negotiates `/iroh-qad/0`
//! reaches a handler instead of being dropped by `negotiatingStep`.
//!
//! **Nothing calls it, on purpose.** Read "Nothing calls this, and that is the
//! decision" below before concluding the tree forgot a line; it did not.
//!
//! # The reservation and the refusal both survive this file
//!
//! Nothing here weakens either half, and nothing here could:
//!
//! - **The string lives in one place.** This module never writes the ALPN
//!   out. It reaches it through `Builder.acceptInternal`, which takes no ALPN
//!   argument at all, so there is no second spelling of `/iroh-qad/0` in the
//!   tree to pass to `Builder.accept` and no way for this file to disagree
//!   with the reservation about what the internal protocol is called.
//! - **The public path still refuses.** `Builder.accept` is untouched and
//!   still answers `error.reserved_alpn` before it writes anything, whether
//!   or not this route has been registered. A test here asserts that *after*
//!   `registerLast`, so the reservation cannot be widened into a general
//!   capability by a later change to this file.
//! - **The entry can be created once.** `acceptInternal` routes through
//!   `Builder.push`, which offers a repeated ALPN twice and dispatches to the
//!   newer entry. `registerLast` refuses a second registration instead, so
//!   the internal protocol is offered to a peer once and dispatches to one
//!   handler.
//!
//! # Why it registers last, and how a reader can tell
//!
//! **Last is a property of the offer list, not of negotiation.** Registration
//! order is what `Router.alpns` yields and what the endpoint hands the TLS
//! stack, and in this core the *peer's* list decides which name is chosen: the
//! server walks the client's entries and takes the first one it also offers
//! (`vendor/quic/src/quic/tls13.zig:2862-2883`). An internal entry ahead of an
//! application's would therefore win nothing here. Last is still the right
//! position — it is the one that reads as "the protocol the caller configured,
//! then the internal one" — and `Router.lookup` is an exact match either way,
//! so an entry's position never decides which handler answers it.
//!
//! A reader does not have to take that on trust:
//!
//! - `registerLast` returns the index it wrote, so the caller compares one
//!   number against `Builder.len` rather than re-deriving the position.
//! - `isLast` answers the property on a frozen table, and it can be false —
//!   a registration made after this one turns it false, and a test here is
//!   exactly that.
//!
//! # Nothing calls this, and that is the decision
//!
//! **The route exists, is tested, and is deliberately not registered.** The
//! reason is not `max_alpns`. That bound is one this tree chose: `TlsConfig.alpn`
//! is `[]const []const u8` and the server matcher walks every entry
//! (`vendor/quic/src/quic/tls13.zig:1280`, `:2867`), so `alpn_list` in
//! `transport/bridge_manager.zig:82` and `transport/dial_client.zig:82` could
//! each be `[2][]const u8` and the core would carry both names. The reason is
//! that the vendored core has nowhere to put the protocol's two halves:
//!
//! - **No OBSERVED_ADDRESS frame.** `FrameType` names no type in
//!   `0x9f81a6..0x9f81a7` (`vendor/quic/src/quic/frame.zig:45-75`), and
//!   `Frame.parseSized` answers `error.FrameEncodingError` for a type it has no
//!   arm for (`frame.zig:670`). There is no arm to build an outbound frame
//!   from, and an inbound one fails the connection.
//! - **No `address_discovery` transport parameter.** `ParamId` carries no
//!   `0x9f81a176` (`vendor/quic/src/quic/transport_params.zig:24-46`), and
//!   `decode` skips an unknown id by its declared length
//!   (`transport_params.zig:609-612`), so a peer that sent the parameter reads
//!   as one that never asked for QAD.
//!
//! `vendor/quic/` is read-only here, so neither is this tree's to add. A node
//! that registered this route would offer `/iroh-qad/0`, negotiate it, and be
//! unable to report one observed address — the whole service — with
//! `net/qad.zig`'s `Role.shouldReport` gate answerable by nothing. A peer that
//! negotiated QAD and received silence would be worse served than by today's
//! drop, which names itself (`conn_dispatch.zig:303-304`). **So the reservation
//! is the honest state: the ALPN is refused at `Builder.accept`, a table in
//! this tree never offers it, and a peer that negotiates it is dropped.**
//!
//! What closes it, and only then: both vendored-core additions named above; a
//! transport seam on the connection handle, which is an opaque `*anyopaque`
//! the router never dereferences, so a body can neither read a peer's role nor
//! write a frame; and `max_alpns` at 2 with the two `alpn_list` widenings.
//!
//! # What the handler can and cannot do here
//!
//! Upstream's QAD body is `handle_connection` in `iroh-relay/src/quic.rs`:
//! await the connection, then wait for the peer to close it, treating an
//! application close of code 1 ("finished") as the ordinary end and anything
//! else as an error. Neither half is reachable from this tree today, and the
//! reasons are worth naming rather than papering over:
//!
//! - The `Connection` handed to `accept` is an opaque handle the endpoint
//!   layer minted. The router never dereferences it, so a body can neither
//!   wait for a close nor read a close code off it.
//! - The vendored core has no OBSERVED_ADDRESS frame and no
//!   `address_discovery` transport parameter — the two gaps named with their
//!   line numbers in "Nothing calls this, and that is the decision" above,
//!   which is also why they are the reason nothing is registered.
//!
//! So `acceptConnection` records that a QAD connection reached the handler
//! and returns, which is the whole of what the handler shape can observe. It
//! is deliberately the same honesty `node/node_accept.zig` keeps about the
//! gossip protocol: a body that looped over a connection handle it cannot read
//! would be a lie about what this route serves. What closes the gap is a
//! transport seam on the connection handle plus the two vendored-core
//! features above; neither is in this file, and neither is invented here.
//!
//! Neither of the handler's two optional fields is filled either, and that is
//! upstream's own shape rather than a gap in it: `on_accepting` is null
//! because the router already runs that await and QAD's negotiation *is* the
//! handshake, so a handler-level await would wait for the same thing twice;
//! `shutdown` is null because a QAD handler owns nothing that outlives its
//! accepts.
//!
//! This module does not import `net/qad.zig`, and that is the shape rather
//! than an omission: the router sees a negotiated ALPN and nothing about
//! bytes, and the codec sees bytes and nothing about a router.

const std = @import("std");
const router = @import("router.zig");

const t = std.testing;

/// What a QAD registration can be refused for. `RegisterError`'s two arms are
/// the router's own and pass through unchanged; the third is this file's.
pub const Error = router.RegisterError || error{
    /// The reserved ALPN is already in the table.
    ///
    /// `Builder.push` would otherwise offer `/iroh-qad/0` to every peer
    /// twice and dispatch it to the newer of two handlers, so the second
    /// registration is refused rather than absorbed. The table is left as it
    /// was.
    already_registered,
};

/// Register the reserved QAD ALPN, and say which slot it went into.
///
/// **Call this after every application registration.** Nothing here can
/// enforce that ordering — a registration made later simply lands later — so
/// this returns the index it wrote for the caller to check against
/// `Builder.len`, and `isLast` is there to check the frozen table.
///
/// The one way past `Builder.accept`'s `error.reserved_alpn`, and the only
/// caller of `acceptInternal` in the tree. The ALPN is not an argument: the
/// internal protocol is not reachable by passing a different string, and a
/// call site that says `registerLast` says which protocol it meant.
pub fn registerLast(
    builder: *router.Builder,
    handler: router.ProtocolHandler,
) Error!usize {
    for (builder.entries[0..builder.len]) |entry| {
        if (std.mem.eql(u8, entry.alpn, router.qad_alpn)) return error.already_registered;
    }
    // `.fresh` is the only answer left: the loop above found no entry for the
    // reserved ALPN, so `push` cannot displace one.
    const registered = try builder.acceptInternal(handler);
    std.debug.assert(registered == .fresh);
    return builder.len - 1;
}

/// Whether the reserved ALPN is the last ALPN the table offers.
///
/// The property `registerLast` cannot enforce, as a question about the value
/// rather than a sentence about the call site. False for an empty table, and
/// false for a table where an application ALPN was registered after the QAD
/// route — which is the mistake this exists to make visible.
pub fn isLast(table: *const router.Router) bool {
    if (table.entries.len == 0) return false;
    return std.mem.eql(u8, table.entries[table.entries.len - 1].alpn, router.qad_alpn);
}

/// The state behind one QAD handler.
///
/// Its address is the `ProtocolHandler.ptr`, so it must outlive every
/// registration naming it — `ProtocolHandler`'s own rule, and the reason this
/// is a caller-owned value rather than something the route allocates.
pub const Context = struct {
    /// QAD connections this handler has been given. The only thing the
    /// handler shape can observe: see the module doc for why it cannot also
    /// report what the peer did on the connection.
    connections: u64 = 0,

    /// The handler the router dispatches to. See the module doc for why
    /// `on_accepting` and `shutdown` are both null.
    pub fn handler(self: *Context) router.ProtocolHandler {
        return .{
            .ptr = @ptrCast(self),
            // Null is upstream's default body, which the router runs itself:
            // it awaits the handshake and reports the same two outcomes under
            // the same log line. For QAD the handshake *is* the negotiation —
            // the ALPN and the address-discovery transport parameter are both
            // settled when it finishes — and upstream's `handle_connection`
            // awaits `incoming` before doing anything, so a handler that
            // ran in `on_accepting` would await the same thing twice.
            .on_accepting = null,
            .accept = acceptConnection,
            // Null for the same reason upstream leaves its default body
            // empty: a QAD handler owns nothing that outlives its accepts.
            // Node's own `shutdownHandler` is the discipline to copy — give up
            // the handler's own state, touch nothing else.
            .shutdown = null,
        };
    }
};

/// `ProtocolHandler::accept`: one QAD connection handed to this route.
///
/// The handle is borrowed for the call and never kept, and the count is the
/// route's whole observable effect. `node/node_accept.zig`'s `acceptConnection`
/// does the same for the gossip protocol and says why in the same terms.
pub fn acceptConnection(
    ptr: *anyopaque,
    connection: router.Connection,
) router.AcceptError!void {
    // The endpoint mints the handle from the handler's context, so this is
    // what turns that contract into a checked claim rather than a comment.
    std.debug.assert(connection.ptr == ptr);
    const self: *Context = @ptrCast(@alignCast(ptr));
    self.connections += 1;
}

/// The ALPNs a table offers, into storage the test owns.
fn offered(table: *const router.Router, out: [][]const u8) usize {
    var alpns = table.alpns();
    var count: usize = 0;
    while (count < out.len) {
        const alpn = alpns.next() orelse break;
        out[count] = alpn;
        count += 1;
    }
    return count;
}

/// A handler that records nothing, for the registrations that only exist to
/// fill the table.
fn inert(context: *Context) router.ProtocolHandler {
    return context.handler();
}

// --- tests

test "the reservation and the public refusal both survive this registration" {
    var context: Context = .{};
    var entries: [4]router.Entry = undefined;
    var builder = router.Builder.init(&entries);

    // Before: the reserved ALPN is unreachable through the public path, and
    // the refusal writes nothing.
    try t.expectError(
        error.reserved_alpn,
        builder.accept(router.qad_alpn, inert(&context)),
    );
    try t.expectEqual(@as(usize, 0), builder.len);

    _ = try registerLast(&builder, inert(&context));

    // After: the same call is still refused, and still writes nothing. This
    // is the assertion that keeps the reservation from being widened by a
    // later change to this file.
    try t.expectEqual(@as(usize, 1), builder.len);
    try t.expectError(
        error.reserved_alpn,
        builder.accept(router.qad_alpn, inert(&context)),
    );
    try t.expectEqual(@as(usize, 1), builder.len);

    // And the one registration that exists dispatches to this route's
    // handler, under the ALPN the reservation names.
    const table = builder.build();
    const entry = table.lookup(router.qad_alpn) orelse return error.TestUnexpectedResult;
    try t.expectEqual(@as(*anyopaque, &context), entry.handler.ptr);
}

test "registerLast writes the reserved ALPN into the last slot" {
    var context: Context = .{};
    var entries: [4]router.Entry = undefined;
    var builder = router.Builder.init(&entries);

    _ = try builder.accept("/echo", inert(&context));
    _ = try builder.accept("/blob", inert(&context));
    const index = try registerLast(&builder, inert(&context));

    // The index it reports is the slot it wrote, which is the end of the
    // builder: the call site checks one number rather than trusting the
    // order it happened to call things in.
    try t.expectEqual(builder.len - 1, index);
    try t.expectEqual(@as(usize, 2), index);

    // And the offer list ends with the reserved ALPN, after both application
    // ALPNs — which is the whole of "registered last", as a fact about the
    // bytes a peer is offered.
    var list: [4][]const u8 = undefined;
    const table = builder.build();
    try t.expectEqual(@as(usize, 3), offered(&table, &list));
    try t.expectEqualStrings("/echo", list[0]);
    try t.expectEqualStrings("/blob", list[1]);
    try t.expectEqualStrings(router.qad_alpn, list[2]);
    try t.expect(isLast(&table));
}

test "a reader can tell it registered last, and the check can fail" {
    var context: Context = .{};
    var entries: [4]router.Entry = undefined;
    var builder = router.Builder.init(&entries);

    // Nothing registered is not "last", so the predicate has a negative
    // space of its own before the interesting one.
    const empty = builder.build();
    try t.expect(!isLast(&empty));

    _ = try registerLast(&builder, inert(&context));
    try t.expect(isLast(&builder.build()));

    // The mistake this exists to catch: an application ALPN registered after
    // the route. The reservation still holds and the route still resolves,
    // but the internal protocol is no longer preferred last, and `isLast`
    // says so.
    _ = try builder.accept("/late", inert(&context));
    try t.expect(!isLast(&builder.build()));
    try t.expect((builder.build().lookup(router.qad_alpn) != null));

    var list: [4][]const u8 = undefined;
    const table = builder.build();
    try t.expectEqual(@as(usize, 2), offered(&table, &list));
    try t.expectEqualStrings(router.qad_alpn, list[0]);
    try t.expectEqualStrings("/late", list[1]);
}

test "a peer that negotiates the reserved ALPN is served, where it was dropped" {
    var qad: Context = .{};
    var application: Context = .{};
    var entries: [3]router.Entry = undefined;
    var builder = router.Builder.init(&entries);
    _ = try builder.accept("/echo", inert(&application));
    _ = try registerLast(&builder, qad.handler());
    const table = builder.build();

    // The application ALPN still resolves to the application's handler.
    const app = table.lookup("/echo") orelse return error.TestUnexpectedResult;
    try t.expectEqual(@as(*anyopaque, &application), app.handler.ptr);

    // The reserved ALPN resolves too, so the handshake that reaches
    // `negotiatingStep` with it now produces a handler to call rather than
    // `.drop unsupported_alpn`.
    const served = router.dispatchStep(&table, .negotiating, .{
        .outcome = .{ .alpn = router.qad_alpn },
    });
    try t.expectEqual(router.ConnState{ .accepting = qad.handler() }, served.state);
    // `await_handshake`, because the handler registers no `on_accepting`: the
    // handshake is what negotiates QAD, and the router runs that await itself.
    try t.expectEqual(router.DispatchAction.await_handshake, served.action);
    try t.expectEqual(router.PeerOutcome.nothing, served.action.peerOutcome());
    try t.expectEqual(@as(u64, 0), qad.connections);

    // And an ALPN nobody registered is still dropped rather than refused, so
    // registering a route did not turn the table into a catch-all.
    const unknown = router.dispatchStep(&table, .negotiating, .{
        .outcome = .{ .alpn = "/unknown" },
    });
    try t.expectEqual(
        router.ConnState{ .dropped = .{ .unsupported_alpn = "/unknown" } },
        unknown.state,
    );
    try t.expectEqual(router.PeerOutcome.nothing, unknown.action.peerOutcome());
}

test "registering the reserved ALPN twice is refused and changes nothing" {
    var context: Context = .{};
    var other: Context = .{};
    var entries: [3]router.Entry = undefined;
    var builder = router.Builder.init(&entries);
    _ = try builder.accept("/echo", inert(&context));
    _ = try registerLast(&builder, context.handler());

    try t.expectError(
        error.already_registered,
        registerLast(&builder, other.handler()),
    );
    try t.expectEqual(@as(usize, 2), builder.len);

    // One offer, not two, and the entry that answers is the one that was
    // there before: `Builder.push` would have offered the internal protocol
    // twice and dispatched the second handler.
    var list: [3][]const u8 = undefined;
    const table = builder.build();
    try t.expectEqual(@as(usize, 2), offered(&table, &list));
    try t.expectEqualStrings(router.qad_alpn, list[1]);
    const entry = table.lookup(router.qad_alpn) orelse return error.TestUnexpectedResult;
    try t.expectEqual(@as(*anyopaque, &context), entry.handler.ptr);
    try t.expect(isLast(&table));
}

test "the handler shape is the one the endpoint loop expects" {
    var context: Context = .{};
    const handler = context.handler();

    // Four fields, one of them mandatory, and two defaults left to the
    // router: a QAD route adds no `on_accepting` and no `shutdown`.
    try t.expectEqual(@as(usize, 4), @typeInfo(router.ProtocolHandler).@"struct".fields.len);
    try t.expect(handler.on_accepting == null);
    try t.expect(handler.shutdown == null);
    // `accept` is not optional in the first place: it is the whole of a
    // handler, so a route cannot leave it to a default.
    const accept_field = @typeInfo(@FieldType(router.ProtocolHandler, "accept"));
    comptime std.debug.assert(switch (accept_field) {
        .pointer => true,
        else => false,
    });

    // Driven the way `node/node_accept.zig`'s `runTask` drives it: the step
    // names the call, the caller makes it, and the outcome feeds the next
    // step. That is the whole contract between a handler and the loop.
    const call: *const fn (*anyopaque, router.Connection) router.AcceptError!void =
        handler.accept;
    try call(handler.ptr, .{ .ptr = handler.ptr });
    try t.expectEqual(@as(u64, 1), context.connections);

    var entries: [1]router.Entry = undefined;
    var builder = router.Builder.init(&entries);
    _ = try registerLast(&builder, handler);
    const table = builder.build();
    const offered_alpn = router.dispatchStep(&table, .negotiating, .{
        .outcome = .{ .alpn = router.qad_alpn },
    });
    const handling = router.dispatchStep(&table, offered_alpn.state, .{
        .outcome = .{ .connection = .{ .ptr = handler.ptr } },
    });
    try t.expectEqual(router.ConnState{ .handling = handler }, handling.state);
    try t.expectEqual(router.DispatchAction{ .accept = handler }, handling.action);
    try call(handling.action.accept.ptr, .{
        .ptr = handling.action.accept.ptr,
    });
    try t.expectEqual(@as(u64, 2), context.connections);

    // A handler that returns cleanly releases the connection, which is how
    // this route's accept ends: the connection goes back to the endpoint.
    const released = router.dispatchStep(&table, handling.state, .{
        .outcome = .finished,
    });
    try t.expectEqual(router.ConnState.released, released.state);
    try t.expectEqual(router.DispatchAction.release, released.action);
}
