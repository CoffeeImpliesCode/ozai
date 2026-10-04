//! The retrieval `discovery/dial_source.zig` names as its one gap: a query
//! written to a socket, the answer read back, and the handle that stops both.
//!
//! A node can parse, merge and dial an address it has been handed. It cannot
//! find one, because every answer reaches it as a value something else already
//! fetched. This file is that something else, and it is the half of the seam
//! the other two cannot hold: `discovery/lookup_wire.zig` frames the query,
//! `discovery/lookup_answer.zig` reads the answer, and what is left — the
//! deadline, the entropy, the allocator a copy is taken from, and the handle
//! that stops both — is here, because each of those is something handed in.
//!
//! # Which of the two services this is for, and why not pkarr
//!
//! **DNS, not pkarr**, and the reason is not preference: the seam says the
//! query goes to a `transport/socket.zig` datagram socket, and pkarr's
//! retrieval does not go to one.
//!
//! Upstream iroh 1.3.0 (n0-computer/iroh at
//! 187f59e80afdae6bd9866002b33d3365c00b06d8) resolves pkarr over **HTTPS**.
//! `PkarrRelayClient::resolve` (`iroh/src/address_lookup/pkarr.rs:620`) is an
//! `http_client.get(url)` on `N0_DNS_PKARR_RELAY_PROD`, which is
//! `https://dns.iroh.link/pkarr` (`pkarr.rs:127`), with the node's z32 pushed
//! on as a path segment, and the reply handed to
//! `SignedPacket::from_relay_payload` (`pkarr.rs:651`). A relay client with TLS
//! and HTTP/1.1 is relay work, not a datagram, and a pkarr packet's DNS body
//! does not change what carries it. So the pkarr half stays a relay client,
//! which is what it is upstream, and this file does not pretend otherwise. (The
//! `pubky/pkarr` crate also has a plain-UDP client; iroh does not use it, so a
//! UDP pkarr client would ask a relay iroh never asks.)
//!
//! The DNS retrieval *is* UDP. `DnsAddressLookup` resolves through
//! `n0-dns-resolver` (`iroh/src/address_lookup/dns.rs`), which is UDP for a
//! standard query — RFC 1035 §4.2.1: "UDP is not acceptable for zone
//! transfers, but is the recommended method for standard queries in the
//! Internet" — and the name is built at `iroh-dns/src/dns.rs:1062` exactly as
//! `discovery/dns.zig` already builds it. So this file asks for TXT records.
//!
//! # The four things, and the constraint each answers
//!
//! 1. **A query written to a socket, and the answer read back** —
//!    `lookup_wire.writeQuery` and `lookup_answer.readAnswer`, with `Datagram`
//!    between them. The constraint is that a DNS message is bytes and nothing
//!    else, and `docs/ARCHITECTURE.md`'s
//!    "wire codecs are pure and separate from the transport" says the codec may
//!    not open one. So the codec is a pair of functions over a buffer and the
//!    socket is a vtable handed in: this file opens nothing, ever.
//! 2. **A deadline** — `Request.deadline_ms`. The constraint is purity: a
//!    timeout is an argument, because a module that reads a clock cannot be
//!    driven at a fixed one. RFC 1035 §7.2's "the client should try other
//!    servers before repeating a query" is a *policy*, and policies need an
//!    instant this file deliberately does not carry. One `ask` is one datagram
//!    out and one in.
//! 3. **Entropy** — `Retrieval.begin` draws RFC 1035 §4.1.1's `ID` from the
//!    caller's `std.Random`. The constraint is purity and matching together: the
//!    identifier is what lets a reply be matched to the question that asked it,
//!    and a global generator is a global. What a lookup *signs* is pkarr's, and
//!    `discovery/pkarr.zig` already takes its key and its timestamp as
//!    arguments.
//! 4. **A copy of the answer** — `lookup_answer.Answer.records` owns the bytes
//!    taken from `alloc`. The constraint is that a buffer an `Io` read fills does
//!    not outlive the call, and `record.RecordSet` is a value a service holds
//!    after this function has returned. `Request.reply` is the caller's and is
//!    dead the moment `ask` returns; the records are not.
//!
//! And the abort handle, which is not a fifth thing: `resolve.Cancellation` over
//! `Retrieval`, whose `stop` reaches `Datagram.stop`. See `Retrieval`.
//!
//! # A timeout is its own answer, and here is the argument
//!
//! `item.Resolution` keeps "cannot resolve at all" apart from "resolved to
//! nothing", and invariant 13 says they must not be conflated. A timeout is
//! **neither**, and mapping it onto either one is wrong in a way that shows up
//! as behaviour rather than as a type error:
//!
//! * `cannot_resolve` **stops the walk**. `dial_source.zig` returns on the
//!   first service that refuses, so a resolver answering `null` because a
//!   nameserver was slow would end the run before a second source holding the
//!   address was ever asked. Upstream says the opposite in as many words — a
//!   single failing service must not hide results from the others still in
//!   flight (`iroh/src/address_lookup.rs:584`). So a timeout is not
//!   `cannot_resolve`.
//! * `nothing` is a fact about the world: every source that could answer had
//!   nothing to say. A timeout is not a fact about the world at all — nobody
//!   said the node published nothing. Upstream keeps the three apart too: a name
//!   that does not exist is an error and a name that exists with no TXT records
//!   is an empty iterator (`iroh-dns/src/dns.rs`, `lookup_txt`), and a timeout
//!   is `DnsError::Timeout` (`iroh-dns/src/dns.rs`, `map_resolve_error`) —
//!   neither of them the empty answer set `discovery/dns.zig` already calls "a
//!   node that published nothing".
//!
//! So it is the third answer: `lookup_answer.Answer.timeout`, the question asked
//! and nothing answered in time. Above this file that becomes a
//! `resolve.Event.failed` — one answer that was not an item, recorded in
//! `first_failure`, walk carries on — and naming it needs one arm this file
//! does not own: `resolve.Reason.TimedOut`.
//!
//! # Truncation is the answer that would need TCP, and what it costs
//!
//! `error.Truncated` is the `TC` bit of RFC 1035 §4.1.1: the answer did not
//! fit one datagram. Over UDP an answer is 512 bytes unless the query
//! advertises more — §4.2.1, "Messages carried by UDP are restricted to 512
//! bytes ... Longer messages are truncated and the TC bit is set" — which is
//! why `Retrieval.udp_payload` sends RFC 6891 §6.2.3's OPT record and
//! advertises `max_udp_payload` (1232, the DNS Flag Day 2020 figure, and
//! inside §6.2.5's 512..4096 range). An `_iroh` answer outgrows 512 bytes
//! readily: `record.max_record_length` alone is 274, so one relay record plus
//! two addresses does it.
//!
//! When `TC` is set anyway, the retry is the same question over TCP behind a
//! two octet length prefix (RFC 1035 §4.2.2). That is **not** built here, and
//! it should not be inferred from this module's silence:
//! `transport/socket.zig` is a datagram socket with no stream, no length prefix
//! and no half-close, so the cost is a TCP socket and its
//! connect/read/write/cancel set — the whole relay work this milestone does
//! not do. The second cost is that a TCP retry needs a connection held open for
//! it, which is a lifetime this value deliberately does not have. So truncated
//! is refused as its own error and a caller decides whether to retry at a
//! layer that owns both.
//!
//! # What is not here
//!
//! No `transport/socket.zig` import, and that is the layering rather than a
//! shortcut: `docs/ARCHITECTURE.md` draws `ozai.transport` *above*
//! `ozai.discovery`, so a file under `discovery/` that bound this seam to a
//! transport socket would invert the tree. The binding is three arms of
//! mapping, and all three are in `SocketError`'s doc.
//!
//! Also not here: CNAME chasing, DNSSEC, and the fetching `AddressLookup` that
//! turns an answer into an `item.Item`. The first two are a resolver's policy
//! and the third is `discovery/dns.zig`'s stream with a retrieval behind it;
//! this file is the retrieval, and the stream that consumes an `Answer` is
//! built by handing the records to `DnsAddressLookup` with this `Retrieval`'s
//! `Cancellation`.
//!
//! # Purity
//!
//! No clock, no global, no thread, no environment. `io: std.Io` is a parameter
//! of `Datagram`'s two calls and of `Retrieval.ask`, and is stored nowhere, for
//! the reason `docs/DECISIONS/0002-async-substrate.md` gives: a struct holding
//! an `Io` cannot be driven twice with different runtimes. The allocator is the
//! caller's. `Retrieval` holds a descriptor it was handed and a vtable, which
//! is a borrowed view and not ownership.

const std = @import("std");
const addr = @import("../base/addr.zig");
const resolve = @import("resolve.zig");
const wire = @import("lookup_wire.zig");
const answer = @import("lookup_answer.zig");

/// Everything one lookup can fail with: the decoder's refusals, the socket's,
/// and the allocator an answer's copy is taken from.
///
/// Spelled here as the decoder's set plus this file's own rather than declared
/// over there, so the dependency runs one way: `discovery/lookup_answer.zig`
/// does not know a socket exists and cannot grow an arm because one was added
/// to the seam.
pub const Error = answer.DecodeError || SocketError;

// The section rule is 78 columns wide, which is the width this file is held
// to; Z024 counts UTF-8 bytes, and the box-drawing glyphs are three each.
// ziglint-ignore: Z024
// ───────────────────────────────────────────────────────────── the retrieval

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
/// Injected, and the reason is layering as much as testability:
/// `docs/ARCHITECTURE.md` puts `ozai.transport` above `ozai.discovery`, and a
/// lookup's socket is the one thing above it that a lookup needs. `io: std.Io`
/// is a parameter of both calls and is stored nowhere, for the reason
/// `docs/DECISIONS/0002-async-substrate.md` gives.
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

/// One lookup in flight, and the handle that stops it.
///
/// A value the caller owns, holding a descriptor it was handed and nothing
/// else: no allocator, no runtime, no clock. The four seam-supplied things sit
/// on it — the query and the answer through `ask`, the deadline through
/// `Request`, the transaction id through `begin`, and the abort through
/// `cancellation`.
///
/// Two of its fields are state rather than configuration. `stopped` is
/// terminal: `cancellation().fire()` sets it, and every later `ask` answers
/// `error.Canceled` — a retrieval that was stopped is one that will not ask
/// again, which is a state rather than a failure to retry. `owner` is scratch,
/// reused by every ask, and nothing handed out points into it: the records that
/// leave an ask are copies.
///
/// Serialize `ask` calls. After `cancellation`, keep this value at the same
/// address until all asks and fires return. Cancellation may run concurrently;
/// its callback must synchronize with send and receive. It does not join them.
/// Copies have separate latches but share the borrowed datagram context.
pub const Retrieval = struct {
    /// The socket to ask, borrowed. It, and everything its `ctx` reaches, has to
    /// outlive this retrieval and every ask made through it, because an ask
    /// reads all three of its functions.
    datagram: Datagram,
    /// Who the question goes to, kept so a datagram from anywhere else can be
    /// refused. A TXT answer carries no signature, so the source address is the
    /// only thing standing between a lookup and a forged one.
    server: addr.SocketAddr,
    /// RFC 1035 §4.1.1's `ID`. Drawn here and not read from a global, because
    /// it is the one thing on the wire a resolver must not predict and this
    /// file is not allowed a global.
    id: u16,
    /// What the query advertises it can receive. See `max_udp_payload`.
    udp_payload: u16 = max_udp_payload,
    /// Set by `cancellation`, and the reason `ask` refuses rather than waits.
    stopped: std.atomic.Value(bool) = .init(false),
    /// One decoded owner name, so matching an answer's records against the name
    /// asked about allocates nothing. Fixed-size because RFC 1035 §2.3.4 caps a
    /// name, which makes this a bound rather than a guess.
    owner: [max_name_length]u8 = undefined,

    /// Start a lookup: one transaction id, drawn from `random`.
    ///
    /// Nothing is sent. A send is an `ask`, and an `ask` is one datagram out and
    /// one in — RFC 1035 §7.2's "the client should try other servers before
    /// repeating a query" is a policy, and a policy needs an instant this value
    /// deliberately does not carry.
    pub fn begin(
        datagram: Datagram,
        server: addr.SocketAddr,
        random: std.Random,
    ) Retrieval {
        return .{
            .datagram = datagram,
            .server = server,
            .id = random.int(u16),
        };
    }

    /// `resolve.Cancellation` over this retrieval: `fire` reaches the socket.
    ///
    /// The one handle invariant 13 is about, and it points at the producer
    /// rather than at this struct's state — `resolve.Cancellation` says so, and
    /// a stream that cancelled only itself would be exactly the failure the
    /// invariant names.
    pub fn cancellation(self: *Retrieval) resolve.Cancellation {
        return .{ .ctx = @ptrCast(@alignCast(self)), .stop = stopRetrieval };
    }

    /// Ask, and read the answer, once.
    ///
    /// `request.name` is `_iroh.<z32>.<origin>` in presentation form, built by
    /// `discovery/dns.zig`'s `queryName` into storage the caller owns. What
    /// comes back is this call's to free with `Answer.deinit`.
    ///
    /// Waits for a datagram, deadline or stop through the supplied seam.
    /// Stop is checked before I/O and after receive. An observed stop returns
    /// `error.Canceled`, including when receive reports a concurrent timeout.
    /// A result can win if cancellation comes after the final check.
    ///
    /// Both buffers are caller-owned scratch and may retain old bytes.
    /// `wire` changes during query encoding; `reply` changes only as the seam
    /// receives into it. An early cancellation can leave both untouched.
    /// Errors release any answer allocation, but do not restore scratch,
    /// undo a sent query, or return a consumed datagram to the socket.
    ///
    /// This is not a retry. The transaction id was drawn once by `begin`, so a
    /// second ask asks the same question and will read the first one's late
    /// answer if one is still coming. Repeating a query is RFC 1035 §7.2's
    /// policy and needs an instant this value does not carry, so a caller that
    /// wants one begins another retrieval with another id.
    pub fn ask(
        self: *Retrieval,
        alloc: std.mem.Allocator,
        io: std.Io,
        request: Request,
    ) Error!answer.Answer {
        if (self.stopped.load(.acquire)) return error.Canceled;
        const framed = try wire.writeQuery(request.name, .{
            .id = self.id,
            .udp_payload = self.udp_payload,
        }, request.wire);
        try self.datagram.send(self.datagram.ctx, io, self.server, framed);
        const reply = self.datagram.receive(
            self.datagram.ctx,
            io,
            request.reply,
            request.deadline_ms,
        ) catch |err| {
            if (self.stopped.load(.acquire)) return error.Canceled;
            return switch (err) {
                error.Empty => .{ .timeout = {} },
                else => |rest| rest,
            };
        };
        // A reply that arrived after stop is not an answer to deliver.
        if (self.stopped.load(.acquire)) return error.Canceled;
        if (reply.from.order(self.server) != .eq) return error.ForeignSource;
        return answer.readAnswer(
            alloc,
            reply.bytes,
            request.name,
            self.id,
            self.owner[0..],
        );
    }
};

/// One retrieval's stop: mark it, then stop the socket.
///
/// The order is what makes a second `fire` cheap rather than wrong:
/// `resolve.Stream.deinit` fires on every path out of a resolve, including the
/// ones where nothing was in flight, so the flag is set first and the socket is
/// told once.
fn stopRetrieval(ctx: *anyopaque) void {
    const self: *Retrieval = @ptrCast(@alignCast(ctx));
    if (self.stopped.swap(true, .acq_rel)) return;
    self.datagram.stop(self.datagram.ctx);
}

/// What one `ask` writes, and how long it waits.
///
/// An options struct because two of these are the same type and a positional
/// list that long is a list nothing distinguishes. The buffers are the
/// caller's because a read buffer does not outlive the call and a query may be
/// longer than anything this file could own.
///
/// Encoding and receive may overwrite prefixes only. Buffer contents are not
/// an outcome channel: inspect the returned `Answer`, not unwritten bytes.
pub const Request = struct {
    /// The name asked about, in presentation form with its trailing dot.
    name: []const u8,
    /// Query scratch of at least `queryLength(name)` bytes. Encoding can
    /// overwrite it; a retrieval stopped before encoding leaves it unchanged.
    wire: []u8,
    /// Receive scratch. `reply_length` bytes fits an answer within the advertised
    /// limit. A short receive leaves the tail unchanged; timeout and error may
    /// leave the whole buffer unchanged.
    reply: []u8,
    /// How long one receive waits, in milliseconds, and null for as long as the
    /// caller means. Upstream gives each of its six staggered queries three
    /// seconds (`iroh/src/address_lookup/dns.rs:19`); the staggering is a policy
    /// and needs an instant, so only the per-query deadline is here.
    deadline_ms: ?i32,
};

