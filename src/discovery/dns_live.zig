//! The live `dns.DnsAddressLookup`: a question asked on a real descriptor, and
//! the service that reads the records that came back.
//!
//! `discovery/dns.zig` names the whole difference between a resolver and a
//! resolver's test in its own module doc: upstream awaits
//! `DnsResolver::lookup_endpoint_by_id_staggered`, which opens a socket, and
//! here the answer is injected. `discovery/lookup_live.zig` crossed the
//! transport seam and stopped one line short of using it — a `Datagram` over a
//! real descriptor with a `Retrieval` to ask through it and nothing asking.
//! This file is the asking, in the order `discovery/lookup_io_tests.zig`
//! writes down for that hand-off: open a socket, bind the seam to it, begin one
//! `Retrieval`, make one `ask`, and hand the records to `DnsAddressLookup`
//! together with that retrieval's `Cancellation`.
//!
//! # One question, and why not the six upstream sends
//!
//! Upstream asks up to six nameservers on a six-second budget, staggered
//! (`iroh/src/address_lookup/dns.rs`, `lookup_endpoint_by_id_staggered`), and
//! `discovery/lookup_io.zig`'s module doc is the argument for not reproducing
//! that: both the staggering and the six seconds are a policy over an instant,
//! and the values below deliberately carry no instant. So `Request.server` is
//! one server and `Request.deadline_ms` is one budget. A caller that wants
//! upstream's other five asks for them, and each one begins another `Lookup` —
//! which draws another transaction id, which is what makes the second question
//! a different question rather than a duplicate of the first
//! (`Retrieval.begin`'s doc).
//!
//! The deadline is the caller's for the same reason and not for tidiness:
//! upstream gives each of its six queries three seconds
//! (`iroh/src/address_lookup/dns.rs:19`), and a number written here would be a
//! second place for that one to live.
//!
//! # The three answers, and which of them is a service
//!
//! `Retrieval.ask` answers with three arms and no error for two of them, so
//! this file has to say what each one becomes:
//!
//! - `records` is the service, over the bytes the ask copied out. The copy is
//!   the fourth of `discovery/lookup_io.zig`'s four things: `Request.reply` is
//!   this call's and is dead the moment `ask` returns, and a service holds its
//!   answers as values.
//! - `nothing` is also the service, over an empty set. The name exists and
//!   published no records, which is a fact about the world rather than a
//!   failure — and `discovery/dial_source.zig` already names what that run is
//!   (a source that named the node and gave no path to it), with
//!   `dns.DnsAddressLookup` over no records as its example.
//! - `timeout` is `error.TimedOut` and nothing else. It is not the empty set,
//!   because nobody said anything here, and it is not a service, because a
//!   service that had already failed would have to carry the failure in its
//!   records and `DnsAddressLookup` has no arm for one. `resolve.Reason.TimedOut`
//!   is the name it has above this layer, and `discovery/lookup_io.zig`'s
//!   module doc is why it is neither of the other two answers.
//!
//! So `error.Truncated` passes out as itself and the caller decides, and the
//! TCP retry RFC 1035 §4.2.2 asks for is not here for the reason
//! `discovery/lookup_live.zig`'s module doc gives: it needs a stream and a
//! connection held open for it, and this file owns a datagram descriptor.
//!
//! # Where the socket comes from
//!
//! The unspecified address of the server's own family, on an ephemeral port.
//! The family is not a default to pick once: `socket_control.open` derives the
//! descriptor's family from the address it binds (`batch.Family.of`), so a v4
//! socket bound to `0.0.0.0` is a socket that cannot carry a query to a v6
//! nameserver, and the bound has to follow `Request.server` rather than lead
//! it. A wildcard rather than an interface address because the source address
//! of a DNS query is not part of what it is asking, and `getsockname` hands
//! back the wildcard with the port the kernel chose — which is where this node
//! is *bound*, not where a peer may reach it, and a query's source is never
//! read out of it.
//!
//! One socket per `Lookup`, closed by `deinit`. A node with many sources to ask
//! pays a descriptor each, and sharing one across them is a policy this file
//! deliberately does not have: `Retrieval.ask` serializes on the seam it was
//! begun with, and two lookups sharing a descriptor would need that policy
//! spelled out somewhere the type does not.
//!
//! # Ownership, and the one address that cannot move
//!
//! `open` returns a pointer rather than a value because three of the handles
//! this file hands out keep a pointer into it: `Datagram.seam` points at the
//! `Datagram`, `Retrieval.cancellation` at the `Retrieval`, and
//! `DnsAddressLookup.lookup` at the service. A `Lookup` returned by value would
//! be copied out from under all three by the assignment that received it,
//! which is the dangling descriptor `lookup_live.Datagram.init`'s doc warns its
//! own caller about. One allocation is what a stable address costs, and it is
//! the only one this file makes: the answer's bytes are the second, and they
//! are `discovery/lookup_io.zig`'s.
//!
//! The three scratch buffers are the call's and die with it, which is what
//! lets them be `undefined` rather than fields: nothing that outlives `ask`
//! borrows them. The name is built into one, the framed query into a second and
//! the answer read into a third, and the buffer a read fills is the thing
//! `lookup_io`'s fourth constraint is about.
//!
//! Every stream started through `lookup` has to be closed before `deinit`:
//! `Stream.deinit` fires the retrieval's handle, and the handle is what stops
//! the query behind it. `deinit` closes the descriptor rather than stopping
//! it, so a caller that dropped a stream alive would be closing the socket
//! under a live read.
//!
//! # What is not here
//!
//! No `resolv.conf` and no search domain: `Request.origin` is the caller's, and
//! `discovery/dns.zig` says the origin is the caller's for the same reason.
//! No cache, no `n0_dns_resolver`, no `NXDOMAIN` of its own —
//! `discovery/lookup_io.zig` already refuses a name that does not exist as
//! `error.NameError`, and a second opinion about it would be a second answer
//! to a question that has one. And no `std.Io` stored, for the reason
//! `docs/DECISIONS/0002-async-substrate.md` gives: `io` is a parameter of the
//! one call that needs it and is never a field.

const std = @import("std");
const addr = @import("../base/addr.zig");
const key = @import("../base/key.zig");
const resolve = @import("resolve.zig");
const record = @import("resolve_record.zig");
const socket = @import("../transport/socket.zig");
const dns = @import("dns.zig");
const wire = @import("lookup_wire.zig");
const lookup_io = @import("lookup_io.zig");
const lookup_live = @import("lookup_live.zig");

/// What one lookup can refuse with.
///
/// The two sets underneath are whole rather than restated, for the reason
/// `discovery/dial_source.zig` gives: a second copy of a set is a list that
/// goes stale when the file it came from grows an arm. `TimedOut` is the only
/// name this file adds, and it is `resolve.Reason.TimedOut` under the name the
/// layer above already uses for the same fact.
pub const Error = lookup_io.Error || socket.OpenError || error{
    /// The question went out and nothing answered it inside the deadline.
    /// Neither an answer nor a failure anybody can be handed in a record set;
    /// see the module doc.
    TimedOut,
};

/// A presentation name, in characters. RFC 1035 §2.3.4 caps the *wire* form
/// at 255 octets, which is 254 characters plus the terminating dot.
///
/// This is the bound the name buffer below is sized from, so it is an RFC's
/// number and not a guess at how long an origin might be. A name longer than
/// it is refused rather than truncated: a truncated name is a name somebody
/// else published.
const name_length = wire.max_name_length;

/// The framed query for a name of `name_length`, which is every name this file
/// will build. `lookup_wire.queryLength` of a string of that length, so the
/// buffer is the codec's own size rather than an arithmetic restatement of it.
///
/// A name that did not fit would be refused by `writeQuery` with
/// `error.BufferTooSmall` rather than overrun it — the check above is what
/// stops the name buffer being the one that runs out first.
const query_length = wire.queryLength("x" ** name_length);

/// One question, as its caller states it.
pub const Request = struct {
    /// The node whose records are being asked for, and the middle label of the
    /// name built from it. The name is `_iroh.<z32>.<origin>`, character for
    /// character as `iroh-dns/src/dns.rs:1062` builds it.
    node_id: key.NodeId,
    /// The origin to ask under, with its trailing dot: `dns.prod_origin` or
    /// `dns.staging_origin`. The caller's, because a name without the dot may
    /// be completed with a local search domain and this file reads no
    /// configuration to complete it with.
    origin: []const u8,
    /// The one nameserver the question goes to. Its address family also
    /// decides the family of the socket opened for it; see the module doc.
    server: addr.SocketAddr,
    /// How long the answer may take, and null for as long as the caller means.
    /// Spent in slices by `discovery/lookup_live.zig`, and nothing else here
    /// reads a clock.
    deadline_ms: ?i32,
    /// Where RFC 1035 §4.1.1's transaction id comes from. The caller's, for
    /// the reason `discovery/lookup_io.zig`'s module doc gives: a global
    /// generator is a global, and this identifier is the one thing that lets a
    /// reply be matched to the question that asked it.
    random: std.Random,
};

// 74 display columns; the rule counts UTF-8 bytes, three per box character.
// ziglint-ignore: Z024
// ──────────────────────────────────────────────────────────── the lookup

/// One question already asked, and the service that reads what it came back
/// with.
///
/// Everything the answer needs to keep alive is here: the descriptor, the seam
/// bound to it, the retrieval the answer came off, and the bytes the answer
/// was copied into. A caller holds this while a resolve runs and calls
/// `deinit` after every stream it started is closed.
///
/// Nothing may move it. `open` returns a pointer because the handles below
/// point into it; a copy would be a value whose service, seam and cancellation
/// all name the original.
pub const Lookup = struct {
    /// What the answer's bytes were taken from. A field rather than an argument
    /// because `deinit` releases this whole value, and named first so that
    /// everything `deinit` touches is described before what `open` builds.
    alloc: std.mem.Allocator,
    /// The descriptor the question went out on, and the one `deinit` closes.
    /// It has to stay open until every stream started here is closed, which is
    /// what `Socket.close`'s own doc asks for.
    socket: socket.Socket,
    /// The seam over that descriptor, borrowed by the retrieval below.
    datagram: lookup_live.Datagram,
    /// The transaction the question was asked under, and the handle that stops
    /// it. Its `cancellation` is the one handed to the service, so closing a
    /// stream stops the query rather than only the reading of it.
    retrieval: lookup_io.Retrieval,
    /// What the caller actually wanted: a `resolve.AddressLookup` over the
    /// records that came back.
    service: dns.DnsAddressLookup,
    /// The answer's bytes, owned here because `Answer.records` owns them and
    /// `service` only borrows them; `deinit` is their one release.
    ///
    /// Null when the answer was `nothing`: that set is empty and borrows
    /// nothing, so there is no allocation to hand back and freeing the empty
    /// slice it points at would be the bug the null is for.
    records: ?[]const u8,

    /// Open a socket, ask `request` of the nameserver it names, and hand back
    /// the service over whatever answered.
    ///
    /// `io` is a parameter and never a field, for the reason
    /// `docs/DECISIONS/0002-async-substrate.md` gives. It is needed for
    /// exactly one call in this file, so storing it would be storing it for a
    /// reader rather than for a use.
    ///
    /// A refusal owns nothing: the descriptor is closed and the value released
    /// on every path out, so a caller that catches `error.TimedOut` has no
    /// cleanup of its own to remember.
    pub fn open(
        alloc: std.mem.Allocator,
        io: std.Io,
        request: Request,
    ) Error!*Lookup {
        // Before the descriptor, because it is the only check in this file
        // that costs nothing and the only one a caller can get wrong with an
        // argument rather than with the network.
        if (dns.queryNameLength(request.origin) > name_length) return error.BufferTooSmall;

        const live = try alloc.create(Lookup);
        errdefer alloc.destroy(live);

        live.alloc = alloc;
        live.socket = try socket.Socket.create(localFor(request.server), .{});
        errdefer live.socket.close();
        // From here on every address below is final, and `seam` and
        // `cancellation` both keep one into this value.
        live.datagram = lookup_live.Datagram.init(&live.socket);
        live.retrieval = lookup_io.Retrieval.begin(
            live.datagram.seam(),
            request.server,
            request.random,
        );

        var name_storage: [name_length]u8 = undefined;
        var query_bytes: [query_length]u8 = undefined;
        var reply_bytes: [wire.reply_length]u8 = undefined;
        const answer = try live.retrieval.ask(alloc, io, .{
            .name = dns.queryName(&name_storage, request.node_id, request.origin),
            .wire = &query_bytes,
            .reply = &reply_bytes,
            .deadline_ms = request.deadline_ms,
        });

        const records = switch (answer) {
            .records => |set| set,
            .nothing => record.RecordSet.init(""),
            .timeout => return error.TimedOut,
        };
        live.records = switch (answer) {
            .records => |set| set.bytes,
            .nothing, .timeout => null,
        };
        live.service = dns.DnsAddressLookup.init(records, live.retrieval.cancellation());
        return live;
    }

    /// A handle onto the service, borrowed. The lookup has to outlive every
    /// stream started through it, and every one of those streams is closed
    /// before `deinit`.
    pub fn lookup(self: *Lookup) resolve.AddressLookup {
        return self.service.lookup();
    }

    /// Release the answer, close the descriptor, and release this value.
    ///
    /// Every stream started through `lookup` must already be closed: closing
    /// one is what fires the retrieval's handle, and a stream still reading
    /// the records this frees is a use-after-free the type cannot see.
    pub fn deinit(self: *Lookup) void {
        const alloc = self.alloc;
        if (self.records) |records| alloc.free(records);
        self.socket.close();
        alloc.destroy(self);
    }
};

/// Where a socket bound for `server` goes: the unspecified address of the
/// server's own family, on a port the kernel chooses.
///
/// The port is ephemeral because a query does not ask to be reachable: the
/// answer comes back to the port the descriptor was bound to, and nothing
/// else will ever send to it.
fn localFor(server: addr.SocketAddr) addr.SocketAddr {
    return .{
        .ip = switch (server.ip) {
            .v4 => .{ .v4 = @splat(0) },
            .v6 => .{ .v6 = @splat(0) },
        },
        .port = 0,
    };
}

// 74 display columns; the rule counts UTF-8 bytes, three per box character.
// ziglint-ignore: Z024
// ───────────────────────────────────────────────────────────────── tests

const t = std.testing;
const Prng = std.Random.DefaultPrng;

/// The node every test asks about, so the name and the id are the same bytes
/// on every run. A fixed seed rather than a random one for the reason
/// `discovery/lookup_live.zig` gives its own.
fn testNode() !key.NodeId {
    var secret = try key.SecretKey.fromSeed([_]u8{7} ** key.SecretKey.seed_length);
    defer secret.deinit();
    return secret.nodeId();
}

/// Loopback on an ephemeral port, which is what the one test below binds: a
/// descriptor, and no nameserver and no network.
const loopback: addr.SocketAddr = .{ .ip = .{ .v4 = .{ 127, 0, 0, 1 } }, .port = 0 };

// A nameserver that answers would have to answer from another thread while
// `open` sits in the ask, and this tree has no thread in any test. So what
// this file's tests can drive is everything around the answer: that a question
// leaves a real descriptor, that the deadline is spent and reported, and that
// a name too long to exist is refused before a descriptor is opened. The
// records-to-service hand-off is proved where it can be driven without one —
// `discovery/lookup_io_tests.zig`'s test of that hand-off, and the
// real-descriptor tests at the bottom of `discovery/lookup_live.zig`.

test "integration: the question leaves a real socket, and a silent server times out" {
    var server = try socket.Socket.create(loopback, .{});
    defer server.close();
    const node_id = try testNode();

    var engine: Prng = .init(101);
    // The same generator, drawn the same way, so the identifier this test
    // expects on the wire is the one `Retrieval.begin` drew inside `open`.
    var shadow: Prng = .init(101);
    const id = shadow.random().int(u16);

    // Nothing on the server answers, so the deadline is spent and `open`
    // refuses. `error.TimedOut` and not an empty service: nobody said anything
    // about this node.
    try t.expectError(error.TimedOut, Lookup.open(t.allocator, t.io, .{
        .node_id = node_id,
        .origin = dns.prod_origin,
        .server = server.address,
        .deadline_ms = 50,
        .random = engine.random(),
    }));

    // And the question was really framed and sent, byte for byte the query the
    // codec frames for that name under that identifier — which is also what
    // says the OPT record advertising the advertised size went with it, since
    // `lookup_wire.writeQuery` refuses a buffer shorter than this.
    var framed: [query_length]u8 = undefined;
    var storage: [name_length]u8 = undefined;
    const question = try wire.writeQuery(
        dns.queryName(&storage, node_id, dns.prod_origin),
        .{ .id = id, .udp_payload = wire.max_udp_payload },
        &framed,
    );
    var control: socket.ControlBuffer = undefined;
    // A second buffer, and not the framing one: the server's read would land
    // where `question` borrows, and a buffer compared against itself passes
    // whether or not either side was written.
    var read: [query_length]u8 = undefined;
    const asked = try server.receive(t.io, &read, &control, 1000);
    try t.expectEqualSlices(u8, question, asked.bytes);
}

test "an origin too long to be a DNS name is refused before anything is opened" {
    var engine: Prng = .init(103);
    // RFC 1035 §2.3.4's cap, one character past it: a name this long is not a
    // name, and truncating it would ask about a name somebody else published.
    const origin = "x" ** (name_length + 1);
    try t.expectError(error.BufferTooSmall, Lookup.open(t.allocator, t.io, .{
        .node_id = try testNode(),
        .origin = origin,
        .server = loopback,
        .deadline_ms = 1,
        .random = engine.random(),
    }));
}