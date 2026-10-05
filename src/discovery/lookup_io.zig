//! The retrieval `discovery/dial_source.zig` names as its one gap: a query
//! written to a socket, the answer read back, and the handle that stops both.
//!
//! A node can parse, merge and dial an address it has been handed. It cannot
//! find one, because every answer reaches it as a value something else already
//! fetched. This file is that something else, and it is the whole of what the
//! seam's bullets name, in the seam's order.
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
//! 1. **A query written to a socket, and the answer read back** — `writeQuery`
//!    and `readAnswer`, with `Datagram` between them. The constraint is that a
//!    DNS message is bytes and nothing else, and `docs/ARCHITECTURE.md`'s
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
//! 4. **A copy of the answer** — `Answer.records` owns bytes taken from
//!    `alloc`. The constraint is that a buffer an `Io` read fills does not
//!    outlive the call, and `resolve.RecordSet` is a value a service holds after
//!    this function has returned. `Request.reply` is the caller's and is dead
//!    the moment `ask` returns; the records are not.
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
//! So it is the third answer: `Answer.timeout`, the question asked and nothing
//! answered in time. Above this file that becomes a `resolve.Event.failed` —
//! one answer that was not an item, recorded in `first_failure`, walk carries
//! on — and naming it needs one arm this file does not own:
//! `resolve.Reason.TimedOut`.
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
//! readily: `resolve.max_record_length` alone is 274, so one relay record plus
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
//!
//! # The modules behind this one
//!
//! Six files, one responsibility each, and this one is the facade that names
//! all of them:
//!
//! * `lookup_wire.zig` — RFC 1035's header constants, the two byte orders, and
//!   `WireError`, the one failure set both codecs name.
//! * `lookup_name.zig` — a name in both forms, including §4.1.4's compression
//!   pointer. Both codecs need it, so it is one module rather than two.
//! * `lookup_query.zig` — the question: `queryLength`, `Query`, `writeQuery`.
//! * `lookup_answer.zig` — the reply: `Answer`, `readAnswer`.
//! * `lookup_datagram.zig` — the injected seam: `SocketError`, `Datagram`.
//! * `lookup_retrieval.zig` — `Retrieval`, `Request`, and `Error`, which is
//!   the union of the other two halves and so closes in the one module above
//!   both.
//!
//! `lookup_test_support.zig` holds the captured vectors and the scripted
//! socket the three test tails stand on; it is imported only by them.

const answer = @import("lookup_answer.zig");
const datagram = @import("lookup_datagram.zig");
const query = @import("lookup_query.zig");
const retrieval = @import("lookup_retrieval.zig");
const wire = @import("lookup_wire.zig");

/// The header, in bytes: RFC 1035 §4.1.1's `ID`, its flags, and four counts.
pub const header_length = wire.header_length;

/// `TYPE` and `QTYPE` for a text record. RFC 1035 §3.2.2, `TXT 16`.
pub const type_txt = wire.type_txt;

/// `CLASS` and `QCLASS` for the Internet. RFC 1035 §3.2.5, `IN 1`.
pub const class_in = wire.class_in;

/// `TYPE` for EDNS0's pseudo-record. RFC 6891 §6.1.3, `OPT 41`.
pub const type_opt = wire.type_opt;

/// The `QR` bit: this message is a response. RFC 1035 §4.1.1.
pub const flag_response = wire.flag_response;

/// The `TC` bit: the message did not fit the channel. RFC 1035 §4.1.1.
pub const flag_truncated = wire.flag_truncated;

/// The `RD` bit: pursue the query recursively. RFC 1035 §4.1.1.
pub const flag_recursion_desired = wire.flag_recursion_desired;

/// A label's maximum length. RFC 1035 §2.3.4.
pub const max_label_length = wire.max_label_length;

/// A name's maximum length, in presentation characters. RFC 1035 §2.3.4 caps
/// the *wire* form at 255 octets, which is 254 characters plus the terminating
/// dot, so 256 is the bound rather than a guess.
pub const max_name_length = wire.max_name_length;

/// What a query advertises it can receive, as RFC 6891 §6.2.3's `CLASS`.
///
/// 1232, because that is the figure DNS Flag Day 2020 settled on and it sits
/// inside RFC 6891 §6.2.5's 512..4096 range with room for the headers a path
/// adds. With nothing advertised the limit is RFC 1035 §4.2.1's 512, which an
/// `_iroh` answer outgrows — see the module doc.
pub const max_udp_payload = wire.max_udp_payload;

/// The datagram size a reply is read into, which is what a peer that honours
/// the advertised size can send.
pub const reply_length = wire.reply_length;

/// One OPT record: the root label, `TYPE`, the advertised size as `CLASS`, an
/// all-zero `TTL` — RFC 6891 §6.1.3 puts the extended `RCODE` and the version
/// there and the version must be zero — and an empty `RDATA`.
pub const opt_length = wire.opt_length;

/// How many entries one section may claim before the walk gives up.
///
/// The counts are wire bytes, so a count is checked rather than trusted: 64
/// entries is far past anything a lookup's answer holds, and a header claiming
/// more is a header to refuse rather than a loop to run.
pub const max_section_records = wire.max_section_records;

/// Why bytes are not a query, or not an answer to this question.
pub const WireError = wire.WireError;

/// Everything one lookup can fail with: the wire's failures, the socket's, and
/// the allocator's.
///
/// `OutOfMemory` is here because the answer is copied into `alloc` and that copy
/// is the fourth of the seam's four things. Nothing else here allocates.
pub const Error = retrieval.Error;

/// Bytes a query for a presentation `name` of this length occupies.
///
/// `name.len + 1` for the wire name: every dot in the text becomes a length
/// octet, and the name's own trailing dot becomes the terminator RFC 1035
/// §4.1.2 spells "the zero length octet for the null label of the root". The
/// root name is one octet and so comes in under this bound.
pub const queryLength = query.queryLength;

/// What one query is, as far as the wire is concerned.
pub const Query = query.Query;

/// Frame one query for `name` into `out`, and hand back what was written.
pub const writeQuery = query.writeQuery;

/// What one lookup came to, with the answer already copied out of the read
/// buffer.
pub const Answer = answer.Answer;

/// Read one answer out of `message` and copy what it carried into `alloc`.
pub const readAnswer = answer.readAnswer;

/// Everything an injected datagram can fail with here, in three arms, because a
/// lookup acts on exactly three things.
pub const SocketError = datagram.SocketError;

/// The socket a lookup goes out on: two calls and a stop, as a vtable.
pub const Datagram = datagram.Datagram;

/// One lookup in flight, and the handle that stops it.
pub const Retrieval = retrieval.Retrieval;

/// What one `ask` writes, and how long it waits.
pub const Request = retrieval.Request;