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

const std = @import("std");
const addr = @import("../base/addr.zig");
const dns = @import("dns.zig");
const resolve = @import("resolve.zig");

// The section rule is 77 columns wide, which is the width this file is held
// to; Z024 counts UTF-8 bytes, and the box-drawing glyphs are three each.
// ziglint-ignore: Z024
// ───────────────────────────────────────────────────────────────── the wire

/// The header, in bytes: RFC 1035 §4.1.1's `ID`, its flags, and four counts.
pub const header_length = 12;

/// `TYPE` and `QTYPE` for a text record. RFC 1035 §3.2.2, `TXT 16`.
pub const type_txt: u16 = 16;

/// `CLASS` and `QCLASS` for the Internet. RFC 1035 §3.2.5, `IN 1`.
pub const class_in: u16 = 1;

/// `TYPE` for EDNS0's pseudo-record. RFC 6891 §6.1.3, `OPT 41`.
pub const type_opt: u16 = 41;

/// The `QR` bit: this message is a response. RFC 1035 §4.1.1.
pub const flag_response: u16 = 1 << 15;

/// The `TC` bit: the message did not fit the channel. RFC 1035 §4.1.1.
pub const flag_truncated: u16 = 1 << 9;

/// The `RD` bit: pursue the query recursively. RFC 1035 §4.1.1.
pub const flag_recursion_desired: u16 = 1 << 8;

/// `RCODE`, the low four bits of the flags. RFC 1035 §4.1.1.
const rcode_bits: u16 = 0x000f;

/// A label, or the reserved encoding that is neither.
const name_label: u8 = 0x00;

/// A compression pointer. RFC 1035 §4.1.4 spells it `11` in the top two bits
/// and an offset in the low fourteen.
const name_pointer: u8 = 0xc0;

/// A label's maximum length. RFC 1035 §2.3.4.
pub const max_label_length = 63;

/// A name's maximum length, in presentation characters. RFC 1035 §2.3.4 caps
/// the *wire* form at 255 octets, which is 254 characters plus the terminating
/// dot, so 256 is the bound rather than a guess.
pub const max_name_length = 256;

/// What this file advertises it can receive, as RFC 6891 §6.2.3's `CLASS`.
///
/// 1232, because that is the figure DNS Flag Day 2020 settled on and it sits
/// inside RFC 6891 §6.2.5's 512..4096 range with room for the headers a path
/// adds. With nothing advertised the limit is RFC 1035 §4.2.1's 512, which an
/// `_iroh` answer outgrows — see the module doc.
pub const max_udp_payload: u16 = 1232;

/// The datagram size a reply is read into, which is what a peer that honours
/// the advertised size can send.
pub const reply_length = max_udp_payload;

/// One OPT record: the root label, `TYPE`, the advertised size as `CLASS`, an
/// all-zero `TTL` — RFC 6891 §6.1.3 puts the extended `RCODE` and the version
/// there and the version must be zero — and an empty `RDATA`.
pub const opt_length = 11;

/// `QTYPE` plus `QCLASS`. RFC 1035 §4.1.2.
const question_length = 4;

/// How many entries one section may claim before the walk gives up.
///
/// The counts are wire bytes, so a count is checked rather than trusted: 64
/// entries is far past anything a lookup's answer holds, and a header claiming
/// more is a header to refuse rather than a loop to run.
pub const max_section_records = 64;

/// Why bytes are not a query, or not an answer to this question.
pub const WireError = error{
    /// `out` cannot hold what was handed to it. The only way a fixed writer
    /// fails, so a short buffer and a full one are one event.
    BufferTooSmall,
    /// A label over RFC 1035 §2.3.4's 63 octets.
    LabelTooLong,
    /// An empty label that is not the name's terminator, which is
    /// `_iroh..example.`: two dots in a row is a name nobody published.
    EmptyLabel,
    /// A name that does not end in the root label's dot. RFC 1035 §2.3.1 asks
    /// for it and `discovery/dns.zig`'s `prod_origin` has it, because a name
    /// without one may be completed with a local search domain.
    UnterminatedName,
    /// Fewer bytes than a header, a section or a field the walk reads.
    ShortMessage,
    /// A name that runs past the message, a compression pointer that does not
    /// point at a name, or one of the two reserved length encodings.
    BadName,
    /// The message says it is a question: RFC 1035 §4.1.1's `QR` bit is 0.
    NotAResponse,
    /// The `ID` is not the one this question was asked under, so the datagram
    /// is another query's answer. §4.1.1: the `ID` "is copied [into] the
    /// corresponding reply and can be used by the requester to match up replies
    /// to outstanding queries".
    ForeignTransaction,
    /// The datagram came from somewhere other than the server it was asked of.
    /// A TXT answer carries no signature, so the source address is the only
    /// thing standing between a lookup and a forged one.
    ForeignSource,
    /// `RCODE` 3, `NXDOMAIN`: the name does not exist. Upstream's `lookup_txt`
    /// treats that as an error rather than as an answer with nothing in it, and
    /// so does this, because a name that was never published and a name with
    /// nothing published for it are different facts.
    NameError,
    /// `RCODE` 2, `SERVFAIL`: the server could not process a query it
    /// understood.
    ServiceFailure,
    /// `RCODE` 4, `NOTIMP`: no such query kind here.
    Unimplemented,
    /// `RCODE` 5, `REFUSED`: the server declines this query.
    ServiceRefused,
    /// `RCODE` 1, `FORMERR`: the server could not interpret the query.
    MalformedResponse,
    /// An `RCODE` outside 0..5, which §4.1.1 reserves.
    UnknownResponseCode,
    /// The `TC` bit is set: the answer did not fit one datagram and the rest of
    /// it is somewhere this file cannot reach. See the module doc.
    Truncated,
};

/// Everything one lookup can fail with: the wire's failures, the socket's, and
/// the allocator's.
///
/// `OutOfMemory` is here because the answer is copied into `alloc` and that copy
/// is the fourth of the seam's four things. Nothing else here allocates.
pub const Error = WireError || SocketError || error{OutOfMemory};

/// Bytes a query for a presentation `name` of this length occupies.
///
/// `name.len + 1` for the wire name: every dot in the text becomes a length
/// octet, and the name's own trailing dot becomes the terminator RFC 1035
/// §4.1.2 spells "the zero length octet for the null label of the root". The
/// root name is one octet and so comes in under this bound.
pub fn queryLength(name: []const u8) usize {
    return header_length + name.len + 1 + question_length + opt_length;
}

/// What one query is, as far as the wire is concerned.
pub const Query = struct {
    /// RFC 1035 §4.1.1's `ID`, which the answer must echo. Drawn by the caller
    /// from its own generator; see `Retrieval.begin`.
    id: u16,
    /// `QTYPE`. TXT and nothing else: a lookup asks for records, and a name
    /// that answers with something else has published nothing here.
    qtype: u16 = type_txt,
    /// The datagram size to advertise in an OPT record, or null for RFC 1035's
    /// 512-byte message with no OPT at all. Null is the default because it is
    /// what a query carrying no negotiation looks like; `Retrieval` asks for
    /// 1232 because a real answer needs it.
    udp_payload: ?u16 = null,
};

/// Frame one query for `name` into `out`, and hand back what was written.
///
/// `name` is the presentation form with its trailing dot — `discovery/dns.zig`'s
/// `queryName` writes one — and `out` needs `queryLength(name)` bytes.
///
/// No pointers are written, which RFC 1035 §4.1.4 permits ("Programs are free
/// to avoid using pointers in messages they generate") and which keeps this
/// function free of the offset bookkeeping a pointer needs. The reader below
/// understands them either way, because every implementation must.
pub fn writeQuery(name: []const u8, query: Query, out: []u8) WireError![]const u8 {
    const payload = query.udp_payload;
    if (out.len < header_length) return error.BufferTooSmall;
    put16(out, 0, query.id);
    // `RD` and nothing else: `QR` is 0 because this is a question, and the
    // three `Z` bits are 0 because §4.1.1 requires it in all queries.
    put16(out, 2, flag_recursion_desired);
    put16(out, 4, 1);
    put16(out, 6, 0);
    put16(out, 8, 0);
    put16(out, 10, if (payload != null) 1 else 0);
    const written = try writeName(name, out[header_length..]);
    var at = header_length + written;
    if (at + question_length > out.len) return error.BufferTooSmall;
    put16(out, at, query.qtype);
    put16(out, at + 2, class_in);
    at += question_length;
    // The OPT record, and only for a query that advertises a size: the count
    // above says one additional record, so the record has to be written
    // whenever the count was raised.
    if (payload) |advertised| {
        if (at + opt_length > out.len) return error.BufferTooSmall;
        out[at] = 0;
        put16(out, at + 1, type_opt);
        put16(out, at + 3, advertised);
        put32(out, at + 5, 0);
        put16(out, at + 9, 0);
        at += opt_length;
    }
    return out[0..at];
}

/// What one lookup came to, with the answer already copied out of the read
/// buffer.
///
/// Three arms, and the module doc is why there is no fourth: "cannot resolve at
/// all" and "resolved to nothing" are the vocabulary `item.Resolution` keeps
/// apart, and a timeout belongs to neither.
pub const Answer = union(enum) {
    /// The name exists and carried no record this question asked for. A fact
    /// about the world, and the one `discovery/dns.zig` already calls "a node
    /// that published nothing".
    nothing,
    /// The question went out and nothing answered inside the deadline.
    ///
    /// Its own arm rather than either of the others; see the module doc. It is
    /// an arm and not an error so that a caller which forgets it cannot lose it:
    /// `switch` over this union has to name it.
    timeout,
    /// The records, one per NUL, owned by `alloc`.
    records: resolve.RecordSet,

    /// Hand the copy back. A no-op on the two arms that hold no bytes, so a
    /// caller need not know which one it got before it can clean up.
    pub fn deinit(self: Answer, alloc: std.mem.Allocator) void {
        switch (self) {
            .records => |set| alloc.free(set.bytes),
            .nothing, .timeout => {},
        }
    }

    /// Whether this answer holds the records it was asked for, which is the
    /// only arm a caller can hand to `resolve.parseTxt` as an answer rather
    /// than as an event.
    pub fn hasRecords(self: Answer) bool {
        return self == .records;
    }
};

/// Read one answer out of `message` and copy what it carried into `alloc`.
///
/// `name` is the presentation name that was asked about and `id` the
/// transaction it was asked under; a message that is not that question's
/// answer is refused rather than read. `owner` is scratch for one decoded owner
/// name and needs `max_name_length` bytes.
///
/// Records come out in the order the answer listed them, one `key=value` per
/// NUL, which is `resolve.RecordSet`'s own shape: upstream reads them with
/// `packet.txt_records(IROH_TXT_NAME)` and joins a record's character strings
/// before the record is read. A record whose owner name is not the name asked
/// about is skipped rather than refused — §4.1.1's `AA` note says an answer
/// "may have multiple owner names because of aliases", and refusing the whole
/// message over an alias we did not ask to chase would lose the records behind
/// it.
pub fn readAnswer(
    alloc: std.mem.Allocator,
    message: []const u8,
    name: []const u8,
    id: u16,
    owner: []u8,
) Error!Answer {
    const counts = try readHeader(message, id);
    var at: usize = header_length;
    for (0..counts.questions) |_| {
        at = (try readName(message, at, &.{})).end;
        if (at + question_length > message.len) return error.ShortMessage;
        at += question_length;
    }
    var records: std.ArrayList(u8) = .empty;
    defer records.deinit(alloc);
    for (0..counts.answers) |_| {
        at = try walkRecord(alloc, message, at, name, owner, &records);
    }
    // The authority and additional sections carry no `_iroh` records, and the
    // OPT this query advertised is answered with one in the second of them.
    // Walking them is still the only way to know the message was not cut short
    // inside one — and they are walked without collecting, because a TXT record
    // in an authority section is somebody else's authority and not this node's
    // address.
    for (0..counts.authorities + counts.additionals) |_| {
        at = try skipRecord(message, at);
    }
    if (records.items.len == 0) return .nothing;
    return .{ .records = .init(try records.toOwnedSlice(alloc)) };
}

/// What one header says, once the fields this file acts on have been checked.
const Counts = struct {
    questions: u16,
    answers: u16,
    authorities: u16,
    additionals: u16,
};

/// Read the header and refuse anything that is not this question's answer.
///
/// The order is the order the checks can be made in: the length, then the `ID`
/// — a foreign transaction is not a malformed message and must not be reported
/// as one — then `QR`, then `TC`, then the counts.
fn readHeader(message: []const u8, id: u16) WireError!Counts {
    if (message.len < header_length) return error.ShortMessage;
    if (be16(message, 0) != id) return error.ForeignTransaction;
    const flags = be16(message, 2);
    if (flags & flag_response == 0) return error.NotAResponse;
    if (flags & flag_truncated != 0) return error.Truncated;
    switch (flags & rcode_bits) {
        0 => {},
        1 => return error.MalformedResponse,
        2 => return error.ServiceFailure,
        3 => return error.NameError,
        4 => return error.Unimplemented,
        5 => return error.ServiceRefused,
        else => return error.UnknownResponseCode,
    }
    var counts: Counts = .{
        .questions = be16(message, 4),
        .answers = be16(message, 6),
        .authorities = be16(message, 8),
        .additionals = be16(message, 10),
    };
    inline for (.{
        &counts.questions,
        &counts.answers,
        &counts.authorities,
        &counts.additionals,
    }) |count| {
        if (count.* > max_section_records) return error.ShortMessage;
    }
    return counts;
}

/// Walk one resource record and hand back the offset just past it.
///
/// RFC 1035 §4.1.3's shape: `NAME`, then `TYPE`, `CLASS`, `TTL` and `RDLENGTH`
/// as two, two, four and two octets, then `RDLENGTH` octets of `RDATA`. A TXT
/// record for the name asked about contributes its records; every other record
/// contributes its length and nothing else.
fn walkRecord(
    alloc: std.mem.Allocator,
    message: []const u8,
    at: usize,
    name: []const u8,
    owner: []u8,
    records: *std.ArrayList(u8),
) Error!usize {
    const decoded = try readName(message, at, owner);
    const fixed = try recordBody(message, decoded.end);
    const kind = be16(message, decoded.end);
    const class = be16(message, decoded.end + 2);
    const rdlength = be16(message, decoded.end + 8);
    const ours = kind == type_txt and
        class == class_in and
        std.ascii.eqlIgnoreCase(owner[0..decoded.written], name);
    if (ours) try appendTxt(alloc, message[fixed..][0..rdlength], records);
    return fixed + rdlength;
}

/// Walk one record without reading what it holds, for the sections that cannot
/// carry this question's answer.
fn skipRecord(message: []const u8, at: usize) WireError!usize {
    const decoded = try readName(message, at, &.{});
    const fixed = try recordBody(message, decoded.end);
    return fixed + be16(message, decoded.end + 8);
}

/// `TYPE`, `CLASS`, `TTL` and `RDLENGTH` end here: the offset the `RDATA`
/// starts at, checked against the message so a `RDLENGTH` past the end is a
/// short message and not a read out of bounds.
fn recordBody(message: []const u8, at: usize) WireError!usize {
    const fixed = at + 2 + 2 + 4 + 2;
    if (fixed > message.len) return error.ShortMessage;
    const rdlength = be16(message, at + 8);
    if (fixed + rdlength > message.len) return error.ShortMessage;
    return fixed;
}

/// Join one TXT record's character strings into one record of the answer set.
///
/// RFC 1035 §3.3.14: "One or more `<character-string>`s", each a length octet
/// and that many octets. Upstream concatenates a record's strings with nothing
/// between them and one record becomes one `key=value` (`iroh-dns/src/dns.rs`,
/// `TxtRecordData`), so the strings of one record join and the NUL between
/// records is this list's own separator — which is exactly `resolve.RecordSet`'s
/// shape, and the reason a publisher's output and a resolver's input are the
/// same value.
fn appendTxt(
    alloc: std.mem.Allocator,
    rdata: []const u8,
    records: *std.ArrayList(u8),
) Error!void {
    var at: usize = 0;
    while (at < rdata.len) {
        const length = rdata[at];
        at += 1;
        if (at + length > rdata.len) return error.ShortMessage;
        try records.appendSlice(alloc, rdata[at..][0..length]);
        at += length;
    }
    try records.append(alloc, 0);
}

/// The wire form of a presentation name, written into `out`, and its length.
///
/// Every dot is a length octet and the name's own trailing dot is the root's
/// terminator, so `out` needs `name.len + 1` bytes.
fn writeName(name: []const u8, out: []u8) WireError!usize {
    if (name.len == 0 or name[name.len - 1] != '.') return error.UnterminatedName;
    var rest = name[0 .. name.len - 1];
    if (rest.len == 0) {
        // The root: one zero octet and no labels.
        if (out.len == 0) return error.BufferTooSmall;
        out[0] = 0;
        return 1;
    }
    var at: usize = 0;
    while (true) {
        const dot = std.mem.indexOfScalar(u8, rest, '.') orelse rest.len;
        const label = rest[0..dot];
        if (label.len == 0) return error.EmptyLabel;
        if (label.len > max_label_length) return error.LabelTooLong;
        if (at + 1 + label.len > out.len) return error.BufferTooSmall;
        out[at] = @intCast(label.len);
        @memcpy(out[at + 1 ..][0..label.len], label);
        at += 1 + label.len;
        if (dot == rest.len) break;
        rest = rest[dot + 1 ..];
    }
    if (at + 1 > out.len) return error.BufferTooSmall;
    out[at] = 0;
    return at + 1;
}

/// Where a decoded name ends in the message, and how much of it was written.
const Decoded = struct {
    /// Just past the name in the message, which is *not* where the walk
    /// finished when a pointer was taken: a pointer is two octets and the rest
    /// of the name is elsewhere, so this is the position after those two.
    end: usize,
    /// The presentation form written into the caller's buffer, trailing dot
    /// included. Zero when the caller asked for no name.
    written: usize,
};

/// Decode the name at `at` into `out`, in presentation form.
///
/// An `out` of length zero decodes without materialising, which is what walking
/// past a question is. The walk needs no step counter because RFC 1035 §4.1.4's
/// pointer names a *prior* occurrence: a target at or after the pointer's own
/// offset is `BadName`, so every jump moves strictly backwards while labels
/// move forwards, and neither can revisit a byte.
fn readName(message: []const u8, at: usize, out: []u8) WireError!Decoded {
    const capture = out.len != 0;
    var cursor = at;
    var written: usize = 0;
    var end: ?usize = null;
    while (true) {
        if (cursor >= message.len) return error.ShortMessage;
        const lead = message[cursor];
        switch (lead & name_pointer) {
            name_pointer => {
                if (cursor + 1 >= message.len) return error.ShortMessage;
                const target = (@as(usize, lead & ~name_pointer) << 8) | message[cursor + 1];
                if (target >= message.len or target >= cursor) return error.BadName;
                if (end == null) end = cursor + 2;
                cursor = target;
            },
            name_label => {
                cursor += 1;
                if (lead == 0) {
                    // Every label already wrote the dot that follows it, so the
                    // root's terminator adds one only for a name that was the
                    // root all along — which is how `"."` comes out of a name
                    // with no labels rather than an empty string.
                    if (capture and written == 0) try writeByte(out, &written, '.');
                    // `end` is null only when no pointer was taken, and then it
                    // is this cursor: a name that ends at its own terminator
                    // ends one past it, which is where a record's `TYPE` is.
                    return .{ .end = end orelse cursor, .written = written };
                }
                if (cursor + lead > message.len) return error.ShortMessage;
                if (capture) {
                    try writeBytes(out, &written, message[cursor..][0..lead]);
                    try writeByte(out, &written, '.');
                }
                cursor += lead;
            },
            // `01` and `10` are reserved by §4.1.4 and there is no length to
            // read out of them, so a name using one is refused.
            else => return error.BadName,
        }
    }
}

fn writeByte(out: []u8, at: *usize, value: u8) WireError!void {
    if (at.* >= out.len) return error.BufferTooSmall;
    out[at.*] = value;
    at.* += 1;
}

fn writeBytes(out: []u8, at: *usize, bytes: []const u8) WireError!void {
    if (at.* + bytes.len > out.len) return error.BufferTooSmall;
    @memcpy(out[at.*..][0..bytes.len], bytes);
    at.* += bytes.len;
}

fn be16(bytes: []const u8, at: usize) u16 {
    return std.mem.readInt(u16, bytes[at..][0..2], .big);
}

fn be32(bytes: []const u8, at: usize) u32 {
    return std.mem.readInt(u32, bytes[at..][0..4], .big);
}

fn put16(bytes: []u8, at: usize, value: u16) void {
    std.mem.writeInt(u16, bytes[at..][0..2], value, .big);
}

fn put32(bytes: []u8, at: usize, value: u32) void {
    std.mem.writeInt(u32, bytes[at..][0..4], value, .big);
}

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
    /// The socket's own value, borrowed and reached by all three calls. It has
    /// to stay alive and unchanged until every `Retrieval` begun over this
    /// `Datagram` is finished with it.
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
    /// `into` does not outlive this call, which is why the answer is copied out
    /// of it rather than handed back pointing into it; whatever was in `into`
    /// before is gone afterwards. `deadline_ms` is `null` for "as long as the
    /// caller means" and a count of milliseconds otherwise, and `error.Empty` is
    /// what that wait running out looks like.
    ///
    /// Called synchronously, on the thread that asked, with `io` borrowed for
    /// the call. The `Reply` borrows `into` and dies with this call, so a
    /// datagram to keep is one to copy before the next receive.
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
    stop: *const fn (ctx: *anyopaque) void,

    /// One datagram, and who sent it.
    pub const Reply = struct {
        /// Borrowed from the buffer the receive was given, and dead as soon as
        /// that call is.
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
pub const Retrieval = struct {
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
    stopped: bool = false,
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
    /// Blocks until one datagram arrives, the deadline passes or the abort
    /// handle fires, and is cancellable the whole way: `error.Canceled` answers
    /// a retrieval that was stopped, whether before this call or while the
    /// receive was in flight.
    ///
    /// Both of `request`'s buffers are written — `wire` holds the query this
    /// call sent, `reply` whatever came back — so neither keeps what it held
    /// before. Nothing survives an error: a refused send, a refused receive and
    /// a malformed message each release what they had built, and the datagram
    /// is gone from the socket either way.
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
    ) Error!Answer {
        if (self.stopped) return error.Canceled;
        const wire = try writeQuery(request.name, .{
            .id = self.id,
            .udp_payload = self.udp_payload,
        }, request.wire);
        try self.datagram.send(self.datagram.ctx, io, self.server, wire);
        const reply = self.datagram.receive(
            self.datagram.ctx,
            io,
            request.reply,
            request.deadline_ms,
        ) catch |err| switch (err) {
            // The deadline arrived with nothing. The third answer; see the
            // module doc for why it is not one of the other two.
            error.Empty => return .{ .timeout = {} },
            else => |rest| return rest,
        };
        if (reply.from.order(self.server) != .eq) return error.ForeignSource;
        // A datagram that landed after the resolve was abandoned is nobody's
        // answer, and parsing it would make an abandoned resolve produce one.
        if (self.stopped) return error.Canceled;
        return readAnswer(alloc, reply.bytes, request.name, self.id, self.owner[0..]);
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
    if (self.stopped) return;
    self.stopped = true;
    self.datagram.stop(self.datagram.ctx);
}

/// What one `ask` writes, and how long it waits.
///
/// An options struct because two of these are the same type and a positional
/// list that long is a list nothing distinguishes. The buffers are the
/// caller's because a read buffer does not outlive the call and a query may be
/// longer than anything this file could own.
///
/// `ask` writes `wire` and `reply` on every call, so what either buffer holds is
/// meaningful after an ask that used it and only until the next one.
pub const Request = struct {
    /// The name asked about, in presentation form with its trailing dot.
    name: []const u8,
    /// Where the framed query goes before it is sent: `queryLength(name)`
    /// bytes. Written by `ask`, and what it held before is gone after one.
    wire: []u8,
    /// Where the datagram is read before it is parsed. `reply_length` bytes is
    /// what a peer that honours the advertised size can send. Written by `ask`,
    /// and a shorter datagram leaves the rest of it as it was — which is no
    /// problem, because a caller reads the parsed `Answer` and not this buffer.
    reply: []u8,
    /// How long one receive waits, in milliseconds, and null for as long as the
    /// caller means. Upstream gives each of its six staggered queries three
    /// seconds (`iroh/src/address_lookup/dns.rs:19`); the staggering is a policy
    /// and needs an instant, so only the per-query deadline is here.
    deadline_ms: ?i32,
};

const t = std.testing;
const key = @import("../base/key.zig");

/// The node `discovery/dns.zig` holds against upstream's own test.
const upstream_id = "1992d53c02cdc04566e5c0edb1ce83305cd550297953a047a445ea3264b54b18";

/// The name and the size the questions below are framed at.
const asked_len = dns.queryNameLength(dns.prod_origin);
const asked_bytes = queryLength("x" ** asked_len);

/// A datagram socket that answers from a script, which is how every test below
/// runs a whole lookup with no nameserver and no network.
///
/// `sent` keeps what the last `ask` put on the wire, so a test reads the bytes
/// that actually left rather than trusting that a function was called.
const Scripted = struct {
    sent: [asked_bytes]u8 = undefined,
    sent_len: usize = 0,
    sent_to: addr.SocketAddr = undefined,
    sends: u32 = 0,
    /// The answer the next `receive` hands back, or null for a socket that
    /// answers nothing.
    reply: ?[]u8 = null,
    /// Who the scripted answer comes from. Off the server by default, so a test
    /// has to name the server before a reply is acceptable.
    from: addr.SocketAddr,
    /// How many times the abort handle reached the socket.
    stops: u32 = 0,
    /// What the last `receive` was asked to wait for, so a test can read the
    /// deadline that was actually threaded down.
    deadline_ms: ?i32 = null,

    fn send(
        ctx: *anyopaque,
        // `ctx` is the vtable slot itself, not an ordinary parameter:
        // `Datagram.send` names it first and a reordered one is a different
        // function type. Z023 reads `*anyopaque` as a plain runtime value.
        // ziglint-ignore: Z023
        _: std.Io,
        to: addr.SocketAddr,
        bytes: []const u8,
    ) SocketError!void {
        const self: *Scripted = @ptrCast(@alignCast(ctx));
        if (bytes.len > self.sent.len) return error.Refused;
        @memcpy(self.sent[0..bytes.len], bytes);
        self.sent_len = bytes.len;
        self.sent_to = to;
        self.sends += 1;
    }

    fn receive(
        ctx: *anyopaque,
        // `ctx` is the vtable slot itself, not an ordinary parameter:
        // `Datagram.receive` names it first and a reordered one is a different
        // function type. Z023 reads `*anyopaque` as a plain runtime value.
        // ziglint-ignore: Z023
        _: std.Io,
        into: []u8,
        deadline_ms: ?i32,
    ) SocketError!Datagram.Reply {
        const self: *Scripted = @ptrCast(@alignCast(ctx));
        self.deadline_ms = deadline_ms;
        const answer = self.reply orelse return error.Empty;
        if (answer.len > into.len) return error.Refused;
        @memcpy(into[0..answer.len], answer);
        return .{ .bytes = into[0..answer.len], .from = self.from };
    }

    fn stop(ctx: *anyopaque) void {
        const self: *Scripted = @ptrCast(@alignCast(ctx));
        self.stops += 1;
        // What a real socket does: a datagram nobody will read is dropped, so
        // there is nothing left for a second receive to hand back either.
        self.reply = null;
    }

    fn datagram(self: *Scripted) Datagram {
        return .{
            .ctx = @ptrCast(@alignCast(self)),
            .send = send,
            .receive = receive,
            .stop = stop,
        };
    }
};

/// The server a scripted socket answers for, and a different one it answers
/// from, because a TXT answer is unsigned.
const nameserver: addr.SocketAddr = .{ .ip = .{ .v4 = .{ 127, 0, 0, 1 } }, .port = 53 };
const elsewhere: addr.SocketAddr = .{ .ip = .{ .v4 = .{ 127, 0, 0, 2 } }, .port = 53 };

/// An engine, so the transaction id is the same every run.
const Prng = std.Random.DefaultPrng;

// The section rule is 77 columns wide, which is the width this file is held
// to; Z024 counts UTF-8 bytes, and the box-drawing glyphs are three each.
// ziglint-ignore: Z024
// ────────────────────────────────────────────────────────────────── vectors

/// The query RFC 8484 §4.1.1 prints, byte for byte: an `IN A` question for
/// `www.example.com`, `ID` zero, no EDNS0. Thirty-three octets, which is
/// `queryLength` less the OPT record, and every octet of it is the RFC's.
const rfc8484_hex =
    "00000100000100000000000003777777076578616d706c6503636f6d0000010001";

/// The same section's second query, and the better of the two here: its label
/// is 62 octets, one under RFC 1035 §2.3.4's 63, so it pins the longest label
/// this encoder can be handed from a primary source rather than from a
/// boundary this file chose. Ninety-four octets, and `queryLength` over its
/// 77-character name comes to 94 less the OPT record — the same arithmetic the
/// first vector confirms, on a second name.
const rfc8484_long_hex =
    "00000100000100000000000001613e36326368617261637465726c6162656c2d" ++
    "6d616b65732d62617365363475726c2d64697374696e63742d66726f6d2d7374" ++
    "616e646172642d626173653634076578616d706c6503636f6d0000010001";

/// The DNS answer inside `discovery/pkarr.zig`'s `small_dns_hex`, which is the
/// body of a packet the `pkarr` crate v8.0.2 produced (`pubky/pkarr`
/// `pkarr/src/types/signed_packet.rs` at
/// aa4011cabc3676d533dd3c633dc0801c94bfca86). One TXT record under
/// `_iroh.<z32>`, TTL 30, holding one `relay=` record: a real answer from the
/// reference implementation, and not a hand-built one.
const captured_answer_hex =
    "000080000000000100000000055f69726f6834376a66676161396e75746a7969" ++
    "787a696b623774676d736639676b77713769717a3439387a72316e6435696731" ++
    "666e673465737900001000010000001e001b1a72656c61793d68747470733a2f" ++
    "2f6578616d706c652e636f6d2f";

/// The one record that answer carried, in `resolve.RecordSet`'s own shape.
const captured_record = "relay=https://example.com/\x00";

/// The seed that packet was signed with, and so the node its name is about.
const captured_seed = [_]u8{7} ** key.SecretKey.seed_length;

/// The name in `captured_answer_hex`: `_iroh.<z32>.` with no origin, which is
/// what a publisher signs for itself.
fn capturedName(secret: key.NodeId, out: []u8) []const u8 {
    const label = secret.toZ32();
    @memcpy(out[0..resolve.iroh_txt_name.len], resolve.iroh_txt_name);
    out[resolve.iroh_txt_name.len] = '.';
    @memcpy(out[resolve.iroh_txt_name.len + 1 ..][0..label.len], &label);
    out[resolve.iroh_txt_name.len + 1 + label.len] = '.';
    return out[0 .. resolve.iroh_txt_name.len + 2 + label.len];
}

fn hexBytes(out: []u8, hex: []const u8) ![]u8 {
    if (hex.len % 2 != 0) return error.OddHexLength;
    if (out.len < hex.len / 2) return error.BufferTooSmall;
    return std.fmt.hexToBytes(out[0 .. hex.len / 2], hex);
}

test "golden: a query is the RFC's own bytes" {
    const name = "www.example.com.";
    var out: [queryLength(name)]u8 = undefined;
    var expected: [reply_length]u8 = undefined;
    // `IN A`, so `QTYPE` is 1 and not this file's TXT default: the vector is
    // the RFC's own query and nothing about it is ours to change.
    const written = try writeQuery(name, .{ .id = 0, .qtype = 1 }, &out);
    try expectHex(try hexBytes(&expected, rfc8484_hex), written);
    try t.expectEqual(@as(usize, 33), written.len);

    // The long-label query, which is the same layout with a 62-octet label in
    // place of three three-octet ones.
    const long = "a.62characterlabel-makes-base64url-distinct-from-standard-" ++
        "base64.example.com.";
    var long_out: [queryLength(long)]u8 = undefined;
    var long_expected: [reply_length]u8 = undefined;
    const long_written = try writeQuery(long, .{ .id = 0, .qtype = 1 }, &long_out);
    try expectHex(try hexBytes(&long_expected, rfc8484_long_hex), long_written);
    try t.expectEqual(@as(usize, 94), long_written.len);
    // The same layout for the question this file actually asks, which differs
    // from the RFC's in two fields and two bytes of name: `ID` and `QTYPE`.
    var asked: [asked_len]u8 = undefined;
    const text = dns.queryName(&asked, try nodeOf(upstream_id), dns.prod_origin);
    var wire: [asked_bytes]u8 = undefined;
    const ask_wire = try writeQuery(text, .{ .id = 0x1234 }, &wire);
    try t.expectEqual(header_length + asked_len + 1 + question_length, ask_wire.len);
    try t.expectEqual(type_txt, be16(ask_wire, header_length + asked_len + 1));
    try t.expectEqual(class_in, be16(ask_wire, header_length + asked_len + 3));
    try t.expectEqual(@as(u16, 0), be16(ask_wire, 10));
}

test "the header is the one RFC 1035 draws, field by field" {
    var name: [asked_len]u8 = undefined;
    const text = dns.queryName(&name, try nodeOf(upstream_id), dns.prod_origin);
    // `discovery/dns.zig` holds this string against upstream's own test; here
    // it is the bytes that leave, which is a different claim.
    try t.expectEqualStrings(
        "_iroh.dgjpkxyn3zyrk3zfads5duwdgbqpkwbjxfj4yt7rezidr3fijccy.dns.iroh.link.",
        text,
    );

    var out: [asked_bytes]u8 = undefined;
    const wire = try writeQuery(text, .{
        .id = 0x1234,
        .udp_payload = max_udp_payload,
    }, &out);
    try t.expectEqual(@as(u16, 0x1234), be16(wire, 0));
    // `RD` alone: `QR` is 0 because this is a question and §4.1.1 requires the
    // three `Z` bits to be zero in all queries.
    try t.expectEqual(flag_recursion_desired, be16(wire, 2));
    try t.expectEqual(@as(u16, 1), be16(wire, 4));
    try t.expectEqual(@as(u16, 0), be16(wire, 6));
    try t.expectEqual(@as(u16, 0), be16(wire, 8));
    // One additional record, which is the OPT advertising what this node can
    // receive. Without it the limit is §4.2.1's 512 bytes.
    try t.expectEqual(@as(u16, 1), be16(wire, 10));
    try t.expectEqual(queryLength(text), wire.len);

    const opt = header_length + asked_len + 1 + question_length;
    try t.expectEqual(@as(u8, 0), wire[opt]);
    try t.expectEqual(type_opt, be16(wire, opt + 1));
    try t.expectEqual(max_udp_payload, be16(wire, opt + 3));
    // RFC 6891 §6.1.3 puts the version in the TTL's high byte and it is zero.
    try t.expectEqual(@as(u32, 0), be32(wire, opt + 5));
    try t.expectEqual(@as(u16, 0), be16(wire, opt + 9));

    // And the name that goes out reads back as the name that was asked for,
    // which is the round trip the answer decoder is asked to make.
    var owner: [max_name_length]u8 = undefined;
    const decoded = try readName(wire, header_length, &owner);
    try t.expectEqualStrings(text, owner[0..decoded.written]);
}

test "golden: a captured answer decodes into the records it carried" {
    var buffer: [reply_length]u8 = undefined;
    const answer = try hexBytes(&buffer, captured_answer_hex);

    var secret = try key.SecretKey.fromSeed(captured_seed);
    defer secret.deinit();
    var name: [max_name_length]u8 = undefined;
    const asked = capturedName(secret.nodeId(), &name);

    var owner: [max_name_length]u8 = undefined;
    const read = try readAnswer(t.allocator, answer, asked, 0, &owner);
    defer read.deinit(t.allocator);
    const records = switch (read) {
        .records => |set| set,
        else => return error.ExpectedRecords,
    };
    // The reference implementation's own record, with the character strings
    // inside one TXT record read as one value.
    try t.expectEqualStrings(captured_record, records.bytes);

    // The node the packet is about is the key that signed it, and the name the
    // answer was read under is that key's z32 — read back by the same parser
    // `discovery/dns.zig` uses on a record name.
    try t.expectEqual(secret.nodeId(), try dns.endpointIdFromName(asked));
}

test "a query is framed, sent, and its answer parsed, with no network" {
    var engine: Prng = Prng.init(7);
    var name: [asked_len]u8 = undefined;
    const text = dns.queryName(&name, try nodeOf(upstream_id), dns.prod_origin);

    var script: Scripted = .{ .from = nameserver };
    var retrieval = Retrieval.begin(script.datagram(), nameserver, engine.random());
    var wire: [asked_bytes]u8 = undefined;
    var reply: [reply_length]u8 = undefined;
    const request: Request = .{
        .name = text,
        .wire = &wire,
        .reply = &reply,
        .deadline_ms = 3000,
    };

    // Nothing answers yet, so this run observes the framing and the send.
    try t.expectEqual(Answer.timeout, retrieval.ask(t.allocator, t.io, request));
    try t.expectEqual(@as(u32, 1), script.sends);
    try t.expectEqual(nameserver, script.sent_to);
    try t.expectEqual(queryLength(text), script.sent_len);
    try t.expectEqual(@as(?i32, 3000), script.deadline_ms);
    try t.expectEqual(retrieval.id, be16(script.sent[0..], 0));
    try t.expectEqual(@as(u16, 1), be16(script.sent[0..], 10));
    try t.expectEqual(type_txt, be16(script.sent[0..], header_length + asked_len + 1));

    // The answer arrives. It is read under the name *it* was published for, and
    // the transaction id this retrieval drew, so the whole path — the ID from
    // the generator, the send, the receive, the header, the record walk, the
    // TXT read — runs against bytes the reference implementation produced.
    var sender = try key.SecretKey.fromSeed(captured_seed);
    defer sender.deinit();
    var published: [max_name_length]u8 = undefined;
    var scripted: [reply_length]u8 = undefined;
    script.reply = try hexBytes(&scripted, captured_answer_hex);
    // The captured answer answers transaction zero, and this retrieval drew its
    // own id: §4.1.1's `ID` is copied into the reply, so a real nameserver
    // echoes it and the vector has to be told what to echo.
    put16(script.reply.?, 0, retrieval.id);
    const read = try retrieval.ask(t.allocator, t.io, .{
        .name = capturedName(sender.nodeId(), &published),
        .wire = &wire,
        .reply = &reply,
        .deadline_ms = 3000,
    });
    defer read.deinit(t.allocator);
    try t.expect(read.hasRecords());

    // The records are this call's and not the read buffer's: overwriting every
    // byte the socket wrote leaves them reading the same. That is the fourth
    // of the seam's four things — an `Io` read buffer does not outlive the
    // call — proven rather than asserted.
    const records = switch (read) {
        .records => |set| set,
        else => return error.ExpectedRecords,
    };
    @memset(&reply, 0xaa);
    try t.expectEqualStrings(captured_record, records.bytes);
}

test "an abandoned resolve stops the query that was in flight" {
    var engine: Prng = Prng.init(9);
    var name: [asked_len]u8 = undefined;
    const text = dns.queryName(&name, try nodeOf(upstream_id), dns.prod_origin);
    var script: Scripted = .{ .from = nameserver };
    var retrieval = Retrieval.begin(script.datagram(), nameserver, engine.random());
    var wire: [asked_bytes]u8 = undefined;
    var reply: [reply_length]u8 = undefined;
    const request: Request = .{
        .name = text,
        .wire = &wire,
        .reply = &reply,
        .deadline_ms = 3000,
    };

    // A resolve whose query is now in flight and is about to be dropped.
    try t.expectEqual(Answer.timeout, retrieval.ask(t.allocator, t.io, request));
    try t.expectEqual(@as(u32, 1), script.sends);

    // `Stream.deinit` fires it, and the abort reaches the socket rather than a
    // flag this test already owns: `stops` is the socket's own count.
    var cancellation = retrieval.cancellation();
    cancellation.fire();
    try t.expectEqual(@as(u32, 1), script.stops);
    try t.expect(retrieval.stopped);

    // A second fire is free, because `deinit` fires on every path out of a
    // resolve including the ones with nothing in flight.
    cancellation.fire();
    try t.expectEqual(@as(u32, 1), script.stops);

    // And nothing more goes out: an abandoned resolve cannot leave a query
    // pending, which is the whole of what `resolve.Cancellation` is for.
    try t.expectError(error.Canceled, retrieval.ask(t.allocator, t.io, request));
    try t.expectEqual(@as(u32, 1), script.sends);
}

test "a lookup that got no answer in time is not a node that published nothing" {
    var engine: Prng = Prng.init(11);
    var name: [asked_len]u8 = undefined;
    const text = dns.queryName(&name, try nodeOf(upstream_id), dns.prod_origin);
    var script: Scripted = .{ .from = nameserver };
    var retrieval = Retrieval.begin(script.datagram(), nameserver, engine.random());
    var wire: [asked_bytes]u8 = undefined;
    var reply: [reply_length]u8 = undefined;

    // Nothing answered inside the deadline.
    const late = try retrieval.ask(t.allocator, t.io, .{
        .name = text,
        .wire = &wire,
        .reply = &reply,
        .deadline_ms = 1,
    });
    try t.expectEqual(Answer.timeout, late);
    try t.expect(!late.hasRecords());
    try t.expectEqual(@as(?i32, 1), script.deadline_ms);

    // The name exists and carries nothing, which is a fact about the world and
    // a different one: a header with no records at all.
    var empty: [header_length]u8 = @splat(0);
    put16(&empty, 0, retrieval.id);
    put16(&empty, 2, flag_response);
    var owner: [max_name_length]u8 = undefined;
    const nothing = try readAnswer(t.allocator, &empty, text, retrieval.id, &owner);
    try t.expectEqual(Answer.nothing, nothing);

    // A third answer, and it is an error: `NXDOMAIN` says the name was never
    // published, which upstream reports rather than answering empty.
    put16(&empty, 2, flag_response | 3);
    try t.expectError(error.NameError, readAnswer(t.allocator, &empty, text, retrieval.id, &owner));

    // The three are three. A caller that read a timeout as `nothing` would tell
    // the world this node published nothing, having learned nothing at all.
    try t.expectEqual(.timeout, std.meta.activeTag(late));
    try t.expectEqual(.nothing, std.meta.activeTag(nothing));
    try t.expect(!late.hasRecords());
}

test "a datagram that is not this question's answer is refused" {
    var buffer: [reply_length]u8 = undefined;
    const answer = try hexBytes(&buffer, captured_answer_hex);
    var secret = try key.SecretKey.fromSeed(captured_seed);
    defer secret.deinit();
    var name: [max_name_length]u8 = undefined;
    const asked = capturedName(secret.nodeId(), &name);
    var owner: [max_name_length]u8 = undefined;

    // Another query's transaction, which RFC 1035 §4.1.1's `ID` exists to
    // catch: the answer is real and it is not ours.
    try t.expectError(
        error.ForeignTransaction,
        readAnswer(t.allocator, answer, asked, 1, &owner),
    );

    // This one's own transaction, read against a name it is not about: the
    // records are not silently attributed to a node that never published them.
    var other: [max_name_length]u8 = @splat('x');
    other[0] = '_';
    const wrong = try readAnswer(
        t.allocator,
        answer,
        other[0..asked.len],
        0,
        &owner,
    );
    defer wrong.deinit(t.allocator);
    try t.expectEqual(Answer.nothing, wrong);

    // A question arriving where an answer was wanted.
    var query: [header_length]u8 = @splat(0);
    put16(&query, 4, 1);
    try t.expectError(error.NotAResponse, readAnswer(t.allocator, &query, asked, 0, &owner));

    // An answer that did not fit its datagram, which is the one a TCP retry
    // would be for.
    var cut: [reply_length]u8 = undefined;
    const truncated = try hexBytes(&cut, captured_answer_hex);
    put16(truncated[0..], 2, flag_response | flag_truncated);
    try t.expectError(error.Truncated, readAnswer(t.allocator, truncated[0..], asked, 0, &owner));
}

test "an answer from somewhere else is not this query's answer" {
    var engine: Prng = Prng.init(13);
    var script: Scripted = .{ .from = elsewhere };
    var retrieval = Retrieval.begin(script.datagram(), nameserver, engine.random());
    var wire: [asked_bytes]u8 = undefined;
    var reply: [reply_length]u8 = undefined;
    var scripted: [reply_length]u8 = undefined;
    var secret = try key.SecretKey.fromSeed(captured_seed);
    defer secret.deinit();
    var published: [max_name_length]u8 = undefined;
    script.reply = try hexBytes(&scripted, captured_answer_hex);

    // A TXT answer carries no signature, so the source address is the only
    // thing telling this datagram from a forged one. A datagram off the queried
    // server is refused even though it echoes the right transaction id.
    try t.expectError(error.ForeignSource, retrieval.ask(t.allocator, t.io, .{
        .name = capturedName(secret.nodeId(), &published),
        .wire = &wire,
        .reply = &reply,
        .deadline_ms = 3000,
    }));
    try t.expectEqual(@as(u32, 1), script.sends);
}

test "every response code is named, and a name that loops is refused" {
    const name = "_iroh.example.";
    var owner: [max_name_length]u8 = undefined;
    var message: [header_length]u8 = @splat(0);

    // RFC 1035 §4.1.1's six codes, each with the answer this file gives rather
    // than one generic "no", which is the point of naming them.
    const cases = [_]struct { code: u16, expect: ?anyerror }{
        .{ .code = 0, .expect = null },
        .{ .code = 1, .expect = error.MalformedResponse },
        .{ .code = 2, .expect = error.ServiceFailure },
        .{ .code = 3, .expect = error.NameError },
        .{ .code = 4, .expect = error.Unimplemented },
        .{ .code = 5, .expect = error.ServiceRefused },
    };
    inline for (cases) |case| {
        put16(&message, 2, flag_response | case.code);
        const read = readAnswer(t.allocator, &message, name, 0, &owner);
        if (case.expect) |wanted| {
            try t.expectError(wanted, read);
        } else {
            try t.expectEqual(Answer.nothing, try read);
        }
    }
    // And the reserved range above them, which is not "no error".
    for (6..16) |code| {
        put16(&message, 2, flag_response | @as(u16, @intCast(code)));
        try t.expectError(
            error.UnknownResponseCode,
            readAnswer(t.allocator, &message, name, 0, &owner),
        );
    }

    // A name whose pointer points forward can never end, so §4.1.4's "prior
    // occurrence" is checked rather than followed. Every other encoding of the
    // two high bits is reserved and has no length to read.
    var looping: [header_length + 2]u8 = @splat(0);
    put16(&looping, 0, 0);
    put16(&looping, 2, flag_response);
    put16(&looping, 6, 1);
    const at = header_length;
    const alias = looping[0 .. header_length + 2];
    looping[at] = name_pointer;
    looping[at + 1] = @intCast(at);
    try t.expectError(error.BadName, readAnswer(t.allocator, alias, name, 0, &owner));
    looping[at] = 0x40;
    try t.expectError(error.BadName, readAnswer(t.allocator, alias, name, 0, &owner));
    looping[at] = 0x80;
    try t.expectError(error.BadName, readAnswer(t.allocator, alias, name, 0, &owner));

    // A message cut short inside a record is refused rather than read past.
    var cut: [header_length + 4]u8 = @splat(0);
    put16(&cut, 0, 0);
    put16(&cut, 2, flag_response);
    put16(&cut, 6, 1);
    cut[header_length] = 0;
    try t.expectError(
        error.ShortMessage,
        readAnswer(t.allocator, cut[0 .. at + 4], name, 0, &owner),
    );
    try t.expectError(error.ShortMessage, readAnswer(t.allocator, cut[0..4], name, 0, &owner));

    // A count a 64-octet message cannot hold is a header to refuse, not a loop.
    put16(&cut, 2, flag_response);
    put16(&cut, 6, max_section_records + 1);
    try t.expectError(
        error.ShortMessage,
        readAnswer(t.allocator, cut[0 .. at + 4], name, 0, &owner),
    );
}

test "a compression pointer is followed and a bad one is refused" {
    // RFC 1035 §4.1.4's own example: the name `F.ISI.ARPA` written out, and
    // `FOO.F.ISI.ARPA` written as one label and a pointer back to it. A reader
    // has to expand the alias to the name the writer meant, and the pointer is
    // the whole difficulty. Here the pointed-at name is the question, which is
    // where a real answer keeps it.
    var message: [64]u8 = @splat(0);
    put16(&message, 0, 0);
    put16(&message, 2, flag_response);
    put16(&message, 4, 1);
    put16(&message, 6, 1);
    var at: usize = question_at;
    var labels = std.mem.splitScalar(u8, spelled, '.');
    while (labels.next()) |label| {
        if (label.len == 0) continue;
        message[at] = @intCast(label.len);
        @memcpy(message[at + 1 ..][0..label.len], label);
        at += 1 + label.len;
    }
    message[at] = 0;
    at += 1;
    put16(&message, at, type_txt);
    put16(&message, at + 2, class_in);
    at += question_length;
    try t.expectEqual(alias_at, at);

    // One label and the pointer, which is the whole of §4.1.4's alias.
    message[at] = 3;
    @memcpy(message[at + 1 ..][0..3], "foo");
    at += 4;
    message[at] = name_pointer;
    message[at + 1] = @intCast(question_at);
    at += 2;
    put16(&message, at, type_txt);
    put16(&message, at + 2, class_in);
    put32(&message, at + 4, 30);
    put16(&message, at + 8, 4);
    at += 10;
    message[at] = 3;
    @memcpy(message[at + 1 ..][0..3], "bar");
    at += 4;

    var owner: [max_name_length]u8 = undefined;
    const decoded = try readName(message[0 .. alias_at + 6], alias_at, &owner);
    try t.expectEqualStrings("foo.f.isi.arpa.", owner[0..decoded.written]);
    // The name ends after the two pointer octets, which is where the record's
    // `TYPE` starts — and getting that wrong is how a parser reads a type out
    // of a pointer.
    try t.expectEqual(alias_at + 6, decoded.end);

    // And the whole message reads: past the pointer, through the names it
    // expands to, and into the record the pointer stands in for.
    const read = try readAnswer(t.allocator, message[0..at], "foo.f.isi.arpa.", 0, &owner);
    defer read.deinit(t.allocator);
    try t.expectEqualStrings("bar\x00", switch (read) {
        .records => |set| set.bytes,
        else => return error.ExpectedRecords,
    });

    // A pointer past the message, and one that points at itself.
    var bad: [header_length + 2]u8 = undefined;
    bad[header_length] = name_pointer;
    bad[header_length + 1] = 200;
    try t.expectError(error.BadName, readName(&bad, header_length, &owner));
    bad[header_length + 1] = 0;
    try t.expectError(error.BadName, readName(&bad, header_length, &owner));
    // A label whose length runs past the message.
    var cut: [header_length + 2]u8 = @splat(0);
    cut[header_length] = 40;
    try t.expectError(
        error.ShortMessage,
        readName(cut[0 .. header_length + 2], header_length, &owner),
    );
    // A pointer with no second octet at all.
    var lone: [header_length + 1]u8 = @splat(0);
    lone[header_length] = name_pointer;
    try t.expectError(error.ShortMessage, readName(&lone, header_length, &owner));
}

/// The name RFC 1035 §4.1.4's example writes out, and where this message keeps
/// it: as the question, which is where a real answer points back at.
const spelled = "f.isi.arpa.";
const question_at = header_length;
const alias_at = question_at + spelled.len + 1 + question_length;

test "a name has to be a name" {
    var out: [asked_bytes]u8 = undefined;
    try t.expectError(error.UnterminatedName, writeQuery("example.com", .{ .id = 0 }, &out));
    try t.expectError(error.EmptyLabel, writeQuery("a..b.", .{ .id = 0 }, &out));
    try t.expectError(error.BufferTooSmall, writeQuery("a.b.", .{ .id = 0 }, out[0..4]));
    // 63 octets is RFC 1035 §2.3.4's cap and one more is refused: a length
    // octet over 63 is indistinguishable from a pointer's first octet.
    _ = try writeQuery("a." ++ "x" ** max_label_length ++ ".example.com.", .{ .id = 0 }, &out);
    try t.expectError(
        error.LabelTooLong,
        writeQuery("a." ++ "x" ** (max_label_length + 1) ++ ".example.com.", .{ .id = 0 }, &out),
    );
    // The root, and nothing else: one zero octet, and a name of zero characters
    // is still a name. It comes in under `queryLength`, which is a bound.
    const root = try writeQuery(".", .{ .id = 7 }, &out);
    try t.expectEqual(header_length + question_length + 1, root.len);
    try t.expectEqual(@as(u8, 0), root[header_length]);
    try t.expect(root.len < queryLength("."));
    try t.expectEqual(@as(usize, 32), queryLength("a.b."));
}

/// The node a wire vector is about, from the hex constant the vector names.
/// Fallible: a literal that is not a canonical curve point is a typo in the
/// vector, and the test that carries it should say so rather than take the
/// process down on the way to saying anything at all.
fn nodeOf(hex: []const u8) key.KeyError!key.NodeId {
    return key.NodeId.parseHex(hex);
}

fn expectHex(expected: []const u8, actual: []const u8) !void {
    if (std.mem.eql(u8, expected, actual)) return;
    var buffer: [dump_bytes]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    // `std`'s formatter rather than a hand-rolled dump: this only runs when a
    // wire vector has moved, and what a reader needs then is the bytes.
    writer.print("expected {d}: {x}\n     got {d}: {x}\n", .{
        expected.len,
        expected[0..@min(expected.len, max_dumped_bytes)],
        actual.len,
        actual[0..@min(actual.len, max_dumped_bytes)],
    }) catch return error.WireFormatMismatch;
    std.debug.print("{s}", .{writer.buffered()});
    return error.WireFormatMismatch;
}

/// How much of a mismatch is printed, and the buffer it is printed into.
const max_dumped_bytes = 48;
const dump_bytes = 2 * (4 + 2 * max_dumped_bytes) + 8;
