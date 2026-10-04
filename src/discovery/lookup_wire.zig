//! RFC 1035's query side: the constants, the name encoder, and the one
//! function that frames a question.
//!
//! Pure, and separate from the transport because `docs/ARCHITECTURE.md` says
//! wire codecs are. That is the same constraint `discovery/lookup_io.zig`'s
//! module doc argues for the seam existing at all: a codec is a pair of
//! functions over a buffer, and the socket the query will go out on is
//! somebody else's. Nothing here opens one, and nothing here reads a clock,
//! keeps a global, or allocates.
//!
//! # What is here, and what is not
//!
//! Here: `writeQuery`, `queryLength`, `Query`, the wire's own constants, and
//! `WireError`. Reading an answer back is `discovery/lookup_answer.zig`; the
//! socket a query goes out on is `discovery/lookup_io.zig`'s `Datagram`.
//!
//! `error.ForeignSource` is the one arm of `WireError` this module cannot
//! produce, because who sent a datagram is not in its bytes. A TXT answer
//! carries no signature, so the source address is the only thing standing
//! between a lookup and a forged one, and `Retrieval.ask` is what compares it
//! before a reply is read at all.
//!
//! # Why the encoded name carries no pointer
//!
//! No pointers are written, which RFC 1035 §4.1.4 permits — "Programs are free
//! to avoid using pointers in messages they generate" — and which keeps
//! `writeQuery` free of the offset bookkeeping a pointer needs. A reader has to
//! understand them either way, because every implementation must; see
//! `discovery/lookup_answer.zig`.
//!
//! # The bounds here are the RFC's
//!
//! Every check is against one of `max_label_length`, `max_name_length`,
//! `max_section_records` or `max_udp_payload`, and each of those cites the
//! section that sets it rather than a number chosen here.

const std = @import("std");

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
pub const rcode_bits: u16 = 0x000f;

/// A label, or the reserved encoding that is neither.
pub const name_label: u8 = 0x00;

/// A compression pointer. RFC 1035 §4.1.4 spells it `11` in the top two bits
/// and an offset in the low fourteen.
pub const name_pointer: u8 = 0xc0;

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
pub const question_length = 4;

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

/// One big-endian `u16` at `at`, read without a bounds check because every
/// caller has already checked the field it is reading.
///
/// Published rather than kept private because the answer decoder reads the same
/// fields, and one definition of the byte order is what stops two decoders
/// disagreeing about a message.
pub fn be16(bytes: []const u8, at: usize) u16 {
    return std.mem.readInt(u16, bytes[at..][0..2], .big);
}

/// One big-endian `u32` at `at`, for the same reason as `be16`.
pub fn be32(bytes: []const u8, at: usize) u32 {
    return std.mem.readInt(u32, bytes[at..][0..4], .big);
}

/// One big-endian `u16` written at `at`. No `WireError`, because every caller
/// bounds-checks the whole frame before it starts writing.
pub fn put16(bytes: []u8, at: usize, value: u16) void {
    std.mem.writeInt(u16, bytes[at..][0..2], value, .big);
}

/// One big-endian `u32` written at `at`, for the same reason as `put16`.
pub fn put32(bytes: []u8, at: usize, value: u32) void {
    std.mem.writeInt(u32, bytes[at..][0..4], value, .big);
}
