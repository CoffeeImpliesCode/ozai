//! The RFC 1035 vocabulary one lookup shares with itself: the header's
//! constants, the two byte orders, and `WireError`, the one failure set both
//! the framer and the answer decoder name.
//!
//! Nothing here frames a message or reads one. `lookup_query.zig` writes with
//! these names, `lookup_name.zig` encodes and decodes a name in them, and
//! `lookup_answer.zig` walks a message with them. `lookup_io.zig` is the
//! facade, and its module doc is the argument for the whole seam.

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

/// A label's maximum length. RFC 1035 §2.3.4.
pub const max_label_length = 63;

/// A name's maximum length, in presentation characters. RFC 1035 §2.3.4 caps
/// the *wire* form at 255 octets, which is 254 characters plus the terminating
/// dot, so 256 is the bound rather than a guess.
pub const max_name_length = 256;

/// What a query advertises it can receive, as RFC 6891 §6.2.3's `CLASS`.
///
/// 1232, because that is the figure DNS Flag Day 2020 settled on and it sits
/// inside RFC 6891 §6.2.5's 512..4096 range with room for the headers a path
/// adds. With nothing advertised the limit is RFC 1035 §4.2.1's 512, which an
/// `_iroh` answer outgrows — see `lookup_io.zig`'s module doc.
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
    /// it is somewhere a datagram socket cannot reach. See `lookup_io.zig`'s
    /// module doc.
    Truncated,
};

pub fn be16(bytes: []const u8, at: usize) u16 {
    return std.mem.readInt(u16, bytes[at..][0..2], .big);
}

pub fn be32(bytes: []const u8, at: usize) u32 {
    return std.mem.readInt(u32, bytes[at..][0..4], .big);
}

pub fn put16(bytes: []u8, at: usize, value: u16) void {
    std.mem.writeInt(u16, bytes[at..][0..2], value, .big);
}

pub fn put32(bytes: []u8, at: usize, value: u32) void {
    std.mem.writeInt(u32, bytes[at..][0..4], value, .big);
}