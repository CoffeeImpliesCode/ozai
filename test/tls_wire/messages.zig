//! An independent oracle for the TLS messages that carry a certificate, a
//! name or a certificate type: RFC 8446 §4.4.2's Certificate list, §4.3.2's
//! CertificateRequest, RFC 6066 §3's `server_name`, RFC 7250 §3's two
//! certificate-type extensions, and the requests this build emits.
//!
//! **What is under test.** `parseCertificateList`, `parseCertificateRequest`,
//! `buildCertificateRequest`, `parseServerNameExtension`,
//! `parseCertificateTypeOffer`, `parseCertificateTypeSelection`,
//! `encodeCertificateTypeOffer` and `encodeCertificateTypeSelection` — all
//! `pub`, all reached here. The extension walk the handshake performs over a
//! ClientHello lives in `hello.zig`, which uses this file's `server_name`
//! verdict as its own precondition rather than re-deciding it.
//!
//! **Why these are worth a boundary each.** All five take a length a peer
//! chose, and every one of those lengths can disagree with the message around
//! it: a `certificate_list` that does not close its own message, an empty
//! `cert_data`, a `ServerNameList` of length zero, a second `host_name` entry,
//! a certificate-type count that does not close its own body.
//! RFC 8446 §4.2 makes every one of those `decode_error` and §4.4.2 makes a
//! non-empty `certificate_request_context` an `illegal_parameter`, so the
//! refusal is a specified alert rather than a shrug — which is exactly what an
//! oracle can check.
//!
//! **Why the certificate-type extensions are here and not there.** They are
//! the one pair whose refusal is decided *outside* the grammar — an offer that
//! is well formed and names nothing in common is RFC 7250 §4.2's
//! `unsupported_certificate`, not a decode error — and the walk that reaches
//! that decision is a ClientHello walk. What belongs to this file is
//! everything up to that point: the two payloads' shapes, their encoders, and
//! whether what comes out can be read back as what went in.
//!
//! **Where the reference stops and where it refuses.** Every walk here refuses
//! exactly where the decoder under it refuses: a certificate `extensions` block
//! that runs past its message, an extension header that does not close a
//! `CertificateRequest`, a `signature_algorithms` body that is not a whole list
//! of pairs. The one walk in this family that *stops* rather than refusing is
//! the ClientHello's, and it lives in `hello.zig` because that is where the
//! parser it mirrors is; a stack that tightened it would be a finding to
//! report, not one this file may assert.
//!
//! **The chain bound is a caller's, and this file picks one.** `out` is where
//! `parseCertificateList` writes and its length is the caller's bound on chain
//! depth — RFC 8446 §4.4.2's answer to an over-long chain is that bound being
//! reached, not a claim that the chain is bad. Two entries is the shape a real
//! chain has (leaf and issuer), so an input carrying a third exercises
//! `BadCertificate` rather than reaching a bound of four that nothing would
//! ever meet. It is a two-element stack value: every decoder here returns
//! slices borrowed from the caller's own bytes and allocates nothing, so
//! nothing in this file's interface needs an allocator to be threaded.
//!
//! Nothing here reads a clock, an `std.Io`, a global or a source file. The
//! references are written from the four RFCs named above; the error tags they
//! return are RFC 8446 §4.2's *alert* names, which the decoders also use.

const std = @import("std");
const tls13 = @import("quic").tls13;
const err = @import("der.zig");

pub const Error = err.Error;

/// The chain depth this file asks for. See the module doc: two is a real
/// chain, and it is what makes `BadCertificate` reachable.
const chain_bound = 2;

/// What a caller that never wrote to `out` is left holding, so "the decoder
/// wrote nothing past here" is checkable rather than assumed.
const untouched = "untouched";

/// A big-endian u16 read off two bytes the reference has already bounds
/// checked, written out rather than reached for so the reference does not
/// depend on which `std.mem` signature the toolchain has.
fn be16(b: []const u8) u16 {
    return @as(u16, b[0]) << 8 | b[1];
}

/// Whether `slice` is a window into `d` rather than bytes of its own: every
/// decoder here borrows what it parsed, so a slice a caller keeps has to point
/// inside the peer's own message — and inside it whole, or a window running
/// past the end would pass.
fn borrowedFrom(d: []const u8, slice: []const u8) bool {
    if (slice.len > d.len) return false;
    const base = @intFromPtr(d.ptr);
    const at = @intFromPtr(slice.ptr);
    return at >= base and at - base <= d.len - slice.len;
}

/// What one walk of RFC 8446 §4.2's `Extension extensions<0..2^16-1>`
/// establishes: the `signature_algorithms` list body the message carried, and
/// whether it carried one at all. A second occurrence and a body that is not a
/// whole list of pairs are refusals rather than a count, because §4.3.2 makes
/// each of them its own alert and this walk has to name the same one the
/// decoder names.
const Scan = struct {
    found: bool = false,
    body: []const u8 = &.{},
};

/// The walk, refusing where the decoder refuses: an extension header that does
/// not close the block is `decode_error` rather than a walk that stops, and a
/// `signature_algorithms` body is judged where it is met rather than after the
/// whole block — otherwise a malformed first one followed by a second would be
/// reported as the duplicate instead of as the malformed body it is.
fn scanExtensions(block: []const u8) error{ DecodeError, IllegalParameter }!Scan {
    const sig_algs: u16 = @intFromEnum(std.crypto.tls.ExtensionType.signature_algorithms);
    var s: Scan = .{};
    var p: usize = 0;
    while (p < block.len) {
        if (p + 4 > block.len) return error.DecodeError;
        const kind = be16(block[p..]);
        const len = be16(block[p + 2 ..]);
        p += 4;
        if (p + len > block.len) return error.DecodeError;
        const data = block[p..][0..len];
        p += len;
        if (kind != sig_algs) continue;
        // §4.3.2 makes the extension mandatory and singular, so a second one is
        // `illegal_parameter`; §4.2.3 makes the body a length over two-octet
        // schemes, and anything else is `decode_error`.
        if (s.found) return error.IllegalParameter;
        if (data.len < 2 or @as(usize, be16(data)) + 2 != data.len or data.len % 2 != 0) {
            return error.DecodeError;
        }
        s.body = data[2..];
        s.found = true;
    }
    return s;
}

/// RFC 8446 §4.3.2 plus §4.4.2:
///     struct { opaque certificate_request_context<0..2^8-1>;
///               Extension extensions<0..2^16-1>; } CertificateRequest;
/// with the context empty — this stack never does post-handshake
/// authentication — and a `signature_algorithms` list that is mandatory, once,
/// and of even length under a length that closes its own extension.
fn refCertificateRequest(d: []const u8) error{ DecodeError, MissingExtension, IllegalParameter }![]const u8 {
    if (d.len < 1) return error.DecodeError;
    if (d[0] != 0) return error.IllegalParameter;
    if (d.len < 3) return error.DecodeError;
    // §4.2's `Extension extensions<0..2^16-1>` is measured against a byte
    // count, so the peer's length is read as a `usize`: a peer that writes
    // `ff ff` names a block longer than any buffer, and adding three to it in
    // a `u16` would overflow before the comparison could answer that.
    const exts_len: usize = be16(d[1..]);
    if (3 + exts_len != d.len) return error.DecodeError;
    const s = try scanExtensions(d[3..]);
    // §4.3.2 makes the extension mandatory, so a well-formed request carrying
    // none is `missing_extension` and not a decode of an empty list.
    if (!s.found) return error.MissingExtension;
    return s.body;
}

/// RFC 8446 §4.4.2:
///     struct { opaque certificate_request_context<0..2^8-1>;
///               CertificateEntry certificate_list<0..2^24-1>; } Certificate;
///     struct { opaque cert_data<1..2^24-1>;
///               Extension extensions<0..2^16-1>; } CertificateEntry;
/// A `cert_data` is never empty — RFC 8446 §4.4.2's own minimum is one byte and
/// a zero-length one would be a certificate with nothing in it. The first
/// `chain_bound` entries are written into `want` and their count returned; the
/// bound is reached as `error.BadCertificate`, which is the caller's bound and
/// not a claim about the chain.
fn refCertificateList(d: []const u8, want: [][]const u8) error{ DecodeError, IllegalParameter, BadCertificate }!usize {
    if (d.len < 4) return error.DecodeError;
    if (d[0] != 0) return error.IllegalParameter;
    const list_len = std.mem.readInt(u24, d[1..4], .big);
    if (4 + @as(usize, list_len) != d.len) return error.DecodeError;
    var p: usize = 4;
    var n: usize = 0;
    while (p < d.len) {
        if (p + 3 > d.len) return error.DecodeError;
        const len = std.mem.readInt(u24, d[p..][0..3], .big);
        p += 3;
        if (len == 0 or p + len + 2 > d.len) return error.DecodeError;
        if (n == want.len) return error.BadCertificate;
        want[n] = d[p..][0..len];
        n += 1;
        p += len;
        const ext_len = be16(d[p..]);
        p += 2;
        if (p + ext_len > d.len) return error.DecodeError;
        p += ext_len;
    }
    return n;
}

/// RFC 6066 §3:
///     ServerNameList server_name_list<2..2^16-1>;
///     struct { NameType name_type; select (name_type) { host_name(0): ... }
///              opaque host_name<1..2^16-1>; } ServerName;
/// So the list is never empty, it closes the extension exactly, at most one
/// `host_name` appears, and it is never a zero-length one. Other name types are
/// defined for uses this stack has none, so they are walked past, and a list
/// with none of them is a well-formed answer meaning "no name" rather than a
/// refusal.
fn refServerName(d: []const u8) error{DecodeError}!?[]const u8 {
    if (d.len < 2) return error.DecodeError;
    // Widened for the same reason as above: `list_len + 2` in a `u16` would
    // overflow on a peer that wrote `ff ff` rather than answer `decode_error`.
    const list_len: usize = be16(d);
    if (list_len == 0 or 2 + list_len != d.len) return error.DecodeError;
    var p: usize = 2;
    var host: ?[]const u8 = null;
    while (p < d.len) {
        if (p + 3 > d.len) return error.DecodeError;
        const kind = d[p];
        const len = be16(d[p + 1 ..]);
        p += 3;
        if (p + len > d.len) return error.DecodeError;
        if (kind == 0) {
            if (host != null or len == 0) return error.DecodeError;
            host = d[p..][0..len];
        }
        p += len;
    }
    return host;
}

/// RFC 7250 §3, read from the RFC and not from the decoder beside it:
///
///     CertificateType client_certificate_types<1..2^8-1>;  // a ClientHello
///     CertificateType client_certificate_type;            // a server's answer
///
/// The first is a one-byte count followed by that many one-byte types, and
/// the count is the vector's own length; the second is a bare `CertificateType`
/// with no count in front of it, because §4.2 says "only a single value is
/// permitted in the server_certificate_type extension when carried in the
/// server hello". A zero count is not an offer of nothing — the vector's own
/// minimum is one — and a value outside the IANA registry is a field this
/// build cannot decode rather than a type it decided against.
fn refCertificateTypeOffer(d: []const u8) ?[]const u8 {
    if (d.len < 2) return null;
    // Widened before the addition: in a `u8` a peer writing `ff` would overflow
    // the count instead of earning the decode_error its length does.
    const count: usize = d[0];
    if (count == 0 or count + 1 != d.len) return null;
    return d[1..];
}

/// The same RFC's bare `CertificateType`: one byte naming one of the four
/// values the registry holds from RFC 5246 and RFC 7250.
fn refCertificateTypeSelection(d: []const u8) ?tls13.CertificateType {
    if (d.len != 1) return null;
    return switch (d[0]) {
        0 => .x509,
        1 => .open_pgp_cert,
        2 => .raw_public_key,
        3 => .generic_cert,
        else => null,
    };
}

/// The whole of the registry, so both decoders are asked about every value
/// rather than only the one this build negotiates — and so `offerContains` has
/// a case where the answer has to be no.
const certificate_types = [_]tls13.CertificateType{
    .x509,
    .open_pgp_cert,
    .raw_public_key,
    .generic_cert,
};

/// A type from the same registry that is not `kind`.
fn otherThan(kind: tls13.CertificateType) tls13.CertificateType {
    return switch (kind) {
        .x509 => .generic_cert,
        .open_pgp_cert => .raw_public_key,
        .raw_public_key => .open_pgp_cert,
        .generic_cert => .x509,
    };
}

/// RFC 7250 §3's own shapes, written out here rather than left to the fuzzer
/// to stumble into: an offer of one type, an offer of several in preference
/// order, a count that does not close its own body, a count of zero, a
/// selection, a value outside the registry, and a list where the grammar
/// allows one value. What the RFC owes each is written next to it, and a body
/// it has no shape for is named as such rather than left to a fuzzer.
///
/// The two roles are answered separately because they are separate
/// declarations and a body can be one without being the other. §3 writes
/// `CertificateType client_certificate_types<1..2^8-1>` as a count in front
/// of the list and `CertificateType client_certificate_type` as a bare byte
/// with no count in front of it, because §4.2 says "only a single value is
/// permitted in the server_certificate_type extension when carried in the
/// server hello". So a count of zero is no offer at all and yet is a whole
/// selection of `x509`, and `{1, 2}` is a whole offer that no selection
/// grammar has a shape for. One classification per body can say neither, and
/// asking it to would hold both decoders to the same verdict about two
/// different structures.
const certificate_type_shapes = [_]struct {
    body: []const u8,
    /// Whether the body is §3's list form: a one-byte count and that many
    /// one-byte types.
    offer: bool,
    /// Whether the body is §3's bare form: one byte naming one type, with
    /// no count in front of it.
    selection: bool,
}{
    // §4.1: "a list containing a single element" is one type, and three is
    // three in the client's preference order. Each carries a count, so none of
    // them is the bare byte §4.2 permits in a selection.
    .{ .body = &.{ 1, 0 }, .offer = true, .selection = false },
    .{ .body = &.{ 1, 2 }, .offer = true, .selection = false },
    .{ .body = &.{ 3, 0, 2, 1 }, .offer = true, .selection = false },
    .{ .body = &.{ 2, 2, 2 }, .offer = true, .selection = false },
    // The count is the vector's own length and its minimum is one, so a zero
    // in front is not an offer of nothing — a body this grammar has no shape
    // for. The same byte is a whole selection of `x509`, and the byte after
    // it is a whole selection of `raw_public_key`: this is the pair the two
    // roles disagree on, neither of them an offer.
    .{ .body = &.{0}, .offer = false, .selection = true },
    .{ .body = &.{2}, .offer = false, .selection = true },
    // A count that does not close its own body, and a count that leaves a
    // byte past the types it counted. Neither is an offer, and both are longer
    // than the single byte a selection allows.
    .{ .body = &.{ 2, 2 }, .offer = false, .selection = false },
    .{ .body = &.{ 1, 2, 0 }, .offer = false, .selection = false },
    // A value the IANA registry does not hold: a field this build cannot
    // decode rather than a type it decided against, so neither role reads it
    // even though it is one byte long.
    .{ .body = &.{4}, .offer = false, .selection = false },
    // A body with nothing in it: below the list's own minimum of one, and
    // short of the byte a selection is made of.
    .{ .body = &.{}, .offer = false, .selection = false },
};

/// The two decoders against the table above, each asked only about its own
/// role: an offer is the offered types themselves, borrowed, and a body the
/// table does not call an offer is a `DecodeError` for the reason the table
/// gives — never a different one. The selection half of the same loop reads
/// its own column and owes the same of it, so neither verdict is read off
/// the other.
fn certificateTypeShapes() Error!void {
    for (certificate_type_shapes) |vector| {
        if (vector.offer) {
            const parsed = tls13.parseCertificateTypeOffer(vector.body) catch
                return error.TestUnexpectedError;
            const owed = refCertificateTypeOffer(vector.body) orelse
                return error.TestUnexpectedResult;
            if (!std.mem.eql(u8, parsed, owed)) return error.TestExpectedEqual;
            if (!borrowedFrom(vector.body, parsed)) return error.TestExpectedEqual;
        } else if (tls13.parseCertificateTypeOffer(vector.body)) |_| {
            return error.TestExpectedEqual;
        } else |actual| {
            if (actual != error.DecodeError) return error.TestExpectedError;
        }

        if (vector.selection) {
            const parsed = tls13.parseCertificateTypeSelection(vector.body) catch
                return error.TestUnexpectedError;
            const owed = refCertificateTypeSelection(vector.body) orelse
                return error.TestUnexpectedResult;
            if (parsed != owed) return error.TestExpectedEqual;
        } else if (tls13.parseCertificateTypeSelection(vector.body)) |_| {
            return error.TestExpectedEqual;
        } else |actual| {
            if (actual != error.DecodeError) return error.TestExpectedError;
        }
    }
}

/// Both decoders against the reference above, on bytes a peer chose: the same
/// types, borrowed from the peer's own body, or the same refusal — and
/// `offerContains` asked about every value in the registry rather than only
/// the one this stack speaks.
fn checkCertificateType(d: []const u8) Error!void {
    if (refCertificateTypeOffer(d)) |owed| {
        const parsed = tls13.parseCertificateTypeOffer(d) catch return error.TestUnexpectedError;
        if (!std.mem.eql(u8, parsed, owed)) return error.TestExpectedEqual;
        if (!borrowedFrom(d, parsed)) return error.TestExpectedEqual;
        for (certificate_types) |kind| {
            const want = std.mem.indexOfScalar(u8, owed, @intFromEnum(kind)) != null;
            if (tls13.offerContains(parsed, kind) != want) return error.TestExpectedEqual;
        }
    } else if (tls13.parseCertificateTypeOffer(d)) |_| {
        return error.TestExpectedEqual;
    } else |actual| {
        if (actual != error.DecodeError) return error.TestExpectedError;
    }

    if (refCertificateTypeSelection(d)) |owed| {
        const parsed = tls13.parseCertificateTypeSelection(d) catch
            return error.TestUnexpectedError;
        if (parsed != owed) return error.TestExpectedEqual;
    } else if (tls13.parseCertificateTypeSelection(d)) |_| {
        return error.TestExpectedEqual;
    } else |actual| {
        if (actual != error.DecodeError) return error.TestExpectedError;
    }
}

/// The two encoders, against bytes written out from RFC 7250 §3 rather than
/// from another copy of the same expression; the buffer-too-small refusal,
/// which is the only way either can fail; and the round trip back through the
/// parsers, so no accepted spelling can be re-read as a different type.
fn emittedCertificateTypes() Error!void {
    var buf: [8]u8 = undefined;
    for (certificate_types) |kind| {
        const one = [_]u8{@intFromEnum(kind)};
        const offer = tls13.encodeCertificateTypeOffer(&buf, kind) catch
            return error.TestUnexpectedResult;
        if (!std.mem.eql(u8, offer, &([_]u8{1} ++ one))) return error.TestExpectedEqual;
        if (tls13.encodeCertificateTypeOffer(buf[0 .. offer.len - 1], kind)) |_| {
            return error.TestUnexpectedResult;
        } else |why| {
            if (why != error.BufferTooSmall) return error.TestExpectedError;
        }
        const parsed_offer = tls13.parseCertificateTypeOffer(offer) catch
            return error.TestUnexpectedError;
        if (!std.mem.eql(u8, parsed_offer, &one)) return error.TestExpectedEqual;
        if (!tls13.offerContains(parsed_offer, kind)) return error.TestExpectedEqual;
        if (tls13.offerContains(parsed_offer, otherThan(kind))) return error.TestExpectedEqual;

        const selection = tls13.encodeCertificateTypeSelection(&buf, kind) catch
            return error.TestUnexpectedResult;
        if (!std.mem.eql(u8, selection, &one)) return error.TestExpectedEqual;
        if (tls13.encodeCertificateTypeSelection(buf[0 .. selection.len - 1], kind)) |_| {
            return error.TestUnexpectedResult;
        } else |why| {
            if (why != error.BufferTooSmall) return error.TestExpectedError;
        }
        const parsed = tls13.parseCertificateTypeSelection(selection) catch
            return error.TestUnexpectedError;
        if (parsed != kind) return error.TestExpectedEqual;
    }
}

/// The one call a fuzz driver makes: `input` is the bytes a peer would hand the
/// decoder, verbatim — a Certificate body, a CertificateRequest body, a
/// `server_name` extension body or an RFC 7250 certificate-type extension
/// body, one of the four at a time.
pub fn check(input: []const u8) Error!void {
    try checkCertificateRequest(input);
    try checkCertificateList(input);
    try checkServerName(input);
    try checkCertificateType(input);
    try emittedRequest();
    try certificateTypeShapes();
    try emittedCertificateTypes();
}

/// One decoder against one reference on an answer that is never absent: the
/// same bytes out, or the same refusal for the reason named.
fn checkCertificateRequest(d: []const u8) Error!void {
    const owed = refCertificateRequest(d);
    const got = tls13.parseCertificateRequest(d);
    if (owed) |expected| {
        const list = got catch return error.TestUnexpectedError;
        if (!std.mem.eql(u8, list, expected)) return error.TestExpectedEqual;
        // Oracle: borrowed. The list is a window into the peer's own bytes, so
        // a decoder that copied or rebuilt them would answer something no peer
        // sent.
        if (!borrowedFrom(d, list)) return error.TestExpectedEqual;
    } else |reason| {
        if (got) |_| {
            return error.TestUnexpectedResult;
        } else |actual| {
            if (actual != reason) return error.TestExpectedError;
        }
    }
}

fn checkCertificateList(d: []const u8) Error!void {
    var out: [chain_bound][]const u8 = undefined;
    var want: [chain_bound][]const u8 = undefined;
    for (&out) |*slot| slot.* = untouched;
    const owed = refCertificateList(d, want[0..]);
    const got = tls13.parseCertificateList(d, out[0..]);
    if (owed) |n| {
        const chain = got catch return error.TestUnexpectedError;
        if (n == 0) {
            // A well-formed empty list is how a client answers a
            // CertificateRequest it cannot meet, so null is the answer.
            if (chain != null) return error.TestExpectedEqual;
        } else {
            const list = chain orelse return error.TestExpectedEqual;
            if (list.len != n) return error.TestExpectedEqual;
            for (list, want[0..n]) |got_cert, want_cert| {
                if (!std.mem.eql(u8, got_cert, want_cert)) return error.TestExpectedEqual;
            }
        }
        // Nothing past the chain was written: the caller sized `out`, and only
        // the certificates in the message may occupy it.
        for (out[n..]) |slice| {
            if (!std.mem.eql(u8, slice, untouched)) return error.TestExpectedEqual;
        }
        return;
    } else |reason| {
        if (got) |_| {
            return error.TestExpectedEqual;
        } else |actual| {
            if (actual != reason) return error.TestExpectedError;
        }
        // Oracle: the caller's storage past the failure is theirs. Whatever the
        // decoder wrote had to be a window into the peer's own bytes; every
        // other entry still holds what it held.
        for (out) |slice| {
            if (borrowedFrom(d, slice)) continue;
            if (!std.mem.eql(u8, slice, untouched)) return error.TestExpectedEqual;
        }
    }
}

/// One decoder against one reference on an answer that may legitimately be
/// absent: the same name, the same "no name in this list", or the same refusal
/// for the reason named. A null is a well-formed list with no `host_name` — a
/// client that sent no name — and is not a failure.
fn checkServerName(d: []const u8) Error!void {
    const owed = refServerName(d);
    const got = tls13.parseServerNameExtension(d);
    // Both sides answer with three facts rather than one — a refusal, a name,
    // and the "no host_name in this list" null — so the refusal is unwrapped
    // first, and the null is an answer rather than a failure.
    if (owed) |maybe_named| {
        const answered = got catch return error.TestUnexpectedError;
        const named = maybe_named orelse {
            // A list of name types this stack has none of is a well-formed
            // answer that names nothing, so the decoder owes that and not a
            // name of its own.
            if (answered != null) return error.TestExpectedEqual;
            try checkSelection(null);
            return;
        };
        const lifted = answered orelse return error.TestExpectedEqual;
        if (!std.mem.eql(u8, lifted, named)) return error.TestExpectedEqual;
        // Oracle: borrowed. The name is a window into the peer's own extension
        // rather than bytes the decoder copied out and rebuilt.
        if (!borrowedFrom(d, lifted)) return error.TestExpectedEqual;
        try checkSelection(lifted);
        return;
    } else |reason| {
        // §3's grammar condemns these bytes, so the decoder owes the same
        // refusal for the same reason; anything else is an answer to a list
        // that has none.
        if (got) |answered| {
            _ = answered;
            return error.TestExpectedError;
        } else |actual| {
            if (actual != reason) return error.TestExpectedError;
        }
        try checkSelection(null);
    }
}

/// The consumer the name exists for. RFC 6066 §3 defines `server_name` so a
/// server picks a certificate, and `selectCertificate` is that step, so the
/// name this file lifts has to be a name the selector can act on.
///
/// The fixture puts a decoy in front of the entry carrying the lifted name, so
/// an implementation that served the first entry rather than the matching one
/// would answer with the decoy — and the two cases are told apart by `matched`,
/// which is what a caller reads to separate "this certificate is for the name I
/// asked for" from "nothing matched, so here is the first one". A name that is
/// the decoy's own is the one input where the decoy is the right answer, and
/// the expected index says so rather than assuming the name is distinctive.
fn checkSelection(host: ?[]const u8) Error!void {
    const decoy = "decoy.invalid";
    const cert: tls13.ServerCertificate = .{ .cert_chain_der = &.{}, .private_key_bytes = &.{} };
    // RFC 6066 §3.1 forbids a trailing dot and the selector strips one, so the
    // entry carries the name as the selector will read it rather than as it
    // arrived.
    var name: []const u8 = "";
    if (host) |h| name = if (h.len > 0 and h[h.len - 1] == '.') h[0 .. h.len - 1] else h;
    var names: [1][]const u8 = undefined;
    names[0] = if (name.len > 0) name else "fallback.invalid";
    const entries = [_]tls13.CertEntry{
        .{ .server_names = &.{decoy}, .cert = cert },
        .{ .server_names = names[0..], .cert = cert },
    };
    const picked = tls13.selectCertificate(&entries, host) orelse return error.TestUnexpectedResult;
    if (picked.matched != (name.len > 0)) return error.TestExpectedEqual;
    const index: usize = if (name.len == 0 or std.ascii.eqlIgnoreCase(decoy, name)) 0 else 1;
    if (picked.entry != &entries[index]) return error.TestExpectedEqual;
}

/// The request this build emits, checked against the RFC rather than against
/// the decoder that will read it: it must fit the caller's buffer exactly, be
/// refused one byte short of that, and name a scheme list a server can answer a
/// CertificateVerify with for every key algorithm this stack holds.
fn emittedRequest() Error!void {
    var buf: [64]u8 = undefined;
    const msg = tls13.buildCertificateRequest(&buf) catch return error.TestUnexpectedResult;
    if (tls13.buildCertificateRequest(buf[0 .. msg.len - 1])) |_| {
        return error.TestUnexpectedResult;
    } else |why| {
        if (why != error.BufferTooSmall) return error.TestExpectedError;
    }
    const got = tls13.parseCertificateRequest(msg[4..]) catch return error.TestUnexpectedError;
    // `client_auth_signature_schemes` is the encoded list itself — RFC 8446
    // §4.2.3's `SignatureScheme` vector, two bytes each and already in network
    // order — so the list this message carries is compared with it byte for
    // byte rather than index by index against an enum.
    const schemes = tls13.client_auth_signature_schemes;
    if (!std.mem.eql(u8, got, &schemes)) return error.TestExpectedEqual;
    for ([_]tls13.PrivateKeyAlgorithm{ .ecdsa_p256_sha256, .ed25519, .rsa }) |alg| {
        if (tls13.signatureSchemeFor(alg, got) == null) return error.TestUnexpectedError;
    }
}
