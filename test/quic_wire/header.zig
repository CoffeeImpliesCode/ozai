//! RFC 9000 §17.2 and §17.3 (with RFC 9369 §5.1): the long and short packet
//! headers, over `vendor/quic/src/quic/packet.zig`'s published entry point
//! `parseQuicHeader`.
//!
//! The header is the first thing a stranger's datagram is read as, and it is
//! the only place a peer's connection-id lengths and version number enter the
//! core. §17.2 states the long-header layout exactly — first byte, Version,
//! DCID Length, DCID, SCID Length, SCID, then per-type fields — and §17.3 the
//! short one, and both are short enough to walk independently here. `walk`
//! below is that second reading of the same bytes: it computes what the parse
//! must produce and which of the RFC's refusals must fire first, from the RFC
//! alone, and every value the parse returns is compared against it.
//!
//! Three things this file deliberately does not do. It does not compare the
//! parse against `Header.encode`: encode writes the unprotected prefix only,
//! omitting the Length field, the packet number and Retry's integrity tag, so
//! re-encoding a random header is not required to reproduce its bytes. It does
//! not read the protected header's low bits — `packet_number_len`, `key_phase`
//! and `reserved_bits_set` are meaningful only once header protection is
//! removed, so asserting anything about them before that asserts noise. And it
//! does not bound `remainder_len`: for Initial, 0-RTT and Handshake that field
//! is a *declared* length and for Retry, Version Negotiation and 1-RTT it is
//! the rest of the datagram, and RFC 9000 puts the bound on decryption.
//!
//! A short header's DCID length is connection state, not wire bytes, so this
//! takes it from the input rather than from a constant: byte 1 modulo 21 spans
//! the whole legal range of §17.2 without adding a hidden input of its own.

const std = @import("std");
const quic = @import("quic");
const packet = quic.packet;

/// RFC 9369's version constant. `lib.zig` does not export `quic.protocol`, so
/// this is restated rather than read — and restating it is the point: the
/// packet-type table below is checked against the RFC, not against a constant
/// copied out of the code under test.
const rfc_v2: u32 = 0x6b3343cf;

/// The longest connection id §17.2 permits a peer to send.
const rfc_cid_max: usize = 20;

/// Retry's integrity tag, §17.2.5.
const rfc_retry_tag: usize = 16;

pub const Error = error{
    TestUnexpectedResult,
    TestExpectedEqual,
    TestExpectedError,
    TestUnexpectedError,
};

/// Why an independent reading of these bytes stops. The refusals are kept
/// apart because §17.2 orders them: a destination CID that is too long is
/// reported before a source CID that is too long, and both before the fixed
/// bit, and each is a differently named error from the entry point. It is an
/// error set and not a tag because `walk` stops *by* refusing, and `none` is
/// the value a refusal §17.2 has no name for carries.
const Reason = error{
    none,
    end_of_stream,
    buffer_too_short,
    invalid_packet,
    packet_error,
    var_int_too_large,
};

fn toError(reason: Reason) anyerror {
    return switch (reason) {
        error.none => error.TestUnexpectedResult,
        error.end_of_stream => error.EndOfStream,
        error.buffer_too_short => error.BufferTooShort,
        error.invalid_packet => error.InvalidPacket,
        error.packet_error => error.PacketError,
        error.var_int_too_large => error.VarIntTooLarge,
    };
}

/// The one place a walk refusal is not already answered. `walk` stops by
/// refusing, and a refusal reaching here means `parseQuicHeader` *accepted*
/// these bytes: §17.2 read a different fact about them — a field past the end
/// (`end_of_stream`), a connection id past a buffer or a declared Length
/// (`buffer_too_short`), a source id over the RFC's ceiling or a long header
/// without the fixed bit (`invalid_packet`), a destination id over that
/// ceiling (`packet_error`), or a Length wider than a `usize` (`var_int_too_large`)
/// — and the parser owes that refusal. Every stop is the same defect, and the
/// one that fired is named on the way out rather than folded into the tag.
fn walked(shape: Reason!Shape) Error!Shape {
    return shape catch |why| {
        std.debug.print("quic header fuzz: accepted bytes the RFC walk refused: {s}\n", .{@errorName(why)});
        return error.TestUnexpectedError;
    };
}

/// What §17.2/§17.3 say these bytes decode to.
const Shape = struct {
    long: bool,
    version: u32,
    packet_type: packet.PacketType,
    dcid: []const u8,
    scid: []const u8,
    token: ?[]const u8,
    remainder_len: usize,
    span: usize,
};

/// RFC 9000 §16: one varint at the cursor, read by the table rather than by
/// any reader in the tree, failing the way a truncated read must.
fn varintAt(bytes: []const u8, cursor: *usize) Reason!u64 {
    const rest = bytes[cursor.*..];
    if (rest.len == 0) return error.end_of_stream;
    const width = @as(usize, 1) << @intCast(rest[0] >> 6);
    if (rest.len < width) return error.end_of_stream;
    var value: u64 = rest[0] & 0x3f;
    for (rest[1..width]) |b| value = (value << 8) | b;
    cursor.* += width;
    return value;
}

/// The same read, where §17.2's Length field must also fit a real buffer.
fn lengthAt(bytes: []const u8, cursor: *usize) Reason!usize {
    const value = try varintAt(bytes, cursor);
    // §16 stops at 2^62-1, so only a target narrower than 64 bits narrows a
    // length further, and the published reader names that case explicitly.
    if (value > std.math.maxInt(usize)) return error.var_int_too_large;
    return @intCast(value);
}

/// RFC 9000 §17.2.3 through §17.2.5 map the two type bits to a type; RFC 9369
/// §5.1 remaps them for v2 and leaves them as they were for every other
/// version, including a version this core does not speak.
fn rfcType(first: u8, version: u32) packet.PacketType {
    const bits = (first >> 4) & 0x03;
    if (version == rfc_v2) return switch (bits) {
        0b00 => .retry,
        0b01 => .initial,
        0b10 => .zero_rtt,
        else => .handshake,
    };
    return switch (bits) {
        0b00 => .initial,
        0b01 => .zero_rtt,
        0b10 => .handshake,
        else => .retry,
    };
}

/// The independent reading of one datagram. `short_dcid_len` is the only
/// caller-supplied state §17.3 needs, and §17.2 bounds it at 20.
fn walk(bytes: []const u8, short_dcid_len: u8) Reason!Shape {
    var out: Shape = .{
        .long = false,
        .version = 0,
        .packet_type = .one_rtt,
        .dcid = &.{},
        .scid = &.{},
        .token = null,
        .remainder_len = 0,
        .span = 1,
    };
    if (bytes.len < 1) return error.end_of_stream;
    const first = bytes[0];
    const dcid_want = @as(usize, short_dcid_len);

    // §17.3: bit 7 clear is a short header, and the DCID that follows is as
    // long as the connection says it is — or as long as the datagram allows,
    // which is why a DCID that does not fit leaves the field empty.
    if ((first & 0x80) == 0) {
        if (dcid_want <= bytes.len - 1) {
            out.dcid = bytes[1..][0..dcid_want];
            out.span += dcid_want;
        }
        out.remainder_len = bytes.len - out.span;
        return out;
    }

    out.long = true;
    if (bytes.len < 5) return error.end_of_stream;
    out.version = std.mem.readInt(u32, bytes[1..5], .big);
    out.span = 5;

    if (out.span >= bytes.len) return error.end_of_stream;
    const dcid_len = @as(usize, bytes[out.span]);
    out.span += 1;
    if (dcid_len > rfc_cid_max) return error.packet_error;
    if (dcid_len > bytes.len - out.span) return error.buffer_too_short;
    out.dcid = bytes[out.span..][0..dcid_len];
    out.span += dcid_len;

    if (out.span >= bytes.len) return error.end_of_stream;
    const scid_len = @as(usize, bytes[out.span]);
    out.span += 1;
    if (scid_len > rfc_cid_max) return error.invalid_packet;
    if (scid_len > bytes.len - out.span) return error.buffer_too_short;
    out.scid = bytes[out.span..][0..scid_len];
    out.span += scid_len;

    // §17.2: the fixed bit is set on every packet a version of QUIC defines,
    // so a long header without it is not one and the datagram is refused.
    if ((first & 0x40) == 0) return error.invalid_packet;

    // §17.2.1: a zero Version marks a Version Negotiation packet, the one
    // long-header type whose bit patterns carry no meaning.
    out.packet_type = if (out.version == 0) .version_negotiation else rfcType(first, out.version);

    switch (out.packet_type) {
        // §17.2.2: Token Length, Token, Length.
        .initial => {
            const token_length = try varintAt(bytes, &out.span);
            if (token_length > @as(u64, bytes.len - out.span)) return error.buffer_too_short;
            // A zero token length is an absent Token, not a zero-length one,
            // so the parse leaves the field unset rather than empty.
            if (token_length != 0) out.token = bytes[out.span..][0..@intCast(token_length)];
            out.span += @intCast(token_length);
            out.remainder_len = try lengthAt(bytes, &out.span);
        },
        // §17.2.5: no Length field and no packet number. The rest of the
        // datagram is the Retry, less the tag the sender appended.
        .retry => {
            const rest = bytes.len - out.span;
            if (rest > rfc_retry_tag) out.token = bytes[out.span .. bytes.len - rfc_retry_tag];
            out.remainder_len = rest;
        },
        // §17.2.1: a Version Negotiation packet is a whole datagram.
        .version_negotiation => out.remainder_len = bytes.len - out.span,
        // §17.2.4 and §17.2.3: Length and nothing else.
        .handshake, .zero_rtt => out.remainder_len = try lengthAt(bytes, &out.span),
        // §17.2 names exactly those four types plus Version Negotiation; the
        // long-header bit patterns do not name a fifth.
        else => unreachable,
    }
    return out;
}

/// Oracle: the RFC's packet-type table, against both names the parser
/// publishes for it. A caller switching on `longHeaderPacketType` and a caller
/// switching on a parsed `packet_type` must not be able to disagree.
fn checkTypeTable(first: u8, version: u32) Error!void {
    for (0..4) |bits| {
        const probe: u8 = @intCast(bits << 4);
        if (packet.longHeaderPacketType(probe, version) != rfcType(probe, version)) {
            return error.TestExpectedEqual;
        }
    }
    if (packet.longHeaderPacketType(first, version) != rfcType(first, version)) {
        return error.TestExpectedEqual;
    }
}

/// Oracle: what an accepted parse produced, field by field, against §17.2.
fn checkAccepted(header: packet.Header, shape: Shape, bytes: []const u8, seek: usize) Error!void {
    if (header.packet_start != 0) return error.TestExpectedEqual;
    if (header.version != shape.version) return error.TestExpectedEqual;
    if (header.packet_type != shape.packet_type) return error.TestExpectedEqual;
    // §17.2 sets bit 7 on a long header and §17.3 clears it, so the form that
    // bit selects and the type the parser reported cannot come apart.
    if (packet.isLongHeader(bytes[0]) != shape.long) return error.TestExpectedEqual;
    if (shape.long != (header.packet_type != .one_rtt)) return error.TestExpectedEqual;

    if (!std.mem.eql(u8, header.dcid, shape.dcid)) return error.TestExpectedEqual;
    if (!std.mem.eql(u8, header.scid, shape.scid)) return error.TestExpectedEqual;
    if (header.remainder_len != shape.remainder_len) return error.TestExpectedEqual;

    if (header.token) |got| {
        const want = shape.token orelse return error.TestExpectedEqual;
        if (!std.mem.eql(u8, got, want)) return error.TestExpectedEqual;
    } else if (shape.token != null) return error.TestExpectedEqual;

    // Oracle: the cursor. A coalesced datagram is walked one packet at a time
    // and the next packet starts exactly where this header ended, so where
    // the stream came to rest is part of what a parse promises.
    if (seek != shape.span) return error.TestExpectedEqual;
}

pub fn check(input: []const u8) Error!void {
    const short_dcid_len: u8 = if (input.len < 2) 0 else input[1] % 21;
    var reader = quic.io_compat.fixedBufferStream(input);

    const parsed = packet.parseQuicHeader(&reader, short_dcid_len) catch |err| {
        const got: anyerror = err;
        if (walk(input, short_dcid_len)) |_| {
            // §17.2/§17.3 read these bytes as a well-formed header, so
            // refusing them is a defect rather than a refusal.
            return error.TestUnexpectedError;
        } else |why| {
            // A refusal is legal only where the RFC condemns these bytes, and
            // only for the reason the independent walk reached first.
            if (got != toError(why)) return error.TestExpectedEqual;
            return;
        }
    };

    const shape = try walked(walk(input, short_dcid_len));
    try checkAccepted(parsed, shape, input, reader.seek);
    if (shape.long and shape.version != 0) try checkTypeTable(input[0], shape.version);
}
