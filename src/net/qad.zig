//! Quic Address Discovery: the OBSERVED_ADDRESS frame and the transport
//! parameter that negotiates it, as pure bytes over a caller's slice.
//!
//! QAD is not a request and not a response. A peer advertises, in the
//! handshake, whether it will report observed addresses and whether it wants
//! them reported; after that the two ends exchange an ack-eliciting probing
//! frame — one per new path, and one for the handshake path — carrying a
//! sequence number and the address the sender was seen at. There is no
//! question, no answer and no request id, which is why this module has two
//! halves and no session:
//!
//! - `Role` and `transport_parameter_id` — what the handshake negotiates.
//! - `ObservedAddress`, `encode` and `decode` — what one path's frame holds.
//!
//! # Where the bytes come from
//!
//! Two primary sources, and they agree:
//!
//! - `draft-ietf-quic-address-discovery` §3 and §4.1: the
//!   `address_discovery` transport parameter `0x9f81a176` carrying a
//!   variable-length integer role, and the OBSERVED_ADDRESS frame whose type
//!   is `0x9f81a6..0x9f81a7` with the least significant bit selecting the
//!   address family, whose body is a sequence number, the address, and a
//!   16-bit port in network byte order.
//! - n0-computer/noq: `noq-proto/src/frame.rs` (`FrameType::ObservedIpv4Addr`
//!   = `0x9f81a6`, `FrameType::ObservedIpv6Addr` = `0x9f81a7`, and
//!   `ObservedAddr::read` / `ObservedAddr::encode`, which read and write
//!   `seq_no`, then the address, then `buf.write::<u16>(port)`), and
//!   `noq-proto/src/address_discovery.rs` (`Role`'s three values, its
//!   `should_report`, and `as_transport_parameter`'s refusal of a fourth).
//!
//! The draft revision read on 2026-10-05 was
//! `draft-ietf-quic-address-discovery-latest` (15 August 2026). Its three
//! constants and its field order are byte-identical to `-00` of 3 March 2025.
//!
//! # What is pinned here, and what is not
//!
//! **Pinned by the tests below:** the two frame types and the transport
//! parameter id, each as the exact bytes a QUIC variable-length integer
//! spells them; the field order and the width of every field; all three role
//! values and the refusal of every other one; the truncation bound; the
//! buffer bound; and the round trip for both families at every varint width.
//!
//! **Not pinned:** no upstream bytes were captured on this node. The golden
//! frame in the test below is *derived* — §4.1's field order composed with
//! RFC 9000 §16 — and it agrees with noq's own round-trip fixture, which
//! asserts only that its encode and its decode agree and names no bytes. So
//! the layout rests on two written specifications and on a peer
//! implementation read, not on a packet. What closes that gap is one
//! golden-vector test carrying bytes captured from a real iroh relay's
//! `/iroh-qad/0` connection; this node has no such capture and cannot make
//! one, so that test does not exist yet.
//!
//! **Not implemented here, and said here rather than left to be assumed:**
//! the sequence number's monotonicity rule — ignore an OBSERVED_ADDRESS frame
//! for a path whose sequence number is not greater than the last accepted one
//! for that path (§4.1; noq's `PathData::update_observed_addr_report`). That
//! rule is per-path state, so it belongs to whoever holds the paths and not to
//! a codec over bytes.
//!
//! # No socket, no clock, no allocator
//!
//! Every function is a function of its arguments and the caller's slice. A
//! decoded frame borrows nothing and owns a fixed number of bytes, so it can
//! sit in a report entry with no lifetime attached to it. Encoding writes
//! into the caller's buffer and refuses rather than growing it, which is the
//! rule `relay/frame_writer.zig` follows and for the same reason.

const std = @import("std");
const addr = @import("../base/addr.zig");

const IpAddress = addr.IpAddress;
const SocketAddr = addr.SocketAddr;

const t = std.testing;

/// The `address_discovery` transport parameter id, draft §3. A QUIC
/// variable-length integer, so it is eight bytes wide on the wire.
///
/// The value is a `Role`, and its **absence** means the extension is not
/// negotiated at all — there is no "none" role and this module has no
/// encoding for one, so a decoder that finds no such parameter has not found
/// a disabled QAD but a handshake that never asked for it.
pub const transport_parameter_id: u64 = 0x9f81a176;

/// The OBSERVED_ADDRESS frame type for an IPv4 address, draft §4.1. Also
/// `noq_proto::FrameType::ObservedIpv4Addr`.
pub const frame_type_ipv4: u64 = 0x9f81a6;

/// The OBSERVED_ADDRESS frame type for an IPv6 address, draft §4.1. Also
/// `noq_proto::FrameType::ObservedIpv6Addr`. One more than the IPv4 type,
/// because the least significant bit of the type is the family.
pub const frame_type_ipv6: u64 = 0x9f81a7;

/// The widest a QUIC variable-length integer is (RFC 9000 §16), and so the
/// widest this frame's type and sequence number can each be.
pub const max_varint_length: usize = 8;

/// The largest sequence number a variable-length integer can carry, and so
/// the largest this frame can name. A *decoded* frame cannot exceed it — the
/// encoding has nowhere to put a 62nd bit — which is why the check is on the
/// way in only.
pub const max_sequence: u64 = (@as(u64, 1) << 62) - 1;

/// The longest frame `encode` can write: a type, a sequence number, a
/// sixteen-byte address and a two-byte port. Both type constants are
/// four-byte varints, so this is a bound and not a length.
pub const max_frame_length: usize = max_varint_length * 2 + 16 + 2;

/// Everything this codec can refuse, in one closed set. There is no
/// `anyerror` in this file and no arm a peer cannot provoke.
pub const Error = error{
    /// The caller's buffer cannot hold the frame. Raised before the bytes
    /// that did fit mean anything, so a caller that retries must discard
    /// what a failed `encode` wrote.
    NoRoom,
    /// The slice ended inside a field the frame's type promised.
    Truncated,
    /// The frame type is not one this build carries, so the address family
    /// behind it is one this build does not carry.
    ///
    /// **Refused by name, never skipped.** The family is the only thing this
    /// frame's type decides, so a type that is neither constant names a
    /// family with no arm here. An error is what keeps a caller from
    /// treating an unreadable frame as an absent one: §4.1's SHOULD-ignore
    /// applies to a *sequence number*, and RFC 9000 §12.4 makes an
    /// unrecognised frame type a connection error rather than something to
    /// step over.
    UnknownAddressFamily,
    /// The sequence number is past `max_sequence`, so it has no
    /// variable-length integer spelling and this frame cannot be written.
    SequenceTooLarge,
};

/// Why a transport parameter's value is refused. Separate from `Error`
/// because a handshake parameter and a packet frame are read at different
/// moments by different peers, and a caller handling both wants to tell the
/// two refusals apart.
pub const RoleError = error{
    /// The value ended inside its variable-length integer.
    Truncated,
    /// Bytes are behind the role's integer. The parameter's declared length
    /// is the integer's canonical width, so anything left over is a
    /// parameter that is not the one this is — noq refuses the same shape as
    /// `Error::Malformed` when `len != value.size()`.
    TrailingBytes,
    /// The value is not 0, 1 or 2. Draft §3 requires the peer to be failed
    /// with TRANSPORT_PARAMETER_ERROR for any other value, and noq refuses it
    /// as `Error::IllegalValue`.
    UnknownRole,
};

/// What a peer says it will do about address observations, draft §3, and
/// `noq_proto::address_discovery::Role`.
///
/// The discriminants are the wire values rather than positions, so
/// `@intFromEnum` is the parameter's integer and there is no table to keep
/// beside it.
pub const Role = enum(u64) {
    /// 0: willing to report observed addresses, not interested in receiving
    /// them. A relay's role.
    send_only = 0,
    /// 1: interested in receiving observed addresses, not willing to report
    /// them. A probing client's role.
    receive_only = 1,
    /// 2: interested in receiving them and willing to report them.
    both = 2,

    /// Whether this peer may send an OBSERVED_ADDRESS frame to `theirs`.
    ///
    /// Two conditions, not one: this peer must be willing to report, and the
    /// peer at the other end must have asked to receive. §4.1 makes sending
    /// to a peer that did not request receipt a PROTOCOL_VIOLATION, so a
    /// caller checking only its own role sends frames that close the
    /// connection. This is noq's `Role::should_report`.
    pub fn shouldReport(self: Role, theirs: Role) bool {
        const willing = self == .send_only or self == .both;
        const asked = theirs == .receive_only or theirs == .both;
        return willing and asked;
    }
};

/// The transport parameter's value: this role as the variable-length
/// integer draft §3 says it is.
///
/// Every arm is below 64, so the encoding is a single byte whatever the
/// role — which is what makes the parameter's declared length 1 for all
/// three, and the test below is what holds that.
pub fn encodeRole(role: Role, out: []u8) Error!usize {
    return putVarint(out, @intFromEnum(role));
}

/// The role a parameter's value spells, and how many bytes it occupied.
///
/// The whole of `value` must be the integer: RFC 9000 §7.4 makes the
/// parameter a length-delimited blob, §3 makes that blob a role, and noq
/// requires the two lengths to agree. Bytes behind the integer are
/// `error.TrailingBytes` rather than a role, because a value that is not
/// one integer is not a value this parameter can carry.
pub fn decodeRole(value: []const u8) RoleError!DecodedRole {
    var offset: usize = 0;
    const raw = try getVarint(value, &offset);
    if (offset != value.len) return error.TrailingBytes;
    const role: Role = switch (raw) {
        0 => .send_only,
        1 => .receive_only,
        2 => .both,
        else => return error.UnknownRole,
    };
    return .{ .role = role, .length = offset };
}

/// A role and the bytes it took, so a caller walking a peer's transport
/// parameters knows where the next one starts.
pub const DecodedRole = struct {
    role: Role,
    length: usize,
};

/// Which address family an OBSERVED_ADDRESS frame carries, and how wide
/// that family's address is.
///
/// Two arms, because §4.1 gives the family two spellings and no third. The
/// width is a method rather than a second table because the width is a
/// property of the family and the frame is the only place it is asked for.
pub const Family = enum {
    v4,
    v6,

    /// The bytes the family occupies in a frame body: four or sixteen.
    pub fn addressLength(self: Family) usize {
        return switch (self) {
            .v4 => 4,
            .v6 => 16,
        };
    }
};

/// The family an OBSERVED_ADDRESS frame type selects, or
/// `error.UnknownAddressFamily`.
///
/// The type's least significant bit is the family (§4.1), so the two
/// registered constants differ only in that bit and anything else in this
/// range names a family this build does not carry.
pub fn familyOf(frame_type: u64) Error!Family {
    return switch (frame_type) {
        frame_type_ipv4 => .v4,
        frame_type_ipv6 => .v6,
        else => error.UnknownAddressFamily,
    };
}

/// The frame type that carries `family`, the inverse of `familyOf`.
pub fn frameTypeOf(family: Family) u64 {
    return switch (family) {
        .v4 => frame_type_ipv4,
        .v6 => frame_type_ipv6,
    };
}

/// One OBSERVED_ADDRESS frame: a sequence number and the address the sender
/// was seen at, with the port inside the address.
///
/// Upstream splits these into three fields (`ObservedAddr`'s `seq_no`, `ip`
/// and `port`); `addr.SocketAddr` already is an address and a port, and one
/// type for both is what keeps a decoder from building a value this tree
/// cannot put anywhere.
pub const ObservedAddress = struct {
    /// Monotonically increasing per connection, per §4.1. This module does
    /// not check that and cannot: the previous number belongs to a path, not
    /// to a frame. See the module doc.
    sequence: u64,
    /// The observed address, unconverted: a relay answering an IPv4 probe
    /// with an IPv6 address is the reporting layer's finding, and
    /// `report_fold.zig` is where the mismatch is caught, not here.
    addr: SocketAddr,
};

/// A decoded frame and the bytes it occupied.
///
/// The length is the reason this is not just an `ObservedAddress`: a QUIC
/// packet holds several frames and the frame before this one has to be able
/// to find where this one ends.
pub const Decoded = struct {
    observed: ObservedAddress,
    /// How many bytes of the input this frame took, type included.
    length: usize,
};

/// Write `observed` into the front of `out`, and say how many bytes it took.
///
/// The type is derived from the address's own family, so a frame cannot be
/// written with a type that contradicts the address behind it — the two
/// mistakes a caller could make with a hand-rolled type are both
/// unrepresentable here.
///
/// Refuses `error.SequenceTooLarge` before writing anything, and
/// `error.NoRoom` partway through, so a caller that retries with a bigger
/// buffer must discard what a failed call wrote.
pub fn encode(observed: ObservedAddress, out: []u8) Error!usize {
    if (observed.sequence > max_sequence) return error.SequenceTooLarge;
    const family: Family = switch (observed.addr.ip) {
        .v4 => .v4,
        .v6 => .v6,
    };
    var offset: usize = 0;
    offset += try putVarint(out[offset..], frameTypeOf(family));
    offset += try putVarint(out[offset..], observed.sequence);
    switch (observed.addr.ip) {
        .v4 => |octets| {
            if (out[offset..].len < 4 + 2) return error.NoRoom;
            @memcpy(out[offset..][0..4], octets[0..]);
            offset += 4;
        },
        .v6 => |octets| {
            if (out[offset..].len < 16 + 2) return error.NoRoom;
            @memcpy(out[offset..][0..16], octets[0..]);
            offset += 16;
        },
    }
    var port_bytes: [2]u8 = undefined;
    std.mem.writeInt(u16, &port_bytes, observed.addr.port, .big);
    @memcpy(out[offset..][0..2], port_bytes[0..]);
    return offset + 2;
}

/// Read one OBSERVED_ADDRESS frame off the front of `bytes`.
///
/// The family is resolved from the type before the body is read, because the
/// type is what says how long the body is: reading the address first would
/// make the four- and sixteen-byte cases two guesses rather than one rule.
/// Every prefix that ends inside a field is `error.Truncated`, and a type
/// this build does not carry is `error.UnknownAddressFamily` — a refusal, not
/// a skip.
pub fn decode(bytes: []const u8) Error!Decoded {
    var offset: usize = 0;
    const family = try familyOf(try getVarint(bytes, &offset));
    const octets = family.addressLength();
    const sequence = try getVarint(bytes, &offset);
    if (bytes[offset..].len < octets + 2) return error.Truncated;
    var ip: IpAddress = undefined;
    switch (family) {
        .v4 => {
            var address: [4]u8 = undefined;
            @memcpy(address[0..], bytes[offset..][0..4]);
            ip = .{ .v4 = address };
        },
        .v6 => {
            var address: [16]u8 = undefined;
            @memcpy(address[0..], bytes[offset..][0..16]);
            ip = .{ .v6 = address };
        },
    }
    offset += octets;
    var port_bytes: [2]u8 = undefined;
    @memcpy(port_bytes[0..], bytes[offset..][0..2]);
    return .{
        .observed = .{
            .sequence = sequence,
            .addr = .{ .ip = ip, .port = std.mem.readInt(u16, &port_bytes, .big) },
        },
        .length = offset + 2,
    };
}

/// How many bytes the variable-length integer for `value` takes, RFC 9000
/// §16: two prefix bits in the first byte say the width, and the value is
/// what is left of it.
fn varintLength(value: u64) usize {
    if (value < 1 << 6) return 1;
    if (value < 1 << 14) return 2;
    if (value < 1 << 30) return 4;
    return max_varint_length;
}

/// Write `value` as a variable-length integer at the front of `out`, and say
/// how wide it was.
///
/// `noq_proto::VarInt::encode`, and `noq_proto::VarInt::size` for the width.
/// Both type constants and the parameter id are past the two-byte range, so
/// they are four and eight bytes wide; nothing here writes one byte for a
/// value that needs more, and nothing here reads a width it did not write.
fn putVarint(out: []u8, value: u64) Error!usize {
    const length = varintLength(value);
    if (out.len < length) return error.NoRoom;
    const prefix: u64 = switch (length) {
        1 => 0b00,
        2 => 0b01,
        4 => 0b10,
        else => 0b11,
    };
    const shift: u6 = @intCast(8 * length - 2);
    const wide = value | (prefix << shift);
    switch (length) {
        1 => out[0] = @intCast(wide),
        2 => {
            var bytes: [2]u8 = undefined;
            std.mem.writeInt(u16, &bytes, @intCast(wide), .big);
            @memcpy(out[0..2], bytes[0..]);
        },
        4 => {
            var bytes: [4]u8 = undefined;
            std.mem.writeInt(u32, &bytes, @intCast(wide), .big);
            @memcpy(out[0..4], bytes[0..]);
        },
        else => {
            var bytes: [max_varint_length]u8 = undefined;
            std.mem.writeInt(u64, &bytes, wide, .big);
            @memcpy(out[0..max_varint_length], bytes[0..]);
        },
    }
    return length;
}

/// Why a variable-length integer cannot be read. Its own set rather than
/// `Error`, because a read has exactly one failure and this module has two
/// readers with two different wider sets: a frame body widens it with the
/// frame's refusals, and a transport parameter's value with the role's.
const VarintError = error{
    /// The slice ended before the width the first byte named was behind it.
    Truncated,
};

/// Read the variable-length integer at `bytes[offset..]`, leaving `offset`
/// after it.
///
/// `noq_proto::VarInt::decode`, loop for loop. One rejection: a first byte
/// naming a two-, four- or eight-byte integer with fewer bytes behind it.
/// There is no second, because a QUIC variable-length integer is
/// self-describing and every value below 2^62 has exactly one spelling — the
/// over-long encodings a postcard varint admits cannot be written here.
fn getVarint(bytes: []const u8, offset: *usize) VarintError!u64 {
    const rest = bytes[offset.*..];
    if (rest.len == 0) return error.Truncated;
    const length: usize = @as(usize, 1) << @intCast(rest[0] >> 6);
    if (rest.len < length) return error.Truncated;
    var value: u64 = rest[0] & 0b0011_1111;
    for (rest[1..length]) |byte| value = (value << 8) | byte;
    offset.* += length;
    return value;
}

comptime {
    // The bound above is a bound because of these two facts, and a reader
    // who changes a constant should be told here rather than by a test that
    // stops holding.
    std.debug.assert(varintLength(frame_type_ipv4) == 4);
    std.debug.assert(varintLength(frame_type_ipv6) == 4);
    std.debug.assert(varintLength(transport_parameter_id) == max_varint_length);
}

// --- tests

/// The bytes `text` spells, spaces allowed between them, into `scratch`.
///
/// Written out rather than borrowed from `relay/frame_vectors.zig`, which is
/// the relay's own test fixture and reaches into relay types this module has
/// no business naming.
fn hex(text: []const u8, scratch: []u8) ![]const u8 {
    var length: usize = 0;
    var high: ?u8 = null;
    for (text) |character| {
        if (character == ' ') continue;
        const nibble = std.fmt.charToDigit(character, 16) catch return error.InvalidHex;
        if (high) |top| {
            scratch[length] = (top << 4) | nibble;
            length += 1;
            high = null;
        } else {
            high = nibble;
        }
    }
    // A half byte is a typo in a vector, not a byte on the wire.
    if (high != null) return error.InvalidHex;
    return scratch[0..length];
}

fn expectHex(text: []const u8, actual: []const u8) !void {
    var scratch: [64]u8 = undefined;
    const expected = try hex(text, &scratch);
    try t.expectEqualSlices(u8, expected, actual);
}

/// The variable-length integer `value` spells, compared against `text`.
fn expectVarint(text: []const u8, value: u64) !void {
    var scratch: [max_varint_length]u8 = undefined;
    const length = try putVarint(&scratch, value);
    try expectHex(text, scratch[0..length]);
}

/// Every family, every sequence width, and the two ports a `u16` can hold.
///
/// The widths are the boundaries RFC 9000 §16 draws, and the sweep is a
/// comptime one so a family added later is swept without a test being
/// edited.
const sequences = [_]u64{ 0, 1, 42, 63, 64, 16_383, 16_384, 1 << 30, max_sequence };

/// `2001:db8::1` out of the documentation prefix, as the sixteen bytes the
/// frame carries. One constant rather than a literal per test, so the golden
/// vectors and the sweeps cannot drift apart.
const doc_v6: [16]u8 = .{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01 };

test "the three protocol constants are the bytes the draft and noq name" {
    // Draft §3 and §4.1, and noq's `TransportParameterId::ObservedAddr` and
    // `FrameType::ObservedIpv4Addr` / `ObservedIpv6Addr`. Encoded as QUIC
    // variable-length integers, which is how both a transport parameter id
    // and a frame type reach the wire.
    try expectVarint("c0 00 00 00 9f 81 a1 76", transport_parameter_id);
    try expectVarint("80 9f 81 a6", frame_type_ipv4);
    try expectVarint("80 9f 81 a7", frame_type_ipv6);

    // The two types differ only in the least significant bit, and that bit is
    // the family — so `familyOf` and `frameTypeOf` are inverses over both arms
    // and nothing else is a type.
    try t.expectEqual(frame_type_ipv6 - 1, frame_type_ipv4);
    inline for ([_]Family{ .v4, .v6 }) |family| {
        try t.expectEqual(family, try familyOf(frameTypeOf(family)));
    }
    try t.expectEqual(@as(usize, 4), Family.v4.addressLength());
    try t.expectEqual(@as(usize, 16), Family.v6.addressLength());
}

test "one IPv4 frame, field by field, and it reads back" {
    // The values are noq's own round-trip fixture (`test_observed_addr_roundrip`
    // in `noq-proto/src/frame.rs`): sequence 42, 127.0.0.1, port 4242. The
    // bytes are derived from §4.1 rather than captured, and noq's test names
    // no bytes — see the module doc.
    const observed: ObservedAddress = .{
        .sequence = 42,
        .addr = .{ .ip = .{ .v4 = .{ 127, 0, 0, 1 } }, .port = 4242 },
    };
    var out: [max_frame_length]u8 = undefined;
    const length = try encode(observed, &out);
    //          type          seq 127.0.0.1  4242
    //        80 9f 81 a6     2a   7f 00 00 01  10 92
    try expectHex("80 9f 81 a6 2a 7f 00 00 01 10 92", out[0..length]);
    try t.expectEqual(@as(usize, 11), length);

    const read = try decode(out[0..length]);
    try t.expectEqual(observed, read.observed);
    try t.expectEqual(length, read.length);
}

test "an IPv6 frame is the same frame with a wider address" {
    const observed: ObservedAddress = .{
        .sequence = 1,
        .addr = .{ .ip = .{ .v6 = doc_v6 }, .port = 65_535 },
    };
    var out: [max_frame_length]u8 = undefined;
    const length = try encode(observed, &out);
    //          type          seq  2001:db8::1            port
    //        80 9f 81 a7     01   20 01 0d b8 00 … 01   ff ff
    try expectHex(
        "80 9f 81 a7 01 20 01 0d b8 00 00 00 00 00 00 00 00 00 00 00 01 ff ff",
        out[0..length],
    );
    try t.expectEqual(observed, (try decode(out[0..length])).observed);

    // Sixteen bytes more of address and nothing else: the two families differ
    // only in the address, so the frame's overhead is the same for both.
    var v4: [max_frame_length]u8 = undefined;
    const v4_length = try encode(.{
        .sequence = 1,
        .addr = .{ .ip = .{ .v4 = .{ 203, 0, 113, 9 } }, .port = 65_535 },
    }, &v4);
    try t.expectEqual(v4_length + 12, length);
}

test "every sequence width round trips for both families" {
    var first: [max_frame_length]u8 = undefined;
    var second: [max_frame_length]u8 = undefined;
    inline for ([_]Family{ .v4, .v6 }) |family| {
        for (sequences) |sequence| {
            const observed: ObservedAddress = .{
                .sequence = sequence,
                .addr = switch (family) {
                    .v4 => .{ .ip = .{ .v4 = .{ 198, 51, 100, 7 } }, .port = 0 },
                    .v6 => .{ .ip = .{ .v6 = doc_v6 }, .port = 65_535 },
                },
            };
            const length = try encode(observed, &first);
            const read = try decode(first[0..length]);
            try t.expectEqual(observed, read.observed);
            try t.expectEqual(length, read.length);
            // The encoding is a fixed point: the value names the bytes, not
            // the spelling that happened to be chosen for them.
            const again = try encode(read.observed, &second);
            try t.expectEqual(length, again);
            try t.expectEqualSlices(u8, first[0..length], second[0..again]);
        }
    }
    // A frame's overhead is its type and its port, and the widest of them is
    // the bound the caller's buffer is sized from.
    try t.expect(max_frame_length >= 4 + max_varint_length + 16 + 2);
}

test "every prefix that ends inside the frame is Truncated" {
    var full: [max_frame_length]u8 = undefined;
    inline for ([_]Family{ .v4, .v6 }) |family| {
        const length = try encode(.{
            .sequence = max_sequence,
            .addr = switch (family) {
                .v4 => .{ .ip = .{ .v4 = .{ 198, 51, 100, 7 } }, .port = 1 },
                .v6 => .{ .ip = .{ .v6 = [_]u8{0} ** 16 }, .port = 1 },
            },
        }, &full);
        var cut: usize = 0;
        while (cut < length) : (cut += 1) {
            try t.expectError(error.Truncated, decode(full[0..cut]));
        }
        try t.expectEqual(length, (try decode(full[0..length])).length);
    }
}

test "a frame type this build does not carry is refused by name" {
    // One below the IPv4 type and one above the IPv6 type: each names a
    // family with no arm here, and each is refused rather than skipped.
    // `0x1f` is a real QUIC frame type (IMMEDIATE_ACK), which is the point:
    // this is a decoder for one frame, not a packet walk, so a type that is
    // not this frame cannot be anything but a refusal.
    for ([_]u64{ frame_type_ipv4 - 1, frame_type_ipv6 + 1, 0x1f, 0x00 }) |frame_type| {
        var scratch: [max_varint_length]u8 = undefined;
        const length = try putVarint(&scratch, frame_type);
        try t.expectError(error.UnknownAddressFamily, decode(scratch[0..length]));
    }

    // And the refusal is not the truncation refusal: a type this build does
    // carry with no body behind it is Truncated, which is a different fault
    // with a different remedy.
    try t.expectError(error.Truncated, decode(&[_]u8{ 0x80, 0x9f, 0x81 }));
}

test "a buffer one byte short is NoRoom, and the widest frame fits" {
    const widest: ObservedAddress = .{
        .sequence = max_sequence,
        .addr = .{ .ip = .{ .v6 = [_]u8{0xff} ** 16 }, .port = 65_535 },
    };
    var out: [max_frame_length]u8 = undefined;
    const length = try encode(widest, &out);
    // Every length under the frame's own is refused, and the widest buffer
    // the module publishes is exactly enough.
    var room: usize = 0;
    while (room < length) : (room += 1) {
        try t.expectError(error.NoRoom, encode(widest, out[0..room]));
    }
    try t.expect(length < max_frame_length);
}

test "the sequence number stops at the widest a varint can carry" {
    const widest: ObservedAddress = .{
        .sequence = max_sequence,
        .addr = .{ .ip = .{ .v4 = .{ 198, 51, 100, 7 } }, .port = 1 },
    };
    var out: [max_frame_length]u8 = undefined;
    const length = try encode(widest, &out);
    try t.expectEqual(max_sequence, (try decode(out[0..length])).observed.sequence);

    // One more has no spelling: an eight-byte varint's top two bits are the
    // width, so there is no ninth byte to put it in.
    try t.expectError(
        error.SequenceTooLarge,
        encode(.{ .sequence = max_sequence + 1, .addr = widest.addr }, &out),
    );
}

test "the transport parameter carries three roles and no fourth" {
    var value: [max_varint_length]u8 = undefined;
    // All three are below 64, so the parameter's declared length is 1 for
    // every role and noq's `len != value.size()` check can never fail on a
    // value this module wrote.
    for ([_]Role{ .send_only, .receive_only, .both }) |role| {
        const length = try encodeRole(role, &value);
        try t.expectEqual(@as(usize, 1), length);
        const read = try decodeRole(value[0..length]);
        try t.expectEqual(role, read.role);
        try t.expectEqual(length, read.length);
    }

    // A fourth value, the widest a varint can carry, and a value that ends
    // inside its own integer are three different refusals.
    try t.expectError(error.UnknownRole, decodeRole(&[_]u8{3}));
    // The widest spelling of a value outside the table, which is the same
    // refusal as the one-byte `03` and not a width this decoder cares about.
    try t.expectError(error.UnknownRole, decodeRole(&[_]u8{ 0xc0, 0, 0, 0, 0, 0, 0, 3 }));
    try t.expectError(error.Truncated, decodeRole(&[_]u8{}));
    try t.expectError(error.Truncated, decodeRole(&[_]u8{0x40}));
    try t.expectError(error.TrailingBytes, decodeRole(&[_]u8{ 0x02, 0x00 }));
}

test "a frame is sent only when both ends asked for it" {
    // The whole nine-cell table written out, because the rule has two
    // independent conditions and a caller that checks only its own role sends
    // frames the peer closes the connection over.
    const roles = [_]Role{ .send_only, .receive_only, .both };
    const table = [_][3]bool{
        // ours send_only:     theirs send_only, receive_only, both
        .{ false, true, true },
        // ours receive_only:  theirs send_only, receive_only, both
        .{ false, false, false },
        // ours both:          theirs send_only, receive_only, both
        .{ false, true, true },
    };
    for (table, roles) |row, ours| {
        for (row, roles) |expected, theirs| {
            try t.expectEqual(expected, ours.shouldReport(theirs));
        }
    }
}
