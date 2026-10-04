//! RFC 9000 §18 (with §9.6 and RFC 9368 §4): the QUIC transport parameters,
//! over `vendor/quic/src/quic/transport_params.zig`'s published
//! `TransportParams.decode`.
//!
//! §18.2 gives each parameter a wire form, and this file reads those forms
//! itself. Every parameter is `id (varint), length (varint), value` — RFC
//! 9000's extension mechanism — so `rfcWalk` below re-derives the decoded
//! value of every parameter it names, refuses the inputs §18.2, §9.6 and
//! RFC 9368 §4 refuse, and skips the ones §18.1 says a receiver must skip.
//! The decode's own struct is then compared field by field against that
//! derivation, so a defect in one parameter's length, value or absence is
//! caught by a reader that never called the decoder.
//!
//! Three things that are worth stating rather than leaving to be discovered.
//! A repeated parameter is decoded twice and the last occurrence wins, so this
//! walks to the end and compares the final map rather than the first hit. The
//! id `0xff04de1b` is spelled like one of RFC 9000 §18.1's greased identifiers
//! (31*N+27) and is a real parameter all the same, so an oracle that skipped
//! by grease rule would skip something the decode reads. And
//! `version_info_chosen_in_available` is the one field `encode` never writes,
//! which is why nothing here compares against an encoding.
//!
//! `decode` borrows the three connection ids out of the buffer it was handed
//! and owns every other value inline, so `checkDecoded` also asks that each
//! borrowed id really points into the input rather than at a copy.

const std = @import("std");
const quic = @import("quic");
const tp = quic.transport_params;

pub const Error = error{
    TestUnexpectedResult,
    TestExpectedEqual,
    TestExpectedError,
    TestUnexpectedError,
};

const Reason = error{ none, end_of_stream, bad_parameter };

/// RFC 9000 §16: one varint at the cursor, read from the table.
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

/// §16 applied to a value already known to be exactly one varint.
fn scalarValue(value: []const u8) u64 {
    var out: u64 = value[0] & 0x3f;
    for (value[1..]) |b| out = (out << 8) | b;
    return out;
}

/// §18.2's integer parameters, in one list. The enum value indexes the
/// expected-value table; the id is the wire value.
const Slots = enum(u8) {
    max_idle_timeout,
    max_udp_payload_size,
    initial_max_data,
    initial_max_stream_data_bidi_local,
    initial_max_stream_data_bidi_remote,
    initial_max_stream_data_uni,
    initial_max_streams_bidi,
    initial_max_streams_uni,
    ack_delay_exponent,
    max_ack_delay,
    active_connection_id_limit,
    max_datagram_frame_size,
    min_ack_delay,
};

const slot_count = std.enums.values(Slots).len;

fn slotOf(id: u64) ?Slots {
    return switch (id) {
        0x01 => .max_idle_timeout,
        0x03 => .max_udp_payload_size,
        0x04 => .initial_max_data,
        0x05 => .initial_max_stream_data_bidi_local,
        0x06 => .initial_max_stream_data_bidi_remote,
        0x07 => .initial_max_stream_data_uni,
        0x08 => .initial_max_streams_bidi,
        0x09 => .initial_max_streams_uni,
        0x0a => .ack_delay_exponent,
        0x0b => .max_ack_delay,
        0x0e => .active_connection_id_limit,
        0x20 => .max_datagram_frame_size,
        // draft-ietf-quic-ack-frequency's provisional id.
        0xff04de1b => .min_ack_delay,
        else => null,
    };
}

/// The value the decode holds for one §18.2 integer. A null means the
/// parameter has no value at all, which is different from a value of zero and
/// is how §18.2 marks `max_datagram_frame_size` and `min_ack_delay` absent.
fn readSlot(params: tp.TransportParams, slot: Slots) ?u64 {
    return switch (slot) {
        .max_idle_timeout => params.max_idle_timeout,
        .max_udp_payload_size => params.max_udp_payload_size,
        .initial_max_data => params.initial_max_data,
        .initial_max_stream_data_bidi_local => params.initial_max_stream_data_bidi_local,
        .initial_max_stream_data_bidi_remote => params.initial_max_stream_data_bidi_remote,
        .initial_max_stream_data_uni => params.initial_max_stream_data_uni,
        .initial_max_streams_bidi => params.initial_max_streams_bidi,
        .initial_max_streams_uni => params.initial_max_streams_uni,
        .ack_delay_exponent => params.ack_delay_exponent,
        .max_ack_delay => params.max_ack_delay,
        .active_connection_id_limit => params.active_connection_id_limit,
        .max_datagram_frame_size => params.max_datagram_frame_size,
        .min_ack_delay => params.min_ack_delay,
    };
}

/// §18.2's defaults, so a parameter the peer never sent still has a value to
/// be compared against. The three the RFC defines as absent are null; the rest
/// carry the default §18.2 names for them.
fn defaults() [slot_count]?u64 {
    return .{ 0, 65527, 0, 0, 0, 0, 0, 0, 3, 25, 2, null, null };
}

/// RFC 9368 §4's Version Information, recomputed from the wire list.
const VersionInfo = struct {
    present: bool = false,
    chosen: u32 = 0,
    count: u8 = 0,
    available: [8]u32 = .{0} ** 8,
    chosen_in_available: bool = false,
};

const Shape = struct {
    scalars: [slot_count]?u64 = defaults(),
    original_dcid: ?[]const u8 = null,
    initial_scid: ?[]const u8 = null,
    retry_scid: ?[]const u8 = null,
    reset_token: ?[16]u8 = null,
    migration_disabled: bool = false,
    preferred: ?tp.PreferredAddress = null,
    version: VersionInfo = .{},
};

/// RFC 9000 §9.6's Preferred Address: IPv4 address and port, IPv6 address and
/// port, a one-byte connection id length, the id, and a 16-byte stateless
/// reset token — 41 + cid_len octets, with a cid_len of 1 to 20.
fn preferredAddress(value: []const u8) Reason!tp.PreferredAddress {
    if (value.len < 42) return error.bad_parameter;
    var out: tp.PreferredAddress = .{};
    @memcpy(out.ipv4_addr[0..], value[0..4]);
    out.ipv4_port = std.mem.readInt(u16, value[4..6], .big);
    @memcpy(out.ipv6_addr[0..], value[6..22]);
    out.ipv6_port = std.mem.readInt(u16, value[22..24], .big);
    out.cid_len = value[24];
    if (out.cid_len == 0 or out.cid_len > 20) return error.bad_parameter;
    if (value.len != 41 + @as(usize, out.cid_len)) return error.bad_parameter;
    const cid_len: usize = out.cid_len;
    @memcpy(out.cid_buf[0..cid_len], value[25..][0..cid_len]);
    @memcpy(out.stateless_reset_token[0..], value[41 + cid_len ..]);
    return out;
}

/// RFC 9368 §4: a chosen version followed by a list of versions, four octets
/// each. Too short or not divisible by four is a parsing failure, and so is a
/// zero in either half — zero is not a version. The list may be longer than
/// the eight the value keeps, so every word is checked and membership is
/// decided over the whole list.
fn versionInfo(value: []const u8, out: *VersionInfo) Reason!void {
    if (value.len < 4 or value.len % 4 != 0) return error.bad_parameter;
    const chosen = std.mem.readInt(u32, value[0..4], .big);
    if (chosen == 0) return error.bad_parameter;
    out.present = true;
    out.chosen = chosen;
    out.chosen_in_available = false;
    var i: usize = 4;
    while (i < value.len) : (i += 4) {
        const version = std.mem.readInt(u32, value[i..][0..4], .big);
        if (version == 0) return error.bad_parameter;
        if ((i - 4) / 4 < 8) out.available[(i - 4) / 4] = version;
        if (version == chosen) out.chosen_in_available = true;
    }
    out.count = @intCast(@min((value.len - 4) / 4, 8));
}

/// §18's parameter list, walked from the RFC's own description of each id.
fn rfcWalk(bytes: []const u8) Reason!Shape {
    var out: Shape = .{};
    var cursor: usize = 0;
    while (cursor < bytes.len) {
        const id = try varintAt(bytes, &cursor);
        const length = try varintAt(bytes, &cursor);
        // A parameter cannot extend past the buffer it was decoded from.
        if (length > @as(u64, bytes.len - cursor)) return error.bad_parameter;
        const value = bytes[cursor..][0..@intCast(length)];

        if (slotOf(id)) |slot| {
            // §18.2: a scalar's declared length must be the width of the varint
            // it holds, and that width is named by the value's own first byte,
            // so a scalar cannot carry a wider encoding than it declares.
            const width: usize = if (value.len == 0) 0 else @as(usize, 1) << @intCast(value[0] >> 6);
            if (value.len == 0 or width != value.len) return error.bad_parameter;
            out.scalars[@intFromEnum(slot)] = scalarValue(value);
        } else {
            switch (id) {
                // §18.2: the three connection ids are length-prefixed opaque
                // fields rather than varints, so any length is legal.
                0x00 => {
                    out.original_dcid = value;
                },
                0x0f => {
                    out.initial_scid = value;
                },
                0x10 => {
                    out.retry_scid = value;
                },
                0x02 => {
                    if (length != 16) return error.bad_parameter;
                    var token: [16]u8 = undefined;
                    @memcpy(token[0..], value);
                    out.reset_token = token;
                },
                // §18.2: the value is empty, so a present parameter carrying
                // anything at all is a parsing failure.
                0x0c => {
                    if (length != 0) return error.bad_parameter;
                    out.migration_disabled = true;
                },
                0x0d => {
                    out.preferred = try preferredAddress(value);
                },
                0x11 => {
                    try versionInfo(value, &out.version);
                },
                // §18.1: an unknown id — a greased 31*N+27 among them — is
                // skipped by its declared length, not rejected.
                else => {},
            }
        }
        cursor += @intCast(length);
    }
    return out;
}

/// Oracle: a connection id is borrowed out of the decode buffer, so it must
/// point into these bytes at the offset §18.2 put it, and must hold what this
/// walk says the last occurrence of that parameter carried.
fn expectCid(bytes: []const u8, borrowed: ?[]const u8, want: ?[]const u8) Error!void {
    if (borrowed) |got| {
        const expected = want orelse return error.TestExpectedEqual;
        if (!std.mem.eql(u8, got, expected)) return error.TestExpectedEqual;
        if (got.len > bytes.len) return error.TestExpectedEqual;
        const base = @intFromPtr(bytes.ptr);
        const at = @intFromPtr(got.ptr);
        if (at < base or at - base > bytes.len - got.len) return error.TestExpectedEqual;
    } else if (want != null) return error.TestExpectedEqual;
}

/// Oracle: every §18.2 field, against the walk's derivation. `std.enums.values`
/// is in declaration order, which is the order `defaults` and the walk index by.
fn checkDecoded(bytes: []const u8, params: tp.TransportParams, shape: Shape) Error!void {
    for (std.enums.values(Slots), 0..) |slot, index| {
        const want = shape.scalars[index];
        const got = readSlot(params, slot);
        if (want == null) {
            // §18.2's two parameters with no default: a peer that sent none
            // must leave them absent, not zero.
            if (got != null) return error.TestExpectedEqual;
        } else if (got != want) return error.TestExpectedEqual;
    }

    try expectCid(bytes, params.original_destination_connection_id, shape.original_dcid);
    try expectCid(bytes, params.initial_source_connection_id, shape.initial_scid);
    try expectCid(bytes, params.retry_source_connection_id, shape.retry_scid);

    if (params.stateless_reset_token) |got| {
        const want = shape.reset_token orelse return error.TestExpectedEqual;
        if (!std.mem.eql(u8, &got, &want)) return error.TestExpectedEqual;
    } else if (shape.reset_token != null) return error.TestExpectedEqual;

    if (params.disable_active_migration != shape.migration_disabled) return error.TestExpectedEqual;
    if (!std.meta.eql(params.preferred_address, shape.preferred)) return error.TestExpectedEqual;

    if ((params.version_info_chosen != null) != shape.version.present) return error.TestExpectedEqual;
    if (shape.version.present) try checkVersion(params, shape.version);
}

/// Oracle: the version list, and the two different questions its membership
/// answers. `hasAvailableVersion` reads the eight the value keeps;
/// `chosenInAvailableVersions` also answers for a chosen version that sat past
/// the eighth, because RFC 9368 §3 lets a list be that long.
fn checkVersion(params: tp.TransportParams, want: VersionInfo) Error!void {
    const chosen = params.version_info_chosen orelse return error.TestUnexpectedResult;
    if (chosen != want.chosen) return error.TestExpectedEqual;
    const count = @as(usize, params.version_info_available_count);
    if (count != @as(usize, want.count)) return error.TestExpectedEqual;
    for (params.version_info_available[0..count], want.available[0..count]) |got, expect| {
        if (got != expect) return error.TestExpectedEqual;
    }
    if (params.version_info_chosen_in_available != want.chosen_in_available) {
        return error.TestExpectedEqual;
    }
    var in_prefix = false;
    for (want.available[0..count]) |version| {
        if (version == want.chosen) in_prefix = true;
    }
    if (params.hasAvailableVersion(want.chosen) != in_prefix) return error.TestExpectedEqual;
    if (params.chosenInAvailableVersions() != want.chosen_in_available) {
        return error.TestExpectedEqual;
    }
}

/// `TransportParams.decode` answers `TransportParameterError` for a wrong length
/// or a bad id, and lets a truncated varint surface as `EndOfStream` from §16,
/// so which arm comes back depends on where the truncation fell. The walk knows
/// which reason it reached and the decoder does not say, so this compares the
/// decision and not the arm.
pub fn check(input: []const u8) Error!void {
    const shape = rfcWalk(input) catch |why| {
        if (tp.TransportParams.decode(input)) |accepted| {
            _ = accepted;
            // The walk found a well-formed parameter list, so refusing it is a
            // defect rather than a refusal.
            return error.TestUnexpectedError;
        } else |err| {
            // A refusal is legal only where §18.2, §9.6 or RFC 9368 §4
            // condemns these bytes, and the decoder must refuse them too. Which
            // arm it used is not compared, because the decoder does not name
            // the reason the walk reached.
            std.mem.doNotOptimizeAway(&err);
            std.mem.doNotOptimizeAway(&why);
            return;
        }
    };

    const params = tp.TransportParams.decode(input) catch return error.TestExpectedError;
    try checkDecoded(input, params, shape);
}
