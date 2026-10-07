//! Native Noq 1.3 observed-address codecs and allocation-free per-path state.
//! Source: Noq c1f411562e6078852749b8bcf1190523096a107f, address_discovery.rs,
//! frame.rs ObservedAddr, and connection/paths.rs update_observed_addr_report.
//! The connection owns the global send sequence and commits it after emission.
//! Reports identify the packet's path, not a PathId carried inside the frame.

const std = @import("std");
const io = @import("../io_compat.zig");
const packet = @import("packet.zig");
const Address = @import("../address.zig").Address;

pub const transport_parameter_id: u64 = 0x9f81a176;
pub const ipv4_frame_type: u64 = 0x9f81a6;
pub const ipv6_frame_type: u64 = 0x9f81a7;
pub const sequence_max: u64 = (1 << 62) - 1;
pub const max_frame_length: usize = 4 + 8 + 16 + 2;

pub const CodecError = error{
    InvalidTransportParameter,
    InvalidFrame,
    InvalidAddress,
    InvalidSequence,
    NoSpaceLeft,
};

/// Disabled is represented by absence, never by a fourth wire value.
pub const Role = enum {
    disabled,
    send_only,
    receive_only,
    both,

    pub fn transportValue(self: Role) ?u64 {
        return switch (self) {
            .disabled => null,
            .send_only => 0,
            .receive_only => 1,
            .both => 2,
        };
    }

    /// Noq's enclosing TP parser requires length == decoded VarInt.size().
    pub fn decodeTransportValue(bytes: []const u8) CodecError!Role {
        var reader = io.fixedBufferStream(bytes);
        const value = packet.readVarInt(&reader) catch return error.InvalidTransportParameter;
        if (reader.seek != bytes.len) return error.InvalidTransportParameter;
        if (bytes.len != packet.varIntLength(value)) return error.InvalidTransportParameter;
        return switch (value) {
            0 => .send_only,
            1 => .receive_only,
            2 => .both,
            else => error.InvalidTransportParameter,
        };
    }

    pub fn shouldReport(self: Role, peer: Role) bool {
        return (self == .send_only or self == .both) and
            (peer == .receive_only or peer == .both);
    }
};

/// Inline native address ownership. IPv6 scope is deliberately not on wire.
pub const Report = struct {
    sequence: u64,
    address: Address,

    pub fn frameType(self: Report) CodecError!u64 {
        return switch (self.address) {
            .ipv4 => ipv4_frame_type,
            .ipv6 => ipv6_frame_type,
            .unset => error.InvalidAddress,
        };
    }

    pub fn length(self: Report) CodecError!usize {
        if (self.sequence > sequence_max) return error.InvalidSequence;
        const frame_type = try self.frameType();
        const address_length: usize = if (frame_type == ipv6_frame_type) 16 else 4;
        return packet.varIntLength(frame_type) +
            packet.varIntLength(self.sequence) + address_length + 2;
    }

    /// Writes type and body using the vendor's reader/writer surface.
    /// A writer failure can leave a prefix; discard the enclosing packet.
    pub fn write(self: Report, writer: anytype) !void {
        const frame_type = try self.frameType();
        if (self.sequence > sequence_max) return error.InvalidSequence;
        try packet.writeVarInt(writer, frame_type);
        try packet.writeVarInt(writer, self.sequence);
        switch (self.address) {
            .ipv4 => |address| {
                try writer.writeAll(&address.bytes);
                try writer.writeInt(u16, address.port, .big);
            },
            .ipv6 => |address| {
                try writer.writeAll(&address.bytes);
                try writer.writeInt(u16, address.port, .big);
            },
            .unset => unreachable,
        }
    }

    /// Checked fixed-buffer encoding does not mutate a short destination.
    pub fn encode(self: Report, bytes: []u8) CodecError!usize {
        const required = try self.length();
        if (bytes.len < required) return error.NoSpaceLeft;
        var writer = io.fixedBufferStream(bytes);
        self.write(&writer) catch return error.NoSpaceLeft;
        return writer.seek;
    }

    /// Body only: the frame parser already consumed and identified the type.
    /// Nonminimal sequence varints are legal, matching Noq's private decoder.
    pub fn read(reader: anytype, is_ipv6: bool) !Report {
        const sequence = try packet.readVarInt(reader);
        const address: Address = if (is_ipv6) address: {
            const bytes = (try reader.takeArray(16)).*;
            const port = try reader.takeInt(u16, .big);
            break :address .initIpv6(bytes, port, 0);
        } else address: {
            const bytes = (try reader.takeArray(4)).*;
            const port = try reader.takeInt(u16, .big);
            break :address .initIpv4(bytes, port);
        };
        return .{ .sequence = sequence, .address = address };
    }
};

pub const Decoded = struct {
    report: Report,
    consumed: usize,
};

/// Returns body bytes consumed, leaving following frames to the caller.
pub fn decodeBody(frame_type: u64, bytes: []const u8) CodecError!Decoded {
    const is_ipv6 = switch (frame_type) {
        ipv4_frame_type => false,
        ipv6_frame_type => true,
        else => return error.InvalidFrame,
    };
    var reader = io.fixedBufferStream(bytes);
    const report = Report.read(&reader, is_ipv6) catch return error.InvalidFrame;
    return .{ .report = report, .consumed = reader.seek };
}

/// Returns type plus body bytes consumed, not the length of the whole packet.
pub fn decode(bytes: []const u8) CodecError!Decoded {
    var reader = io.fixedBufferStream(bytes);
    const frame_type = packet.readVarInt(&reader) catch return error.InvalidFrame;
    const parsed = try decodeBody(frame_type, bytes[reader.seek..]);
    return .{ .report = parsed.report, .consumed = reader.seek + parsed.consumed };
}

pub const ReceiveContext = struct {
    local_role: Role,
    peer_role: Role,
    data_space: bool,
};

/// Reset this state for each new network path, including migration.
/// The connection handles open-path event deferral and packet path attribution.
pub const PathState = struct {
    pending: bool = false,
    last_received: ?Report = null,

    /// Called on negotiation, path creation, migration and path probes.
    pub fn schedule(self: *PathState, local: Role, peer: Role) void {
        self.pending = local.shouldReport(peer);
    }

    pub fn lost(self: *PathState, local: Role, peer: Role) void {
        self.schedule(local, peer);
    }

    /// No mutation until the caller writes a whole report and commits it.
    /// The caller must gate abandoned paths and non-Data packet spaces.
    pub fn prepare(
        self: *const PathState,
        local: Role,
        peer: Role,
        remote: Address,
        sequence: u64,
    ) CodecError!?Report {
        if (!local.shouldReport(peer)) return null;
        if (!self.pending) return null;
        const report: Report = .{ .sequence = sequence, .address = remote };
        const required = try report.length();
        std.debug.assert(required <= max_frame_length);
        return report;
    }

    pub fn sent(self: *PathState) void {
        std.debug.assert(self.pending);
        self.pending = false;
    }
};

pub const ReceiveTransition = struct {
    state: PathState,
    address: ?Address,
};

/// The caller owns mutation and decides when an address event becomes visible.
/// Older/equal sequence leaves the input state unchanged; a newer identical
/// endpoint advances the watermark without emitting another address event.
pub fn receiveTransition(
    state: PathState,
    report: Report,
    context: ReceiveContext,
) error{ProtocolViolation}!ReceiveTransition {
    if (!context.peer_role.shouldReport(context.local_role)) return error.ProtocolViolation;
    if (!context.data_space) return error.ProtocolViolation;
    const required = report.length() catch return error.ProtocolViolation;
    std.debug.assert(required <= max_frame_length);
    var next = state;
    if (state.last_received) |previous| {
        if (previous.sequence >= report.sequence) return .{ .state = state, .address = null };
        if (Address.eql(previous.address, report.address)) {
            next.last_received.?.sequence = report.sequence;
            return .{ .state = next, .address = null };
        }
    }
    next.last_received = report;
    return .{ .state = next, .address = report.address };
}

test "observed role negotiation is directional and malformed values fail closed" {
    const roles = [_]Role{ .disabled, .send_only, .receive_only, .both };
    for (roles) |local| {
        for (roles) |peer| {
            const expected = (local == .send_only or local == .both) and
                (peer == .receive_only or peer == .both);
            try std.testing.expectEqual(expected, local.shouldReport(peer));
        }
    }
    try std.testing.expectEqual(@as(?u64, null), Role.disabled.transportValue());
    for ([_]Role{ .send_only, .receive_only, .both }, 0..) |role, value| {
        try std.testing.expectEqual(@as(?u64, value), role.transportValue());
        try std.testing.expectEqual(role, try Role.decodeTransportValue(&.{@intCast(value)}));
        // Noq requires the declared TP length to equal the minimal varint width.
        try std.testing.expectError(error.InvalidTransportParameter,
            Role.decodeTransportValue(&.{ 0x40, @intCast(value) }));
    }
    for ([_][]const u8{ &.{}, &.{3}, &.{0x40}, &.{ 0, 0 }, &.{ 0x40, 3 } }) |bytes| {
        try std.testing.expectError(error.InvalidTransportParameter, Role.decodeTransportValue(bytes));
    }
}

test "observed frame roundtrip boundaries truncation and consumed length" {
    const addresses = [_]Address{
        .initIpv4(.{ 203, 0, 113, 9 }, 443),
        .initIpv6(.{ 0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }, 65535, 0),
    };
    for (addresses) |address| {
        for ([_]u64{ 0, 63, 64, 16383, 16384, 1073741823, 1073741824, sequence_max }) |sequence| {
            const report: Report = .{ .sequence = sequence, .address = address };
            var bytes: [max_frame_length + 1]u8 = undefined;
            const length = try report.encode(&bytes);
            try std.testing.expectEqual(try report.length(), length);
            bytes[length] = 1;
            const parsed = try decode(bytes[0 .. length + 1]);
            try std.testing.expectEqual(length, parsed.consumed);
            try std.testing.expectEqual(sequence, parsed.report.sequence);
            try std.testing.expect(Address.eql(address, parsed.report.address));
            for (0..length) |cut| {
                try std.testing.expectError(error.InvalidFrame, decode(bytes[0..cut]));
            }
            try std.testing.expectError(error.NoSpaceLeft, report.encode(bytes[0 .. length - 1]));
            var short = [_]u8{0xaa} ** max_frame_length;
            try std.testing.expectError(error.NoSpaceLeft, report.encode(short[0 .. length - 1]));
            try std.testing.expectEqualSlices(u8,
                &([_]u8{0xaa} ** max_frame_length), &short);
        }
    }
    const unset: Report = .{ .sequence = 0, .address = .unset };
    try std.testing.expectError(error.InvalidAddress, unset.length());
    const overflow: Report = .{ .sequence = sequence_max + 1, .address = addresses[0] };
    try std.testing.expectError(error.InvalidSequence, overflow.length());
    try std.testing.expectError(error.InvalidFrame, decodeBody(1, &.{}));
    // A nonminimal sequence remains legal and is normalized on encode.
    const overlong = try decodeBody(ipv4_frame_type, &.{ 0x40, 0, 127, 0, 0, 1, 0, 80 });
    try std.testing.expectEqual(@as(u64, 0), overlong.report.sequence);
    try std.testing.expectEqual(@as(usize, 8), overlong.consumed);
}

test "observed pure receive transition filters stale reports per path" {
    const initial: PathState = .{};
    const context: ReceiveContext = .{
        .local_role = .receive_only, .peer_role = .send_only, .data_space = true,
    };
    const first: Report = .{ .sequence = 5, .address = .initIpv4(.{ 1, 2, 3, 4 }, 80) };
    const changed: Report = .{ .sequence = 4, .address = .initIpv4(.{ 1, 2, 3, 4 }, 81) };
    var transition = try receiveTransition(initial, first, context);
    try std.testing.expect(initial.last_received == null);
    try std.testing.expect(Address.eql(first.address, transition.address.?));
    transition = try receiveTransition(transition.state, changed, context);
    try std.testing.expect(transition.address == null);
    try std.testing.expectEqual(@as(u64, 5), transition.state.last_received.?.sequence);
    var same = first;
    same.sequence = 6;
    transition = try receiveTransition(transition.state, same, context);
    try std.testing.expect(transition.address == null);
    try std.testing.expectEqual(@as(u64, 6), transition.state.last_received.?.sequence);
    var next = changed;
    next.sequence = 6;
    transition = try receiveTransition(transition.state, next, context);
    try std.testing.expect(transition.address == null);
    next.sequence = 7;
    transition = try receiveTransition(transition.state, next, context);
    try std.testing.expect(Address.eql(next.address, transition.address.?));
    const other_path = try receiveTransition(initial, changed, context);
    try std.testing.expect(other_path.address != null);
    for ([_]ReceiveContext{
        .{ .local_role = .disabled, .peer_role = .both, .data_space = true },
        .{ .local_role = .both, .peer_role = .receive_only, .data_space = true },
        .{ .local_role = .both, .peer_role = .both, .data_space = false },
    }) |denied| {
        try std.testing.expectError(error.ProtocolViolation,
            receiveTransition(transition.state, next, denied));
        try std.testing.expectEqual(@as(u64, 7), transition.state.last_received.?.sequence);
    }
}

test "observed pure receive transition rejects malformed reports" {
    const context: ReceiveContext = .{
        .local_role = .both, .peer_role = .both, .data_space = true,
    };
    const valid: Report = .{ .sequence = 1, .address = .initIpv4(.{ 1, 2, 3, 4 }, 80) };
    const transition = try receiveTransition(.{}, valid, context);
    try std.testing.expect(transition.address != null);
    for ([_]Report{
        .{ .sequence = 2, .address = .unset },
        .{ .sequence = sequence_max + 1, .address = valid.address },
    }) |invalid| {
        try std.testing.expectError(error.ProtocolViolation,
            receiveTransition(transition.state, invalid, context));
        try std.testing.expectEqual(@as(u64, 1), transition.state.last_received.?.sequence);
        try std.testing.expect(Address.eql(valid.address, transition.state.last_received.?.address));
    }
}

test "observed path schedules retransmission without consuming sequence before commit" {
    var state: PathState = .{};
    const remote: Address = .initIpv4(.{ 127, 0, 0, 1 }, 443);
    state.schedule(.send_only, .receive_only);
    try std.testing.expect(state.pending);
    const report = (try state.prepare(.send_only, .receive_only, remote, 2)).?;
    try std.testing.expectEqual(@as(u64, 2), report.sequence);
    try std.testing.expect(state.pending);
    state.sent();
    try std.testing.expectEqual(@as(?Report, null), try state.prepare(.both, .both, remote, 3));
    state.lost(.both, .both);
    try std.testing.expect((try state.prepare(.both, .both, remote, 3)) != null);
    try std.testing.expectEqual(@as(?Report, null), try state.prepare(.disabled, .both, remote, 3));
    state.schedule(.both, .disabled);
    try std.testing.expect(!state.pending);
}

test "observed decoder fuzz normalizes successful frames" {
    try std.testing.fuzz({}, fuzzDecode, .{});
}

fn fuzzDecode(_: void, smith: *std.testing.Smith) !void {
    var bytes: [max_frame_length + 8]u8 = undefined;
    const count = smith.slice(&bytes);
    if (Role.decodeTransportValue(bytes[0..count])) |role| {
        try std.testing.expect(role != .disabled);
        const canonical = [_]u8{@intCast(role.transportValue().?)};
        try std.testing.expectEqual(role, try Role.decodeTransportValue(&canonical));
    } else |_| {}
    const parsed = decode(bytes[0..count]) catch return;
    var encoded: [max_frame_length]u8 = undefined;
    const length = try parsed.report.encode(&encoded);
    const again = try decode(encoded[0..length]);
    try std.testing.expectEqual(parsed.report.sequence, again.report.sequence);
    try std.testing.expect(Address.eql(parsed.report.address, again.report.address));
    try std.testing.expectEqual(length, again.consumed);
}

test "observed frame structured fuzz preserves address and sequence" {
    try std.testing.fuzz({}, fuzzReport, .{});
}

fn fuzzReport(_: void, smith: *std.testing.Smith) !void {
    const sequence = smith.value(u64) & sequence_max;
    const port = smith.value(u16);
    var ipv6_bytes: [16]u8 = undefined;
    smith.bytes(&ipv6_bytes);
    const address: Address = if (smith.value(bool))
        .initIpv6(ipv6_bytes, port, 0)
    else
        .initIpv4(ipv6_bytes[0..4].*, port);
    const report: Report = .{ .sequence = sequence, .address = address };
    var bytes: [max_frame_length]u8 = undefined;
    const count = try report.encode(&bytes);
    const parsed = try decode(bytes[0..count]);
    try std.testing.expectEqual(sequence, parsed.report.sequence);
    try std.testing.expect(Address.eql(address, parsed.report.address));
}

test "observed IPv6 reports omit interface scope as upstream does" {
    const report: Report = .{
        .sequence = 0,
        .address = .initIpv6([_]u8{0} ** 16, 80, 9),
    };
    var bytes: [max_frame_length]u8 = undefined;
    const count = try report.encode(&bytes);
    const parsed = try decode(bytes[0..count]);
    try std.testing.expectEqual(@as(u32, 0), parsed.report.address.ipv6.scope_id);
}
