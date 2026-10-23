//! QUIC transport-parameter encoding and decoding without I/O or allocation.
//! Decoded CID slices borrow the input; all other decoded fields are inline.
//! Known fields must consume their complete declared value, and a
//! `version_information` whose length is not a multiple of four, or that
//! carries a zero chosen or available version, is refused rather than
//! skipped (RFC 9368 §4). Unknown IDs are skipped within that boundary.

const std = @import("std");
const io = @import("../io_compat.zig");
const testing = std.testing;

const address = @import("../address.zig");

const packet = @import("packet.zig");
const protocol = @import("protocol.zig");
const observed_address = @import("observed_address.zig");
const native_nat = @import("native_nat.zig");

/// QUIC Transport Parameter IDs (RFC 9000 Section 18.2).
///
/// The values are the varint that goes on the wire, so `@intFromEnum` of a
/// tag is what `encode` writes and what `decode` switches on. `_` catches
/// every other ID — unknown extension parameters and the greased IDs of
/// RFC 9000 §18.1 (31*N+27), which `decode` skips by their declared length
/// rather than rejecting.
pub const ParamId = enum(u64) {
    original_destination_connection_id = 0x00,
    max_idle_timeout = 0x01,
    stateless_reset_token = 0x02,
    max_udp_payload_size = 0x03,
    initial_max_data = 0x04,
    initial_max_stream_data_bidi_local = 0x05,
    initial_max_stream_data_bidi_remote = 0x06,
    initial_max_stream_data_uni = 0x07,
    initial_max_streams_bidi = 0x08,
    initial_max_streams_uni = 0x09,
    ack_delay_exponent = 0x0a,
    max_ack_delay = 0x0b,
    disable_active_migration = 0x0c,
    preferred_address = 0x0d,
    active_connection_id_limit = 0x0e,
    initial_source_connection_id = 0x0f,
    retry_source_connection_id = 0x10,
    version_information = 0x11, // RFC 9368
    max_datagram_frame_size = 0x20,
    min_ack_delay = 0xff04de1b, // draft-ietf-quic-ack-frequency (provisional)
    observed_address = observed_address.transport_parameter_id,
    initial_max_path_id = 0x3e,
    n0_nat_traversal = native_nat.transport_parameter_id,
    _,
};

/// Server's Preferred Address (RFC 9000 §9.6, §18.2).
///
/// Every field is fixed-size, so the whole parameter is owned by value: it
/// borrows nothing, allocates nothing, has no teardown, and copying it copies
/// every byte. It is peer-supplied, so a non-null `TransportParams.preferred_address`
/// is a claim a peer made about an address this endpoint has not verified.
pub const PreferredAddress = struct {
    /// The offered IPv4 address as 4 octets in network order.
    ipv4_addr: [4]u8 = .{0} ** 4,
    /// Network byte order. 0 is how RFC 9000 §9.6 says the IPv4 half is
    /// absent, so a zero port means `hasIpv4` is false and the address octets
    /// beside it are meaningless.
    ipv4_port: u16 = 0,
    /// The offered IPv6 address as 16 octets in network order.
    ipv6_addr: [16]u8 = .{0} ** 16,
    /// Network byte order, with the same 0-means-absent rule as `ipv4_port`.
    ipv6_port: u16 = 0,
    /// Inline storage for the connection ID the peer wants this endpoint to
    /// use when migrating. Fixed at 20 bytes because that is the RFC 9000
    /// §17.2 maximum connection ID length; only `cid_buf[0..cid_len]` is the
    /// ID and the rest is zero.
    cid_buf: [20]u8 = .{0} ** 20,
    /// Caller-enforced length, 1..20 when offered. The default zero is not an
    /// offered address. `decode` rejects lengths outside 1..20; `encode` trusts
    /// the local value and slices `cid_buf` by this length.
    cid_len: u8 = 0,
    /// The reset token to use for the connection ID the peer chose. Peer-
    /// supplied and unverifiable, and it is the only thing that makes a reset
    /// for the migrated connection recognisable.
    stateless_reset_token: [16]u8 = .{0} ** 16,

    /// Whether the peer offered an IPv4 address, which RFC 9000 §9.6 encodes
    /// as a non-zero port.
    pub fn hasIpv4(self: *const PreferredAddress) bool {
        return self.ipv4_port != 0;
    }

    /// Whether the peer offered an IPv6 address, on the same zero-port rule as
    /// `hasIpv4`. The two are independent: a peer may offer one, the other, or
    /// both.
    pub fn hasIpv6(self: *const PreferredAddress) bool {
        return self.ipv6_port != 0;
    }

    /// The connection ID the peer chose for this endpoint's use, as
    /// `cid_buf[0..cid_len]`.
    ///
    /// Borrowed from this value, so it dies with it: a caller that keeps the
    /// ID past the `PreferredAddress` copies it. It is empty when `cid_len` is
    /// 0, and `decode` never produces that — a peer that offers a preferred
    /// address must carry a connection ID with it.
    pub fn getCid(self: *const PreferredAddress) []const u8 {
        return self.cid_buf[0..self.cid_len];
    }

    /// The IPv4 address this parameter offers, as the core holds an address.
    pub fn ipv4Address(self: *const PreferredAddress) address.Address {
        return address.Address.initIpv4(self.ipv4_addr, self.ipv4_port);
    }

    /// The IPv6 address this parameter offers, as the core holds an address.
    ///
    /// The scope is zero and the wire format is why: RFC 9000 §9.6 carries no
    /// scope, so a peer that offers a link-local address here has named one
    /// that no interface can be inferred for, and guessing an interface for it
    /// would be the core inventing a path the peer never said existed.
    pub fn ipv6Address(self: *const PreferredAddress) address.Address {
        return address.Address.initIpv6(self.ipv6_addr, self.ipv6_port, 0);
    }
};

/// QUIC Transport Parameters (RFC 9000 Section 18).
///
/// One value serves both directions and both roles: `Connection` fills one to
/// send as its own limits, and `decode` fills one from what a peer sent. Only
/// the connection IDs are borrows — they point into the buffer `decode` was
/// handed — and everything else is either a scalar or inline fixed storage, so
/// a decoded value owns nothing but those three slices and needs no teardown.
/// A field is peer-supplied when it came out of `decode` and locally set when
/// the caller put it there; `encode` emits a field only when it differs from
/// its RFC default, so a value left at the default is a value not sent.
///
/// Every integer parameter below is a QUIC varint on the wire, so its legal
/// range is 0 to 2^62-1 and nothing here narrows it further.
pub const TransportParams = struct {
    /// The connection ID this connection started with, as a length-prefixed
    /// opaque field rather than a varint. `null` means the parameter was not
    /// sent, which for a server is a protocol violation rather than an option;
    /// `encode` writes whatever slice it holds and `decode` borrows it out of
    /// its input, so it dies with that buffer.
    original_destination_connection_id: ?[]const u8 = null,
    /// Milliseconds, as a varint. 0 is the RFC default and is not sent; there
    /// is no other sentinel, so an endpoint that means "no timeout" states 0
    /// and lets the peer apply its own policy.
    max_idle_timeout: u64 = 0,
    /// 16 raw bytes, not a varint: the token to recognise a stateless reset
    /// from this peer. `null` means the peer sent none, which is why this is
    /// optional while RFC 9000 §10.3.1 requires it once the peer might issue a
    /// Retry. A decode rejects any other length as
    /// `error.TransportParameterError`.
    stateless_reset_token: ?[16]u8 = null,
    /// Bytes. 65527 is the RFC default and is not sent; RFC 9000 §18.2 bounds
    /// it below by 1200, the QUIC minimum datagram, and `Connection` is what
    /// enforces that on a peer's value.
    max_udp_payload_size: u64 = 65527,
    /// Bytes of connection-level flow control credit, as a varint. 0 is the
    /// default and is not sent, which a peer reads as "no credit yet" rather
    /// than "unlimited".
    initial_max_data: u64 = 0,
    /// Bytes of flow control credit for a bidirectional stream this endpoint
    /// opened. Varint, 0 default, 0 means zero credit and is not sent.
    initial_max_stream_data_bidi_local: u64 = 0,
    /// Bytes of flow control credit for a bidirectional stream the peer
    /// opened. Varint, 0 default, 0 means zero credit and is not sent.
    initial_max_stream_data_bidi_remote: u64 = 0,
    /// Bytes of flow control credit for a unidirectional stream the peer
    /// opened. Varint, 0 default, 0 means zero credit and is not sent.
    initial_max_stream_data_uni: u64 = 0,
    /// How many bidirectional streams the peer may open, as a varint. 0 is
    /// the default and is not sent, so an endpoint that sets it grants a
    /// lifetime budget rather than a rate.
    initial_max_streams_bidi: u64 = 0,
    /// How many unidirectional streams the peer may open. Varint, 0 default,
    /// 0 is not sent.
    initial_max_streams_uni: u64 = 0,
    /// ACK delay exponent, default 3 and at most 20 (RFC 9000 §18.2).
    /// Frames encode microseconds scaled by this exponent; RTT uses nanoseconds.
    ack_delay_exponent: u64 = 3,
    /// Milliseconds — the wire unit, unlike the nanoseconds `RttStats` keeps.
    /// 25 is the RFC default and is not sent; RFC 9000 §18.2 caps it at 2^14,
    /// and `Connection` closes the connection on a larger peer value.
    max_ack_delay: u64 = 25,
    /// True requests no peer migration and emits an empty parameter. False
    /// omits it. `decode` rejects a present value with nonzero length.
    disable_active_migration: bool = false,
    /// Server address offered in encrypted transport parameters; `null` omits
    /// it. Inline storage makes copies independent; it is not a Retry field.
    preferred_address: ?PreferredAddress = null,
    /// How many connection IDs the peer may hold, as a varint. 2 is the RFC
    /// default and is not sent; RFC 9000 §18.2 sets 2 as the floor, and a
    /// smaller peer value is a transport parameter error for `Connection` to
    /// detect.
    active_connection_id_limit: u64 = 2,
    /// The connection ID this endpoint chose as its source, length-prefixed
    /// opaque rather than a varint. `null` means not sent. On decode it
    /// borrows the input buffer; `Connection` sets it locally before its own
    /// first flight.
    initial_source_connection_id: ?[]const u8 = null,
    /// The connection ID from the Retry that caused this attempt, same
    /// encoding. `null` means no Retry happened, which is the ordinary case
    /// and is not an error.
    retry_source_connection_id: ?[]const u8 = null,
    /// Bytes: the largest DATAGRAM frame payload the sender will accept, as a
    /// varint. `null` is not "unlimited" but "this endpoint does not support
    /// DATAGRAM at all" (RFC 9221), and it is the parameter's absence that
    /// tells the peer so — there is no zero value that means it.
    max_datagram_frame_size: ?u64 = null,
    /// Microseconds: the minimum delay the sender will put between ACKs if
    /// asked. `null` means the ACK-frequency extension is not supported and
    /// the parameter is not sent, which is the answer a peer acts on.
    min_ack_delay: ?u64 = null,
    /// RFC 9368 version_information transport parameter.
    /// chosen_version: the version used for this connection.
    /// available_versions: list of all supported versions (up to 8).
    ///
    /// `null` means the parameter is absent, and `encode` writes neither half
    /// without it: the available list is nested inside it on the wire, so a
    /// populated `version_info_available` with a null chosen version is
    /// locally built state that never reaches the peer.
    ///
    /// Zero is not a version. RFC 9368 §4 makes a chosen version of zero a
    /// parsing failure, and `decode` refuses it, so a decoded value is either
    /// null — no parameter — or a version the peer can actually speak.
    version_info_chosen: ?u32 = null,
    /// The peer-supported versions, big-endian on the wire. Only
    /// `version_info_available[0..version_info_available_count]` is
    /// meaningful; the tail is zero-filled and ignored by every reader here.
    /// `decode` keeps the first 8 and drops the rest — but it checks every
    /// entry of a longer list on the way past, so a zero behind the eighth is
    /// refused rather than dropped unread.
    version_info_available: [8]u32 = .{0} ** 8,
    /// How many entries of `version_info_available` are set, 0 to 8. It is
    /// the count `encode` writes and the bound `hasAvailableVersion` reads to,
    /// so a value above 8 would read past the array. Zero here means an empty
    /// list, which RFC 9368 §3 lets a server send; it is not the zero version,
    /// which `decode` refuses.
    version_info_available_count: u8 = 0,
    /// Whether `version_info_chosen` appears anywhere in the peer's Available
    /// Versions list, including entries past the eight `version_info_available`
    /// retains. RFC 9368 §4 makes a chosen version absent from that list a
    /// parsing failure, and the list can be longer than this value keeps, so
    /// `decode` records the membership it saw rather than leaving a reader to
    /// infer it from a prefix that may not hold the answer.
    ///
    /// `decode` is the only writer, and it decides over every word of the
    /// declared list. `encode` ignores it, so it does not round-trip. A
    /// locally built value leaves it false, and for such a value the stored
    /// prefix IS the whole list — which is why `chosenInAvailableVersions`
    /// also consults the prefix, making this a widening rather than the whole
    /// answer. An empty available list is not a contradiction: RFC 9368 §3
    /// lets a server send one, and the Chosen Version need not be in it.
    ///
    /// The three version fields are public, so anything that changes
    /// `version_info_chosen`, `version_info_available` or
    /// `version_info_available_count` after a decode invalidates this: clear
    /// it, or set it to what the new list says. Left stale it answers about
    /// the list the peer sent rather than the one in hand.
    version_info_chosen_in_available: bool = false,

    address_discovery_role: observed_address.Role = .disabled,
    /// Peer capacity is a nonzero raw byte, not a QUIC varint.
    max_remote_nat_traversal_addresses: ?u8 = null,
    /// Local advertisement is bounded to path IDs zero and one.
    initial_max_path_id: ?u32 = null,

    /// Check if a version is listed in the peer's available versions.
    ///
    /// Reads only the first `version_info_available_count` entries, so a
    /// version past 8 on the wire is invisible here even though `decode` read
    /// and checked it. `version_info_chosen` is not consulted: this answers
    /// about what the peer can speak, not about what it chose.
    pub fn hasAvailableVersion(self: *const TransportParams, version: u32) bool {
        for (0..self.version_info_available_count) |i| {
            if (self.version_info_available[i] == version) return true;
        }
        return false;
    }

    /// Whether `version_info_chosen` is in the peer's Available Versions.
    ///
    /// This is the question RFC 9368 §4 asks, and it is not the question
    /// `hasAvailableVersion` answers: a chosen version can sit past the eight
    /// this value retains — a client that lists eight reserved versions and
    /// then chooses QUIC v1 is a legal §3 list — and reading membership out of
    /// the retained prefix alone would call that peer a liar. `decode` sets
    /// the flag from the whole list, so the prefix is consulted only for a
    /// value no decode produced, where the prefix is the whole list.
    ///
    /// A null chosen version is false: there is nothing to have chosen.
    pub fn chosenInAvailableVersions(self: *const TransportParams) bool {
        const chosen = self.version_info_chosen orelse return false;
        return self.version_info_chosen_in_available or self.hasAvailableVersion(chosen);
    }

    /// Encode transport parameters into a buffer.
    ///
    /// `random` is drawn once, and only for the greased parameter below.
    ///
    /// Each parameter is emitted only when it differs from its RFC default, so
    /// a `TransportParams` left at its defaults writes almost nothing — but the
    /// greased parameter is always written, so the output is never empty.
    /// `version_information` is written only when `version_info_chosen` is
    /// non-null, and carries `version_info_available_count` entries.
    ///
    /// `writer` supplies `writeAll`, `writeByte` and `writeInt`, typically
    /// through `FixedBufferStream`; the caller's writer
    /// owns the bytes and nothing is borrowed from it afterwards.
    /// Writer errors or `error.VarIntTooLarge` may leave a prefix to discard.
    /// Inline lengths must fit their buffers; CID lengths must be at most 20
    /// and the version count at most 8. Allocates nothing and rolls nothing back.
    pub fn encode(self: *const TransportParams, writer: anytype, random: std.Random) !void {
        // Helper to write a single parameter
        const Helper = struct {
            fn writeParam(w: anytype, id: ParamId, value: u64) !void {
                try packet.writeVarInt(w, @intFromEnum(id));
                const len = packet.varIntLength(value);
                try packet.writeVarInt(w, len);
                try packet.writeVarInt(w, value);
            }

            fn writeParamBytes(w: anytype, id: ParamId, data: []const u8) !void {
                try packet.writeVarInt(w, @intFromEnum(id));
                try packet.writeVarInt(w, data.len);
                try w.writeAll(data);
            }

            fn writeParamEmpty(w: anytype, id: ParamId) !void {
                try packet.writeVarInt(w, @intFromEnum(id));
                try packet.writeVarInt(w, 0);
            }
        };

        if (self.original_destination_connection_id) |cid| {
            try Helper.writeParamBytes(writer, .original_destination_connection_id, cid);
        }

        if (self.max_idle_timeout > 0) {
            try Helper.writeParam(writer, .max_idle_timeout, self.max_idle_timeout);
        }

        if (self.stateless_reset_token) |token| {
            try packet.writeVarInt(writer, @intFromEnum(ParamId.stateless_reset_token));
            try packet.writeVarInt(writer, 16);
            try writer.writeAll(&token);
        }

        if (self.max_udp_payload_size != 65527) {
            try Helper.writeParam(writer, .max_udp_payload_size, self.max_udp_payload_size);
        }

        if (self.initial_max_data > 0) {
            try Helper.writeParam(writer, .initial_max_data, self.initial_max_data);
        }

        if (self.initial_max_stream_data_bidi_local > 0) {
            try Helper.writeParam(writer, .initial_max_stream_data_bidi_local, self.initial_max_stream_data_bidi_local);
        }

        if (self.initial_max_stream_data_bidi_remote > 0) {
            try Helper.writeParam(writer, .initial_max_stream_data_bidi_remote, self.initial_max_stream_data_bidi_remote);
        }

        if (self.initial_max_stream_data_uni > 0) {
            try Helper.writeParam(writer, .initial_max_stream_data_uni, self.initial_max_stream_data_uni);
        }

        if (self.initial_max_streams_bidi > 0) {
            try Helper.writeParam(writer, .initial_max_streams_bidi, self.initial_max_streams_bidi);
        }

        if (self.initial_max_streams_uni > 0) {
            try Helper.writeParam(writer, .initial_max_streams_uni, self.initial_max_streams_uni);
        }

        if (self.ack_delay_exponent != 3) {
            try Helper.writeParam(writer, .ack_delay_exponent, self.ack_delay_exponent);
        }

        if (self.max_ack_delay != 25) {
            try Helper.writeParam(writer, .max_ack_delay, self.max_ack_delay);
        }

        if (self.disable_active_migration) {
            try Helper.writeParamEmpty(writer, .disable_active_migration);
        }

        if (self.preferred_address) |pref| {
            try packet.writeVarInt(writer, @intFromEnum(ParamId.preferred_address));
            // Length: 4+2 + 16+2 + 1+cid_len + 16 = 41 + cid_len
            const pref_len: u64 = 41 + @as(u64, pref.cid_len);
            try packet.writeVarInt(writer, pref_len);
            try writer.writeAll(&pref.ipv4_addr);
            try writer.writeAll(&std.mem.toBytes(std.mem.nativeToBig(u16, pref.ipv4_port)));
            try writer.writeAll(&pref.ipv6_addr);
            try writer.writeAll(&std.mem.toBytes(std.mem.nativeToBig(u16, pref.ipv6_port)));
            try writer.writeByte(pref.cid_len);
            try writer.writeAll(pref.cid_buf[0..pref.cid_len]);
            try writer.writeAll(&pref.stateless_reset_token);
        }

        if (self.active_connection_id_limit != 2) {
            try Helper.writeParam(writer, .active_connection_id_limit, self.active_connection_id_limit);
        }

        if (self.initial_source_connection_id) |cid| {
            try Helper.writeParamBytes(writer, .initial_source_connection_id, cid);
        }

        if (self.retry_source_connection_id) |cid| {
            try Helper.writeParamBytes(writer, .retry_source_connection_id, cid);
        }

        if (self.max_datagram_frame_size) |size| {
            try Helper.writeParam(writer, .max_datagram_frame_size, size);
        }

        if (self.min_ack_delay) |delay| {
            try Helper.writeParam(writer, .min_ack_delay, delay);
        }

        if (self.address_discovery_role.transportValue()) |role| {
            try Helper.writeParam(writer, .observed_address, role);
        }
        if (self.initial_max_path_id) |maximum| {
            if (maximum > 1) return error.TransportParameterError;
            try Helper.writeParam(writer, .initial_max_path_id, maximum);
        }
        if (self.max_remote_nat_traversal_addresses) |capacity| {
            if (capacity == 0) return error.TransportParameterError;
            try Helper.writeParamBytes(writer, .n0_nat_traversal, &.{capacity});
        }

        // RFC 9000 §18.1: Transport parameter greasing — send a reserved parameter
        // with ID of form 31*N+27 so peers learn to ignore unknown parameters.
        //
        // This draw is a protocol probe, not a secret, and the two halves of
        // that pull in opposite directions. It has to be unpredictable, or a
        // peer learns the one ID we always send and special-cases it, which is
        // the parser bug the probe exists to find. It has to be reproducible,
        // or no test can assert on the bytes it produced. So it stays a plain
        // draw from the caller's generator: hardening it into a value that
        // "must come from a CSPRNG" buys nothing — a peer ignores it either
        // way — and pinning it to a constant retires the probe entirely.
        {
            var grease_entropy: [6]u8 = undefined;
            random.bytes(&grease_entropy);
            // Pick N in [0..255], giving IDs like 27, 58, 89, ...
            const n: u64 = @as(u64, grease_entropy[0]);
            const grease_id: u64 = 31 * n + 27;
            // Value: 1-4 random bytes
            const grease_val_len: u64 = @as(u64, grease_entropy[1] & 0x03) + 1;
            try packet.writeVarInt(writer, grease_id);
            try packet.writeVarInt(writer, grease_val_len);
            try writer.writeAll(grease_entropy[2..][0..@intCast(grease_val_len)]);
        }

        // RFC 9368: version_information
        if (self.version_info_chosen) |chosen| {
            const n = self.version_info_available_count;
            const param_len: u64 = 4 + @as(u64, n) * 4; // chosen(4) + available(n*4)
            try packet.writeVarInt(writer, @intFromEnum(ParamId.version_information));
            try packet.writeVarInt(writer, param_len);
            try writer.writeInt(u32, chosen, .big);
            for (0..n) |i| {
                try writer.writeInt(u32, self.version_info_available[i], .big);
            }
        }
    }

    /// Decode transport parameters from a buffer.
    ///
    /// The returned connection IDs — `original_destination_connection_id`,
    /// `initial_source_connection_id` and `retry_source_connection_id` — point
    /// into `data`, so `data` must stay alive and unmodified for as long as the
    /// decoded `TransportParams` is used; nothing is copied and nothing is
    /// allocated. Every other field is an inline value the decode owns.
    ///
    /// `error.TransportParameterError` means an invalid TLV boundary, a scalar
    /// whose varint does not fill its declared length, a reset token other than
    /// 16 bytes, a nonempty migration-disable flag, an incomplete preferred
    /// address or CID outside 1..20 bytes, or a `version_information` too
    /// short for the chosen version it has to carry, one whose length is not
    /// a multiple of four, or one whose chosen version or any available
    /// version is zero (RFC 9368 §4). `error.EndOfStream` means a truncated
    /// parameter ID. Neither error returns a partial value, and those two are
    /// the whole set this signature can return.
    ///
    /// Unknown IDs, including grease, are skipped by their declared length.
    /// Native extension duplicates fail closed; other fields retain existing behavior.
    pub fn decode(data: []const u8) error{ TransportParameterError, EndOfStream }!TransportParams {
        var params = TransportParams{};
        var fbs = io.fixedBufferStream(data);
        const reader = &fbs;

        while (fbs.seek < data.len) {
            const param_id = try packet.readVarInt(reader);
            // A parameter cannot extend past the buffer it was decoded from,
            // and its varint length has to survive a 32-bit usize.
            const param_len = packet.readVarIntUsize(reader) catch
                return error.TransportParameterError;
            if (param_len > data.len - fbs.seek) return error.TransportParameterError;
            const param_start = fbs.seek;

            switch (param_id) {
                @intFromEnum(ParamId.observed_address) => {
                    if (params.address_discovery_role != .disabled)
                        return error.TransportParameterError;
                    params.address_discovery_role = observed_address.Role.decodeTransportValue(
                        data[fbs.seek..][0..param_len],
                    ) catch return error.TransportParameterError;
                    fbs.seek += param_len;
                },
                @intFromEnum(ParamId.initial_max_path_id) => {
                    if (params.initial_max_path_id != null) return error.TransportParameterError;
                    const maximum = try readParamVarInt(reader, param_len);
                    if (maximum > std.math.maxInt(u32)) return error.TransportParameterError;
                    if (param_len != packet.varIntLength(maximum))
                        return error.TransportParameterError;
                    params.initial_max_path_id = @intCast(maximum);
                },
                @intFromEnum(ParamId.n0_nat_traversal) => {
                    if (params.max_remote_nat_traversal_addresses != null)
                        return error.TransportParameterError;
                    if (param_len != 1) return error.TransportParameterError;
                    const capacity = try reader.takeByte();
                    if (capacity == 0) return error.TransportParameterError;
                    params.max_remote_nat_traversal_addresses = capacity;
                },
                @intFromEnum(ParamId.original_destination_connection_id) => {
                    params.original_destination_connection_id = data[fbs.seek..][0..param_len];
                    fbs.seek += param_len;
                },
                @intFromEnum(ParamId.max_idle_timeout) => {
                    params.max_idle_timeout = try readParamVarInt(reader, param_len);
                },
                @intFromEnum(ParamId.stateless_reset_token) => {
                    if (param_len != 16) return error.TransportParameterError;
                    var token: [16]u8 = undefined;
                    try reader.readSliceAll(&token);
                    params.stateless_reset_token = token;
                },
                @intFromEnum(ParamId.max_udp_payload_size) => {
                    params.max_udp_payload_size = try readParamVarInt(reader, param_len);
                },
                @intFromEnum(ParamId.initial_max_data) => {
                    params.initial_max_data = try readParamVarInt(reader, param_len);
                },
                @intFromEnum(ParamId.initial_max_stream_data_bidi_local) => {
                    params.initial_max_stream_data_bidi_local = try readParamVarInt(reader, param_len);
                },
                @intFromEnum(ParamId.initial_max_stream_data_bidi_remote) => {
                    params.initial_max_stream_data_bidi_remote = try readParamVarInt(reader, param_len);
                },
                @intFromEnum(ParamId.initial_max_stream_data_uni) => {
                    params.initial_max_stream_data_uni = try readParamVarInt(reader, param_len);
                },
                @intFromEnum(ParamId.initial_max_streams_bidi) => {
                    params.initial_max_streams_bidi = try readParamVarInt(reader, param_len);
                },
                @intFromEnum(ParamId.initial_max_streams_uni) => {
                    params.initial_max_streams_uni = try readParamVarInt(reader, param_len);
                },
                @intFromEnum(ParamId.ack_delay_exponent) => {
                    params.ack_delay_exponent = try readParamVarInt(reader, param_len);
                },
                @intFromEnum(ParamId.max_ack_delay) => {
                    params.max_ack_delay = try readParamVarInt(reader, param_len);
                },
                @intFromEnum(ParamId.disable_active_migration) => {
                    params.disable_active_migration = true;
                },
                @intFromEnum(ParamId.preferred_address) => {
                    if (param_len < 42) return error.TransportParameterError;
                    var pref = PreferredAddress{};
                    try reader.readSliceAll(&pref.ipv4_addr);
                    var ipv4_port_bytes: [2]u8 = undefined;
                    try reader.readSliceAll(&ipv4_port_bytes);
                    pref.ipv4_port = std.mem.readInt(u16, &ipv4_port_bytes, .big);
                    try reader.readSliceAll(&pref.ipv6_addr);
                    var ipv6_port_bytes: [2]u8 = undefined;
                    try reader.readSliceAll(&ipv6_port_bytes);
                    pref.ipv6_port = std.mem.readInt(u16, &ipv6_port_bytes, .big);
                    pref.cid_len = try reader.takeByte();
                    if (pref.cid_len == 0 or pref.cid_len > 20) {
                        return error.TransportParameterError;
                    }
                    if (param_len != 41 + @as(usize, pref.cid_len)) {
                        return error.TransportParameterError;
                    }
                    try reader.readSliceAll(pref.cid_buf[0..pref.cid_len]);
                    try reader.readSliceAll(&pref.stateless_reset_token);
                    params.preferred_address = pref;
                },
                @intFromEnum(ParamId.active_connection_id_limit) => {
                    params.active_connection_id_limit = try readParamVarInt(reader, param_len);
                },
                @intFromEnum(ParamId.initial_source_connection_id) => {
                    params.initial_source_connection_id = data[fbs.seek..][0..param_len];
                    fbs.seek += param_len;
                },
                @intFromEnum(ParamId.retry_source_connection_id) => {
                    params.retry_source_connection_id = data[fbs.seek..][0..param_len];
                    fbs.seek += param_len;
                },
                @intFromEnum(ParamId.max_datagram_frame_size) => {
                    params.max_datagram_frame_size = try readParamVarInt(reader, param_len);
                },
                @intFromEnum(ParamId.min_ack_delay) => {
                    params.min_ack_delay = try readParamVarInt(reader, param_len);
                },
                @intFromEnum(ParamId.version_information) => {
                    // RFC 9368 §4: too short, or not divisible by four, is a
                    // parsing failure the endpoint has to act on. Skipping it
                    // left `version_info_chosen` null, which is also what a
                    // peer that sent no Version Information looks like — so a
                    // list built to downgrade the negotiation was read as no
                    // list at all.
                    if (param_len < 4 or (param_len % 4) != 0) {
                        return error.TransportParameterError;
                    }
                    const chosen = try reader.takeInt(u32, .big);
                    // A zero chosen version is a parsing failure by the same
                    // sentence, and storing it would hand every reader below
                    // a version statement the RFC says is a failure.
                    if (chosen == 0) return error.TransportParameterError;
                    params.version_info_chosen = chosen;

                    // Every word of the declared list is read and checked, not
                    // only the eight this value keeps. The eight are what
                    // `hasAvailableVersion` can search; they are not what the
                    // peer sent, and a zero sitting behind that boundary is
                    // still a zero. The loop consumes exactly
                    // 4 + avail_count * 4 == param_len, so the walk still ends
                    // on this parameter's last byte and the trailing
                    // boundary check needs no skip to satisfy it.
                    const avail_count = (param_len - 4) / 4;
                    const retained = @min(avail_count, params.version_info_available.len);
                    // Membership is decided over every word, not over the
                    // retained prefix: a chosen version past the eighth is a
                    // legal §3 list, and a prefix-only answer would report that
                    // peer as contradicting itself. Reset per occurrence, so a
                    // repeated parameter still lets the last one win here as
                    // it does for every other field.
                    params.version_info_chosen_in_available = false;
                    for (0..avail_count) |i| {
                        const version = try reader.takeInt(u32, .big);
                        if (version == 0) return error.TransportParameterError;
                        if (i < retained) params.version_info_available[i] = version;
                        if (version == chosen) params.version_info_chosen_in_available = true;
                    }
                    params.version_info_available_count = @intCast(retained);
                },
                else => {
                    // Unknown parameter - skip
                    fbs.seek = param_start + param_len;
                },
            }

            if (fbs.seek != param_start + param_len) return error.TransportParameterError;
        }

        return params;
    }
};

/// The largest number of bytes `TransportParams.encode` can produce from a
/// value whose every field is set to its own largest legal value, and the
/// ceiling a caller must give that encode to be sure nothing is truncated.
/// This is a property of `encode`, not of any one caller, so it is named here
/// rather than beside each buffer somebody hands it.
///
/// QUIC varints take 1, 2, 4 or 8 bytes and every id below except
/// `min_ack_delay` (0xff04de1b) encodes in 1; each connection-id parameter
/// carries at most the RFC 9000 §17.2 maximum of 20 bytes, and
/// `preferred_address` is 41 + `cid_len`. Per parameter, worst case:
/// original_destination_connection_id 22, max_idle_timeout 10,
/// stateless_reset_token 18, max_udp_payload_size 10, initial_max_data 10,
/// initial_max_stream_data_bidi_local 10, initial_max_stream_data_bidi_remote
/// 10, initial_max_stream_data_uni 10, initial_max_streams_bidi 10,
/// initial_max_streams_uni 10, ack_delay_exponent 3, max_ack_delay 10,
/// disable_active_migration 2, preferred_address 63, active_connection_id_limit
/// 10, initial_source_connection_id 22, retry_source_connection_id 22,
/// max_datagram_frame_size 10, min_ack_delay 17, the greased parameter 7 and
/// version_information 38 — 324 in total.
///
/// Requires legal varints, at most 20-byte connection IDs, at most 8 nonzero
/// versions and ACK exponent at most 20. A zero in either half of
/// `version_information` is legal for `encode` to write and refused by
/// `decode`, so such output does not round-trip. Invalid inline lengths may
/// trap before a writer can report an error. This bound is derived, not a
/// measured runtime cost.
pub const encode_len_max: usize = 324;

/// Reads a scalar parameter whose declared length must be exactly the varint
/// the value itself occupies: the top two bits of the first byte name the
/// width, so the length is checked against the encoding rather than trusted.
fn readParamVarInt(reader: anytype, param_len: usize) error{TransportParameterError}!u64 {
    if (param_len == 0) return error.TransportParameterError;
    const encoded_len = @as(usize, 1) << @intCast(reader.buffer[reader.seek] >> 6);
    if (param_len != encoded_len) return error.TransportParameterError;
    return packet.readVarInt(reader) catch return error.TransportParameterError;
}

// Tests

test "TransportParams: encode and decode roundtrip" {
    const original = TransportParams{
        .max_idle_timeout = 30000,
        .initial_max_data = 1048576,
        .initial_max_stream_data_bidi_local = 65536,
        .initial_max_stream_data_bidi_remote = 65536,
        .initial_max_stream_data_uni = 65536,
        .initial_max_streams_bidi = 100,
        .initial_max_streams_uni = 100,
        .active_connection_id_limit = 4,
        .max_datagram_frame_size = 65536,
    };

    var prng = std.Random.DefaultPrng.init(0x726f756e);
    var buf: [512]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    try original.encode(&fbs, prng.random());

    const encoded = fbs.buffered();
    const decoded = try TransportParams.decode(encoded);

    try testing.expectEqual(original.max_idle_timeout, decoded.max_idle_timeout);
    try testing.expectEqual(original.initial_max_data, decoded.initial_max_data);
    try testing.expectEqual(original.initial_max_stream_data_bidi_local, decoded.initial_max_stream_data_bidi_local);
    try testing.expectEqual(original.initial_max_streams_bidi, decoded.initial_max_streams_bidi);
    try testing.expectEqual(original.initial_max_streams_uni, decoded.initial_max_streams_uni);
    try testing.expectEqual(original.active_connection_id_limit, decoded.active_connection_id_limit);
    try testing.expectEqual(original.max_datagram_frame_size, decoded.max_datagram_frame_size);
}

test "TransportParams: default values" {
    const params = TransportParams{};
    try testing.expectEqual(@as(u64, 65527), params.max_udp_payload_size);
    try testing.expectEqual(@as(u64, 3), params.ack_delay_exponent);
    try testing.expectEqual(@as(u64, 25), params.max_ack_delay);
    try testing.expectEqual(@as(u64, 2), params.active_connection_id_limit);
    try testing.expect(!params.disable_active_migration);
}

test "TransportParams: encode empty params" {
    const params = TransportParams{};
    var prng = std.Random.DefaultPrng.init(0x656d7074);
    var buf: [512]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    try params.encode(&fbs, prng.random());

    // Empty params should produce minimal output
    const encoded = fbs.buffered();
    const decoded = try TransportParams.decode(encoded);

    try testing.expectEqual(@as(u64, 65527), decoded.max_udp_payload_size);
    try testing.expectEqual(@as(u64, 3), decoded.ack_delay_exponent);
}

// PreferredAddress encode/decode roundtrip
test "TransportParams: preferred_address roundtrip" {
    var pref = PreferredAddress{};
    pref.ipv4_addr = .{ 10, 0, 0, 1 };
    pref.ipv4_port = 4433;
    pref.ipv6_addr = .{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01 };
    pref.ipv6_port = 4434;
    pref.cid_len = 8;
    @memset(pref.cid_buf[0..8], 0xAB);
    @memset(&pref.stateless_reset_token, 0xCD);

    const original = TransportParams{
        .max_idle_timeout = 30000,
        .preferred_address = pref,
    };
    var prng = std.Random.DefaultPrng.init(0x70726566);

    var buf: [512]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    try original.encode(&fbs, prng.random());

    const decoded = try TransportParams.decode(fbs.buffered());
    try testing.expect(decoded.preferred_address != null);

    const dp = decoded.preferred_address.?;
    try testing.expectEqualSlices(u8, &pref.ipv4_addr, &dp.ipv4_addr);
    try testing.expectEqual(pref.ipv4_port, dp.ipv4_port);
    try testing.expectEqualSlices(u8, &pref.ipv6_addr, &dp.ipv6_addr);
    try testing.expectEqual(pref.ipv6_port, dp.ipv6_port);
    try testing.expectEqual(pref.cid_len, dp.cid_len);
    try testing.expectEqualSlices(u8, pref.cid_buf[0..8], dp.cid_buf[0..8]);
    try testing.expectEqualSlices(u8, &pref.stateless_reset_token, &dp.stateless_reset_token);
}

test "TransportParams: disable_active_migration roundtrip" {
    const original = TransportParams{
        .disable_active_migration = true,
        .max_idle_timeout = 10000,
    };
    var prng = std.Random.DefaultPrng.init(0x6d696772);

    var buf: [512]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    try original.encode(&fbs, prng.random());

    const decoded = try TransportParams.decode(fbs.buffered());
    try testing.expect(decoded.disable_active_migration);
    try testing.expectEqual(@as(u64, 10000), decoded.max_idle_timeout);
}

test "TransportParams: version_information roundtrip" {
    var original = TransportParams{
        .max_idle_timeout = 5000,
    };
    original.version_info_chosen = protocol.QUIC_V1;
    original.version_info_available = .{ protocol.QUIC_V2, protocol.QUIC_V1, 0, 0, 0, 0, 0, 0 };
    original.version_info_available_count = 2;
    var prng = std.Random.DefaultPrng.init(0x76657273);

    var buf: [512]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    try original.encode(&fbs, prng.random());

    const decoded = try TransportParams.decode(fbs.buffered());
    try testing.expectEqual(protocol.QUIC_V1, decoded.version_info_chosen);
    try testing.expectEqual(@as(u8, 2), decoded.version_info_available_count);
    try testing.expectEqual(protocol.QUIC_V2, decoded.version_info_available[0]);
    try testing.expectEqual(protocol.QUIC_V1, decoded.version_info_available[1]);
}

test "TransportParams: a version_information length that is not a multiple of four is refused" {
    // RFC 9368 §4: Version Information that is too short, or whose length is
    // not divisible by four, is a parsing failure the endpoint has to act on —
    // on QUIC v1, TRANSPORT_PARAMETER_ERROR. Skipping it left every reader
    // downstream looking at a null chosen version, which is what a peer that
    // sent no version information at all also looks like.
    inline for (.{ 0, 1, 2, 3, 5, 6, 7, 9 }) |value_len| {
        var buffer: [32]u8 = undefined;
        var writer = io.fixedBufferStream(&buffer);
        try packet.writeVarInt(&writer, @intFromEnum(ParamId.version_information));
        try packet.writeVarInt(&writer, value_len);
        try writer.writeAll(&([_]u8{0x11} ** value_len));
        try testing.expectError(
            error.TransportParameterError,
            TransportParams.decode(writer.buffered()),
        );
    }

    // What the RFC does allow survives both ways: a chosen version with no
    // available versions beside it, and a list longer than the eight this
    // buffer keeps, which holds the first eight rather than being refused.
    var buffer: [64]u8 = undefined;
    var writer = io.fixedBufferStream(&buffer);
    try packet.writeVarInt(&writer, @intFromEnum(ParamId.version_information));
    try packet.writeVarInt(&writer, 4 + 10 * 4);
    try writer.writeInt(u32, protocol.QUIC_V1, .big);
    for (0..10) |i| {
        try writer.writeInt(u32, 0xface_0000 + @as(u32, @intCast(i)), .big);
    }

    const decoded = try TransportParams.decode(writer.buffered());
    try testing.expectEqual(protocol.QUIC_V1, decoded.version_info_chosen);
    try testing.expectEqual(@as(u8, 8), decoded.version_info_available_count);
    try testing.expectEqual(@as(u32, 0xface_0000), decoded.version_info_available[0]);
    try testing.expectEqual(@as(u32, 0xface_0007), decoded.version_info_available[7]);
}

/// The ten-word available list the version-information tests below walk:
/// QUIC v2 first, then nine further distinct nonzero versions, so a retained
/// entry is recognisable by the position it was written at.
fn version_list_entry(index: usize) u32 {
    return if (index == 0) protocol.QUIC_V2 else 0xface_0000 + @as(u32, @intCast(index - 1));
}

/// A `max_idle_timeout` TLV, a ten-entry `version_information` with the word
/// at `zero_at` (if any) zeroed, and a `disable_active_migration` TLV. The two
/// neighbours are what make the assertion about `version_information` rather
/// than about the walk: a skip that ran short or long would consume one of
/// them, so the legal decode below only succeeds if the declared length is
/// consumed exactly.
///
/// `01 04 80 00 75 30 | 11 2c <chosen> <ten words> | 0c 00`. The leading TLV is
/// the one shape easy to get wrong by hand: 30000 needs a four-byte QUIC
/// varint, and a four-byte varint's first byte carries `10` in its top two
/// bits, so the value is `80 00 75 30` and not `00 00 75 30`. Written as a
/// bare big-endian `u32` the latter decodes as a varint of some other width,
/// which `readParamVarInt` refuses before `version_information` is ever
/// reached — a fixture failure, not the refusal under test.
fn write_neighboured_version_information(out: []u8, zero_at: ?usize) ![]const u8 {
    var writer = io.fixedBufferStream(out);
    try packet.writeVarInt(&writer, @intFromEnum(ParamId.max_idle_timeout));
    try packet.writeVarInt(&writer, 4);
    try writer.writeInt(u32, 0x8000_7530, .big);
    try packet.writeVarInt(&writer, @intFromEnum(ParamId.version_information));
    try packet.writeVarInt(&writer, 4 + 10 * 4);
    try writer.writeInt(u32, protocol.QUIC_V1, .big);
    for (0..10) |i| {
        const zero_here = zero_at != null and zero_at.? == i;
        try writer.writeInt(u32, if (zero_here) 0 else version_list_entry(i), .big);
    }
    try packet.writeVarInt(&writer, @intFromEnum(ParamId.disable_active_migration));
    try packet.writeVarInt(&writer, 0);
    return writer.buffered();
}

test "TransportParams: a zero chosen version is refused" {
    // RFC 9368 §4: "If an endpoint receives a Chosen Version equal to zero,
    // or any Available Version equal to zero, it MUST treat it as a parsing
    // failure" — on QUIC v1, TRANSPORT_PARAMETER_ERROR. Decoding zero as a
    // fact is worse than refusing it, because every reader downstream
    // (`hasAvailableVersion`, `Connection.validatePeerTransportParams`)
    // treats a non-null chosen version as a version statement and none of
    // them tests it against zero.
    //
    // 11 04 00 00 00 00 — chosen 0x00000000, no available versions at all.
    const chosen_alone = [_]u8{ 0x11, 0x04, 0x00, 0x00, 0x00, 0x00 };
    try testing.expectError(error.TransportParameterError, TransportParams.decode(&chosen_alone));

    // 11 08 00 00 00 00 00 00 00 01 — chosen 0, available {QUIC_V1}. A
    // nonzero available list does not make the chosen half legal.
    const chosen_with_available = [_]u8{
        0x11, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    };
    try testing.expectError(
        error.TransportParameterError,
        TransportParams.decode(&chosen_with_available),
    );

    // The same chosen version with an empty available list is the shape
    // RFC 9368 §3 lets a server send — the Chosen Version need not be in the
    // list, and the list MAY be empty — and it survives.
    const server_shape = [_]u8{ 0x11, 0x04, 0x00, 0x00, 0x00, 0x01 };
    const decoded = try TransportParams.decode(&server_shape);
    try testing.expectEqual(protocol.QUIC_V1, decoded.version_info_chosen);
    try testing.expectEqual(@as(u8, 0), decoded.version_info_available_count);
}

test "TransportParams: a zero available version among the eight stored is refused" {
    // Every one of the eight retained slots in turn, so the refusal is not an
    // accident of position: `11 24` (length 36), `00 00 00 01` for the chosen
    // version, then eight words that are all QUIC_V2 but for the one zeroed.
    inline for (0..8) |zero_at| {
        var buffer: [38]u8 = undefined;
        var writer = io.fixedBufferStream(&buffer);
        try packet.writeVarInt(&writer, @intFromEnum(ParamId.version_information));
        try packet.writeVarInt(&writer, 4 + 8 * 4);
        try writer.writeInt(u32, protocol.QUIC_V1, .big);
        for (0..8) |i| {
            try writer.writeInt(u32, if (i == zero_at) @as(u32, 0) else protocol.QUIC_V2, .big);
        }
        try testing.expectError(error.TransportParameterError, TransportParams.decode(
            writer.buffered(),
        ));
    }
}

test "TransportParams: a zero available version past the eight stored is refused" {
    // The eight slots are a retention limit, not a validation limit. RFC 9368
    // §4 says "any Available Version equal to zero", so a zero in the ninth
    // or the tenth word has to be refused rather than skipped along with the
    // rest of a list this buffer does not keep: `11 2c` (length 44),
    // `00 00 00 01` for the chosen version, then the ten words of
    // `version_list_entry` with the word at `zero_at` zeroed. Both positions
    // past the retained eight are covered, so neither the first dropped word
    // nor the last one on the wire can carry a zero.
    inline for (.{ 8, 9 }) |zero_at| {
        var buffer: [46]u8 = undefined;
        var writer = io.fixedBufferStream(&buffer);
        try packet.writeVarInt(&writer, @intFromEnum(ParamId.version_information));
        try packet.writeVarInt(&writer, 4 + 10 * 4);
        try writer.writeInt(u32, protocol.QUIC_V1, .big);
        for (0..10) |i| {
            try writer.writeInt(u32, if (i == zero_at) 0 else version_list_entry(i), .big);
        }
        try testing.expectError(error.TransportParameterError, TransportParams.decode(
            writer.buffered(),
        ));
    }
}

test "TransportParams: a legal version_information leaves its neighbours decodable" {
    // The legal ten-word list: eight entries retained, the ninth and tenth
    // checked and dropped, and both neighbouring TLVs read. The parameter is
    // 44 bytes of value, and the walk has to land exactly on the end of it.
    var buffer: [64]u8 = undefined;
    const legal = try write_neighboured_version_information(&buffer, null);
    const decoded = try TransportParams.decode(legal);
    try testing.expectEqual(@as(u64, 30000), decoded.max_idle_timeout);
    try testing.expect(decoded.disable_active_migration);
    try testing.expectEqual(protocol.QUIC_V1, decoded.version_info_chosen);
    try testing.expectEqual(@as(u8, 8), decoded.version_info_available_count);
    try testing.expectEqual(@as(u32, protocol.QUIC_V2), decoded.version_info_available[0]);
    try testing.expectEqual(@as(u32, 0xface_0000), decoded.version_info_available[1]);
    try testing.expectEqual(@as(u32, 0xface_0006), decoded.version_info_available[7]);
    // The ninth word is validated and dropped, so it is not searchable: the
    // retention limit stays the eight `hasAvailableVersion` reads.
    try testing.expect(!decoded.hasAvailableVersion(0xface_0007));

    // The same three TLVs with one word zeroed are refused, whichever slot
    // holds it. The refusal is this parameter's: the identical buffer without
    // the zero decoded above, neighbours and all.
    inline for (.{ 0, 7, 8, 9 }) |zero_at| {
        var refused: [64]u8 = undefined;
        const result = TransportParams.decode(
            try write_neighboured_version_information(&refused, zero_at),
        );
        try testing.expectError(error.TransportParameterError, result);
    }
}

test "TransportParams: connection IDs roundtrip" {
    const scid = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    const odcid = [_]u8{ 0x11, 0x12, 0x13, 0x14 };

    const original = TransportParams{
        .initial_source_connection_id = &scid,
        .original_destination_connection_id = &odcid,
        .max_idle_timeout = 30000,
    };
    var prng = std.Random.DefaultPrng.init(0x63696473);

    var buf: [512]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    try original.encode(&fbs, prng.random());

    const decoded = try TransportParams.decode(fbs.buffered());
    try testing.expect(decoded.initial_source_connection_id != null);
    try testing.expectEqualSlices(u8, &scid, decoded.initial_source_connection_id.?);
    try testing.expect(decoded.original_destination_connection_id != null);
    try testing.expectEqualSlices(u8, &odcid, decoded.original_destination_connection_id.?);
}

// RFC 9000 §18.1: greased transport parameters are encoded and decode is tolerant
test "TransportParams: greasing roundtrip" {
    const original = TransportParams{
        .max_idle_timeout = 30000,
        .initial_max_data = 1048576,
    };

    // Two generators, seeded alike. `encode` draws the greased parameter from
    // the generator it is handed, so one seed gives the same bytes twice and
    // the encoder's output becomes something a test can read.
    var prng1 = std.Random.DefaultPrng.init(0x67726561);
    var prng2 = std.Random.DefaultPrng.init(0x67726561);

    var buf: [512]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    try original.encode(&fbs, prng1.random());

    // Decode should succeed — unknown params (greased) are silently ignored
    const decoded = try TransportParams.decode(fbs.buffered());
    try std.testing.expectEqual(@as(u64, 30000), decoded.max_idle_timeout);
    try std.testing.expectEqual(@as(u64, 1048576), decoded.initial_max_data);

    var buf2: [512]u8 = undefined;
    var fbs2 = io.fixedBufferStream(&buf2);
    try original.encode(&fbs2, prng2.random());
    const decoded2 = try TransportParams.decode(fbs2.buffered());
    try std.testing.expectEqual(@as(u64, 30000), decoded2.max_idle_timeout);
    try std.testing.expectEqualSlices(u8, buf[0..fbs.seek], buf2[0..fbs2.seek]);

    // The greased id sits in the reserved 31*N+27 family, and in this encoding
    // nothing else does: a peer handed the same id every handshake can learn to
    // tolerate that id specifically, which is the bug the probe exists to find.
    var walk = io.fixedBufferStream(buf[0..fbs.seek]);
    var greased: ?u64 = null;
    while (walk.seek < walk.buffer.len) {
        const id = try packet.readVarInt(&walk);
        const len = try packet.readVarIntUsize(&walk);
        if (id % 31 == 27) greased = id;
        walk.seek += len;
    }
    try std.testing.expect(greased != null);
}

test "transport parameter longer than the buffer is rejected" {
    // id=0x00 (original_destination_connection_id), len=16383, 2 bytes present.
    const params = [_]u8{ 0x00, 0x7f, 0xff, 0xaa, 0xbb };
    try std.testing.expectError(error.TransportParameterError, TransportParams.decode(&params));
}

test "TransportParams: scalar values must fill their declared length" {
    inline for (.{
        ParamId.max_idle_timeout,
        ParamId.max_udp_payload_size,
        ParamId.initial_max_data,
        ParamId.initial_max_stream_data_bidi_local,
        ParamId.initial_max_stream_data_bidi_remote,
        ParamId.initial_max_stream_data_uni,
        ParamId.initial_max_streams_bidi,
        ParamId.initial_max_streams_uni,
        ParamId.ack_delay_exponent,
        ParamId.max_ack_delay,
        ParamId.active_connection_id_limit,
        ParamId.max_datagram_frame_size,
        ParamId.min_ack_delay,
    }) |id| {
        var buffer: [16]u8 = undefined;
        var writer = io.fixedBufferStream(&buffer);
        try packet.writeVarInt(&writer, @intFromEnum(id));
        // A zero-length value must not borrow the following parameter's id.
        try packet.writeVarInt(&writer, 0);
        try packet.writeVarInt(&writer, @intFromEnum(ParamId.disable_active_migration));
        try packet.writeVarInt(&writer, 0);
        try testing.expectError(error.TransportParameterError, TransportParams.decode(
            writer.buffered(),
        ));

        writer.seek = 0;
        try packet.writeVarInt(&writer, @intFromEnum(id));
        try packet.writeVarInt(&writer, 2);
        try writer.writeAll(&.{ 5, 7 });
        try testing.expectError(error.TransportParameterError, TransportParams.decode(
            writer.buffered(),
        ));
    }
}

const preferred_test_parameter =
    [_]u8{ @intFromEnum(ParamId.preferred_address), 42 } ++
    ([_]u8{0} ** 24) ++ [_]u8{ 1, 0xaa } ++ ([_]u8{0xcd} ** 16);

test "TransportParams: preferred addresses require a nonempty cid" {
    var buffer = preferred_test_parameter;
    buffer[26] = 0;
    // The fixed fields and reset token fit, but CID length zero is invalid.
    buffer[1] = 41;
    try testing.expectError(error.TransportParameterError, TransportParams.decode(buffer[0..43]));

    const valid = (try TransportParams.decode(&preferred_test_parameter)).preferred_address.?;
    try testing.expectEqualSlices(u8, &.{0xaa}, valid.getCid());
    try testing.expectEqualSlices(u8, &([_]u8{0xcd} ** 16), &valid.stateless_reset_token);
}

test "TransportParams: preferred addresses require complete fixed fields and reset token" {
    var buffer = preferred_test_parameter;

    // Each short value still fits its TLV envelope; the contents do not.
    for (0..42) |short_by| {
        const length = 41 - short_by;
        buffer[1] = @intCast(length);
        try testing.expectError(error.TransportParameterError, TransportParams.decode(
            buffer[0 .. length + 2],
        ));
    }
}

test "Noq native extension parameters source vectors and duplicates" {
    // Source oracle: transport_parameters.rs encodes NAT capacity as one raw byte.
    var buffer: [64]u8 = undefined;
    var writer = io.fixedBufferStream(&buffer);
    try packet.writeVarInt(&writer, 0x9f81a176);
    try writer.writeAll(&.{ 1, 2 });
    try writer.writeAll(&.{ 0x3e, 1, 1 });
    try packet.writeVarInt(&writer, 0x3d7f91120401);
    try writer.writeAll(&.{ 1, 255 });
    const parsed = try TransportParams.decode(writer.buffered());
    try testing.expectEqual(observed_address.Role.both, parsed.address_discovery_role);
    try testing.expectEqual(@as(?u32, 1), parsed.initial_max_path_id);
    try testing.expectEqual(@as(?u8, 255), parsed.max_remote_nat_traversal_addresses);
    const prefix_len = writer.seek;
    @memcpy(buffer[prefix_len..][0..prefix_len], buffer[0..prefix_len]);
    try testing.expectError(error.TransportParameterError, TransportParams.decode(buffer[0 .. prefix_len * 2]));
    writer.seek = 0;
    try packet.writeVarInt(&writer, 0x3d7f91120401);
    try writer.writeAll(&.{ 1, 0 });
    try testing.expectError(error.TransportParameterError, TransportParams.decode(writer.buffered()));
}

test "native transport parameters reject malformed lengths and canonicality" {
    const ids = [_]u64{ 0x9f81a176, 0x3e, 0x3d7f91120401 };
    for (ids) |id| {
        var buffer: [32]u8 = undefined;
        var writer = io.fixedBufferStream(&buffer);
        try packet.writeVarInt(&writer, id);
        const start = writer.seek;
        for ([_][]const u8{ &.{0}, &.{ 2, 0x40, 1 }, &.{ 2, 1, 0 } }) |value| {
            writer.seek = start;
            try writer.writeAll(value);
            try testing.expectError(error.TransportParameterError, TransportParams.decode(writer.buffered()));
        }
        writer.seek = start;
        try writer.writeAll(&.{ 1, 1 });
        const length = writer.seek;
        @memcpy(buffer[length..][0..length], buffer[0..length]);
        try testing.expectError(error.TransportParameterError, TransportParams.decode(buffer[0 .. length * 2]));
    }
    try testing.expectError(error.TransportParameterError, TransportParams.decode(&.{ 0x3e, 8, 0xc0, 0, 0, 1, 0, 0, 0, 0 }));
}

test "native transport parameter fuzz remains bounded and fails closed" {
    // Coverage needs fuzz instrumentation, but Zig 0.16.0's fuzz runner has bug #36326.
    if (comptime @import("builtin").fuzz and @import("coverage_options").coverage) {
        var smith: testing.Smith = .{ .in = &.{} };
        try fuzzNativeParams({}, &smith);
    } else {
        try testing.fuzz({}, fuzzNativeParams, .{});
    }
}

fn fuzzNativeParams(_: void, smith: *testing.Smith) !void {
    var input: [128]u8 = undefined;
    const count = smith.slice(&input);
    const params = TransportParams.decode(input[0..count]) catch return;
    if (params.max_remote_nat_traversal_addresses) |capacity| try testing.expect(capacity != 0);
    if (params.address_discovery_role.transportValue()) |role| try testing.expect(role <= 2);
}
