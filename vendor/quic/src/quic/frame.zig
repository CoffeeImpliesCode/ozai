//! QUIC frame types, the wire codec that decodes and encodes them, and the
//! queue that holds control frames until the next packet can carry them.
//!
//! Everything is a pure function of the caller's bytes: no allocator, no
//! clock, no socket. The one obligation a caller has to read is that
//! `Frame.parse` and `Frame.parseSized` **borrow** — every slice in a decoded
//! `Frame` points into the `[]u8` it was handed — while a `Frame` built by a
//! caller owns whatever slices were put in it, and `PendingControlFrame`
//! owns nothing at all because every variant is inline fixed storage.

const std = @import("std");
const io = @import("../io_compat.zig");

const packet = @import("packet.zig");
const observed_address = @import("observed_address.zig");
const native_nat = @import("native_nat.zig");

/// Length of the run of PADDING (zero) bytes at the start of `bytes`.
/// Padded Initials and PMTU probes carry ~1000 of them, so it scans a vector
/// at a time.
pub fn paddingLen(bytes: []const u8) usize {
    const V = std.simd.suggestVectorLength(u8) orelse 16;
    var i: usize = 0;
    while (i + V <= bytes.len) : (i += V) {
        const v: @Vector(V, u8) = bytes[i..][0..V].*;
        if (@reduce(.Or, v) != 0) break;
    }
    while (i < bytes.len and bytes[i] == 0) i += 1;
    return i;
}

/// The failure a decode can report (RFC 9000 §12.4). It is returned for a
/// frame type this module does not know, a length that does not fit, an
/// ACK range below packet number 0, and any other frame the RFC calls
/// malformed. It is the codec's own error set; a caller turns it into the
/// `frame_encoding_error` transport code when it closes the connection.
pub const FrameError = error{
    FrameEncodingError,
};

/// The QUIC frame types (RFC 9000 §12.4 Table 3) as the varint that appears
/// on the wire. `stream` (0x08) is the base: 0x08..0x0f are the same frame
/// with OFF/LEN/FIN flags set, so 0x08 is the canonical tag. `_` matches any
/// other ID; `Frame.parseSized` answers `error.FrameEncodingError` for those
/// rather than producing a `Frame`. The tag is the union tag of `Frame`, so a
/// `Frame`'s `std.meta.activeTag` is this enum.
pub const FrameType = enum(u64) {
    padding = 0x00,
    ping = 0x01,
    ack = 0x02,
    ack_ecn = 0x03,
    reset_stream = 0x04,
    stop_sending = 0x05,
    crypto = 0x06,
    new_token = 0x07,
    stream = 0x08,
    max_data = 0x10,
    max_stream_data = 0x11,
    max_streams_bidi = 0x12,
    max_streams_uni = 0x13,
    data_blocked = 0x14,
    stream_data_blocked = 0x15,
    streams_blocked_bidi = 0x16,
    streams_blocked_uni = 0x17,
    new_connection_id = 0x18,
    retire_connection_id = 0x19,
    path_challenge = 0x1a,
    path_response = 0x1b,
    connection_close = 0x1c,
    application_close = 0x1d,
    handshake_done = 0x1e,
    immediate_ack = 0x1f,
    datagram = 0x30,
    datagram_with_length = 0x31,
    ack_frequency = 0xaf,
    observed_address = 0x9f81a6,
    add_address = 0x3d7f90,
    reach_address = 0x3d7f92,
    remove_address = 0x3d7f94,
    path_ack = 0x3e,
    path_ack_ecn = 0x3f,
    path_abandon = 0x3e75,
    path_status_backup = 0x3e76,
    path_status_available = 0x3e77,
    path_new_connection_id = 0x3e78,
    path_retire_connection_id = 0x3e79,
    max_path_id = 0x3e7a,
    paths_blocked = 0x3e7b,
    path_cids_blocked = 0x3e7c,
    _,
};

/// The error codes a CONNECTION_CLOSE carries (RFC 9000 §20). `_` is any code
/// an application or a future RFC chooses: `Connection` puts application
/// codes there, so a peer can send one this module cannot name and the
/// connection still closes. `cryptoError` builds the CRYPTO_ERROR range that
/// has no tags here.
pub const TransportError = enum(u64) {
    no_error = 0x00,
    internal_error = 0x01,
    connection_refused = 0x02,
    flow_control_error = 0x03,
    stream_limit_error = 0x04,
    stream_state_error = 0x05,
    final_size_error = 0x06,
    frame_encoding_error = 0x07,
    transport_parameter_error = 0x08,
    connection_id_limit_error = 0x09,
    protocol_violation = 0x0a,
    invalid_token = 0x0b,
    application_error = 0x0c,
    crypto_buffer_exceeded = 0x0d,
    key_update_error = 0x0e,
    aead_limit_reached = 0x0f,
    no_viable_path = 0x10,
    version_negotiation_error = 0x11,
    _,

    /// Create a CRYPTO_ERROR code (0x100 + TLS alert code)
    ///
    /// The result is a raw `u64`, not a `TransportError` tag: RFC 9000 §20.1
    /// puts CRYPTO_ERROR at 0x100 and above, which is outside every tag named
    /// above, so a caller passes the value straight through to
    /// `closeWithTransportError` rather than casting it. `alert` is the TLS
    /// alert number the handshake produced, not a QUIC code.
    pub fn cryptoError(alert: u64) u64 {
        return 0x100 + alert;
    }
};

/// ACK range: represents a contiguous range of acknowledged packet numbers.
///
/// Inclusive at both ends; manually constructed ranges require `start <= end`.
/// Decoding rejects ranges that would extend below packet number zero.
pub const AckRange = struct {
    /// Smallest packet number in this range.
    start: u64,
    /// Largest packet number in this range.
    end: u64,
};

/// Maximum number of additional ACK ranges stored inline (avoids allocation).
///
/// A wire ACK frame may declare more ranges than this; `parseSized` validates
/// every one of them and keeps only the first `MAX_ACK_RANGES`, so `Frame`'s
/// `ack_range_count` never exceeds this. A frame declaring more is not
/// truncated silently into a wrong answer, only into a shorter ACK.
pub const MAX_ACK_RANGES: usize = 32;

const AckPayload = struct {
    /// Largest packet number the peer acknowledges.
    largest_ack: u64,
    /// The peer's ACK delay as it went on the wire, unscaled: the
    /// consumer applies `TransportParams.ack_delay_exponent` to get
    /// microseconds.
    ack_delay: u64,
    /// How far below `largest_ack` the first acknowledged range reaches.
    /// The range is `[largest_ack - first_ack_range, largest_ack]`.
    first_ack_range: u64,
    /// How many entries of `ack_ranges` are valid, 0 to `MAX_ACK_RANGES`.
    /// The tail of the array is not part of the frame even after a decode.
    ack_range_count: u8 = 0,
    /// Ranges below the first, in descending order. Only
    /// `ack_ranges[0..ack_range_count]` is valid.
    ack_ranges: [MAX_ACK_RANGES]AckRange = undefined,
};

const AckEcnPayload = struct {
    /// The same four ACK fields, with the same validity rule on
    /// `ack_ranges`; the three ECN counts follow.
    largest_ack: u64,
    ack_delay: u64,
    first_ack_range: u64,
    ack_range_count: u8 = 0,
    ack_ranges: [MAX_ACK_RANGES]AckRange = undefined,
    /// Packets the peer received with ECN ECT(0), cumulative.
    ecn_ect0: u64,
    /// Packets the peer received with ECN ECT(1), cumulative.
    ecn_ect1: u64,
    /// Packets the peer received with ECN CE, cumulative.
    ecn_ce: u64,
};

const NewConnectionIdPayload = struct {
    /// The peer's sequence number for this connection ID.
    seq_num: u64,
    /// The lowest sequence number the peer still wants; a receiver retires
    /// everything below it.
    retire_prior_to: u64,
    /// Borrowed from the decode buffer; see the type doc.
    conn_id: []u8,
    /// Copied out of the wire at decode, so it is owned and stays valid
    /// past the receive buffer.
    stateless_reset_token: [16]u8,
};

/// One QUIC frame, tagged by `FrameType`.
///
/// **Which variants borrow.** Every `[]u8` and `[]const u8` payload a decode
/// produces — `crypto.data`, `new_token`, `stream.data`,
/// `new_connection_id.conn_id`, `connection_close.reason`,
/// `application_close.reason`, `datagram.data` and
/// `datagram_with_length.data` — is a view into the buffer `parse` was
/// handed, not a copy. The caller must keep that buffer alive and unmodified
/// for as long as it reads them. `path_challenge`, `path_response` and
/// `new_connection_id.stateless_reset_token` are fixed-size arrays copied out
/// of the wire, so those three own their bytes and are safe to keep.
///
/// Manually supplied slices remain caller-owned and must stay live while used.
/// A frame never allocates or frees their storage. Copy bytes to retain them
/// beyond their source buffer's lifetime.
///
/// `Frame` is a plain value — no allocator, no clock, no thread state — so it
/// may be copied freely and used from more than one thread; a decoded one is
/// only as shareable as the buffer behind it.
pub const Frame = union(FrameType) {
    /// How many leading zero bytes this PADDING frame covers. On the wire
    /// PADDING is a run of zero bytes with no length of its own, and a decode
    /// coalesces the whole run into one frame; `write` emits `size` zeros.
    padding: usize,

    ping: void,

    ack: AckPayload,

    ack_ecn: AckEcnPayload,

    reset_stream: struct {
        /// Which stream is being reset: a stream ID, not an index or a count.
        stream_id: u64,
        /// The application error code the reset carries; this frame has no
        /// transport codes of its own.
        error_code: u64,
        /// Bytes: the final size the sender declares for the stream — its end
        /// offset, which flow control accounts in full whether or not the
        /// bytes were delivered (RFC 9000 §4.5).
        final_size: u64,
    },

    stop_sending: struct {
        /// Which stream the peer is asked to stop sending on.
        stream_id: u64,
        /// The application error code that explains the request.
        error_code: u64,
    },

    crypto: struct {
        /// Byte offset into the CRYPTO stream this data belongs at.
        offset: u64,
        /// Borrowed from the decode buffer; see the type doc.
        data: []u8,
    },
    /// The token a Retry handed out. Borrowed from the decode buffer.
    new_token: []u8,

    stream: struct {
        /// Which stream this frame carries data on.
        stream_id: u64,
        /// Byte offset into that stream.
        offset: u64,
        /// `data.len`; repeated so a caller does not have to trust the slice
        /// it was handed.
        length: u64,
        /// Whether this frame carries the stream's final byte.
        fin: bool,
        /// Borrowed from the decode buffer; see the type doc.
        data: []u8,
    },

    /// Bytes: this connection's aggregate send limit — an absolute offset into
    /// the sum of the data sent on every stream, not an offset on one stream.
    max_data: u64,

    max_stream_data: struct {
        /// Which stream this limit applies to.
        stream_id: u64,
        /// Bytes: an absolute offset into that stream's send space, not a
        /// count and not a freshly granted number of bytes.
        max: u64,
    },

    /// A count of streams, not bytes: the cumulative limit on how many the
    /// peer may open in this direction.
    max_streams_bidi: u64,
    /// As `max_streams_bidi`, for unidirectional streams.
    max_streams_uni: u64,
    /// Bytes: the connection-level limit the sender is stuck at, in the same
    /// aggregate offset space as `max_data`.
    data_blocked: u64,

    stream_data_blocked: struct {
        /// Which stream is blocked.
        stream_id: u64,
        /// Bytes: that stream's send limit, an absolute offset like
        /// `max_stream_data.max`, not the number of bytes blocked.
        limit: u64,
    },

    /// A count of streams, not bytes: the cumulative limit the sender had
    /// reached when it could not open another of this direction
    /// (RFC 9000 §19.14) — the limit, not an observation of what was opened.
    streams_blocked_bidi: u64,
    /// As `streams_blocked_bidi`, for unidirectional streams.
    streams_blocked_uni: u64,

    new_connection_id: NewConnectionIdPayload,

    retire_connection_id: struct {
        /// The sequence number of the connection ID being retired, in the
        /// numbering of whoever issued it (ours, for an ID this side sent).
        seq_num: u64,
    },

    path_challenge: [8]u8,
    path_response: [8]u8,

    connection_close: struct {
        /// The transport error code, or an application code when the peer used
        /// 0x1c anyway.
        error_code: u64,
        /// The frame type that triggered the close; 0 when none did.
        frame_type: u64,
        /// Borrowed from the decode buffer; see the type doc.
        reason: []u8,
    },

    application_close: struct {
        /// An application-defined code. There is no RFC meaning for it.
        error_code: u64,
        /// Borrowed from the decode buffer; see the type doc.
        reason: []u8,
    },

    handshake_done: void,

    // draft-ietf-quic-ack-frequency
    immediate_ack: void,

    datagram: struct {
        /// Everything left in the packet, borrowed from the decode buffer.
        /// A DATAGRAM frame has no length field, so this is the remainder by
        /// definition.
        data: []u8,
    },
    datagram_with_length: struct {
        /// The declared payload, borrowed from the decode buffer. `const`
        /// because the wire carries no reason for a decoded DATAGRAM to be
        /// rewritten.
        data: []const u8,
    },

    /// draft-ietf-quic-ack-frequency: the peer telling this endpoint when to
    /// ACK. Purely inbound state; it is not flow control and grants no credit.
    ack_frequency: struct {
        /// The peer's sequence number for this request, so a later request
        /// from the same peer supersedes this one.
        sequence_number: u64,
        /// ACK after this many ack-eliciting packets. 0 is not a special
        /// value here: it is the number the peer sent.
        ack_eliciting_threshold: u64,
        /// Microseconds; the longest the peer asks this endpoint to wait
        /// between ACKs.
        request_max_ack_delay: u64,
        /// Packets out of order before the peer wants an immediate ACK.
        reordering_threshold: u64,
    },

    observed_address: observed_address.Report,
    add_address: native_nat.AddAddress,
    reach_address: native_nat.ReachAddress,
    remove_address: u64,
    path_ack: struct { path_id: u32, ack: AckPayload },
    path_ack_ecn: struct { path_id: u32, ack: AckEcnPayload },
    path_abandon: struct { path_id: u32, error_code: u64 },
    path_status_backup: struct { path_id: u32, status_seq_no: u64 },
    path_status_available: struct { path_id: u32, status_seq_no: u64 },
    path_new_connection_id: struct { path_id: u32, cid: NewConnectionIdPayload },
    path_retire_connection_id: struct { path_id: u32, seq_num: u64 },
    max_path_id: u32,
    paths_blocked: u32,
    path_cids_blocked: struct { path_id: u32, next_seq: u64 },

    fn readPathId(reader: anytype) error{ FrameEncodingError, EndOfStream }!u32 {
        const value = try packet.readVarInt(reader);
        if (value > std.math.maxInt(u32)) return error.FrameEncodingError;
        return @intCast(value);
    }

    /// A frame body cannot extend past the datagram it was decoded from.
    /// Wire lengths are u64 varints, so this is also where they narrow to
    /// usize (RFC 9000 12.4: a violation is FRAME_ENCODING_ERROR).
    fn body(bytes: []u8, seek: *usize, len: u64) ![]u8 {
        if (len > bytes.len - seek.*) return error.FrameEncodingError;
        defer seek.* += @intCast(len);
        return bytes[seek.*..][0..@intCast(len)];
    }

    /// Parse a single frame from a byte buffer.
    ///
    /// `bytes` is the packet payload from the current frame onward; the
    /// returned `Frame`'s slices borrow it, so it must stay alive and
    /// unmodified as long as they are read. Nothing is allocated and nothing
    /// is copied except `path_challenge`, `path_response` and
    /// `new_connection_id.stateless_reset_token`.
    ///
    /// `error.FrameEncodingError` is a frame this module cannot decode: an
    /// unknown type, a body running past the end, an ACK range below packet
    /// number 0, or a connection ID length outside 1..20. `error.EndOfStream`
    /// reports a truncated varint or fixed-size field. Neither returns a frame,
    /// and those two are the whole set this signature can return.
    ///
    /// The buffer may hold frames after this one; use `parseSized` to find
    /// where it ended.
    pub fn parse(bytes: []u8) error{ FrameEncodingError, EndOfStream }!Frame {
        var size: usize = undefined;
        return parseSized(bytes, &size);
    }

    /// Parse a single frame, and set `size` to the bytes it took up, so the
    /// next frame starts at `bytes[size..]`.
    ///
    /// Identical to `parse` in what it decodes, borrows and fails on; `size`
    /// is how a caller walks a coalesced packet one frame at a time. It is
    /// written on the error path too, where it names how far the reader got
    /// rather than where a frame ended — so only a successful call's `size`
    /// points at the next frame.
    pub fn parseSized(bytes: []u8, size: *usize) error{ FrameEncodingError, EndOfStream }!Frame {
        var stream = io.fixedBufferStream(bytes);
        var reader = &stream;
        defer size.* = stream.seek;

        const frame_type = try packet.readVarInt(reader);

        return switch (frame_type) {
            // padding
            0x00 => .{
                .padding = blk: {
                    const len = paddingLen(bytes);
                    stream.seek = len;
                    break :blk len;
                },
            },

            // ping
            0x01 => .{
                .ping = {},
            },

            // ack (0x02) and ack_ecn (0x03)
            0x02, 0x03, 0x3e, 0x3f => blk: {
                const is_path = frame_type == 0x3e or frame_type == 0x3f;
                const path_id = if (is_path) try readPathId(reader) else 0;
                const is_ecn = frame_type == 0x03 or frame_type == 0x3f;
                const largest_ack = try packet.readVarInt(reader);
                const ack_delay = try packet.readVarInt(reader);
                const ack_range_count = try packet.readVarInt(reader);
                const first_ack_range = try packet.readVarInt(reader);

                // RFC 9000 19.3.1: a range reaching below packet number 0 is
                // FRAME_ENCODING_ERROR, not something to clamp into range.
                if (first_ack_range > largest_ack) return error.FrameEncodingError;

                // Parse additional ACK ranges, computing absolute PN ranges
                var additional_ranges: [MAX_ACK_RANGES]AckRange = undefined;
                var range_count: u8 = 0;
                var smallest = largest_ack - first_ack_range;

                var i: u64 = 0;
                while (i < ack_range_count) : (i += 1) {
                    const gap = try packet.readVarInt(reader);
                    const ack_range_len = try packet.readVarInt(reader);
                    // Validate every range, including the ones past our cap.
                    if (smallest < gap +| 2) return error.FrameEncodingError;
                    const range_largest = smallest - gap - 2;
                    if (ack_range_len > range_largest) return error.FrameEncodingError;
                    const range_smallest = range_largest - ack_range_len;
                    if (range_count < MAX_ACK_RANGES) {
                        additional_ranges[range_count] = .{ .start = range_smallest, .end = range_largest };
                        range_count += 1;
                    }
                    smallest = range_smallest;
                }

                var ecn_ect0: u64 = 0;
                var ecn_ect1: u64 = 0;
                var ecn_ce: u64 = 0;
                if (is_ecn) {
                    ecn_ect0 = try packet.readVarInt(reader);
                    ecn_ect1 = try packet.readVarInt(reader);
                    ecn_ce = try packet.readVarInt(reader);
                }

                if (is_path) {
                    if (is_ecn) break :blk .{ .path_ack_ecn = .{
                        .path_id = path_id,
                        .ack = .{
                            .largest_ack = largest_ack,
                            .ack_delay = ack_delay,
                            .first_ack_range = first_ack_range,
                            .ack_range_count = range_count,
                            .ack_ranges = additional_ranges,
                            .ecn_ect0 = ecn_ect0,
                            .ecn_ect1 = ecn_ect1,
                            .ecn_ce = ecn_ce,
                        },
                    } };
                    break :blk .{ .path_ack = .{
                        .path_id = path_id,
                        .ack = .{
                            .largest_ack = largest_ack,
                            .ack_delay = ack_delay,
                            .first_ack_range = first_ack_range,
                            .ack_range_count = range_count,
                            .ack_ranges = additional_ranges,
                        },
                    } };
                }
                if (is_ecn) {
                    break :blk .{
                        .ack_ecn = .{
                            .largest_ack = largest_ack,
                            .ack_delay = ack_delay,
                            .first_ack_range = first_ack_range,
                            .ack_range_count = range_count,
                            .ack_ranges = additional_ranges,
                            .ecn_ect0 = ecn_ect0,
                            .ecn_ect1 = ecn_ect1,
                            .ecn_ce = ecn_ce,
                        },
                    };
                } else {
                    break :blk .{
                        .ack = .{
                            .largest_ack = largest_ack,
                            .ack_delay = ack_delay,
                            .first_ack_range = first_ack_range,
                            .ack_range_count = range_count,
                            .ack_ranges = additional_ranges,
                        },
                    };
                }
            },

            // reset_stream
            0x04 => .{
                .reset_stream = .{
                    .stream_id = try packet.readVarInt(reader),
                    .error_code = try packet.readVarInt(reader),
                    .final_size = try packet.readVarInt(reader),
                },
            },

            // stop_sending
            0x05 => .{
                .stop_sending = .{
                    .stream_id = try packet.readVarInt(reader),
                    .error_code = try packet.readVarInt(reader),
                },
            },

            // crypto
            0x06 => {
                const offset = try packet.readVarInt(reader);
                const length = try packet.readVarInt(reader);

                return .{
                    .crypto = .{
                        .offset = offset,
                        .data = try body(bytes, &stream.seek, length),
                    },
                };
            },

            // new token
            0x07 => {
                const len = try packet.readVarInt(reader);
                return .{
                    .new_token = try body(bytes, &stream.seek, len),
                };
            },

            // stream frame (0x08 - 0x0f)
            0x08...0x0f => blk: {
                const type_byte: u8 = @intCast(frame_type);
                const has_offset = (type_byte & 0x04) != 0;
                const has_length = (type_byte & 0x02) != 0;
                const has_fin = (type_byte & 0x01) != 0;

                const stream_id = try packet.readVarInt(reader);
                const offset: u64 = if (has_offset) try packet.readVarInt(reader) else 0;
                const data_length: u64 = if (has_length)
                    try packet.readVarInt(reader)
                else
                    bytes.len - stream.seek;

                break :blk .{ .stream = .{
                    .stream_id = stream_id,
                    .offset = offset,
                    .length = data_length,
                    .fin = has_fin,
                    .data = try body(bytes, &stream.seek, data_length),
                } };
            },

            // max data
            0x10 => .{
                .max_data = try packet.readVarInt(reader),
            },

            // max stream data
            0x11 => .{
                .max_stream_data = .{
                    .stream_id = try packet.readVarInt(reader),
                    .max = try packet.readVarInt(reader),
                },
            },

            // max streams bidi
            0x12 => .{
                .max_streams_bidi = try packet.readVarInt(reader),
            },

            // max streams uni
            0x13 => .{
                .max_streams_uni = try packet.readVarInt(reader),
            },

            // data blocked
            0x14 => .{
                .data_blocked = try packet.readVarInt(reader),
            },

            // stream data blocked
            0x15 => .{
                .stream_data_blocked = .{
                    .stream_id = try packet.readVarInt(reader),
                    .limit = try packet.readVarInt(reader),
                },
            },

            // streams blocked bidi
            0x16 => .{
                .streams_blocked_bidi = try packet.readVarInt(reader),
            },

            // streams blocked uni
            0x17 => .{
                .streams_blocked_uni = try packet.readVarInt(reader),
            },

            // new connection id
            0x18 => {
                var conn_id_len: u8 = undefined;

                return .{
                    .new_connection_id = .{
                        .seq_num = try packet.readVarInt(reader),
                        .retire_prior_to = try packet.readVarInt(reader),
                        .conn_id = blk: {
                            conn_id_len = try reader.takeByte();

                            if (conn_id_len < 1 or conn_id_len > 20) {
                                return error.FrameEncodingError;
                            }

                            break :blk try body(bytes, &stream.seek, conn_id_len);
                        },
                        .stateless_reset_token = (try reader.takeArray(16)).*,
                    },
                };
            },

            // retire connection id
            0x19 => .{
                .retire_connection_id = .{
                    .seq_num = try packet.readVarInt(reader),
                },
            },

            // path challenge
            0x1a => .{
                .path_challenge = (try reader.takeArray(8)).*,
            },

            // path response
            0x1b => .{
                .path_response = (try reader.takeArray(8)).*,
            },

            // connection close
            0x1c => .{
                .connection_close = .{
                    .error_code = try packet.readVarInt(reader),
                    .frame_type = try packet.readVarInt(reader),
                    .reason = blk: {
                        const len = try packet.readVarInt(reader);
                        break :blk try body(bytes, &stream.seek, len);
                    },
                },
            },

            // application close
            0x1d => .{
                .application_close = .{
                    .error_code = try packet.readVarInt(reader),
                    .reason = blk: {
                        const len = try packet.readVarInt(reader);
                        break :blk try body(bytes, &stream.seek, len);
                    },
                },
            },

            // handshake done
            0x1e => .{ .handshake_done = {} },

            // immediate ack (draft-ietf-quic-ack-frequency)
            0x1f => .{ .immediate_ack = {} },

            // datagram without length (0x30) — data is rest of packet
            0x30 => .{ .datagram = .{
                .data = try body(bytes, &stream.seek, bytes.len - stream.seek),
            } },

            // datagram with length (0x31) — varint length prefix
            0x31 => blk: {
                const length = try packet.readVarInt(reader);
                break :blk .{ .datagram_with_length = .{
                    .data = try body(bytes, &stream.seek, length),
                } };
            },

            // ack frequency (draft-ietf-quic-ack-frequency)
            0xaf => .{ .ack_frequency = .{
                .sequence_number = try packet.readVarInt(reader),
                .ack_eliciting_threshold = try packet.readVarInt(reader),
                .request_max_ack_delay = try packet.readVarInt(reader),
                .reordering_threshold = try packet.readVarInt(reader),
            } },

            0x9f81a6, 0x9f81a7 => .{ .observed_address = try observed_address.Report.read(reader, frame_type == 0x9f81a7) },
            0x3d7f90, 0x3d7f91 => .{ .add_address = try native_nat.AddAddress.read(reader, frame_type == 0x3d7f91) },
            0x3d7f92, 0x3d7f93 => .{ .reach_address = try native_nat.ReachAddress.read(reader, frame_type == 0x3d7f93) },
            0x3d7f94 => .{ .remove_address = try packet.readVarInt(reader) },
            0x3e75 => .{ .path_abandon = .{
                .path_id = try readPathId(reader),
                .error_code = try packet.readVarInt(reader),
            } },
            0x3e76 => .{ .path_status_backup = .{
                .path_id = try readPathId(reader),
                .status_seq_no = try packet.readVarInt(reader),
            } },
            0x3e77 => .{ .path_status_available = .{
                .path_id = try readPathId(reader),
                .status_seq_no = try packet.readVarInt(reader),
            } },
            0x3e78 => blk: {
                const path_id = try readPathId(reader);
                const sequence = try packet.readVarInt(reader);
                const retire = try packet.readVarInt(reader);
                if (retire > sequence) return error.FrameEncodingError;
                const length = try reader.takeByte();
                if (length == 0 or length > 20) return error.FrameEncodingError;
                const cid = try body(bytes, &stream.seek, length);
                var token: [16]u8 = undefined;
                try reader.readSliceAll(&token);
                break :blk .{ .path_new_connection_id = .{
                    .path_id = path_id,
                    .cid = .{
                        .seq_num = sequence,
                        .retire_prior_to = retire,
                        .conn_id = cid,
                        .stateless_reset_token = token,
                    },
                } };
            },
            0x3e79 => .{ .path_retire_connection_id = .{
                .path_id = try readPathId(reader),
                .seq_num = try packet.readVarInt(reader),
            } },
            0x3e7a => .{ .max_path_id = try readPathId(reader) },
            0x3e7b => .{ .paths_blocked = try readPathId(reader) },
            0x3e7c => .{ .path_cids_blocked = .{
                .path_id = try readPathId(reader),
                .next_seq = try packet.readVarInt(reader),
            } },
            else => return error.FrameEncodingError,
        };
    }

    /// Write a frame to the given writer.
    ///
    /// `writer` supplies `writeAll`, `writeByte` and `writeInt`. Slices in
    /// `self` are read for the call, not retained, so a
    /// frame decoded from a receive buffer can be written straight back out
    /// while that buffer is still alive.
    ///
    /// Writer errors and `error.VarIntTooLarge` can leave an encoded prefix;
    /// discard that packet. Allocates nothing. Manual ACKs must have
    /// `first_ack_range <= largest_ack`, at most `MAX_ACK_RANGES` additional
    /// ranges with `start <= end`, descending with at least one unacked packet
    /// between ranges. Violating these preconditions may trap in checked builds
    /// or produce invalid wire bytes in unchecked builds.
    pub fn write(self: Frame, writer: anytype) !void {
        switch (self) {
            .padding => |size| {
                var i: usize = 0;
                while (i < size) : (i += 1) {
                    try writer.writeByte(0x00);
                }
            },

            .ping => {
                try packet.writeVarInt(writer, 0x01);
            },

            .ack => |ack| {
                try packet.writeVarInt(writer, 0x02);
                try packet.writeVarInt(writer, ack.largest_ack);
                try packet.writeVarInt(writer, ack.ack_delay);
                try packet.writeVarInt(writer, @as(u64, ack.ack_range_count));
                try packet.writeVarInt(writer, ack.first_ack_range);

                // Convert absolute ranges back to gap/ack_range wire format
                var prev_smallest = ack.largest_ack -| ack.first_ack_range;
                for (ack.ack_ranges[0..ack.ack_range_count]) |r| {
                    const gap = prev_smallest -| r.end -| 2;
                    const ack_range_len = r.end - r.start;
                    try packet.writeVarInt(writer, gap);
                    try packet.writeVarInt(writer, ack_range_len);
                    prev_smallest = r.start;
                }
            },

            .ack_ecn => |ack| {
                try packet.writeVarInt(writer, 0x03);
                try packet.writeVarInt(writer, ack.largest_ack);
                try packet.writeVarInt(writer, ack.ack_delay);
                try packet.writeVarInt(writer, @as(u64, ack.ack_range_count));
                try packet.writeVarInt(writer, ack.first_ack_range);

                var prev_smallest = ack.largest_ack -| ack.first_ack_range;
                for (ack.ack_ranges[0..ack.ack_range_count]) |r| {
                    const gap = prev_smallest -| r.end -| 2;
                    const ack_range_len = r.end - r.start;
                    try packet.writeVarInt(writer, gap);
                    try packet.writeVarInt(writer, ack_range_len);
                    prev_smallest = r.start;
                }

                try packet.writeVarInt(writer, ack.ecn_ect0);
                try packet.writeVarInt(writer, ack.ecn_ect1);
                try packet.writeVarInt(writer, ack.ecn_ce);
            },

            .reset_stream => |rs| {
                try packet.writeVarInt(writer, 0x04);
                try packet.writeVarInt(writer, rs.stream_id);
                try packet.writeVarInt(writer, rs.error_code);
                try packet.writeVarInt(writer, rs.final_size);
            },

            .stop_sending => |ss| {
                try packet.writeVarInt(writer, 0x05);
                try packet.writeVarInt(writer, ss.stream_id);
                try packet.writeVarInt(writer, ss.error_code);
            },

            .crypto => |c| {
                try packet.writeVarInt(writer, 0x06);
                try packet.writeVarInt(writer, c.offset);
                try packet.writeVarInt(writer, c.data.len);
                try writer.writeAll(c.data);
            },

            .new_token => |token| {
                try packet.writeVarInt(writer, 0x07);
                try packet.writeVarInt(writer, token.len);
                try writer.writeAll(token);
            },

            .stream => |s| {
                // Always set the LEN flag to prevent subsequent frames from being
                // misinterpreted as stream data (RFC 9000 §19.8)
                var type_byte: u8 = 0x08 | 0x02; // LEN always set
                if (s.offset > 0) type_byte |= 0x04;
                if (s.fin) type_byte |= 0x01;

                try packet.writeVarInt(writer, type_byte);
                try packet.writeVarInt(writer, s.stream_id);
                if (s.offset > 0) try packet.writeVarInt(writer, s.offset);
                try packet.writeVarInt(writer, s.length); // always write length
                try writer.writeAll(s.data);
            },

            .max_data => |max| {
                try packet.writeVarInt(writer, 0x10);
                try packet.writeVarInt(writer, max);
            },

            .max_stream_data => |msd| {
                try packet.writeVarInt(writer, 0x11);
                try packet.writeVarInt(writer, msd.stream_id);
                try packet.writeVarInt(writer, msd.max);
            },

            .max_streams_bidi => |max| {
                try packet.writeVarInt(writer, 0x12);
                try packet.writeVarInt(writer, max);
            },

            .max_streams_uni => |max| {
                try packet.writeVarInt(writer, 0x13);
                try packet.writeVarInt(writer, max);
            },

            .data_blocked => |limit| {
                try packet.writeVarInt(writer, 0x14);
                try packet.writeVarInt(writer, limit);
            },

            .stream_data_blocked => |sdb| {
                try packet.writeVarInt(writer, 0x15);
                try packet.writeVarInt(writer, sdb.stream_id);
                try packet.writeVarInt(writer, sdb.limit);
            },

            .streams_blocked_bidi => |max| {
                try packet.writeVarInt(writer, 0x16);
                try packet.writeVarInt(writer, max);
            },

            .streams_blocked_uni => |max| {
                try packet.writeVarInt(writer, 0x17);
                try packet.writeVarInt(writer, max);
            },

            .new_connection_id => |ncid| {
                try packet.writeVarInt(writer, 0x18);
                try packet.writeVarInt(writer, ncid.seq_num);
                try packet.writeVarInt(writer, ncid.retire_prior_to);
                try writer.writeByte(@intCast(ncid.conn_id.len));
                try writer.writeAll(ncid.conn_id);
                try writer.writeAll(&ncid.stateless_reset_token);
            },

            .retire_connection_id => |rcid| {
                try packet.writeVarInt(writer, 0x19);
                try packet.writeVarInt(writer, rcid.seq_num);
            },

            .path_challenge => |data| {
                try packet.writeVarInt(writer, 0x1a);
                try writer.writeAll(&data);
            },

            .path_response => |data| {
                try packet.writeVarInt(writer, 0x1b);
                try writer.writeAll(&data);
            },

            .connection_close => |cc| {
                try packet.writeVarInt(writer, 0x1c);
                try packet.writeVarInt(writer, cc.error_code);
                try packet.writeVarInt(writer, cc.frame_type);
                try packet.writeVarInt(writer, cc.reason.len);
                try writer.writeAll(cc.reason);
            },

            .application_close => |ac| {
                try packet.writeVarInt(writer, 0x1d);
                try packet.writeVarInt(writer, ac.error_code);
                try packet.writeVarInt(writer, ac.reason.len);
                try writer.writeAll(ac.reason);
            },

            .handshake_done => {
                try packet.writeVarInt(writer, 0x1e);
            },

            .immediate_ack => {
                try packet.writeVarInt(writer, 0x1f);
            },

            .datagram => |d| {
                try packet.writeVarInt(writer, 0x30);
                try writer.writeAll(d.data);
            },

            .datagram_with_length => |d| {
                try packet.writeVarInt(writer, 0x31);
                try packet.writeVarInt(writer, d.data.len);
                try writer.writeAll(d.data);
            },

            .ack_frequency => |af| {
                try packet.writeVarInt(writer, 0xaf);
                try packet.writeVarInt(writer, af.sequence_number);
                try packet.writeVarInt(writer, af.ack_eliciting_threshold);
                try packet.writeVarInt(writer, af.request_max_ack_delay);
                try packet.writeVarInt(writer, af.reordering_threshold);
            },
            .observed_address => |report| try report.write(writer),
            .add_address => |add| try add.write(writer),
            .reach_address => |reach| try reach.write(writer),
            .remove_address => |sequence| {
                try packet.writeVarInt(writer, 0x3d7f94);
                try packet.writeVarInt(writer, sequence);
            },
            inline .path_ack, .path_ack_ecn => |value| {
                try packet.writeVarInt(writer, @backingInt(std.meta.activeTag(self)));
                try packet.writeVarInt(writer, value.path_id);
                const ack = &value.ack;
                try packet.writeVarInt(writer, ack.largest_ack);
                try packet.writeVarInt(writer, ack.ack_delay);
                try packet.writeVarInt(writer, ack.ack_range_count);
                try packet.writeVarInt(writer, ack.first_ack_range);
                var previous = ack.largest_ack - ack.first_ack_range;
                for (ack.ack_ranges[0..ack.ack_range_count]) |range| {
                    try packet.writeVarInt(writer, previous - range.end - 2);
                    try packet.writeVarInt(writer, range.end - range.start);
                    previous = range.start;
                }
                if (@hasField(@TypeOf(value.ack), "ecn_ect0")) {
                    try packet.writeVarInt(writer, ack.ecn_ect0);
                    try packet.writeVarInt(writer, ack.ecn_ect1);
                    try packet.writeVarInt(writer, ack.ecn_ce);
                }
            },
            .path_abandon => |value| {
                try packet.writeVarInt(writer, 0x3e75);
                try packet.writeVarInt(writer, value.path_id);
                try packet.writeVarInt(writer, value.error_code);
            },
            inline .path_status_backup, .path_status_available => |value| {
                try packet.writeVarInt(writer, @backingInt(std.meta.activeTag(self)));
                try packet.writeVarInt(writer, value.path_id);
                try packet.writeVarInt(writer, value.status_seq_no);
            },
            .path_new_connection_id => |value| {
                try packet.writeVarInt(writer, 0x3e78);
                try packet.writeVarInt(writer, value.path_id);
                try packet.writeVarInt(writer, value.cid.seq_num);
                try packet.writeVarInt(writer, value.cid.retire_prior_to);
                try writer.writeByte(@intCast(value.cid.conn_id.len));
                try writer.writeAll(value.cid.conn_id);
                try writer.writeAll(&value.cid.stateless_reset_token);
            },
            .path_retire_connection_id => |value| {
                try packet.writeVarInt(writer, 0x3e79);
                try packet.writeVarInt(writer, value.path_id);
                try packet.writeVarInt(writer, value.seq_num);
            },
            .max_path_id, .paths_blocked => |value| {
                try packet.writeVarInt(writer, @backingInt(std.meta.activeTag(self)));
                try packet.writeVarInt(writer, value);
            },
            .path_cids_blocked => |value| {
                try packet.writeVarInt(writer, 0x3e7c);
                try packet.writeVarInt(writer, value.path_id);
                try packet.writeVarInt(writer, value.next_seq);
            },
        }
    }

    /// Whether this frame is ack-eliciting (RFC 9000 §13.2.1): a peer that
    /// receives one owes an ACK for it.
    ///
    /// False for PADDING, ACK, ACK_ECN and both CONNECTION_CLOSE forms — the
    /// frames that must not provoke an ACK or would loop. True for everything
    /// else, DATAGRAM included. Depends only on the tag, never on the payload,
    /// so a decoded frame and a hand-built one answer the same.
    pub fn isAckEliciting(self: Frame) bool {
        return switch (self) {
            .padding, .ack, .ack_ecn, .path_ack, .path_ack_ecn, .connection_close, .application_close => false,
            .datagram, .datagram_with_length => true,
            else => true,
        };
    }

    /// Whether Noq classifies this frame as part of a probing packet.
    ///
    /// True only for PADDING, PATH_CHALLENGE, PATH_RESPONSE,
    /// NEW_CONNECTION_ID and OBSERVED_ADDR; PATH_NEW_CONNECTION_ID and every
    /// other frame are false. A packet is probing only when all its frames
    /// answer true.
    pub fn isProbing(self: Frame) bool {
        return switch (self) {
            .padding, .path_challenge, .path_response, .new_connection_id, .observed_address => true,
            else => false,
        };
    }

    /// Check if this frame type is allowed in the given packet type (RFC 9000 §12.5, Table 3).
    ///
    /// Whether the frame may legally appear in a packet of that encryption
    /// level; it says nothing about whether the packet may be sent at all.
    /// PADDING and PING are legal everywhere, ACK/ACK_ECN/CRYPTO and transport
    /// CONNECTION_CLOSE are legal everywhere except 0-RTT, the connection-ID
    /// and handshake frames are 1-RTT only, and everything else is 0-RTT or
    /// 1-RTT. Reads only.
    pub fn isAllowedIn(self: Frame, pkt_type: packet.PacketType) bool {
        return switch (self) {
            // PADDING, PING: all packet types
            .padding, .ping => true,
            // ACK, ACK_ECN: Initial, Handshake, 1-RTT (NOT 0-RTT)
            .ack, .ack_ecn => pkt_type != .zero_rtt,
            // CRYPTO: Initial, Handshake, 1-RTT (NOT 0-RTT)
            .crypto => pkt_type != .zero_rtt,
            // CONNECTION_CLOSE: Initial, Handshake, 1-RTT (NOT 0-RTT)
            .connection_close => pkt_type != .zero_rtt,
            // NEW_TOKEN, NEW_CONNECTION_ID, RETIRE_CONNECTION_ID, HANDSHAKE_DONE: 1-RTT only
            // ACK_FREQUENCY, IMMEDIATE_ACK: 1-RTT only (draft-ietf-quic-ack-frequency)
            .new_token,
            .new_connection_id,
            .retire_connection_id,
            .handshake_done,
            .ack_frequency,
            .immediate_ack,
            .observed_address,
            .add_address,
            .reach_address,
            .remove_address,
            .path_ack,
            .path_ack_ecn,
            .path_abandon,
            .path_status_backup,
            .path_status_available,
            .path_new_connection_id,
            .path_retire_connection_id,
            .max_path_id,
            .paths_blocked,
            .path_cids_blocked,
            => pkt_type == .one_rtt,
            // All others: 0-RTT and 1-RTT only
            .reset_stream,
            .stop_sending,
            .stream,
            .max_data,
            .max_stream_data,
            .max_streams_bidi,
            .max_streams_uni,
            .data_blocked,
            .stream_data_blocked,
            .streams_blocked_bidi,
            .streams_blocked_uni,
            .path_challenge,
            .path_response,
            .application_close,
            .datagram,
            .datagram_with_length,
            => pkt_type == .one_rtt or pkt_type == .zero_rtt,
        };
    }
};

const PendingNewConnectionIdPayload = struct {
    /// The sequence number to attach to this connection ID.
    seq_num: u64,
    /// The lowest sequence number the peer should keep.
    retire_prior_to: u64,
    /// Inline storage for the connection ID, at most 20 bytes (RFC 9000
    /// §17.2); only `cid_buf[0..cid_len]` is the ID.
    cid_buf: [20]u8,
    /// Caller-enforced length, 1..20; `write` slices the inline buffer.
    cid_len: u8,
    /// The token a reset for this connection ID must end with, copied in
    /// alongside the ID so the pair stays together in the queue.
    stateless_reset_token: [16]u8,
};

/// A pending control frame to be sent in the next outgoing packet.
/// Uses value types only (no slices) to avoid dangling references.
///
/// Every variant is inline fixed-size storage, so a `PendingControlFrame`
/// owns its bytes, borrows nothing, and survives in a queue across packets
/// with no lifetime to track. It allocates nothing and needs no teardown, and
/// a copy is an independent value. It is not a `Frame` and does not convert
/// one-way for every variant: `toFrame` answers `unreachable` for
/// `new_token` and `new_connection_id`, which `write` serializes directly
/// because their payload lives in a fixed buffer this type would have to
/// borrow to hand to a `Frame`.
pub const PendingControlFrame = union(enum) {
    ping: void,
    path_challenge: [8]u8,
    path_response: [8]u8,
    /// As `Frame.retire_connection_id.seq_num`: the number of the CID to retire.
    retire_connection_id: u64,
    connection_close: struct {
        /// The transport or application code, depending on `is_app`.
        error_code: u64,
        /// The frame type that triggered the close, or 0. Only meaningful
        /// when `is_app` is false.
        frame_type: u64,
        /// Which CONNECTION_CLOSE variant `write` emits: true for the
        /// application form (0x1d, no `frame_type`, empty reason), false for
        /// the transport form (0x1c). One tag carries both because the reason
        /// is dropped either way.
        is_app: bool,
    },

    /// Bytes, the connection aggregate limit; as `Frame.max_data`.
    max_data: u64,
    max_stream_data: struct {
        /// As `Frame.max_stream_data.stream_id`.
        stream_id: u64,
        /// Bytes, that stream's send space; as `Frame.max_stream_data.max`.
        max: u64,
    },
    /// A count of streams, not bytes; as `Frame.max_streams_bidi`.
    max_streams_bidi: u64,
    /// A count of streams, not bytes; as `Frame.max_streams_uni`.
    max_streams_uni: u64,
    /// The cumulative limit the sender is blocked at; as
    /// `Frame.streams_blocked_bidi`.
    streams_blocked_bidi: u64,
    /// As `streams_blocked_bidi`, for unidirectional streams.
    streams_blocked_uni: u64,
    /// Bytes, the connection limit; as `Frame.data_blocked`.
    data_blocked: u64,
    stream_data_blocked: struct {
        /// As `Frame.stream_data_blocked.stream_id`.
        stream_id: u64,
        /// Bytes, that stream's send limit; as `Frame.stream_data_blocked.limit`.
        limit: u64,
    },
    new_token: struct {
        /// Inline storage for the token. 92 bytes is the largest a
        /// NEW_TOKEN may carry (RFC 9000 §19.7), so the token is copied in
        /// rather than borrowed; `token_len` says how much of it is real.
        token_buf: [92]u8 = @splat(0),
        /// Bytes of `token_buf` to emit, 0 to 92. `write` does not check the
        /// bound, so a producer that sets more than 92 gets a slice that runs
        /// past the array.
        token_len: u8 = 0,
    },

    reset_stream: struct {
        /// As `Frame.reset_stream.stream_id`.
        stream_id: u64,
        /// The application error code; as `Frame.reset_stream.error_code`.
        error_code: u64,
        /// Bytes, the stream's final size; as `Frame.reset_stream.final_size`.
        final_size: u64,
    },
    stop_sending: struct {
        /// As `Frame.stop_sending.stream_id`.
        stream_id: u64,
        /// The application error code; as `Frame.stop_sending.error_code`.
        error_code: u64,
    },
    new_connection_id: PendingNewConnectionIdPayload,

    /// draft-ietf-quic-ack-frequency: when the peer asked this endpoint to
    /// ACK. The fields carry the same meanings as `Frame.ack_frequency`, and
    /// `request_max_ack_delay` is still microseconds here.
    ack_frequency: struct {
        sequence_number: u64,
        ack_eliciting_threshold: u64,
        request_max_ack_delay: u64,
        reordering_threshold: u64,
    },
    immediate_ack: void,
    observed_address: observed_address.Report,
    add_address: native_nat.AddAddress,
    reach_address: native_nat.ReachAddress,
    remove_address: u64,
    path_abandon: @FieldType(Frame, "path_abandon"),
    path_status_backup: @FieldType(Frame, "path_status_backup"),
    path_status_available: @FieldType(Frame, "path_status_available"),
    path_retire_connection_id: @FieldType(Frame, "path_retire_connection_id"),
    max_path_id: u32,
    paths_blocked: u32,
    path_cids_blocked: @FieldType(Frame, "path_cids_blocked"),
    path_new_connection_id: struct {
        path_id: u32,
        cid: PendingNewConnectionIdPayload,
    },

    /// Write this pending control frame directly on the wire.
    /// For new_connection_id we serialize directly (avoids dangling slice from toFrame()).
    ///
    /// Borrows the writer for the call. Writer errors and `error.VarIntTooLarge`
    /// may leave a prefix, which the caller must discard. Inline lengths must
    /// fit their buffers. The two fixed-buffer variants are serialized here:
    /// `toFrame` cannot represent them without a borrow.
    pub fn write(self: PendingControlFrame, writer: anytype) !void {
        switch (self) {
            .new_token => |nt| {
                try packet.writeVarInt(writer, 0x07);
                try packet.writeVarInt(writer, nt.token_len);
                try writer.writeAll(nt.token_buf[0..nt.token_len]);
            },
            .new_connection_id => |ncid| {
                try packet.writeVarInt(writer, 0x18);
                try packet.writeVarInt(writer, ncid.seq_num);
                try packet.writeVarInt(writer, ncid.retire_prior_to);
                try writer.writeByte(ncid.cid_len);
                try writer.writeAll(ncid.cid_buf[0..ncid.cid_len]);
                try writer.writeAll(&ncid.stateless_reset_token);
            },
            .path_new_connection_id => |value| {
                const cid = value.cid;
                try packet.writeVarInt(writer, 0x3e78);
                try packet.writeVarInt(writer, value.path_id);
                try packet.writeVarInt(writer, cid.seq_num);
                try packet.writeVarInt(writer, cid.retire_prior_to);
                try writer.writeByte(cid.cid_len);
                try writer.writeAll(cid.cid_buf[0..cid.cid_len]);
                try writer.writeAll(&cid.stateless_reset_token);
            },
            else => {
                const f = self.toFrame();
                try f.write(writer);
            },
        }
    }

    /// Convert to a Frame for writing on the wire.
    ///
    /// The result borrows nothing: every payload is copied into the `Frame`'s
    /// own fixed-size fields, and the CONNECTION_CLOSE reason becomes an empty
    /// static slice. It is a value the caller owns outright and can write out
    /// with `Frame.write` after this returns.
    ///
    /// `new_token` and `new_connection_id` answer `unreachable` — a `Frame`
    /// would have to borrow their inline buffers — so a caller must route those
    /// two through `PendingControlFrame.write` instead.
    pub fn toFrame(self: PendingControlFrame) Frame {
        return switch (self) {
            .ping => .{ .ping = {} },
            .path_challenge => |data| .{ .path_challenge = data },
            .path_response => |data| .{ .path_response = data },
            .retire_connection_id => |seq| .{ .retire_connection_id = .{ .seq_num = seq } },
            .connection_close => |cc| if (cc.is_app)
                .{ .application_close = .{ .error_code = cc.error_code, .reason = &.{} } }
            else
                .{ .connection_close = .{ .error_code = cc.error_code, .frame_type = cc.frame_type, .reason = &.{} } },
            .max_data => |max| .{ .max_data = max },
            .max_stream_data => |msd| .{ .max_stream_data = .{ .stream_id = msd.stream_id, .max = msd.max } },
            .max_streams_bidi => |max| .{ .max_streams_bidi = max },
            .max_streams_uni => |max| .{ .max_streams_uni = max },
            .streams_blocked_bidi => |max| .{ .streams_blocked_bidi = max },
            .streams_blocked_uni => |max| .{ .streams_blocked_uni = max },
            .data_blocked => |limit| .{ .data_blocked = limit },
            .stream_data_blocked => |sdb| .{ .stream_data_blocked = .{ .stream_id = sdb.stream_id, .limit = sdb.limit } },
            .reset_stream => |rs| .{ .reset_stream = .{ .stream_id = rs.stream_id, .error_code = rs.error_code, .final_size = rs.final_size } },
            .stop_sending => |ss| .{ .stop_sending = .{ .stream_id = ss.stream_id, .error_code = ss.error_code } },
            .ack_frequency => |af| .{ .ack_frequency = .{
                .sequence_number = af.sequence_number,
                .ack_eliciting_threshold = af.ack_eliciting_threshold,
                .request_max_ack_delay = af.request_max_ack_delay,
                .reordering_threshold = af.reordering_threshold,
            } },
            .immediate_ack => .{ .immediate_ack = {} },
            .observed_address => |value| .{ .observed_address = value },
            .add_address => |value| .{ .add_address = value },
            .reach_address => |value| .{ .reach_address = value },
            .remove_address => |value| .{ .remove_address = value },
            .path_abandon => |value| .{ .path_abandon = value },
            .path_status_backup => |value| .{ .path_status_backup = value },
            .path_status_available => |value| .{ .path_status_available = value },
            .path_retire_connection_id => |value| .{ .path_retire_connection_id = value },
            .max_path_id => |value| .{ .max_path_id = value },
            .paths_blocked => |value| .{ .paths_blocked = value },
            .path_cids_blocked => |value| .{ .path_cids_blocked = value },
            .path_new_connection_id => unreachable, // Written from inline storage.
            .new_token => unreachable, // handled directly in write()
            .new_connection_id => unreachable, // handled directly in write()
        };
    }
};

/// Fixed-capacity queue for pending control frames.
///
/// Full means the connection is producing control frames faster than it can
/// send them. What happens then depends on the frame, so callers choose:
/// `push` is for frames that are safe to lose (PING, PATH_*, BLOCKED — each
/// regenerated or superseded); frames the peer must eventually see go through
/// `tryPush`, and their producer retries on a later pass when it fails.
/// CONNECTION_CLOSE always gets in: one slot is held back for it.
///
/// The queue owns its storage: the fixed array is inline in the value, nothing
/// is allocated and nothing is borrowed, so there is no teardown and a copy
/// is a full independent copy. Its capacity comes from
/// `limits.zig.pending_frames`, so making the queue larger is a change to
/// `Connection`'s footprint, not to this file. Nothing here synchronises:
/// a queue belongs to one connection on one thread.
pub const PendingFrameQueue = struct {
    const capacity = @import("limits.zig").pending_frames;

    /// The slots, in the order they will be popped. Only
    /// `items[0..len]` is live; the tail is whatever the last eviction left.
    /// A caller reading the array directly takes on the queue's own invariant.
    items: [capacity]PendingControlFrame = undefined,
    /// How many slots are live, 0 to `capacity`. `capacity` is an `usize` and
    /// `len` a `u8`, so the two only meet because the capacity is small
    /// enough; a capacity above 255 would make `len` unable to hold it.
    len: u8 = 0,

    /// Queue `frame`, dropping it if the queue is full; see `tryPush`.
    ///
    /// The fire-and-forget entry: no return value, so a caller learns nothing
    /// about whether the frame survived. That is the point — a PING or a
    /// PATH_RESPONSE is regenerated or superseded, and losing it is cheaper
    /// than branching. A frame the peer must see goes through `tryPush`.
    pub fn push(self: *PendingFrameQueue, frame: PendingControlFrame) void {
        _ = self.tryPush(frame);
    }

    /// Whether `n` new, unmerged frames would fit.
    ///
    /// It counts the slot held back for CONNECTION_CLOSE, so a true answer
    /// means those `n` frames would all queue without evicting anything. A
    /// merge into an existing frame frees room, so this is the pessimistic
    /// test and may say no where `tryPush` would still succeed. Reads only.
    pub fn hasRoomFor(self: *const PendingFrameQueue, n: usize) bool {
        return self.len + n < capacity;
    }

    /// Put back a frame just popped. Never fails: `pop` freed its slot.
    ///
    /// It cannot return an error, but it is not lossless: if the queue filled
    /// between the `pop` and this call, and the frame does not merge into
    /// something already queued, the frame is dropped without a diagnostic.
    /// A caller that popped a frame it must eventually send either has the
    /// room for it or knows it does not.
    pub fn requeue(self: *PendingFrameQueue, frame: PendingControlFrame) void {
        if (self.tryPush(frame)) return;
        if (self.len < capacity) {
            self.items[self.len] = frame;
            self.len += 1;
        }
    }

    /// Queue `frame`, merging it into a queued frame of the same kind where
    /// one exists. False if it did not fit.
    ///
    /// A merge means the queue does not grow: a second PING or IMMEDIATE_ACK
    /// is discarded as a duplicate, and a second MAX_DATA, MAX_STREAMS_*,
    /// DATA_BLOCKED, STREAMS_BLOCKED_* or a same-stream MAX_STREAM_DATA /
    /// STREAM_DATA_BLOCKED keeps the larger of the old and new values. The
    /// merge only ever raises a limit, so a peer never sees a smaller one.
    /// True means the frame is queued or merged; false means nothing changed
    /// and the caller still owns `frame`.
    ///
    /// CONNECTION_CLOSE always returns true: one slot is reserved for it, and
    /// if even that is taken the last queued frame is evicted, because nothing
    /// queued matters once the connection is closing.
    pub fn tryPush(self: *PendingFrameQueue, frame: PendingControlFrame) bool {
        var i: u8 = 0;
        while (i < self.len) : (i += 1) {
            switch (frame) {
                .ping => switch (self.items[i]) {
                    .ping => return true,
                    else => {},
                },
                .immediate_ack => switch (self.items[i]) {
                    .immediate_ack => return true,
                    else => {},
                },
                .max_data => |new_max| switch (self.items[i]) {
                    .max_data => |old_max| {
                        self.items[i] = .{ .max_data = @max(old_max, new_max) };
                        return true;
                    },
                    else => {},
                },
                .max_stream_data => |new_msd| switch (self.items[i]) {
                    .max_stream_data => |old_msd| if (old_msd.stream_id == new_msd.stream_id) {
                        self.items[i] = .{ .max_stream_data = .{
                            .stream_id = new_msd.stream_id,
                            .max = @max(old_msd.max, new_msd.max),
                        } };
                        return true;
                    },
                    else => {},
                },
                .max_streams_bidi => |new_max| switch (self.items[i]) {
                    .max_streams_bidi => |old_max| {
                        self.items[i] = .{ .max_streams_bidi = @max(old_max, new_max) };
                        return true;
                    },
                    else => {},
                },
                .max_streams_uni => |new_max| switch (self.items[i]) {
                    .max_streams_uni => |old_max| {
                        self.items[i] = .{ .max_streams_uni = @max(old_max, new_max) };
                        return true;
                    },
                    else => {},
                },
                .data_blocked => |new_limit| switch (self.items[i]) {
                    .data_blocked => |old_limit| {
                        self.items[i] = .{ .data_blocked = @max(old_limit, new_limit) };
                        return true;
                    },
                    else => {},
                },
                .stream_data_blocked => |new_sdb| switch (self.items[i]) {
                    .stream_data_blocked => |old_sdb| if (old_sdb.stream_id == new_sdb.stream_id) {
                        self.items[i] = .{ .stream_data_blocked = .{
                            .stream_id = new_sdb.stream_id,
                            .limit = @max(old_sdb.limit, new_sdb.limit),
                        } };
                        return true;
                    },
                    else => {},
                },
                .streams_blocked_bidi => |new_limit| switch (self.items[i]) {
                    .streams_blocked_bidi => |old_limit| {
                        self.items[i] = .{ .streams_blocked_bidi = @max(old_limit, new_limit) };
                        return true;
                    },
                    else => {},
                },
                .streams_blocked_uni => |new_limit| switch (self.items[i]) {
                    .streams_blocked_uni => |old_limit| {
                        self.items[i] = .{ .streams_blocked_uni = @max(old_limit, new_limit) };
                        return true;
                    },
                    else => {},
                },
                else => {},
            }
        }
        const is_close = frame == .connection_close;
        if (self.len < capacity - 1 or (is_close and self.len < capacity)) {
            self.items[self.len] = frame;
            self.len += 1;
            return true;
        }
        if (is_close) {
            // Nothing queued matters once we are closing.
            self.items[self.len - 1] = frame;
            return true;
        }
        return false;
    }

    /// Takes the oldest queued frame, or `null` when the queue is empty.
    ///
    /// FIFO: the frame at `items[0]` comes out and the rest shift down, so
    /// the order a producer pushed them in is the order a caller sees. The
    /// result is a value copy that owns its bytes and outlives the queue, so
    /// it stays usable after the slot is reused.
    ///
    /// A caller that pops and cannot send has to hand the frame back with
    /// `requeue`; nothing else preserves it. Cost is a shift of the remaining
    /// slots, so a caller draining a full queue pays capacity² copies rather
    /// than a constant time.
    pub fn pop(self: *PendingFrameQueue) ?PendingControlFrame {
        if (self.len == 0) return null;
        const item = self.items[0];
        self.len -= 1;
        // Shift remaining items
        var i: u8 = 0;
        while (i < self.len) : (i += 1) {
            self.items[i] = self.items[i + 1];
        }
        return item;
    }
};

// Tests

test "parseSized ends each frame where the next one starts" {
    // picoquic packs HANDSHAKE_DONE and stream data behind ACK_FREQUENCY.
    const frames = [_]Frame{
        .{ .ack_frequency = .{ .sequence_number = 0, .ack_eliciting_threshold = 2, .request_max_ack_delay = 1000, .reordering_threshold = 0 } },
        .immediate_ack,
        .{ .crypto = .{ .offset = 7, .data = @constCast("hello") } },
        .{ .stream = .{ .stream_id = 4, .offset = 9, .length = 3, .fin = true, .data = @constCast("abc") } },
        .{ .new_connection_id = .{ .seq_num = 1, .retire_prior_to = 0, .conn_id = @constCast(&@as([8]u8, @splat(0xcd))), .stateless_reset_token = @splat(0) } },
        .{ .connection_close = .{ .error_code = 1, .frame_type = 0, .reason = @constCast("bye") } },
        .{ .datagram_with_length = .{ .data = @constCast("dg") } },
    };
    for (frames) |f| {
        var buf: [96]u8 = undefined;
        var fbs = io.fixedBufferStream(&buf);
        try f.write(&fbs);
        const len = fbs.seek;
        buf[len] = 0x1e; // HANDSHAKE_DONE follows
        var size: usize = undefined;
        _ = try Frame.parseSized(buf[0 .. len + 1], &size);
        try std.testing.expectEqual(len, size);
    }
}

test "parse padding frame" {
    {
        var bytes = [_]u8{0x00};
        switch (try Frame.parse(&bytes)) {
            FrameType.padding => |padding| try std.testing.expect(1 == padding),
            else => unreachable,
        }
    }
    {
        var bytes = [_]u8{ 0x00, 0x00, 0x01 };
        var size: usize = undefined;
        switch (try Frame.parseSized(&bytes, &size)) {
            FrameType.padding => |padding| try std.testing.expect(2 == padding),
            else => unreachable,
        }
        // The PING that follows is the next frame, not part of the padding.
        try std.testing.expectEqual(2, size);
    }
    {
        var bytes = [_]u8{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };
        switch (try Frame.parse(&bytes)) {
            FrameType.padding => |padding| try std.testing.expect(10 == padding),
            else => unreachable,
        }
    }
}

test "paddingLen: runs across and inside vector-sized blocks" {
    var buf: [200]u8 = @splat(0);
    try std.testing.expectEqual(200, paddingLen(&buf));
    try std.testing.expectEqual(0, paddingLen(&.{}));
    for ([_]usize{ 0, 1, 15, 16, 17, 31, 32, 33, 63, 64, 150, 199 }) |at| {
        buf[at] = 0x01;
        try std.testing.expectEqual(at, paddingLen(&buf));
        buf[at] = 0x00;
    }
}

test "parse ping frame" {
    var bytes = [_]u8{ 0x01, 0x00 };
    switch (try Frame.parse(&bytes)) {
        FrameType.ping => try std.testing.expect(true),
        else => unreachable,
    }
}

test "parse ack frame" {
    {
        // ACK frame: largest=10, delay=5, range_count=0, first_range=3
        var bytes = [_]u8{ 0x02, 0x0a, 0x05, 0x00, 0x03 };
        switch (try Frame.parse(&bytes)) {
            FrameType.ack => |ack| {
                try std.testing.expectEqual(@as(u64, 10), ack.largest_ack);
                try std.testing.expectEqual(@as(u64, 5), ack.ack_delay);
                try std.testing.expectEqual(@as(u64, 3), ack.first_ack_range);
            },
            else => unreachable,
        }
    }
    {
        // ACK-ECN frame
        var bytes = [_]u8{ 0x03, 0x0a, 0x05, 0x00, 0x03, 0x01, 0x02, 0x03 };
        switch (try Frame.parse(&bytes)) {
            FrameType.ack_ecn => |ack| {
                try std.testing.expectEqual(@as(u64, 10), ack.largest_ack);
                try std.testing.expectEqual(@as(u64, 1), ack.ecn_ect0);
                try std.testing.expectEqual(@as(u64, 2), ack.ecn_ect1);
                try std.testing.expectEqual(@as(u64, 3), ack.ecn_ce);
            },
            else => unreachable,
        }
    }
}

test "ACK ranges reaching below packet number 0 are FRAME_ENCODING_ERROR" {
    // first_ack_range 11 below largest 10.
    var first = [_]u8{ 0x02, 0x0a, 0x00, 0x00, 0x0b };
    try std.testing.expectError(error.FrameEncodingError, Frame.parse(&first));

    // [7,10], then a gap of 6 would put the next range's top at -1.
    var gap = [_]u8{ 0x02, 0x0a, 0x00, 0x01, 0x03, 0x06, 0x00 };
    try std.testing.expectError(error.FrameEncodingError, Frame.parse(&gap));

    // [7,10], gap 1 → next range tops at 4; a length of 5 reaches -1.
    var len = [_]u8{ 0x02, 0x0a, 0x00, 0x01, 0x03, 0x01, 0x05 };
    try std.testing.expectError(error.FrameEncodingError, Frame.parse(&len));

    // The same range ending exactly at 0 is fine.
    var ok = [_]u8{ 0x02, 0x0a, 0x00, 0x01, 0x03, 0x01, 0x04 };
    const f = try Frame.parse(&ok);
    try std.testing.expectEqual(@as(u64, 0), f.ack.ack_ranges[0].start);
    try std.testing.expectEqual(@as(u64, 4), f.ack.ack_ranges[0].end);
}

test "parse reset_stream frame" {
    var bytes = [_]u8{
        0x04,
        0x00, 0x00, 0x00, 0x00, // Stream ID
        0x00, 0x00, 0x00, 0x00, // Application Protocol Error Code
        0x00, 0x00, 0x00, 0x00, // Final Size
    };
    switch (try Frame.parse(&bytes)) {
        FrameType.reset_stream => try std.testing.expect(true),
        else => unreachable,
    }
}

test "parse stop_sending frame" {
    var bytes = [_]u8{
        0x05,
        0x00, 0x00, 0x00, 0x00, // Stream ID
        0x00, 0x00, 0x00, 0x00, // Error Code
    };
    switch (try Frame.parse(&bytes)) {
        FrameType.stop_sending => try std.testing.expect(true),
        else => unreachable,
    }
}

test "parse crypto frame" {
    var bytes = [_]u8{
        0x06,
        0x00, // Offset: 0
        0x04, // Data Length: 4
        0xde, 0xad, 0xbe, 0xef, // Data
    };
    switch (try Frame.parse(&bytes)) {
        FrameType.crypto => |crypto| {
            try std.testing.expectEqual(@as(u64, 0), crypto.offset);
            try std.testing.expectEqualSlices(u8, &[_]u8{ 0xde, 0xad, 0xbe, 0xef }, crypto.data);
        },
        else => unreachable,
    }
}

test "parse new_token frame" {
    var bytes = [_]u8{
        0x07,
        16, // size
        97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, // "abcdefghijklmnop"
    };
    switch (try Frame.parse(&bytes)) {
        FrameType.new_token => |frame| {
            try std.testing.expectEqualStrings("abcdefghijklmnop", frame);
            try std.testing.expect(true);
        },
        else => unreachable,
    }
}

test "parse stream frame with all flags" {
    // Stream frame type 0x0f = FIN + LEN + OFF
    var bytes = [_]u8{
        0x0f,
        0x04, // stream id: 4
        0x0a, // offset: 10
        0x03, // length: 3
        0x41, 0x42, 0x43, // data: "ABC"
    };
    switch (try Frame.parse(&bytes)) {
        FrameType.stream => |s| {
            try std.testing.expectEqual(@as(u64, 4), s.stream_id);
            try std.testing.expectEqual(@as(u64, 10), s.offset);
            try std.testing.expectEqual(@as(u64, 3), s.length);
            try std.testing.expect(s.fin);
            try std.testing.expectEqualSlices(u8, &[_]u8{ 0x41, 0x42, 0x43 }, s.data);
        },
        else => unreachable,
    }
}

test "parse stream frame minimal (no offset, no length, no fin)" {
    // Stream frame type 0x08 = no flags
    var bytes = [_]u8{
        0x08,
        0x00, // stream id: 0
        0xAA, 0xBB, // remaining data (no length field, so all remaining)
    };
    switch (try Frame.parse(&bytes)) {
        FrameType.stream => |s| {
            try std.testing.expectEqual(@as(u64, 0), s.stream_id);
            try std.testing.expectEqual(@as(u64, 0), s.offset);
            try std.testing.expect(!s.fin);
            try std.testing.expectEqualSlices(u8, &[_]u8{ 0xAA, 0xBB }, s.data);
        },
        else => unreachable,
    }
}

test "parse max_data frame" {
    var bytes = [_]u8{ 0x10, 0x9d, 0x7f, 0x3e, 0x7d }; // 494878333
    switch (try Frame.parse(&bytes)) {
        FrameType.max_data => |max_data| {
            try std.testing.expect(max_data == 494878333);
        },
        else => unreachable,
    }
}

test "parse max_stream_data frame" {
    var bytes = [_]u8{
        0x11,
        0x00, // stream id: 0
        0x7b, 0xbd, // max: 15293
    };
    switch (try Frame.parse(&bytes)) {
        FrameType.max_stream_data => |max_stream_data| {
            try std.testing.expect(max_stream_data.stream_id == 0);
            try std.testing.expect(max_stream_data.max == 15293);
        },
        else => unreachable,
    }
}

test "parse max_streams_bidi frame" {
    var bytes = [_]u8{ 0x12, 0x9d, 0x7f, 0x3e, 0x7d }; // 494878333
    switch (try Frame.parse(&bytes)) {
        FrameType.max_streams_bidi => |value| {
            try std.testing.expect(value == 494878333);
        },
        else => unreachable,
    }
}

test "parse max_streams_uni frame" {
    var bytes = [_]u8{ 0x13, 0x9d, 0x7f, 0x3e, 0x7d }; // 494878333
    switch (try Frame.parse(&bytes)) {
        FrameType.max_streams_uni => |value| {
            try std.testing.expect(value == 494878333);
        },
        else => unreachable,
    }
}

test "parse data_blocked frame" {
    var bytes = [_]u8{ 0x14, 0x9d, 0x7f, 0x3e, 0x7d }; // 494878333
    switch (try Frame.parse(&bytes)) {
        FrameType.data_blocked => |value| {
            try std.testing.expect(value == 494878333);
        },
        else => unreachable,
    }
}

test "parse stream_data_blocked frame" {
    var bytes = [_]u8{
        0x15,
        0x00, // stream id: 0
        0x7b, 0xbd, // limit: 15293
    };
    switch (try Frame.parse(&bytes)) {
        FrameType.stream_data_blocked => |stream_data_blocked| {
            try std.testing.expect(stream_data_blocked.stream_id == 0);
            try std.testing.expect(stream_data_blocked.limit == 15293);
        },
        else => unreachable,
    }
}

test "parse streams_blocked_bidi frame" {
    var bytes = [_]u8{ 0x16, 0x9d, 0x7f, 0x3e, 0x7d }; // 494878333
    switch (try Frame.parse(&bytes)) {
        FrameType.streams_blocked_bidi => |value| {
            try std.testing.expect(value == 494878333);
        },
        else => unreachable,
    }
}

test "parse streams_blocked_uni frame" {
    var bytes = [_]u8{ 0x17, 0x9d, 0x7f, 0x3e, 0x7d }; // 494878333
    switch (try Frame.parse(&bytes)) {
        FrameType.streams_blocked_uni => |value| {
            try std.testing.expect(value == 494878333);
        },
        else => unreachable,
    }
}

test "parse new_connection_id frame" {
    var bytes = [_]u8{
        0x18, // Type
        0x00, // Sequence Number: 0
        0x01, // Retire Prior To: 0
        0x02, // Length (8)
        0x00, 0x01, // Connection ID (8..160)
        97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, // Stateless Reset Token
    };

    switch (try Frame.parse(&bytes)) {
        FrameType.new_connection_id => |new_connection_id| {
            try std.testing.expect(new_connection_id.seq_num == 0);
            try std.testing.expect(new_connection_id.retire_prior_to == 1);
            try std.testing.expectFmt("{ 0, 1 }", "{any}", .{new_connection_id.conn_id});
            try std.testing.expectEqualStrings("abcdefghijklmnop", &new_connection_id.stateless_reset_token);
        },
        else => unreachable,
    }
}

test "parse retire_connection_id frame" {
    var bytes = [_]u8{
        0x19, // Type
        0x02, // Sequence Number: 0
    };
    switch (try Frame.parse(&bytes)) {
        FrameType.retire_connection_id => |retire_connection_id| {
            try std.testing.expect(retire_connection_id.seq_num == 2);
        },
        else => unreachable,
    }
}

test "parse path_challenge frame" {
    var bytes = [_]u8{ 0x1a, 1, 2, 3, 4, 5, 6, 7, 8 };
    switch (try Frame.parse(&bytes)) {
        FrameType.path_challenge => |data| {
            try std.testing.expectFmt("{ 1, 2, 3, 4, 5, 6, 7, 8 }", "{any}", .{data});
        },
        else => unreachable,
    }
}

test "parse path_response frame" {
    var bytes = [_]u8{ 0x1b, 1, 2, 3, 4, 5, 6, 7, 8 };
    switch (try Frame.parse(&bytes)) {
        FrameType.path_response => |data| {
            try std.testing.expectFmt("{ 1, 2, 3, 4, 5, 6, 7, 8 }", "{any}", .{data});
        },
        else => unreachable,
    }
}

test "parse connection_close frame" {
    var bytes = [_]u8{ 0x1c, 0x10, @backingInt(FrameType.max_data), 16, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112 };

    switch (try Frame.parse(&bytes)) {
        FrameType.connection_close => |connection_close| {
            try std.testing.expect(connection_close.error_code == 0x10);
            try std.testing.expect(connection_close.frame_type == @backingInt(FrameType.max_data));
            try std.testing.expectEqualStrings("abcdefghijklmnop", connection_close.reason);
        },
        else => unreachable,
    }
}

test "parse application_close frame" {
    var bytes = [_]u8{ 0x1d, 0x10, 16, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112 };

    switch (try Frame.parse(&bytes)) {
        FrameType.application_close => |connection_close| {
            try std.testing.expect(connection_close.error_code == 0x10);
            try std.testing.expectEqualStrings("abcdefghijklmnop", connection_close.reason);
        },
        else => unreachable,
    }
}

test "parse handshake_done frame" {
    var bytes = [_]u8{0x1e};
    switch (try Frame.parse(&bytes)) {
        FrameType.handshake_done => try std.testing.expect(true),
        else => unreachable,
    }
}

test "write and parse ping frame roundtrip" {
    var buf: [64]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    const frame = Frame{ .ping = {} };
    try frame.write(&fbs);
    const written = fbs.buffered();
    var written_mut: [64]u8 = undefined;
    @memcpy(written_mut[0..written.len], written);
    const parsed = try Frame.parse(written_mut[0..written.len]);
    try std.testing.expectEqual(FrameType.ping, parsed);
}

test "write and parse max_data frame roundtrip" {
    var buf: [64]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    const frame = Frame{ .max_data = 999999 };
    try frame.write(&fbs);
    const written = fbs.buffered();
    var written_mut: [64]u8 = undefined;
    @memcpy(written_mut[0..written.len], written);
    const parsed = try Frame.parse(written_mut[0..written.len]);
    switch (parsed) {
        .max_data => |val| try std.testing.expectEqual(@as(u64, 999999), val),
        else => unreachable,
    }
}

test "PendingControlFrame: max_streams_bidi write and parse roundtrip" {
    var buf: [64]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    const pcf = PendingControlFrame{ .max_streams_bidi = 42 };
    try pcf.write(&fbs);
    const written = fbs.buffered();
    var written_mut: [64]u8 = undefined;
    @memcpy(written_mut[0..written.len], written);
    const parsed = try Frame.parse(written_mut[0..written.len]);
    switch (parsed) {
        .max_streams_bidi => |val| try std.testing.expectEqual(@as(u64, 42), val),
        else => unreachable,
    }
}

test "PendingControlFrame: max_streams_uni write and parse roundtrip" {
    var buf: [64]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    const pcf = PendingControlFrame{ .max_streams_uni = 100 };
    try pcf.write(&fbs);
    const written = fbs.buffered();
    var written_mut: [64]u8 = undefined;
    @memcpy(written_mut[0..written.len], written);
    const parsed = try Frame.parse(written_mut[0..written.len]);
    switch (parsed) {
        .max_streams_uni => |val| try std.testing.expectEqual(@as(u64, 100), val),
        else => unreachable,
    }
}

test "PendingControlFrame: streams_blocked_bidi write and parse roundtrip" {
    var buf: [64]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    const pcf = PendingControlFrame{ .streams_blocked_bidi = 7 };
    try pcf.write(&fbs);
    const written = fbs.buffered();
    var written_mut: [64]u8 = undefined;
    @memcpy(written_mut[0..written.len], written);
    const parsed = try Frame.parse(written_mut[0..written.len]);
    switch (parsed) {
        .streams_blocked_bidi => |val| try std.testing.expectEqual(@as(u64, 7), val),
        else => unreachable,
    }
}

test "PendingControlFrame: streams_blocked_uni write and parse roundtrip" {
    var buf: [64]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    const pcf = PendingControlFrame{ .streams_blocked_uni = 3 };
    try pcf.write(&fbs);
    const written = fbs.buffered();
    var written_mut: [64]u8 = undefined;
    @memcpy(written_mut[0..written.len], written);
    const parsed = try Frame.parse(written_mut[0..written.len]);
    switch (parsed) {
        .streams_blocked_uni => |val| try std.testing.expectEqual(@as(u64, 3), val),
        else => unreachable,
    }
}

test "PendingControlFrame: toFrame mapping for new variants" {
    // max_streams_bidi
    const pcf1 = PendingControlFrame{ .max_streams_bidi = 50 };
    const f1 = pcf1.toFrame();
    switch (f1) {
        .max_streams_bidi => |val| try std.testing.expectEqual(@as(u64, 50), val),
        else => unreachable,
    }

    // max_streams_uni
    const pcf2 = PendingControlFrame{ .max_streams_uni = 25 };
    const f2 = pcf2.toFrame();
    switch (f2) {
        .max_streams_uni => |val| try std.testing.expectEqual(@as(u64, 25), val),
        else => unreachable,
    }

    // streams_blocked_bidi
    const pcf3 = PendingControlFrame{ .streams_blocked_bidi = 10 };
    const f3 = pcf3.toFrame();
    switch (f3) {
        .streams_blocked_bidi => |val| try std.testing.expectEqual(@as(u64, 10), val),
        else => unreachable,
    }

    // streams_blocked_uni
    const pcf4 = PendingControlFrame{ .streams_blocked_uni = 5 };
    const f4 = pcf4.toFrame();
    switch (f4) {
        .streams_blocked_uni => |val| try std.testing.expectEqual(@as(u64, 5), val),
        else => unreachable,
    }
}

test "PendingFrameQueue: push and pop max_streams variants" {
    var queue = PendingFrameQueue{};

    queue.push(.{ .max_streams_bidi = 100 });
    queue.push(.{ .max_streams_uni = 50 });
    queue.push(.{ .streams_blocked_bidi = 10 });
    queue.push(.{ .streams_blocked_uni = 5 });

    try std.testing.expectEqual(@as(u8, 4), queue.len);

    const f1 = queue.pop().?;
    switch (f1) {
        .max_streams_bidi => |val| try std.testing.expectEqual(@as(u64, 100), val),
        else => unreachable,
    }

    const f2 = queue.pop().?;
    switch (f2) {
        .max_streams_uni => |val| try std.testing.expectEqual(@as(u64, 50), val),
        else => unreachable,
    }

    const f3 = queue.pop().?;
    switch (f3) {
        .streams_blocked_bidi => |val| try std.testing.expectEqual(@as(u64, 10), val),
        else => unreachable,
    }

    const f4 = queue.pop().?;
    switch (f4) {
        .streams_blocked_uni => |val| try std.testing.expectEqual(@as(u64, 5), val),
        else => unreachable,
    }

    try std.testing.expect(queue.pop() == null);
}

test "frame body longer than the datagram is rejected, not sliced" {
    // 0x06 CRYPTO, offset 0, length 16383 — but only 4 bytes follow.
    var crypto_frame = [_]u8{ 0x06, 0x00, 0x7f, 0xff, 0xde, 0xad, 0xbe, 0xef };
    try std.testing.expectError(error.FrameEncodingError, Frame.parse(&crypto_frame));

    // Same shape via CONNECTION_CLOSE's reason phrase.
    var close_frame = [_]u8{ 0x1c, 0x00, 0x00, 0x7f, 0xff, 0x41 };
    try std.testing.expectError(error.FrameEncodingError, Frame.parse(&close_frame));

    // 0x07 NEW_TOKEN with a length past the end.
    var token_frame = [_]u8{ 0x07, 0x7f, 0xff, 0x01, 0x02 };
    try std.testing.expectError(error.FrameEncodingError, Frame.parse(&token_frame));
}

test "PendingFrameQueue: full refuses new frames but always admits CONNECTION_CLOSE" {
    var q = PendingFrameQueue{};
    var i: u64 = 0;
    while (q.tryPush(.{ .reset_stream = .{ .stream_id = i * 4, .error_code = 0, .final_size = 0 } })) i += 1;
    try std.testing.expect(!q.hasRoomFor(1));
    try std.testing.expect(!q.tryPush(.{ .stop_sending = .{ .stream_id = 1, .error_code = 0 } }));

    // The reserved slot, then eviction: a close is never lost.
    try std.testing.expect(q.tryPush(.{ .connection_close = .{ .error_code = 1, .frame_type = 0, .is_app = false } }));
    try std.testing.expect(q.tryPush(.{ .connection_close = .{ .error_code = 2, .frame_type = 0, .is_app = false } }));
    try std.testing.expect(q.items[q.len - 1] == .connection_close);

    // A popped frame can always be put back.
    const f = q.pop().?;
    q.requeue(f);
    try std.testing.expectEqual(@as(usize, @import("limits.zig").pending_frames), q.len);
}

test "Noq 1.3 native traversal and multipath source wire vectors" {
    // Source oracle: noq-proto 1.3.0 frame.rs encoders, including path prefix.
    const vectors = [_][]const u8{
        &.{ 0x80, 0x3d, 0x7f, 0x94, 0x40, 0x40 },
        &.{ 0x7e, 0x75, 1, 0 },
        &.{ 0x7e, 0x76, 1, 2 },
        &.{ 0x7e, 0x77, 1, 2 },
        &.{ 0x7e, 0x79, 1, 0 },
        &.{ 0x7e, 0x7a, 1 },
        &.{ 0x7e, 0x7b, 1 },
        &.{ 0x7e, 0x7c, 1, 2 },
        &.{ 0x3e, 1, 10, 0, 0, 3 },
        &.{ 0x3f, 1, 10, 0, 0, 3, 1, 2, 3 },
    };
    for (vectors) |vector| {
        var bytes: [64]u8 = undefined;
        @memcpy(bytes[0..vector.len], vector);
        var consumed: usize = 0;
        const decoded = try Frame.parseSized(bytes[0..vector.len], &consumed);
        try std.testing.expectEqual(vector.len, consumed);
        var encoded: [64]u8 = undefined;
        var writer = io.fixedBufferStream(&encoded);
        try decoded.write(&writer);
        try std.testing.expectEqualSlices(u8, vector, writer.buffered());
        for (0..vector.len) |cut| {
            if (Frame.parse(bytes[0..cut])) |_| return error.AcceptedTruncatedFrame else |_| {}
        }
        try std.testing.expect(decoded.isAllowedIn(.one_rtt));
        try std.testing.expect(!decoded.isAllowedIn(.zero_rtt));
    }
}

test "native extension malformed path IDs and ACK ranges" {
    var overflow = [_]u8{ 0x7e, 0x75, 0xc0, 0, 0, 1, 0, 0, 0, 0, 0 };
    try std.testing.expectError(error.FrameEncodingError, Frame.parse(&overflow));
    var range = [_]u8{ 0x3e, 1, 0, 0, 0, 1 };
    try std.testing.expectError(error.FrameEncodingError, Frame.parse(&range));
    var gap = [_]u8{ 0x3e, 1, 0, 0, 1, 0, 0, 0 };
    try std.testing.expectError(error.FrameEncodingError, Frame.parse(&gap));
    var cid = [_]u8{ 0x7e, 0x78, 1, 0, 1, 1, 0 };
    try std.testing.expectError(error.FrameEncodingError, Frame.parse(&cid));
}

test "native extension frame fuzz canonical encoding fixed point" {
    // Coverage needs fuzz instrumentation, but Zig 0.16.0's fuzz runner has bug #36326.
    if (comptime @import("builtin").fuzz and @import("coverage_options").coverage) {
        var smith: std.testing.Smith = .{ .in = &.{} };
        try fuzzNativeFrame({}, &smith);
    } else {
        try std.testing.fuzz({}, fuzzNativeFrame, .{});
    }
}

fn fuzzNativeFrame(_: void, smith: *std.testing.Smith) !void {
    const types = [_]u64{
        0x9f81a6, 0x9f81a7, 0x3d7f90, 0x3d7f91, 0x3d7f92, 0x3d7f93, 0x3d7f94,
        0x3e,     0x3f,     0x3e75,   0x3e76,   0x3e77,   0x3e78,   0x3e79,
        0x3e7a,   0x3e7b,   0x3e7c,
    };
    var input: [128]u8 = undefined;
    var stream = io.fixedBufferStream(&input);
    const selected = smith.value(u8) % types.len;
    try packet.writeVarInt(&stream, types[selected]);
    const body_start = stream.seek;
    const body_length = smith.slice(input[body_start..]);
    var consumed: usize = 0;
    const decoded = Frame.parseSized(input[0 .. body_start + body_length], &consumed) catch return;
    try std.testing.expect(consumed <= body_start + body_length);
    var encoded: [640]u8 = undefined;
    var writer = io.fixedBufferStream(&encoded);
    try decoded.write(&writer);
    const again = try Frame.parseSized(encoded[0..writer.seek], &consumed);
    try std.testing.expectEqual(writer.seek, consumed);
    var fixed_bytes: [640]u8 = undefined;
    var fixed_writer = io.fixedBufferStream(&fixed_bytes);
    try again.write(&fixed_writer);
    try std.testing.expectEqualSlices(u8, writer.buffered(), fixed_writer.buffered());
}

test "multipath pending CID owns storage and writes complete body" {
    const pending = PendingControlFrame{ .path_new_connection_id = .{
        .path_id = 1,
        .cid = .{
            .seq_num = 0,
            .retire_prior_to = 0,
            .cid_buf = @splat(0xab),
            .cid_len = 1,
            .stateless_reset_token = @splat(0xcd),
        },
    } };
    var buffer: [64]u8 = undefined;
    var writer = io.fixedBufferStream(&buffer);
    try pending.write(&writer);
    var consumed: usize = 0;
    const frame = try Frame.parseSized(buffer[0..writer.seek], &consumed);
    try std.testing.expectEqual(writer.seek, consumed);
    try std.testing.expectEqual(@as(u32, 1), frame.path_new_connection_id.path_id);
    try std.testing.expectEqualSlices(u8, &.{0xab}, frame.path_new_connection_id.cid.conn_id);
    try std.testing.expectEqualSlices(u8, &(@as([16]u8, @splat(0xcd))), &frame.path_new_connection_id.cid.stateless_reset_token);
    try std.testing.expect(!frame.isProbing());
    for (0..writer.seek) |cut| {
        if (Frame.parse(buffer[0..cut])) |_| return error.AcceptedTruncatedCid else |_| {}
    }
}

test "Frame.isProbing matches native Noq classification" {
    const probes = [_]Frame{
        .{ .padding = 1 },
        .{ .path_challenge = @splat(0) },
        .{ .path_response = @splat(0) },
        .{ .new_connection_id = .{
            .seq_num = 0,
            .retire_prior_to = 0,
            .conn_id = @constCast(&[_]u8{0xab}),
            .stateless_reset_token = @splat(0),
        } },
        .{ .observed_address = .{
            .sequence = 0,
            .address = .initIpv4(.{ 127, 0, 0, 1 }, 443),
        } },
    };
    for (probes) |frame| try std.testing.expect(frame.isProbing());

    const path_new_connection_id: Frame = .{ .path_new_connection_id = .{
        .path_id = 1,
        .cid = .{
            .seq_num = 0,
            .retire_prior_to = 0,
            .conn_id = @constCast(&[_]u8{0xab}),
            .stateless_reset_token = @splat(0),
        },
    } };
    try std.testing.expect(!path_new_connection_id.isProbing());
}
