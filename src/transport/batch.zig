//! The UDP batch seam: a list of datagrams in, socket writes out.
//!
//! `docs/DECISIONS/0002-async-substrate.md` records the decision this module
//! implements: zio's `std.Io` bridge sends one datagram per `sendmsg`, and a
//! batch of datagrams wants `UDP_SEGMENT`, so the batcher lives here at the
//! transport seam and degrades to one-datagram sends where the platform
//! cannot segment.
//!
//! # There is no socket here
//!
//! A send is a value: bytes, a segment size, and the ancillary data a socket
//! would be handed. What the socket refuses comes back as a `Report` and
//! nothing else. That is the whole reason the fallback is testable without an
//! operating system: a caller learns which path it took by reading a value,
//! not by noticing the wire got slower.
//!
//! # Purity
//!
//! No clock, no environment, no global, no allocator. The platform's
//! capability is an argument, its option numbers are named once in
//! `batch_platform.zig` and read from the Zig 0.16 std tree, and every buffer
//! is the caller's. See `docs/ARCHITECTURE.md`, "Wire codecs are pure and
//! separate from the transport".
//!
//! # Three runtime responsibilities, three modules, one vocabulary
//!
//! This file is the seam and the vocabulary both sides share. The work is
//! split by what runs, not by size:
//!
//! - `batch_platform.zig` — what this platform's socket can be *asked* for and
//!   what it answered: the option numbers, the kernel's segment and payload
//!   ceilings, and the `Capability` a probe produces.
//! - `batch_send.zig` — the send half. `Send` and `Runs` (a payload and the
//!   runs one `sendmsg` each can carry) and what a refused run costs.
//! - `batch_recv.zig` — the receive half. `Recv`, one buffer that is either a
//!   datagram or a list of them coalesced into it.
//!
//! The traffic-class and segmentation *control messages* were a fourth thing
//! and are not one: `batch_send.zig` writes them beside the payload they
//! describe, because a message is only meaningful next to the `Send` it goes
//! out with. `max_cmsg`, `Value`, `Cmsg`, `tosBits` and `cmsg` therefore
//! belong to the send half.
//!
//! `Ecn`, `Error` and `Family` are here because both halves and the platform
//! need them and a rule written down twice is a rule one extension away from
//! being wrong twice. Every other name below is *declared* where the
//! responsibility is and *named* here, which is the same thing `socket.zig`
//! does with `SendError` and `Received`: this file is where a caller looks,
//! and the module a declaration lives in is where a reader goes to change it.

const std = @import("std");
const frame = @import("../relay/frame.zig");
const addr = @import("../base/addr.zig");

const batch_platform = @import("batch_platform.zig");
const batch_send = @import("batch_send.zig");
const batch_recv = @import("batch_recv.zig");

const std_testing = std.testing;

/// Explicit congestion notification, as a datagram carries it.
///
/// `noq_udp::EcnCodepoint` (`noq-udp/src/lib.rs:248`), which is
/// `noq_proto::EcnCodepoint` (`shared.rs:180`) spelled a second time. ozai
/// keeps one: the three codepoints are the same three values in both, and a
/// rule written down twice is a rule one table extension away from being
/// wrong in two places. `relay/frame.zig` owns the definition because it got
/// there first; `base` is where it belongs.
pub const Ecn = frame.Ecn;

/// Every way a batch value can be refused.
///
/// The first name is `relay/frame.zig`'s, for `relay/frame.zig`'s reason: a
/// zero size names no datagram, and the codec refusing one on decode is the
/// same fact as this refusing one on the way to the socket. The second is
/// upstream's bug: noq writes the segment size with `segment_size as u16`
/// (`noq-udp/src/unix.rs:629`), so a segment larger than a `u16` is
/// truncated there and refused here.
pub const Error = error{
    /// A zero segment size or a zero receive stride. Zero names no datagram.
    ZeroSegmentSize,
    /// A segment size the `UDP_SEGMENT` control message cannot carry, or one
    /// wider than a single datagram may be (`max_send_payload`). Either way no
    /// run can be built out of it.
    SegmentSizeTooLarge,
    /// A receive stride larger than the buffer it describes. A datagram
    /// cannot be bigger than the bytes that hold it.
    StrideExceedsBuffer,
};

/// Which IP version a datagram goes out as, or came back on.
///
/// This is the only thing about a destination this module cares about: it is
/// what decides which control message carries the codepoint. The address
/// belongs to the path, not to the batch.
pub const Family = enum {
    v4,
    v6,

    /// The family an address belongs to, so that no caller has to hand-write
    /// the tag next to an address it just read.
    pub fn of(ip: addr.IpAddress) Family {
        return switch (ip) {
            .v4 => .v4,
            .v6 => .v6,
        };
    }
};

/// The most datagrams one `sendmsg` may carry as ancillary data. Declared in
/// `batch_send.zig` and named here.
pub const max_cmsg = batch_send.max_cmsg;

/// The Linux control-message options this seam names. Declared in
/// `batch_platform.zig` and named here.
pub const linux = batch_platform.linux;

/// The width a traffic-class control message's value takes. Declared in
/// `batch_platform.zig` and named here.
pub const tos_width = batch_platform.tos_width;

/// `UDP_MAX_SEGMENTS` as noq reports it. Declared in `batch_platform.zig`.
pub const max_segments_linux = batch_platform.max_segments_linux;

/// The most payload bytes one `sendmsg` may carry. Declared in
/// `batch_platform.zig`.
pub const max_send_payload = batch_platform.max_send_payload;

/// `UDP_GRO_CNT_MAX` as noq installs it. Declared in `batch_platform.zig`.
pub const max_gro_segments_linux = batch_platform.max_gro_segments_linux;

/// What setting a socket option returned. Declared in `batch_platform.zig`.
pub const Probe = batch_platform.Probe;

/// What a socket on this platform can do. Declared in `batch_platform.zig`.
pub const Capability = batch_platform.Capability;

/// The capability of a socket that answered two probes. Declared in
/// `batch_platform.zig`.
pub const capability = batch_platform.capability;

/// One `setsockopt` call, by name and value. Declared in
/// `batch_platform.zig`.
pub const SocketOption = batch_platform.SocketOption;

/// The options a socket has to be given to carry a codepoint back. Declared in
/// `batch_platform.zig`.
pub const socketOptions = batch_platform.socketOptions;

/// A payload going out. Declared in `batch_send.zig`.
pub const Send = batch_send.Send;

/// The runs one socket write each may carry. Declared in `batch_send.zig`.
pub const Runs = batch_send.Runs;

/// What a `sendmsg` refused to carry. Declared in `batch_send.zig`.
pub const Refused = batch_send.Refused;

/// What one send carried, and what it did not. Declared in `batch_send.zig`.
pub const Report = batch_send.Report;

/// The report for one send. Declared in `batch_send.zig`.
pub const report = batch_send.report;

/// The value a control message carries. Declared in `batch_send.zig`.
pub const Value = batch_send.Value;

/// One control message, as a `sendmsg` writes it. Declared in
/// `batch_send.zig`.
pub const Cmsg = batch_send.Cmsg;

/// The traffic class a send puts in its control message. Declared in
/// `batch_send.zig`.
pub const tosBits = batch_send.tosBits;

/// The control messages one `sendmsg` carries. Declared in `batch_send.zig`.
pub const cmsg = batch_send.cmsg;

/// One buffer a `recvmsg` filled. Declared in `batch_recv.zig`.
pub const Recv = batch_recv.Recv;

/// `a / b` rounded up, for a `b` the caller has already established is not
/// zero.
///
/// Written out rather than `std.math.divCeil` so that the precondition is at
/// the call site instead of inside a `catch`. Every `b` here is a receive
/// stride from `Recv.init` or a run bound from `Runs.init`, both of which have
/// already refused zero.
pub fn divCeil(a: usize, b: usize) usize {
    return a / b + @intFromBool(a % b != 0);
}

// The refusal a size or a stride that names no datagram gets, from every
// entry point that raises one. It spans both halves on purpose: a zero
// segment size and a zero receive stride are the same fault, and only a
// module that can see `Send`, `Runs` and `Recv` can say that once.
test "a stride that names no datagram, or one past the buffer, is refused" {
    const bytes = [_]u8{0} ** 8;
    try std_testing.expectError(error.ZeroSegmentSize, Recv.init(&bytes, 0, null));
    try std_testing.expectError(error.ZeroSegmentSize, Recv.init(&.{}, null, null));
    try std_testing.expectError(error.StrideExceedsBuffer, Recv.init(&bytes, 9, null));
    try std_testing.expectError(error.ZeroSegmentSize, Send.batch(&bytes, 0, null));
    try std_testing.expectError(
        error.SegmentSizeTooLarge,
        Send.batch(&bytes, @as(usize, std.math.maxInt(u16)) + 1, null),
    );
    // A hand-built zero is the one shape a constructor cannot reach, and the
    // walk refuses it rather than dividing by it.
    const handbuilt: Send = .{ .ecn = null, .contents = &bytes, .segment_size = 0 };
    try std_testing.expectError(
        error.ZeroSegmentSize,
        Runs.init(handbuilt, Capability.linux_full),
    );
}

test "error inventory: every declared arm is refused by a concrete value" {
    // Three arms, and each is reachable from more than one entry point, so each
    // is walked from every place that raises it. `std_testing.expectError` is
    // the assertion: the point is that the named error is what came back rather
    // than a different one or a panic.
    const alloc = std_testing.allocator;
    const bytes = try alloc.alloc(u8, 4096);
    defer alloc.free(bytes);
    @memset(bytes, 0x5a);
    const full = Capability.linux_full;

    // `ZeroSegmentSize`: a zero segment size and a zero receive stride both
    // name no datagram, and each is refused by every function that divides by
    // it or names datagrams with it.
    try std_testing.expectError(error.ZeroSegmentSize, Send.batch(bytes, 0, null));
    try std_testing.expectError(error.ZeroSegmentSize, full.maxRunDatagrams(0));
    try std_testing.expectError(error.ZeroSegmentSize, Recv.init(bytes, 0, null));
    // An empty buffer with no stride is a zero stride, and is refused with it.
    try std_testing.expectError(error.ZeroSegmentSize, Recv.init(&.{}, null, null));
    // A hand-built value with a zero is the shape no constructor can reach.
    try std_testing.expectError(
        error.ZeroSegmentSize,
        Runs.init(.{ .ecn = null, .contents = bytes, .segment_size = 0 }, full),
    );

    // `SegmentSizeTooLarge`: a size `UDP_SEGMENT` cannot carry, and a size no
    // datagram may carry at all. Both are refused rather than divided into zero
    // datagrams, which is the hazard the two checks exist for.
    try std_testing.expectError(
        error.SegmentSizeTooLarge,
        Send.batch(bytes, @as(usize, std.math.maxInt(u16)) + 1, null),
    );
    try std_testing.expectError(
        error.SegmentSizeTooLarge,
        full.maxRunDatagrams(max_send_payload + 1),
    );
    try std_testing.expectError(
        error.SegmentSizeTooLarge,
        Runs.init(try Send.batch(bytes, max_send_payload + 1, null), full),
    );

    // `StrideExceedsBuffer`: a datagram cannot be bigger than the bytes that
    // hold it, so a stride past the buffer describes nothing on the wire.
    try std_testing.expectError(
        error.StrideExceedsBuffer,
        Recv.init(bytes[0..16], 17, null),
    );
    try std_testing.expectError(
        error.StrideExceedsBuffer,
        Recv.init(bytes[0..16], bytes.len, null),
    );
}
