//! The relay's internal control statements, in and out of the wire message for
//! each protocol version.
//!
//! `relay/server_queue.zig`'s `Control` is what a relay decides to tell one
//! client: a peer has gone, or the connection's health changed. Neither is a
//! frame type. On the wire they are `endpoint_gone` in both versions, and
//! `status` in v2 or a `health` problem in v1 — `docs/ARCHITECTURE.md` rule 8 is
//! "the server translates", and this file is the translation.
//!
//! # A refusal one version can express and another cannot
//!
//! **The v1 spelling of a `Status` is text, and a condition this build has no
//! name for has no text.** `frame_types.zig` keeps `Status.unknown: u8` on
//! purpose so a relay that grows a fourth condition does not break a client that
//! is only reading; on a v2 connection that byte goes out and comes back
//! unchanged. On a v1 connection the only wire form is a `health` problem, and
//! the one honest way to render a condition this build cannot name is to refuse:
//! any sentence would be relay-authored prose that a v1 client cannot tell from a
//! decision the relay did make, which is the same objection `frame_encode.zig`
//! raises against shortening a denial's reason. So it is
//! `error.StatusNotExpressible`, and a caller that hits it knows to send
//! something else rather than believe something was sent.
//!
//! # The v1 problem text is this relay's own, not upstream's
//!
//! `relay/frame_types.zig` records that a v1 `Health` is a bare `problem: String`
//! (`relay.rs:115`) that upstream puts into a buffer that grows. **Upstream
//! publishes no captured bytes of the text it writes for a status, and this tree
//! has no iroh checkout to read one out of, so the three sentences below are
//! this relay's vocabulary and not a reproduction of upstream's.** They are
//! pinned by a test so they cannot drift, and a caller that needs a different
//! wording must write its own translation rather than edit a constant and hope.
//! That is also why the reverse direction refuses a `health` frame rather than
//! parsing one back into a `Status`: a v1 peer sends arbitrary prose, and a
//! module that recognised only its own three sentences would report a round trip
//! that holds against itself and against nothing else.
//!
//! # Nothing here touches a socket, a clock or an allocator
//!
//! Both directions are pure over values: a `Control` and a version in, a
//! `Message` out, and a message that survives `relay/frame.zig`'s real codec
//! gives back the `Control` it came from. The tests below run that through the
//! bytes a relay actually writes rather than asserting the translation against
//! itself.

const std = @import("std");
const frame = @import("frame.zig");
const relay_test_ids = @import("relay_test_ids.zig");
const server_queue = @import("server_queue.zig");

/// What a relay decided to tell one client, as the send queue holds it.
pub const Control = server_queue.Control;
/// The wire message one such statement becomes.
pub const Message = frame.Message;
/// The version the two ends negotiated.
pub const ProtocolVersion = frame.ProtocolVersion;
/// The frame type a message is written under.
pub const FrameType = frame.FrameType;

/// Every way a statement cannot be put in, or taken out of, a version.
pub const Error = error{
    /// A `Status` this build has no name for, on a version whose only spelling
    /// is text. See the file comment for why refusal beats a sentence.
    StatusNotExpressible,
    /// The message is not a statement this relay's control queue carries. A v1
    /// `health` frame is one: its payload is prose, and prose is not a `Status`.
    NotAControlStatement,
    /// The frame is not one the named version defines at all — a `status` on a v1
    /// connection or a `health` on a v2 one. `relay/frame.zig` already refuses
    /// this on the way in; naming it again is what keeps a hand-built `Message`
    /// from reaching a version it does not belong to.
    FrameNotAllowedInVersion,
};

/// The v1 `health` problem text this relay writes for a named `Status`.
///
/// **Null for `.unknown`, and the null is the point.** The arm exists so a relay
/// that grows a fourth condition does not break a v2 client that is only reading,
/// and on a v2 connection the byte goes out as itself. A v1 connection has no
/// byte for it, and inventing a sentence would be a claim about the relay's
/// state that nobody asked for.
pub fn healthText(status: frame.Status) ?[]const u8 {
    return switch (status) {
        .healthy => "the relay connection is healthy",
        .same_endpoint_id_connected => "another endpoint connected with the same node id",
        .rate_limited => "the relay is rate limiting this endpoint",
        .unknown => null,
    };
}

/// The message `control` becomes on a connection speaking `version`.
///
/// **`peer_gone` is `endpoint_gone` in both versions**, because the frame type is
/// the same number in both and carries the same node id. A `status` is `status`
/// on v2 and a `health` problem on v1, and a `Status` this build cannot name is
/// `error.StatusNotExpressible` on v1 rather than a message at all.
///
/// **The v1 text borrows a comptime literal**, so the returned `Message` is
/// independent of any buffer and a caller may keep it for as long as it likes.
/// The v2 arms are values the codec copied, so the whole return is a value.
pub fn toMessage(control: Control, version: ProtocolVersion) Error!Message {
    return switch (control) {
        .peer_gone => |node_id| .{ .endpoint_gone = node_id },
        .status => |status| switch (version) {
            .v2 => .{ .status = status },
            .v1 => .{ .health = healthText(status) orelse
                return error.StatusNotExpressible },
        },
    };
}

/// The statement `message` is, on a connection speaking `version`.
///
/// **Only two of the fourteen frame types are statements.** `endpoint_gone` is a
/// `peer_gone` in both versions and `status` is a `status` on v2; every other
/// arm — a denial, a datagram, a ping, a restarting notice, and a v1 `health`
/// problem — is `error.NotAControlStatement` or `error.FrameNotAllowedInVersion`,
/// and none of them is silently dropped into something else. The v1 `health`
/// refusal is the interesting one: it is the shape a v2 `Status` takes on a v1
/// connection, and it cannot come back because its payload is prose this relay
/// chose rather than a value it can recognise.
pub fn fromMessage(message: Message, version: ProtocolVersion) Error!Control {
    const frame_type: FrameType = std.meta.activeTag(message);
    if (!frame_type.allowedIn(version)) return error.FrameNotAllowedInVersion;
    return switch (message) {
        .endpoint_gone => |node_id| .{ .peer_gone = node_id },
        .status => |status| .{ .status = status },
        .health => error.NotAControlStatement,
        else => error.NotAControlStatement,
    };
}

// --- tests
const std_testing = std.testing;

/// One statement per version, through the bytes a relay actually writes.
fn roundTrip(control: Control, version: ProtocolVersion) !Control {
    var out: [256]u8 = undefined;
    const message = try toMessage(control, version);
    const bytes = try frame.encode(message, version, &out);
    const read = try frame.decode(bytes, version);
    return fromMessage(read, version);
}

test "round trip: every expressible statement survives the real codec" {
    // The whole claim of this module, run through `relay/frame.zig` rather than
    // through itself: `Control` to `Message`, the bytes a relay writes, the
    // bytes read back, and the statement again. `expectEqualDeep` and not
    // `expectEqual`, because the two hold slices — `Message.health` among them —
    // and comparing those by pointer would pass on two different buffers and
    // fail on two equal ones.
    const gone = try relay_test_ids.testNodeId(7);

    // `peer_gone` in both versions, because the frame type is the same number in
    // both and carries the same node id.
    for ([_]ProtocolVersion{ .v1, .v2 }) |version| {
        try std_testing.expectEqualDeep(
            Control{ .peer_gone = gone },
            try roundTrip(.{ .peer_gone = gone }, version),
        );
    }

    // Every named `Status` round trips on v2, where the wire form is the byte
    // itself. `unknown` is in the list on purpose: it is the arm v1 cannot
    // carry, and it is exactly as round-trippable as the other three on v2 as
    // long as the byte is one this build has no name for. `.{ .unknown = 0 }`
    // is deliberately absent, along with 1 and 2: `Status.fromBits` gives those
    // three back as the named arms, so a round trip that asserted them would be
    // asserting a distinction the wire does not carry.
    const statuses = [_]frame.Status{
        .healthy,
        .same_endpoint_id_connected,
        .rate_limited,
        .{ .unknown = 3 },
        .{ .unknown = 200 },
    };
    for (statuses) |status| {
        try std_testing.expectEqualDeep(
            Control{ .status = status },
            try roundTrip(.{ .status = status }, .v2),
        );
    }
    // And the two ends really are different, so the loop above is not one test
    // run twice: the v2 form is a type byte and a status byte, and the v1 form
    // is a type byte and this relay's sentence for the same event. Two buffers,
    // because the two results alias what they were written into.
    var v2_out: [8]u8 = undefined;
    var v1_out: [256]u8 = undefined;
    const v2_bytes = try frame.encode(
        try toMessage(.{ .status = .rate_limited }, .v2),
        .v2,
        &v2_out,
    );
    const v1_bytes = try frame.encode(
        try toMessage(.{ .status = .rate_limited }, .v1),
        .v1,
        &v1_out,
    );
    try std_testing.expectEqual(@as(usize, 2), v2_bytes.len);
    // A v1 `health` frame is the frame-type byte and the problem text and
    // nothing else: the type says how long the rest is, so there is no length
    // of its own to write.
    try std_testing.expectEqual(healthText(.rate_limited).?.len + 1, v1_bytes.len);
    try std_testing.expectEqual(
        @as(FrameType, .status),
        std.meta.activeTag(try frame.decode(v2_bytes, .v2)),
    );
    try std_testing.expectEqual(
        @as(FrameType, .health),
        std.meta.activeTag(try frame.decode(v1_bytes, .v1)),
    );
}

test "refusal: a status v1 cannot carry, and a health that is not a statement" {
    // The two directions a v1 status cannot make, and they are different
    // claims: the first is a decision this relay made that cannot be spelled, the
    // second is a message that arrived that was never a decision at all.
    const unnamed: frame.Status = .{ .unknown = 200 };
    try std_testing.expectEqual(@as(?[]const u8, null), healthText(unnamed));
    try std_testing.expectError(
        error.StatusNotExpressible,
        toMessage(.{ .status = unnamed }, .v1),
    );
    // The same statement on v2 is one byte, and the byte is the one the relay
    // sent rather than a stand-in for it.
    var unnamed_out: [2]u8 = undefined;
    const unnamed_bytes = try frame.encode(
        try toMessage(.{ .status = unnamed }, .v2),
        .v2,
        &unnamed_out,
    );
    try std_testing.expectEqualSlices(u8, &.{ 13, 200 }, unnamed_bytes);

    // A v1 health problem is prose this relay wrote, and prose is not a status.
    // The prefix holds — the statement became a message, the message became
    // bytes, and the bytes came back as that same message — and the last step is
    // the named refusal rather than a guess at which sentence this was.
    const control: Control = .{ .status = .rate_limited };
    const message = try toMessage(control, .v1);
    var out: [256]u8 = undefined;
    const bytes = try frame.encode(message, .v1, &out);
    const read = try frame.decode(bytes, .v1);
    try std_testing.expectEqualDeep(message, read);
    try std_testing.expectError(error.NotAControlStatement, fromMessage(read, .v1));

    // And a frame this version does not define is refused as such rather than
    // read as something else: `status` on v1 and `health` on v2 are each the
    // other version's spelling.
    try std_testing.expectError(
        error.FrameNotAllowedInVersion,
        fromMessage(.{ .status = .healthy }, .v1),
    );
    try std_testing.expectError(
        error.FrameNotAllowedInVersion,
        fromMessage(.{ .health = "the relay connection is healthy" }, .v2),
    );
}

test "refusal: the eleven frames that are not statements" {
    // Every remaining arm of `Message`, one case each, so that the two refusals
    // above are the whole of what a caller has to handle for a message that is
    // not a control statement. A denial, four datagram arms, an empty
    // confirmation, a challenge, an auth, a ping, a pong and a restarting notice
    // are all things a relay sends or reads that are none of them a `Control`.
    const node_id = try relay_test_ids.testNodeId(11);
    const datagrams: frame.Datagrams = .{ .ecn = .ce, .segment_size = null, .contents = "o" };
    const datagram: frame.DatagramFrame = .{ .node_id = node_id, .datagrams = datagrams };
    const batch_datagrams: frame.Datagrams = .{
        .ecn = .ce,
        .segment_size = 1,
        .contents = "o",
    };
    const batch: frame.DatagramFrame = .{
        .node_id = node_id,
        .datagrams = batch_datagrams,
    };
    const not_statements = [_]Message{
        .{ .server_challenge = .{ .challenge = @splat(0) } },
        .{
            .client_auth = .{
                .node_id = node_id,
                .signature = .{ .bytes = @splat(0) },
            },
        },
        .server_confirms_auth,
        .{ .server_denies_auth = .{ .reason = "no" } },
        .{ .client_to_relay_datagram = datagram },
        .{ .client_to_relay_datagram_batch = batch },
        .{ .relay_to_client_datagram = datagram },
        .{ .relay_to_client_datagram_batch = batch },
        .{ .ping = @splat(0) },
        .{ .pong = @splat(0) },
        .{ .restarting = .{ .reconnect_in_ms = 1, .try_for_ms = 2 } },
    };
    try std_testing.expectEqual(@as(usize, 11), not_statements.len);
    // Twelve arms of `Message` and one refusal each: the two statements are the
    // other two, so the count is the whole of the union's coverage stated here
    // rather than left to be inferred.
    try std_testing.expectEqual(@as(usize, 14), @typeInfo(Message).@"union".field_names.len);
    for (not_statements) |message| {
        for ([_]ProtocolVersion{ .v1, .v2 }) |version| {
            try std_testing.expectError(
                error.NotAControlStatement,
                fromMessage(message, version),
            );
        }
    }
}

test "the three v1 sentences, and the length bound they have to meet" {
    // The vocabulary this relay writes on a v1 connection is three sentences and
    // one refusal, and they are held to the bound `relay/frame.zig` enforces on
    // a v1 health problem — because a sentence that did not fit would be
    // `error.TextTooLong` at the codec, and a caller finding that there would be
    // learning it from the wrong module.
    const named = [_]struct { status: frame.Status, text: []const u8 }{
        .{ .status = .healthy, .text = "the relay connection is healthy" },
        .{
            .status = .same_endpoint_id_connected,
            .text = "another endpoint connected with the same node id",
        },
        .{ .status = .rate_limited, .text = "the relay is rate limiting this endpoint" },
    };
    for (named) |entry| {
        try std_testing.expectEqual(entry.text, healthText(entry.status).?);
        try std_testing.expect(entry.text.len <= frame.max_text_length);
        try std_testing.expect(std.unicode.utf8ValidateSlice(entry.text));
        // And the sentence is what actually reaches the wire, not a description
        // of it: `toMessage` hands the codec the same bytes.
        try std_testing.expectEqualDeep(
            Message{ .health = entry.text },
            try toMessage(.{ .status = entry.status }, .v1),
        );
    }
    // Three sentences and one null: `healthText` is a table, not a formatter, so
    // a fourth `Status` arm cannot reach it without this function changing.
    try std_testing.expectEqual(@as(usize, 3), named.len);
}
