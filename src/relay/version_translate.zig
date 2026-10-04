//! One relay-side statement about a connection, and the frame each protocol
//! version spells it as.
//!
//! A relay learns the same thing twice over its life: something is wrong with
//! a connection, and then it is not. Upstream writes that down twice too —
//! `Health { problem: String }` before iroh 0.98.0 and `Status` after
//! (`relay.rs:115`, `relay.rs:122`), and `relay.rs:441` and `relay.rs:468`
//! reject each frame in the version that replaced it. **This module is the one
//! place that decides which of the two a connection hears**, so a relay decides
//! what is true once and the version decides how to say it.
//!
//! # The two encodings are not the same width
//!
//! v1's `Health` is free text the relay chooses; v2's `Status` is one byte with
//! four named conditions. So the translation is one-directional for anything
//! that is a sentence, and saying so is the whole reason this is a function
//! that can fail rather than a `switch` with a default:
//!
//! - **Healthy** is in both. v1 has no "no problem" frame, so it is a `Health`
//!   with an empty `problem`, which upstream's `Health { problem: String }`
//!   spells as exactly that — an empty string, not a missing one.
//! - **A problem in words** is v1 only. A v2 peer has no frame to read a
//!   sentence into, and inventing one would put bytes on the wire the far end
//!   has agreed not to understand.
//! - **The two conditions `Status` added** are v2 only, and v1 has no way to
//!   be told either — a v1 peer learns that its connection is going away when
//!   it closes. Each becomes a fixed sentence, because a v1 `Health` reason is
//!   relay-chosen text and this module is the relay.
//!
//! Every fixed sentence is a comptime constant of this module rather than a
//! caller's, so the text a v1 peer sees is a fact about this file and not a
//! string a caller can change per connection.
//!
//! Nothing here reads a clock, allocates, or borrows past the call: `Control`
//! is a value, `Message` is `relay/frame.zig`'s own type, and the only borrow
//! is the `problem` slice, which is the caller's and is refused in every
//! version but v1.

const std = @import("std");
const frame = @import("frame_types.zig");
const codec = @import("frame_codec.zig");
const writer = @import("frame_writer.zig");

const Message = frame.Message;
const ProtocolVersion = frame.ProtocolVersion;
const std_testing = std.testing;

/// What a relay has to say about a connection, before the version has had its
/// say about how.
///
/// The two v2-only arms and the v1-only `problem` are the interesting shape of
/// this union: every one of them exists because the other version cannot carry
/// it, and each is a named refusal in the version that has no room.
pub const Control = union(enum) {
    /// Nothing is wrong, and anything that was has cleared. v1 has no frame for
    /// "no problem", so this is a `Health` with an empty `problem`; v2 has a
    /// byte for it and this is that byte.
    healthy,
    /// Another endpoint connected with the same node id, and nothing more will
    /// arrive on this connection.
    same_endpoint_id_connected,
    /// The relay is rate-limiting what this endpoint sends.
    rate_limited,
    /// UTF-8 problem text, and the only arm with a borrow in it. **v1 only**:
    /// v2's `Status` is one byte wide and has no arm a sentence can be read
    /// into.
    problem: []const u8,
};

/// Why a statement cannot be put on the wire a connection negotiated.
///
/// One arm, not three: RFC 6455 says nothing here, and the fact worth naming is
/// the single one — this connection negotiated a version in which the statement
/// has no representation. A caller cannot act differently per missing
/// representation, and a caller that wants to know *which* statement it was
/// already has the `Control` it passed in.
pub const Error = error{
    /// This statement has no frame in `version`. See the module comment for the
    /// three cases and why none of them gets a substitute frame.
    NotExpressibleInVersion,
};

/// The v1 text for a condition v2 spells with a byte.
///
/// A v1 `Health` reason is relay-chosen prose (`relay.rs:115`), so these are
/// this module's sentences and not a caller's — and they are bounded by
/// `frame.max_text_length`, because `codec.encode` refuses anything longer and a
/// relay that could not say why would fail at the moment it most needed to.
pub const v1_same_endpoint_id_connected = "another endpoint connected with this node id";
pub const v1_rate_limited = "this relay is rate limiting this endpoint";

/// The frame `control` is on `version`'s wire.
///
/// **Every arm of both `switch`es is named and neither has an `else`.** `Control`
/// and `ProtocolVersion` are both closed domains, and a default arm here would
/// answer a question nobody asked — what a new condition, or a third version,
/// means — by putting some other frame on the wire.
pub fn toMessage(control: Control, version: ProtocolVersion) Error!Message {
    return switch (version) {
        // v2's `Status` (`relay.rs:122`). Healthy is 0, so the empty problem
        // v1 needs becomes the byte v2 already had.
        .v2 => switch (control) {
            .healthy => .{ .status = .healthy },
            .same_endpoint_id_connected => .{ .status = .same_endpoint_id_connected },
            .rate_limited => .{ .status = .rate_limited },
            // The one refusal this direction has, and it is a refusal rather
            // than a default byte because `Status` has no arm for prose: a
            // byte picked here would name a condition the relay did not report.
            .problem => error.NotExpressibleInVersion,
        },
        // v1's `Health { problem: String }` (`relay.rs:115`): a frame type and
        // then text to the end of the message.
        .v1 => switch (control) {
            // An empty `problem`, which is how upstream spells "nothing is
            // wrong" on a version with no frame for it.
            .healthy => .{ .health = "" },
            // The two conditions v2 added have no v1 frame, so each becomes the
            // fixed sentence this module chose for it.
            .same_endpoint_id_connected => .{ .health = v1_same_endpoint_id_connected },
            .rate_limited => .{ .health = v1_rate_limited },
            .problem => |text| .{ .health = text },
        },
    };
}

/// The statement `message` says, or null when it says nothing a relay decides.
///
/// **The tag is the version, so this takes no `ProtocolVersion`:** `Health`
/// exists only in v1 and `Status` only in v2, and `relay/frame.zig`'s `decode`
/// has already refused the other pairing outright. A `Status` byte this build
/// has no name for is null rather than a guess, for the reason
/// `frame.Status.unknown` exists — a relay that grows a fourth condition is not
/// something a reader may invent a meaning for.
pub fn fromMessage(message: Message) ?Control {
    return switch (message) {
        .status => |status| switch (status) {
            .healthy => .healthy,
            .same_endpoint_id_connected => .same_endpoint_id_connected,
            .rate_limited => .rate_limited,
            .unknown => null,
        },
        .health => |problem| if (problem.len == 0) .healthy else .{ .problem = problem },
        // Every other frame type is not something this module decides, and the
        // switch says so by name rather than by a default.
        .server_challenge,
        .client_auth,
        .server_confirms_auth,
        .server_denies_auth,
        .client_to_relay_datagram,
        .client_to_relay_datagram_batch,
        .relay_to_client_datagram,
        .relay_to_client_datagram_batch,
        .endpoint_gone,
        .ping,
        .pong,
        .restarting,
        => null,
    };
}

/// The most bytes `toMessage` can produce in either direction.
///
/// `frame_writer.encodedLen` is the exact answer for any `Message`, so it is
/// the answer for a caller that has no value yet and has to size a buffer before
/// it builds one. It is the sum of the largest of each arm rather than a number
/// measured once, because a bound written down beside the code it bounds is a
/// bound that goes stale when the code changes.
pub const max_message_length = 1 + frame.max_text_length;

// ---------------------------------------------------------------------------
// Tests. The round trip is `Control -> Message -> bytes -> Message -> Control`,
// which is the only shape that proves both halves agree about the version they
// are speaking.
// ---------------------------------------------------------------------------

test "translation: every statement reaches its own version" {
    var out: [max_message_length]u8 = undefined;

    // v2 has a byte for the three conditions it names and no arm for prose.
    try expectTag(.status, try toMessage(.healthy, .v2));
    try expectTag(.status, try toMessage(.same_endpoint_id_connected, .v2));
    try expectTag(.status, try toMessage(.rate_limited, .v2));
    try std_testing.expectError(
        error.NotExpressibleInVersion,
        toMessage(.{ .problem = "the relay is full" }, .v2),
    );

    // v1 has text and nothing else, so the two conditions v2 added arrive as
    // this module's fixed sentences.
    try expectTag(.health, try toMessage(.healthy, .v1));
    try expectTag(.health, try toMessage(.same_endpoint_id_connected, .v1));
    try expectTag(.health, try toMessage(.rate_limited, .v1));
    try expectTag(.health, try toMessage(.{ .problem = "the relay is full" }, .v1));

    // And each is a frame the version may actually carry: the refusal below is
    // about prose, not about a frame `relay/frame.zig` would refuse to write.
    const spoken = try toMessage(.same_endpoint_id_connected, .v1);
    try std_testing.expectEqual(
        writer.encodedLen(spoken),
        (try codec.encode(spoken, .v1, &out)).len,
    );
    const status = try toMessage(.rate_limited, .v2);
    try std_testing.expectEqual(
        writer.encodedLen(status),
        (try codec.encode(status, .v2, &out)).len,
    );
}

test "translation: healthy is an empty problem on v1 and a zero byte on v2" {
    // The two encodings of one fact, and the reason the round trip is a fixed
    // point in both directions: what v2 writes as 0x00, v1 writes as no text.
    const problem: Message = .{ .health = "" };
    const status: Message = .{ .status = .healthy };
    var out_v1: [8]u8 = undefined;
    var out_v2: [8]u8 = undefined;
    try expectHex(&.{0x0b}, try codec.encode(problem, .v1, &out_v1));
    try expectHex(&.{ 0x0d, 0x00 }, try codec.encode(status, .v2, &out_v2));
    // `fromMessage` reads the empty problem back as healthy and not as an empty
    // `problem`, which is what makes the two the same statement.
    try std_testing.expectEqual(Control.healthy, fromMessage(problem).?);
    try std_testing.expectEqual(Control.healthy, fromMessage(status).?);
}

test "round trip: Control to Message to bytes to Message to Control" {
    // The shape this module exists for. Both versions, every arm each version
    // can carry, through `relay/frame.zig`'s own codec rather than around it —
    // so a statement that survives here survives the bytes a relay writes.
    var out: [max_message_length]u8 = undefined;
    const cases = [_]struct { control: Control, version: ProtocolVersion }{
        .{ .control = .healthy, .version = .v1 },
        .{ .control = .healthy, .version = .v2 },
        .{ .control = .same_endpoint_id_connected, .version = .v1 },
        .{ .control = .same_endpoint_id_connected, .version = .v2 },
        .{ .control = .rate_limited, .version = .v1 },
        .{ .control = .rate_limited, .version = .v2 },
        .{ .control = .{ .problem = "the relay is full" }, .version = .v1 },
    };
    for (cases) |case| {
        const message = try toMessage(case.control, case.version);
        const bytes = try codec.encode(message, case.version, &out);
        const read = try codec.decode(bytes, case.version);
        try std_testing.expect(codec.eql(message, read));
        // The read frame is the same statement the relay decided, and not merely
        // the same bytes.
        try std_testing.expectEqualDeep(case.control, fromMessage(read).?);
    }
}

test "the refusal is one arm, and the only arm that cannot be written" {
    // `Error` has one member and this walks it, checked against the type rather
    // than trusted, so a second arm added without a case here fails the build.
    const arms = [_]Error{error.NotExpressibleInVersion};
    try std_testing.expectEqual(@typeInfo(Error).error_set.?.len, arms.len);

    // Exactly one `(control, version)` pair is refused, and it is the same pair
    // for every problem text: prose on v2.
    for ([_][]const u8{ "", "x", v1_rate_limited }) |text| {
        try std_testing.expectError(
            error.NotExpressibleInVersion,
            toMessage(.{ .problem = text }, .v2),
        );
    }
}

test "fromMessage: only the two frames this module writes come back" {
    // A `Status` byte with no name is null rather than a guess, and every frame
    // that is not a statement this module makes is null too — including the two
    // that carry borrowed text, so a caller cannot read a denial reason as a
    // connection problem.
    try std_testing.expectEqual(
        @as(?Control, null),
        fromMessage(.{ .status = .{ .unknown = 7 } }),
    );
    try std_testing.expectEqual(
        @as(?Control, null),
        fromMessage(.{ .server_denies_auth = .{ .reason = "no" } }),
    );
    try std_testing.expectEqual(@as(?Control, null), fromMessage(.server_confirms_auth));
    try std_testing.expectEqual(
        @as(?Control, null),
        fromMessage(.{ .ping = [_]u8{42} ** 8 }),
    );
    // Every value of `FrameType` is one of the arms above or the two this
    // module reads, so a frame type added later has to say which it is.
    comptime std.debug.assert(@typeInfo(Message).@"union".fields.len == 14);
}

fn expectTag(tag: frame.FrameType, message: Message) !void {
    try std_testing.expectEqual(tag, std.meta.activeTag(message));
}

fn expectHex(expected: []const u8, actual: []const u8) !void {
    if (std.mem.eql(u8, expected, actual)) return;
    return error.WireFormatMismatch;
}
