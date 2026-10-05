//! The protocol version one relay connection speaks, bound to that connection.
//!
//! # Where the negotiated version lives
//!
//! **In a `Binding` the caller stores beside the connection, and nowhere else.**
//! Not in a parameter, because a parameter is a value the caller can hold two
//! of and pass the wrong one: `frame.encode` takes a `ProtocolVersion` today,
//! and every call site in this tree spells it `.v2` (`node_relay_frame.zig:77`,
//! `node_relay_client.zig:134`, `node_relay_forward.zig:72`). That is a
//! global answer written three times, and it is the answer this file exists to
//! make impossible: `Binding.encode` and `Binding.decode` take the version
//! from the binding, so a call site *cannot* name one. The only way a version
//! enters a connection is `bind`.
//!
//! `negotiate` is the same rule both ends run, which is what makes one function
//! right for each of them. The client sends `client_offer` and reads the relay's
//! answer; the relay reads the client's field and writes its own. All three
//! fields are lists of tokens, and `frame_types.negotiate` takes the largest
//! version any token names — so the relay's answer, being one token, settles on
//! the same version the relay computed from the request.
//!
//! # One connection negotiates once
//!
//! `bind` refuses a second call as `error.AlreadyBound`, and `frame_types.zig`
//! says why a frame cannot be legal in one version and not the other: `Health`
//! is v1 and `Status` is v2. A connection that re-negotiated mid-stream could
//! have admitted a frame it had already promised the peer it would refuse, so
//! the latch is a protocol rule rather than an optimisation. It is one field
//! rather than a flag pair, and the refusal leaves the first version in place.
//!
//! # A connection that has not settled cannot speak
//!
//! `version`, `decode` and `encode` all answer `error.NotBound` until `bind`
//! has run, and every one of them takes `*const Binding`. A relay that holds
//! the binding in the same struct as the connection's queues therefore cannot
//! read a frame from a connection whose upgrade never finished — the failure
//! is a named error at the call site rather than a default version standing in
//! for an answer nobody gave.
//!
//! Nothing here reads a clock, a socket, the environment or a global. The
//! binding is two words wide, copying it is free, and the same `Binding` may be
//! read from any thread as long as nothing is binding it underneath the call.

const std = @import("std");
const frame = @import("frame.zig");

const std_testing = std.testing;

/// The version a connection speaks. See `frame.ProtocolVersion`.
pub const ProtocolVersion = frame.ProtocolVersion;

/// The frame type a connection may be asked about.
pub const FrameType = frame.FrameType;

/// A decoded frame. See `frame.Message`.
pub const Message = frame.Message;

/// Every way settling a connection can be refused, and the one way reading
/// from it before it has settled is refused.
///
/// **The first two are the relay's answer and the last is the client's.** A
/// field naming no version this build speaks is upstream's
/// `UnsupportedRelayVersion` (`http_server.rs:612`) and the relay closes rather
/// than choosing, because the version it picked would be one the client never
/// offered.
pub const BindError = error{
    /// The field named no version both ends speak. The connection is closed;
    /// choosing is the one answer that cannot be right.
    NoCommonVersion,
    /// This connection already settled on a version. The first one stands.
    AlreadyBound,
    /// A frame was read from, or written to, a connection that has not
    /// settled. There is no version to use and no default that would be honest.
    NotBound,
};

/// What `bind` can refuse and what the codec can refuse.
pub const Error = frame.Error || BindError;

/// The `Sec-WebSocket-Protocol` field a client sends, newest first.
///
/// Upstream advertises newest first too (`http.rs:68`), and the order is what
/// makes `negotiate`'s `max()` load-bearing rather than a refinement: iroh's
/// client sends this exact order, so a first-match server would pin every
/// connection to v1 and keep `Health` alive forever.
///
/// **A comptime concatenation of two comptime literals**, so it has static
/// lifetime, is never built at run time, and cannot fall out of step with
/// `ProtocolVersion.name`. The comma and space are the separators upstream's
/// field parser splits on (`http_server.rs:612`).
pub const client_offer: []const u8 =
    ProtocolVersion.name(.v2) ++ ", " ++ ProtocolVersion.name(.v1);

/// One connection's negotiated version.
///
/// **The field is public and `bind` is the only guarded way to set it**, which
/// is the same arrangement `relay/client.zig`'s `PingTracker` states for its own
/// fields: Zig has no private field, so a literal with `.settled` set bypasses
/// the latch. Nothing turns on that here — a version is a checked enum value,
/// not an invariant a bad write would corrupt — but a caller that builds one by
/// hand has said the connection settled and must know why it did.
pub const Binding = struct {
    /// The version, or null until `bind` has run. One connection, one field.
    settled: ?ProtocolVersion,

    /// Settle on the version `header_value` names.
    ///
    /// `header_value` is a whole header field: a comma-separated list of
    /// tokens, each possibly surrounded by whitespace, with tokens this build
    /// does not speak dropped rather than refused (`frame_types.negotiate`).
    ///
    /// **Both ends call this and neither passes a version it chose.** The relay
    /// calls it with the client's request field and gets the version it must
    /// answer with; the client calls it with the relay's response field and gets
    /// the version it must speak. A caller that wants to know whether the
    /// relay agreed with what was offered reads the version back and compares it
    /// against its own list — and the test below does exactly that, because a
    /// relay answering `iroh-relay-v1` when the client offered only v2 would
    /// otherwise settle silently.
    pub fn bind(self: *Binding, header_value: []const u8) BindError!void {
        if (self.settled != null) return error.AlreadyBound;
        self.settled = frame.negotiate(header_value) orelse
            return error.NoCommonVersion;
    }

    /// The version this connection speaks, or `error.NotBound`.
    pub fn version(self: *const Binding) BindError!ProtocolVersion {
        return self.settled orelse error.NotBound;
    }
    /// Whether this connection may carry `frame_type`.
    ///
    /// `FrameType.allowedIn` is the rule; this is the binding's half of it, so a
    /// caller holding the connection asks the connection. A connection that has
    /// not settled carries nothing, which is the same answer `decode` gives.
    pub fn allows(self: *const Binding, frame_type: FrameType) BindError!bool {
        return frame_type.allowedIn(try self.version());
    }

    /// The bytes are exactly what `node_relay_frame.peekFrame` delimited: one
    /// WebSocket message's worth, and nothing of the next. `frame.decode` copies
    /// everything that has a fixed width, so the returned `Message` borrows only
    /// the datagram contents, a denial's reason and a health problem — and the
    /// same rule `frame.zig` states applies unchanged.
    pub fn decode(self: *const Binding, bytes: []const u8) Error!Message {
        return frame.decode(bytes, try self.version());
    }

    /// Write one frame in the version this connection negotiated.
    ///
    /// **Refused before a byte is written** on both counts the codec names: a
    /// frame the version does not allow, and a frame that does not fit. A
    /// caller that gets an error must discard `out`.
    pub fn encode(self: *const Binding, message: Message, out: []u8) Error![]const u8 {
        return frame.encode(message, try self.version(), out);
    }
};

// --- tests

// The version both ends settle on from the client's own offer, which is the
// only field a client sends.
test "the client offers newest first and the relay settles on v2" {
    try std_testing.expectEqual(
        @as(?ProtocolVersion, .v2),
        frame.negotiate(client_offer),
    );

    // What the relay writes back is one token naming the version it chose, and
    // the client's own binding computes the same answer from it: one
    // computation, two ends.
    var answered: Binding = .{ .settled = null };
    try answered.bind(client_offer);
    try std_testing.expectEqual(ProtocolVersion.v2, try answered.version());

    // The relay answers with the one token naming what it chose, and the client
    // reading that token back computes the same version: one `negotiate`, two
    // ends. A relay that answered a version it was never offered could not
    // settle a client at all.
    var relay: Binding = .{ .settled = null };
    try relay.bind(client_offer);
    var client: Binding = .{ .settled = null };
    try client.bind(ProtocolVersion.name(try relay.version()));
    try std_testing.expectEqual(try relay.version(), try client.version());
    try std_testing.expectEqual(try relay.version(), try answered.version());
}

// A connection that has not settled cannot read, write or name a version.
test "an unsettled connection refuses rather than defaulting to a version" {
    const pending: Binding = .{ .settled = null };
    try std_testing.expectError(error.NotBound, pending.version());

    var out: [128]u8 = undefined;
    try std_testing.expectError(error.NotBound, pending.encode(.server_confirms_auth, &out));
    try std_testing.expectError(
        error.NotBound,
        pending.decode(&[_]u8{@intFromEnum(frame.FrameType.server_confirms_auth)}),
    );
    try std_testing.expectError(error.NotBound, pending.allows(.ping));
}

// The same bytes, two connections, two answers: the version is the
// connection's and not this build's.
test "a frame the connection's version forbids is refused, on the same bytes" {
    const problem = "the relay is shedding load";
    var out: [128]u8 = undefined;
    // `health` is v1 only, so writing it needs a v1 connection to begin with.
    const v1: Binding = .{ .settled = .v1 };
    const bytes = try v1.encode(.{ .health = problem }, &out);

    const read_on_v1 = try v1.decode(bytes);
    try std_testing.expectEqualStrings(problem, read_on_v1.health);
    try std_testing.expect((try v1.allows(.health)));

    // And a v2 connection holding the same connection's role on the same
    // bytes refuses it, which is the whole of "carried on the connection".
    const v2: Binding = .{ .settled = .v2 };
    try std_testing.expectError(error.FrameNotAllowedInVersion, v2.decode(bytes));
    try std_testing.expect(!(try v2.allows(.health)));
    try std_testing.expect((try v2.allows(.status)));

    // The other direction is the same refusal, on the way out.
    try std_testing.expectError(
        error.FrameNotAllowedInVersion,
        v2.encode(.{ .health = problem }, &out),
    );
}

// A connection settles once, and the second attempt changes nothing.
test "one connection negotiates once" {
    var binding: Binding = .{ .settled = null };
    try binding.bind(ProtocolVersion.name(.v1));
    try std_testing.expectEqual(ProtocolVersion.v1, try binding.version());

    try std_testing.expectError(
        error.AlreadyBound,
        binding.bind(ProtocolVersion.name(.v2)),
    );
    // The first answer stands: a connection that re-negotiated could accept a
    // frame it had already promised to refuse.
    try std_testing.expectEqual(ProtocolVersion.v1, try binding.version());
}

// A field naming nothing usable is a refusal, not a choice.
test "a header naming no usable version closes rather than choosing" {
    for ([_][]const u8{ "", "iroh-relay", "iroh-relay-v3", ",,," }) |field| {
        var binding: Binding = .{ .settled = null };
        try std_testing.expectError(error.NoCommonVersion, binding.bind(field));
        // Nothing was half-settled: the connection is unbound, not bound to
        // nothing.
        try std_testing.expectError(error.NotBound, binding.version());
    }
}
