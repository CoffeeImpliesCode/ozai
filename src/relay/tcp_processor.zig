//! Deterministic carrier transitions. Actions borrow decoded frame data until the next decode.
const std = @import("std");
const frame = @import("frame.zig");
const key = @import("../base/key.zig");
const authentication = @import("client.zig");

pub const Error = error{ Closed, InvalidUpgrade, UnexpectedMessage, SignatureInvalid };
pub const ClientState = enum { connecting, request, upgrade, challenge, confirm, ready, closed };
pub const ServerState = enum { upgrade, response, auth, confirming, ready };
pub const ClientEvent = union(enum) {
    connected,
    request,
    upgrade: bool,
    message: frame.Message,
};
pub const ServerEvent = union(enum) {
    upgrade: bool,
    drained,
    message: frame.Message,
};
pub const Action = union(enum) {
    request,
    response,
    relay: frame.Message,
    register: key.NodeId,
    deliver: frame.DatagramFrame,
    forward: frame.DatagramFrame,
};
pub const ClientResult = struct {
    state: ClientState,
    actions: [2]Action = undefined,
    count: u8 = 0,
};
pub const ServerResult = struct {
    state: ServerState,
    actions: [2]Action = undefined,
    count: u8 = 0,
};

/// The adapter supplies entropy and HTTP validation as data and executes actions in order.
pub fn client(
    state: ClientState,
    event: ClientEvent,
    secret: *const key.SecretKey,
) Error!ClientResult {
    if (state == .closed) return error.Closed;
    var result: ClientResult = .{ .state = state };
    switch (event) {
        .connected => {
            if (state != .connecting) return error.UnexpectedMessage;
            result.state = .request;
        },
        .request => {
            if (state != .request) return error.UnexpectedMessage;
            result.state = .upgrade;
            result.actions[0] = .request;
            result.count = 1;
        },
        .upgrade => |accepted| {
            if (state != .upgrade) return error.UnexpectedMessage;
            if (!accepted) return error.InvalidUpgrade;
            result.state = .challenge;
        },
        .message => |message| switch (state) {
            .challenge => switch (message) {
                .server_challenge => |challenge| {
                    result.actions[0] = .{ .relay = .{
                        .client_auth = authentication.signChallenge(secret, challenge),
                    } };
                    result.count = 1;
                    result.state = .confirm;
                },
                else => return error.UnexpectedMessage,
            },
            .confirm => switch (message) {
                .server_confirms_auth => result.state = .ready,
                else => return error.UnexpectedMessage,
            },
            .ready => switch (message) {
                .relay_to_client_datagram, .relay_to_client_datagram_batch => |datagram| {
                    result.actions[0] = .{ .deliver = datagram };
                    result.count = 1;
                },
                .ping => |ping| {
                    result.actions[0] = .{ .relay = .{ .pong = ping } };
                    result.count = 1;
                },
                .pong, .endpoint_gone, .restarting => {},
                .status => |status| switch (status) {
                    .same_endpoint_id_connected => return error.Closed,
                    else => {},
                },
                else => return error.UnexpectedMessage,
            },
            else => return error.UnexpectedMessage,
        },
    }
    return result;
}

/// Challenge bytes are explicit input, never generated or retained by this processor.
pub fn server(
    state: ServerState,
    event: ServerEvent,
    challenge: frame.ServerChallenge,
) Error!ServerResult {
    var result: ServerResult = .{ .state = state };
    switch (event) {
        .upgrade => |accepted| {
            if (state != .upgrade) return error.UnexpectedMessage;
            if (!accepted) return error.InvalidUpgrade;
            result.state = .response;
            result.actions[0] = .response;
            result.count = 1;
        },
        .drained => switch (state) {
            .response => {
                result.actions[0] = .{ .relay = .{ .server_challenge = challenge } };
                result.count = 1;
                result.state = .auth;
            },
            .confirming => result.state = .ready,
            else => {},
        },
        .message => |message| switch (state) {
            .auth => switch (message) {
                .client_auth => |auth| {
                    try authentication.verifyClientAuth(auth, challenge);
                    result.actions[0] = .{ .register = auth.node_id };
                    result.actions[1] = .{ .relay = .{ .server_confirms_auth = {} } };
                    result.count = 2;
                    result.state = .confirming;
                },
                else => return error.UnexpectedMessage,
            },
            .ready => switch (message) {
                .client_to_relay_datagram, .client_to_relay_datagram_batch => |datagram| {
                    result.actions[0] = .{ .forward = datagram };
                    result.count = 1;
                },
                .ping => |ping| {
                    result.actions[0] = .{ .relay = .{ .pong = ping } };
                    result.count = 1;
                },
                .pong => {},
                else => return error.UnexpectedMessage,
            },
            else => return error.UnexpectedMessage,
        },
    }
    return result;
}

test "decoded handshake replay authenticates only after confirmation drains" {
    var secret = try key.SecretKey.fromSeed(.{19} ** 32);
    defer secret.deinit();
    const challenge: frame.ServerChallenge = .{ .challenge = .{23} ** 16 };
    const connected = try client(.connecting, .connected, &secret);
    const requested = try client(connected.state, .request, &secret);
    try std.testing.expectEqual(ClientState.upgrade, requested.state);
    const upgraded = try client(requested.state, .{ .upgrade = true }, &secret);
    const response = try server(.upgrade, .{ .upgrade = true }, challenge);
    const challenged = try server(response.state, .drained, challenge);
    try std.testing.expectEqual(ServerState.auth, challenged.state);
    const signed = try client(upgraded.state, .{
        .message = challenged.actions[0].relay,
    }, &secret);
    try std.testing.expectEqual(ClientState.confirm, signed.state);
    const verified = try server(
        challenged.state,
        .{ .message = signed.actions[0].relay },
        challenge,
    );
    try std.testing.expectEqual(ServerState.confirming, verified.state);
    try std.testing.expectEqual(secret.nodeId(), verified.actions[0].register);
    const ready = try server(verified.state, .drained, challenge);
    try std.testing.expectEqual(ServerState.ready, ready.state);
    const confirmed = try client(signed.state, .{ .message = verified.actions[1].relay }, &secret);
    try std.testing.expectEqual(ClientState.ready, confirmed.state);
}

test "decoded refusal and out of order authentication cannot reach ready" {
    var secret = try key.SecretKey.fromSeed(.{29} ** 32);
    defer secret.deinit();
    const challenge: frame.ServerChallenge = .{ .challenge = .{31} ** 16 };
    try std.testing.expectError(
        error.InvalidUpgrade,
        client(.upgrade, .{ .upgrade = false }, &secret),
    );
    try std.testing.expectError(
        error.InvalidUpgrade,
        server(.upgrade, .{ .upgrade = false }, challenge),
    );
    try std.testing.expectError(error.UnexpectedMessage, client(.challenge, .{
        .message = .{ .server_confirms_auth = {} },
    }, &secret));
    try std.testing.expectError(error.UnexpectedMessage, server(.confirming, .{
        .message = .{ .ping = .{0} ** 8 },
    }, challenge));
    const auth = authentication.signChallenge(&secret, challenge);
    try std.testing.expectError(error.SignatureInvalid, server(.auth, .{
        .message = .{ .client_auth = auth },
    }, .{ .challenge = .{32} ** 16 }));
}

test "ready processors return borrowed datagrams and ordered pong actions" {
    var secret = try key.SecretKey.fromSeed(.{59} ** 32);
    defer secret.deinit();
    const datagram: frame.DatagramFrame = .{
        .node_id = secret.nodeId(),
        .datagrams = .{ .ecn = null, .segment_size = null, .contents = "borrowed" },
    };
    const delivered = try client(.ready, .{
        .message = .{ .relay_to_client_datagram = datagram },
    }, &secret);
    try std.testing.expectEqual(@as(u8, 1), delivered.count);
    try std.testing.expectEqual(
        datagram.datagrams.contents.ptr,
        delivered.actions[0].deliver.datagrams.contents.ptr,
    );
    const forwarded = try server(.ready, .{
        .message = .{ .client_to_relay_datagram = datagram },
    }, .{ .challenge = .{0} ** 16 });
    try std.testing.expectEqual(@as(u8, 1), forwarded.count);
    try std.testing.expectEqual(
        datagram.datagrams.contents.ptr,
        forwarded.actions[0].forward.datagrams.contents.ptr,
    );
    const ping = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    const pong = try client(.ready, .{ .message = .{ .ping = ping } }, &secret);
    try std.testing.expectEqualSlices(u8, &ping, &pong.actions[0].relay.pong);
    try std.testing.expectError(error.Closed, client(.closed, .connected, &secret));
}
