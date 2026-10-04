const std = @import("std");
const quic_error = @import("../transport/quic_error.zig");
const quic_config = @import("../transport/quic_config.zig");
const dial = @import("../transport/dial.zig");
const socket = @import("../transport/socket.zig");
const router = @import("../router/router.zig");
const relay_frame = @import("../relay/frame_types.zig");
const relay_server = @import("../relay/server_queue.zig");
const hyparview = @import("../gossip/hyparview.zig");
const plumtree = @import("../gossip/plumtree.zig");
const codec = @import("../gossip/codec.zig");

/// Seam failures and the node's own refusals, without widening any error set.
pub const Error =
    quic_error.Error ||
    quic_config.CreateError ||
    dial.Error ||
    socket.OpenError ||
    socket.SendError ||
    socket.ReceiveError ||
    router.AcceptError ||
    router.RegisterError ||
    relay_frame.Error ||
    relay_server.Queue(relay_server.Packet).PushError ||
    hyparview.Error ||
    plumtree.Error ||
    codec.Error ||
    std.mem.Allocator.Error ||
    error{
        InstantOutOfRange,
        DatagramTooLarge,
        NoRelay,
        TooManyProtocols,
        DuplicateProtocol,
        NoStandardProtocol,
        NoSuchProtocol,
        ProtocolRetired,
        TooManyRelayClients,
        RelayQueueDepthZero,
    };