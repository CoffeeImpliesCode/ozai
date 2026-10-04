//! Native package tests, including the node's real-socket consumers.
//! This root is not imported by production modules or the socket-free test root.

const std = @import("std");
const library = @import("root.zig");
const node_tests = @import("node/node_tests.zig");
const node_retirement_tests = @import("node/node_retirement_tests.zig");
const node_relay_serve_tests = @import("node/node_relay_serve_tests.zig");
const gossip_codec_tests = @import("gossip/codec_tests.zig");

test {
    std.testing.refAllDecls(library);
    std.testing.refAllDecls(node_tests);
    std.testing.refAllDecls(node_retirement_tests);
    std.testing.refAllDecls(node_relay_serve_tests);
    std.testing.refAllDecls(gossip_codec_tests);
}
