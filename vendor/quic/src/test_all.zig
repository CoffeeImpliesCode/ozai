// The test root for the vendored core.
//
// Upstream built its tests from a file like this one, and this file was not
// vendored — it imported three of the deleted socket-layer files, so it could
// not come across as-is. Rebuilding it is not optional: Zig analyses a test
// block only if the compilation reaches it, and `lib.zig` is nothing but
// re-exports. Under lazy analysis a re-exported file's tests are never looked
// at, so a root that only re-exports discovers ZERO tests and exits 0. That is
// a green step proving nothing, and it is the failure mode this file exists to
// prevent.
//
// Every vendored file that carries test blocks is named here explicitly. A new
// file with tests is not run until it is added below, which is deliberate: a
// test that nobody references is not a test.

test {
    _ = @import("quic/ack_handler.zig");
    _ = @import("quic/aes_gcm.zig");
    _ = @import("quic/congestion.zig");
    _ = @import("quic/connection.zig");
    _ = @import("quic/connection_manager.zig");
    _ = @import("quic/crypto.zig");
    _ = @import("quic/crypto_stream.zig");
    _ = @import("quic/ecdsa_p256.zig");
    _ = @import("quic/ecn.zig");
    _ = @import("quic/flow_control.zig");
    _ = @import("quic/frame.zig");
    _ = @import("quic/lossy_link_test.zig");
    _ = @import("quic/mont.zig");
    _ = @import("quic/mtu.zig");
    _ = @import("quic/packet.zig");
    _ = @import("quic/packet_packer.zig");
    _ = @import("quic/protocol.zig");
    _ = @import("quic/quic_lb.zig");
    _ = @import("quic/ranges.zig");
    _ = @import("quic/rsa.zig");
    _ = @import("quic/rtt.zig");
    _ = @import("quic/stateless_reset.zig");
    _ = @import("quic/stream.zig");
    _ = @import("quic/tls13.zig");
    _ = @import("quic/transport_params.zig");
    _ = @import("quic/util.zig");
}
