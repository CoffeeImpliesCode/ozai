// Reach every supported module through refAllDecls, then explicitly include
// internal and test-only modules. A new exported module is covered by the
// declaration sweep; an internal module needs a reachable import.

test {
    const root = @import("lib.zig");
    @import("std").testing.refAllDecls(root);
    inline for (@typeInfo(root).@"struct".decls) |decl| {
        @import("std").testing.refAllDecls(@field(root, decl.name));
    }
    _ = @import("address.zig");
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
    _ = @import("quic/native_nat.zig");
    _ = @import("quic/native_nat_state.zig");
    _ = @import("quic/native_path_state.zig");
    _ = @import("quic/observed_address.zig");
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
