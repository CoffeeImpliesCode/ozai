//! ozai — dial a node by its id, not its address.
//!
//! Import the registered `ozai` module for values, codecs, state machines,
//! discovery and endpoint drivers. Import the registered `quic` module
//! separately when naming the vendored core's types.
//!
//! Pure logic uses caller-supplied bytes, state, time and entropy. The Linux
//! socket and node drivers require libc and take `std.Io` per operation.
//! Allocating results name their release operation at the owning declaration.
//! Address lists and runtime handles are shallow copies, not independent owners.

const std = @import("std");

pub const base32 = @import("base/base32.zig");
pub const key = @import("base/key.zig");
pub const addr = @import("base/addr.zig");
pub const ula = @import("base/ula.zig");
pub const postcard = @import("wire/postcard.zig");
pub const net_report = @import("net/report.zig");
pub const holepunch = @import("net/holepunch.zig");
pub const net_probe = @import("net/probe.zig");
pub const net_probe_run = @import("net/probe_run.zig");
pub const net_holepunch_run = @import("net/holepunch_run.zig");

pub const discovery_item = @import("discovery/item.zig");
pub const discovery_resolve = @import("discovery/resolve.zig");
pub const discovery_dns = @import("discovery/dns.zig");
pub const discovery_dial_source = @import("discovery/dial_source.zig");
pub const pkarr = @import("discovery/pkarr.zig");
pub const discovery_lookup_io = @import("discovery/lookup_io.zig");
pub const discovery_lookup_live = @import("discovery/lookup_live.zig");

pub const relay_frame = @import("relay/frame.zig");
pub const relay_client = @import("relay/client.zig");
pub const relay_server = @import("relay/server.zig");

pub const addr_map = @import("transport/addr_map.zig");
pub const transport_batch = @import("transport/batch.zig");
pub const transport_quic_bridge = @import("transport/quic_bridge.zig");
pub const transport_socket = @import("transport/socket.zig");
pub const transport_dial = @import("transport/dial.zig");

pub const endpoint = @import("endpoint/endpoint.zig");
pub const incoming_filter = @import("endpoint/incoming_filter.zig");

pub const router = @import("router/router.zig");

pub const range_spec = @import("blobs/range_spec.zig");
pub const blobs_protocol = @import("blobs/protocol.zig");
pub const endpoint_ticket = @import("ticket/endpoint_ticket.zig");
pub const blob_ticket = @import("ticket/blob_ticket.zig");

pub const gossip_hyparview = @import("gossip/hyparview.zig");
pub const gossip_plumtree = @import("gossip/plumtree.zig");
pub const node = @import("node/node.zig");

pub const NodeId = key.NodeId;
pub const SecretKey = key.SecretKey;
pub const Signature = key.Signature;
pub const KeyError = key.KeyError;

pub const IpAddress = addr.IpAddress;
pub const SocketAddr = addr.SocketAddr;
pub const RelayUrl = addr.RelayUrl;
pub const CustomAddr = addr.CustomAddr;
pub const TransportAddr = addr.TransportAddr;
pub const NodeAddr = addr.NodeAddr;

/// The fake address a path is reached at, or the path's own address when it
/// already has one. See `base/ula.zig` for what is and is not pure here.
pub const syntheticSocketAddr = ula.syntheticSocketAddr;

test {
    // Reference every declaration so an unused module still type-checks. Zig
    // 0.16 dropped `refAllDeclsRecursive`; the roots are named explicitly.
    std.testing.refAllDecls(@This());
    // A split leaves the facade naming the layer, but a facade re-export does
    // not pull in the tests of the module behind it: Zig collects a file's test
    // blocks only when that file is itself referenced. Without these lines the
    // build stays green and the tests silently stop running.
    const dial_source_harness = @import("discovery/dial_source_harness.zig");
    const item_merge = @import("discovery/item_merge.zig");
    const item_record = @import("discovery/item_record.zig");
    const item_resolution = @import("discovery/item_resolution.zig");
    const lookup_answer = @import("discovery/lookup_answer.zig");
    const lookup_query = @import("discovery/lookup_query.zig");
    const lookup_retrieval = @import("discovery/lookup_retrieval.zig");
    const preset = @import("discovery/preset.zig");
    const accept_machine = @import("endpoint/accept_machine.zig");
    const hyparview_config_test = @import("gossip/hyparview/config_test.zig");
    const hyparview_peer_data_test = @import("gossip/hyparview/peer_data_test.zig");
    const hyparview_sim_test = @import("gossip/hyparview/sim_test.zig");
    const hyparview_state_test = @import("gossip/hyparview/state_test.zig");
    const hyparview_topic_id_test = @import("gossip/hyparview/topic_id_test.zig");
    const plumtree_blake3_test = @import("gossip/plumtree/blake3_test.zig");
    const plumtree_cache_test = @import("gossip/plumtree/cache_test.zig");
    const plumtree_recovery_test = @import("gossip/plumtree/recovery_test.zig");
    const plumtree_state_test = @import("gossip/plumtree/state_test.zig");
    const relay_frame_decode = @import("relay/frame_decode.zig");
    const relay_frame_encode = @import("relay/frame_encode.zig");
    const relay_frame_roundtrip = @import("relay/frame_roundtrip.zig");
    const relay_frame_types = @import("relay/frame_types.zig");
    const relay_frame_writer = @import("relay/frame_writer.zig");
    const relay_server_handshake = @import("relay/server_handshake.zig");
    const relay_server_queue = @import("relay/server_queue.zig");
    const relay_server_registry = @import("relay/server_registry.zig");
    const transport_bridge_config = @import("transport/bridge_config.zig");
    const transport_bridge_conn = @import("transport/bridge_conn.zig");
    const transport_bridge_manager = @import("transport/bridge_manager.zig");
    const transport_dial_client = @import("transport/dial_client.zig");
    const transport_dial_route = @import("transport/dial_route.zig");
    std.testing.refAllDecls(dial_source_harness);
    std.testing.refAllDecls(item_merge);
    std.testing.refAllDecls(item_record);
    std.testing.refAllDecls(item_resolution);
    std.testing.refAllDecls(lookup_answer);
    std.testing.refAllDecls(lookup_query);
    std.testing.refAllDecls(lookup_retrieval);
    std.testing.refAllDecls(preset);
    std.testing.refAllDecls(accept_machine);
    std.testing.refAllDecls(hyparview_config_test);
    std.testing.refAllDecls(hyparview_peer_data_test);
    std.testing.refAllDecls(hyparview_sim_test);
    std.testing.refAllDecls(hyparview_state_test);
    std.testing.refAllDecls(hyparview_topic_id_test);
    std.testing.refAllDecls(plumtree_blake3_test);
    std.testing.refAllDecls(plumtree_cache_test);
    std.testing.refAllDecls(plumtree_recovery_test);
    std.testing.refAllDecls(plumtree_state_test);
    std.testing.refAllDecls(relay_frame_decode);
    std.testing.refAllDecls(relay_frame_encode);
    std.testing.refAllDecls(relay_frame_roundtrip);
    std.testing.refAllDecls(relay_frame_types);
    std.testing.refAllDecls(relay_frame_writer);
    std.testing.refAllDecls(relay_server_handshake);
    std.testing.refAllDecls(relay_server_queue);
    std.testing.refAllDecls(relay_server_registry);
    std.testing.refAllDecls(transport_bridge_config);
    std.testing.refAllDecls(transport_bridge_conn);
    std.testing.refAllDecls(transport_bridge_manager);
    std.testing.refAllDecls(transport_dial_client);
    std.testing.refAllDecls(transport_dial_route);
    const crypto_blake3_core = @import("crypto/blake3_core.zig");
    const crypto_blake3_nodes = @import("crypto/blake3_nodes.zig");
    const crypto_blake3_subtree = @import("crypto/blake3_subtree.zig");
    const discovery_host_answer = @import("discovery/host_answer.zig");
    const discovery_host_io = @import("discovery/host_io.zig");
    const discovery_host_wire = @import("discovery/host_wire.zig");
    const gossip_codec_test = @import("gossip/codec_test.zig");
    const gossip_codec_chunk_test = @import("gossip/codec/chunk_test.zig");
    const node_conn_index = @import("node/conn_index.zig");
    const node_topic_table = @import("node/topic_table.zig");
    const relay_http_upgrade = @import("relay/http_upgrade.zig");
    const relay_version_translate = @import("relay/version_translate.zig");
    const relay_ws_frame = @import("relay/ws_frame.zig");
    const relay_ws_frame_mask = @import("relay/ws_frame_mask.zig");
    const transport_tcp = @import("transport/tcp.zig");
    const transport_tcp_error = @import("transport/tcp_error.zig");
    const transport_tcp_sys = @import("transport/tcp_sys.zig");
    std.testing.refAllDecls(crypto_blake3_core);
    std.testing.refAllDecls(crypto_blake3_nodes);
    std.testing.refAllDecls(crypto_blake3_subtree);
    std.testing.refAllDecls(discovery_host_answer);
    std.testing.refAllDecls(discovery_host_io);
    std.testing.refAllDecls(discovery_host_wire);
    std.testing.refAllDecls(gossip_codec_test);
    std.testing.refAllDecls(gossip_codec_chunk_test);
    std.testing.refAllDecls(node_conn_index);
    std.testing.refAllDecls(node_topic_table);
    std.testing.refAllDecls(relay_http_upgrade);
    std.testing.refAllDecls(relay_version_translate);
    std.testing.refAllDecls(relay_ws_frame);
    std.testing.refAllDecls(relay_ws_frame_mask);
    std.testing.refAllDecls(transport_tcp);
    std.testing.refAllDecls(transport_tcp_error);
    std.testing.refAllDecls(transport_tcp_sys);
    std.testing.refAllDecls(base32);
    std.testing.refAllDecls(key);
    std.testing.refAllDecls(addr);
    std.testing.refAllDecls(ula);
    std.testing.refAllDecls(net_report);
    std.testing.refAllDecls(holepunch);
    std.testing.refAllDecls(net_probe);
    std.testing.refAllDecls(net_probe_run);
    std.testing.refAllDecls(net_holepunch_run);
    std.testing.refAllDecls(discovery_item);
    std.testing.refAllDecls(discovery_resolve);
    std.testing.refAllDecls(discovery_dial_source);
    std.testing.refAllDecls(discovery_dns);
    std.testing.refAllDecls(discovery_lookup_io);
    std.testing.refAllDecls(discovery_lookup_live);
    std.testing.refAllDecls(postcard);
    std.testing.refAllDecls(pkarr);
    std.testing.refAllDecls(relay_frame);
    std.testing.refAllDecls(relay_client);
    std.testing.refAllDecls(relay_server);
    std.testing.refAllDecls(range_spec);
    std.testing.refAllDecls(blobs_protocol);
    std.testing.refAllDecls(addr_map);
    std.testing.refAllDecls(transport_batch);
    std.testing.refAllDecls(transport_quic_bridge);
    std.testing.refAllDecls(transport_socket);
    std.testing.refAllDecls(transport_dial);
    std.testing.refAllDecls(endpoint);
    std.testing.refAllDecls(incoming_filter);
    std.testing.refAllDecls(router);
    std.testing.refAllDecls(endpoint_ticket);
    std.testing.refAllDecls(blob_ticket);
    std.testing.refAllDecls(gossip_hyparview);
    std.testing.refAllDecls(gossip_plumtree);
    std.testing.refAllDecls(node);
}
