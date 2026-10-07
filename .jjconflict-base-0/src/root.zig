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
//! `relay_tcp_carrier` and `transport_tcp` expose live TCP drivers; `blobs_store`
//! owns file-backed blob storage. The native NAT modules and `path_action`
//! expose pure packet, state and path-planning logic.

const std = @import("std");

pub const base32 = @import("base/base32.zig");
pub const key = @import("base/key.zig");
pub const addr = @import("base/addr.zig");
pub const ula = @import("base/ula.zig");
pub const postcard = @import("wire/postcard.zig");
pub const quic_varint = @import("wire/quic_varint.zig");
pub const net_report = @import("net/report.zig");
pub const holepunch = @import("net/holepunch.zig");
pub const net_probe = @import("net/probe.zig");
pub const net_probe_run = @import("net/probe_run.zig");
pub const net_holepunch_run = @import("net/holepunch_run.zig");
pub const native_nat = @import("net/native_nat.zig");
pub const native_nat_state = @import("net/native_nat_state.zig");
pub const path_action = @import("net/path_action.zig");

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
pub const relay_tcp_carrier = @import("relay/tcp_carrier.zig");

pub const addr_map = @import("transport/addr_map.zig");
pub const transport_batch = @import("transport/batch.zig");
pub const transport_quic_bridge = @import("transport/quic_bridge.zig");
pub const transport_socket = @import("transport/socket.zig");
pub const transport_dial = @import("transport/dial.zig");
pub const transport_tcp = @import("transport/tcp.zig");

pub const endpoint = @import("endpoint/endpoint.zig");
pub const incoming_filter = @import("endpoint/incoming_filter.zig");

pub const router = @import("router/router.zig");

pub const range_spec = @import("blobs/range_spec.zig");
pub const blobs_protocol = @import("blobs/protocol.zig");
pub const blobs_framing = @import("blobs/framing.zig");
pub const blobs_requests = @import("blobs/requests.zig");
pub const blobs_responses = @import("blobs/responses.zig");
pub const blobs_store = @import("blobs/store.zig");
pub const endpoint_ticket = @import("ticket/endpoint_ticket.zig");
pub const blob_ticket = @import("ticket/blob_ticket.zig");
pub const node_gossip_wire = @import("node/node_gossip_wire.zig");
pub const node_discovery = @import("node/node_discovery.zig");
pub const bao_tree = @import("blobs/bao_tree.zig");
pub const bao_plan = @import("blobs/bao_plan.zig");
pub const bao_proof_encode = @import("blobs/bao_proof_encode.zig");
pub const bao_proof_verify = @import("blobs/bao_proof_verify.zig");

pub const gossip_codec = @import("gossip/codec.zig");

pub const relay_ws_frame = @import("relay/ws_frame.zig");

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
    const relay_ws_frame_mask = @import("relay/ws_frame_mask.zig");
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
    std.testing.refAllDecls(relay_ws_frame_mask);
    std.testing.refAllDecls(transport_tcp);
    std.testing.refAllDecls(transport_tcp_error);
    std.testing.refAllDecls(transport_tcp_sys);
    const blobs_bao_tree = @import("blobs/bao_tree.zig");
    const blobs_bao_plan = @import("blobs/bao_plan.zig");
    const blobs_bao_outboard = @import("blobs/bao_outboard.zig");
    const blobs_bao_proof_encode = @import("blobs/bao_proof_encode.zig");
    const blobs_bao_proof_verify = @import("blobs/bao_proof_verify.zig");
    const discovery_dns_live = @import("discovery/dns_live.zig");
    const discovery_pkarr_body = @import("discovery/pkarr_body.zig");
    const discovery_pkarr_live = @import("discovery/pkarr_live.zig");
    const discovery_publisher = @import("discovery/publisher.zig");
    const discovery_tls_client = @import("discovery/tls_client.zig");
    const relay_access_policy = @import("relay/access_policy.zig");
    const relay_carrier = @import("relay/carrier.zig");
    const relay_conn_version = @import("relay/conn_version.zig");
    const relay_liveness = @import("relay/liveness.zig");
    const relay_reconnect = @import("relay/reconnect.zig");
    std.testing.refAllDecls(blobs_bao_tree);
    std.testing.refAllDecls(blobs_bao_plan);
    std.testing.refAllDecls(blobs_bao_outboard);
    std.testing.refAllDecls(blobs_bao_proof_encode);
    std.testing.refAllDecls(blobs_bao_proof_verify);
    std.testing.refAllDecls(discovery_dns_live);
    std.testing.refAllDecls(discovery_pkarr_body);
    std.testing.refAllDecls(discovery_pkarr_live);
    std.testing.refAllDecls(discovery_publisher);
    std.testing.refAllDecls(discovery_tls_client);
    std.testing.refAllDecls(relay_access_policy);
    std.testing.refAllDecls(relay_carrier);
    std.testing.refAllDecls(relay_conn_version);
    std.testing.refAllDecls(relay_liveness);
    std.testing.refAllDecls(relay_reconnect);
    const blobs_provider = @import("blobs/provider.zig");
    const blobs_getter = @import("blobs/getter.zig");
    const blobs_resume = @import("blobs/resume.zig");
    const net_qad = @import("net/qad.zig");
    const router_qad_route = @import("router/qad_route.zig");
    const net_interface = @import("net/interface.zig");
    const net_path_table = @import("net/path_table.zig");
    const net_path_select = @import("net/path_select.zig");
    const net_holepunch_target = @import("net/holepunch_target.zig");
    const net_holepunch_trigger = @import("net/holepunch_trigger.zig");
    const net_probe_live = @import("net/probe_live.zig");
    std.testing.refAllDecls(blobs_store);
    std.testing.refAllDecls(blobs_provider);
    std.testing.refAllDecls(blobs_getter);
    std.testing.refAllDecls(blobs_resume);
    std.testing.refAllDecls(net_qad);
    std.testing.refAllDecls(router_qad_route);
    std.testing.refAllDecls(net_interface);
    std.testing.refAllDecls(net_path_table);
    std.testing.refAllDecls(net_path_select);
    std.testing.refAllDecls(net_holepunch_target);
    std.testing.refAllDecls(net_holepunch_trigger);
    std.testing.refAllDecls(net_probe_live);
    const net_observed_address = @import("net/observed_address.zig");
    const net_observed_reporter = @import("net/observed_reporter.zig");
    const transport_resumption = @import("transport/resumption.zig");
    const transport_early_data = @import("transport/early_data.zig");
    const transport_session_store = @import("transport/session_store.zig");
    std.testing.refAllDecls(net_observed_address);
    std.testing.refAllDecls(net_observed_reporter);
    std.testing.refAllDecls(transport_resumption);
    std.testing.refAllDecls(transport_early_data);
    std.testing.refAllDecls(transport_session_store);
    const blobs_blob_set = @import("blobs/blob_set.zig");
    const net_blobs_route = @import("net/blobs_route.zig");
    const net_path_revalidate = @import("net/path_revalidate.zig");
    const transport_multipath = @import("transport/multipath.zig");
    std.testing.refAllDecls(blobs_blob_set);
    std.testing.refAllDecls(net_blobs_route);
    std.testing.refAllDecls(net_path_revalidate);
    std.testing.refAllDecls(transport_multipath);
    const blobs_blob_claim = @import("blobs/blob_claim.zig");
    const blobs_observe = @import("blobs/observe.zig");
    const blobs_push = @import("blobs/push.zig");
    const discovery_resolve_fanin = @import("discovery/resolve_fanin.zig");
    const discovery_resolve_deadline = @import("discovery/resolve_deadline.zig");
    const gossip_topic_policy = @import("gossip/topic_policy.zig");
    const gossip_gossip_actions = @import("gossip/gossip_actions.zig");
    const net_address_change = @import("net/address_change.zig");
    const net_ecn_feedback = @import("net/ecn_feedback.zig");
    const net_path_probe = @import("net/path_probe.zig");
    const net_qnt = @import("net/qnt.zig");
    const net_qnt_state = @import("net/qnt_state.zig");
    const net_statistics = @import("net/statistics.zig");
    const net_statistics_report = @import("net/statistics_report.zig");
    const net_connection_budget = @import("net/connection_budget.zig");
    const net_preferred_relay = @import("net/preferred_relay.zig");
    const net_relay_selection = @import("net/relay_selection.zig");
    const net_replay_window = @import("net/replay_window.zig");
    const net_resumption_acceptance = @import("net/resumption_acceptance.zig");
    const node_lane_budget = @import("node/lane_budget.zig");
    const node_shutdown_order = @import("node/shutdown_order.zig");
    const node_shutdown_budget = @import("node/shutdown_budget.zig");
    const node_ticket_cache = @import("node/ticket_cache.zig");
    const node_ticket_lifecycle = @import("node/ticket_lifecycle.zig");
    std.testing.refAllDecls(blobs_blob_claim);
    std.testing.refAllDecls(blobs_observe);
    std.testing.refAllDecls(blobs_push);
    std.testing.refAllDecls(discovery_resolve_fanin);
    std.testing.refAllDecls(discovery_resolve_deadline);
    std.testing.refAllDecls(gossip_topic_policy);
    std.testing.refAllDecls(gossip_gossip_actions);
    std.testing.refAllDecls(net_address_change);
    std.testing.refAllDecls(net_ecn_feedback);
    std.testing.refAllDecls(net_path_probe);
    std.testing.refAllDecls(net_qnt);
    std.testing.refAllDecls(net_qnt_state);
    std.testing.refAllDecls(net_statistics);
    std.testing.refAllDecls(net_statistics_report);
    std.testing.refAllDecls(net_connection_budget);
    std.testing.refAllDecls(net_preferred_relay);
    std.testing.refAllDecls(net_relay_selection);
    std.testing.refAllDecls(net_replay_window);
    std.testing.refAllDecls(net_resumption_acceptance);
    std.testing.refAllDecls(node_lane_budget);
    std.testing.refAllDecls(node_shutdown_order);
    std.testing.refAllDecls(node_shutdown_budget);
    std.testing.refAllDecls(node_ticket_cache);
    std.testing.refAllDecls(node_ticket_lifecycle);
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
    std.testing.refAllDecls(relay_tcp_carrier);
    std.testing.refAllDecls(range_spec);
    std.testing.refAllDecls(blobs_protocol);
    std.testing.refAllDecls(addr_map);
    std.testing.refAllDecls(transport_batch);
    std.testing.refAllDecls(transport_quic_bridge);
    std.testing.refAllDecls(transport_socket);
    std.testing.refAllDecls(transport_dial);
    std.testing.refAllDecls(native_nat);
    std.testing.refAllDecls(native_nat_state);
    std.testing.refAllDecls(path_action);
    const native_nat_probe = @import("net/native_nat_probe.zig");
    std.testing.refAllDecls(native_nat_probe);
    const blobs_oracle_test = @import("blobs/oracle_test.zig");
    std.testing.refAllDecls(blobs_oracle_test);
    const node_blobs = @import("node/node_blobs.zig");
    const node_native = @import("node/node_native.zig");
    const node_holepunch = @import("node/node_holepunch.zig");
    const node_relay_runtime = @import("node/node_relay_runtime.zig");
    std.testing.refAllDecls(node_blobs);
    std.testing.refAllDecls(node_native);
    std.testing.refAllDecls(node_holepunch);
    std.testing.refAllDecls(node_relay_runtime);
    std.testing.refAllDecls(endpoint);
    std.testing.refAllDecls(incoming_filter);
    std.testing.refAllDecls(router);
    std.testing.refAllDecls(endpoint_ticket);
    std.testing.refAllDecls(blob_ticket);
    std.testing.refAllDecls(gossip_hyparview);
    std.testing.refAllDecls(gossip_plumtree);
    std.testing.refAllDecls(node);
}
