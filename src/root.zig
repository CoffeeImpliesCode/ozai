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
pub const relay_url = @import("base/relay_url.zig");
pub const transport_addr = @import("base/transport_addr.zig");
pub const node_addr = @import("base/node_addr.zig");
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

pub const relay_frame_types = @import("relay/frame_types.zig");
pub const relay_frame_writer = @import("relay/frame_writer.zig");
pub const relay_frame_codec = @import("relay/frame_codec.zig");
pub const relay_client = @import("relay/client.zig");
pub const relay_server_handshake = @import("relay/server_handshake.zig");
pub const relay_server_queue = @import("relay/server_queue.zig");
pub const relay_server_registry = @import("relay/server_registry.zig");

pub const addr_map = @import("transport/addr_map.zig");
pub const transport_batch = @import("transport/batch.zig");
pub const transport_quic_bridge = @import("transport/quic_bridge.zig");
pub const transport_quic_conn = @import("transport/quic_conn.zig");
pub const transport_quic_config = @import("transport/quic_config.zig");
pub const transport_quic_error = @import("transport/quic_error.zig");
pub const transport_quic_stream = @import("transport/quic_stream.zig");
pub const transport_quic_datagram = @import("transport/quic_datagram.zig");
pub const transport_socket = @import("transport/socket.zig");
pub const transport_dial = @import("transport/dial.zig");
pub const transport_dial_route = @import("transport/dial_route.zig");
pub const transport_retry = @import("transport/retry.zig");

pub const endpoint = @import("endpoint/endpoint.zig");
pub const incoming_filter = @import("endpoint/incoming_filter.zig");
pub const endpoint_tasks = @import("endpoint/tasks.zig");

pub const router = @import("router/router.zig");
pub const router_dispatch = @import("router/dispatch.zig");
pub const router_shutdown = @import("router/shutdown.zig");
pub const router_lifetime = @import("router/lifetime.zig");

pub const range_spec = @import("blobs/range_spec.zig");
pub const blobs_protocol = @import("blobs/protocol.zig");
// The four concerns `blobs_protocol` is split into, named so a consumer that
// wants one of them directly does not have to reach through the facade. They
// are also named because `refAllDecls` does not recurse: without these rows
// the tests in the four files would not be part of any test root, and the
// re-exports alone would reach the declarations without reaching their tests.
pub const blobs_chunk = @import("blobs/chunk.zig");
pub const blobs_request = @import("blobs/request.zig");
pub const blobs_framing = @import("blobs/framing.zig");
pub const blobs_response = @import("blobs/response.zig");
pub const endpoint_ticket = @import("ticket/endpoint_ticket.zig");
pub const blob_ticket = @import("ticket/blob_ticket.zig");
pub const ticket_codec = @import("ticket/ticket_codec.zig");

pub const gossip_hyparview = @import("gossip/hyparview.zig");
pub const gossip_plumtree = @import("gossip/plumtree.zig");
pub const gossip_codec = @import("gossip/codec.zig");
pub const gossip_swarm_codec = @import("gossip/swarm_codec.zig");
pub const gossip_tree_codec = @import("gossip/tree_codec.zig");
pub const node = @import("node/node.zig");
pub const node_error = @import("node/node_error.zig");
pub const node_protocol = @import("node/node_protocol.zig");
pub const node_config = @import("node/node_config.zig");
pub const node_stats = @import("node/node_stats.zig");
pub const node_framing = @import("node/node_framing.zig");
pub const node_lane = @import("node/node_lane.zig");
pub const node_dispatch = @import("node/node_dispatch.zig");
pub const node_accept = @import("node/node_accept.zig");
pub const node_close = @import("node/node_close.zig");
pub const node_connection_close = @import("node/node_connection_close.zig");
pub const node_ingress = @import("node/node_ingress.zig");
pub const node_egress = @import("node/node_egress.zig");
pub const node_gossip = @import("node/node_gossip.zig");
pub const node_conn_index = @import("node/conn_index.zig");
pub const node_topic_table = @import("node/topic_table.zig");
pub const node_relay_serve = @import("node/node_relay_serve.zig");
pub const node_relay_serve_admit = @import("node/node_relay_serve_admit.zig");
pub const node_relay_serve_read = @import("node/node_relay_serve_read.zig");
pub const node_relay_registry = @import("node/node_relay_registry.zig");
pub const node_relay_client = @import("node/node_relay_client.zig");
pub const node_runtime = @import("node/node_runtime.zig");
pub const node_lifecycle = @import("node/node_lifecycle.zig");
pub const node_report = @import("node/node_report.zig");

pub const NodeId = key.NodeId;
pub const SecretKey = key.SecretKey;
pub const Signature = key.Signature;
pub const KeyError = key.KeyError;

pub const IpAddress = addr.IpAddress;
pub const SocketAddr = addr.SocketAddr;
pub const RelayUrl = relay_url.RelayUrl;
pub const CustomAddr = addr.CustomAddr;
pub const TransportAddr = transport_addr.TransportAddr;
pub const NodeAddr = node_addr.NodeAddr;

/// The fake address a path is reached at, or the path's own address when it
/// already has one. See `base/ula.zig` for what is and is not pure here.
pub const syntheticSocketAddr = ula.syntheticSocketAddr;

test {
    // Reference every declaration so an unused module still type-checks. Zig
    // 0.16 dropped `refAllDeclsRecursive`; the roots are named explicitly.
    std.testing.refAllDecls(@This());
    std.testing.refAllDecls(base32);
    std.testing.refAllDecls(key);
    std.testing.refAllDecls(addr);
    std.testing.refAllDecls(relay_url);
    std.testing.refAllDecls(transport_addr);
    std.testing.refAllDecls(node_addr);
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
    std.testing.refAllDecls(relay_frame_types);
    std.testing.refAllDecls(relay_frame_writer);
    std.testing.refAllDecls(relay_frame_codec);
    std.testing.refAllDecls(relay_client);
    std.testing.refAllDecls(relay_server_handshake);
    std.testing.refAllDecls(relay_server_queue);
    std.testing.refAllDecls(relay_server_registry);
    std.testing.refAllDecls(range_spec);
    std.testing.refAllDecls(blobs_protocol);
    std.testing.refAllDecls(blobs_chunk);
    std.testing.refAllDecls(blobs_request);
    std.testing.refAllDecls(blobs_framing);
    std.testing.refAllDecls(blobs_response);
    std.testing.refAllDecls(addr_map);
    std.testing.refAllDecls(transport_batch);
    std.testing.refAllDecls(transport_quic_bridge);
    std.testing.refAllDecls(transport_quic_conn);
    std.testing.refAllDecls(transport_quic_config);
    std.testing.refAllDecls(transport_quic_error);
    std.testing.refAllDecls(transport_quic_stream);
    std.testing.refAllDecls(transport_quic_datagram);
    std.testing.refAllDecls(transport_socket);
    std.testing.refAllDecls(transport_dial);
    std.testing.refAllDecls(transport_dial_route);
    std.testing.refAllDecls(transport_retry);
    std.testing.refAllDecls(endpoint);
    std.testing.refAllDecls(incoming_filter);
    std.testing.refAllDecls(endpoint_tasks);
    std.testing.refAllDecls(router);
    std.testing.refAllDecls(router_dispatch);
    std.testing.refAllDecls(router_shutdown);
    std.testing.refAllDecls(router_lifetime);
    std.testing.refAllDecls(endpoint_ticket);
    std.testing.refAllDecls(blob_ticket);
    std.testing.refAllDecls(ticket_codec);
    std.testing.refAllDecls(gossip_hyparview);
    std.testing.refAllDecls(gossip_plumtree);
    std.testing.refAllDecls(gossip_codec);
    std.testing.refAllDecls(gossip_swarm_codec);
    std.testing.refAllDecls(gossip_tree_codec);
    std.testing.refAllDecls(node);
    std.testing.refAllDecls(node_error);
    std.testing.refAllDecls(node_protocol);
    std.testing.refAllDecls(node_config);
    std.testing.refAllDecls(node_stats);
    std.testing.refAllDecls(node_framing);
    std.testing.refAllDecls(node_lane);
    std.testing.refAllDecls(node_dispatch);
    std.testing.refAllDecls(node_accept);
    std.testing.refAllDecls(node_close);
    std.testing.refAllDecls(node_connection_close);
    std.testing.refAllDecls(node_ingress);
    std.testing.refAllDecls(node_egress);
    std.testing.refAllDecls(node_gossip);
    std.testing.refAllDecls(node_conn_index);
    std.testing.refAllDecls(node_topic_table);
    std.testing.refAllDecls(node_relay_serve);
    std.testing.refAllDecls(node_relay_serve_admit);
    std.testing.refAllDecls(node_relay_serve_read);
    std.testing.refAllDecls(node_relay_registry);
    std.testing.refAllDecls(node_relay_client);
    std.testing.refAllDecls(node_runtime);
    std.testing.refAllDecls(node_lifecycle);
    std.testing.refAllDecls(node_report);
}
