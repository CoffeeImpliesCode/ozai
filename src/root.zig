//! ozai — dial a node by its id, not its address.
//!
//! This is the library root. It re-exports the pure value layer and is the only
//! module an importer needs to name.
//!
//! Scope, as of the first milestone: identity and addressing only. Everything
//! that touches a socket is deliberately absent until the transport substrate
//! is settled — see `docs/PLAN.md`. `ula` maps a path onto the fake address a
//! QUIC stack would take it on; that is a value, not a socket.

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
