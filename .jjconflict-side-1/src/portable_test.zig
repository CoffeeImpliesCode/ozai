//! Existing protocol and state-machine tests without the Linux live adapters.
//! Importing `root.zig` here would pull socket and process tests into this scope.

const std = @import("std");

const base32 = @import("base/base32.zig");
const key = @import("base/key.zig");
const addr = @import("base/addr.zig");
const ula = @import("base/ula.zig");
const postcard = @import("wire/postcard.zig");
const net_report = @import("net/report.zig");
const holepunch = @import("net/holepunch.zig");
const net_probe = @import("net/probe.zig");
const net_probe_run = @import("net/probe_run.zig");
const net_holepunch_run = @import("net/holepunch_run.zig");
const discovery_item = @import("discovery/item.zig");
const discovery_resolve = @import("discovery/resolve.zig");
const discovery_dns = @import("discovery/dns.zig");
const pkarr = @import("discovery/pkarr.zig");
const discovery_lookup_io = @import("discovery/lookup_io.zig");
const discovery_dial_source = @import("discovery/dial_source.zig");
const relay_frame = @import("relay/frame.zig");
const relay_client = @import("relay/client.zig");
const relay_server = @import("relay/server.zig");
const addr_map = @import("transport/addr_map.zig");
const transport_batch = @import("transport/batch.zig");
const transport_quic_bridge = @import("transport/quic_bridge.zig");
const transport_dial = @import("transport/dial.zig");
const incoming_filter = @import("endpoint/incoming_filter.zig");
const endpoint = @import("endpoint/endpoint.zig");
const router = @import("router/router.zig");
const range_spec = @import("blobs/range_spec.zig");
const blobs_protocol = @import("blobs/protocol.zig");
const endpoint_ticket = @import("ticket/endpoint_ticket.zig");
const blob_ticket = @import("ticket/blob_ticket.zig");
const gossip_hyparview = @import("gossip/hyparview.zig");
const gossip_plumtree = @import("gossip/plumtree.zig");

test {
    std.testing.refAllDecls(@This());
    std.testing.refAllDecls(base32);
    std.testing.refAllDecls(key);
    std.testing.refAllDecls(addr);
    std.testing.refAllDecls(ula);
    std.testing.refAllDecls(postcard);
    std.testing.refAllDecls(net_report);
    std.testing.refAllDecls(holepunch);
    std.testing.refAllDecls(net_probe);
    std.testing.refAllDecls(net_probe_run);
    std.testing.refAllDecls(net_holepunch_run);
    std.testing.refAllDecls(discovery_item);
    std.testing.refAllDecls(discovery_resolve);
    std.testing.refAllDecls(discovery_dns);
    std.testing.refAllDecls(pkarr);
    std.testing.refAllDecls(discovery_lookup_io);
    std.testing.refAllDecls(discovery_dial_source);
    std.testing.refAllDecls(relay_frame);
    std.testing.refAllDecls(relay_client);
    std.testing.refAllDecls(relay_server);
    std.testing.refAllDecls(addr_map);
    std.testing.refAllDecls(transport_batch);
    std.testing.refAllDecls(transport_quic_bridge);
    std.testing.refAllDecls(transport_dial);
    std.testing.refAllDecls(incoming_filter);
    std.testing.refAllDecls(endpoint);
    std.testing.refAllDecls(router);
    std.testing.refAllDecls(range_spec);
    std.testing.refAllDecls(blobs_protocol);
    std.testing.refAllDecls(endpoint_ticket);
    std.testing.refAllDecls(blob_ticket);
    std.testing.refAllDecls(gossip_hyparview);
    std.testing.refAllDecls(gossip_plumtree);
}
