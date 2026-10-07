//! The record this node publishes about itself: the relay addresses it is
//! reachable at, merged into one publication and written as `_iroh` records.
//!
//! It is its own module because it is the one part of the discovery pass that
//! is a *decision about what may leave this process*, and `AGENTS.md` §2 wants
//! that separated from the transport so it can be read without reading a
//! socket. `node_discovery.zig` owns the pass and the timers; this file owns
//! what the pass publishes.
//!
//! # What is in the record, and what is not
//!
//! **Relay addresses, and no direct address.** `discovery/preset.zig`'s
//! `Publication.relay_only` is this project's publication default and it is
//! kept: the node "is reachable through the relays in `Preset.relays` and
//! publishes nothing anywhere else: no DNS TXT record, no pkarr packet, no
//! direct address handed to a third party". What goes to a pkarr relay is
//! therefore the relay URLs a caller named, and the node's own listen address
//! is not one of them.
//!
//! That is a decision and not an omission, and it is worth stating why: a node
//! behind NAT that published its own socket address would advertise an address
//! no peer can reach, and a node that *is* reachable at it has no need to say
//! so to a third party. Upstream publishes direct addresses
//! (`iroh/src/address_lookup/pkarr.rs`) because its endpoint gathers its own
//! address candidates; this node does not gather any, and
//! `docs/ARCHITECTURE.md`'s rule about unverified claims is the reason nothing
//! here invents them.
//!
//! # One fan-in, one grammar
//!
//! `publisher.mergePublished` is the only rule about what may be published
//! under one node's key — it refuses `error.MixedNodeIds` for exactly this —
//! and `pkarr_services.PkarrPublisher.writeTxtStrings` is the only writer of the
//! `_iroh` record grammar (`pkarr_body.zig`'s doc says so by name). Both are
//! reached; neither is restated here.

const std = @import("std");

const node_mod = @import("node.zig");

const pkarr_services = @import("../discovery/pkarr_services.zig");
const preset = @import("../discovery/preset.zig");
const publisher = @import("../discovery/publisher.zig");
const txt = @import("../discovery/txt.zig");

const base_addr = @import("../base/addr.zig");

const Node = node_mod.Node;

/// How many relays one record may carry.
///
/// `preset.relay_urls_prod` has four and its staging twin two, so four is the
/// widest this tree's own presets name. A preset naming more is refused by name
/// (`node_discovery_wire.Refused.too_many_relays`) rather than truncated,
/// because a record that silently dropped relays is a node that believes it is
/// reachable somewhere it is not.
pub const max_relays: usize = preset.relay_urls_prod.len;

/// The room one signed packet's records need.
///
/// `max_relays` is the bound on the address list a record may hold and
/// `txt.maxTxtStringsLength` is the writer's own arithmetic for exactly that
/// many records. Two published modules' bounds composed into one storage field,
/// rather than a third number chosen here: a buffer too small for a record built
/// here would refuse a publish as `Refused.nothing_to_publish`, and a reader
/// would have to guess whether the bound or the writer was wrong.
pub const record_room: usize = txt.maxTxtStringsLength(max_relays);

/// Arm the publisher with this node's own record, or say why it cannot be.
///
/// **The record is relay-only and a direct address is never in it.**
/// `preset.Publication.relay_only` is the default this project publishes under,
/// and its own doc rules out "a direct address handed to a third party": what
/// goes to a pkarr relay is the relay URLs from `Config.discovery.relays`, and
/// nothing else. `Config.relay` decides which relay URLs those are, and a node
/// with `.off` has none — so its record is empty, `mergePublished` answers
/// `error.NoAddresses`, and this is the `Refused.nothing_to_publish` refusal.
///
/// The listen address is *not* published, and it is worth being explicit about
/// why that is a decision and not an omission: a node behind NAT that
/// published its own socket address would advertise an address no peer can
/// reach, and a node that can be reached at it has no need to say so to a
/// third party. Upstream publishes direct addresses
/// (`iroh/src/address_lookup/pkarr.rs`) because its endpoint knows its own
/// candidates; this node does not gather them, and `docs/ARCHITECTURE.md`'s
/// rule about unverified claims is the reason nothing here invents them.
pub fn arm(self: *Node) void {
    const relays = self.config.discovery.relays;
    if (relays.len > max_relays) {
        self.discovery.refused.too_many_relays += 1;
        return;
    }
    if (relays.len == 0) {
        self.discovery.refused.nothing_to_publish += 1;
        return;
    }
    var sources: [max_relays]publisher.Published = undefined;
    var count: usize = 0;
    for (relays) |text| {
        const url = base_addr.RelayUrl.parse(text) catch {
            // A relay URL this tree cannot parse is refused here rather than at
            // the first publish: an address that cannot be dialled is not a
            // record, and `preset.zig`'s own tests hold every preset relay to
            // `RelayUrl.format`'s canonical spelling.
            self.discovery.refused.nothing_to_publish += 1;
            return;
        };
        sources[count] = .{
            .alloc = self.gpa,
            .endpoint = base_addr.NodeAddr.withRelay(self.gpa, self.nodeId(), url) catch {
                self.discovery.refused.out_of_memory += 1;
                return;
            },
            .last_updated = null,
        };
        count += 1;
    }
    // One fan-in for every source, so `publisher.mergePublished`'s own rule is
    // the only rule about what may be published under one node's key. It
    // releases all `sources` on the way out, including on the error paths, so
    // the caller keeps no half-built list to clean up.
    const merged = publisher.mergePublished(self.gpa, sources[0..count]) catch |err| {
        // `MixedNodeIds` cannot happen: every source above is this node's own
        // id. It is named rather than swallowed so a future source that is not
        // the node's own is refused by name too.
        std.log.warn("node {f} could not merge its own relays: {t}", .{ self.nodeId(), err });
        self.discovery.refused.nothing_to_publish += 1;
        return;
    };
    self.discovery.publisher.set(.{
        .alloc = self.gpa,
        .endpoint = merged,
        .last_updated = null,
    });
}

/// The `_iroh` records this node's own address list writes to, into `out`.
///
/// A free function over a `NodeAddr` and not a `PkarrPublisher` method because
/// this node holds its record in `publisher.State` rather than in a
/// `PkarrPublisher`'s slot, and `writeTxtStrings` is the only writer of that
/// grammar in the tree (`pkarr_body.zig`'s doc says so by name). One grammar,
/// called twice, rather than a second one written here.
pub fn recordsOf(
    alloc: std.mem.Allocator,
    endpoint: base_addr.NodeAddr,
    out: []u8,
) !txt.RecordSet {
    var writer = pkarr_services.PkarrPublisher.init();
    writer.stored = .{ .alloc = alloc, .endpoint = endpoint, .last_updated = null };
    return txt.RecordSet.init(try writer.writeTxtStrings(out));
}
