//! The four tag tables, in the order upstream declares them.
//!
//! A tag is a discriminant, and a discriminant is a position: postcard writes
//! it as a `varint(u32)` holding the index the declaration gives the variant, so
//! moving an arm upstream moves every byte after it. Nothing here is derived from
//! a Zig union's field order at run time and nothing is a bare `@intFromEnum` on
//! a value: the four tables below are written out, upstream order for upstream
//! order, and a comptime proof at the end of the file holds the Zig unions to
//! them.
//!
//! Sources, `n0-computer/iroh-gossip` at commit
//! `2885dd9f1120e46aca5acbcd7f212e4c64e278b9`:
//!
//! - `src/proto/topic.rs:92-97` — `topic::Message`, `Swarm` then `Gossip`.
//! - `src/proto/hyparview.rs:68-93` — `hyparview::Message`, `Join`,
//!   `ForwardJoin`, `Shuffle`, `ShuffleReply`, `Neighbor`, `Disconnect`.
//! - `src/proto/hyparview.rs:129-136` — `Priority`, `High` then `Low`.
//! - `src/proto/plumtree.rs:129-141` — `plumtree::Message`, `Gossip`, `Prune`,
//!   `Graft`, `IHave`.
//! - `src/proto/plumtree.rs:172-181` — `DeliveryScope`, `Swarm` then
//!   `Neighbors`.
//!
//! The protocol-wide story — the framing, the stream header, the byte budget and
//! every divergence from upstream — is in `../codec.zig`, which is the module
//! callers import. This file is one piece of it.

const std = @import("std");

const gossip = @import("../hyparview.zig");
const plumtree = @import("../plumtree.zig");

const delivery_scope = plumtree.DeliveryScope;
const swarm_priority = gossip.Priority;
const swarm_message = gossip.SwarmMessage;
const topic_message = gossip.Message;
const tree_message = plumtree.Message;

/// Which layer a message belongs to. Upstream `proto::topic::Message`.
///
/// The two arms are the two layers and nothing else travels, so this is the first
/// byte of every body after the length prefix.
pub const Layer = enum(u8) {
    /// The membership layer's vocabulary. Upstream `Message::Swarm`.
    swarm = 0,
    /// The broadcast layer's vocabulary. Upstream `Message::Gossip`.
    gossip = 1,
};

/// The membership layer's six messages. Upstream `hyparview::Message`.
///
/// `Join` is upstream's `Option<PeerData>` and the rest are upstream's structs,
/// in the order `hyparview.rs:68-93` declares them. `Disconnect` is the one
/// message whose Zig form is missing a field upstream has; `membership.zig` says
/// which.
pub const Swarm = enum(u8) {
    /// "Let me in". Upstream `Message::Join`, `hyparview.rs:70`.
    join = 0,
    /// "A peer joined; introduce it". Upstream `Message::ForwardJoin`, `:73`.
    forward_join = 1,
    /// "Exchange a slice of my view for a slice of yours". Upstream
    /// `Message::Shuffle`, `:76`.
    shuffle = 2,
    /// The answer to a `Shuffle`. Upstream `Message::ShuffleReply`, `:81`.
    shuffle_reply = 3,
    /// "I want you in my active view". Upstream `Message::Neighbor`, `:85`.
    neighbor = 4,
    /// "I am closing the connection". Upstream `Message::Disconnect`, `:90`.
    disconnect = 5,
};

/// The broadcast layer's four messages. Upstream `plumtree::Message`.
pub const Tree = enum(u8) {
    /// A payload, to be forwarded. Upstream `Message::Gossip`,
    /// `plumtree.rs:130`.
    gossip = 0,
    /// "You are a lazy peer now". Upstream `Message::Prune`, `:135`.
    prune = 1,
    /// "Send me that message, and push it to me whole". Upstream
    /// `Message::Graft`, `:137`.
    graft = 2,
    /// "I have this message, this far from its origin". Upstream
    /// `Message::IHave`, `:140`.
    i_have = 3,
};

/// Whether a `Join` or `ForwardJoin` may be refused. Upstream `Priority`.
///
/// `High` is first upstream (`hyparview.rs:130`) and therefore zero here. The
/// Zig `Priority` names it `high`, which is the same variant in a different
/// spelling and not a different one.
pub const Priority = enum(u8) {
    /// May not be denied.
    high = 0,
    /// Denied if the active view is full.
    low = 1,
};

/// Where a received broadcast came from. Upstream `DeliveryScope`.
///
/// **`Swarm` is first upstream (`plumtree.rs:174`) and therefore zero here**, and
/// this is the one table in this file where a Zig union's field order and a
/// locally chosen order part company: the union is declared `swarm` then
/// `neighbors` as upstream declares them, so the two agree, and a reader
/// comparing this codec with `test/protocol_codec.zig` will find that file
/// numbers them the other way round.
pub const Scope = enum(u8) {
    /// Received from the swarm, this many hops from the broadcaster.
    swarm = 0,
    /// Received from a direct neighbour that broadcast to neighbours only.
    neighbors = 1,
};

/// The arm names upstream declares, which is the order the tables above are.
///
/// The proof below is what keeps the tables and the Zig unions from drifting
/// apart: an arm inserted into `SwarmMessage` in the middle would renumber every
/// message after it on the wire, and the build is where that has to stop.
const layer_names = [_][]const u8{ "swarm", "gossip" };
const swarm_names = [_][]const u8{
    "join",
    "forward_join",
    "shuffle",
    "shuffle_reply",
    "neighbor",
    "disconnect",
};
const tree_names = [_][]const u8{ "gossip", "prune", "graft", "i_have" };
const priority_names = [_][]const u8{ "high", "low" };
const scope_names = [_][]const u8{ "swarm", "neighbors" };

comptime {
    assertOrder(@typeInfo(topic_message).@"union".fields, &layer_names);
    assertOrder(@typeInfo(swarm_message).@"union".fields, &swarm_names);
    assertOrder(@typeInfo(tree_message).@"union".fields, &tree_names);
    assertOrder(@typeInfo(swarm_priority).@"enum".fields, &priority_names);
    assertOrder(@typeInfo(delivery_scope).@"union".fields, &scope_names);
}

fn assertOrder(comptime fields: anytype, comptime names: []const []const u8) void {
    if (fields.len != names.len) {
        @compileError("a message union gained or lost an arm; its tag table is out of date");
    }
    inline for (names, 0..) |name, index| {
        if (!std.mem.eql(u8, fields[index].name, name)) {
            @compileError("a message arm was reordered; its tag table is out of date");
        }
    }
}
