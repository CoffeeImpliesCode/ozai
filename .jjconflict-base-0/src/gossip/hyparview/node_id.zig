//! Node identity: the one comparison every peer-keyed structure below is
//! built on.
//!
//! A `NodeId` has no `==` a caller can reach for through a union arm, so
//! `sameNode` is the total order the views, the contact table and the pending
//! sets look up by, and `containsNode` is the same question asked of a slice.
//! The protocol-wide story — the `Neighbor` deviation, the `TopicId` privacy
//! note and the purity rules — is in `../hyparview.zig`, which is the module
//! callers import. This file is one piece of it.

const key = @import("../../base/key.zig");

const NodeId = key.NodeId;

pub fn sameNode(a: NodeId, b: NodeId) bool {
    return a.order(b) == .eq;
}

pub fn containsNode(peers: []const NodeId, peer: NodeId) bool {
    for (peers) |item| {
        if (sameNode(item, peer)) return true;
    }
    return false;
}
