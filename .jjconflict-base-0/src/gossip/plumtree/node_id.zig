//! Node identity: the one comparison every peer-keyed structure in this
//! protocol is built on.
//!
//! A `NodeId` has no `==` a caller can reach for through a union arm, so
//! `sameNode` is the total order every set, cache and queue below orders and
//! looks up by. It is spelled once here so no two structures can disagree
//! about what "the same peer" means.
//!
//! The protocol-wide story — the `MessageId` rule, re-validation, the iTree,
//! purity, bounds and divergences — is in `../plumtree.zig`, which is the module
//! callers import. This file is one piece of it.

const key = @import("../../base/key.zig");

const NodeId = key.NodeId;

pub fn sameNode(a: NodeId, b: NodeId) bool {
    return a.order(b) == .eq;
}
