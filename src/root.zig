//! ozai — dial a node by its id, not its address.
//!
//! This is the library root. It re-exports the pure value layer and is the only
//! module an importer needs to name.
//!
//! Scope, as of the first milestone: identity and addressing only. Everything
//! that touches a socket is deliberately absent until the transport substrate
//! is settled — see `docs/PLAN.md`.

const std = @import("std");

pub const base32 = @import("base/base32.zig");
pub const key = @import("base/key.zig");
pub const addr = @import("base/addr.zig");

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

test {
    // Reference every declaration so an unused module still type-checks. Zig
    // 0.16 dropped `refAllDeclsRecursive`; the roots are named explicitly.
    std.testing.refAllDecls(@This());
    std.testing.refAllDecls(base32);
    std.testing.refAllDecls(key);
    std.testing.refAllDecls(addr);
}
