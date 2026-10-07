//! Decoded events and actions for the bounded Noq state transition boundary.
const Address = @import("../address.zig").Address;
pub const Challenge = struct { address: Address, token: [8]u8 };
pub const Candidate = struct { sequence: u64, address: Address };
pub const Event = union(enum) {
    /// Caller lifts actual socket capability; admission/provenance stays caller-owned.
    configure: struct { supported_ipv6: bool },
    cancel,
    /// Use only after real direct-path validation, never for an off-path response.
    directValidated,
    /// Check immediately before packet allocation; commit recordProbe without intervening events.
    preflightProbe: Address,
    add: Address,
    remove: Address,
    receiveAdd: struct { sequence: u64, address: Address },
    receiveRemove: u64,
    initiate: i64,
    receiveReach: struct { round: u64, address: Address, now: i64 },
    nextProbe: i64,
    recordProbe: Challenge,
    recordChallenge: Challenge,
    response: Challenge,
};
pub const Result = union(enum) { none, sequence: ?u64, probe: ?Address, matched: bool, ready: bool };
