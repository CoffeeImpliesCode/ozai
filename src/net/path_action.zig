//! Native path actions over copied observations. Candidate capacity is not
//! transport capability: only two initialized native slots can be actuated.
//! Authentication is supplied by the owner of the peer's candidate record;
//! merely discovering an address never authorizes sending a challenge to it.
const std = @import("std");
const addr = @import("../base/addr.zig");
const path_table = @import("path_table.zig");
const revalidate = @import("path_revalidate.zig");

pub const supported_paths: usize = 2;
pub const Key = struct {
    local: addr.SocketAddr,
    peer: addr.SocketAddr,

    pub fn eql(self: Key, other: Key) bool {
        return self.local.order(other.local) == .eq and self.peer.order(other.peer) == .eq;
    }
};
pub const Snapshot = struct {
    key: Key,
    validated: bool,
    selected: bool = false,
    probing: bool = false,
};
pub const Slots = [supported_paths]?Snapshot;
pub const Target = struct { id: u8, key: Key };
pub const Action = union(enum) {
    none,
    open: Key,
    probe: Target,
    select: Target,
    revalidate: Target,
};

/// Keys travel with IDs so an action planned before slot replacement cannot
/// accidentally challenge or select the replacement.
pub fn matches(target: Target, slots: *const Slots) bool {
    if (target.id >= supported_paths) return false;
    const snapshot = slots[target.id] orelse return false;
    return snapshot.key.eql(target.key);
}

fn find(key: Key, slots: *const Slots) ?Target {
    for (slots, 0..) |snapshot, id| {
        if (snapshot) |path| {
            if (path.key.eql(key)) return .{ .id = @intCast(id), .key = key };
        }
    }
    return null;
}

pub fn planOpen(
    local_addr: addr.SocketAddr,
    candidate: *const path_table.Entry,
    authenticated: bool,
    slots: *const Slots,
) Action {
    if (!authenticated or !candidate.dialable()) return .none;
    const peer_addr = switch (candidate.addr) {
        .ip => |value| value,
        .relay, .custom => return .none,
    };
    const key: Key = .{ .local = local_addr, .peer = peer_addr };
    if (find(key, slots) != null) return .none;
    for (slots) |snapshot| {
        if (snapshot == null) return .{ .open = key };
    }
    return .none;
}

pub fn planSelect(key: Key, slots: *const Slots) Action {
    for (slots, 0..) |snapshot, id| {
        const path = snapshot orelse continue;
        if (!path.key.eql(key)) continue;
        if (!path.validated or path.selected) return .none;
        return .{ .select = .{ .id = @intCast(id), .key = key } };
    }
    return .none;
}

pub fn planProbe(key: Key, slots: *const Slots) Action {
    for (slots, 0..) |snapshot, id| {
        const path = snapshot orelse continue;
        if (!path.key.eql(key)) continue;
        if (path.probing) return .none;
        return .{ .probe = .{ .id = @intCast(id), .key = key } };
    }
    return .none;
}

pub fn planRevalidate(
    candidate: *const path_table.Entry,
    now: path_table.Nanos,
    slots: *const Slots,
) Action {
    if (candidate.status != .open or revalidate.verdict(candidate, now) == .fresh) return .none;
    const peer_addr = switch (candidate.addr) {
        .ip => |value| value,
        .relay, .custom => return .none,
    };
    for (slots, 0..) |snapshot, id| {
        const path = snapshot orelse continue;
        if (path.selected and path.key.peer.order(peer_addr) == .eq and !path.probing) {
            return .{ .revalidate = .{ .id = @intCast(id), .key = path.key } };
        }
    }
    return .none;
}

const local: addr.SocketAddr = .{ .ip = .{ .v4 = .{ 192, 0, 2, 1 } }, .port = 4000 };
const peer: addr.SocketAddr = .{ .ip = .{ .v4 = .{ 192, 0, 2, 2 } }, .port = 4001 };

test "untrusted and recorded failed candidates cannot open native paths" {
    var candidate: path_table.Entry = .{ .addr = .{ .ip = peer }, .status = .unknown };
    const slots: Slots = .{ null, null };
    try std.testing.expect(planOpen(local, &candidate, false, &slots) == .none);
    candidate.status = .unusable;
    try std.testing.expect(planOpen(local, &candidate, true, &slots) == .none);
}

test "native two slot limit is not historical candidate capacity" {
    const candidate: path_table.Entry = .{ .addr = .{ .ip = peer }, .status = .unknown };
    const snapshot: Snapshot = .{ .key = .{ .local = local, .peer = local }, .validated = true };
    const slots: Slots = .{ snapshot, snapshot };
    try std.testing.expect(planOpen(local, &candidate, true, &slots) == .none);
    try std.testing.expectEqual(@as(usize, 2), supported_paths);
}

test "selection cannot promote unvalidated path and action identity detects reused slot" {
    const key: Key = .{ .local = local, .peer = peer };
    var slots: Slots = .{ null, .{ .key = key, .validated = false } };
    try std.testing.expect(planSelect(key, &slots) == .none);
    const selected_slot = if (slots[1]) |*snapshot| snapshot else return error.TestUnexpectedResult;
    selected_slot.validated = true;
    const action = planSelect(key, &slots);
    try std.testing.expect(action == .select);
    try std.testing.expect(matches(action.select, &slots));
    selected_slot.key.peer = local;
    try std.testing.expect(!matches(action.select, &slots));
    slots[1] = null;
    try std.testing.expect(!matches(action.select, &slots));
}

test "pending challenge prevents repeated probes while stale evidence requests revalidation" {
    const key: Key = .{ .local = local, .peer = peer };
    var slots: Slots = .{ .{ .key = key, .validated = true, .selected = true }, null };
    const entry: path_table.Entry = .{ .addr = .{ .ip = peer }, .status = .open, .rtt = 1 };
    try std.testing.expect(
        planRevalidate(&entry, revalidate.revalidate_after + 1, &slots) == .revalidate,
    );
    const probing_slot = if (slots[0]) |*snapshot| snapshot else return error.TestUnexpectedResult;
    probing_slot.probing = true;
    try std.testing.expect(planProbe(key, &slots) == .none);
    try std.testing.expect(
        planRevalidate(&entry, revalidate.revalidate_after + 1, &slots) == .none,
    );
}
