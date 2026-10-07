//! Initialized native path snapshots and bounded policy actuation.
//! The bridge owns slot initialization; historical address-pair folding lives
//! in multipath.zig and never reads native arrays.

const std = @import("std");
const path_action = @import("../net/path_action.zig");
const bridge_config = @import("bridge_config.zig");
const bridge_conn = @import("bridge_conn.zig");
const multipath = @import("multipath.zig");

pub const ActionError = bridge_conn.PathError || error{StalePath};

/// Copies only initialized bridge snapshots; there is no native-array read.
pub fn actionSlots(conn: bridge_conn.Conn) path_action.Slots {
    var slots: path_action.Slots = .{ null, null };
    for (0..path_action.supported_paths) |index| {
        const snapshot = conn.pathSnapshot(@intCast(index)) orelse continue;
        const local = snapshot.local orelse continue;
        const peer = snapshot.peer orelse continue;
        slots[index] = .{
            .key = .{ .local = local, .peer = peer },
            .validated = snapshot.validated,
            .selected = snapshot.selected,
            .probing = snapshot.state == .pending,
        };
    }
    return slots;
}

/// The caller owns candidate provenance, connection lifetime, clock and entropy.
pub fn applyAction(
    conn: bridge_conn.Conn,
    action: path_action.Action,
    at: bridge_config.Instant,
    random: std.Random,
) ActionError!?u8 {
    switch (action) {
        .none => return null,
        .open => |key| return try conn.openPath(key.local, key.peer, at, random),
        .probe, .select, .revalidate => |target| {
            const slots = actionSlots(conn);
            if (!path_action.matches(target, &slots)) return error.StalePath;
            switch (action) {
                .select => {
                    if (path_action.planSelect(target.key, &slots) == .none) return null;
                    try conn.selectPath(target.id);
                },
                .probe, .revalidate => {
                    if (path_action.planProbe(target.key, &slots) == .none) return null;
                    try conn.probePath(target.id, at, random);
                },
                .none, .open => unreachable,
            }
            return null;
        },
    }
}

/// Feeds both initialized slots, including a non-selected candidate, to history.
pub fn mirror(
    table: *multipath.Table,
    conn: bridge_conn.Conn,
    at: bridge_config.Instant,
) multipath.Mirror {
    table.conn = conn.id();
    var observations: multipath.Observations = .{ null, null };
    for (0..path_action.supported_paths) |index| {
        const id: u8 = @intCast(index);
        const snapshot = conn.pathSnapshot(id) orelse continue;
        const local = snapshot.local orelse continue;
        const peer = snapshot.peer orelse continue;
        observations[index] = .{
            .key = .{ .local = local, .peer = peer },
            .report = .{
                .slot = id,
                .validated = snapshot.validated,
                .state = snapshot.state,
                .sent = snapshot.sent,
                .received = snapshot.received,
            },
        };
    }
    return table.mirrorObservations(&observations, at);
}
