//! Pure connection-lifetime state for native multipath IDs 0 and 1.
//! The connection owns authentication, address validation, CIDs, and packet spaces.
//! Noq 1.3: connection/mod.rs 555-578, 625-707, 4383-4385, 7090-7092;
//! connection/paths.rs 994-999 specifies strictly increasing remote status sequences.

const std = @import("std");

/// Peer-advertised scheduling preference; it never proves address validation.
pub const Status = enum {
    /// Default until a peer advertises a different preference.
    available,
    backup,
};

/// Fixed record retained for the entire connection, including abandonment tombstones.
pub const Entry = struct {
    opened: bool = false,
    abandoned: bool = false,
    /// Only the connection's successful address-validation path may set this true.
    validated: bool = false,
    status: Status = .available,
    /// `null` means no peer status has arrived; sequence zero is a valid first update.
    status_seq: ?u64 = null,
};

/// Rejected operations leave state unchanged.
pub const Error = error{
    MultipathNotNegotiated,
    InvalidPathId,
    MaxPathIdReached,
    ServerSideNotAllowed,
    AlreadyOpen,
    ClosedPath,
    PathNotValidated,
};

/// Independent, allocation-free value initialized for an established initial path.
/// Construct once per connection; negotiation must never clear lifetime tombstones.
pub const State = struct {
    negotiated: bool = false,
    /// Effective sending ceiling: minimum of local and peer initial maximum IDs.
    peer_max_path_id: u32 = 0,
    /// Receive ceiling is local-only: peer ceiling updates may arrive out of order.
    local_max_path_id: u32 = 0,
    /// May name an abandoned path if none is usable; callers must gate data transmission.
    selected: u8 = 0,
    entries: [2]Entry = .{ .{ .opened = true, .validated = true }, .{} },

    fn negotiate(self: *State, local_max: ?u32, peer_max: ?u32) void {
        self.negotiated = local_max != null and peer_max != null;
        self.local_max_path_id = @min(@as(u32, 1), local_max orelse 0);
        self.peer_max_path_id = if (self.negotiated)
            @min(self.local_max_path_id, peer_max.?)
        else
            0;
    }

    fn open(self: *State, id: u32, is_server: bool) Error!void {
        try self.checkMultipath(id);
        if (is_server) return error.ServerSideNotAllowed;
        const entry = &self.entries[id];
        if (entry.abandoned) return error.ClosedPath;
        if (entry.opened) return error.AlreadyOpen;
        entry.opened = true;
    }

    fn accept(self: *State, id: u32) Error!void {
        try self.checkId(id);
        if (!self.negotiated) return error.MultipathNotNegotiated;
        if (id > self.local_max_path_id) return error.MaxPathIdReached;
        const entry = &self.entries[id];
        if (entry.abandoned) return error.ClosedPath;
        entry.opened = true;
    }

    fn select(self: *State, id: u32) Error!void {
        try self.checkMultipath(id);
        const entry = &self.entries[id];
        if (!entry.opened or entry.abandoned) return error.ClosedPath;
        if (!entry.validated) return error.PathNotValidated;
        self.selected = @intCast(id);
    }

    fn status(self: *State, id: u32, seq: u64, value: Status) Error!void {
        if (!self.negotiated) return error.MultipathNotNegotiated;
        if (id >= self.entries.len) return;
        const entry = &self.entries[id];
        if (!entry.opened or entry.abandoned) return;
        if (entry.status_seq) |previous| {
            if (seq <= previous) return;
        }
        entry.status_seq = seq;
        entry.status = value;
    }

    fn abandon(self: *State, id: u32) Error!void {
        if (!self.negotiated) return error.MultipathNotNegotiated;
        // Remote abandonment of unknown or already closed paths is idempotent.
        // Sending credit applies to opening a path, not to this notification.
        if (id >= self.entries.len or id > self.local_max_path_id) return;
        const entry = &self.entries[id];
        if (!entry.opened or entry.abandoned) return;
        entry.abandoned = true;
        entry.validated = false;
        if (self.selected == id) {
            const other: u8 = @as(u8, @intCast(id)) ^ 1;
            const replacement = &self.entries[other];
            if (other <= self.peer_max_path_id and replacement.opened and
                !replacement.abandoned and replacement.validated)
            {
                self.selected = other;
            }
        }
    }

    fn checkId(self: *const State, id: u32) Error!void {
        if (id >= self.entries.len) return error.InvalidPathId;
    }

    fn checkMultipath(self: *const State, id: u32) Error!void {
        try self.checkId(id);
        if (!self.negotiated) return error.MultipathNotNegotiated;
        if (id > self.peer_max_path_id) return error.MaxPathIdReached;
    }
};

/// Authenticated and decoded input supplied by the connection owner.
pub const Event = union(enum) {
    /// Call after handshake; either absent parameter disables MP without clearing tombstones.
    negotiate: struct { local_max: ?u32, peer_max: ?u32 },
    open: struct { id: u32, is_server: bool },
    /// Server-only authenticated packet acceptance, not address validation.
    accept: u32,
    select: u32,
    /// Peer preference never proves validation; stale/unknown/abandoned updates are ignored.
    status: struct { id: u32, seq: u64, value: Status },
    /// Remote last-path abandonment is allowed; local policy and timers live in the connection.
    abandon: u32,
    /// Address-validation outcome, not a packet-authentication outcome.
    validated: struct { id: u32, value: bool },
};

/// Returns an independent new state; the input is unchanged on success or error.
/// Requires negotiated MP except negotiation; ordinary QUIC selection is outside this helper.
pub fn process(state: State, event: Event) Error!State {
    var next = state;
    switch (event) {
        .negotiate => |value| next.negotiate(value.local_max, value.peer_max),
        .open => |value| try next.open(value.id, value.is_server),
        .accept => |id| try next.accept(id),
        .select => |id| try next.select(id),
        .status => |value| try next.status(value.id, value.seq, value.value),
        .abandon => |id| try next.abandon(id),
        .validated => |value| {
            try next.checkId(value.id);
            if (!next.negotiated) return error.MultipathNotNegotiated;
            const entry = &next.entries[value.id];
            if (!entry.opened or entry.abandoned) return error.ClosedPath;
            entry.validated = value.value;
        },
    }
    return next;
}

test "absent MP fails closed and processing never changes its input" {
    const initial: State = .{};
    const state = try process(initial, .{ .negotiate = .{ .local_max = null, .peer_max = 1 } });
    try std.testing.expect(!state.negotiated);
    try std.testing.expectError(error.MultipathNotNegotiated, process(state, .{ .select = 0 }));
    try std.testing.expectError(error.MultipathNotNegotiated, process(state,
        .{ .open = .{ .id = 1, .is_server = false } }));
    try std.testing.expectError(error.MultipathNotNegotiated, process(state, .{ .accept = 1 }));
    try std.testing.expectError(error.MultipathNotNegotiated, process(state,
        .{ .status = .{ .id = 0, .seq = 0, .value = .backup } }));
    try std.testing.expectError(error.MultipathNotNegotiated, process(state, .{ .abandon = 0 }));
    const missing_peer = try process(initial,
        .{ .negotiate = .{ .local_max = 1, .peer_max = null } });
    try std.testing.expect(!missing_peer.negotiated);
    try std.testing.expect(!initial.entries[1].opened);
}

test "sending and authenticated receiving use independent negotiated ceilings" {
    var state = try process(.{}, .{ .negotiate = .{ .local_max = 0, .peer_max = 1 } });
    try std.testing.expect(state.negotiated);
    try std.testing.expectError(error.MaxPathIdReached, process(state,
        .{ .open = .{ .id = 1, .is_server = false } }));
    try std.testing.expectError(error.MaxPathIdReached, process(state, .{ .accept = 1 }));
    state = try process(state, .{ .negotiate = .{ .local_max = 1, .peer_max = 0 } });
    state = try process(state, .{ .accept = 1 });
    try std.testing.expect(!state.entries[1].validated);
    try std.testing.expectError(error.MaxPathIdReached, process(state, .{ .select = 1 }));
    state = try process(.{}, .{ .negotiate = .{ .local_max = 9, .peer_max = 7 } });
    try std.testing.expectEqual(@as(u32, 1), state.peer_max_path_id);
    try std.testing.expectError(error.InvalidPathId, process(state,
        .{ .open = .{ .id = 2, .is_server = false } }));
    state = try process(state, .{ .open = .{ .id = 1, .is_server = false } });
    try std.testing.expectError(error.AlreadyOpen, process(state,
        .{ .open = .{ .id = 1, .is_server = false } }));
}

test "client initiation and server acceptance require separate address validation" {
    var state = try process(.{}, .{ .negotiate = .{ .local_max = 1, .peer_max = 1 } });
    try std.testing.expectError(error.ServerSideNotAllowed, process(state,
        .{ .open = .{ .id = 1, .is_server = true } }));
    try std.testing.expectError(error.ClosedPath, process(state, .{ .select = 1 }));
    try std.testing.expectError(error.ClosedPath, process(state,
        .{ .validated = .{ .id = 1, .value = true } }));
    state = try process(state, .{ .accept = 1 });
    state = try process(state, .{ .accept = 1 });
    try std.testing.expectError(error.PathNotValidated, process(state, .{ .select = 1 }));
    state = try process(state, .{ .validated = .{ .id = 1, .value = true } });
    state = try process(state, .{ .select = 1 });
    try std.testing.expectEqual(@as(u8, 1), state.selected);
}

test "remote status accepts first zero and ignores stale duplicate unknown updates" {
    var state = try process(.{}, .{ .negotiate = .{ .local_max = 1, .peer_max = 1 } });
    state = try process(state, .{ .status = .{ .id = 99, .seq = 0, .value = .backup } });
    state = try process(state, .{ .status = .{ .id = 1, .seq = 0, .value = .backup } });
    try std.testing.expectEqual(@as(?u64, null), state.entries[1].status_seq);
    state = try process(state, .{ .open = .{ .id = 1, .is_server = false } });
    state = try process(state, .{ .status = .{ .id = 1, .seq = 0, .value = .backup } });
    state = try process(state, .{ .status = .{ .id = 1, .seq = 0, .value = .available } });
    try std.testing.expectEqual(Status.backup, state.entries[1].status);
    state = try process(state, .{ .status = .{ .id = 1, .seq = 3, .value = .available } });
    state = try process(state, .{ .status = .{ .id = 1, .seq = 2, .value = .backup } });
    try std.testing.expectEqual(Status.available, state.entries[1].status);
    try std.testing.expectEqual(@as(?u64, 3), state.entries[1].status_seq);
    try std.testing.expect(!state.entries[1].validated);
}

test "abandonment is permanent and never invents a validated replacement" {
    var state = try process(.{}, .{ .negotiate = .{ .local_max = 1, .peer_max = 1 } });
    state = try process(state, .{ .open = .{ .id = 1, .is_server = false } });
    state = try process(state, .{ .abandon = 0 });
    try std.testing.expectEqual(@as(u8, 0), state.selected);
    try std.testing.expectError(error.PathNotValidated, process(state, .{ .select = 1 }));
    state = try process(state, .{ .validated = .{ .id = 1, .value = true } });
    state = try process(state, .{ .select = 1 });
    state = try process(state, .{ .abandon = 1 });
    state = try process(state, .{ .negotiate = .{ .local_max = 1, .peer_max = 1 } });
    try std.testing.expectError(error.ClosedPath, process(state,
        .{ .open = .{ .id = 1, .is_server = false } }));
    try std.testing.expectError(error.ClosedPath, process(state, .{ .accept = 1 }));
    try std.testing.expectError(error.ClosedPath, process(state, .{ .select = 1 }));
    try std.testing.expectError(error.ClosedPath, process(state,
        .{ .validated = .{ .id = 1, .value = true } }));
    state = try process(state, .{ .status = .{ .id = 1, .seq = 4, .value = .available } });
    try std.testing.expectEqual(@as(?u64, null), state.entries[1].status_seq);
    try std.testing.expectEqualDeep(state, try process(state, .{ .abandon = 1 }));
}

test "negotiation clamps to implemented two paths" {
    const state = try process(.{}, .{
        .negotiate = .{ .local_max = 99, .peer_max = 88 },
    });
    try std.testing.expectEqual(@as(u32, 1), state.local_max_path_id);
    try std.testing.expectEqual(@as(u32, 1), state.peer_max_path_id);
}

test "remote abandon ignores unopened duplicate and unknown paths independently of sending credit" {
    const state = try process(.{}, .{ .negotiate = .{ .local_max = 1, .peer_max = 0 } });
    try std.testing.expectEqualDeep(state, try process(state, .{ .abandon = 1 }));
    const closed = try process(state, .{ .abandon = 0 });
    try std.testing.expectEqualDeep(closed, try process(closed, .{ .abandon = 0 }));
    const bounded = try process(.{}, .{ .negotiate = .{ .local_max = 0, .peer_max = 1 } });
    try std.testing.expectEqualDeep(bounded, try process(bounded, .{ .abandon = 1 }));
    try std.testing.expectEqualDeep(state, try process(state, .{ .abandon = 2 }));
}
