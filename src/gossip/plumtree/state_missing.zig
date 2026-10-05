//! The table of messages this node does not have and the claims on them.
//!
//! An `IHave` claims a message for a peer; the claims on one id are the entry
//! that decides who gets grafted next, and the entry also carries the latch
//! saying a graft timer is owed against it. Draining an entry hands the claims
//! to the caller and forgets the entry, which is why the drained list is
//! copied rather than borrowed.
const claim_table = @import("claim_table.zig");
const limits = @import("limits.zig");
const message_id = @import("message_id.zig");
const tree = @import("state_tree.zig");

const Claim = claim_table.Claim;
const MissingEntry = claim_table.MissingEntry;
const Error = limits.Error;
const MessageId = message_id.MessageId;
const max_claims = limits.max_claims;
const max_missing = limits.max_missing;
const State = tree.State;

fn findMissing(self: *State, id: MessageId) ?*MissingEntry {
    for (self.missing_messages[0..self.missing_messages_len]) |*entry| {
        if (entry.id.eql(id)) return entry;
    }
    return null;
}

/// The entry the claim landed in, which is also the entry a graft timer is
/// owed against. It is handed back rather than looked up again because the
/// caller has just created or found it, so the write that follows cannot
/// miss; that is what lets the graft timer need no error of its own.
pub fn pushClaim(self: *State, id: MessageId, claim: Claim) Error!*MissingEntry {
    if (findMissing(self, id)) |entry| {
        if (entry.count == max_claims) return error.MissingTableFull;
        entry.peers[entry.count] = claim.peer;
        entry.rounds[entry.count] = claim.round;
        entry.count += 1;
        return entry;
    }
    if (self.missing_messages_len == max_missing) return error.MissingTableFull;
    const entry = &self.missing_messages[self.missing_messages_len];
    entry.id = id;
    entry.count = 1;
    entry.graft_timer_scheduled = false;
    entry.peers[0] = claim.peer;
    entry.rounds[0] = claim.round;
    self.missing_messages_len += 1;
    return entry;
}

/// Drain one id's claims into the caller's buffer and return the filled
/// part of it. The entry is gone after the call, so the list cannot borrow
/// it, and a buffer in this frame would be dead before `optimizeTree` is
/// done reading it.
pub fn takeMissing(self: *State, id: MessageId, storage: *[max_claims]Claim) ?[]const Claim {
    const index = missingIndex(self, id) orelse return null;
    const entry = &self.missing_messages[index];
    const count = entry.count;
    for (entry.peers[0..count], entry.rounds[0..count], 0..) |peer, round, at| {
        storage[at] = .{ .peer = peer, .round = round };
    }
    removeMissing(self, index);
    return storage[0..count];
}

/// Pop the front of one id's claim queue, which is the peer we graft next.
pub fn takeOldestClaim(self: *State, id: MessageId) ?Claim {
    const index = missingIndex(self, id) orelse return null;
    const entry = &self.missing_messages[index];
    const claim: Claim = .{ .peer = entry.peers[0], .round = entry.rounds[0] };
    var at: usize = 1;
    while (at < entry.count) : (at += 1) {
        entry.peers[at - 1] = entry.peers[at];
        entry.rounds[at - 1] = entry.rounds[at];
    }
    entry.count -= 1;
    if (entry.count == 0) removeMissing(self, index);
    return claim;
}

fn missingIndex(self: *State, id: MessageId) ?usize {
    for (self.missing_messages[0..self.missing_messages_len], 0..) |entry, index| {
        if (entry.id.eql(id)) return index;
    }
    return null;
}

fn removeMissing(self: *State, index: usize) void {
    @memmove(
        self.missing_messages[index .. self.missing_messages_len - 1],
        self.missing_messages[index + 1 .. self.missing_messages_len],
    );
    self.missing_messages_len -= 1;
}

pub fn forgetGraftTimer(self: *State, id: MessageId) void {
    const entry = findMissing(self, id) orelse return;
    entry.graft_timer_scheduled = false;
}
