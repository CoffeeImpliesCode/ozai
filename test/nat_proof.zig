const std = @import("std");

pub const Proof = struct {
    stable_id: u64,
    remote_id: []const u8,
    direct: bool,
};

// Proof parsing must not open forwarding for prefixes, partial lines, or wrong bytes.
test "phase proof requires exact route pin payload and stable identity" {
    const pin = "0d7550754e0800a5d237eef5826035766b9b3e5a15868a940ab289958788e3b0";
    const line = "relay-phase1: stable_id 42 remote_id " ++ pin ++
        " selected relay bytes 2 payload_hex 6869";
    const first = try parse(line, .{ .phase = 1, .pin = pin, .message = "hi" });
    try std.testing.expectEqual(@as(u64, 42), first.stable_id);
    try std.testing.expectError(
        error.InvalidProof,
        parse(line, .{ .phase = 2, .pin = pin, .message = "hi" }),
    );
    try std.testing.expectError(
        error.InvalidProof,
        parse(line, .{ .phase = 1, .pin = pin, .message = "ho" }),
    );
    try std.testing.expectError(
        error.InvalidProof,
        parse(line ++ " extra", .{ .phase = 1, .pin = pin, .message = "hi" }),
    );
    try std.testing.expectError(
        error.IdentityChanged,
        same(first, .{ .stable_id = 43, .remote_id = pin, .direct = true }),
    );
}

pub fn parse(line: []const u8, expected: struct {
    phase: u8,
    pin: []const u8,
    message: []const u8,
}) error{InvalidProof}!Proof {
    var words = std.mem.splitScalar(u8, line, ' ');
    const phase = if (expected.phase == 1) "relay-phase1:" else "relay-phase2:";
    try word(&words, phase);
    try word(&words, "stable_id");
    const stable_id = std.fmt.parseInt(
        u64,
        words.next() orelse return error.InvalidProof,
        10,
    ) catch return error.InvalidProof;
    try word(&words, "remote_id");
    const remote_id = words.next() orelse return error.InvalidProof;
    if (!std.mem.eql(u8, remote_id, expected.pin)) return error.InvalidProof;
    try word(&words, "selected");
    try word(&words, if (expected.phase == 1) "relay" else "direct");
    try word(&words, "bytes");
    const size = std.fmt.parseInt(
        usize,
        words.next() orelse return error.InvalidProof,
        10,
    ) catch return error.InvalidProof;
    if (size != expected.message.len) return error.InvalidProof;
    try word(&words, "payload_hex");
    const payload = words.next() orelse return error.InvalidProof;
    if (payload.len != expected.message.len * 2) return error.InvalidProof;
    const hex = "0123456789abcdef";
    for (expected.message, 0..) |byte, index| {
        if (payload[index * 2] != hex[byte >> 4] or
            payload[index * 2 + 1] != hex[byte & 15]) return error.InvalidProof;
    }
    if (words.next() != null) return error.InvalidProof;
    return .{ .stable_id = stable_id, .remote_id = remote_id, .direct = expected.phase == 2 };
}

fn word(words: *std.mem.SplitIterator(u8, .scalar), expected: []const u8) error{InvalidProof}!void {
    if (!std.mem.eql(u8, words.next() orelse return error.InvalidProof, expected))
        return error.InvalidProof;
}

pub fn same(first: Proof, second: Proof) error{IdentityChanged}!void {
    if (first.stable_id != second.stable_id or
        !std.mem.eql(u8, first.remote_id, second.remote_id)) return error.IdentityChanged;
    if (first.direct or !second.direct) return error.IdentityChanged;
}

pub const Scan = struct {
    offset: usize = 0,
    phase1: ?Proof = null,
    phase2: ?Proof = null,
    counts: ?Counts = null,

    pub fn consume(
        self: *Scan,
        bytes: []const u8,
        pin: []const u8,
        message: []const u8,
    ) error{ InvalidProof, IdentityChanged, DuplicateProof }!void {
        while (self.offset < bytes.len) {
            const end = std.mem.indexOfScalarPos(u8, bytes, self.offset, '\n') orelse break;
            const line = bytes[self.offset..end];
            self.offset = end + 1;
            if (std.mem.startsWith(u8, line, "relay-phase1:")) {
                if (self.phase1 != null) return error.DuplicateProof;
                self.phase1 = try parse(line, .{ .phase = 1, .pin = pin, .message = message });
            } else if (std.mem.startsWith(u8, line, "relay-phase2:")) {
                if (self.phase2 != null) return error.DuplicateProof;
                const second = try parse(line, .{ .phase = 2, .pin = pin, .message = message });
                try same(self.phase1 orelse return error.InvalidProof, second);
                self.phase2 = second;
            } else if (std.mem.startsWith(u8, line, "relay-counts:")) {
                if (self.counts != null) return error.DuplicateProof;
                if (self.phase2 == null) return error.InvalidProof;
                self.counts = try parseCounts(line);
            }
        }
    }
};

pub const Counts = struct {
    dials: u32,
    accepts: u32,

    pub fn validate(self: Counts, server: bool) error{InvalidProof}!void {
        if (self.dials != @intFromBool(!server) or
            self.accepts != @intFromBool(server)) return error.InvalidProof;
    }
};

test "connection counts reject a second actual connection and extra fields" {
    try (try parseCounts("relay-counts: dials 1 accepts 0")).validate(false);
    try std.testing.expectError(
        error.InvalidProof,
        (try parseCounts("relay-counts: dials 2 accepts 0")).validate(false),
    );
    try std.testing.expectError(
        error.InvalidProof,
        parseCounts("relay-counts: dials 1 accepts 0 extra"),
    );
}

fn parseCounts(line: []const u8) error{InvalidProof}!Counts {
    var words = std.mem.splitScalar(u8, line, ' ');
    try word(&words, "relay-counts:");
    try word(&words, "dials");
    const dials = std.fmt.parseInt(
        u32,
        words.next() orelse return error.InvalidProof,
        10,
    ) catch return error.InvalidProof;
    try word(&words, "accepts");
    const accepts = std.fmt.parseInt(
        u32,
        words.next() orelse return error.InvalidProof,
        10,
    ) catch return error.InvalidProof;
    if (words.next() != null) return error.InvalidProof;
    return .{ .dials = dials, .accepts = accepts };
}

test "partial proof lines cannot trigger phase and repeated phase is rejected" {
    const pin = "0d7550754e0800a5d237eef5826035766b9b3e5a15868a940ab289958788e3b0";
    const line = "relay-phase1: stable_id 42 remote_id " ++ pin ++
        " selected relay bytes 2 payload_hex 6869";
    var scan: Scan = .{};
    try scan.consume(line, pin, "hi");
    try std.testing.expect(scan.phase1 == null);
    try scan.consume(line ++ "\n", pin, "hi");
    try std.testing.expect(scan.phase1 != null);
    try std.testing.expectError(
        error.DuplicateProof,
        scan.consume(line ++ "\n" ++ line ++ "\n", pin, "hi"),
    );
}
