const std = @import("std");

const router_a = "router_alice\ncounter translated { packets 11 bytes 3 }\n";
const router_b = "router_bob\ncounter translated { packets 17 bytes 3 }\n";
const peers = "alice\nbob\nwan\n";
const wan_gate = "table bridge ozai_wan {\n" ++
    "counter blocked_peer_udp { packets 5 bytes 320 }\n" ++
    "counter direct_peer_udp { packets 20 bytes 1280 }\n}\n";

test "snapshot summary reads WAN gate counters and sums router source NAT counters" {
    const summary = try counters(router_a ++ router_b ++ peers ++ wan_gate);
    try std.testing.expectEqual(@as(u64, 5), summary.blocked);
    try std.testing.expectEqual(@as(u64, 20), summary.direct);
    try std.testing.expectEqual(@as(u64, 28), summary.translated);
}

test "snapshot summary rejects missing duplicate and misplaced counters" {
    for ([_][]const u8{
        router_a ++ router_b ++ peers,
        router_a ++ peers ++ wan_gate,
        router_a ++ router_b ++ peers ++
            "counter blocked_peer_udp { packets 5 bytes 320 }\n",
        router_a ++ router_b ++ peers ++ wan_gate ++
            "counter blocked_peer_udp { packets 9 bytes 0 }\n",
        router_a ++ router_b ++ peers ++ wan_gate ++
            "counter direct_peer_udp { packets 9 bytes 0 }\n",
        router_a ++ "counter translated { packets 9 bytes 0 }\n" ++
            router_b ++ peers ++ wan_gate,
        "router_alice\n" ++ router_b ++ peers ++ wan_gate,
        router_a ++ "router_bob\n" ++ peers ++ wan_gate,
        router_a ++ "counter blocked_peer_udp { packets 9 bytes 0 }\n" ++
            router_b ++ peers ++ wan_gate,
        router_a ++ router_b ++ peers ++ wan_gate ++
            "counter translated { packets 9 bytes 0 }\n",
        router_a ++ router_b ++ peers ++ "table bridge ozai_wan {\n" ++
            "counter blocked_peer_udp { packets 5 bytes 320 }\n}\n",
        router_a ++ router_b ++ peers ++ "table bridge ozai_wan {\n" ++
            "counter direct_peer_udp { packets 20 bytes 1280 }\n}\n",
        router_a ++ router_b ++ peers ++ "table bridge ozai_wan {\n" ++
            "counter blocked_peer_udp { packets nope bytes 320 }\n" ++
            "counter direct_peer_udp { packets 20 bytes 1280 }\n}\n",
        "router_alice\ncounter translated { packets 11 bytes nope }\n" ++
            router_b ++ peers ++ wan_gate,
        router_a ++ router_b ++ peers ++ wan_gate ++ "wan\n",
        router_a ++ router_b ++ peers ++ wan_gate ++ "table bridge ozai_wan {\n}\n",
    }) |text| {
        try std.testing.expectError(error.InvalidCounterEvidence, counters(text));
    }
}

test "snapshot summary rejects overflowing translation totals" {
    try std.testing.expectError(
        error.InvalidCounterEvidence,
        counters(
            "router_alice\ncounter translated { packets 18446744073709551615 bytes 0 }\n" ++
                router_b ++ peers ++ wan_gate,
        ),
    );
}

test "named counters reject malformed packet and byte evidence" {
    for ([_][]const u8{
        "counter blocked_peer_udp { packets nope bytes 0 }",
        "counter blocked_peer_udp { packets 18446744073709551616 bytes 0 }",
        "counter blocked_peer_udp { packets 1 }",
        "counter blocked_peer_udp { packets 1 bytes nope }",
        "counter blocked_peer_udp { packets 1 bytes 18446744073709551616 }",
        "counter blocked_peer_udp { packets 1 bytes 0 packets 2 }",
        "counter blocked_peer_udp { packets 1 bytes 0",
        "counter blocked_peer_udp { bytes 0 packets 1 }",
        "counter blocked_peer_udp { packets -1 bytes 0 }",
        "counter blocked_peer_udp { packets +1 bytes 0 }",
    }) |text| {
        try std.testing.expectError(error.InvalidCounterEvidence, single(text, "blocked_peer_udp"));
    }
}

pub const Counters = struct {
    /// Candidate WAN frames dropped at the shared post-SNAT bridge gate.
    blocked: u64,
    /// Candidate WAN frames accepted at that same physical gate.
    direct: u64,
    /// First UDP packets source-translated in the two routers' NAT hooks.
    translated: u64,
};

pub const Error = error{InvalidCounterEvidence};

pub fn counters(text: []const u8) Error!Counters {
    const alice_start = try uniqueMarker(text, "router_alice\n");
    const bob_start = try uniqueMarker(text, "router_bob\n");
    const routers_end = try uniqueMarker(text, "\nalice\n");
    const bob_peer = try uniqueMarker(text, "\nbob\n");
    const wan_start = try uniqueMarker(text, "\nwan\n");
    const gate_start = try uniqueMarker(text, "table bridge ozai_wan {");
    if (alice_start != 0 or bob_start <= alice_start or routers_end <= bob_start or
        bob_peer <= routers_end or wan_start <= bob_peer or gate_start <= wan_start)
        return error.InvalidCounterEvidence;
    const alice = text[alice_start..bob_start];
    const bob = text[bob_start..routers_end];
    const gate = text[gate_start..];
    // Old router gate counters must not masquerade as bridge evidence.
    const blocked = try single(gate, "blocked_peer_udp");
    const direct = try single(gate, "direct_peer_udp");
    if (try single(text, "blocked_peer_udp") != blocked or
        try single(text, "direct_peer_udp") != direct or
        std.mem.indexOf(u8, text[routers_end..], "counter translated") != null)
        return error.InvalidCounterEvidence;
    return .{
        .blocked = blocked,
        .direct = direct,
        .translated = try sum(alice, bob, "translated"),
    };
}

fn uniqueMarker(text: []const u8, marker: []const u8) Error!usize {
    const start = std.mem.indexOf(u8, text, marker) orelse return error.InvalidCounterEvidence;
    if (std.mem.indexOfPos(u8, text, start + marker.len, marker) != null)
        return error.InvalidCounterEvidence;
    return start;
}

fn sum(alice: []const u8, bob: []const u8, name: []const u8) Error!u64 {
    return std.math.add(u64, try single(alice, name), try single(bob, name)) catch
        error.InvalidCounterEvidence;
}

pub fn single(text: []const u8, name: []const u8) Error!u64 {
    var marker_buffer: [128]u8 = undefined;
    const marker = std.fmt.bufPrint(&marker_buffer, "counter {s} {{", .{name}) catch
        return error.InvalidCounterEvidence;
    const start = std.mem.indexOf(u8, text, marker) orelse return error.InvalidCounterEvidence;
    if (std.mem.indexOfPos(u8, text, start + marker.len, marker) != null)
        return error.InvalidCounterEvidence;
    const body = text[start + marker.len ..];
    const end = std.mem.indexOfScalar(u8, body, '}') orelse return error.InvalidCounterEvidence;
    var tokens = std.mem.tokenizeAny(u8, body[0..end], " \t\r\n");
    if (!std.mem.eql(u8, tokens.next() orelse return error.InvalidCounterEvidence, "packets"))
        return error.InvalidCounterEvidence;
    const packets = try decimal(tokens.next() orelse return error.InvalidCounterEvidence);
    if (!std.mem.eql(u8, tokens.next() orelse return error.InvalidCounterEvidence, "bytes"))
        return error.InvalidCounterEvidence;
    _ = try decimal(tokens.next() orelse return error.InvalidCounterEvidence);
    if (tokens.next() != null) return error.InvalidCounterEvidence;
    return packets;
}

fn decimal(text: []const u8) Error!u64 {
    if (text.len == 0) return error.InvalidCounterEvidence;
    for (text) |byte| {
        if (byte < '0' or byte > '9') return error.InvalidCounterEvidence;
    }
    return std.fmt.parseInt(u64, text, 10) catch error.InvalidCounterEvidence;
}
