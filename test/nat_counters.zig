const std = @import("std");

const router_a = "router_alice\ncounter blocked_peer_udp { packets 2 bytes 3 }\n" ++
    "counter direct_peer_udp { packets 7 bytes 3 }\n" ++
    "counter masqueraded { packets 11 bytes 3 }\n";
const router_b = "router_bob\ncounter blocked_peer_udp { packets 3 bytes 3 }\n" ++
    "counter direct_peer_udp { packets 13 bytes 3 }\n" ++
    "counter masqueraded { packets 17 bytes 3 }\nalice\nbob\nwan\n";

test "snapshot summary sums exact counters from both routers" {
    const summary = try counters(router_a ++ router_b);
    try std.testing.expectEqual(@as(u64, 5), summary.blocked);
    try std.testing.expectEqual(@as(u64, 20), summary.direct);
    try std.testing.expectEqual(@as(u64, 28), summary.masqueraded);
}

test "snapshot summary rejects missing duplicate and overflowing counters" {
    try std.testing.expectError(error.InvalidCounterEvidence, counters(router_a));
    try std.testing.expectError(error.InvalidCounterEvidence,
        counters(router_a ++ "counter blocked_peer_udp { packets 9 }\n" ++ router_b));
    try std.testing.expectError(error.InvalidCounterEvidence,
        counters("router_alice\ncounter blocked_peer_udp { packets 18446744073709551615 }\n" ++
        "counter direct_peer_udp { packets 0 }\ncounter masqueraded { packets 0 }\n" ++ router_b));
    try std.testing.expectError(error.InvalidCounterEvidence,
        single("counter blocked_peer_udp { packets nope }", "blocked_peer_udp"));
}


pub const Counters = struct {
    blocked: u64,
    direct: u64,
    masqueraded: u64,
};

pub const Error = error{InvalidCounterEvidence};

pub fn counters(text: []const u8) Error!Counters {
    const alice_start = std.mem.indexOf(u8, text, "router_alice\n") orelse
        return error.InvalidCounterEvidence;
    const bob_start = std.mem.indexOfPos(u8, text, alice_start + 13, "router_bob\n") orelse
        return error.InvalidCounterEvidence;
    const routers_end = std.mem.indexOfPos(u8, text, bob_start + 11, "\nalice\n") orelse
        return error.InvalidCounterEvidence;
    const alice = text[alice_start..bob_start];
    const bob = text[bob_start..routers_end];
    return .{
        .blocked = try sum(alice, bob, "blocked_peer_udp"),
        .direct = try sum(alice, bob, "direct_peer_udp"),
        .masqueraded = try sum(alice, bob, "masqueraded"),
    };
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
    const body = text[start + marker.len..];
    const end = std.mem.indexOfScalar(u8, body, '}') orelse return error.InvalidCounterEvidence;
    var tokens = std.mem.tokenizeAny(u8, body[0..end], " \t\r\n");
    if (!std.mem.eql(u8, tokens.next() orelse return error.InvalidCounterEvidence, "packets"))
        return error.InvalidCounterEvidence;
    return std.fmt.parseInt(u64, tokens.next() orelse return error.InvalidCounterEvidence, 10) catch
        error.InvalidCounterEvidence;
}