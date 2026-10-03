//! Integration tests: the public `ozai` surface, exercised the way a consumer
//! would use it rather than through `src/base/*` internals.
//!
//! These live outside `src/` because Zig only runs the test blocks a root file
//! reaches; a test that never gets referenced is not a test.

const std = @import("std");
const ozai = @import("ozai");

const t = std.testing;

test "a node id is the same identity in hex, z32 and local tls name" {
    var secret = try ozai.SecretKey.fromSeed([_]u8{0} ** ozai.SecretKey.seed_length);
    defer secret.deinit();
    const node_id = secret.nodeId();

    try t.expectEqual(node_id, try ozai.NodeId.parseHex(&node_id.toHex()));
    try t.expectEqual(node_id, try ozai.NodeId.parseZ32(&node_id.toZ32()));
    try t.expectEqual(node_id, try ozai.NodeId.parseLocalTlsName(&node_id.toLocalTlsName()));
}

test "a signed address verifies at the far end and nothing else does" {
    // The shape of a ticket before tickets exist: an address, signed by the node
    // that owns it. Both halves are what a relay or a peer will check.
    var secret = try ozai.SecretKey.fromSeed([_]u8{42} ** ozai.SecretKey.seed_length);
    defer secret.deinit();

    const alloc = t.allocator;
    var address = try ozai.NodeAddr.withRelay(
        alloc,
        secret.nodeId(),
        try ozai.RelayUrl.parse("https://use1-1.relay.iroh.network./"),
    );
    defer address.deinit(alloc);
    const host = ozai.IpAddress.parse("192.0.2.7") orelse return error.TestUnexpectedResult;
    const direct: ozai.TransportAddr = .{ .ip = .{ .ip = host, .port = 41641 } };
    address = (try address.insert(alloc, direct)) orelse
        return error.TestUnexpectedResult;

    var buffer: [256]u8 = undefined;
    const payload = try std.fmt.bufPrint(&buffer, "{f}", .{address});

    const signature = secret.sign(payload);
    try signature.verify(payload, address.node_id);

    // A different address string, signed by the same key, must not verify.
    try t.expectError(error.BadSignature, signature.verify("192.0.2.8", address.node_id));
    // The right address, under the wrong key, must not verify either.
    try t.expectError(
        error.BadSignature,
        signature.verify(payload, (try ozai.NodeId.fromBytes([_]u8{1} ** 32))),
    );
}

test "an address renders to the same text every time" {
    // The property that makes a ticket a stable identifier: the same address
    // must always print the same bytes, whatever order it was built in.
    var secret = try ozai.SecretKey.fromSeed([_]u8{7} ** ozai.SecretKey.seed_length);
    defer secret.deinit();
    const node_id = secret.nodeId();

    const alloc = t.allocator;
    const relay = try ozai.RelayUrl.parse("https://derp.example./");
    const host = ozai.IpAddress.parse("127.0.0.1") orelse return error.TestUnexpectedResult;
    const direct: ozai.TransportAddr = .{ .ip = .{ .ip = host, .port = 1024 } };

    // The same two addresses, inserted in opposite orders.
    var relay_first = ozai.NodeAddr.init(node_id);
    defer relay_first.deinit(alloc);
    relay_first = (try relay_first.insert(alloc, .{ .relay = relay })) orelse
        return error.TestUnexpectedResult;
    relay_first = (try relay_first.insert(alloc, direct)) orelse
        return error.TestUnexpectedResult;

    var ip_first = ozai.NodeAddr.init(node_id);
    defer ip_first.deinit(alloc);
    ip_first = (try ip_first.insert(alloc, direct)) orelse
        return error.TestUnexpectedResult;
    ip_first = (try ip_first.insert(alloc, .{ .relay = relay })) orelse
        return error.TestUnexpectedResult;

    var buffer: [256]u8 = undefined;
    const from_relay = try std.fmt.bufPrint(&buffer, "{f}", .{relay_first});

    var second: [256]u8 = undefined;
    const from_ip = try std.fmt.bufPrint(&second, "{f}", .{ip_first});

    // Insertion order must not change the bytes: relay sorts before ip by
    // variant, so it lands first either way. This is what lets a ticket be an
    // identifier rather than a fresh value on every send.
    try t.expectEqualStrings(from_relay, from_ip);
    try t.expect(std.mem.indexOf(u8, from_relay, "relay:https://derp.example./") != null);
    try t.expect(std.mem.indexOf(u8, from_relay, "ip:127.0.0.1:1024") != null);
}
