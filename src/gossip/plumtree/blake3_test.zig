//! The `MessageId` rule, checked against BLAKE3's published vectors
//! rather than against this implementation's own output.

const std = @import("std");
const wire = @import("message.zig");
const message_id = @import("message_id.zig");
const vectors = @import("blake3_vectors.zig");

const t = std.testing;

const Gossip = wire.Gossip;
const Round = wire.Round;
const MessageId = message_id.MessageId;
const domainSeparatedId = message_id.domainSeparatedId;
const blake3Input = vectors.blake3Input;
const blake3_vectors = vectors.blake3_vectors;
const messageIdFromHex = vectors.messageIdFromHex;

// A `MessageId` is the plain BLAKE3 hash of the content, checked against the
// published vectors rather than against this implementation's own output.
test "a message id is blake3 of the content, and nothing else" {
    for (blake3_vectors) |vector| {
        const input = try blake3Input(vector.len);
        defer t.allocator.free(input);
        try t.expectEqualStrings(vector.hash, &std.fmt.bytesToHex(
            MessageId.fromContent(input).toBytes(),
            .lower,
        ));
        try t.expect(messageIdFromHex(vector.hash).eql(MessageId.fromContent(input)));
        try t.expect(!messageIdFromHex(vector.derive_key).eql(MessageId.fromContent(input)));
    }
}

// The failure this module is most likely to suffer: an id computed under a
// context string. It is a different value for the same content, so it is not
// an id, and a message carrying one is dropped.
test "a domain-separated id is not a message id" {
    const content = try blake3Input(2);
    defer t.allocator.free(content);
    const context = "BLAKE3 2019-12-27 16:29:52 test vectors context";
    const separated = domainSeparatedId(context, content);
    try t.expect(!MessageId.fromContent(content).eql(separated));

    for (blake3_vectors) |vector| {
        const input = try blake3Input(vector.len);
        defer t.allocator.free(input);
        const wrong = messageIdFromHex(vector.derive_key);
        const gossip: Gossip = .{
            .id = wrong,
            .content = input,
            .scope = .{ .swarm = Round.zero },
        };
        try t.expect(!gossip.validate());
    }
}
