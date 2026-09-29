//! Print the node id this machine would use, in every form ozai puts on the
//! wire. Run with `zig build run-ozai-node-id`.
//!
//! The example is not decoration: it is the shortest end-to-end proof that the
//! key type survives a round trip through each encoding.

const std = @import("std");
const ozai = @import("ozai");

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    var out_buffer: [512]u8 = undefined;
    var out = std.Io.File.stdout().writerStreaming(io, &out_buffer);

    var secret = ozai.SecretKey.generate(io);
    defer secret.deinit();

    const node_id = secret.nodeId();
    const out_text = &out.interface;

    try out_text.print("hex         {f}\n", .{node_id});
    try out_text.print("short       {s}\n", .{node_id.shortHex()});
    try out_text.print("z-base-32   {s}\n", .{node_id.toZ32()});
    try out_text.print("dns label   {s}\n", .{node_id.toLocalTlsName()});
    try out_text.splatByteAll('\n', 1);

    // A relay path and a direct path for this node, as a peer would receive it.
    const alloc = init.gpa;
    var address = ozai.NodeAddr.init(node_id);
    address = (try address.insert(alloc, .{
        .relay = try ozai.RelayUrl.parse("https://relay.ozai.invalid./"),
    })).?;
    address = (try address.insert(alloc, .{ .ip = .{
        .ip = ozai.IpAddress.parse("192.0.2.1").?,
        .port = 41641,
    } })).?;
    defer address.deinit(alloc);

    try out_text.print("address     {f}\n", .{address});

    // Sign the rendered address and check it here, so the example fails loudly
    // if the text form ever stops being a faithful description of the value.
    var scratch: [256]u8 = undefined;
    const signed = try std.fmt.bufPrint(&scratch, "{f}", .{address});
    const signature = secret.sign(signed);
    try signature.verify(signed, node_id);
    try out_text.splatByteAll('\n', 1);
    try out.flush();
}
