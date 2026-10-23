const std = @import("std");
const codec = @import("gossip/codec.zig");

test {
    std.testing.refAllDecls(codec);
}
