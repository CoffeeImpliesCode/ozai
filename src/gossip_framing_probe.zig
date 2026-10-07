const std = @import("std");
test {
    std.testing.refAllDecls(@import("gossip/codec.zig"));
}
