//! One fixed4BE frame at a time; a completed frame borrows this assembly until release.
const std = @import("std");
const codec = @import("../gossip/codec.zig");
const TopicId = @import("../gossip/hyparview.zig").TopicId;

pub const Error = error{ FrameTooLarge, BadHeader, Truncated, FramePending };
pub const Assembly = struct {
    bytes: [codec.max_message_size + 4]u8 = undefined,
    used: usize = 0,
    target: usize = 4,
    complete: bool = false,

    pub fn push(self: *Assembly, input: []const u8) Error!struct { consumed: usize } {
        if (self.complete) return error.FramePending;
        var consumed: usize = 0;
        while (consumed < input.len and !self.complete) {
            const count = @min(self.target - self.used, input.len - consumed);
            @memcpy(self.bytes[self.used..][0..count], input[consumed..][0..count]);
            self.used += count;
            consumed += count;
            if (self.used != self.target) break;
            if (self.target == 4) {
                const length: usize = @intCast(std.mem.readInt(u32, self.bytes[0..4], .big));
                if (length > codec.max_message_size) return error.FrameTooLarge;
                self.target = 4 + length;
                if (self.target == 4) self.complete = true;
            } else {
                self.complete = true;
            }
        }
        return .{ .consumed = consumed };
    }

    pub fn frame(self: *const Assembly) []const u8 {
        std.debug.assert(self.complete);
        return self.bytes[0..self.used];
    }

    pub fn takeHeader(self: *Assembly) Error!TopicId {
        if (!self.complete or self.used != 36) return error.BadHeader;
        const topic = TopicId.fromBytes(self.bytes[4..36].*);
        self.release();
        return topic;
    }

    pub fn release(self: *Assembly) void {
        std.debug.assert(self.complete);
        self.used = 0;
        self.target = 4;
        self.complete = false;
    }

    pub fn finish(self: *const Assembly) Error!void {
        if (self.used != 0) return error.Truncated;
    }
};

test {
    _ = @import("node_gossip_receive_test.zig");
}
