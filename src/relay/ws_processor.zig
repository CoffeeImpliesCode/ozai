//! Decoded WebSocket transitions. Action payloads borrow the event until execution completes.
//! State contains no buffers or I/O capability; the session owns framing and action execution.
const std = @import("std");
const ws = @import("ws_frame.zig");

pub const Error = error{ UnexpectedMessage, FrameTooLarge, InvalidUtf8, InvalidCloseFrame };

pub const State = struct {
    message_len: usize = 0,
    fragmented: bool = false,
    text_message: bool = false,
    complete: bool = false,
    utf8_remaining: u3 = 0,
    utf8_value: u32 = 0,
    utf8_min: u32 = 0,
};

pub const Event = struct {
    opcode: ws.Opcode,
    fin: bool,
    payload: []const u8,
    capacity: usize,
    output_ready: bool,
};

pub const Action = union(enum) {
    append: []const u8,
    consume,
    pong: []const u8,
    deliver,
    reset,
    close,
};

pub const Result = struct {
    state: State,
    actions: [3]Action = undefined,
    count: usize = 0,

    fn add(self: *Result, action: Action) void {
        std.debug.assert(self.count < self.actions.len);
        self.actions[self.count] = action;
        self.count += 1;
    }
};

pub fn process(state: State, event: Event) Error!Result {
    var result: Result = .{ .state = state };
    std.debug.assert(state.message_len <= event.capacity);
    switch (event.opcode) {
        .close => {
            try validateClose(event.payload);
            result.add(.close);
        },
        .ping => {
            if (!event.output_ready) return result;
            result.add(.{ .pong = event.payload });
            result.add(.consume);
        },
        .pong => result.add(.consume),
        .text, .binary, .continuation => {
            if (event.opcode == .continuation) {
                if (!state.fragmented) return error.UnexpectedMessage;
            } else {
                if (state.fragmented) return error.UnexpectedMessage;
                result.state.text_message = event.opcode == .text;
            }
            if (event.payload.len > event.capacity - state.message_len)
                return error.FrameTooLarge;
            if (result.state.text_message) {
                try validateText(&result.state, event.payload);
                if (event.fin and result.state.utf8_remaining != 0) return error.InvalidUtf8;
            }
            result.state.message_len += event.payload.len;
            result.state.fragmented = !event.fin;
            result.add(.{ .append = event.payload });
            result.add(.consume);
            if (event.fin) {
                if (result.state.text_message) {
                    result.state.message_len = 0;
                    result.add(.reset);
                } else {
                    result.state.complete = true;
                    result.add(.deliver);
                }
            }
        },
    }
    return result;
}

fn validateText(state: *State, bytes: []const u8) Error!void {
    for (bytes) |byte| {
        if (state.utf8_remaining != 0) {
            if (byte < 0x80 or byte > 0xbf) return error.InvalidUtf8;
            state.utf8_value = (state.utf8_value << 6) | (byte & 0x3f);
            state.utf8_remaining -= 1;
            if (state.utf8_remaining == 0) {
                const value = state.utf8_value;
                if (value < state.utf8_min or value > 0x10ffff or
                    (value >= 0xd800 and value <= 0xdfff)) return error.InvalidUtf8;
            }
        } else if (byte < 0x80) {
            continue;
        } else if (byte >= 0xc2 and byte <= 0xdf) {
            state.utf8_remaining = 1;
            state.utf8_value = byte & 0x1f;
            state.utf8_min = 0x80;
        } else if (byte >= 0xe0 and byte <= 0xef) {
            state.utf8_remaining = 2;
            state.utf8_value = byte & 0x0f;
            state.utf8_min = 0x800;
        } else if (byte >= 0xf0 and byte <= 0xf4) {
            state.utf8_remaining = 3;
            state.utf8_value = byte & 0x07;
            state.utf8_min = 0x10000;
        } else return error.InvalidUtf8;
    }
}

fn validateClose(payload: []const u8) Error!void {
    if (payload.len == 0) return;
    if (payload.len == 1) return error.InvalidCloseFrame;
    const code = std.mem.readInt(u16, payload[0..2], .big);
    const protocol_code = code >= 1000 and code <= 1014 and
        code != 1004 and code != 1005 and code != 1006;
    const application_code = code >= 3000 and code <= 4999;
    if (!protocol_code and !application_code) return error.InvalidCloseFrame;
    if (!std.unicode.utf8ValidateSlice(payload[2..])) return error.InvalidCloseFrame;
}

test "decoded ping backpressure preserves fragment state without actions" {
    const state: State = .{ .fragmented = true, .message_len = 5 };
    const result = try process(state, .{
        .opcode = .ping,
        .fin = true,
        .payload = "probe",
        .capacity = 32,
        .output_ready = false,
    });
    try std.testing.expectEqualDeep(state, result.state);
    try std.testing.expectEqual(@as(usize, 0), result.count);
}

test "text UTF8 validation spans fragments and rejects incomplete final codepoint" {
    const first = try process(.{}, .{
        .opcode = .text,
        .fin = false,
        .payload = &.{0xe2},
        .capacity = 32,
        .output_ready = true,
    });
    const last = try process(first.state, .{
        .opcode = .continuation,
        .fin = true,
        .payload = &.{ 0x82, 0xac },
        .capacity = 32,
        .output_ready = true,
    });
    try std.testing.expectEqual(@as(usize, 0), last.state.message_len);
    try std.testing.expectError(error.InvalidUtf8, process(first.state, .{
        .opcode = .continuation,
        .fin = true,
        .payload = "",
        .capacity = 32,
        .output_ready = true,
    }));
}
