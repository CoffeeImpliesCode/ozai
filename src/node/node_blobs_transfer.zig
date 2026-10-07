//! Transfer decisions over decoded inputs; the node executes allocation and I/O actions.
const std = @import("std");
const protocol = @import("../blobs/protocol.zig");
const getter = @import("../blobs/getter.zig");

pub const Mode = enum { getter, provider };
pub const State = struct {
    mode: Mode,
    request_sent: bool,
    done: bool = false,

    pub fn init(mode: Mode) State {
        return .{ .mode = mode, .request_sent = mode == .provider };
    }
};

pub const Completion = struct {
    claimed_size: ?u64,
    verified_size: ?u64,
    written: usize,
    answered: bool,
};

pub const Event = union(enum) {
    ready: struct { buffered: usize, allowance: usize },
    request_written,
    received: struct { drained: bool, finished: bool },
    request: protocol.GetRequest,
    response: getter.Decoded,
    provider_answer: ?u64,
    provider_refusal,
};

pub const Action = union(enum) {
    write_request,
    drain: usize,
    decode_request,
    decode_response,
    answer: protocol.GetRequest,
    close_stream,
    complete: Completion,
};

pub const Transition = struct {
    state: State,
    actions: [2]Action = undefined,
    len: usize = 0,

    fn add(self: *Transition, action: Action) void {
        std.debug.assert(self.len < self.actions.len);
        self.actions[self.len] = action;
        self.len += 1;
    }
};

pub fn process(state: State, event: Event) error{MessageTooLarge}!Transition {
    var next: Transition = .{ .state = state };
    if (state.done) return next;
    switch (event) {
        .ready => |ready| {
            if (ready.buffered > ready.allowance) return error.MessageTooLarge;
            if (!state.request_sent) {
                next.add(.write_request);
            } else {
                next.add(.{ .drain = ready.allowance - ready.buffered });
            }
        },
        .request_written => {
            std.debug.assert(state.mode == .getter);
            std.debug.assert(!state.request_sent);
            next.state.request_sent = true;
        },
        .received => |received| {
            std.debug.assert(state.request_sent);
            if (!received.drained and received.finished) {
                next.add(if (state.mode == .getter) .decode_response else .decode_request);
            }
        },
        .request => |request| {
            std.debug.assert(state.mode == .provider);
            next.add(.{ .answer = request });
        },
        .response => |response| {
            std.debug.assert(state.mode == .getter);
            next.state.done = true;
            next.add(.{ .complete = .{
                .claimed_size = response.claimed_size,
                .verified_size = response.verified_size,
                .written = response.written,
                .answered = true,
            } });
        },
        .provider_answer => |size| {
            std.debug.assert(state.mode == .provider);
            next.state.done = true;
            next.add(.close_stream);
            next.add(.{ .complete = .{
                .claimed_size = size,
                .verified_size = size,
                .written = 0,
                .answered = size != null,
            } });
        },
        .provider_refusal => {
            std.debug.assert(state.mode == .provider);
            next.state.done = true;
            next.add(.close_stream);
            next.add(.{ .complete = .{
                .claimed_size = null,
                .verified_size = null,
                .written = 0,
                .answered = false,
            } });
        },
    }
    return next;
}

// Replaying a ready event after a refused write leaves the request eligible for transmission.
test "transfer request commits only after executor reports successful write" {
    const initial = State.init(.getter);
    const ready: Event = .{ .ready = .{ .buffered = 0, .allowance = 9 } };
    const first = try process(initial, ready);
    try std.testing.expectEqual(initial, first.state);
    try std.testing.expect(first.actions[0] == .write_request);
    const replay = try process(first.state, ready);
    try std.testing.expect(replay.actions[0] == .write_request);
    const sent = try process(initial, .request_written);
    const reading = try process(sent.state, ready);
    try std.testing.expectEqual(@as(usize, 9), reading.actions[0].drain);
    try std.testing.expectError(error.MessageTooLarge, process(sent.state, .{
        .ready = .{ .buffered = 10, .allowance = 9 },
    }));
}

// FIN cannot start verification while a bounded drain pass still committed receive runs.
test "transfer completion waits for consumption and preserves metadata trust" {
    const state = State.init(.provider);
    const pending = try process(state, .{ .received = .{ .drained = true, .finished = true } });
    try std.testing.expectEqual(@as(usize, 0), pending.len);
    const ready = try process(state, .{ .received = .{ .drained = false, .finished = true } });
    try std.testing.expect(ready.actions[0] == .decode_request);
    const refused = try process(state, .provider_refusal);
    try std.testing.expect(refused.state.done);
    try std.testing.expect(refused.actions[0] == .close_stream);
    try std.testing.expect(!refused.actions[1].complete.answered);
    const getter_state = (try process(State.init(.getter), .request_written)).state;
    const completed = try process(getter_state, .{ .response = .{
        .claimed_size = 2050,
        .verified_size = null,
        .written = 1024,
    } });
    try std.testing.expectEqual(@as(?u64, null), completed.actions[0].complete.verified_size);
    try std.testing.expectEqual(@as(?u64, 2050), completed.actions[0].complete.claimed_size);
    try std.testing.expect(completed.state.done);
    const again = try process(completed.state, .{
        .ready = .{ .buffered = 0, .allowance = 9 },
    });
    try std.testing.expectEqual(@as(usize, 0), again.len);
}

// The request action borrows only for immediate execution; completion follows provider evidence.
test "transfer routes decoded request and closes answered or absent provider stream" {
    const state = State.init(.provider);
    const request = protocol.GetRequest.blob(@splat(0x42));
    const answer = try process(state, .{ .request = request });
    try std.testing.expectEqual(state, answer.state);
    try std.testing.expectEqual(request.hash, answer.actions[0].answer.hash);
    for ([_]?u64{ null, 2049 }) |size| {
        const completed = try process(state, .{ .provider_answer = size });
        try std.testing.expect(completed.actions[0] == .close_stream);
        try std.testing.expectEqual(size, completed.actions[1].complete.verified_size);
        try std.testing.expectEqual(size != null, completed.actions[1].complete.answered);
        try std.testing.expect(completed.state.done);
    }
    const getter_state = (try process(State.init(.getter), .request_written)).state;
    const open = try process(getter_state, .{ .received = .{
        .drained = false,
        .finished = false,
    } });
    try std.testing.expectEqual(@as(usize, 0), open.len);
    const finished = try process(getter_state, .{ .received = .{
        .drained = false,
        .finished = true,
    } });
    try std.testing.expect(finished.actions[0] == .decode_response);
    const boundary = try process(getter_state, .{ .ready = .{
        .buffered = 9,
        .allowance = 9,
    } });
    try std.testing.expectEqual(@as(usize, 0), boundary.actions[0].drain);
}
