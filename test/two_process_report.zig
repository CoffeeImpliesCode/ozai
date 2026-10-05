//! A node's final report, read as the counters it is.
//!
//! Every number on a report line is introduced by the words *before* it, so
//! nothing here counts lines: `Count` and `Text` name a label and what it has
//! to be, and `expectCounts` and `expectTexts` print the node's whole output if
//! one of them does not hold — because a counter that did not hold is half an
//! answer. `expectRefused` reads a command line the program refused instead,
//! which is the one claim here that is about what a node never became.

const std = @import("std");

const child = @import("two_process_child.zig");

const Process = child.Process;

// ---------------------------------------------------------------------------
// Reading a report
// ---------------------------------------------------------------------------

/// One counter to check in a node's report: the line it is on, the word that
/// introduces it, and what it has to be.
///
/// The label rather than the position, because a report is prose and prose
/// moves: a counter that changed sentence on its own line is still read, and one
/// whose label no longer introduces a number fails and says so. On the shutdown
/// line the label is the phase's own comma, because that is what comes before
/// the handler count.
pub const Count = struct {
    line: []const u8,
    label: []const u8,
    want: u64,
    /// Set when `want` is the least that will do rather than the whole answer.
    at_least: bool = false,
};

/// One word to check in a node's report: the line, what introduces it, and the
/// word itself. The shutdown phase and the socket are words, not counts.
pub const Text = struct {
    line: []const u8,
    label: []const u8,
    want: []const u8,
};

/// The number a label introduces on a line.
fn numberAfter(line_text: []const u8, label: []const u8) ?u64 {
    var from: usize = 0;
    while (std.mem.findPos(u8, line_text, from, label)) |at| {
        from = at + label.len;
        var digits = from;
        while (digits < line_text.len and line_text[digits] == ' ') digits += 1;
        var end = digits;
        while (end < line_text.len and std.ascii.isDigit(line_text[end])) end += 1;
        if (end == digits) continue;
        return std.fmt.parseInt(u64, line_text[digits..end], 10) catch null;
    }
    return null;
}

/// The word a label introduces: from after the label to the end of the line or
/// to its next comma, whichever comes first.
fn textAfter(line_text: []const u8, label: []const u8) ?[]const u8 {
    const at = std.mem.indexOf(u8, line_text, label) orelse return null;
    const rest = line_text[at + label.len ..];
    const comma = std.mem.indexOf(u8, rest, ", ") orelse rest.len;
    return std.mem.trim(u8, rest[0..comma], " ");
}

/// Check the counters a run is about, having printed the node's whole output
/// if one of them does not hold: a counter that did not hold is half an answer.
pub fn expectCounts(process: *const Process, counts: []const Count) !void {
    for (counts) |count| {
        const line_text = process.line(count.line) orelse
            return process.gaveUp("its report has no line starting '{s}'", .{count.line});
        const got = numberAfter(line_text, count.label) orelse return process.gaveUp(
            "the '{s}' line says no number after '{s}'",
            .{ count.line, count.label },
        );
        const held = if (count.at_least) got >= count.want else got == count.want;
        if (!held) {
            return process.gaveUp(
                "reported {s} = {d} on '{s}', and the run needed {s}{d}",
                .{
                    count.label,
                    got,
                    count.line,
                    if (count.at_least) "at least " else "",
                    count.want,
                },
            );
        }
    }
}

pub fn expectTexts(process: *const Process, texts: []const Text) !void {
    for (texts) |text| {
        const line_text = process.line(text.line) orelse
            return process.gaveUp("its report has no line starting '{s}'", .{text.line});
        const got = textAfter(line_text, text.label) orelse return process.gaveUp(
            "the '{s}' line says nothing after '{s}'",
            .{ text.line, text.label },
        );
        if (!std.mem.eql(u8, got, text.want)) {
            return process.gaveUp(
                "reported {s} as '{s}' on '{s}', and the run needed '{s}'",
                .{ text.label, got, text.line, text.want },
            );
        }
    }
}

/// A node stopped the way it is supposed to: it exited, and it exited zero.
pub fn expectExit(process: *const Process, term: ?std.process.Child.Term) !void {
    const ended = term orelse
        return process.gaveUp("was still running when this file ran out of patience", .{});
    const status = switch (ended) {
        .exited => |code| code,
        else => return process.gaveUp("was {s} rather than an exit", .{@tagName(ended)}),
    };
    if (status != 0) return process.gaveUp("exited with {d}", .{status});
}

/// Every node ends the same way, and every node here ends the same way: the
/// handler shut down, the phase reached `closed`, and the socket is gone.
pub fn expectWoundDown(process: *const Process, term: ?std.process.Child.Term) !void {
    try expectExit(process, term);
    try expectTexts(process, &.{
        .{ .line = "shutdown:", .label = "shutdown: ", .want = "closed" },
        .{ .line = "shutdown:", .label = "cancelled, socket ", .want = "closed" },
    });
    try expectCounts(process, &.{
        .{ .line = "shutdown:", .label = "closed, ", .want = 1 },
    });
}

/// The gate's whole claim: a handshake completed between two processes, counted
/// by the process that accepted the arrival, and the gate then shut itself down
/// in order.
pub fn expectGate(gate: *const Process, term: ?std.process.Child.Term) !void {
    try expectWoundDown(gate, term);
    try expectCounts(gate, &.{
        .{ .line = "stopped:", .label = "passes, ", .want = 1, .at_least = true },
        .{ .line = "stopped:", .label = "datagrams in, ", .want = 1, .at_least = true },
        // One arrival offered to the filter, one task spawned, one handler
        // accept. The last of those is after the handshake and nowhere before
        // it, which is what makes it the proof.
        .{ .line = "accept loop:", .label = "accept loop: ", .want = 1 },
        .{ .line = "accept loop:", .label = "attempts, ", .want = 1 },
        .{ .line = "accept loop:", .label = "spawned, ", .want = 1 },
        .{ .line = "dials:", .label = "dials: ", .want = 0 },
        .{ .line = "dials:", .label = " of ", .want = 0 },
    });
}

/// A relay's whole claim, for the clients it was given: it admitted each of
/// them once, each arrival was offered to the filter and given a handler, and
/// every departure was reported exactly once.
///
/// The three zeros are the half that matters. A departure that is reported
/// twice is a registry that let go of a connection twice, and one that is
/// swallowed is a connection the registry has let go of while the relay still
/// believes it has one: `disconnects` alone cannot tell those apart, so the
/// arms that would absorb a report are asserted at zero rather than left to
/// the sum — for the same reason and in the same words `relay_wire_test.zig`
/// gives, one process closer.
pub fn expectRelayServed(
    relay: *const Process,
    term: ?std.process.Child.Term,
    clients: u64,
) !void {
    try expectWoundDown(relay, term);
    try expectCounts(relay, &.{
        .{ .line = "relay in:", .label = "admitted ", .want = clients },
        .{ .line = "relay in:", .label = "replaced ", .want = 0 },
        .{ .line = "relay in:", .label = "promoted ", .want = 0 },
        .{ .line = "relay in:", .label = "refused ", .want = 0 },
        // One arrival per client offered to the filter, one task spawned for
        // it, one handler connection. All of that is after the QUIC handshake
        // and before the relay's challenge, and none of it can happen for a
        // client that did not arrive.
        .{ .line = "accept loop:", .label = "accept loop: ", .want = clients },
        .{ .line = "accept loop:", .label = "attempts, ", .want = clients },
        .{ .line = "relay away:", .label = "disconnects ", .want = clients },
        .{ .line = "relay away:", .label = "already gone ", .want = 0 },
        .{ .line = "relay away:", .label = "told displaced ", .want = 0 },
    });
}

/// A relay client's whole claim against the relay it was handed: it dialled
/// once, the relay did not refuse it, and the handshake came back.
///
/// The accept counters are at zero and are part of the claim: a client that
/// reaches a relay is an arrival *to it* and accepts nothing on this socket,
/// so a nonzero count here would be a node that dialled and answered.
///
/// `peer gone` is **not** in here: it says a datagram found nobody at the
/// relay, which is a fact about what this client was asked to send rather than
/// about whether it reached the relay. The tests that send nothing assert it at
/// zero themselves, and the test that sends something expects it to be
/// whatever the relay answered.
pub fn expectClientReached(client: *const Process, term: ?std.process.Child.Term) !void {
    try expectWoundDown(client, term);
    try expectCounts(client, &.{
        .{ .line = "relay in:", .label = "dialled ", .want = 1 },
        .{ .line = "relay in:", .label = "refused ", .want = 0 },
        .{ .line = "relay in:", .label = "auth sent ", .want = 1 },
        .{ .line = "relay in:", .label = "established ", .want = 1 },
        .{ .line = "relay in:", .label = "displaced ", .want = 0 },
        .{ .line = "accept loop:", .label = "accept loop: ", .want = 0 },
        .{ .line = "dials:", .label = "dials: ", .want = 0 },
    });
}

/// One datagram came out of the relay and arrived here, from the peer named,
/// with the bytes it was sent.
///
/// The count is the relay's arithmetic and this is the payload, so a relay
/// that forwarded the right number of datagrams to the wrong client, or the
/// right one with the wrong bytes, prints something else here. The sender is
/// what says the datagram crossed *through* the relay: it is the other
/// process's node id, and the relay was the only path between the two sockets.
pub fn expectHanded(
    process: *const Process,
    from: *const Process,
    payload: []const u8,
) !void {
    try expectCounts(process, &.{
        .{ .line = "relay out:", .label = "handed to this node ", .want = 1 },
        .{ .line = "relay inbox:", .label = "datagrams ", .want = 1 },
        .{ .line = "relay inbox[0]:", .label = "bytes ", .want = @intCast(payload.len) },
    });
    const line_text = process.line("relay inbox[0]:") orelse
        return process.gaveUp("printed no line saying what its relay handed it", .{});
    const from_word = " from ";
    const at = std.mem.indexOf(u8, line_text, from_word) orelse
        return process.gaveUp("the datagram it was handed says nothing about its sender", .{});
    const rest = line_text[at + from_word.len ..];
    const space = std.mem.findScalar(u8, rest, ' ') orelse
        return process.gaveUp("the datagram it was handed has no bytes after its sender", .{});
    const sender = from.value("node") orelse
        return from.gaveUp("printed a banner with no node id in it", .{});
    if (!std.mem.eql(u8, rest[0..space], sender)) return process.gaveUp(
        "was handed a datagram from {s}, and the peer that sent one is {s}",
        .{ rest[0..space], sender },
    );
    // The bytes, hexed the way the report prints them and into a room big
    // enough for the most a report will ever show of one. These payloads are
    // shorter than the program's cut, so what it printed is all of them.
    var room: [128]u8 = undefined;
    var out = std.Io.Writer.fixed(&room);
    try out.print("{x}", .{payload});
    if (!std.mem.eql(u8, out.buffered(), rest[space + 1 ..])) return process.gaveUp(
        "was handed {s}, and the bytes that were sent are {s}",
        .{ rest[space + 1 ..], out.buffered() },
    );
}

/// A refused command line: exit 1, the refusal on one line, and no trace.
///
/// The two markers are the whole of what an error return looks like from out
/// here — `error:` and the `file:line` frames under it — and stderr is empty
/// because a program's own refusal is its interface rather than a failure of
/// the program. So this is also the test that adding a flag did not change
/// what a bad command line does.
pub fn expectRefused(
    process: *const Process,
    term: ?std.process.Child.Term,
    refusal: []const u8,
) !void {
    const ended = term orelse
        return process.gaveUp("was still running when this file ran out of patience", .{});
    const status = switch (ended) {
        .exited => |code| code,
        else => return process.gaveUp("was {s} rather than an exit", .{@tagName(ended)}),
    };
    if (status != 1) return process.gaveUp("exited with {d}, and a refusal is 1", .{status});
    if (process.err_out.items.len != 0) return process.gaveUp(
        "wrote to stderr, and a refusal is not a failure of the program:\n{s}",
        .{process.err_out.items},
    );
    for ([_][]const u8{ "error:", "??" }) |marker| {
        if (std.mem.indexOf(u8, process.out.items, marker) != null) return process.gaveUp(
            "printed '{s}', which is what an error return looks like from out here",
            .{marker},
        );
    }
    const line_text = process.line("ozai-node: ") orelse
        return process.gaveUp("printed no line refusing anything", .{});
    if (std.mem.indexOf(u8, line_text, refusal) == null) return process.gaveUp(
        "refused with '{s}', and the run needed a line naming '{s}'",
        .{ line_text, refusal },
    );
}
