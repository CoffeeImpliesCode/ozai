//! A node's final report, read as the counters it is.
//!
//! Every number on a report line is introduced by the words *before* it, so
//! nothing here counts lines: `Count` and `Text` name a label and what it has
//! to be, and `expectCounts` and `expectTexts` print the node's whole output if
//! one of them does not hold — because a counter that did not hold is half an
//! answer.

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
