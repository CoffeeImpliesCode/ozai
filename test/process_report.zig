//! What a child said, read as the two reports this project has.
//!
//! `ozai-node --progress` writes a snapshot line after every pass that changes
//! a counter, and a final report at a normal shutdown. Both are prose written
//! by a program in another process, so reading one is a parsing job and not an
//! access: this module knows the labels, the fields, and the sense of each
//! check, and it refuses a line it does not recognise rather than matching
//! nothing.
//!
//! The split from the driver is by meaning rather than by shape. A `Progress`
//! is a child *saying what state it is in*, which is what a wait is gated on; a
//! `Count` or a `Text` is a child's *final account of what it did*, which is
//! what a finished run is checked against. Both arrive as lines of the same
//! pipe, and both are read here.
//!
//! Nothing here spawns, signals or waits. A check that does not hold prints
//! the child it was reading — the child named, and the words that did not hold
//! — and hands back `error.CheckFailed` for the caller to end the run on.

const std = @import("std");

const driver = @import("process_driver.zig");

const Process = driver.Process;

/// What every `progress:` line begins with.
const progress_prefix = "progress: ";

/// Named counters in the CLI snapshot. An array permits runtime iteration.
const progress_fields = [_][]const u8{
    "dials",     "refused",     "accepted",   "finished",     "up",
    "admitted",  "established", "registered", "sent",         "received",
    "forwarded", "attempts",    "spawned",    "disconnected", "closed",
};

/// One `progress:` line, read whole.
const Progress = struct {
    counts: [progress_fields.len]u64 = @splat(0),

    /// The number this line gave for `field`.
    fn count(self: Progress, field: []const u8) u64 {
        for (progress_fields, self.counts) |name, value| {
            if (std.mem.eql(u8, name, field)) return value;
        }
        // A field this file names that the program does not publish is a bug in
        // this file, and a gate that quietly matched nothing would turn it into
        // a timeout instead.
        std.debug.panic("no progress field named '{s}'", .{field});
    }
};

/// A whole `progress:` line, or null when it is not one this file can read.
///
/// Strict on purpose: the field names are matched against `progress_fields` in
/// order and a number that does not parse is a refusal, so a program that
/// changes its line produces a named failure here rather than a gate that
/// quietly never holds.
fn parseProgress(line_text: []const u8) ?Progress {
    var result: Progress = .{};
    var rest = line_text[progress_prefix.len..];
    for (progress_fields, 0..) |name, at| {
        const piece, const rest_after = splitOnce(rest) orelse return null;
        if (!std.mem.startsWith(u8, piece, name)) return null;
        const digits = std.mem.trim(u8, piece[name.len..], " ");
        if (digits.len == 0) return null;
        result.counts[at] = std.fmt.parseInt(u64, digits, 10) catch return null;
        rest = rest_after;
    }
    return if (std.mem.trim(u8, rest, " ").len == 0) result else null;
}

/// One comma-separated piece and everything after it.
fn splitOnce(text: []const u8) ?struct { []const u8, []const u8 } {
    const comma = std.mem.indexOf(u8, text, ", ") orelse
        return .{ text, text[text.len..] };
    return .{ text[0..comma], text[comma + 2 ..] };
}

/// The newest complete snapshot a child has written, read as its counts.
///
/// Null when there is none, which is a child that has not got to the state and
/// not a parser's opinion about one.
fn newestProgress(process: *const Process) ?Progress {
    const line_text = process.newestLine(progress_prefix) orelse return null;
    return parseProgress(line_text);
}

/// One number this file needs a node to have reported, and the sense of it.
const Need = struct {
    field: []const u8,
    want: u64,
    /// Set when the number has to have come *down* to `want` rather than up.
    at_most: bool = false,

    fn holds(self: Need, seen: Progress) bool {
        const got = seen.count(self.field);
        return if (self.at_most) got <= self.want else got >= self.want;
    }

    fn say(self: Need) void {
        std.debug.print(
            "  {s} {s} {d}\n",
            .{ self.field, if (self.at_most) "at most" else "at least", self.want },
        );
    }
};

/// A state this file waits for: every `Need` in `all` holds, and — when `any`
/// is given — at least one of its groups holds as well.
///
/// The `any` half exists for one honest reason. A counter that has to come
/// *down*, `up` reaching zero, is also true before anything happened, so it
/// witnesses nothing on its own; a monotonic counter has to stand beside it,
/// and which monotonic counter moves first is a property of the core rather
/// than of this file. Asking for either is the truthful form of "it noticed",
/// where naming one of them would be a bet.
pub const Want = struct {
    all: []const Need = &.{},
    any: []const []const Need = &.{},
};

/// Whether the newest progress line `process` has written satisfies `want`.
///
/// A node that has written no progress line at all satisfies nothing, which is
/// the right answer: it has not got to the state, and the failure names the
/// counters rather than a parser's opinion of them.
pub fn holds(process: *const Process, want: Want) bool {
    const seen = newestProgress(process) orelse return false;
    for (want.all) |need| {
        if (!need.holds(seen)) return false;
    }
    if (want.any.len == 0) return true;
    for (want.any) |either| {
        var all_of_them = true;
        for (either) |need| {
            if (!need.holds(seen)) all_of_them = false;
        }
        if (all_of_them) return true;
    }
    return false;
}

/// Name the counters that were being waited for and what the node last said.
pub fn reportUnmet(process: *const Process, want: Want) void {
    std.debug.print("  it was waiting for:\n", .{});
    for (want.all) |need| need.say();
    for (want.any) |group| {
        std.debug.print("  and at least one of:\n", .{});
        for (group) |need| need.say();
    }
    if (process.newestLine(progress_prefix)) |line_text| {
        std.debug.print("  its last progress line said:\n  {s}\n", .{line_text});
    } else {
        std.debug.print("  and it had written no progress line at all\n", .{});
    }
}

/// One counter to check in a node's report: the line it is on, the word that
/// introduces it, and what it has to be.
///
/// The label rather than the position, because a report is prose and prose
/// moves: a counter that changed sentence on its own line is still read, and one
/// whose label no longer introduces a number fails and says so. On the shutdown
/// line the label is the phase's own comma, because that is what comes before
/// the handler count.
const Count = struct {
    line: []const u8,
    label: []const u8,
    want: u64,
    /// Set when `want` is the least that will do rather than the whole answer.
    at_least: bool = false,
};

/// One word to check in a node's report: the line, what introduces it, and the
/// word itself. The shutdown phase and the socket are words, not counts.
const Text = struct {
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

fn expectTexts(process: *const Process, texts: []const Text) !void {
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
fn expectExit(process: *const Process, term: ?std.process.Child.Term) !void {
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
    if (process.stderrText().len != 0) return process.gaveUp(
        "wrote to stderr, and a refusal is not a failure of the program:\n{s}",
        .{process.stderrText()},
    );
    for ([_][]const u8{ "error:", "??" }) |marker| {
        if (std.mem.indexOf(u8, process.stdoutText(), marker) != null) return process.gaveUp(
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
