//! One `progress:` line, read whole, and the state a wait is gated on.
//!
//! The rule is strict on purpose: the field names are matched against
//! `progress_fields` in order and a number that does not parse is a refusal, so
//! a program that changes its line produces a named failure here rather than a
//! gate that quietly never holds. `Need` is one counter and the sense of it, and
//! `Want` is a conjunction of them — with an `any` half, because a counter that
//! has to come *down* is also true before anything happened and witnesses
//! nothing on its own.

const std = @import("std");

const child = @import("two_process_child.zig");

const Process = child.Process;

// ---------------------------------------------------------------------------
// Reading a progress line, and waiting on one
// ---------------------------------------------------------------------------

/// What every `progress:` line begins with.
pub const progress_prefix = "progress: ";

/// Named counters in the CLI snapshot. An array permits runtime iteration.
const progress_fields = [_][]const u8{
    "dials",     "refused",     "accepted",   "finished",     "up",
    "admitted",  "established", "registered", "sent",         "received",
    "forwarded", "attempts",    "spawned",    "disconnected", "closed",
};

/// One `progress:` line, read whole.
pub const Progress = struct {
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
pub fn parseProgress(line_text: []const u8) ?Progress {
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

/// One number this file needs a node to have reported, and the sense of it.
pub const Need = struct {
    field: []const u8,
    want: u64,
    /// Set when the number has to have come *down* to `want` rather than up.
    at_most: bool = false,

    /// `pub` because `two_process_roster.zig` calls it across the file boundary
    /// the split that gave this module its own name introduced.
    pub fn holds(self: Need, seen: Progress) bool {
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

/// Name the counters that were being waited for and what the node last said.
pub fn reportUnmet(process: *const Process, want: Want) void {
    std.debug.print("  it was waiting for:\n", .{});
    for (want.all) |need| need.say();
    for (want.any) |group| {
        std.debug.print("  and at least one of:\n", .{});
        for (group) |need| need.say();
    }
    if (process.progressLine()) |line_text| {
        std.debug.print("  its last progress line said:\n  {s}\n", .{line_text});
    } else {
        std.debug.print("  and it had written no progress line at all\n", .{});
    }
}
