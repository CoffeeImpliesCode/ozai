const std = @import("std");
pub const Error = error{InvalidZbcAnnotation};

// Native ZBC scans the first raw double slash on each physical line, even inside literals.
// Such active candidates must be rejected, never registered as actual Zig annotations.
pub fn rejectLiteral(source: []const u8, start: usize, end: usize) Error!void {
    if (start == end) return;
    if (std.mem.find(u8, source[start..end], "//") == null) return;
    var line_start = if (std.mem.findScalarLast(u8, source[0..start], '\n')) |newline|
        newline + 1
    else
        0;
    while (line_start < end) {
        const line_end = line_start +
            (std.mem.indexOfScalar(u8, source[line_start..], '\n') orelse
                (source.len - line_start));
        const line = source[line_start..line_end];
        if (std.mem.find(u8, line, "//")) |relative| {
            const position = line_start + relative;
            if (position >= start and position < end and active(line[relative + 2 ..]))
                return error.InvalidZbcAnnotation;
        }
        if (line_end == source.len) break;
        line_start = line_end + 1;
    }
}

fn active(body: []const u8) bool {
    const trimmed = std.mem.trim(u8, body, " \t");
    for ([_][]const u8{ "zbc-disable-next-line:", "zbc-disable-line:" }) |prefix| {
        if (!std.mem.startsWith(u8, trimmed, prefix)) continue;
        var rules = std.mem.splitScalar(u8, trimmed[prefix.len..], ',');
        while (rules.next()) |raw| {
            const rule = std.mem.trim(u8, raw, " \t");
            const id = rule[0..(std.mem.indexOfAny(u8, rule, " \t") orelse rule.len)];
            if (std.mem.eql(u8, id, "*") or validRule(id)) return true;
        }
    }
    return false;
}

fn validRule(rule: []const u8) bool {
    var segment_length: usize = 0;
    for (rule) |byte| {
        if (byte == '-') {
            if (segment_length == 0) return false;
            segment_length = 0;
        } else {
            if (!(byte >= 'a' and byte <= 'z') and !(byte >= '0' and byte <= '9'))
                return false;
            segment_length += 1;
        }
    }
    return segment_length != 0;
}
