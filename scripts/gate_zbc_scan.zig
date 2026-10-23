const std = @import("std");

pub const Scan = struct {
    selected: usize,
    unresolved_import_lookups: usize,
};
pub const Error = error{InvalidZbcScan};

pub fn parse(
    stdout: []const u8,
    stderr: []const u8,
    paths: []const []const u8,
) Error!Scan {
    if (stdout.len != 0 or stderr.len == 0 or paths.len == 0 or
        stderr[stderr.len - 1] != '\n') return error.InvalidZbcScan;
    const text = stderr[0 .. stderr.len - 1];
    if (std.mem.indexOfScalar(u8, text, '\n') != null) return error.InvalidZbcScan;
    var fields = std.mem.splitScalar(u8, text, ' ');
    if (!std.mem.eql(u8, fields.next() orelse "", "zbc:")) return error.InvalidZbcScan;
    const selected = try count(&fields, "selected=");
    if (selected != paths.len) return error.InvalidZbcScan;
    if (try count(&fields, "analyzed=") != selected) return error.InvalidZbcScan;
    if (try count(&fields, "failed=") != 0) return error.InvalidZbcScan;
    if (try count(&fields, "findings=") != 0) return error.InvalidZbcScan;
    if (!std.mem.eql(u8, fields.next() orelse "", "parser=Zig-0.16.0"))
        return error.InvalidZbcScan;
    const lookups = try count(&fields, "unresolved-import-lookups=");
    if (fields.next() != null) return error.InvalidZbcScan;
    return .{ .selected = selected, .unresolved_import_lookups = lookups };
}

fn count(fields: *std.mem.SplitIterator(u8, .scalar), prefix: []const u8) Error!usize {
    const field = fields.next() orelse return error.InvalidZbcScan;
    if (!std.mem.startsWith(u8, field, prefix)) return error.InvalidZbcScan;
    const digits = field[prefix.len..];
    if (digits.len == 0 or (digits.len > 1 and digits[0] == '0'))
        return error.InvalidZbcScan;
    for (digits) |byte| if (byte < '0' or byte > '9') return error.InvalidZbcScan;
    return std.fmt.parseInt(usize, digits, 10) catch return error.InvalidZbcScan;
}

const inventory = [_][]const u8{"./src/a.zig"};
const summary = "zbc: selected=1 analyzed=1 failed=0 findings=0 " ++
    "parser=Zig-0.16.0 unresolved-import-lookups=2288\n";

// The scan count authenticates the entire input selection; lookups are not hidden.
test "complete clean scan retains selection and unresolved lookups" {
    const result = try parse("", summary, &inventory);
    try std.testing.expectEqual(@as(usize, 1), result.selected);
    try std.testing.expectEqual(@as(usize, 2288), result.unresolved_import_lookups);
}

// No output outside the exact complete clean summary can be accepted.
test "reject malformed partial dirty or unauthenticated scan" {
    const invalid = [_][]const u8{
        "",
        "zbc: selected=1\n",
        summary[0 .. summary.len - 1],
        "zbc: selected=1 analyzed=0 failed=0 findings=0 " ++
            "parser=Zig-0.16.0 unresolved-import-lookups=0\n",
        "zbc: selected=2 analyzed=2 failed=0 findings=0 " ++
            "parser=Zig-0.16.0 unresolved-import-lookups=0\n",
        "zbc: selected=1 analyzed=1 failed=1 findings=0 " ++
            "parser=Zig-0.16.0 unresolved-import-lookups=0\n",
        "zbc: selected=1 analyzed=1 failed=0 findings=1 " ++
            "parser=Zig-0.16.0 unresolved-import-lookups=0\n",
        "zbc: selected=1 analyzed=1 failed=0 findings=0 " ++
            "parser=Zig-0.15.0 unresolved-import-lookups=0\n",
        "zbc: selected=1 analyzed=1 failed=0 findings=0 " ++
            "parser=Zig-0.16.0 unresolved-import-lookups=-1\n",
        "zbc: selected=01 analyzed=1 failed=0 findings=0 " ++
            "parser=Zig-0.16.0 unresolved-import-lookups=0\n",
        "zbc: selected=1 analyzed=1 failed=0 findings=0 " ++
            "parser=Zig-0.16.0 unresolved-import-lookups=184467440737095516160\n",
        summary ++ summary,
        summary ++ "unknown failure\n",
        summary ++ "\n",
        "devenv: loading environment\n" ++ summary,
        "fatal: source lookup failed\n" ++ summary,
        "/project/src/a.zig:97:5: error(use-undefined): message\n" ++ summary,
        "/outside/src/a.zig:97:5: warning(use-undefined): message\n" ++ summary,
        "   | error(fake): not a header\n" ++ summary,
        "zbc: selected=0 analyzed=0 failed=0 findings=0 " ++
            "parser=Zig-0.16.0 unresolved-import-lookups=0\n",
        "zbc: selected=1 analyzed=1 failed=0 findings=0 " ++
            "parser=Zig-0.16.0 unresolved-import-lookups=0 extra\n",
        "zbc: selected=1 analyzed=1 failed=0 findings=0 " ++
            "parser=Zig-0.16.0 unresolved-import-lookups=0\r\n",
    };
    for (invalid) |input| {
        try std.testing.expectError(error.InvalidZbcScan, parse("", input, &inventory));
    }
    try std.testing.expectError(error.InvalidZbcScan, parse(" ", summary, &inventory));
    try std.testing.expectError(error.InvalidZbcScan, parse("", summary, &.{}));
}
