const std = @import("std");
pub const Error = error{PartialMapping};

pub const Mapping = enum { project_line, project_unknown, external, unowned };

/// Source claims borrow the parsed row; external and unowned rows make no source claim.
/// A project unknown row carries its path but has `line = null`.
pub const ParsedMapping = struct {
    category: Mapping,
    path: ?[]const u8 = null,
    line: ?u32 = null,
};

/// Borrowed mapping context; both strings must remain valid for the classification call.
pub const Options = struct {
    /// Absolute project root used to determine source ownership.
    cwd: []const u8,
    /// Exact basename of the current artifact-validated binary, never a symbolizer row.
    binary_basename: []const u8,
};

fn projectPath(path: []const u8, cwd: []const u8) bool {
    const relative = if (std.fs.path.isAbsolute(path)) absolute: {
        if (!std.mem.startsWith(u8, path, cwd)) return false;
        if (path.len == cwd.len) return true;
        if (path[cwd.len] != '/') return false;
        break :absolute path[cwd.len + 1 ..];
    } else path;
    // Normalize relative ownership without allocating for every measured PC.
    // A parent component at depth zero leaves the project, not a project file.
    var depth: usize = 0;
    var components = std.mem.tokenizeScalar(u8, relative, '/');
    while (components.next()) |component| {
        if (std.mem.eql(u8, component, ".")) continue;
        if (std.mem.eql(u8, component, "..")) {
            if (depth == 0) return false;
            depth -= 1;
        } else {
            depth += 1;
        }
    }
    return true;
}

/// Validates newline framing, exactly `expected` rows, and every row's source classification.
/// Returns `error.PartialMapping` for malformed or incomplete output; retains no input.
pub fn checkMapping(text: []const u8, expected: usize, options: Options) Error!void {
    if (text.len == 0 or text[text.len - 1] != '\n') return error.PartialMapping;
    var count: usize = 0;
    var lines = std.mem.splitScalar(u8, text[0 .. text.len - 1], '\n');
    while (lines.next()) |line| {
        if (count >= expected) return error.PartialMapping;
        _ = try parseMapping(line, options);
        count += 1;
    }
    if (count != expected) return error.PartialMapping;
}

/// Parses a source location without inferring a numeric line for unknown source locations.
/// Only `??:0` and the current binary basename with `:?` are unowned; malformed rows fail closed.
/// Project paths borrow `line` until its storage is released; this function allocates nothing.
pub fn parseMapping(line: []const u8, options: Options) Error!ParsedMapping {
    // The tool has no source ownership for this exact location, not an external file.
    if (std.mem.eql(u8, line, "??:0")) return .{ .category = .unowned };
    if (std.mem.indexOf(u8, line, "??") != null) return error.PartialMapping;
    const separator = std.mem.lastIndexOfScalar(u8, line, ':') orelse
        return error.PartialMapping;
    const path = line[0..separator];
    if (path.len == 0) return error.PartialMapping;
    const suffix = line[separator + 1 ..];
    if (std.mem.eql(u8, path, options.binary_basename)) {
        // A binary compile-unit label supplies no source-file or numeric line claim.
        if (std.mem.eql(u8, suffix, "?")) return .{ .category = .unowned };
        return error.PartialMapping;
    }
    if (std.mem.eql(u8, suffix, "?")) {
        if (!std.fs.path.isAbsolute(path)) return error.PartialMapping;
        return if (projectPath(path, options.cwd))
            .{ .category = .project_unknown, .path = path }
        else
            .{ .category = .external };
    }
    const number = std.mem.sliceTo(suffix, ' ');
    if (number.len == 0) return error.PartialMapping;
    for (number) |digit| {
        if (digit < '0' or digit > '9') return error.PartialMapping;
    }
    if (number.len != suffix.len) {
        const annotation = suffix[number.len..];
        const prefix = " (discriminator ";
        if (!std.mem.startsWith(u8, annotation, prefix) or
            !std.mem.endsWith(u8, annotation, ")")) return error.PartialMapping;
        const discriminator = annotation[prefix.len .. annotation.len - 1];
        if (discriminator.len == 0) return error.PartialMapping;
        for (discriminator) |digit| {
            if (digit < '0' or digit > '9') return error.PartialMapping;
        }
        _ = std.fmt.parseInt(u32, discriminator, 10) catch return error.PartialMapping;
    }
    const line_number = std.fmt.parseInt(u32, number, 10) catch return error.PartialMapping;
    if (line_number == 0) return error.PartialMapping;
    return if (projectPath(path, options.cwd))
        .{ .category = .project_line, .path = path, .line = line_number }
    else
        .{ .category = .external };
}

test "parsed mappings expose only actual project source locations" {
    const options: Options = .{ .cwd = "/project", .binary_basename = "ozai-test" };
    const known = try parseMapping("./src/../src/a.zig:4 (discriminator 2)", options);
    try std.testing.expectEqual(Mapping.project_line, known.category);
    try std.testing.expectEqualStrings("./src/../src/a.zig", known.path.?);
    try std.testing.expectEqual(@as(?u32, 4), known.line);
    const unknown = try parseMapping("/project/src/a.zig:?", options);
    try std.testing.expectEqual(Mapping.project_unknown, unknown.category);
    try std.testing.expectEqualStrings("/project/src/a.zig", unknown.path.?);
    try std.testing.expectEqual(@as(?u32, null), unknown.line);
    for ([_][]const u8{ "??:0", "ozai-test:?", "/opt/zig/std/a.zig:4" }) |row| {
        const parsed = try parseMapping(row, options);
        try std.testing.expectEqual(@as(?[]const u8, null), parsed.path);
        try std.testing.expectEqual(@as(?u32, null), parsed.line);
    }
}

test "external unknown source lines accept valid project mappings" {
    try checkMapping(
        "/opt/zig/lib/std/debug.zig:?\n/project/src/a.zig:4\n",
        2,
        .{ .cwd = "/project", .binary_basename = "ozai-test" },
    );
}

test "absolute project unknown source lines are valid without a line number" {
    const options: Options = .{ .cwd = "/project", .binary_basename = "ozai-test" };
    try checkMapping("/project/test/expected_log_runner.zig:?\n/project:?\n", 2, options);
}

test "relative and malformed unknown source lines fail closed" {
    const options: Options = .{ .cwd = "/project", .binary_basename = "ozai-test" };
    const mappings = [_][]const u8{
        "src/a.zig:?\n",
        "/project/src/a.zig:? extra\n",
        "/project/src/a.zig:??\n",
        "/project/src/a.zig:0\n",
        ":4\n",
    };
    for (mappings) |mapping| {
        try std.testing.expectError(error.PartialMapping, checkMapping(mapping, 1, options));
    }
}

test "partial address mapping fails even with plausible known lines" {
    const options: Options = .{ .cwd = "/project", .binary_basename = "ozai-test" };
    const mappings = [_][]const u8{
        "src/a.zig:4\n??:?\n",
        "src/a.zig:4\n/opt/zig/lib/std/debug.zig:??\n",
        "src/a.zig:4\n",
        "src/a.zig:4\n/opt/zig/lib/std/debug.zig\n",
        "src/a.zig:4\n/opt/zig/lib/std/debug.zig:0\n",
        "src/a.zig:4\n/opt/zig/lib/std/debug.zig:invalid\n",
        "src/a.zig:4\n/opt/zig/lib/std/debug.zig:4294967296\n",
        "src/a.zig:4\n/opt/zig/lib/std/debug.zig:?invalid\n",
        "src/a.zig:4\n/opt/zig/lib/std/debug.zig:3\nsrc/b.zig:5\n",
        "src/a.zig:4\n??:\n",
        "src/a.zig:4\n??:0 extra\n",
        "src/a.zig:4\n??:00\n",
        "src/a.zig:4\n??:1\n",
        "src/a.zig:4\n\n??:0\n",
        "src/a.zig:4\n??:0",
    };
    for (mappings) |mapping| {
        try std.testing.expectError(error.PartialMapping, checkMapping(mapping, 2, options));
    }
}

test "relative external source paths never belong to the project" {
    try std.testing.expect(!projectPath("../sysdeps/x86_64/crti.S", "/project"));
    try std.testing.expect(!projectPath("src/../../sysdeps/start.S", "/project"));
    try std.testing.expect(!projectPath("/project/../sysdeps/start.S", "/project"));
    try std.testing.expect(projectPath("./src/../src/a.zig", "/project"));
    try std.testing.expect(!projectPath("/project2/src/a.zig", "/project"));
    try std.testing.expect(projectPath("src/a.zig", "/project"));
    try std.testing.expectEqual(
        Mapping.external,
        (try parseMapping("../sysdeps/x86_64/crti.S:4", .{
            .cwd = "/project",
            .binary_basename = "ozai-test",
        })).category,
    );
}

test "exact unknown location is unowned without fabricating project ownership" {
    const options: Options = .{ .cwd = "/project", .binary_basename = "ozai-test" };
    try std.testing.expectEqual(Mapping.unowned, (try parseMapping("??:0", options)).category);
    try checkMapping("src/a.zig:4\n??:0\n/opt/zig/std/a.zig:?\n", 3, options);
}

test "documented discriminator suffix retains known source ownership" {
    try checkMapping("src/a.zig:4 (discriminator 2)\n", 1, .{
        .cwd = "/project",
        .binary_basename = "ozai-test",
    });
}

test "missing and malformed symbolizer rows fail closed" {
    const options: Options = .{ .cwd = "/project", .binary_basename = "ozai-test" };
    const mappings = [_][]const u8{
        "\n",
        "??\n",
        "??:0\n\n",
        " ??:0\n",
        "??:0 \n",
        "src/a.zig:4 garbage\n",
        "src/a.zig:+4\n",
        "src/a.zig:4 (discriminator 2\n",
    };
    for (mappings) |text| {
        try std.testing.expectError(error.PartialMapping, checkMapping(text, 1, options));
    }
}

test "current binary compile unit with unknown line is unowned" {
    // Only the current validated binary label is source-unowned metadata.
    const options: Options = .{ .cwd = "/project", .binary_basename = "ozai-test" };
    try std.testing.expectEqual(
        Mapping.unowned,
        (try parseMapping("ozai-test:?", options)).category,
    );
    try std.testing.expectEqual(Mapping.unowned, (try parseMapping("??:0", options)).category);
    try std.testing.expectEqual(
        Mapping.project_unknown,
        (try parseMapping("/project/src/a.zig:?", options)).category,
    );
    try std.testing.expectEqual(
        Mapping.project_unknown,
        (try parseMapping("/project/ozai-test:?", options)).category,
    );
    try checkMapping("ozai-test:?\n??:0\n/project/src/a.zig:?\n", 3, options);
    try std.testing.expectEqual(
        Mapping.unowned,
        (try parseMapping("other-test:?", .{
            .cwd = "/project",
            .binary_basename = "other-test",
        })).category,
    );
}

test "binary compile unit allowance rejects other labels and source paths" {
    // Basename overlap cannot turn a relative source path into binary metadata.
    const options: Options = .{ .cwd = "/project", .binary_basename = "ozai-test" };
    const rows = [_][]const u8{
        "other-test:?",
        "src/a.zig:?",
        "src/ozai-test:?",
        "./ozai-test:?",
        "../ozai-test:?",
        "ozai-test:4",
        "ozai-test:0",
        "ozai-test:4 (discriminator 2)",
        "ozai-test:? extra",
    };
    for (rows) |row| {
        try std.testing.expectError(error.PartialMapping, parseMapping(row, options));
        var buffer: [128]u8 = undefined;
        const text = try std.fmt.bufPrint(&buffer, "{s}\n", .{row});
        try std.testing.expectError(error.PartialMapping, checkMapping(text, 1, options));
    }
    try std.testing.expectError(
        error.PartialMapping,
        parseMapping("ozai-test:?", .{
            .cwd = "/project",
            .binary_basename = "other-test",
        }),
    );
    try std.testing.expectError(
        error.PartialMapping,
        parseMapping("src/a.zig:?", .{
            .cwd = "/project",
            .binary_basename = "a.zig",
        }),
    );
}

test "binary compile unit allowance preserves exact mapping framing" {
    // Accepting source-unowned metadata must not hide missing or extra frames.
    const options: Options = .{ .cwd = "/project", .binary_basename = "ozai-test" };
    try checkMapping("ozai-test:?\n", 1, options);
    const texts = [_][]const u8{
        "ozai-test:?",
        "ozai-test:?\n\n",
        "ozai-test:?\n??:0\n",
        "",
    };
    for (texts) |text| {
        try std.testing.expectError(error.PartialMapping, checkMapping(text, 1, options));
    }
    try std.testing.expectError(
        error.PartialMapping,
        checkMapping("ozai-test:?\n", 2, options),
    );
}
