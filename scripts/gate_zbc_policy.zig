const std = @import("std");
const schema = @import("gate_zbc_policy_schema.zig");
const native = @import("gate_zbc_native_suppression.zig");

pub const AuthenticateError = std.mem.Allocator.Error || std.process.CurrentPathAllocError ||
    std.Io.Dir.ReadFileAllocError || std.Io.Dir.RealPathFileError || schema.ParseError ||
    native.Error || error{
    InvalidZbcPolicy,
    StaleZbcTool,
    DuplicateZbcSourceException,
    DuplicateZbcInventory,
    ExtraZbcSourceException,
    MissingZbcSourceException,
    StaleZbcSource,
    InvalidZbcSource,
    InvalidZbcAnnotation,
};
const AnnotationError = native.Error || error{ InvalidZbcSource, InvalidZbcAnnotation };
const MatchSourceError = AnnotationError ||
    error{ ExtraZbcSourceException, MissingZbcSourceException, StaleZbcSource };

pub fn authenticate(
    gpa: std.mem.Allocator,
    io: std.Io,
    policy_bytes: []const u8,
    tool_sha256: []const u8,
    inventory: []const []const u8,
) AuthenticateError!usize {
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const temporary = arena.allocator();
    const policy = try schema.parse(temporary, policy_bytes);
    if (!schema.validHash(tool_sha256)) return error.InvalidZbcPolicy;
    if (!std.mem.eql(u8, tool_sha256, policy.tool_sha256)) return error.StaleZbcTool;
    var records: std.StringHashMapUnmanaged(schema.SourceFile) = .empty;
    for (policy.files) |record| {
        const entry = try records.getOrPut(temporary, record.path);
        if (entry.found_existing) return error.DuplicateZbcSourceException;
        entry.value_ptr.* = record;
    }
    const root = try std.process.currentPathAlloc(io, gpa);
    defer gpa.free(root);
    var seen: std.StringHashMapUnmanaged(void) = .empty;
    var authenticated: usize = 0;
    for (inventory) |input_path| {
        if (!std.mem.startsWith(u8, input_path, "./")) return error.InvalidZbcPolicy;
        const path = input_path[2..];
        if (!schema.validPath(path)) return error.InvalidZbcPolicy;
        const entry = try seen.getOrPut(temporary, path);
        if (entry.found_existing) return error.DuplicateZbcInventory;
        try authenticatePath(io, root, path);
        const source = try std.Io.Dir.cwd().readFileAllocOptions(
            io,
            path,
            gpa,
            .limited(16 * 1024 * 1024),
            .of(u8),
            0,
        );
        defer gpa.free(source);
        if (try matchSource(source, records.get(path))) authenticated += 1;
    }
    for (policy.files) |record| {
        if (!seen.contains(record.path)) return error.ExtraZbcSourceException;
    }
    return authenticated;
}

fn matchSource(source: [:0]const u8, record: ?schema.SourceFile) MatchSourceError!bool {
    const has_annotation = try annotated(source);
    if (!has_annotation) {
        if (record != null) return error.ExtraZbcSourceException;
        return false;
    }
    const reviewed = record orelse return error.MissingZbcSourceException;
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(source, &digest, .{});
    const hash = std.fmt.bytesToHex(digest, .lower);
    if (!std.mem.eql(u8, reviewed.source_sha256, &hash)) return error.StaleZbcSource;
    return true;
}

fn annotated(source: [:0]const u8) AnnotationError!bool {
    var tokenizer = std.zig.Tokenizer.init(source);
    var cursor = tokenizer.index;
    var found = false;
    while (cursor <= source.len) {
        const token = tokenizer.next();
        // Ordinary comments are skipped; token gaps exclude string and character literals.
        var gap_cursor = cursor;
        while (gap_cursor < token.loc.start) {
            const relative =
                std.mem.find(u8, source[gap_cursor..token.loc.start], "//") orelse break;
            const start = gap_cursor + relative;
            const end = start +
                (std.mem.indexOfScalar(u8, source[start..token.loc.start], '\n') orelse
                    (token.loc.start - start));
            if (try directive(source, start, end)) found = true;
            gap_cursor = end;
        }
        switch (token.tag) {
            .doc_comment, .container_doc_comment => {
                if (try directive(source, token.loc.start, token.loc.end)) found = true;
            },
            .invalid => return error.InvalidZbcSource,
            .eof => return found,
            else => try native.rejectLiteral(source, token.loc.start, token.loc.end),
        }
        cursor = token.loc.end;
    }
    unreachable;
}

fn directive(source: []const u8, start: usize, end: usize) error{InvalidZbcAnnotation}!bool {
    const comment = std.mem.trimEnd(u8, source[start..end], " \t\r");
    var suppression_like = false;
    for ([_][]const u8{ "zbc-disable", "zbc-enable", "zbc-ignore" }) |marker| {
        if (std.mem.find(u8, comment, marker) != null) suppression_like = true;
    }
    if (!suppression_like) return false;
    const next_line = "// zbc-disable-next-line: ";
    const same_line = "// zbc-disable-line: ";
    const rule = if (std.mem.startsWith(u8, comment, next_line))
        comment[next_line.len..]
    else if (std.mem.startsWith(u8, comment, same_line)) blk: {
        const line_start = if (std.mem.findScalarLast(u8, source[0..start], '\n')) |newline|
            newline + 1
        else
            0;
        if (std.mem.trim(u8, source[line_start..start], " \t\r").len == 0)
            return error.InvalidZbcAnnotation;
        break :blk comment[same_line.len..];
    } else return error.InvalidZbcAnnotation;
    if (rule.len == 0 or std.mem.eql(u8, rule, "all")) return error.InvalidZbcAnnotation;
    var segment_length: usize = 0;
    for (rule) |byte| {
        if (byte == '-') {
            if (segment_length == 0) return error.InvalidZbcAnnotation;
            segment_length = 0;
        } else {
            if (!(byte >= 'a' and byte <= 'z') and !(byte >= '0' and byte <= '9'))
                return error.InvalidZbcAnnotation;
            segment_length += 1;
        }
    }
    if (segment_length == 0) return error.InvalidZbcAnnotation;
    return true;
}

fn authenticatePath(
    io: std.Io,
    root: []const u8,
    path: []const u8,
) (std.Io.Dir.RealPathFileError || error{InvalidZbcPolicy})!void {
    var buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const resolved = buffer[0..try std.Io.Dir.cwd().realPathFile(io, path, &buffer)];
    // Reject symlink aliases as well as links escaping the project root.
    const separator: usize = if (std.mem.endsWith(u8, root, "/")) 0 else 1;
    if (resolved.len != root.len + separator + path.len) return error.InvalidZbcPolicy;
    if (!std.mem.startsWith(u8, resolved, root)) return error.InvalidZbcPolicy;
    if (separator == 1 and resolved[root.len] != '/') return error.InvalidZbcPolicy;
    if (!std.mem.eql(u8, resolved[root.len + separator ..], path))
        return error.InvalidZbcPolicy;
}

const test_tool = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const annotated_source = "// zbc-disable-next-line: unchecked-error\nconst value = 1;\n";

test "tokenizer distinguishes comments from ordinary and multiline fixture strings" {
    try std.testing.expect(!try annotated(
        "const text = \"// zbc-disable-file: *\";\n" ++
            "const fixture =\n    \\\\// zbc-ignore: all\n;\n",
    ));
    try std.testing.expect(try annotated(annotated_source));
    try std.testing.expect(try annotated("const value = 1; // zbc-disable-line: rule-2\n"));
    try std.testing.expect(!try annotated("// An ordinary explanation.\nconst value = 1;\n"));
}

test "all broad malformed and unsupported actual comment suppressions fail closed" {
    const comments = [_][:0]const u8{
        "// zbc-disable\n",
        "// zbc-disable-file: unchecked-error\n",
        "// zbc-enable: unchecked-error\n",
        "// zbc-ignore: unchecked-error\n",
        "// zbc-disable-next-line: *\n",
        "// zbc-disable-next-line: all\n",
        "// zbc-disable-next-line: Uppercase\n",
        "// zbc-disable-next-line: bad_rule\n",
        "// zbc-disable-next-line: -rule\n",
        "// zbc-disable-next-line: rule-\n",
        "// zbc-disable-next-line: rule--name\n",
        "// " ++ "zbc-disable-next-line: rule,other\n",
        "// zbc-disable-next-line: \n",
        "//zbc-disable-next-line: rule\n",
        "/// zbc-disable-next-line: rule\n",
        "//! zbc-disable-next-line: rule\n",
        "// Mentioning zbc-disable in commentary cannot authorize a suppression.\n",
        "// zbc-disable-line: rule\n",
    };
    for (comments) |source| {
        try std.testing.expectError(error.InvalidZbcAnnotation, annotated(source));
    }
}

test "source matching rejects missing stale extra and newly introduced annotations" {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(annotated_source, &digest, .{});
    const hash = std.fmt.bytesToHex(digest, .lower);
    const record: schema.SourceFile = .{
        .path = "scripts/example.zig",
        .source_sha256 = &hash,
        .reason = "Reviewed precise rule.",
    };
    try std.testing.expect(try matchSource(annotated_source, record));
    try std.testing.expectError(
        error.MissingZbcSourceException,
        matchSource(annotated_source, null),
    );
    try std.testing.expectError(
        error.ExtraZbcSourceException,
        matchSource("const value = 1;\n", record),
    );
    try std.testing.expectError(
        error.StaleZbcSource,
        matchSource(annotated_source ++ "\n", record),
    );
    try std.testing.expect(!try matchSource("const value = 1;\n", null));
}

fn testAuthenticate(
    records: []const schema.SourceFile,
    inventory: []const []const u8,
    tool: []const u8,
) AuthenticateError!usize {
    const gpa = std.testing.allocator;
    const bytes = try std.json.Stringify.valueAlloc(gpa, schema.Policy{
        .schema = 1,
        .tool_sha256 = test_tool,
        .files = records,
    }, .{});
    defer gpa.free(bytes);
    return authenticate(gpa, std.testing.io, bytes, tool, inventory);
}

test "authentication scans current repository source not strings within guard fixtures" {
    try std.testing.expectEqual(
        @as(usize, 0),
        try testAuthenticate(&.{}, &.{"./scripts/gate_zbc_policy.zig"}, test_tool),
    );
    try std.testing.expectError(error.StaleZbcTool, testAuthenticate(&.{}, &.{}, &@as([64:0]u8, @splat('a'))));
    try std.testing.expectError(
        error.InvalidZbcPolicy,
        testAuthenticate(&.{}, &.{"scripts/gate_zbc_policy.zig"}, test_tool),
    );
    try std.testing.expectError(
        error.DuplicateZbcInventory,
        testAuthenticate(
            &.{},
            &.{ "./scripts/gate_zbc_policy.zig", "./scripts/gate_zbc_policy.zig" },
            test_tool,
        ),
    );
    const record: schema.SourceFile = .{
        .path = "scripts/gate_zbc_policy.zig",
        .source_sha256 = &@as([64:0]u8, @splat('0')),
        .reason = "This unannotated record is forbidden.",
    };
    try std.testing.expectError(
        error.ExtraZbcSourceException,
        testAuthenticate(&.{record}, &.{}, test_tool),
    );
    try std.testing.expectError(
        error.ExtraZbcSourceException,
        testAuthenticate(&.{record}, &.{"./scripts/gate_zbc_policy.zig"}, test_tool),
    );
    try std.testing.expectError(
        error.DuplicateZbcSourceException,
        testAuthenticate(&.{ record, record }, &.{}, test_tool),
    );
}

test "policy schema declarations remain reachable" {
    std.testing.refAllDecls(schema);
    std.testing.refAllDecls(@This());
    std.testing.refAllDecls(native);
}

test "authentication accepts reviewed annotated repository file and rejects new registration" {
    const gpa = std.testing.allocator;
    const path = "scripts/gate_measure.zig";
    const source = try std.Io.Dir.cwd().readFileAllocOptions(
        std.testing.io,
        path,
        gpa,
        .limited(16 * 1024 * 1024),
        .of(u8),
        0,
    );
    defer gpa.free(source);
    try std.testing.expect(try annotated(source));
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(source, &digest, .{});
    const hash = std.fmt.bytesToHex(digest, .lower);
    var record: schema.SourceFile = .{
        .path = path,
        .source_sha256 = &hash,
        .reason = "Bounded heap allocation intentionally " ++
            "leaves freshly allocated storage undefined.",
    };
    try std.testing.expectEqual(@as(usize, 1), try testAuthenticate(
        &.{record},
        &.{"./scripts/gate_measure.zig"},
        test_tool,
    ));
    try std.testing.expectError(
        error.MissingZbcSourceException,
        testAuthenticate(&.{}, &.{"./scripts/gate_measure.zig"}, test_tool),
    );
    record.source_sha256 = &@as([64:0]u8, @splat('0'));
    try std.testing.expectError(
        error.StaleZbcSource,
        testAuthenticate(&.{record}, &.{"./scripts/gate_measure.zig"}, test_tool),
    );
}

test "raw native literal suppression bypasses fail without becoming registered annotations" {
    const fixtures = [_][:0]const u8{
        "const text = \"// " ++ "zbc-disable-next-line: * \";\nconst x: u8 = undefined;\n",
        "const text = \"// " ++ "zbc-disable-line: use-undefined \";\n",
        "const text = \"// " ++ "zbc-disable-next-line: bogus,use-undefined \";\n",
        "const text =\n    \\\\// " ++ "zbc-disable-next-line: use-undefined\n;\n",
        "const text = \"// " ++ "zbc-disable-next-line: , * \";\n",
    };
    for (fixtures) |source| {
        try std.testing.expectError(error.InvalidZbcAnnotation, annotated(source));
    }
    try std.testing.expect(!try annotated(
        "const text = \"// not a directive // " ++ "zbc-disable-next-line: * \";\n",
    ));
    try std.testing.expect(!try annotated(
        "const text = \"// " ++ "zbc-disable-next-line: use-undefined\";\n",
    ));
}
