const std = @import("std");
pub const ParseError = error{ OutOfMemory, InvalidZbcPolicy };

pub const SourceFile = struct {
    path: []const u8,
    source_sha256: []const u8,
    reason: []const u8,
};

pub const Policy = struct {
    schema: u32,
    tool_sha256: []const u8,
    files: []const SourceFile,
};

test "schema rejects malformed duplicate missing unknown and incorrectly typed fields" {
    const tool = "0" ** 64;
    const cases = [_][]const u8{
        "{}",
        "null",
        "[]",
        "{",
        "{\"schema\":1,\"tool_sha256\":\"" ++ tool ++ "\",\"files\":[],\"extra\":0}",
        "{\"schema\":1,\"schema\":1,\"tool_sha256\":\"" ++ tool ++ "\",\"files\":[]}",
        "{\"schema\":\"1\",\"tool_sha256\":\"" ++ tool ++ "\",\"files\":[]}",
        "{\"schema\":1.0,\"tool_sha256\":\"" ++ tool ++ "\",\"files\":[]}",
        "{\"schema\":2,\"tool_sha256\":\"" ++ tool ++ "\",\"files\":[]}",
        "{\"schema\":1,\"tool_sha256\":\"bad\",\"files\":[]}",
        "{\"schema\":1,\"tool_sha256\":\"" ++ tool ++ "\",\"files\":[{}]}",
    };
    for (cases) |bytes| {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();
        try std.testing.expectError(error.InvalidZbcPolicy, parse(arena.allocator(), bytes));
    }
}

test "record values require canonical Zig paths lower hashes and nonempty reasons" {
    const cases = .{
        .{ "path", "../scripts/example.zig" }, .{ "path", "./scripts/example.zig" },
        .{ "path", "/scripts/example.zig" },   .{ "path", "scripts//example.zig" },
        .{ "path", "scripts/./example.zig" },  .{ "path", "scripts\\example.zig" },
        .{ "path", "scripts/example.zig/" },   .{ "path", "" },
        .{ "path", "scripts/example.txt" },    .{ "source_sha256", "A" ** 64 },
        .{ "source_sha256", "0" ** 63 },       .{ "reason", " \t\r\n" },
    };
    inline for (cases) |case| {
        var record: SourceFile = .{
            .path = "scripts/example.zig",
            .source_sha256 = "0" ** 64,
            .reason = "Reviewed.",
        };
        @field(record, case[0]) = case[1];
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();
        const bytes = try std.json.Stringify.valueAlloc(arena.allocator(), Policy{
            .schema = 1,
            .tool_sha256 = "0" ** 64,
            .files = &.{record},
        }, .{});
        try std.testing.expectError(error.InvalidZbcPolicy, parse(arena.allocator(), bytes));
    }
}

test "strict record JSON rejects duplicate extra missing and nonstring fields" {
    const gpa = std.testing.allocator;
    const valid = try std.json.Stringify.valueAlloc(gpa, Policy{
        .schema = 1,
        .tool_sha256 = "0" ** 64,
        .files = &.{.{
            .path = "scripts/example.zig",
            .source_sha256 = "0" ** 64,
            .reason = "Reviewed.",
        }},
    }, .{});
    defer gpa.free(valid);
    for (0..5) |case| {
        var arena = std.heap.ArenaAllocator.init(gpa);
        defer arena.deinit();
        const temporary = arena.allocator();
        var value = try std.json.parseFromSliceLeaky(std.json.Value, temporary, valid, .{});
        const files = value.object.getPtr("files") orelse return error.TestUnexpectedResult;
        const record = &files.array.items[0];
        switch (case) {
            0 => try record.object.put(temporary, "extra", .null),
            1 => try std.testing.expect(record.object.swapRemove("reason")),
            2 => {
                const path = record.object.getPtr("path") orelse return error.TestUnexpectedResult;
                path.* = .{ .integer = 1 };
            },
            3 => {
                const hash = record.object.getPtr("source_sha256") orelse
                    return error.TestUnexpectedResult;
                hash.* = .null;
            },
            4 => {
                const reason = record.object.getPtr("reason") orelse
                    return error.TestUnexpectedResult;
                reason.* = .{ .array = .init(temporary) };
            },
            else => unreachable,
        }
        const malformed = try std.json.Stringify.valueAlloc(temporary, value, .{});
        try std.testing.expectError(error.InvalidZbcPolicy, parse(temporary, malformed));
    }
    const duplicate =
        "{\"schema\":1,\"tool_sha256\":\"" ++ "0" ** 64 ++ "\",\"files\":[" ++
        "{\"path\":\"a.zig\",\"path\":\"a.zig\",\"source_sha256\":\"" ++ "0" ** 64 ++
        "\",\"reason\":\"Reviewed.\"}]}";
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    try std.testing.expectError(error.InvalidZbcPolicy, parse(arena.allocator(), duplicate));
}

// Dynamic values preserve JSON types: typed integer parsing also accepts numeric strings.
pub fn parse(gpa: std.mem.Allocator, bytes: []const u8) ParseError!Policy {
    const value = std.json.parseFromSliceLeaky(std.json.Value, gpa, bytes, .{
        .duplicate_field_behavior = .@"error",
    }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidZbcPolicy,
    };
    try exactObject(Policy, value);
    const version = try field(value, "schema");
    if (version != .integer or version.integer != 1) return error.InvalidZbcPolicy;
    const tool = try text(try field(value, "tool_sha256"));
    if (!validHash(tool)) return error.InvalidZbcPolicy;
    const records = try field(value, "files");
    if (records != .array) return error.InvalidZbcPolicy;
    const source_files = try gpa.alloc(SourceFile, records.array.items.len);
    for (records.array.items, source_files) |record, *source_file| {
        // Only count/contains read the parsed object; neither can grow records.array.
        // zbc-disable-next-line: slice-loop-reentrant-grow
        try exactObject(SourceFile, record);
        source_file.* = .{
            // get returns a value without mutation; text only borrows its immutable string.
            // zbc-disable-next-line: slice-loop-reentrant-grow
            .path = try text(try field(record, "path")),
            // The hash lookup is read-only; this output allocation is separate from records.array.
            // zbc-disable-next-line: slice-loop-reentrant-grow
            .source_sha256 = try text(try field(record, "source_sha256")),
            // The reason lookup only reads the parsed object and cannot resize records.array.
            // zbc-disable-next-line: slice-loop-reentrant-grow
            .reason = try text(try field(record, "reason")),
        };
        // Path/hash validation reads immutable bytes; only the local split cursor changes.
        // zbc-disable-next-line: slice-loop-reentrant-grow
        if (!validPath(source_file.path) or !validHash(source_file.source_sha256))
            return error.InvalidZbcPolicy;
        if (std.mem.trim(u8, source_file.reason, &std.ascii.whitespace).len == 0)
            return error.InvalidZbcPolicy;
    }
    return .{ .schema = 1, .tool_sha256 = tool, .files = source_files };
}

fn exactObject(comptime T: type, value: std.json.Value) error{InvalidZbcPolicy}!void {
    if (value != .object) return error.InvalidZbcPolicy;
    const fields = std.meta.fields(T);
    if (value.object.count() != fields.len) return error.InvalidZbcPolicy;
    inline for (fields) |entry| {
        if (!value.object.contains(entry.name)) return error.InvalidZbcPolicy;
    }
}

fn field(value: std.json.Value, name: []const u8) error{InvalidZbcPolicy}!std.json.Value {
    return value.object.get(name) orelse error.InvalidZbcPolicy;
}

fn text(value: std.json.Value) error{InvalidZbcPolicy}![]const u8 {
    if (value != .string) return error.InvalidZbcPolicy;
    return value.string;
}

pub fn validHash(bytes: []const u8) bool {
    if (bytes.len != 64) return false;
    for (bytes) |byte| {
        if (!(byte >= '0' and byte <= '9') and !(byte >= 'a' and byte <= 'f')) return false;
    }
    return true;
}

pub fn validPath(path: []const u8) bool {
    if (!std.mem.endsWith(u8, path, ".zig")) return false;
    for (path) |byte| {
        if (byte < 0x20 or byte == 0x7f or byte == '\\' or byte == ':') return false;
    }
    var parts = std.mem.splitScalar(u8, path, '/');
    while (parts.next()) |part| {
        if (part.len == 0 or std.mem.eql(u8, part, ".") or std.mem.eql(u8, part, ".."))
            return false;
    }
    return true;
}
