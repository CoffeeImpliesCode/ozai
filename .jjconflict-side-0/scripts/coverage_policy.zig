const std = @import("std");

const fixture_item: Item = .{ .mode = "Debug", .path = "src/a.zig", .source_sha256 = "abc", .line = 7, .unit = "inferred_line" };
const fixture_disposition: Disposition = .{ .mode = "Debug", .path = "src/a.zig", .source_sha256 = "abc", .line = 7, .unit = "inferred_line", .action = "accept", .reason = "Defensive failure after validated bounds; tested through caller." };
fn fixtureLedger(dispositions: []const Disposition) Ledger {
    return .{ .schema = 1, .source_digest = "current", .compiler = "0.16.0", .scope = scope, .modes = modes, .dispositions = dispositions };
}
test "current complete dispositions pass" {
    try validate(std.testing.allocator, fixtureLedger(&.{fixture_disposition}), "current", "0.16.0", &.{fixture_item});
}
test "new cold item without disposition fails" {
    try std.testing.expectError(error.MissingDisposition, validate(std.testing.allocator, fixtureLedger(&.{}), "current", "0.16.0", &.{fixture_item}));
}
test "stale source digest fails before dispositions" {
    try std.testing.expectError(error.StaleLedger, validate(std.testing.allocator, fixtureLedger(&.{fixture_disposition}), "changed", "0.16.0", &.{fixture_item}));
}
test "partial mode scope fails" {
    var ledger = fixtureLedger(&.{fixture_disposition});
    ledger.modes = &.{"Debug"};
    try std.testing.expectError(error.PartialScope, validate(std.testing.allocator, ledger, "current", "0.16.0", &.{fixture_item}));
}
test "unmatched disposition cannot conceal removed finding" {
    try std.testing.expectError(error.UnmatchedDisposition, validate(std.testing.allocator, fixtureLedger(&.{fixture_disposition}), "current", "0.16.0", &.{}));
}
test "disallowed disposition fails" {
    var disposition = fixture_disposition;
    disposition.action = "skip";
    try std.testing.expectError(error.InvalidDisposition, validate(std.testing.allocator, fixtureLedger(&.{disposition}), "current", "0.16.0", &.{fixture_item}));
}
test "duplicate dispositions fail" {
    try std.testing.expectError(error.DuplicateDisposition, validate(std.testing.allocator, fixtureLedger(&.{ fixture_disposition, fixture_disposition }), "current", "0.16.0", &.{fixture_item}));
}
test "empty reason fails" {
    var disposition = fixture_disposition;
    disposition.reason = "  \n";
    try std.testing.expectError(error.InvalidDisposition, validate(std.testing.allocator, fixtureLedger(&.{disposition}), "current", "0.16.0", &.{fixture_item}));
}
test "unattributed source cannot be disposed as measured test" {
    var item = fixture_item;
    item.line = 0;
    item.unit = "unattributed_file";
    var disposition = fixture_disposition;
    disposition.line = 0;
    disposition.unit = "unattributed_file";
    disposition.action = "test";
    try std.testing.expectError(error.InvalidDisposition, validate(std.testing.allocator, fixtureLedger(&.{disposition}), "current", "0.16.0", &.{item}));
}
test "missing embedded record fails" {
    try std.testing.expectError(error.MissingLedger, extractRecord("# historical narrative only"));
}

pub const scope: []const []const u8 = &.{ "test", "test-portable", "quic-test", "invariants", "test-gate-policy" };
pub const modes: []const []const u8 = &.{ "Debug", "ReleaseSafe" };
pub const Item = struct {
    mode: []const u8,
    path: []const u8,
    source_sha256: []const u8,
    line: u32,
    unit: []const u8,
};
pub const Disposition = struct {
    mode: []const u8,
    path: []const u8,
    source_sha256: []const u8,
    line: u32,
    unit: []const u8,
    action: []const u8,
    reason: []const u8,
};
pub const Ledger = struct {
    schema: u32,
    source_digest: []const u8,
    compiler: []const u8,
    scope: []const []const u8,
    modes: []const []const u8,
    dispositions: []const Disposition,
};
fn equal(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}
fn same(a: anytype, b: anytype) bool {
    return equal(a.mode, b.mode) and equal(a.path, b.path) and
        equal(a.source_sha256, b.source_sha256) and a.line == b.line and equal(a.unit, b.unit);
}
fn exactList(a: []const []const u8, b: []const []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| {
        if (!equal(x, y)) return false;
    }
    return true;
}
pub fn validate(gpa: std.mem.Allocator, ledger: Ledger, digest: []const u8, compiler: []const u8, items: []const Item) !void {
    if (ledger.schema != 1 or !equal(ledger.source_digest, digest) or
        !equal(ledger.compiler, compiler)) return error.StaleLedger;
    if (!exactList(ledger.scope, scope) or !exactList(ledger.modes, modes)) return error.PartialScope;
    var identities: std.HashMap(Item, bool, ItemContext, 80) = .init(gpa);
    defer identities.deinit();
    for (items) |item| {
        const entry = try identities.getOrPut(item);
        if (entry.found_existing) return error.PartialScope;
        entry.value_ptr.* = false;
    }
    for (ledger.dispositions) |disposition| {
        const measured = equal(disposition.unit, "inferred_line") and disposition.line > 0;
        const unattributed = equal(disposition.unit, "unattributed_file") and disposition.line == 0;
        if ((!measured and !unattributed) or
            (!equal(disposition.action, "test") and !equal(disposition.action, "refactor") and
                !equal(disposition.action, "accept")) or
            (unattributed and equal(disposition.action, "test")) or
            std.mem.trim(u8, disposition.reason, " \t\r\n").len == 0)
            return error.InvalidDisposition;
        const item: Item = .{ .mode = disposition.mode, .path = disposition.path,
            .source_sha256 = disposition.source_sha256, .line = disposition.line,
            .unit = disposition.unit };
        const matched = identities.getPtr(item) orelse return error.UnmatchedDisposition;
        if (matched.*) return error.DuplicateDisposition;
        matched.* = true;
    }
    var iterator = identities.valueIterator();
    while (iterator.next()) |matched| {
        if (!matched.*) return error.MissingDisposition;
    }
}
const ItemContext = struct {
    pub fn hash(_: ItemContext, item: Item) u64 {
        var hasher = std.hash.Wyhash.init(0);
        hasher.update(item.mode);
        hasher.update(item.path);
        hasher.update(item.source_sha256);
        hasher.update(std.mem.asBytes(&item.line));
        hasher.update(item.unit);
        return hasher.final();
    }
    pub fn eql(_: ItemContext, a: Item, b: Item) bool {
        return same(a, b);
    }
};
pub fn extractRecord(markdown: []const u8) ![]const u8 {
    const marker = "```ozai-coverage-v1\n";
    const start = std.mem.indexOf(u8, markdown, marker) orelse return error.MissingLedger;
    const rest = markdown[start + marker.len ..];
    if (std.mem.indexOf(u8, rest, marker) != null) return error.DuplicateLedger;
    const end = std.mem.indexOf(u8, rest, "\n```") orelse return error.MissingLedger;
    return rest[0..end];
}
