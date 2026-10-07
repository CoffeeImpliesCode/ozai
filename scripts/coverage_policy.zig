const std = @import("std");

pub const ValidateError = std.mem.Allocator.Error || error{
    StaleLedger,
    InvalidMeasurementReference,
    PartialScope,
    InvalidDisposition,
    UnmatchedDisposition,
    DuplicateDisposition,
    MissingDisposition,
};
pub const CountsError = error{
    PartialScope,
    MissingDisposition,
    InvalidDisposition,
    UnmatchedDisposition,
};
pub const ReferenceError = error{InvalidMeasurementReference};
pub const RecordError = error{ MissingLedger, DuplicateLedger };

const fixture_item: Item = .{
    .mode = "Debug",
    .path = "src/a.zig",
    .source_sha256 = "abc",
    .line = 7,
    .unit = "inferred_line",
};
const fixture_disposition: Disposition = .{
    .mode = "Debug",
    .path = "src/a.zig",
    .source_sha256 = "abc",
    .line = 7,
    .unit = "inferred_line",
    .action = "accept",
    .reason = "Defensive failure after validated bounds; tested through caller.",
};
fn fixtureLedger(dispositions: []const Disposition) Ledger {
    return .{
        .schema = schema_version,
        .source_digest = "current",
        .compiler = "0.16.0",
        .measurement = .{
            .path = "/retained/measurement.json",
            .sha256 = "a" ** 64,
        },
        .scope = scope,
        .modes = modes,
        .dispositions = dispositions,
        .unmapped_project = &.{},
        .unowned = &fixture_zero_unowned,
    };
}
test "current complete dispositions pass" {
    try validate(
        std.testing.allocator,
        fixtureLedger(&.{fixture_disposition}),
        "current",
        "0.16.0",
        &.{fixture_item},
    );
}
test "new cold item without disposition fails" {
    try std.testing.expectError(
        error.MissingDisposition,
        validate(
            std.testing.allocator,
            fixtureLedger(&.{}),
            "current",
            "0.16.0",
            &.{fixture_item},
        ),
    );
}
test "stale source digest fails before dispositions" {
    try std.testing.expectError(
        error.StaleLedger,
        validate(
            std.testing.allocator,
            fixtureLedger(&.{fixture_disposition}),
            "changed",
            "0.16.0",
            &.{fixture_item},
        ),
    );
}
test "partial mode scope fails" {
    var ledger = fixtureLedger(&.{fixture_disposition});
    ledger.modes = &.{"Debug"};
    try std.testing.expectError(
        error.PartialScope,
        validate(
            std.testing.allocator,
            ledger,
            "current",
            "0.16.0",
            &.{fixture_item},
        ),
    );
}
test "unmatched disposition cannot conceal removed finding" {
    try std.testing.expectError(
        error.UnmatchedDisposition,
        validate(
            std.testing.allocator,
            fixtureLedger(&.{fixture_disposition}),
            "current",
            "0.16.0",
            &.{},
        ),
    );
}
test "disallowed disposition fails" {
    var disposition = fixture_disposition;
    disposition.action = "skip";
    try std.testing.expectError(
        error.InvalidDisposition,
        validate(
            std.testing.allocator,
            fixtureLedger(&.{disposition}),
            "current",
            "0.16.0",
            &.{fixture_item},
        ),
    );
}
test "duplicate dispositions fail" {
    try std.testing.expectError(
        error.DuplicateDisposition,
        validate(
            std.testing.allocator,
            fixtureLedger(&.{ fixture_disposition, fixture_disposition }),
            "current",
            "0.16.0",
            &.{fixture_item},
        ),
    );
}
test "empty reason fails" {
    var disposition = fixture_disposition;
    disposition.reason = "  \n";
    try std.testing.expectError(
        error.InvalidDisposition,
        validate(
            std.testing.allocator,
            fixtureLedger(&.{disposition}),
            "current",
            "0.16.0",
            &.{fixture_item},
        ),
    );
}
test "unattributed source cannot be disposed as measured test" {
    var item = fixture_item;
    item.line = 0;
    item.unit = "unattributed_file";
    var disposition = fixture_disposition;
    disposition.line = 0;
    disposition.unit = "unattributed_file";
    disposition.action = "test";
    try std.testing.expectError(
        error.InvalidDisposition,
        validate(
            std.testing.allocator,
            fixtureLedger(&.{disposition}),
            "current",
            "0.16.0",
            &.{item},
        ),
    );
}
test "missing embedded record fails" {
    try std.testing.expectError(error.MissingLedger, extractRecord("# historical narrative only"));
}

const fixture_unmapped: UnmappedCounts = .{
    .mode = "Debug",
    .unmapped_project_blocks = 2,
    .unmapped_project_hits = 1,
};
const fixture_unmapped_disposition: UnmappedDisposition = .{
    .mode = "Debug",
    .unmapped_project_blocks = 2,
    .unmapped_project_hits = 1,
    .reason = "Compiler DWARF line 0 for test/expected_log_runner.zig's accounted helper; " ++
        "no source-line coverage claim.",
};

test "unmapped project disposition requires exact counts and a nonempty rationale" {
    var safe = fixture_unmapped;
    safe.mode = "ReleaseSafe";
    var safe_disposition = fixture_unmapped_disposition;
    safe_disposition.mode = "ReleaseSafe";
    var ledger = fixtureLedger(&.{});
    const counts = [_]UnmappedCounts{ fixture_unmapped, safe };
    var dispositions = [_]UnmappedDisposition{ fixture_unmapped_disposition, safe_disposition };
    ledger.unmapped_project = &dispositions;
    try validateUnmapped(ledger, &counts);
    dispositions[0].unmapped_project_blocks = 3;
    try std.testing.expectError(error.UnmatchedDisposition, validateUnmapped(ledger, &counts));
    dispositions[0].unmapped_project_blocks = 2;
    dispositions[0].unmapped_project_hits = 0;
    try std.testing.expectError(error.UnmatchedDisposition, validateUnmapped(ledger, &counts));
    dispositions[0].unmapped_project_hits = 1;
    dispositions[0].reason = " \t\n";
    try std.testing.expectError(error.InvalidDisposition, validateUnmapped(ledger, &counts));
    ledger.unmapped_project = &.{fixture_unmapped_disposition};
    try std.testing.expectError(error.MissingDisposition, validateUnmapped(ledger, &counts));
    ledger.unmapped_project = &.{ fixture_unmapped_disposition, fixture_unmapped_disposition };
    try std.testing.expectError(error.PartialScope, validateUnmapped(ledger, &counts));
}

test "zero unmapped count still requires an explicit per mode rationale" {
    const counts = [_]UnmappedCounts{
        .{ .mode = "Debug", .unmapped_project_blocks = 0, .unmapped_project_hits = 0 },
        .{ .mode = "ReleaseSafe", .unmapped_project_blocks = 0, .unmapped_project_hits = 0 },
    };
    var dispositions = [_]UnmappedDisposition{
        .{
            .mode = "Debug",
            .unmapped_project_blocks = 0,
            .unmapped_project_hits = 0,
            .reason = "No compiler DWARF line 0 project counters in this mode.",
        },
        .{
            .mode = "ReleaseSafe",
            .unmapped_project_blocks = 0,
            .unmapped_project_hits = 0,
            .reason = "No compiler DWARF line 0 project counters in this mode.",
        },
    };
    var ledger = fixtureLedger(&.{});
    ledger.unmapped_project = &dispositions;
    try validateUnmapped(ledger, &counts);
    dispositions[1].reason = "";
    try std.testing.expectError(error.InvalidDisposition, validateUnmapped(ledger, &counts));
}

test "machine ledger cannot omit unmapped disposition or rationale fields" {
    const missing =
        \\{"schema":3,"source_digest":"current","compiler":"0.16.0",
        \\ "measurement":{"path":"/retained/measurement.json",
        \\ "sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
        \\ "scope":[],"modes":[],"dispositions":[],"unowned":[]}
    ;
    try std.testing.expectError(
        error.MissingField,
        std.json.parseFromSlice(
            Ledger,
            std.testing.allocator,
            missing,
            .{},
        ),
    );
    const missing_reason =
        \\{"mode":"Debug","unmapped_project_blocks":2,"unmapped_project_hits":1}
    ;
    try std.testing.expectError(
        error.MissingField,
        std.json.parseFromSlice(
            UnmappedDisposition,
            std.testing.allocator,
            missing_reason,
            .{},
        ),
    );
}

const fixture_unowned: UnownedCounts = .{
    .mode = "Debug",
    .unowned_blocks = 2,
    .unowned_hits = 1,
};
const fixture_unowned_disposition: UnownedDisposition = .{
    .mode = "Debug",
    .unowned_blocks = 2,
    .unowned_hits = 1,
    .reason = "Binary counters have no compiler source ownership; no source coverage claim.",
};
const fixture_zero_unowned = [_]UnownedDisposition{
    .{
        .mode = "Debug",
        .unowned_blocks = 0,
        .unowned_hits = 0,
        .reason = "No source-unowned binary counters in this mode.",
    },
    .{
        .mode = "ReleaseSafe",
        .unowned_blocks = 0,
        .unowned_hits = 0,
        .reason = "No source-unowned binary counters in this mode.",
    },
};

test "unowned dispositions require exact counts and nonempty rationale" {
    var safe = fixture_unowned;
    safe.mode = "ReleaseSafe";
    var safe_disposition = fixture_unowned_disposition;
    safe_disposition.mode = "ReleaseSafe";
    var ledger = fixtureLedger(&.{});
    var counts = [_]UnownedCounts{ fixture_unowned, safe };
    var dispositions = [_]UnownedDisposition{ fixture_unowned_disposition, safe_disposition };
    ledger.unowned = &dispositions;
    try validateUnowned(ledger, &counts);
    dispositions[0].unowned_blocks = 3;
    try std.testing.expectError(error.UnmatchedDisposition, validateUnowned(ledger, &counts));
    dispositions[0].unowned_blocks = 2;
    dispositions[0].unowned_hits = 0;
    try std.testing.expectError(error.UnmatchedDisposition, validateUnowned(ledger, &counts));
    dispositions[0].unowned_hits = 3;
    try std.testing.expectError(error.InvalidDisposition, validateUnowned(ledger, &counts));
    dispositions[0].unowned_hits = 1;
    counts[0].unowned_hits = 3;
    try std.testing.expectError(error.InvalidDisposition, validateUnowned(ledger, &counts));
    counts[0].unowned_hits = 1;
    dispositions[0].reason = " \t\r\n";
    try std.testing.expectError(error.InvalidDisposition, validateUnowned(ledger, &counts));
}

test "unowned records match every ledger mode exactly in order" {
    var safe = fixture_unowned;
    safe.mode = "ReleaseSafe";
    var safe_disposition = fixture_unowned_disposition;
    safe_disposition.mode = "ReleaseSafe";
    const counts = [_]UnownedCounts{ fixture_unowned, safe };
    var ledger = fixtureLedger(&.{});
    ledger.unowned = &.{ fixture_unowned_disposition, safe_disposition };
    try validateUnowned(ledger, &counts);
    try std.testing.expectError(
        error.PartialScope,
        validateUnowned(ledger, &.{fixture_unowned}),
    );
    try std.testing.expectError(
        error.PartialScope,
        validateUnowned(ledger, &.{ fixture_unowned, safe, safe }),
    );
    try std.testing.expectError(
        error.PartialScope,
        validateUnowned(ledger, &.{ safe, fixture_unowned }),
    );
    try std.testing.expectError(
        error.PartialScope,
        validateUnowned(ledger, &.{ fixture_unowned, fixture_unowned }),
    );
    ledger.unowned = &.{fixture_unowned_disposition};
    try std.testing.expectError(error.MissingDisposition, validateUnowned(ledger, &counts));
    ledger.unowned = &.{ fixture_unowned_disposition, safe_disposition, safe_disposition };
    try std.testing.expectError(error.MissingDisposition, validateUnowned(ledger, &counts));
    ledger.unowned = &.{ safe_disposition, fixture_unowned_disposition };
    try std.testing.expectError(error.PartialScope, validateUnowned(ledger, &counts));
    ledger.unowned = &.{ fixture_unowned_disposition, fixture_unowned_disposition };
    try std.testing.expectError(error.PartialScope, validateUnowned(ledger, &counts));
    var stale = safe_disposition;
    stale.mode = "ReleaseFast";
    ledger.unowned = &.{ fixture_unowned_disposition, stale };
    try std.testing.expectError(error.PartialScope, validateUnowned(ledger, &counts));
    ledger.unowned = &.{ fixture_unowned_disposition, safe_disposition };
    ledger.modes = &.{"Debug"};
    try std.testing.expectError(error.PartialScope, validateUnowned(ledger, &counts));
}

test "zero unowned counts still require explicit rationale in every mode" {
    const counts = [_]UnownedCounts{
        .{ .mode = "Debug", .unowned_blocks = 0, .unowned_hits = 0 },
        .{ .mode = "ReleaseSafe", .unowned_blocks = 0, .unowned_hits = 0 },
    };
    var dispositions = fixture_zero_unowned;
    var ledger = fixtureLedger(&.{});
    ledger.unowned = &dispositions;
    try validateUnowned(ledger, &counts);
    for (&dispositions) |*disposition| {
        const reason = disposition.reason;
        disposition.reason = "";
        try std.testing.expectError(error.InvalidDisposition, validateUnowned(ledger, &counts));
        disposition.reason = reason;
    }
    ledger.unowned = &.{};
    try std.testing.expectError(error.MissingDisposition, validateUnowned(ledger, &counts));
}

test "machine ledger requires unowned records and all unowned record fields" {
    const missing_unowned =
        \\{"schema":3,"source_digest":"current","compiler":"0.16.0",
        \\ "measurement":{"path":"/retained/measurement.json",
        \\ "sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
        \\ "scope":[],"modes":[],"dispositions":[],"unmapped_project":[]}
    ;
    try std.testing.expectError(
        error.MissingField,
        std.json.parseFromSlice(Ledger, std.testing.allocator, missing_unowned, .{}),
    );
    const missing_fields = [_][]const u8{
        \\{"unowned_blocks":2,"unowned_hits":1,"reason":"Reviewed"}
        ,
        \\{"mode":"Debug","unowned_hits":1,"reason":"Reviewed"}
        ,
        \\{"mode":"Debug","unowned_blocks":2,"reason":"Reviewed"}
        ,
        \\{"mode":"Debug","unowned_blocks":2,"unowned_hits":1}
        ,
    };
    for (missing_fields) |missing| {
        try std.testing.expectError(
            error.MissingField,
            std.json.parseFromSlice(UnownedDisposition, std.testing.allocator, missing, .{}),
        );
    }
    const missing_counts = [_][]const u8{
        \\{"unowned_blocks":2,"unowned_hits":1}
        ,
        \\{"mode":"Debug","unowned_hits":1}
        ,
        \\{"mode":"Debug","unowned_blocks":2}
        ,
    };
    for (missing_counts) |missing| {
        try std.testing.expectError(
            error.MissingField,
            std.json.parseFromSlice(UnownedCounts, std.testing.allocator, missing, .{}),
        );
    }
}

pub const schema_version: u32 = 3;
pub const MeasurementReference = struct {
    path: []const u8,
    sha256: []const u8,
};

pub const scope: []const []const u8 = &.{
    "test",
    "test-portable",
    "quic-test",
    "invariants",
    "test-gate-policy",
};
pub const modes: []const []const u8 = &.{ "Debug", "ReleaseSafe" };
pub const UnmappedCounts = struct {
    mode: []const u8,
    unmapped_project_blocks: u64,
    unmapped_project_hits: u64,
};
pub const UnmappedDisposition = struct {
    mode: []const u8,
    unmapped_project_blocks: u64,
    unmapped_project_hits: u64,
    reason: []const u8,
};
/// Unique binary counters without source ownership; not part of source coverage denominators.
pub const UnownedCounts = struct {
    mode: []const u8,
    unowned_blocks: u64,
    unowned_hits: u64,
};
pub const UnownedDisposition = struct {
    mode: []const u8,
    unowned_blocks: u64,
    unowned_hits: u64,
    reason: []const u8,
};
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
    measurement: MeasurementReference,
    scope: []const []const u8,
    modes: []const []const u8,
    dispositions: []const Disposition,
    unmapped_project: []const UnmappedDisposition,
    unowned: []const UnownedDisposition,
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
pub fn validate(
    gpa: std.mem.Allocator,
    ledger: Ledger,
    digest: []const u8,
    compiler: []const u8,
    items: []const Item,
) ValidateError!void {
    if (ledger.schema != schema_version or !equal(ledger.source_digest, digest) or
        !equal(ledger.compiler, compiler)) return error.StaleLedger;
    try validateReference(ledger.measurement);
    if (!exactList(ledger.scope, scope) or
        !exactList(ledger.modes, modes)) return error.PartialScope;
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
        const item: Item = .{
            .mode = disposition.mode,
            .path = disposition.path,
            .source_sha256 = disposition.source_sha256,
            .line = disposition.line,
            .unit = disposition.unit,
        };
        const matched = identities.getPtr(item) orelse return error.UnmatchedDisposition;
        if (matched.*) return error.DuplicateDisposition;
        matched.* = true;
    }
    var iterator = identities.valueIterator();
    while (iterator.next()) |matched| {
        if (!matched.*) return error.MissingDisposition;
    }
}

pub fn validateUnmapped(ledger: Ledger, counts: []const UnmappedCounts) CountsError!void {
    if (counts.len != modes.len) return error.PartialScope;
    if (ledger.unmapped_project.len != modes.len) return error.MissingDisposition;
    for (counts, ledger.unmapped_project, modes) |count, disposition, mode| {
        if (!equal(count.mode, mode) or !equal(disposition.mode, mode))
            return error.PartialScope;
        if (disposition.unmapped_project_hits > disposition.unmapped_project_blocks or
            std.mem.trim(u8, disposition.reason, " \t\r\n").len == 0)
            return error.InvalidDisposition;
        if (count.unmapped_project_blocks != disposition.unmapped_project_blocks or
            count.unmapped_project_hits != disposition.unmapped_project_hits)
            return error.UnmatchedDisposition;
    }
}

/// Requires exact ordered per-mode binary counts and an explicit rationale, including zero counts.
pub fn validateUnowned(ledger: Ledger, counts: []const UnownedCounts) CountsError!void {
    if (!exactList(ledger.modes, modes) or counts.len != ledger.modes.len)
        return error.PartialScope;
    if (ledger.unowned.len != ledger.modes.len) return error.MissingDisposition;
    for (counts, ledger.unowned, ledger.modes) |count, disposition, mode| {
        if (!equal(count.mode, mode) or !equal(disposition.mode, mode))
            return error.PartialScope;
        if (count.unowned_hits > count.unowned_blocks or
            disposition.unowned_hits > disposition.unowned_blocks or
            std.mem.trim(u8, disposition.reason, " \t\r\n").len == 0)
            return error.InvalidDisposition;
        if (count.unowned_blocks != disposition.unowned_blocks or
            count.unowned_hits != disposition.unowned_hits)
            return error.UnmatchedDisposition;
    }
}
pub const ItemContext = struct {
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
pub fn validateReference(reference: MeasurementReference) ReferenceError!void {
    if (reference.path.len == 0 or reference.sha256.len != 64)
        return error.InvalidMeasurementReference;
    for (reference.sha256) |byte| {
        if (!std.ascii.isHex(byte)) return error.InvalidMeasurementReference;
    }
}

pub fn extractRecord(markdown: []const u8) RecordError![]const u8 {
    const marker = "```ozai-coverage-v3\n";
    const start = std.mem.indexOf(u8, markdown, marker) orelse return error.MissingLedger;
    const rest = markdown[start + marker.len ..];
    if (std.mem.indexOf(u8, rest, marker) != null) return error.DuplicateLedger;
    const end = std.mem.indexOf(u8, rest, "\n```") orelse return error.MissingLedger;
    return rest[0..end];
}
