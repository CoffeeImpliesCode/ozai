//! The `zbc` policy, and nothing softer than it.
//!
//! `zbc` reports diagnostics and exits 1 on this tree — on 50 diagnostics the
//! retained audit reviewed one at a time, whose individual dispositions live in
//! `gate_zbc_dispositions.zig`. A raw exit 1 is therefore not a pass and not a
//! failure either; the question is whether every diagnostic it reported is one
//! somebody actually read, against source that is still the source they read.
//!
//! Four things fail the gate, and only these four: a diagnostic at a key no
//! disposition covers, a reviewed diagnostic whose file no longer hashes to
//! what was reviewed, a disposition the tool did not report this time, and a
//! report this gate cannot read — a tool exit outside the classes it knows, or
//! one whose exit and contents contradict each other.
//!
//! **What the report is, exactly.** `zbc --format=json` writes a bare array of
//! findings to stdout and its run summary to stderr. There is no envelope and
//! no `findings` key; the summary — `selected=`, `analyzed=`, `failed=` and the
//! unresolved-import lookups — is on the other stream, which this gate never
//! captures, because `gate_steps.Step` runs the child with an inherited stderr.
//! So the figure that bounds the run's coverage is not in the bytes this module
//! reads, and it is recorded as `Coverage.unreported` rather than as a number.
//! A zero there would be invented, and an invented zero is exactly the "every
//! import resolved" claim the tool never made; see `Verdict.unresolved_imports`
//! for why the field itself stays an integer.

const std = @import("std");
const scope = @import("gate_scope.zig");
const reviewed = @import("gate_zbc_dispositions.zig");

/// Why a diagnostic was not accepted.
pub const Rejection = enum {
    /// A key no disposition covers: a new rule firing, a new site, or a site
    /// that moved.
    new_diagnostic,
    /// A reviewed key whose file has changed since it was reviewed. The
    /// disposition still describes code that is no longer there.
    source_changed,
    /// A reviewed disposition the tool did not report this time. Not progress
    /// and not a pass: a record nothing reports describes a finding that may
    /// have moved rather than one that went away, and a disposition that
    /// matches nothing is one nobody is maintaining.
    stale_disposition,
    /// An exit status outside the classes this gate knows how to read, or a
    /// report whose exit and contents contradict each other.
    unusable_report,
};

pub const Match = struct {
    key: []const u8,
    rejection: Rejection,
    detail: []const u8,
};

/// What the report says about how much of the tree the run reached.
///
/// The tool keeps that number on stderr, so the report this gate reads cannot
/// carry it. This is the honest label for that, and it is the reason a run over
/// 2453 unresolved import lookups is not a run over a fully resolved tree: the
/// figure is a limit on what the pass proves, and it is printed and recorded as
/// one.
pub const Coverage = enum {
    unreported,

    /// The words the gate and the receipt use. Short enough to sit in a summary
    /// line, explicit enough that nobody reads it as "none".
    pub fn text(self: Coverage) []const u8 {
        return switch (self) {
            .unreported => "unreported (zbc writes it to stderr, not into the report); " ++
                "this run's import coverage is unproven",
        };
    }
};

pub const Verdict = struct {
    findings: usize,
    /// Diagnostics that matched a disposition whose source still hashes to the
    /// digest that disposition was read against.
    accepted: usize,
    /// Everything else, named in full. Non-empty fails the gate; there is no
    /// count at which an unexpected diagnostic is acceptable.
    rejected: []const Match,
    /// Reviewed dispositions the tool did not report this time. Each one is
    /// also named in `rejected` under `stale_disposition`, so this is a count
    /// and not a second, quieter channel.
    stale: usize,
    /// The unresolved-import figure the report carried. This tool's report
    /// carries none, so the field is `0` on every run; it is kept because
    /// `gate_receipts.zig` prints it, and a reader who sees `0` next to
    /// `Coverage.unreported` in `summary` is reading both halves. Read alone it
    /// would say nothing true — which is what `summary` is for.
    unresolved_imports: usize,
    coverage: Coverage,
    raw_exit: u8,
    summary: []const u8,

    pub fn passes(self: Verdict) bool {
        return self.rejected.len == 0;
    }
};

/// What `zbc --format=json` writes to stdout: a bare array of findings, one per
/// diagnostic, and nothing else.
///
/// `ignore_unknown_fields` is on because each finding carries `severity`,
/// `end`, `message`, `notes`, `verdict` and `witness` that this gate does not
/// claim to understand. It has no fallback shape on purpose: bytes that are not
/// an array are a report this gate cannot read, and reading them as "no findings"
/// is how a tool that died at exit 2 came to look like a clean tree.
const Report = []const Finding;

const Position = struct { line: usize, column: usize };

pub const Finding = struct {
    path: []const u8,
    rule_id: []const u8,
    start: Position,
};

pub fn triage(
    gpa: std.mem.Allocator,
    stdout: []const u8,
    raw_exit: u8,
    sources: scope.Scope,
) !Verdict {
    const parsed = try std.json.parseFromSlice(
        Report,
        gpa,
        stdout,
        .{ .ignore_unknown_fields = true },
    );
    defer parsed.deinit();
    const report = parsed.value;

    var rejected: std.ArrayList(Match) = .empty;
    // Arena storage: `gpa` is `init.arena.allocator()` (gate.zig:105), which
    // releases every byte it handed out when `main` returns, so there is no
    // per-allocation owner to free this to and a `free` here would be an
    // arena free of storage the arena reclaims anyway.
    // zwanzig-disable-next-line: store-violations-engine
    const reported = try gpa.alloc(bool, reviewed.dispositions.len);
    @memset(reported, false);
    var accepted: usize = 0;

    for (report) |finding| {
        const path = relativePath(finding.path, sources);
        // The same arena as the line above, and for the same reason: the key
        // lives only until the receipt is written and the process exits.
        // zwanzig-disable-next-line: store-violations-engine
        const key = try std.fmt.allocPrint(gpa, "{s}:{d}:{d}:{s}", .{
            path,
            finding.start.line,
            finding.start.column,
            finding.rule_id,
        });
        const index = reviewed.find(path, finding.start.line, finding.start.column, finding.rule_id) orelse {
            try rejected.append(gpa, .{
                .key = key,
                .rejection = .new_diagnostic,
                .detail = "no disposition covers this key; re-triage it rather than adding it to the list",
            });
            continue;
        };
        const disposition = reviewed.dispositions[index];
        const was_reviewed = reviewed.reviewedDigest(path) orelse {
            try rejected.append(gpa, .{
                .key = key,
                .rejection = .new_diagnostic,
                .detail = "the reviewed-source table does not cover this file",
            });
            continue;
        };
        const digest = sources.digestOf(path) orelse {
            try rejected.append(gpa, .{
                .key = key,
                .rejection = .new_diagnostic,
                .detail = "this run did not read the file the diagnostic is reported in",
            });
            continue;
        };
        if (!std.mem.eql(u8, was_reviewed, &digest)) {
            try rejected.append(gpa, .{
                .key = key,
                .rejection = .source_changed,
                .detail = try std.fmt.allocPrint(
                    gpa,
                    "{s}: reviewed {s}, this run read {s}",
                    .{ @tagName(disposition.kind), was_reviewed, digest },
                ),
            });
            continue;
        }
        reported[index] = true;
        accepted += 1;
    }

    // A disposition the tool did not report describes a finding that may have
    // moved rather than one that went away. Silently dropping it is how a table
    // rots into a baseline that accepts everything it once saw, so it is named
    // here and fails the gate like any other disagreement.
    var stale: usize = 0;
    for (reported, reviewed.dispositions) |was_reported, disposition| {
        if (was_reported) continue;
        stale += 1;
        try rejected.append(gpa, .{
            .key = try std.fmt.allocPrint(gpa, "{s}:{d}:{d}:{s}", .{
                disposition.path,
                disposition.line,
                disposition.column,
                disposition.rule,
            }),
            .rejection = .stale_disposition,
            .detail = "no diagnostic this run matches this disposition; the rule stopped firing here " ++
                "or the site moved, and a record that matches nothing is not evidence of anything",
        });
    }

    // Only 0 and 1 are classes this gate can read: 0 means nothing to report,
    // 1 means findings. Anything above that is the tool failing rather than
    // reporting, and a report nobody can trust is not evidence of a clean tree.
    if (raw_exit > 1) {
        try rejected.append(gpa, .{
            .key = "zbc",
            .rejection = .unusable_report,
            .detail = try std.fmt.allocPrint(
                gpa,
                "exit {d} is not a class this gate can read",
                .{raw_exit},
            ),
        });
    } else if ((raw_exit == 0) != (report.len == 0)) {
        try rejected.append(gpa, .{
            .key = "zbc",
            .rejection = .unusable_report,
            .detail = try std.fmt.allocPrint(
                gpa,
                "exit {d} over {d} findings: the report contradicts its own exit",
                .{ raw_exit, report.len },
            ),
        });
    }

    const coverage: Coverage = .unreported;
    return .{
        .findings = report.len,
        .accepted = accepted,
        .rejected = rejected.items,
        .stale = stale,
        .unresolved_imports = 0,
        .coverage = coverage,
        .raw_exit = raw_exit,
        .summary = try std.fmt.allocPrint(
            gpa,
            "{d} findings; unresolved-import lookups {s}",
            .{ report.len, coverage.text() },
        ),
    };
}

/// The tool reports whatever path it was handed and the audit handed it
/// absolute ones. Matching the longest suffix this scope knows turns any of
/// those into the one name this repository uses; a path that matches nothing
/// keeps its own spelling, which names an unread file as one instead of
/// pretending it was checked.
fn relativePath(path: []const u8, sources: scope.Scope) []const u8 {
    var best: []const u8 = "";
    for (sources.all) |candidate| {
        if (!std.mem.eql(u8, path, candidate) and !endsAtComponent(path, candidate)) continue;
        if (candidate.len > best.len) best = candidate;
    }
    return if (best.len == 0) path else best;
}

/// Whether `path` ends with `"/" ++ candidate`. Spelled out rather than
/// concatenated: the scope's paths are plain slices, not sentinel strings.
fn endsAtComponent(path: []const u8, candidate: []const u8) bool {
    if (!std.mem.endsWith(u8, path, candidate)) return false;
    const cut = path.len - candidate.len;
    return cut > 0 and path[cut - 1] == '/';
}
