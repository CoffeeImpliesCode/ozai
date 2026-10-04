//! The gate on what the vendored QUIC core is allowed to reach for.
//!
//! M8 spent most of its cost making `vendor/quic/` obey the one rule
//! `AGENTS.md` §2 and `docs/ARCHITECTURE.md` state plainly: nothing below
//! `ozai.base` may read a clock, read the environment, or take an allocator it
//! was not handed. A state machine that reads a clock cannot be driven by a
//! test — there is no way to put a connection at a chosen time — and one that
//! opens a socket cannot be handed a datagram at all.
//!
//! That rule is enforced here and nowhere else. The gate does format,
//! AST-check and zlint every scoped Zig file, `vendor/` included; `ziglint`,
//! `zwanzig` and `zbc` are handed the first-party list, which is the same walk
//! without `vendor/`. Dropping upstream code from those three is the right call
//! — it is not this project's code, and linting it against this project's rules
//! would report findings nobody intends to fix — but it leaves one question
//! unasked, because none of the tools that do see the tree would fail over it.
//! `zig fmt --check` does not read what a call means, and a linter asks about
//! spelling. So a patch that reaches for `std.posix.socket`, or for a clock,
//! would land green and the endpoint would quietly stop being drivable. This
//! file is where that is answered.
//!
//! The boundaries, and why each is where it is:
//!
//! * Library code is held to the full rule. A state machine that draws a
//!   clock, a file, the environment, OS entropy or its own PRNG is not
//!   drivable, so these are structural failures rather than style.
//!
//! * Test code is held to the same rule for everything a test does not get to
//!   do differently. A socket is a socket inside a `test` block too: a test
//!   that opens one exercises the kernel instead of the core. One thing is
//!   exempt, and it is the opposite of a hidden input: a seeded PRNG.
//!   `TestRandom` is the sanctioned spelling and appears in about a hundred of
//!   them, and a generator seeded with a constant is what makes a test
//!   repeatable.
//!
//! That line is drawn by what a function mentions, and it is drawn in one
//! direction. An imprecision there can cost a complaint about a test helper,
//! which a reader dismisses, or it can cost a library PRNG nobody reports,
//! which nothing catches. Which of the two it is turns on whether a brace has
//! been mistaken for a function body, so the pass that draws the line has to
//! know which `fn` keywords are declarations at all — see
//! `vendored_scanner.zig`'s `classify`.
//!
//! Three modules behind that one sentence, each owning one responsibility:
//!
//! * `vendored_sources.zig` — which files exist, and the check that the list
//!   stays sorted and equal to the tree.
//! * `vendored_scanner.zig` — the token stream: what each token is, and
//!   whether the code around it is library or test code.
//! * `vendored_policy.zig` — the forbidden constructs, and what each one costs.
//!
//! This file drives them and reports. It may not touch the filesystem: it runs
//! on every `zig build test` and reads 1.3 MB of vendored source at comptime.
//! It therefore cannot discover an omission itself — that is
//! `build_support.zig`'s walk of the directory — and pretending otherwise would
//! be the worst kind of gate, one that looks like coverage.

const std = @import("std");

const vendored_policy = @import("vendored_policy.zig");
const vendored_scanner = @import("vendored_scanner.zig");
const vendored_sources = @import("vendored_sources.zig");

const t = std.testing;

/// The gate's coverage, exported for `build_support.zig`, which walks the
/// vendored tree on every configure and fails the build when this list and the
/// directory disagree in either direction.
pub const vendored_files = vendored_sources.vendored_files;

const AuditError = error{ OutOfMemory, VendoredInvariantViolated };

fn audit(alloc: std.mem.Allocator) AuditError!void {
    var scanner: vendored_scanner.Scanner = .{};
    defer scanner.deinit(alloc);

    var test_blocks: u32 = 0;
    // Checked before anything is embedded, so a list that is out of order says
    // so rather than failing on a path first.
    if (vendored_sources.unsortedAt(&vendored_files)) |pair| {
        std.debug.print(
            "vendored_files is not sorted and duplicate-free: {s} then {s}\n" ++
                "    A repeated entry checks one file twice while an omitted " ++
                "one is invisible. Keep the list sorted so that a diff of " ++
                "it shows exactly which file came and went.\n",
            .{ vendored_files[pair.before], vendored_files[pair.after] },
        );
        return error.VendoredInvariantViolated;
    }
    // `inline for` because `@embedFile` takes a comptime-known path: naming the
    // whole tree in one expression is what the builtin's limits force.
    inline for (vendored_files) |embedded| {
        const src: [:0]const u8 = @embedFile("../" ++ embedded);
        const path = embedded;
        test_blocks += try scanner.scanFile(alloc, src, path, vendored_policy.judge);
    }

    if (scanner.hits == 0) return;
    std.debug.print(
        "\n{d} architectural violation(s) across {d} vendored files " ++
            "({d} test blocks inspected). These restrictions keep I/O, time " ++
            "and process entropy at the caller boundary.\n",
        .{ scanner.hits, vendored_files.len, test_blocks },
    );
    return error.VendoredInvariantViolated;
}

test "the vendored QUIC core reaches for nothing its caller did not hand it" {
    try audit(t.allocator);
}

// Names the gate's other modules, which is the idiom `build_support.zig` and
// `vendor/quic/src/test_all.zig` use for the same reason: under lazy analysis a
// test block in a file the compilation never analyses is not a slow test, it is
// no test at all, and the run still exits 0.
test {
    _ = vendored_policy;
    _ = vendored_scanner;
    _ = vendored_sources;
}

/// Scan one synthetic source and report what the gate made of it. The hits are
/// what the rules found, the tests what the scanner counted as a test block.
///
/// A fresh `Scanner` each time because `hits` accumulates across a tree on a
/// purpose, which is exactly what a per-case count cannot reuse.
fn scanSynthetic(
    alloc: std.mem.Allocator,
    src: [:0]const u8,
    path: []const u8,
) !struct { hits: u32, tests: u32 } {
    var scanner: vendored_scanner.Scanner = .{};
    defer scanner.deinit(alloc);
    const tests = try scanner.scanFile(alloc, src, path, vendored_policy.judge);
    return .{ .hits = scanner.hits, .tests = tests };
}

test "a `testing.` reference outside every brace neither traps nor hides" {
    // `reachesTesting` marks the innermost frame that is open, and at container
    // scope there is none — the read is `frames[len - 1]` over an empty list.
    // Being outside every brace is the common state, not a curiosity: every
    // vendored file opens with top-level declarations, and `testing.` is the
    // spelling this gate itself hunts for. Drop the bound on that read and this
    // source traps the whole test suite before it reports anything.
    //
    // The PRNG is what keeps the assertion from being satisfied by a scanner
    // that stopped early: a file whose only violation is below the empty stack
    // still has to be reported.
    const src: [:0]const u8 =
        \\const std = @import("std");
        \\const testing = std.testing;
        \\const Probe = testing.Nested;
        \\
        \\const Generator = struct {
        \\    pub fn draw() std.Random.Xoshiro256 {
        \\        return undefined;
        \\    }
        \\};
        \\
    ;
    const result = try scanSynthetic(t.allocator, src, "synthetic/top_level.zig");
    try t.expectEqual(1, result.hits);
    try t.expectEqual(0, result.tests);
}

test "a `fn` with no body does not make the next brace a function body" {
    // `*const fn (u64) void` is a function *type*. Three of them are live in
    // the tree today, in `connection.zig` and `connection_manager.zig`, so the
    // brace that follows one belongs to whatever encloses it — a struct here.
    // Marking that brace as a function body makes the code inside count as test
    // scaffolding, and the PRNG below goes unreported. This is the one
    // imprecision in this gate that costs coverage rather than noise, which is
    // why the `;` and `,` that end a declaration clear the pending mark.
    const src: [:0]const u8 =
        \\const std = @import("std");
        \\const testing = std.testing;
        \\const Timer = *const fn (u64) void;
        \\
        \\const Registry = struct {
        \\    const alloc = testing.allocator;
        \\    pub fn draw() std.Random.Xoshiro256 {
        \\        _ = alloc;
        \\        return undefined;
        \\    }
        \\};
        \\
    ;
    const result = try scanSynthetic(t.allocator, src, "synthetic/function_type.zig");
    try t.expectEqual(1, result.hits);
}

test "a function body that reaches the testing namespace is scaffolding" {
    // The other side of the same boundary, and the reason the boundary exists:
    // a helper between two test blocks allocates from the testing allocator
    // and cannot run outside a test, so counting it as library code would make
    // the gate fail on the tree it is auditing.
    const src: [:0]const u8 =
        \\const std = @import("std");
        \\const testing = std.testing;
        \\
        \\pub fn helper() void {
        \\    _ = testing.allocator;
        \\    var gen: std.Random.Xoshiro256 = undefined;
        \\    _ = &gen;
        \\}
        \\
    ;
    const result = try scanSynthetic(t.allocator, src, "synthetic/helper.zig");
    try t.expectEqual(0, result.hits);
}
