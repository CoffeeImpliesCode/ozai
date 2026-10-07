//! The gate on what the vendored QUIC core is allowed to reach for.
//!
//! M8 spent most of its cost making `vendor/quic/` obey the one rule
//! `AGENTS.md` §2 and `docs/ARCHITECTURE.md` state plainly: nothing below
//! `ozai.base` may read a clock, read the environment, or take an allocator it
//! was not handed. A state machine that reads a clock cannot be driven by a
//! test — there is no way to put a connection at a chosen time — and one that
//! opens a socket cannot be handed a datagram at all.
//!
//! That rule is enforced here and nowhere else. `vendor/` is excluded from
//! `zig fmt`, `zlint` and `zbc` through `GATE_EXCLUDE=vendor`, which is the
//! right call: it is upstream code, and reformatting thirty thousand lines
//! would bury the patch under a diff nobody can review. The price of that
//! decision is that no tool is watching this tree, so a patch that reaches for
//! `std.posix.socket`, or for a clock, would land green and the endpoint would
//! quietly stop being drivable. This file is where that exclusion is paid back.
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
//! know which `fn` keywords are declarations at all — see `Scanner.classify`.
//!
//! The library/test boundary is drawn from the token stream, never from line
//! numbers: a `test` declaration's body ends where brace depth returns to the
//! level the declaration opened at, so library code after a test block is
//! still library code. That is not pedantry. `packet.zig` has its first `test`
//! block on line 120 and over a thousand lines of live code after it, so the
//! usual `awk '/^test /{t=1}'` rule calls all of it test code and every
//! violation in it survives — the session this gate was written in lost four
//! that way. Counting braces from Zig's own tokenizer cannot make that
//! mistake, and it also reads comments and string literals correctly, so a
//! `// std.posix.socket` in a comment and a `test "no sockets"` name are not
//! evidence of anything.
//!
//! There are no carve-outs. Upstream had one: `sys.zig`, holding the sockets,
//! the clock and the process CSPRNG behind a single import. DECISIONS/0001 step
//! 2 deleted it once its last caller went, and this gate is what keeps that
//! deletion true. A clock, a libc call, an entropy draw, a file, a process or a
//! socket anywhere in this tree — its own tests included — is a failure here,
//! and so is an `@import` of the deleted seam, so the file cannot come back as
//! a temporary convenience.
//!
//! The file list below is the whole gate's coverage, and `@embedFile` cannot
//! glob, so `build.zig` walks `vendor/quic/src` on every configure and fails
//! the build when the list and the tree disagree in either direction. This test
//! may not touch the filesystem: it runs on every `zig build test` and reads
//! 1.3 MB of vendored source at comptime. It therefore cannot discover an
//! omission itself, and pretending otherwise would be the worst kind of gate —
//! one that looks like coverage.

const std = @import("std");

const t = std.testing;

const judge = @import("vendored_judge.zig");
const rulebook = @import("vendored_rulebook.zig");
const scanner_ns = @import("vendored_scanner.zig");

const Scanner = scanner_ns.Scanner;

/// The vendored root. Every path below is repo-relative, so `build.zig` can
/// compare the list against the directory without knowing how `@embedFile`
/// spells a path — that builtin resolves against this file, not the root.
const vendored_root = "vendor/quic/src";

/// Every `.zig` file under the vendored root, sorted. An entry is a promise
/// that this test reads the file, and `build.zig` is what keeps the promise
/// honest: a list that quietly omits a file is worse than no gate at all,
/// because it looks like coverage.
pub const vendored_files = [_][]const u8{
    vendored_root ++ "/address.zig",
    vendored_root ++ "/io_compat.zig",
    vendored_root ++ "/lib.zig",
    vendored_root ++ "/quic/ack_handler.zig",
    vendored_root ++ "/quic/aes_gcm.zig",
    vendored_root ++ "/quic/aes_gcm_vectors.zig",
    vendored_root ++ "/quic/congestion.zig",
    vendored_root ++ "/quic/connection.zig",
    vendored_root ++ "/quic/connection_manager.zig",
    vendored_root ++ "/quic/crypto.zig",
    vendored_root ++ "/quic/crypto_stream.zig",
    vendored_root ++ "/quic/ecdsa_p256.zig",
    vendored_root ++ "/quic/ecn.zig",
    vendored_root ++ "/quic/flow_control.zig",
    vendored_root ++ "/quic/frame.zig",
    vendored_root ++ "/quic/ghash.zig",
    vendored_root ++ "/quic/limits.zig",
    vendored_root ++ "/quic/lossy_link_test.zig",
    vendored_root ++ "/quic/mont.zig",
    vendored_root ++ "/quic/mtu.zig",
    vendored_root ++ "/quic/native_nat.zig",
    vendored_root ++ "/quic/native_nat_policy.zig",
    vendored_root ++ "/quic/native_nat_state.zig",
    vendored_root ++ "/quic/native_nat_transition.zig",
    vendored_root ++ "/quic/native_path_state.zig",
    vendored_root ++ "/quic/observed_address.zig",
    vendored_root ++ "/quic/packet.zig",
    vendored_root ++ "/quic/packet_packer.zig",
    vendored_root ++ "/quic/protocol.zig",
    vendored_root ++ "/quic/quic_lb.zig",
    vendored_root ++ "/quic/ranges.zig",
    vendored_root ++ "/quic/rsa.zig",
    vendored_root ++ "/quic/rtt.zig",
    vendored_root ++ "/quic/stateless_reset.zig",
    vendored_root ++ "/quic/stream.zig",
    vendored_root ++ "/quic/tls13.zig",
    vendored_root ++ "/quic/transport_params.zig",
    vendored_root ++ "/quic/util.zig",
    vendored_root ++ "/test_all.zig",
};

/// The first pair of `files` that breaks it being sorted and duplicate-free,
/// or null when there is none. `before` and `after` are indices into `files`.
///
/// The pair is what the reader needs: naming the two entries says which file
/// came and which went, which an index alone would not.
///
/// The first entry has nothing before it, so the walk starts at one and an
/// empty list and a one-entry list are both in order — there is no pair to
/// compare in either, which is the whole answer for both. The bound is
/// restated in the expression the read sits in, the shape
/// `RangeSpecSeq.isInfinite` uses for the same last-element read.
///
/// This lives here rather than inside `audit`'s `inline for` so that a test
/// can reach it: the `inline for` exists because `@embedFile` needs a
/// comptime-known path, and nothing in a comptime-only loop can be tested for
/// the case where the walk runs off the front of the list.
pub fn unsortedAt(files: []const []const u8) ?struct { before: usize, after: usize } {
    var index: usize = 1;
    while (index < files.len) : (index += 1) {
        if (index > 0 and std.mem.order(u8, files[index - 1], files[index]) != .lt) {
            return .{ .before = index - 1, .after = index };
        }
    }
    return null;
}

pub fn audit(alloc: std.mem.Allocator) rulebook.AuditError!void {
    var scanner: Scanner = .{};
    defer scanner.tokens.deinit(alloc);
    defer scanner.scaffolding.deinit(alloc);
    defer scanner.local_fns.deinit(alloc);

    var test_blocks: u32 = 0;
    // Checked before anything is embedded, so a list that is out of order says
    // so rather than failing on a path first.
    if (unsortedAt(&vendored_files)) |pair| {
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
        test_blocks += try judge.scanFile(&scanner, alloc, src, path);
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

/// Scan one synthetic source and report what the gate made of it. The hits are
/// what the rules found, the tests what the scanner counted as a test block.
///
/// A fresh `Scanner` each time because `hits` accumulates across a tree on
/// purpose, which is exactly what a per-case count cannot reuse.
fn scanSynthetic(
    alloc: std.mem.Allocator,
    src: [:0]const u8,
    path: []const u8,
) !struct { hits: u32, tests: u32 } {
    var scanner: Scanner = .{};
    defer scanner.tokens.deinit(alloc);
    defer scanner.scaffolding.deinit(alloc);
    defer scanner.local_fns.deinit(alloc);
    const tests = try judge.scanFile(&scanner, alloc, src, path);
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
    // imprecision in this file that costs coverage rather than noise, which is
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

test "a list with no pair in it is in order" {
    // `unsortedAt` walks from one, so these two are the arms where the walk
    // never runs and `index - 1` would have nothing in front of it.
    const empty: [0][]const u8 = .{};
    const one = [_][]const u8{"only.zig"};
    try t.expect(unsortedAt(&empty) == null);
    try t.expect(unsortedAt(&one) == null);
}

test "the sortedness check names the pair that is out of order" {
    const sorted = [_][]const u8{ "a.zig", "b.zig", "c.zig" };
    try t.expect(unsortedAt(&sorted) == null);

    // Out of order in the middle, not at an end: a check that only compared
    // the first entry against the rest would pass this list.
    const unsorted = [_][]const u8{ "a.zig", "c.zig", "b.zig" };
    const pair = unsortedAt(&unsorted) orelse return error.TestUnexpectedResult;
    try t.expectEqual(@as(usize, 1), pair.before);
    try t.expectEqual(@as(usize, 2), pair.after);

    // A repeated entry is the same defect from the other side: that file is
    // checked twice while the one it displaced is checked never.
    const repeated = [_][]const u8{ "a.zig", "b.zig", "b.zig" };
    const dup = unsortedAt(&repeated) orelse return error.TestUnexpectedResult;
    try t.expectEqual(@as(usize, 1), dup.before);
    try t.expectEqual(@as(usize, 2), dup.after);
}
