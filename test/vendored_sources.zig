//! What the gate reads: the vendored root, every `.zig` file under it, and the
//! check that the list stays sorted.
//!
//! The list is data, but it is the gate's coverage claim and two independent
//! callers depend on it, so it is stated once here.
//! `test/vendored_invariants.zig` embeds every entry at comptime, which is
//! what makes an entry a promise that the file is actually read.
//! `build_support.zig` walks `vendor/quic/src` on every configure and fails the
//! build when the list and the directory disagree in either direction:
//! `@embedFile` cannot glob, so nothing else would notice a file that was added
//! and never listed — and a file the gate does not read is a file nothing is
//! watching, while the gate still reports full coverage of the tree.
//!
//! Sortedness is checked here rather than by the caller because it is a
//! property of the list rather than of any one scan. A repeated entry checks
//! one file twice while an omitted one is invisible, and a sorted list is the
//! form whose diff shows exactly which file came and which went.

const std = @import("std");

const t = std.testing;

/// The vendored root. Every path below is repo-relative, so `build_support.zig`
/// can compare the list against the directory without knowing how `@embedFile`
/// spells a path — that builtin resolves against the file that calls it, not
/// the repository root.
const vendored_root = "vendor/quic/src";

/// Every `.zig` file under the vendored root, sorted. An entry is a promise
/// that the gate reads the file, and `build_support.zig` is what keeps the
/// promise honest: a list that quietly omits a file is worse than no gate at
/// all, because it looks like coverage.
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

/// The two entries that break the list being sorted and duplicate-free. Naming
/// both is what the reader needs: the pair says which file came and which went,
/// which an index alone would not.
pub const Unordered = struct {
    before: usize,
    after: usize,
};

/// The first pair of `files` that breaks it being sorted and duplicate-free, or
/// null when there is none.
///
/// The first entry has nothing before it, so the walk starts at one and an
/// empty list and a one-entry list are both in order — there is no pair to
/// compare in either, which is the whole answer for both. The bound is
/// restated in the expression the read sits in, the shape
/// `RangeSpecSeq.isInfinite` uses for the same last-element read.
///
/// This lives here rather than inside the caller's `inline for` so that a test
/// can reach it: the `inline for` exists because `@embedFile` needs a
/// comptime-known path, and nothing in a comptime-only loop can be tested for
/// the case where the walk runs off the front of the list.
pub fn unsortedAt(files: []const []const u8) ?Unordered {
    var index: usize = 1;
    while (index < files.len) : (index += 1) {
        if (index > 0 and std.mem.order(u8, files[index - 1], files[index]) != .lt) {
            return .{ .before = index - 1, .after = index };
        }
    }
    return null;
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

    // Out of order in the middle, not at an end: a check that only compared the
    // first entry against the rest would pass this list.
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
