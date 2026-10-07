//! Test support the blobs protocol's own test suites share: the arena one
//! decode fills, and the hex comparison a written-down wire vector is checked
//! with.
//!
//! **Test support, and nothing else.** Nothing here is on a wire and nothing
//! here is called by a codec: it lives in one file because `framing.zig`,
//! `responses.zig` and `protocol.zig` all run their tests through a reader that
//! needs a `Storage` and a way to compare a hexdump, and three copies of a
//! decode arena is one arena too many. It sits beside those three rather than
//! under `wire/`, because it is the blobs protocol's own vocabulary and no
//! other protocol's.

const std = @import("std");

const requests = @import("requests.zig");

const Storage = requests.Storage;
const Hash = requests.Hash;

const range_spec = @import("range_spec.zig");

/// Storage for one decode, with the buffers it names beside it.
///
/// The slices in a `Storage` are the only place a decode writes, so they
/// cannot outlive the buffer they point into: a helper returning a `Storage`
/// alone would hand back a dangling one. `Room` and its buffers are a pair
/// because of that and not for tidiness.
pub const Room = struct {
    items: [16]range_spec.Item = undefined,
    widths: [64]u64 = undefined,
    hashes: [4]Hash = undefined,
    boundaries: [32]u64 = undefined,

    pub fn storage(self: *Room) Storage {
        return .{
            .items = &self.items,
            .widths = &self.widths,
            .hashes = &self.hashes,
            .boundaries = &self.boundaries,
        };
    }
};
/// The bytes a hex string stands for, decoded into `out`. A hexdump needs no
/// allocator: every one of them lands in a scratch buffer a test already has.
pub fn parseHex(out: []u8, hex: []const u8) ![]const u8 {
    if (hex.len % 2 != 0) return error.OddHexLength;
    return std.fmt.hexToBytes(out, hex);
}
/// Long enough for every hexdump above. A diagnostic, not a general formatter:
/// the bytes it prints are the ones written down in this file.
const max_dumped_bytes = 64;

pub fn expectHex(expected: []const u8, actual: []const u8) !void {
    if (std.mem.eql(u8, expected, actual)) return;
    std.debug.print("expected {d} bytes: {s}\n     got {d} bytes: {s}\n", .{
        expected.len, &hexdump(expected),
        actual.len,   &hexdump(actual),
    });
    return error.WireFormatMismatch;
}

fn hexdump(bytes: []const u8) [2 * max_dumped_bytes]u8 {
    var out: [2 * max_dumped_bytes]u8 = undefined;
    const digits = "0123456789abcdef";
    const shown = @min(bytes.len, max_dumped_bytes);
    for (bytes[0..shown], 0..) |byte, index| {
        out[index * 2] = digits[byte >> 4];
        out[index * 2 + 1] = digits[byte & 15];
    }
    @memset(out[shown * 2 ..], ' ');
    // ZBC cannot combine the loop's byte pairs with memset to prove the full array initialized.
    // zbc-disable-next-line: use-undefined
    return out;
}
