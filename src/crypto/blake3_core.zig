//! BLAKE3's compression function: seven rounds over one 64-byte block, the
//! chaining value it starts from, and the flag byte that says what the block
//! is.
//!
//! It is ported rather than reached for because `std.crypto.hash.Blake3` keeps
//! its `Flags`, its chaining values and its output shape file-private, and its
//! `final` always sets ROOT. A Bao tree needs all three: to compress a node it
//! chose itself, to reduce a subtree to a chaining value that is not a root,
//! and to merge two chaining values at a level it picked. The shapes built on
//! top of this function are `blake3_nodes.zig`, and the walk over them is
//! `blake3_subtree.zig`.
//!
//! Unkeyed, and no extended output. A key would replace `iv` and set a fifth
//! flag bit, which a tree never does; extended output is a second counter over
//! this same function, and a tree never asks for more than 32 bytes. Neither
//! is ported rather than ported and left unused.
//!
//! `AGENTS.md` §2 makes interoperability a test, so nothing here is a wire
//! claim until the published vectors say so. The test block below is where
//! that happens, against `../gossip/plumtree/blake3_vectors.zig`.

const std = @import("std");
const mem = std.mem;

/// The compression's block size, and the block length of a parent node.
pub const block_length = 64;

/// BLAKE3's output width, which is a chaining value's width too.
pub const digest_length = 32;

/// The bytes one node at the bottom of the tree covers.
pub const chunk_length = 1024;

/// How deep the tree over a `u64` chunk counter can be, and so how many
/// chaining values a left-to-right walk must be able to hold. `chunk_length`
/// is 2^10 and a `u64` byte count is 2^64, so the deepest tree names 2^54
/// chunks and holds at most 54 complete left-hand nodes.
pub const max_depth = 54;

/// A chaining value as the compression carries it: eight little-endian words.
pub const ChainingValue = [8]u32;

/// A chaining value as a tree stores it and as a wire carries it.
pub const CvBytes = [digest_length]u8;

/// The compression's starting words, and an unkeyed chunk's starting chaining
/// value.
pub const iv: ChainingValue = .{
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
};

/// Which of the compression's sixteen words each round mixes in, in order.
const msg_schedule: [7][16]u8 = .{
    .{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
    .{ 2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8 },
    .{ 3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1 },
    .{ 10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6 },
    .{ 12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4 },
    .{ 9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7 },
    .{ 11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13 },
};

/// The compression's flag byte, bit for bit with the reference layout. The
/// four flags below are the only ones a tree ever sets; the upper four are
/// the keyed and key-derivation bits, which no path here reaches, so they are
/// not carried and are never set.
pub const Flags = packed struct(u4) {
    chunk_start: bool = false,
    chunk_end: bool = false,
    parent: bool = false,
    root: bool = false,

    /// The byte a compression of this node is given. Wire: this is what the
    /// block's flags word is read as. The widening is the point of the `u4`
    /// backing: the four carried flags occupy the low nibble of the reference
    /// byte and the keyed bits above them are absent rather than zero-filled by
    /// a field nobody sets.
    pub fn toInt(self: Flags) u8 {
        const narrow: u4 = @bitCast(self);
        return narrow;
    }

    /// Both sets of flags at once. A node sets its own flags when it is built
    /// and the caller's when it is reduced to a chaining value, and the two
    /// are combined here rather than at each of those places.
    pub fn with(self: Flags, other: Flags) Flags {
        return @bitCast(@as(u4, @truncate(self.toInt() | other.toInt())));
    }
};

inline fn rotr32(w: u32, c: u5) u32 {
    return std.math.rotr(u32, w, c);
}

inline fn load32(bytes: []const u8) u32 {
    return mem.readInt(u32, bytes[0..4], .little);
}

inline fn store32(bytes: []u8, w: u32) void {
    mem.writeInt(u32, bytes[0..4], w, .little);
}

/// A chaining value in the byte order a tree stores and sends it in.
pub fn cvBytes(cv: ChainingValue) CvBytes {
    var bytes: CvBytes = undefined;
    for (0..8) |i| {
        store32(bytes[i * 4 ..][0..4], cv[i]);
    }
    // ZBC cannot prove the fixed loop's eight store32 writes cover all 32 bytes.
    // zbc-disable-next-line: use-undefined
    return bytes;
}

/// A stored chaining value back into the words the compression mixes.
pub fn cvFromBytes(bytes: CvBytes) ChainingValue {
    var cv: ChainingValue = undefined;
    for (0..8) |i| {
        cv[i] = load32(bytes[i * 4 ..][0..4]);
    }
    // ZBC cannot prove the fixed loop assigns every word of the eight-word chaining value.
    // zbc-disable-next-line: use-undefined
    return cv;
}

inline fn g(state: *[16]u32, a: usize, b: usize, c: usize, d: usize, x: u32, y: u32) void {
    state[a] +%= state[b] +% x;
    state[d] = rotr32(state[d] ^ state[a], 16);
    state[c] +%= state[d];
    state[b] = rotr32(state[b] ^ state[c], 12);
    state[a] +%= state[b] +% y;
    state[d] = rotr32(state[d] ^ state[a], 8);
    state[c] +%= state[d];
    state[b] = rotr32(state[b] ^ state[c], 7);
}

inline fn roundFn(state: *[16]u32, msg: *const [16]u32, round: usize) void {
    const schedule = &msg_schedule[round];

    g(state, 0, 4, 8, 12, msg[schedule[0]], msg[schedule[1]]);
    g(state, 1, 5, 9, 13, msg[schedule[2]], msg[schedule[3]]);
    g(state, 2, 6, 10, 14, msg[schedule[4]], msg[schedule[5]]);
    g(state, 3, 7, 11, 15, msg[schedule[6]], msg[schedule[7]]);

    g(state, 0, 5, 10, 15, msg[schedule[8]], msg[schedule[9]]);
    g(state, 1, 6, 11, 12, msg[schedule[10]], msg[schedule[11]]);
    g(state, 2, 7, 8, 13, msg[schedule[12]], msg[schedule[13]]);
    g(state, 3, 4, 9, 14, msg[schedule[14]], msg[schedule[15]]);
}

fn compressPre(
    state: *[16]u32,
    cv: *const ChainingValue,
    block: []const u8,
    block_len: u8,
    counter: u64,
    flags: Flags,
) void {
    var block_words: [16]u32 = undefined;
    for (0..16) |i| {
        block_words[i] = load32(block[i * 4 ..][0..4]);
    }

    for (0..8) |i| {
        state[i] = cv[i];
    }
    for (0..4) |i| {
        state[i + 8] = iv[i];
    }
    state[12] = @truncate(counter);
    state[13] = @truncate(counter >> 32);
    state[14] = @as(u32, block_len);
    state[15] = @as(u32, flags.toInt());

    for (0..7) |round| {
        roundFn(state, &block_words, round);
    }
}

/// One compression: the eight words of `cv` through seven rounds over `block`,
/// read little-endian, with `block_len` real bytes of it and `counter` and
/// `flags` in the last four words. The result is in `cv`.
///
/// `block` is always `block_length` bytes; a short final block is zero-padded
/// and `block_len` says how much of it is real.
pub fn compressInPlace(
    cv: *ChainingValue,
    block: []const u8,
    block_len: u8,
    counter: u64,
    flags: Flags,
) void {
    var state: [16]u32 = undefined;
    compressPre(&state, cv, block, block_len, counter, flags);
    for (0..8) |i| {
        cv[i] = state[i] ^ state[i + 8];
    }
}

const t = std.testing;
const published = @import("../gossip/plumtree/blake3_vectors.zig");

// Pinned to published bytes, through the bare compression. An empty input is
// one compression of `iv` over a block of zeroes with block length zero and
// CHUNK_START, CHUNK_END and ROOT set and nothing else, so a wrong word in
// `iv`, a wrong place for the counter, a wrong word in the schedule or a
// wrong bit in the flag byte all change the answer, and the answer is
// published.
test "the compression alone reproduces the published digest of an empty input" {
    var cv: ChainingValue = iv;
    const block: [block_length]u8 = @splat(0);
    const empty: Flags = .{ .chunk_start = true, .chunk_end = true, .root = true };
    compressInPlace(&cv, &block, 0, 0, empty);

    const digest = cvBytes(cv);
    try t.expectEqualStrings(
        published.blake3_vectors[0].hash,
        &std.fmt.bytesToHex(&digest, .lower),
    );
}

// The flag byte is wire. Its bit positions are not a choice: the empty input
// above compresses with 0b1011, so the first three of these four positions
// are pinned by a published digest, and PARENT is pinned the same way by every
// multi-chunk digest in `blake3_subtree_vectors.zig`. Bits 4 to 7 are the
// keyed and key-derivation flags, which no path in this directory sets.
test "the flag byte keeps the reference bit positions" {
    const none: Flags = .{};
    const start: Flags = .{ .chunk_start = true };
    const end: Flags = .{ .chunk_end = true };
    const parent: Flags = .{ .parent = true };
    const root: Flags = .{ .root = true };
    try t.expectEqual(@as(u8, 0b0000), none.toInt());
    try t.expectEqual(@as(u8, 0b0001), start.toInt());
    try t.expectEqual(@as(u8, 0b0010), end.toInt());
    try t.expectEqual(@as(u8, 0b0100), parent.toInt());
    try t.expectEqual(@as(u8, 0b1000), root.toInt());
}

// A stored chaining value is the same eight words little-endian, and a wire
// carries that form. Nothing in the compression goes near these bytes, so a
// tree that wrote them in one order and read them in the other would merge
// garbage at every level and still agree with every digest above.
test "a chaining value is stored little-endian, word by word" {
    var words: ChainingValue = iv;
    words[0] = 0x01020304;
    words[7] = 0xaabbccdd;

    const stored = cvBytes(words);
    try t.expectEqualSlices(u8, &.{ 0x04, 0x03, 0x02, 0x01 }, stored[0..4]);
    try t.expectEqualSlices(u8, &.{ 0xdd, 0xcc, 0xbb, 0xaa }, stored[28..32]);
    try t.expectEqual(words, cvFromBytes(stored));
}
