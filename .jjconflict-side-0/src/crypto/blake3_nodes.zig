//! The shapes a Bao tree builds on the compression: what a node's output is
//! while it is still unevaluated, the parent node over two chaining values,
//! and the chunk state that feeds them.
//!
//! These are the three things `std.crypto.hash.Blake3` keeps file-private, and
//! they are here because a tree reaches all three at a moment its own walk
//! chooses. The root-output path and the parent-output path are the same
//! compression with different flags, and they are separated here rather than
//! folded into one function so a caller has to say which node it is building.
//!
//! Every function here is pure over its arguments and the state it is handed:
//! no clock, no allocator, no socket.

const std = @import("std");
const core = @import("blake3_core.zig");

/// One compression's worth of work, left unevaluated: the chaining value it
/// started from, the block, how much of that block is real, the counter, and
/// the flags. The root flag is not here — it belongs to the last compression
/// of a tree and to no other, so `chainingValue` adds it at the one place
/// that is the root.
pub const Output = struct {
    input_cv: core.ChainingValue,
    block: [core.block_length]u8,
    block_len: u8,
    counter: u64,
    flags: core.Flags,

    /// This output's chaining value with `extra` OR-ed onto its flags.
    /// `.{}` is a node as an interior node, and is what a tree stores;
    /// `.{ .root = true }` is the root hash of everything below this output.
    pub fn chainingValue(self: *const Output, extra: core.Flags) core.ChainingValue {
        var cv = self.input_cv;
        const flags = self.flags.with(extra);
        core.compressInPlace(&cv, &self.block, self.block_len, self.counter, flags);
        return cv;
    }

    /// This output with `extra` OR-ed onto its flags and nothing else
    /// recomputed. A tree builds the root node ROOT-free and adds ROOT once at
    /// the end: a flag added earlier would change the value of the node above
    /// it, and with it the root.
    pub fn withFlags(self: Output, extra: core.Flags) Output {
        var out = self;
        out.flags = out.flags.with(extra);
        return out;
    }
};

/// The node over two chaining values: one compression of both in order, with
/// PARENT set. `extra` carries ROOT when this node is the tree's own root; an
/// interior node passes `.{}`.
pub fn parentOutput(left: core.ChainingValue, right: core.ChainingValue, extra: core.Flags) Output {
    const parent: core.Flags = .{ .parent = true };
    return .{
        .input_cv = core.iv,
        .block = core.cvBytes(left) ++ core.cvBytes(right),
        .block_len = core.block_length,
        .counter = 0,
        .flags = parent.with(extra),
    };
}

/// The chaining value of `parentOutput`, for callers that never want the block
/// it was compressed from.
pub fn parentChainingValue(
    left: core.ChainingValue,
    right: core.ChainingValue,
    extra: core.Flags,
) core.ChainingValue {
    return parentOutput(left, right, extra).chainingValue(.{});
}

/// One node at the bottom of the tree: the compression of up to
/// `chunk_length` bytes, reduced to a chaining value and never looked at
/// again.
pub const ChunkState = struct {
    cv: core.ChainingValue = core.iv,
    chunk_counter: u64 = 0,
    buf: [core.block_length]u8 = @splat(0),
    buf_len: u8 = 0,
    blocks_compressed: u8 = 0,

    pub fn init(chunk_counter: u64) ChunkState {
        return .{ .chunk_counter = chunk_counter };
    }

    /// Start the chunk at `chunk_counter`. The counter is the only thing that
    /// tells one chunk from another, so a reset without a new one would hash
    /// the same node twice.
    pub fn reset(self: *ChunkState, chunk_counter: u64) void {
        self.cv = core.iv;
        self.chunk_counter = chunk_counter;
        self.buf = @splat(0);
        self.buf_len = 0;
        self.blocks_compressed = 0;
    }

    /// The bytes of this chunk seen so far, blocks already compressed included.
    pub fn len(self: *const ChunkState) usize {
        return core.block_length * @as(usize, self.blocks_compressed) + @as(usize, self.buf_len);
    }

    fn startFlag(self: *const ChunkState) core.Flags {
        return if (self.blocks_compressed == 0) .{ .chunk_start = true } else .{};
    }

    fn fillBuf(self: *ChunkState, input: []const u8) usize {
        const free = core.block_length - @as(usize, self.buf_len);
        const take = @min(free, input.len);
        @memcpy(self.buf[self.buf_len..][0..take], input[0..take]);
        self.buf_len += @intCast(take);
        return take;
    }

    /// Take bytes. A block is compressed as soon as a byte after it arrives,
    /// so the last block of a chunk is still in `buf` when `output` is called.
    pub fn update(self: *ChunkState, input: []const u8) void {
        var inp = input;
        while (inp.len > 0) {
            if (self.buf_len == core.block_length) {
                self.compressBuf();
            }
            const take = self.fillBuf(inp);
            inp = inp[take..];
        }
    }

    fn compressBuf(self: *ChunkState) void {
        core.compressInPlace(
            &self.cv,
            &self.buf,
            core.block_length,
            self.chunk_counter,
            self.startFlag(),
        );
        self.blocks_compressed += 1;
        self.buf = @splat(0);
        self.buf_len = 0;
    }

    /// The last compression of this chunk. CHUNK_END goes here and not earlier,
    /// because this is the final block the chunk will ever see.
    pub fn output(self: *const ChunkState) Output {
        return .{
            .input_cv = self.cv,
            .block = self.buf,
            .block_len = self.buf_len,
            .counter = self.chunk_counter,
            .flags = self.startFlag().with(.{ .chunk_end = true }),
        };
    }
};

const t = std.testing;
const published = @import("../gossip/plumtree/blake3_vectors.zig");

// Pinned to published bytes. Every length in that table is one chunk or
// shorter, so nothing here walks a tree: the digest is the compression, the
// counter, the block length and all four flag bits at once. The length-0 case
// is the sharpest of them, because its block is empty and only CHUNK_START,
// CHUNK_END and ROOT are left to get right.
test "a chunk reproduces every published digest of one chunk" {
    for (published.blake3_vectors) |vector| {
        const input = try published.blake3Input(vector.len);
        defer t.allocator.free(input);

        var chunk = ChunkState.init(0);
        chunk.update(input);
        const digest = core.cvBytes(chunk.output().chainingValue(.{ .root = true }));

        try t.expectEqualStrings(vector.hash, &std.fmt.bytesToHex(&digest, .lower));
    }
}

// ROOT is one bit on the same compression, and it changes the value. If the
// root and non-root outputs were equal, a tree could not tell a range's own
// value from its root hash, and every subtree in it would be wrong.
test "a root output and a chaining value over the same node differ" {
    const input = try published.blake3Input(64);
    defer t.allocator.free(input);

    var chunk = ChunkState.init(0);
    chunk.update(input);
    const output = chunk.output();

    try t.expect(!std.meta.eql(
        output.chainingValue(.{ .root = true }),
        output.chainingValue(.{}),
    ));
}

// The node is over its left child and then its right child. An unordered pair
// would make a tree accept a mirrored one.
test "a parent node is over its left child and then its right" {
    var left: core.ChainingValue = core.iv;
    var right: core.ChainingValue = core.iv;
    left[0] = 0xaa;
    right[0] = 0xbb;

    try t.expect(!std.meta.eql(
        parentChainingValue(left, right, .{}),
        parentChainingValue(right, left, .{}),
    ));
}

// The counter is in the compression, not in the tree above it. Without it two
// chunks of the same bytes would be one node.
test "a chunk's counter is part of its value" {
    const input = try published.blake3Input(core.chunk_length);
    defer t.allocator.free(input);

    var first = ChunkState.init(0);
    var second = ChunkState.init(1);
    first.update(input);
    second.update(input);

    try t.expect(!std.meta.eql(
        first.output().chainingValue(.{}),
        second.output().chainingValue(.{}),
    ));
}

// How the bytes are cut up cannot be part of the value. A full sixteen-block
// chunk is where a block-boundary mistake would show, because every block is
// compressed over the chaining value the one before it left behind.
test "a chunk is the same value one byte at a time" {
    const input = try published.blake3Input(core.chunk_length);
    defer t.allocator.free(input);

    var whole = ChunkState.init(0);
    whole.update(input);

    var split = ChunkState.init(0);
    for (input) |byte| {
        split.update(&[_]u8{byte});
    }

    try t.expectEqual(
        whole.output().chainingValue(.{ .root = true }),
        split.output().chainingValue(.{ .root = true }),
    );
}
