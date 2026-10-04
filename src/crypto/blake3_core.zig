//! The BLAKE3 compression function and the node one compression produces,
//! ported out of the standard library's BLAKE3 (`lib/std/crypto/blake3.zig`)
//! because the two values a Bao tree is built from cannot be asked of it.
//!
//! A Bao tree holds the *chaining value* of every interior node and the root
//! hash of the whole, and a node's chaining value is its root hash compression
//! with the ROOT flag absent — the same bytes, a different value.
//! `std.crypto.hash.Blake3` has no way to produce one: `final` (`:1160`) is the
//! only way out of the hasher and it always sets ROOT (`rootBytes`, `:920`),
//! while everything needed to do otherwise is file-private — `Flags` (`:41`),
//! `ChunkState` (`:837`), `Output` (`:907`) and the CV stack of `Blake3`
//! (`:952`). There is no way to reach the hash of a subtree either: the hasher
//! is told the bytes, never where they start.
//!
//! So this is the same file's compression and node handling moved into a
//! module that exposes them, not a second implementation of BLAKE3. The round
//! function, the flags, the chunk state and the parent output are std's; the
//! sibling `blake3_subtree.zig` walks them and checks every digest it produces
//! against the published BLAKE3 vectors.
//!
//! Only the unkeyed hash is here. A tree is content addressing, so the key
//! words are the IV and there is no keyed or key-derivation mode here to get
//! wrong; `std.crypto.hash.Blake3` still covers those.

const std = @import("std");

/// A digest is 32 bytes, and so is a chaining value: the two are the same
/// width and different values, which is why they carry different names.
pub const digest_length = 32;

/// The compression block, 64 bytes: the unit one BLAKE3 compression reads.
pub const block_length = 64;

/// The chunk, 1024 bytes, sixteen blocks: the unit the tree is built from.
pub const chunk_length = 1024;

/// The eight initial words, which are also the key words of an unkeyed hash
/// and so the chaining value every compression starts from.
const iv: [8]u32 = .{
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
};

/// The message word permutation of each of the seven rounds.
const msg_schedule: [7][16]u8 = .{
    .{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
    .{ 2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8 },
    .{ 3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1 },
    .{ 10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6 },
    .{ 12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4 },
    .{ 9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7 },
    .{ 11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13 },
};

/// What a compression is a compression *of*: the four domain flags this module
/// ever sets. The three bits keyed hashing and key derivation claim
/// (`lib/std/crypto/blake3.zig:55`) are left zero, because a tree has no key.
pub const Flags = packed struct(u8) {
    /// The first block of a chunk.
    chunk_start: bool = false,
    /// The last block of a chunk, or of the whole input.
    chunk_end: bool = false,
    /// The block is two chaining values rather than input bytes.
    parent: bool = false,
    /// This compression is the root, so its output is a hash and not a value
    /// to be merged into a parent.
    root: bool = false,
    unused: u3 = 0,

    fn toInt(self: Flags) u8 {
        return @bitCast(self);
    }

    fn with(self: Flags, other: Flags) Flags {
        return @bitCast(self.toInt() | other.toInt());
    }
};

fn load32(bytes: []const u8) u32 {
    return std.mem.readInt(u32, bytes[0..4], .little);
}

fn store32(bytes: []u8, word: u32) void {
    std.mem.writeInt(u32, bytes[0..4], word, .little);
}

/// The eight words of a chaining value, which is how it is stored on a stack
/// while a subtree is being folded and how a parent's block is laid out.
pub fn loadCvWords(bytes: [digest_length]u8) [8]u32 {
    var words: [8]u32 = undefined;
    for (0..8) |i| words[i] = load32(bytes[i * 4 ..][0..4]);
    return words;
}

/// The 32 bytes of a chaining value, which is how a tree names one.
pub fn storeCvWords(words: [8]u32) [digest_length]u8 {
    var bytes: [digest_length]u8 = undefined;
    for (0..8) |i| store32(bytes[i * 4 ..][0..4], words[i]);
    return bytes;
}

inline fn g(state: *[16]u32, a: usize, b: usize, c: usize, d: usize, x: u32, y: u32) void {
    state[a] +%= state[b] +% x;
    state[d] = std.math.rotr(u32, state[d] ^ state[a], 16);
    state[c] +%= state[d];
    state[b] = std.math.rotr(u32, state[b] ^ state[c], 12);
    state[a] +%= state[b] +% y;
    state[d] = std.math.rotr(u32, state[d] ^ state[a], 8);
    state[c] +%= state[d];
    state[b] = std.math.rotr(u32, state[b] ^ state[c], 7);
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

/// The compression itself: the sixteen words every node is read out of,
/// which the two outputs differ on — a chaining value folds them back into
/// the chaining value the compression started from, a root output writes
/// them out.
fn compressPre(
    state: *[16]u32,
    cv: *const [8]u32,
    block: *const [block_length]u8,
    block_len: u8,
    counter: u64,
    flags: Flags,
) void {
    var block_words: [16]u32 = undefined;
    for (0..16) |i| block_words[i] = load32(block[i * 4 ..][0..4]);

    for (0..8) |i| state[i] = cv[i];
    for (0..4) |i| state[i + 8] = iv[i];
    state[12] = @truncate(counter);
    state[13] = @truncate(counter >> 32);
    state[14] = @as(u32, block_len);
    state[15] = @as(u32, flags.toInt());

    for (0..7) |round| roundFn(state, &block_words, round);
}

/// The chaining value of a node, and nothing else: the value a parent merges.
/// The ROOT flag is not added here, which is what makes the result a chaining
/// value rather than a hash of the same bytes.
pub fn compressInPlace(
    cv: *[8]u32,
    block: *const [block_length]u8,
    block_len: u8,
    counter: u64,
    flags: Flags,
) void {
    var state: [16]u32 = undefined;
    compressPre(&state, cv, block, block_len, counter, flags);
    for (0..8) |i| cv[i] = state[i] ^ state[i + 8];
}

/// The root hash of a node: the same compression with the ROOT flag set,
/// written out instead of folded back. The output counter is zero, because
/// only the first 32 bytes of the extended output are ever read here and a
/// digest in this build is 32 bytes.
fn compressRoot(
    cv: *const [8]u32,
    block: *const [block_length]u8,
    block_len: u8,
    flags: Flags,
    out: *[digest_length]u8,
) void {
    var state: [16]u32 = undefined;
    compressPre(&state, cv, block, block_len, 0, flags.with(.{ .root = true }));
    for (0..8) |i| store32(out[i * 4 ..][0..4], state[i] ^ state[i + 8]);
}

/// One node of the tree, held the way its last compression reads it: the
/// chaining value it starts from, the block, and the three things that make
/// that block what it is.
pub const Output = struct {
    input_cv: [8]u32,
    block: [block_length]u8,
    /// The bytes of `block` that are input rather than padding, 0 to 64.
    /// Zero is the empty input's own node, not a padded block.
    block_len: u8,
    /// The chunk counter, for a chunk node; zero for a parent node.
    counter: u64,
    flags: Flags,

    /// What this node's parent merges. The ROOT flag is absent, so the 32
    /// bytes are a chaining value and not a hash of this node.
    pub fn chainingValue(self: *const Output) [8]u32 {
        var words = self.input_cv;
        compressInPlace(&words, &self.block, self.block_len, self.counter, self.flags);
        return words;
    }

    /// This node's hash: the root compression of it, in bytes.
    pub fn rootHash(self: *const Output) [digest_length]u8 {
        var bytes: [digest_length]u8 = undefined;
        compressRoot(&self.input_cv, &self.block, self.block_len, self.flags, &bytes);
        return bytes;
    }
};

/// The parent of two children, which is a node like any other: one block of
/// the left chaining value followed by the right, the PARENT flag, no chunk
/// counter and no chunk flags. Whether it is also the root is decided by the
/// caller that owns it, which is the whole difference between
/// `mergeSubtreesNonRoot` and `mergeSubtreesRoot`.
pub fn parentOutput(left: [8]u32, right: [8]u32) Output {
    var block: [block_length]u8 = undefined;
    for (0..8) |i| {
        store32(block[i * 4 ..][0..4], left[i]);
        store32(block[(i + 8) * 4 ..][0..4], right[i]);
    }
    return .{
        .input_cv = iv,
        .block = block,
        .block_len = block_length,
        .counter = 0,
        .flags = .{ .parent = true },
    };
}

/// One chunk: the lowest node of the tree, sixteen blocks whose first and
/// last carry the chunk flags. It buffers blocks rather than compressing as
/// it goes, because the last block of a chunk is only known to be last when
/// the bytes after it are not there.
pub const ChunkState = struct {
    cv: [8]u32,
    /// The index of this chunk in the whole input, which is the counter every
    /// compression of it reads. It is what makes a subtree hash what it is:
    /// the same bytes at another offset are another chunk and another value.
    chunk_counter: u64,
    buf: [block_length]u8,
    buf_len: u8,
    blocks_compressed: u8,
    flags: Flags,

    /// The chunk at `chunk_counter`, under `flags`.
    pub fn init(chunk_counter: u64, flags: Flags) ChunkState {
        return .{
            .cv = iv,
            .chunk_counter = chunk_counter,
            .buf = @splat(0),
            .buf_len = 0,
            .blocks_compressed = 0,
            .flags = flags,
        };
    }

    /// The empty chunk at `chunk_counter`, keeping `flags`: what the chunk
    /// after a completed one starts as.
    pub fn reset(self: *ChunkState, chunk_counter: u64) void {
        self.cv = iv;
        self.chunk_counter = chunk_counter;
        self.buf = @splat(0);
        self.buf_len = 0;
        self.blocks_compressed = 0;
    }

    /// The bytes of this chunk that have been fed: the compressed blocks and
    /// the buffered one. Never more than `chunk_length`.
    pub fn len(self: *const ChunkState) usize {
        return block_length * @as(usize, self.blocks_compressed) + @as(usize, self.buf_len);
    }

    /// CHUNK_START belongs to the chunk's first block and to no other.
    fn maybeStartFlag(self: *const ChunkState) Flags {
        return if (self.blocks_compressed == 0) .{ .chunk_start = true } else .{};
    }

    /// Feed input to this chunk, which must not run past its end.
    pub fn update(self: *ChunkState, input: []const u8) void {
        var remaining = input;
        while (remaining.len > 0) {
            // A full buffer is compressed only here, where there are bytes
            // after it. That is what leaves the final block of the chunk for
            // `output` to compress with CHUNK_END.
            if (self.buf_len == block_length) {
                compressInPlace(
                    &self.cv,
                    &self.buf,
                    block_length,
                    self.chunk_counter,
                    self.flags.with(self.maybeStartFlag()),
                );
                self.blocks_compressed += 1;
                self.buf = @splat(0);
                self.buf_len = 0;
            }
            const take = @min(block_length - @as(usize, self.buf_len), remaining.len);
            @memcpy(self.buf[self.buf_len..][0..take], remaining[0..take]);
            self.buf_len += @intCast(take);
            remaining = remaining[take..];
        }
    }

    /// This chunk's node: the chunk flags on the last block, which is the
    /// buffered one.
    pub fn output(self: *const ChunkState) Output {
        return .{
            .input_cv = self.cv,
            .block = self.buf,
            .block_len = self.buf_len,
            .counter = self.chunk_counter,
            .flags = self.flags.with(self.maybeStartFlag()).with(.{ .chunk_end = true }),
        };
    }
};

const testing = std.testing;

test "the empty chunk at chunk zero is the digest of no bytes" {
    // The published vector for an empty input. `blake3_subtree.zig` mirrors
    // the whole table from `src/gossip/plumtree.zig:1561`; this is the case
    // that the chunk flags and the root output can be wrong on their own.
    const chunk = ChunkState.init(0, .{});
    try testing.expectEqualStrings(
        "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
        &std.fmt.bytesToHex(chunk.output().rootHash(), .lower),
    );
}

test "a parent node is not a root node" {
    const left = loadCvWords(ChunkState.init(0, .{}).output().chainingValue());
    const right = loadCvWords(ChunkState.init(1, .{}).output().chainingValue());
    const parent = parentOutput(left, right);
    // One node, one compression, two values: the ROOT flag is the only thing
    // between them, so a tree that mixes them up proves nothing about the
    // bytes it was given.
    try testing.expect(!std.mem.eql(
        u8,
        &parent.rootHash(),
        &storeCvWords(parent.chainingValue()),
    ));
}

test "the same bytes at another chunk index are another node" {
    // The counter is in the compression, so where a subtree starts is part of
    // its value. This is what a range hash has to carry, and what hashing a
    // range from byte zero would throw away.
    const first = ChunkState.init(0, .{});
    const second = ChunkState.init(1, .{});
    const input: [16]u8 = @splat(7);
    first.update(&input);
    second.update(&input);
    try testing.expect(!std.mem.eql(
        u8,
        &first.output().rootHash(),
        &second.output().rootHash(),
    ));
}