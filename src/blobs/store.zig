//! Owned blob storage: the two files one blob is made of, and the rule that
//! keeps a half-written blob from ever being readable as a whole one.
//!
//! Upstream's counterpart is `iroh_blobs::fs::Store` (`src/fs/store.rs` at
//! `e82cbdcbdac9a78033174aad55e3199b2cf4c0dc`, the commit
//! `ticket/blob_ticket.zig` cites). Its shape survives whole: a blob at `hash`
//! is a data file named by that hash and a bao outboard beside it, each with a
//! second name carrying `.partial` for the write in progress, and a blob is
//! complete when its two `.partial` names have become their two plain ones.
//!
//! # Why a partial is a different file rather than a flag
//!
//! Upstream records nothing about how far a write got and re-derives it from
//! the file's length, so a crash leaves a `.partial` whose length is the only
//! evidence of what it holds and every reader must know that rule to tell a
//! short blob from a short file. Here the two states are two *names* on one
//! directory entry and promotion is `rename`, which the kernel makes atomic: a
//! reader sees either every byte under the plain name or no file under it at
//! all. There is no length to interpret and no instant at which a truncated
//! write is a blob.
//!
//! `std.Io.Dir.createFileAtomic` is deliberately not used. It materialises one
//! file and would promote each half independently, which is exactly the torn
//! pair this module exists to prevent; `Store.commit` names the order the two
//! renames run in instead, and says what a half-done commit leaves.
//!
//! # Why two directories
//!
//! Upstream carries `data_path` and `outboard_path` as two fields and opens
//! both, because an outboard is worth putting on different storage than the
//! data it describes — a 64 KiB outboard for a 4 GiB blob is the usual case.
//! That reason is not ours to drop, and one directory cannot express it. It
//! also has a second consequence, which `commit` is shaped around: two
//! renames in two directories cannot be one atomic operation, so the window
//! between them is a real state and the order decides what it looks like.
//!
//! # What is not here
//!
//! Nothing allocates and nothing is buffered on the store's behalf. Every byte
//! that crosses a file boundary goes through a slice the caller owns, and the
//! four file names live in a `Scratch` the caller declares. A store that copied
//! a blob into its own heap would hold two copies of it and put no bound on
//! either, and the protocol layer above already has the answer's buffer in
//! hand. `io` is a parameter of every call and is stored nowhere, for the
//! reason `docs/DECISIONS/0002-async-substrate.md` gives.
//!
//! Resumption, garbage collection and the collection/tag layer are separate
//! slices and deliberately absent: `openPartial` truncates, so it is a *fresh*
//! write and a caller cannot resume by accident.

const std = @import("std");
const assert = std.debug.assert;

const Io = std.Io;
const Dir = Io.Dir;
const File = Io.File;

/// The 32 bytes a blob is named by. A file-private alias, for the reason
/// `protocol.zig` gives: three modules naming the same value is not three
/// types, and a fourth exported name for it would be a second convention.
const Hash = [32]u8;
const hash_length = @sizeOf(Hash);

/// Characters in the hex form a hash is stored under, and the half of a file
/// name that is not a suffix.
const hash_hex_length = hash_length * 2;

/// The outboard's suffix, applied whether or not the write is finished.
const outboard_suffix = ".outboard";
/// The suffix that marks a write in progress, on either file.
const partial_suffix = ".partial";

/// The longest suffix pair a name carries: the outboard's plus the partial's.
const longest_suffix_length = outboard_suffix.len + partial_suffix.len;

/// Bytes the longest name a store ever writes occupies, and so the size of the
/// `Scratch` a caller declares.
pub const max_name_length = hash_hex_length + longest_suffix_length;

/// Bytes the data file's complete name occupies.
pub const data_name_length = hash_hex_length;
/// Bytes the outboard's complete name occupies.
pub const outboard_name_length = hash_hex_length + outboard_suffix.len;
/// Bytes the data file's in-progress name occupies.
pub const partial_data_name_length = hash_hex_length + partial_suffix.len;
/// Bytes the outboard's in-progress name occupies: the longest of the four.
pub const partial_outboard_name_length = max_name_length;

// **A `Scratch` array is longer than the name in it, and the tail is never
// written.** These four are how a caller slices one down to the name itself.
// They are stated here rather than computed at each `sub_path` because a
// whole-array slice is a path with whatever was on the stack behind it, and
// that is a filename no test in this file would notice until the store could
// not find a blob it had just written.
comptime {
    assert(max_name_length == hash_hex_length + longest_suffix_length);
    assert(outboard_suffix.len + partial_suffix.len == longest_suffix_length);
    assert(partial_suffix.len <= longest_suffix_length);
    assert(data_name_length == hash_hex_length);
    assert(partial_data_name_length == data_name_length + partial_suffix.len);
    assert(outboard_name_length == data_name_length + outboard_suffix.len);
    assert(partial_outboard_name_length == outboard_name_length + partial_suffix.len);
    assert(partial_outboard_name_length == max_name_length);
}

/// A directory could not be opened, or a file within one could not be created
/// or opened. `error.FileNotFound` from `Pair.openComplete` is a clean miss
/// and nothing else.
///
/// The two halves are one union because a store does both: `Dir.OpenError`
/// covers opening the two directories and `File.OpenError` covers the files
/// inside them, and neither is a subset of the other — `Dir.OpenError` has no
/// `IsDir` and `File.OpenError` has no `PipeBusy`. Naming whichever appeared
/// first would drop a refusal the other half can return.
pub const OpenError = Dir.OpenError || File.OpenError;
/// Bytes could not be read out of one of the pair's files.
pub const ReadError = File.ReadPositionalError;
/// Bytes could not be written into one of the pair's files.
pub const WriteError = File.WritePositionalError;
/// The data file's length could not be read.
pub const SizeError = File.LengthError;
/// A `.partial` name could not be renamed onto its complete name.
pub const CommitError = Dir.RenameError;
/// A `.partial` name could not be unlinked.
pub const AbortError = Dir.DeleteFileError;

/// Write the two names `hash` is stored under into caller-owned slices.
///
/// `partial` selects which pair: `.partial` names when it is set, the plain
/// names when it is not. Both destinations must be `max_name_length` bytes;
/// every caller reaches them through a `Scratch`, whose arrays are exactly
/// that, so there is no length to check here and nothing to get wrong.
///
/// The longest form of each name is written first and the short form is simply
/// left out, because overwriting the tail of a longer name is the kind of
/// two-step that goes wrong without saying so.
fn writeNames(hash: Hash, partial: bool, data_out: []u8, outboard_out: []u8) void {
    const hex = std.fmt.bytesToHex(&hash, .lower);
    @memcpy(data_out[0..hash_hex_length], &hex);
    @memcpy(outboard_out[0..hash_hex_length], &hex);
    @memcpy(data_out[hash_hex_length..], partial_suffix);
    @memcpy(outboard_out[hash_hex_length..], outboard_suffix);
    if (partial) @memcpy(outboard_out[hash_hex_length + outboard_suffix.len ..], partial_suffix);
}

/// Every file name a store operation needs, in storage the caller owns.
///
/// Four entries because promotion needs both the `.partial` names and the names
/// they become, and building the second pair over the first would leave one of
/// them unnamed. Fixed-size because a name is 64 hex digits and at most two
/// suffixes: a store that built these on its own heap would own what is really
/// a caller's stack value.
pub const Scratch = struct {
    /// The data file's complete name: 64 hex digits.
    data: [max_name_length]u8,
    /// The outboard's complete name: 64 hex digits and `.outboard`.
    outboard: [max_name_length]u8,
    /// The data file's in-progress name: 64 hex digits and `.partial`.
    partial_data: [max_name_length]u8,
    /// The outboard's in-progress name: both suffixes.
    partial_outboard: [max_name_length]u8,

    /// The four names `hash` is stored under, ready to hand to a `Dir` call.
    ///
    /// Every entry is written on every call, so a `Scratch` reused across two
    /// blobs carries nothing of the first one into the second.
    pub fn fill(self: *Scratch, hash: Hash) void {
        writeNames(hash, false, &self.data, &self.outboard);
        writeNames(hash, true, &self.partial_data, &self.partial_outboard);
    }
};

/// Which of a pair's two files a read or a write names.
pub const Side = enum {
    /// The blob's bytes.
    data,
    /// The blob's bao outboard: the tree of chunk hashes a partial transfer is
    /// checked against.
    outboard,

    /// The file `self` names, copied out. The `Pair` is not released by this
    /// and the copy is a descriptor value, which is what every `std.Io.File`
    /// call takes.
    fn pick(self: Side, pair: *const Pair) File {
        return switch (self) {
            .data => pair.data,
            .outboard => pair.outboard,
        };
    }
};

/// The owned pair of directories: blob bytes in one, bao outboards in the
/// other. Both handles are this store's and `close` releases both.
///
/// The handles are all it owns. No name is kept, no hash is cached and nothing
/// is open between calls, so a `Store` copied by value is two copies of one
/// store's two descriptors rather than a second store.
pub const Store = struct {
    /// Where the blob bytes live.
    data: Dir,
    /// Where the outboards live.
    outboard: Dir,

    /// Open both directories by absolute path, creating neither.
    ///
    /// A store does not create the directories it writes into: which paths
    /// exist and with what permissions is the caller's decision, and a store
    /// that made them would be a store that could put a blob somewhere the
    /// operator did not ask for.
    ///
    /// A failure to open `outboard_path` closes the handle already taken for
    /// `data_path` rather than leaking it, which is what the `errdefer` is
    /// for and why the handle is a named local rather than an inline field.
    pub fn open(
        io: Io,
        data_path: []const u8,
        outboard_path: []const u8,
    ) OpenError!Store {
        const data = try Dir.openDirAbsolute(io, data_path, .{});
        errdefer Dir.close(data, io);
        const outboard = try Dir.openDirAbsolute(io, outboard_path, .{});
        return .{ .data = data, .outboard = outboard };
    }

    /// Release both directory handles. Consumes the store: do not close a copy
    /// or call this twice, and neither handle is reset.
    pub fn close(self: Store, io: Io) void {
        Dir.close(self.data, io);
        Dir.close(self.outboard, io);
    }

    /// Promote the `.partial` pair for `hash` to its two complete names.
    ///
    /// **The outboard is renamed first, and that order is the whole safety
    /// property.** Two renames in two directories cannot be one atomic
    /// operation, so a window exists and the only question is which way it
    /// fails. With the outboard first the window is an outboard with no data
    /// file beside it, and `openComplete` cannot see that state because it
    /// opens the data file first: the store reads as a miss, which is what an
    /// absent blob is. The other order leaves a data file a reader opens and
    /// then cannot find an outboard beside, which is a torn pair and not a
    /// miss — and a torn pair is the one answer a reader would have to guess
    /// its way out of.
    ///
    /// **A failure here is a torn pair, and it is reported rather than
    /// finished.** The outboard may already be at its complete name, and this
    /// call does not pretend otherwise: an outboard that is already there and
    /// one that was never written are one state on disk, so a `commit` that
    /// treated a missing outboard partial as done would report success for a
    /// blob with no outboard behind it. Re-running is not the recovery either,
    /// because the outboard half is already moved and renaming it again fails.
    /// The recovery is the caller's and it is two writes: put both partials
    /// back and commit again.
    pub fn commit(self: Store, io: Io, hash: Hash, scratch: *Scratch) CommitError!void {
        scratch.fill(hash);
        try Dir.rename(
            self.outboard,
            scratch.partial_outboard[0..partial_outboard_name_length],
            self.outboard,
            scratch.outboard[0..outboard_name_length],
            io,
        );
        try Dir.rename(
            self.data,
            scratch.partial_data[0..partial_data_name_length],
            self.data,
            scratch.data[0..data_name_length],
            io,
        );
    }

    /// Unlink the `.partial` pair for `hash`, so no in-progress write survives
    /// this call.
    ///
    /// Both halves are attempted even when the first fails, because a caller
    /// told about one would have to run a second abort to learn the other, and
    /// the point of an abort is that nothing is left. The first failure is the
    /// one reported, as the one a retry is most likely to hit again. A file
    /// that is already gone is not a failure at all: a name that was never
    /// created cannot survive an abort.
    pub fn abort(self: Store, io: Io, hash: Hash, scratch: *Scratch) AbortError!void {
        scratch.fill(hash);
        // Both are computed before either is reported, which is what makes the
        // second attempt happen even when the first one was refused.
        const data_failure =
            unlinkMaybe(self.data, io, scratch.partial_data[0..partial_data_name_length]);
        const outboard_failure = unlinkMaybe(
            self.outboard,
            io,
            scratch.partial_outboard[0..partial_outboard_name_length],
        );
        // Two captures rather than one `orelse`: `orelse` unwraps to a value,
        // and a value is not something an error capture can be taken from.
        if (data_failure) |refusal| return refusal;
        if (outboard_failure) |refusal| return refusal;
    }
};

/// Unlink `sub_path`, reporting `null` for the file that is already gone and
/// any other refusal as itself.
///
/// Split out so `abort` reads as two attempts and a choice rather than as four
/// catch blocks, and so the "already gone is the postcondition" rule is stated
/// once for both halves.
fn unlinkMaybe(dir: Dir, io: Io, sub_path: []const u8) ?AbortError {
    dir.deleteFile(io, sub_path) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    return null;
}

/// The owned pair of open files one blob is made of.
///
/// A `Pair` holds both handles or is not a pair: opening the outboard after the
/// data closes the data again if it fails, so a `Pair` a caller holds has two
/// live descriptors and `close` releases exactly those two.
pub const Pair = struct {
    /// The blob these files are. Copied rather than borrowed so a caller that
    /// keeps the pair can name the blob after the handles are gone.
    hash: Hash,
    /// The blob's bytes. Owned on the terms `close` states.
    data: File,
    /// The blob's bao outboard. Owned on the same terms as `data`.
    outboard: File,

    /// The complete pair for `hash`, opened read-only, or `error.FileNotFound`
    /// when the store does not hold the blob.
    ///
    /// The data file is opened first on purpose, and it is what makes the
    /// promotion window in `commit` invisible: a store that has renamed the
    /// outboard and not yet the data has no data file at this name, so this
    /// returns the miss an absent blob returns rather than half a pair.
    ///
    /// `allow_directory` is off so a directory sitting at a blob's name is
    /// refused here, at the open, instead of surfacing later as a read that
    /// fails on the first byte.
    pub fn openComplete(io: Io, store: Store, hash: Hash) OpenError!Pair {
        var scratch: Scratch = undefined;
        scratch.fill(hash);
        const data = try store.data.openFile(io, scratch.data[0..data_name_length], .{
            .mode = .read_only,
            .allow_directory = false,
        });
        errdefer File.close(data, io);
        const outboard = try store.outboard.openFile(
            io,
            scratch.outboard[0..outboard_name_length],
            .{
                .mode = .read_only,
                .allow_directory = false,
            },
        );
        return .{ .hash = hash, .data = data, .outboard = outboard };
    }

    /// The `.partial` pair for `hash`, created if absent and truncated, opened
    /// read-write.
    ///
    /// Truncating is what makes this a *fresh* write: an in-progress file left
    /// by an earlier attempt is discarded rather than continued. Resumption is
    /// a separate slice with its own open, and giving it one is the only way a
    /// caller cannot get this one by mistake.
    ///
    /// `read` is on so a writer can read back what it wrote and check it
    /// against the outboard before committing, which is the whole point of
    /// keeping the pair and not two files.
    ///
    /// A failure to create the outboard leaves the data partial behind, closed.
    /// That is an in-progress write with no outboard, which is a state the
    /// store already has a name for, so it is recoverable rather than
    /// reported twice.
    pub fn openPartial(io: Io, store: Store, hash: Hash) OpenError!Pair {
        var scratch: Scratch = undefined;
        scratch.fill(hash);
        const flags: Dir.CreateFileOptions = .{ .read = true, .truncate = true };
        const data =
            try store.data.createFile(io, scratch.partial_data[0..partial_data_name_length], flags);
        errdefer File.close(data, io);
        const outboard = try store.outboard.createFile(
            io,
            scratch.partial_outboard[0..partial_outboard_name_length],
            flags,
        );
        return .{ .hash = hash, .data = data, .outboard = outboard };
    }

    /// Release both descriptors, data first. Consumes the pair: do not close a
    /// copy and do not call this twice. Neither descriptor is reset, and a
    /// partial stays on disk under its `.partial` name either way — committing
    /// is `Store.commit`'s decision, not this one's.
    pub fn close(self: Pair, io: Io) void {
        File.close(self.data, io);
        File.close(self.outboard, io);
    }

    /// The blob's length in bytes, which is the data file's length and says
    /// nothing about the outboard's.
    pub fn size(self: *const Pair, io: Io) SizeError!u64 {
        return self.data.length(io);
    }

    /// Read from `side` at byte `at` into `out`, and how many bytes arrived.
    ///
    /// A short count is end of file and not a failure: reading the last chunk
    /// of a blob is a shorter read than reading a full one, and a blob whose
    /// length is not a multiple of the block size is shorter at the end by
    /// construction. `out` is the caller's buffer and nothing is copied on the
    /// way out, so a range wider than the file costs the file's length and no
    /// more.
    pub fn read(self: *const Pair, io: Io, side: Side, at: u64, out: []u8) ReadError!usize {
        return side.pick(self).readPositionalAll(io, out, at);
    }

    /// Write `bytes` to `side` at byte `at`: all of them, or an error.
    ///
    /// Positional, so a write does not depend on where the last one left the
    /// descriptor and two writers at two offsets cannot interleave into one
    /// file's middle. Nothing is flushed here beyond what the call does, and
    /// nothing is promoted here either: bytes written to a `.partial` name are
    /// not a blob until `Store.commit` has run.
    pub fn write(
        self: *const Pair,
        io: Io,
        side: Side,
        at: u64,
        bytes: []const u8,
    ) WriteError!void {
        try side.pick(self).writePositionalAll(io, bytes, at);
    }
};

const t = std.testing;

/// Two directories under one `TmpDir`, and the store over them. The test owns
/// all of it, so cleanup is one `defer` and nothing outlives the test that
/// made it.
const Fixture = struct {
    tmp: std.testing.TmpDir,
    store: Store,
    scratch: Scratch,

    fn init() !Fixture {
        var tmp: std.testing.TmpDir = .tmpDir(.{});
        errdefer tmp.cleanup();
        const io = t.io;
        // Two real subdirectories, because a store that put both halves in one
        // directory would pass every test here that a store using two does not.
        const data = try tmp.dir.createDirPathOpen(io, "data", .{});
        defer data.close(io);
        const outboard = try tmp.dir.createDirPathOpen(io, "outboard", .{});
        defer outboard.close(io);
        return .{
            .tmp = tmp,
            .store = try openAt(io, data, outboard),
            .scratch = undefined,
        };
    }

    fn deinit(self: *Fixture) void {
        self.store.close(t.io);
        self.tmp.cleanup();
    }
};

/// The store over two open directories, through the absolute paths `Store.open`
/// takes: the constructor under test is the one the tests use, rather than a
/// test-only path into the same struct.
fn openAt(io: std.Io, data: std.Io.Dir, outboard: std.Io.Dir) !Store {
    var data_path: [Dir.max_path_bytes]u8 = undefined;
    var outboard_path: [Dir.max_path_bytes]u8 = undefined;
    const data_len = try data.realPath(io, &data_path);
    const outboard_len = try outboard.realPath(io, &outboard_path);
    return Store.open(io, data_path[0..data_len], outboard_path[0..outboard_len]);
}

/// A hash, filled with a byte so two calls with different arguments cannot
/// collide by accident.
fn hashOf(byte: u8) Hash {
    return [_]u8{byte} ** hash_length;
}

test "a name is its hash in hex and nothing else, and the longest one fits" {
    var scratch: Scratch = undefined;
    scratch.fill(hashOf(0xab));

    // The complete data name is the hex and nothing else, and this compares
    // the whole name rather than a prefix of it: a suffix appended after byte
    // 64 is exactly what a partial-compare would not see.
    try t.expectEqualStrings(
        "abababababababababababababababababababababababababababababababab",
        scratch.data[0..data_name_length],
    );

    // The two finished names and the two in-progress ones, and the in-progress
    // outboard is the only name carrying both suffixes.
    try t.expectEqualStrings(
        "abababababababababababababababababababababababababababababababab.partial",
        scratch.partial_data[0..nameLen(true, false)],
    );
    try t.expectEqualStrings(
        "abababababababababababababababababababababababababababababababab.outboard",
        scratch.outboard[0..nameLen(false, true)],
    );
    try t.expectEqualStrings(
        "abababababababababababababababababababababababababababababababab.outboard.partial",
        scratch.partial_outboard[0..nameLen(true, true)],
    );

    // `max_name_length` is the length of the longest of them, so a caller who
    // sizes a buffer from it cannot be short and has no slack to be wrong with.
    try t.expectEqual(max_name_length, nameLen(true, true));

    // The rule this test recomputes and the constants production code slices
    // with have to be the same four numbers, or the assertions above are
    // measuring a name the store never opens.
    try t.expectEqual(data_name_length, nameLen(false, false));
    try t.expectEqual(outboard_name_length, nameLen(false, true));
    try t.expectEqual(partial_data_name_length, nameLen(true, false));
    try t.expectEqual(partial_outboard_name_length, nameLen(true, true));

    // A second fill replaces every name, so nothing of one blob reaches into
    // the next one's scratch.
    scratch.fill(hashOf(0x01));
    try t.expectEqualStrings(
        "0101010101010101010101010101010101010101010101010101010101010101",
        scratch.data[0..hash_hex_length],
    );
    try t.expectEqualStrings(
        "0101010101010101010101010101010101010101010101010101010101010101.outboard.partial",
        scratch.partial_outboard[0..nameLen(true, true)],
    );
}

/// The bytes a name occupies: the hex, then the suffixes it carries. Written
/// out here rather than computed by the production code, so a test asserting a
/// name is checking the name against the rule and not against itself.
fn nameLen(partial: bool, outboard: bool) usize {
    var total = hash_hex_length;
    if (outboard) total += outboard_suffix.len;
    if (partial) total += partial_suffix.len;
    return total;
}

test "a partial pair is invisible until commit, and a miss is a miss" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const io = t.io;
    const hash = hashOf(0x11);

    const pair = try Pair.openPartial(io, fixture.store, hash);
    const bytes = [_]u8{ 1, 2, 3, 4, 5 };
    const outboard_bytes = [_]u8{ 0xaa, 0xbb, 0xcc };
    try pair.write(io, .data, 0, &bytes);
    try pair.write(io, .outboard, 0, &outboard_bytes);
    try t.expectEqual(@as(u64, bytes.len), try pair.size(io));
    pair.close(io);

    // Every byte is on disk and the blob is still not there: the complete names
    // are two other files, and this is what makes a reader unable to see a
    // half-written blob.
    try t.expectError(error.FileNotFound, Pair.openComplete(io, fixture.store, hash));

    try fixture.store.commit(io, hash, &fixture.scratch);

    const read = try Pair.openComplete(io, fixture.store, hash);
    var into: [8]u8 = undefined;
    try t.expectEqual(bytes.len, try read.read(io, .data, 0, &into));
    try t.expectEqualSlices(u8, &bytes, into[0..bytes.len]);
    try t.expectEqual(outboard_bytes.len, try read.read(io, .outboard, 0, &into));
    try t.expectEqualSlices(u8, &outboard_bytes, into[0..outboard_bytes.len]);
    // A read past the end is a short count, not an error: the last chunk of a
    // blob is short by construction and must not read as a failure.
    try t.expectEqual(@as(usize, 0), try read.read(io, .data, bytes.len, &into));
    read.close(io);
}

test "commit puts the outboard first, and a failed data rename says so" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const io = t.io;
    const hash = hashOf(0x22);

    const pair = try Pair.openPartial(io, fixture.store, hash);
    try pair.write(io, .data, 0, "data");
    try pair.write(io, .outboard, 0, "tree");
    pair.close(io);

    // A directory already sits at the data file's complete name, so the second
    // rename cannot put a regular file there. This is the one way to fail a
    // single rename without a fault-injecting `Io`, and the data side is the
    // one to block because the outboard has to move first for the ordering to
    // be observable at all.
    fixture.scratch.fill(hash);
    try fixture.store.data.createDir(
        io,
        fixture.scratch.data[0..data_name_length],
        .default_dir,
    );

    // Which refusal this is belongs to the platform — `EISDIR`, `ENOTDIR` and
    // `ENOTEMPTY` all say the same thing here — so what is asserted is that
    // the commit failed, not which way it failed, and the error is bound rather
    // than dropped because a test that discards it cannot say why it happened.
    if (fixture.store.commit(io, hash, &fixture.scratch)) |_| {
        return error.TestUnexpectedResult;
    } else |refusal| {
        try t.expect(refusal == error.IsDir or
            refusal == error.NotDir or
            refusal == error.DirNotEmpty);
    }

    // The outboard moved and the data did not, which is the ordering the whole
    // safety argument rests on: a store in this state has no *data file* at the
    // plain name, and `openComplete` opens the data file first, so a reader
    // sees a miss rather than a pair with a hole in it.
    const moved = try fixture.store.outboard.openFile(
        io,
        fixture.scratch.outboard[0..outboard_name_length],
        .{ .mode = .read_only, .allow_directory = false },
    );
    moved.close(io);
    const kept = try fixture.store.data.openFile(
        io,
        fixture.scratch.partial_data[0..partial_data_name_length],
        .{ .mode = .read_only, .allow_directory = false },
    );
    kept.close(io);

    // A torn pair is not something a second `commit` walks back into: the
    // outboard half is already at its complete name, so the rename behind it
    // has nothing to move and is refused rather than quietly treated as done.
    // That refusal is the fail-closed half of the ordering, and it is what
    // keeps a blob with no outboard from ever being promoted.
    try fixture.store.data.deleteTree(io, fixture.scratch.data[0..data_name_length]);
    try t.expectError(error.FileNotFound, fixture.store.commit(io, hash, &fixture.scratch));

    // So the recovery is the caller's, and it is both halves written again.
    const rewritten = try Pair.openPartial(io, fixture.store, hash);
    try rewritten.write(io, .data, 0, "data");
    rewritten.close(io);
    try fixture.store.commit(io, hash, &fixture.scratch);
    const read = try Pair.openComplete(io, fixture.store, hash);
    defer read.close(io);
    var into: [4]u8 = undefined;
    try t.expectEqual(@as(usize, 4), try read.read(io, .data, 0, &into));
    try t.expectEqualStrings("data", into[0..]);
}

test "an abort leaves nothing, and aborting nothing is not a failure" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const io = t.io;
    const hash = hashOf(0x33);

    const pair = try Pair.openPartial(io, fixture.store, hash);
    try pair.write(io, .data, 0, "half a blob");
    pair.close(io);

    // A second writer for the same blob truncates rather than continuing: a
    // partial is not resumed by accident.
    const again = try Pair.openPartial(io, fixture.store, hash);
    try t.expectEqual(@as(u64, 0), try again.size(io));
    again.close(io);

    try fixture.store.abort(io, hash, &fixture.scratch);
    try t.expectError(error.FileNotFound, Pair.openComplete(io, fixture.store, hash));

    // Aborting twice is the same answer: a name that is not there cannot
    // survive an abort, so `FileNotFound` is the postcondition and not a fault.
    try fixture.store.abort(io, hash, &fixture.scratch);

    // And the pair opens again afterwards, so an abort discards the write and
    // not the store.
    const fresh = try Pair.openPartial(io, fixture.store, hash);
    fresh.close(io);
}