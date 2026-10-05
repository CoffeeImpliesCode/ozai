//! Owned blob storage: two files per blob, one commit point, no allocation.
//!
//! A blob is a data file and its outboard, and nothing in this file allocates,
//! reads a clock, or keeps an `std.Io`. `io` is a parameter of every call and a
//! field of nothing, so one `Names` value serves any number of `Io`s.
//!
//! # The four names
//!
//! Sixty-four lowercase hex digits — the blob's BLAKE3 root hash — then one of
//! `.data`, `.outboard`, `.data.partial`, `.outboard.partial`. The digits are
//! the blob's identity, so two blobs can never share a file. The names are
//! written into caller storage and borrowed back, for the reason
//! `discovery/dns.zig` gives for a query name: a name handed out of a dead
//! buffer is a name later read from freed memory.
//!
//! # Ordering is the invariant
//!
//! **The last rename of a commit is the first open of the read.** `commit`
//! promotes the outboard first and the data second; `openComplete` opens the
//! data first and the outboard second. So the one state a reader can observe
//! between the two renames — the outboard at its final name, the data still
//! partial — is refused on the *first* open, before a second descriptor is
//! taken.
//!
//! That is what makes a torn pair read as a miss rather than as corruption. A
//! miss costs a re-request and nothing else. A half-open pair is
//! indistinguishable from a store that lost a file, and every caller would then
//! need a way to tell "the other half is late" from "the other half is gone".
//! Reversing either order produces exactly that: a reader that took the data
//! descriptor first and then found no outboard has been handed one file of a
//! pair and no way to know which of the two failures it is looking at.
//!
//! # Both descriptors or neither
//!
//! `openComplete` and `createPartial` hold two descriptors or none. The second
//! open runs under an `errdefer` on the first, so a failure releases the first
//! before the error propagates. No value in this file means "the data but not
//! the outboard".
//!
//! # Why not `std.Io.Dir.createFileAtomic`
//!
//! `createFileAtomic` promotes **one** file, atomically, under a temporary name
//! the caller never sees. A blob is two files and needs **one** commit point.
//! Two independent atomic promotions give two commit points with no order
//! between them, and the interval between them is the torn pair this file
//! exists to make unreachable: the data at its final name with no outboard
//! beside it — the state `openComplete` reaches on its *second* open. Its
//! guarantee is per file, and what is needed here is per pair.
//!
//! It fails for the second reason regardless: its temporary is unnamed, so a
//! writer that dies leaves nothing behind to find. Every byte written through
//! this module lands under `.partial`, which is a name on disk, and
//! `resume.zig` finds it there.

const std = @import("std");
const requests = @import("requests.zig");

/// The BLAKE3 hash a store names a blob by. `requests.zig` owns the type and
/// the wire form; this file only spells it.
pub const Hash = requests.Hash;

const hash_bytes = @sizeOf(Hash);
const hex_length = 2 * hash_bytes;

const data_suffix = ".data";
const outboard_suffix = ".outboard";
const data_partial_suffix = ".data.partial";
const outboard_partial_suffix = ".outboard.partial";

/// The longest of the four names, so one buffer slot fits any of them.
pub const name_length: usize = hex_length + outboard_partial_suffix.len;

/// Storage for the four names of one blob, in the order `Names` lists them.
pub const NameStorage = [4][name_length]u8;

/// The four names of one blob, each borrowing the caller's `NameStorage`.
///
/// The names must not outlive the storage, and the storage must not be reused
/// for another blob while these names are still in use.
pub const Names = struct {
    /// The committed data file. Its presence is the commit point.
    data: []const u8,
    /// The committed outboard.
    outboard: []const u8,
    /// Where the data of an unfinished write lands.
    data_partial: []const u8,
    /// Where the outboard of an unfinished write lands.
    outboard_partial: []const u8,
};

/// The four names of `hash`, written into `storage`.
pub fn names(storage: *NameStorage, hash: Hash) Names {
    const digits = std.fmt.bytesToHex(&hash, .lower);
    return .{
        .data = fill(storage[0][0..], &digits, data_suffix),
        .outboard = fill(storage[1][0..], &digits, outboard_suffix),
        .data_partial = fill(storage[2][0..], &digits, data_partial_suffix),
        .outboard_partial = fill(storage[3][0..], &digits, outboard_partial_suffix),
    };
}

fn fill(out: []u8, digits: []const u8, suffix: []const u8) []const u8 {
    std.debug.assert(out.len >= hex_length + suffix.len);
    @memcpy(out[0..hex_length], digits);
    @memcpy(out[hex_length..][0..suffix.len], suffix);
    return out[0 .. hex_length + suffix.len];
}

/// Two descriptors of a pair, held or not held at all.
///
/// `openComplete` and `createPartial` both return this; which pair of names
/// they came from is the caller's business, because both obey the same rule
/// and the rule does not depend on the names.
pub const Handles = struct {
    data: std.Io.File,
    outboard: std.Io.File,

    /// Release both, in one call. There is no way to release one, which is the
    /// point of the type.
    pub fn close(self: Handles, io: std.Io) void {
        std.Io.File.closeMany(io, &.{ self.data, self.outboard });
    }
};

/// Open a blob that is completely here.
///
/// The data is opened first and on purpose: `error.FileNotFound` from the data
/// is the torn-pair window described in the module comment, and it must cost
/// one syscall rather than two. A blob whose data is here and whose outboard
/// is not also fails here, on the second open, after the first has been
/// released.
pub fn openComplete(
    io: std.Io,
    dir: std.Io.Dir,
    paths: Names,
) std.Io.File.OpenError!Handles {
    // `allow_directory = false` on both opens: a directory standing where a
    // half of a pair belongs is not a half of a pair, and on Linux a read-only
    // open of a directory succeeds. Refusing it here costs one syscall and
    // keeps `Handles` a promise of two readable files, which is the same thing
    // the write-mode open in `createPartial` already does on its own.
    const options: std.Io.Dir.OpenFileOptions = .{ .allow_directory = false };
    const data = try dir.openFile(io, paths.data, options);
    errdefer data.close(io);
    const outboard = try dir.openFile(io, paths.outboard, options);
    return .{ .data = data, .outboard = outboard };
}

/// Create, or truncate and create, both partial files. Data first, as
/// everywhere else.
///
/// Truncating is the caller's decision expressed here: re-running a write over
/// an abandoned partial starts it again rather than appending to it.
pub fn createPartial(
    io: std.Io,
    dir: std.Io.Dir,
    paths: Names,
) std.Io.File.OpenError!Handles {
    const flags: std.Io.Dir.CreateFileOptions = .{ .read = true, .truncate = true };
    const data = try dir.createFile(io, paths.data_partial, flags);
    errdefer data.close(io);
    const outboard = try dir.createFile(io, paths.outboard_partial, flags);
    return .{ .data = data, .outboard = outboard };
}

/// Promote both partials, the outboard first.
///
/// The caller holds no descriptors across this: on Linux the rename is visible
/// to a reader the instant it returns whatever the old descriptor is still
/// open, so the pair is committed by name and not by an open file. If the
/// second rename fails the store is left in the torn window, which reads as a
/// miss; the orphan outboard is never reached, because `openComplete` never
/// gets past the data.
pub fn commit(io: std.Io, dir: std.Io.Dir, paths: Names) std.Io.Dir.RenameError!void {
    try std.Io.Dir.rename(dir, paths.outboard_partial, dir, paths.outboard, io);
    try std.Io.Dir.rename(dir, paths.data_partial, dir, paths.data, io);
}

/// Delete both partials. One that is not there is already discarded, which is
/// what makes this idempotent and therefore safe to call on a partial that was
/// never created.
pub fn discardPartials(
    io: std.Io,
    dir: std.Io.Dir,
    paths: Names,
) std.Io.Dir.DeleteFileError!void {
    try remove(io, dir, paths.data_partial);
    try remove(io, dir, paths.outboard_partial);
}

fn remove(io: std.Io, dir: std.Io.Dir, path: []const u8) std.Io.Dir.DeleteFileError!void {
    dir.deleteFile(io, path) catch |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    };
}

const t = std.testing;

// Sixty-four hex digits and a suffix, and the two halves share nothing.
test "the four names are the hash's digits and four different suffixes" {
    var storage: NameStorage = undefined;
    const built = names(&storage, @splat(0xab));
    const digits = "ab" ** 32;
    try t.expectEqualStrings(digits ++ ".data", built.data);
    try t.expectEqualStrings(digits ++ ".outboard", built.outboard);
    try t.expectEqualStrings(digits ++ ".data.partial", built.data_partial);
    try t.expectEqualStrings(digits ++ ".outboard.partial", built.outboard_partial);

    const all = [_][]const u8{
        built.data,
        built.outboard,
        built.data_partial,
        built.outboard_partial,
    };
    for (all, 0..) |left, left_index| {
        for (all, 0..) |right, right_index| {
            if (left_index == right_index) continue;
            // The four are four different whole names, which is what every
            // syscall in this file matches on: a rename takes `.data.partial`
            // and lands on `.data`, and no two of the four strings are equal,
            // so it can never land on another of them.
            //
            // A committed name *is* a prefix of its own partial — `.data` of
            // `.data.partial`, and `.outboard` of `.outboard.partial`. That is
            // not a hazard here and the test above it says why: nothing in this
            // module matches a name by prefix, so the two spellings of one half
            // cannot be confused for one another.
            try t.expect(!std.mem.eql(u8, right, left));
        }
    }
}

// The committed pair is reachable by name, and the partials are not.
test "a commit is two renames, and the result opens as a pair" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    const data = [_]u8{ 1, 2, 3, 4, 5 };

    var storage: NameStorage = undefined;
    const built = names(&storage, @splat(0x11));
    const partial = try createPartial(t.io, tmp.dir, built);
    try partial.data.writeStreamingAll(t.io, &data);
    try partial.outboard.writeStreamingAll(t.io, &data);
    partial.close(t.io);

    try t.expectError(error.FileNotFound, openComplete(t.io, tmp.dir, built));

    try commit(t.io, tmp.dir, built);

    const handles = try openComplete(t.io, tmp.dir, built);
    defer handles.close(t.io);
    var read_back: [data.len]u8 = undefined;
    _ = try handles.data.readPositionalAll(t.io, &read_back, 0);
    try t.expectEqualSlices(u8, &data, &read_back);
    // The partial names are gone: a rename does not leave the old name behind,
    // which is what makes a second `commit` fail rather than re-promote.
    try t.expectError(error.FileNotFound, openFileAt(t.io, tmp.dir, built.data_partial));
    try t.expectError(error.FileNotFound, openFileAt(t.io, tmp.dir, built.outboard_partial));
}

// The data is what a torn pair is missing, so the data is what is opened
// first. A directory standing where the outboard belongs makes the *second*
// open fail, which is the only way to observe that the first was released.
test "a failed second open releases the first, and a missing data is one miss" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();

    var storage: NameStorage = undefined;
    const built = names(&storage, @splat(0x22));
    const file = try createFileAt(t.io, tmp.dir, built.data);
    file.close(t.io);
    try tmp.dir.createDir(t.io, built.outboard, .default_dir);

    const before = try openDescriptors();
    try t.expectError(error.IsDir, openComplete(t.io, tmp.dir, built));
    try t.expectEqual(before, try openDescriptors());

    // Now the other way round: the data absent, the outboard present. Same
    // answer, and one open rather than two. The data goes first, because a
    // half-open pair is the torn window the module comment is about.
    try tmp.dir.deleteDir(t.io, built.outboard);
    const outboard = try createFileAt(t.io, tmp.dir, built.outboard);
    outboard.close(t.io);
    try tmp.dir.deleteFile(t.io, built.data);
    try t.expectError(error.FileNotFound, openComplete(t.io, tmp.dir, built));
}

// Discarding is idempotent, which is the property that makes it safe to call
// on a partial that was never created.
test "discarding twice is the same as discarding once" {
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    var storage: NameStorage = undefined;
    const built = names(&storage, @splat(0x33));

    try discardPartials(t.io, tmp.dir, built);
    const partial = try createPartial(t.io, tmp.dir, built);
    partial.close(t.io);
    try discardPartials(t.io, tmp.dir, built);
    try t.expectError(error.FileNotFound, openFileAt(t.io, tmp.dir, built.data_partial));
    try t.expectError(error.FileNotFound, openFileAt(t.io, tmp.dir, built.outboard_partial));
}

fn createFileAt(io: std.Io, dir: std.Io.Dir, path: []const u8) !std.Io.File {
    return dir.createFile(io, path, .{ .read = true });
}

fn openFileAt(io: std.Io, dir: std.Io.Dir, path: []const u8) !std.Io.File {
    return dir.openFile(io, path, .{});
}

/// How many descriptors this process holds.
///
/// It is the only direct way to see that an `errdefer` ran: the alternative is
/// to read the code that says it does. Linux-only by construction, and it
/// fails the test rather than skipping when `/proc` is not there, because a
/// descriptor count of zero would make the assertion vacuous.
fn openDescriptors() !usize {
    const proc = try std.Io.Dir.openDirAbsolute(t.io, "/proc/self/fd", .{ .iterate = true });
    defer proc.close(t.io);
    var count: usize = 0;
    var iterator = proc.iterate();
    while (try iterator.next(t.io)) |_| count += 1;
    return count;
}
