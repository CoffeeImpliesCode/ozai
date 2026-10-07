const std = @import("std");
const Allocator = std.mem.Allocator;
const Dir = std.Io.Dir;
pub const ReadFileError = Dir.ReadFileAllocError;
pub const HashFileError = Allocator.Error || std.Io.File.OpenError ||
    std.Io.File.StatError || std.Io.File.ReadPositionalError ||
    error{ InvalidEvidenceFile, MissingArtifact, EvidenceChangedDuringHash };

pub const Artifact = struct { path: []const u8, sha256: []const u8 };

// Full numeric DWARF ledgers exceed 16 MiB; compiled binaries use streaming hashes.
pub fn readFile(gpa: Allocator, io: std.Io, path: []const u8) ReadFileError![]const u8 {
    return Dir.cwd().readFileAlloc(io, path, gpa, .limited(64 * 1024 * 1024));
}

pub fn hashBytes(gpa: Allocator, bytes: []const u8) Allocator.Error![]const u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    return gpa.dupe(u8, &std.fmt.bytesToHex(digest, .lower));
}

pub fn artifact(gpa: Allocator, io: std.Io, path: []const u8) HashFileError!Artifact {
    return .{ .path = path, .sha256 = try hashFile(gpa, io, path, true) };
}

pub fn hashFile(gpa: Allocator, io: std.Io, path: []const u8, nonempty: bool) HashFileError![]const u8 {
    const file = try Dir.cwd().openFile(io, path, .{});
    defer file.close(io);
    const before = try file.stat(io);
    if (before.kind != .file) return error.InvalidEvidenceFile;
    if (nonempty and before.size == 0) return error.MissingArtifact;
    var buffer: [64 * 1024]u8 = undefined;
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    var offset: u64 = 0;
    // The initial file size bounds both memory use and the number of reads.
    while (offset < before.size) {
        const remaining: usize = @intCast(@min(buffer.len, before.size - offset));
        const count = try file.readPositional(io, &.{buffer[0..remaining]}, offset);
        if (count == 0) return error.EvidenceChangedDuringHash;
        hasher.update(buffer[0..count]);
        offset += count;
    }
    const after = try file.stat(io);
    if (before.size != after.size or before.mtime.nanoseconds != after.mtime.nanoseconds or
        before.ctime.nanoseconds != after.ctime.nanoseconds)
        return error.EvidenceChangedDuringHash;
    var digest: [32]u8 = undefined;
    hasher.final(&digest);
    return gpa.dupe(u8, &std.fmt.bytesToHex(digest, .lower));
}

test "SHA256 bytes use canonical lower-case encoding" {
    const digest = try hashBytes(std.testing.allocator, "abc");
    defer std.testing.allocator.free(digest);
    try std.testing.expectEqualStrings(
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        digest,
    );
}
