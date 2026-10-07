const std = @import("std");
const process = @import("nat_process.zig");

pub const Evidence = struct {
    directory: std.Io.Dir,

    pub fn open(io: std.Io, path: []const u8) !Evidence {
        const prefix = "/tmp/scratch/";
        if (!std.mem.startsWith(u8, path, prefix)) return error.UnsafeEvidencePath;
        var canonical: [4096]u8 = undefined;
        const length = try std.Io.Dir.realPathFileAbsolute(io, path, &canonical);
        if (!std.mem.eql(u8, canonical[0..length], path)) return error.UnsafeEvidencePath;
        const directory = try std.Io.Dir.openDirAbsolute(io, path,
            .{ .follow_symlinks = false });
        errdefer directory.close(io);
        try process.assertOwnedDir(directory);
        return .{ .directory = directory };
    }

    pub fn close(self: *Evidence, io: std.Io) void {
        self.directory.close(io);
    }

    // Exclusive creation preserves prior runs and all user files, including on failure.
    pub fn save(self: *Evidence, io: std.Io, name: []const u8, bytes: []const u8) !void {
        if (name.len == 0 or std.mem.indexOfScalar(u8, name, '/') != null)
            return error.InvalidEvidenceName;
        try process.assertOwnedDir(self.directory);
        const file = try self.directory.createFile(io, name,
            .{ .exclusive = true, .truncate = false, .permissions = .fromMode(0o600) });
        defer file.close(io);
        try file.writeStreamingAll(io, bytes);
    }
};
