const std = @import("std");
const Dir = std.Io.Dir;
const gate_scratch = @import("gate_scratch.zig");

test "test scratch rejects missing and relative roots before filesystem writes" {
    const t = std.testing;
    var environment: std.process.Environ.Map = .init(t.allocator);
    defer environment.deinit();
    try t.expectError(error.MissingScratch, createTmpDir(t.allocator, t.io, &environment, .{}));
    try environment.put("HOST_SCRATCH_ROOT", ".zig-cache/tmp");
    try t.expectError(error.UnapprovedScratch, createTmpDir(t.allocator, t.io, &environment, .{}));
}

test "test scratch writes externally without changing fixture cwd and removes its own child" {
    const t = std.testing;
    const cwd_before = try std.process.currentPathAlloc(t.io, t.allocator);
    defer t.allocator.free(cwd_before);
    var temporary = try tmpDir(.{});
    var cleaned = false;
    defer if (!cleaned) temporary.cleanup();
    const path = try t.allocator.dupe(u8, temporary.path);
    defer t.allocator.free(path);
    var environment = try t.environ.createMap(t.allocator);
    defer environment.deinit();
    const scratch = try gate_scratch.validatedScratch(t.allocator, t.io, &environment, path);
    defer t.allocator.free(scratch);
    try t.expect(std.mem.startsWith(u8, path, scratch));
    try t.expectEqual(@as(u8, '/'), path[scratch.len]);
    const file = try temporary.dir.createFile(t.io, "payload", .{ .exclusive = true });
    try file.writeStreamingAll(t.io, "external test data");
    file.close(t.io);
    const bytes = try temporary.dir.readFileAlloc(t.io, "payload", t.allocator, .limited(100));
    defer t.allocator.free(bytes);
    try t.expectEqualStrings("external test data", bytes);
    const cwd_after = try std.process.currentPathAlloc(t.io, t.allocator);
    defer t.allocator.free(cwd_after);
    try t.expectEqualStrings(cwd_before, cwd_after);
    temporary.cleanup();
    cleaned = true;
    try t.expectError(error.FileNotFound, Dir.cwd().statFile(t.io, path, .{}));
}
