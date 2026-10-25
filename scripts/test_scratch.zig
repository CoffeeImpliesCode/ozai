const std = @import("std");
const builtin = @import("builtin");
const Dir = std.Io.Dir;
const gate_scratch = @import("gate_scratch.zig");
pub const CreateError = std.process.Environ.CreateMapError ||
    gate_scratch.ValidateError || std.mem.Allocator.Error || Dir.OpenError ||
    Dir.CreateDirError || Dir.RealPathError || std.Io.File.StatError || std.Io.RandomSecureError ||
    error{ NoSpaceLeft, SharedScratchParent, UnapprovedScratch };
const CreateTmpDirError = gate_scratch.ValidateError || Dir.OpenError ||
    Dir.CreateDirError || Dir.RealPathError || std.Io.File.StatError || std.Io.RandomSecureError ||
    error{ NoSpaceLeft, SharedScratchParent };
const ParentValidationError = Dir.OpenError || std.Io.File.StatError ||
    error{ SharedScratchParent, UnapprovedScratch };
const CleanupError = gate_scratch.ValidateError || ParentValidationError ||
    Dir.RealPathError || Dir.StatFileError || std.process.RunError ||
    Dir.DeleteTreeError || error{ NoSpaceLeft, ScratchIdentityChanged, UnprovenScratchCleanup };

// Only inspect the owned tree and this test process, never unrelated users' PIDs.
// A mounted descendant, foreign entry, symlink, hard link, open descriptor or
// mapping invalidates the private-tree deletion proof.
const cleanup_script =
    \\set -euo pipefail
    \\die() { printf '%s\n' "$1" >&2; exit 1; }
    \\target=$1
    \\pid=$2
    \\uid=$(id -u)
    \\[ "$(stat -c '%a' -- "$target")" = 700 ] || die 'scratch child is no longer private'
    \\bad=$(find -P "$target" -xdev \
    \\    \( ! -uid "$uid" -o ! \( -type d -o -type f \) -o -type f -links +1 \) -print -quit)
    \\[ -z "$bad" ] || die 'foreign-owned, linked or special entry in scratch child'
    \\find -P "$target" -xdev -print0 | (
    \\    remaining=1048576
    \\    while IFS= read -r -d '' candidate; do
    \\        [ "$remaining" -gt 0 ] || die 'scratch entry bound exceeded'
    \\        remaining=$((remaining - 1))
    \\        if mountpoint -q -- "$candidate"; then
    \\            die 'mounted descendant in scratch child'
    \\        else
    \\            status=$?
    \\            [ "$status" = 32 ] || die 'mountpoint inspection failed'
    \\        fi
    \\    done
    \\)
    \\[ -d "/proc/$pid/fd" ] && [ -r "/proc/$pid/fd" ] && [ -x "/proc/$pid/fd" ] &&
    \\    [ -r "/proc/$pid/maps" ] ||
    \\    die 'own process live-use proof unavailable'
    \\remaining=65536
    \\for entry in "/proc/$pid"/fd/* "/proc/$pid/cwd" "/proc/$pid/root" "/proc/$pid/exe"; do
    \\    [ "$remaining" -gt 0 ] || die 'own process descriptor bound exceeded'
    \\    remaining=$((remaining - 1))
    \\    [ -e "$entry" ] || [ -L "$entry" ] || continue
    \\    physical=$(readlink -- "$entry") || die 'own process descriptor cannot be inspected'
    \\    case "$physical" in
    \\        "$target"|"$target"/*) die 'scratch child still has a live descriptor';;
    \\    esac
    \\done
    \\remaining=1048576
    \\while IFS= read -r line; do
    \\    [ "$remaining" -gt 0 ] || die 'own process mapping bound exceeded'
    \\    remaining=$((remaining - 1))
    \\    case "$line" in *"$target"/*) die 'scratch child still has a live mapping';; esac
    \\done < "/proc/$pid/maps"
;

pub const TmpDir = struct {
    dir: Dir,
    path: []const u8,
    backing: union(enum) {
        standard: std.testing.TmpDir,
        external: External,
    },
    gpa: std.mem.Allocator,
    io: std.Io,
    environment: std.process.Environ.Map,

    const External = struct {
        parent_dir: Dir,
        sub_path: [42]u8,
        inode: std.Io.File.INode,
    };

    /// Default scratch uses std.testing cleanup. For an explicit root, the
    /// exclusively created 0700 child is private to this test. Callers must
    /// close all child handles and join/stop any child process before cleanup;
    /// they must not publish this path to unrelated processes. Cleanup closes
    /// its own child handle, revalidates the approved mount and inode, and checks
    /// tree ownership, symlinks, mounts and this process's remaining live uses.
    /// If any proof/check fails, retain the tree and print its path and reason.
    /// No global PID scan, signals, CWD changes or unverified deletion occur.
    pub fn cleanup(self: *TmpDir) void {
        defer self.gpa.free(self.path);
        defer self.environment.deinit();
        switch (self.backing) {
            .standard => |*temporary| temporary.cleanup(),
            .external => |*external| {
                self.dir.close(self.io);
                defer external.parent_dir.close(self.io);
                self.removeOwnedChild(external) catch |err| {
                    std.debug.print("retained test scratch {s}: {s}\n", .{ self.path, @errorName(err) });
                };
            },
        }
    }

    fn removeOwnedChild(self: *TmpDir, external: *const External) CleanupError!void {
        try validatePrivateParent(self.io, external.parent_dir);
        try gate_scratch.validateRoot(self.gpa, self.io, &self.environment, self.path);
        var parent_buffer: [Dir.max_path_bytes]u8 = undefined;
        const parent_path = parent_buffer[0..try external.parent_dir.realPath(self.io, &parent_buffer)];
        const expected_parent = std.fs.path.dirname(self.path) orelse
            return error.ScratchIdentityChanged;
        if (!std.mem.eql(u8, expected_parent, parent_path)) return error.ScratchIdentityChanged;
        const metadata = try external.parent_dir.statFile(self.io, &external.sub_path, .{
            .follow_symlinks = false,
        });
        if (metadata.kind != .directory or metadata.inode != external.inode)
            return error.ScratchIdentityChanged;
        const process_id = switch (builtin.os.tag) {
            .linux => std.os.linux.getpid(),
            else => return error.UnprovenScratchCleanup,
        };
        var pid_buffer: [32]u8 = undefined;
        const pid = try std.fmt.bufPrint(&pid_buffer, "{d}", .{process_id});
        const checked = try std.process.run(self.gpa, self.io, .{
            .argv = &.{ "bash", "-c", cleanup_script, "test-scratch-cleanup", self.path, pid },
            .environ_map = &self.environment,
            .expand_arg0 = .expand,
        });
        defer self.gpa.free(checked.stdout);
        defer self.gpa.free(checked.stderr);
        switch (checked.term) {
            .exited => |code| if (code != 0) {
                std.debug.print("test scratch cleanup proof failed: {s}\n", .{checked.stderr});
                return error.UnprovenScratchCleanup;
            },
            else => return error.UnprovenScratchCleanup,
        }
        try external.parent_dir.deleteTree(self.io, &external.sub_path);
    }
};

/// Use standard test scratch by default; validate an explicit GATE_SCRATCH strictly.
pub fn tmpDir(opts: Dir.OpenOptions) CreateError!TmpDir {
    const t = std.testing;
    var environment = try t.environ.createMap(t.allocator);
    errdefer environment.deinit();
    return tmpDirFromEnvironment(t.allocator, t.io, &environment, opts);
}

fn tmpDirFromEnvironment(
    gpa: std.mem.Allocator,
    io: std.Io,
    environment: *const std.process.Environ.Map,
    opts: Dir.OpenOptions,
) CreateTmpDirError!TmpDir {
    if (environment.get("GATE_SCRATCH") == null) {
        var temporary = std.testing.tmpDir(opts);
        errdefer temporary.cleanup();
        var buffer: [Dir.max_path_bytes]u8 = undefined;
        const path = try gpa.dupe(u8, buffer[0..try temporary.dir.realPath(io, &buffer)]);
        return .{
            .dir = temporary.dir,
            .backing = .{ .standard = temporary },
            .path = path,
            .gpa = gpa,
            .io = io,
            .environment = environment.*,
        };
    }
    return createTmpDir(gpa, io, environment, opts);
}

// On success the result takes ownership of the environment; on error the caller keeps it.
fn createTmpDir(
    gpa: std.mem.Allocator,
    io: std.Io,
    environment: *const std.process.Environ.Map,
    opts: Dir.OpenOptions,
) CreateTmpDirError!TmpDir {
    const scratch = try gate_scratch.validatedScratch(gpa, io, environment, "");
    defer gpa.free(scratch);
    const parent = try Dir.openDirAbsolute(io, scratch, .{ .follow_symlinks = false });
    errdefer parent.close(io);
    try validatePrivateParent(io, parent);
    var random: [16]u8 = undefined;
    try io.randomSecure(&random);
    var sub_path: [42]u8 = undefined;
    const name = try std.fmt.bufPrint(&sub_path, "ozai-test-{s}", .{
        std.fmt.bytesToHex(random, .lower),
    });
    std.debug.assert(name.len == sub_path.len);
    const path = try std.fs.path.join(gpa, &.{ scratch, name });
    errdefer gpa.free(path);
    // Exclusive creation, never createDirPathOpen (which accepts existing trees).
    try parent.createDir(io, name, .fromMode(0o700));
    errdefer std.debug.print("retained test scratch {s}: initialization failed\n", .{path});
    try gate_scratch.validateRoot(gpa, io, environment, path);
    var open_options = opts;
    open_options.follow_symlinks = false;
    const dir = try parent.openDir(io, name, open_options);
    errdefer dir.close(io);
    const metadata = try dir.stat(io);
    return .{
        .dir = dir,
        .backing = .{ .external = .{
            .parent_dir = parent,
            .sub_path = sub_path,
            .inode = metadata.inode,
        } },
        .path = path,
        .gpa = gpa,
        .io = io,
        .environment = environment.*,
    };
}

// A private child is not exclusive if another UID can rename its ancestors.
fn validatePrivateParent(io: std.Io, parent: Dir) ParentValidationError!void {
    const root = try parent.openDir(io, "..", .{ .follow_symlinks = false });
    defer root.close(io);
    const base = try root.openDir(io, "..", .{ .follow_symlinks = false });
    defer base.close(io);
    const scratch_metadata = try parent.stat(io);
    const root_metadata = try root.stat(io);
    const base_metadata = try base.stat(io);
    switch (builtin.os.tag) {
        .linux => {
            if (scratch_metadata.permissions.toMode() & 0o022 != 0 or
                root_metadata.permissions.toMode() & 0o022 != 0)
                return error.SharedScratchParent;
            const base_mode = base_metadata.permissions.toMode();
            if (base_mode & 0o022 != 0 and base_mode & 0o1000 == 0)
                return error.SharedScratchParent;
        },
        else => return error.UnapprovedScratch,
    }
}

test "test scratch rejects missing and relative roots before filesystem writes" {
    const t = std.testing;
    var environment: std.process.Environ.Map = .init(t.allocator);
    defer environment.deinit();
    try t.expectError(error.MissingScratch, createTmpDir(t.allocator, t.io, &environment, .{}));
    try environment.put("GATE_SCRATCH", ".zig-cache/tmp");
    try t.expectError(error.UnapprovedScratch, tmpDirFromEnvironment(t.allocator, t.io, &environment, .{}));
}

test "test scratch uses a standard temporary directory when unset" {
    const t = std.testing;
    var environment: std.process.Environ.Map = .init(t.allocator);
    var temporary = tmpDirFromEnvironment(t.allocator, t.io, &environment, .{}) catch |err| {
        environment.deinit();
        return err;
    };
    defer temporary.cleanup();
    const file = try temporary.dir.createFile(t.io, "payload", .{ .exclusive = true });
    defer file.close(t.io);
    try file.writeStreamingAll(t.io, "default test scratch");
    const bytes = try temporary.dir.readFileAlloc(t.io, "payload", t.allocator, .limited(100));
    defer t.allocator.free(bytes);
    try t.expectEqualStrings("default test scratch", bytes);
}

test "test scratch writes without changing fixture cwd and removes its own child" {
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
    if (environment.get("GATE_SCRATCH") != null) {
        const scratch = try gate_scratch.validatedScratch(t.allocator, t.io, &environment, path);
        defer t.allocator.free(scratch);
        try t.expect(std.mem.startsWith(u8, path, scratch));
        try t.expectEqual(@as(u8, '/'), path[scratch.len]);
    }
    {
        const file = try temporary.dir.createFile(t.io, "payload", .{ .exclusive = true });
        defer file.close(t.io);
        try file.writeStreamingAll(t.io, "external test data");
    }
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
