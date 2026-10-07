//! Proc identity and private namespace mutation guards for the NAT fixture.
const std = @import("std");
const c = std.c;
pub const Error = error{
    InvalidProc, ProcOverflow, ProcUnavailable, OwnershipMismatch, UnsafeNamespace,
    InvalidCommand, CommandOverflow,
};

test "uid map permits only root mapped to one specified caller" {
    try checkUidMap("         0       1000          1\n", 1000);
    try std.testing.expectError(error.UnsafeNamespace, checkUidMap("0 0 1\n", 0));
    try std.testing.expectError(error.UnsafeNamespace, checkUidMap("0 1001 1\n", 1000));
    try std.testing.expectError(error.UnsafeNamespace, checkUidMap("0 1000 2\n", 1000));
    try std.testing.expectError(error.UnsafeNamespace, checkUidMap("0 1000 1\n1 1001 1\n", 1000));
}

test "proc status requires four caller uids and direct child parent" {
    const status = "Name:\tkeeper\nState:\tS (sleeping)\nPPid:\t42\nUid:\t1000\t1000\t1000\t1000\n";
    try checkStatus(status, 1000, 42);
    try std.testing.expectError(error.OwnershipMismatch, checkStatus(status, 1001, 42));
    try std.testing.expectError(error.OwnershipMismatch, checkStatus(status, 1000, 43));
    try std.testing.expectError(error.InvalidProc, statusNumber("PPid:\tbad\n", "PPid:"));
}

pub fn statusField(status: []const u8, name: []const u8) ?[]const u8 {
    var lines = std.mem.splitScalar(u8, status, '\n');
    while (lines.next()) |line| {
        if (std.mem.startsWith(u8, line, name))
            return std.mem.trim(u8, line[name.len..], " \t");
    }
    return null;
}

pub fn statusNumber(status: []const u8, name: []const u8) Error!u32 {
    return std.fmt.parseInt(u32, statusField(status, name) orelse return error.InvalidProc, 10)
        catch return error.InvalidProc;
}

pub fn checkStatus(status: []const u8, uid: u32, parent: c.pid_t) Error!void {
    if (try statusNumber(status, "PPid:") != parent) return error.OwnershipMismatch;
    var fields = std.mem.tokenizeAny(u8, statusField(status, "Uid:") orelse
        return error.InvalidProc, " \t");
    for (0..4) |_| {
        const value = std.fmt.parseInt(u32, fields.next() orelse return error.InvalidProc, 10)
            catch return error.InvalidProc;
        if (value != uid) return error.OwnershipMismatch;
    }
    if (fields.next() != null) return error.InvalidProc;
}

pub fn excludeAncestors(pid: c.pid_t) Error!void {
    if (pid <= 1) return error.OwnershipMismatch;
    var ancestor = c.getpid();
    for (0..128) |_| {
        if (ancestor == pid) return error.OwnershipMismatch;
        if (ancestor <= 1) return;
        var buffer: [4096]u8 = undefined;
        ancestor = @intCast(try statusNumber(try procRead(ancestor, "status", &buffer), "PPid:"));
    }
    return error.OwnershipMismatch;
}

pub fn procRead(pid: c.pid_t, leaf: []const u8, buffer: []u8) Error![]const u8 {
    var path_buffer: [128]u8 = undefined;
    const path = std.fmt.bufPrintZ(&path_buffer, "/proc/{d}/{s}", .{ pid, leaf })
        catch return error.InvalidProc;
    return readPath(path, buffer);
}

fn readPath(path: [:0]const u8, buffer: []u8) Error![]const u8 {
    const fd = c.open(path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true });
    if (fd < 0) return error.ProcUnavailable;
    defer std.debug.assert(c.close(fd) == 0);
    var offset: usize = 0;
    for (0..32) |_| {
        var probe: [1]u8 = undefined;
        const target = if (offset < buffer.len) buffer[offset..] else &probe;
        const count = c.read(fd, target.ptr, target.len);
        if (count == 0) return buffer[0..offset];
        if (count < 0) {
            if (c.errno(count) == .INTR) continue;
            return error.ProcUnavailable;
        }
        if (offset == buffer.len) return error.ProcOverflow;
        offset += @intCast(count);
    }
    return error.ProcOverflow;
}

fn checkUidMap(map: []const u8, caller_uid: u32) Error!void {
    if (caller_uid == 0) return error.UnsafeNamespace;
    var fields = std.mem.tokenizeAny(u8, map, " \t\r\n");
    const expected = [_]u32{ 0, caller_uid, 1 };
    for (expected) |value| {
        const parsed = std.fmt.parseInt(u32, fields.next() orelse
            return error.UnsafeNamespace, 10) catch return error.UnsafeNamespace;
        if (parsed != value) return error.UnsafeNamespace;
    }
    if (fields.next() != null) return error.UnsafeNamespace;
}

pub fn verifyUidMapping(io: std.Io, pid: c.pid_t, caller_uid: u32) Error!void {
    _ = io;
    var buffer: [256]u8 = undefined;
    try checkUidMap(try procRead(pid, "uid_map", &buffer), caller_uid);
}

pub const Namespace = enum { user, net };

pub fn namespaceIdentity(
    io: std.Io,
    pid: c.pid_t,
    kind: Namespace,
    buffer: *[128]u8,
) Error![]const u8 {
    _ = io;
    var path_buffer: [128]u8 = undefined;
    const path = std.fmt.bufPrintZ(&path_buffer, "/proc/{d}/ns/{s}", .{ pid, @tagName(kind) })
        catch return error.InvalidProc;
    const count = c.readlink(path.ptr, buffer, buffer.len);
    if (count <= 0 or count >= buffer.len) return error.ProcUnavailable;
    return buffer[0..@intCast(count)];
}

pub fn assertPrivate(io: std.Io) Error!void {
    if (c.getuid() != 0 or c.geteuid() != 0) return error.UnsafeNamespace;
    var map_buffer: [256]u8 = undefined;
    const map = try procRead(c.getpid(), "uid_map", &map_buffer);
    var fields = std.mem.tokenizeAny(u8, map, " \t\r\n");
    _ = fields.next() orelse return error.UnsafeNamespace;
    const outside = std.fmt.parseInt(u32, fields.next() orelse
        return error.UnsafeNamespace, 10) catch return error.UnsafeNamespace;
    try checkUidMap(map, outside);
    // The one-entry nonzero root map excludes the initial user namespace.
    // Parent is the caller-owned launcher/controller, not inaccessible host PID 1.
    const parent = c.getppid();
    if (parent <= 1) return error.UnsafeNamespace;
    try verifyProcOwner(parent, c.geteuid());
    var own_buffer: [128]u8 = undefined;
    var parent_buffer: [128]u8 = undefined;
    const own = try namespaceIdentity(io, c.getpid(), .net, &own_buffer);
    const original = try namespaceIdentity(io, parent, .net, &parent_buffer);
    if (std.mem.eql(u8, own, original)) return error.UnsafeNamespace;
}

pub fn setPrivateForwarding(io: std.Io, expected_netns: []const u8) Error!void {
    try assertPrivate(io);
    var own_buffer: [128]u8 = undefined;
    const own = try namespaceIdentity(io, c.getpid(), .net, &own_buffer);
    if (!std.mem.eql(u8, own, expected_netns)) return error.UnsafeNamespace;
    const path = "/proc/sys/net/ipv4/ip_forward";
    const fd = c.open(path, .{ .ACCMODE = .WRONLY, .CLOEXEC = true, .NOFOLLOW = true });
    if (fd < 0) return error.UnsafeNamespace;
    defer std.debug.assert(c.close(fd) == 0);
    if (c.write(fd, "1\n", 2) != 2) return error.UnsafeNamespace;
    var value_buffer: [16]u8 = undefined;
    const value = try readPath(path, &value_buffer);
    if (!std.mem.eql(u8, std.mem.trim(u8, value, " \t\r\n"), "1"))
        return error.UnsafeNamespace;
}

extern "c" fn statx(
    dirfd: c_int,
    path: [*:0]const u8,
    flags: c_int,
    mask: c_uint,
    result: *std.os.linux.Statx,
) c_int;

pub fn assertOwnedDir(dir: std.Io.Dir) Error!void {
    const linux = std.os.linux;
    var info: linux.Statx = undefined;
    const requested: linux.STATX = .{ .TYPE = true, .MODE = true, .UID = true };
    if (statx(dir.handle, "", linux.AT.EMPTY_PATH, @bitCast(requested), &info) != 0)
        return error.OwnershipMismatch;
    if (!info.mask.TYPE or !info.mask.UID) return error.OwnershipMismatch;
    if (info.uid != c.geteuid()) return error.OwnershipMismatch;
    if (info.mode & linux.S.IFMT != linux.S.IFDIR) return error.OwnershipMismatch;
}

pub fn verifyProcOwner(pid: c.pid_t, uid: u32) Error!void {
    var path_buffer: [64]u8 = undefined;
    const path = std.fmt.bufPrintZ(&path_buffer, "/proc/{d}", .{pid})
        catch return error.InvalidProc;
    var info: std.os.linux.Statx = undefined;
    const requested: std.os.linux.STATX = .{ .TYPE = true, .UID = true };
    if (statx(std.os.linux.AT.FDCWD, path, std.os.linux.AT.SYMLINK_NOFOLLOW,
        @bitCast(requested), &info) != 0) return error.ProcUnavailable;
    if (!info.mask.TYPE or !info.mask.UID) return error.OwnershipMismatch;
    if (info.uid != uid) return error.OwnershipMismatch;
    if (info.mode & std.os.linux.S.IFMT != std.os.linux.S.IFDIR)
        return error.OwnershipMismatch;
}
test "expected command preserves empty arguments and rejects embedded nul" {
    var bytes: [32]u8 = undefined;
    const command = try encodeCommand(&bytes, &.{ "keeper", "", "alice" });
    try std.testing.expectEqualSlices(u8, "keeper\x00\x00alice\x00", command);
    try std.testing.expectError(error.InvalidCommand, encodeCommand(&bytes, &.{"bad\x00arg"}));
    try std.testing.expectError(error.InvalidCommand, encodeCommand(&bytes, &.{}));
    try std.testing.expectError(error.CommandOverflow, encodeCommand(bytes[0..2], &.{"keeper"}));
}

pub fn encodeCommand(buffer: []u8, argv: []const []const u8) Error![]const u8 {
    if (argv.len == 0 or argv[0].len == 0) return error.InvalidCommand;
    var offset: usize = 0;
    for (argv) |arg| {
        if (std.mem.indexOfScalar(u8, arg, 0) != null) return error.InvalidCommand;
        if (arg.len >= buffer.len - offset) return error.CommandOverflow;
        @memcpy(buffer[offset..][0..arg.len], arg);
        offset += arg.len;
        buffer[offset] = 0;
        offset += 1;
    }
    return buffer[0..offset];
}
