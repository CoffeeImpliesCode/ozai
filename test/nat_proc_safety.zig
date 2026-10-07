//! Proc identity and private namespace mutation guards for the NAT fixture.
const std = @import("std");
const c = std.c;
pub const Error = error{
    InvalidProc, ProcOverflow, ProcUnavailable, OwnershipMismatch, UnsafeNamespace,
    InvalidCommand, CommandOverflow,
};

/// Borrowed identities captured by the caller before entering private namespaces.
pub const Baseline = struct {
    net: []const u8,
    user: []const u8,
};

/// Reject noncanonical or missing baseline identities without accessing proc.
pub fn validateBaseline(baseline: Baseline) Error!void {
    try validateNamespaceIdentity(baseline.net, .net);
    try validateNamespaceIdentity(baseline.user, .user);
}

fn validateNamespaceIdentity(identity: []const u8, kind: Namespace) Error!void {
    const prefix = switch (kind) {
        .net => "net:[",
        .user => "user:[",
    };
    if (identity.len <= prefix.len + 1 or identity.len > prefix.len + 21)
        return error.UnsafeNamespace;
    if (!std.mem.startsWith(u8, identity, prefix) or identity[identity.len - 1] != ']')
        return error.UnsafeNamespace;
    const digits = identity[prefix.len .. identity.len - 1];
    if (digits[0] < '1' or digits[0] > '9') return error.UnsafeNamespace;
    for (digits) |digit| {
        if (digit < '0' or digit > '9') return error.UnsafeNamespace;
    }
    _ = std.fmt.parseInt(u64, digits, 10) catch return error.UnsafeNamespace;
}

fn checkNamespaceSeparation(baseline: Baseline, own: Baseline) Error!void {
    try validateBaseline(baseline);
    try validateBaseline(own);
    if (std.mem.eql(u8, own.net, baseline.net)) return error.UnsafeNamespace;
    if (std.mem.eql(u8, own.user, baseline.user)) return error.UnsafeNamespace;
}

test "namespace baselines require canonical nonzero bounded decimal identities" {
    try validateBaseline(.{ .net = "net:[1]", .user = "user:[18446744073709551615]" });
    const malformed = [_][]const u8{
        "", "net:[]", "net:[0]", "net:[01]", "net:[+1]", "net:[-1]",
        "net:[ 1]", "net:[1 ]", "net:[1]\n", "net:[1]junk", "user:[1]",
        "net:[18446744073709551616]", "net:[100000000000000000000]",
    };
    for (malformed) |net| {
        try std.testing.expectError(error.UnsafeNamespace,
            validateBaseline(.{ .net = net, .user = "user:[2]" }));
    }
    for ([_][]const u8{ "", "user:[0]", "user:[01]", "user:[+2]", "net:[2]" }) |user| {
        try std.testing.expectError(error.UnsafeNamespace,
            validateBaseline(.{ .net = "net:[1]", .user = user }));
    }
}

test "private namespaces must both differ from the explicit outside baseline" {
    const baseline: Baseline = .{ .net = "net:[1]", .user = "user:[2]" };
    try checkNamespaceSeparation(baseline, .{ .net = "net:[3]", .user = "user:[4]" });
    try std.testing.expectError(error.UnsafeNamespace,
        checkNamespaceSeparation(baseline, .{ .net = "net:[1]", .user = "user:[4]" }));
    try std.testing.expectError(error.UnsafeNamespace,
        checkNamespaceSeparation(baseline, .{ .net = "net:[3]", .user = "user:[2]" }));
    try std.testing.expectError(error.UnsafeNamespace, checkNamespaceSeparation(baseline, baseline));
    try std.testing.expectError(error.UnsafeNamespace,
        checkNamespaceSeparation(baseline, .{ .net = "net:[03]", .user = "user:[4]" }));
}

test "uid map permits only root mapped to one specified caller" {
    try checkUidMap("         0       1000          1\n", 1000);
    try std.testing.expectError(error.UnsafeNamespace, checkUidMap("0 0 1\n", 0));
    try std.testing.expectError(error.UnsafeNamespace, checkUidMap("0 1001 1\n", 1000));
    try std.testing.expectError(error.UnsafeNamespace, checkUidMap("0 1000 2\n", 1000));
    try std.testing.expectError(error.UnsafeNamespace, checkUidMap("0 1000 1\n1 1001 1\n", 1000));
}

test "uid mapping rejects a split row and signed mapping fields" {
    try std.testing.expectError(error.UnsafeNamespace, checkUidMap("0\n1000 1\n", 1000));
    try std.testing.expectError(error.UnsafeNamespace, checkUidMap("+0 1000 1\n", 1000));
    try std.testing.expectError(error.UnsafeNamespace, checkUidMap("0 +1000 1\n", 1000));
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
    const row = std.mem.trim(u8, map, " \t\r\n");
    if (std.mem.indexOfAny(u8, row, "\r\n") != null) return error.UnsafeNamespace;
    var fields = std.mem.tokenizeAny(u8, row, " \t");
    const expected = [_]u32{ 0, caller_uid, 1 };
    for (expected) |value| {
        const field = fields.next() orelse return error.UnsafeNamespace;
        for (field) |digit| {
            if (digit < '0' or digit > '9') return error.UnsafeNamespace;
        }
        const parsed = std.fmt.parseInt(u32, field, 10) catch return error.UnsafeNamespace;
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

pub fn assertPrivate(io: std.Io, baseline: Baseline) Error!void {
    try validateBaseline(baseline);
    if (c.getuid() != 0 or c.geteuid() != 0) return error.UnsafeNamespace;
    var map_buffer: [256]u8 = undefined;
    const map = try procRead(c.getpid(), "uid_map", &map_buffer);
    var fields = std.mem.tokenizeAny(u8, map, " \t\r\n");
    _ = fields.next() orelse return error.UnsafeNamespace;
    const outside = std.fmt.parseInt(u32, fields.next() orelse
        return error.UnsafeNamespace, 10) catch return error.UnsafeNamespace;
    try checkUidMap(map, outside);
    // Read only our identities: a rootless user namespace cannot inspect its parent.
    const own_pid = c.getpid();
    var net_buffer: [128]u8 = undefined;
    var user_buffer: [128]u8 = undefined;
    const own: Baseline = .{
        .net = try namespaceIdentity(io, own_pid, .net, &net_buffer),
        .user = try namespaceIdentity(io, own_pid, .user, &user_buffer),
    };
    try checkNamespaceSeparation(baseline, own);
}

pub fn setPrivateForwarding(
    io: std.Io,
    baseline: Baseline,
    expected_netns: []const u8,
) Error!void {
    try assertPrivate(io, baseline);
    try validateNamespaceIdentity(expected_netns, .net);
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
