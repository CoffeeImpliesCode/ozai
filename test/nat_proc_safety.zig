//! Proc identity and private namespace mutation guards for the NAT fixture.
const std = @import("std");
const c = std.c;
pub const Error = error{
    InvalidProc,
    ProcOverflow,
    ProcUnavailable,
    OwnershipMismatch,
    UnsafeNamespace,
    InvalidCommand,
    CommandOverflow,
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
    // zbc cannot carry the earlier length guard through prefix selection.
    // zbc-disable-next-line: index-minus-one-without-zero-guard
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
        "",
        "net:[]",
        "net:[0]",
        "net:[01]",
        "net:[+1]",
        "net:[-1]",
        "net:[ 1]",
        "net:[1 ]",
        "net:[1]\n",
        "net:[1]junk",
        "user:[1]",
        "net:[18446744073709551616]",
        "net:[100000000000000000000]",
    };
    for (malformed) |net| {
        try std.testing.expectError(
            error.UnsafeNamespace,
            validateBaseline(.{ .net = net, .user = "user:[2]" }),
        );
    }
    for ([_][]const u8{ "", "user:[0]", "user:[01]", "user:[+2]", "net:[2]" }) |user| {
        try std.testing.expectError(
            error.UnsafeNamespace,
            validateBaseline(.{ .net = "net:[1]", .user = user }),
        );
    }
}

test "private namespaces must both differ from the explicit outside baseline" {
    const baseline: Baseline = .{ .net = "net:[1]", .user = "user:[2]" };
    try checkNamespaceSeparation(baseline, .{ .net = "net:[3]", .user = "user:[4]" });
    try std.testing.expectError(
        error.UnsafeNamespace,
        checkNamespaceSeparation(baseline, .{ .net = "net:[1]", .user = "user:[4]" }),
    );
    try std.testing.expectError(
        error.UnsafeNamespace,
        checkNamespaceSeparation(baseline, .{ .net = "net:[3]", .user = "user:[2]" }),
    );
    try std.testing.expectError(
        error.UnsafeNamespace,
        checkNamespaceSeparation(baseline, baseline),
    );
    try std.testing.expectError(
        error.UnsafeNamespace,
        checkNamespaceSeparation(baseline, .{ .net = "net:[03]", .user = "user:[4]" }),
    );
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
    const field = statusField(status, name) orelse return error.InvalidProc;
    return std.fmt.parseInt(u32, field, 10) catch return error.InvalidProc;
}

pub fn checkStatus(status: []const u8, uid: u32, parent: c.pid_t) Error!void {
    if (try statusNumber(status, "PPid:") != parent) return error.OwnershipMismatch;
    var fields = std.mem.tokenizeAny(u8, statusField(status, "Uid:") orelse
        return error.InvalidProc, " \t");
    for (0..4) |_| {
        const field = fields.next() orelse return error.InvalidProc;
        const value = std.fmt.parseInt(u32, field, 10) catch return error.InvalidProc;
        if (value != uid) return error.OwnershipMismatch;
    }
    if (fields.next() != null) return error.InvalidProc;
}

pub fn excludeAncestors(io: std.Io, pid: c.pid_t) Error!void {
    if (pid <= 1) return error.OwnershipMismatch;
    var ancestor = c.getpid();
    for (0..128) |_| {
        if (ancestor == pid) return error.OwnershipMismatch;
        if (ancestor <= 1) return;
        var buffer: [4096]u8 = undefined;
        ancestor = @intCast(try statusNumber(try procRead(io, ancestor, "status", &buffer), "PPid:"));
    }
    return error.OwnershipMismatch;
}

pub fn procRead(io: std.Io, pid: c.pid_t, leaf: []const u8, buffer: []u8) Error![]const u8 {
    var path_buffer: [128]u8 = undefined;
    const path = std.fmt.bufPrintSentinel(
        &path_buffer,
        "/proc/{d}/{s}",
        .{ pid, leaf },
        0,
    ) catch return error.InvalidProc;
    return readPath(io, path, buffer);
}

fn readPath(io: std.Io, path: []const u8, buffer: []u8) Error![]const u8 {
    const file = std.Io.Dir.openFileAbsolute(io, path, .{}) catch return error.ProcUnavailable;
    defer file.close(io);
    var offset: usize = 0;
    for (0..32) |_| {
        var probe: [1]u8 = undefined;
        const target = if (offset < buffer.len) buffer[offset..] else &probe;
        const count = file.readStreaming(io, &.{target}) catch |err| switch (err) {
            error.EndOfStream => return buffer[0..offset],
            else => return error.ProcUnavailable,
        };
        if (count == 0) continue;
        if (offset == buffer.len) return error.ProcOverflow;
        offset += count;
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
    var buffer: [256]u8 = undefined;
    try checkUidMap(try procRead(io, pid, "uid_map", &buffer), caller_uid);
}

pub const Namespace = enum { user, net };

pub fn namespaceIdentity(
    io: std.Io,
    pid: c.pid_t,
    kind: Namespace,
    buffer: *[128]u8,
) Error![]const u8 {
    var path_buffer: [128]u8 = undefined;
    const path = std.fmt.bufPrintSentinel(
        &path_buffer,
        "/proc/{d}/ns/{s}",
        .{ pid, @tagName(kind) },
        0,
    ) catch return error.InvalidProc;
    const count = std.Io.Dir.readLinkAbsolute(io, path, buffer) catch
        return error.ProcUnavailable;
    if (count == 0 or count >= buffer.len) return error.ProcUnavailable;
    return buffer[0..count];
}

pub fn assertPrivate(io: std.Io, baseline: Baseline) Error!void {
    try validateBaseline(baseline);
    if (c.getuid() != 0 or c.geteuid() != 0) return error.UnsafeNamespace;
    var map_buffer: [256]u8 = undefined;
    const map = try procRead(io, c.getpid(), "uid_map", &map_buffer);
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
    const value = try readPath(io, path, &value_buffer);
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
    const path = std.fmt.bufPrintSentinel(&path_buffer, "/proc/{d}", .{pid}, 0) catch
        return error.InvalidProc;
    var info: std.os.linux.Statx = undefined;
    const requested: std.os.linux.STATX = .{ .TYPE = true, .UID = true };
    if (statx(
        std.os.linux.AT.FDCWD,
        path,
        std.os.linux.AT.SYMLINK_NOFOLLOW,
        @bitCast(requested),
        &info,
    ) != 0) return error.ProcUnavailable;
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

// Borrow the runner's backend, replacing only proc reads; no global proc stub or mutation.
const ProcReadTripwire = struct {
    fail_open: bool,
    opens: usize = 0,
    reads: usize = 0,
    links: usize = 0,
    closes: usize = 0,
    content: ?[]const u8 = null,
    content_offset: usize = 0,
    empty_reads: usize = 0,

    fn context(userdata: ?*anyopaque) *ProcReadTripwire {
        return @ptrCast(@alignCast(userdata.?));
    }

    fn open(
        userdata: ?*anyopaque,
        _: std.Io.Dir,
        path: []const u8,
        _: std.Io.Dir.OpenFileOptions,
    ) std.Io.File.OpenError!std.Io.File {
        const self = context(userdata);
        std.debug.assert(std.mem.startsWith(u8, path, "/proc/"));
        self.opens += 1;
        if (self.fail_open) return error.AccessDenied;
        return .{ .handle = -1, .flags = .{ .nonblocking = false } };
    }

    fn read(
        userdata: ?*anyopaque,
        _: std.Io.File,
        _: []const []u8,
        _: u64,
    ) std.Io.File.ReadPositionalError!usize {
        context(userdata).reads += 1;
        return error.InputOutput;
    }

    fn operate(
        userdata: ?*anyopaque,
        operation: std.Io.Operation,
    ) std.Io.Cancelable!std.Io.Operation.Result {
        std.debug.assert(operation == .file_read_streaming);
        const self = context(userdata);
        self.reads += 1;
        const content = self.content orelse
            return .{ .file_read_streaming = error.InputOutput };
        if (self.empty_reads != 0) {
            self.empty_reads -= 1;
            return .{ .file_read_streaming = 0 };
        }
        if (self.content_offset == content.len)
            return .{ .file_read_streaming = error.EndOfStream };
        const read_operation = operation.file_read_streaming;
        std.debug.assert(read_operation.data.len == 1);
        const target = read_operation.data[0];
        const count = @min(target.len, content.len - self.content_offset);
        @memcpy(target[0..count], content[self.content_offset..][0..count]);
        self.content_offset += count;
        return .{ .file_read_streaming = count };
    }

    fn close(userdata: ?*anyopaque, files: []const std.Io.File) void {
        context(userdata).closes += files.len;
        for (files) |file| std.debug.assert(file.handle == -1);
    }

    fn readLink(
        userdata: ?*anyopaque,
        _: std.Io.Dir,
        path: []const u8,
        _: []u8,
    ) std.Io.Dir.ReadLinkError!usize {
        std.debug.assert(std.mem.startsWith(u8, path, "/proc/"));
        context(userdata).links += 1;
        return error.AccessDenied;
    }

    fn io(self: *ProcReadTripwire, vtable: *std.Io.VTable) std.Io {
        vtable.* = std.testing.io.vtable.*;
        vtable.dirOpenFile = open;
        vtable.fileReadPositional = read;
        vtable.operate = operate;
        vtable.fileClose = close;
        vtable.dirReadLink = readLink;
        return .{ .userdata = self, .vtable = vtable };
    }
};

test "proc uid mapping open and read failures obey supplied Io" {
    for ([_]bool{ true, false }) |fail_open| {
        var tripwire: ProcReadTripwire = .{ .fail_open = fail_open };
        var vtable: std.Io.VTable = undefined;
        const io = tripwire.io(&vtable);
        // Reading our own uid_map is harmless even on the broken backend bypass.
        try std.testing.expectError(
            error.ProcUnavailable,
            verifyUidMapping(io, c.getpid(), 1000),
        );
        try std.testing.expectEqual(@as(usize, 1), tripwire.opens);
        try std.testing.expectEqual(@as(usize, if (fail_open) 0 else 1), tripwire.reads);
        try std.testing.expectEqual(@as(usize, if (fail_open) 0 else 1), tripwire.closes);
    }
}

test "proc namespace identity failure obeys supplied Io" {
    var tripwire: ProcReadTripwire = .{ .fail_open = true };
    var vtable: std.Io.VTable = undefined;
    const io = tripwire.io(&vtable);
    var buffer: [128]u8 = undefined;
    try std.testing.expectError(
        error.ProcUnavailable,
        namespaceIdentity(io, c.getpid(), .net, &buffer),
    );
    try std.testing.expectEqual(@as(usize, 1), tripwire.links);
}

test "proc uid mapping survives no progress and accepts streaming EOF after the row" {
    var tripwire: ProcReadTripwire = .{
        .fail_open = false,
        .content = "0 1000 1\n",
        .empty_reads = 1,
    };
    var vtable: std.Io.VTable = undefined;
    try verifyUidMapping(tripwire.io(&vtable), 42, 1000);
    try std.testing.expectEqual(@as(usize, 1), tripwire.opens);
    try std.testing.expectEqual(@as(usize, 3), tripwire.reads);
    try std.testing.expectEqual(@as(usize, 1), tripwire.closes);
}

test "proc read probes past a full buffer without accepting truncation" {
    for ([_][]const u8{ "1234", "12345" }) |content| {
        var tripwire: ProcReadTripwire = .{ .fail_open = false, .content = content };
        var vtable: std.Io.VTable = undefined;
        var buffer: [4]u8 = undefined;
        const result = procRead(tripwire.io(&vtable), 42, "status", &buffer);
        if (content.len == buffer.len) {
            try std.testing.expectEqualStrings(content, try result);
        } else {
            try std.testing.expectError(error.ProcOverflow, result);
        }
        try std.testing.expectEqual(@as(usize, 2), tripwire.reads);
        try std.testing.expectEqual(@as(usize, 1), tripwire.closes);
    }
}
