//! Borrowed TCP operations. Providers outlive every owner and concurrent stop caller.
//! No Io or payload is retained. Only the native provider permits signal-handler stop.
const std = @import("std");
const addr = @import("../base/addr.zig");
const errors = @import("tcp_error.zig");
const sys = @import("tcp_sys.zig");
const socket_open = @import("socket_open.zig");
const socket_addr = @import("socket_addr.zig");

pub const Accepted = struct { handle: std.c.fd_t, peer: ?addr.SocketAddr };
pub const WaitOptions = struct {
    handle: std.c.fd_t,
    wake: std.c.fd_t,
    events: i16,
    timeout_ms: ?i32,
};

pub const Execution = struct {
    context: ?*anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        createStream: *const fn (std.Io, ?*anyopaque, addr.IpAddress) errors.OpenError!std.c.fd_t,
        createWake: *const fn (std.Io, ?*anyopaque) errors.OpenError!std.c.fd_t,
        bind: *const fn (std.Io, ?*anyopaque, std.c.fd_t, addr.SocketAddr) errors.OpenError!void,
        listen: *const fn (std.Io, ?*anyopaque, std.c.fd_t) errors.ListenError!void,
        boundAddress: *const fn (std.Io, ?*anyopaque, std.c.fd_t) errors.OpenError!addr.SocketAddr,
        accept: *const fn (std.Io, ?*anyopaque, std.c.fd_t) errors.AcceptError!?Accepted,
        startConnect: *const fn (std.Io, ?*anyopaque, std.c.fd_t, addr.SocketAddr) errors.ConnectError!bool,
        wait: *const fn (std.Io, ?*anyopaque, WaitOptions) errors.WaitError!void,
        connectionError: *const fn (std.Io, ?*anyopaque, std.c.fd_t) errors.ConnectError!void,
        read: *const fn (std.Io, ?*anyopaque, std.c.fd_t, []u8) errors.ReadError!usize,
        write: *const fn (std.Io, ?*anyopaque, std.c.fd_t, []const u8) errors.WriteError!usize,
        wake: *const fn (?*anyopaque, std.c.fd_t) void,
        close: *const fn (?*anyopaque, std.c.fd_t) void,
    };

    pub const native: Execution = .{ .context = null, .vtable = &native_vtable };
};

const native_vtable: Execution.VTable = .{
    .createStream = createStream,
    .createWake = createWake,
    .bind = bind,
    .listen = listen,
    .boundAddress = boundAddress,
    .accept = accept,
    .startConnect = startConnect,
    .wait = wait,
    .connectionError = connectionError,
    .read = read,
    .write = write,
    .wake = wake,
    .close = close,
};

fn createStream(io: std.Io, _: ?*anyopaque, ip: addr.IpAddress) errors.OpenError!std.c.fd_t {
    try io.checkCancel();
    return sys.createStream(ip);
}
fn createWake(io: std.Io, _: ?*anyopaque) errors.OpenError!std.c.fd_t {
    try io.checkCancel();
    return socket_open.createWake();
}
fn bind(io: std.Io, _: ?*anyopaque, handle: std.c.fd_t, address: addr.SocketAddr) errors.OpenError!void {
    try io.checkCancel();
    var name: std.c.sockaddr.storage = undefined;
    const length = socket_addr.writeSockaddr(address, &name);
    return socket_open.bindSocket(handle, &name, length);
}
fn listen(io: std.Io, _: ?*anyopaque, handle: std.c.fd_t) errors.ListenError!void {
    return sys.listenStream(io, handle);
}
fn boundAddress(io: std.Io, _: ?*anyopaque, handle: std.c.fd_t) errors.OpenError!addr.SocketAddr {
    try io.checkCancel();
    return socket_open.boundAddress(handle);
}
fn accept(io: std.Io, _: ?*anyopaque, handle: std.c.fd_t) errors.AcceptError!?Accepted {
    return sys.acceptStream(io, handle);
}
fn startConnect(io: std.Io, _: ?*anyopaque, handle: std.c.fd_t, peer: addr.SocketAddr) errors.ConnectError!bool {
    return sys.beginConnect(io, handle, peer);
}
fn wait(io: std.Io, _: ?*anyopaque, options: WaitOptions) errors.WaitError!void {
    return sys.waitStream(io, options);
}
fn connectionError(io: std.Io, _: ?*anyopaque, handle: std.c.fd_t) errors.ConnectError!void {
    try io.checkCancel();
    return sys.connectResult(handle);
}
fn read(io: std.Io, _: ?*anyopaque, handle: std.c.fd_t, buffer: []u8) errors.ReadError!usize {
    return sys.recvStream(io, handle, buffer);
}
fn write(io: std.Io, _: ?*anyopaque, handle: std.c.fd_t, bytes: []const u8) errors.WriteError!usize {
    return sys.sendStream(io, handle, bytes);
}
fn wake(_: ?*anyopaque, handle: std.c.fd_t) void {
    var one: u64 = 1;
    _ = std.c.write(handle, std.mem.asBytes(&one), @sizeOf(u64));
}
fn close(_: ?*anyopaque, handle: std.c.fd_t) void {
    _ = std.c.close(handle);
}
