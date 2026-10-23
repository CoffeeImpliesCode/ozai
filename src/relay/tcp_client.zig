const std = @import("std");
const key = @import("../base/key.zig");
const frame = @import("frame.zig");
const tcp = @import("../transport/tcp.zig");
const SocketAddr = @import("../base/addr.zig").SocketAddr;
const upgrade = @import("http_upgrade.zig");
const session = @import("tcp_session.zig");
const processor = @import("tcp_processor.zig");
const Session = session.Session;
pub const Error = session.Error;
pub const NodeId = key.NodeId;
pub const SecretKey = key.SecretKey;
const http = @import("tcp_http.zig");
const Execution = @import("../transport/tcp_execution.zig").Execution;
/// The execution context is borrowed until client teardown; the host bytes are copied at init.
pub const Config = struct {
    address: SocketAddr,
    host: []const u8,
    secret: SecretKey,
    execution: Execution,
};

pub const Packet = struct {
    source: NodeId,
    datagrams: frame.Datagrams,
};

pub const Client = struct {
    address: SocketAddr,
    connection: Session,
    secret: SecretKey,
    host: [256]u8 = undefined,
    host_len: usize,
    state: processor.ClientState,
    accept: [upgrade.accept_length]u8 = undefined,
    packet: ?Packet = null,

    pub fn init(io: std.Io, config: Config) Error!Client {
        if (config.host.len == 0 or config.host.len > 256) return error.InvalidHost;
        for (config.host) |byte| {
            if (byte <= 32 or byte >= 127) return error.InvalidHost;
        }
        var stream = try tcp.Tcp.create(io, config.address, config.execution);
        errdefer stream.close();
        const connected = try stream.startConnect(io);
        var result: Client = .{
            .address = config.address,
            .connection = .{ .stream = stream },
            .secret = config.secret,
            .host_len = config.host.len,
            .state = if (connected) .request else .connecting,
        };
        @memcpy(result.host[0..config.host.len], config.host);
        return result;
    }

    pub fn deinit(self: *Client) void {
        self.connection.close();
        self.secret.deinit();
        self.state = .closed;
    }

    pub fn isReady(self: *const Client) bool {
        return self.state == .ready;
    }

    pub fn send(self: *Client, target: NodeId, datagram: []const u8) Error!void {
        if (!self.isReady()) return error.WouldBlock;
        try self.connection.relay(.{ .client_to_relay_datagram = .{
            .node_id = target,
            .datagrams = .{ .ecn = null, .segment_size = null, .contents = datagram },
        } });
    }

    /// Packet storage is invalidated by the next poll, not by receive.
    pub fn receive(self: *Client) Error!?Packet {
        const packet = self.packet;
        self.packet = null;
        return packet;
    }

    pub fn poll(self: *Client, io: std.Io) Error!void {
        self.packet = null;
        self.pollInner(io) catch |err| {
            self.connection.close();
            self.state = .closed;
            return err;
        };
    }

    fn pollInner(self: *Client, io: std.Io) Error!void {
        if (self.state == .closed) return error.Closed;
        if (self.state == .connecting) {
            if (!try self.connection.stream.finishConnect(io)) return;
            self.state = (try processor.client(self.state, .connected, &self.secret)).state;
        }
        if (self.state == .request) {
            const result = try processor.client(self.state, .request, &self.secret);
            for (result.actions[0..result.count]) |action| {
                switch (action) {
                    .request => try http.request(&self.connection, io, self.host[0..self.host_len], &self.accept),
                    else => unreachable,
                }
            }
            self.state = result.state;
        }
        try self.connection.flush(io, .client);
        try self.connection.read(io);
        if (self.state == .upgrade) {
            const end = http.headerEnd(self.connection.rx[0..self.connection.rx_len]) orelse {
                if (self.connection.rx_len >=
                    upgrade.max_header_length) return error.InvalidUpgrade;
                if (self.connection.eof) return error.UnexpectedEnd;
                return;
            };
            const accepted = if (http.verifyResponse(self.connection.rx[0..end], &self.accept))
                true
            else |err| switch (err) {
                error.InvalidUpgrade => false,
                else => return err,
            };
            const result = try processor.client(self.state, .{ .upgrade = accepted }, &self.secret);
            self.connection.consume(end);
            self.state = result.state;
        }
        for (0..8) |_| {
            if (self.connection.busy()) return;
            const bytes = try self.connection.next(.client) orelse return;
            const message = try frame.decode(bytes, .v2);
            const result = try processor.client(self.state, .{ .message = message }, &self.secret);
            for (result.actions[0..result.count]) |action| {
                switch (action) {
                    .relay => |outgoing| try self.connection.relay(outgoing),
                    .deliver => |datagram| {
                        self.packet = .{
                            .source = datagram.node_id,
                            .datagrams = datagram.datagrams,
                        };
                    },
                    else => unreachable,
                }
            }
            self.state = result.state;
            if (self.packet != null) return;
        }
    }
};
