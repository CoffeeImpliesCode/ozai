//! Store-backed /iroh-bytes/4 transfers over authenticated Bridge streams.
const std = @import("std");
const bridge_mod = @import("../transport/quic_bridge.zig");
const protocol = @import("../blobs/protocol.zig");
const provider_mod = @import("../blobs/provider.zig");
const getter_mod = @import("../blobs/getter.zig");
const store = @import("../blobs/store.zig");
const range_spec = @import("../blobs/range_spec.zig");
const postcard = @import("../wire/postcard.zig");

pub const Provider = struct { dir: std.Io.Dir, hash: store.Hash };
pub const Getter = struct {
    hash: store.Hash,
    size: ?u64 = null,
    range: ?protocol.ChunkRange = null,
};
pub const Config = union(enum) { disabled, provider: Provider, getter: Getter };
pub const Error = bridge_mod.Error || provider_mod.Error || getter_mod.DecodeError ||
    protocol.Error || std.mem.Allocator.Error || error{ InvalidRange, WrongRequest };

const Transfer = struct {
    connection: u64,
    stream_id: u64,
    stream: ?bridge_mod.Stream,
    request_sent: bool,
    bytes: std.ArrayList(u8) = .empty,
    verified: std.ArrayList(u8) = .empty,
    done: bool = false,
};

pub const State = struct {
    config: Config,
    transfers: std.ArrayList(Transfer) = .empty,
    completed: u64 = 0,
    sent_bytes: u64 = 0,
    received_bytes: u64 = 0,
    last_size: ?u64 = null,
    last_hash: ?store.Hash = null,

    pub fn init(config: Config) State { return .{ .config = config }; }

    pub fn deinit(self: *State, gpa: std.mem.Allocator) void {
        for (self.transfers.items) |*transfer| {
            transfer.bytes.deinit(gpa);
            transfer.verified.deinit(gpa);
        }
        self.transfers.deinit(gpa);
        self.* = .init(.disabled);
    }

    pub fn payload(self: *const State, connection: u64) ?[]const u8 {
        if (self.config != .getter) return null;
        for (self.transfers.items) |transfer| {
            if (transfer.connection == connection and transfer.done) return transfer.verified.items;
        }
        return null;
    }
    pub fn firstCompletedConnection(self: *const State) ?u64 {
        if (self.config != .getter) return null;
        for (self.transfers.items) |transfer| {
            if (transfer.done) return transfer.connection;
        }
        return null;
    }


    /// Node calls after admission, before draining transport packets.
    pub fn drive(self: *State, gpa: std.mem.Allocator, io: std.Io, bridge: *bridge_mod.Bridge) Error!bool {
        if (self.config == .disabled) return false;
        self.pruneTransfers(gpa, bridge);
        var moved = false;
        var index: usize = 0;
        while (bridge.connectionAt(index)) |conn| : (index += 1) {
            if (!conn.established() or conn.closed()) continue;
            const alpn = conn.alpn() orelse continue;
            if (!std.mem.eql(u8, alpn, protocol.alpn)) continue;
            if (self.config == .getter) {
                moved = try self.driveTransfer(gpa, io, conn, null) or moved;
            } else {
                var stream_index: usize = 0;
                while (conn.incomingStream(stream_index)) |stream| : (stream_index += 1) {
                    moved = try self.driveTransfer(gpa, io, conn, stream) or moved;
                }
            }
        }
        return moved;
    }

    fn pruneTransfers(self: *State, gpa: std.mem.Allocator, bridge: *bridge_mod.Bridge) void {
        var index: usize = 0;
        while (index < self.transfers.items.len) {
            const transfer = &self.transfers.items[index];
            var connection_index: usize = 0;
            var live = false;
            while (bridge.connectionAt(connection_index)) |conn| : (connection_index += 1) {
                if (conn.id() == transfer.connection) {
                    live = true;
                    break;
                }
            }
            if (live) {
                index += 1;
            } else if (self.config == .provider or !transfer.done) {
                transfer.bytes.deinit(gpa);
                transfer.verified.deinit(gpa);
                _ = self.transfers.swapRemove(index);
            } else {
                transfer.stream = null;
                index += 1;
            }
        }
    }

    fn driveTransfer(
        self: *State,
        gpa: std.mem.Allocator,
        io: std.Io,
        conn: bridge_mod.Conn,
        incoming: ?bridge_mod.Stream,
    ) Error!bool {
        var existing: ?*Transfer = null;
        for (self.transfers.items) |*transfer| {
            if (transfer.connection == conn.id() and
                (incoming == null or transfer.stream_id == incoming.?.id()))
            {
                existing = transfer;
                break;
            }
        }
        var request_bytes: [128]u8 = undefined;
        const request = if (self.config == .getter and
            (existing == null or !existing.?.request_sent))
            try encodeRequest(self.config.getter, &request_bytes)
        else
            &.{};
        var moved = false;
        const transfer = existing orelse block: {
            try self.transfers.ensureUnusedCapacity(gpa, 1);
            const stream = incoming orelse bridge_mod.Stream.open(conn) catch |err|
                switch (err) {
                    error.NoStreamRoom => return false,
                    else => return err,
                };
            self.transfers.appendAssumeCapacity(.{
                .connection = conn.id(),
                .stream_id = stream.id(),
                .stream = stream,
                .request_sent = self.config == .provider,
            });
            moved = true;
            break :block &self.transfers.items[self.transfers.items.len - 1];
        };
        if (transfer.done) return moved;
        const stream = if (transfer.stream) |*value| value else return moved;
        // Retain the opened stream on a refused write; never publish an unsent request.
        if (!transfer.request_sent) {
            try stream.write(request);
            stream.close();
            transfer.request_sent = true;
            self.sent_bytes += request.len;
            moved = true;
        }
        if (self.config == .provider and
            transfer.bytes.items.len > protocol.max_message_size + 1)
        {
            return error.MessageTooLarge;
        }
        const drained = block: {
            const before = transfer.bytes.items.len;
            // Allocation failure may still commit earlier ready runs.
            defer self.received_bytes += transfer.bytes.items.len - before;
            break :block try stream.drain(gpa, &transfer.bytes);
        };
        if (self.config == .provider and
            transfer.bytes.items.len > protocol.max_message_size + 1)
        {
            return error.MessageTooLarge;
        }
        moved = drained or moved;
        // FIN describes receipt, not consumption. A bounded pass can leave bytes queued.
        if (drained or !stream.finished()) return moved;
        switch (self.config) {
            .provider => |options| {
                const answered = try self.respond(gpa, io, transfer, options);
                if (answered) {
                    self.last_hash = options.hash;
                    self.completed += 1;
                }
            },
            .getter => |options| {
                const wire = transfer.bytes.items;
                var export_bytes: u64 = 0;
                if (wire.len >= 8) {
                    const size = std.mem.readInt(u64, wire[0..8], .little);
                    const start = if (options.range) |range| range.start *| protocol.chunk_size else 0;
                    const end = if (options.range) |range|
                        @min(range.end *| protocol.chunk_size, size)
                    else
                        size;
                    export_bytes = end -| start;
                }
                // The unchecked size bounds allocation only; decode authenticates before copying.
                try transfer.verified.resize(gpa, @intCast(@min(export_bytes, wire.len)));
                const decoded = try decodeResponse(
                    options, transfer.bytes.items, transfer.verified.items,
                );
                transfer.verified.items.len = decoded.written;
                self.last_size = decoded.size;
                self.last_hash = options.hash;
                self.completed += 1;
            },
            .disabled => unreachable,
        }
        transfer.done = true;
        transfer.stream = null;
        transfer.bytes.clearAndFree(gpa);
        return true;
    }

    fn respond(
        self: *State,
        gpa: std.mem.Allocator,
        io: std.Io,
        transfer: *Transfer,
        options: Provider,
    ) Error!bool {
        var items: [2]range_spec.Item = undefined;
        var widths: [4]u64 = undefined;
        var storage: protocol.Storage = .{ .items = &items, .widths = &widths };
        var reader = postcard.Reader.init(transfer.bytes.items);
        const request = try protocol.Request.read(&reader, &storage);
        if (request != .to_eof or request.to_eof != .get) return error.WrongRequest;
        var names: store.NameStorage = undefined;
        var scratch: [16384]u8 = undefined;
        const provider = try provider_mod.Provider.init(options.dir, &names, options.hash, &scratch);
        var response: std.Io.Writer.Allocating = .init(gpa);
        defer response.deinit();
        const outcome = try provider.answer(io, &response.writer, request.to_eof.get);
        const bytes = response.written();
        const stream = &transfer.stream.?;
        try stream.write(bytes);
        stream.close();
        self.sent_bytes += bytes.len;
        if (outcome == .answered) self.last_size = std.mem.readInt(u64, bytes[0..8], .little);
        return outcome == .answered;
    }
};

pub fn encodeRequest(options: Getter, out: []u8) (protocol.Error || error{InvalidRange})![]const u8 {
    var widths: [2]u64 = undefined;
    var items: [2]range_spec.Item = undefined;
    const request = try makeRequest(options, &widths, &items);
    var writer = postcard.Writer.init(out);
    try (protocol.Request{ .to_eof = .{ .get = request } }).write(&writer, &.{});
    return writer.finish();
}

fn makeRequest(options: Getter, widths: *[2]u64, items: *[2]range_spec.Item) error{InvalidRange}!protocol.GetRequest {
    const range = options.range orelse return protocol.GetRequest.blob(options.hash);
    if (range.start >= range.end) return error.InvalidRange;
    widths.* = .{ range.start, range.end - range.start };
    items.* = .{
        .{ .delta = 0, .spec = .{ .widths = widths } },
        .{ .delta = 1, .spec = .empty },
    };
    return .{ .hash = options.hash, .ranges = .{ .items = items } };
}

pub fn decodeResponse(options: Getter, wire: []const u8, out: []u8) (getter_mod.DecodeError || error{InvalidRange})!getter_mod.Decoded {
    var widths: [2]u64 = undefined;
    var items: [2]range_spec.Item = undefined;
    const request = try makeRequest(options, &widths, &items);
    return getter_mod.decode(request, options.size, options.hash, wire, out);
}

test {
    _ = @import("node_blobs_test.zig");
    _ = @import("node_blobs_state_test.zig");
}
