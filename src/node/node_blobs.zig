//! Store-backed /iroh-bytes/4 transfers over authenticated Bridge streams.
const std = @import("std");
const bridge_mod = @import("../transport/quic_bridge.zig");
const protocol = @import("../blobs/protocol.zig");
const provider_mod = @import("../blobs/provider.zig");
const getter_mod = @import("../blobs/getter.zig");
const store = @import("../blobs/store.zig");
const range_spec = @import("../blobs/range_spec.zig");
const postcard = @import("../wire/postcard.zig");
const transfer_mod = @import("node_blobs_transfer.zig");

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
    machine: transfer_mod.State,
    bytes: std.ArrayList(u8) = .empty,
    verified: std.ArrayList(u8) = .empty,
};

pub const State = struct {
    config: Config,
    transfers: std.ArrayList(Transfer) = .empty,
    completed: u64 = 0,
    sent_bytes: u64 = 0,
    received_bytes: u64 = 0,
    last_size: ?u64 = null,
    last_claimed_size: ?u64 = null,
    last_hash: ?store.Hash = null,

    pub fn init(config: Config) State {
        return .{ .config = config };
    }

    /// Release transfer storage once; the state is invalid until replaced with init.
    pub fn deinit(self: *State, gpa: std.mem.Allocator) void {
        for (self.transfers.items) |*transfer| {
            transfer.bytes.deinit(gpa);
            transfer.verified.deinit(gpa);
        }
        self.transfers.deinit(gpa);
        self.* = undefined;
    }

    pub fn payload(self: *const State, connection: u64) ?[]const u8 {
        if (self.config != .getter) return null;
        for (self.transfers.items) |transfer| {
            if (transfer.connection == connection and transfer.machine.done) {
                return transfer.verified.items;
            }
        }
        return null;
    }
    pub fn firstCompletedConnection(self: *const State) ?u64 {
        if (self.config != .getter) return null;
        for (self.transfers.items) |transfer| {
            if (transfer.machine.done) return transfer.connection;
        }
        return null;
    }

    /// Node calls after admission, before draining transport packets.
    pub fn drive(
        self: *State,
        gpa: std.mem.Allocator,
        io: std.Io,
        bridge: *bridge_mod.Bridge,
    ) Error!bool {
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
            } else if (self.config == .provider or !transfer.machine.done) {
                transfer.bytes.deinit(gpa);
                transfer.verified.deinit(gpa);
                _ = self.transfers.swapRemove(index);
            } else {
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
                .machine = .init(if (self.config == .getter) .getter else .provider),
            });
            moved = true;
            break :block &self.transfers.items[self.transfers.items.len - 1];
        };
        if (transfer.machine.done) return moved;
        var stream = conn.stream(transfer.stream_id) orelse return moved;
        const had_header = transfer.bytes.items.len >= 8;
        const response_allowance = try self.allowance(transfer.bytes.items);
        var next = try transfer_mod.process(transfer.machine, .{ .ready = .{
            .buffered = transfer.bytes.items.len,
            .allowance = response_allowance,
        } });
        if (next.actions[0] == .write_request) {
            var buffer: [128]u8 = undefined;
            const request = try encodeRequest(self.config.getter, &buffer);
            try stream.write(request);
            stream.close();
            transfer.machine = (try transfer_mod.process(transfer.machine, .request_written)).state;
            self.sent_bytes += request.len;
            moved = true;
            next = try transfer_mod.process(transfer.machine, .{ .ready = .{
                .buffered = transfer.bytes.items.len,
                .allowance = response_allowance,
            } });
        }
        const drained = block: {
            const before = transfer.bytes.items.len;
            // A refused run leaves bytes pending; earlier accepted runs remain committed.
            defer self.received_bytes += transfer.bytes.items.len - before;
            break :block stream.drain(gpa, &transfer.bytes, next.actions[0].drain) catch |err|
                switch (err) {
                    error.ByteBudgetExceeded => return error.MessageTooLarge,
                    error.OutOfMemory => return error.OutOfMemory,
                };
        };
        // Re-evaluate only when the response header first arrives.
        if (self.config == .getter and !had_header and transfer.bytes.items.len >= 8) {
            _ = try self.allowance(transfer.bytes.items);
        }
        next = try transfer_mod.process(transfer.machine, .{ .received = .{
            .drained = drained,
            .finished = stream.finished(),
        } });
        if (next.len == 0) return drained or moved;
        switch (next.actions[0]) {
            .decode_request => return self.respond(gpa, io, transfer, &stream),
            .decode_response => {
                const decoded = try self.decode(gpa, transfer);
                next = try transfer_mod.process(transfer.machine, .{ .response = decoded });
                self.finish(gpa, transfer, &stream, next);
                return true;
            },
            else => unreachable,
        }
    }

    fn allowance(self: *const State, wire: []const u8) Error!usize {
        const limit = if (self.config == .provider)
            protocol.max_message_size + 1
        else block: {
            const options = self.config.getter;
            var widths: [2]u64 = undefined;
            var items: [2]range_spec.Item = undefined;
            const request = try makeRequest(options, &widths, &items);
            const initial = try getter_mod.budget(request, options.size);
            if (wire.len < 8) break :block initial;
            const claimed = std.mem.readInt(u64, wire[0..8], .little);
            if (options.size) |expected| {
                if (claimed != expected) return error.SizeMismatch;
                break :block initial;
            }
            break :block @min(initial, try getter_mod.budget(request, claimed));
        };
        if (wire.len > limit) return error.MessageTooLarge;
        return limit;
    }

    fn decode(self: *State, gpa: std.mem.Allocator, transfer: *Transfer) Error!getter_mod.Decoded {
        const options = self.config.getter;
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
        // Allocation is bounded by received proof bytes; verification precedes payload exposure.
        try transfer.verified.resize(gpa, @intCast(@min(export_bytes, wire.len)));
        return decodeResponse(options, wire, transfer.verified.items);
    }

    fn finish(
        self: *State,
        gpa: std.mem.Allocator,
        transfer: *Transfer,
        stream: *bridge_mod.Stream,
        next: transfer_mod.Transition,
    ) void {
        for (next.actions[0..next.len]) |action| switch (action) {
            .close_stream => stream.close(),
            .complete => |completion| {
                if (completion.answered) {
                    self.last_size = completion.verified_size;
                    self.last_claimed_size = completion.claimed_size;
                    self.last_hash = switch (self.config) {
                        .getter => |options| options.hash,
                        .provider => |options| options.hash,
                        .disabled => unreachable,
                    };
                    if (self.config == .getter) {
                        transfer.verified.items.len = completion.written;
                        self.completed += 1;
                    }
                }
                transfer.bytes.clearAndFree(gpa);
            },
            else => unreachable,
        };
        transfer.machine = next.state;
    }

    fn respond(
        self: *State,
        gpa: std.mem.Allocator,
        io: std.Io,
        transfer: *Transfer,
        stream: *bridge_mod.Stream,
    ) Error!bool {
        var items: [2]range_spec.Item = undefined;
        var widths: [4]u64 = undefined;
        var storage: protocol.Storage = .{ .items = &items, .widths = &widths };
        var reader = postcard.Reader.init(transfer.bytes.items);
        const request = try protocol.Request.read(&reader, &storage);
        if (request != .to_eof or request.to_eof != .get) return error.WrongRequest;
        const next = try transfer_mod.process(transfer.machine, .{ .request = request.to_eof.get });
        const options = self.config.provider;
        var names: store.NameStorage = undefined;
        var scratch: [16384]u8 = undefined;
        const provider = try provider_mod.Provider.init(
            options.dir,
            &names,
            options.hash,
            &scratch,
        );
        var response: std.Io.Writer.Allocating = .init(gpa);
        defer response.deinit();
        const outcome = provider.answer(io, &response.writer, next.actions[0].answer) catch |err|
            switch (err) {
                error.ShortData, error.ShortOutboard, error.InvalidOutboard => {
                    const refused = try transfer_mod.process(transfer.machine, .provider_refusal);
                    self.finish(gpa, transfer, stream, refused);
                    return true;
                },
                else => return err,
            };
        const bytes = response.written();
        try stream.write(bytes);
        self.sent_bytes += bytes.len;
        const size: ?u64 = if (outcome == .answered)
            std.mem.readInt(u64, bytes[0..8], .little)
        else
            null;
        const finished = try transfer_mod.process(transfer.machine, .{ .provider_answer = size });
        self.finish(gpa, transfer, stream, finished);
        return true;
    }
};

pub fn encodeRequest(
    options: Getter,
    out: []u8,
) (protocol.Error || error{InvalidRange})![]const u8 {
    var widths: [2]u64 = undefined;
    var items: [2]range_spec.Item = undefined;
    const request = try makeRequest(options, &widths, &items);
    var writer = postcard.Writer.init(out);
    try (protocol.Request{ .to_eof = .{ .get = request } }).write(&writer, &.{});
    return writer.finish();
}

fn makeRequest(
    options: Getter,
    widths: *[2]u64,
    items: *[2]range_spec.Item,
) error{InvalidRange}!protocol.GetRequest {
    const range = options.range orelse return protocol.GetRequest.blob(options.hash);
    if (range.start >= range.end) return error.InvalidRange;
    widths.* = .{ range.start, range.end - range.start };
    items.* = .{
        .{ .delta = 0, .spec = .{ .widths = widths } },
        .{ .delta = 1, .spec = .empty },
    };
    return .{ .hash = options.hash, .ranges = .{ .items = items } };
}

pub fn decodeResponse(
    options: Getter,
    wire: []const u8,
    out: []u8,
) (getter_mod.DecodeError || error{InvalidRange})!getter_mod.Decoded {
    var widths: [2]u64 = undefined;
    var items: [2]range_spec.Item = undefined;
    const request = try makeRequest(options, &widths, &items);
    return getter_mod.decode(request, options.size, options.hash, wire, out);
}

test {
    _ = @import("node_blobs_test.zig");
    _ = @import("node_blobs_state_test.zig");
}
