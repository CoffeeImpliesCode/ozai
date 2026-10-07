//! The two endpoints a blobs exchange needs, and the bookkeeping a stall wants.
//!
//! One getter and one provider over the transport in `protocol_wire.zig`, a
//! round loop that moves bytes both ways, and per-stream receive buffers keyed
//! by stream id — because the plan's first blob property is about one stream
//! and not about the connection: "missing data is EOF, not an error frame" is a
//! statement about what the getter sees on the stream nobody answered.

const std = @import("std");
const ozai = @import("ozai");

const t = std.testing;

const gossip = ozai.gossip_hyparview;
const postcard = ozai.postcard;
const blobs = ozai.blobs_protocol;
const range_spec = ozai.range_spec;

const codec = @import("protocol_codec.zig");
const wire = @import("protocol_wire.zig");

const SecretKey = ozai.SecretKey;

// ---------------------------------------------------------------------------
// Blobs over a socket
// ---------------------------------------------------------------------------

/// The two endpoints a blobs exchange needs, and the bookkeeping a stall wants.
pub const BlobLink = struct {
    getter: wire.Wire,
    provider: wire.Wire,
    now: gossip.Nanos = wire.start_ns,
    /// What the provider read off each stream, and whether each saw its FIN.
    provider_bytes: std.AutoHashMap(u64, std.ArrayList(u8)),
    provider_fin: std.AutoHashMap(u64, bool),
    getter_bytes: std.AutoHashMap(u64, std.ArrayList(u8)),
    getter_fin: std.AutoHashMap(u64, bool),
    /// What `scratch` and `body` were taken from. A field rather than the
    /// global `t.allocator` so a test can hand `init` an allocator that
    /// refuses: the steps *after* a wire is up are the ones whose unwind is
    /// worth proving, and without a refusal they are never taken.
    alloc: std.mem.Allocator,
    scratch: []u8,
    body: []u8,
    sent: [2]usize = .{ 0, 0 },
    received: [2]usize = .{ 0, 0 },
    /// The connection the getter's dial opened. Held so the assertions can read
    /// the identity the pin produced off the handshake.
    dialled: wire.Conn,

    /// Both ends up, dialled, and pinned to each other.
    ///
    /// `pub` because `protocol_loopback_test.zig` calls it across the file
    /// boundary the split that gave this module its own name introduced.
    pub fn init(link: *BlobLink, alloc: std.mem.Allocator) !void {
        link.* = .{
            .getter = undefined,
            .provider = undefined,
            .dialled = undefined,
            .provider_bytes = .init(t.allocator),
            .provider_fin = .init(t.allocator),
            .getter_bytes = .init(t.allocator),
            .getter_fin = .init(t.allocator),
            .scratch = undefined,
            .body = undefined,
            .alloc = alloc,
        };
        errdefer link.deinitBuffers();
        // Both ends pin the other, because a pair has one peer and
        // `Bridge.Config.expect_peer` is a value rather than a list.
        const getter_seed: [SecretKey.seed_length]u8 = @splat(0xb1);
        const provider_seed: [SecretKey.seed_length]u8 = @splat(0xb2);
        var getter_secret = try SecretKey.fromSeed(getter_seed);
        var provider_secret = try SecretKey.fromSeed(provider_seed);
        // Both wires *copy* their key: `Wire.init` keeps it in `self.secret`,
        // and the bridge and the dialer each derive their own seed bytes from
        // the `Config` they are handed. These two stack copies are therefore
        // the ones no owner shares, which makes `defer` — not `errdefer` — their
        // guard. The errdefer this replaced wiped a copy nothing else pointed
        // at, and left both keys live on every path that succeeded.
        defer getter_secret.deinit();
        defer provider_secret.deinit();
        try link.getter.init("getter", 0, getter_secret, null, blobs.alpn, 21);
        // From here each wire owns a socket, a bridge, a dialer, an address map
        // and four buffers, so every step below unwinds through the wires that
        // are already up.
        errdefer link.getter.deinit();
        try link.provider.init(
            "provider",
            1,
            provider_secret,
            getter_secret.nodeId(),
            blobs.alpn,
            22,
        );
        errdefer link.provider.deinit();
        link.scratch = try alloc.alloc(u8, codec.codec_room);
        errdefer alloc.free(link.scratch);
        link.body = try alloc.alloc(u8, codec.codec_room);
        errdefer alloc.free(link.body);
        // One dial, pinned to the provider's node id, so the handshake proves
        // who was dialled rather than merely that somebody answered. The id is
        // named before the dial because the dial writes into `link` and both
        // keys are wiped when this function returns: a value read off a wiped
        // key is a value that has to have been read before, not after.
        const provider_id = provider_secret.nodeId();
        link.dialled = (try link.getter.dialer.dial(
            .{ .ip = link.provider.socket.address },
            provider_id,
            link.getter.socket.address,
            &link.getter.map,
            @intCast(link.now),
            link.getter.random(),
        )).conn;
    }

    fn deinitBuffers(link: *BlobLink) void {
        link.freeSides(&link.provider_bytes);
        link.freeSides(&link.getter_bytes);
        link.provider_fin.deinit();
        link.provider_bytes.deinit();
        link.getter_fin.deinit();
        link.getter_bytes.deinit();
    }

    fn freeSides(_: *BlobLink, map: *std.AutoHashMap(u64, std.ArrayList(u8))) void {
        var it = map.valueIterator();
        while (it.next()) |buffer| buffer.deinit(t.allocator);
    }

    /// `pub` because `protocol_loopback_test.zig` calls it across the file
    /// boundary the split that gave this module its own name introduced.
    pub fn deinit(link: *BlobLink) void {
        link.deinitBuffers();
        link.alloc.free(link.body);
        link.alloc.free(link.scratch);
        link.provider.deinit();
        link.getter.deinit();
        link.* = undefined;
    }

    /// One round over both ends: pump, exchange, drain, and report the counts.
    ///
    /// `pub` because `protocol_loopback_test.zig` calls it across the file
    /// boundary the split that gave this module its own name introduced.
    pub fn round(link: *BlobLink) !bool {
        link.now += wire.time_quantum;
        const at: wire.Instant = @intCast(link.now);
        var getter_stats: wire.Counters = .{};
        var provider_stats: wire.Counters = .{};
        var moved = try link.getter.exchange(at, &getter_stats);
        moved = (try link.provider.exchange(at, &provider_stats)) or moved;
        link.sent[0] += getter_stats.out;
        link.received[0] += getter_stats.in;
        link.sent[1] += provider_stats.out;
        link.received[1] += provider_stats.in;
        moved = (try link.drain(&link.getter, &link.getter_bytes, &link.getter_fin)) or moved;
        moved = (try link.drain(&link.provider, &link.provider_bytes, &link.provider_fin)) or moved;
        return moved;
    }

    /// Copy every stream's readable bytes into a buffer per stream, and note
    /// which streams have seen their FIN.
    ///
    /// `allReceived` rather than `fin_received` alone: a FIN behind a hole is
    /// not the end of the stream, and treating it as one is how a `get` decodes
    /// a truncated request instead of waiting for the rest of it.
    fn drain(
        _: *BlobLink,
        side: *wire.Wire,
        bytes: *std.AutoHashMap(u64, std.ArrayList(u8)),
        fin: *std.AutoHashMap(u64, bool),
    ) !bool {
        const conn = side.bridge.connectionAt(0) orelse return false;
        if (!conn.established()) return false;
        var moved = false;
        var it = conn.entry.conn.streams.streams.iterator();
        while (it.next()) |entry| {
            const id = entry.key_ptr.*;
            const stream = entry.value_ptr.*;
            const gop = try bytes.getOrPut(id);
            if (!gop.found_existing) gop.value_ptr.* = .empty;
            while (stream.recv.read()) |chunk| {
                // The same handover `protocol_node.readStream` uses: the append is what
                // copies, and the chunk is the caller's from the `try` on.
                defer t.allocator.free(chunk);
                moved = true;
                try gop.value_ptr.appendSlice(t.allocator, chunk);
            }
            if (stream.recv.allReceived()) try fin.put(id, true);
        }
        return moved;
    }

    /// `pub` because `protocol_loopback_test.zig` calls it across the file
    /// boundary the split that gave this module its own name introduced.
    pub fn finished(
        link: *BlobLink,
        fin: *const std.AutoHashMap(u64, bool),
        id: u64,
    ) bool {
        _ = link;
        return fin.get(id) orelse false;
    }

    /// Encode a request the way the getter writes it: one `postcard.Writer`
    /// into `scratch`, with `body` as the length-prefixed arm's scratch.
    /// `pub` because `protocol_loopback_test.zig` calls it across the file
    /// boundary the split that gave this module its own name introduced.
    pub fn writeRequest(link: *BlobLink, request: blobs.Request) ![]const u8 {
        var writer = postcard.Writer.init(link.scratch);
        try request.write(&writer, link.body);
        return writer.finish();
    }

    /// `pub` because `protocol_loopback_test.zig` calls it across the file
    /// boundary the split that gave this module its own name introduced.
    pub fn report(link: *BlobLink, reason: []const u8) void {
        std.debug.print("\nblobs wire stalled: {s}\n", .{reason});
        for (0..2) |which| {
            const side: *wire.Wire = if (which == 0) &link.getter else &link.provider;
            std.debug.print(
                "  {s} ({f}) at {f}: {d} datagrams out, {d} in\n",
                .{
                    side.name,
                    side.id,
                    side.socket.address,
                    link.sent[which],
                    link.received[which],
                },
            );
            var index: usize = 0;
            while (side.bridge.connectionAt(index)) |conn| : (index += 1) {
                std.debug.print(
                    "    conn {d}: state {t}, established {}\n",
                    .{ conn.id(), conn.entry.conn.state, conn.established() },
                );
                var it = conn.entry.conn.streams.streams.iterator();
                while (it.next()) |entry| {
                    const id = entry.key_ptr.*;
                    const held = if (which == 0)
                        link.getter_bytes.get(id)
                    else
                        link.provider_bytes.get(id);
                    const seen = if (which == 0)
                        link.getter_fin.get(id)
                    else
                        link.provider_fin.get(id);
                    std.debug.print(
                        "    stream {d}: {d} bytes, fin {}\n",
                        .{ id, if (held) |buffer| buffer.items.len else 0, seen orelse false },
                    );
                }
            }
        }
        std.debug.print("  virtual time {d} ms; round bound {d}\n", .{
            link.now / gossip.nanos_per_milli,
            wire.max_rounds,
        });
    }
};

/// Scratch a blobs decode borrows into.
///
/// The counts are this file's own bounds, not the protocol's: a request longer
/// than any of them is a frame this artifact cannot hold, and
/// `RangeSpecSeq.parse` reports that as `error.BufferFull` rather than
/// pretending it read the request.
const decode_slots = 64;

pub const DecodeStorage = struct {
    /// The four buffers a blobs decode fills, and the `Storage` that borrows
    /// them. The arrays are fields rather than constants because a decode
    /// writes through them, and `Storage`'s slices have to point at the same
    /// memory — so `init` points them at `self` rather than returning one.
    items: [decode_slots]range_spec.Item = @splat(.{ .delta = 0, .spec = .empty }),
    widths: [decode_slots]u64 = @splat(0),
    hashes: [decode_slots][32]u8 = @splat(@splat(0)),
    boundaries: [decode_slots]u64 = @splat(0),
    inner: blobs.Storage = undefined,

    /// Point `inner` at this struct's own arrays, in place.
    ///
    /// `fn init() DecodeStorage` was the shape before, and it took the address
    /// of a returned value: the slices `Storage` carries were cut from the
    /// local `self` inside `init`, so every decode through them read a frame
    /// that had already unwound. A debug build still found the bytes there and
    /// a release build had reused the slot, which is the same failure the
    /// gossip module's own contact data had; see the module doc.
    /// `pub` because `protocol_loopback_test.zig` calls it across the file
    /// boundary the split that gave this module its own name introduced.
    pub fn init(self: *DecodeStorage) void {
        self.inner = .{
            .items = self.items[0..],
            .widths = self.widths[0..],
            .hashes = self.hashes[0..],
            .boundaries = self.boundaries[0..],
        };
    }
};

/// What the provider writes for the request it can answer.
///
/// Opaque bytes, and the doc says so: this project has no bao encoder, so what
/// is under test is the framing and not the content hash. A real provider
/// writes bao data here and the getter's decode is a bao problem, not a
/// transport one.
pub const answer_bytes = "bao data, opaque to this layer";
