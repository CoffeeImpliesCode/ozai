//! The link: the two endpoints a blobs transfer needs and the round that moves
//! bytes between them.
//!
//! A provider that has the bytes and a getter that does not, one connection and
//! one round loop — and, for each round, every stream's readable bytes copied
//! into a buffer per stream so a `get` that nobody answered can be told from a
//! `get` that was answered short. Which request is on which stream, and what the
//! provider made of it, are `transfer_jobs.zig` and `transfer_ranges.zig`.

const std = @import("std");
const ozai = @import("ozai");

const t = std.testing;

const blobs = ozai.blobs_protocol;

const jobs = @import("transfer_jobs.zig");
const ranges_mod = @import("transfer_ranges.zig");
const wire = @import("transfer_wire.zig");

const Wire = wire.Wire;
const SecretKey = ozai.SecretKey;

/// The most jobs one link carries, and so the most decode storages.
pub const max_jobs = 8;

// ---------------------------------------------------------------------------
// The link
// ---------------------------------------------------------------------------

/// The two endpoints a blobs transfer needs: a provider that has the bytes and
/// a getter that does not, one connection, one round loop.
pub const Link = struct {
    getter: Wire,
    provider: Wire,
    store: ranges_mod.Store,
    jobs: [max_jobs]jobs.Job = @splat(.{ .name = "unused" }),
    now: u64 = wire.start_ns,

    /// What the provider read off each stream, and whether each saw its FIN.
    provider_bytes: std.AutoHashMap(u64, jobs.StreamBytes),
    provider_fin: std.AutoHashMap(u64, bool),
    getter_bytes: std.AutoHashMap(u64, jobs.StreamBytes),
    getter_fin: std.AutoHashMap(u64, bool),

    /// The `push` arm's length-prefixed body scratch, which `Request.write`
    /// needs because a varint length cannot be backpatched once its width is
    /// known.
    body: [jobs.request_room]u8 = undefined,
    /// Scratch the getter decodes an `observe` run into. Separate from every
    /// job's, because the run's items are compared after the run is over and
    /// the job's storage belongs to the provider.
    seen: jobs.DecodeStorage = .{},

    /// The connection the getter's dial opened, held so the assertions can read
    /// the identity the pin produced off the handshake.
    dialled: wire.Conn,

    /// Both ends up, dialled, and pinned to each other.
    ///
    /// `pub` because `blobs_transfer_test.zig` calls it across the file
    /// boundary the split that gave this module its own name introduced.
    pub fn init(link: *Link) !void {
        const store = try ranges_mod.Store.init(t.allocator);
        errdefer store.deinit(t.allocator);
        link.* = .{
            .getter = undefined,
            .provider = undefined,
            .store = store,
            .provider_bytes = .init(t.allocator),
            .provider_fin = .init(t.allocator),
            .getter_bytes = .init(t.allocator),
            .getter_fin = .init(t.allocator),
            .dialled = undefined,
        };
        link.seen.init();
        for (&link.jobs) |*job| job.storage.init();
        errdefer link.deinitBuffers();
        // Both ends pin the other, because a pair has one peer and
        // `Bridge.Config.expect_peer` is a value rather than a list.
        const getter_seed: [SecretKey.seed_length]u8 = @splat(0xc1);
        const provider_seed: [SecretKey.seed_length]u8 = @splat(0xc2);
        var getter_secret = try SecretKey.fromSeed(getter_seed);
        var provider_secret = try SecretKey.fromSeed(provider_seed);
        // Both wires *copy* their key: `Wire.init` keeps it in `self.secret`,
        // and the bridge and the dialer each derive their own seed bytes from
        // the `Config` they are handed. These two stack copies are therefore
        // the ones no owner shares, which makes `defer` — not `errdefer` —
        // their guard.
        defer getter_secret.deinit();
        defer provider_secret.deinit();
        try link.getter.init("getter", getter_secret, null, blobs.alpn, 31);
        // From here each wire owns a socket, a bridge, a dialer, an address map
        // and four buffers, so every step below unwinds through the wires that
        // are already up.
        errdefer link.getter.deinit();
        try link.provider.init(
            "provider",
            provider_secret,
            getter_secret.nodeId(),
            blobs.alpn,
            32,
        );
        errdefer link.provider.deinit();
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

    /// Put a job on the link and point its decode storage at its own arrays.
    ///
    /// Assigning a `Job` wholesale replaces the storage, so this is where the
    /// slices get pointed again; a decode through a `Storage` whose arrays are
    /// not the ones it names reads whatever is in a frame that has unwound.
    /// `pub` because `blobs_transfer_test.zig` calls it across the file
    /// boundary the split that gave this module its own name introduced.
    pub fn put(link: *Link, index: usize, job: jobs.Job) void {
        link.jobs[index] = job;
        link.jobs[index].storage.init();
    }

    fn deinitBuffers(link: *Link) void {
        jobs.freeSides(&link.provider_bytes);
        jobs.freeSides(&link.getter_bytes);
        link.provider_fin.deinit();
        link.provider_bytes.deinit();
        link.getter_fin.deinit();
        link.getter_bytes.deinit();
    }

    /// `pub` because `blobs_transfer_test.zig` calls it across the file
    /// boundary the split that gave this module its own name introduced.
    pub fn deinit(link: *Link) void {
        link.deinitBuffers();
        link.store.deinit(t.allocator);
        link.provider.deinit();
        link.getter.deinit();
        link.* = undefined;
    }

    /// One round: the clock moves, both sides take and flush, both sides drain
    /// their streams, and the provider answers whatever has arrived whole.
    /// `pub` because `blobs_transfer_test.zig` calls it across the file
    /// boundary the split that gave this module its own name introduced.
    pub fn round(link: *Link) !bool {
        link.now += wire.quantum;
        const at: wire.Instant = @intCast(link.now);
        var moved = try link.getter.exchange(at);
        moved = (try link.provider.exchange(at)) or moved;
        moved = (try link.drain(&link.getter, &link.getter_bytes, &link.getter_fin)) or moved;
        moved = (try link.drain(&link.provider, &link.provider_bytes, &link.provider_fin)) or moved;
        moved = (try ranges_mod.serve(link)) or moved;
        return moved;
    }

    /// Copy every stream's readable bytes into a buffer per stream, and note
    /// which streams have seen their FIN.
    ///
    /// `allReceived` rather than `fin_received` alone: a FIN behind a hole is
    /// not the end of the stream, and treating it as one is how a `get` decodes
    /// a truncated request instead of waiting for the rest of it.
    fn drain(
        _: *Link,
        side: *Wire,
        bytes: *std.AutoHashMap(u64, jobs.StreamBytes),
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
            if (!gop.found_existing) gop.value_ptr.* = jobs.StreamBytes.empty;
            while (stream.recv.read()) |chunk| {
                // The same handover `Wire.take` uses: the append is what
                // copies, and the chunk is the caller's from the `try` on.
                defer t.allocator.free(chunk);
                moved = true;
                try gop.value_ptr.push(chunk);
            }
            if (stream.recv.allReceived()) try fin.put(id, true);
        }
        return moved;
    }

    /// `pub` because `blobs_transfer_test.zig` calls it across the file
    /// boundary the split that gave this module its own name introduced.
    pub fn finished(
        _: *Link,
        fin: *const std.AutoHashMap(u64, bool),
        stream: u64,
    ) bool {
        return fin.get(stream) orelse false;
    }
};
