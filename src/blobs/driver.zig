//! The two halves of a blobs transfer as production code runs them: a provider
//! that answers a decoded `get` out of a store, and a getter that decodes the
//! `BaoResponse` a provider sent.
//!
//! # Why this file is here
//!
//! `protocol.zig` is a codec. It has `BaoResponse` and nothing that answers one,
//! so every transfer in this tree so far has been a test that wrote its own
//! provider half — `test/blobs_transfer_test.zig`'s `Link.serve` and the two
//! writers beside it are the protocol's own range walk, store read and framing,
//! and that belong here. What this file adds is the store and the bao decode,
//! and nothing else:
//! the walk is `RangeSpec.resolve`, the spans are `chunksToBytes`, the request
//! is `Request.read` and the answer is what the store held.
//!
//! # Both halves are turns, never loops
//!
//! A handler is handed one connection and one bounded step pass
//! (`node_protocol.Handler.accept`), so a half that blocked would block the pass
//! — and a whole-blob answer is megabytes. `Provider.step` and `Getter.step`
//! each do one bounded piece and hand the connection back: one request decoded
//! per stream, `block_size` of answer per pass, and every byte the peer sent so
//! far on the receive side.
//!
//! # The store and the decoder are injected
//!
//! Two vtables, for the reason `probe_run.Transport` and `incoming_filter` are:
//! a seam costs no allocation and puts no `anyerror` in a type. A provider here
//! answers from whatever holds blobs — a memory map under a test, a file-backed
//! store in a node — and a getter verifies with whatever implements the bao
//! decode. Nothing in this file opens a file, hashes a byte or reads a clock.
//!
//! **This module is not one of the pure ones.** It imports `node_protocol`, so
//! it sits above the wire codecs with everything the node's own handlers sit
//! above them: a test target that imports it needs the `quic` module and libc
//! the way `blobs-transfer` already needs them.
//!
//! # Missing data is an empty answer, and it is not this file's to decide
//!
//! `BaoResponse` has no error arm, and `protocol.zig` gives the reason: a
//! provider that does not have what it was asked stops writing. So a `get` this
//! provider cannot answer is closed with *nothing* written — never a partial
//! answer, never an invented error frame — and whether that empty answer is a
//! whole empty blob or a range the provider lacks is the decoder's to say,
//! because only the decoder holds the root hash the answer is checked against.

const std = @import("std");
const protocol = @import("protocol.zig");
const chunk = @import("chunk.zig");
const range_spec = @import("range_spec.zig");
const postcard = @import("../wire/postcard.zig");
const quic_stream = @import("../transport/quic_stream.zig");
const node_protocol = @import("../node/node_protocol.zig");
const node_error = @import("../node/node_error.zig");

/// Whether a handler turn has more to do or is finished: the node's own answer,
/// so a blobs handler returns what the lane expects rather than a shape of its
/// own that the lane would have to translate.
pub const Turn = node_protocol.Turn;

/// What a store can refuse.
pub const StoreError = error{
    /// The store does not have the blob a request named. The answer to that is
    /// an empty stream, not an error on this side of the wire.
    UnknownBlob,
    /// A read was asked for bytes outside the blob. The provider clips at the
    /// size it was told, so reaching this is the store's own disagreement
    /// about its own length.
    OutOfRange,
};

/// Every way a step of either half can fail.
///
/// `node_error.Error` is in it because the one call this file makes into the
/// node is `Connection.openStream` and the node's refusal to open a stream is
/// the node's own set; the protocol's is here because both halves decode a
/// peer's bytes, and the decoder's is here because the getter runs one.
pub const Error = node_error.Error || protocol.Error || StoreError || error{
    /// `Getter.step` before `start`, or after the transfer has ended.
    NoTransferInFlight,
    /// `Getter.start` while a transfer is already in flight.
    TransferInFlight,
};

/// The blobs a provider answers from: a size by hash, and bytes by hash.
///
/// **Two calls, because those are the two questions a range walk asks.** The
/// walk needs the size to resolve a spec and to clip the last chunk, and it
/// needs bytes for each span it produces; a store that could only hand back a
/// whole blob could not answer a partial one without copying it somewhere
/// first. `read` is asked for exactly `out.len` bytes and nothing else, which
/// is what lets the provider stream a span through one fixed buffer.
///
/// A vtable is a borrowed view: the store behind `ctx` is the caller's, is never
/// dereferenced here, and has to stay alive and unmoved for every call made
/// through the handle.
pub const Store = struct {
    /// The store's own method set, borrowed.
    vtable: *const VTable,
    /// The store value behind this handle, borrowed and reinterpreted.
    ctx: *anyopaque,

    pub const VTable = struct {
        /// The blob's size in bytes, which is what a spec is resolved against
        /// and what the answer is clipped at.
        size: *const fn (ctx: *anyopaque, hash: [32]u8) StoreError!u64,
        /// Fill `out` with the blob's bytes from `start`. Exactly `out.len`
        /// bytes; a shorter blob at that offset is `error.OutOfRange`.
        read: *const fn (ctx: *anyopaque, hash: [32]u8, start: u64, out: []u8) StoreError!void,
    };

    pub fn size(self: Store, hash: [32]u8) StoreError!u64 {
        return self.vtable.size(self.ctx, hash);
    }

    pub fn read(self: Store, hash: [32]u8, start: u64, out: []u8) StoreError!void {
        return self.vtable.read(self.ctx, hash, start, out);
    }
};

/// The bao decode a getter runs an answer through.
///
/// **Bytes in, one answer out.** The decoder holds the root hash the answer is
/// checked against, so `verified` is a question only it can answer, and it is
/// asked once the provider has ended the stream rather than after every feed:
/// a preorder answer is short until it is whole, and a decoder asked "is this
/// done yet" mid-stream would be asked a question about bytes that have not
/// arrived.
pub const Decoder = struct {
    /// The decoder's own method set, borrowed.
    vtable: *const VTable,
    /// The decoder value behind this handle, borrowed and reinterpreted.
    ctx: *anyopaque,

    pub const VTable = struct {
        /// Take the next bytes of an answer, in the order they arrived. Bytes
        /// are handed over in whole runs and never re-handed: each call gets
        /// what the last one did not take.
        feed: *const fn (ctx: *anyopaque, bytes: []const u8) Error!void,
        /// Whether what has been fed proves the blob against the root hash this
        /// decoder was built for.
        verified: *const fn (ctx: *anyopaque) bool,
    };

    pub fn feed(self: Decoder, bytes: []const u8) Error!void {
        return self.vtable.feed(self.ctx, bytes);
    }

    pub fn verified(self: Decoder) bool {
        return self.vtable.verified(self.ctx);
    }
};

/// How many `(delta, spec)` pairs, widths, hashes and boundaries one decode may
/// fill.
///
/// A bound rather than an allocator, for the reason `protocol.Storage` is
/// caller-owned: nothing in a blobs transfer is unbounded on this side, and a
/// peer that names more than this is refused with the codec's own
/// `error.BufferFull` rather than being given room. A whole-blob request names
/// two pairs and no widths, so this is room for a range sequence and a little
/// over.
pub const decode_slots = 32;

/// Room for one encoded request.
///
/// A whole-blob `get` is 39 bytes, and everything past that is widths at one
/// varint each, so this holds a request of a few hundred ranges. A request this
/// file cannot encode is `error.BufferFull` from the writer, and it is refused
/// before a stream is opened.
pub const max_frame = 512;

/// A provider: one connection's worth of `get`s, answered from a store.
///
/// **One stream at a time, and that is a bound rather than a limitation.** A
/// getter opens a stream per request, so a second one means a second transfer
/// the store has to answer too; taking streams in order and finishing each
/// before taking the next is what keeps a pass's work proportional to one
/// transfer instead of to every stream the peer has opened.
///
/// The decode scratch is a field rather than a local because the span walk
/// reads the widths for as long as it runs, and the walk outlives the decode:
/// a request is decoded once and answered over as many passes as it takes.
pub const Provider = struct {
    /// Where the answers come from, borrowed.
    store: Store,
    /// The node's allocator: the stream was made with it and `Stream.drain`
    /// hands its chunks to the allocator that made the stream, so this is not
    /// a choice this file gets to make.
    gpa: std.mem.Allocator,
    /// What the peer has written, accumulated across passes. Cleared per
    /// stream with its capacity kept, because a request is the whole stream and
    /// the next one is the same size.
    inbox: std.ArrayList(u8) = .empty,
    /// Decode scratch, for the reasons above. `protocol.Storage` borrows these
    /// for the length of the decode and the walk borrows the widths.
    pairs: [decode_slots]range_spec.Item = @splat(.{ .delta = 0, .spec = .empty }),
    widths: [decode_slots]u64 = @splat(0),
    hashes: [decode_slots][32]u8 = @splat(@splat(0)),
    boundaries: [decode_slots]u64 = @splat(0),
    /// The blob a request named, its size, and where the answer has got to.
    hash: [32]u8 = @splat(0),
    size: u64 = 0,
    spans: range_spec.SpanIter = undefined,
    /// The span being written and the bytes of it already written.
    cursor: u64 = 0,
    limit: u64 = 0,
    /// The stream in flight, and the id of the last one taken: `peerStream`'s
    /// cursor, which is null until something has been taken because a peer's
    /// first bidirectional stream can be id zero.
    stream: ?quic_stream.Stream = null,
    after: ?u64 = null,
    state: enum { reading, sending, answered } = .reading,
    /// One pass's budget of answer, and the buffer a store read fills. A store
    /// read copies into a buffer the provider owns because the store's bytes
    /// may be its own storage and `Stream.write` copies again out of here.
    scratch: [@as(usize, chunk.block_size)]u8 = undefined,

    pub fn init(store: Store, gpa: std.mem.Allocator) Provider {
        return .{ .store = store, .gpa = gpa };
    }

    pub fn deinit(self: *Provider) void {
        self.inbox.deinit(self.gpa);
        self.stream = null;
    }

    /// One pass over one connection: take the next peer stream if there is
    /// nothing in flight, then read, answer or keep answering it.
    ///
    /// `.finished` means no stream is in flight *and* the connection is
    /// closing, which is the node's own rule for ending an accept
    /// (`node_protocol.Turn`). A connection with nothing on it is not
    /// finished: a peer that has asked nothing yet gets `.more`.
    pub fn step(self: *Provider, conn: node_protocol.Connection) Error!Turn {
        if (self.stream == null) {
            const taken = conn.peerStream(self.after) orelse
                return if (conn.closed()) .finished else .more;
            self.after = taken.id();
            self.stream = taken;
            self.begin();
        }
        const stream = &self.stream.?;
        switch (self.state) {
            .reading => {
                _ = try stream.drain(self.gpa, &self.inbox);
                // Nothing is decoded off a stream that has not ended. A `get`
                // *is* the whole stream (`protocol.EofFraming`), so a body
                // decoded early would be a body decoded wrong, and a `push`
                // decoded before its payload arrived would be a length read
                // against bytes that are not there yet.
                if (!stream.finished()) return .more;
                try self.answer();
                // A request that was answered with bytes has an answer to
                // write, and writing it is the next pass's work: falling
                // through here would close a stream the store never read.
                if (self.state == .sending) return .more;
            },
            // A turn's budget spent is not the end of the answer; the span walk
            // keeps the position and the next pass picks it up where it stopped.
            .sending => if (try self.send(stream)) return .more,
            .answered => {},
        }
        stream.close();
        self.stream = null;
        return .more;
    }

    /// Start a stream: nothing read, nothing planned.
    fn begin(self: *Provider) void {
        self.inbox.clearRetainingCapacity();
        self.state = .reading;
        self.size = 0;
        self.cursor = 0;
        self.limit = 0;
    }

    /// Decode the request that has just ended, and plan the answer for it.
    fn answer(self: *Provider) Error!void {
        var storage = protocol.Storage{
            .items = self.pairs[0..],
            .widths = self.widths[0..],
            .hashes = self.hashes[0..],
            .boundaries = self.boundaries[0..],
        };
        var reader = postcard.Reader.init(self.inbox.items);
        const request = try protocol.Request.read(&reader, &storage);
        var get: ?protocol.GetRequest = null;
        switch (request) {
            .to_eof => |body| switch (body) {
                .get => |value| get = value,
                .get_many, .observe => {},
            },
            .length_prefixed => {},
        }
        if (get == null or get.?.ranges.items.len == 0) {
            // Not served, and the protocol has no way to say so. A `get_many`
            // asks for unrelated blobs and an `observe` opens an availability
            // run, neither of which this build answers; a `push` carries data
            // this store is not asked to absorb. All three are closed with
            // nothing written, which is `BaoResponse`'s EOF and which the
            // getter's decoder can tell from a whole empty blob.
            self.state = .answered;
            return;
        }
        // One spec, for the blob itself. A sequence's later pairs name the
        // children of a collection, and this store answers one blob.
        var walk = get.?.ranges.iter();
        const spec = walk.next().?;
        self.hash = get.?.hash;
        self.size = self.store.size(self.hash) catch |err| switch (err) {
            error.UnknownBlob => {
                self.state = .answered;
                return;
            },
            error.OutOfRange => return error.OutOfRange,
        };
        self.spans = spec.resolve(chunk.chunkAfterByte(self.size));
        self.state = .sending;
    }

    /// Write up to `block_size` of the answer. False when the walk is spent.
    ///
    /// **A span is clipped at the blob's real length, and the clip is
    /// required.** `chunksToBytes` is exact only for a whole number of chunks,
    /// so a blob whose length is not a multiple of 1024 has a short last chunk
    /// and the arithmetic answers one byte-range past the end of it.
    fn send(self: *Provider, stream: *quic_stream.Stream) Error!bool {
        var budget: u64 = chunk.block_size;
        while (budget > 0) {
            if (self.cursor >= self.limit) {
                const span = self.spans.next() orelse return false;
                const bytes = chunk.chunksToBytes(.{
                    .start = span.offset,
                    .end = span.offset +| span.size,
                });
                self.cursor = @min(bytes.start, self.size);
                self.limit = @min(bytes.end, self.size);
                // A span past the end of the blob covers nothing, and skipping
                // it is the whole of what an out-of-range span does here.
                if (self.cursor >= self.limit) continue;
            }
            const take: usize = @intCast(@min(budget, self.limit - self.cursor));
            try self.store.read(self.hash, self.cursor, self.scratch[0..take]);
            _ = try stream.write(self.scratch[0..take]);
            self.cursor += take;
            budget -= take;
        }
        return true;
    }
};

/// A getter: one transfer, from asking to the provider's last byte.
///
/// **The request is written once and the answer is read in whole.** The request
/// frame is a field because it is written in `start` and read by the stream
/// before that call returns; the answer is accumulated because a provider's
/// answer has no length in front of it — it runs to the end of the stream, so
/// there is no point at which "the answer is complete" could be read off a
/// length the way a framed message's can.
pub const Getter = struct {
    /// The decode every byte of the answer goes through.
    decoder: Decoder,
    /// The node's allocator, for the reason `Provider.gpa` gives.
    gpa: std.mem.Allocator,
    /// The encoded request, written once by `start`.
    frame: [max_frame]u8 = undefined,
    /// What the provider has written, and how much of it the decoder has taken.
    inbox: std.ArrayList(u8) = .empty,
    fed: usize = 0,
    /// The stream the request went out on, and null once it has ended.
    stream: ?quic_stream.Stream = null,

    pub fn init(decoder: Decoder, gpa: std.mem.Allocator) Getter {
        return .{ .decoder = decoder, .gpa = gpa };
    }

    pub fn deinit(self: *Getter) void {
        self.inbox.deinit(self.gpa);
        self.stream = null;
    }

    /// Open a stream, put `request` on it, and stop writing.
    ///
    /// **The send half closes here, and that is the framing.** A `get` is the
    /// whole stream, so the request ends where this getter's writing does and
    /// not at a length; a provider that saw no FIN would be waiting for a
    /// request that has already arrived in full.
    pub fn start(
        self: *Getter,
        conn: node_protocol.Connection,
        request: protocol.GetRequest,
    ) Error!void {
        if (self.stream != null) return error.TransferInFlight;
        var writer = postcard.Writer.init(&self.frame);
        // The push arm's length-prefixed body scratch, which a `get` never
        // touches: the framing is chosen by the union arm above it.
        const no_body: [0]u8 = .{};
        try (protocol.Request{ .to_eof = .{ .get = request } }).write(&writer, &no_body);
        const frame = writer.finish();
        var stream = try conn.openStream();
        // A stream opened and never written is worse than none: it is a stream
        // the peer will wait on for a request that is not coming.
        errdefer stream.close();
        _ = try stream.write(frame);
        stream.close();
        self.stream = stream;
    }

    /// One pass. Null until the provider has ended its stream, which is the
    /// only moment an answer can be judged: before it, the bytes that arrived
    /// are a prefix of an answer nobody has finished sending.
    pub fn step(self: *Getter) Error!?Outcome {
        const stream = &(self.stream orelse return error.NoTransferInFlight);
        _ = try stream.drain(self.gpa, &self.inbox);
        // `BaoResponse` is the rest of the buffer, so this is every byte the
        // provider has written and `fed` is how much of them the decoder has
        // already taken. The bytes live in `inbox` because `drain` copies them
        // there: a decode borrows a run across passes, and the core's own chunk
        // is gone by the next read.
        var reader = postcard.Reader.init(self.inbox.items);
        const response = protocol.BaoResponse.read(&reader);
        const fresh = response.bytes[self.fed..];
        if (fresh.len > 0) {
            try self.decoder.feed(fresh);
            self.fed = response.bytes.len;
        }
        if (!stream.finished()) return null;
        self.stream = null;
        // An empty answer and a short one are the same thing here, and both are
        // `missing`: the decoder holds the root hash, so it is the only thing
        // in the tree that can say an empty blob is whole and anything else is
        // not.
        return if (self.decoder.verified()) .complete else .missing;
    }
};

/// What a finished transfer turned out to be.
pub const Outcome = enum {
    /// The answer proved the blob against the root hash the decoder holds.
    complete,
    /// The provider stopped writing without it: the answer covered less than
    /// the request asked for, or nothing at all.
    missing,
};
