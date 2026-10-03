//! CRYPTO-stream reassembly and buffering: one `CryptoStream` per encryption
//! level, held by `CryptoStreamManager` and reached through
//! `Connection.crypto_streams`. It reads no clock, draws no randomness and
//! opens nothing.
//!
//! Ownership is stated on the two methods that cross the boundary and
//! disagree: `read` returns bytes the caller owns and must free, and
//! `popCryptoFrame` returns a frame borrowing the stream's send buffer.

const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;

const Frame = @import("frame.zig").Frame;
const limits = @import("limits.zig");
const stream_mod = @import("stream.zig");
const FrameSorter = stream_mod.FrameSorter;

/// A crypto stream for TLS handshake data.
///
/// Unlike regular QUIC streams, crypto streams:
/// - Have no flow control
/// - Have no stream ID
/// - Exist at each encryption level (Initial, Handshake, 1-RTT)
/// - Carry CRYPTO frames instead of STREAM frames
///
/// Having no flow control is why no method here moves credit in either
/// direction: nothing is charged against a peer window, and nothing is
/// returned to one. The receive side's bound is the reassembly ceiling in
/// `handleCryptoFrame` instead.
///
/// The stream owns the reassembly chunks and the send buffer, both from the
/// allocator `init` was given, and one `deinit` releases them. `init` starts
/// with static empty storage, so a stream that has neither received nor
/// queued anything allocates nothing. Nothing here is safe to call from more
/// than the one thread holding the value.
pub const CryptoStream = struct {
    /// Retained at `init` and used to release the send buffer in `deinit`
    /// and to allocate it in `writeData`. The reassembly chunks behind
    /// `recv_sorter` were allocated from this same allocator, so `read`
    /// hands back bytes the caller must return to it.
    allocator: Allocator,

    /// Reassembly buffer for incoming CRYPTO frame data. Owns its chunks
    /// from `allocator`; `read` removes them from here and hands ownership to
    /// the caller, and `deinit` releases whatever is left.
    recv_sorter: FrameSorter,

    /// Outgoing data buffer, owned from `allocator` and never resized except
    /// by `writeData`. Every `send_offset` and `write_offset` counts bytes
    /// from its front, and a frame from `popCryptoFrame` points into it.
    send_buffer: std.ArrayList(u8),

    /// Byte offset into `send_buffer` of the next unsent byte. Bytes below
    /// it have already been handed to a packer; `resetSendOffset` moves it
    /// back to 0 and nothing else ever does.
    send_offset: u64 = 0,

    /// Total bytes ever queued through `writeData`, and so the end of the
    /// unsent region. Never decreases except when the whole stream is
    /// rebuilt, which is why a retransmission re-sends from `send_buffer[0]`
    /// rather than appending.
    write_offset: u64 = 0,

    /// Whether all incoming data has been received.
    ///
    /// Never written and never read: `init` sets it false and no method in
    /// this struct or in `CryptoStreamManager` consults it. A CRYPTO stream
    /// carries no FIN, so this is not the end-of-stream marker a caller might
    /// expect it to be — the handshake's own completion is what ends it.
    recv_complete: bool = false,

    /// A stream with no buffered data in either direction and nothing owed.
    /// The allocator is retained immediately; one `deinit` is owed whether or
    /// not the stream ever grew.
    pub fn init(allocator: Allocator) CryptoStream {
        return .{
            .allocator = allocator,
            .recv_sorter = FrameSorter.init(allocator),
            .send_buffer = .{ .items = &.{}, .capacity = 0 },
        };
    }

    /// Releases the reassembly chunks and the send buffer. Does not free
    /// `allocator`, and does not free anything `read` already handed out —
    /// those belong to the caller. The stream is unusable afterwards and a
    /// second call frees the same bytes twice.
    pub fn deinit(self: *CryptoStream) void {
        self.recv_sorter.deinit();
        self.send_buffer.deinit(self.allocator);
    }

    /// Buffers an incoming CRYPTO frame at `offset`. Reassembly is
    /// out-of-order: data past a gap is kept until the gap is filled, and
    /// overlapping or repeated bytes are absorbed. `data` is borrowed for the
    /// duration of the call and copied; nothing in the result points into it.
    ///
    /// `error.CryptoBufferExceeded` when the frame ends more than
    /// `limits.max_crypto_stream_offset` bytes past what TLS has already
    /// read. The check runs before the push, so nothing from this frame is
    /// buffered on that path and a retransmission of the same frame fails
    /// the same way.
    ///
    /// `error.TooManyChunks` when the peer leaves more holes than
    /// `limits.max_reassembly_chunks`; the frame is not buffered.
    /// `error.OutOfMemory` leaves the stream holding whatever it held before
    /// this call — the push either takes the chunk or does not — and the
    /// stream stays usable, so the peer may retransmit the frame.
    pub fn handleCryptoFrame(self: *CryptoStream, offset: u64, data: []const u8) !void {
        std.log.info("CryptoStream.handleCryptoFrame: offset={d} len={d}", .{ offset, data.len });
        // RFC 9000 7.5: CRYPTO frames are not flow controlled, so this ceiling
        // is the only thing bounding reassembly memory before the handshake
        // completes — and the peer is unauthenticated until it does. Measured
        // from what TLS has consumed, so a long-lived 1-RTT stream (session
        // tickets) never runs into it.
        if (offset + data.len > self.recv_sorter.read_pos + limits.max_crypto_stream_offset) {
            return error.CryptoBufferExceeded;
        }
        try self.recv_sorter.push(offset, data, false);
    }

    /// The next contiguous run of received handshake bytes, owned by the
    /// caller, or `null` when no run starts at the read position.
    ///
    /// The slice is a whole allocation from the allocator `init` was given
    /// and must be freed with that same allocator; it is not a view into the
    /// stream and stays valid after any later call on it. Successive calls
    /// hand back successive runs.
    ///
    /// `null` covers two states the caller cannot tell apart: nothing is
    /// ready, and a run was ready but could not be copied out because the
    /// allocator failed. The second case leaves the run buffered, so the
    /// next call may return it — there is no data loss either way, but a
    /// caller under memory pressure sees a stall rather than an error.
    pub fn read(self: *CryptoStream) ?[]const u8 {
        return self.recv_sorter.pop();
    }

    /// Copies `data` into the send buffer and counts it as queued. `data` is
    /// borrowed for the call only.
    ///
    /// `error.OutOfMemory` queues nothing and does not advance
    /// `write_offset`, so the caller's handshake data is simply not on its
    /// way and `error.OutOfMemory` may be retried with the same bytes.
    pub fn writeData(self: *CryptoStream, data: []const u8) !void {
        try self.send_buffer.appendSlice(self.allocator, data);
        self.write_offset += data.len;
    }

    /// Rewinds the send cursor to the start of the buffer so the same bytes
    /// are sent again, used after a Retry to re-send the same ClientHello.
    /// The bytes themselves are kept, so this cannot fail and cannot lose
    /// data; anything already written to the wire in this flight is sent a
    /// second time, and the packet numbers already spent are not returned.
    pub fn resetSendOffset(self: *CryptoStream) void {
        self.send_offset = 0;
    }

    /// Whether bytes are queued but not yet handed to a packer. Pure read:
    /// `popCryptoFrame` is what makes this false.
    pub fn hasData(self: *const CryptoStream) bool {
        return self.send_offset < self.write_offset;
    }

    /// Takes the next CRYPTO frame, carrying at most `max_len` bytes of
    /// payload, or `null` when nothing is unsent. `null` is also the answer
    /// for `max_len` of zero, which yields no payload and would carry no
    /// frame.
    ///
    /// The frame's `data` borrows the send buffer. It is invalidated by the
    /// next `writeData` (which may reallocate the buffer) and by `deinit`;
    /// `hasData` and `resetSendOffset` leave the bytes valid. The caller
    /// frees nothing — the bytes belong to the stream.
    ///
    /// The send cursor advances by the bytes carried, whether or not the
    /// frame is then written anywhere: a frame the caller drops is a run of
    /// handshake bytes that will not be offered again. Queue the frame or
    /// accept that loss.
    pub fn popCryptoFrame(self: *CryptoStream, max_len: u64) ?Frame {
        const unsent_len = self.write_offset - self.send_offset;
        if (unsent_len == 0) return null;

        const data_len = @min(unsent_len, max_len);
        const offset = self.send_offset;
        const data = self.send_buffer.items[@intCast(offset)..][0..@intCast(data_len)];

        self.send_offset += data_len;

        return Frame{
            .crypto = .{
                .offset = offset,
                .data = @constCast(data),
            },
        };
    }
};

/// Manages crypto streams for all three encryption levels.
///
/// Owns the three `CryptoStream` values it holds; one `deinit` releases all
/// of them, through the allocator each was given. Borrowed from
/// `Connection.crypto_streams`, and like a `CryptoStream` it is single
/// threaded.
pub const CryptoStreamManager = struct {
    /// Crypto stream for Initial encryption level.
    initial: CryptoStream,

    /// Crypto stream for Handshake encryption level.
    handshake: CryptoStream,

    /// Crypto stream for 1-RTT (Application) encryption level.
    one_rtt: CryptoStream,

    /// Three empty streams, one per encryption level, all sharing `allocator`.
    /// The allocator is retained immediately — by each of the three, which is
    /// why they must all be released together through this value's `deinit`
    /// rather than individually — and one `deinit` is owed whether or not
    /// any CRYPTO frame ever arrives.

    pub fn init(allocator: Allocator) CryptoStreamManager {
        return .{
            .initial = CryptoStream.init(allocator),
            .handshake = CryptoStream.init(allocator),
            .one_rtt = CryptoStream.init(allocator),
        };
    }

    /// Releases all three streams. Does not free the allocator, which the
    /// caller still owns. Every stream pointer previously returned by
    /// `getStream` dangles afterwards.
    pub fn deinit(self: *CryptoStreamManager) void {
        self.initial.deinit();
        self.handshake.deinit();
        self.one_rtt.deinit();
    }

    /// Get the crypto stream for the given encryption level index.
    /// EncryptionLevel enum: initial=0, early_data=1, handshake=2, application=3
    ///
    /// `1` is not a stream of its own: QUIC's early data is CRYPTO data at
    /// the Initial level, so that index returns `initial` as well. The
    /// returned pointer addresses the manager's own field and is invalidated
    /// by moving the manager; a caller that keeps one across a move must copy
    /// out of it first.
    ///
    /// A `level` above 3 reaches `unreachable`, which is a trap in every
    /// optimize mode, not a recoverable error. The bound is the
    /// `EncryptionLevel` enum: the caller must not pass anything else.
    pub fn getStream(self: *CryptoStreamManager, level: u8) *CryptoStream {
        return switch (level) {
            0 => &self.initial,       // initial
            1 => &self.initial,       // early_data (not used, reuse initial)
            2 => &self.handshake,     // handshake
            3 => &self.one_rtt,       // application (1-RTT)
            else => unreachable,
        };
    }

    /// Routes an incoming CRYPTO frame to the stream for `level` and buffers
    /// it there, with the same three reachable errors and the same
    /// left-behind state as `CryptoStream.handleCryptoFrame`. A `level`
    /// above 3 traps in `getStream`.
    pub fn handleCryptoFrame(self: *CryptoStreamManager, level: u8, offset: u64, data: []const u8) !void {
        const stream = self.getStream(level);
        try stream.handleCryptoFrame(offset, data);
    }
};

// Tests

// RFC 9000 §7.5: CRYPTO is not flow controlled, so the buffer has its own cap.
test "CryptoStream: rejects data past the crypto buffer ceiling" {
    var cs = CryptoStream.init(testing.allocator);
    defer cs.deinit();

    try testing.expectError(
        error.CryptoBufferExceeded,
        cs.handleCryptoFrame(limits.max_crypto_stream_offset, "x"),
    );
    try cs.handleCryptoFrame(0, "hello");
}

test "CryptoStream: the ceiling moves with what TLS has consumed" {
    var cs = CryptoStream.init(testing.allocator);
    defer cs.deinit();

    const chunk = [_]u8{0} ** 4096;
    const cap = limits.max_crypto_stream_offset;
    var off: u64 = 0;
    while (off < cap) : (off += chunk.len) try cs.handleCryptoFrame(off, &chunk);
    // Full: nothing past the window until the TLS stack reads.
    try testing.expectError(error.CryptoBufferExceeded, cs.handleCryptoFrame(cap, "x"));
    while (cs.read()) |d| testing.allocator.free(d);
    try cs.handleCryptoFrame(cap, &chunk);
    // Still bounded ahead of the read position.
    try testing.expectError(error.CryptoBufferExceeded, cs.handleCryptoFrame(2 * cap, "x"));
}

test "CryptoStream: write and pop" {
    var cs = CryptoStream.init(testing.allocator);
    defer cs.deinit();

    try cs.writeData("ClientHello");
    try testing.expect(cs.hasData());

    const frame = cs.popCryptoFrame(100);
    try testing.expect(frame != null);
    switch (frame.?) {
        .crypto => |c| {
            try testing.expectEqual(@as(u64, 0), c.offset);
            try testing.expectEqualSlices(u8, "ClientHello", c.data);
        },
        else => unreachable,
    }

    try testing.expect(!cs.hasData());
}

test "CryptoStream: receive and read" {
    var cs = CryptoStream.init(testing.allocator);
    defer cs.deinit();

    try cs.handleCryptoFrame(0, "ServerHello");

    const data = cs.read();
    try testing.expect(data != null);
    try testing.expectEqualStrings("ServerHello", data.?);
    testing.allocator.free(data.?);
}

test "CryptoStream: out-of-order receive" {
    var cs = CryptoStream.init(testing.allocator);
    defer cs.deinit();

    // Receive second part first
    try cs.handleCryptoFrame(5, "World");
    try testing.expect(cs.read() == null);

    // Receive first part: it joins the run already buffered after it.
    try cs.handleCryptoFrame(0, "Hello");
    const data = cs.read();
    try testing.expect(data != null);
    try testing.expectEqualStrings("HelloWorld", data.?);
    testing.allocator.free(data.?);
    try testing.expect(cs.read() == null);
}

test "CryptoStreamManager: route to correct stream" {
    var csm = CryptoStreamManager.init(testing.allocator);
    defer csm.deinit();

    try csm.handleCryptoFrame(0, 0, "Initial");
    try csm.handleCryptoFrame(2, 0, "Handshake");
    try csm.handleCryptoFrame(3, 0, "OneRTT");

    const d1 = csm.initial.read();
    try testing.expect(d1 != null);
    try testing.expectEqualStrings("Initial", d1.?);
    testing.allocator.free(d1.?);

    const d2 = csm.handshake.read();
    try testing.expect(d2 != null);
    try testing.expectEqualStrings("Handshake", d2.?);
    testing.allocator.free(d2.?);

    const d3 = csm.one_rtt.read();
    try testing.expect(d3 != null);
    try testing.expectEqualStrings("OneRTT", d3.?);
    testing.allocator.free(d3.?);
}
