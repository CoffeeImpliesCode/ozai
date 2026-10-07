//! The bytes every relay-frame test names: the hexdumps upstream wrote, the
//! node id they carry, and the helpers that read one.
//!
//! **Test support, and nothing else.** It sits under `frame_writer.zig`,
//! `frame_types.zig`, `frame_encode.zig`, `frame_decode.zig` and
//! `frame_roundtrip.zig` so that none of them has to own the captured vectors
//! and none of them imports another, and it imports nothing from the relay
//! except `base/key.zig`, which is what derives the node id the dumps carry.
//!
//! Every hexdump here is copied out of `iroh-relay/src/protos/relay.rs` at
//! commit 187f59e80afdae6bd9866002b33d3365c00b06d8, out of the two snapshot
//! tests in its `mod tests`: `test_relay_client_frames_snapshot` at `relay.rs:612`
//! for the frames the relay sends and `test_client_relay_frames_snapshot` at
//! `relay.rs:704` for the frames a client sends. Upstream strips the whitespace
//! out of its own hexdumps before decoding them (`relay.rs:592`), so the spacing
//! here is ours and the bytes are theirs.
//! The native ClientAuth fixture is source-derived, not a captured hexdump:
//! iroh-relay 1.3.0 `handshake.rs:88-96` uses `serde_bytes` for its signature,
//! and `handshake.rs:561` writes the struct with `postcard::to_io`.

const std = @import("std");

const key = @import("../base/key.zig");

const NodeId = key.NodeId;

/// The node id every captured vector carries.
///
/// Both snapshot tests build their frames from `SecretKey::from_bytes(&[42u8;
/// 32])` (`relay.rs:610` and `relay.rs:702`), and an ed25519 secret key is a
/// seed, so this is the same derivation. "golden: the captured node id is seed
/// [42]" is what holds that claim to the bytes.
pub fn captureKey() !key.SecretKey {
    return key.SecretKey.fromSeed([_]u8{42} ** key.SecretKey.seed_length);
}

pub fn captureId() !NodeId {
    var secret = try captureKey();
    defer secret.deinit();
    return secret.nodeId();
}

/// The contents of every captured datagram frame, and twelve bytes: two datagrams
/// at the six-byte segment size upstream chose.
pub const hello_world = "Hello World!";

/// The node id as upstream's hexdumps spell it, in two halves because 64 hex
/// digits do not fit on one line under a hundred columns.
pub const id_hex = "197f6b23e16c8532c6abc838" ++ "facd5ea789be0c76b2920334039bfa8b3d368d61";

/// 32 bytes of `ff`: a compressed ed25519 point whose `y` is `2^255 - 1`, past
/// the field modulus, so `NodeId.fromBytes` rejects it.
pub const non_canonical_id_hex = "ff" ** 32;

/// Source-derived native authentication bytes, independent of the relay encoder.
/// iroh-base 1.3.0 `key.rs:78-87` serializes the public key as a raw array;
/// `serde_bytes` serializes the signature as postcard length 0x40 then 64 bytes.
/// The signature is deterministic local test data, not an upstream capture.
pub fn nativeClientAuth() ![98]u8 {
    var secret = try captureKey();
    defer secret.deinit();
    var bytes: [98]u8 = undefined;
    bytes[0] = 0x01;
    @memcpy(bytes[1..33], &secret.nodeId().toBytes());
    bytes[33] = 0x40;
    @memcpy(bytes[34..98], &secret.sign("a message no peer has sent").toBytes());
    return bytes;
}

/// Covers the captured hexdumps and the largest authentication frame tested here:
/// ClientAuth is 98 bytes; ServerDeniesAuth.max_frame_length is 258.
pub const scratch_len = 512;

pub fn expectEqualStringsSlices(a: []const u8, b: []const u8) !void {
    if (std.mem.eql(u8, a, b)) return;
    return error.WireFormatMismatch;
}

/// How many datagrams `contents` holds at a segment size, for the tests that need
/// the number upstream never puts on the wire. A QUIC socket derives it the same
/// way: everything but the last datagram is exactly one segment.
pub fn datagramsIn(contents: []const u8, segment_size: usize) usize {
    if (segment_size == 0 or contents.len == 0) return 0;
    return 1 + @divFloor(contents.len - 1, segment_size);
}

/// The bytes a hexdump above stands for, decoded into `out`. A hexdump needs no
/// allocator: every one of them lands in a scratch buffer the test already has.
pub fn parseHex(out: []u8, hex: []const u8) ![]const u8 {
    var clean: [256]u8 = undefined;
    var length: usize = 0;
    for (hex) |c| {
        if (std.ascii.isWhitespace(c)) continue;
        if (length == clean.len) return error.HexdumpTooLong;
        clean[length] = c;
        length += 1;
    }
    if (length % 2 != 0) return error.OddHexLength;
    return std.fmt.hexToBytes(out, clean[0..length]);
}

/// Long enough for every hexdump a failure prints, and a diagnostic rather than a
/// general formatter: the bytes it prints are the ones written down in this file.
const max_dumped_bytes = 80;

pub fn expectHex(expected: []const u8, actual: []const u8) !void {
    if (std.mem.eql(u8, expected, actual)) return;
    std.debug.print("expected {d} bytes: {s}\n     got {d} bytes: {s}\n", .{
        expected.len, &hexdump(expected),
        actual.len,   &hexdump(actual),
    });
    return error.WireFormatMismatch;
}

fn hexdump(bytes: []const u8) [2 * max_dumped_bytes]u8 {
    var out: [2 * max_dumped_bytes]u8 = undefined;
    const digits = "0123456789abcdef";
    const shown = @min(bytes.len, max_dumped_bytes);
    for (bytes[0..shown], 0..) |byte, index| {
        out[index * 2] = digits[byte >> 4];
        out[index * 2 + 1] = digits[byte & 15];
    }
    @memset(out[shown * 2 ..], ' ');
    return out;
}
