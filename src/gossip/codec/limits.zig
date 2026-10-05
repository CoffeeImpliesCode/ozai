//! Every number this codec answers with, and every way a peer can make it
//! refuse.
//!
//! The byte budget, the widest a length prefix or a stream header can be, the
//! largest one `IHave` can occupy, the two widths postcard writes a tag at, and
//! `Error` live together because they are one contract stated five ways: what a
//! frame may weigh, and what is said when it may not.
//!
//! The protocol-wide story — the tags, the framing, the stream header and every
//! divergence from upstream — is in `../codec.zig`, which is the module callers
//! import. This file is one piece of it.

const std = @import("std");

const gossip = @import("../hyparview.zig");
const key = @import("../../base/key.zig");
const plumtree = @import("../plumtree.zig");
const postcard = @import("../../wire/postcard.zig");

const id_length = plumtree.id_length;
const topic_id_length = gossip.topic_id_length;

/// Every way a gossip frame can fail to encode or decode.
///
/// `postcard.Error` and `key.KeyError` are included rather than restated: a
/// varint that never ends and a peer id that is not a point are both refusals a
/// peer can provoke, and a second name for either would be a caller learning the
/// same rule twice. The two protocol error sets are in for the same reason — a
/// peer list over `max_shuffle_nodes` is `error.ShuffleNodeListTooLong`, named by
/// the module that owns the bound rather than by this one.
pub const Error = postcard.Error || key.KeyError || gossip.Error || plumtree.Error || error{
    /// A message body over `max_message_size`.
    FrameTooLarge,
    /// A stream header body that is not exactly `topic_id_length` bytes.
    BadHeaderSize,
    /// A byte budget too small for one `IHave`, so a caller cutting a list with
    /// `chunk.chunkLen` would not advance.
    ChunkBudgetTooSmall,
};

/// The most bytes one message body may occupy. Upstream's
/// `DEFAULT_MAX_MESSAGE_SIZE` (`proto.rs:66`).
///
/// **The budget is on the body and not on the frame.** It is upstream's own
/// measure: `write_frame` compares `postcard::experimental::serialized_size`
/// against it (`net/util.rs:379`) and `read_lp` compares the length it read
/// (`net/util.rs:384`), and neither counts the length prefix in front of the
/// body. That prefix is postcard's, at most `max_prefix_size` bytes, so a frame
/// this codec writes is at most `max_message_size + max_prefix_size` bytes on
/// the wire.
///
/// **It is an inclusive ceiling, and upstream's two sides disagree by one
/// frame.** Upstream writes `if len >= max_message_size { TooLarge }` and reads
/// `if size > max_message_size { TooLarge }`, so a body of exactly the budget is
/// refused on the way out and admitted on the way in. One number has to be
/// chosen here and it is the reader's, because the reader's is the one a peer
/// obeys: a frame this codec writes is then a frame upstream's read side accepts.
/// `chunk.chunkLen` budgets against this number, so a list it cuts is a list
/// that can be sent.
pub const max_message_size: usize = 4096;

/// The smallest budget a configuration may set. Upstream's
/// `MIN_MAX_MESSAGE_SIZE` (`proto.rs:69`), which its `State::new` asserts.
///
/// Nothing here reads it: the budget is an argument of `encode` and of
/// `chunk.chunkLen`, and the default above is what a caller with no configured
/// budget gets. It is written down so a caller validating a configured budget
/// validates it against upstream's floor rather than against a number of its
/// own.
pub const min_message_size: usize = 512;

/// The widest a frame's length prefix can be: a postcard `varint(u64)`.
pub const max_prefix_size: usize = postcard.varintMax(u64);

/// The widest a stream header frame can be: its prefix and its topic id.
pub const max_header_size: usize = max_prefix_size + topic_id_length;

/// Every discriminant on this wire, and the `Option` tag postcard writes, are
/// below 128, so a `varint(u32)` tag and a raw byte are the same byte for every
/// value that exists.
///
/// `blobs/framing.zig` argues the same point for its own table from the other
/// side, and it is why `wire/postcard.zig` may read a tag with `readVariant` and
/// get one byte back. It is also why a byte with the top bit set is a
/// discriminant this build does not have and not a truncated varint.
pub const tag_length: usize = 1;

/// The `Option` tag: `wire/postcard.zig` writes it as one raw byte, 0 for none
/// and 1 for some, and `Neighbor.data`, `Join`'s payload, `Graft.id` and every
/// `PeerInfo.data` are the four places it appears.
pub const option_length: usize = 1;

/// The most bytes one `IHave` occupies inside a `Message::IHave`: a 32-byte id
/// and a `u16` round, which postcard varints in at most three.
///
/// Upstream cuts its `IHave` batches with this number —
/// `(max_message_size - 3) / IHave::POSTCARD_MAX_SIZE` (`plumtree.rs:454-459`),
/// and `MaxSize` derives 35 for it, 32 + 3. `chunk.chunkLen` uses it to refuse a
/// budget that cannot hold one entry before it looks at any; the cut itself is
/// made against the encoded body, which is exact where 35 is an upper bound.
pub const ihave_max_size: usize = id_length + postcard.varintMax(u16);

/// The bytes a length-prefixed byte string occupies: its length prefix and its
/// bytes.
///
/// postcard gives a `Vec`, a `String` and a `Bytes` these same three parts, so a
/// `Shuffle`'s peer list, a `Graft`'s id and a `Gossip`'s content are all this.
pub fn byteStringLen(bytes: []const u8) usize {
    return varintLen(bytes.len) + bytes.len;
}

/// The canonical length of the postcard varint `wire/postcard.zig` writes for
/// `value`: one byte per seven bits, low bits first, and no more.
///
/// `encodedLen` is the byte count `encode` writes, so this has to be the
/// encoder's own rule and not a second spelling of it. A length that disagreed
/// with the bytes in front of the payload would make every buffer a caller sizes
/// from `encodedLen` the wrong size, and the fault would land on the peer
/// rather than here.
pub fn varintLen(value: anytype) usize {
    const Unsigned = @TypeOf(value);
    comptime std.debug.assert(@typeInfo(Unsigned) == .int);
    comptime std.debug.assert(@typeInfo(Unsigned).int.signedness == .unsigned);
    var rest: u64 = @intCast(value);
    var length: usize = 1;
    while (rest >= 0x80) : (length += 1) {
        rest >>= 7;
    }
    return length;
}
