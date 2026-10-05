//! The gossip wire codec: one postcard encoding for the membership layer and
//! the broadcast layer, framed for a stream.
//!
//! This file is the module callers import and it holds no logic: every name
//! below is re-exported from the sibling that owns it, so nothing outside
//! `src/gossip/codec/` and this file has to know how the split goes.
//!
//! - `codec/limits.zig` — the byte budget, the fixed widths, the size rules, and
//!   every way a frame is refused.
//! - `codec/tags.zig` — the four tag tables, in upstream's declaration order,
//!   with the comptime proof that keeps them and the Zig unions in step.
//! - `codec/membership.zig` — the six `hyparview` messages.
//! - `codec/broadcast.zig` — the four `plumtree` messages.
//! - `codec/frame.zig` — the length prefix, the layer tag, and the stream header.
//! - `codec/chunk.zig` — the byte-budget cut of an `IHave` list.
//!
//! # What a stream is
//!
//! ```
//! stream := header_frame message_frame*
//! frame  := varint(u64) body_length ++ body
//! header := varint(u64) 32 ++ topic_id[32]
//! body   := varint(u32) layer ++ arm
//! ```
//!
//! The prefix is postcard's own length-prefixed byte string — `writeLen` and
//! `readBytes` in `wire/postcard.zig` — and not a width invented here. The topic
//! travels once, in the header, exactly as upstream's `StreamHeader` does
//! (`net/util.rs:53-55`, written at `net/util.rs:299-310`), so every payload
//! after it is 32 bytes shorter than a frame that repeated the topic.
//!
//! # The tags are upstream's declaration order, and nothing else may be
//!
//! postcard writes a discriminant as the index its declaration gives the
//! variant, so the numbering is the wire. From `n0-computer/iroh-gossip` at
//! commit `2885dd9f1120e46aca5acbcd7f212e4c64e278b9`:
//!
//! | Table | Tags | Upstream |
//! |---|---|---|
//! | layer | `swarm` 0, `gossip` 1 | `proto/topic.rs:92-97` |
//! | membership | `join` 0 … `disconnect` 5 | `proto/hyparview.rs:68-93` |
//! | broadcast | `gossip` 0, `prune` 1, `graft` 2, `i_have` 3 | `proto/plumtree.rs:129-141` |
//! | priority | `high` 0, `low` 1 | `proto/hyparview.rs:129-136` |
//! | scope | `swarm` 0, `neighbors` 1 | `proto/plumtree.rs:172-181` |
//!
//! Every discriminant is below 128, so the `varint(u32)` postcard writes and the
//! raw byte a reader might expect are the same byte for every tag that exists;
//! `codec/limits.zig` says what follows from that. A tag with no declared arm is
//! `error.UnknownVariant`, refused by `wire/postcard.zig` before any payload is
//! read: nothing is skipped and nothing is defaulted.
//!
//! # The `Disconnect` byte the Zig type does not have
//!
//! Upstream's `Disconnect` is `{ alive: bool, _respond: bool }`, the second field
//! marked "obsolete … kept in the struct to maintain wire compatibility"
//! (`hyparview.rs:168-175`) and written `false` by every sender
//! (`hyparview.rs:380`). The Zig `Disconnect` has one field, and
//! `hyparview/message.zig` says what follows from that: "When the codec lands,
//! the byte goes in." It goes in — `membership.respond_byte` is what is written,
//! and a decoder reads the byte and drops it, because a field nothing reads is a
//! field a receiver would otherwise have to work out the meaning of.
//!
//! # `IHave` batches are cut by bytes
//!
//! `chunk.chunkLen` measures each candidate chunk with the same `encodedLen` the
//! encoder writes with, so the cut and the frame cannot disagree. Upstream
//! divides the budget by a per-entry constant instead (`plumtree.rs:454-459`),
//! which is an upper bound rather than a size; `plumtree.zig` records the
//! divergence and the reason, and the reason is this file.
//!
//! # This is not `test/protocol_codec.zig`, and it is not the same bytes
//!
//! The harness codec in `test/protocol_codec.zig` is a second, local encoding, and
//! its own doc says so: "they are **not** the project's wire format — they are
//! one plausible encoding". **It is not byte-compatible with this codec**, in
//! two places and two places only:
//!
//! 1. **`DeliveryScope` is numbered the other way round.** That file declares
//!    `scope_neighbors: u8 = 0` and `scope_swarm: u8 = 1`; upstream declares
//!    `Swarm` first (`plumtree.rs:174`) and so does `codec/tags.zig`. Every
//!    `Gossip` message differs in the byte after its content, and nothing else in
//!    the broadcast layer differs.
//! 2. **`Disconnect` is one byte shorter.** That file writes `alive` alone, so
//!    its frame leaves the obsolete byte for a reader to trip over, and this
//!    codec's frame read by that file decodes and drops it, because that file
//!    never checks for a trailing byte.
//!
//! Everything else is the same byte for the same message: the framing (both use
//! postcard's length prefix), the two layer tags, the six membership tags, the
//! four broadcast tags, the two priority tags, and the field order and widths of
//! every payload. The difference is not an accident — that file numbers its
//! discriminants to be stable against edits in `src/gossip/`, which is the same
//! job `codec/tags.zig`'s comptime proof does, and it had no second reason to
//! pin them to upstream. This codec has the second reason.
//!
//! # Nothing here has been checked against bytes from the reference
//!
//! **No byte of this codec has been captured from the Rust implementation, and
//! this file makes no interoperability claim.** Every tag, field order, the
//! stream header and the obsolete byte are read off the sources cited above; the
//! encodings are postcard's rules as `wire/postcard.zig` states them. That is a
//! derivation, and `AGENTS.md` §2 is explicit that a claim of interoperability is
//! a golden-vector test carrying bytes captured from the Rust implementation or
//! it is an unverified claim. The byte sequences in `codec_test.zig` are
//! *declared* vectors: they are what these declarations have to produce, asserted
//! so that a later edit to a table cannot move them silently, and they are not
//! evidence about upstream.
//!
//! Three things would close the gap, in this order:
//!
//! 1. **Captured vectors.** A Rust program at the commit above that builds one
//!    message of every arm and prints `postcard::to_stdvec` of it, beside
//!    `plumtree/blake3_vectors.zig` as `codec_vectors.zig`, each vector naming
//!    the file and line it came from. That is the only thing that turns the tag
//!    and field tables above from a derivation into a test, and it would also
//!    settle the one assumption this codec cannot check for itself: that
//!    upstream's `PeerIdentity` — `PublicKey` — postcard-encodes as 32 raw bytes,
//!    which is what `NodeId` is and what no source in this tree proves.
//! 2. **The frame prefix.** Upstream's is a fixed four-byte big-endian `u32`
//!    (`net/util.rs:369`, `:392`); this one is postcard's varint, because that is
//!    the framing `wire/postcard.zig` implements and the instruction for this
//!    codec was to reuse it rather than add a second one. A peer from the
//!    reference cannot read these frames whatever the vectors say, so closing
//!    this means deciding the prefix is a wire change and not a codec detail.
//! 3. **The one-frame budget disagreement.** Upstream writes `if len >=
//!    max_message_size` and reads `if size > max_message_size`
//!    (`net/util.rs:379`, `:384`), so a body of exactly the budget is refused on
//!    the way out and admitted on the way in. `codec/limits.zig` takes the
//!    reader's rule; a peer that wrote such a frame would be refused by upstream
//!    and is not refused here.
//!
//! Until all three are done, this codec is a second implementation of the same
//! declarations and nothing more.

const chunk = @import("codec/chunk.zig");
const frame = @import("codec/frame.zig");
const gossip = @import("hyparview.zig");
const limits = @import("codec/limits.zig");
const membership = @import("codec/membership.zig");
const tags = @import("codec/tags.zig");

/// Every way a frame can fail to encode or decode.
pub const Error = limits.Error;

/// A message, whichever layer it belongs to. Upstream `proto::topic::Message`,
/// and it is `hyparview.Message` rather than a second vocabulary: the codec
/// reuses the state machines' own types and adds no type of its own here.
pub const Message = gossip.Message;

/// The four tag tables, in upstream's declaration order.
pub const Layer = tags.Layer;
pub const Swarm = tags.Swarm;
pub const Tree = tags.Tree;
pub const Priority = tags.Priority;
pub const Scope = tags.Scope;

/// The topic a stream carries, written once as the first frame on it.
pub const StreamHeader = frame.StreamHeader;
pub const encodeStreamHeader = frame.encodeStreamHeader;
pub const decodeStreamHeader = frame.decodeStreamHeader;

/// The bytes a body occupies, and the body itself: a length prefix followed by
/// the layer tag and the arm.
pub const encodedLen = frame.encodedLen;
pub const encode = frame.encode;
pub const encodeBody = frame.encodeBody;
pub const decode = frame.decode;
pub const decodeBody = frame.decodeBody;

/// The most bytes one message body may occupy, and the smallest budget a
/// configuration may set. See `codec/limits.zig`.
pub const max_message_size = limits.max_message_size;
pub const min_message_size = limits.min_message_size;

/// The widest a frame or a stream header can be, for a caller sizing a buffer.
pub const max_prefix_size = limits.max_prefix_size;
pub const max_header_size = limits.max_header_size;

/// The smallest budget `chunkLen` will cut against: the smallest body one
/// `IHave` can occupy in one frame.
pub const min_chunk_size = chunk.min_chunk_size;

/// What the obsolete second field of a `Disconnect` is written as, which is
/// upstream's `false` and a byte the Zig type does not hold.
pub const respond_byte = membership.respond_byte;

/// How many `IHave`s fit in one frame under a byte budget.
pub const chunkLen = chunk.chunkLen;
