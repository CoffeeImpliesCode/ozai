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
//! frame  := u32be body_length ++ body
//! header := u32be 32 ++ topic_id[32]
//! body   := varint(u32) layer ++ arm
//! ```
//!
//! The frame length is fixed four-byte big-endian, as pinned upstream
//! `net/util.rs::read_lp` and `write_frame` require. Internal fields retain
//! postcard encoding. The topic travels once in the stream header; each later
//! body contains only the nested topic message.
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
//! Upstream retains `_respond` for wire compatibility and always sends false.
//! The codec writes that byte and consumes it on receive; membership state
//! carries only `alive`, because the obsolete field has no behavior.
//!
//! # `IHave` batches are cut by bytes
//!
//! `chunk.chunkLen` measures each candidate chunk with the same `encodedLen` the
//! encoder writes with, so the cut and the frame cannot disagree. Upstream
//! divides the budget by a per-entry constant instead (`plumtree.rs:454-459`),
//! which is an upper bound rather than a size; `plumtree.zig` records the
//! divergence and the reason, and the reason is this file.
//!
//! # Reference evidence and bounds
//!
//! `codec_test.zig` contains explicitly source-derived framing regressions.
//! Actual upstream state-machine serializer vectors are generated separately
//! by the pinned Rust `gossip-vectors` binary; these are not network captures.
//! Live Node/Rust interoperability is a separate integration check.
//!
//! Sending rejects bodies at or above 4096 bytes, while receiving admits exactly
//! 4096, matching the upstream writer/reader asymmetry. Peer and IHave vectors,
//! owned PeerData, and cached content can hold every value fitting that receive
//! budget. Runtime peer tables remain bounded and may still report capacity errors.

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
