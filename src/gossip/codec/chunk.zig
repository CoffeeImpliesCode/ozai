//! Cutting an `IHave` list into the frames a byte budget allows.
//!
//! PlumTree's state machine batches `IHave` entries by count to stay independent
//! of wire sizing. This separate byte-budget helper is not used by that batching
//! path. It measures each cut with the same `encodedLen` the encoder writes
//! with, so the byte budget does not depend on a duplicate sizing rule.
//!
//! Nothing here allocates, reads a clock, or touches a socket. The input is a
//! list of values and a budget, and the output is how many of them one frame
//! holds.

const frame = @import("frame.zig");
const limits = @import("limits.zig");
const plumtree = @import("../plumtree.zig");

const IHave = plumtree.IHave;
const IHaves = plumtree.IHaves;
const Error = limits.Error;
const ihave_max_size = limits.ihave_max_size;
const max_ihaves_per_message = plumtree.max_ihaves_per_message;
const tag_length = limits.tag_length;

/// The smallest budget a caller may cut against: the smallest body one entry can
/// occupy, which is the layer tag, the arm tag, the count's own varint, and the
/// widest one `IHave` can be.
///
/// **It is a floor and not the answer for one list.** A one-entry chunk whose
/// round is under 128 is two bytes smaller than this, and would fit a budget
/// this refuses. The rule below is the floor rather than the measurement anyway,
/// because a budget under it makes the cut depend on the round of the list's
/// first entry rather than on the budget, and a caller that set one has set a
/// budget this codec will not cut against.
pub const min_chunk_size = tag_length * 2 + 1 + ihave_max_size;

/// How many leading entries of `ihaves` fit in one `Message::IHave` whose body
/// is at most `budget` bytes.
///
/// **The limit is bytes and not a count.** Upstream divides the budget by a
/// constant per-entry size — `(max_message_size - 3) / IHave::POSTCARD_MAX_SIZE`
/// (`plumtree.rs:454-459`), where `MaxSize` derives 35 for a 32-byte id and a
/// `u16` round — and a constant is an upper bound rather than a size: a round
/// below 128 is one byte and not three, so that count leaves budget unspent and
/// is only right for the budget it was measured against. Here every candidate is
/// measured with `frame.encodedLen`, so the cut and the frame it produces cannot
/// disagree about how many bytes there are.
///
/// Two ceilings bind and the smaller one wins. `max_ihaves_per_message` is there
/// because a chunk is one `IHaves` value, which cannot hold more entries than
/// that however much budget there is; a caller with a longer list advances by
/// this number until the list has been cut up.
///
/// A budget below `min_chunk_size` is `error.ChunkBudgetTooSmall` and not a
/// zero, because a caller advancing by a zero does not advance and a list too
/// large to send is not a list whose entries may be dropped. An empty list is
/// zero whatever the budget: there is nothing to cut and nothing to send.
pub fn chunkLen(ihaves: []const IHave, budget: usize) Error!usize {
    if (ihaves.len == 0) return 0;
    // A budget that cannot hold the widest one entry cannot hold the first entry
    // of this list either, and the loop below would only find that out after
    // measuring a candidate it did not have to.
    if (budget < min_chunk_size) return error.ChunkBudgetTooSmall;
    const send_budget = @min(budget, limits.max_message_size - 1);
    var count: usize = 0;
    while (count < ihaves.len and count < max_ihaves_per_message) {
        const grown = count + 1;
        const list = try IHaves.init(ihaves[0..grown]);
        const body = frame.encodedLen(.{ .gossip = .{ .i_have = list } });
        if (body > send_budget) break;
        count = grown;
    }
    return count;
}
