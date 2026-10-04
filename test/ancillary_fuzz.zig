//! Fuzz target for the ancillary control-message decoder.
//!
//! One target file per decoder: `zig build fuzz` replays the corpus, and
//! `zig build fuzz --fuzz=N` hands the same corpus to Zig's coverage-guided
//! fuzzer and lets it mutate for N iterations. A decoder is only worth this
//! once the same bytes have been shown not to panic, and `ancillary.readCmsg`
//! is the narrowest decoder in the tree: everything above it hands it a
//! buffer the kernel filled, and nothing it had ever been handed by a test
//! came from a stranger.
//!
//! The bytes go in as a plan rather than as a blob: this file decides what
//! messages to write, writes them itself, and then asks the decoder about
//! every prefix of the result. The decoder is told nothing about the plan.
//!
//! Three oracles, each exact rather than "it did not crash":
//!
//!   * **codepoint.** The two bits a traffic-class message carried are the low
//!     two bits of its first value byte at every width the kernel writes, and
//!     a message whose value region is empty carries none. The answer is
//!     compared against the byte that was written rather than against what the
//!     codec computes out of it.
//!   * **stride.** `UDP_GRO` reads a native `unsigned int` and reports no
//!     stride at all when its value is narrower than that, which is what a
//!     `UDP_SEGMENT` value in the same place looks like.
//!   * **truncation.** A blob is truncated exactly when it ends strictly inside
//!     a message the length check has not yet accepted: fewer bytes than a
//!     header, or fewer than the length the header claims. Ending on a message
//!     boundary, or inside the padding after the last value, is not truncation
//!     — and a message after the cut is simply not in the read, which is why
//!     the codepoint and stride oracles are folds over the prefix that
//!     survived.

const std = @import("std");
const builtin = @import("builtin");
const ozai = @import("ozai");

const anc = ozai.transport_socket.ancillary;
const batch = ozai.transport_batch;

const t = std.testing;

/// `batch.linux`: the option numbers, named once and reached rather than
/// re-spelled as a literal here.
const names = batch.linux;

/// Control integers use native byte order, the way the kernel wrote them.
const endian = builtin.cpu.arch.endian();

/// The header a planned message carries, spelled as the bytes the decoder
/// reads back: a word-sized length at offset zero and two `int`s behind it.
///
/// This is deliberately neither `std.c.cmsghdr` nor the producer's own writer.
/// The oracle has to be able to put a header in front of the decoder that the
/// producer would never write — one narrower than a header, one claiming past
/// what the blob holds — so it writes its own rather than asking the code
/// under test for help. The layout is the kernel's own, and `readCmsg` reads
/// the length as one `usize` word at offset zero, so this is the same bytes
/// on every ABI including a 32-bit one.
const Planned = extern struct {
    length: usize,
    level: i32,
    kind: i32,
};

/// How many messages one planned blob may carry.
const max_plan = 6;

/// The widest value region a planned message may fill, which is the `c_int` a
/// traffic-class option takes.
const max_value = @sizeOf(i32);

/// Where a header's value begins, which is the header rounded up to a word.
const value_at: usize = anc.cmsgLen(0);

/// The widest a planned header may claim, aligned: that is what a message
/// costs the blob rather than what it reports about itself, and every other
/// claim is narrower.
const widest_claim: usize = anc.cmsgAlign(anc.cmsgLen(max_value) + @sizeOf(usize));

/// The blob one plan is written into. Every planned message costs at most
/// `widest_claim` bytes of it, so this holds any plan the fuzzer builds.
const blob_len: usize = max_plan * widest_claim;

/// The widths the fuzzer fills a value region with: nothing, the one byte
/// `ip_cmsg_put` writes, `UDP_SEGMENT`'s `u16`, and the option's own `c_int`.
const value_widths = [_]usize{ 0, 1, @sizeOf(u16), max_value };

/// The length words a planned header may carry: one the length check refuses
/// for being narrower than a header, one that leaves an empty value region,
/// the two a real kernel write takes, and one that claims past what any blob
/// holds.
///
/// There is no length that falls between a header and `value_at` to put here,
/// and that is not a hole in the property: the decoder refuses anything below
/// a header before it slices, and `value_at` is exactly a header's size on
/// every ABI. Every reachable length is already in this list.
const claims = [_]usize{
    @sizeOf(Planned) - 1,
    value_at,
    anc.cmsgLen(1),
    anc.cmsgLen(max_value),
    widest_claim,
};

/// The levels and option names a planned header may name: the three this
/// module asks for, and one nobody does.
const levels = [_]u32{ names.udp_level, names.ip_level, names.ipv6_level, 0xdead };
const kinds = [_]u32{ names.gro, names.segment, names.ipv4_tos, names.ipv6_tclass, 0xbeef };

/// One planned message: the header to write, and the answer the read owes for
/// it.
const Plan = struct {
    level: u32,
    kind: u32,
    /// The length word the header carries.
    claimed: usize,
    /// The value bytes, zero-padded: as many of them as the claimed length
    /// leaves room for behind the header are written, and a claim that leaves
    /// none is a message with no value at all.
    value: [max_value]u8,
    /// Where the message starts, filled in as the blob is written.
    offset: usize,
};

/// One planned blob, and the arithmetic that walks it without ever asking the
/// decoder what it thinks.
const Built = struct {
    blob: [blob_len]u8,
    used: usize,
    plans: [max_plan]Plan,
    /// How many of them the plan wrote.
    count: usize,

    /// The answer `readCmsg` owes for the blob's first `p` bytes, worked out
    /// from the framing that was written.
    ///
    /// The walk is the framing rule and nothing else: a message is at an
    /// offset, claims a length, and the next one starts `cmsgAlign` of that
    /// length further on. The values and the truncated flag are read off the
    /// plan rather than out of the blob, so a codec that read the wrong byte
    /// or reported a cut that was not one fails here instead of agreeing with
    /// itself.
    fn expected(self: *const Built, p: usize) anc.CmsgRead {
        var read: anc.CmsgRead = .{ .stride = null, .ecn = null, .truncated = false };
        for (self.plans[0..self.count]) |plan| {
            if (plan.offset >= p) break;
            const remaining = p - plan.offset;
            // The three ways a walk ends early, and the only ones: fewer bytes
            // than a header, a header that claims less than one, and a header
            // that claims past what is left of the blob.
            if (remaining < @sizeOf(Planned) or
                plan.claimed < @sizeOf(Planned) or
                plan.claimed > remaining)
            {
                read.truncated = true;
                break;
            }
            applyPlan(&read, plan);
        }
        return read;
    }
};

/// Fold one planned message into the answer the read owes, from the header the
/// plan wrote and the bytes it put behind it.
fn applyPlan(read: *anc.CmsgRead, plan: Plan) void {
    // The whole of the value region the header leaves room for, out of the
    // four bytes the plan holds: a message that claims more room than the
    // input had bytes for is zero-padded in the blob, and the oracle has to
    // see the same zeros `UDP_GRO` would read as the rest of its word.
    const region = plan.value[0..@min(reachable(plan), max_value)];
    if (plan.level == names.udp_level and plan.kind == names.gro) {
        if (region.len < @sizeOf(u32)) return;
        read.stride = std.mem.readInt(u32, region[0..@sizeOf(u32)], endian);
        return;
    }
    const carries_class = (plan.level == names.ip_level and plan.kind == names.ipv4_tos) or
        (plan.level == names.ipv6_level and plan.kind == names.ipv6_tclass);
    if (!carries_class) return;
    // A value region the header leaves empty carries nothing, and every width
    // past that spells the codepoint in its first byte: an `int` on the way
    // out, a byte on the way in, and the two bits in the low byte either way.
    read.ecn = if (region.len == 0) null else batch.Recv.ecnFromBits(region[0]);
}

/// How many of a message's own bytes reach its value region, which is nothing
/// at all when the length it claims does not reach past the header.
fn reachable(plan: Plan) usize {
    return if (plan.claimed > value_at) plan.claimed - value_at else 0;
}

/// Seeds that are the shapes rather than the bytes. Each is a message count
/// and then, per message, the four choices and the value bytes — and every
/// one of these reaches a different arm of the decoder:
///
///  * nothing at all, so an empty blob is a read with nothing in it;
///  * a `UDP_GRO` message with a whole-word value, which is the only shape
///    that reports a stride;
///  * an IPv4 traffic class carrying one byte, which is what `ip_cmsg_put`
///    writes and two bytes narrower than the option takes;
///  * an IPv6 traffic class carrying a whole word, which is the send's own
///    shape and a different ABI from the read above;
///  * a message at a level nobody here names, in front of the stride behind
///    it, so a walk that stopped at the first stranger would lose it;
///  * a header claiming more than the blob holds, and one narrower than a
///    header, which are the two shapes a reader must call truncated;
///  * a class message whose header leaves no room for a value at all.
const corpus = [_][]const u8{
    "",
    "\x01\x03\x03\x00\x00\x14\x00\x00\x00",
    "\x01\x02\x01\x01\x02\x02",
    "\x01\x03\x03\x02\x03\x03\x00\x00\x00",
    "\x02\x04\x00\x03\x04\x03\x03\x00\x00\x0e\x00\x00\x00",
    "\x01\x04\x03\x00\x00\x40\x00\x00\x00",
    "\x01\x00\x03\x01\x03\x02",
    "\x01\x01\x03\x01\x02",
};

/// Long enough to overrun every choice a plan reads, so a mutated input can
/// still reach a claim it was not grown for, and short enough that a blob of
/// six messages and every prefix of it fits this stack frame.
const input_buffer_len = 64;

comptime {
    // A seed longer than the window the fuzzer reads into would be cut short on
    // its way to the oracle, and the plan built from it would be missing the
    // bytes the rest of it names.
    for (corpus) |seed| std.debug.assert(seed.len <= input_buffer_len);
    // A claim of zero aligns to zero, and a message that claims it occupies no
    // bytes at all: the walk below would stand still on it forever.
    for (claims) |claim| std.debug.assert(anc.cmsgAlign(claim) > 0);
    for (claims) |claim| std.debug.assert(anc.cmsgAlign(claim) <= widest_claim);
    // The truncation oracle below compares against a header's own size, so
    // the mirror this file writes has to be that size.
    std.debug.assert(@sizeOf(Planned) == value_at);
}

test "an ancillary blob reads back exactly what was written into it" {
    // A fuzz test is a plain test to a plain build. Without `-ffuzz` the
    // runner walks the corpus instead of handing it to the fuzzer.
    try t.fuzz(Context{}, testOne, .{ .corpus = &corpus });
}

/// The fuzzer keeps this by pointer for the whole run, so it is empty by
/// design: the oracle needs nothing but a stack blob and a clip.
const Context = struct {};

fn testOne(_: Context, smith: *t.Smith) anyerror!void {
    var buffer: [input_buffer_len]u8 = undefined;
    // `in` is the corpus entry verbatim while the corpus is replayed, and null
    // when the fuzzer drives, in which case `slice` consumes its input.
    const bytes = if (smith.in) |replay| replay else buffer[0..smith.slice(&buffer)];
    const built = buildPlan(bytes);
    // Every prefix, and the whole blob last: a cut at any offset the blob can
    // be cut at is one a reader can be handed, and each of them has exactly
    // one answer.
    var p: usize = 0;
    while (p <= built.used) : (p += 1) {
        try t.expectEqualDeep(built.expected(p), anc.readCmsg(built.blob[0..p]));
    }
}

/// Turn the fuzzer's bytes into a blob and the plan that describes it.
///
/// The bytes are a message count and then, per message, four bytes of choices
/// — the length word, the value width, the level and the option name — followed
/// by as many value bytes as the message is given room for. The four choices
/// are separate bytes on purpose: one byte for all of them would tie the
/// option name to the length word, and a `UDP_GRO` message would then only
/// ever be the shape whose header the length check refuses.
///
/// A run that runs out of bytes ends there: a plan is a prefix of the choices
/// rather than a fixed-length record, so a short input is a short plan and not
/// a refused one.
fn buildPlan(bytes: []const u8) Built {
    var built: Built = .{ .blob = undefined, .used = 0, .plans = undefined, .count = 0 };
    if (bytes.len == 0) return built;
    const wanted = bytes[0] % (max_plan + 1);
    var at: usize = 1;
    var index: usize = 0;
    while (index < wanted and at + 3 < bytes.len) : (index += 1) {
        const claimed = claims[bytes[at] % claims.len];
        const width = value_widths[bytes[at + 1] % value_widths.len];
        const level = levels[bytes[at + 2] % levels.len];
        const kind = kinds[bytes[at + 3] % kinds.len];
        at += 4;
        const message = writePlanned(&built, claimed, width, level, kind, bytes, &at);
        built.plans[index] = message;
        built.count = index + 1;
    }
    return built;
}

/// Write one planned message into the blob and hand back what was written.
fn writePlanned(
    built: *Built,
    claimed: usize,
    width: usize,
    level: u32,
    kind: u32,
    bytes: []const u8,
    at: *usize,
) Plan {
    const space = anc.cmsgAlign(claimed);
    std.debug.assert(built.used + space <= built.blob.len);
    const reach = @min(width, if (claimed > value_at) claimed - value_at else 0);
    var slot: Plan = .{
        .level = level,
        .kind = kind,
        .claimed = claimed,
        // Zeroed before the input's bytes go in, so the plan holds the same
        // value region the blob does: a width the input ran out of is padded
        // with zeros rather than left undefined, and `applyPlan` reads the
        // same word the decoder will.
        .value = [_]u8{0} ** max_value,
        .offset = built.used,
    };
    for (0..reach) |byte| {
        if (at.* < bytes.len) {
            slot.value[byte] = bytes[at.*];
            at.* += 1;
        } else {
            // A value the input ran out of is a zero, which is not-ECT and a
            // stride of nothing — two answers a real message can carry, and
            // neither of them an absence.
            slot.value[byte] = 0;
        }
    }
    const start = built.blob[built.used..][0..space];
    @memset(start, 0);
    const header: Planned = .{
        .length = claimed,
        .level = @bitCast(level),
        .kind = @bitCast(kind),
    };
    @memcpy(start[0..@sizeOf(Planned)], std.mem.asBytes(&header));
    @memcpy(start[value_at..][0..reach], slot.value[0..reach]);
    built.used += space;
    return slot;
}
