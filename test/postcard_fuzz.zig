//! Fuzz target for postcard, the codec every other wire format is serialised
//! through.
//!
//! One target file and one corpus directory per decoder: `zig build fuzz`
//! replays the corpus, and `zig build fuzz --fuzz=<N>` hands the same corpus
//! to Zig's coverage-guided fuzzer and lets it mutate for N iterations. A
//! decoder is only worth this once the same bytes have been shown not to
//! panic, and this one is the bottom of the stack: a ticket, a pkarr record, a
//! relay frame and a `RangeSpec` are all postcard underneath, so a byte that
//! reaches the wrong field here reaches the wrong field in all of them.
//!
//! postcard is a codec and not a message, so there is no single type to
//! decode. There are fifteen read methods and their fifteen write
//! counterparts, and this file offers the bytes to all of them three ways,
//! through two oracle modules it calls and does not hold:
//!
//! - `postcard_scalar_oracle.zig` offers them to one read method at a time,
//!   which is where the rejection, the round trip and the second spelling of
//!   one field are judged against references written from the spec.
//! - `postcard_record_oracle.zig` offers them to a whole message of every
//!   shape the codec has, so the fuzzer also walks fields in sequence, a
//!   count and the elements it names, a trailing byte, and a message that has
//!   a second spelling.
//!
//! Both judge their decodes against `postcard_decode_reference.zig`, which
//! holds the byte-decoding rules and imports no codec: an oracle that asked
//! the decoder what the decoder should have said would agree with the bug it
//! is meant to catch.
//!
//! The next decoder's target is this file with those modules replaced by that
//! decoder's one message type.
//!
//! Nothing here tightens the decoder. A panic, a wrong error, or an encoding
//! that decodes when the spec says it should not is a finding about
//! `src/wire/postcard.zig`, and the answer is to report it.

const std = @import("std");
const scalar = @import("postcard_scalar_oracle.zig");
const record = @import("postcard_record_oracle.zig");
const t = std.testing;

/// Seeds are the bytes a peer would hand over as a postcard message.
///
/// `captured_struct` and `captured_string` are vectors from
/// `jamesmunns/postcard` at commit 872b9082589ebd1384a1b95ca232b1727bcddd29 —
/// `loopback`'s `BasicU8S` struct and its `heapless::String "helLO!"` — so a
/// mutation starts from something upstream actually wrote. `captured_record`
/// is a message of every shape the codec has, its first three fields carrying
/// the values upstream's `BasicU8S` used, and `captured_record_trailing_byte`
/// is that with one byte behind it, which is a second message rather than a
/// longer one. `captured_record_zero` is that record with every varint zero and
/// every string empty, which is the cheapest valid record there is — eighteen
/// one-byte fields — so a mutation of it has more room than any other seed here
/// to land on another valid record.
///
/// The rest are the shapes the decoder has a rule for and a fuzzer would not
/// reach on its own: nothing at all, one byte, a varint truncated at each of
/// the three widths, an unterminated varint at the widest width, a varint one
/// group past the width, a length prefix of `0xFF` groups with nothing behind
/// it, a length prefix wider than the buffer can ever satisfy, an element
/// count with no elements, a `bool` byte of two, an `Option` tag of two, a
/// discriminant this build has no arm for, a string whose length is right and
/// whose bytes are not UTF-8, and the documented second spelling of zero.
///
/// `str_then_varint` is the one the fuzzer found, and it is a finding about
/// this harness rather than about the decoder: a well-formed string with a
/// `varint` behind it is a message with a field behind it, and the reference
/// that judged a string by the whole tail instead of the payload it named
/// called it `InvalidUtf8`. It is here because a corpus is the record of what
/// the oracles got wrong as much as of what the decoder does.
///
/// `bool_two` and `option_two` are the same byte, which is the point: one rule
/// and two methods, and a target that reached only one of them would not know
/// the other has it.
///
/// `test/corpus/postcard/` is the record, and a file there is live only once it
/// is named here.
const corpus = [_][]const u8{
    @embedFile("corpus/postcard/empty"), // 0 bytes: no field at all
    @embedFile("corpus/postcard/one_byte"), // 0xff: a u8, and no varint terminator
    @embedFile("corpus/postcard/captured_struct"), // upstream: a whole BasicU8S
    @embedFile("corpus/postcard/captured_string"), // upstream: "helLO!"
    @embedFile("corpus/postcard/captured_record"), // one of every shape
    @embedFile("corpus/postcard/captured_record_trailing_byte"), // that, and one byte
    @embedFile("corpus/postcard/captured_record_zero"), // a record of nothing at all
    @embedFile("corpus/postcard/noncanonical_zero"), // 0 as two groups
    @embedFile("corpus/postcard/u16_truncated"), // the loopback u16, one byte short
    @embedFile("corpus/postcard/u32_truncated"), // the loopback u32, one byte short
    @embedFile("corpus/postcard/u64_truncated"), // the loopback u64, one byte short
    @embedFile("corpus/postcard/overlong_varint"), // ten groups, none of which ends it
    @embedFile("corpus/postcard/u64_too_large"), // a tenth group of two
    @embedFile("corpus/postcard/length_no_payload"), // a u32 length of 2^32-1
    @embedFile("corpus/postcard/length_wider_than_buffer"), // a u64 length of 2^64-1
    @embedFile("corpus/postcard/count_no_elements"), // a count, and nothing behind it
    @embedFile("corpus/postcard/bool_two"), // 2, which is not a bool
    @embedFile("corpus/postcard/option_two"), // 2, which is not an Option tag
    @embedFile("corpus/postcard/unknown_variant"), // one past the last arm
    @embedFile("corpus/postcard/invalid_utf8"), // a length that fits, bytes that do not
    @embedFile("corpus/postcard/str_then_varint"), // the fuzzer found this one
};

comptime {
    // A seed longer than the window the fuzzer reads into would be cut short
    // on its way to the oracle, and the length checks would never see the rest.
    for (corpus) |seed| std.debug.assert(seed.len <= scalar.input_buffer_len);
}

/// The fuzzer keeps one of these by pointer for the whole run, so it is empty
/// by design: everything the oracle needs is comptime.
const Context = struct {};

test "postcard decode" {
    // A fuzz test is a plain test to a plain build. Without `-ffuzz` the runner
    // walks the corpus instead of handing it to the fuzzer, which is what makes
    // a bare `zig build fuzz` a bounded gate rather than an empty step.
    try t.fuzz(Context{}, testOne, .{ .corpus = &corpus });
}

fn testOne(_: Context, smith: *t.Smith) anyerror!void {
    var buffer: [scalar.input_buffer_len]u8 = undefined;
    // `in` is the corpus entry verbatim while the corpus is replayed, and null
    // when the fuzzer drives, in which case `slice` consumes its input.
    const bytes = if (smith.in) |replay| replay else buffer[0..smith.slice(&buffer)];
    try check(bytes);
}

/// One input, offered to every field and then to the whole message.
fn check(bytes: []const u8) !void {
    try scalar.checkAllFields(bytes);
    try record.checkRecord(bytes);
}
