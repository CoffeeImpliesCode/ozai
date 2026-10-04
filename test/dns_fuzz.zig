//! Fuzz target for the DNS answer decoder: name compression, section counts,
//! the `TC` bit, and one TXT record's character strings.
//!
//! `discovery/lookup_io.zig` reads bytes that arrive from a nameserver and
//! copies out the records of one `_iroh` name. Everything it reads is shaped by
//! whoever answered: a compression pointer can point anywhere, a count can claim
//! 65535 records, and a `TXT` record's character strings can claim a length
//! their `RDATA` does not hold. This target drives that one public entry point,
//! `readAnswer`, and holds it to oracles that never ask the decoder what it
//! thinks.
//!
//! This file is the driver and nothing else: it runs the Smith callback once
//! per input and hands the bytes to the oracles. The two halves of the work are
//! separate files because they are separate responsibilities —
//! `dns_wire/seeds.zig` writes DNS messages and owns the named corpus of shapes,
//! `dns_wire/oracle.zig` reads bytes back through a second, independent
//! implementation of RFC 1035 §4.1 and compares what it finds.

const std = @import("std");
const oracle = @import("dns_wire/oracle.zig");
const seeds = @import("dns_wire/seeds.zig");
const t = std.testing;

/// The fuzzer keeps one of these by pointer for the whole run, so it is empty
/// by design: everything the oracles need is built from the input.
const Context = struct {};

test "dns answer decode" {
    // A fuzz test is a plain test to a plain build. Without `-ffuzz` the runner
    // walks the corpus instead of handing it to the fuzzer, which is what makes
    // a bare `zig build fuzz` a bounded gate rather than an empty step. The
    // corpus is the named shapes in `dns_wire/seeds.zig`, built here rather
    // than embedded, so there is no corpus directory to register.
    var storage: [seeds.seed_count][seeds.input_buffer_len]u8 = undefined;
    var lengths: [seeds.seed_count]usize = undefined;
    seeds.buildSeeds(&storage, &lengths);
    var corpus: [seeds.seed_count][]const u8 = undefined;
    for (0..seeds.seed_count) |index| corpus[index] = storage[index][0..lengths[index]];

    try t.fuzz(Context{}, testOne, .{ .corpus = &corpus });
}

fn testOne(_: Context, smith: *t.Smith) anyerror!void {
    var buffer: [seeds.input_buffer_len]u8 = undefined;
    // `in` is the corpus entry verbatim while the corpus is replayed, and null
    // when the fuzzer drives, in which case `slice` consumes its input.
    const bytes = if (smith.in) |replay| replay else buffer[0..smith.slice(&buffer)];
    try oracle.check(bytes);
    try oracle.checkRoundTrip(bytes);
}
