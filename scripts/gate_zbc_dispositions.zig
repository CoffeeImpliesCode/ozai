//! The `zbc` diagnostics the retained audit reviewed one at a time, and the
//! source they were reviewed against.
//!
//! This file is evidence, not policy: it is replaced wholesale whenever the
//! triage is redone, while `gate_zbc.zig` (which decides) is not. Every record
//! names the reason the diagnostic is what it is, so "reviewed" is a claim a
//! reader can check rather than a line number in a baseline.
//!
//! All fifty are here. The two `test/tls_wire/hello.zig` key-share windows that
//! an earlier pass deliberately left uncovered now have records, because the
//! guard they were missing is in the source: `serverHello` bounds them with
//! `len >= 36` and `len >= 69` (hello.zig:407 and 410) rather than with the
//! enclosing block, so `data[4..]` cannot run into the bytes behind the
//! extension. The finding is still a `slice-from-fixed-offset-without-len-check`
//! on the tool's side; it is false positive now rather than out of scope.
//!
//! The rest are three kinds of answer. Most are `false_positive`: the tool's
//! flow analysis stopped short of a fact the source states outright. The
//! panics are deliberately different from each other and from the false
//! positives — one is a shutdown backstop whose error arm has no channel, the
//! other a test teardown that has no channel either. The `arena_owned` records
//! are about an allocator rather than about control flow: the gate runs on an
//! arena, so a "leaked" allocation is storage the arena reclaims wholesale and
//! `toOwnedSlice()` would be the mistake, not the fix.
//!
//! `sha256` is the whole file as reviewed. It is the whole file on purpose: a
//! fingerprint clever enough to survive an unrelated edit is a fingerprint that
//! can be wrong, and a disposition that survives the code under it changing is
//! worse than no disposition at all. Any edit to a reviewed file fails the
//! triage until someone looks again.

const std = @import("std");

/// Why a diagnostic is not a defect.
pub const Kind = enum {
    /// The flagged code is source-proven correct; the tool's flow analysis is
    /// what failed, not the program.
    false_positive,
    /// A deliberate panic. Distinct from the false positives: this one really
    /// does abort the process, and the disposition is the argument for why
    /// that is the right thing to do at this site.
    justified_panic,
    /// The tool wants a per-allocation owner. There is none, because the gate
    /// allocates from the arena `std.process.Init` carries, and that arena's
    /// storage is released whole when `main` returns.
    arena_owned,
};

pub const Reviewed = struct {
    /// Repository-relative path, matching `gate_scope.Scope.all`.
    path: []const u8,
    /// Whole-file SHA-256 of the source this disposition was read against.
    sha256: []const u8,
};

pub const Disposition = struct {
    path: []const u8,
    line: usize,
    column: usize,
    rule: []const u8,
    kind: Kind,
    /// One line: what the source proves, cited by line.
    why: []const u8,
};

/// The source each disposition below was read against. Re-triage means replacing
/// these digests and the records, not editing a baseline of keys.
pub const reviewed_sources = [_]Reviewed{
    .{
        .path = "scripts/gate.zig",
        .sha256 = "6baaede56052564556b0e29182e0ba22d59ee8012cc8afe43816b61199af9ddd",
    },
    .{
        .path = "scripts/gate_paths.zig",
        .sha256 = "e6b4b737bf0bb690b3d27f5532f9505e12a2f0219fddef2b0d394da73f76aecd",
    },
    .{
        .path = "scripts/gate_receipts.zig",
        .sha256 = "b68b479e8eb9d2da60204cf59a958058c0ee9006b2de31c75698d08845726b83",
    },
    .{
        .path = "scripts/gate_run.zig",
        .sha256 = "1d93e51444e5bfdab138bac8c13768ae4500e451a91ebce2e5415742f1a32ff1",
    },
    .{
        .path = "scripts/gate_scope.zig",
        .sha256 = "fe269f79d0f3ea9d470789a964643bb6fb617d5a5310dde732a2f63eeb4ebb67",
    },
    .{
        .path = "scripts/gate_steps.zig",
        .sha256 = "d96cf1444f724e2c73250aed021c7e3e5dd6f86946084c39fe590ba8fa9e95f4",
    },
    .{
        .path = "src/base/base32.zig",
        .sha256 = "d1680ad94da7442b36dfa550e5600b0359281f1f8f00e91d012aea142c77c0da",
    },
    .{
        .path = "src/base/key.zig",
        .sha256 = "788643f4698c263499fdbc2027e4b7c36d17b779a37fe468950d1a6d7d83ff6d",
    },
    .{
        .path = "src/base/ula.zig",
        .sha256 = "1a765e34f8503e58106011bbaf1f204374bcf82b59ba92007ee02fd5df7cd60d",
    },
    .{
        .path = "src/blobs/protocol.zig",
        .sha256 = "eece0d28e79f997ade618b598e72a70a6c0015bd04070b13ba515bad392d6ee9",
    },
    .{
        .path = "src/blobs/range_spec.zig",
        .sha256 = "6c09b6ec6347e2cec6fe576ec5da692b62685e43f7676844b4101c8a2910478a",
    },
    .{
        .path = "src/discovery/item.zig",
        .sha256 = "4c83623d0fb3db079b2d5650939cad2e60cfebb90eb0e99f9a82a45d369c1bbc",
    },
    .{
        .path = "src/discovery/lookup_io.zig",
        .sha256 = "77500f086232e23f65678cf57b4afaf754642e17368a18050623cf0f6111e5e3",
    },
    .{
        .path = "src/discovery/resolve.zig",
        .sha256 = "b9ae0d707400772a4832c4e617bfea40b68b9530aa03e4d3ab39d26e49513415",
    },
    .{
        .path = "src/gossip/hyparview.zig",
        .sha256 = "9d197a0739a88cab6cd81519e6b63856022c275a073973ff634b4b19cf15e7fc",
    },
    .{
        .path = "src/node/node.zig",
        .sha256 = "0ec70cd1ade81cca71f49230d22b6631ba0cc73d050fb2f68dfa8537af1dabef",
    },
    .{
        .path = "src/relay/frame.zig",
        .sha256 = "48bc556536eda3bb0a54d2219a33cbc51eb98af9dc3bdeb34d188b77a434c329",
    },
    .{
        .path = "test/dns_wire/seeds.zig",
        .sha256 = "4c6eb9163c654a0a3b708e4cfd6b5eabbf69e32d60dfd688560526d715183972",
    },
    .{
        .path = "test/loopback_test.zig",
        .sha256 = "859f2d7ba3f8659e14327fa7f46de3f35b19861a3bc76e99562ccc6dc6e1a115",
    },
    .{
        .path = "test/protocol_loopback_test.zig",
        .sha256 = "637abb1c6f9d9e33d5477099724a939d1b763be8a9f257581d6fbf5f445b631b",
    },
    .{
        .path = "test/quic_wire/transport_params.zig",
        .sha256 = "1da0fe59b57b6bd672bfd102eb1b0bf3a76689d408ad3ab12ce431efdaf80ecf",
    },
    .{
        .path = "test/tls_wire/hello.zig",
        .sha256 = "7ef1e42150d4f9665ed78f26df4036af34a2360dbcd9416da28383da9dc6fd97",
    },
    .{
        .path = "test/tls_wire/messages.zig",
        .sha256 = "23fe80f1d717895d3d9b8c0f4854222d7bf8038bada294816189aedcc5bfaa52",
    },
    .{
        .path = "test/vendored_scanner.zig",
        .sha256 = "3606bdf5c1f95277f6ff0956c13e581516d33716cccc952c4ff51f97034d0e3b",
    },
};

pub const dispositions = [_]Disposition{
    .{
        .path = "scripts/gate.zig",
        .line = 293,
        .column = 5,
        .rule = "return-arraylist-items",
        .kind = .arena_owned,
        .why = "The gate allocates from `init.arena.allocator()` (gate.zig:105), so this list's backing storage" ++
            " belongs to the arena `main` releases on return; there is no per-allocation owner to hand a" ++
            " free to, and `toOwnedSlice()` would only ask the caller to free into an arena that never" ++
            " tracked it.",
    },
    .{
        .path = "scripts/gate_paths.zig",
        .line = 259,
        .column = 13,
        .rule = "index-minus-one-without-zero-guard",
        .kind = .false_positive,
        .why = "`within` returns false on its first line at 255 when `root.len == 0`, and returns true at 257" ++
            " when the two lengths are equal, so `root.len >= 1` is proved above the subtraction at 259; the" ++
            " guard is not carried across the early return.",
    },
    .{
        .path = "scripts/gate_receipts.zig",
        .line = 149,
        .column = 5,
        .rule = "return-arraylist-items",
        .kind = .arena_owned,
        .why = "Same allocator: the tools list is arena storage released wholesale when `main` returns, and the" ++
            " receipt walks it in place at 72 without keeping a reference past the write.",
    },
    .{
        .path = "scripts/gate_run.zig",
        .line = 75,
        .column = 34,
        .rule = "slice-loop-reentrant-grow",
        .kind = .false_positive,
        .why = "`steps.run` is handed the allocator and one `Step` by value at 75 and is never given" ++
            " `group_steps`; the list was finished by `buildSteps` on the line above the loop at 73, and" ++
            " nothing in the loop appends to it.",
    },
    .{
        .path = "scripts/gate_run.zig",
        .line = 88,
        .column = 63,
        .rule = "slice-loop-reentrant-grow",
        .kind = .false_positive,
        .why = "The loop at 74 walks `group_steps.items`, and this call is handed `result.stdout` — the" ++
            " child's own report bytes. `fuzzReportedFailure` only reads that slice and answers a bool; the" ++
            " appends in this body go to `results` at 89, which is a list `runGroups` declared, not this loop.",
    },
    .{
        .path = "scripts/gate_run.zig",
        .line = 107,
        .column = 30,
        .rule = "slice-loop-reentrant-grow",
        .kind = .false_positive,
        .why = "`triageStatic` is handed `gpa`, `result`, `sources`, `results`, `verdict` and `text`; the one" ++
            " list it can grow is `results`, declared by `runGroups`. The slice this loop iterates is" ++
            " `group_steps`, which nothing here is given.",
    },
    .{
        .path = "scripts/gate_scope.zig",
        .line = 75,
        .column = 43,
        .rule = "slice-loop-reentrant-grow",
        .kind = .false_positive,
        .why = "`hashes` is declared on the line above at 74 with its own allocation, a third list beside" ++
            " `all` and `first_party`; the loop reads `all.items` and writes `hashes`, and neither name is" ++
            " the other's storage.",
    },
    .{
        .path = "scripts/gate_scope.zig",
        .line = 75,
        .column = 59,
        .rule = "slice-loop-reentrant-grow",
        .kind = .false_positive,
        .why = "`hashFile` takes a directory and a path and returns a digest; it is never handed `all`," ++
            " whose only writes are the walk at 72 and the sort at 73, both above this loop.",
    },
    .{
        .path = "scripts/gate_scope.zig",
        .line = 79,
        .column = 29,
        .rule = "slice-loop-reentrant-grow",
        .kind = .false_positive,
        .why = "`first_party` is declared at 76 and appended to at 79 while the loop at 77 reads `all`; the" ++
            " two are separate ArrayLists and `all` is not written anywhere between 73 and this loop.",
    },
    .{
        .path = "scripts/gate_steps.zig",
        .line = 119,
        .column = 13,
        .rule = "struct-literal-multiple-try",
        .kind = .arena_owned,
        .why = "This is the second `try` in the literal whose first is at 118, and the label it drops on" ++
            " the floor is allocated from the gate's arena (gate.zig:105); the whole label list is arena" ++
            " storage released when `main` returns, so an errdefer here would buy nothing but noise.",
    },
    .{
        .path = "scripts/gate_steps.zig",
        .line = 221,
        .column = 5,
        .rule = "return-arraylist-items",
        .kind = .arena_owned,
        .why = "The argv the caller receives is arena storage like everything else the gate allocates; a" ++
            " `Step` is never freed and the process that would own it exits immediately after the receipt" ++
            " is written.",
    },
    .{
        .path = "src/base/base32.zig",
        .line = 87,
        .column = 5,
        .rule = "use-undefined",
        .kind = .false_positive,
        .why = "encode returns a [encodedLen(n)]u8 written consecutively from index 0 by the five-bit loop" ++
            " and the tail arm, and encodedLen(n)=(8n+4)/5=ceil(8n/5) is exactly the symbol count for the" ++
            " n>=1 bytes the comptime assert guarantees.",
    },
    .{
        .path = "src/base/base32.zig",
        .line = 87,
        .column = 12,
        .rule = "use-undefined",
        .kind = .false_positive,
        .why = "The out operand of that same return; the writes cover indices 0..encodedLen(n)-1 with no" ++
            " gap, so no undefined byte reaches the caller.",
    },
    .{
        .path = "src/base/base32.zig",
        .line = 144,
        .column = 5,
        .rule = "use-undefined",
        .kind = .false_positive,
        .why = "decode pins text.len to encodedLen(n) at the length check and emits" ++
            " floor(5*ceil(8n/5)/8)==n bytes at consecutive indices; both ways out of the loop before the" ++
            " return are error returns.",
    },
    .{
        .path = "src/base/base32.zig",
        .line = 144,
        .column = 12,
        .rule = "use-undefined",
        .kind = .false_positive,
        .why = "The out operand of that same decode return; the emitted byte count equals n exactly, so the" ++
            " whole array is written before it is returned.",
    },
    .{
        .path = "src/base/key.zig",
        .line = 141,
        .column = 9,
        .rule = "use-undefined",
        .kind = .false_positive,
        .why = "toLocalTlsName writes [0..52) from base32.encode of the 32-byte Ed25519 key" ++
            " (byte_length=32, dnssec_length=encodedLen(32)=52) and [52..65) from the 13-byte" ++
            " \".iroh.invalid\" literal; the two ranges partition the 65-byte array.",
    },
    .{
        .path = "src/base/key.zig",
        .line = 141,
        .column = 16,
        .rule = "use-undefined",
        .kind = .false_positive,
        .why = "The name operand of that same return; both memcpy sources have exact comptime widths that" ++
            " sum to the declared 65.",
    },
    .{
        .path = "src/base/ula.zig",
        .line = 118,
        .column = 5,
        .rule = "use-undefined",
        .kind = .false_positive,
        .why = "ulaFor writes [0..8) from prefixFor's fully written [8]u8 and [8..16) from the [8]u8 host" ++
            " parameter, so the disjoint halves partition the returned [16]u8 Ula.",
    },
    .{
        .path = "src/base/ula.zig",
        .line = 118,
        .column = 12,
        .rule = "use-undefined",
        .kind = .false_positive,
        .why = "The octets operand of that same return; the two writes cover [0..8) and [8..16) of the" ++
            " 16-byte array declared before them.",
    },
    .{
        .path = "src/blobs/protocol.zig",
        .line = 2597,
        .column = 5,
        .rule = "use-undefined",
        .kind = .false_positive,
        .why = "hexdump writes out[0..2*shown) in the loop and memsets out[2*shown..128) for" ++
            " shown=@min(bytes.len, 64) with max_dumped_bytes=64 at 2577; the regions are adjacent and" ++
            " cover the returned [128]u8.",
    },
    .{
        .path = "src/blobs/protocol.zig",
        .line = 2597,
        .column = 12,
        .rule = "use-undefined",
        .kind = .false_positive,
        .why = "The out operand of that same hexdump return; the return type is a fixed array, not a slice," ++
            " so no partially filled owned capacity can escape.",
    },
    .{
        .path = "src/blobs/range_spec.zig",
        .line = 1126,
        .column = 5,
        .rule = "use-undefined",
        .kind = .false_positive,
        .why = "hexdump writes out[0..2*shown) in the loop and memsets out[2*shown..64) for" ++
            " shown=@min(bytes.len, 32) with max_dumped_bytes=32 at 1106; adjacent regions cover the" ++
            " returned [64]u8.",
    },
    .{
        .path = "src/blobs/range_spec.zig",
        .line = 1126,
        .column = 12,
        .rule = "use-undefined",
        .kind = .false_positive,
        .why = "The out operand of that same hexdump return; the written prefix and the memset tail are" ++
            " disjoint and cover the whole array.",
    },
    .{
        .path = "src/discovery/item.zig",
        .line = 454,
        .column = 5,
        .rule = "use-undefined",
        .kind = .false_positive,
        .why = "corpusIds loops over &ids, a *[3]NodeId, with one assignment per iteration, which runs" ++
            " exactly three times and writes indices 0, 1 and 2 before the return.",
    },
    .{
        .path = "src/discovery/item.zig",
        .line = 454,
        .column = 12,
        .rule = "use-undefined",
        .kind = .false_positive,
        .why = "The ids operand of that same return; a failing try returns the error union, and the partly" ++
            " filled local dies with the frame.",
    },
    .{
        .path = "src/discovery/lookup_io.zig",
        .line = 1670,
        .column = 20,
        .rule = "index-type-narrowing-wraparound",
        .kind = .false_positive,
        .why = "`octet` takes a u8 and every label reaching it is a dot-separated part of a compile-time" ++
            " literal: `_iroh.example.` at 1615 and 1747, `other.example.` at 1759, and `swept_records`" ++
            " at 1620. The longest part is 7 bytes, a fourteenth of what a length octet holds.",
    },
    .{
        .path = "src/discovery/lookup_io.zig",
        .line = 1711,
        .column = 24,
        .rule = "index-type-narrowing-wraparound",
        .kind = .false_positive,
        .why = "Every character string passed to `txt` is a literal in this file — the longest is" ++
            " `relay=https://elsewhere.example./` at 1760 — so no length octet this writes exceeds the" ++
            " 255 RFC 1035 §3.3.14 allows.",
    },
    .{
        .path = "src/discovery/resolve.zig",
        .line = 706,
        .column = 47,
        .rule = "index-minus-one-without-zero-guard",
        .kind = .false_positive,
        .why = "`owned.append(alloc, data)` at 692 has a catch arm at 693 that frees the copy and returns," ++
            " so reaching 706 means the list holds at least the one entry just appended; nothing in" ++
            " between mutates `owned`, and the entry freed is that one.",
    },
    .{
        .path = "src/gossip/hyparview.zig",
        .line = 2818,
        .column = 5,
        .rule = "use-undefined",
        .kind = .false_positive,
        .why = "describe fills described[0..out.count()) and its only reader, expectSameActions at 2823," ++
            " walks exactly [0..want.count()] against [0..got.count()] at 2831 after asserting the counts" ++
            " equal at 2828; the tail past count is never read.",
    },
    .{
        .path = "src/gossip/hyparview.zig",
        .line = 2818,
        .column = 12,
        .rule = "use-undefined",
        .kind = .false_positive,
        .why = "The described operand of that same return; every element a caller can reach is one the" ++
            " loop above wrote.",
    },
    .{
        .path = "src/gossip/hyparview.zig",
        .line = 4529,
        .column = 5,
        .rule = "use-undefined",
        .kind = .false_positive,
        .why = "describeTopic fills described[0..out.count()) and expectSameTopicActions at 4532 reads" ++
            " exactly [0..want.count()] and [0..got.count()] at 4540 after the counts are asserted equal at" ++
            " 4537, so the tail past count is never read.",
    },
    .{
        .path = "src/gossip/hyparview.zig",
        .line = 4529,
        .column = 12,
        .rule = "use-undefined",
        .kind = .false_positive,
        .why = "The described operand of that same return; every element a caller can reach is one the" ++
            " loop above wrote.",
    },
    .{
        .path = "src/node/node.zig",
        .line = 1543,
        .column = 51,
        .rule = "catch-error-panic",
        .kind = .justified_panic,
        .why = "dispose returns void and passes (null, null) to finish, so an error from the shutdown" ++
            " backstop has no channel to travel; the doc at 1538-1541 states the call cannot fail with no" ++
            " Io and no instant, and the panic keeps a real failure from being swallowed rather than" ++
            " asserting one is impossible.",
    },
    .{
        .path = "src/node/node.zig",
        .line = 2758,
        .column = 26,
        .rule = "unreleased-refs-on-error",
        .kind = .false_positive,
        .why = "Node.retain at 2801 takes no refcount: Spoke.retain at 149 dups the borrowed payload at" ++
            " 153, errdefers the free at 154, and hands ownership to spoke.delivered at 155, which" ++
            " clearDelivered at 172 walks. The call is a switch prong with nothing after it in the prong.",
    },
    .{
        .path = "src/node/node.zig",
        .line = 3249,
        .column = 50,
        .rule = "catch-error-panic",
        .kind = .justified_panic,
        .why = "closedOnExit returns void and is used beside a `defer` at 3248, so the real failure of" ++
            " Node.close has no channel; swallowing it would let a test pass over a node left" ++
            " mid-shutdown. Every caller is a test teardown.",
    },
    .{
        .path = "src/relay/frame.zig",
        .line = 2552,
        .column = 5,
        .rule = "use-undefined",
        .kind = .false_positive,
        .why = "hexdump writes out[0..2*shown) in the loop and memsets out[2*shown..160) for" ++
            " shown=@min(bytes.len, 80) with max_dumped_bytes=80 at 2532; adjacent regions cover the" ++
            " returned [160]u8.",
    },
    .{
        .path = "src/relay/frame.zig",
        .line = 2552,
        .column = 12,
        .rule = "use-undefined",
        .kind = .false_positive,
        .why = "The out operand of that same hexdump return; the written prefix and the memset tail are" ++
            " disjoint and cover the whole array.",
    },
    .{
        .path = "test/dns_wire/seeds.zig",
        .line = 85,
        .column = 20,
        .rule = "index-type-narrowing-wraparound",
        .kind = .false_positive,
        .why = "`octet` takes a u8 and every label reaching Writer.label is a dot-separated part of a" ++
            " compile-time literal — `asked` is \"_iroh.example.\" at 22 and the other is the literal" ++
            " \"fwd\" at 200 — so the longest part is 7 bytes.",
    },
    .{
        .path = "test/dns_wire/seeds.zig",
        .line = 134,
        .column = 29,
        .rule = "index-type-narrowing-wraparound",
        .kind = .false_positive,
        .why = "The one caller outside this file breaks its split when a run is longer than" ++
            " max_character_string (oracle.zig:294), and every caller inside it passes a literal of at" ++
            " most 40 bytes, so string.len is 1..255 and fits the length octet.",
    },
    .{
        .path = "test/loopback_test.zig",
        .line = 170,
        .column = 5,
        .rule = "use-undefined",
        .kind = .false_positive,
        .why = "spkiOf memcpy's a 12-byte header into out[0..12) and node.toBytes() into out[12..44);" ++
            " both lengths are comptime and 12+32 equals spki_length.",
    },
    .{
        .path = "test/loopback_test.zig",
        .line = 170,
        .column = 12,
        .rule = "use-undefined",
        .kind = .false_positive,
        .why = "The out operand of that same spkiOf return; the two memcpys are disjoint and cover the" ++
            " whole array, which the comptime length check also proves.",
    },
    .{
        .path = "test/protocol_loopback_test.zig",
        .line = 2121,
        .column = 5,
        .rule = "use-undefined",
        .kind = .false_positive,
        .why = "spkiOf here uses the same 12-byte header literal and the same comptime 12+32 partition of" ++
            " the array as the other bridge helper.",
    },
    .{
        .path = "test/protocol_loopback_test.zig",
        .line = 2121,
        .column = 12,
        .rule = "use-undefined",
        .kind = .false_positive,
        .why = "The out operand of that same spkiOf return; the same comptime-length partition covers the" ++
            " whole array.",
    },
    .{
        .path = "test/quic_wire/transport_params.zig",
        .line = 223,
        .column = 39,
        .rule = "use-undefined",
        .kind = .false_positive,
        .why = "`length != 16` returns on the line above at 220 and value is" ++
            " bytes[cursor..][0..@intCast(length)] at 197, so value.len is 16 and the @memcpy at 222" ++
            " writes all sixteen bytes of token before it reaches out.reset_token.",
    },
    .{
        .path = "test/tls_wire/hello.zig",
        .line = 323,
        .column = 24,
        .rule = "slice-from-fixed-offset-without-len-check",
        .kind = .false_positive,
        .why = "data is ext[p + 4 ..][0..len] at 298, so its length is len; the guard on the line above" ++
            " at 322 returns unless len >= 2, which is the data.len >= 2 the rule asks for under another" ++
            " name.",
    },
    .{
        .path = "test/tls_wire/hello.zig",
        .line = 395,
        .column = 35,
        .rule = "slice-from-fixed-offset-without-len-check",
        .kind = .false_positive,
        .why = "data is ext[at..][0..len] at 390 and `len < 4` returned at 393, so data.len >= 4 before" ++
            " be16(data[2..]) reads the two bytes it needs.",
    },
    .{
        .path = "test/tls_wire/hello.zig",
        .line = 409,
        .column = 29,
        .rule = "slice-from-fixed-offset-without-len-check",
        .kind = .false_positive,
        .why = "This arm is reached only under len >= 36 at 407 and data is ext[at..][0..len] at 390, so" ++
            " data[4..] holds at least 32 bytes; the window cannot reach past the key_share extension the" ++
            " peer declared.",
    },
    .{
        .path = "test/tls_wire/hello.zig",
        .line = 412,
        .column = 29,
        .rule = "slice-from-fixed-offset-without-len-check",
        .kind = .false_positive,
        .why = "The same bound one arm down: len >= 69 at 410 gives data[4..] at least 65 bytes of the" ++
            " ext[at..][0..len] window built at 390, so data[4..][0..65] ends inside the extension itself.",
    },
    .{
        .path = "test/tls_wire/messages.zig",
        .line = 272,
        .column = 14,
        .rule = "use-undefined",
        .kind = .false_positive,
        .why = "out is written before it is walked: `for (&out) |*slot| slot.* = untouched` at 241 fills" ++
            " both slots and parseCertificateList at 243 replaces them only with windows into `d`, so" ++
            " the by-value walk at 272 reads nothing undefined.",
    },
    .{
        .path = "test/vendored_scanner.zig",
        .line = 144,
        .column = 40,
        .rule = "slice-loop-reentrant-grow",
        .kind = .false_positive,
        .why = "self.local_fns and self.tokens are separate fields with separate backing allocations, and" ++
            " nothing appends to self.tokens inside classify — its only append is at 376, before this" ++
            " walk. The names appended borrow self.src (text at 204), not the token buffer.",
    },
};

/// The digest the disposition for `path` was read against, or null when the
/// file is not one the triage covered — a diagnostic in an unreviewed file is
/// new by definition, whatever its key looks like.
pub fn reviewedDigest(path: []const u8) ?[]const u8 {
    for (reviewed_sources) |source| {
        if (std.mem.eql(u8, source.path, path)) return source.sha256;
    }
    return null;
}

/// The index into `dispositions` of the record covering this key, or null when
/// nothing does. The index rather than the record itself, because a caller
/// also has to mark the record as seen.
pub fn find(path: []const u8, line: usize, column: usize, rule: []const u8) ?usize {
    for (dispositions, 0..) |disposition, index| {
        if (disposition.line != line) continue;
        if (disposition.column != column) continue;
        if (!std.mem.eql(u8, disposition.path, path)) continue;
        if (!std.mem.eql(u8, disposition.rule, rule)) continue;
        return index;
    }
    return null;
}
