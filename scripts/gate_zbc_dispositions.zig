//! The `zbc` diagnostics the retained audit reviewed one at a time, and the
//! source they were reviewed against.
//!
//! This file is evidence, not policy: it is replaced wholesale whenever the
//! triage is redone, while `gate_zbc.zig` (which decides) is not. Every record
//! names the reason the diagnostic is what it is, so "reviewed" is a claim a
//! reader can check rather than a line number in a baseline.
//!
//! The two tables below are the whole of the retained audit: every record is a
//! diagnostic the tool actually reported, and every record names the whole-file
//! digest of the source it was read against. No count is written here on
//! purpose. A number in this comment is a number the next re-triage has to
//! remember to edit, and a stale number in a file that argues for evidence is
//! the one claim here that cannot be checked by reading the tables.
//!
//! The `test/tls_wire/hello.zig` key-share windows that an earlier pass
//! deliberately left uncovered do have records, because the guard is in the
//! source rather than in the tool's flow analysis: `serverHello` bounds them
//! with `len >= 36` and `len >= 69` itself rather than with the enclosing
//! block, so `data[4..]` cannot run into the bytes behind the extension. The
//! finding is still a `slice-from-fixed-offset-without-len-check` on the tool's
//! side; it is a false positive rather than out of scope. The line numbers are
//! in the records, which is why this comment quotes none.
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
        .sha256 = "33c6a21136f0f68a89bee5fe64ed3a13899de768825ec0a87419c610ab308680",
    },
    .{
        .path = "scripts/gate_scope.zig",
        .sha256 = "fe269f79d0f3ea9d470789a964643bb6fb617d5a5310dde732a2f63eeb4ebb67",
    },
    .{
        .path = "scripts/gate_steps.zig",
        .sha256 = "3882bd038249bf47c88483c4a27f9068d28fbb13e86b6260774e224b5a63ad60",
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
        .sha256 = "0665db5ac29110f17810965571df67578c8d428e960be2b42047b16b976716f9",
    },
    .{
        .path = "src/discovery/resolve.zig",
        .sha256 = "b9ae0d707400772a4832c4e617bfea40b68b9530aa03e4d3ab39d26e49513415",
    },
    .{
        .path = "src/endpoint/tasks.zig",
        .sha256 = "1cf229d09327be54641c179b21bc300c37edd75651def4e95726e7720b55a158",
    },
    .{
        .path = "src/gossip/hyparview.zig",
        .sha256 = "9d197a0739a88cab6cd81519e6b63856022c275a073973ff634b4b19cf15e7fc",
    },
    .{
        .path = "src/node/node_lane.zig",
        .sha256 = "55f4057303b7a35053a7990b9bcc376b3df5fa307c5b62ca592988619a0a4ceb",
    },
    .{
        .path = "src/node/node_lifecycle.zig",
        .sha256 = "0e31e69300547fd8c953f5a4cac03b074fe2130a09927012b3da9ffdc008091f",
    },
    .{
        .path = "src/node/node_relay_serve_tests.zig",
        .sha256 = "ad1ab229c9ac2f6b60acd772644b942af7cf545c7f95896f9caa0a66e4b8c512",
    },
    .{
        .path = "src/node/node_retirement_tests.zig",
        .sha256 = "80dd2bcb5017d2fcd727bc9eff2b87afdfcce87af088772c3fc3a4f23818c09d",
    },
    .{
        .path = "src/node/node_runtime.zig",
        .sha256 = "c4cbc71ed36c6a2d959ba14d60efe30d520cdb817c865daad4d22e6a21237465",
    },
    .{
        .path = "src/node/node_tests.zig",
        .sha256 = "2812925c0af1e79b1e92fbceddd840da7902ffa6a9c4add634fc02ffd2e097c4",
    },
    .{
        .path = "src/relay/frame.zig",
        .sha256 = "8d6ea7c4a6c59ec217c538d50ea50114852ec2943d9c9c9f5271dc59e986654c",
    },
    .{
        .path = "src/transport/quic_bridge.zig",
        .sha256 = "629f794a3163c8147ca77bcf14eea76b73b64631a1dc2999de250f80131340b2",
    },
    .{
        .path = "test/dns_wire/seeds.zig",
        .sha256 = "4c6eb9163c654a0a3b708e4cfd6b5eabbf69e32d60dfd688560526d715183972",
    },
    .{
        .path = "test/interop_runtime.zig",
        .sha256 = "40a04aad46080f5f1b2397fe372d7a42fde13d2f46460af84605a17ededaa70b",
    },
    .{
        .path = "test/loopback_link.zig",
        .sha256 = "4882f7fd5e91276c72beefcbf731e1b6308683da0f450d550cacd801387948a3",
    },
    .{
        .path = "test/loopback_retry_test.zig",
        .sha256 = "c1d855026e1af88e715c909432a8345e684fc95ecc46cdc6ae6cb02b1648c3dc",
    },
    .{
        .path = "test/quic_wire/transport_params.zig",
        .sha256 = "218e4fd770fa6bf6db78c8f9c65b3de349bd8930f9dbb2b49748e3321a6f9bfa",
    },
    .{
        .path = "test/tls_wire/hello.zig",
        .sha256 = "c3f71a5c537018213ac305f98eb4b19d82ac71d287dcabb2395b0c98a214fff2",
    },
    .{
        .path = "test/tls_wire/messages.zig",
        .sha256 = "c34d2ad57a52f3fd00bba63860764537e9651c8f4d8400b3babf391bfe67c625",
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
        .why = "`return described.items;` at gate.zig:293 hands back storage appended with " ++
            "`gpa` at gate.zig:290, and that `gpa` is `init.arena.allocator()` at " ++
            "gate.zig:105 passed through `drive` at gate.zig:111 to the single call site at " ++
            "gate.zig:194; std/start.zig:721-722 builds that arena and `defer " ++
            "arena_allocator.deinit()`s it once `root.main` (std/start.zig:737) returns, so " ++
            "the list dies inside `receipts.write` at gate.zig:187 and there is no " ++
            "per-allocation owner to free it to.",
    },
    .{
        .path = "scripts/gate_paths.zig",
        .line = 259,
        .column = 13,
        .rule = "index-minus-one-without-zero-guard",
        .kind = .false_positive,
        .why = "In `within`, gate_paths.zig:256 returns false when `root.len == 0` and " ++
            "gate_paths.zig:258 returns true when the two lengths are equal, so `root.len " ++
            ">= 1` is already proved when gate_paths.zig:259 evaluates `root[root.len - " ++
            "1]`; the zero-length guard is not carried across those early returns.",
    },
    .{
        .path = "scripts/gate_receipts.zig",
        .line = 149,
        .column = 5,
        .rule = "return-arraylist-items",
        .kind = .arena_owned,
        .why = "`return tools.items;` at gate_receipts.zig:149 hands back storage appended " ++
            "with `gpa` at gate_receipts.zig:147, and that allocator is the arena from " ++
            "gate.zig:105 that std/start.zig:721-722 deinits when `main` returns; the only " ++
            "consumer is the `for (try toolDigests(...), 0..)` at gate_receipts.zig:72, " ++
            "which copies each `Tool` field into the receipt during that call and retains " ++
            "no reference past the write.",
    },
    .{
        .path = "scripts/gate_run.zig",
        .line = 75,
        .column = 34,
        .rule = "slice-loop-reentrant-grow",
        .kind = .false_positive,
        .why = "Column 34 is the `run` of `steps.run` inside `for (group_steps.items) |step|` " ++
            "at 74. `steps.run(gpa, io, step)` takes the `Step` by value " ++
            "(gate_steps.zig:258), so the body holds a copy and no handle to the list the " ++
            "loop walks. `group_steps` is declared at 72, filled once by " ++
            "`steps.buildSteps(gpa, inputs, group, &group_steps)` at 73 before the loop " ++
            "opens, and named nowhere else in the file after 74, so no writer can " ++
            "reallocate `group_steps.items` while this body runs. Every append in the body " ++
            "targets a different list: 76 and 90 append to `results`, the parameter " ++
            "declared at gate_run.zig:40 that points at the `var results` declared at " ++
            "gate.zig:170 and handed in at gate.zig:184, and 91-96 writes the gate's own " ++
            "`text`. An append moves `results.items` and leaves `group_steps.items` where " ++
            "it is; sharing `gpa` with it does not make them one buffer.",
    },
    .{
        .path = "scripts/gate_run.zig",
        .line = 103,
        .column = 30,
        .rule = "slice-loop-reentrant-grow",
        .kind = .false_positive,
        .why = "Column 30 is `triageStatic` in the call at 103, which sits inside the same " ++
            "`for (group_steps.items) |step|` loop at 74. `group_steps` does not reach this " ++
            "call: the parameters are the six declared at 125-132, `gpa`, `result`, " ++
            "`sources`, `results`, `verdict` and `text`, and the loop's iterator is the " ++
            "only handle to `group_steps` in scope. What the call can grow is three other " ++
            "allocations. `results` is the parameter at 129, the arena list declared at " ++
            "gate.zig:170 and passed at gate.zig:184, and `triageStatic` appends to it at " ++
            "138 and 172, which moves `results.items` and not `group_steps.items`. One " ++
            "level down, `zbc.triage` grows a local list of its own, declared at " ++
            "gate_zbc.zig:134 and appended to at gate_zbc.zig:156, gate_zbc.zig:165, " ++
            "gate_zbc.zig:173, gate_zbc.zig:181, gate_zbc.zig:204, gate_zbc.zig:221 and " ++
            "gate_zbc.zig:231; it leaves as `.rejected = rejected.items` at " ++
            "gate_zbc.zig:246, a slice the caller only reads at gate_run.zig:168, so " ++
            "nothing appends to it once it is out. `sources` arrives by value at " ++
            "gate_run.zig:128 as a `scope.Scope`, whose three fields `all`, `first_party` " ++
            "and `hashes` are `[]const` slices at gate_scope.zig:57-68, filled only by " ++
            "`Scope.collect`'s own locals at gate_scope.zig:71-75, which returned before " ++
            "this call. Sharing `gpa` is not aliasing: it is `init.arena.allocator()` " ++
            "(gate.zig:105), and an append reallocates only the list it is called on, so " ++
            "nothing reachable from 103 can invalidate the slice the loop at 74 is walking.",
    },
    .{
        .path = "scripts/gate_scope.zig",
        .line = 75,
        .column = 43,
        .rule = "slice-loop-reentrant-grow",
        .kind = .false_positive,
        .why = "Column 43 is the `append` of `hashes.append` in `for (all.items) |path| try " ++
            "hashes.append(gpa, try hashFile(io, dir, path));`; `hashes` is a " ++
            "`std.ArrayList(Hashed)` declared on the line above at 74 and `all` is a " ++
            "separate `std.ArrayList([]const u8)` declared at 71, both initialised `.empty` " ++
            "so each owns its own backing slice, and the loop reads `all.items` while " ++
            "appending only to `hashes`, which is never appended anywhere else in the file.",
    },
    .{
        .path = "scripts/gate_scope.zig",
        .line = 75,
        .column = 59,
        .rule = "slice-loop-reentrant-grow",
        .kind = .false_positive,
        .why = "Column 59 is the `hashFile` of `hashFile(io, dir, path)`; `pub fn hashFile(io: " ++
            "std.Io, dir: std.Io.Dir, path: []const u8) !Hashed` (166-185) takes no list " ++
            "argument, opens the file at 171, hashes in 64 KiB chunks at 175-181 and " ++
            "appends to nothing, and `all`'s only writes in the function are the `walk(gpa, " ++
            "io, dir, \"\", 0, &all)` at 72 and the in-place `std.mem.sort([]const u8, " ++
            "all.items, {}, lessThanPath)` at 73, both above this loop and neither able to " ++
            "reallocate while the loop runs.",
    },
    .{
        .path = "scripts/gate_scope.zig",
        .line = 79,
        .column = 29,
        .rule = "slice-loop-reentrant-grow",
        .kind = .false_positive,
        .why = "Column 29 is the `append` of `first_party.append` in the loop opened at 77, " ++
            "`for (all.items) |path| {`; `first_party` is declared at 76 and `all` at 71 as " ++
            "two distinct `std.ArrayList([]const u8)` values both initialised `.empty`, and " ++
            "`all` is written nowhere between the sort at 73 and this loop, the only " ++
            "intervening statement being the `hashes` declaration at 74 and the `hashes` " ++
            "append at 75.",
    },
    .{
        .path = "scripts/gate_steps.zig",
        .line = 149,
        .column = 13,
        .rule = "struct-literal-multiple-try",
        .kind = .arena_owned,
        .why = "Column 13 is the `.argv` field of the struct literal spanning 147-150, whose " ++
            "first `try` is the `std.fmt.allocPrint(gpa, \"ast:{s}\", .{path})` at 148 and " ++
            "whose second is this `try gpa.dupe([]const u8, &.{...})`, so a `dupe` failure " ++
            "drops the label string with no errdefer; both allocations come from `gpa`, " ++
            "which `main` sets to `init.arena.allocator()` at gate.zig:105, and that arena " ++
            "releases every byte it handed out when `main` returns at gate.zig:120, so " ++
            "there is no per-allocation owner for an errdefer to free to.",
    },
    .{
        .path = "scripts/gate_steps.zig",
        .line = 255,
        .column = 5,
        .rule = "return-arraylist-items",
        .kind = .arena_owned,
        .why = "Column 5 is the `return argv.items;` of `argvWith`, whose local `var argv: " ++
            "std.ArrayList([]const u8) = .empty` at 252 is filled by `appendSlice` at 253 " ++
            "and 254 from `gpa` (`init.arena.allocator()`, gate.zig:105); the returned " ++
            "slice is stored as `Step.argv` at buildSteps lines 193, 204 and 213, those " ++
            "`Step` values live in `group_steps` (gate_run.zig:72-73) which is never freed " ++
            "and `Step` has no deinit, and `main` returns at gate.zig:120 immediately after " ++
            "the receipt is written at gate.zig:187, so nothing ever owns `argv.items` to " ++
            "free it.",
    },
    .{
        .path = "src/base/base32.zig",
        .line = 87,
        .column = 5,
        .rule = "use-undefined",
        .kind = .false_positive,
        .why = "`out` is declared undefined at 62 and returned at 87, but n>0 is " ++
            "comptime-asserted at 60, the loop writes out[index] at 72 once per whole 5-bit " ++
            "symbol (floor(8n/5) of them) and 82-84 writes exactly one more when 8n mod 5 " ++
            "!= 0, so indices 0..encodedLen(n)-1 with encodedLen(n)=(n*8+4)/5=ceil(8n/5) " ++
            "(45) are all written before the return; the assert at 86 is a Debug-mode check " ++
            "and the count above holds in every mode.",
    },
    .{
        .path = "src/base/base32.zig",
        .line = 87,
        .column = 12,
        .rule = "use-undefined",
        .kind = .false_positive,
        .why = "The `out` operand of that same return: index starts at 0 (65) and advances at " ++
            "73 after each write at 72, so the writes at 72 and 83 cover consecutive " ++
            "indices 0..encodedLen(n)-1 with no gap, and no byte of the array declared at " ++
            "62 is still undefined when it is returned at 87.",
    },
    .{
        .path = "src/base/base32.zig",
        .line = 144,
        .column = 5,
        .rule = "use-undefined",
        .kind = .false_positive,
        .why = "`out` is declared undefined at 124 and returned at 144, but 122 pins text.len " ++
            "to encodedLen(n) before the loop and each 5-bit symbol emits exactly one byte " ++
            "at 135 when bits>=8, so floor(5*ceil(8n/5)/8)==n bytes are written at " ++
            "consecutive indices 0..n-1; the only other exits, at 130 and 142, are error " ++
            "returns, so no partially filled array reaches 144.",
    },
    .{
        .path = "src/base/base32.zig",
        .line = 144,
        .column = 12,
        .rule = "use-undefined",
        .kind = .false_positive,
        .why = "The `out` operand of that same decode return: index starts at 0 (127) and " ++
            "advances at 136 after each write at 135, and a text of encodedLen(n) symbols " ++
            "yields exactly n emitted bytes, so every element of the [n]u8 declared at 124 " ++
            "is written before it is returned at 144.",
    },
    .{
        .path = "src/base/key.zig",
        .line = 141,
        .column = 9,
        .rule = "use-undefined",
        .kind = .false_positive,
        .why = "`name` is declared undefined at 134 and returned at 141; the memcpy at 135-139 " ++
            "fills name[0..52] from base32.encode(dnssec, byte_length=32, ...) whose return " ++
            "width is encodedLen(32)=(256+4)/5=52 (63), and the memcpy at 140 fills " ++
            "name[52..] from the 13-byte \".iroh.invalid\" literal, so the disjoint ranges " ++
            "0..52 and 52..65 partition the declared 52+13=65-byte array.",
    },
    .{
        .path = "src/base/key.zig",
        .line = 141,
        .column = 16,
        .rule = "use-undefined",
        .kind = .false_positive,
        .why = "The `name` operand of that same return: the two memcpy sources have exact " ++
            "comptime widths, 52 from encode and 13 from the suffix literal, which sum to " ++
            "the [dnssec_length + \".iroh.invalid\".len]u8 declared at 133 and 134, so both " ++
            "writes at 135 and 140 land inside the returned array and together cover it.",
    },
    .{
        .path = "src/base/ula.zig",
        .line = 118,
        .column = 5,
        .rule = "use-undefined",
        .kind = .false_positive,
        .why = "`octets` is declared undefined at 115 and returned at 118; the memcpy at 116 " ++
            "fills octets[0..8] from prefixFor's fully written [8]u8 (prefix[0]=prefix_l at " ++
            "104, global_id into [1..6] at 105, subnetFor's [2]u8 into [6..8] at 106) and " ++
            "the memcpy at 117 fills octets[8..16] from the [8]u8 host parameter, so the " ++
            "disjoint halves partition the returned [16]u8 Ula.",
    },
    .{
        .path = "src/base/ula.zig",
        .line = 118,
        .column = 12,
        .rule = "use-undefined",
        .kind = .false_positive,
        .why = "The `octets` operand of that same return: the writes at 116 and 117 cover " ++
            "exactly [0..8) and [8..16) of the 16-byte array declared at 115, with no index " ++
            "left unwritten, so nothing undefined reaches the caller at 118.",
    },
    .{
        .path = "src/blobs/protocol.zig",
        .line = 2597,
        .column = 5,
        .rule = "use-undefined",
        .kind = .false_positive,
        .why = "The returned `out` is `[2 * max_dumped_bytes]u8` = [128]u8 declared undefined " ++
            "at 2589, and the loop at 2592-2595 writes out[0..2*shown) while @memset at " ++
            "2596 writes out[2*shown..128); shown = @min(bytes.len, max_dumped_bytes) at " ++
            "2591 with max_dumped_bytes = 64 at 2577, so shown*2 <= 128 and the two " ++
            "adjacent regions cover all 128 bytes that `{s}` prints at 2582-2583.",
    },
    .{
        .path = "src/blobs/protocol.zig",
        .line = 2597,
        .column = 12,
        .rule = "use-undefined",
        .kind = .false_positive,
        .why = "The `out` operand of that same return; the return type is the fixed array `[2 " ++
            "* max_dumped_bytes]u8` (2588), not a slice, and the loop prefix [0..2*shown) " ++
            "and the @memset tail [2*shown..128) at 2596 partition the whole array, so no " ++
            "undefined byte and no partially filled owned capacity reaches the caller.",
    },
    .{
        .path = "src/blobs/range_spec.zig",
        .line = 1126,
        .column = 5,
        .rule = "use-undefined",
        .kind = .false_positive,
        .why = "The returned `out` is `[2 * max_dumped_bytes]u8` = [64]u8 declared undefined " ++
            "at 1118, and the loop at 1121-1124 writes out[0..2*shown) while @memset at " ++
            "1125 writes out[2*shown..64); shown = @min(bytes.len, max_dumped_bytes) at " ++
            "1120 with max_dumped_bytes = 32 at 1106, so shown*2 <= 64 and the two adjacent " ++
            "regions cover all 64 bytes that `{s}` prints at 1111-1112.",
    },
    .{
        .path = "src/blobs/range_spec.zig",
        .line = 1126,
        .column = 12,
        .rule = "use-undefined",
        .kind = .false_positive,
        .why = "The `out` operand of that same return; the return type is the fixed array `[2 " ++
            "* max_dumped_bytes]u8` (1117), not a slice, and the written prefix " ++
            "[0..2*shown) and the @memset tail [2*shown..64) at 1125 partition the whole " ++
            "array, so no undefined byte and no partially filled owned capacity escapes.",
    },
    .{
        .path = "src/discovery/item.zig",
        .line = 454,
        .column = 5,
        .rule = "use-undefined",
        .kind = .false_positive,
        .why = "`corpusIds` declares `var ids: [3]key.NodeId = undefined` at 448 and returns " ++
            "it at 454; the only loop exit before that return is the `try` at 452 returning " ++
            "the error union, and the loop at 449-453 has no break or continue, so reaching " ++
            "454 means three iterations ran and `id.*` at 452 wrote indices 0, 1 and 2 of " ++
            "the [3] array whole.",
    },
    .{
        .path = "src/discovery/item.zig",
        .line = 454,
        .column = 12,
        .rule = "use-undefined",
        .kind = .false_positive,
        .why = "The `ids` operand of that same `return` at 454; every element a reader can " ++
            "reach was written by `id.*` at 452 during the third iteration of 449-453, and " ++
            "the only earlier exit is the `try` at 452 which leaves the function before the " ++
            "read.",
    },
    .{
        .path = "src/discovery/lookup_io.zig",
        .line = 1670,
        .column = 20,
        .rule = "index-type-narrowing-wraparound",
        .kind = .false_positive,
        .why = "`octet` takes a u8 (1653), so the `@intCast(value.len)` at 1670 narrows a " ++
            "usize; `label`'s only caller is `name` at 1680, and `name`'s only callers are " ++
            "1747/1751/1762 (`sweep_name = \"_iroh.example.\"` at 1615) and 1759 " ++
            "(`\"other.example.\"`), while `Message` is a file-private `const` at 1635 so " ++
            "no other file can widen the set \xe2\x80\x94 splitting either name on `.` " ++
            "yields `example` (7) as the longest part, the empty trailing part is dropped " ++
            "at 1679, and 7 < 255 cannot wrap.",
        // Proof kept from StaticDiscoveryWireRetriage; StaticDiscoveryReview (own proof) read these
        // same bytes and reached false_positive without disagreement.
    },
    .{
        .path = "src/discovery/lookup_io.zig",
        .line = 1711,
        .column = 24,
        .rule = "index-type-narrowing-wraparound",
        .kind = .false_positive,
        .why = "`txt`'s only callers are 1752, 1754, 1756, 1760 and 1763, every argument a " ++
            "comptime literal slice (`swept_first_strings` at 1628, then 33, 20 and 22 " ++
            "octets at 1760, 1754, 1756, 1763), so the `@intCast(string.len)` at 1711 sees " ++
            "a length of at most the 33 octets of `relay=https://elsewhere.example./` at " ++
            "1760 and cannot leave the u8 range `octet` takes at 1653.",
        // Proof kept from StaticDiscoveryWireRetriage; StaticDiscoveryReview (own proof) read these
        // same bytes and reached false_positive without disagreement.
    },
    .{
        .path = "src/discovery/resolve.zig",
        .line = 706,
        .column = 47,
        .rule = "index-minus-one-without-zero-guard",
        .kind = .false_positive,
        .why = "`owned` starts empty at 644 and `owned.append(alloc, data)` at 692 has a catch " ++
            "arm at 693-694 that frees `data` and returns, so reaching 706 means items.len " ++
            ">= 1; nothing between 692 and 706 appends to or removes from `owned` " ++
            "(`endpoint.insert` at 696 only touches the address list), so " ++
            "`owned.items[owned.items.len - 1]` is the `data` just appended, and " ++
            "`NodeAddr.insert` returns null at src/base/node_addr.zig:60 before copying " ++
            "`addr` when the address is already present, so nothing refers to that copy and " ++
            "freeing it is the lifetime-correct act.",
    },
    .{
        .path = "src/endpoint/tasks.zig",
        .line = 111,
        .column = 25,
        .rule = "index-minus-one-without-zero-guard",
        .kind = .false_positive,
        .why = "Column 25 is the '[' of slots[live - 1], and line 110's `const index = " ++
            "indexOf(slots, live, id) orelse return live;` already excludes live == 0: " ++
            "indexOf's only non-null return is tasks.zig:70 `if (slots[index].id == id) " ++
            "return index;`, reached only under tasks.zig:69 `while (index < live)`, so a " ++
            "non-null result proves index < live, hence live >= 1 and live - 1 cannot " ++
            "underflow. The same loop bound proves live <= slots.len on every path that " ++
            "reaches 111 (indexOf read slots[index] with index < live), and that bound is " ++
            "maintained by callers: tasks.zig:94 `if (!room(slots, live)) return null;` " ++
            "plus room's `live < slots.len`, with endpoint.zig:632-635 " ++
            "`task_table.hold(...) orelse return ...refuse` incrementing live only on a " ++
            "non-null hold. tasks.zig:252-254 already exercises the empty-window reap and " ++
            "asserts live stays 0. The guard deleted this wave was unreachable, and " ++
            "re-adding it would be a record that exists only to silence the diagnostic; the " ++
            "subtraction is provably safe from the source above.",
    },
    .{
        .path = "src/gossip/hyparview.zig",
        .line = 2818,
        .column = 5,
        .rule = "use-undefined",
        .kind = .false_positive,
        .why = "describe's `return` at 2818: the only caller is expectSameActions at 2823, " ++
            "which consumes exactly left_actions[0..want.count()] at 2831 after " ++
            "expectEqual(want.count(), got.count()) at 2828, so the tail of the " ++
            "[max_actions]Action array declared `undefined` at 2788 is never read; the loop " ++
            "at 2790 writes precisely out.count() elements because Actions.slice " ++
            "(plumtree.zig:221) returns self.items.items and Actions.count " ++
            "(plumtree.zig:213) returns that slice's .len, and std.debug.assert at 2789 " ++
            "bounds the loop by max_actions = 16 at 2785.",
    },
    .{
        .path = "src/gossip/hyparview.zig",
        .line = 2818,
        .column = 12,
        .rule = "use-undefined",
        .kind = .false_positive,
        .why = "The `described` operand of that same return at 2818: every prong of the switch " ++
            "at 2791-2817 assigns all three Action fields (tag 2776, to 2777, listed 2778) " ++
            "\xe2\x80\x94 the .send_message inner switch sets .listed = reply.nodes.count " ++
            "at 2795 and .listed = 0 on the else prong at 2797 \xe2\x80\x94 so each written " ++
            "element is whole and no undefined byte escapes into a caller-visible element.",
    },
    .{
        .path = "src/gossip/hyparview.zig",
        .line = 4529,
        .column = 5,
        .rule = "use-undefined",
        .kind = .false_positive,
        .why = "describeTopic's `return` at 4529: the only caller is expectSameTopicActions at " ++
            "4532, which reads exactly left_actions[0..want.count()] and " ++
            "right_actions[0..got.count()] at 4540 after expectEqual(want.count(), " ++
            "got.count()) at 4537 makes those counts equal, so the tail past count of the " ++
            "[max_actions]TopicAction declared `undefined` at 4492 is never read; the loop " ++
            "at 4494 writes exactly out.count() elements through the same " ++
            "Actions.slice/Actions.count pair, bounded by std.debug.assert at 4493.",
    },
    .{
        .path = "src/gossip/hyparview.zig",
        .line = 4529,
        .column = 12,
        .rule = "use-undefined",
        .kind = .false_positive,
        .why = "The `described` operand of that same return at 4529: all three TopicAction " ++
            "fields (tag 4485, to 4486, layer 4487) are assigned in every prong at " ++
            "4495-4527, including .layer from the .swarm/.gossip switch at 4498-4501, " ++
            ".schedule_timer at 4503-4516, .disconnect_peer at 4517, .emit_event at " ++
            "4518-4526 and .peer_data at 4527.",
    },
    .{
        .path = "src/node/node_lane.zig",
        .line = 10,
        .column = 62,
        .rule = "aligncast-on-byte-slice",
        .kind = .false_positive,
        .why = "`connection.ptr` is only `*anyopaque` (router.zig:176-179); every value this " ++
            "node hands a lane is `@ptrCast(&handle)` at node_accept.zig:219, :233 and :243 " ++
            "over `var handle: Connection` (node_accept.zig:210, :321), and " ++
            "`node_protocol.Connection` holds a `quic_conn.Conn` and a `usize` " ++
            "(node_protocol.zig:74-77), so the address already meets `@alignOf(usize)` and " ++
            "the check `@alignCast` inserts cannot fail \xe2\x80\x94 the only other " ++
            "`accept` invocations for this table are node.zig:74 (the custom handler, " ++
            "reached from this same handle) and node_accept.zig:322.",
        // Proof kept from StaticNodeRetriage; StaticNodeReview (own proof) read these same bytes
        // and reached false_positive without disagreement.
    },
    .{
        .path = "src/node/node_lifecycle.zig",
        .line = 81,
        .column = 20,
        .rule = "use-undefined",
        .kind = .false_positive,
        .why = "`offer_list` is left `undefined` at 59 only until `register(self)` at 80, " ++
            "which fills `self.lanes` at 186 and `self.table` at 206; `Router.offers` " ++
            "(router.zig:399-404) writes `out[count]` on every iteration and returns " ++
            "exactly that count, so the slice `[0..count]` is the written prefix and " ++
            "elements at or past it are never read \xe2\x80\x94 the call the tool cannot " ++
            "follow is the one that establishes the bound.",
    },
    .{
        .path = "src/node/node_relay_serve_tests.zig",
        .line = 43,
        .column = 63,
        .rule = "catch-error-panic",
        .kind = .justified_panic,
        .why = "The serving relay's teardown helper moved out of node_relay_serve.zig into " ++
            "this file when the pass driver was split, and the finding moved with it " ++
            "unchanged: `closeOnExit` returns void (41) with `defer lifecycle.deinit(node)` " ++
            "at 42, and both of its call sites are test teardowns, `defer " ++
            "closeOnExit(relay, &at)` (104) and `defer closeOnExit(peer, &at)` (120). " ++
            "`closing.close` is `Error!void` (node_close.zig:15-18), fallible through `try " ++
            "finish` (:17), `try dispatch.performShutdown` (:35), `try cancelLane` (:98) " ++
            "and `try connection_close.closeOne` (:122), and the real `t.io` plus the live " ++
            "`at.*` stamped by every pass make the endpoint close reachable here. A void " ++
            "teardown helper has no channel for that failure, and Zig's panic aborts and " ++
            "unwinds nothing, so it is not a cleanup path; swallowing it would let the " ++
            "suite report green over a node that never closed.",
    },
    .{
        .path = "src/node/node_retirement_tests.zig",
        .line = 111,
        .column = 61,
        .rule = "catch-error-panic",
        .kind = .justified_panic,
        .why = "`closeOnExit` returns void (109) and its one call site is the teardown `defer " ++
            "closeOnExit(server, at)` (225); `node_close.close` is `Error!void` " ++
            "(node_close.zig:15, fallible via `try finish` :17) and the real `t.io` and " ++
            "instant on 111 make it reachable, so a void helper has no channel and the " ++
            "panic is the fatal verdict that ends the run \xe2\x80\x94 it unwinds nothing " ++
            "and frees nothing \xe2\x80\x94 whereas swallowing would let a retirement test " ++
            "report green over a node left mid-shutdown. This is the reachable case " ++
            "node_runtime.zig:97 is not: there a literal null Io skips the only reachable " ++
            "try.",
    },
    .{
        .path = "src/node/node_retirement_tests.zig",
        .line = 170,
        .column = 65,
        .rule = "catch-error-panic",
        .kind = .justified_panic,
        .why = "`Dialer.deinit` returns void (164) and its three call sites are teardowns " ++
            "(233, 235, 237); `self.* = undefined` (167) is the terminal state that makes a " ++
            "second call read the invalid fixture instead of freeing `peers` (168) and " ++
            "releasing `node` (169) again, and the `Error!void` `node_close.close` " ++
            "(node_close.zig:15) it guards has no channel out of a void helper, so the " ++
            "panic is a fatal verdict that unwinds nothing \xe2\x80\x94 not a cleanup " ++
            "\xe2\x80\x94 and swallowing it would release a peer node that never closed " ++
            "while the test reported green.",
    },
    .{
        .path = "src/node/node_runtime.zig",
        .line = 97,
        .column = 66,
        .rule = "catch-error-panic",
        .kind = .justified_panic,
        .why = "`dispose` returns void (96) and hands `finish` `(null, null)`, so a failure " ++
            "has no channel; the walk's only fallible step is `closeConnections` at " ++
            "node_dispatch.zig:242 behind `if (io)` (240) and `if (at)` (241), and the doc " ++
            "at 94-95 calls this the non-failing backstop \xe2\x80\x94 the panic reports a " ++
            "failure that would otherwise be swallowed rather than asserting one is " ++
            "impossible.",
    },
    .{
        .path = "src/node/node_tests.zig",
        .line = 73,
        .column = 67,
        .rule = "catch-error-panic",
        .kind = .justified_panic,
        .why = "`closedOnExit` returns void with `defer lifecycle.deinit(node)` at 72 and is " ++
            "registered by `defer` only (331, 346, 353, 534, 641, 652, 1259, 1270, 1288, " ++
            "1295, 2055, 2065, 2072, 2107, 2130, 2149, 2160, 2221); `closing.close` is " ++
            "`Error!void` (node_close.zig:15-18) and a swallowed error would leave `deinit` " ++
            "to do nothing but `std.log.err` the abandoned phase " ++
            "(node_lifecycle.zig:217-224) before freeing a node whose socket may still be " ++
            "open, so the panic is the only channel a test has.",
    },
    .{
        .path = "src/relay/frame.zig",
        .line = 2553,
        .column = 5,
        .rule = "use-undefined",
        .kind = .false_positive,
        .why = "The `return` of `hexdump` reads no undefined byte: `out` is `[2 * " ++
            "max_dumped_bytes]u8` with `max_dumped_bytes = 80` (2533), `shown = " ++
            "@min(bytes.len, 80)` (2547), the loop at 2548-2551 writes indices `0 .. " ++
            "2*shown - 1` (both `index * 2` and `index * 2 + 1` for `index < shown`), and " ++
            "the memset at 2552 writes `[2*shown .. 160)`; those two regions are disjoint " ++
            "and their union is the whole 160-byte array for every `bytes.len`, including " ++
            "the ends: `shown = 0` leaves the whole array to the memset, `shown = 80` " ++
            "leaves it to the loop and makes `out[160 ..]` an empty slice at the end rather " ++
            "than past it, so 2553 returns a fully initialised array.",
        // Proof kept from StaticRelayInteropRetriage; StaticGossipRelayReview (own proof) read
        // these same bytes and reached false_positive without disagreement.
    },
    .{
        .path = "src/relay/frame.zig",
        .line = 2553,
        .column = 12,
        .rule = "use-undefined",
        .kind = .false_positive,
        .why = "The `out` operand of that same `return out;` is the array initialised by the " ++
            "loop at 2548-2551 over `[0, 2*shown)` and the memset at 2552 over `[2*shown, " ++
            "160)` with `shown = @min(bytes.len, max_dumped_bytes)` (2547) and " ++
            "`max_dumped_bytes = 80` (2533): disjoint regions covering all 160 indices, so " ++
            "the operand carries no undefined byte.",
        // Proof kept from StaticRelayInteropRetriage; StaticGossipRelayReview (own proof) read
        // these same bytes and reached false_positive without disagreement.
    },
    .{
        .path = "src/transport/quic_bridge.zig",
        .line = 383,
        .column = 16,
        .rule = "use-undefined",
        .kind = .false_positive,
        .why = "Column 16 is the '.' of the returned struct literal, whose only " ++
            "undefined-derived field is .alpn at line 390 " ++
            "`self.alpn_list[0..self.alpn_count]`; every byte of that slice is written " ++
            "first. Line 381 sets alpn_list undefined and line 382 " ++
            "`@memcpy(self.alpn_list[0..config.alpns.len], config.alpns);` writes exactly " ++
            "indices [0, config.alpns.len) of the [config_mod.max_alpns][]const u8 array " ++
            "declared at line 163. Line 390 hands the core alpn_list[0..self.alpn_count], " ++
            "and create sets .alpn_count = config.alpns.len at line 225 before the single " ++
            "buildTlsConfig call at line 238, passing the same by-value `config` " ++
            "\xe2\x80\x94 so the slice range is exactly the range the memcpy covered. " ++
            "alpn_count is only ever written at 225 and lowered by withdrawAlpn at 350, " ++
            "never raised, so the slice can never grow past what was written; the slots " ++
            "above it stay undefined and are never read (withdrawAlpn's walk and its " ++
            "@memset at 349 are both inside the previously written [0..alpn_count), and the " ++
            "test at 2403 reads alpn_list[0..offers.len]). The proof does not even need the " ++
            "lower bound: with config.alpns.len == 0 the slice is empty, and validateAlpns " ++
            "(quic_config.zig:84-91) has already refused that at line 212 before any " ++
            "allocation.",
    },
    .{
        .path = "test/dns_wire/seeds.zig",
        .line = 85,
        .column = 20,
        .rule = "index-type-narrowing-wraparound",
        .kind = .false_positive,
        .why = "`Writer.label`'s only callers are 95, whose `part` comes from `name` splitting " ++
            "a name, and 200's literal \"fwd\"; `name` is reached only from `question` at " ++
            "110 with `asked` (22, \"_iroh.example.\") and from " ++
            "test/dns_wire/oracle.zig:309 with the same `seeds.asked`, 93-94 skips empty " ++
            "parts, and the longest part of \"_iroh.example.\" is \"example\" at 7 bytes, " ++
            "so `@intCast(value.len)` at 85 cannot wrap.",
    },
    .{
        .path = "test/dns_wire/seeds.zig",
        .line = 134,
        .column = 29,
        .rule = "index-type-narrowing-wraparound",
        .kind = .false_positive,
        .why = "`Writer.txt`'s in-file callers 219, 239, 250, 258, 260 and 262 pass literals " ++
            "of at most 41 bytes (\"relay=https://use1-1.relay.iroh.network./\"), and its " ++
            "one caller outside this file, test/dns_wire/oracle.zig:310, only ever sees a " ++
            "`texts` entry the split at test/dns_wire/oracle.zig:294 bounds to " ++
            "1..=seeds.max_character_string (255 at 39), so `string.len` at 134 is 1..255 " ++
            "and fits the u8 length octet.",
    },
    .{
        .path = "test/interop_runtime.zig",
        .line = 653,
        .column = 18,
        .rule = "free-without-null-then-check",
        .kind = .false_positive,
        .why = "`self.buf` is allocated exactly once, at 613, with its init-time errdefer at " ++
            "614 armed only while `Peer.init` is still running (613 is its last statement, " ++
            "615 is its closing brace), and freed exactly once here by `self.gpa`, which is " ++
            "`config.gpa` from 569; no statement after this one reads the field (654-656 " ++
            "free the other three buffers, 657 reads `self.map` and `self.gpa`, 658 reads " ++
            "`self.socket`, 659 branches on the local `refusal` captured at 645, and the " ++
            "function ends at 660), so there is no check left to be misled by a non-null " ++
            "pointer, and the one other reader in the file, `self.socket.receive(self.io, " ++
            "self.buf, ...)` at 750 in `take`, is unreachable once teardown starts because " ++
            "`windDown`'s only call site in the tree is `Peer.deinit` at 665, whose next " ++
            "statement on every path is `self.* = undefined` at 673 \xe2\x80\x94 including " ++
            "the refusal path that returns at 659 \xe2\x80\x94 and `deinit`'s only call " ++
            "site is `defer peer.deinit()` at test/interop_peer.zig:265, registered after " ++
            "`try peer.init(...)` at 249 has returned, so no path reaches this free twice.",
    },
    .{
        .path = "test/interop_runtime.zig",
        .line = 654,
        .column = 18,
        .rule = "free-without-null-then-check",
        .kind = .false_positive,
        .why = "`self.scratch` is the one allocation at 611 (`try config.gpa.alloc(u8, " ++
            "scratch_room)`) whose errdefer at 612 can only cover a later `init` step, and " ++
            "it is freed exactly once here by the same allocator assigned at 569; after 654 " ++
            "the field is never named (655 and 656 free `out` and `egress`, 657 " ++
            "`self.map.deinit(self.gpa)`, 658 `self.socket.close()`, 659 a local, end 660) " ++
            "and its only other reader is `self.bridge.recv(..., self.scratch, ...)` at 782 " ++
            "in `take`, a pass path that cannot run after teardown; destruction is the " ++
            "sole-caller chain \xe2\x80\x94 `windDown` at 632 has exactly one call site, " ++
            "665 inside `deinit`, which poisons `self.*` at 673 on every path, and `deinit` " ++
            "has exactly one, `defer peer.deinit()` at test/interop_peer.zig:265 after the " ++
            "successful `try peer.init` at 249 \xe2\x80\x94 so a second free is unreachable.",
    },
    .{
        .path = "test/interop_runtime.zig",
        .line = 655,
        .column = 18,
        .rule = "free-without-null-then-check",
        .kind = .false_positive,
        .why = "`self.out` is the one allocation at 609 (`try config.gpa.alloc(u8, " ++
            "send_room)`) with its init errdefer at 610, freed exactly once here by " ++
            "`self.gpa` (569); nothing after 655 reads it \xe2\x80\x94 656 frees `egress`, " ++
            "657 `self.map.deinit(self.gpa)`, 658 `self.socket.close()`, 659 `if (refusal) " ++
            "|err| return err` which inspects the local `?dial_mod.DestroyError` captured " ++
            "at 645 and no buffer, end 660 \xe2\x80\x94 and its only other use is " ++
            "`conn.drain(self.egress, self.out, at, self.random())` at 734 in `drain`, " ++
            "which the pass loop reaches only before teardown; as at 653 and 654 the freed " ++
            "pointer cannot be observed again, because the only `windDown` call site (665) " ++
            "is inside `deinit`, which writes `self.* = undefined` at 673 whether or not " ++
            "659 returned a refusal, and `deinit`'s only call site is `defer peer.deinit()` " ++
            "at test/interop_peer.zig:265.",
    },
    .{
        .path = "test/interop_runtime.zig",
        .line = 656,
        .column = 18,
        .rule = "free-without-null-then-check",
        .kind = .false_positive,
        .why = "`self.egress` is the one allocation at 607 (`try config.gpa.alloc(Egress, " ++
            "max_egress)`), released exactly once here by `self.gpa` (569) with the init " ++
            "errdefer at 608 covering only a later `init` failure; after 656 no statement " ++
            "names it \xe2\x80\x94 657 releases the address map, 658 closes the descriptor " ++
            "opened at 589, 659 branches on a local, end 660 \xe2\x80\x94 and its only " ++
            "reader is 734 in `drain`, a pass path, so the second free the rule asks a null " ++
            "for has no reachable path: `windDown` (632) is called from exactly one place, " ++
            "665 in `deinit`, which poisons `self.*` at 673 on every path, and `deinit` is " ++
            "registered once, at test/interop_peer.zig:265, after `try peer.init(...)` at " ++
            "249 succeeded.",
    },
    .{
        .path = "test/loopback_link.zig",
        .line = 129,
        .column = 5,
        .rule = "use-undefined",
        .kind = .false_positive,
        .why = "spkiOf returns the local declared undefined at 126 (`var out: " ++
            "[quic_config.spki_length]u8 = undefined;`) only after the two @memcpy calls at " ++
            "127-128 have between them covered it: 127 writes `out[0..header.len]` = " ++
            "[0..12) because the `header` literal at 120-125 holds exactly 12 initializers, " ++
            "and 128 writes `out[header.len..]` = [12..44); @memcpy requires its two " ++
            "operands to be equal-length, and `spki_length` is " ++
            "`quic.tls13.ed25519_spki_len` = 44 (src/transport/quic_config.zig:43; " ++
            "vendor/quic/src/quic/tls13.zig:190) while the source at 128 is " ++
            "`&node.toBytes()` of type `[byte_length]u8` with `byte_length = " ++
            "Ed25519.PublicKey.encoded_length` (src/base/key.zig:55 and :77), so 44 - 12 == " ++
            "32 is a comptime requirement of the type checker, not an assumption -- " ++
            "tls13.ed25519Spki (vendor/quic/src/quic/tls13.zig:218-223) is the same 12 + " ++
            "ed25519_key_len split into the same 44 bytes and compiles in the same build, " ++
            "which forces ed25519_key_len == 32 there too. The two written regions are " ++
            "adjacent and disjoint, so the return at 129 exposes no byte the calls above " ++
            "did not write.",
    },
    .{
        .path = "test/loopback_link.zig",
        .line = 129,
        .column = 12,
        .rule = "use-undefined",
        .kind = .false_positive,
        .why = "The `out` operand of that same `return out;` (column 12 of line 129); its " ++
            "coverage is the one proved for the return itself at 127-128 -- out[0..12] " ++
            "written from the 12-byte header literal at 120-125, then out[12..44] written " ++
            "from `&node.toBytes()` -- with the 12 + 32 == spki_length == 44 split forced " ++
            "at comptime by @memcpy's equal-length rule against ed25519_spki_len = 44 " ++
            "(vendor/quic/src/quic/tls13.zig:190) and NodeId.toBytes's [byte_length]u8 " ++
            "(src/base/key.zig:55, :77), so every byte this operand hands the caller was " ++
            "written first.",
    },
    .{
        .path = "test/loopback_retry_test.zig",
        .line = 335,
        .column = 24,
        .rule = "truncate-len-to-narrow-int",
        .kind = .false_positive,
        .why = "`@truncate(issued.len)` at column 24 of line 335 narrows the token length into " ++
            "the u8 lvalue `datagram[at + 1]` (the array's element type is u8, declared at " ++
            "310). The bound is the token's own storage, not an assumption: `issued` is " ++
            "`token.slice()` (288) over `RetryToken.bytes: [max_token_length]u8` and " ++
            "`length` (src/transport/retry.zig:186-194, slice at 191-193), the token came " ++
            "from `Bridge.issueRetryToken` (src/transport/quic_bridge.zig:569-577), and the " ++
            "one `length` on that path is what `Gate.issue` assigns from " ++
            "`packet.generateRetryToken`'s return (src/transport/retry.zig:256-268). That " ++
            "return is `TOKEN_NONCE_LEN + pt_len + TOKEN_TAG_LEN` " ++
            "(vendor/quic/src/quic/packet.zig:933) with `pt_len = pt_fbs.seek` over a " ++
            "fixedBufferStream on `[TOKEN_MAX_PLAINTEXT_LEN]u8` whose every write is " ++
            "try-checked and so cannot pass that buffer (packet.zig:902-915), hence pt_len " ++
            "<= TOKEN_MAX_PLAINTEXT_LEN = 1 + 20 + 1 + 20 + 8 + 23 = 73 (packet.zig:871, " ++
            "with address.identity_length = 23 at vendor/quic/src/address.zig:159) and " ++
            "issued.len <= max_token_length = TOKEN_MAX_LEN = 12 + 73 + 16 = 101 " ++
            "(packet.zig:867-873; retry.zig:98) < 256, so the retained low 8 bits are the " ++
            "whole length -- this fixture's own 8-byte `original_dcid`/`retry_scid` " ++
            "(113-114) give 12 + 49 + 16 = 77. The bound is a type-level maximum that holds " ++
            "in every optimize mode; the on-site `std.debug.assert(issued.len < 1 << 14)` " ++
            "at 333 is what covers the two-byte varint width and the `>> 8` intCast at 334, " ++
            "not the u8, so the exactness of this narrowing does not rest on that runtime " ++
            "guard.",
    },
    .{
        .path = "test/quic_wire/transport_params.zig",
        .line = 223,
        .column = 39,
        .rule = "use-undefined",
        .kind = .false_positive,
        .why = "The `token` operand of the same assignment at " ++
            "test/quic_wire/transport_params.zig:223, and the coverage argument is the one " ++
            "proved for the destination operand: 221 declares `var token: [16]u8 = " ++
            "undefined;`, 220 returns unless `length == 16`, and the `@memcpy(token[0..], " ++
            "value)` at 222 copies the whole 16-byte `value` built at 197 under the bound " ++
            "at 196. Every byte this operand hands `out.reset_token` was written on the " ++
            "line above.",
        // Proof kept from ZbcRetriage; WaveOneEvidenceMap (own proof) read these same bytes and
        // reached false_positive without disagreement.
    },
    .{
        .path = "test/tls_wire/hello.zig",
        .line = 381,
        .column = 24,
        .rule = "slice-from-fixed-offset-without-len-check",
        .kind = .false_positive,
        .why = "Re-read in the current bytes, not shifted from the old 375:24 anchor. Line 381 " ++
            "is `algs = data[2..];` and column 24 is the `[` of that slice. `data` is " ++
            "`ext[p + 4 ..][0..len]` built at 339, so data.len == len exactly, inside the " ++
            "walk whose own bound `if (p + 4 + len > ext.len) break;` at 338 refuses an " ++
            "entry running past the block. The signature_algorithms arm's guard at 380, `if " ++
            "(len < 2 or @as(usize, be16(data)) + 2 != len or len % 2 != 0) return " ++
            "error.DecodeError;`, returns unless len >= 2 \xe2\x80\x94 and the `be16(data)` " ++
            "and `+ 2 == len` terms each independently require two bytes \xe2\x80\x94 so " ++
            "data.len >= 2 at 381 and data[2..] starts inside the window the peer declared. " ++
            "The u16 widening at 376-379 changed only the width of be16's result, not this " ++
            "bound.",
    },
    .{
        .path = "test/tls_wire/hello.zig",
        .line = 484,
        .column = 35,
        .rule = "slice-from-fixed-offset-without-len-check",
        .kind = .false_positive,
        .why = "Re-read in the current bytes, not shifted from the old 478:35 anchor. Line 484 " ++
            "is `const klen = be16(data[2..]);` and column 35 is the `[`. `data` is " ++
            "`ext[at..][0..len]` built at 479 with `if (at + len > ext.len) return " ++
            "error.DecodeError;` at 478, so data.len == len; the key_share guard `if (len < " ++
            "4) return error.DecodeError;` at 482 leaves data.len >= 4 before " ++
            "be16(data[2..]) reads the two bytes it needs. Same shape as 381, four bytes " ++
            "instead of two, and the same guard-then-slice order.",
    },
    .{
        .path = "test/tls_wire/hello.zig",
        .line = 498,
        .column = 29,
        .rule = "slice-from-fixed-offset-without-len-check",
        .kind = .false_positive,
        .why = "Re-read in the current bytes, not shifted from the old 492:29 anchor. Line 498 " ++
            "is `share = data[4..][0..32];` and column 29 is the first `[`. This arm runs " ++
            "only under `named == x25519 and klen == 32 and len >= 36` at 496, over the " ++
            "`ext[at..][0..len]` window built at 479, so data[4..] holds at least 32 bytes " ++
            "and data[4..][0..32] ends at 36 <= len \xe2\x80\x94 inside the key_share " ++
            "extension the peer declared, not the block behind it. The bound is the one " ++
            "this arm was written to carry (485-495 explains why it is stricter than the " ++
            "decoder and why it stays).",
    },
    .{
        .path = "test/tls_wire/hello.zig",
        .line = 501,
        .column = 29,
        .rule = "slice-from-fixed-offset-without-len-check",
        .kind = .false_positive,
        .why = "Re-read in the current bytes, not shifted from the old 495:29 anchor. Line 501 " ++
            "is `share = data[4..][0..65];` and column 29 is the first `[`. The same bound " ++
            "one arm down: `named == secp256r1 and klen == 65 and len >= 69` at 499 gives " ++
            "data.len >= 69 over the ext[at..][0..len] window built at 479, so " ++
            "data[4..][0..65] ends at 69 <= len and cannot reach past the extension.",
    },
    .{
        .path = "test/tls_wire/hello.zig",
        .line = 1035,
        .column = 14,
        .rule = "index-type-narrowing-wraparound",
        .kind = .false_positive,
        .why = "Re-read in the current bytes, not shifted from the old 1029:14 anchor. Line " ++
            "1035 is `out[8] = @intCast(der.len >> 16);` and column 14 is the `@` of that " ++
            "cast. entry_len = 3 + der.len + 2 and body_len = 1 + 3 + entry_len = der.len + " ++
            "9 at 1024-1025, and `if (out.len < 4 + body_len) return " ++
            "error.TestUnexpectedResult;` at 1026 runs before any write, so der.len <= " ++
            "out.len - 13; certificateMessage has exactly one call, at 1531, passing the " ++
            "`var buf: [256]u8` declared at 1530 as out, hence der.len <= 243 and der.len " ++
            ">> 16 == 0, so the narrowing is exact and cannot wrap. The der at 1531 is " ++
            "`tls13.ed25519Spki(&somebody_elses_node)` (1529) whose return type is the " ++
            "fixed `[ed25519_spki_len]u8` = [44]u8 (vendor/quic/src/quic/tls13.zig:190,218)," ++
            " so der.len == 44 at comptime and 44 >> 16 == 0. No guard was removed to reach " ++
            "that: the out.len check at 1026 is what carries it, and it is still first.",
    },
    .{
        .path = "test/tls_wire/messages.zig",
        .line = 497,
        .column = 14,
        .rule = "use-undefined",
        .kind = .false_positive,
        .why = "Re-keyed, not shifted: the ledger's 472:14 is this same statement, moved by " ++
            "the 25 lines the certificate-type table fix added above it. Line 497 is `for " ++
            "(out) |slice| {` and column 14 is the `out` of `for (out)`. `out` is " ++
            "`[chain_bound = 2][]const u8` declared undefined at 464, and 466 `for (&out) " ++
            "|*slot| slot.* = untouched;` is an unconditional two-iteration walk over the " ++
            "whole array whose body has no break, continue or return, so it cannot exit " ++
            "early and both slots hold `untouched` (67) before " ++
            "`tls13.parseCertificateList(d, out[0..])` at 468 can replace them; the " ++
            "by-value walk at 497 therefore copies nothing undefined. The walk that can " ++
            "exit early is refCertificateList's while at 169-182, which writes only want[n] " ++
            "for n < want.len (guarded at 174) immediately before n += 1 at 176, and every " ++
            "early return from it goes to the `else |reason|` arm at 488 that never reads " ++
            "want; the sole reader of want is `want[0..n]` at 478, where n is exactly the " ++
            "count that write loop reached.",
    },
    .{
        .path = "test/vendored_scanner.zig",
        .line = 144,
        .column = 40,
        .rule = "slice-loop-reentrant-grow",
        .kind = .false_positive,
        .why = "Column 40 is `append` on `self.local_fns`, not on the slice the walk iterates: " ++
            "`for (self.tokens.items, 0..)` at 140 is the loop body, and `self.local_fns` " ++
            "(declared 80, deinit 85) is a separate field with its own backing allocation, " ++
            "as are the other two in-loop writers \xe2\x80\x94 `frames.append` at 153 " ++
            "targets the local list declared at 128, and the `self.scaffolding` slice write " ++
            "at 164-166 targets a third field. The walked buffer is only cleared at 370 and " ++
            "appended to at 376, both inside `scanFile` before `try self.classify(alloc);` " ++
            "at 380, so no reallocation of `self.tokens.items` can happen while the loop at " ++
            "140 runs.",
    },
};

/// The index of the record covering `path:line:column:rule`, or null when no
/// record does.
///
/// The match is exact on all four fields on purpose. A record whose site has
/// moved is not the same record with new numbers, so a partial match would let
/// a disposition follow its code across an edit it was never read against.
pub fn find(path: []const u8, line: usize, column: usize, rule: []const u8) ?usize {
    for (dispositions, 0..) |disposition, index| {
        if (disposition.line != line or disposition.column != column) continue;
        if (!std.mem.eql(u8, disposition.path, path)) continue;
        if (!std.mem.eql(u8, disposition.rule, rule)) continue;
        return index;
    }
    return null;
}

/// The whole-file digest this file was reviewed against, or null when the
/// reviewed-source table does not list it.
pub fn reviewedDigest(path: []const u8) ?[]const u8 {
    for (reviewed_sources) |reviewed| {
        if (std.mem.eql(u8, reviewed.path, path)) return reviewed.sha256;
    }
    return null;
}
