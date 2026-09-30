//! The gate on what the vendored QUIC core is allowed to reach for.
//!
//! M8 spent most of its cost making `vendor/quic/` obey the one rule
//! `AGENTS.md` §2 and `docs/ARCHITECTURE.md` state plainly: nothing below
//! `ozai.base` may read a clock, read the environment, or take an allocator it
//! was not handed. A state machine that reads a clock cannot be driven by a
//! test — there is no way to put a connection at a chosen time — and one that
//! opens a socket cannot be handed a datagram at all.
//!
//! That rule is enforced here and nowhere else. `vendor/` is excluded from
//! `zig fmt`, `zlint` and `zbc` through `GATE_EXCLUDE=vendor`, which is the
//! right call: it is upstream code, and reformatting thirty thousand lines
//! would bury the patch under a diff nobody can review. The price of that
//! decision is that no tool is watching this tree, so a patch that reaches for
//! `std.posix.socket`, or for a clock, would land green and the endpoint would
//! quietly stop being drivable. This file is where that exclusion is paid back.
//!
//! The boundaries, and why each is where it is:
//!
//! * Library code is held to the full rule. A state machine that draws a
//!   clock, a file, the environment, OS entropy or its own PRNG is not
//!   drivable, so these are structural failures rather than style.
//!
//! * Test code is held to the same rule for everything a test does not get to
//!   do differently. A socket is a socket inside a `test` block too: a test
//!   that opens one exercises the kernel instead of the core. One thing is
//!   exempt, and it is the opposite of a hidden input: a seeded PRNG.
//!   `TestRandom` is the sanctioned spelling and appears in about a hundred of
//!   them, and a generator seeded with a constant is what makes a test
//!   repeatable.
//!
//! The library/test boundary is drawn from the token stream, never from line
//! numbers: a `test` declaration's body ends where brace depth returns to the
//! level the declaration opened at, so library code after a test block is
//! still library code. That is not pedantry. `packet.zig` has its first `test`
//! block on line 120 and over a thousand lines of live code after it, so the
//! usual `awk '/^test /{t=1}'` rule calls all of it test code and every
//! violation in it survives — the session this gate was written in lost four
//! that way. Counting braces from Zig's own tokenizer cannot make that
//! mistake, and it also reads comments and string literals correctly, so a
//! `// std.posix.socket` in a comment and a `test "no sockets"` name are not
//! evidence of anything.
//!
//! There are no carve-outs. Upstream had one: `sys.zig`, holding the sockets,
//! the clock and the process CSPRNG behind a single import. DECISIONS/0001 step
//! 2 deleted it once its last caller went, and this gate is what keeps that
//! deletion true. A clock, a libc call, an entropy draw, a file, a process or a
//! socket anywhere in this tree — its own tests included — is a failure here,
//! and so is an `@import` of the deleted seam, so the file cannot come back as
//! a temporary convenience.
//!
//! The file list below is the whole gate's coverage, and `@embedFile` cannot
//! glob, so `build.zig` walks `vendor/quic/src` on every configure and fails
//! the build when the list and the tree disagree in either direction. This test
//! may not touch the filesystem: it runs on every `zig build test` and reads
//! 1.3 MB of vendored source at comptime. It therefore cannot discover an
//! omission itself, and pretending otherwise would be the worst kind of gate —
//! one that looks like coverage.

const std = @import("std");

const t = std.testing;

/// The vendored root. Every path below is repo-relative, so `build.zig` can
/// compare the list against the directory without knowing how `@embedFile`
/// spells a path — that builtin resolves against this file, not the root.
const vendored_root = "vendor/quic/src";

/// Every `.zig` file under the vendored root, sorted. An entry is a promise
/// that this test reads the file, and `build.zig` is what keeps the promise
/// honest: a list that quietly omits a file is worse than no gate at all,
/// because it looks like coverage.
pub const vendored_files = [_][]const u8{
    vendored_root ++ "/io_compat.zig",
    vendored_root ++ "/lib.zig",
    vendored_root ++ "/quic/ack_handler.zig",
    vendored_root ++ "/quic/aes_gcm.zig",
    vendored_root ++ "/quic/aes_gcm_vectors.zig",
    vendored_root ++ "/quic/congestion.zig",
    vendored_root ++ "/quic/connection.zig",
    vendored_root ++ "/quic/connection_manager.zig",
    vendored_root ++ "/quic/crypto.zig",
    vendored_root ++ "/quic/crypto_stream.zig",
    vendored_root ++ "/quic/ecdsa_p256.zig",
    vendored_root ++ "/quic/ecn.zig",
    vendored_root ++ "/quic/flow_control.zig",
    vendored_root ++ "/quic/frame.zig",
    vendored_root ++ "/quic/ghash.zig",
    vendored_root ++ "/quic/limits.zig",
    vendored_root ++ "/quic/lossy_link_test.zig",
    vendored_root ++ "/quic/mont.zig",
    vendored_root ++ "/quic/mtu.zig",
    vendored_root ++ "/quic/packet.zig",
    vendored_root ++ "/quic/packet_packer.zig",
    vendored_root ++ "/quic/protocol.zig",
    vendored_root ++ "/quic/quic_lb.zig",
    vendored_root ++ "/quic/ranges.zig",
    vendored_root ++ "/quic/rsa.zig",
    vendored_root ++ "/quic/rtt.zig",
    vendored_root ++ "/quic/stateless_reset.zig",
    vendored_root ++ "/quic/stream.zig",
    vendored_root ++ "/quic/tls13.zig",
    vendored_root ++ "/quic/transport_params.zig",
    vendored_root ++ "/quic/util.zig",
    vendored_root ++ "/sockaddr.zig",
    vendored_root ++ "/test_all.zig",
};

/// The root the vendored suite is built from. Zig analyses a test block only if
/// the compilation reaches it, so a file whose tests are not named here is a
/// file whose tests do not run. That is why the test root is a file that
/// imports its subjects and not a re-export of `lib.zig`.
const test_root = vendored_root ++ "/test_all.zig";

/// Upstream's syscall seam, deleted by DECISIONS/0001 step 2 once its last
/// caller went. Named here so the rule that forbids importing it never depends
/// on remembering the spelling.
const deleted_seam = "sys.zig";

/// Qualifiers that mean "reached through a system namespace". A method call on
/// a type is not a syscall — `Connection.accept(` is this project's handshake
/// entry point — so a socket is only a socket when a namespace stands in front
/// of it. `posix.sockaddr`, `posix.AF` and `posix.socklen_t` are in none of the
/// name sets below on purpose: carrying an address is not holding a descriptor,
/// and those three appear on library lines all over the tree.
const namespaces = [_][]const u8{ "c", "fs", "linux", "os", "posix", "process", "std", "sys" };

/// Syscalls that own a descriptor. Reached as a bare call or through a
/// namespace; nothing else in the tree carries one of these names.
const socket_calls = [_][]const u8{
    "accept",
    "accept4",
    "bind",
    "connect",
    "getpeername",
    "getsockname",
    "getsockopt",
    "listen",
    "recvfrom",
    "recvmsg",
    "recvmmsg",
    "sendmmsg",
    "sendmsg",
    "sendto",
    "setsockopt",
    "shutdown",
    "socket",
    "socketpair",
};

/// File operations. `openFileRead` is the name upstream's own deleted socket
/// layer used; the rest are the libc spellings a patch would reach for instead.
const file_calls = [_][]const u8{
    "access",
    "fopen",
    "fstat",
    "fsync",
    "lseek",
    "openFileRead",
    "openat",
    "rename",
    "stat",
    "statx",
    "truncate",
    "unlink",
};

/// Draws from the kernel's entropy pool, plus the seam's own two entry points:
/// a library file calling `sys.randomBytes` draws from that same pool with one
/// more indirection, and the indirection is what makes it invisible.
const entropy_calls = [_][]const u8{
    "arc4random_buf",
    "getrandom",
    "randomBytes",
    "randomInt",
    "urandom",
};

/// The environment, however it is reached.
const env_readers = [_][]const u8{
    "getEnvMap",
    "getEnvVarOwned",
    "getenv",
    "hasEnvVar",
    "secure_getenv",
};

/// Clock reads by names that can only be one: the libc call underneath both
/// readers, and the seam's two replacements for `std.time`.
const clock_aliases = [_][]const u8{
    "clock_gettime",
    "gettimeofday",
    "realtimeNs",
    "realtimeSeconds",
};

/// The stdlib spellings. `timestamp` is an ordinary variable name — `packet.zig`
/// has a local called `timestamp` — so a mention only counts when it is
/// qualified by `std.time` or called.
const clock_std_names = [_][]const u8{
    "milliTimestamp",
    "nanoTimestamp",
    "timestamp",
};

/// PRNG types as they may appear in a mutable global, including the vendored
/// `TestRandom` alias: a global holding one is a shared generator whoever drew
/// it. `Random` is the namespace in `std.Random.Xoshiro256Plus`.
const rng_types = [_][]const u8{
    "DefaultPrng",
    "Random",
    "Sfc64",
    "SmallRng",
    "SplitMix64",
    "TestRandom",
    "Xoroshiro128",
    "Xoroshiro256",
    "Xoshiro256",
    "Xoshiro256Plus",
};

/// The same types without the two spellings a test block is allowed to reach
/// for: `TestRandom` is the sanctioned seeded idiom, and `Random` is only ever
/// part of a longer qualified name that the longer name already covers.
const unaliased_rng_types = [_][]const u8{
    "DefaultPrng",
    "Sfc64",
    "SmallRng",
    "SplitMix64",
    "Xoroshiro128",
    "Xoroshiro256",
    "Xoshiro256",
    "Xoshiro256Plus",
};

/// One forbidden construct, and what its presence costs.
///
/// The consequence is part of the rule rather than a postscript: a failure that
/// only names the construct is a failure the next person deletes.
const Rule = struct {
    name: []const u8,
    breaks: []const u8,
};

const rule_socket = Rule{
    .name = "a socket syscall",
    .breaks = "a stack that owns a descriptor cannot be handed a datagram by " ++
        "the transport multiplexer, so the endpoint stops being drivable in " ++
        "process. DECISIONS/0001 dropped the socket-owning layers for this.",
};

const rule_libc_call = Rule{
    .name = "a libc call",
    .breaks = "the vendored module declares no `link_libc`, so a std.c call " ++
        "that reaches an unlinked symbol fails the build for whoever is left " ++
        "reading the error, with nothing pointing at this file.",
};

const rule_extern = Rule{
    .name = "a hand-declared libc symbol",
    .breaks = "`extern \"c\"` is how a libc dependency comes back without the " ++
        "build script noticing, and nothing in this tree needs one.",
};

const rule_link_libc = Rule{
    .name = "`link_libc`",
    .breaks = "the vendored module deliberately does not link libc; setting " ++
        "it here would make every consumer pay for a dependency that " ++
        "DECISIONS/0001 removed.",
};

const rule_cimport = Rule{
    .name = "`@cImport`",
    .breaks = "a C header is a dependency this tree does not vendor and the " ++
        "build does not resolve, so it breaks on every machine but this one.",
};

const rule_clock = Rule{
    .name = "a clock read",
    .breaks = "the real clock is hidden input. A test cannot put a " ++
        "connection at a chosen time, so loss recovery and idle timeouts can " ++
        "only be exercised by waiting. AGENTS.md §2 forbids this below " ++
        "`ozai.base`, and the vendored core is below it.",
};

const rule_entropy = Rule{
    .name = "entropy from the kernel",
    .breaks = "a draw no test can predict: the same run twice is not the same " ++
        "run, so a failure found once cannot be reproduced and a proof that " ++
        "held once does not hold.",
};

const rule_env = Rule{
    .name = "the environment",
    .breaks = "a value that changes with the machine makes the result depend " ++
        "on where it ran, and a state machine has no way to be handed one.",
};

const rule_fs = Rule{
    .name = "a file",
    .breaks = "the core is fed bytes by its caller. Reading a file makes the " ++
        "behaviour under test depend on that file's contents, and a file read " ++
        "is a blocking syscall inside a state machine.",
};

const rule_process = Rule{
    .name = "a process",
    .breaks = "spawning or querying a process puts the machine outside the " ++
        "state machine, where no assertion can reach it.",
};

const rule_global_rng = Rule{
    .name = "a mutable global PRNG",
    .breaks = "every caller shares one generator, so the bytes one call draws " ++
        "change what the next call draws. Entropy belongs in a parameter, and " ++
        "the generator it came from belongs to the caller.",
};

const rule_library_rng = Rule{
    .name = "a PRNG in library code",
    .breaks = "a state machine that draws its own randomness cannot be " ++
        "replayed or asserted on. In test code a seeded `TestRandom` is the " ++
        "sanctioned idiom; in library code the caller hands the entropy in.",
};

const rule_seam_import = Rule{
    .name = "an import of the deleted seam",
    .breaks = "`sys.zig` held the sockets, the clock and the process CSPRNG " ++
        "behind one import, and DECISIONS/0001 step 2 deleted it once its last " ++
        "caller went. Naming it again does not restore it; it fails the build " ++
        "and points at whoever expected it back.",
};

const rule_unwired_tests = Rule{
    .name = "test blocks that nothing runs",
    .breaks = "Zig analyses a test block only if the compilation reaches it, " ++
        "so a file the test root does not name has no tests at all, and a " ++
        "green step that discovered nothing still exits 0.",
};

/// What one embedded file contributed to the audit. `quoted` is the path as
/// the test root spells it, `@import("quic/rsa.zig")`, so checking the wiring
/// needs no allocation: the testing allocator is watching this function.
const FileFacts = struct {
    path: []const u8,
    quoted: []const u8,
    tests: u32,
};

const AuditError = error{ OutOfMemory, VendoredInvariantViolated };

fn has(set: []const []const u8, text: []const u8) bool {
    for (set) |name| {
        if (std.mem.eql(u8, name, text)) return true;
    }
    return false;
}

/// Reads one file's token stream and holds it to the rules.
///
/// Everything structural comes from `std.zig.Tokenizer`, which skips comments
/// and string literals, knows that `test` is a keyword rather than an
/// identifier, and gives brace depth exactly. Nothing here is positional.
const Scanner = struct {
    tokens: std.ArrayList(std.zig.Token) = .empty,
    src: [:0]const u8 = "",
    path: []const u8 = "",
    tests: u32 = 0,
    hits: u32 = 0,

    /// Per token: inside a function that mentions `std.testing`. Reused across
    /// files and sized by the largest one, so the classification costs one
    /// byte per token and nothing after the first file.
    scaffolding: std.ArrayList(bool) = .empty,

    /// Function names this file declares, from `fn <name>`. A bare call to one
    /// of them is this project's own code rather than a syscall:
    /// `connection.zig` declares `connect` as its client handshake entry point,
    /// and `Connection.accept` is its server-side one, so the POSIX spellings
    /// `connect(3)` and `accept(2)` cannot be found by name alone. A file that
    /// declares a name and also calls that libc entry point bare would be
    /// missed; the qualified spelling is not, and no vendored file does it.
    local_fns: std.ArrayList([]const u8) = .empty,

    fn declaresLocally(self: *const Scanner, name: []const u8) bool {
        for (self.local_fns.items) |local| {
            if (std.mem.eql(u8, local, name)) return true;
        }
        return false;
    }

    /// One pass for the two classifications a whole-file look can give and a
    /// single token cannot.
    ///
    /// A `fn` body that reaches the testing namespace is test scaffolding. The
    /// vendored tree puts several helpers between its test blocks —
    /// `ack_handler.zig` has a `skipSequence` that allocates from
    /// `testing.allocator` — and a helper that allocates from the testing
    /// allocator cannot run outside a test, so counting that code as library
    /// code would make the gate fail on the tree it is auditing. The boundary
    /// stays structural: it is decided by what the function mentions, not by
    /// where the function sits in the file.
    ///
    /// The same pass records the names this file declares, because a syscall is
    /// only a syscall by what stands in front of it, and a declaration is only
    /// a declaration by its own `fn`.
    fn classify(self: *Scanner, alloc: std.mem.Allocator) !void {
        const Frame = struct { is_fn: bool, first: usize, uses_testing: bool };
        var frames: std.ArrayList(Frame) = .empty;
        defer frames.deinit(alloc);
        var want_fn_body = false;

        self.scaffolding.clearRetainingCapacity();
        try self.scaffolding.appendNTimes(alloc, false, self.tokens.items.len);
        self.local_fns.clearRetainingCapacity();

        for (self.tokens.items, 0..) |tok, i| {
            if (tok.tag == .keyword_fn) {
                want_fn_body = true;
                if (self.tagAfter(i) == .identifier) {
                    try self.local_fns.append(alloc, self.textAfter(i).?);
                }
            }
            switch (tok.tag) {
                .l_brace => {
                    try frames.append(alloc, .{
                        .is_fn = want_fn_body,
                        .first = i,
                        .uses_testing = false,
                    });
                    want_fn_body = false;
                },
                .r_brace => {
                    if (frames.pop()) |frame| {
                        if (frame.is_fn and frame.uses_testing) {
                            for (self.scaffolding.items[frame.first .. i + 1]) |*slot| {
                                slot.* = true;
                            }
                        }
                    }
                },
                else => {
                    if (frames.items.len == 0) continue;
                    if (self.reachesTesting(i)) {
                        frames.items[frames.items.len - 1].uses_testing = true;
                    }
                },
            }
        }
    }

    fn token(self: *const Scanner, i: usize) ?std.zig.Token {
        if (i >= self.tokens.items.len) return null;
        return self.tokens.items[i];
    }

    fn tagAt(self: *const Scanner, i: usize, back: usize) ?std.zig.Token.Tag {
        const ahead = self.token(i -| back) orelse return null;
        return ahead.tag;
    }

    /// The tag of the token after `i`. `tagAt` counts backwards because a
    /// qualifier chain is read left to right and ends at the current token;
    /// these forward helpers exist because a few questions are about what
    /// follows a token — whether a `test` keyword carries a name, whether a name
    /// is called, whether a declaration gives its name. Every forward question
    /// goes through one of them, so the two directions cannot be confused at a
    /// call site.
    fn tagAfter(self: *const Scanner, i: usize) ?std.zig.Token.Tag {
        if (i + 1 >= self.tokens.items.len) return null;
        return self.tokens.items[i + 1].tag;
    }

    /// The text of the token after `i`.
    fn textAfter(self: *const Scanner, i: usize) ?[]const u8 {
        const ahead = self.token(i + 1) orelse return null;
        return self.src[ahead.loc.start..ahead.loc.end];
    }

    fn textAt(self: *const Scanner, i: usize, back: usize) ?[]const u8 {
        const ahead = self.token(i -| back) orelse return null;
        return self.src[ahead.loc.start..ahead.loc.end];
    }

    /// True when the token `back` places before `i` is the identifier `name`.
    fn names(self: *const Scanner, i: usize, back: usize, name: []const u8) bool {
        if (self.tagAt(i, back) != .identifier) return false;
        const text = self.textAt(i, back) orelse return false;
        return std.mem.eql(u8, text, name);
    }

    fn puncts(self: *const Scanner, i: usize, back: usize, tag: std.zig.Token.Tag) bool {
        return self.tagAt(i, back) == tag;
    }

    fn namespace(self: *const Scanner, i: usize, back: usize) bool {
        if (self.tagAt(i, back) != .identifier) return false;
        return has(&namespaces, self.textAt(i, back) orelse "");
    }

    /// `std.<name>`, whatever the file aliased `std` to.
    fn stdChain(self: *const Scanner, i: usize, name: []const u8) bool {
        return self.names(i, 0, name) and self.puncts(i, 1, .period) and self.names(i, 2, "std");
    }

    /// `std.time.<name>`.
    fn stdTime(self: *const Scanner, i: usize, name: []const u8) bool {
        return self.names(i, 0, name) and self.puncts(i, 1, .period) and
            self.names(i, 2, "time") and self.puncts(i, 3, .period) and
            self.names(i, 4, "std");
    }

    /// True when the token at `i` is the callee of a call that could reach the
    /// operating system: a bare `socket(`, or one through a system namespace,
    /// `posix.socket(`. Two shapes are deliberately not that. A declaration,
    /// `fn accept(`, is not a call at all. And `Connection.accept(` is this
    /// project's handshake entry point rather than a syscall, which is why the
    /// qualifier in front has to be a namespace and not merely a period.
    fn isSyscall(self: *const Scanner, i: usize) bool {
        if (self.tagAfter(i) != .l_paren) return false;
        if (self.tagAt(i, 1) == .keyword_fn) return false;
        if (!self.puncts(i, 1, .period)) {
            return !self.declaresLocally(self.textAt(i, 0) orelse "");
        }
        return self.namespace(i, 2);
    }

    /// A body that reaches the testing namespace counts as test scaffolding.
    /// Every vendored file declares `const testing = std.testing;` at file
    /// scope and then spells `testing.allocator`, so the alias is not part of
    /// the match. A file that bound `std.testing` to some other name would need
    /// that name added here, and until it is, such a helper is reported rather
    /// than missed: the failure is a gate that complains about test scaffolding,
    /// which a reader can see, and never a violation that went unreported.
    fn reachesTesting(self: *const Scanner, i: usize) bool {
        return self.names(i, 0, "testing") and self.tagAfter(i) == .period;
    }

    /// The tag in front of the identifier's own qualifier chain, so a type
    /// position is found the way a reader finds it: in `prng:
    /// std.Random.DefaultPrng` the colon sits in front of `std`, four tokens
    /// before the type name and not one.
    fn beforeChain(self: *const Scanner, i: usize) ?std.zig.Token.Tag {
        var k = i;
        while (self.tagAt(k, 1) == .period and self.tagAt(k, 2) == .identifier) k -= 2;
        return self.tagAt(k, 1);
    }

    fn hit(self: *Scanner, rule: Rule, line: usize, loc: std.zig.Token.Loc) void {
        self.hits += 1;
        std.debug.print("{s}:{d}: {s}\n    {s}\n    | {s}\n", .{
            self.path,
            line,
            rule.name,
            rule.breaks,
            self.sourceLine(loc),
        });
    }

    /// The offending line, for the reader who has to go look at it.
    fn sourceLine(self: *const Scanner, loc: std.zig.Token.Loc) []const u8 {
        const head = self.src[0..loc.start];
        const from = if (std.mem.lastIndexOfScalar(u8, head, '\n')) |at| at + 1 else 0;
        const to = std.mem.indexOfScalarPos(u8, self.src, loc.end, '\n') orelse self.src.len;
        return std.mem.trim(u8, self.src[from..to], " \t\r");
    }

    /// The extent of a container-scope declaration, for the one check that has
    /// to read past the `var` it starts at.
    fn declEnd(self: *const Scanner, from: usize) usize {
        var open: u32 = 0;
        var i = from;
        while (i < self.tokens.items.len) : (i += 1) {
            switch (self.tokens.items[i].tag) {
                .l_brace, .l_bracket, .l_paren => open += 1,
                .r_brace, .r_bracket, .r_paren => {
                    if (open > 0) open -= 1;
                },
                .semicolon => if (open == 0) return i,
                .keyword_fn, .keyword_test => if (open == 0) return i,
                else => {},
            }
        }
        return self.tokens.items.len;
    }

    fn scanFile(
        self: *Scanner,
        alloc: std.mem.Allocator,
        src: [:0]const u8,
        path: []const u8,
    ) !u32 {
        self.src = src;
        self.path = path;
        self.tests = 0;
        self.tokens.clearRetainingCapacity();

        var tokenizer = std.zig.Tokenizer.init(src);
        while (true) {
            const tok = tokenizer.next();
            if (tok.tag == .eof) break;
            try self.tokens.append(alloc, tok);
        }
        // Both classifications read the token stream, so they wait for the
        // tokenization above.
        try self.classify(alloc);

        var depth: u32 = 0;
        // The depth the current test body opened at, or `null` outside one. A
        // test body ends where that depth closes, not where the file ends.
        var test_depth: ?u32 = null;
        var pending_test = false;
        var line: usize = 1;
        var cursor: usize = 0;

        for (self.tokens.items, 0..) |tok, i| {
            // Comments and string literals produce no tokens, so the gap
            // between two of them is where the file's other lines went.
            line += std.mem.count(u8, src[cursor..tok.loc.start], "\n");
            const token_line = line;
            cursor = tok.loc.end;

            // `test` is a keyword, so this is never an identifier: the grammar
            // is `test` (name)? block, and anything else after the keyword
            // means this is not a test declaration at all.
            if (test_depth == null and tok.tag == .keyword_test) {
                switch (self.tagAfter(i) orelse .eof) {
                    .string_literal, .multiline_string_literal_line, .l_brace => {
                        self.tests += 1;
                        pending_test = true;
                    },
                    else => {},
                }
            }
            if (pending_test and tok.tag == .l_brace and depth == 0) {
                test_depth = depth + 1;
                pending_test = false;
            }
            if (tok.tag == .l_brace) {
                depth += 1;
            } else if (tok.tag == .r_brace) {
                if (test_depth) |opened| {
                    if (depth == opened) test_depth = null;
                }
                depth -= 1;
            }

            // Test code is a test body or a helper that reaches for
            // `std.testing`; both boundaries come from structure, never from
            // where the code sits in the file.
            const in_test = test_depth != null or self.scaffolding.items[i];
            const text = self.textAt(i, 0) orelse "";

            // --- a socket, in library code and in test code alike. ---------
            if (has(&socket_calls, text) and self.isSyscall(i)) {
                self.hit(rule_socket, token_line, tok.loc);
            }

            // --- the deleted seam, whichever way it is reached. -----------
            if (self.tagAt(i, 0) == .builtin and std.mem.eql(u8, text, "@import")) {
                if (self.tagAt(i, 1) == .l_paren and self.tagAt(i, 2) == .string_literal) {
                    const quoted = self.textAt(i, 2).?;
                    if (quoted.len > 2) {
                        const inner = quoted[1 .. quoted.len - 1];
                        if (std.mem.endsWith(u8, inner, deleted_seam)) {
                            self.hit(rule_seam_import, token_line, tok.loc);
                        }
                    }
                }
            }

            // --- libc. The build script says this tree does not link it, so
            // --- this tree must not contradict the build script. ----------
            if (self.stdChain(i, "c")) self.hit(rule_libc_call, token_line, tok.loc);
            if (tok.tag == .keyword_extern and
                self.tagAt(i, 1) == .string_literal and
                std.mem.eql(u8, self.textAt(i, 1).?, "\"c\"") and
                self.tagAt(i, 2) == .keyword_fn)
            {
                self.hit(rule_extern, token_line, tok.loc);
            }

            if (self.names(i, 0, "link_libc")) self.hit(rule_link_libc, token_line, tok.loc);
            if (self.tagAt(i, 0) == .builtin and std.mem.eql(u8, text, "@cImport")) {
                self.hit(rule_cimport, token_line, tok.loc);
            }

            // --- a clock. `timestamp` alone is not enough to fail: it is an
            // --- ordinary variable name in `packet.zig`, so a mention counts
            // --- only when `std.time` qualifies it or it is called. --------
            if (has(&clock_aliases, text)) self.hit(rule_clock, token_line, tok.loc);
            if (has(&clock_std_names, text)) {
                if (self.stdTime(i, text) or self.isSyscall(i)) {
                    self.hit(rule_clock, token_line, tok.loc);
                }
            }
            if (self.names(i, 0, "random") and self.puncts(i, 1, .period) and
                self.names(i, 2, "crypto"))
            {
                self.hit(rule_entropy, token_line, tok.loc);
            }

            // --- entropy, files, processes, the environment. --------------
            if (has(&entropy_calls, text) and self.isSyscall(i)) {
                self.hit(rule_entropy, token_line, tok.loc);
            }
            if (has(&file_calls, text) and self.isSyscall(i)) {
                self.hit(rule_fs, token_line, tok.loc);
            }
            if (has(&env_readers, text) and self.isSyscall(i)) {
                self.hit(rule_env, token_line, tok.loc);
            }
            if (self.stdChain(i, "fs")) self.hit(rule_fs, token_line, tok.loc);
            if (self.stdChain(i, "process")) self.hit(rule_process, token_line, tok.loc);

            // --- a global generator. `depth == 0` is what makes this library
            // --- code by construction: a test body opens its own brace, so a
            // --- `var` inside one can never be at depth 0. The rule is
            // --- narrowed to a PRNG on purpose — `ecdsa_p256.zig` keeps two
            // --- lazily built tables at container scope and they are fine.
            if (tok.tag == .keyword_var and depth == 0) {
                for (self.tokens.items[i + 1 .. self.declEnd(i + 1)]) |ahead| {
                    if (has(&rng_types, self.src[ahead.loc.start..ahead.loc.end])) {
                        self.hit(rule_global_rng, token_line, tok.loc);
                        break;
                    }
                }
            }

            // --- an unaliased PRNG outside a test block. A bare type alias
            // --- (`const TestRandom = std.Random.DefaultPrng;`) and a type
            // --- position (a field, a parameter, an annotated local) name a
            // --- PRNG without constructing one, and both are decided by the
            // --- tokens either side, never by the line.
            if (!in_test) {
                for (unaliased_rng_types) |name| {
                    if (!self.names(i, 0, name)) continue;
                    if (self.tagAfter(i) == .semicolon) continue;
                    if (self.beforeChain(i) == .colon) continue;
                    self.hit(rule_library_rng, token_line, tok.loc);
                    break;
                }
            }
        }

        return self.tests;
    }
};

fn audit(alloc: std.mem.Allocator) AuditError!void {
    var scanner: Scanner = .{};
    defer scanner.tokens.deinit(alloc);
    defer scanner.scaffolding.deinit(alloc);
    defer scanner.local_fns.deinit(alloc);

    var facts: std.ArrayList(FileFacts) = .empty;
    defer facts.deinit(alloc);

    var test_root_src: []const u8 = "";
    // `inline for` because `@embedFile` takes a comptime-known path: naming the
    // whole tree in one expression is what the builtin's limits force.
    inline for (vendored_files, 0..) |embedded, i| {
        if (i > 0 and std.mem.order(u8, vendored_files[i - 1], embedded) != .lt) {
            std.debug.print(
                "vendored_files is not sorted and duplicate-free: {s} then {s}\n" ++
                    "    A repeated entry checks one file twice while an omitted " ++
                    "one is invisible. Keep the list sorted so that a diff of " ++
                    "it shows exactly which file came and went.\n",
                .{ vendored_files[i - 1], embedded },
            );
            return error.VendoredInvariantViolated;
        }
        const src: [:0]const u8 = @embedFile("../" ++ embedded);
        const path = embedded;
        const tests = try scanner.scanFile(alloc, src, path);
        try facts.append(alloc, .{
            .path = path,
            .quoted = "\"" ++ path[vendored_root.len + 1 ..] ++ "\"",
            .tests = tests,
        });
        if (std.mem.eql(u8, path, test_root)) test_root_src = src;
    }

    // A file carrying a test block has to be named in the test root, or its
    // tests are never analysed and the suite is green having run none of them.
    // The root does not name itself.
    for (facts.items) |fact| {
        if (fact.tests == 0 or std.mem.eql(u8, fact.path, test_root)) continue;
        const quoted = fact.quoted;
        if (std.mem.indexOf(u8, test_root_src, quoted) == null) {
            std.debug.print(
                "{s}: {s}: {s}\n    Add `_ = @import({s});` to {s}.\n",
                .{
                    fact.path,
                    rule_unwired_tests.name,
                    rule_unwired_tests.breaks,
                    quoted,
                    test_root,
                },
            );
            scanner.hits += 1;
        }
    }

    if (scanner.hits == 0) return;
    std.debug.print(
        "\n{d} violation(s) across {d} vendored files. vendor/ is excluded from " ++
            "fmt, zlint and zbc, so this test is the only thing watching it, and " ++
            "a failure here means the core cannot be driven in process any " ++
            "more.\n",
        .{ scanner.hits, facts.items.len },
    );
    return error.VendoredInvariantViolated;
}

test "the vendored QUIC core reaches for nothing its caller did not hand it" {
    try audit(t.allocator);
}
