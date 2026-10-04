//! What the vendored core is forbidden to reach for, and what each of those
//! costs.
//!
//! Every rule here is a hidden input: something the code under test would read
//! from outside itself rather than take as a parameter. A state machine that
//! draws a clock cannot be put at a chosen time; one that opens a socket cannot
//! be handed a datagram; one that reads the environment is a function of the
//! machine it happened to run on. Those are structural failures rather than
//! style, because the caller has no way to hold the state machine still.
//!
//! The consequence is part of each rule rather than a postscript. A failure
//! that only names the construct is a failure the next person deletes.
//!
//! Scope is decided by `vendored_scanner.zig` and this module never re-decides
//! it. `At.in_test` arrives as an input, and the one exemption that exists —
//! the seeded `TestRandom` a test block is allowed — is narrower than it looks:
//! it applies to test code only, and `TestRandom` is the sanctioned spelling
//! rather than a general allowance for PRNGs in tests.
//!
//! There are no carve-outs. Upstream had one: `sys.zig`, holding the sockets,
//! the clock and the process CSPRNG behind a single import. DECISIONS/0001 step
//! 2 deleted it once its last caller went, and `rule_seam_import` is what keeps
//! that deletion true — the file cannot come back as a temporary convenience.

const std = @import("std");

const vendored_scanner = @import("vendored_scanner.zig");

const Rule = vendored_scanner.Rule;
const At = vendored_scanner.At;
const Scanner = vendored_scanner.Scanner;

/// Upstream's syscall seam, deleted by DECISIONS/0001 step 2 once its last
/// caller went. Named here so the rule that forbids importing it never depends
/// on remembering the spelling.
const deleted_seam = "sys.zig";

/// Qualifiers that mean "reached through a system namespace". A call is read
/// as a syscall only when the identifier standing directly in front of the
/// callee's period is in this list — `isSyscall` says what that leaves out.
/// `posix` is here for the syscalls it names, not for the address types it used
/// to carry: the core's address is its own value (`vendor/quic/src/address.zig`)
/// and the tree now names no `posix` at all, so a `posix.` appearing in it from
/// here on is reaching for the system.
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
/// part of a longer qualified name that the longer name already covers. This
/// list is the whole of the test exemption, and it is applied only where
/// `At.in_test` is false — the exemption widens nothing else.
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

const rule_socket: Rule = .{
    .name = "a socket syscall",
    .breaks = "a stack that owns a descriptor cannot be handed a datagram by " ++
        "the transport multiplexer, so the endpoint stops being drivable in " ++
        "process. DECISIONS/0001 dropped the socket-owning layers for this.",
};

const rule_libc_call: Rule = .{
    .name = "a libc call",
    .breaks = "the vendored module declares no `link_libc`, so a std.c call " ++
        "that reaches an unlinked symbol fails the build for whoever is left " ++
        "reading the error, with nothing pointing at this file.",
};

const rule_extern: Rule = .{
    .name = "a hand-declared libc symbol",
    .breaks = "`extern \"c\"` is how a libc dependency comes back without the " ++
        "build script noticing, and nothing in this tree needs one.",
};

const rule_link_libc: Rule = .{
    .name = "`link_libc`",
    .breaks = "the vendored module deliberately does not link libc; setting " ++
        "it here would make every consumer pay for a dependency that " ++
        "DECISIONS/0001 removed.",
};

const rule_cimport: Rule = .{
    .name = "`@cImport`",
    .breaks = "a C header is a dependency this tree does not vendor and the " ++
        "build does not resolve, so it breaks on every machine but this one.",
};

const rule_clock: Rule = .{
    .name = "a clock read",
    .breaks = "the real clock is hidden input. A test cannot put a " ++
        "connection at a chosen time, so loss recovery and idle timeouts can " ++
        "only be exercised by waiting. AGENTS.md §2 forbids this below " ++
        "`ozai.base`, and the vendored core is below it.",
};

const rule_entropy: Rule = .{
    .name = "entropy from the kernel",
    .breaks = "a draw no test can predict: the same run twice is not the same " ++
        "run, so a failure found once cannot be reproduced and a proof that " ++
        "held once does not hold.",
};

const rule_env: Rule = .{
    .name = "the environment",
    .breaks = "a value that changes with the machine makes the result depend " ++
        "on where it ran, and a state machine has no way to be handed one.",
};

const rule_fs: Rule = .{
    .name = "a file",
    .breaks = "the core is fed bytes by its caller. Reading a file makes the " ++
        "behaviour under test depend on that file's contents, and a file read " ++
        "is a blocking syscall inside a state machine.",
};

const rule_process: Rule = .{
    .name = "a process",
    .breaks = "spawning or querying a process puts the machine outside the " ++
        "state machine, where no assertion can reach it.",
};

const rule_global_rng: Rule = .{
    .name = "a mutable global PRNG",
    .breaks = "every caller shares one generator, so the bytes one call draws " ++
        "change what the next call draws. Entropy belongs in a parameter, and " ++
        "the generator it came from belongs to the caller.",
};

const rule_library_rng: Rule = .{
    .name = "a PRNG in library code",
    .breaks = "a state machine that draws its own randomness cannot be " ++
        "replayed or asserted on. In test code a seeded `TestRandom` is the " ++
        "sanctioned idiom; in library code the caller hands the entropy in.",
};

const rule_seam_import: Rule = .{
    .name = "an import of the deleted seam",
    .breaks = "`sys.zig` held the sockets, the clock and the process CSPRNG " ++
        "behind one import, and DECISIONS/0001 step 2 deleted it once its last " ++
        "caller went. Naming it again does not restore it; it fails the build " ++
        "and points at whoever expected it back.",
};

fn has(set: []const []const u8, text: []const u8) bool {
    for (set) |name| {
        if (std.mem.eql(u8, name, text)) return true;
    }
    return false;
}

/// True when the token at `i` is the callee of a call that could reach the
/// operating system: a bare `socket(`, or one whose immediately preceding
/// qualifier is a namespace, `posix.socket(`. Two shapes are deliberately not
/// that. A declaration, `fn accept(`, is not a call at all. And a qualifier that
/// is not a namespace — a type or a value, `endpoint.accept(` — is left alone.
///
/// That last one is a lexical boundary, not a fact about the code, so it is
/// worth stating plainly. This reads exactly one qualifier: the identifier
/// directly in front of the period. A syscall reached through a type,
/// `std.Io.net.IpAddress.bind(`, or through a namespace bound to another name is
/// not a shape this rule matches, and no method is classified as the project's
/// own or as the kernel's. A run that passes says the tree used none of the
/// spellings this module names — not that it cannot take a descriptor.
fn isSyscall(scanner: *const Scanner, i: usize) bool {
    if (scanner.tagAfter(i) != .l_paren) return false;
    if (scanner.tagAt(i, 1) == .keyword_fn) return false;
    if (!scanner.puncts(i, 1, .period)) {
        return !scanner.declaresLocally(scanner.textAt(i, 0) orelse "");
    }
    const qualifier = scanner.identifierAt(i, 2) orelse return false;
    return has(&namespaces, qualifier);
}

/// What one token is judged against. Everything this module knows about scope
/// arrives in `at`; nothing here re-derives it from a line number.
pub fn judge(scanner: *Scanner, at: At) void {
    const i = at.index;
    const tok = scanner.token(i) orelse return;
    const text = scanner.textAt(i, 0) orelse "";

    // --- a socket, in library code and in test code alike. ---------------
    if (has(&socket_calls, text) and isSyscall(scanner, i)) scanner.hit(rule_socket, at, tok.loc);

    // --- the deleted seam, whichever way it is reached. ------------------
    if (scanner.tagAt(i, 0) == .builtin and std.mem.eql(u8, text, "@import")) {
        const quoted = scanner.stringAt(i, 2) orelse "";
        if (scanner.tagAt(i, 1) == .l_paren and quoted.len > 2) {
            const inner = quoted[1 .. quoted.len - 1];
            if (std.mem.endsWith(u8, inner, deleted_seam)) {
                scanner.hit(rule_seam_import, at, tok.loc);
            }
        }
    }

    // --- libc. The build script says this tree does not link it, so this
    // --- tree must not contradict the build script. ----------------------
    if (scanner.stdChain(i, "c")) scanner.hit(rule_libc_call, at, tok.loc);
    if (tok.tag == .keyword_extern and
        std.mem.eql(u8, scanner.stringAt(i, 1) orelse "", "\"c\"") and
        scanner.tagAt(i, 2) == .keyword_fn)
    {
        scanner.hit(rule_extern, at, tok.loc);
    }

    if (scanner.names(i, 0, "link_libc")) scanner.hit(rule_link_libc, at, tok.loc);
    if (scanner.tagAt(i, 0) == .builtin and std.mem.eql(u8, text, "@cImport")) {
        scanner.hit(rule_cimport, at, tok.loc);
    }

    // --- a clock. `timestamp` alone is not enough to fail: it is an
    // --- ordinary variable name in `packet.zig`, so a mention counts only
    // --- when `std.time` qualifies it or it is called. --------------------
    if (has(&clock_aliases, text)) scanner.hit(rule_clock, at, tok.loc);
    if (has(&clock_std_names, text)) {
        if (scanner.stdTime(i, text) or isSyscall(scanner, i)) {
            scanner.hit(rule_clock, at, tok.loc);
        }
    }
    if (scanner.names(i, 0, "random") and scanner.puncts(i, 1, .period) and
        scanner.names(i, 2, "crypto"))
    {
        scanner.hit(rule_entropy, at, tok.loc);
    }

    // --- entropy, files, processes, the environment. ---------------------
    if (has(&entropy_calls, text) and isSyscall(scanner, i)) scanner.hit(rule_entropy, at, tok.loc);
    if (has(&file_calls, text) and isSyscall(scanner, i)) scanner.hit(rule_fs, at, tok.loc);
    if (has(&env_readers, text) and isSyscall(scanner, i)) scanner.hit(rule_env, at, tok.loc);
    if (scanner.stdChain(i, "fs")) scanner.hit(rule_fs, at, tok.loc);
    if (scanner.stdChain(i, "process")) scanner.hit(rule_process, at, tok.loc);

    // --- a global generator. `at.depth == 0` is what makes this library
    // --- code by construction: a test body opens its own brace, so a `var`
    // --- inside one can never be at depth 0. The rule is narrowed to a PRNG
    // --- on purpose — `ecdsa_p256.zig` keeps two lazily built tables at
    // --- container scope and they are fine. ------------------------------
    if (tok.tag == .keyword_var and at.depth == 0) {
        for (scanner.tokens.items[i + 1 .. scanner.declEnd(i + 1)]) |ahead| {
            if (has(&rng_types, scanner.text(ahead))) {
                scanner.hit(rule_global_rng, at, tok.loc);
                break;
            }
        }
    }

    // --- an unaliased PRNG outside a test block. A bare type alias
    // --- (`const TestRandom = std.Random.DefaultPrng;`) and a type position
    // --- (a field, a parameter, an annotated local) name a PRNG without
    // --- constructing one, and both are decided by the tokens either side,
    // --- never by the line. ---------------------------------------------
    if (!at.in_test) {
        for (unaliased_rng_types) |name| {
            if (!scanner.names(i, 0, name)) continue;
            if (scanner.tagAfter(i) == .semicolon) continue;
            if (scanner.beforeChain(i) == .colon) continue;
            scanner.hit(rule_library_rng, at, tok.loc);
            break;
        }
    }
}
