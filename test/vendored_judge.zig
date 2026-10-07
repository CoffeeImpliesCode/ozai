//! Applying the rule book to one file, token by token.
//!
//! `scanFile` is the gate's inner loop: it walks the classified token stream,
//! asks each question `vendored_scanner.zig` knows how to ask, and reports every
//! answer that is a violation. `hit` prints one, `sourceLine` prints the line it
//! is on, and `declEnd` finds the end of a container-scope declaration for the
//! one check that has to read past the `var` it starts at.
//!
//! All four were `Scanner` methods whose bodies never touch a field of the
//! struct they hung off — the receiver is `self` in each, and it stays named
//! `self` here, so no statement of theirs changed.

const std = @import("std");

const rulebook = @import("vendored_rulebook.zig");
const scanner_ns = @import("vendored_scanner.zig");

const Rule = rulebook.Rule;
const Scanner = scanner_ns.Scanner;

pub fn hit(self: *Scanner, rule: Rule, line: usize, loc: std.zig.Token.Loc) void {
    self.hits += 1;
    std.debug.print("{s}:{d}: {s}\n    {s}\n    | {s}\n", .{
        self.path,
        line,
        rule.name,
        rule.breaks,
        sourceLine(self, loc),
    });
}

/// The offending line, for the reader who has to go look at it.
pub fn sourceLine(self: *const Scanner, loc: std.zig.Token.Loc) []const u8 {
    const head = self.src[0..loc.start];
    const from = if (std.mem.findScalarLast(u8, head, '\n')) |at| at + 1 else 0;
    const to = std.mem.indexOfScalarPos(u8, self.src, loc.end, '\n') orelse self.src.len;
    return std.mem.trim(u8, self.src[from..to], " \t\r");
}

/// The extent of a container-scope declaration, for the one check that has
/// to read past the `var` it starts at.
pub fn declEnd(self: *const Scanner, from: usize) usize {
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

/// Count the tests in one file and check it reaches for nothing undeclared.
///
/// `pub` because `vendored_invariants.zig` calls it across the file boundary
/// the split that gave this module its own name introduced.
pub fn scanFile(
    alloc: std.mem.Allocator,
    self: *Scanner,
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

    // Braces in a token stream balance, so `depth` never reaches zero on a
    // `}` and the decrement cannot wrap. Were it to, the trap is the answer:
    // a `depth` wrong in either direction moves lines between library and
    // test code, and a panic says which build broke where a wrong answer
    // would only say the gate went quiet.
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
        // zbc cannot prove this rule lookup only compares fixed rule slices.
        // zbc-disable-next-line: slice-loop-reentrant-grow
        if (rulebook.has(&rulebook.socket_calls, text) and self.isSyscall(i)) {
            // zbc cannot prove hit updates scalar counts, not the token list.
            // zbc-disable-next-line: slice-loop-reentrant-grow
            hit(self, rulebook.rule_socket, token_line, tok.loc);
        }

        // --- the deleted seam, whichever way it is reached. -----------
        if (self.tagAt(i, 0) == .builtin and std.mem.eql(u8, text, "@import")) {
            const quoted = self.stringAt(i, 2) orelse "";
            if (self.tagAt(i, 1) == .l_paren and quoted.len > 2) {
                const inner = quoted[1 .. quoted.len - 1];
                if (std.mem.endsWith(u8, inner, rulebook.deleted_seam)) {
                    // zbc cannot prove hit updates scalar counts, not the token list.
                    // zbc-disable-next-line: slice-loop-reentrant-grow
                    hit(self, rulebook.rule_seam_import, token_line, tok.loc);
                }
            }
        }

        // --- libc. The build script says this tree does not link it, so
        // --- this tree must not contradict the build script. ----------
        // zbc cannot prove hit updates scalar counts, not the token list.
        // zbc-disable-next-line: slice-loop-reentrant-grow
        if (self.stdChain(i, "c")) hit(self, rulebook.rule_libc_call, token_line, tok.loc);
        if (tok.tag == .keyword_extern and
            std.mem.eql(u8, self.stringAt(i, 1) orelse "", "\"c\"") and
            self.tagAt(i, 2) == .keyword_fn)
        {
            // zbc cannot prove hit updates scalar counts, not the token list.
            // zbc-disable-next-line: slice-loop-reentrant-grow
            hit(self, rulebook.rule_extern, token_line, tok.loc);
        }

        if (self.names(i, 0, "link_libc")) {
            // zbc cannot prove hit updates scalar counts, not the token list.
            // zbc-disable-next-line: slice-loop-reentrant-grow
            hit(self, rulebook.rule_link_libc, token_line, tok.loc);
        }
        if (self.tagAt(i, 0) == .builtin and std.mem.eql(u8, text, "@cImport")) {
            // zbc cannot prove hit updates scalar counts, not the token list.
            // zbc-disable-next-line: slice-loop-reentrant-grow
            hit(self, rulebook.rule_cimport, token_line, tok.loc);
        }

        // --- a clock. `timestamp` alone is not enough to fail: it is an
        // --- ordinary variable name in `packet.zig`, so a mention counts
        // --- only when `std.time` qualifies it or it is called. --------
        // zbc cannot prove this rule lookup only compares fixed rule slices.
        // zbc-disable-next-line: slice-loop-reentrant-grow
        if (rulebook.has(&rulebook.clock_aliases, text)) {
            // zbc cannot prove hit updates scalar counts, not the token list.
            // zbc-disable-next-line: slice-loop-reentrant-grow
            hit(self, rulebook.rule_clock, token_line, tok.loc);
        }
        // zbc cannot prove this rule lookup only compares fixed rule slices.
        // zbc-disable-next-line: slice-loop-reentrant-grow
        if (rulebook.has(&rulebook.clock_std_names, text)) {
            if (self.stdTime(i, text) or self.isSyscall(i)) {
                // zbc cannot prove hit updates scalar counts, not the token list.
                // zbc-disable-next-line: slice-loop-reentrant-grow
                hit(self, rulebook.rule_clock, token_line, tok.loc);
            }
        }
        if (self.names(i, 0, "random") and self.puncts(i, 1, .period) and
            self.names(i, 2, "crypto"))
        {
            // zbc cannot prove hit updates scalar counts, not the token list.
            // zbc-disable-next-line: slice-loop-reentrant-grow
            hit(self, rulebook.rule_entropy, token_line, tok.loc);
        }

        // --- entropy, files, processes, the environment. --------------
        // zbc cannot prove this rule lookup only compares fixed rule slices.
        // zbc-disable-next-line: slice-loop-reentrant-grow
        if (rulebook.has(&rulebook.entropy_calls, text) and self.isSyscall(i)) {
            // zbc cannot prove hit updates scalar counts, not the token list.
            // zbc-disable-next-line: slice-loop-reentrant-grow
            hit(self, rulebook.rule_entropy, token_line, tok.loc);
        }
        // zbc cannot prove this rule lookup only compares fixed rule slices.
        // zbc-disable-next-line: slice-loop-reentrant-grow
        if (rulebook.has(&rulebook.file_calls, text) and self.isSyscall(i)) {
            // zbc cannot prove hit updates scalar counts, not the token list.
            // zbc-disable-next-line: slice-loop-reentrant-grow
            hit(self, rulebook.rule_fs, token_line, tok.loc);
        }
        // zbc cannot prove this rule lookup only compares fixed rule slices.
        // zbc-disable-next-line: slice-loop-reentrant-grow
        if (rulebook.has(&rulebook.env_readers, text) and self.isSyscall(i)) {
            // zbc cannot prove hit updates scalar counts, not the token list.
            // zbc-disable-next-line: slice-loop-reentrant-grow
            hit(self, rulebook.rule_env, token_line, tok.loc);
        }
        // zbc cannot prove hit updates scalar counts, not the token list.
        // zbc-disable-next-line: slice-loop-reentrant-grow
        if (self.stdChain(i, "fs")) hit(self, rulebook.rule_fs, token_line, tok.loc);
        // zbc cannot prove hit updates scalar counts, not the token list.
        // zbc-disable-next-line: slice-loop-reentrant-grow
        if (self.stdChain(i, "process")) hit(self, rulebook.rule_process, token_line, tok.loc);

        // --- a global generator. `depth == 0` is what makes this library
        // --- code by construction: a test body opens its own brace, so a
        // --- `var` inside one can never be at depth 0. The rule is
        // --- narrowed to a PRNG on purpose — `ecdsa_p256.zig` keeps two
        // --- lazily built tables at container scope and they are fine.
        if (tok.tag == .keyword_var and depth == 0) {
            for (self.tokens.items[i + 1 .. declEnd(self, i + 1)]) |ahead| {
                const type_name = self.src[ahead.loc.start..ahead.loc.end];
                // zbc cannot prove this rule lookup only compares fixed rule slices.
                // zbc-disable-next-line: slice-loop-reentrant-grow
                if (rulebook.has(&rulebook.rng_types, type_name)) {
                    // zbc cannot prove hit updates scalar counts, not the token list.
                    // zbc-disable-next-line: slice-loop-reentrant-grow
                    hit(self, rulebook.rule_global_rng, token_line, tok.loc);
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
            for (rulebook.unaliased_rng_types) |name| {
                if (!self.names(i, 0, name)) continue;
                if (self.tagAfter(i) == .semicolon) continue;
                if (self.beforeChain(i) == .colon) continue;
                // zbc cannot prove hit updates scalar counts, not the token list.
                // zbc-disable-next-line: slice-loop-reentrant-grow
                hit(self, rulebook.rule_library_rng, token_line, tok.loc);
                break;
            }
        }
    }

    return self.tests;
}
