//! One vendored file, read as a token stream: what each token is, whether the
//! code around it is library code or test code, and where a violation would be
//! reported. Whether a token is *forbidden* is not decided here — that is
//! `vendored_policy.zig`, and the seam between the two is one function.
//!
//! Everything structural comes from `std.zig.Tokenizer`, which skips comments
//! and string literals, knows that `test` is a keyword rather than an
//! identifier, and gives brace depth exactly. Nothing here is positional.
//!
//! The library/test line is drawn from that stream and never from line
//! numbers: a `test` declaration's body ends where brace depth returns to the
//! level the declaration opened at, so library code after a test block is still
//! library code. That is not pedantry. `packet.zig` has its first `test` block
//! on line 120 and over a thousand lines of live code after it, so the usual
//! `awk '/^test /{t=1}'` rule calls all of it test code and every violation in
//! it survives — the session this gate was written in lost four that way.
//! Counting braces from Zig's own tokenizer cannot make that mistake, and it
//! reads comments and string literals correctly too, so a
//! `// std.posix.socket` in a comment and a `test "no sockets"` name are not
//! evidence of anything.

const std = @import("std");

/// One forbidden construct, and what its presence costs. The rules themselves
/// are in `vendored_policy.zig`; this is the shape a finding is reported in.
pub const Rule = struct {
    name: []const u8,
    breaks: []const u8,
};

/// What the walk knows about one token before any rule has looked at it. These
/// are all of the structural facts a rule may ask for, so a rule reads them
/// instead of re-deriving the walk's state: the token's position in the stream,
/// the line it is reported on, the brace depth it sits at, and whether the code
/// around it is test code.
pub const At = struct {
    index: usize,
    line: usize,
    depth: u32,
    in_test: bool,
};

/// The judgement, handed one token at a time. It is a function rather than a
/// method because the walk and the rules are separate responsibilities: the
/// walk knows where every token sits, the rules know what is forbidden, and
/// neither needs the other's data beyond `At`.
pub const Judge = *const fn (scanner: *Scanner, at: At) void;

pub const Scanner = struct {
    /// The file's token stream. Public because one rule reads a whole
    /// declaration rather than a single token, and the scanner is where that
    /// stream lives.
    tokens: std.ArrayList(std.zig.Token) = .empty,

    /// The file the tokens came from, kept for the two reads that need bytes
    /// rather than a tag: a token's text and the line a finding prints.
    src: [:0]const u8 = "",

    /// The path findings are reported under, and the count of `test`
    /// declarations the walk saw.
    path: []const u8 = "",
    tests: u32 = 0,

    /// How many violations the scan has found. Public because the caller is
    /// what decides whether a run passes. It accumulates across a tree on
    /// purpose, which is why a per-case count cannot reuse one scanner.
    hits: u32 = 0,

    /// Per token: inside a function that mentions `std.testing`. Reused across
    /// files and sized by the largest one, so the classification costs one byte
    /// per token and nothing after the first file.
    scaffolding: std.ArrayList(bool) = .empty,

    /// Function names this file declares, from `fn <name>`. A bare call to one
    /// of them is this project's own code rather than a syscall, which is why a
    /// name shared with libc — `connect(3)` and `accept(2)` are the spellings
    /// this one meets — cannot be read as a syscall by name alone. A file that
    /// declares a name and also calls that libc entry point bare would be
    /// missed; the qualified spelling is not, and no vendored file does it.
    local_fns: std.ArrayList([]const u8) = .empty,

    pub fn deinit(self: *Scanner, alloc: std.mem.Allocator) void {
        self.tokens.deinit(alloc);
        self.scaffolding.deinit(alloc);
        self.local_fns.deinit(alloc);
        // Invalid rather than merely emptied. The three lists are released
        // here and `src` borrows bytes the caller still owns, so nothing a
        // reader could reach outlives this call; left standing, a second
        // teardown or a read after the `defer` would walk storage that is
        // already back in the allocator and would still look like a value.
        // Z030 wants the terminal state to be a state it can name, and
        // `undefined` is the one it names for a released owner.
        self.* = undefined;
    }

    pub fn declaresLocally(self: *const Scanner, name: []const u8) bool {
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
    /// So a `fn` keyword has to be known to be in *declaration* position,
    /// because a `fn` with no body — a function type in a field, a parameter
    /// or a type alias — would otherwise hand its mark to the next brace, which
    /// is not a function body and would then be read as test scaffolding. That
    /// is the one direction this gate cannot afford: every other imprecision
    /// here costs a complaint about a test helper, and this one costs a library
    /// PRNG nobody reports.
    ///
    /// The same pass records the names this file declares, because a syscall is
    /// only a syscall by what stands in front of it, and a declaration is only a
    /// declaration by its own `fn`.
    fn classify(self: *Scanner, alloc: std.mem.Allocator) !void {
        const Frame = struct { is_fn: bool, first: usize, uses_testing: bool };
        var frames: std.ArrayList(Frame) = .empty;
        defer frames.deinit(alloc);
        // Set by a `fn` keyword and spent by the brace that opens its body.
        var want_fn_body = false;
        // `(` depth, so the `;` and `,` that end a declaration are told apart
        // from the ones inside a parameter list or a call.
        var paren: u32 = 0;

        self.scaffolding.clearRetainingCapacity();
        try self.scaffolding.appendNTimes(alloc, false, self.tokens.items.len);
        self.local_fns.clearRetainingCapacity();

        for (self.tokens.items, 0..) |tok, i| {
            if (tok.tag == .keyword_fn) {
                want_fn_body = true;
                if (self.fnNameAfter(i)) |name| {
                    try self.local_fns.append(alloc, name);
                }
            }
            switch (tok.tag) {
                .l_paren => paren += 1,
                .r_paren => {
                    if (paren > 0) paren -= 1;
                },
                .l_brace => {
                    try frames.append(alloc, .{
                        .is_fn = want_fn_body,
                        .first = i,
                        .uses_testing = false,
                    });
                    want_fn_body = false;
                },
                .r_brace => {
                    if (paren == 0) want_fn_body = false;
                    if (frames.pop()) |frame| {
                        if (frame.is_fn and frame.uses_testing) {
                            for (self.scaffolding.items[frame.first .. i + 1]) |*slot| {
                                slot.* = true;
                            }
                        }
                    }
                },
                else => {
                    // A `;` or a `,` at depth zero ends the declaration a
                    // pending `fn` belongs to, exactly as the `}` above does.
                    // Three of these are live in the tree today — the
                    // `?*const fn` fields in `connection.zig` and
                    // `connection_manager.zig` — so this is not a shape that
                    // might arrive later.
                    if (paren == 0 and (tok.tag == .semicolon or tok.tag == .comma)) {
                        want_fn_body = false;
                    }
                    if (self.reachesTesting(i)) {
                        // The bound is restated in the expression the read
                        // sits in. Being outside every brace is a real state
                        // and a common one — every vendored file opens with
                        // top-level declarations — and this read used to sit
                        // behind a `continue` that proved it here and nowhere
                        // else, which zbc cannot follow. A gate that reports
                        // itself is a gate nobody keeps running.
                        if (frames.items.len > 0) {
                            frames.items[frames.items.len - 1].uses_testing = true;
                        }
                    }
                },
            }
        }
    }

    pub fn token(self: *const Scanner, i: usize) ?std.zig.Token {
        if (i >= self.tokens.items.len) return null;
        return self.tokens.items[i];
    }

    /// The bytes of a token. A caller that has a token rather than an index
    /// reads its text through here, so no rule slices `src` itself.
    pub fn text(self: *const Scanner, tok: std.zig.Token) []const u8 {
        return self.src[tok.loc.start..tok.loc.end];
    }

    /// `back > i` reads token zero rather than nothing, which is a lie the
    /// callers have to be able to survive. `beforeChain` is: at `i` below two,
    /// both its reads land on the same token, so its condition asks one token to
    /// be both a period and an identifier, and the walk stops. Getting that
    /// wrong costs a hit this gate did not have to report — a type position read
    /// as something else is the safe direction — which is why it is left as a
    /// saturating read rather than a checked one.
    pub fn tagAt(self: *const Scanner, i: usize, back: usize) ?std.zig.Token.Tag {
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
    pub fn tagAfter(self: *const Scanner, i: usize) ?std.zig.Token.Tag {
        if (i + 1 >= self.tokens.items.len) return null;
        return self.tokens.items[i + 1].tag;
    }

    /// The text of the token after `i`.
    pub fn textAfter(self: *const Scanner, i: usize) ?[]const u8 {
        const ahead = self.token(i + 1) orelse return null;
        return self.text(ahead);
    }

    /// The name a `fn` keyword declares, or null when it declares none: a
    /// function *type* — in a field, a parameter or a type alias — carries no
    /// name, and the brace that follows one belongs to whatever encloses it.
    ///
    /// `tagAfter` and `textAfter` in one read, so the shape of the token and
    /// the payload a caller unwraps cannot come apart at the call site.
    pub fn fnNameAfter(self: *const Scanner, i: usize) ?[]const u8 {
        if (self.tagAfter(i) != .identifier) return null;
        return self.textAfter(i);
    }

    pub fn textAt(self: *const Scanner, i: usize, back: usize) ?[]const u8 {
        const ahead = self.token(i -| back) orelse return null;
        return self.text(ahead);
    }

    /// The text of the token `back` places before `i`, or null unless that
    /// token is an identifier. A qualifier name is only a qualifier name when
    /// the token is one, and this is where those are one question.
    pub fn identifierAt(self: *const Scanner, i: usize, back: usize) ?[]const u8 {
        if (self.tagAt(i, back) != .identifier) return null;
        return self.textAt(i, back);
    }

    /// The text of the token `back` places before `i`, or null unless that
    /// token is a string literal. A caller that wants the literal's bytes has
    /// to know it is one first, and this is where the two are one question.
    pub fn stringAt(self: *const Scanner, i: usize, back: usize) ?[]const u8 {
        if (self.tagAt(i, back) != .string_literal) return null;
        return self.textAt(i, back);
    }

    /// True when the token `back` places before `i` is the identifier `name`.
    pub fn names(self: *const Scanner, i: usize, back: usize, name: []const u8) bool {
        const ident = self.identifierAt(i, back) orelse return false;
        return std.mem.eql(u8, ident, name);
    }

    pub fn puncts(self: *const Scanner, i: usize, back: usize, tag: std.zig.Token.Tag) bool {
        return self.tagAt(i, back) == tag;
    }

    /// `std.<name>`, whatever the file aliased `std` to.
    pub fn stdChain(self: *const Scanner, i: usize, name: []const u8) bool {
        return self.names(i, 0, name) and self.puncts(i, 1, .period) and self.names(i, 2, "std");
    }

    /// `std.time.<name>`.
    pub fn stdTime(self: *const Scanner, i: usize, name: []const u8) bool {
        return self.names(i, 0, name) and self.puncts(i, 1, .period) and
            self.names(i, 2, "time") and self.puncts(i, 3, .period) and
            self.names(i, 4, "std");
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

    /// Reports one finding. The line travels as part of `at` rather than as its
    /// own argument, so the token a rule judged and the line it is reported on
    /// cannot come apart at a call site.
    pub fn hit(self: *Scanner, rule: Rule, at: At, loc: std.zig.Token.Loc) void {
        self.hits += 1;
        std.debug.print("{s}:{d}: {s}\n    {s}\n    | {s}\n", .{
            self.path,
            at.line,
            rule.name,
            rule.breaks,
            self.sourceLine(loc),
        });
    }

    /// The offending line, for the reader who has to go look at it.
    fn sourceLine(self: *const Scanner, loc: std.zig.Token.Loc) []const u8 {
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

    /// The tag in front of the identifier's own qualifier chain, so a type
    /// position is found the way a reader finds it: in `prng:
    /// std.Random.DefaultPrng` the colon sits in front of `std`, four tokens
    /// before the type name and not one.
    pub fn beforeChain(self: *const Scanner, i: usize) ?std.zig.Token.Tag {
        var k = i;
        while (self.tagAt(k, 1) == .period and self.tagAt(k, 2) == .identifier) k -= 2;
        return self.tagAt(k, 1);
    }

    /// Reads one file's token stream and hands every token to `judge`, returning
    /// the number of test declarations it saw.
    ///
    /// This is the only place brace depth, line numbers and the library/test
    /// line are tracked, which is what keeps every rule reading the same scope
    /// of the same file.
    pub fn scanFile(
        self: *Scanner,
        alloc: std.mem.Allocator,
        src: [:0]const u8,
        path: []const u8,
        judge: Judge,
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

            judge(self, .{
                .index = i,
                .line = line,
                .depth = depth,
                // Test code is a test body or a helper that reaches for
                // `std.testing`; both boundaries come from structure, never from
                // where the code sits in the file.
                .in_test = test_depth != null or self.scaffolding.items[i],
            });
        }

        return self.tests;
    }
};
