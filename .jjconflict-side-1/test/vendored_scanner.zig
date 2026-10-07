//! One vendored file's token stream, read and classified.
//!
//! Everything structural comes from `std.zig.Tokenizer`, which skips comments
//! and string literals, knows that `test` is a keyword rather than an
//! identifier, and gives brace depth exactly. Nothing here is positional: the
//! questions below are answered from the tokens either side of the one under
//! question, never from a line number.

const std = @import("std");

const rulebook = @import("vendored_rulebook.zig");

/// Reads one file's token stream and holds it to the rules.
///
/// Everything structural comes from `std.zig.Tokenizer`, which skips comments
/// and string literals, knows that `test` is a keyword rather than an
/// identifier, and gives brace depth exactly. Nothing here is positional.
///
/// This module answers the questions and `vendored_judge.zig` asks them, so
/// the whole query surface below is `pub`: the split that gave each its own
/// file left the answers private to the file that stores the tokens. Two stay
/// private because they are answers only another answer needs — `classify` is
/// the pass the others are built on, and `declaresLocally` is a question only
/// `isSyscall` asks.
pub const Scanner = struct {
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
    /// of them is this project's own code rather than a syscall, which is why a
    /// name shared with libc — `connect(3)` and `accept(2)` are the spellings
    /// this one meets — cannot be read as a syscall by name alone. A file that
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
    /// So a `fn` keyword has to be known to be in *declaration* position,
    /// because a `fn` with no body — a function type in a field, a parameter
    /// or a type alias — would otherwise hand its mark to the next brace,
    /// which is not a function body and would then be read as test
    /// scaffolding. That is the one direction this gate cannot afford: every
    /// other imprecision here costs a complaint about a test helper, and this
    /// one costs a library PRNG nobody reports.
    ///
    /// The same pass records the names this file declares, because a syscall is
    /// only a syscall by what stands in front of it, and a declaration is only
    /// a declaration by its own `fn`.
    ///
    /// `pub` because `vendored_judge.zig` calls it across the file boundary
    /// the split that gave this module its own name introduced.
    pub fn classify(self: *Scanner, alloc: std.mem.Allocator) !void {
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
                    // `connection_manager.zig` — so this is not a shape
                    // that might arrive later.
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

    fn token(self: *const Scanner, i: usize) ?std.zig.Token {
        if (i >= self.tokens.items.len) return null;
        return self.tokens.items[i];
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
    fn textAfter(self: *const Scanner, i: usize) ?[]const u8 {
        const ahead = self.token(i + 1) orelse return null;
        return self.src[ahead.loc.start..ahead.loc.end];
    }

    /// The name a `fn` keyword declares, or null when it declares none: a
    /// function *type* — in a field, a parameter or a type alias — carries no
    /// name, and the brace that follows one belongs to whatever encloses it.
    ///
    /// `tagAfter` and `textAfter` in one read, so the shape of the token and
    /// the payload a caller unwraps cannot come apart at the call site.
    fn fnNameAfter(self: *const Scanner, i: usize) ?[]const u8 {
        if (self.tagAfter(i) != .identifier) return null;
        return self.textAfter(i);
    }

    pub fn textAt(self: *const Scanner, i: usize, back: usize) ?[]const u8 {
        const ahead = self.token(i -| back) orelse return null;
        return self.src[ahead.loc.start..ahead.loc.end];
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
        if (self.tagAt(i, back) != .identifier) return false;
        const text = self.textAt(i, back) orelse return false;
        return std.mem.eql(u8, text, name);
    }

    pub fn puncts(self: *const Scanner, i: usize, back: usize, tag: std.zig.Token.Tag) bool {
        return self.tagAt(i, back) == tag;
    }

    fn namespace(self: *const Scanner, i: usize, back: usize) bool {
        if (self.tagAt(i, back) != .identifier) return false;
        return rulebook.has(&rulebook.namespaces, self.textAt(i, back) orelse "");
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

    /// True when the token at `i` is the callee of a call that could reach the
    /// operating system: a bare `socket(`, or one whose immediately preceding
    /// qualifier is a namespace, `posix.socket(`. Two shapes are deliberately
    /// not that. A declaration, `fn accept(`, is not a call at all. And a
    /// qualifier that is not a namespace — a type or a value, `endpoint.accept(`
    /// — is left alone.
    ///
    /// That last one is a lexical boundary, not a fact about the code, so it
    /// is worth stating plainly. This reads exactly one qualifier: the
    /// identifier directly in front of the period. A syscall reached through a
    /// type, `std.Io.net.IpAddress.bind(`, or through a namespace bound to
    /// another name is not a shape this rule matches, and no method is
    /// classified as the project's own or as the kernel's. Nothing here
    /// resolves a declaration or a type, so a run that passes says the tree
    /// used none of the spellings this file names — not that it cannot take a
    /// descriptor.
    pub fn isSyscall(self: *const Scanner, i: usize) bool {
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
    pub fn beforeChain(self: *const Scanner, i: usize) ?std.zig.Token.Tag {
        var k = i;
        while (self.tagAt(k, 1) == .period and self.tagAt(k, 2) == .identifier) k -= 2;
        return self.tagAt(k, 1);
    }
};
