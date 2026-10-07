//! One answer to a question about a host: the addresses it carried, the alias
//! they were reached under, and the TTL a cache must not outlive.
//!
//! This is the `lookup_answer.zig` that asks `IN A` or `IN AAAA` rather than
//! `IN TXT`, and it is not a variant of that file with a flag on it: a host
//! answer is a set of addresses rather than a set of character strings, so
//! there is an `RDLENGTH` to check against the family's own width, an owner
//! that may be an alias rather than the name asked about, and a `TTL` worth
//! keeping. The header rule, the `RDLENGTH` bounds and the walk past a record
//! are `lookup_answer.readHeader`, `lookup_answer.recordBody` and
//! `lookup_answer.skipRecord` — called there, not restated here.
//!
//! # An answer is a struct, and a union would drop half of one
//!
//! `Answer` carries `records`, `alias` and `ttl_s` as three fields of one
//! value, not as arms of a `union`. The reason is a single DNS message: an
//! answer to `www.example.com` may carry **both**
//!
//! ```text
//! www.example.com.        CNAME  host.example.net.
//! host.example.net.       A      192.0.2.1
//! ```
//!
//! and a union of alias-or-address holds whichever arm it was last given, so
//! the caller that chased the alias loses the address and the caller that read
//! the address cannot say which name it belongs to. Both facts are wanted at
//! once — the address to dial and the name to cache it under — so both are
//! fields.
//!
//! # What is collected, and the three tests before anything is read
//!
//! `RDATA` is taken only when all three hold: `TYPE` is the family's own
//! record type, `CLASS` is `IN`, and the owner is the name the chain has
//! reached. In particular an `A` question collects no `AAAA` record, because
//! `TYPE` is checked against the family and not against "some address". Once
//! a record does qualify, its `RDLENGTH` must equal the family's width or the
//! whole answer is refused (`host_wire.Error.BadRecordLength`): a record whose
//! type and contents disagree is not an address to be salvaged.
//!
//! # The alias chain, and the hop that stops it
//!
//! A `CNAME` whose owner is the name being chased moves the chase. The bound
//! is `max_cname_hops`, and it is what refuses a loop: RFC 1034 §4.3.2 lets a
//! name be an alias of an alias for as long as the zone says so, and a zone
//! that says `a` is an alias of `b` and `b` of `a` cannot be resolved at all.
//! Every hop consumes a record, so `lookup_wire.max_section_records` is the
//! outer bound on how long a loop can even be.
//!
//! # Purity
//!
//! No clock, no socket, no global, no thread, no environment. The allocator is
//! the caller's and the scratch is the caller's; a decoded name never outlives
//! the call, and the one name that does outlive it — the alias — is a copy the
//! answer owns and `Answer.deinit` releases.
//!
//! # No golden vector is claimed
//!
//! The records below are constructed, not captured, and the tests therefore
//! prove *this decoder's* refusals and field reads and nothing about any other
//! implementation. Whether these bytes interoperate with a nameserver is
//! unverified here, and `AGENTS.md` §2 says a wire claim is only as good as a
//! captured vector — so no such claim is made. `lookup_answer.zig` holds the
//! one captured DNS answer this project has.

const std = @import("std");

const base_addr = @import("../base/addr.zig");

const names = @import("lookup_name.zig");
const wire = @import("lookup_wire.zig");
const lookup_answer = @import("lookup_answer.zig");

const host_wire = @import("host_wire.zig");

/// What reading one host answer can fail with: the wire's failures, this
/// module's own, and the allocator's.
///
/// `OutOfMemory` is here because the records and the alias are copied into
/// `alloc`, exactly as `lookup_answer.Error` is for the records it copies.
/// `BadRecordLength` is `host_wire`'s and belongs to no other caller, and
/// `CnameLoop` is this module's own: it is the one refusal that is about the
/// shape of the answer's owner names rather than about a field's value.
pub const Error = wire.WireError || host_wire.Error || error{ OutOfMemory, CnameLoop };

/// How many `CNAME` records one answer may make this walk follow.
///
/// A bound and not a budget. RFC 1034 §4.3.2 lets a name be an alias of an
/// alias for as long as the zone says so, and a cycle — `a` is an alias of
/// `b` and `b` of `a` — is a zone nobody can resolve, so a chain longer than
/// this is refused rather than followed. Eight is far past any published
/// chain and well below `lookup_wire.max_section_records`, which is the bound
/// the answer's own `ANCOUNT` puts on how many hops can be present at all.
pub const max_cname_hops: usize = 8;

/// One address an answer carried, and what it may be cached for.
pub const Record = struct {
    /// The address. Always present, which is the whole of why `Answer` is a
    /// struct and not a union: an address with no name behind it is a fact,
    /// and an alias with no address behind it is a different fact.
    ip: base_addr.IpAddress,
    /// This record's own `TTL`, in whole seconds, after RFC 2181 §5.2's rule
    /// that a field with the top bit set is zero.
    ///
    /// Per record and not per answer, because RFC 1035 §4.1.3 gives every
    /// record its own and two records under one name routinely disagree; the
    /// one number a cache is bound by is `Answer.ttl_s`, which is the lowest
    /// of these.
    ttl_s: u32,
};

/// What one answer to a host question came to.
pub const Answer = struct {
    /// Every address of the family asked about, in the order the answer
    /// listed them. Empty is a fact about the world — the name exists and
    /// carries no address of this family — and it is not `error.NameError`,
    /// which is the name not existing at all.
    ///
    /// Owned by `alloc`. An empty set is the static empty slice and
    /// `deinit` frees nothing for it.
    records: []const Record,
    /// The name the addresses were reached under when the answer carried a
    /// `CNAME` chain, and null when it answered under the name that was
    /// asked about.
    ///
    /// Owned by `alloc`, and only here: one chain reaches one terminal name,
    /// so every record in `records` shares it and no record needs its own
    /// copy.
    alias: ?[]const u8,
    /// The lowest `TTL` over `records`, and the number a cache entry for the
    /// whole answer may not outlive. Zero when `records` is empty, because a
    /// set with nothing in it caches for no time at all.
    ttl_s: u32,

    /// Hand back everything this answer owns and nothing a caller still holds:
    /// `records` and `alias` are the answer's, the scratch it was decoded into
    /// is the caller's and is untouched.
    pub fn deinit(self: Answer, alloc: std.mem.Allocator) void {
        if (self.alias) |alias| alloc.free(alias);
        if (self.records.len != 0) alloc.free(self.records);
    }
};

/// The scratch one decode needs.
///
/// An options struct rather than two positional `[]u8`s because the two are the
/// same type and a pair of them in a parameter list is a list nothing
/// distinguishes. Both are caller-owned and fixed-size, because RFC 1035
/// §2.3.4 caps a name and that cap is what makes this a bound rather than a
/// guess.
pub const Scratch = struct {
    /// One decoded owner name, `lookup_wire.max_name_length` bytes.
    owner: []u8,
    /// The name a `CNAME`'s `RDATA` decodes into, `lookup_wire.max_name_length`
    /// bytes. The walk copies what it decodes here into the answer's own
    /// alias before chasing it, so nothing this returns points into scratch
    /// and the caller may reuse it the moment `readAnswer` returns.
    target: []u8,
};

/// Read one answer to `name` out of `message` and copy its addresses into
/// `alloc`.
///
/// `family` is the `QTYPE` that was asked, `id` the transaction it was asked
/// under, and `scratch` is the two name buffers above. A message that is not
/// this question's answer is refused rather than read — the length, then the
/// `ID`, then `QR`, then `TC`, then the `RCODE`, then the counts, in
/// `lookup_answer.readHeader` and in that order, because a message belonging
/// to another question is a different fact from a malformed one.
///
/// The sections that cannot carry this question's answer are walked without
/// collecting: a record in an authority section is somebody else's authority
/// and not this node's address. They are walked at all because walking is the
/// only way to know the message was not cut short inside one — and the `OPT`
/// record a query advertised is answered with sits in the additional section.
///
/// On error nothing is allocated and nothing is freed twice. On success the
/// answer owns `records` and `alias`, and the caller releases them with
/// `Answer.deinit`.
pub fn readAnswer(
    alloc: std.mem.Allocator,
    message: []const u8,
    name: []const u8,
    family: host_wire.Family,
    id: u16,
    scratch: Scratch,
) Error!Answer {
    const counts = try lookup_answer.readHeader(message, id);
    var at: usize = wire.header_length;
    for (0..counts.questions) |_| {
        at = (try names.readName(message, at, &.{})).end;
        if (at + wire.question_length > message.len) return error.ShortMessage;
        at += wire.question_length;
    }

    var records: std.ArrayList(Record) = .empty;
    defer records.deinit(alloc);
    // The chain's terminal name, and this answer's copy of it. Released on the
    // way out only when the way out is an error; a successful return hands the
    // ownership to the caller instead.
    var alias: ?[]u8 = null;
    errdefer if (alias) |held| alloc.free(held);

    // The name the next record has to be owned by: the one asked about, until
    // a `CNAME` moves it. Borrowed from `scratch` and from the copy above,
    // both of which outlive the walk.
    var chasing: []const u8 = name;
    var hops: usize = 0;
    for (0..counts.answers) |_| {
        const decoded = try names.readName(message, at, scratch.owner);
        const body = decoded.end;
        // The record is walked whole first, so every offset read below is
        // inside the bounds the record's own `RDLENGTH` vouches for. This
        // decodes the name a second time, and it is worth saying why that is
        // not a second spelling of anything: `skipRecord` is the only
        // definition of "past this record" in the project, and a walk that
        // recomputed it here would be the copy this file exists not to have.
        at = try lookup_answer.skipRecord(message, at);
        const owner = scratch.owner[0..decoded.written];
        // The owner has to be the name being chased. RFC 1035 §4.1.1's `AA`
        // note says an answer "may have multiple owner names because of
        // aliases", which is the arm below and not an excuse for this one: a
        // record under any other name belongs to a name nobody asked about,
        // and refusing the whole message over it would lose this question's
        // records behind somebody else's.
        if (!std.ascii.eqlIgnoreCase(owner, chasing)) continue;
        if (wire.be16(message, body + host_wire.class_at) != wire.class_in) continue;
        const kind = wire.be16(message, body + host_wire.type_at);
        if (kind == host_wire.type_cname) {
            // Checked before the hop is taken, so the refusal lands on the hop
            // that would have made the chain one too long.
            if (hops == max_cname_hops) return error.CnameLoop;
            hops += 1;
            const start = try lookup_answer.recordBody(message, body);
            const target = try names.readName(message, start, scratch.target);
            const held = try alloc.dupe(u8, scratch.target[0..target.written]);
            if (alias) |previous| alloc.free(previous);
            alias = held;
            chasing = held;
            continue;
        }
        // Family isolation, and the one test a host question adds to the TXT
        // walk: `TYPE` must be this family's own record type. An `A` question
        // reads no `AAAA` and an `AAAA` question reads no `A`, because a
        // record of the other family is not an answer to this question.
        if (kind != family.recordType()) continue;
        const start = try lookup_answer.recordBody(message, body);
        const length = wire.be16(message, body + host_wire.rdlength_at);
        try records.append(alloc, .{
            .ip = try family.ip(message[start..][0..length]),
            .ttl_s = try host_wire.ttlSeconds(message, body),
        });
    }
    for (0..counts.authorities + counts.additionals) |_| {
        at = try lookup_answer.skipRecord(message, at);
    }

    const ttl = lowest(records.items);
    const owned: []const Record = if (records.items.len == 0)
        &.{}
    else
        try records.toOwnedSlice(alloc);
    return .{ .records = owned, .alias = alias, .ttl_s = ttl };
}

/// The lowest `TTL` over a set, which is the number the whole set's cache
/// entry is bound by.
///
/// RFC 1034 §4.3.2 caches a set for the TTL of the records in it, and the
/// only number safe for all of them is the shortest life any of them has: a
/// cache that outlived the record with the smallest `TTL` would answer from a
/// name its author has already withdrawn.
fn lowest(records: []const Record) u32 {
    if (records.len == 0) return 0;
    var ttl: u32 = std.math.maxInt(u32);
    for (records) |record| ttl = @min(ttl, record.ttl_s);
    return ttl;
}

const t = std.testing;

/// One record as a test writes it.
const Written = struct {
    /// The owner name in presentation form, written out with no §4.1.4
    /// pointer. RFC 1035 §4.1.4 permits that in a generated message and it
    /// keeps the fixture honest: a pointer would make a test's expectation
    /// depend on an offset it had not written down.
    owner: []const u8,
    /// `TYPE`. RFC 1035 §3.2.2, §3.2.3, §3.2.5.
    kind: u16,
    /// `CLASS`. `lookup_wire.class_in` unless a test is writing somebody
    /// else's, which is the only way a record's class is ever wrong.
    class: u16 = wire.class_in,
    /// `TTL`. RFC 1035 §4.1.3.
    ttl_s: u32 = 60,
    /// `RDATA`: four octets for an address, a wire name for a `CNAME`, and
    /// whatever width a test is using to be wrong about `RDLENGTH`.
    rdata: []const u8,
};

/// The longest owner name the loop fixture writes, `l8.example.` and one
/// octet of terminator. `max_cname_hops` is eight and the fixture writes
/// `max_cname_hops + 1` names, so the index never reaches two digits.
const loop_name_length = 12;

/// Frame `records` as the answer section of a response to `name` with no
/// compression, and say how long the message is.
///
/// Every field is the RFC's own, written from `lookup_wire`'s constants, so a
/// test and this builder disagree if either changes its mind about the format.
/// The question is written with `lookup_wire.type_txt` because the walk skips
/// questions and the question's own `QTYPE` is not what any test here is about.
fn frameAnswer(
    message: []u8,
    name: []const u8,
    id: u16,
    records: []const Written,
) wire.WireError!usize {
    if (message.len < wire.header_length) return error.BufferTooSmall;
    wire.put16(message, 0, id);
    wire.put16(message, 2, wire.flag_response);
    wire.put16(message, 4, 1);
    wire.put16(message, 6, @intCast(records.len));
    wire.put16(message, 8, 0);
    wire.put16(message, 10, 0);
    var at: usize = wire.header_length;
    at += try names.writeName(name, message[at..]);
    if (at + wire.question_length > message.len) return error.BufferTooSmall;
    wire.put16(message, at, wire.type_txt);
    wire.put16(message, at + 2, wire.class_in);
    at += wire.question_length;
    for (records) |record| {
        at += try names.writeName(record.owner, message[at..]);
        if (at + host_wire.fixed_length > message.len) return error.BufferTooSmall;
        wire.put16(message, at + host_wire.type_at, record.kind);
        wire.put16(message, at + host_wire.class_at, record.class);
        wire.put32(message, at + host_wire.ttl_at, record.ttl_s);
        wire.put16(message, at + host_wire.rdlength_at, @intCast(record.rdata.len));
        at += host_wire.fixed_length;
        if (at + record.rdata.len > message.len) return error.BufferTooSmall;
        @memcpy(message[at..][0..record.rdata.len], record.rdata);
        at += record.rdata.len;
    }
    return at;
}

/// The wire form of `name`, and how many octets of it there are.
///
/// RFC 1035 §3.3.1 puts a name in a `CNAME`'s `RDATA`, and the walk decodes it
/// with `lookup_name.readName` out of the message rather than out of the
/// fixture, so a test writes the name once and reads it back the same way.
fn wireName(name: []const u8) ![wire.max_name_length]u8 {
    var out: [wire.max_name_length]u8 = undefined;
    const written = try names.writeName(name, &out);
    @memset(out[written..], 0);
    return out;
}

const v4_first = [_]u8{ 192, 0, 2, 1 };
const v4_second = [_]u8{ 198, 51, 100, 3 };
const v6_only = [_]u8{
    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
    0,    0,    0,    0,    0, 0, 0, 1,
};

test "an A question collects no AAAA and an AAAA question collects no A" {
    // RFC 1035 §3.2.2's `A 1` and §3.2.5's `AAAA 28` are different `TYPE`s
    // over different widths, and a walk that filtered on "looks like an
    // address" would take both and hand the caller a v4 where it asked for a
    // v6. Both records are in one message, so both questions see the same
    // bytes and a filter matching on class or owner alone would return two.
    const asked = "www.example.com.";
    var message: [256]u8 = undefined;
    const records = [_]Written{
        .{ .owner = asked, .kind = host_wire.type_a, .ttl_s = 300, .rdata = &v4_first },
        .{ .owner = asked, .kind = host_wire.type_aaaa, .ttl_s = 300, .rdata = &v6_only },
    };
    const at = try frameAnswer(&message, asked, 0x1234, &records);
    var owner: [wire.max_name_length]u8 = undefined;
    var held: [wire.max_name_length]u8 = undefined;
    const scratch: Scratch = .{ .owner = &owner, .target = &held };

    const four = try readAnswer(t.allocator, message[0..at], asked, .v4, 0x1234, scratch);
    defer four.deinit(t.allocator);
    try t.expectEqual(@as(usize, 1), four.records.len);
    try t.expectEqual(base_addr.IpAddress{ .v4 = v4_first }, four.records[0].ip);
    try t.expectEqual(@as(u32, 300), four.records[0].ttl_s);
    try t.expectEqual(@as(?[]const u8, null), four.alias);

    const six = try readAnswer(t.allocator, message[0..at], asked, .v6, 0x1234, scratch);
    defer six.deinit(t.allocator);
    try t.expectEqual(@as(usize, 1), six.records.len);
    try t.expectEqual(base_addr.IpAddress{ .v6 = v6_only }, six.records[0].ip);
    try t.expectEqual(host_wire.Family.v6, host_wire.Family.of(six.records[0].ip));
}

test "an alias and the address behind it are both kept, and a union would drop one" {
    // The message that decides the type: RFC 1035 §4.1.1's `AA` note says an
    // answer may carry several owner names because of aliases, so one answer
    // holds `www.example.com. CNAME host.example.net.` *and*
    // `host.example.net. A 192.0.2.1`. Both are fields of `Answer` because
    // both are wanted: the address to dial and the name to cache it under.
    const asked = "www.example.com.";
    const canonical = "host.example.net.";
    const target = try wireName(canonical);
    var records = [_]Written{
        .{
            .owner = asked,
            .kind = host_wire.type_cname,
            .ttl_s = 300,
            .rdata = target[0 .. canonical.len + 1],
        },
        .{ .owner = canonical, .kind = host_wire.type_a, .ttl_s = 60, .rdata = &v4_first },
    };
    var message: [256]u8 = undefined;
    const at = try frameAnswer(&message, asked, 7, &records);
    var owner: [wire.max_name_length]u8 = undefined;
    var held: [wire.max_name_length]u8 = undefined;

    const answer = try readAnswer(
        t.allocator,
        message[0..at],
        asked,
        .v4,
        7,
        .{ .owner = &owner, .target = &held },
    );
    defer answer.deinit(t.allocator);
    try t.expectEqual(@as(usize, 1), answer.records.len);
    try t.expectEqual(base_addr.IpAddress{ .v4 = v4_first }, answer.records[0].ip);
    // The chain's terminal name, owned by the answer and not a borrow of the
    // scratch: the caller reads it after the call has returned, and the
    // scratch is the caller's to reuse at once.
    try t.expectEqualStrings(canonical, answer.alias.?);
    // The two TTLs disagree on purpose, so the set's number is the shorter
    // one and not the first one read.
    try t.expectEqual(@as(u32, 60), answer.records[0].ttl_s);
    try t.expectEqual(@as(u32, 60), answer.ttl_s);

    // The same message asked under the name it already answered for: the
    // `CNAME` is no longer addressed to the question, so the address is found
    // directly and there is no alias to report.
    const direct = try readAnswer(
        t.allocator,
        message[0..at],
        canonical,
        .v4,
        7,
        .{ .owner = &owner, .target = &held },
    );
    defer direct.deinit(t.allocator);
    try t.expectEqual(@as(usize, 1), direct.records.len);
    try t.expectEqual(@as(?[]const u8, null), direct.alias);
}

test "a chain is followed to the address behind it" {
    // Three names and one address at the end: the walk has to move the name it
    // is chasing on each `CNAME`, or the address's owner is a name nobody
    // asked about and the answer comes back empty.
    const first = "a.example.com.";
    const second = "b.example.com.";
    const third = "c.example.com.";
    const to_second = try wireName(second);
    const to_third = try wireName(third);
    const records = [_]Written{
        .{
            .owner = first,
            .kind = host_wire.type_cname,
            .ttl_s = 120,
            .rdata = to_second[0 .. second.len + 1],
        },
        .{
            .owner = second,
            .kind = host_wire.type_cname,
            .ttl_s = 120,
            .rdata = to_third[0 .. third.len + 1],
        },
        .{
            .owner = third,
            .kind = host_wire.type_a,
            .ttl_s = 120,
            .rdata = &[_]u8{ 203, 0, 113, 5 },
        },
    };
    var message: [512]u8 = undefined;
    const at = try frameAnswer(&message, first, 1, &records);
    var owner: [wire.max_name_length]u8 = undefined;
    var held: [wire.max_name_length]u8 = undefined;

    const answer = try readAnswer(
        t.allocator,
        message[0..at],
        first,
        .v4,
        1,
        .{ .owner = &owner, .target = &held },
    );
    defer answer.deinit(t.allocator);
    try t.expectEqual(@as(usize, 1), answer.records.len);
    try t.expectEqual(base_addr.IpAddress{ .v4 = .{ 203, 0, 113, 5 } }, answer.records[0].ip);
    // The terminal name, which is the third and not the first: an alias chain
    // has one end and the answer reports that end.
    try t.expectEqualStrings(third, answer.alias.?);
}

test "a chain longer than the hop bound is refused, and a loop is what hits it" {
    // `l0` is an alias of `l1`, `l1` of `l2`, and the last of them an alias of
    // `l0` again, so the chase can never end. `max_cname_hops` is what refuses
    // it: `ANCOUNT` bounds how long the loop can be at all, and this bound is
    // what turns running out of chain into a named error rather than into an
    // empty answer a caller would read as "this host has no address".
    const hops = max_cname_hops + 1;
    var owner_names: [hops][loop_name_length]u8 = undefined;
    var owners: [hops][]const u8 = undefined;
    var targets: [hops][wire.max_name_length]u8 = undefined;
    var records: [hops]Written = undefined;
    for (0..hops) |index| {
        owners[index] = std.fmt.bufPrint(&owner_names[index], "l{d}.example.", .{index}) catch
            return error.NameTooLong;
    }
    for (0..hops) |index| {
        const ahead = (index + 1) % hops;
        const written = try names.writeName(owners[ahead], &targets[index]);
        records[index] = .{
            .owner = owners[index],
            .kind = host_wire.type_cname,
            .ttl_s = 60,
            .rdata = targets[index][0..written],
        };
    }
    var message: [1024]u8 = undefined;
    const at = try frameAnswer(&message, owners[0], 2, &records);
    var owner: [wire.max_name_length]u8 = undefined;
    var held: [wire.max_name_length]u8 = undefined;

    try t.expectError(error.CnameLoop, readAnswer(
        t.allocator,
        message[0..at],
        owners[0],
        .v4,
        2,
        .{ .owner = &owner, .target = &held },
    ));

    // One hop short of the bound is followed rather than refused, which is what
    // makes the bound a bound: the same fixture with the last alias removed
    // answers.
    var shorter: [hops - 1]Written = undefined;
    for (0..hops - 1) |index| shorter[index] = records[index];
    shorter[hops - 2] = .{
        .owner = owners[hops - 2],
        .kind = host_wire.type_a,
        .ttl_s = 60,
        .rdata = &[_]u8{ 203, 0, 113, 6 },
    };
    var short_message: [1024]u8 = undefined;
    const short_at = try frameAnswer(&short_message, owners[0], 3, &shorter);
    const answer = try readAnswer(
        t.allocator,
        short_message[0..short_at],
        owners[0],
        .v4,
        3,
        .{ .owner = &owner, .target = &held },
    );
    defer answer.deinit(t.allocator);
    try t.expectEqual(@as(usize, 1), answer.records.len);
    try t.expectEqual(base_addr.IpAddress{ .v4 = .{ 203, 0, 113, 6 } }, answer.records[0].ip);
}

test "a record whose RDLENGTH is not its family's width is refused" {
    // `TYPE 1` with three octets and `TYPE 28` with fifteen. Neither is an
    // address with a byte missing: each is a record whose declared type and
    // its contents disagree, and a decoder that read four octets out of the
    // first would be reporting an address the zone never published.
    const asked = "www.example.com.";
    const fifteen = [_]u8{
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
        0,    0,    0,    0,    0, 0, 1,
    };
    var owner: [wire.max_name_length]u8 = undefined;
    var held: [wire.max_name_length]u8 = undefined;
    const scratch: Scratch = .{ .owner = &owner, .target = &held };

    var narrow: [256]u8 = undefined;
    const narrow_at = try frameAnswer(&narrow, asked, 3, &.{
        .{ .owner = asked, .kind = host_wire.type_a, .rdata = &[_]u8{ 192, 0, 2 } },
    });
    try t.expectError(error.BadRecordLength, readAnswer(
        t.allocator,
        narrow[0..narrow_at],
        asked,
        .v4,
        3,
        scratch,
    ));

    // And the same message read as a `AAAA` question is not refused at all,
    // because the record's `TYPE` is not the family's and so it is skipped:
    // the width rule applies to a record that is already the family's.
    var wide: [256]u8 = undefined;
    const wide_at = try frameAnswer(&wide, asked, 4, &.{
        .{ .owner = asked, .kind = host_wire.type_a, .rdata = &v4_first },
    });
    const six = try readAnswer(t.allocator, wide[0..wide_at], asked, .v6, 4, scratch);
    defer six.deinit(t.allocator);
    try t.expectEqual(@as(usize, 0), six.records.len);

    // Fifteen octets under `TYPE 28`, one short of the sixteen the type
    // requires: the same disagreement, and the refusal is the same one.
    var under: [256]u8 = undefined;
    const under_at = try frameAnswer(&under, asked, 5, &.{
        .{ .owner = asked, .kind = host_wire.type_aaaa, .rdata = &fifteen },
    });
    try t.expectError(error.BadRecordLength, readAnswer(
        t.allocator,
        under[0..under_at],
        asked,
        .v6,
        5,
        scratch,
    ));
    // And one octet over, which `RDLENGTH` can name and `Family` cannot read.
    var over: [256]u8 = undefined;
    const seventeen = [_]u8{0} ** 17;
    const over_at = try frameAnswer(&over, asked, 6, &.{
        .{ .owner = asked, .kind = host_wire.type_aaaa, .rdata = &seventeen },
    });
    try t.expectError(error.BadRecordLength, readAnswer(
        t.allocator,
        over[0..over_at],
        asked,
        .v6,
        6,
        scratch,
    ));
}

test "a record owned by another name, or answering under another class, is skipped" {
    // Three records that must not be collected, beside one that must be: the
    // first is owned by a name nobody asked about, the second answers under
    // `CH` rather than `IN`, and the third is the question's own address.
    // Refusing the whole message over either of the first two would lose the
    // third, which is why they are skipped and not refused.
    const asked = "www.example.com.";
    var message: [256]u8 = undefined;
    const records = [_]Written{
        .{
            .owner = "other.example.com.",
            .kind = host_wire.type_a,
            .ttl_s = 300,
            .rdata = &[_]u8{ 198, 51, 100, 1 },
        },
        .{
            .owner = asked,
            .kind = host_wire.type_a,
            .class = 3,
            .ttl_s = 300,
            .rdata = &[_]u8{ 198, 51, 100, 2 },
        },
        .{ .owner = asked, .kind = host_wire.type_a, .ttl_s = 300, .rdata = &v4_second },
    };
    const at = try frameAnswer(&message, asked, 11, &records);
    var owner: [wire.max_name_length]u8 = undefined;
    var held: [wire.max_name_length]u8 = undefined;
    const scratch: Scratch = .{ .owner = &owner, .target = &held };

    const answer = try readAnswer(t.allocator, message[0..at], asked, .v4, 11, scratch);
    defer answer.deinit(t.allocator);
    try t.expectEqual(@as(usize, 1), answer.records.len);
    try t.expectEqual(base_addr.IpAddress{ .v4 = v4_second }, answer.records[0].ip);

    // A message with none of this question's records in it has an answer, and
    // it is an answer with nothing in it — which is a fact about the world and
    // not `error.NameError`, which is the name not existing. `t.allocator`
    // fails this test if `deinit` frees the static empty slice.
    var nothing: [256]u8 = undefined;
    const nothing_at = try frameAnswer(&nothing, asked, 12, &.{
        .{
            .owner = "other.example.com.",
            .kind = host_wire.type_a,
            .rdata = &[_]u8{ 198, 51, 100, 4 },
        },
    });
    const empty = try readAnswer(t.allocator, nothing[0..nothing_at], asked, .v4, 12, scratch);
    defer empty.deinit(t.allocator);
    try t.expectEqual(@as(usize, 0), empty.records.len);
    try t.expectEqual(@as(u32, 0), empty.ttl_s);
    try t.expectEqual(@as(?[]const u8, null), empty.alias);
}

test "a message that is not this question's answer is refused before it is walked" {
    const asked = "www.example.com.";
    var message: [256]u8 = undefined;
    const at = try frameAnswer(&message, asked, 0xbeef, &.{
        .{ .owner = asked, .kind = host_wire.type_a, .rdata = &v4_first },
    });
    var owner: [wire.max_name_length]u8 = undefined;
    var held: [wire.max_name_length]u8 = undefined;
    const scratch: Scratch = .{ .owner = &owner, .target = &held };

    // RFC 1035 §4.1.1's `ID` is what matches a reply to its question, and a
    // real answer under another transaction is not this question's answer:
    // the records are real and they are not ours to attribute.
    try t.expectError(error.ForeignTransaction, readAnswer(
        t.allocator,
        message[0..at],
        asked,
        .v4,
        0xbeef + 1,
        scratch,
    ));
    // A question arriving where an answer was wanted.
    wire.put16(message[0..], 2, wire.flag_recursion_desired);
    try t.expectError(error.NotAResponse, readAnswer(
        t.allocator,
        message[0..at],
        asked,
        .v4,
        0xbeef,
        scratch,
    ));
    // Every `RCODE` §4.1.1 defines, and the reserved range above them. A
    // `SERVFAIL` is a fact about this server's willingness to answer and not a
    // name that carries no address.
    const codes = [_]struct { code: u16, expect: anyerror }{
        .{ .code = 1, .expect = error.MalformedResponse },
        .{ .code = 2, .expect = error.ServiceFailure },
        .{ .code = 3, .expect = error.NameError },
        .{ .code = 4, .expect = error.Unimplemented },
        .{ .code = 5, .expect = error.ServiceRefused },
        .{ .code = 6, .expect = error.UnknownResponseCode },
    };
    for (codes) |case| {
        wire.put16(message[0..], 2, wire.flag_response | case.code);
        try t.expectError(case.expect, readAnswer(
            t.allocator,
            message[0..at],
            asked,
            .v4,
            0xbeef,
            scratch,
        ));
    }
    // Cut short, and a header claiming more records than a message this size
    // could hold. Both are `ShortMessage` and neither is a walk.
    wire.put16(message[0..], 2, wire.flag_response);
    try t.expectError(error.ShortMessage, readAnswer(
        t.allocator,
        message[0 .. wire.header_length - 1],
        asked,
        .v4,
        0xbeef,
        scratch,
    ));
    wire.put16(message[0..], 6, wire.max_section_records + 1);
    try t.expectError(error.ShortMessage, readAnswer(
        t.allocator,
        message[0..at],
        asked,
        .v4,
        0xbeef,
        scratch,
    ));
}

test "an answer set's TTL is the lowest of its records, and a signed TTL is zero" {
    const asked = "www.example.com.";
    var owner: [wire.max_name_length]u8 = undefined;
    var held: [wire.max_name_length]u8 = undefined;
    const scratch: Scratch = .{ .owner = &owner, .target = &held };

    var message: [256]u8 = undefined;
    const at = try frameAnswer(&message, asked, 21, &.{
        .{ .owner = asked, .kind = host_wire.type_a, .ttl_s = 900, .rdata = &v4_first },
        .{
            .owner = asked,
            .kind = host_wire.type_a,
            .ttl_s = 120,
            .rdata = &[_]u8{ 192, 0, 2, 2 },
        },
    });
    const answer = try readAnswer(t.allocator, message[0..at], asked, .v4, 21, scratch);
    defer answer.deinit(t.allocator);
    try t.expectEqual(@as(usize, 2), answer.records.len);
    // Per record, in the order the answer listed them.
    try t.expectEqual(@as(u32, 900), answer.records[0].ttl_s);
    try t.expectEqual(@as(u32, 120), answer.records[1].ttl_s);
    // And the set's own number is the shorter of the two, not the first.
    try t.expectEqual(@as(u32, 120), answer.ttl_s);

    // RFC 2181 §5.2 through the decoder: a `TTL` whose top bit is set is
    // zero, whole field and not the low bits, and it drags the set's number
    // down with it rather than leaving the other record's life standing.
    var signed: [256]u8 = undefined;
    const signed_at = try frameAnswer(&signed, asked, 22, &.{
        .{
            .owner = asked,
            .kind = host_wire.type_a,
            .ttl_s = (1 << 31) | 3600,
            .rdata = &v4_first,
        },
        .{
            .owner = asked,
            .kind = host_wire.type_a,
            .ttl_s = 120,
            .rdata = &[_]u8{ 192, 0, 2, 2 },
        },
    });
    const signed_answer = try readAnswer(
        t.allocator,
        signed[0..signed_at],
        asked,
        .v4,
        22,
        scratch,
    );
    defer signed_answer.deinit(t.allocator);
    try t.expectEqual(@as(u32, 0), signed_answer.records[0].ttl_s);
    try t.expectEqual(@as(u32, 0), signed_answer.ttl_s);
}

test "a record in the additional section is walked past, not collected" {
    // The `OPT` record a query advertised is answered with, and it sits in the
    // additional section. Walking it is the only way to know the message was
    // not cut short inside it — and none of it may reach `records`.
    const asked = "www.example.com.";
    var message: [512]u8 = undefined;
    const at = try frameAnswer(&message, asked, 31, &.{
        .{ .owner = asked, .kind = host_wire.type_a, .ttl_s = 60, .rdata = &v4_first },
    });
    wire.put16(message[0..], 10, 1);
    var tail = at;
    message[tail] = 0;
    wire.put16(message[0..], tail + 1, wire.type_opt);
    wire.put16(message[0..], tail + 3, wire.max_udp_payload);
    wire.put32(message[0..], tail + 5, 0);
    wire.put16(message[0..], tail + 9, 0);
    tail += wire.opt_length;
    var owner: [wire.max_name_length]u8 = undefined;
    var held: [wire.max_name_length]u8 = undefined;
    const scratch: Scratch = .{ .owner = &owner, .target = &held };

    const answer = try readAnswer(t.allocator, message[0..tail], asked, .v4, 31, scratch);
    defer answer.deinit(t.allocator);
    try t.expectEqual(@as(usize, 1), answer.records.len);
    try t.expectEqual(base_addr.IpAddress{ .v4 = v4_first }, answer.records[0].ip);

    // And the same message one octet short is a short message inside that
    // additional record, not a shorter answer.
    try t.expectError(error.ShortMessage, readAnswer(
        t.allocator,
        message[0 .. tail - 1],
        asked,
        .v4,
        31,
        scratch,
    ));
}
