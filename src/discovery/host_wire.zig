//! The RFC 1035 vocabulary a host lookup needs and a TXT lookup does not: the
//! three record types neither `lookup_wire.zig` nor `lookup_answer.zig` names,
//! where each field of a resource record's fixed block sits, what a `TTL` is
//! worth after RFC 2181 §5.2, and the rule that an address record's `RDATA`
//! is exactly as wide as its family.
//!
//! Nothing here frames a message or reads one. `host_answer.zig` walks an
//! answer with these names and with `lookup_answer.readHeader`,
//! `lookup_answer.recordBody` and `lookup_answer.skipRecord` — the header
//! rule, the `RDLENGTH` bounds and the walk-past-a-record all live there and
//! are called there, not copied. `host_io.zig` is the facade over both.
//!
//! # Why a second wire module at all
//!
//! `lookup_wire.zig` holds what a lookup and its answer agree on, and adding
//! `A`, `AAAA` and `CNAME` to it would put a host question's vocabulary in the
//! module every TXT lookup reaches. The direction of the dependency is the
//! reason and not tidiness: `lookup_wire.zig` is settled and owned, and a new
//! name in it is a change to a file a caller outside `src/discovery/` reads.
//! This one depends on `lookup_wire.zig` and adds to it, and nothing under
//! `src/discovery/` has to change to take it.
//!
//! # The field offsets, and who reads them
//!
//! Every offset below is relative to a record's fixed block and is named once,
//! here, so a decoder that needs `TTL` reads `host_wire.ttl_at` and not `+ 4`.
//! `lookup_answer.walkRecord` still spells its own two offsets against its own
//! private helper, which is a file this project owns and did not widen; the
//! point of naming them here is that no *new* code spells them a second time.

const std = @import("std");

const base_addr = @import("../base/addr.zig");

const wire = @import("lookup_wire.zig");

/// `TYPE` for an IPv4 host address. RFC 1035 §3.2.2, `A 1`.
pub const type_a: u16 = 1;

/// `TYPE` for a canonical name, the alias one owner points at. RFC 1035
/// §3.2.3, `CNAME 5`.
pub const type_cname: u16 = 5;

/// `TYPE` for an IPv6 host address. RFC 1035 §3.2.5, `AAAA 28`.
pub const type_aaaa: u16 = 28;

/// `TYPE`, in the block RFC 1035 §4.1.3 puts after every owner name. Every
/// offset below is relative to that block and `fixed_length` is the block's
/// own width, which is also where `RDATA` starts because `RDLENGTH` is its
/// last field.
pub const type_at: usize = 0;
/// `CLASS`. RFC 1035 §4.1.3.
pub const class_at: usize = 2;
/// `TTL`. RFC 1035 §4.1.3.
pub const ttl_at: usize = 4;
/// `RDLENGTH`. RFC 1035 §4.1.3.
pub const rdlength_at: usize = 8;
/// The whole fixed block: `TYPE`, `CLASS`, `TTL`, `RDLENGTH`.
pub const fixed_length: usize = 10;

/// The top bit of a `TTL`, which RFC 2181 §5.2 gives a meaning of its own.
const ttl_sign_bit: u32 = 1 << 31;

/// `RDLENGTH` is two octets, so this is the widest `RDATA` a record can carry.
pub const max_rdata_length: usize = std.math.maxInt(u16);

comptime {
    // `fixed_length` is the block's own width and `rdlength_at + 2` is the
    // same number written the other way round; a decoder that sized one from
    // the other would silently skip a field if they ever disagreed.
    if (fixed_length != rdlength_at + 2) @compileError("the record block and RDLENGTH disagree");
    if (ttl_at != type_at + 2 + 2) @compileError("the record block's field order is not read here");
    if (fixed_length > max_rdata_length) @compileError("a record cannot outgrow its RDLENGTH");
}

/// Why an address record is refused before it becomes an address.
pub const Error = error{
    /// `RDLENGTH` was not the width the family's `TYPE` requires: four octets
    /// for `A`, sixteen for `AAAA`.
    ///
    /// A refusal and not a truncation, and the reason is that a length this
    /// module accepts is a length the kernel's own resolver would refuse: a
    /// four-octet `RDATA` under `TYPE 28` is not an address with a byte
    /// missing, it is a record whose type and its contents disagree, and
    /// reading it as an address invents one.
    BadRecordLength,
};

/// Which address family a question was asked for.
///
/// The value and not a `base_addr.IpAddress`, because a question has a
/// `QTYPE` long before it has an answer: the family has to be nameable with no
/// address in hand. `Family.of` is the way back once one is.
pub const Family = enum {
    /// `IN A`, four octets.
    v4,
    /// `IN AAAA`, sixteen octets.
    v6,

    /// The `TYPE` — and the `QTYPE` — an address of this family is asked for
    /// and answered with.
    pub fn recordType(self: Family) u16 {
        return switch (self) {
            .v4 => type_a,
            .v6 => type_aaaa,
        };
    }

    /// How many octets one address record of this family carries in `RDATA`,
    /// which is `host_wire.Error.BadRecordLength` to disagree with.
    pub fn rdataLength(self: Family) u16 {
        return switch (self) {
            .v4 => 4,
            .v6 => 16,
        };
    }

    /// The address `rdata` carries, or `error.BadRecordLength` when it is not
    /// this family's width. The check is here rather than at each call site so
    /// that no caller can read four octets out of a record that says sixteen.
    pub fn ip(self: Family, rdata: []const u8) Error!base_addr.IpAddress {
        if (rdata.len != self.rdataLength()) return error.BadRecordLength;
        return switch (self) {
            .v4 => .{ .v4 = rdata[0..4].* },
            .v6 => .{ .v6 = rdata[0..16].* },
        };
    }

    /// The family `address` belongs to.
    pub fn of(address: base_addr.IpAddress) Family {
        return switch (address) {
            .v4 => .v4,
            .v6 => .v6,
        };
    }
};

/// The `TTL` of the record whose `TYPE` is at `at`, in whole seconds.
///
/// RFC 2181 §5.2: "Implementations SHOULD treat TTL values received with the
/// top bit set as if the entire value received was zero." The **whole field**,
/// then, and not the low bits with the top one cleared — `0x8000_003c` is zero
/// and not sixty seconds, and reading it the other way is how a cache entry
/// dated 2045 gets invented out of a value that meant "do not cache this".
pub fn ttlSeconds(message: []const u8, at: usize) wire.WireError!u32 {
    if (at + fixed_length > message.len) return error.ShortMessage;
    const field = wire.be32(message, at + ttl_at);
    if (field & ttl_sign_bit != 0) return 0;
    return field;
}

const t = std.testing;

/// One record's fixed block and its `RDATA`, written field by field: what an
/// `A` record looks like on the wire and nothing else.
fn addressRecord(kind: u16, ttl: u32, rdata: []const u8) [fixed_length + 16]u8 {
    var record = [_]u8{0} ** (fixed_length + 16);
    wire.put16(&record, type_at, kind);
    wire.put16(&record, class_at, wire.class_in);
    wire.put32(&record, ttl_at, ttl);
    // Test callers pass four-byte RDATA; ZBC cannot prove this helper's input bound.
    // zbc-disable-next-line: index-type-narrowing-wraparound
    wire.put16(&record, rdlength_at, @intCast(rdata.len));
    @memcpy(record[fixed_length..][0..rdata.len], rdata);
    return record;
}

test "an address record is the block read at the offsets named here" {
    const record = addressRecord(type_a, 300, &.{ 192, 0, 2, 1 });
    try t.expectEqual(@as(u32, 300), try ttlSeconds(&record, 0));
    // The four octets sit immediately after the ten the fields take, and that
    // is the layout `ttlSeconds` indexes into and the one `Family.ip` is
    // handed, so a byte moved in either function shows up here.
    try t.expectEqual(
        base_addr.IpAddress{ .v4 = .{ 192, 0, 2, 1 } },
        try Family.v4.ip(record[fixed_length..][0..4]),
    );
    try t.expectEqual(@as(u16, type_a), wire.be16(&record, type_at));
    try t.expectEqual(@as(u16, wire.class_in), wire.be16(&record, class_at));
    try t.expectEqual(@as(u16, 4), wire.be16(&record, rdlength_at));
}

test "a TTL with the top bit set is zero, and the whole field goes" {
    const seconds: u32 = 60;
    // RFC 2181 §5.2's whole field and not its low bits: the sixty is gone as
    // surely as the sign, which is the difference between "cache this for a
    // minute" and "do not cache this at all".
    const signed_zero = addressRecord(type_a, ttl_sign_bit | seconds, &.{ 192, 0, 2, 1 });
    try t.expectEqual(@as(u32, 0), try ttlSeconds(&signed_zero, 0));
    // The field is still four octets on the wire. The rule is about what the
    // number means, not about how wide the record is, and a decoder that
    // dropped the octet would disagree with every server about the layout.
    try t.expectEqual(@as(u32, ttl_sign_bit | seconds), wire.be32(&signed_zero, ttl_at));

    // The top bit alone is the boundary: it is zero, one below it is the
    // largest TTL RFC 2181 §5.2 leaves alone, and an ordinary value is itself.
    const bare = addressRecord(type_a, ttl_sign_bit, &.{ 192, 0, 2, 1 });
    try t.expectEqual(@as(u32, 0), try ttlSeconds(&bare, 0));
    const largest = addressRecord(type_a, ttl_sign_bit - 1, &.{ 192, 0, 2, 1 });
    try t.expectEqual(@as(u32, 2147483647), try ttlSeconds(&largest, 0));
    const ordinary = addressRecord(type_a, seconds, &.{ 192, 0, 2, 1 });
    try t.expectEqual(seconds, try ttlSeconds(&ordinary, 0));

    // A `TTL` field that is not even there is a short message and not a
    // zero-second TTL, which is the same reason `rdataLength` is a refusal.
    try t.expectError(error.ShortMessage, ttlSeconds(ordinary[0 .. ttl_at + 3], 0));
}

test "a record's RDATA is exactly its family's width" {
    const four: [4]u8 = .{ 203, 0, 113, 9 };
    const sixteen: [16]u8 = .{
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
        0,    0,    0,    0,    0, 0, 0, 1,
    };
    try t.expectEqual(base_addr.IpAddress{ .v4 = four }, try Family.v4.ip(&four));
    try t.expectEqual(base_addr.IpAddress{ .v6 = sixteen }, try Family.v6.ip(&sixteen));
    try t.expectEqual(Family.v4, Family.of(base_addr.IpAddress{ .v4 = four }));
    try t.expectEqual(Family.v6, Family.of(base_addr.IpAddress{ .v6 = sixteen }));
    try t.expectEqual(@as(u16, type_a), Family.v4.recordType());
    try t.expectEqual(@as(u16, type_aaaa), Family.v6.recordType());
    try t.expectEqual(@as(u16, 4), Family.v4.rdataLength());
    try t.expectEqual(@as(u16, 16), Family.v6.rdataLength());

    // The refusal the widths exist for: a `TYPE 28` record carrying fifteen
    // octets is a record that disagrees with itself, not an address with a
    // byte missing, and `TYPE 1` carrying sixteen is the same disagreement
    // the other way round.
    try t.expectError(error.BadRecordLength, Family.v6.ip(four[0..3]));
    try t.expectError(error.BadRecordLength, Family.v4.ip(sixteen[0..15]));
    try t.expectError(error.BadRecordLength, Family.v4.ip(&.{}));
    // A `RDLENGTH` is two octets, which is the outer bound on all of this.
    try t.expectEqual(@as(usize, 65535), max_rdata_length);
}

test "the block's own width is the width `RDLENGTH` is read at" {
    // `fixed_length` and `rdlength_at` are the same layout read two ways, and
    // the comptime block above refuses the file if they ever disagree. This
    // test is the runtime half of that claim: an `RDATA` that begins at
    // `fixed_length` and a `RDLENGTH` read at `rdlength_at` have to be the
    // same four octets, or `ttlSeconds` would be reading the wrong field.
    const record = addressRecord(type_a, 120, &.{ 198, 51, 100, 7 });
    const length = wire.be16(&record, rdlength_at);
    const address = record[fixed_length..][0..length];
    try t.expectEqualSlices(u8, &[_]u8{ 198, 51, 100, 7 }, address);
    try t.expectEqual(@as(u32, 120), try ttlSeconds(&record, type_at));
}
