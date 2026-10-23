//! Where this node can be reached, and whether that moved.
//!
//! `net/holepunch_run.zig` lists seven inputs to `holepunch.decide` and marks
//! four of them gaps. This file closes one of those four — "the socket's
//! interface addresses | gap: no interface enumeration" — and not the other
//! three. It gives the gate no connection (`transport/quic_bridge`'s table), no
//! stack answer (`qnt` is not in the vendored core) and no per-path traffic
//! status (there is no multipath layer). What it gives is the producer for the
//! one argument `observeReport` still asks its caller to find: the half of the
//! local candidate set that no probe round measures, because a round sees this
//! node from the outside and a relay reports only the address it saw.
//! `transport/socket.zig` cannot stand in for it — that file's own doc says a
//! wildcard bind's `getsockname` is `0.0.0.0` or `::`, which is where this node
//! is *bound*, and advertising a wildcard is worse than advertising nothing.
//!
//! # Snapshot comparison, not a platform event
//!
//! **The decision: the caller asks for the current state, and the two answers
//! are compared.** Not a netlink subscription, and not a thread. The reasons,
//! in the order they decided it:
//!
//! 1. **The event cannot answer the question.** The platform route is an
//!    `AF_NETLINK` / `SOCK_RAW` socket on `NETLINK_ROUTE`, bound to the
//!    multicast groups `RTMGRP_IPV4_IFADDR` and `RTMGRP_IPV6_IFADDR`, and it
//!    delivers `nlmsghdr` messages whose payload is an `ifaddrmsg` — an
//!    `RTM_NEWADDR` or `RTM_DELADDR` naming one address on one interface. That
//!    is not "what the interfaces look like now": the netmask, the flags and
//!    every other address are not in the message, so a handler still has to
//!    read. The event saves one syscall and costs a descriptor.
//! 2. **The descriptor is the problem, not the work.**
//!    `transport/socket.zig` records that a descriptor it opened is a
//!    descriptor no `Io` backend can poll, and that its waits are a
//!    hand-rolled `poll` with a hand-rolled stop. A netlink socket would be a
//!    *third* such wait with its own cancellation story, in a tree where
//!    `src/net/` has no threads at all and `holepunch.Planner` already owns the
//!    one loop that has a deadline.
//! 3. **Events are lossy and a re-read is the repair.** A socket bound after a
//!    change misses it, and an overflowing receive buffer delivers `ENOBUFS`
//!    with the state already stale. Snapshot comparison has no missed-event
//!    case at all: the answer is a function of two reads, and the caller can
//!    only be wrong if it failed to read.
//! 4. **One call.** `getifaddrs` is a libc function: one walk, no descriptor,
//!    no buffer to size, no cancellation.
//!
//! **What that costs**, stated rather than waved away. A change is noticed at
//! the next read, so the delay is the caller's own poll interval rather than
//! the kernel's edge. A read costs one syscall per interval, and the comparison
//! is at most `max_entries * max_entries` address comparisons per family, once
//! per read. Both are set by the constants below, and both are the smaller
//! half of what a probe round already spends.
//!
//! # Pure, and the one call that is not
//!
//! Everything except `read` is a function of a `Snapshot`, a `Change` or an
//! `Entry`, and every one of those is driven by a test that writes a snapshot
//! by hand. `read` is the whole impure surface: one libc call, one chain walk,
//! no clock, no allocator, no `io: std.Io`, and nothing kept between calls.
//! The kernel's flags are recorded in the `Entry` rather than applied inside
//! `read`, so a `Snapshot` is what the machine said and `reachableAt` is what
//! a peer may use — a snapshot that had already discarded the loopback flag
//! could not be asked the other question afterwards.
//!
//! `Change` holds both reads *and* the policy they were compared under, so
//! `moved` is the only way to ask and it cannot be asked under a policy other
//! than the one the caller is holding. Copying a `Change` copies both reads;
//! that is the cost of making it a value, and it is the arrangement
//! `net/holepunch_run.zig` already pays for in `holepunch_run_candidate.Set`.
//!
//! # Two spellings this file does not have
//!
//! The address a path is reached at is built by `base/ula.zig` and handed back
//! unchanged; `base/addr.zig` owns `IpAddress` and `SocketAddr`. The single
//! bridge to the kernel's layout is `ipFrom`, which reads a `sockaddr` and
//! produces an `IpAddress` — the read `transport/socket_addr.zig` makes
//! without the port, spelled here because `src/net/` does not import
//! `src/transport/`, the direction `net/holepunch_run.zig`'s module doc keeps.
//! The port is not in `read` either: an interface address has no port, the port
//! belongs to the socket, and `reachableAt` takes it.
//!
//! # What is pinned, and what is not
//!
//! Nothing here is a wire format, so there are no captured bytes to pin
//! against: `AGENTS.md` §2's "wire compatibility is a test" has nothing to bite
//! on. What this file depends on is two ABIs. `struct ifaddrs` is spelled once
//! below and is pinned by a test that fills a `sockaddr` by hand plus a test
//! that reads this machine; `getifaddrs` itself is pinned by the link. Both are
//! libc headers rather than a peer implementation, and neither has been
//! checked against a musl build — that needs a second toolchain and is not
//! claimed here.

const std = @import("std");

const addr = @import("../base/addr.zig");
const ula = @import("../base/ula.zig");

const c = std.c;
const linux = std.os.linux;

const HostBits = ula.HostBits;
const IpAddress = addr.IpAddress;
const SocketAddr = addr.SocketAddr;

/// `IFF_UP` from `<net/if.h>`, 0x1. `std` has no spelling of it.
const flag_up: u32 = 0x1;
/// `IFF_LOOPBACK` from `<net/if.h>`, 0x8. `std` has no spelling of it.
const flag_loopback: u32 = 0x8;

/// How many interface addresses one `Snapshot` holds.
///
/// `getifaddrs` returns one row per *address*, not per interface, so a host
/// with a VPN client, a container bridge and a virtualisation layer walks past
/// this. The ceiling is a refusal and not a truncation: a snapshot quietly
/// missing an address would publish a local set short of the truth, and a
/// caller that hit `error.TooManyEntries` can still decide what to do about
/// it.
pub const max_entries = 64;

/// `IFNAMSIZ` less the NUL: the most bytes of an interface name a kernel can
/// hand over. `nameFrom` is bounded by it, and the bound is the point.
pub const name_length = 15;

/// A `Snapshot` that grew past `max_entries`.
pub const SnapshotError = error{
    /// `add` was called one entry past the ceiling. The length is left where
    /// it was, so a caller that refuses here still holds the entries it did
    /// accept and nothing else.
    TooManyEntries,
};

/// What one read of this machine can refuse.
///
/// `SnapshotError` is the ceiling above, folded in rather than refused at: a
/// machine with more addresses than a `Snapshot` holds is a read that did not
/// finish. The other three are libc's, named so a caller can tell a host that
/// would not answer from one that has no addresses to give.
pub const ReadError = SnapshotError || error{
    /// `ENOMEM`: the kernel could not build the list at all.
    OutOfMemory,
    /// `EAFNOSUPPORT` or `EPROTONOSUPPORT`: no interface list on this kernel.
    Unsupported,
    /// Any other errno. `getifaddrs` answers -1 and sets `errno`, and a list
    /// that could not be produced is one fact with one name.
    Unavailable,
};

/// An interface's name, fixed width and self-terminating.
///
/// A `[15]u8` and a length rather than a slice: a `Snapshot` is a value and has
/// to be copyable into a caller's stack frame, so nothing in it borrows.
pub const Name = struct {
    bytes: [name_length]u8,
    len: u8,

    /// The name, without the padding after it.
    pub fn slice(self: *const Name) []const u8 {
        return self.bytes[0..self.len];
    }
};

/// One address on one interface, as the kernel described it.
///
/// The flags are recorded rather than applied — see the module doc's "Pure,
/// and the one call that is not".
pub const Entry = struct {
    /// Which interface carries it. `reachableAt` deliberately does not read
    /// this: a peer's address is not qualified by the interface behind it, and
    /// a bond or an anycast address has two of them.
    interface: Name,
    /// The address itself. `addr.IpAddress` carries the family, so nothing
    /// here has to.
    ip: IpAddress,
    /// `IFF_UP`. The kernel does not route an address off an interface that
    /// is down, so it is not an address a peer can be sent to whatever else
    /// the row says.
    up: bool,
    /// `IFF_LOOPBACK`. Reachable from this host and from nowhere else, which
    /// is a fact about the caller's peer and not about the machine.
    loopback: bool,
};

/// What the machine said, once.
///
/// A value with no allocator and no lifetime: the entries are inline and `len`
/// is the only authority on how many are live, so building one costs a store
/// per entry and never a memset of the whole array.
pub const Snapshot = struct {
    entries: [max_entries]Entry,
    len: usize,

    /// How many entries are live.
    pub fn count(self: *const Snapshot) usize {
        return self.len;
    }

    /// Forget every entry. The storage is left as it is; `len` is what makes
    /// it unread.
    pub fn clear(self: *Snapshot) void {
        self.len = 0;
    }

    /// The entry at `index`, or null when there is not one.
    pub fn at(self: *const Snapshot, index: usize) ?*const Entry {
        if (index >= self.len) return null;
        return &self.entries[index];
    }

    /// Record one entry, or refuse. Whole or nothing: `len` moves only after
    /// the entry is in place.
    pub fn add(self: *Snapshot, entry: Entry) SnapshotError!void {
        if (self.len == max_entries) return error.TooManyEntries;
        self.entries[self.len] = entry;
        self.len += 1;
    }
};

/// Where this node can be reached, per family.
///
/// `v4` and `v6` are interface addresses, on the port the socket bound.
/// `any_path` is not one of them: it is the synthetic address a peer sends to
/// before it has chosen a path, it is not routable, and nothing punches at
/// it. It is here because it is an address this node is reached at, and
/// `base/ula.zig` is the one place that builds it. `reachableAt` writes it;
/// `Change.moved` compares only `v4` and `v6` and leaves it unset, for the
/// reason that method's doc gives.
pub const Reach = struct {
    any_path: SocketAddr,
    v4: [max_entries]SocketAddr,
    v4_len: usize,
    v6: [max_entries]SocketAddr,
    v6_len: usize,

    /// The IPv4 addresses, in the order the kernel listed them.
    pub fn v4Addrs(self: *const Reach) []const SocketAddr {
        return self.v4[0..self.v4_len];
    }

    /// The IPv6 addresses, in the order the kernel listed them.
    pub fn v6Addrs(self: *const Reach) []const SocketAddr {
        return self.v6[0..self.v6_len];
    }
};

/// A `Reach` with nothing in it, for the two callers that fill its halves
/// separately. `any_path` stays undefined on purpose: `Change.moved` never
/// reads it, and handing back a value with a field nobody looked at is
/// cheaper than inventing one for it.
fn emptyReach() Reach {
    return .{
        .any_path = undefined,
        .v4 = undefined,
        .v4_len = 0,
        .v6 = undefined,
        .v6_len = 0,
    };
}

/// How much of the reachable set moved between two reads.
///
/// Counts, and not the addresses: a caller that needs the addresses diffs two
/// `Reach` values itself, which is what `net/holepunch_run.zig` already does
/// with `holepunch.hasNewAddress` over its own local buffer. Restating the
/// set difference here would be a second answer to a question one caller has
/// already answered.
pub const Move = struct {
    /// Addresses the later read has and the earlier one did not.
    appeared: usize,
    /// Addresses the earlier read has and the later one does not.
    retired: usize,

    /// Whether anything moved at all. This is the whole of the question a
    /// caller with a debounce asks; the two counts are for one that wants to
    /// know which way it moved.
    pub fn changed(self: Move) bool {
        return self.appeared != 0 or self.retired != 0;
    }
};

/// Two reads of one machine, and the policy they were compared under.
pub const Change = struct {
    /// The read the caller's last decision was made on.
    previous: Snapshot,
    /// The read this one is compared with, and the one the caller acts on.
    current: Snapshot,
    /// Whether the comparison counted `IFF_LOOPBACK` interfaces. Stored rather
    /// than taken as an argument to `moved`: comparing two reads under a
    /// policy other than the one the caller is holding is the mistake this
    /// type exists to make impossible.
    loopback: bool,

    /// What moved. The synthetic address is not compared: its host bits are
    /// allocated by the transport seam — `base/ula.zig`'s module doc says so —
    /// and a reallocation there is that seam's event, not a change in this
    /// machine's interfaces.
    pub fn moved(self: *const Change) Move {
        var before = emptyReach();
        var after = emptyReach();
        // The port is a placeholder and nothing below reads it, because an
        // address is compared as an `IpAddress`: a node that was reachable on
        // one port is not reachable on another without a decision of its own.
        interfaceAddrs(&self.previous, 0, self.loopback, &before);
        interfaceAddrs(&self.current, 0, self.loopback, &after);

        var counted: Move = .{ .appeared = 0, .retired = 0 };
        for (after.v4Addrs()) |socket| {
            if (!holds(before.v4Addrs(), socket.ip)) counted.appeared += 1;
        }
        for (after.v6Addrs()) |socket| {
            if (!holds(before.v6Addrs(), socket.ip)) counted.appeared += 1;
        }
        for (before.v4Addrs()) |socket| {
            if (!holds(after.v4Addrs(), socket.ip)) counted.retired += 1;
        }
        for (before.v6Addrs()) |socket| {
            if (!holds(after.v6Addrs(), socket.ip)) counted.retired += 1;
        }
        return counted;
    }
};

/// `struct ifaddrs` from `<ifaddrs.h>`, in libc's layout.
///
/// `std.c` has no `getifaddrs` at all, so this is the only copy of the chain
/// record in the tree and the two externs below are the only copies of the
/// names. `ifa_broadaddr` and `ifa_dstaddr` are a union of two pointers in the
/// header and neither of them is the address, so the field is named for the
/// union and is never read.
const Ifaddrs = extern struct {
    next: ?*Ifaddrs,
    name: ?[*:0]const u8,
    flags: c_uint,
    addr: ?*const c.sockaddr.storage,
    netmask: ?*const c.sockaddr.storage,
    either: ?*const c.sockaddr.storage,
    data: ?*anyopaque,
};

extern "c" fn getifaddrs(ifap: *?*Ifaddrs) c_int;
extern "c" fn freeifaddrs(ifa: ?*Ifaddrs) void;

/// Read this machine's interfaces into `snapshot`.
///
/// The only call here that leaves this process's own data, and the only one a
/// test cannot write a `Snapshot` for. It opens no descriptor, keeps nothing
/// between calls, and an artifact that calls it has to have been built with
/// `linkLibC()` — which is why this file's registration belongs in
/// `src/root.zig` and not in the socket-free `src/portable_test.zig`.
pub fn read(snapshot: *Snapshot) ReadError!void {
    var head: ?*Ifaddrs = null;
    const errno = c.errno(getifaddrs(&head));
    if (errno != .SUCCESS) {
        return switch (errno) {
            .NOMEM => error.OutOfMemory,
            .AFNOSUPPORT, .PROTONOSUPPORT => error.Unsupported,
            else => error.Unavailable,
        };
    }
    defer freeifaddrs(head);

    snapshot.clear();
    // A read that fails leaves nothing behind. A caller that mishandles
    // `error.TooManyEntries` and reads the snapshot anyway gets zero
    // addresses rather than a subset, which is the whole of what fail closed
    // means for a value that is about to be published.
    errdefer snapshot.clear();

    var row = head;
    while (row) |link| : (row = link.next) {
        // A row with no address is an interface the kernel knows about and
        // carries none. `reachableAt` is a function of addresses, so such a
        // row cannot appear in it and cannot move it.
        const raw = link.addr orelse continue;
        const ip = ipFrom(raw) orelse continue;
        const kernel_name = link.name orelse continue;

        try snapshot.add(.{
            .interface = nameFrom(kernel_name),
            .ip = ip,
            .up = link.flags & flag_up != 0,
            .loopback = link.flags & flag_loopback != 0,
        });
    }
}

/// The address out of a `sockaddr` `getifaddrs` filled in, or null for a
/// family this file does not speak.
///
/// `transport/socket_addr.zig`'s read without the port, spelled here because
/// `src/net/` does not import `src/transport/`. The IPv4 read is a bit cast
/// and not a byte swap, for the reason that file gives: `s_addr` is a word
/// whose four bytes *are* the address in wire order.
fn ipFrom(raw: *const c.sockaddr.storage) ?IpAddress {
    const header: *const c.sockaddr = @ptrCast(@alignCast(raw));
    return switch (header.family) {
        linux.AF.INET => word: {
            const narrow: *const c.sockaddr.in = @ptrCast(@alignCast(raw));
            break :word IpAddress{ .v4 = @bitCast(narrow.addr) };
        },
        linux.AF.INET6 => wide: {
            const broad: *const c.sockaddr.in6 = @ptrCast(@alignCast(raw));
            break :wide IpAddress{ .v6 = broad.addr };
        },
        else => null,
    };
}

/// An interface's name as at most `name_length` bytes.
///
/// The kernel cannot hand over a longer one — `IFNAMSIZ` is the width the name
/// was created in — so the bound below is that width and not a truncation, and
/// the length says how much of the buffer is the name.
fn nameFrom(raw: [*:0]const u8) Name {
    var result: Name = .{ .bytes = undefined, .len = 0 };
    for (0..name_length) |index| {
        const octet = raw[index];
        if (octet == 0) break;
        result.bytes[index] = octet;
        result.len += 1;
    }
    return result;
}

/// Where a peer may reach this node: the interface addresses, plus the
/// synthetic address a peer reaches it at before it has chosen a path.
///
/// `host` is the eight host bits the transport seam allocated for this node —
/// see `base/ula.zig`, which is where those bits come from and why they are an
/// argument here rather than a draw. `loopback` is a parameter and not a
/// constant because the answer is not a fact about this machine: a peer on
/// another host cannot use `127.0.0.1` and a peer on this one can, and this
/// file cannot tell which of them it is publishing for.
pub fn reachableAt(snapshot: *const Snapshot, host: HostBits, port: u16, loopback: bool) Reach {
    var reach = emptyReach();
    reach.any_path = ula.anyPathSocketAddr(host);
    interfaceAddrs(snapshot, port, loopback, &reach);
    return reach;
}

/// The interface addresses a peer may reach, into `reach`.
///
/// Order is the kernel's and no rule depends on it, for the reason
/// `net/holepunch_run.zig`'s module doc gives about the local candidate set.
/// Neither list can outgrow `max_entries`: a `Snapshot` holds at most
/// `max_entries` entries and each entry adds at most one address, so the
/// ceiling above `Reach` is inherited rather than a second one.
fn interfaceAddrs(snapshot: *const Snapshot, port: u16, loopback: bool, reach: *Reach) void {
    for (snapshot.entries[0..snapshot.len]) |link| {
        if (!link.up) continue;
        if (link.loopback and !loopback) continue;

        const socket: SocketAddr = .{ .ip = link.ip, .port = port };
        switch (link.ip) {
            .v4 => if (!holds(reach.v4Addrs(), link.ip)) {
                reach.v4[reach.v4_len] = socket;
                reach.v4_len += 1;
            },
            .v6 => if (!holds(reach.v6Addrs(), link.ip)) {
                reach.v6[reach.v6_len] = socket;
                reach.v6_len += 1;
            },
        }
    }
}

/// Whether `list` already carries `ip`. Two interfaces can hold one address — a
/// bond, or an anycast address on two links — and a peer reaches the same place
/// either way, so the second copy is not a second address.
fn holds(list: []const SocketAddr, ip: IpAddress) bool {
    for (list) |socket| {
        if (std.meta.eql(socket.ip, ip)) return true;
    }
    return false;
}

const t = std.testing;

/// A host value that is not all zero, so a golden comparison cannot be
/// satisfied by an address that happens to be zero.
const test_host: HostBits = .{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef };
/// The port the socket bound, so a test is about the interface addresses and
/// not about which port they happen to be paired with.
const test_port: u16 = 41234;

/// The documentation range, so a test that prints an address is never mistaken
/// for a routable host. The last octet is the argument.
fn v4(last: u8) IpAddress {
    return .{ .v4 = .{ 192, 0, 2, last } };
}

/// An IPv6 unique-local address, written in full rather than built, so a test
/// that flipped one of the eight leading zero octets fails.
fn v6() IpAddress {
    return .{ .v6 = .{ 0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } };
}

/// A kernel name, NUL-terminated, handed to the one function that copies one.
///
/// The buffer is `name_length` wide and not `text.len` wide, because `text` is
/// a runtime slice and an array's width is part of its type: a buffer sized
/// from it is only a type when `text` is comptime. That width is the bound
/// `nameFrom` already enforces — the same `IFNAMSIZ - 1` the read is handed —
/// so the two agree by construction, and a longer argument is cut at the one
/// length the kernel cannot produce rather than at a length chosen here.
fn ifaceName(text: []const u8) Name {
    const kept = @min(text.len, name_length);
    var buffer: [name_length + 1]u8 = @splat(0);
    @memcpy(buffer[0..kept], text[0..kept]);
    const sentinel: [*:0]const u8 = @ptrCast(&buffer);
    return nameFrom(sentinel);
}

fn onIface(interface: []const u8, ip: IpAddress, up: bool, loopback: bool) Entry {
    return .{ .interface = ifaceName(interface), .ip = ip, .up = up, .loopback = loopback };
}

/// A `Snapshot` carrying `entries` in the order they are written.
///
/// `add` refuses the sixty-fifth entry, and the refusal is propagated rather
/// than discarded: a fixture that grew past `max_entries` is a broken fixture
/// this file should be told about, and `Snapshot.add` already has a test that
/// walks the ceiling itself.
fn filled(entries: []const Entry) SnapshotError!Snapshot {
    var snapshot: Snapshot = undefined;
    snapshot.clear();
    for (entries) |one| try snapshot.add(one);
    return snapshot;
}

fn carries(reach: *const Reach, ip: IpAddress) bool {
    return holds(reach.v4Addrs(), ip) or holds(reach.v6Addrs(), ip);
}

test "an interface address is reachable and the families stay apart" {
    const snapshot = try filled(&.{
        onIface("eth0", v4(1), true, false),
        onIface("eth0", v6(), true, false),
        onIface("docker0", v4(2), true, false),
    });

    const reach = reachableAt(&snapshot, test_host, test_port, false);
    try t.expectEqual(@as(usize, 2), reach.v4Addrs().len);
    try t.expectEqual(@as(usize, 1), reach.v6Addrs().len);
    // Families do not leak into each other, and the order is the one the
    // snapshot was written in.
    try t.expect(std.meta.eql(v4(1), reach.v4Addrs()[0].ip));
    try t.expect(std.meta.eql(v4(2), reach.v4Addrs()[1].ip));
    try t.expect(std.meta.eql(v6(), reach.v6Addrs()[0].ip));
    // Every one of them is on the socket's port: an interface does not know a
    // port, and the caller pairs the addresses with the one it bound.
    for (reach.v4Addrs()) |socket| try t.expectEqual(test_port, socket.port);
    for (reach.v6Addrs()) |socket| try t.expectEqual(test_port, socket.port);
}

test "an interface that is down reaches nobody" {
    const up = try filled(&.{onIface("eth0", v4(1), true, false)});
    const down = try filled(&.{onIface("eth0", v4(1), false, false)});

    // The flags are recorded by `read` and applied here, so one bit the caller
    // never set is the whole difference between a published address and none.
    const before = reachableAt(&up, test_host, test_port, false);
    const after = reachableAt(&down, test_host, test_port, false);
    try t.expectEqual(@as(usize, 1), before.v4Addrs().len);
    try t.expectEqual(@as(usize, 0), after.v4Addrs().len);

    // And the two reads are a change: the address retired, and came back.
    const fell: Change = .{ .previous = up, .current = down, .loopback = false };
    const drop = fell.moved();
    try t.expect(drop.changed());
    try t.expectEqual(@as(usize, 1), drop.retired);
    try t.expectEqual(@as(usize, 0), drop.appeared);

    const rose: Change = .{ .previous = down, .current = up, .loopback = false };
    const rise = rose.moved();
    try t.expect(rise.changed());
    try t.expectEqual(@as(usize, 1), rise.appeared);
    try t.expectEqual(@as(usize, 0), rise.retired);
}

test "loopback is counted only when the caller says its peer is this host" {
    const snapshot = try filled(&.{
        onIface("eth0", v4(1), true, false),
        onIface("lo", v4(3), true, true),
    });

    const off = reachableAt(&snapshot, test_host, test_port, false);
    const on = reachableAt(&snapshot, test_host, test_port, true);
    try t.expectEqual(@as(usize, 1), off.v4Addrs().len);
    try t.expectEqual(@as(usize, 2), on.v4Addrs().len);
    // The one the wider set adds is the loopback address, and the address both
    // sets carry is unchanged: a policy that dropped a live interface would
    // show up as a shorter `off`, not as a different first entry.
    try t.expect(std.meta.eql(v4(1), off.v4Addrs()[0].ip));
    try t.expect(std.meta.eql(v4(3), on.v4Addrs()[1].ip));
}

test "one address on two interfaces is one address" {
    const bonded = try filled(&.{
        onIface("eth0", v4(1), true, false),
        onIface("bond0", v4(1), true, false),
        onIface("eth1", v4(1), true, false),
    });

    // A bond or an anycast address has three interfaces behind it here and a
    // peer reaches the same place either way. Three rows, one address.
    const reach = reachableAt(&bonded, test_host, test_port, false);
    try t.expectEqual(@as(usize, 1), reach.v4Addrs().len);

    // And a read in which the address moved to one of those interfaces is not
    // a change at all, which is what makes the dedup load-bearing rather than
    // a tidy-up.
    const onto_bond = try filled(&.{onIface("bond0", v4(1), true, false)});
    const change: Change = .{ .previous = bonded, .current = onto_bond, .loopback = false };
    try t.expect(!change.moved().changed());
}

test "the synthetic address is the one ula builds and ula reads it back" {
    const snapshot = try filled(&.{});

    const reach = reachableAt(&snapshot, test_host, test_port, false);
    // Built by `base/ula.zig` and not spelled here: the port is ula's and the
    // /64 is n0's. A second spelling of either would leave a node unreachable
    // through the map that every other path is reached at.
    try t.expect(std.meta.eql(ula.anyPathSocketAddr(test_host), reach.any_path));
    try t.expectEqual(ula.mapped_port, reach.any_path.port);
    // And it round-trips through ula's own classifier, which is the other
    // direction the map has to be right in.
    const want: ula.Classification = .{ .any_path = ula.ulaFor(.any_path, test_host) };
    try t.expect(std.meta.eql(want, ula.classify(reach.any_path)));
    // The synthetic address is not in either family list: it is not routable,
    // and a caller that punched at it would be punching at a private range.
    try t.expect(!carries(&reach, reach.any_path.ip));
}

test "two reads of an unchanged machine differ in nothing, in either order" {
    const first = try filled(&.{
        onIface("eth0", v4(1), true, false),
        onIface("eth1", v4(2), true, false),
    });
    const same = try filled(&.{
        onIface("eth0", v4(1), true, false),
        onIface("eth1", v4(2), true, false),
    });
    const reversed = try filled(&.{
        onIface("eth1", v4(2), true, false),
        onIface("eth0", v4(1), true, false),
    });

    // Order is the kernel's and no rule depends on it, so a read that came back
    // in another order is not a network change. Comparing index by index would
    // report one on every boot that enumerated a different way round.
    const identical: Change = .{ .previous = first, .current = same, .loopback = false };
    const shuffled: Change = .{ .previous = first, .current = reversed, .loopback = false };
    try t.expect(!identical.moved().changed());
    try t.expect(!shuffled.moved().changed());
}

test "the comparison follows the policy the change was stored with" {
    const with_loopback = try filled(&.{
        onIface("lo", v4(3), true, true),
        onIface("eth0", v4(1), true, false),
    });
    const without_loopback = try filled(&.{onIface("eth0", v4(1), true, false)});

    // The same two reads, one machine that lost nothing. Counted under a
    // policy that hides loopback — a peer on another host — the interface
    // that went is invisible in both reads, and nothing moved. Counted under
    // the policy that admits it — a peer on this host — that interface's
    // address was in the first read and not the second, and it retired.
    const narrow: Change = .{
        .previous = with_loopback,
        .current = without_loopback,
        .loopback = false,
    };
    const wide: Change = .{
        .previous = with_loopback,
        .current = without_loopback,
        .loopback = true,
    };
    const quiet = narrow.moved();
    try t.expect(!quiet.changed());
    try t.expectEqual(@as(usize, 0), quiet.retired);
    try t.expectEqual(@as(usize, 0), quiet.appeared);

    const drop = wide.moved();
    try t.expect(drop.changed());
    try t.expectEqual(@as(usize, 1), drop.retired);
    try t.expectEqual(@as(usize, 0), drop.appeared);
}

test "a change reports what appeared and what retired" {
    const before = try filled(&.{
        onIface("eth0", v4(1), true, false),
        onIface("eth1", v4(2), true, false),
    });
    const after = try filled(&.{
        onIface("eth1", v4(2), true, false),
        onIface("eth2", v4(9), true, false),
    });

    // One address went and a different one came: a swap. Reporting it as
    // neither would need the two counts compared to each other by the caller.
    const change: Change = .{ .previous = before, .current = after, .loopback = false };
    const move = change.moved();
    try t.expect(move.changed());
    try t.expectEqual(@as(usize, 1), move.appeared);
    try t.expectEqual(@as(usize, 1), move.retired);

    // And `current` is the read the caller acts on, not the one it came from.
    const reach = reachableAt(&change.current, test_host, test_port, change.loopback);
    try t.expect(std.meta.eql(v4(9), reach.v4Addrs()[1].ip));
}

test "a snapshot past the ceiling refuses rather than truncating" {
    var snapshot: Snapshot = undefined;
    snapshot.clear();
    for (1..max_entries + 1) |index| {
        try snapshot.add(onIface("eth0", v4(@intCast(index)), true, false));
    }
    try t.expectEqual(max_entries, snapshot.count());

    // A snapshot quietly missing an address would publish a local set short of
    // the truth, so the ceiling is a refusal and the entries already in are
    // still all there.
    try t.expectError(error.TooManyEntries, snapshot.add(onIface("eth1", v4(200), true, false)));
    try t.expectEqual(max_entries, snapshot.count());
    try t.expect(std.meta.eql(v4(1), snapshot.at(0).?.ip));
    try t.expect(snapshot.at(max_entries) == null);
}

test "a kernel address word is the address, not its byte swap" {
    var raw: c.sockaddr.storage = undefined;
    const narrow: *c.sockaddr.in = @ptrCast(&raw);
    narrow.* = .{
        .family = linux.AF.INET,
        .port = std.mem.nativeToBig(u16, test_port),
        .addr = @bitCast([4]u8{ 192, 0, 2, 7 }),
    };
    // Written out. A byte swap in `ipFrom` where the bit cast belongs turns
    // this into `7.2.0.192`, which is routable, wrong, and silently so.
    try t.expect(std.meta.eql(IpAddress{ .v4 = .{ 192, 0, 2, 7 } }, ipFrom(&raw).?));

    const broad: *c.sockaddr.in6 = @ptrCast(&raw);
    broad.* = .{
        .family = linux.AF.INET6,
        .port = 0,
        .flowinfo = 0,
        .addr = .{ 0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 },
        .scope_id = 0,
    };
    try t.expect(std.meta.eql(v6(), ipFrom(&raw).?));

    // A family this file does not speak is not an address a peer can reach,
    // and it is skipped rather than read as one.
    const other: *c.sockaddr = @ptrCast(&raw);
    other.family = linux.AF.UNIX;
    try t.expect(ipFrom(&raw) == null);
}

test "an interface name is at most fifteen bytes" {
    try t.expectEqualStrings("eth0", ifaceName("eth0").slice());
    // The width is `IFNAMSIZ - 1`, so this name fills it exactly and a copy
    // bounded one byte short would lose the last one.
    try t.expectEqualStrings("abcdefghijklmno", ifaceName("abcdefghijklmno").slice());
    // And the bound holds for a name the kernel cannot produce. Nothing writes
    // sixteen bytes, so this pins the width rather than a machine.
    try t.expectEqual(name_length, ifaceName("abcdefghijklmnopqrst").len);
}

// The only test here that needs this machine's real interface list, because it
// is `read`'s own test and `read` is the one function in this file a test
// cannot write a `Snapshot` for. It asserts invariants that hold for any
// machine rather than any machine's addresses: a test that named an address
// would be a test about the host it ran on. What it does pin is the whole
// chain — the extern declaration, the chain walk, the flags, the name copy and
// the sockaddr read — because a wrong `struct ifaddrs` layout produces a
// garbage family and a wrong `s_addr` conversion produces swapped octets, and
// neither shows up anywhere else.
test "a read of this machine reaches every interface address that is up" {
    var snapshot: Snapshot = undefined;
    snapshot.clear();
    try read(&snapshot);
    // A host with no interface addresses at all is not a host this file can
    // serve, and saying so beats passing over an empty read.
    try t.expect(snapshot.count() >= 1);

    const on = reachableAt(&snapshot, test_host, test_port, true);
    const off = reachableAt(&snapshot, test_host, test_port, false);
    for (snapshot.entries[0..snapshot.count()]) |*link| {
        try t.expect(link.interface.slice().len > 0);
        try t.expect(link.interface.len <= name_length);
        if (!link.up) continue;
        try t.expect(carries(&on, link.ip));
        // A loopback address reaches a peer on this host and no other, so it
        // is the one entry the narrower set is allowed to be missing.
        if (link.loopback) continue;
        try t.expect(carries(&off, link.ip));
    }
    // Counting loopback only ever adds.
    try t.expect(off.v4Addrs().len <= on.v4Addrs().len);
    try t.expect(off.v6Addrs().len <= on.v6Addrs().len);
}
