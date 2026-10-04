//! The bytes a socket's control messages are made of, and nothing else.
//!
//! This is the pure half of what `transport/socket.zig` hands a kernel: the
//! `CMSG_*` arithmetic, the traffic-class and `UDP_GRO` codecs, the one value
//! read out of a received blob, and the two directions of a socket address.
//! There is no descriptor, no `Io`, no allocator and no syscall here.
//!
//! # Where the decoder is driven from
//!
//! `readCmsg` is the narrowest decoder in the tree, and
//! `test/ancillary_fuzz.zig` is a bounded Smith property over it: that root
//! plans blobs out of the fuzzer's bytes and asks this decoder, about every
//! prefix of every one of them, for exactly the codepoint, stride and
//! truncation the ABI says is owed. It needs four names from here —
//! `readCmsg`, `CmsgRead`, `cmsgLen` and `cmsgAlign` — and everything else it
//! needs it reaches through `batch.zig`. It is a separate root rather than a
//! test here because a fuzz artifact is built at its own optimize mode (the
//! `-ffuzz` rebuild cannot meet the toolchain's error path in Debug,
//! ziglang/zig#36326), and because a property with a plan and a corpus beside
//! it is not production code.
//!
//! # Why `std.c` and not `std.Io.net`
//!
//! `docs/DECISIONS/0002-async-substrate.md` names both gaps in the stock
//! surface, and this file is the answer to the first of them:
//!
//! 1. **Control messages.** `std.Io.net` has `OutgoingMessage.control` and
//!    `IncomingMessage.control` in the type, and `Io.Threaded` lowers a
//!    receive to one `recvmsg` with that buffer. Its send path goes through
//!    `netSend`, which folds `errno` into a dozen named answers, and a socket
//!    that cannot tell `EMSGSIZE` from `EAGAIN` has backpressure it invented.
//!    `std.posix` has no `sendmsg` at all. `std.c` has both, and the errno is
//!    the caller's to read.
//! 2. **Socket options.** `BindOptions` carries `ip6_only` and
//!    `allow_broadcast` and nothing else, and `SO_REUSEPORT` only counts when
//!    it is set *before* the bind. A socket created through `netBindIp` cannot
//!    be given one, so the descriptor is created in `socket_control.zig` and no
//!    `Io` ever learns it.
//!
//! Everything below is the layout work, which is arithmetic on bytes, and
//! every test here reaches a claim about the kernel's ABI without leaving a
//! syscall behind.
//!
//! # Linux, and only Linux
//!
//! `batch.zig` names its option numbers out of `std.os.linux` and says a
//! platform without them answers `Capability.none`. The same is true here:
//! `SOL_UDP` has no `std` spelling at all and the whole control-message path
//! below is written against the Linux `cmsghdr`. This is ozai's socket, not
//! the vendored core's — `test/vendored_invariants.zig` guards `vendor/`,
//! where neither a socket nor a libc is allowed.

const std = @import("std");
const builtin = @import("builtin");
const batch = @import("batch.zig");
const base_addr = @import("../base/addr.zig");

const c = std.c;
const linux = std.os.linux;

/// `batch.linux`, under the name this file uses for it. The option numbers
/// are named once — in `batch.zig`, with the std line beside each — so that a
/// search for `103` finds that block and not a literal in the middle of a
/// decode.
const names = batch.linux;

const socklen_t = c.socklen_t;

/// Control integers use native byte order. `UDP_SEGMENT` sends a `u16`,
/// `UDP_GRO` returns an integer, and traffic classes arrive as a byte or an integer.
const endian = builtin.cpu.arch.endian();

// 80 display columns; the rule counts UTF-8 bytes, three per box character.
// ziglint-ignore: Z024
// ────────────────────────────────────────────────────── control-message layout

/// The boundary a control message is padded to, and the one number in this
/// file that decides where a message ends and the next one begins.
///
/// It is `sizeof(size_t)` and not the alignment of a `cmsghdr`, and on musl
/// those are two different numbers: `CMSG_ALIGN` in musl's `sys/socket.h`
/// and in the kernel's `include/linux/socket.h` both round a length up to a
/// word, while glibc declares `cmsg_len` a `size_t`, so its struct is
/// eight-byte aligned and the two agree there. musl aims at POSIX and
/// declares the same field a `socklen_t` with four bytes of padding above it,
/// which makes its struct four-byte aligned and twelve or sixteen bytes wide
/// depending on the width of a word, while `CMSG_ALIGN` still rounds to
/// whatever `size_t` is — `std/c.zig` says as much over `posix_cmsghdr`.
///
/// Rounding by the struct instead is not cosmetic. The buffer below is ten
/// bytes short of the two messages a coalesced read carries, and the kernel
/// answers a control buffer it cannot fill with `MSG_CTRUNC`; a send's second
/// message lands four bytes before the offset the kernel's own `CMSG_NXTHDR`
/// walks to, so what it reads there is padding rather than a header.
const cmsg_boundary: usize = @sizeOf(usize);

/// `CMSG_DATA`: where a header's value begins, which is the header rounded up
/// rather than the header itself.
///
/// It is named once because the write path and the read path need the same
/// number, and two spellings of an offset is two chances to disagree about
/// where a value is.
const value_at: usize = cmsgAlign(@sizeOf(c.cmsghdr));

/// `CMSG_ALIGN`: a length rounded up to that boundary. The 0.16 std tree
/// carries no `CMSG_*` macro — a search for `CMSG_LEN` across `lib/std`
/// finds nothing — so the three arithmetic facts are here once and every
/// message below is written and read through them.
pub fn cmsgAlign(length: usize) usize {
    return std.mem.alignForward(usize, length, cmsg_boundary);
}

/// `CMSG_LEN`: the aligned header plus the value, and nothing else. The
/// length a message reports about itself, and the length the kernel checks
/// a value against — a message that reports the padded length instead is a
/// message whose value is two bytes wider than the one that was written.
pub fn cmsgLen(width: usize) usize {
    return value_at + width;
}

/// `CMSG_SPACE`: `cmsgLen` rounded up, which is what a buffer must hold for
/// this message to be followed by another one.
pub fn cmsgSpace(width: usize) usize {
    return cmsgAlign(cmsgLen(width));
}

/// Room for a traffic class and either UDP_SEGMENT's u16 or UDP_GRO's int.
/// The receive integer is wider, so it bounds the shared control buffer.
pub const control_size: usize = cmsgSpace(batch.tos_width) + cmsgSpace(@sizeOf(c_int));

/// The width `msg_controllen` is spelled in: POSIX says `socklen_t` and musl
/// says POSIX, while glibc follows the kernel and spells it a `size_t`.
pub const ControlExtent = @FieldType(c.msghdr_const, "controllen");

comptime {
    // The bound every narrowing of a control length is taken against. No
    // buffer this module hands to a syscall is longer than `control_size` —
    // `writeCmsg` cannot return more of a `ControlBuffer` than it holds —
    // so this is what proves a send's own narrowing cannot lose a bit.
    std.debug.assert(control_size <= std.math.maxInt(ControlExtent));
    // `readCmsg` slices a value region out of a message whose length it has
    // already accepted, and the acceptance test compares against `@sizeOf`
    // while the slice starts at `value_at`. Those are equal on every ABI
    // rather than equal by accident on the ones this happens to have been run
    // on: `std.os.linux.cmsghdr` leads with a `usize`, so its alignment is at
    // least `cmsg_boundary` and its size is a whole number of boundaries, and
    // `alignForward` returns a value that is already aligned unchanged. So the
    // accepted length is never below the slice's start, on a 32-bit target
    // with a twelve-byte header and a four-byte boundary as much as on a
    // 64-bit one with sixteen and eight.
    std.debug.assert(value_at == @sizeOf(c.cmsghdr));
}

/// The bytes a `sendmsg` writes its control messages into, and the bytes a
/// `recvmsg` reads them back out of.
///
/// One traffic-class message and one `UDP_GRO` message is every message a
/// socket asked for: `IP_PKTINFO` and `SO_TIMESTAMP` are not set, so the
/// kernel has no other reason to send one. The struct carries its own
/// alignment, because the kernel writes these headers at `cmsg_boundary` and
/// a bare `[]u8` does not promise it.
pub const ControlBuffer = extern struct {
    bytes: [control_size]u8 align(cmsg_boundary),
};

/// Why a set of control messages would not fit.
pub const ControlError = error{
    /// The buffer cannot hold what it was handed. A control message that
    /// stops halfway is a different message, not a shorter one: the kernel
    /// reads `cmsg_len` bytes whatever the buffer holds.
    BufferTooSmall,
    /// A field the ABI's own type cannot hold: a header's length past what
    /// `socklen_t` spells, a level or an option past what an `int` spells, or
    /// a control buffer longer than `msg_controllen` can say. The truncated
    /// field would be a header pointing at bytes that are not there, so it is
    /// refused instead of written.
    FieldTooWide,
};

/// Write `messages` into `out` in the order given, and hand back the part of
/// it that was used.
///
/// The order is `batch.cmsg`'s — traffic class, then segment size — and it is
/// the caller's list that fixes it: the seam above decides what a send
/// carries and this function only lays it out.
pub fn writeCmsg(messages: []const batch.Cmsg, out: *ControlBuffer) ControlError![]const u8 {
    var used: usize = 0;
    for (messages) |message| {
        const width: usize = message.value.width();
        const space = cmsgSpace(width);
        if (used + space > out.bytes.len) return error.BufferTooSmall;
        const at = out.bytes[used..];
        try putHeader(at, .{
            .length = cmsgLen(width),
            .level = message.level,
            .kind = message.kind,
        });
        putValue(at, message.value);
        used += space;
    }
    return out.bytes[0..used];
}

/// What one blob of received control data said, in the model's vocabulary.
pub const CmsgRead = struct {
    /// The `UDP_GRO` stride, or null when no such message arrived. A read
    /// with no stride is uncoalesced, and a coalesced read of exactly one
    /// datagram carries the buffer's own length — the same value, which is
    /// what `batch.Recv.init` treats as the same read.
    stride: ?usize,
    /// The codepoint the traffic class carried, or null for a datagram that
    /// carried none. Zero is not-ECT and not a missing message, which is why
    /// this is a value and not the absence of one.
    ecn: ?batch.Ecn,
    /// Whether the blob ended inside a message. This is the one way a
    /// coalesced read can arrive looking uncoalesced, and a caller that cannot
    /// tell has a buffer it must not read as one datagram.
    truncated: bool,
};

/// Read the `UDP_GRO` stride and the traffic class out of a received blob and
/// ignore every other message in it.
///
/// A message this seam did not ask for is skipped rather than ended on: a
/// socket may carry options that add messages, and stopping at the first one
/// nobody recognises would lose the stride that came after it.
pub fn readCmsg(blob: []const u8) CmsgRead {
    var read: CmsgRead = .{ .stride = null, .ecn = null, .truncated = false };
    var at: usize = 0;
    while (at < blob.len) {
        const rest = blob[at..];
        if (rest.len < @sizeOf(c.cmsghdr)) {
            read.truncated = rest.len != 0;
            break;
        }
        const length: usize = getLength(rest);
        if (length < @sizeOf(c.cmsghdr) or length > rest.len) {
            read.truncated = true;
            break;
        }
        takeValue(rest, length, &read);
        at += cmsgAlign(length);
    }
    return read;
}

const Header = struct {
    length: usize,
    level: u32,
    kind: u32,
};

// A header is read and written as bytes, never through a `*cmsghdr`. The
// buffer a caller supplies is a `[]u8` and carries no alignment, so a pointer
// to a header inside it would be a claim the type cannot make; the offsets come
// from the struct itself, which is what makes the ABIs that spell `cmsg_len` as
// a `socklen_t` work without a second spelling of any of this.

fn putHeader(at: []u8, header: Header) ControlError!void {
    // Three narrowings, none of them proved anywhere above: the C header
    // spells `cmsg_len` a `socklen_t` under musl and a `size_t` under glibc,
    // spells its level and type an `int`, and a bare `@intCast` panics in
    // Debug on a value that does not fit rather than writing a defined one.
    // Each is narrowed here, where the bound is, and a header the ABI cannot
    // spell is refused rather than written with a field that describes
    // something else.
    const ControlLength = @FieldType(c.cmsghdr, "len");
    const length = std.math.cast(ControlLength, header.length) orelse return error.FieldTooWide;
    const level = std.math.cast(c_int, header.level) orelse return error.FieldTooWide;
    const kind = std.math.cast(c_int, header.kind) orelse return error.FieldTooWide;
    // The word that goes out is the kernel's and not the C struct's. `struct
    // cmsghdr` in `include/linux/socket.h` spells `cmsg_len` a
    // `__kernel_size_t` at offset zero of a sixteen-byte header, and
    // `__sys_sendmsg` copies that whole word out of this buffer before
    // `sock_cmsg_send` and `udp_cmsg_send` read it back and check it against
    // `CMSG_OK` and `CMSG_LEN(sizeof(u16))`. musl's own header spells the
    // same field a `socklen_t` and puts four bytes of padding around it —
    // above the field on a little-endian host, below it on a big-endian one —
    // inside that same word. So the word is zeroed and the field written into
    // the middle of it: writing the field alone would hand the kernel a
    // length with whatever the stack held inside it, and whether a send is
    // refused at all would come to depend on that.
    const len_at = @offsetOf(c.cmsghdr, "len");
    const control_width = @sizeOf(ControlLength);
    @memset(at[0..@sizeOf(usize)], 0);
    std.mem.writeInt(ControlLength, at[len_at..][0..control_width], length, endian);
    const word = @sizeOf(c_int);
    const level_at = @offsetOf(c.cmsghdr, "level");
    const kind_at = @offsetOf(c.cmsghdr, "type");
    std.mem.writeInt(c_int, at[level_at..][0..word], level, endian);
    std.mem.writeInt(c_int, at[kind_at..][0..word], kind, endian);
}

/// The length a header reports, read in the width the kernel wrote it.
///
/// One word at offset zero of the header, which is where the kernel's own
/// `__kernel_size_t` is and which therefore holds musl's `socklen_t` and its
/// padding together. The C struct's field offset would be the same number on
/// a little-endian host and would read into the level that follows the length
/// on a big-endian one, so it is the word and not the field that is read.
fn getLength(at: []const u8) usize {
    return std.mem.readInt(usize, at[0..@sizeOf(usize)], endian);
}

/// The level or the option a header names, which are an `int` on every ABI
/// here — `getLength` is the one field that is not the same width twice.
fn getHeader(comptime field: []const u8, at: []const u8) u32 {
    const offset = @offsetOf(c.cmsghdr, field);
    const word = @sizeOf(c_int);
    return @bitCast(std.mem.readInt(c_int, at[offset..][0..word], endian));
}

fn putValue(at: []u8, value: batch.Value) void {
    const start = value_at;
    switch (value) {
        .bits => |bits| {
            const word = @sizeOf(c_int);
            std.mem.writeInt(c_int, at[start..][0..word], @intCast(bits), endian);
        },
        .short => |short| {
            std.mem.writeInt(u16, at[start..][0..@sizeOf(u16)], short, endian);
        },
    }
}

fn takeValue(header: []const u8, length: usize, read: *CmsgRead) void {
    // The caller has already refused a length below `@sizeOf(c.cmsghdr)`, and
    // `value_at` is that same number by construction — see the comptime block
    // above — so this slice cannot start past its own end.
    const value = header[value_at..length];
    const level = getHeader("level", header);
    const kind = getHeader("type", header);
    if (level == names.udp_level and kind == names.gro) {
        // The receive ABI is a full native int, unlike UDP_SEGMENT's u16.
        if (value.len < @sizeOf(c_uint)) return;
        read.stride = std.mem.readInt(c_uint, value[0..@sizeOf(c_uint)], endian);
        return;
    }
    const carries_class = (level == names.ip_level and kind == names.ipv4_tos) or
        (level == names.ipv6_level and kind == names.ipv6_tclass);
    if (!carries_class) return;
    read.ecn = trafficClass(value);
}

/// The codepoint a traffic-class message carried, or null for a value that
/// carries no byte at all.
///
/// The width here is not `batch.tos_width`, and the difference is the whole
/// reason this function exists. `batch.tos_width` is the width the *option*
/// takes, and it is what a send writes: `ip_cmsg_send` reads
/// `*(int *)CMSG_DATA(cmsg)`, so four bytes on Linux and one on the two BSDs
/// that declare the option a `c_uchar`. A *read* is a different ABI: Linux's
/// `ip_cmsg_put` writes `cmsg_len = CMSG_LEN(sizeof(u8))` and one byte, while
/// the BSDs write one byte too. So on Linux the message that arrives is two
/// bytes shorter than the message that left, and a reader that insists on
/// `tos_width` reads every IPv4 datagram as not-ECT and says nothing.
///
/// Both spellings put the two bits in the low byte on every ABI this builds
/// for, so the value is read at the width the message actually arrived at.
fn trafficClass(value: []const u8) ?batch.Ecn {
    if (value.len == 0) return null;
    if (value.len < @sizeOf(c_int)) return batch.Recv.ecnFromBits(value[0]);
    // The wire carries two bits and the rest of the word is other people's
    // traffic. `batch.Recv.ecnFromBits` masks; zero is not-ECT, not nothing.
    const word = @sizeOf(c_int);
    const raw = std.mem.readInt(c_int, value[0..word], endian);
    return batch.Recv.ecnFromBits(@truncate(@as(u32, @bitCast(raw))));
}

// 79 display columns; the rule counts UTF-8 bytes, three per box character.
// ziglint-ignore: Z024
// ───────────────────────────────────────────────────────────── address layout

/// Write `address` into `out` in the kernel's own layout and say how many
/// bytes of `out` are the address.
///
/// The port goes out in network order. The IPv4 address does not get the
/// same treatment, and the reason is worth writing down: `s_addr` is a word
/// whose four bytes *are* the address in wire order, so a bit cast is the
/// conversion and a byte swap would reverse the octets. Everything else
/// about an address belongs to the path and not to the socket.
pub fn writeSockaddr(address: base_addr.SocketAddr, out: *c.sockaddr.storage) socklen_t {
    switch (address.ip) {
        .v4 => |octets| {
            const target: *c.sockaddr.in = @ptrCast(@alignCast(out));
            target.* = .{
                .family = linux.AF.INET,
                .port = std.mem.nativeToBig(u16, address.port),
                .addr = @bitCast(octets),
            };
            return @sizeOf(c.sockaddr.in);
        },
        .v6 => |octets| {
            const target: *c.sockaddr.in6 = @ptrCast(@alignCast(out));
            target.* = .{
                .family = linux.AF.INET6,
                .port = std.mem.nativeToBig(u16, address.port),
                .flowinfo = 0,
                .addr = octets,
                .scope_id = 0,
            };
            return @sizeOf(c.sockaddr.in6);
        },
    }
}

/// Read a name the kernel filled, or null when it is not an address this
/// module speaks — an `AF_UNIX` peer, which a UDP socket can still be handed
/// by a caller that used the wrong type.
pub fn readSockaddr(raw: *const c.sockaddr.storage) ?base_addr.SocketAddr {
    const name: *const c.sockaddr = @ptrCast(@alignCast(raw));
    return switch (name.family) {
        linux.AF.INET => v4: {
            const peer: *const c.sockaddr.in = @ptrCast(@alignCast(raw));
            break :v4 base_addr.SocketAddr{
                .ip = .{ .v4 = @bitCast(peer.addr) },
                .port = std.mem.bigToNative(u16, peer.port),
            };
        },
        linux.AF.INET6 => v6: {
            const peer: *const c.sockaddr.in6 = @ptrCast(@alignCast(raw));
            break :v6 base_addr.SocketAddr{
                .ip = .{ .v6 = peer.addr },
                .port = std.mem.bigToNative(u16, peer.port),
            };
        },
        else => null,
    };
}

// 78 display columns; the rule counts UTF-8 bytes, three per box character.
// ziglint-ignore: Z024
// ───────────────────────────────────────────────────────────────────── tests

const t = std.testing;

// Linux 6.12 recvmsg capture: GRO has an int payload, not UDP_SEGMENT's u16.
// The receive fixture must not use the send codec that made the width mistake.
const KernelGro = extern struct {
    length: usize,
    level: c_int,
    kind: c_int,
    stride: c_int,
};

fn kernelGro(stride: c_int) KernelGro {
    return .{
        .length = cmsgLen(@sizeOf(c_int)),
        .level = @intCast(names.udp_level),
        .kind = @intCast(names.gro),
        .stride = stride,
    };
}

test "a single datagram writes one control message" {
    const payload = [_]u8{0xaa} ** 64;
    const send = batch.Send.single(&payload, .ect1);
    var messages: [batch.max_cmsg]batch.Cmsg = undefined;
    var control: ControlBuffer = undefined;
    const written = try writeCmsg(batch.cmsg(send, .v4, &messages), &control);

    try t.expectEqual(cmsgSpace(batch.tos_width), written.len);
    try t.expectEqual(names.ip_level, messages[0].level);
    try t.expectEqual(names.ipv4_tos, messages[0].kind);
    // Not-ECT is zero, so a send with no codepoint still writes the message
    // rather than letting a codepoint set on the socket leak onto it.
    try t.expectEqual(@as(u8, 0b01), messages[0].value.bits);

    const read = readCmsg(written);
    try t.expect(!read.truncated);
    try t.expectEqual(@as(?usize, null), read.stride);
    try t.expectEqual(@as(?batch.Ecn, .ect1), read.ecn);
}

test "a header field the ABI cannot spell is refused, not a trap" {
    // `cmsg_level` and `cmsg_type` are an `int` and the model names them as
    // `u32`, so a level or an option above `2^31 - 1` has no spelling. A bare
    // `@intCast` panics in Debug on the way to writing one, which is a crash
    // no caller can catch and this function can name.
    var at: [cmsgLen(0)]u8 = undefined;
    try t.expectError(error.FieldTooWide, putHeader(&at, .{
        .length = cmsgLen(0),
        .level = std.math.maxInt(u32),
        .kind = names.gro,
    }));
    try t.expectError(error.FieldTooWide, putHeader(&at, .{
        .length = cmsgLen(0),
        .level = names.udp_level,
        .kind = std.math.maxInt(u32),
    }));

    // A length past what `cmsg_len` spells is the third narrowing, and no
    // caller reaches it: `writeCmsg` builds its lengths from `cmsgLen` over a
    // buffer of `control_size`, a fixed number well inside what any
    // `socklen_t` holds. What that bound cannot say is the width — musl
    // declares the field a `socklen_t` where the kernel reads a `size_t` — and
    // that is the next test.
}

test "a header spells its length in the width the kernel reads" {
    // The kernel copies one whole word out of this buffer for every send it
    // validates a message from, and musl's own `cmsghdr` puts a `socklen_t`
    // and four bytes of padding inside that same word. A header written
    // through the C struct's declared field alone would leave four bytes of an
    // undefined buffer in the middle of the length the kernel reads, and a
    // send refused or not would come to depend on what the stack held. The
    // buffer is poisoned first, so this fails the same way every time instead
    // of passing on a stack that happened to be zeros.
    var messages: [batch.max_cmsg]batch.Cmsg = undefined;
    var control: ControlBuffer = undefined;
    @memset(&control.bytes, 0xaa);
    const written = try writeCmsg(
        batch.cmsg(batch.Send.single(&.{}, .ect1), .v4, &messages),
        &control,
    );

    const word = std.mem.readInt(usize, control.bytes[0..@sizeOf(usize)], endian);
    try t.expectEqual(cmsgLen(batch.tos_width), word);

    // And the message is still the one that was written: the word is the
    // header's own length and not one field too wide into the level.
    const read = readCmsg(written);
    try t.expect(!read.truncated);
    try t.expectEqual(@as(?batch.Ecn, .ect1), read.ecn);
}

test "an IPv4 ECN byte is read even when shorter than the send option" {
    // The kernel's byte payload differs from the integer send option. Spell
    // its native ABI explicitly; a fixed x86_64 capture is invalid on 32-bit
    // and big-endian targets.
    const KernelByte = extern struct {
        length: usize,
        level: c_int,
        kind: c_int,
        codepoint: u8,
    };
    const captured: KernelByte = .{
        .length = @offsetOf(KernelByte, "codepoint") + @sizeOf(u8),
        .level = @intCast(names.ip_level),
        .kind = @intCast(names.ipv4_tos),
        .codepoint = 0b10,
    };
    const read = readCmsg(std.mem.asBytes(&captured)[0..captured.length]);
    try t.expect(!read.truncated);
    try t.expectEqual(@as(?batch.Ecn, .ect0), read.ecn);
    try t.expectEqual(@as(?usize, null), read.stride);

    // The same message at the send width, which is what a platform that
    // hands the option an `int` back would deliver.
    var messages: [batch.max_cmsg]batch.Cmsg = undefined;
    var control: ControlBuffer = undefined;
    const send = batch.Send.single(&.{}, .ce);
    const wide = try writeCmsg(batch.cmsg(send, .v4, &messages), &control);
    try t.expectEqual(@as(?batch.Ecn, .ce), readCmsg(wide).ecn);

    // Not-ECT is zero and is still a codepoint's absence, not a lost message.
    const not_ect = try writeCmsg(batch.cmsg(
        batch.Send.single(&.{}, null),
        .v6,
        &messages,
    ), &control);
    try t.expectEqual(@as(?batch.Ecn, null), readCmsg(not_ect).ecn);

    // A message with no value at all carries nothing, and says so by being
    // absent rather than by claiming not-ECT.
    var empty: [cmsgLen(0)]u8 = undefined;
    try putHeader(&empty, .{
        .length = cmsgLen(0),
        .level = names.ip_level,
        .kind = names.ipv4_tos,
    });
    try t.expectEqual(@as(?batch.Ecn, null), readCmsg(&empty).ecn);
}

test "a segmented run writes the traffic class then the segment size" {
    const payload = [_]u8{0} ** 200;
    const send = try batch.Send.batch(&payload, 100, .ce);
    var messages: [batch.max_cmsg]batch.Cmsg = undefined;
    var control: ControlBuffer = undefined;
    const written = try writeCmsg(batch.cmsg(send, .v6, &messages), &control);

    try t.expectEqual(2, batch.cmsg(send, .v6, &messages).len);
    try t.expectEqual(cmsgSpace(batch.tos_width) + cmsgSpace(@sizeOf(u16)), written.len);
    try t.expectEqual(control_size, written.len);
    try t.expectEqual(names.ipv6_level, messages[0].level);
    try t.expectEqual(names.ipv6_tclass, messages[0].kind);
    try t.expectEqual(names.udp_level, messages[1].level);
    try t.expectEqual(names.segment, messages[1].kind);
    try t.expectEqual(@as(u16, 100), messages[1].value.short);

    // The traffic class reads back because the send and the receive spell it
    // the same. The segment size does not: a send carries `UDP_SEGMENT` and a
    // read carries `UDP_GRO`, 103 and 104, and a reader that mistook the one
    // for the other would hand a caller a stride no kernel ever sent.
    const read = readCmsg(written);
    try t.expectEqual(@as(?usize, null), read.stride);
    try t.expectEqual(@as(?batch.Ecn, .ce), read.ecn);
    try t.expect(!read.truncated);
}

test "a message this seam did not ask for does not hide the one after it" {
    const payload = [_]u8{0} ** 200;
    const send = try batch.Send.batch(&payload, 100, .ect0);
    var messages: [batch.max_cmsg]batch.Cmsg = undefined;
    var control: ControlBuffer = undefined;
    const written = try writeCmsg(batch.cmsg(send, .v4, &messages), &control);
    const class = cmsgSpace(batch.tos_width);

    // A message between the two, at a level nobody here names. A walk that
    // stopped at the first unrecognised header would lose the stride after
    // it and read a coalesced list as one long datagram.
    const stranger = [_]batch.Cmsg{.{
        .level = 0xdead,
        .kind = 0xbeef,
        .value = .{ .short = 0 },
    }};
    var stranger_control: ControlBuffer = undefined;
    const between = try writeCmsg(&stranger, &stranger_control);
    const stride_message = kernelGro(100);
    const stride_bytes = std.mem.asBytes(&stride_message)[0..stride_message.length];

    var blob: [control_size * 3]u8 = undefined;
    var used: usize = 0;
    @memcpy(blob[used..][0..class], written[0..class]);
    used += class;
    @memcpy(blob[used..][0..between.len], between);
    used += between.len;
    @memcpy(blob[used..][0..stride_bytes.len], stride_bytes);
    used += stride_bytes.len;

    const read = readCmsg(blob[0..used]);
    try t.expect(!read.truncated);
    try t.expectEqual(@as(?usize, 100), read.stride);
    try t.expectEqual(@as(?batch.Ecn, .ect0), read.ecn);
}

test "a blob that ends inside a message says so" {
    const payload = [_]u8{0} ** 200;
    const send = try batch.Send.batch(&payload, 100, .ect0);
    var messages: [batch.max_cmsg]batch.Cmsg = undefined;
    var control: ControlBuffer = undefined;
    const written = try writeCmsg(batch.cmsg(send, .v4, &messages), &control);
    const class = cmsgSpace(batch.tos_width);

    // A header that claims more than the blob holds, which is the shape a
    // control buffer too small for the kernel's messages takes.
    var claimed: [control_size]u8 = undefined;
    @memcpy(claimed[0..class], written[0..class]);
    try putHeader(claimed[0..class], .{
        .length = class + 64,
        .level = names.udp_level,
        .kind = names.gro,
    });
    try t.expect(readCmsg(claimed[0..class]).truncated);

    // Trailing bytes too short to be a header at all, and no bytes at all:
    // the first is a message this seam did not ask for and the second is no
    // message, which is a read with no stride rather than a broken one.
    const ragged = written[0..4];
    try t.expect(readCmsg(ragged).truncated);
    try t.expect(!readCmsg("").truncated);
}

test "more messages than the buffer holds is refused, not truncated" {
    var messages: [3]batch.Cmsg = undefined;
    for (&messages, 0..) |*message, index| {
        message.* = .{
            .level = names.udp_level,
            .kind = names.segment,
            .value = .{ .short = @intCast(index + 1) },
        };
    }
    var control: ControlBuffer = undefined;
    try t.expectError(error.BufferTooSmall, writeCmsg(messages[0..3], &control));
    // Two is what the model builds and two is what the buffer holds.
    try t.expectEqual(control_size, (try writeCmsg(messages[0..2], &control)).len);
}

test "an address survives the kernel's own layout" {
    var raw: c.sockaddr.storage = undefined;

    const v4: base_addr.SocketAddr = .{ .ip = .{ .v4 = .{ 127, 0, 0, 1 } }, .port = 33433 };
    try t.expectEqual(@as(socklen_t, @sizeOf(c.sockaddr.in)), writeSockaddr(v4, &raw));
    // The port is network order on the wire and host order in the value: an
    // address that round-trips only because both ends agree to be wrong is
    // not a round trip. The four octets are the four bytes of the word, in
    // the order the wire has them, which is what makes the bit cast the
    // conversion and a byte swap the bug.
    const v4_raw: *const c.sockaddr.in = @ptrCast(@alignCast(&raw));
    try t.expectEqual(std.mem.nativeToBig(u16, 33433), v4_raw.port);
    try t.expectEqualSlices(u8, &.{ 127, 0, 0, 1 }, std.mem.asBytes(&v4_raw.addr));
    try t.expectEqual(v4, readSockaddr(&raw).?);

    const v6: base_addr.SocketAddr = .{
        .ip = .{ .v6 = [_]u8{0} ** 15 ++ [_]u8{0x01} },
        .port = 65535,
    };
    try t.expectEqual(@as(socklen_t, @sizeOf(c.sockaddr.in6)), writeSockaddr(v6, &raw));
    const v6_raw: *const c.sockaddr.in6 = @ptrCast(@alignCast(&raw));
    try t.expectEqual(std.mem.nativeToBig(u16, 65535), v6_raw.port);
    try t.expectEqual(v6, readSockaddr(&raw).?);

    // An address of a family this module does not speak reads as nothing
    // rather than as an IPv4 address built from the wrong first two bytes.
    raw.family = linux.AF.LOCAL;
    try t.expect(readSockaddr(&raw) == null);
}

test "a kernel GRO integer defines datagram boundaries, and a short value does not" {
    var message = kernelGro(14);
    const read = readCmsg(std.mem.asBytes(&message)[0..message.length]);
    try t.expectEqual(@as(?usize, 14), read.stride);
    try t.expectEqual(@as(?batch.Ecn, null), read.ecn);
    try t.expect(!read.truncated);

    var payload: [42]u8 = undefined;
    for (&payload, 0..) |*byte, index| byte.* = @intCast(index);
    const received = try batch.Recv.init(&payload, read.stride, null);
    try t.expectEqual(@as(usize, 3), received.datagramCount());
    try t.expectEqualSlices(u8, payload[14..28], received.datagram(1).?);
    try t.expect(received.datagram(3) == null);

    message.length = cmsgLen(@sizeOf(u16));
    const short = readCmsg(std.mem.asBytes(&message)[0..message.length]);
    try t.expectEqual(@as(?usize, null), short.stride);
}
