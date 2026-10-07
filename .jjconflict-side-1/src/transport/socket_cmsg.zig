//! The bytes a control message is made of: the alignment arithmetic, the
//! buffer a `sendmsg` writes them into and a `recvmsg` reads them back out of,
//! and the two walks that lay them down and take them apart.
//!
//! Split out of `transport/socket.zig`, which is now the facade over this and
//! five other named modules. The boundary is the ABI: every line below is
//! arithmetic over bytes and a `std.c` struct layout, and none of it touches a
//! descriptor, which is why there is no `std.Io` here at all — the two entries
//! take a message that is already built and hand back the bytes that carry it.
//! That is also what the tests in that file are above the syscall for: the
//! layout work *is* this module, so they reach libc's code without leaving a
//! syscall behind.

const std = @import("std");
const builtin = @import("builtin");
const batch = @import("batch.zig");

const c = std.c;

/// `batch.linux`, under the name this file uses for it. The option numbers
/// are named once — in `batch.zig`, with the std line beside each — so that a
/// search for `103` finds that block and not a literal in the middle of a
/// send. Everything else below is named out of `std.os.linux` directly.
const names = batch.linux;

/// Control integers use native byte order. `UDP_SEGMENT` sends a `u16`,
/// `UDP_GRO` returns an integer, and traffic classes arrive as a byte or an integer.
pub const endian = builtin.cpu.arch.endian();

/// The boundary a control message is padded to, and the one number in this
/// file that decides where a message ends and the next one begins.
///
/// It is `sizeof(size_t)` and not the alignment of a `cmsghdr`, and on musl
/// those are two different numbers: `CMSG_ALIGN` in musl's `sys/socket.h`
/// and in the kernel's `include/linux/socket.h` both round a length up to a
/// word, while glibc declares `cmsg_len` a `size_t`, so its struct is
/// eight-byte aligned and the two agree there. musl aims at POSIX and
/// declares the same field a `socklen_t` with four bytes of padding above it,
/// which makes its struct four-byte aligned and sixteen bytes wide while
/// `CMSG_ALIGN` still rounds to eight — `std/c.zig` says as much over
/// `posix_cmsghdr`.
///
/// Rounding by the struct instead is not cosmetic. The buffer below is ten
/// bytes short of the two messages a coalesced read carries, and the kernel
/// answers a control buffer it cannot fill with `MSG_CTRUNC`; a send's second
/// message lands four bytes before the offset the kernel's own `CMSG_NXTHDR`
/// walks to, so what it reads there is padding rather than a header.
const cmsg_boundary: usize = @sizeOf(usize);

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
    return cmsgAlign(@sizeOf(c.cmsghdr)) + width;
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
    // buffer this file hands to a syscall is longer than `control_size` —
    // `writeCmsg` cannot return more of a `ControlBuffer` than it holds —
    // so this is what proves `sendmsg`'s own narrowing cannot lose a bit.
    std.debug.assert(control_size <= std.math.maxInt(ControlExtent));
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
    const value_at = cmsgAlign(@sizeOf(c.cmsghdr));
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
        takeValue(rest, value_at, length, &read);
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

pub fn putHeader(at: []u8, header: Header) ControlError!void {
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
    const start = cmsgAlign(@sizeOf(c.cmsghdr));
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

fn takeValue(header: []const u8, value_at: usize, length: usize, read: *CmsgRead) void {
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
