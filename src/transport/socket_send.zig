//! One `sendmsg`, and the passes over a batch that decide what it cost.
//!
//! `transport/batch.zig` is the specification — what a socket write may be
//! handed, what it may refuse, and which of those refusals is permanent — and
//! this file is where that specification meets the kernel. Three things live
//! here and nothing else:
//!
//!   * `SendError`, which is the whole of what one syscall can answer,
//!   * `sendmsg`, which is one call and one errno translation, and
//!   * `sendBatch` and `walkRuns`, the two passes that decide what a refused
//!     run costs and which runs behind it have to go out on their own.
//!
//! **Every datagram a batch sends reaches the wire once.** A run refused for
//! segmentation lowers the socket's capability for good and is answered by
//! sending that run and the runs behind it, one datagram per `sendmsg`; the
//! runs before it are already on the wire and are not sent again. A codepoint
//! the retried tail lost is reported as lost, because the datagram carrying it
//! has gone and no retry can put it back.
//!
//! `socket.zig` passes its private `Socket.sendRun` operation as a comptime callback.
//! The callback acts on the caller-owned context. No socket method becomes public.

const std = @import("std");
const batch = @import("batch.zig");
const base_addr = @import("../base/addr.zig");
const ancillary = @import("ancillary.zig");
const control = @import("socket_control.zig");

const c = std.c;
const linux = std.os.linux;

const socklen_t = c.socklen_t;

/// Why a send did not go out.
///
/// `WouldBlock` and `MessageTooLarge` are the two that must never share a
/// name: the first is backpressure, which the caller waits out or absorbs, and
/// the second is a datagram this path will never carry, which retrying turns
/// into a stall. Collapsing them is how a congestion signal becomes a hung
/// socket. `ControlError` is in the set because a set names every way a call
/// can fail and not only the ones that are convenient; `batch.cmsg` builds at
/// most two messages out of the model's own constants and `ControlBuffer`
/// holds exactly two, so a caller cannot reach either of `ControlError`'s two
/// members through `Socket.send`.
pub const SendError = batch.Error || ancillary.ControlError || error{
    /// The task was cancelled before the datagram left. A socket that sends
    /// after its caller has given up is a socket nobody is waiting for.
    Canceled,
    /// `EAGAIN`: the socket's send queue is full and nothing left the host.
    WouldBlock,
    /// `EMSGSIZE`: the payload is larger than the path carries.
    MessageTooLarge,
    /// `ENETUNREACH`: no route to the network.
    NetworkUnreachable,
    /// `EHOSTUNREACH`: no route to that host.
    HostUnreachable,
    /// `ENETDOWN`: the interface that would carry it is down.
    NetworkDown,
    /// `ECONNREFUSED`: a previous send drew an ICMP port unreachable and the
    /// kernel held it back for exactly this call.
    PortUnreachable,
    /// `EADDRNOTAVAIL`: the destination is not one this host may send to.
    AddressNotAvailable,
    /// `EACCES` or `EPERM`.
    PermissionDenied,
    /// `ENOBUFS` or `ENOMEM`: the kernel could not build the datagram.
    ResourcesExhausted,
    /// `EDESTADDRREQ` or `ENOTCONN`.
    SocketUnusable,
    /// `EIO` or `EINVAL` on a run carrying no control message this module is
    /// willing to drop, and on a family whose traffic class is a core option.
    /// The kernel refused a send there without saying which half it disliked,
    /// and guessing would be worse than saying so.
    UnknownControlMessage,
    /// The kernel took fewer bytes than the payload held. UDP has no such
    /// answer, so this is the kernel disagreeing about where the datagram
    /// ends, and the caller has to know that it did.
    PartialDatagram,
    /// A bound on this call ran out: `EINTR` on every attempt the refused run
    /// had, or a stop whose queue or wake counter a send could not empty within
    /// `max_discarded` and `max_wakes_spent`.
    ///
    /// The bound is on the call and not on the batch. A batch is one
    /// `sendmsg` per run, and every run that finished before this one left the
    /// socket: nothing the refused run carried went out, while datagrams ahead
    /// of it may have. Which is why `Socket.send` returns no sent-prefix count
    /// and why the caller is the one that decides about duplicates — the same
    /// residue every other error here leaves, and this one is no exception.
    ///
    /// A stop this send did not deal with leaves the socket stopped, so asking
    /// again is what drains the rest and makes progress.
    Interrupted,
    /// Anything else.
    Unexpected,
};

/// What one `sendmsg` said, before the model's name is put on it.
pub const Outcome = enum {
    /// Every byte of the payload left as one message.
    accepted,
    /// `EIO` or `EINVAL`. Only the run can tell a driver that will not
    /// segment from a kernel that does not know an option.
    refused,
};

/// One `sendmsg` of `bytes` to `name`, carrying `control_bytes` and nothing
/// else.
///
/// The control slice is the caller's and carries no allocation: `Socket.sendRun`
/// lays it out on its stack through `ancillary.writeCmsg`, which can only hand
/// back part of the `ControlBuffer` it was given. `io` is here because this is
/// the one call where a cancellation is seen between attempts, and a socket
/// that sends after its caller has given up is a socket nobody is waiting for.
pub fn sendmsg(
    io: std.Io,
    handle: c.fd_t,
    bytes: []const u8,
    name: *const c.sockaddr.storage,
    name_length: socklen_t,
    control_bytes: []const u8,
) SendError!Outcome {
    var vectors = [_]c.iovec_const{.{ .base = bytes.ptr, .len = bytes.len }};
    // The length narrowed where the bound is, rather than by a bare
    // `@intCast` that traps in Debug on a value which does not fit: under
    // musl `msg_controllen` is a `socklen_t` and a slice length is a
    // `usize`. It cannot fail, because `writeCmsg` hands back no more of a
    // `ControlBuffer` than it holds and `ancillary.control_size` is proved
    // against this very field at comptime — but the proof is that assertion,
    // and this is the cast that reads it.
    const control_length = std.math.cast(ancillary.ControlExtent, control_bytes.len) orelse
        return error.FieldTooWide;
    const control_ptr: ?*const anyopaque = if (control_length == 0) null else control_bytes.ptr;
    var header: c.msghdr_const = .{
        .name = @as(?*const c.sockaddr, @ptrCast(name)),
        .namelen = name_length,
        .iov = vectors[0..].ptr,
        .iovlen = vectors.len,
        .control = control_ptr,
        .controllen = control_length,
        .flags = 0,
    };
    var attempt: usize = 0;
    while (attempt < control.max_syscall_attempts) : (attempt += 1) {
        // A signal arrived before the datagram did. Asking again is the
        // only correct answer, and the loop is also where a cancellation
        // lands. `NOSIGNAL` because a UDP send to a port nobody is on has
        // to raise `ECONNREFUSED` here rather than `SIGPIPE` there.
        try io.checkCancel();
        const rc = c.sendmsg(handle, &header, linux.MSG.NOSIGNAL);
        switch (c.errno(rc)) {
            .SUCCESS => {
                if (@as(usize, @intCast(rc)) != bytes.len) return error.PartialDatagram;
                return .accepted;
            },
            .INTR => continue,
            .AGAIN => return error.WouldBlock,
            .MSGSIZE => return error.MessageTooLarge,
            .IO, .INVAL => return .refused,
            .DESTADDRREQ, .NOTCONN => return error.SocketUnusable,
            .ACCES, .PERM => return error.PermissionDenied,
            .ADDRNOTAVAIL => return error.AddressNotAvailable,
            .HOSTUNREACH => return error.HostUnreachable,
            .NETUNREACH => return error.NetworkUnreachable,
            .NETDOWN => return error.NetworkDown,
            .CONNREFUSED => return error.PortUnreachable,
            .NOMEM, .NOBUFS => return error.ResourcesExhausted,
            else => return error.Unexpected,
        }
    }
    return error.Interrupted;
}

/// What one pass over a batch left behind.
///
/// The refusal is the codepoint one when there was one, because a codepoint
/// dropped from a run is not on the next one either; a refused segmentation is
/// not a refusal of the codepoint at all and is reported by `tail` being there
/// rather than by being ranked against a loss.
const Pass = struct {
    /// What the runs drew. `.none` when every one of them went out.
    refused: batch.Refused = .none,
    /// The payload from the refused run onwards, and null when there is none:
    /// a run that went out took its datagrams with it, so a pass that refused
    /// nothing has nothing to send again, and a pass that refused one leaves
    /// the tail starting on that run rather than behind it.
    tail: ?batch.Send = null,
};

/// Send `payload` to `dest` through `context`, and say what it carried.
///
/// One pass over the runs, and a second over the runs that did not go out when
/// one of them was refused for segmentation. Every datagram reaches the wire
/// once: the runs before the refused one are already there, so the tail starts
/// on the refused run itself and the retry cannot put a second copy of
/// anything on it.
///
/// `context` is the writer the runs go out on, and not the socket type: the
/// refusals below come from the driver, and a driver that refuses a segmented
/// run is a node a test may not be running on. `io` comes before it because a
/// runtime parameter is a parameter of the call rather than of its subject,
/// and a writer that has one is the writer, not the context.
///
/// The writer is reached through `send_run_callback` rather than by naming a
/// method on it, and that is a privacy fact rather than a taste one. The
/// writer in production is a `Socket`, and its `sendRun` is private to
/// `socket.zig`, which a monomorphised `context.sendRun(...)` written here
/// cannot do — a private declaration is private to its file, and this is not
/// it. A function pointer carries the operation without carrying the access:
/// `Socket.sendRun` stays private, and this signature is the whole of what
/// this module is allowed to know about the thing it walks the runs on.
pub fn sendBatch(
    comptime Context: type,
    comptime send_run_callback: *const fn (
        Context,
        std.Io,
        base_addr.SocketAddr,
        batch.Send,
    ) SendError!batch.Refused,
    io: std.Io,
    context: Context,
    dest: base_addr.SocketAddr,
    payload: batch.Send,
    caps: *batch.Capability,
) SendError!batch.Report {
    const family = batch.Family.of(dest.ip);
    const first = try walkRuns(Context, send_run_callback, io, context, dest, payload, caps.*);
    const tail = first.tail orelse return batch.report(payload, family, first.refused);
    // Found by sending, not by asking, and permanent: noq lowers the cap and
    // never raises it (`noq-udp/src/unix.rs:436-445`), because a driver that
    // could segment on the next send would fail it again on the one after.
    caps.* = caps.*.withoutSegmentation();
    // Nothing behind that refusal was segmented, so the retry draws no second
    // segmentation and cannot leave a tail of its own.
    const second = try walkRuns(Context, send_run_callback, io, context, dest, tail, caps.*);

    // `batch.report` is given the refusal no retry can undo: a codepoint either
    // pass dropped is on the wire without it, and nothing downstream can get it
    // back. A refused segmentation is answered by the retry above and is not a
    // report about the codepoint at all — that fact is `degraded`, below.
    const unrecoverable = if (first.refused == .unknown_control_message)
        first.refused
    else
        second.refused;
    var report = batch.report(payload, family, unrecoverable);
    // The degradation is the other fact and the retry does not undo it: it is
    // the reason there was a retry, and a batch that went out one datagram per
    // `sendmsg` went out that way whatever the retry found. Same rule
    // `batch.report` uses — one datagram is one `sendmsg` either way.
    report.degraded = payload.datagramCount() > 1;
    return report;
}

/// One `send_run_callback` per run of `payload`, and what the pass left behind.
///
/// Stops at the first run refused for segmentation: that run carried nothing,
/// and every run behind it is one this socket will refuse the same way — the
/// cap is lowered by the caller, not argued with here.
fn walkRuns(
    comptime Context: type,
    comptime send_run_callback: *const fn (
        Context,
        std.Io,
        base_addr.SocketAddr,
        batch.Send,
    ) SendError!batch.Refused,
    io: std.Io,
    context: Context,
    dest: base_addr.SocketAddr,
    payload: batch.Send,
    caps: batch.Capability,
) SendError!Pass {
    var runs = try batch.Runs.init(payload, caps);
    var pass: Pass = .{};
    // The bytes already sent, which is where a refused run starts: the runs
    // before it left the socket, so the tail is everything behind them.
    var on_wire: usize = 0;
    while (runs.next()) |run| {
        const refused = try send_run_callback(context, io, dest, run);
        if (refused == .segmentation) {
            // The tail starts on the refused run and not behind it: that run
            // carried nothing, so a tail measured from its end drops it.
            pass.tail = .{
                .ecn = payload.ecn,
                .contents = payload.contents[on_wire..],
                .segment_size = payload.segment_size,
            };
            return pass;
        }
        // Both answers that are not a refused segmentation left the socket.
        on_wire += run.contents.len;
        // Sticky: the run went out, and it went out without the codepoint. The
        // runs behind it carry their own, so nothing here clears this.
        if (refused == .unknown_control_message) pass.refused = refused;
    }
    return pass;
}

// 78 display columns; the rule counts UTF-8 bytes, three per box character.
// ziglint-ignore: Z024
// ───────────────────────────────────────────────────────────────────── tests

const t = std.testing;

/// Loopback on an ephemeral port. The spelling `test/loopback_test.zig` uses,
/// and nothing above it is reached: every test below answers about the policy
/// over a scripted writer rather than over a descriptor.
const loopback: base_addr.SocketAddr = .{ .ip = .{ .v4 = .{ 127, 0, 0, 1 } }, .port = 0 };

test "the two probes answer for a socket, one side at a time" {
    // The decision the probe exists to make, over the answers it can get.
    const both = batch.capability(.accepted, .accepted);
    try t.expect(both.supportsSegmentation());
    try t.expect(both.supportsCoalescing());
    try t.expectEqual(batch.max_segments_linux, both.max_send_segments);
    try t.expectEqual(batch.max_gro_segments_linux, both.max_recv_segments);

    try t.expectEqual(batch.Capability.none, batch.capability(.unsupported, .unsupported));

    // A socket that coalesces but cannot segment is a real one, and the two
    // answers stay independent: the kernel can do either without the other,
    // which is why `capability` reads two probes rather than one.
    const recv_only = batch.capability(.unsupported, .accepted);
    try t.expect(!recv_only.supportsSegmentation());
    try t.expect(recv_only.supportsCoalescing());

    // The permanent fallback, and the receive side it leaves alone: a driver
    // that cannot segment can still coalesce.
    const send_only = batch.Capability.linux_full.withoutSegmentation();
    try t.expectEqual(@as(u16, 1), send_only.max_send_segments);
    try t.expectEqual(batch.max_gro_segments_linux, send_only.max_recv_segments);
}

test "a driver that cannot segment degrades the batch and says so" {
    // The fallback, as the value a caller inspects: a four-datagram batch goes
    // out as four `sendmsg`s and the report says the batch was degraded,
    // rather than leaving the wire to be the only evidence.
    const payload = [_]u8{0} ** 40;
    const send = try batch.Send.batch(&payload, 10, .ect0);
    const degraded = batch.report(send, .v4, .segmentation);
    try t.expect(degraded.degraded);
    try t.expect(degraded.ecnSurvived());
    try t.expectEqual(@as(?batch.Ecn, .ect0), degraded.carried);

    // A single datagram is one `sendmsg` either way, so nothing about it is
    // degraded even when the same refusal happens to it.
    const single = batch.report(batch.Send.single(&payload, .ect0), .v4, .segmentation);
    try t.expect(!single.degraded);
    try t.expect(single.ecnSurvived());

    // The walk a degraded socket then takes, where the codepoint survives: a
    // fallback about segmentation is not collateral damage for the ECN.
    var runs = try batch.Runs.init(send, batch.Capability.linux_full.withoutSegmentation());
    var seen: usize = 0;
    while (runs.next()) |run| {
        try t.expectEqual(@as(?u16, null), run.segment_size);
        try t.expectEqual(@as(usize, 1), run.datagramCount());
        try t.expectEqual(@as(?batch.Ecn, .ect0), run.ecn);
        try t.expectEqual(@as(?batch.Ecn, .ect0), batch.report(run, .v4, .none).carried);
        seen += 1;
    }
    try t.expectEqual(@as(usize, 4), seen);
}

test "a lost codepoint is reported, and only on IPv4" {
    const payload = [_]u8{0} ** 8;
    const send = batch.Send.single(&payload, .ce);
    const lost = batch.report(send, .v4, .unknown_control_message);
    try t.expectEqual(@as(?batch.Ecn, null), lost.carried);
    try t.expectEqual(@as(?batch.Ecn, .ce), lost.wanted);
    try t.expect(!lost.ecnSurvived());

    // `IPV6_TCLASS` is a core option, so the same refusal drops nothing.
    const kept = batch.report(send, .v6, .unknown_control_message);
    try t.expectEqual(@as(?batch.Ecn, .ce), kept.carried);
    try t.expect(kept.ecnSurvived());

    // A send that asked for nothing has nothing to lose.
    const nothing = batch.report(batch.Send.single(&payload, null), .v4, .unknown_control_message);
    try t.expect(nothing.ecnSurvived());
    try t.expectEqual(@as(?batch.Ecn, null), nothing.carried);
}

/// A writer that answers what a socket answers, and refuses where a test says
/// to.
///
/// `Socket.sendRun` reads a refusal out of the driver, and a driver that
/// refuses a segmented run is a node this suite may not be running on: the one
/// measured here refuses every count of every segment size that is a multiple
/// of 256, which refuses the first run of a batch and leaves nothing on the
/// wire that a replay could send twice. So the answer is scripted, and what
/// the tests assert is what the policy did with it — the runs it handed here,
/// and the `Report` it gave its caller.
///
/// Two ledgers and not one, because an offer is not a datagram: a run refused
/// for segmentation was handed over and never left the socket, and a test
/// that counted it among the runs that went out would add its datagrams a
/// second time and call the batch whole.
const Scripted = struct {
    /// One answer per run offered, in the order the runs are offered, `.none`
    /// for a run that goes out. A shorter list leaves every run past its end
    /// going out.
    answers: []const batch.Refused,
    /// Every run handed over, in the order it was handed over, a refused run
    /// included.
    offered: [16]batch.Send = undefined,
    /// How many there have been.
    offers: usize = 0,
    /// The runs that reached the wire, in the order they reached it.
    sent: [16]batch.Send = undefined,
    /// How many there have been.
    sends: usize = 0,

    fn sendRun(
        self: *Scripted,
        io: std.Io,
        dest: base_addr.SocketAddr,
        run: batch.Send,
    ) SendError!batch.Refused {
        // The two parameters `walkRuns` calls with that this writer has no use
        // for: it is not a socket, so there is no descriptor to be cancelled
        // on and no address of its own to compare `dest` against.
        _ = io;
        _ = dest;
        std.debug.assert(self.offers < self.offered.len);
        const answer = if (self.offers < self.answers.len) self.answers[self.offers] else .none;
        self.offered[self.offers] = run;
        self.offers += 1;
        // What `Socket.sendRun` does with each answer: a refused segmentation
        // comes back before the kernel was asked to segment anything, so that
        // run is an offer and nothing else. An unknown control message is on
        // the wire — that run went out on the retry which dropped the message
        // — and so is every run that drew no refusal at all.
        if (answer != .segmentation) {
            std.debug.assert(self.sends < self.sent.len);
            self.sent[self.sends] = run;
            self.sends += 1;
        }
        return answer;
    }
};

/// The batch every test below shares: eight datagrams of ten bytes on a socket
/// whose cap takes three per run, which is three runs, with the refusal
/// landing on the middle one.
const RefusedMiddle = struct {
    send: batch.Send,
    caps: batch.Capability,
};

fn refusedMiddleRun(payload: []const u8) batch.Error!RefusedMiddle {
    return .{
        .send = try batch.Send.batch(payload, 10, .ect0),
        .caps = .{ .max_send_segments = 3, .max_recv_segments = 1 },
    };
}

/// `sendBatch` over a scripted writer: the state, its type, and the operation
/// its runs are walked through, bound together once.
///
/// This is the same binding `Socket.send` makes in production — a writer and
/// the operation it is reached through — with a scripted writer in place of a
/// socket. Naming it once is what keeps the tests exercising the real
/// contract rather than a second, shorter spelling of it.
fn scriptedBatch(
    writer: *Scripted,
    dest: base_addr.SocketAddr,
    payload: batch.Send,
    caps: *batch.Capability,
) SendError!batch.Report {
    return sendBatch(*Scripted, Scripted.sendRun, t.io, writer, dest, payload, caps);
}

test "a refused segmentation is answered with the runs that did not leave" {
    // The first run is on the wire and the last was never reached, so the
    // answer is the tail from the refused run onwards. The batch again would
    // put the first run's three datagrams on the wire a second time.
    var payload: [8 * 10]u8 = undefined;
    for (&payload, 0..) |*byte, index| byte.* = @truncate(index);
    var fixture = try refusedMiddleRun(&payload);
    var writer: Scripted = .{ .answers = &.{ .none, .segmentation } };

    _ = try scriptedBatch(&writer, loopback, fixture.send, &fixture.caps);

    // Every datagram on the wire exactly once, in order: the runs that were
    // sent, concatenated, are the payload — no run repeated and none missing.
    // The refused run is not among them, because it never reached the wire;
    // a ledger that counted it would charge its three datagrams twice and
    // still call the batch whole.
    var at: usize = 0;
    for (writer.sent[0..writer.sends]) |run| {
        // The run's own claim on the payload, checked before it reads out of
        // it: a repeat steps `at` off the end, and a test that traps on the
        // defect is a test that cannot say what the defect was.
        try t.expect(run.contents.len <= payload.len - at);
        try t.expectEqualSlices(u8, payload[at..][0..run.contents.len], run.contents);
        at += run.contents.len;
    }
    try t.expectEqual(payload.len, at);

    // Seven runs offered and six sent. The middle one was offered, refused,
    // and is what the retry carried again: three datagrams that were not on
    // the wire at any point before it.
    try t.expectEqual(@as(usize, 7), writer.offers);
    try t.expectEqual(@as(usize, 6), writer.sends);
    try t.expectEqual(@as(usize, 3), writer.offered[1].datagramCount());

    // The first run went out as the socket offered to send it; the tail went
    // out one datagram per `sendmsg`, which is what the lowered cap is for.
    try t.expectEqual(@as(usize, 3), writer.sent[0].datagramCount());
    for (writer.sent[1..writer.sends]) |run| {
        try t.expectEqual(@as(usize, 1), run.datagramCount());
    }

    // And the cap is never raised again, so the next send finds out the same
    // way rather than paying for this discovery twice.
    try t.expectEqual(@as(u16, 1), fixture.caps.max_send_segments);
}

test "a batch that took the fallback says it was degraded" {
    var payload: [8 * 10]u8 = undefined;
    for (&payload, 0..) |*byte, index| byte.* = @truncate(index);
    var fixture = try refusedMiddleRun(&payload);
    var writer: Scripted = .{ .answers = &.{ .none, .segmentation } };

    const report = try scriptedBatch(&writer, loopback, fixture.send, &fixture.caps);

    // The fallback `DECISIONS/0002` promised, made visible rather than a
    // slower wire to notice: the run this socket could take went out as one
    // `sendmsg` and the five datagrams of the tail it refused went out one
    // each, and the caller is told the batch was degraded rather than left to
    // measure it.
    try t.expect(report.degraded);

    // Nothing about the codepoint, because every run this module wrote carried
    // it — the retried tail included.
    try t.expect(report.ecnSurvived());
    try t.expectEqual(@as(?batch.Ecn, .ect0), report.carried);
}

test "a codepoint lost on the retried tail is reported with the degradation" {
    // Both refusals one send can draw: a driver that will not segment, and an
    // IPv4 kernel that does not know `IP_TOS` on the datagram it retries with.
    // The datagram that lost its codepoint is on the wire anyway, so the batch
    // went out slower than it was asked to *and* lost the one thing nothing
    // downstream can get back — which is two facts and not one.
    var payload: [8 * 10]u8 = undefined;
    for (&payload, 0..) |*byte, index| byte.* = @truncate(index);
    var fixture = try refusedMiddleRun(&payload);
    var writer: Scripted = .{ .answers = &.{ .none, .segmentation, .unknown_control_message } };

    const report = try scriptedBatch(&writer, loopback, fixture.send, &fixture.caps);

    try t.expect(report.degraded);
    try t.expect(!report.ecnSurvived());
    try t.expectEqual(@as(?batch.Ecn, null), report.carried);
    try t.expectEqual(@as(?batch.Ecn, .ect0), report.wanted);

    // The tail went out anyway: a dropped control message is a datagram with
    // no codepoint on it, not a datagram missing, and the refused run that
    // opened the tail is not counted here either.
    var at: usize = 0;
    for (writer.sent[0..writer.sends]) |run| {
        try t.expect(run.contents.len <= payload.len - at);
        at += run.contents.len;
    }
    try t.expectEqual(payload.len, at);
}

test "a codepoint lost before a refused segmentation is reported too" {
    // The two refusals in the order that hides one: a run that goes out
    // without its codepoint, and then a later run this socket will not segment
    // at all. The retry carries that run and every run behind it and none of
    // them is refused, so a report built from the retry alone says a codepoint
    // survived a send that demonstrably dropped it — which is the one loss a
    // caller cannot work out for itself afterwards.
    var payload: [8 * 10]u8 = undefined;
    for (&payload, 0..) |*byte, index| byte.* = @truncate(index);
    var fixture = try refusedMiddleRun(&payload);
    var writer: Scripted = .{ .answers = &.{ .unknown_control_message, .segmentation } };

    const report = try scriptedBatch(&writer, loopback, fixture.send, &fixture.caps);

    try t.expect(!report.ecnSurvived());
    try t.expectEqual(@as(?batch.Ecn, null), report.carried);
    try t.expectEqual(@as(?batch.Ecn, .ect0), report.wanted);
    // Both facts: the batch went out one datagram at a time after the refused
    // run whatever the retry found, so it was degraded and it lost the
    // codepoint, and a report that can only name one of them is wrong.
    try t.expect(report.degraded);

    // And the tail still went out once, which is what keeps this a report about
    // a codepoint rather than about a datagram: the one that lost it is on the
    // wire, and nothing behind the refused run is sent twice.
    var at: usize = 0;
    for (writer.sent[0..writer.sends]) |run| {
        try t.expect(run.contents.len <= payload.len - at);
        at += run.contents.len;
    }
    try t.expectEqual(payload.len, at);
}

test "a codepoint lost by one datagram is not put back by the next" {
    // A socket with no segmentation offers every datagram on its own, which is
    // the only shape in which a run can lose its codepoint and be followed by
    // another run: the one behind it carried the message the kernel refused
    // here. The batch lost it, and a later run going out with it does not make
    // the batch whole again — the caller decides what one datagram without a
    // codepoint means, and it can only do that if it is told.
    var payload: [8 * 10]u8 = undefined;
    for (&payload, 0..) |*byte, index| byte.* = @truncate(index);
    const send = try batch.Send.batch(&payload, 10, .ect0);
    var caps: batch.Capability = .{ .max_send_segments = 1, .max_recv_segments = 1 };
    var writer: Scripted = .{ .answers = &.{.unknown_control_message} };

    const report = try scriptedBatch(&writer, loopback, send, &caps);

    // No segmentation was ever refused here, so nothing about the batch is
    // degraded: one `sendmsg` per datagram is how this socket sends every
    // batch, not a fallback it took.
    try t.expect(!report.degraded);
    try t.expect(!report.ecnSurvived());
    try t.expectEqual(@as(?batch.Ecn, null), report.carried);

    // Every datagram went out anyway, all eight of them, none of them twice.
    // Every offer here was a send as well, which is what makes this the shape
    // where no run is ever refused and the two ledgers cannot differ.
    try t.expectEqual(@as(usize, 8), writer.sends);
    try t.expectEqual(@as(usize, 8), writer.offers);
    var at: usize = 0;
    for (writer.sent[0..writer.sends]) |run| at += run.contents.len;
    try t.expectEqual(payload.len, at);
}
