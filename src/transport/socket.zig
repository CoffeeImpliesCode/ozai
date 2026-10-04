//! The UDP socket underneath `transport/batch.zig`: a `Send` in, datagrams out.
//!
//! `batch.zig` is the specification — what a socket write may be handed, what
//! it may refuse, and which of those refusals is permanent. This file is the
//! one place under `src/` where those values meet a descriptor, and it is now
//! only the seam: the `Socket` struct, its two descriptors, the flag that says
//! it was stopped, and the six calls a caller makes on it. Everything each of
//! those calls actually does lives in one of four modules beside this one, and
//! this file's own job is to name which:
//!
//! - `ancillary.zig` — the `CMSG_*` arithmetic, the traffic-class and
//!   `UDP_GRO` codecs, and a socket address in the kernel's own layout. Pure:
//!   no descriptor, no `Io`, no syscall.
//! - `socket_send.zig` — one `sendmsg` and one errno translation, and the two
//!   passes over a batch that decide what a refused run costs.
//! - `socket_receive.zig` — one `recvmsg`, the `poll` in front of it, and the
//!   queue and the wake counter a stop leaves for the next send to clear.
//! - `socket_control.zig` — opening the two descriptors, binding and reading
//!   the name back, and the capability probe.
//!
//! The split is by responsibility and not by size, and it keeps one fact in one
//! place: `ancillary.zig` knows what a control message is, `socket_send.zig`
//! knows what a refusal costs, `socket_receive.zig` knows what a stop owes, and
//! this file knows which descriptor each of those acts on.
//!
//! # Why `std.c` and not `std.Io.net`
//!
//! `docs/DECISIONS/0002-async-substrate.md` names both gaps in the stock
//! surface, and the modules below are the answer to them:
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
//! # Where `io` is, and where it is not
//!
//! `DECISIONS/0002`: "`rt.io()` is never stored. It is a parameter to the
//! functions that need it." So `Socket` holds descriptors and no `Io`, and
//! every operation that can be cancelled takes one. What the runtime is asked
//! for is cancellation and nothing else — `Io.Threaded.checkCancel` is an
//! atomic load — because a descriptor this module opened is a descriptor no
//! `Io` backend can poll, and handing it to one would be a claim that only
//! holds for `Threaded`. The wait before a receive is a `poll` on the
//! descriptor for the same reason, and a task cancelled inside the `recvmsg`
//! is not seen until that call returns.
//!
//! The three functions that walk a socket — `sendBatch`, `walkRuns` and
//! `restart` — take the runtime before the state they walk, and reach that
//! state's operations through callbacks rather than through method calls. A
//! runtime and a descriptor are parameters of the call rather than of its
//! subject, so a runtime reads first, `Z023` is what says so, and a callback
//! last says the rest of it: the operation is the last thing named because it
//! is the only thing that varies.
//!
//! The callbacks are a privacy fact and not a taste one. `sendRun`, `discard`
//! and `clearWake` are private to this file, and a private declaration cannot
//! be named from `socket_send.zig` or `socket_receive.zig` however it is
//! reached — monomorphising over the context does not carry access across a
//! file boundary. A function pointer carries the operation without carrying
//! the access, so those three stay private and the child modules learn only
//! the operation, its arguments and what it may answer. Nothing here is
//! publicised to make the split work: `Socket`'s own surface is exactly the
//! six names and the struct it had before.
//!
//! # The second descriptor, and the wait it ends
//!
//! `Socket` owns two of them: the socket, and an `eventfd` that exists to be
//! woken. It is the first thing besides the socket this struct holds, and it
//! is here because a `poll` is asleep in the kernel — there is nowhere to
//! consult a flag from, so a wait that has to be *ended* rather than run to
//! the end of its slice needs a descriptor to become readable. An `eventfd`
//! rather than a self-pipe: one descriptor instead of two, a counter instead
//! of a byte buffer, and `EFD_SEMAPHORE` makes a read take one wake off the
//! counter rather than all of them.
//!
//! What a wake means belongs to `Socket.stop`, and its two halves are in
//! different places on purpose. `stop` raises the wake with one store and one
//! `write`; `discovery/lookup_live.zig` uses it when a lookup is cancelled.
//! The waiter owns queue cleanup, because the cancellation callback may run
//! while the socket is being polled. A send spends any remaining wake before
//! making the socket usable again.
//! The CLI's signal handler only calls `Stop.request`: it does not raise
//! this wake, so a node notices its stop at the next poll timeout.
//!
//! # The public names, and which module answers for them
//!
//! `Socket`, `Options` and the six names below are this file's surface, and
//! they are the same names they have always been: `discovery/lookup_live.zig`,
//! `node/node.zig` and three integration roots name `ControlBuffer`,
//! `SendError`, `ReceiveError`, `OpenError` and `Received` through this path,
//! and a split that moved those names would be a cutover nobody asked for.
//! Each one is declared where the responsibility is and named here, which is
//! the same thing `src/root.zig` does with `NodeId`.
//!
//! Everything else moved without a name left behind: `cmsgAlign`, `cmsgLen`,
//! `cmsgSpace`, `writeCmsg`, `readCmsg`, `readSockaddr`, `writeSockaddr`,
//! `CmsgRead`, `control_size`, `max_syscall_attempts`, `max_discarded` and
//! `max_wakes_spent` had no consumer outside this file, so each of them is
//! simply declared in the module that owns it. `ancillary` is exposed as a
//! module rather than as seven forwarded functions, so that a fuzz root can
//! drive the decoder without a second copy of the layout.
//!
//! # Linux, and only Linux
//!
//! `batch.zig` names its option numbers out of `std.os.linux` and says a
//! platform without them answers `Capability.none`. The same is true here:
//! `SOL_UDP` has no `std` spelling at all and the whole control-message path
//! below is written against the Linux `cmsghdr`. This is ozai's socket, not
//! the vendored core's — `test/vendored_invariants.zig` guards `vendor/`,
//! where neither a socket nor a libc is allowed.
//!
//! # `link_libc`, and what does not cover these files
//!
//! `socket`, `bind`, `getsockname`, `setsockopt`, `sendmsg`, `recvmsg`,
//! `eventfd`, `read`, `write` and `close` are libc's here, so an artifact that
//! calls any of them needs `linkLibC()`. Nothing above them is: the layout
//! work is arithmetic on bytes, which is why the tests beside the layout reach
//! libc's code without leaving a syscall behind. The one that names
//! `setsockopt` proves a refusal, and the refusal comes before the call.
//!
//! The other half of that was a gate that did not exist. Zig analyses a
//! function body when it is called, not when it is referenced, so
//! `std.testing.refAllDecls` checks the *signatures* of these declarations and
//! none of the bodies below them — `create`, `send`, `recvmsg`, the probes.
//! The whole syscall layer went uncompiled until
//! `test/integration_test.zig` opened a socket on loopback, and `build.zig`
//! puts `link_libc` on the module that runs it, so removing either half turns
//! into a link error rather than a silent hole.

const std = @import("std");
const batch = @import("batch.zig");
const base_addr = @import("../base/addr.zig");

const c = std.c;
const linux = std.os.linux;

/// The pure half: control messages and addresses, in the kernel's own layout.
pub const ancillary = @import("ancillary.zig");

/// The descriptors, and the capability probe. Spelled out rather than
/// abbreviated, because `control` is the name a receive buffer's local
/// carries in this file and Zig 0.16 refuses a declaration that shadows one.
const socket_control = @import("socket_control.zig");

/// The send path: one `sendmsg`, and the passes over a batch.
const send_path = @import("socket_send.zig");

/// The receive path: one `recvmsg`, the `poll`, and the stop's cleanup.
const recv_path = @import("socket_receive.zig");

/// The bytes a caller hands a receive for the kernel's control messages, and the
/// alignment the kernel writes their headers at. Declared in `ancillary.zig`
/// and named here because `discovery/lookup_live.zig`, `node/node.zig` and
/// three integration roots hold one.
pub const ControlBuffer = ancillary.ControlBuffer;

/// Why a send did not go out. Declared in `socket_send.zig`.
pub const SendError = send_path.SendError;

/// Why a receive did not produce a datagram. Declared in
/// `socket_receive.zig`.
pub const ReceiveError = recv_path.ReceiveError;

/// One datagram, or a list coalesced into one buffer. Declared in
/// `socket_receive.zig`.
pub const Received = recv_path.Received;

/// Why a socket could not be opened. Declared in `socket_control.zig`.
pub const OpenError = socket_control.OpenError;

/// What to set on a socket before the bind.
pub const Options = struct {
    /// `SO_REUSEADDR`, for a rebind inside the reuse window. On by default
    /// because an endpoint that comes back on the port it held is the case it
    /// exists for, and it costs nothing when nothing else is bound there.
    reuse_addr: bool = true,
    /// `SO_REUSEPORT`, for a v4 and a v6 socket sharing one port. Off by
    /// default: it lets a second descriptor take the same address and port
    /// and a share of the datagrams, which is a decision to make on purpose.
    reuse_port: bool = false,
};

/// A bound UDP socket that speaks `batch`.
///
/// No `Io` is stored, for the reason `DECISIONS/0002` gives. No buffer is
/// either: the receive buffer and the control buffer are the caller's, which
/// is what lets a stack pool them and what lets a test hand over a stack
/// array. Two descriptors and one flag, and every one of the three is about
/// being stopped rather than about carrying a datagram; see `stop`.
///
/// A successful `create` owns both descriptors. Close them exactly once after
/// all operations and stop callers finish. Copies share those descriptors.
/// Keep the value at a stable address while a lookup or stop caller borrows it.
/// Serialize sends and receives. Only `stop` may run concurrently with them.
/// An operation borrows `io` and its backend only until the operation returns.
pub const Socket = struct {
    /// The descriptor. `O_NONBLOCK` from the moment it exists, which is what
    /// makes `EAGAIN` a fact a caller can act on instead of a stall.
    handle: c.fd_t,
    /// The descriptor a stop writes to, in the same `poll` set as `handle`
    /// and the only thing that can end a wait before its timeout. The first
    /// descriptor this struct owns that is not the socket.
    wake: c.fd_t,
    /// Set by `stop` and cleared by the next send, which drains on its way
    /// past. Between the two, nothing arriving on this descriptor is an
    /// answer to anything.
    stopped: std.atomic.Value(bool),
    /// Which control message carries the codepoint here.
    family: batch.Family,
    /// Capabilities observed at creation and downgraded after refused sends.
    /// A driver that cannot segment is found by sending; a cap is never raised.
    caps: batch.Capability,
    /// Where it is bound, with the ephemeral port the kernel chose written in.
    address: base_addr.SocketAddr,

    /// Open a socket on `address`, set the options, ask what it can do, and
    /// bind.
    ///
    /// The probe runs here and only here. A `Capability` that is guessed
    /// rather than asked is worse than none, because a driver that quietly
    /// ignores `UDP_SEGMENT` turns every batch into a stalled path and
    /// nothing reports it.
    pub fn create(address: base_addr.SocketAddr, options: Options) OpenError!Socket {
        const family: batch.Family = batch.Family.of(address.ip);
        const handle = try socket_control.createSocket(family);
        errdefer _ = c.close(handle);
        // Reuse options first and the congestion option after, because both
        // take effect before the bind: the port is not the socket's until
        // `bind` answers.
        if (options.reuse_addr) {
            socket_control.setFlag(handle, linux.SOL.SOCKET, linux.SO.REUSEADDR, true) catch |err| {
                return socket_control.openFromOption(err);
            };
        }
        if (options.reuse_port) {
            socket_control.setFlag(handle, linux.SOL.SOCKET, linux.SO.REUSEPORT, true) catch |err| {
                return socket_control.openFromOption(err);
            };
        }
        const caps = try socket_control.probe(handle, family);
        // After the probe: a socket refused on its own options never reached
        // the point of having a wait to wake.
        const wake = try socket_control.createWake();
        errdefer _ = c.close(wake);
        var name: c.sockaddr.storage = undefined;
        const length = ancillary.writeSockaddr(address, &name);
        try socket_control.bindSocket(handle, &name, length);
        return .{
            .handle = handle,
            .wake = wake,
            .stopped = .init(false),
            .family = family,
            .caps = caps,
            .address = try socket_control.boundAddress(handle),
        };
    }

    /// Close both descriptors. Nothing is buffered on this side: a send that
    /// returned has left the socket, and a read that returned has been taken.
    /// Do not close a copy or call this twice. Neither descriptor is reset.
    pub fn close(self: *Socket) void {
        _ = c.close(self.wake);
        _ = c.close(self.handle);
    }

    /// Name this socket stopped: end the wait in flight, and leave the queue
    /// as though nothing had ever been asked of it.
    ///
    /// A socket outlives whatever stopped it — it is the caller's, and the
    /// next request on this descriptor is the whole reason it is not closed —
    /// so this is not a latch. It is a message: a wait in flight ends at once,
    /// the queue is emptied, and nothing that arrives is wanted until a
    /// datagram goes out. That last part is what leaves the socket usable,
    /// because nothing queued before the next send can be an answer to it, and
    /// it is deliberately not a `shutdown` — which would answer that next
    /// request with a descriptor no read will ever work on again.
    ///
    /// Everything this body does is something a signal handler may do: one
    /// store and one `write`, both on POSIX's list of calls such a handler is
    /// allowed to make. The queue is emptied by the wait this wakes and by the
    /// next send, because `recvmsg` is not on that list.
    ///
    /// Keep the socket alive and open until every concurrent stop returns.
    pub fn stop(self: *Socket) void {
        self.stopped.store(true, .release);
        var one: u64 = 1;
        _ = c.write(self.wake, std.mem.asBytes(&one), recv_path.wake_width);
    }

    // A method's receiver is its first parameter, so `io` comes second on
    // every operation that needs the runtime — which is all of them except
    // `stop`, and that is the one a signal handler may call.
    // `docs/DECISIONS/0002-async-substrate.md` wants the runtime threaded
    // rather than stored and does not say which position it takes, and every
    // other method on every other type in this project puts its receiver
    // first.

    /// Send `payload` to `dest` and say what it carried.
    ///
    /// One `sendmsg` per `batch.Runs` run, the segmentation control message
    /// on exactly the runs that are segmented, and the traffic class on every
    /// one — the model's own order, from `batch.cmsg`. A run of one datagram
    /// carries no segment size whatever the batch was, which is the fallback
    /// `DECISIONS/0002` promised and which `Report.degraded` makes visible
    /// instead of silent.
    ///
    /// **Every datagram this call sends reaches the wire once.** A run refused
    /// for segmentation lowers the socket's capability for good and is
    /// answered by sending that run and the runs behind it, one datagram per
    /// `sendmsg`; the runs before it are already on the wire and are not sent
    /// again. A codepoint the retried tail lost is reported as lost, because
    /// the datagram carrying it has gone and no retry can put it back.
    ///
    /// The call is nonblocking and borrows `payload.contents` only for the
    /// call. `error.Canceled` is forwarded. On error, earlier runs may already
    /// have left the socket. No sent-prefix count is returned. Do not replay a
    /// batch unless the protocol tolerates duplicates.
    pub fn send(
        self: *Socket,
        io: std.Io,
        dest: base_addr.SocketAddr,
        payload: batch.Send,
    ) SendError!batch.Report {
        try io.checkCancel();
        // What a stop leaves behind is dealt with first, and it is a whole of
        // its own: `restart` drains the queue and spends the wake. Both it and
        // the batch below are handed this socket's private operations as
        // callbacks, because a private declaration of this file cannot be
        // named from theirs — so passing them is the whole of what those two
        // signatures are allowed to know about a socket.
        // The type argument is the receiver type each callback declares, not
        // the struct behind it, and a function pointer type has to match its
        // parameters exactly: all three of these take a `*Socket`.
        try recv_path.restart(*Socket, Socket.discard, Socket.clearWake, io, self);
        return send_path.sendBatch(*Socket, Socket.sendRun, io, self, dest, payload, &self.caps);
    }

    /// Take whatever is queued, or answer that nothing is.
    ///
    /// `error.WouldBlock` is a value and not a failure: the socket has been
    /// non-blocking since it was opened, and a caller with nothing else to do
    /// is the one that decides what an empty queue means.
    ///
    /// The returned bytes borrow `buffer`, not `control_buffer`. Both buffers
    /// may be overwritten even on error. A truncation error consumes the
    /// datagram. `error.Canceled` is forwarded. This call does not wait for
    /// readiness.
    pub fn tryReceive(
        self: *const Socket,
        io: std.Io,
        buffer: []u8,
        control_buffer: *ControlBuffer,
    ) ReceiveError!Received {
        return recv_path.recvmsg(io, self.handle, buffer, control_buffer);
    }

    /// Wait for a datagram and take it. A `timeout_ms` of null waits as long
    /// as the caller means, and time stays the caller's: this reads no clock.
    ///
    /// Zero polls once. Negative values, like `null`, wait without a deadline.
    /// A timeout returns `error.WouldBlock`. `stop` wakes a blocked poll with
    /// `error.Canceled`. An `io` cancellation is checked around the syscalls,
    /// but does not itself wake the poll. Result and error residue follow
    /// `tryReceive`.
    pub fn receive(
        self: *const Socket,
        io: std.Io,
        buffer: []u8,
        control_buffer: *ControlBuffer,
        timeout_ms: ?i32,
    ) ReceiveError!Received {
        try recv_path.awaitReadable(io, self.handle, self.wake, timeout_ms);
        return recv_path.recvmsg(io, self.handle, buffer, control_buffer);
    }

    // One `sendmsg` per run of `payload` is `walkRuns`, and the two passes
    // deciding what a refused batch costs is `sendBatch`; both are functions
    // of their writer rather than methods, and this is where the batch ends.

    /// One run, and what it cost.
    ///
    /// This is the writer `sendBatch` walks its runs with, and the one place
    /// the descriptor, the destination's address and the control messages all
    /// meet: the address goes into the kernel's layout here, the messages come
    /// out of `ancillary.writeCmsg` into this frame's `ControlBuffer`, and the
    /// syscall itself is `socket_send.zig`'s. What is left here is the policy
    /// that has no other home — which refusal of which run is worth retrying
    /// without a control message, and which is not.
    fn sendRun(
        self: *Socket,
        io: std.Io,
        dest: base_addr.SocketAddr,
        run: batch.Send,
    ) SendError!batch.Refused {
        const family: batch.Family = batch.Family.of(dest.ip);
        var name: c.sockaddr.storage = undefined;
        const name_length = ancillary.writeSockaddr(dest, &name);
        var messages: [batch.max_cmsg]batch.Cmsg = undefined;
        var control_buffer: ControlBuffer = undefined;
        const listed = batch.cmsg(run, family, &messages);
        const written = try ancillary.writeCmsg(listed, &control_buffer);
        const sent = try send_path.sendmsg(
            io,
            self.handle,
            run.contents,
            &name,
            name_length,
            written,
        );
        if (sent == .accepted) return .none;
        // `EIO` and `EINVAL` are one answer from the kernel and two from here.
        // Only a run the segment size made segmented can be refused for
        // segmentation, and only an IPv4 run has a control message this module
        // is willing to drop — `IPV6_TCLASS` and `UDP_SEGMENT` are core
        // options, so an unknown-control-message `EINVAL` is about the newest
        // of the three (`noq-udp/src/unix.rs:608-630`).
        if (run.isSegmented()) return .segmentation;
        if (family != .v4) return error.UnknownControlMessage;
        const retried = try send_path.sendmsg(
            io,
            self.handle,
            run.contents,
            &name,
            name_length,
            written[0..0],
        );
        if (retried == .accepted) return .unknown_control_message;
        return error.UnknownControlMessage;
    }

    /// Take the queue: the drain a stop recovery runs first.
    ///
    /// The queue is `handle`'s and the counter is `wake`'s, and those are two
    /// different descriptors: `socket_receive.restart` is written against
    /// whichever socket it is handed, and this is the one that says which of
    /// them each of its two steps acts on. It stays private and reaches
    /// `restart` as its `drain_callback`, which is how a module that must not
    /// name it still gets to call it. The tests below hand `restart` a
    /// different writer to raise a stop inside one of the windows.
    /// Neither this nor `clearWake` writes through the socket, but both take a
    /// mutable receiver because the recovery that calls them does: it raises
    /// `stop` on the same value, and a callback type has to match its receiver
    /// exactly, so `*Socket` is what the recovery's state parameter is.
    fn discard(
        self: *Socket,
        io: std.Io,
    ) recv_path.RestartError!void {
        return recv_path.discard(io, self.handle);
    }

    /// Spend the counter, for the same recovery and as its
    /// `spend_wake_callback`.
    fn clearWake(self: *Socket) error{Interrupted}!void {
        return recv_path.clearWake(self.wake);
    }
};

// 79 display columns; the rule counts UTF-8 bytes, three per box character.
// ziglint-ignore: Z024
// ──────────────────────────────────────────────────────── a stop, on a socket
//
// The wake descriptor is a claim about two descriptors and a `poll` set, and a
// claim about descriptors is worth only what the kernel says about them. Every
// other test in this module's neighbourhood stays above the syscall on purpose;
// this one does not, because there is nothing above the syscall to ask.

const t = std.testing;

/// Loopback on an ephemeral port, so the kernel picks and two tests at once
/// cannot collide. The spelling `test/loopback_test.zig` uses.
const loopback: base_addr.SocketAddr = .{ .ip = .{ .v4 = .{ 127, 0, 0, 1 } }, .port = 0 };

test "a stop ends its wait, and the next query out takes the queue with it" {
    var server = try Socket.create(loopback, .{});
    defer server.close();
    var client = try Socket.create(loopback, .{});
    defer client.close();
    var untouched = try Socket.create(loopback, .{});
    defer untouched.close();
    var buffer: [64]u8 = undefined;
    var control: ControlBuffer = undefined;
    const straggler = "the answer to a query nobody is waiting for";
    const query = "the next query";

    // What a stop has to deal with, shown first where nothing has stopped
    // anything: on loopback the kernel has the datagram queued by the time
    // `sendmsg` answers, and a read finds it. Without this the `WouldBlock` at
    // the end of the test would be satisfied just as well by nothing having
    // been queued in the first place.
    _ = try server.send(t.io, untouched.address, batch.Send.single(straggler, null));
    const found = try untouched.tryReceive(t.io, &buffer, &control);
    try t.expectEqualStrings(straggler, found.bytes);

    // The wait the stop is aimed at. Five seconds, and it ends long before
    // that: nothing was sent to this socket and nothing can be, so the only
    // thing that can end the wait is the descriptor `stop` wrote to. Leave it
    // out of the `poll` set and this is a wait that runs out and answers
    // `WouldBlock` — a deadline reported for a cancellation that had already
    // been asked for.
    client.stop();
    try t.expectError(error.Canceled, client.receive(t.io, &buffer, &control, 5000));

    // The answer, arriving after the stop. It is the send below that takes it,
    // not the wait above, because nothing was waiting when it landed: a
    // datagram queued before the next query went out cannot be that query's
    // answer, whichever of the two arrived first.
    _ = try server.send(t.io, client.address, batch.Send.single(straggler, null));
    _ = try client.send(t.io, server.address, batch.Send.single(query, null));
    try t.expectError(error.WouldBlock, client.tryReceive(t.io, &buffer, &control));

    // And the socket is the caller's again. The wake was spent with the stop,
    // so this wait waits instead of being ended by one already dealt with, and
    // fifty milliseconds is long enough for a datagram sent first to be there.
    _ = try server.send(t.io, client.address, batch.Send.single(query, null));
    const read = try client.receive(t.io, &buffer, &control, 50);
    try t.expectEqualStrings(query, read.bytes);
    try t.expectEqual(server.address, read.from);
}

test "a stop drains every queued datagram, and the next answer is not a leftover" {
    var server = try Socket.create(loopback, .{});
    defer server.close();
    var client = try Socket.create(loopback, .{});
    defer client.close();
    var buffer: [64]u8 = undefined;
    var control: ControlBuffer = undefined;
    const first = "the answer to a query nobody is waiting for";
    const second = "and the answer to the query after it";
    const query = "the next query";
    const answer = "this query's own answer";

    // Both stragglers are real datagrams, shown first where nothing has
    // stopped anything, so the `WouldBlock` below can only be the queue
    // having been drained rather than never having been filled.
    var untouched = try Socket.create(loopback, .{});
    defer untouched.close();
    _ = try server.send(t.io, untouched.address, batch.Send.single(first, null));
    _ = try server.send(t.io, untouched.address, batch.Send.single(second, null));
    try t.expectEqualStrings(first, (try untouched.tryReceive(t.io, &buffer, &control)).bytes);
    try t.expectEqualStrings(second, (try untouched.tryReceive(t.io, &buffer, &control)).bytes);

    // The same two queued on the socket that is about to be stopped. A stop
    // empties the queue, and two datagrams is the smallest case that can
    // tell emptying it from emptying only the first datagram it read: a
    // drain that stops after one leaves the second, and that second is
    // exactly what the receive at the end would report as the answer.
    _ = try server.send(t.io, client.address, batch.Send.single(first, null));
    _ = try server.send(t.io, client.address, batch.Send.single(second, null));
    client.stop();

    // The send is the drain: this is where a stopped socket becomes usable
    // again, and everything the stop found queued goes with it. `WouldBlock`
    // is the only answer that says the queue is empty rather than that a
    // leftover duplicate is waiting in it.
    _ = try client.send(t.io, server.address, batch.Send.single(query, null));
    try t.expectError(error.WouldBlock, client.tryReceive(t.io, &buffer, &control));

    // And the answer to the query that just went out is the next thing read,
    // from the peer that was asked. Fifty milliseconds bounds the wait; the
    // datagram is already queued by the time `sendmsg` above returned, so the
    // criterion is the bytes and not the clock.
    _ = try server.send(t.io, client.address, batch.Send.single(answer, null));
    const read = try client.receive(t.io, &buffer, &control, 50);
    try t.expectEqualStrings(answer, read.bytes);
    try t.expectEqual(server.address, read.from);
}

test "two stops leave no wake standing for the receive that follows the send" {
    var server = try Socket.create(loopback, .{});
    defer server.close();
    var client = try Socket.create(loopback, .{});
    defer client.close();
    var buffer: [64]u8 = undefined;
    var control: ControlBuffer = undefined;
    const query = "the query the send carries";
    const answer = "this query's own answer";

    // The wake descriptor is an `eventfd` in semaphore mode: each `stop` adds
    // one unit to the counter and each read takes one off. Two stops leave two
    // units standing, and the send that resets the stop has to spend both. A
    // unit left behind is a wake nobody asked for, and it ends the next wait
    // exactly the way a real stop would.
    client.stop();
    client.stop();

    // The send resets the stop, spending the counter as it goes, and carries
    // the query whatever the two stops were about.
    _ = try client.send(t.io, server.address, batch.Send.single(query, null));

    // The answer to the query that just went out. With the counter empty the
    // wait ends on the datagram and reads it; with a unit still standing the
    // wait ends on the wake instead and reports `Canceled` for a stop the send
    // has already dealt with — and takes the answer with it.
    _ = try server.send(t.io, client.address, batch.Send.single(answer, null));
    const read = try client.receive(t.io, &buffer, &control, 50);
    try t.expectEqualStrings(answer, read.bytes);
    try t.expectEqual(server.address, read.from);
}

test "a queue or a counter past its bound is refused, and the next send takes it" {
    var server = try Socket.create(loopback, .{});
    defer server.close();
    var client = try Socket.create(loopback, .{});
    defer client.close();
    var buffer: [64]u8 = undefined;
    var control: ControlBuffer = undefined;
    const query = "the query the send carries";
    const answer = "this query's own answer";
    // One byte, so the whole queue this fills costs the kernel a fraction of
    // the receive buffer it opens with: the datagrams have to be *queued*,
    // and a queue the kernel dropped some of would make the bounds below
    // unreachable rather than wrong.
    const filler = [_]u8{0x5a};

    // One datagram past `max_discarded`, which is the depth at which a drain
    // can no longer promise the queue is empty. The bound is on the datagrams
    // and not on the syscalls, so the read that finds the queue still deep is
    // the one that has to refuse.
    for (0..recv_path.max_discarded + 1) |_| {
        _ = try server.send(t.io, client.address, batch.Send.single(&filler, null));
    }
    client.stop();

    // Nothing goes out on a refused cleanup, and the socket stays stopped
    // rather than clean with a straggler in it: that straggler was queued
    // before this query went out, so reading it as the answer is the fault
    // the bound exists to prevent.
    try t.expectError(
        error.Interrupted,
        client.send(t.io, server.address, batch.Send.single(query, null)),
    );

    // The next send drains the rest and carries the query, and `WouldBlock`
    // after it says the queue really is empty — not merely emptied as far as
    // one call's bound goes.
    _ = try client.send(t.io, server.address, batch.Send.single(query, null));
    try t.expectError(error.WouldBlock, client.tryReceive(t.io, &buffer, &control));

    // The same bound on the counter, one `stop` past `max_wakes_spent`. A unit
    // left standing is a wake nobody asked for, and it ends the next wait the
    // way a real stop would, so a counter this deep is refused for the same
    // reason and dealt with by the same retry. Nothing is queued here, which
    // is what makes this the counter's bound and not the queue's.
    for (0..recv_path.max_wakes_spent + 1) |_| client.stop();
    try t.expectError(
        error.Interrupted,
        client.send(t.io, server.address, batch.Send.single(query, null)),
    );

    // And the answer is what the wait after that reads, which is the whole of
    // what spending the counter is for: with a unit still on it the wait would
    // end on the wake and answer `Canceled` for a stop the send has dealt
    // with, taking the answer with it.
    _ = try client.send(t.io, server.address, batch.Send.single(query, null));
    _ = try server.send(t.io, client.address, batch.Send.single(answer, null));
    const read = try client.receive(t.io, &buffer, &control, 50);
    try t.expectEqualStrings(answer, read.bytes);
    try t.expectEqual(server.address, read.from);
}

/// A recovery with a real stop raised inside it.
///
/// The windows are the two moments between taking the queue and the send being
/// a send again, and the only thing that happens in either of them in
/// production is another task's `Socket.stop`. So the test raises one there —
/// on a real socket, with a real drain and a real counter — rather than
/// describing one and asserting the description back.
const StopWindow = enum {
    /// After the drain and before the flag is cleared: the stop has set the
    /// flag again and the line that clears it is next.
    drain,
    /// After the flag is cleared and before the counter is emptied: the check
    /// that decides whether to empty it has answered, and this stop's unit is
    /// the one the read about to take.
    wake,
};

const StopDuringRecovery = struct {
    /// The real socket, so every call below is the real one.
    socket: *Socket,
    /// The real flag, borrowed rather than copied: an atomic copied out of the
    /// socket it belongs to is a second flag, and the whole question here is
    /// what the socket's own flag says.
    stopped: *std.atomic.Value(bool),
    /// Which of the two windows this run raises its stop in.
    window: StopWindow,

    /// The drain a recovery runs first, with this window's stop raised the
    /// moment the drain returns — which is what a second task's `stop` does
    /// while the queue is being taken.
    fn discard(
        self: *StopDuringRecovery,
        io: std.Io,
    ) recv_path.RestartError!void {
        try self.socket.discard(io);
        if (self.window == .drain) self.socket.stop();
    }

    /// The counter spend, with this window's stop raised the moment the check
    /// has answered — so the unit about to be read is the one that stop wrote.
    fn clearWake(self: *StopDuringRecovery) error{Interrupted}!void {
        if (self.window == .wake) self.socket.stop();
        return self.socket.clearWake();
    }

    /// The socket's own way of raising a wake, which a recovery that owes a
    /// waiter one has to use rather than write its own.
    pub fn stop(self: *StopDuringRecovery) void {
        self.socket.stop();
    }
};

/// What a stop raised inside the recovery must leave behind, in either window:
/// the flag up, and a wake unit standing for it.
///
/// Both halves are needed and neither is enough. A flag that went down loses
/// the stop outright — nothing queued after it would ever be drained again. A
/// unit spent for it leaves a wait that nothing ends, because `awaitReadable`
/// reads the wake descriptor and nothing else.
fn expectStopSurviving(window: StopWindow) !void {
    var speaker = try Socket.create(loopback, .{});
    defer speaker.close();
    var socket = try Socket.create(loopback, .{});
    defer socket.close();
    var buffer: [64]u8 = undefined;
    var control: ControlBuffer = undefined;
    const straggler = "the answer to a query nobody is waiting for";

    // A stopped socket with something queued is the state the recovery exists
    // for: the queue goes with the stop, and the wake that stop left is spent
    // so the wait after this send is not woken for a stop already dealt with.
    _ = try speaker.send(t.io, socket.address, batch.Send.single(straggler, null));
    socket.stop();
    var recovery: StopDuringRecovery = .{
        .socket = &socket,
        .stopped = &socket.stopped,
        .window = window,
    };

    try recv_path.restart(
        *StopDuringRecovery,
        StopDuringRecovery.discard,
        StopDuringRecovery.clearWake,
        t.io,
        &recovery,
    );

    try t.expect(socket.stopped.load(.acquire));

    // Claiming the flag the way a send would leaves exactly what a live stop
    // leaves: an empty queue and one unit for it. The quarter of a second is
    // only there so that a unit which is *not* standing fails in a quarter of
    // a second rather than in five — a unit that is standing ends the wait on
    // the descriptor, with no clock involved at all.
    _ = socket.stopped.swap(false, .acq_rel);
    try t.expectError(error.Canceled, socket.receive(t.io, &buffer, &control, 250));
    try t.expectError(error.WouldBlock, socket.tryReceive(t.io, &buffer, &control));
}

// Two tests and not one with two cases: a case that fails stops the test
// before the next one runs, and these two fail for different reasons — one
// loses the flag, the other loses only the wake — so a single test would
// report the first and hide the second.
test "a stop raised after the drain survives the recovery" {
    try expectStopSurviving(.drain);
}

test "a stop raised as the counter is emptied survives the recovery" {
    try expectStopSurviving(.wake);
}

// 79 display columns; the rule counts UTF-8 bytes, three per box character.
// ziglint-ignore: Z024
// ──────────────────────────────────────────────────────── a batch, on loopback
//
// A duplicate datagram is a fact about the wire and not about a return value:
// a policy that re-sends a run the kernel already took reports the same batch
// and hands its caller the same `Report`, and the only place a second copy of
// a datagram exists is the socket at the other end of it. So this one sends
// for real and reads back what arrived, which is the one claim the scripted
// policy tests in `socket_send.zig` cannot make on their own.

/// The most bytes one read may hand back: `UDP_GRO_CNT_MAX` coalesced
/// datagrams of the kilobyte this section sends.
///
/// The count is promoted before the product rather than after it, because it
/// is a `u16` of segments and 64 of them at 1024 bytes is 65536 — one past
/// the largest value the count it came from can hold.
const max_read_bytes: usize = @as(usize, batch.max_gro_segments_linux) * 1024;

test "a batch reaches the wire as its datagrams, once each" {
    var sender = try Socket.create(loopback, .{});
    defer sender.close();
    var receiver = try Socket.create(loopback, .{});
    defer receiver.close();
    // A read this socket hands back may be coalesced: `UDP_GRO` puts as many
    // equal datagrams in one buffer as it is willing to coalesce, each as long
    // as the datagram it took, and a buffer shorter than that gets a read
    // truncated — which `recvmsg` reports as `MSG_TRUNC` and this module as
    // `MessageTooLarge`. Sized for the largest coalesced read rather than for
    // what the sender happened to write.
    var buffer: [max_read_bytes]u8 = undefined;
    var control: ControlBuffer = undefined;

    // Seventy datagrams of a kilobyte: more than one run's worth at this
    // segment size, so the socket has to take the fallback or answer with
    // several `sendmsg`s, and every datagram is filled with its own index so
    // that one which arrives twice is visible in the bytes and not only in the
    // count.
    const datagrams = 70;
    var payload: [datagrams * 1024]u8 = undefined;
    for (&payload, 0..) |*byte, index| byte.* = @truncate(index / 1024);

    const sent = try batch.Send.batch(&payload, 1024, .ect0);
    const report = try sender.send(t.io, receiver.address, sent);
    // The codepoint is on every run this module writes, including a fallback's,
    // so a send that reports it lost lost it to a kernel that refused the
    // message rather than to the degradation below.
    try t.expect(report.ecnSurvived());
    try t.expectEqual(@as(?batch.Ecn, .ect0), report.carried);

    // Everything the kernel has, and no more: a datagram sent twice is twice
    // on this wire, and a receiver that stopped at the expected count would
    // step over the second copy rather than see it. The queue is empty when
    // the reads end, and it was filled before `send` returned.
    var seen: usize = 0;
    while (true) {
        const read = receiver.tryReceive(t.io, &buffer, &control) catch |err| switch (err) {
            error.WouldBlock => break,
            else => return err,
        };
        const coalesced = try read.toRecv();
        for (0..coalesced.datagramCount()) |index| {
            const datagram = coalesced.datagram(index) orelse return error.TestUnexpectedResult;
            try t.expect(seen < datagrams);
            try t.expectEqualSlices(u8, payload[seen * 1024 ..][0..datagram.len], datagram);
            seen += 1;
        }
    }
    try t.expectEqual(@as(usize, datagrams), seen);
}
