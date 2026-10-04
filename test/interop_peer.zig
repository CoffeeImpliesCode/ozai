//! `ozai-interop-peer`: one end of a live interoperability exchange with the
//! Rust partner in `test/rust_partner/`.
//!
//! Everything above `transport/socket.zig` in this project has been tested
//! against itself. `test/loopback_test.zig` runs two endpoints in one process,
//! `test/two_process_test.zig` runs several `ozai-node` processes against each
//! other, and neither has ever put a byte through a QUIC stack this project did
//! not write. Until this program ran, the claim that `src/transport/` speaks
//! iroh's dialect of RFC 9000 and RFC 9221 was an argument from a spec.
//!
//! So this is the program that makes the claim testable. It is a **consumer**,
//! not a second implementation: it opens a real UDP socket, drives the real
//! `Bridge`, dials with the real `Dialer` when it is the dialling end, and
//! speaks the partner's command line so that a reader comparing two runs is
//! comparing two ends of one exchange and not two programs that each did their
//! own thing.
//!
//! # What it prints, and when
//!
//! The output vocabulary is the partner's, deliberately and exactly: `node`,
//! `listening`, `ready`, `dialling`, `connected`, `negotiated_alpn`, `sent_*`,
//! `received_*`, `verified_*`, and `done` or `success`. A script that can read
//! one can read the other, and `test/rust_partner/` is not modified to make that
//! true — it is true because both programs implement the same contract.
//!
//! **The banner is flushed before the first wait on the network.** A listener
//! prints its address and `ready` and returns to the kernel immediately, because
//! a supervising script cannot learn an ephemeral port from a pipe that has not
//! been flushed yet. The same applies to `connected` and `negotiated_alpn`: a
//! script watching for the handshake to complete has to see those lines while
//! this process is still running, not in a buffer flushed at exit.
//!
//! # Exit status is the verdict
//!
//! - **0** — every *declared* payload was verified byte for byte.
//! - **2** — the command line was refused, and the reason and the flag list went
//!   to **stderr**. This is the program's own code and deliberately not the
//!   partner's: `iroh-partner` answers `ExitCode::FAILURE` for every `Err`, and a
//!   command line it will not run is one, so it exits **1** where this program
//!   exits 2 — a script that reads the status alone tells this refusal from
//!   anything the partner exits with.
//! - **1** — everything else: a payload mismatch, a deadline, a refusal from the
//!   transport, or a teardown that could not complete.
//!
//! Zero is reachable only through `Scenario.complete`, which requires every
//! declared expectation to have matched **and** every declared send to have gone
//! out. There is no path from a partial run to a zero: the loop below returns
//! `error.DeadlineReached` rather than falling out of it, and the deadline is
//! measured against the monotonic clock rather than against a pass count, so a
//! run cannot succeed by being slow.
//!
//! # How the exchange ends
//!
//! **The dialling end closes and the listening end waits**, because those are the
//! two things the wire needs and they are not interchangeable. A dialer's
//! scenario completes by having read the listener's answer, so a
//! `CONNECTION_CLOSE` from it with application error 0 (RFC 9000 §10.2.3) says
//! "I have everything" with nothing behind it on the wire. A listener has just
//! written an answer of its own, and a close from there could take the
//! connection down while that answer is still in the core, so it waits for the
//! peer's close instead. Without a close on the dialling end, the partner's
//! listener spends its whole timeout finding out that nobody said goodbye.
//!
//! # The capture is a runtime input, not a build input
//!
//! `--capture <dir>` tees every datagram this socket sends and receives to disk,
//! taken before `Bridge.recv` is asked to parse anything. Nothing here
//! synthesises a vector or repairs a datagram: `test/corpus/rust_wire/` holds
//! only what a real run emitted, and it is non-empty now because one did —
//! `provenance.json` there records which run, and `rust_wire_initial_test.zig`
//! reads the capture back. That is the point of `AGENTS.md` §2's "wire
//! compatibility is a test, not a comment".

const std = @import("std");
const ozai = @import("ozai");

const options = @import("interop_options.zig");
const runtime = @import("interop_runtime.zig");
const transfer = @import("interop_transfer.zig");

const NodeId = ozai.NodeId;
const SecretKey = ozai.SecretKey;
const SocketAddr = ozai.SocketAddr;

/// The vendored QUIC core logs every handshake step at `info` and every
/// received frame at `debug`, which is right for a library with no opinion and
/// wrong for a program whose report is a dozen lines. `std_options` in the root
/// is what a program has to say; a library must not, because it would be
/// deciding for every importer that imported it.
pub const std_options: std.Options = .{ .log_level = .warn };

/// What this program is refused with, beyond what its three modules publish.
///
/// Two names of its own, and they are the two a supervising script most needs to
/// tell apart: a scenario that ran out of time, and a run that was told to stop.
const Error = options.ParseError || runtime.Error || transfer.Error ||
    std.Io.Writer.Error || std.mem.Allocator.Error ||
    std.process.Args.ToSliceError || error{
    /// The scenario did not complete within `--timeout-ms`. The peer either
    /// never arrived, refused this end's pin or ALPN, or stalled mid-
    /// exchange; the counters printed with it say which of those it was.
    DeadlineReached,
    /// `SIGINT` or `SIGTERM` arrived before the scenario finished, so this
    /// run did not verify anything it was asked to.
    Stopped,
};

/// The stop signal, at file scope because a C signal handler is handed nothing
/// but the signal number.
///
/// `src/node/main.zig`'s reason, unchanged: the library holds no global, no
/// `std.Io` and no clock, and the program edge is the only place a process-wide
/// handle belongs.
var stopped = std.atomic.Value(bool).init(false);

/// The signals a process is asked to stop on. `SIGTERM` is here because a
/// supervisor's stop is a `SIGTERM` and a binary that only answers `SIGINT` has
/// to be killed.
const stop_signals = [_]std.posix.SIG{ .INT, .TERM };

/// A `SIGINT` or a `SIGTERM`: set the flag and return.
///
/// Async-signal-safe, because the store is one atomic and nothing else.
fn onSignal(sig: std.posix.SIG) callconv(.c) void {
    _ = sig;
    stopped.store(true, .release);
}

/// Ask to be stopped on both, replacing the default action. The default for
/// `SIGTERM` is to die, and dying mid-exchange leaves a peer's connection to
/// time out rather than being told.
fn watchForStop() void {
    const act: std.posix.Sigaction = .{
        .handler = .{ .handler = onSignal },
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    };
    for (stop_signals) |sig| std.posix.sigaction(sig, &act, null);
}

pub fn main(init: std.process.Init) !void {
    var out_buffer: [1024]u8 = undefined;
    var out = std.Io.File.stdout().writerStreaming(init.io, &out_buffer);
    const text = &out.interface;
    var err_buffer: [512]u8 = undefined;
    var err_out = std.Io.File.stderr().writerStreaming(init.io, &err_buffer);
    const err_text = &err_out.interface;

    // The flag list is parsed into a buffer rather than written straight to a
    // stream, because its two answers belong on different ones and the parser
    // cannot know which one it is about to give: `--help` is this program
    // answering and goes to stdout, a refusal is it objecting and goes to
    // stderr. A parser that had to know that would own where a message goes,
    // and the program is what owns both streams.
    var usage_buffer: [usage_room]u8 = undefined;
    var usage = std.Io.Writer.fixed(&usage_buffer);

    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const parsed = try options.parse(init.arena.allocator(), args, &usage);
    const parsed_options = switch (parsed) {
        .help => {
            try text.writeAll(usage.buffered());
            try out.flush();
            return;
        },
        // The program's own objection, on the stream it belongs to. Status 2 is
        // `refuse`'s to set, so there is nothing for this arm to hand back.
        .rejected => refuse(err_text, usage.buffered()),
        .run => |configured| configured,
    };

    watchForStop();
    const verdict = run(init.gpa, init.io, parsed_options, text, err_text) catch |err| {
        try out.flush();
        try err_text.print("error: {t}\n", .{err});
        try err_text.flush();
        std.process.exit(1);
    };
    try out.flush();
    try err_text.flush();
    std.process.exit(verdict);
}

/// The exit status a completed run reports. Always zero, and named rather than
/// inlined so `main`'s tail reads as what it is.
const RunVerdict = u8;

/// Room for the flag list and a refusal's reason, which is all `parse` writes.
///
/// Generous against the list in `interop_options.zig`, which is a few hundred
/// bytes of compile-time text, because the alternative to a buffer with room is
/// a `WriteFailed` out of the parser — on the one path where a caller is owed a
/// readable refusal.
const usage_room = 4096;

/// The command line was refused: say so on stderr, and end there.
///
/// **Status 2, and this program's own code.** `iroh-partner` answers
/// `ExitCode::FAILURE` for every `Err` and a command line it will not run is
/// one, so it exits 1 where this program exits 2; the status alone is what
/// tells the two apart, and the reason and the flag list are on stderr because
/// that is where a script looks for a program's objections.
///
/// **A write that fails does not change the verdict and is not swallowed.**
/// The run is over whatever the write does, so status 2 is set either way —
/// but a script holding status 2 and no reason beside it would have to guess
/// which half of its own command line was wrong, which is the one thing this
/// program exists to tell it. So the first failure is named through
/// `std.log`, the one channel that does not go through the writer that just
/// failed, and the status is unchanged.
fn refuse(err_text: *std.Io.Writer, what: []const u8) noreturn {
    var lost: ?std.Io.Writer.Error = null;
    err_text.writeAll(what) catch |err| {
        lost = err;
    };
    err_text.flush() catch |err| {
        // The write's refusal is the one worth reporting: the flush is the
        // same channel and can only fail because the write already did.
        if (lost == null) lost = err;
    };
    if (lost) |err| std.log.err(
        "interop peer refusal: the reason did not reach stderr: {t}",
        .{err},
    );
    std.process.exit(2);
}

/// One exchange, from banner to verdict.
///
/// Split out of `main` so that every exit from here — a mismatch, a deadline, a
/// stop, a transport refusal — goes through the same teardown, and so that
/// `main` is only argument handling and the exit code.
fn run(
    gpa: std.mem.Allocator,
    io: std.Io,
    parsed: options.Options,
    text: *std.Io.Writer,
    err_text: *std.Io.Writer,
) Error!RunVerdict {
    // No fallback generator: `SecretKey.generate` draws the seed from
    // `io.randomSecure`, and a peer whose identity came from a process-wide RNG
    // is a peer whose node id moves on every run. `--secret-key` is the one way
    // to fix it, and both ends take the same 32 bytes.
    var secret = parsed.secret orelse try SecretKey.generate(io);
    defer secret.deinit();
    const node = secret.nodeId();

    var peer: runtime.Peer = undefined;
    try peer.init(.{
        .gpa = gpa,
        .io = io,
        .listen = parsed.listen orelse runtime.loopback,
        .secret = secret,
        .expect_peer = parsed.expect_remote,
        .alpns = parsed.alpns,
        .idle_timeout_ms = parsed.timeout_ms,
        .initial_max_streams_uni = options.max_uni_streams,
        .initial_max_stream_data_uni = options.max_payload,
        .require_retry = parsed.require_retry,
        .capture_path = parsed.capture,
        .role = parsed.role.text(),
    });
    // Every exit from here winds the peer down, so a failed run releases its
    // socket, its core and its capture in the one order that is legal.
    defer peer.deinit();

    var scenario: transfer.Scenario = undefined;
    try scenario.init(gpa, parsed.expect_remote, parsed);
    defer scenario.deinit();

    // A supervisor may signal as soon as the banner reaches its pipe, and a
    // listener's port has to be readable before anything is dialled at it.
    try announce(text, node, parsed, peer.socket.address);

    const started = try runtime.nowNs(io);
    const deadline = started + @as(i64, std.math.cast(i64, parsed.timeout_ms) orelse
        return error.DeadlineReached) * std.time.ns_per_ms;

    // The dialling end opens its connection before the loop, and the first
    // `peer.pass` is what puts its first Initial on the wire — the drain leads
    // the wait for exactly that reason (see `interop_runtime.zig`'s module doc).
    const dialled = parsed.role == .dial;
    if (dialled) {
        _ = try peer.dial(.{ .ip = parsed.dial_addr.? }, parsed.dial_id, started);
    }

    // One lookup per pass, read once. It is a borrowed handle into the core's
    // table and `sweep` frees a finished connection, so asking twice could hand
    // the scenario one connection's streams and the report another's.
    var reported_connection = false;
    while (true) {
        const at = try runtime.nowNs(io);
        const conn = peer.liveConn(dialled);
        if (conn != null and !reported_connection) {
            try reportConnection(text, conn.?, err_text);
            reported_connection = true;
        }
        // The scenario's writes are queued in the core before the pass, and
        // the pass's leading drain is what puts them on the wire.
        try scenario.step(conn, at, text);
        try peer.pass(at, runtime.poll_interval_ms);

        if (stopped.load(.acquire)) {
            peer.requestStop();
            return error.Stopped;
        }
        if (scenario.complete()) break;
        if (at >= deadline) {
            try explainDeadline(err_text, &peer, &scenario);
            return error.DeadlineReached;
        }
    }

    try sayGoodbye(io, &peer, dialled, deadline);

    // The verified channels, the counters, and only then the verdict line — so
    // a script that reads `success` has already seen the bytes that earned it.
    try report(text, err_text, &peer, &scenario);
    // The partner's last word, matched so one script can read either end's
    // completion without branching on which language produced it: a listener
    // is `done`, a dialer has succeeded at what it went out to do.
    try text.writeAll(if (parsed.role == .listen) "done\n" else "success\n");
    try outFlush(text);
    return 0;
}

/// How the exchange ends, in the order this role needs.
///
/// **First everything the core still owes the socket goes out.** A scenario that
/// has verified itself says its payload was *queued*, and one drain hands back a
/// prefix when the core has more flight than the egress room holds — so a
/// listener's answer can still be in the core at this point, and a close sent
/// over the top of it would end the connection with the answer undelivered.
///
/// **Then the two roles diverge, and the reason is one wire fact.** A dialer's
/// scenario completes by having read the listener's answer, so a
/// `CONNECTION_CLOSE` from it with application error 0 (RFC 9000 §10.2.3) says
/// "I have everything" with nothing behind it on the wire, and that is the frame
/// the partner's own listener is waiting for. A listener has just written an
/// answer and flushed it, and a close from there would be the peer reading a
/// goodbye where the reply should have been; it waits for the peer's close
/// instead, which `liveConn` reports as null the moment that CONNECTION_CLOSE
/// has carried the connection past `established`.
///
/// **Bounded by what the run already had.** Its deadline ends the wait — this end
/// verified everything it was asked to, and a peer that never says goodbye is not
/// a verification failure — and the stop signal still means stop.
/// The wait itself is `Peer.pass`, the same pass the loop above runs, because
/// that is what carries a peer's close through the bridge and nothing else
/// here does.
fn sayGoodbye(
    io: std.Io,
    peer: *runtime.Peer,
    dialled: bool,
    deadline: runtime.Instant,
) Error!void {
    const flushed = try runtime.nowNs(io);
    try peer.drain(flushed);
    if (dialled) {
        // No connection is not a failure to say goodbye: it is the peer having
        // closed first and the core having carried this one to the end of its
        // draining period while the last payload was being verified.
        const conn = peer.liveConn(dialled) orelse return;
        conn.close(0, "", flushed);
        // A second drain, and this one carries the close — the frame the core
        // queued above reaches the socket on no other path, and the peer is
        // reading this socket rather than a core's pending queue.
        try peer.drain(flushed);
        return;
    }

    var at = flushed;
    while (peer.liveConn(dialled) != null) {
        if (stopped.load(.acquire)) {
            peer.requestStop();
            return error.Stopped;
        }
        if (at >= deadline) return;
        try peer.pass(at, runtime.poll_interval_ms);
        at = try runtime.nowNs(io);
    }
}

/// The banner, and the lines that follow from which end this run is.
///
/// **Flushed before the caller waits on anything**, which is the whole reason
/// `reportConnection` flushes too: a script that reads an ephemeral port from a
/// pipe needs the bytes in the pipe, not sitting in a `Writer`'s buffer. That is
/// the difference between a run a script can drive and one it can only read
/// after the fact.
fn announce(
    text: *std.Io.Writer,
    node: NodeId,
    parsed: options.Options,
    address: SocketAddr,
) !void {
    try text.print("node {s}\n", .{node.toHex()[0..]});
    // Both ends say where they bound, because both ends bound: a dialer pins
    // its own port so a reader can tell the two sockets apart in a capture, and
    // printing it is what makes that possible without guessing.
    try text.print("listening {f}\n", .{address});
    switch (parsed.role) {
        // Only a listener is ready to be dialled at, and only after its address
        // is on the wire.
        .listen => try text.writeAll("ready\n"),
        .dial => try text.print("dialling {s}@{f}\n", .{
            parsed.dial_id.?.toHex()[0..],
            parsed.dial_addr.?,
        }),
    }
    try text.flush();
}

/// The peer that authenticated, and the protocol that was negotiated.
///
/// **The peer id is read off the handshake, not off the pin.** The pin says what
/// was asked for; this says what the peer proved, and the two are equal because
/// the core compared them. A `connected` line built from the pin would only be
/// repeating what the caller already knew.
fn reportConnection(text: *std.Io.Writer, conn: runtime.Conn, err_text: *std.Io.Writer) !void {
    const peer_id = try runtime.authenticatedPeerId(conn);
    if (peer_id) |id| {
        try text.print("connected {s}\n", .{id.toHex()[0..]});
    } else {
        // A connection with no certificate to read. The pin, if one was set,
        // was still enforced, so this is a weaker statement rather than a
        // failure, and it says which it is.
        try text.writeAll("connected none\n");
        try err_text.writeAll("note: the peer presented no certificate to read an id from\n");
    }
    const alpn = runtime.negotiatedAlpn(conn);
    if (alpn.len == 0) {
        try text.writeAll("negotiated_alpn none\n");
    } else {
        // Hex, because the partner prints this value as hex and one line
        // format has to serve both ends of an exchange.
        try text.print("negotiated_alpn {x}\n", .{alpn});
    }
    try outFlush(text);
}

/// What a run that ran out of time can honestly say.
///
/// The connection's state is the diagnosis: a run that never established and a
/// run that established and then stalled are different findings, and only the
/// counters distinguish them. This is `loopback_link.zig`'s `report` for a real
/// peer rather than a loopback.
fn explainDeadline(
    err_text: *std.Io.Writer,
    peer: *const runtime.Peer,
    scenario: *const transfer.Scenario,
) !void {
    const stats = peer.stats;
    try err_text.print(
        \\
        \\deadline: the declared scenario did not finish.
        \\  datagrams: {d} in, {d} out, {d} replies, {d} polls of which {d} expired
        \\  ingress: {d} processed, {d} dropped, {d} foreign
        \\  connections finished: {d}
        \\  still owed: bi {s}, uni {s}, datagram {s}
        \\
    , .{
        stats.datagrams_in,
        stats.datagrams_out,
        stats.replies,
        stats.polls,
        stats.timeouts,
        stats.ingress_processed,
        stats.ingress_dropped,
        stats.ingress_foreign,
        stats.connections_finished,
        state(scenario.bidirectional),
        state(scenario.uni),
        state(scenario.datagram),
    });
    try err_text.flush();
}

fn state(channel: transfer.Channel) []const u8 {
    if (channel.expected == null) return "undeclared";
    return if (channel.complete) "verified" else "unverified";
}

/// The last line, and the numbers behind it.
///
/// `verified_*` is printed once per channel that was declared, and not at all for
/// one that was not — so a handshake-only run says so by its silence rather than
/// by printing zeroes that read as transfers that happened.
fn report(
    text: *std.Io.Writer,
    err_text: *std.Io.Writer,
    peer: *const runtime.Peer,
    scenario: *const transfer.Scenario,
) !void {
    try verifyLine(text, "verified_bi", scenario.bidirectional);
    try verifyLine(text, "verified_uni", scenario.uni);
    try verifyLine(text, "verified_datagram", scenario.datagram);

    const stats = peer.stats;
    try text.print(
        \\
        \\datagrams: {d} in, {d} out, {d} replies, {d} degraded, {d} codepoints lost
        \\ingress: {d} processed, {d} dropped, {d} foreign
        \\capture: {s}
        \\
    , .{
        stats.datagrams_in,
        stats.datagrams_out,
        stats.replies,
        stats.sends_degraded,
        stats.ecn_lost,
        stats.ingress_processed,
        stats.ingress_dropped,
        stats.ingress_foreign,
        if (peer.capture != null) "written" else "none",
    });
    // The verdict line itself is `run`'s to write, after this returns, so that
    // every counter above it is already on the wire when a script reads it.
    try outFlush(text);
    try err_text.flush();
}

fn verifyLine(text: *std.Io.Writer, label: []const u8, channel: transfer.Channel) !void {
    if (channel.expected == null) return;
    // Reached only for a verified channel: `Scenario.complete` required it, and
    // a run that did not reach here never prints this label at all.
    try text.print("{s} {x}\n", .{ label, channel.expected.? });
}

fn outFlush(text: *std.Io.Writer) !void {
    try text.flush();
}
