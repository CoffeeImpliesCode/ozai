//! The batch policy: one pass over a `Runs` cursor, and the second pass over
//! the runs that did not go out when one of them was refused for segmentation.
//!
//! Split out of `transport/socket.zig`, which is now the facade over this and
//! five other named modules. The boundary is the writer rather than the socket:
//! `sendBatch` and `walkRuns` are generic over anything that can take one run,
//! which is what lets the policy be driven by a scripted answer where a driver
//! refuses a segmented run and by the real descriptor everywhere else. Nothing
//! here reads a descriptor, and the capability the walk reads is a pointer the
//! caller lowers and never raises.

const std = @import("std");
const batch = @import("batch.zig");
const base_addr = @import("../base/addr.zig");
const socket_error = @import("socket_error.zig");

const SendError = socket_error.SendError;

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

/// Send `payload` to `dest`, and say what it carried.
///
/// One pass over the runs, and a second over the runs that did not go out when
/// one of them was refused for segmentation. Every datagram reaches the wire
/// once: the runs before the refused one are already there, so the tail starts
/// on the refused run itself and the retry cannot put a second copy of
/// anything on it.
///
/// `context` is the writer the runs go out on, and not the socket type: the
/// refusals below come from the driver, and a driver that refuses a segmented
/// run is a node a test may not be running on. Monomorphised rather than
/// erased, so the production call is `Socket.sendRun` and saying it costs
/// nothing at run time.
pub fn sendBatch(
    io: std.Io,
    context: anytype,
    dest: base_addr.SocketAddr,
    payload: batch.Send,
    caps: *batch.Capability,
) SendError!batch.Report {
    const family = batch.Family.of(dest.ip);
    const first = try walkRuns(io, context, dest, payload, caps.*);
    const tail = first.tail orelse return batch.report(payload, family, first.refused);
    // Found by sending, not by asking, and permanent: noq lowers the cap and
    // never raises it (`noq-udp/src/unix.rs:436-445`), because a driver that
    // could segment on the next send would fail it again on the one after.
    caps.* = caps.*.withoutSegmentation();
    // Nothing behind that refusal was segmented, so the retry draws no second
    // segmentation and cannot leave a tail of its own.
    const second = try walkRuns(io, context, dest, tail, caps.*);

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

/// One `context.sendRun` per run of `payload`, and what the pass left behind.
///
/// Stops at the first run refused for segmentation: that run carried nothing,
/// and every run behind it is one this socket will refuse the same way — the
/// cap is lowered by the caller, not argued with here.
fn walkRuns(
    io: std.Io,
    context: anytype,
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
        const refused = try context.sendRun(io, dest, run);
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
