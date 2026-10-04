//! Reaping a child this gate spawned, on every path out of it.
//!
//! Two things here spawn: a step, and the compiler version probe. Both read
//! from the child and then have to be certain it is gone — a tool still
//! running after its step was recorded is a process the receipt does not
//! account for, and a pipe closed a second time is a descriptor that has since
//! been handed to something else. `Child.kill` is the whole teardown (SIGTERM,
//! then wait, then close of every pipe still recorded on the struct) and does
//! nothing once `wait` has taken the child. Routing every exit through these
//! two functions is what makes "reaped once, closed once" a property of the
//! code rather than something reconstructed per call site.

const std = @import("std");

/// Terminates and reaps `child`, closing whatever is still recorded on it.
/// The one way a spawned child is given up without a verdict, and it cannot
/// fail: a caller that had to report both a broken step and a child nobody
/// reaped would be reporting one failure twice.
pub fn dispose(io: std.Io, child: *std.process.Child) void {
    child.kill(io);
}

/// Waits for `child` and reports how it ended.
///
/// `Child.wait` is a cancelation point, and a cancelled wait tears the struct
/// down without reaping the process behind it — the child is then neither owned
/// nor gone. The wait therefore runs with cancelation blocked, and the caller's
/// own protection is restored on the way out. A wait that fails for any other
/// reason has the same shape, so it terminates and reaps the child before
/// returning the error instead of leaving the receipt to lose it.
pub fn wait(
    io: std.Io,
    child: *std.process.Child,
) std.process.Child.WaitError!std.process.Child.Term {
    const protection = io.swapCancelProtection(.blocked);
    defer _ = io.swapCancelProtection(protection);
    return child.wait(io) catch |err| {
        dispose(io, child);
        return err;
    };
}
