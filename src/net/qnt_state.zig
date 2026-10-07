//! One QNT exchange: the rounds, the result each round produced, and the
//! answer the whole exchange adds up to.
//!
//! `qnt.zig` decodes a frame and stops. What it cannot decide is the question
//! this file answers. QNT's raw material is a stream of samples, each naming
//! the largest packet number the peer had received when it wrote it, and a
//! *single* difference of two of those says almost nothing: one reply caught a
//! burst the peer's send loop had queued, the next caught a scheduler that had
//! gone quiet, and the quotient of the two is a number that describes neither
//! path. So this file runs several rounds, keeps what each one measured, and
//! reports a statistic over them — with a bound, because a peer that never
//! answers must not hold a turn open forever.
//!
//! # No socket, no clock, no allocator
//!
//! Every function is `(state, data) -> state`. The instant is an argument
//! (`now`), the challenge is an argument (`begin`), and nothing here allocates:
//! the round history is an inline array of a compile-time length, so an
//! `Exchange` is a value that can sit on a stack, be copied, and be compared
//! with `==`. Two exchanges driven over the same frames and the same instants
//! produce equal exchanges, which is what makes the whole file testable without
//! a network.
//!
//! # Decision: five rounds, and the median of them
//!
//! **`max_rounds` is five, and one of those five is not a measurement.** The
//! first reply of an exchange sets the reference rather than being differenced
//! against one (`Result.baseline`), so five rounds yield **at most four
//! measurements**. Every justification below is about that number.
//!
//! 1. **Five is the smallest bound that can still produce a median after one
//!    loss.** `min_rounds` is three measurements; three measurements plus the
//!    baseline is four rounds; five leaves exactly one spare round for a reply
//!    that never arrives. A lossy path loses one reply as a matter of course
//!    rather than as an exception, and at four rounds a single loss would drop
//!    the exchange below `min_rounds` and throw away every measurement it had.
//!    The test named for this loses a round on purpose.
//! 2. **Four measurements tolerate an outlier at each end.** That is what the
//!    median buys and it is the whole reason for not using the minimum: a busy
//!    path routinely produces one round that catches a send buffer draining, and
//!    one such round must move the answer by nothing.
//! 3. **Seven buys a second spare round for a cost nobody pays.** Going from
//!    four measurements to six changes the median only when the first four
//!    already disagreed, which is a case the outcome already names as
//!    `.exhausted`, and it costs two more probes *and* two more replies. Five
//!    round trips is comfortably inside what one path operation already costs
//!    in this tree: `docs/DECISIONS/0001` measured a path validation at up to
//!    109 RTTs on a saturated link.
//!
//! **The rule is the median, and the alternatives were weighed:**
//!
//! - **The minimum** is the rate of the luckiest round. On a path whose queue
//!   drains in bursts — which is most paths, and all of them under a
//!   congestion controller — the fastest round reports the depth of the send
//!   buffer rather than the capacity of the link. It is the statistic that
//!   rewards a lucky packet, and a cache built on it reports a rate no round
//!   sustained.
//! - **The mean** is the sum of packets over the sum of the intervals, and one
//!   stalled round inside it does not get pulled out — it *is* the answer,
//!   weighted by its length. A round that caught a sixty-second scheduler pause
//!   contributes sixty seconds of near-zero and shrinks every other round's
//!   share with it.
//! - **The median** survives outliers at either end, which is the one failure
//!   the other two share. It costs a sort, and the array is four elements, so
//!   the cost is bounded by a compile-time constant and there is nothing to
//!   allocate.
//!
//! **The median is always a rate some round measured.** Three measurements give
//! the middle one; four give the lower of the two middle ones. Averaging those
//! two would report a rate nothing measured, and an answer that is going to be
//! cached and believed should be one that happened.
//!
//! **The median is over the rates, not over the packet counts.** Two rounds
//! with equal counts and unequal intervals are not equal measurements, and
//! ordering by count would answer a question nobody asked.
//!
//! **`min_rounds` is three.** The median of fewer than three measurements has
//! no outlier resistance at all: with one there is no median, and with two the
//! "median" is one of the two samples and inherits whichever is worse. Three is
//! the smallest count at which the word means anything, and an exchange that
//! ends below it reports `.undetermined` with no rate at all.
//!
//! # Decision: a round with no measurement is **absent** — not zero, not an error
//!
//! This is the sharpest decision in the file, because all three readings are
//! defensible and two of them are wrong in ways that only show up later.
//!
//! - **Absent** is what this file does, because absent is the only reading that
//!   does not *assert* something the wire never said. A round whose reply never
//!   arrived is a fact about the reply, not about the path. Recording it as zero
//!   asserts the path delivered nothing, and a median built on that assertion
//!   reports a working path as a dead one.
//! - **Zero** is reserved for the case where the wire *did* say it. A reply that
//!   arrived and reported no new packet numbers is a real observation that the
//!   peer has received nothing past where it was, and that round is `.measured`
//!   with a rate of zero. An idle path and a silent path are different facts and
//!   this file keeps them apart; conflating them is how a healthy quiet path
//!   gets reported as a broken one.
//! - **An error** is wrong because QNT is optional measurement traffic on a
//!   connection that is otherwise fine. Failing an exchange over a lost reply
//!   would take down a working connection over a frame nobody asked for, and
//!   `observed_address.zig` reaches the same conclusion about a stale QAD
//!   frame: the errors that belong to this extension are send-side violations
//!   about transport parameters, and none of them is a frame that arrived late.
//!
//! **Three different faults end as `.absent`, and each is named where it is
//! decided**, because a caller debugging a bad exchange has to tell them apart:
//!
//! 1. the round's reply never arrived (`expire`);
//! 2. the sample's highest packet number did not advance — the two samples
//!    describe no interval between them, and calling that zero would say the
//!    path delivered nothing when the wire says the peer is numbering behind
//!    where it was;
//! 3. the two samples landed in the same nanosecond, so there is nothing to
//!    divide by. This also covers a caller whose timeline went backwards, since
//!    the subtraction saturates at zero and arrives here.
//!
//! **`Result.baseline` is a fourth outcome and is not absent.** The first reply
//! sets the reference: there is no earlier sample to difference against, so
//! there is no interval and no rate. It is a real wire assertion with nothing
//! yet to measure it against, and giving it its own arm is what keeps the three
//! absent causes above from hiding inside it.
//!
//! # What moves the reference, and what must not
//!
//! The reference pair (highest packet number, instant) moves on a `.measured`
//! round and on a `.baseline` round. It does **not** move on an absent one. If a
//! reply was lost, the next reply describes an interval that spans the gap, and
//! that is the honest interval, because the gap is part of the path the peer is
//! describing. Resetting the reference at the lost round would shorten the next
//! interval and overstate the rate by whatever the gap was worth.
//!
//! # What correlates a reply to its round
//!
//! Two things, and both are checked before a frame is allowed to move anything:
//!
//! - **The path family.** Packet numbers are numbered per path and per family
//!   under QUIC Multipath, so a frame carrying another family's numbers cannot
//!   be differenced against this one's. Folding it in would compare two number
//!   spaces as if they were one, which is the one mistake here that produces a
//!   plausible wrong answer rather than an obviously broken one.
//! - **The challenge.** Chosen by whoever armed the round, echoed by the peer,
//!   and compared exactly.
//!
//! The frame's sequence number is deliberately **not** part of either check.
//! It cannot correlate anything: the *responder* chooses it, so two exchanges
//! with the same peer both start it wherever it happens to be, and a frame with
//! a high number is not therefore the answer to the newest request. It also
//! needs no monotonicity gate of its own — a replayed frame carries a
//! challenge that no longer matches — and a second gate over the same decision
//! would be duplicate validation of the kind `AGENTS.md` §9 asks to be proved
//! before it is kept.

const std = @import("std");
const qnt = @import("qnt.zig");
const report = @import("report.zig");

/// Nanoseconds on a monotonic timeline the caller owns.
///
/// `net/report.zig` defines it for the fold from probe results, and two
/// definitions of "an instant" in one layer would only invite a conversion
/// nobody wants — `holepunch_gate.zig` aliases it for the same reason.
pub const Nanos = report.Nanos;

/// Which path family an exchange is measuring. QNT's own enum under the name
/// this file needs: a second declaration here would be the second opinion about
/// a path's family that `path_table.zig` refuses to allow.
pub const Family = qnt.Family;

/// The opaque value a round is armed with and its reply must echo.
pub const Challenge = qnt.Challenge;

/// How many rounds one exchange runs before it terminates whatever it has.
pub const max_rounds: usize = 5;

/// The fewest measured rounds that can produce an answer at all.
pub const min_rounds: usize = 3;

/// How far apart the fastest and slowest measured rounds may be, in percent of
/// the fastest, for the exchange to stop early.
///
/// Twenty-five is chosen so a path whose round-to-round rate varies by a quarter
/// still settles, while a path that alternates between idle and busy never does
/// and is reported as varying rather than averaged into a number describing
/// neither. The test is a range and not an equality because an exchange that
/// ran at a *stable* bad rate must also converge: the spread measures the
/// path's variability, not its speed.
pub const converge_tolerance: u32 = 25;

/// Packets per second, in a width chosen so the arithmetic cannot overflow.
///
/// A packet count is a 62-bit variable-length integer and one second is
/// `ns_per_s`, so `count * ns_per_s` reaches about 2^92 and no quotient of it
/// by a nanosecond count fits a `u64`. Every rate this file computes — the
/// rounds', the median's, the spread's — is a whole number of packets per
/// second, because the statistic being reported *is* a count over an interval
/// and a fractional packet has no meaning here.
pub const Rate = u128;

/// Everything a caller can get wrong about how it drives an exchange. Each arm
/// is a fact about the caller's own sequencing, not about the network, which is
/// why none of them is a `qnt.Error`.
pub const Error = error{
    /// A round is already waiting for its reply. One exchange has one round in
    /// flight, so a second `begin` is a caller bug rather than a queue.
    RoundInFlight,
    /// No round is waiting for a reply: either none was armed, or the one that
    /// was has already been folded in. A late or duplicated frame lands here.
    NoRoundInFlight,
    /// The frame names another path family than the round it answers.
    ForeignFamily,
    /// The frame echoes another round's challenge.
    ForeignChallenge,
    /// The exchange has already produced an answer. It does not run again —
    /// which is the whole of what the bound means.
    Finished,
};

/// What one round of the exchange produced.
pub const Result = union(enum) {
    /// A reply arrived and set the reference: there was no earlier sample, so
    /// there is no interval and no rate. A real assertion with nothing yet to
    /// measure against — neither absent nor zero.
    baseline,
    /// The round produced no measurement. Three causes, named where they are
    /// decided; see the module doc.
    absent,
    /// A rate, in packets per second, over an interval this exchange observed.
    measured: Rate,
};

/// One round and what it produced, kept so an answer can be explained rather
/// than only stated.
pub const Round = struct {
    /// Which round this was, counting from zero. Bounded by `max_rounds`.
    index: usize,
    result: Result,
};

/// The round a probe has to put on the wire, the path family it is about, and
/// the value its reply must echo.
pub const Probe = struct {
    /// Which round this probe is, counting from zero.
    round: usize,
    /// The path family this exchange measures. The probe goes out on a path of
    /// this family and the reply has to come back naming it.
    family: Family,
    /// The challenge for this round. A reply echoing anything else is not this
    /// round's answer.
    challenge: Challenge,
};

/// How an exchange ended.
pub const Outcome = enum {
    /// The measured rounds agreed to within `converge_tolerance`, so the
    /// exchange stopped before `max_rounds`. This is the only outcome that
    /// means the rounds agreed with each other.
    converged,
    /// The round bound ran out with the spread still open. The median is still
    /// reported: measured rounds that disagree say the path varies, which is a
    /// finding rather than a reason to discard the finding.
    exhausted,
    /// The round bound ran out with fewer than `min_rounds` measured rounds, so
    /// there is nothing to take a median of. No rate is reported, because a rate
    /// from one or two rounds is a sample and this file does not publish a
    /// sample as an answer.
    undetermined,
};

/// What the exchange concluded.
pub const Answer = struct {
    /// Which way it ended.
    outcome: Outcome,
    /// The median rate in packets per second, or null exactly when `outcome` is
    /// `.undetermined`. Reported for `.exhausted` as well as `.converged`,
    /// because a varying path is still a path with a rate.
    rate: ?Rate,
    /// Rounds that ran, measured or not. Every one of them came out of the
    /// bound.
    rounds_run: usize,
    /// How many of those produced a measurement. `rounds_run - measured` is how
    /// many did not, and each one's reason is in `Exchange.rounds`.
    measured: usize,
};

/// One exchange on one path.
///
/// A plain value: copying it copies values and never a pointer into itself, so a
/// copy reads what the original reads and the two cannot drift apart.
pub const Exchange = struct {
    /// The round waiting for its reply, or null when none is.
    ///
    /// One exchange has one round in flight because a round's answer is
    /// correlated by its family and its challenge, and two rounds outstanding
    /// would leave two replies indistinguishable at the moment both arrived.
    pending: ?Probe = null,
    /// The highest packet number the last accepted sample reported, or null
    /// before any has. The left half of the pair a measurement differences.
    ///
    /// Not moved by an absent round. See the module doc.
    covered: ?u64 = null,
    /// The instant the last accepted sample arrived, on the caller's timeline.
    /// The right half of that pair.
    previous_at: Nanos = 0,
    /// Every round this exchange ran, oldest first. Zeroed rather than undefined
    /// so two exchanges compare with `==`.
    rounds: [max_rounds]Round =
        [_]Round{.{ .index = 0, .result = .absent }} ** max_rounds,
    /// How many entries of `rounds` are real.
    round_count: usize = 0,
    /// The answer, once the exchange has produced one.
    finished: ?Answer = null,
};

/// Arm the next round on a path of `family` with `challenge`, and say what to
/// put on the wire.
///
/// `challenge` is an argument rather than something generated here because this
/// module owns no entropy source: the caller owns the randomness and this file
/// owns the sequencing. Refuses `error.Finished` once an answer exists and
/// `error.RoundInFlight` while a round is outstanding.
pub fn begin(exchange: Exchange, family: Family, challenge: Challenge) Error!Exchange {
    if (exchange.finished != null) return error.Finished;
    if (exchange.pending != null) return error.RoundInFlight;
    // The bound is only reachable through a round that was folded in, and
    // folding one in either finishes the exchange or leaves room for this.
    std.debug.assert(exchange.round_count < max_rounds);
    var next = exchange;
    next.pending = .{
        .round = exchange.round_count,
        .family = family,
        .challenge = challenge,
    };
    return next;
}

/// What to put on the wire right now, or null when nothing is armed.
pub fn probe(exchange: Exchange) ?Probe {
    return exchange.pending;
}

/// Fold a reply in.
///
/// `now` is the instant the frame arrived on the caller's own timeline. The
/// frame's own timestamp is **not** read: it is the *peer's* clock and the two
/// clocks need not agree, so the interval measured here is the interval between
/// two arrivals as this caller saw them.
///
/// Refuses `error.NoRoundInFlight` when nothing is armed, `error.ForeignFamily`
/// and `error.ForeignChallenge` when the frame is not this round's answer. None
/// of them closes the exchange: a frame that cannot be attributed is dropped,
/// and the round it should have answered stays outstanding, so its own reply is
/// still accepted when it arrives.
pub fn observe(exchange: Exchange, now: Nanos, frame: qnt.Frame) Error!Exchange {
    const pending = exchange.pending orelse return error.NoRoundInFlight;
    // The family is checked before the challenge because it is the coarser
    // claim: a frame carrying another path's packet numbers cannot be
    // differenced against this one's, whatever challenge it echoes.
    if (frame.family != pending.family) return error.ForeignFamily;
    if (!std.mem.eql(u8, frame.challenge[0..], pending.challenge[0..])) {
        return error.ForeignChallenge;
    }
    var next = exchange;
    next.pending = null;
    const covered = frame.covered();
    const previous = next.covered orelse {
        // First reply: there is nothing to difference it against.
        next.covered = covered;
        next.previous_at = now;
        return settle(record(next, .baseline));
    };
    const elapsed = now -| next.previous_at;
    if (covered < previous) {
        // The peer numbered behind where it was, so the two samples describe no
        // interval. The reference stays put, which is what keeps the next reply
        // differenced against something it can be compared with.
        return settle(record(next, .absent));
    }
    if (elapsed == 0) {
        // Two samples inside one nanosecond, which is also what a caller whose
        // timeline went backwards produces: the subtraction saturates at zero.
        // There is no interval, so there is no rate — the answer is not
        // "infinitely fast".
        return settle(record(next, .absent));
    }
    next.covered = covered;
    next.previous_at = now;
    const rate = perSecond(covered - previous, elapsed);
    return settle(record(next, .{ .measured = rate }));
}

/// Fold in the fact that a round's reply never arrived.
///
/// Takes no instant because none is used: a round that produced nothing has no
/// interval, so there is nothing here a clock could change.
pub fn expire(exchange: Exchange) Error!Exchange {
    if (exchange.pending == null) return error.NoRoundInFlight;
    var next = exchange;
    next.pending = null;
    return settle(record(next, .absent));
}

/// The answer, or null while the exchange is still running.
pub fn answer(exchange: Exchange) ?Answer {
    return exchange.finished;
}

/// How many of the rounds that ran produced a measurement.
pub fn measuredCount(exchange: Exchange) usize {
    var count: usize = 0;
    var index: usize = 0;
    while (index < exchange.round_count) : (index += 1) {
        if (exchange.rounds[index].result == .measured) count += 1;
    }
    return count;
}

/// Close the exchange if the spread closed, or if the bound is reached.
///
/// Every path that folds a round in comes through here, so this is the only
/// place the exchange can end and the only place the bound is applied.
fn settle(exchange: Exchange) Exchange {
    if (converged(exchange)) return close(exchange, .converged);
    if (exchange.round_count < max_rounds) return exchange;
    const measured = measuredCount(exchange);
    return close(exchange, if (measured >= min_rounds) .exhausted else .undetermined);
}

/// Whether the measured rounds agree closely enough to stop early.
///
/// False below `min_rounds`, because a median of fewer than three measurements
/// is not a median. The spread is taken against the **fastest** round, so a run
/// of rounds that all agree on a slow path converges and a run that alternates
/// between idle and busy does not.
fn converged(exchange: Exchange) bool {
    var scratch: [max_rounds]Rate = undefined;
    const count = collectRates(exchange, &scratch);
    if (count < min_rounds) return false;
    sortRates(scratch[0..count]);
    // The sort is descending, so the fastest is at index zero: the spread is
    // only a subtraction in that order, and taking it the other way underflows.
    const fastest = scratch[0];
    const slowest = scratch[count - 1];
    return (fastest - slowest) * 100 <= fastest * converge_tolerance;
}

/// The measured rounds' rates, in the order they ran. The one array this file
/// fills, and it is the caller's stack.
fn collectRates(exchange: Exchange, out: *[max_rounds]Rate) usize {
    var count: usize = 0;
    var index: usize = 0;
    while (index < exchange.round_count) : (index += 1) {
        switch (exchange.rounds[index].result) {
            .measured => |rate| {
                out[count] = rate;
                count += 1;
            },
            .baseline, .absent => {},
        }
    }
    return count;
}

/// Insertion sort, descending. Five elements at most, the bound is a
/// compile-time constant, so there is no allocation and no dynamic bound.
fn sortRates(rates: []Rate) void {
    var index: usize = 1;
    while (index < rates.len) : (index += 1) {
        const rate = rates[index];
        var hole = index;
        while (hole > 0 and rates[hole - 1] < rate) : (hole -= 1) {
            rates[hole] = rates[hole - 1];
        }
        rates[hole] = rate;
    }
}

/// `count` packet numbers over `elapsed` nanoseconds, as whole packets per
/// second.
///
/// Never called with a zero interval: `observe` has already refused that case,
/// and a division by zero here would be a panic inside the one function whose
/// argument is that the round measured something.
fn perSecond(count: u64, elapsed: Nanos) Rate {
    return @divTrunc(@as(Rate, count) * std.time.ns_per_s, elapsed);
}

/// Append a round, in the one place a round is appended.
fn record(exchange: Exchange, result: Result) Exchange {
    std.debug.assert(exchange.round_count < max_rounds);
    var next = exchange;
    next.rounds[next.round_count] = .{ .index = next.round_count, .result = result };
    next.round_count += 1;
    return next;
}

/// Close the exchange with `outcome` and work out what it is worth.
fn close(exchange: Exchange, outcome: Outcome) Exchange {
    var scratch: [max_rounds]Rate = undefined;
    const count = collectRates(exchange, &scratch);
    sortRates(scratch[0..count]);
    var next = exchange;
    next.finished = .{
        .outcome = outcome,
        .rate = if (count == 0) null else median(scratch[0..count]),
        .rounds_run = next.round_count,
        .measured = count,
    };
    return next;
}

/// The median of rates sorted descending: the middle element for an odd count
/// and the lower of the two middle ones for an even count.
///
/// The even case takes the **lower** middle rather than interpolating, because
/// averaging two middle rates means adding their packet counts and their
/// intervals and dividing, which reports a rate no round measured. The lower
/// middle is a round that happened, and with four measurements it is the lower
/// of the two middles in a descending list.
fn median(sorted_descending: []const Rate) Rate {
    return sorted_descending[sorted_descending.len / 2];
}

comptime {
    // One round of the bound is the baseline, so `max_rounds` has to leave room
    // for `min_rounds` measurements *after* it. Without the spare round the
    // bound and the floor would be the same number and a single lost reply
    // would make every answer `.undetermined` — the exact failure the spare
    // round exists to prevent.
    std.debug.assert(max_rounds > min_rounds + 1);
}

// --- tests

const t = std.testing;

/// One second on the caller's timeline, which is what every round in these
/// tests is one second long.
const second: Nanos = std.time.ns_per_s;

/// The family every sample in these tests names, so a test that means to
/// exercise the family gate says `.v6` on purpose rather than by default.
const here: Family = .v4;

/// `begin` on `here`, which is the family `sample` reports.
fn arm(exchange: Exchange, challenge: Challenge) Error!Exchange {
    return begin(exchange, here, challenge);
}

/// A frame reporting `highest` as the one packet-number run it has seen.
fn sample(challenge: Challenge, highest: u64) qnt.Frame {
    var frame: qnt.Frame = .{
        .family = here,
        .sequence = 1,
        .challenge = challenge,
        .timestamp = 1,
        .ranges = [_]qnt.PacketRange{.{ .first = 0, .last = 0 }} ** qnt.max_packet_ranges,
        .range_count = 1,
    };
    frame.ranges[0] = .{ .first = 0, .last = highest };
    return frame;
}

/// A challenge that is distinct per round, so a test never accidentally matches
/// the wrong one.
fn challengeOf(round: u8) Challenge {
    var bytes: Challenge = [_]u8{0} ** qnt.challenge_length;
    bytes[0] = round;
    return bytes;
}

/// One exchange in which each round runs one second after the last and covers
/// exactly `rates[index]` new packets, so the round's rate *is* `rates[index]`.
///
/// Round zero is the baseline: a reply with nothing to difference against, and
/// no contribution to any statistic.
///
/// The refusals are propagated rather than discarded. `arm` refuses a round
/// that is already in flight and an exchange that has already answered, and
/// `observe` refuses a frame that is not the armed round's answer; the loop
/// below makes each of those unreachable, and a `rates` list long enough to
/// break that is a fixture that should fail this test rather than a claim about
/// a path no caller walks.
fn runRounds(rates: []const u64) Error!Exchange {
    var exchange = try arm(.{}, challengeOf(0));
    exchange = try observe(exchange, 0, sample(challengeOf(0), 0));
    var covered: u64 = 0;
    var index: usize = 0;
    // Stopping on the answer is what a real caller does, and it is what makes
    // `rates` a ceiling rather than a script: an exchange that converges early
    // never reaches the later entries.
    while (index < rates.len and answer(exchange) == null) : (index += 1) {
        covered += rates[index];
        const round: u8 = @intCast(index + 1);
        exchange = try arm(exchange, challengeOf(round));
        exchange = try observe(
            exchange,
            @as(Nanos, index + 1) * second,
            sample(challengeOf(round), covered),
        );
    }
    return exchange;
}

test "one exchange runs one round at a time" {
    try t.expectEqual(@as(?Probe, null), probe(.{}));

    const armed = try arm(.{}, challengeOf(1));
    const outstanding = probe(armed) orelse return error.TestUnexpectedResult;
    try t.expectEqual(@as(usize, 0), outstanding.round);
    try t.expectEqual(here, outstanding.family);
    try t.expectEqual(challengeOf(1), outstanding.challenge);

    // A second challenge while the first round is unanswered is a caller bug,
    // and naming it is what makes "one exchange, one round" enforceable.
    try t.expectError(error.RoundInFlight, arm(armed, challengeOf(2)));

    // Folding the reply in frees the round, and the next one is numbered.
    const answered = try observe(armed, 0, sample(challengeOf(1), 10));
    try t.expectEqual(@as(?Probe, null), probe(answered));
    const rearmed = try arm(answered, challengeOf(2));
    const next = probe(rearmed) orelse return error.TestUnexpectedResult;
    try t.expectEqual(@as(usize, 1), next.round);
}

test "a reply that is not this round's answer is refused by name, and nothing moves" {
    const armed = try arm(.{}, challengeOf(1));

    // The right challenge on the wrong path family: two number spaces, and
    // differencing one against the other would produce a plausible wrong rate.
    var wrong_family = sample(challengeOf(1), 10);
    wrong_family.family = .v6;
    try t.expectError(error.ForeignFamily, observe(armed, 0, wrong_family));

    // The right family on another round's challenge.
    try t.expectError(error.ForeignChallenge, observe(armed, 0, sample(challengeOf(9), 10)));

    // Neither refusal closed the exchange or armed anything: the round this one
    // was asked about is still outstanding, so its own reply is still accepted.
    const outstanding = probe(armed) orelse return error.TestUnexpectedResult;
    try t.expectEqual(challengeOf(1), outstanding.challenge);
    try t.expectEqual(@as(usize, 0), armed.round_count);
    try t.expectEqual(@as(?Answer, null), answer(armed));

    // And with nothing armed there is nothing to fold a frame into.
    const idle: Exchange = .{};
    try t.expectError(error.NoRoundInFlight, observe(idle, 0, sample(challengeOf(1), 1)));
    try t.expectError(error.NoRoundInFlight, expire(idle));
}

test "the first reply is a baseline, not a measurement and not a zero" {
    const armed = try arm(.{}, challengeOf(1));
    const answered = try observe(armed, second, sample(challengeOf(1), 10));
    try t.expectEqual(Result{ .baseline = {} }, answered.rounds[0].result);
    try t.expectEqual(@as(usize, 1), answered.round_count);
    try t.expectEqual(@as(usize, 0), measuredCount(answered));
    // One round is not a median, so nothing has been concluded yet.
    try t.expectEqual(@as(?Answer, null), answer(answered));
}

test "a reply with nothing new measures zero, because the wire said so" {
    // The peer answered and reported the packet number it reported last time:
    // an observation of an idle path, and a real one.
    const first = try observe(
        try arm(.{}, challengeOf(1)),
        0,
        sample(challengeOf(1), 10),
    );
    const idle = try observe(
        try arm(first, challengeOf(2)),
        second,
        sample(challengeOf(2), 10),
    );
    try t.expectEqual(Result{ .measured = 0 }, idle.rounds[1].result);
    try t.expectEqual(@as(usize, 1), measuredCount(idle));
}

test "a round whose reply never arrived is absent, and the gap is not forgotten" {
    var exchange = try observe(
        try arm(.{}, challengeOf(1)),
        0,
        sample(challengeOf(1), 10),
    );
    exchange = try observe(
        try arm(exchange, challengeOf(2)),
        second,
        sample(challengeOf(2), 20),
    );

    const lost = try expire(try arm(exchange, challengeOf(3)));
    try t.expectEqual(Result{ .absent = {} }, lost.rounds[2].result);
    // Nothing about the reference moved: not the packet number, not the instant.
    try t.expectEqual(@as(?u64, 20), lost.covered);
    try t.expectEqual(second, lost.previous_at);

    // So the next reply is differenced against round one and measured over the
    // two seconds that actually elapsed between it and round two — not over the
    // one second a reference reset at the lost round would have used.
    const after = try observe(
        try arm(lost, challengeOf(4)),
        3 * second,
        sample(challengeOf(4), 50),
    );
    try t.expectEqual(Result{ .measured = 15 }, after.rounds[3].result);
}

test "a sample that numbers behind the last one is absent, not zero" {
    const first = try observe(
        try arm(.{}, challengeOf(1)),
        0,
        sample(challengeOf(1), 50),
    );
    const behind = try observe(
        try arm(first, challengeOf(2)),
        second,
        sample(challengeOf(2), 10),
    );
    // Zero would assert the path delivered nothing; the wire says the peer is
    // behind where it was, which is a different fact.
    try t.expectEqual(Result{ .absent = {} }, behind.rounds[1].result);
    // And the reference did not move, so the next reply is still comparable.
    try t.expectEqual(@as(?u64, 50), behind.covered);
}

test "two replies in one nanosecond measure nothing" {
    const first = try observe(
        try arm(.{}, challengeOf(1)),
        7,
        sample(challengeOf(1), 10),
    );
    const same_instant = try observe(
        try arm(first, challengeOf(2)),
        7,
        sample(challengeOf(2), 40),
    );
    try t.expectEqual(Result{ .absent = {} }, same_instant.rounds[1].result);

    // A caller's clock going backwards saturates to the same zero interval and
    // the same answer, rather than dividing by a negative number.
    const backwards = try observe(
        try arm(first, challengeOf(3)),
        1,
        sample(challengeOf(3), 40),
    );
    try t.expectEqual(Result{ .absent = {} }, backwards.rounds[1].result);
}

test "the answer is the median of the measured rounds, not the fastest and not the mean" {
    // Four measurements at 1000, 10, 20 and 30 packets per second — a baseline
    // and four rounds, which is the whole bound. Sorted they are 1000, 30, 20,
    // 10: the lower of the two middles is 20, the minimum is 10 and the mean is
    // 265. The 1000 is a send buffer that drained inside one round, and it must
    // move the answer by nothing at all.
    const measured = [_]u64{ 1000, 10, 20, 30 };
    const exchange = try runRounds(&measured);
    const settled = answer(exchange) orelse return error.TestUnexpectedResult;
    try t.expectEqual(Outcome.exhausted, settled.outcome);
    try t.expectEqual(@as(?Rate, 20), settled.rate);
    try t.expectEqual(@as(usize, 5), settled.rounds_run);
    try t.expectEqual(@as(usize, 4), settled.measured);

    // Every round is on the record, so the median is checked against the
    // measurements rather than taken on trust. Round zero is the baseline.
    try t.expectEqual(Result{ .baseline = {} }, exchange.rounds[0].result);
    for (measured, 0..) |expected, index| {
        try t.expectEqual(@as(Rate, expected), exchange.rounds[index + 1].result.measured);
    }
}

test "a path that alternates idle and busy never settles and says so" {
    // A busy round, an idle one, busy, busy: the spread never closes, so the
    // bound decides, and the outcome is named rather than the loop running on.
    const exchange = try runRounds(&.{ 1000, 0, 1000, 1000 });
    const settled = answer(exchange) orelse return error.TestUnexpectedResult;
    try t.expectEqual(Outcome.exhausted, settled.outcome);
    try t.expectEqual(@as(usize, 5), settled.rounds_run);
    // Three thousands and a zero: the lower middle is still a thousand, and it
    // is reported — rounds that disagree say the path varies, which is a
    // finding rather than a reason to discard it.
    try t.expectEqual(@as(?Rate, 1000), settled.rate);
}

test "a stable slow path converges early, because the spread is about variation" {
    // Four packets per second, the slowest rate in this file, and still a
    // convergence: every round agrees with every other, and what the spread
    // measures is variability rather than speed.
    const exchange = try runRounds(&.{ 4, 4, 4, 4 });
    const settled = answer(exchange) orelse return error.TestUnexpectedResult;
    try t.expectEqual(Outcome.converged, settled.outcome);
    try t.expectEqual(@as(?Rate, 4), settled.rate);
    // Converged on the third measurement, so the fourth round never ran and the
    // exchange holds the baseline plus three rounds.
    try t.expectEqual(@as(usize, 4), settled.rounds_run);
    try t.expectEqual(@as(usize, 3), settled.measured);
}

test "one lost reply still reaches three measurements, which is why five rounds" {
    var exchange = try observe(
        try arm(.{}, challengeOf(0)),
        0,
        sample(challengeOf(0), 0),
    );
    exchange = try observe(
        try arm(exchange, challengeOf(1)),
        second,
        sample(challengeOf(1), 4),
    );
    // Round two's reply is lost, and the round after it spans the gap: four
    // packets over two seconds rather than one.
    exchange = try expire(try arm(exchange, challengeOf(2)));
    exchange = try observe(
        try arm(exchange, challengeOf(3)),
        3 * second,
        sample(challengeOf(3), 8),
    );
    exchange = try observe(
        try arm(exchange, challengeOf(4)),
        4 * second,
        sample(challengeOf(4), 12),
    );

    // Three measurements out of five rounds, so an answer at all. Had the bound
    // been four, the same peer would have ended `.undetermined` and every
    // measurement it made would have been thrown away.
    const settled = answer(exchange) orelse return error.TestUnexpectedResult;
    try t.expectEqual(@as(usize, 5), settled.rounds_run);
    try t.expectEqual(@as(usize, 3), settled.measured);
    try t.expectEqual(@as(?Rate, 4), settled.rate);
    // The rates were 4, 2 and 4 packets per second, so the spread was open at
    // the bound and the outcome says so rather than claiming a convergence.
    try t.expectEqual(Outcome.exhausted, settled.outcome);
}

test "too few measured rounds end as undetermined, with no rate at all" {
    // A baseline and then four lost replies. The baseline is a real wire
    // assertion but it is not a measurement, so nothing here is measurable at
    // all: an exchange with no measurement publishes no rate, rather than a
    // rate of zero or a rate from the one sample it took.
    var exchange = try observe(
        try arm(.{}, challengeOf(1)),
        0,
        sample(challengeOf(1), 10),
    );
    var round: u8 = 2;
    while (round <= 5) : (round += 1) {
        exchange = try expire(try arm(exchange, challengeOf(round)));
    }
    const settled = answer(exchange) orelse return error.TestUnexpectedResult;
    try t.expectEqual(Outcome.undetermined, settled.outcome);
    try t.expectEqual(@as(?Rate, null), settled.rate);
    try t.expectEqual(@as(usize, 5), settled.rounds_run);
    try t.expectEqual(@as(usize, 0), settled.measured);
}

test "the bound holds: five rounds, then the exchange refuses to start another" {
    const exchange = try runRounds(&.{ 1, 2, 3, 4 });
    try t.expectEqual(max_rounds, exchange.round_count);
    try t.expectEqual(@as(?Probe, null), probe(exchange));
    try t.expectError(error.Finished, arm(exchange, challengeOf(9)));
    // And a late reply for a round that already ended is dropped rather than
    // folded into a sixth round that does not exist.
    try t.expectError(
        error.NoRoundInFlight,
        observe(exchange, 9 * second, sample(challengeOf(1), 9)),
    );
}

test "two exchanges over the same frames and instants are equal" {
    // The purity claim, as a test. `==` on the state reaches every field, so
    // this fails if anything in the exchange reads a clock, an allocator or an
    // order the caller did not supply.
    const first = try runRounds(&.{ 1000, 10, 20, 30 });
    const other = try runRounds(&.{ 1000, 10, 20, 30 });
    try t.expectEqual(first, other);
    try t.expectEqual(answer(first), answer(other));
}
