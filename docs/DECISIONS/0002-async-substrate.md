# 0002 — Async substrate

- **Status**: accepted, recorded 2026-09-29. **Reversed 2026-09-30**; see
  [Reconsideration of 2026-09-30](#reconsideration-of-2026-09-30). The
  layering is unchanged and is now the whole decision. What reversed is the
  dependency.
- **zio is not a dependency of this project, and never was.** `build.zig.zon:6`
  is `.dependencies = .{}`, `build.zig` contains no `b.dependency` call, and no
  file under `src/`, `test/`, `vendor/` or `build.zig` names zio except
  `src/transport/batch.zig:4`, which explains why the batcher is *not* written
  against it. The 2026-09-29 record described a dependency this repository does
  not have; that is the part corrected here, and the reason is in the
  reconsideration below.
- Related: [`0001-transport-substrate.md`](0001-transport-substrate.md), whose
  execution record is dated the same day.

## Context

Zig 0.16 replaced the old `std` I/O surface with `std.Io`: a 109-entry vtable
that every I/O-capable call now takes as its first argument, with backends
`Io.Threaded`, `Io.Uring`, `Io.Dispatch` and `Io.Kqueue` in tree.

> **Superseded in part on 2026-09-30.** The three gaps below were real when
> they were written, and all three are closed now — none of them by zio. The
> list is kept as written because it is the reason this record exists; what
> closed each gap, and against which lines of the 0.16.0 std tree, is in
> [Reconsideration of 2026-09-30](#reconsideration-of-2026-09-30).

ozai needs three things the stock surface does not obviously give it:

1. **Control messages on send and receive.** QUIC carries ECN codepoints as
   ancillary data, and a P2P stack that drops ECN cannot report congestion to
   the path it actually used. `std.Io.net` has `OutgoingMessage.control` and
   `IncomingMessage.control` in the type, but zio's `std.Io` bridge implements
   `netSendImpl` as one `sendmsg` per `OutgoingMessage` and `netReceiveImpl` as
   one `recvmsg` per call. The plumbing exists; the control-message path needs
   verifying against the chosen backend rather than assumed.
2. **Socket options.** `SO_REUSEPORT` for the v4/v6 socket pair, `SO_REUSEADDR`
   for a rebind. The `std.Io.net` surface does not expose setters.
3. **An event loop that is finished.** `Io.Evented` — the alias switch that
   would let one build run against whichever backend is best — is, in zio's
   author's words, not finished. Anything that depends on backend selection is
   depending on something that does not exist yet.

Plus the ordinary things: structured concurrency, cancellation, timeouts that
clean up after themselves, and a coroutine runtime so blocking-looking code is
cheap.

## Options

### `zio` — lalinsky/zio, MIT, v0.18.0, `minimum_zig_version = "0.16.0"`

Three layers, each usable alone:

- **`zio.ev`** — callback event loop over io_uring, epoll, kqueue, iocp and
  poll, with ~50 op types and a `LoopGroup`.
- **`zio.coro`** — stackful coroutines with growable stacks, no I/O attached.
- **`zio.Runtime`** — work-stealing or pinned scheduler over the above, plus a
  complete `std.Io` implementation. `Runtime.init(allocator, options) !*Runtime`,
  `rt.io() std.Io`, `spawn` / `spawnBlocking` returning a `JoinHandle`,
  `zio.Group` for structured concurrency, `withTimeout` converting a cancellation
  into a timeout.

`zio.net` is a superset of `std.Io.net`: `recvMsg` / `sendMsg` with control
messages, the `SO_*` setters, and `HostName.lookup`.

Consumes as a plain library dependency:
`b.dependency("zio", .{ .target, .optimize }).module("zio")`.

**Chosen on 2026-09-29. Not adopted, and reversed on 2026-09-30.** It supplies
all three gaps, it is on 0.16.0, it is MIT, and its `std.Io` bridge means
anything written against `std.Io` runs on it unmodified — which is what keeps
the rest of ozai portable if the substrate is ever swapped. The portability
argument was right, and it outlived the dependency: the tree got portable
without it.

The survey above is carried over **unverified**. zio was read from a checkout
outside this repository (`README.md:92`), never vendored here, and not re-read
on 2026-09-30 the way
[`0001`](0001-transport-substrate.md#correction-of-2026-09-30) re-read the
vendored tree. The one claim this project acted on — that the bridge
sends one datagram per `sendmsg` — was taken as a design constraint and paid for
in `src/transport/batch.zig`, which is evidence the constraint held without ever
being tested against zio.

### `std.Io.Threaded` / `Io.Uring` directly

**Rejected on 2026-09-29, taken on 2026-09-30.** No dependency, and correct for
a first milestone. Rejected then for gaps 2 and 3: no socket setters through the
stock net surface, and no usable `Io.Evented` alias.

Both claims were re-read on 2026-09-30 against the 0.16.0 tree this project
pins (`build.zig.zon:5`), and one of the two is no longer true.

- **Gap 3 is closed.** `std.Io.Evented` exists — `lib/std/Io.zig:31-37` — and
  resolves to `Io.Uring` on Linux, `Io.Kqueue` on the BSDs and `Io.Dispatch` on
  Apple. It is `void` only where `Io.fiber.supported` is false, which is every
  architecture but `aarch64`, `riscv64` and `x86_64`
  (`lib/std/Io/fiber.zig:1-4`), so on the targets ozai builds for it is a real
  alias rather than `void`.
- **Gap 1 is closed on `Io.Threaded` and only on the receive side of
  `Io.Uring`.** `Io.Threaded` carries control messages in both directions and
  batches sends: `netSendOnePosix` (`lib/std/Io/Threaded.zig:12748`) sets
  `msghdr.control` at `:12763-12764` and calls `sendmsg` at `:12769`;
  `netSendManyPosix` (`:12805`) sets it per message at `:12826-12827` and calls
  `sendmmsg` at `:12836`; `netReceivePosix` (`:12877`) calls `recvmsg` at
  `:12911`. `Io.Uring` receives with control (`netReceive`,
  `lib/std/Io/Uring.zig:5056`, control at `:5078-5079`) but **cannot send a UDP
  datagram at all**: `netSendUnavailable` (`:5042`) answers `error.NetworkDown`
  at `:5053`.
- **Gap 2 is not closed, and is therefore ours.** `std.Io.net` still exposes
  no generic `setsockopt`. The one option in the stock surface is
  `ListenOptions.reuse_address` (`lib/std/Io/net.zig:229-230`), which is
  `SO_REUSEPORT` on POSIX — and it belongs to `Server.listen` (`:246`), so it is
  not reachable for a datagram socket. `UDP_SEGMENT` and `UDP_GRO` are the
  options the relay batch path needs, and std has no spelling of either.

So the option this record rejected is the one taken, with one caveat: the
transport layer owns the syscalls, and the backend is free to be whichever `Io`
the process was built on. The "ordinary things" the other option listed are in
stock too — `Io.Group` (`lib/std/Io.zig:1218`) with `async` at `:1240`, `await`
at `:1282` and `cancel` at `:1298`, implemented by every backend in the tree
(`Io/Threaded.zig:2176`, `Io/Uring.zig:1796`, `Io/Dispatch.zig:1380`,
`Io/Kqueue.zig:765`); `Io.Timeout` (`:1132`) carrying `.duration` or
`.deadline` and answering `error.Timeout` (`:1137`); and `Io.async` (`:2326`).

## Decision

**No runtime dependency. `std.Io` is the substrate, chosen per process, and it
appears at the edges only.** *Reversed from "zio is the runtime" on 2026-09-30;
see [Reconsideration of 2026-09-30](#reconsideration-of-2026-09-30).*

The load-bearing part was never the runtime's name. It is *where* a runtime is
allowed to appear, and that is unchanged:

```
  ozai.base            pure. Never sees Io, never sees a runtime.
  wire codecs          pure. Never sees Io, never sees a runtime.
  state machines       pure over state, with time passed in as data.
  ────────────────────────────────────────────────────
  ozai.transport       the UDP socket — ours: cmsg, GSO, GRO, setters.
  ozai.endpoint        tasks, cancellation, shutdown. std.Io + Io.Group.
```

Everything above the line is testable with no runtime at all, which is the whole
point of drawing the line there. A runtime is what the socket and the task
scheduler need; it is not something the protocol logic is allowed to know
about, and which one it is is not the protocol logic's business.

No layer moved. `ozai.transport` owned the socket before and owns it now — it
just owns it in `std.c` rather than through `zio.ev`. `ozai.endpoint` owned
tasks, cancellation and shutdown before and owns them now. The only thing this
correction removes is a name, which is why `docs/ARCHITECTURE.md`'s layering
(`ozai.transport — the QUIC seam. Owns the socket.`, `:20-22`) is still exactly
what this record says it is.

Consequences worth stating, because they will be argued about later:

- **Tests of protocol logic construct their own time.** A timestamp or a
  duration is an argument; nothing in this project asks an `Io` what time it
  is. A test that has to stand up a runtime to check a state transition has
  found a boundary in the wrong place. This consequence needed no correction,
  and `0001` spent its largest phase buying it: 60 hidden-input call sites in
  the vendored core became two parameters.
- **An `Io` is never stored.** It is a parameter to the functions that need it,
  exactly like any other `std.Io`. A struct holding an `Io` cannot be driven
  twice with different clocks, and that is the property the design is for —
  written before it was load-bearing, and the reason the runtime turned out to
  be a choice rather than a fact. It holds in the tree: `io: std.Io` is a
  parameter in three places across two files, and `src/base/key.zig:131`,
  `src/transport/quic_bridge.zig:455` and `:656` are all of it.
  `src/transport/quic_bridge.zig:415-417` says so of itself. The sharper
  statement is `src/endpoint/endpoint.zig:27-37`: the two operations that do
  need a runtime — spawn a task, cancel one — are named as `Action` values and
  performed by the caller, with the `Io` the caller already holds for the
  socket.
- **The GSO path is ours, and it is written.** `src/transport/batch.zig` is the
  batch seam: a send is bytes, a segment size and ancillary data, and what the
  socket refuses comes back as a `Report`. `UDP_SEGMENT` and `UDP.GRO` are read
  from the std tree rather than typed in (`batch.zig:99` and `:102`, off
  `std.os.linux.UDP.SEGMENT` and `.GRO`), and a platform that refuses them
  takes the one-datagram path the record promised — which is a value a test can
  read, not a wire that got slower.
- **A test that needs a runtime stands one up over `std.Io`.** `zig build test`
  is the runner and it stays the runner. There is no fourth test runner here.

## Revisit if

*Both original triggers are kept, each with what happened to it on 2026-09-30.*

- `Io.Evented` lands and the stock backends gain the socket setters and control
  messages. **Half fired on 2026-09-30, in 0.16.0.** `Io.Evented` landed
  (`lib/std/Io.zig:31-37`) and so did control messages
  (`Io/Threaded.zig:12763-12769`, `:12826-12836` and `:12911`;
  `Io/Uring.zig:5078-5079` for receive only). The setters did not:
  `std.Io.net` still has no generic `setsockopt`. Half a trigger is not the
  whole argument, and the half that did not fire is why the reversal rests on
  what was built rather than on this list — see
  [Reconsideration](#reconsideration-of-2026-09-30).
- zio's `std.Io` bridge keeps `netSendImpl` single-datagram. Never tested,
  because zio was never added. The consequence the record named is now the
  reason *not* to add it: the batch path would then only ever be exercised
  through `zio.net`, one layer above the socket this project wrote.

And the trigger this record could not have, because on 2026-09-29 the endpoint
did not exist: [the trigger to reopen it](#the-trigger-to-reopen-it).

---

## Reconsideration of 2026-09-30

This section reverses the dependency and changes nothing else. The layering, the
purity rule and the consequences above are the decision; "zio" was the label on
the bottom two rows, and the label is what turned out to be wrong.

### Why reversal rather than deferral

Deferral was the other honest-looking answer, and it does not survive contact
with the tree.

1. **There is nothing to schedule.** No file under `src/` or `test/` calls
   `Io.async`, `Io.Group.async`, or a zio spawn. The endpoint's tasks are
   values: `Action.spawn` carries a `Task` struct the caller drives to the end
   (`src/endpoint/endpoint.zig:136-138`), and `:27-37` of the same file gives
   the reason the file is shaped that way. A scheduler taken on for work that
   does not exist is a dependency every later reader pays to understand.
2. **All three gaps are closed without it.** Control messages, socket options,
   GSO and GRO: `src/transport/batch.zig`, plus the socket seam in
   `ozai.transport` that this milestone lands beside this record —
   `src/transport/socket.zig` was not in the tree when this was written. An
   event loop that is finished: `Io.Evented` (`lib/std/Io.zig:31-37`).
   Structured concurrency, cancellation, timeouts and coroutines: `Io.Group`,
   `Io.Timeout`, `Io.async` (`Io.zig:1218`, `:1132`, `:2326`), implemented by
   every backend in tree.
3. **The reason zio was chosen became a reason to be able to drop it.** The
   argument was portability: a runtime behind one `std.Io` can be swapped.
   Threading `io` as a parameter and never storing it is what makes any runtime
   substitutable, zio included, and that property was bought by the vendoring
   phase in [`0001`](0001-transport-substrate.md#execution-record-of-2026-09-30)
   rather than by this dependency — `src/transport/quic_bridge.zig:34-39`
   records it as a finding: `std.Io` reaches the vendored core nowhere, and `io`
   appears on one function and nowhere else.
4. **Deferring would have been dishonest in one specific way.** This record's
   own second trigger says that on zio the batch path is exercised only through
   `zio.net`, a weaker test than it looks. Adopting zio later therefore costs
   something: it costs a rewrite of the socket seam, at exactly the moment a
   runtime is finally wanted and the seam is finished. Waiting made adoption
   more expensive, not less — which is the opposite of what deferral means.

The mistake being avoided is one this project has already written down once.
`0001` records taking a QUIC stack; this record records taking a runtime. In
both cases the question is not "is this the best available implementation" but
"what in this repository needs it yet", and on 2026-09-29 the honest answer for
a runtime was nothing.

### What is preserved

Stated again, so a reversal cannot be read as a licence to move the boundary:

- **`ozai.base` and the wire codecs stay pure.** No `Io`, no clock, no
  environment, no allocator it was not handed (`AGENTS.md` §2,
  `docs/ARCHITECTURE.md:36-38`). `src/relay/`, `src/router/`, `src/net/` and
  `src/blobs/` hold no `Io` instance at all; `src/discovery/` names
  `std.Io.net.IpAddress`, which is a value type and not a runtime.
- **The runtime stays at the edges.** `ozai.transport` owns the socket,
  `ozai.endpoint` owns tasks and shutdown, and neither may expose which runtime
  it is built on. This is why the reversal is cheap: there is no module to
  rewrite, only a name to change.
- **An `Io` is threaded and never stored.** Unchanged, and it is the property
  that made the reversal possible rather than a consequence of it.
- **Tests construct their own time.** Unchanged.

One consequence is **added**, because a reversal with no burden on it is a
decision nobody has to honour: *the transport layer may not assume which `Io` it
was given.* `Io.Uring` cannot send a UDP datagram in 0.16.0
(`lib/std/Io/Uring.zig:5042-5053`), so a socket written against `std.c` and a
process whose runtime is `Io.Evented` — which resolves to `Io.Uring` on Linux —
are not the same program unless the send path is ours. It is ours, and that is
the second reason owning the syscalls was worth the divergence.

### One stale line, in a file this record does not own

`docs/ARCHITECTURE.md:40-43` says "The runtime is `DECISIONS/0002`: zio, used at
the transport and endpoint layers and invisible above them". The last clause
still holds and is what this record kept. One word in it is now wrong — `zio` —
and it is not this file's to change.

### The trigger to reopen it

Reopen the runtime question — with a fresh read of zio and of `std.Io`, not with
this record's summary of either — when **a connection becomes a task rather
than a value**: when `ozai.endpoint` needs a join set and per-peer cancellation
that `Action` values can no longer name. In `docs/PLAN.md` terms that is M11+,
one process running relay, discovery and gossip at once, where each of those is
a long-lived actor loop instead of a function the caller drives.

The questions to answer then, in this order:

1. Does `Io.Group` (`lib/std/Io.zig:1218`) give the per-peer shutdown the
   endpoint's order requires — handlers, then cancel, then close — or does it
   need a scheduler underneath that this process would not otherwise have.
2. Do the GSO batches go out through a backend's `sendmmsg`
   (`lib/std/Io/Threaded.zig:12836`) or through the socket seam's own `sendmsg`
   carrying `UDP_SEGMENT`. The seam answers this already; it must not be
   re-litigated because a runtime arrived.
3. What a timeout that cleans up after itself costs on `Io.Timeout`
   (`lib/std/Io.zig:1132`) against zio's `withTimeout`. If std cannot express a
   deadline registry that cancels its own timers, that is the one gap worth a
   dependency, and it should be measured before it is paid for.
