# 0002 — Async substrate

- **Status**: accepted, recorded 2026-09-29. **Reversed 2026-09-30**; see
  [Reconsideration of 2026-09-30](#reconsideration-of-2026-09-30). The
  layering is unchanged and is now the whole decision. What reversed is the
  dependency. **Reconsidered 2026-10-01**, answer unchanged; see
  [Reconsideration of 2026-10-01](#reconsideration-of-2026-10-01). What
  expired is the reason the reversal was given, not the reversal.
  **Re-cited 2026-10-04**: every `lib/std` reference was re-read against the
  pinned tree and still holds. The `socket.zig` line numbers did not, because
  that file split into send, receive and control modules; they are replaced by
  the names those lines still carry. No conclusion changed.
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
  ozai.base            pure values. One explicit entropy edge —
                       SecretKey.generate(io) — never stored, never ambient.
  wire codecs          pure. Never sees Io, never sees a runtime.
  state machines       pure over state, with time passed in as data.
  ────────────────────────────────────────────────────
  ozai.transport       the UDP socket — ours: cmsg, GSO, GRO, setters.
  ozai.endpoint        tasks, cancellation, shutdown. std.Io + Io.Group.
```

Everything above the line is drivable without a runtime of its own — the
entropy edge takes the caller's `Io`, and a test passes a fixed one — which is
the whole point of drawing the line there. A runtime is what the socket and the
task scheduler need; it is not something the protocol logic is allowed to know
about, and which one it is is not the protocol logic's business.

**The first row is the one that needs the qualification, because
`ozai.base` does name `std.Io`.** `SecretKey.generate` (`src/base/key.zig:204`)
takes `io: std.Io` and draws the secret from it. That is an entropy *bridge*,
not an ambient dependency: the source is the caller's argument, it is never
stored, and it is the only way entropy enters the module. What the row is
describing is everything else in it — `NodeId`, `Signature`, `RelayUrl`,
`IpAddress`, `SocketAddr`, `CustomAddr`, `TransportAddr` and `NodeAddr` are
values, they hold no `Io`, and their operations touch no socket, no clock and no
entropy of their own. A test can drive every one of those with a fixed `Io`, and
so can a caller that wants a different entropy source.

That qualification is about ownership, not about strength. `SecretKey.generate`
draws through `Io.random`, which the standard library documents as seeded by
`Io.randomSecure` *or by a less secure mechanism when that fails*
(`lib/std/Io.zig:2462-2469`). The node's runtime generator is a separate seam:
the pre-cutover source owns a `std.Random.DefaultCsprng`, seeded at full width
from the caller's `io.randomSecure`, with temporary seed bytes wiped on exit.
Explicit caller-supplied randomness remains a simulation input. These are
source ownership facts, not a claim that a verification gate has passed.

No layer moved. `ozai.transport` owned the socket before and owns it now — it
just owns it in `std.c` rather than through `zio.ev`. `ozai.endpoint` owned
tasks, cancellation and shutdown before and owns them now. The only thing this
correction removes is a name. The transport boundary in
[`ARCHITECTURE.md`](../ARCHITECTURE.md#layering) still owns the socket.

Consequences worth stating, because they will be argued about later:

- **Tests of protocol logic construct their own time.** A timestamp or duration
  is an argument; state transitions do not read an `Io` clock. Runtime bridges
  such as `node_runtime.run` read time and pass it into the protocol logic.
  A test that needs a runtime just to check a state transition has found a misplaced
  boundary. `0001` replaced 60 hidden-input sites in the vendored core with
  explicit time and randomness.
- **An `Io` is never stored.** It is a parameter to the functions that need it,
  exactly like any other `std.Io`. A struct holding an `Io` cannot be driven
  twice with different clocks, and that is the property the design is for —
  written before it was load-bearing, and the reason the runtime turned out to
  be a choice rather than a fact. `SecretKey.generate`, `Bridge.create`,
  `Socket.send` and `Socket.tryReceive` take `io` explicitly; the call-site
  count is not an invariant. The pure endpoint's `Action` values name spawning
  and cancellation for the caller to perform with its runtime.
- **The GSO path is ours, and it is written.** `src/transport/batch.zig` is the
  batch seam: a send is bytes, a segment size and ancillary data, and what the
  socket refuses comes back as a `Report`. The socket layer uses
  `std.os.linux.UDP.SEGMENT` and `.GRO`; it does not duplicate their values.
  A segmentation refusal lowers the capability and sends the unsent tail
  one datagram at a time. The report preserves both degradation and ECN loss.
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
   (`src/endpoint/endpoint.zig:161-178`), and `:27-37` of the same file gives
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

- **`ozai.base` and the wire codecs stay pure.** No ambient `Io`, no clock, no
  environment, no allocator it was not handed (`AGENTS.md` §2,
  `docs/ARCHITECTURE.md:36-38`). The one `Io` in `ozai.base` is the explicit
  entropy parameter of `SecretKey.generate`, which the diagram under *Decision*
  now carries. `src/relay/`, `src/router/`, `src/net/` and `src/blobs/` hold no
  `Io` instance at all; `src/discovery/` names `std.Io.net.IpAddress`, which is a
  value type and not a runtime.
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

### The stale line this record named, now corrected

`docs/ARCHITECTURE.md` used to carry "The runtime is `DECISIONS/0002`: zio,
used at the transport and endpoint layers and invisible above them". The `zio`
half was wrong, and it has been replaced: the layering paragraph there points
at this record, names `Io.Threaded` as the current driver, and gives the reason
out of the pinned standard library. The "invisible above them" clause was
always the part that mattered and still is, so nothing above the line moved.

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

---

## Reconsideration of 2026-10-01

**The reversal stands.** No runtime dependency, `std.Io` is the substrate, and
`Io.Threaded` is what a process will be built on. Nothing below the line moves
and no module changes.

The reason it stood on 2026-09-30 was "there is nothing to schedule". That
premise has expired. What replaces it is not a preference; it is two facts
about the tree and the toolchain, and neither of them is about zio.

### What expired, and what did not

The 2026-09-30 trigger was "a connection becomes a task rather than a value" —
the M11+ milestone in [`PLAN.md`](../PLAN.md). **Its precondition has fired and
the trigger has not.** `Task` is still a value the caller drives
(`src/endpoint/endpoint.zig:69-76`), and `Io.Group`, `Io.async`, `Io.Uring`,
`Io.Evented` and `Io.Timeout` name nothing under `src/`, `test/` or `build.zig`.

What is new is everything *around* the hole. Four endpoints finish a handshake
over real sockets and converge on one membership in a single synchronously
driven round loop: `Mesh.round` (`test/protocol_loopback_test.zig:966-976`)
advances a counter and then runs, per node, `Wire.take` (`:620`) and
`Wire.flush` (`:662`), then the protocol and the timers. Six sockets, six
connections, one loop, no scheduler. The relay registry is complete and driven
by nobody.

So the project is one function short of this question. The useful work now is
naming that function before it is written, and saying what shape it is allowed
to have. That is what the rest of this section does.

### The narrow question

Not "which runtime". **What has to happen between `Action.spawn` and
`Reaped`, and what has to hold the `Io` while it happens.** Two facts answer
it.

1. **The socket asks the runtime for one thing, and it is not I/O.** `Socket`
   holds `handle`, `wake`, `stopped`, `family`, `caps` and `address`, and no
   `Io` (`src/transport/socket.zig:190-208`). Every operation that can be
   cancelled takes `io: std.Io` and calls `io.checkCancel()` and nothing else:
   `Socket.send` at `:318` is the one in this file, and the send, receive and
   control paths carry their own. The wait before a read is a `poll` on the
   descriptors this module opened (`recv_path.awaitReadable`), and no backend
   has ever been told either of them exists.

   So `Io.Uring` is a worse fit rather than a better one. It cannot send a UDP
   datagram at all — `netSendUnavailable` (`lib/std/Io/Uring.zig:5042`) answers
   `error.NetworkDown` at `:5053` — and `Io.Evented` resolves to `Io.Uring` on
   Linux (`lib/std/Io.zig:31-37`). **This is a fact about the toolchain and it
   survives either outcome of this record.** It was true on 2026-09-30, it is
   true now, and it would be true if the project wanted a scheduler badly.
2. **`Io.Threaded` answers that one call for the price of an atomic load.**
   `checkCancel` (`lib/std/Io/Threaded.zig:2411-2414`) is `Thread.checkCancel`,
   which loads `thread.status` monotonically (`:914`) and stores only on the
   `.canceling` arm (`:922-928`). A datagram send is a syscall; the cancel
   check is not what would ever be measured.

### `Io.Group` cannot express `Action.spawn`; `Io.async` can

This is the 2026-09-30 section's first reopen question, answered by reading the
tree rather than by choosing.

- **`Io.Group` is a group, not a join handle.** `Group.async` returns `void`
  (`lib/std/Io.zig:1240`), its function must be coercible to `Cancelable!void`,
  and the error is discarded at `:1245`. `Group.await` returns `Cancelable!void`
  (`:1282`). `Group.cancel` cancels *every* member of the group (`:1298-1300`).
  Nothing in it names which task ended, how it ended, or which one to stop.
- **`Action.spawn` needs all three.** It carries a `Task`
  (`src/endpoint/endpoint.zig:161-178`), the caller drives it to the end, and
  the loop is owed a `Reaped` naming the id and one of three endings —
  `finished`, `cancelled`, `panicked` (`:94-101`) — of which `panicked` is the
  only beginning that is not somebody's request.
- **`Io.async` is the same size and has all three.** It returns `Future(Result)`
  where `Result` is the function's own return type
  (`lib/std/Io.zig:2326-2330`), and `Future.cancel` (`:1191`) and
  `Future.await` (`:1199`) are per-future.

So the shape this decision serves is: **one `Io.Group` for the endpoint's
shutdown, one `Io.async` per accepted connection.** The split is not a
compromise, it is the router's own order. `Group.cancel` *is* the
`cancel_accepts` arm (`src/router/router.zig:718-719`, emitted at `:810-811`),
which by construction falls after every handler has reported and before the
close (`:714-724`), and a `Future` is what lets one peer be stopped without
cancelling every other accept with it.

The cost on `Io.Threaded` is a growable worker pool rather than a thread per
connection: `groupAsync` prepends to `t.run_queue`
(`lib/std/Io/Threaded.zig:2226`) and spawns a worker only when the pool has no
idle thread (`:2205-2216`), under an `async_limit` (`:2197`). Bounded, visible,
and worth stating here rather than discovering later.

### The caller, named

`Action.spawn` and `Action.shutdown` are values for a caller to perform with
its runtime. At the 2026-09-30 reconsideration that caller had not yet been
written. The node cutover names the outer driver `node_runtime.run`; the CLI
driver remains in `src/node/main.zig`. This paragraph is not a current claim
that the package installs only a library.

Its shape is not free. The tree already fixes it:

- It threads `io` into `Socket.send`, `Socket.tryReceive` and `Bridge.create`.
  The loopback consumer does this in `Wire.take` and `Wire.flush` in
  `test/protocol_loopback_test.zig`.
- A caller of the pure endpoint loop owns the task handles and reports
  `Event.arrived`, `Event.reaped` and `Event.close_requested` through `Loop.step`.
- Protocol time is an argument. The outer `node_runtime.run` reads the clock
  at the bridge; the protocol loopback consumer constructs its instants.

Written that way it is a `main` over `Io.Threaded`. Nothing in it needs a third
runtime, and nothing in it may reach above `ozai.endpoint`.

### Node ownership cutover

The canonical node data owner remains `src/node/node.zig`, exposed as
`root.node.Node`. There is no second `NodeData` type or `node_data.zig`.
The chosen API moves existing implementation bodies into free functions whose
first node argument is `*node_mod.Node`; it does not keep forwarding methods,
`Node.module` namespaces, public alias bundles or back-compat facades.

The role owners are explicit:

- `node_lifecycle.zig`: create, register and deinit, with one heap allocation
  owning the node and its existing storage lifetimes.
- `node_runtime.zig`: start, step, wait, run, wind-down and disposal, the outer
  orchestration that may call the lower-level close owner.
- `node_lane.zig`: registered accept and shutdown callbacks and lane shutdown.
- `node_accept.zig`: accept-task admission and driving.
- `node_dispatch.zig`: endpoint actions and shutdown dispatch.
- `node_connection_close.zig`: connection-close and close-drain operations.
- `node_close.zig`: graceful node close, protocol retirement, cancellation and
  protocol/lane inspection.
- `node_ingress.zig` and `node_egress.zig`: intake/delivery and drain/expiry.
- `node_gossip.zig`: the existing gossip state-machine inputs and actions.
- `node_relay_serve.zig` and `node_relay_client.zig`: the existing relay roles.
- `node_relay_registry.zig`: relay registration and release.
- `node_error.zig`, `node_protocol.zig`, `node_config.zig`, `node_stats.zig`
  and `node_framing.zig`: their canonical leaf types and operations.
- `node_report.zig`: the existing reporting bodies; CLI role wording stays in
  main rather than creating a dependency back to the CLI.

Data does not import these processors; production dependencies below the outer
driver do not import `node_runtime.zig`. The task-driving path goes from runtime
to accept, dispatch and connection-close owners. Close uses dispatch and the
connection-close owner without calling back into the runtime. Lane callbacks
use the relay-registry owner; relay serving also uses that registry and the
client owner's queue-depth read. These boundaries keep the existing work under
its canonical owners without dependency cycles, a new scheduler or a change to
the protocol state machines.

The node address is fixed before registration stores `&node.lanes[index]` in
each router handler's `ptr`. Each lane keeps its existing `owner: *Node`, a
copied caller handler or built-in protocol choice, per-lane turn state and
shutdown accounting. The node cannot be copied or moved after those pointers
are installed. ALPN bytes and caller handler userdata retain their existing
borrowed lifetimes; the registered table and offer list are fixed at creation.
Shutdown releases the protocol's own resources before cancelling its accepts;
retiring one lane does not retire another. The callback entry points change
owners, not the callback targets or their lifetime.

`Io` is still passed explicitly to operations that need it and is never stored
in the node. Time and randomness remain supplied state-machine inputs, with
the outer driver reading time and using the node-owned production generator.
The step order stays intake, sweep, admit, drive, relay, drain, expire, gossip.
This cutover does not turn counted gossip actions into network work.

Ownership determines the split, and the Wave 1 structural requirement also
limits each module to 250 nonblank, noncomment production lines, including
imports and braces. The integrated module counts and runtime/test gates remain
for the parent to verify before declaring that requirement closed. This record
does not claim a green size gate, a completed Wave 1 or a Wave 2 implementation.

### What would make the other shape right

The project is not choosing between a thread pool and a poll loop over its own
descriptors. **It already has the poll loop**: `recv_path.awaitReadable` polls
the descriptors `Socket` opened, `tryReceive` answers `error.WouldBlock` as a
value, and `Wire.take` treats exactly that as the loop's exit
(`test/protocol_loopback_test.zig:620-629`). The runtime is one atomic load
around those syscalls and nothing else.

A runtime that owned readiness *and* the sends would become right when:

1. **`Io.Uring` can send a UDP datagram.** `netSendUnavailable`
   (`lib/std/Io/Uring.zig:5042-5054`) becomes a real send path. Until then
   `Io.Evented` on Linux cannot send what this project produces. This is the
   constraint that survives either outcome, and it is the only one of the three
   that is about the toolchain rather than about this project.
2. **ozai stops owning the descriptor**, so that a backend has been told about
   it. `Socket.create` is the reason it does: `SO_REUSEPORT` must be set
   before the bind and `std.Io.net` has no spelling of it. Handing the
   descriptor to a backend means giving up `UDP_SEGMENT`, and the 2026-09-30
   section's second question forbids re-litigating that because a runtime
   arrived.
3. **The poll loop is measured to be the bottleneck.** A number — round count
   and socket count at which it was measured — not a forecast about swarms. The
   six-socket mesh is not it.

### The layering, unchanged

Restated in substance, because a reconsideration that moved it would be a
different decision and this one does not:

- **Wire codecs and network state machines stay pure.** They read no clock or
  environment and use only explicit allocators. `SecretKey.generate` is an
  entropy edge with an explicit `Io` parameter, not pure key derivation.
- **The runtime stays at the edges.** `ozai.transport` owns the socket,
  `ozai.endpoint` owns tasks and shutdown, and neither exposes which runtime it
  is built on.
- **Drivers borrow `Io` per operation.** The backend and its userdata outlive
  all tasks that use them. `Socket` keeps the descriptor, not a backend.
- **Tests construct their own time.** The round loop advances a counter and
  reads no clock (`test/protocol_loopback_test.zig:967-968`).

**One count from the 2026-09-30 wording is superseded, and the correction is kept
rather than dropped.** That date described `io: std.Io` as a parameter "in three
places across two files". The Decision section above carries no call-site count
to update: it names the four functions that take `io` and states that the count
is not an invariant. The cutover threads `io` through key generation, bridge
send/drain operations and socket operations. Documentation mentions, private
helpers and test doubles are not a public-parameter count. The earlier
13-match lexical survey mixed those categories and is withdrawn; it does not
measure the published surface. The explicit-runtime rule is unchanged.

### The trigger to reopen it again

In the direction chosen — towards a runtime that owns readiness — reopen on any
one of these, each measured against the tree this project pins and never
against this record's summary of it:

1. **`Io.Uring` can send a UDP datagram.** Re-read `lib/std/Io/Uring.zig:5042`
   and find a send path. This one alone changes the shape: `Io.Evented` becomes
   an option, `Io.async` could be `Io.concurrent` (`lib/std/Io.zig:2365`), and
   the worker pool could be fibers (`lib/std/Io/fiber.zig`).
2. **`std.Io.net` gains the socket setters** — `SO_REUSEPORT` before the bind,
   `UDP_SEGMENT`, `UDP_GRO` — which would end `socket.zig`'s reason for owning
   the descriptor. This is the first revisit trigger and it is still half fired
   (`lib/std/Io/net.zig:229-230`, `:246`). It carries more weight than it did on
   2026-09-30: it is the only trigger that would make a backend's own send path
   competitive with the seam this project wrote.
3. **A node's connection count makes the poll loop the bottleneck.** A number,
   not a forecast.
4. **The caller exists and its join set wants more than one `Io.Group` plus one
   `Future` per peer give.** Concretely: some ending
   `src/endpoint/endpoint.zig:78-98` names cannot be produced as a `Reaped`, or
   the handlers-then-cancel-then-close order (`src/router/router.zig:714-724`)
   cannot be expressed that way.

And in the other direction — towards *less* runtime — reopen if the caller is
written and turns out to need no `Future` and no `Group` at all: only the poll
loop `recv_path.awaitReadable` already is.
