# 0002 — Async substrate

- **Status**: accepted, recorded 2026-09-29.
- Related: [`0001-transport-substrate.md`](0001-transport-substrate.md).

## Context

Zig 0.16 replaced the old `std` I/O surface with `std.Io`: a 109-entry vtable
that every I/O-capable call now takes as its first argument, with backends
`Io.Threaded`, `Io.Uring`, `Io.Dispatch` and `Io.Kqueue` in tree.

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

**Chosen.** It supplies all three gaps, it is on 0.16.0, it is MIT, and its
`std.Io` bridge means anything written against `std.Io` runs on it unmodified —
which is what keeps the rest of ozai portable if the substrate is ever swapped.

### `std.Io.Threaded` / `Io.Uring` directly

No dependency, and correct for a first milestone. Rejected as the project's
steady state for gaps 2 and 3: no socket setters through the stock net surface,
and no usable `Io.Evented` alias. Worth revisiting if zio is ever abandoned,
because the smaller dependency is genuinely attractive.

## Decision

**zio is the runtime, threaded explicitly, at the edges only.**

The load-bearing part is *where* it appears:

```
  ozai.base            pure. Never sees Io, never sees zio.
  wire codecs          pure. Never sees Io, never sees zio.
  state machines       pure over state, with time passed in as data.
  ────────────────────────────────────────────────────
  ozai.transport       zio.ev — the UDP socket, cmsg, GSO.
  ozai.endpoint        zio.Runtime — tasks, cancellation, shutdown.
```

Everything above the line is testable with no runtime at all, which is the whole
point of drawing the line there. zio is what the socket and the task scheduler
need; it is not something the protocol logic is allowed to know about.

Consequences worth stating, because they will be argued about later:

- **Tests of protocol logic construct their own time.** No `zio.Clock`, no
  `Io.Clock` — a timestamp or a duration is an argument. A test that has to
  stand up a runtime to check a state transition has found a boundary in the
  wrong place.
- **`rt.io()` is never stored.** It is a parameter to the functions that need
  it, exactly like any other `std.Io`. A struct holding an `Io` cannot be driven
  twice with different clocks, and that is the property the design is for.
- **The GSO path is ours.** zio's bridge sends one datagram per `sendmsg`;
  relay batch frames want `UDP_SEGMENT`. `std.os.linux.UDP.SEGMENT` (103) and
  `UDP.GRO` (104) both exist in the 0.16 std tree, so the batcher is written at
  the transport seam with a graceful fallback to one-datagram sends, not as a
  patch to zio.
- **A test that needs a runtime uses a real one.** zio ships its own 0.16 test
  runner for exactly that. Reusing it is cheaper than inventing a fourth thing,
  and it is the same harness upstream validated against.

## Revisit if

- `Io.Evented` lands and the stock backends gain the socket setters and control
  messages. That removes the two real reasons to depend on zio, and dropping a
  dependency is worth more than the remaining conveniences.
- zio's `std.Io` bridge keeps `netSendImpl` single-datagram. Not fatal, but it
  means the relay's batch path is never exercised through the `std.Io` path and
  only through `zio.net` — a weaker test than it looks.
