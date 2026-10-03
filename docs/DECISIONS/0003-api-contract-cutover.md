# 0003 — Public contract cutover

- **Status**: accepted, recorded 2026-10-03. Audit pin: `b7e2d4f2`, native
  Zig 0.16.0, x86-64 Linux.
- Related: [`0001-transport-substrate.md`](0001-transport-substrate.md) (the
  vendored QUIC core this cutover also reaches),
  [`0002-async-substrate.md`](0002-async-substrate.md) (the `Io` seam the
  cancellation repairs run through).

## Context

An audit read every published declaration in this package and reported nine
reproduced defects: an out-of-tree consumer could not build the package at all,
a refused allocation lost bytes a peer had already been sent, a `Cancel` became
an entropy fault, a `Node` returned from `run` leaving its socket open, a
duplicate address leaked a payload, two values that should have compared equal
did not, a copied `Join` answered about the value it was copied from, an empty
shutdown stalled, and an empty byte range became a one-chunk range.

The audit also found contracts stated by the code but not by its
documentation: ownership of shallow copies, what a `null` means, which ranges
are valid, what a callback borrows and on which thread it runs.

## What changed, and what it costs a consumer

### Consuming the package

`build.zig` opened `vendor/quic/src` from the *consumer's* working directory,
so `b.dependency("ozai", …)` aborted before any module was built. Paths resolve
from the package root now, and the package registers two modules: `ozai` and
`quic`. `ozai` imports the QUIC core internally; a consumer names the core's
types by importing `quic` separately. There is no `ozai.quic` alias.

Fetched packages now carry `README.md`, `TODO.md` and `docs/`.

### Ownership

`NodeAddr` owns the outer address list it allocates and borrows every
`CustomAddr.data`. A successful insert replaces the previous outer storage; a
duplicate, a `null` or a refusal leaves the receiver unchanged.

`BlobTicket.new` **transfers** the address list to the ticket. A caller that
built one and used to free the address itself must drop that and call
`ticket.deinit`. `EndpointTicket.new` **borrows**, because that type has no
teardown.

`discovery.Published` carries the allocator its outer list came from, so an
ignored or replaced publish releases it correctly. `PkarrPublisher` holds no
allocator and releases each slot with the one that arrived with it.
`PkarrPublisher.init` lost its allocator parameter.

### Errors and partial results

`Bridge.create` answers `error.Canceled` for a cancelled entropy draw rather
than folding it into `error.EntropyUnavailable`. `Conn.drain` raises
`error.NoRoom` only up front — an empty `out`, a buffer under `min_datagram`, or
a path with no peer address — and nothing is built in those cases. Room running
out between datagrams returns the exact prefix it produced; a caller must drain
until the answer is empty. `Stream.drain` reserves before it reads, so a refused
sink leaves every byte pending and a retry yields them once.

`pkarr.Packet.signable`, `Packet.encode` and `signableForm` return
`pkarr.EncodeError`, which is `error{BodyTooLarge}` alone. They write into
buffers sized for the longest legal form.

A gossip `handle` that answers `error.OutOfMemory` leaves a valid state that is
not the state it was given. Restoring the caller's own before-event copy is
supported when the output list was empty at the call; otherwise the caller
abandons that peer or topic. Replaying the same event is not promised
idempotent.

### Defaults and security

`Config.expect_peer` is no longer erasable by `require_peer_certificate = false`.
A config that names a peer always asks for a certificate and enforces the pin.
A config that names no peer and asks for no certificate still accepts an
anonymous peer.

`BytesToChunks` maps an empty or inverted range to the empty chunk range rather
than to one chunk. `relay.encode` refuses text that is not UTF-8 under
`error.InvalidUtf8`, the name `decode` already returned.

### Copy semantics

`net_report.Report.eql` compares a preferred relay by `RelayUrl.order`, so the
bytes past `host_length` no longer decide it. A settled `Join` copied after
settlement answers from its own recorded set. `holepunch.decide` takes a
`Candidates` struct and `holepunch.settle` no longer takes a local set; a caller
written against the old signatures has to pass the set it already had.

### Teardown

`Node.run` closes the node on every exit, including a first clock reading it
cannot use and a graceful close that fails. The primary error is what it
returns; the cleanup never replaces it.

## Why these and not the alternatives

A snapshot of a `Connection` (about 185 KB with pointers into itself) was
rejected as a way to make `Conn.drain` all-or-nothing: it copies per pass and
its own copies dangle. A commit boundary checked before each `sendAt` costs one
bounds check and no invariant.

Snapshot recovery for a gossip `handle` was kept rather than transactional
rollback because rollback puts a second opinion about the protocol on every
event, and the snapshot is a value copy of a few KB. The alternative is stated
at the declaration rather than left for a caller to discover.

Keeping cancellation distinct from entropy loss follows from `std.Io`'s own
types: `RandomSecureError` carries both tags, and a caller whose cancellation
stopped the operation is not told its entropy source is broken.

## What is not claimed

No iroh interoperability, performance number, C ABI or cross-platform result is
claimed here. The cross-platform matrix is reported by `cross-test`, and this
record says nothing about it.
