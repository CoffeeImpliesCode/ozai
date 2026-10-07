# 0003 — Public contract cutover

- **Status**: accepted, recorded 2026-10-03.
  Decision criteria below were extended on the same date from the same source
  audit; they are judgment, not acceptance evidence. No gate, build or coverage
  result is reproduced in this record. The current native run of the package
  is the README's *Current native gate record* and the matching section of
  [`0004`](0004-vendored-core-contracts.md); nothing in either extends a count
  in this file into a claim about a consumer.
- **Audit baseline**: `b7e2d4f2e43ec546f124f7bce27c2e06a453f83b`;
  Zig 0.16.0, native x86-64 Linux. Runtime evidence below is separate from the
  source audit; this pin is not a claim about a later build.
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

The acceptance pass also reproduced an overflowing index in `Recv.datagram`.
The method promised null for an absent datagram but multiplied before checking
bounds. Checked multiplication now rejects that index in checked and unchecked
builds. The regression uses an index that would otherwise wrap to datagram zero.

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
a path with no peer address — and nothing is built in those cases. One further
check inside `closeRun` is a backstop against a bug in the slot arithmetic
rather than a room answer. Room running out between datagrams returns the exact
prefix it produced; a caller must drain until the answer is empty.
`Stream.drain` reserves before it reads, so a refused sink leaves every byte
pending and a retry yields them once.

`pkarr.Packet.signable`, `Packet.encode` and `signableForm` return
`pkarr.EncodeError`, which is `error{BodyTooLarge}` alone. They write into
buffers sized for the longest legal form.

The pkarr fuzz consumer now handles those error unions too. Relay `Health`
decoding rejects invalid UTF-8 with `error.InvalidUtf8`, as encoding already
does. Version rejection still precedes text validation; a v2 peer's Health
frame remains `error.FrameNotAllowedInVersion`.

A gossip `handle` that answers `error.OutOfMemory` leaves a valid state that is
not the state it was given. Restoring the caller's own before-event copy is
supported when the output list was empty at the call; otherwise the caller
abandons that peer or topic. Replaying the same event is not promised
idempotent.

`Command.quit` promised that a node that has left holds no broadcast tree, a
lazy queue or a payload cache a later event could reach. `plumtree.State` now
carries a `left` latch beside `leave`, and `handle` returns on it, so the
promise is a fact about the state rather than about how empty its fields
happen to be. `hyparview.State` and `hyparview.TopicState` carry the same
latch at their own level. A caller that drove a state past a quit and saw it
answer again now sees it answer nothing.

### Defaults and security

`Config.expect_peer` is no longer erasable by `require_peer_certificate = false`.
A config that names a peer always asks for a certificate and enforces the pin.
A config that names no peer and asks for no certificate still accepts an
anonymous peer.

Direct and custom routes can be unpinned when `require_peer_pin = false`.
Relay routes still need a peer id because their map key includes it. The earlier
claim that every synthetic route requires an id was a documentation error.

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

## Decisions and counterchoices

These grades describe this cutover's design judgments, not endorsements by Zig
or iroh authors. Each entry states what was chosen, what forced it, what a
consumer pays for it, and the setting in which the counterchoice wins; none of
them is a test result or a claim of acceptance for a repair.

### Bounded connection output

- **Priority**: preserve protocol state when caller output space runs out.
- **Constraint**: the caller already owns a bounded transmit buffer, and a
  connection contains pointers into its own storage.
- **Consumer cost**: a short result is a committed prefix; drain again until
  empty. The caller still sizes and owns the buffer.
- **Counterchoice**: a callee-owned growing output wins when callers have no
  reusable buffer and need one collected result; it transfers allocation and
  teardown duties to them. Copying a self-referential connection is not a safe
  rollback strategy and is not an alternative.
- **Grade and origin**: `analyst-inferred`, this implementation audit.

### In-place gossip transitions

- **Priority**: keep protocol state a directly driven value.
- **Constraint**: producing actions can fail after state changes. The current
  method does not implement rollback.
- **Consumer cost**: callers must follow the documented failure residue,
  restore a supported before-event snapshot, or abandon the state; blindly
  replaying an event is not safe.
- **Counterchoice**: transactional transitions win when callers must retry
  without retaining a snapshot. They require reserving every output allocation
  before changing state or maintaining rollback for each transition.
- **Grade and origin**: `analyst-inferred`, this implementation audit.

### Allocator placement

- **Priority**: make allocation authority visible without duplicate ownership.
- **Constraint**: value maps can accept an allocator per operation; core-owned
  connections must later be freed through their owning manager.
- **Consumer cost**: map calls carry the same allocator each time. Bridge,
  dialer and node owners retain an allocator that must outlive teardown.
- **Counterchoice**: a retained allocator on a map wins when its allocation
  domain is fixed and many short-lived callers mutate it; those callers no
  longer pass an allocator but cannot choose a domain per operation.
- **Grade and origin**: `analyst-inferred`, this implementation audit.

### A discovery tie is won on address values

- **Priority**: two services reporting one node must settle on one item without
  talking to each other.
- **Constraint**: an item is a node id, a sorted address list, a provenance and
  an optional timestamp, and no service stamps both an address and a source the
  same way — so ties are the normal case, not the exception. Upstream derives no
  order on the item at all.
- **Consumer cost**: `Item.order` compares timestamp, then node id bytes, then
  the address lists element by element in `TransportAddr.order`, then the list
  length, then `Provenance.rank`; the winner is the greatest of those, so a
  fresher stamp wins first and a stamp-less stream can only win when nothing
  else separates the items (`Item.order` in `src/discovery/item.zig`). Two
  services reporting the same address and stamp are ordered by provenance.
  `.eq` requires every compared field to match. Ordering is not deduplication:
  the resolver preserves provenance-specific items, and the record encoding
  identifies an address on the wire rather than supplying a sort key.
- **Counterchoice**: ordering by the encoded record wins for an implementation
  that already holds the bytes and wants a single comparator for identity and
  order. It reorders merges whenever a ticket encoding moves, and it can pick a
  different relay than the sorted `NodeAddr` list it was handed.
- **Grade and origin**: `analyst-inferred`, this implementation audit.

### CID index synchronization is all-or-nothing

- **Priority**: keep routing keys and the counters that describe them in step.
- **Constraint**: the core synchronizes a connection's live CIDs and peer reset
  tokens after every datagram, and both maps can grow. A refusal part-way would
  otherwise leave a key indexed without its registration count, or a reset token
  indexed under a generation that has already moved.
- **Consumer cost**: `Bridge.recv` answers `error.OutOfMemory` for such a
  refusal. It does not mean the connection died, and it does not mean the input
  may be replayed: the packet is processed and the routing keys stay valid. The
  caller retries `manager.syncCids` on live entries before sending newly issued
  CIDs, or closes the owner (`src/transport/quic_bridge.zig:157-160`, `:864-867`).
  A refusal leaves indexed keys, registration counts and the synchronized
  generation unchanged; only map capacity may have grown.
- **Counterchoice**: a best-effort sync that indexes whatever fit wins for a
  receive path that cannot retry. It leaves a key routable that the manager can
  no longer retire, which is the route-to-freed-memory failure the same module
  documents.
- **Grade and origin**: `analyst-inferred`, this implementation audit.

### One datagram on the wire, one truth about it

- **Priority**: get every datagram onto the wire exactly once, and report what
  it actually carried.
- **Constraint**: one send is a batch the kernel may refuse in the middle — it
  may refuse to segment, and it may drop a control message the caller asked
  for. The runs before the refused one are already out, so a whole-batch retry
  would duplicate them.
- **Consumer cost**: a run refused for segmentation ends the first pass; the
  runs behind it go out one `sendmsg` at a time after segmentation is lowered
  for good, and the report stays `degraded` for the rest of that socket's life
  (`src/transport/socket.zig:1192-1224`). A run that went out *without* its ECN
  codepoint is sticky: it is reported as lost, and nothing behind it clears
  that, because each run carries its own control message
  (`walkRuns` in `src/transport/socket.zig`). A refused segmentation is answered by
  the tail and is not reported about the codepoint at all.
- **Counterchoice**: resending the whole batch after a mid-batch refusal wins
  where a duplicated datagram is cheaper than a per-datagram tail. It puts a
  second copy of datagrams a peer has already counted on the wire, which a
  receiver checking an expected count will step over rather than see.
- **Grade and origin**: `analyst-inferred`, this implementation audit.

### A stop is a message, and the next send spends it

- **Priority**: end a wait that has been cancelled without letting a datagram
  already queued be read as the answer to a later query.
- **Constraint**: the socket is opened with `std.c.socket`, so no backend has
  been told the descriptor exists and readiness is a `poll` over two
  descriptors this module owns — the socket and an `eventfd` in semaphore mode.
  A flag consulted around the call is consulted once per call, not once per
  wait.
- **Consumer cost**: `Socket.stop` sets a flag and writes one wake unit; the
  waiter, not the caller, empties the queue, because the stop may arrive while
  the socket is being polled. The next **send** is what clears it: flag first,
  then queue, then wake counter, and a stop raised inside that window leaves the
  flag up and a unit standing (`src/transport/socket.zig:1138-1162`). The drain
  and the counter are bounded by `max_discarded` and `max_wakes_spent`;
  exceeding either answers `error.Interrupted` and leaves the socket stopped so
  the next send drains again. `Stop.request` is a different thing: it does not
  raise this wake, so a node notices it at the next poll timeout.
- **Counterchoice**: a flag-only stop with no wake descriptor and no drain wins
  for a socket whose queue can never hold an answer to a later query. This
  socket is bidirectional and does not know which queries are outstanding, so a
  leftover datagram is exactly what the drain exists to prevent.
- **Grade and origin**: `analyst-inferred`, this implementation audit.

### A consumed timer is the caller's, and a snapshot cannot hold it

- **Priority**: let a caller recover from a refused event without inventing
  protocol state.
- **Constraint**: a timer belongs to the caller — the state queues it and the
  caller fires it — so a `handle` call cannot know whether the timer it is being
  asked about is still in that queue. A latch saying "a timer is outstanding" is
  only true between the append that published it and the call that consumes it.
- **Consumer cost**: a `.timer_expired` event is delivered *because* the caller
  took that timer out of its queue. A snapshot restored after a refused `handle`
  carries whatever latch that timer had set, with no timer behind it, so the
  caller must re-queue the timer it consumed or leave that latch clear
  (`State.handle` in `src/gossip/plumtree.zig`). The copy is `@sizeOf(State)` with no
  allocation — `plumtree.State` and `hyparview.TopicState` hold no slice of
  their own storage — and restoring is supported only when the output list was
  empty at the call. This is the timer half of the residue named under *In-place
  gossip transitions*, not a second rule.
- **Counterchoice**: transactional transitions win when a caller must retry
  without keeping a snapshot; they require reserving every output allocation
  before changing state, or maintaining a rollback for each transition. That is
  a second copy of every rule in `handle`.
- **Grade and origin**: `analyst-inferred`, this implementation audit.

### Safety and language fixes

Cancellation remains distinct from entropy loss because `std.Io` publishes
both results. A configured peer pin must verify that peer, irrespective of an
anonymous-peer default. An absent datagram index must return null as promised.
Borrowed views and shallow owner copies cannot prove liveness or exactly-once
teardown through their Zig types. These are correctness or language constraints,
not taste choices with an unsafe counterpreference.

## What is not claimed

No iroh interoperability, performance number, C ABI or cross-platform result is
claimed here. The cross-platform matrix is reported by `cross-test`, and this
record says nothing about it.

The cutover this document records is closed on the consumer side. All six
out-of-tree consumer programs pass in Debug and ReleaseSafe, 18/18 steps per mode.
[`0004`](0004-vendored-core-contracts.md) reports that run with what each
program observed. The three attempts that blocked that run failed in the
consumer's own source, not in this package. Coverage against the source this
cutover produced is measured, and the README states the units it counts and
what they do not measure. All six programs also passed in both modes against
a declared-source archive fetched and extracted by Zig's package manager.
At archive creation, 16 required files, including lint config and contract
documents, and all 74 changed Zig files matched the tested source byte for byte.

No node-level 0-RTT feature is claimed either. What this record states is the
boundary the handshake enforces; whether a node ever sends early data is a
separate question that [`0004`](0004-vendored-core-contracts.md) also leaves
open.
