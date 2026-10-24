# Architecture

## Layers

| Layer | Responsibility |
|---|---|
| Application protocols | Gossip, blob transfer, and application stream handling |
| Router | Dispatch by negotiated ALPN through a `ProtocolHandler` vtable |
| Endpoint and Node | Peer identity, connection lifecycle, transports, and protocol composition |
| Transport | QUIC adapter, stream ownership, path mapping, and native socket I/O |
| Relay and discovery | Relay framing and clients, DNS TXT, pkarr, address lookup and publication |
| Network policy | NAT classification, holepunch decisions, candidate paths, and ECN |
| Base | Keys, addresses, base32, and explicit entropy input |

The package exports separate `ozai` and `quic` modules.
`src/root.zig` defines the public `ozai` namespaces.
The [vendored core](../vendor/quic/VENDORED.md) does not own sockets.
The native transport adapter owns the operating-system boundary.

## Inputs and ownership

Wire codecs and state machines consume supplied bytes, time, entropy, and state.
They do not read a process clock, environment, or hidden allocator.
`SecretKey.generate` is an explicit entropy operation and borrows `std.Io`.
Runtime operations borrow `std.Io`. Its backend must outlive the operation and its tasks.
A caller can drive the same state machine with fixed time and deterministic entropy.

Allocating owners require exactly one teardown. A shallow copy does not duplicate ownership.
Borrowed views do not extend an owner's lifetime.
Runtime owners require serialized access unless their API states otherwise.
Public fields do not authorize direct mutation that violates a type's invariants.

`FrameSorter.pop`, `ReceiveStream.read`, and `CryptoStream.read` return owned allocations.
Callers release them with the allocator specified by the owning stream.
Public stream handles borrow their connection's stream map.
Pin a handle across connection processing and release the pin before teardown.

## Transport and cancellation

Pure address mapping represents relay and custom paths as synthetic IPv6 addresses.
Transport state retains stable mappings. Base functions construct and classify values only.
The router dispatches ALPN without implementing the selected protocol.
The reserved `/iroh-qad/0` ALPN is not offered by the endpoint.

The Linux socket driver uses libc syscalls and raw `poll`.
Passing `std.Io` supplies cancellation checks, not an alternate network backend.
Runtime cancellation alone does not wake that poll.
Use a documented stop operation or a finite timeout.
A stop request does not join or dispose an owner. Wait for its run operation before teardown.

DNS UDP and TCP fallback share a request budget.
Operation-local lookup cancellation leaves the resolver available for another query.
Global resolver cancellation is terminal.
Parsed TXT answers own copied bytes. Borrowed record sets must outlive their streams.

## Protocol limits

Node serves blob GET requests, not GetMany, Observe, or Push.
A blob response's claimed size is not a verified length.
Nonterminal Bao proofs authenticate selected bytes, not the total-size claim.
The getter applies a finite proof budget before it accepts response data.

Gossip receive accepts encoded messages up to 4,096 bytes.
Gossip send requires fewer than 4,096 bytes, including scope, round, and TTL encoding.
Preflight rejects oversized input before it changes output, timers, or statistics.

Some blob variants, ticket policies, interface discovery, topic tables, statistics,
ECN policies, budgets, and relay authorization models remain standalone.
The full upstream interoperability matrix and Node-level authenticated 0-RTT remain incomplete.
Core tests do not establish that Node exposes every core capability.

## Coverage policy

The strict gate runs configured checks, then uninstrumented builds and tests in both safety modes.
Its test scope is `test`, `test-portable`, `quic-test`, `invariants`, and `test-gate-policy`.
Declaration sweeps run within those test roots. They are not runtime coverage credit.

The explicit `measure` command captures schema-3 instrumented data under `GATE_SCRATCH`.
That directory must be absolute, owned by the caller, mode 0700, and on a non-NFS filesystem.
Capture retains binaries, raw counters, reports, compiler identity, and runtime-object identity.
The source inventory includes test sources and records absent roots.

`OZAI_COVERAGE_POLICY` selects an external JSON file with the `Ledger` schema from
`scripts/coverage_policy.zig`. It is not a checked-in Markdown record.
The policy binds the exact measurement path and SHA-256, source digest, compiler,
complete scope, both modes, cold-item decisions, and unmapped/unowned counts with reasons.

Replay rehashes source files and artifacts, including the original coverage runtime object.
It checks raw completeness, report rows, exact-PC projection, counters, and exact cold tuples.
Every cold tuple needs a matching policy decision. Extra or stale decisions fail.
The tuple identity is `mode`, `path`, `source_sha256`, `line`, and `unit`.
Project-unmapped and source-unowned counters require exact per-mode counts and reasons.

The line denominator includes positive numeric DWARF rows, not only instrumented PCs.
Positive GNU-PC mappings supply line hits. Unresolved ownership remains outside the source denominator.
Line coverage does not establish branch coverage, interoperability, or production reachability.
See the [README](../README.md#development-checks) for commands.
