# 0001 — Transport substrate

- **Status**: accepted, recorded 2026-09-29. Execution happens at M8, not now.
- **Milestones 2–7 are unaffected.** Everything they build is pure over bytes.

## Context

ozai cannot interoperate with iroh without QUIC, and iroh's QUIC is not stock.
iroh 1.3.0 depends on `noq` / `noq-proto` / `noq-udp`, n0's own fork of QUIC
carrying multipath `PathId` and QNT (`draft-seemann-quic-nat-traversal-02`).
There is no QUIC in the Zig 0.16 standard library, and `std.crypto.tls` has a
client-only driver with no server and no raw-key certificate support.

Three requirements decide this, in order:

1. **Sans-IO packet ingress and egress.** ozai owns the transport multiplexer
   (IP + relay + custom), and must be able to hand a received datagram to QUIC
   and take an outgoing datagram back, per connection, with the QUIC stack never
   owning a socket. A stack that writes directly to its own fd is unusable
   here, however good it is otherwise.
2. **Ed25519 peer authentication via a raw public key.** iroh's identity model
   is TLS 1.3 where the certificate is a 44-byte DER `SubjectPublicKeyInfo`
   wrapping the 32-byte node id, in both directions — the dialer presents one
   too. Verification reduces to a byte comparison against the id you expected.
   A stack that insists on parsing X.509 cannot be an iroh peer.
3. **Proven interop.** Retry, resumption, 0-RTT, handshake and transfer, against
   more than one independent implementation.

## Options considered

### `endel/quic-zig` — Zig 0.16.0, MIT, v0.5.0

- **Sans-IO**: `ConnectionManager.recvDatagram(bytes, from, local, ecn, out_buf) RecvAction`
  is the ingress seam; `entry.conn.send(out_buf) -> usize` is egress, with the
  caller performing the `sendto`. Requirement 1: **pass**.
- **Ed25519**: `signCertificateVerify` already has an `.ed25519` branch signing
  from the raw seed, and `verifyCertificateVerifySignature` already implements
  `.ed25519`. The server sends the leaf verbatim and never parses it, so a bare
  Ed25519 SPKI can be presented as the certificate. The gap is narrow and
  named: `clientProcessCertificate` and `serverProcessClientCertificate` both
  gate on X.509 parsing, and `TlsConfig.skip_cert_verify` defaults to `true`.
  Requirement 2: **pass with a bounded patch** — two functions and one flag.
- **Interop**: matrix dated 2026-09-18 against quic-go-interop and quiche-qns.
  retry, resumption, zerortt, handshake, transfer, longrtt, blackhole and ipv6
  pass in all four directions. Requirement 3: **pass**.
- **Multipath**: not implemented. See the cost below.
- **Licence**: MIT. **Version**: pins `minimum_zig_version = "0.16.0"`.

### `zigstack/zquic` — Zig 0.16.0, MIT, v1.7.86

Rejected on two independent, disqualifying grounds:

- `Server.feedPacket` gives ingress, but egress is
  `fn flushSendBatch(self) { self.send_batch.flush(self.sock); }` — every
  outgoing datagram goes to the socket the server holds. No send callback, no
  drain-outgoing API. Requirement 1: **fail**.
- Its vendored TLS offers only ECDSA and RSA signature schemes. `PrivateKey` is
  `union { rsa, ecdsa }` with no Ed25519 member. `processServerFlight` is
  documented "Certificate is NOT verified — accepts any", and
  `verifyClientCertificateVerifyMessage` handles ECDSA only. Requirement 2:
  **fail**.

Its own CI classifies retry, resumption and 0-RTT against quinn as
`EXPECTED_UNSUPPORTED` rather than failing them, and its roadmap lists
DPLPMTUD, the DATAGRAM extension and BBR as unimplemented. That is the
maintainer's own assessment, and it is the right one to weigh.

### `c4milo/colibri` — 0.6.0, Apache-2.0, Zig 0.16.0

Architecturally the closest match to `AGENTS.md` §2 — sans-IO, owns no socket,
no allocator, no clock, octets in and events out, time passed in. Rejected
because its TLS is a C11 dependency (`c4milo/chapulin`) and its own Limits
section rules out 0-RTT, connection migration, HTTP datagrams, multipath and
QUIC v2. One star, created 2026-09-16. **Re-check when it grows.**

### `ericsssan/zquic` — MIT, sans-IO

The best interop table of anything surveyed (22 tests against 11
implementations) and it has Ed25519 and P-256 certificates. Rejected:
`minimum_zig_version = "0.17.0-dev.657+2faf8debf"`. Unusable on 0.16.0.

### Bind `cloudflare/quiche` over C

The fallback, and the shape the fallback takes: `quiche_config_verify_peer` is
the only verification knob, and `quiche_conn_peer_cert` returns the peer leaf
DER — which, combined with `verify_peer(false)`, is enough for iroh's
byte-comparison model. `quiche_conn_send_on_path` gives per-path egress with a
caller-chosen source and destination.

Cost: roughly one person-week to bind, plus a permanent C/FFI and a Rust
toolchain on the build path. `ChainSafe/quiche-zig` exists and is not worth it —
0 stars, one fork, treat it as scaffolding and write the extern block by hand.

## Decision

**Fork `endel/quic-zig` into the project, strip the parts ozai must not have, and
apply the raw-SPKI TLS patch.**

Concretely, at M8:

1. Vendor the sans-IO core (`connection.zig`, `connection_manager.zig`,
   `tls13.zig`, packet parsing) into `vendor/quic/`.
2. **Delete** the socket-owning layer (`ecn_socket.zig` and its xev event-loop
   wiring) rather than leaving it unused. That also removes the forced
   `link_libc` and the `endel/libxev` dependency, both of which are
   consequences of owning a socket — which ozai has decided not to let it own.
3. Patch `clientProcessCertificate` and `serverProcessClientCertificate` to
   accept a DER SPKI whose only member is the raw 32-byte Ed25519 key, and to
   compare it against the expected node id rather than walking an X.509 chain.
4. Set `skip_cert_verify = false` and keep the verifier and session-store
   identities stable across every client-config construction, or 0-RTT silently
   stops working.
5. Expose it as a module: `b.addModule("quic", …)` consumed by
   `ozai.transport`.

Pin by commit SHA. quic-zig publishes no tags.

## What we give up, and what it costs

**Native multipath.** quic-zig has `paths: [2]NetworkPath` with one active index
and RFC 9000 migration; it does not implement `draft-ietf-quic-multipath`, and
iroh wants up to 8 concurrent paths per connection.

The mitigation is iroh's own, and it is the reason the design is survivable:
the synthetic-ULA map presents relay and custom paths as RFC 4193 unique local
addresses (`fd15:070a:510b:0000/0001/0003::/64`, fixed port 12345) so that one
connection carries a relay path and N direct paths **without the QUIC stack
knowing**. So the cost is not correctness, it is convergence speed: with two
network paths ozai holds a relay path and one direct path at a time, where iroh
holds up to eight. A peer behind a hostile NAT may take longer to reach a direct
path, and `MAX_QNT_ADDRESSES` pruning becomes the tuning knob that matters.

If that turns out not to be good enough, the follow-up is to extend quic-zig's
path table rather than to reimplement QUIC. It is recorded here so the decision
is revisited on evidence rather than on frustration.

**Fork maintenance.** quic-zig is one small project with no tags. The fork has to
be rebased when it moves, and the patch is ours to carry. That is a real cost
and it is accepted: the alternative is a C dependency plus a Rust toolchain in
the build, permanently.

**No QUIC v2, no DPLPMTUD on the vendored path.** Neither is in `SPEC/STATUS.md`
as done. Neither blocks an iroh peer.

## Revisit if

- quic-zig gains a stable release tag, or its Ed25519 raw-SPKI support lands
  upstream, in which case drop the fork and consume the dependency directly.
- A sans-IO QUIC with per-path egress, Ed25519 certificates and multipath appears
  on 0.16.x. `ericsssan/zquic` is the closest thing seen and only needs 0.16
  support.
- `c4milo/colibri` ships a native TLS and closes the gaps in its Limits section.
- The convergence cost above shows up in measurement, in which case the path
  table is extended before anything else is considered.
