# 0001 — Transport substrate

- **Status**: accepted, recorded 2026-09-29. **Corrected 2026-09-30** against a
  measured read of the vendored tree; see
  [Correction of 2026-09-30](#correction-of-2026-09-30). **Executed at M8 on
  2026-09-30**; see
  [Execution record](#execution-record-of-2026-09-30), which names what is
  still open. Item 3 of that list closed after M8; see
  [Still open](#still-open-after-m8).
  **Updated 2026-10-05** against the parent's final Wave 1 runs: the live exchange
  now has receipts from one current binary, the vendored core and the first-party
  suite are both green, and item 8 has closed. Item 9 is still open — see
  [Still open](#still-open-after-m8), where the three remaining names are.
- **The decision is unchanged.** What moved is the price, twice over.
  quic-zig is still the substrate; the work to make it ozai's is 60 hidden-input
  call sites threaded through, plus a 7,194-line layer that was never copied,
  plus the whole X.509 chain walk deleted rather than flag-gated, where the
  first version billed "two functions and one flag". One instruction in that
  first version was wrong in a way that would have failed at M8, and one of its
  estimates was low by the largest phase of the milestone.
- **Milestones 2–7 are unaffected.** Everything they build is pure over bytes.

Every quic-zig claim below was read out of the tree at
`endel/quic-zig@14b9dc3e5e8429d07e7ed18619c7b4f4baaa3719` (2026-09-28) and is cited
by file and line. Line counts are `wc -l` on that tree, whose 74 `.zig` files
under `src/` were fetched and byte-compared against the git tree sizes.
Claims about the *rejected* candidates are marked where they were re-checked on
2026-09-30 and carried over unverified where they were not.

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
3. **Demonstrated interop.** Retry, resumption, 0-RTT, handshake and transfer,
   against more than one independent implementation. **Corrected**: quic-zig
   passes the cases this record names, but not the whole matrix, and the matrix
   does not pin to the commit we would vendor. See
   [Interop](#interop-the-one-claim-that-got-worse). **Where Wave 1 left it, as
   of 2026-10-05**: the native Rust partner leg runs against the **patched** tree
   and completes — **both role orders**, exits 0 and 0, exact peer ids, the agreed
   ALPN, all six declared payloads each way — and the `--require-retry` run and
   all four typed refusals are receipts of that **same** binary,
   `70567c34fdd0f513dde3c21391c50cc74e03757c2304e3f971768aef1c64c399`. The
   **upstream matrix leg is still open** and is still not reproducible from this
   repository. See [item 2](#still-open-after-m8).

## Options considered

### `endel/quic-zig` — Zig 0.16.0, MIT, v0.5.0

**Size.** 74 `.zig` files, 65,164 lines under `src/`. The sans-IO core
`src/quic/*` is 32 files and 30,437 lines, dominated by `connection.zig` (6,666),
`tls13.zig` (4,866) and `stream.zig` (3,767). Everything above the core —
`src/h3` (7,106), `src/webtransport` (3,886), `src/moq` (5,865), `src/tls` (4,887,
a second TLS-over-TCP stack unrelated to QUIC), `src/http1` (3,818) and
`src/h0` (208) — is 25,770 lines ozai has no use for.

- **Sans-IO ingress: real.** `ConnectionManager.recvDatagram(bytes, from, local,
  ecn_val: u2, out_buf) RecvAction` at
  `src/quic/connection_manager.zig:548`. `RecvAction` (`:529`) has **four** arms,
  not three: `processed` (`:531`), `send_response` (`:534`), `dropped` (`:536`),
  `foreign` (`:540`, QUIC-LB steering to another server). The caller sends
  `send_response` itself; `processed` hands back the `ConnEntry`. Requirement 1,
  ingress half: **pass**.
- **Egress: an error union, and it reads a clock.**
  `pub fn send(self: *Connection, out_buf: []u8) !usize` at
  `src/quic/connection.zig:3128` — not the bare `usize` first recorded — and it
  delegates to `sendAt(out_buf, @intCast(sys.nanoTimestamp()))` at `:3129`, so
  the convenience wrapper reads the monotonic clock itself. The seam is already
  half built: `pub fn sendAt(self: *Connection, out_buf: []u8, now: i64) !usize`
  at `:3134` takes the timestamp. Requirement 1, egress half: **pass, once the
  caller uses `sendAt`.**
- **Ed25519: present, and behind four gates plus a flag that must not be
  flipped.** See [the raw-SPKI patch](#3-raw-spki-ed25519). Requirement 2:
  **pass with a bounded but real patch** — four functions, `TlsConfig`, and
  `ClientAuth`.
- **Interop**: the one claim that got worse. See
  [Interop](#interop-the-one-claim-that-got-worse).
- **Multipath**: not implemented, by the maintainer's own statement in
  `SPEC/STATUS.md` ("Multipath QUIC (draft-ietf-quic-multipath) — **Status: Not
  implemented**"). Requirement is iroh's, not RFC 9000's. See the cost below.
- **Licence**: MIT. **Version**: `build.zig.zon` pins
  `.minimum_zig_version = "0.16.0"`, `.version = "0.5.0"`, and `.paths` of
  `build.zig`, `build.zig.zon`, `src`. Sole dependency is `endel/libxev`,
  pinned to tarball `9d7f95fc3ec34ce0a5903127a6c2f3237c1d52d3`.

### `zigstack/zquic` — Zig 0.16.0, MIT

Rejected on two independent grounds:

- **Ed25519: confirmed fail.** At `master` (`b33733d7286058857a70ecc1f8c87aa752957c72`)
  `vendor/tls/src/PrivateKey.zig:13` declares
  `key: union { rsa: rsa.KeyPair, ecdsa: [66]u8 }` with no Ed25519 member.
  Requirement 2: **fail**.
- **Egress: the first version of this record's evidence does not reproduce.**
  It cited `fn flushSendBatch(self) { self.send_batch.flush(self.sock); }`.
  `flushSendBatch` does not exist anywhere in the repository at that revision
  (code search: 0 hits); `send_batch` appears once, in `src/cmd/client.zig:153`,
  as a comment about client-side state. The *verdict* — no per-path egress seam,
  no drain-outgoing API — is **not verified** and is carried over from the
  2026-09-29 survey. Requirement 1: **fail (unverified this pass)**.

One of two grounds is enough, and the confirmed one is the disqualifier.

### `c4milo/colibri` — 0.6.0, Apache-2.0, Zig 0.16.0

Architecturally the closest match to `AGENTS.md` §2 — sans-IO, owns no socket,
no allocator, no clock, octets in and events out, time passed in. Rejected
because its TLS is a C11 dependency (`c4milo/chapulin`) and its own Limits
section rules out 0-RTT, connection migration, HTTP datagrams, multipath and
QUIC v2. Carried over from 2026-09-29 and **not re-read**. As of 2026-09-30 it
is Apache-2.0 with one star and a push later that day. **Re-check when it grows.**

### `ericsssan/zquic` — MIT, sans-IO

The best interop table of anything surveyed (22 tests against 11
implementations) and it has Ed25519 and P-256 certificates. Rejected:
`build.zig.zon` at `main` (`2ccba649370f0a8f5458ce6e1e735e3b27fa83be`) pins
`.minimum_zig_version = "0.17.0-dev.657+2faf8debf"`. Re-checked 2026-09-30, exact
match. Unusable on 0.16.0.

### Bind `cloudflare/quiche` over C

The fallback, and the shape the fallback takes: `quiche_config_verify_peer` is
the only verification knob, and `quiche_conn_peer_cert` returns the peer leaf
DER — which, combined with `verify_peer(false)`, is enough for iroh's
byte-comparison model. `quiche_conn_send_on_path` gives per-path egress with a
caller-chosen source and destination.

Cost: roughly one person-week to bind, plus a permanent C/FFI and a Rust
toolchain on the build path. `ChainSafe/quiche-zig` exists and is not worth it —
0 stars, one fork, treat it as scaffolding and write the extern block by hand.
Carried over from 2026-09-29, **not re-verified**: note that this option escapes
the threading work below entirely, because quiche is already sans-IO and takes
time as a parameter.

## Decision

**Fork `endel/quic-zig` into the project, strip the parts ozai must not have,
thread time and randomness through the core, and apply the raw-SPKI TLS patch.**

Unchanged from 2026-09-29 except for the order, which now has to put the
threading work first: the certificate patch cannot be tested on a core that
reads a clock, and a simulated handshake is the only cheap way to drive it.
The concrete plan is the next section. Pin by commit SHA — quic-zig publishes
zero tags.

## The plan, at measured size

### 1. Delete the socket-owning layer

`ecn_socket.zig` was named alone in the first version of this record. It is the
smaller half. The socket owner is `src/event_loop.zig`, at **5,211 lines** —
about nine times the 584 lines of `ecn_socket.zig` — and its
`Server.init`/`Client.init` constructors open and bind sockets before returning:
`src/event_loop.zig:856` calls `openUdpSocket(config, config.port)`, and `:892-894`
create the `xev.Loop`, the `xev.File` watch on the socket fd, and the
`xev.Timer`. A constructor with a side effect on the host network is exactly what
ozai refuses to have behind it, so this is the file that has to go.

| File | Lines | Why it goes |
|---|---:|---|
| `src/event_loop.zig` | 5,211 | the real socket owner; opens and binds in `init` |
| `src/quic/ecn_socket.zig` | 584 | 5 × `sys.socket`, 4 × `sys.bind`, `sys.sleepNs` |
| `src/http1/e2e_test.zig` | 759 | opens real TCP; binds ports 29440–29449 |
| `src/http1/socket.zig` | 364 | TCP via `std.c.accept4` (`:338`) |
| `src/http1/timers.zig` | 194 | bound to `xev.Timer` (`:43`, `:50`) via `xev_backend` (`:13`) |
| `src/test_all.zig` | 51 | **rewrite, not delete** — see below |
| `src/xev_backend.zig` | 31 | the `xev` re-export everything above reaches through |

`src/test_all.zig` is the part that is easy to miss and breaks the build: it is
the test root, and it imports three of the deleted files
(`quic/ecn_socket.zig:23`, `http1/e2e_test.zig:34`, `event_loop.zig:50`).
`zig build test` does not compile after the deletion until it is rewritten.
Rewrite it in the same commit as the deletion, not after.

`src/sys.zig` (864 lines) **splits rather than deletes.** The socket syscalls go
— `socket` (`:113`), `close` (`:154`), `bind` (`:165`), `sendto` (`:192`),
`recvfrom` (`:236`), `read` (`:267`), `write` (`:286`), `listen` (`:309`),
`resolveHost` (`:336`), `accept` (`:386`), `getsockname` (`:411`) — along with
the file and directory helpers (`File` `:584`, `openFileRead` `:693`,
`createFile` `:718`, `makeDir` `:743`, `readFileAlloc` `:785`), which duplicate
ozai's own IO. What stays is the small block the core actually needs and which
step 2 then replaces: `realtimeSeconds` (`:459`), `nanoTimestamp` (`:484`),
`randomInt` (`:499`), `randomBytes` (`:507`). `getenv` (`:532`) is an
environment read with no caller in `src/` at all — delete it.

The module root `src/lib.zig` (47 lines) re-exports the whole stack and must be
cut in the same pass, or the core does not compile: `ecn_socket` (`:15`), `h3`
(`:18`), `h0` (`:19`), `http1` (`:20`), `tls_server`/`tls_client` (`:21-22`),
`webtransport` (`:24-26`), `event_loop` (`:28`), `moq` (`:29`).

Deleting this layer also drops the forced `link_libc` and the `endel/libxev`
dependency, both of which are consequences of owning a socket that ozai has
decided the QUIC stack must not own.

### 2. Thread time and randomness in

**This is the largest single item in M8 and the first version of this record
omitted it entirely.** The vendored core is not pure over `(state, input)`. It
reads the clock and a global CSPRNG from inside the state machines, which
collides directly with `AGENTS.md` §2 and with this project's own purity
invariant. That makes it a design decision, not a chore.

Measured across `src/quic/*.zig` library code — test blocks excluded,
`ecn_socket.zig` excluded because step 1 deletes it — there are **60 call sites**
that read hidden input:

| File | Clock | CSPRNG | Total |
|---|---:|---:|---:|
| `src/quic/connection.zig` | 23 | 7 | 30 |
| `src/quic/tls13.zig` | 7 | 11 | 18 |
| `src/quic/connection_manager.zig` | 3 | 2 | 5 |
| `src/quic/quic_lb.zig` | 0 | 2 | 2 |
| `src/quic/ack_handler.zig` | 0 | 1 | 1 |
| `src/quic/qlog.zig` | 1 | 0 | 1 |
| `src/quic/rsa.zig` | 0 | 1 | 1 |
| `src/quic/stateless_reset.zig` | 0 | 1 | 1 |
| `src/quic/transport_params.zig` | 0 | 1 | 1 |
| **Total** | **34** | **26** | **60** |

`src/quic/packet.zig` is clean: its 14 `nanoTimestamp` occurrences are all
inside test blocks.

What each read is:

- `sys.nanoTimestamp()` (`src/sys.zig:484`) — `CLOCK_MONOTONIC`, RTT, PTO, idle
  timeout, keep-alive, path-challenge expiry, drain, closing backoff.
- `sys.realtimeSeconds()` (`src/sys.zig:459`) — `CLOCK_REALTIME`, for
  certificate validity and session-ticket creation time.
- `sys.randomBytes()` (`src/sys.zig:507`) — a bare `getrandom`/`arc4random_buf`
  syscall. Un-injectable by construction: there is no seed to pass in.
- `sys.randomInt()` (`src/sys.zig:499`) — wraps `randomBytes`, at
  `src/quic/ack_handler.zig` for the ACK-skip offset.

The stack already knows this is a seam and works around it globally rather than
by injection: `src/sys.zig:472` carries
`pub var test_clock: if (builtin.is_test) ?i64 else void`, read back at `:485`
by `nanoTimestamp` itself, so the library is deterministic only under
`zig build test`. That is a mutable global switched by build mode — precisely
what §2 forbids, and it is the proof that the seam was needed and not taken.

`signCertificateVerify` makes it sharper. `src/quic/tls13.zig:3316` reads
`sys.randomBytes(&noise)` **unconditionally**, before the scheme switch, and the
Ed25519 arm at `:3324-3330` passes that noise to `kp.sign`. A deterministic
Ed25519 signature needs no nonce at all, so that read is pure cost on the exact
path ozai cares about.

The destination is already in the standard library: `std.Io.Clock`
(`lib/std/Io.zig:721`) is the settable/monotonic clock seam, and
`Connection.sendAt` (`:3134`) already takes a `now: i64`. So the work is
mechanical in shape — thread a clock and a byte source down through
`ConnectionManager`, `Connection` and `Tls13Handshake`, and delete
`test_clock` — but it is 60 sites across the two largest files in the tree, and
every one of them sits on a path that has to keep its RFC behaviour.

The measurable acceptance test, and the reason this has to come before the
certificate patch: with a virtual clock the handshake runs in microseconds
instead of seconds, so the four certificate gates in step 3 can be driven
exhaustively instead of once.

### 3. Raw-SPKI Ed25519

**What upstream already does.** `signCertificateVerify`
(`src/quic/tls13.zig:3309`) has an `.ed25519` arm at `:3324` signing from the
raw 32-byte seed via `Ed25519.KeyPair.generateDeterministic` (`:3326`), and
`PrivateKeyAlgorithm` (`:40`) has `.ed25519` at `:42` mapping to that scheme
(`signatureSchemeFor`, `:51`/`:54`). `buildCertificate` (`:3260`, called at
`:1964` and `:2352`) `memcpy`s `cert_chain_der` verbatim and never parses it, so
**a bare Ed25519 SPKI can be presented as the certificate** — the first version
of this record was right about that and it remains true.

`verifyCertificateVerifySignature` (`:70`) also implements `.ed25519`, at `:92`.
But its first statement is `if (pub_key_algo != .curveEd25519) return
error.BadCertificateVerify;` (`:93`), and `pub_key_algo` is a
`Certificate.AlgorithmCategory` produced by X.509 parsing — its only two
assignments are `std.meta.activeTag(parsed.pub_key_algo)` at `:1818` and `:1840`.
The Ed25519 arm is therefore unreachable for a raw SPKI unless the extraction is
patched too. That is the first thing the first version of this record got wrong:
the gap is not "two functions and one flag".

**The four gates**, all in `src/quic/tls13.zig`:

| # | Function | Line |
|---|---|---:|
| 1 | `clientProcessCertificate` | 1754 |
| 2 | `clientProcessCertificateVerify` | 1875 |
| 3 | `serverProcessClientCertificate` | 2462 |
| 4 | `serverProcessClientCertificateVerify` | 2482 |

What each one does, and why the raw SPKI stops there:

- **`clientProcessCertificate` (`:1754`)** — `:1807-1828` lifts the leaf key only
  when `cert_hashes` is set. Otherwise `:1829` runs the X.509 walk: parse, lift,
  `verifyHostName`, issuer chain, CA bundle. A raw SPKI takes neither branch.
- **`clientProcessCertificateVerify` (`:1875`)** — `:1880` runs the CV signature
  check only when `leaf_pub_key_len > 0`, which only the two branches above ever
  set. A raw SPKI leaves it at zero, so the signature is never checked.
- **`serverProcessClientCertificate` (`:2462`)** — `:2473` calls
  `verifyPeerChain` **unconditionally**. No flag guards this one, so a client
  certificate has no raw-SPKI path at all today.
- **`serverProcessClientCertificateVerify` (`:2482`)** — `:2497-2507` re-parses
  `self.peer_cert` as X.509 and passes `std.meta.activeTag(leaf.pub_key_algo)`
  into the same guard at `:93`.

Plus two structural changes:

- **`TlsConfig`** (`:1059`). `skip_cert_verify: bool = true` at `:1076`, with
  the comment "Skip X.509 chain + CertificateVerify validation".
- **`ClientAuth`** (`:331`). `ca_bundle: *const Certificate.Bundle` is a
  non-optional, non-nullable trust anchor, and `serverProcessClientCertificate`
  reaches for it with `self.client_auth.?` at `:2465`. A raw-SPKI peer identity
  has no CA to chain to, so `ClientAuth` needs a pin field beside `ca_bundle`
  rather than a bundle alone.

`verifyPeerChain` (`:486`) takes `(chain, bundle: *const Certificate.Bundle,
now_s: i64)` and walks issuers; it is the wrong shape for a byte comparison and
is not reused.

#### Do not set `skip_cert_verify = false`

The first version of this record's step 4 said *"Set `skip_cert_verify = false`
and keep the verifier and session-store identities stable …, or 0-RTT silently
stops working."* That is wrong, and wrong in the one direction that cannot be
undone cheaply: **the flag's `false` branch is the X.509 chain validation that
must not run.** `:1829-1865` calls `certificateWellFormed`, `Certificate.parse`,
`parsed.verifyHostName` (`:1845`), `prev.verify` (`:1852`) and `bundle.verify`
(`:1860`) — hostname, issuer chain, CA bundle, and validity dates against
`realtimeSeconds`. Setting it false is how you get a stack that insists on
parsing X.509, which requirement 2 says cannot be an iroh peer at all.

The flag also conflates two independent decisions. It is one bit standing for
"walk a chain of trust" **and** "check the CertificateVerify signature". iroh
needs the first **off** and the second **on**. Neither `true` nor `false` is
that, which is why no value of the flag is the fix.

**The right move is to split them, not to set the flag:**

1. Leave `skip_cert_verify` at its default `true`, so `certificateWellFormed`,
   `Certificate.parse`, the hostname check, the issuer walk and `bundle.verify`
   never execute. The chain-validation code is then dead on this path and is
   deleted rather than bypassed.
2. In the `skip_cert_verify` branch of `clientProcessCertificate`, lift the
   32-byte key out of the 44-byte DER SPKI by decoding its BIT STRING, compare
   it byte-for-byte against the expected node id, and set `leaf_pub_key_len` and
   `leaf_pub_key_algo` to `.curveEd25519` **by construction** rather than from
   an X.509 parse. That last part is what makes `verifyCertificateVerifySignature`'s
   existing `.ed25519` arm reachable, so `:93` needs no change.
3. Change the guard at `:1880` from
   `!self.config.skip_cert_verify and self.leaf_pub_key_len > 0` to
   `self.leaf_pub_key_len > 0`, so the signature check runs on the lifted key
   whether or not a chain was walked. This is the "split the bit" step: the
   check becomes unconditional and the chain walk becomes the flag's only job.
4. Mirror all of it on the server side: replace the unconditional
   `verifyPeerChain` at `:2473` with the same byte comparison, and lift the key
   from the 44-byte SPKI at `:2497` instead of re-parsing it as X.509. Extend
   `ClientAuth` with the expected node id so the dialer presents and verifies a
   peer identity, which is what makes this a *mutual* peer check.

Upstream's own comment at `:1077-1082` states the same thing from the other
side: a certificate pin "requires `skip_cert_verify = false`, or
CertificateVerify never runs and the pin proves only that someone copied a
public certificate." The flag is load-bearing for the pin precisely because it
also gates the signature check — which is the coupling to remove.

**The 0-RTT concern in that step was real but unrelated.** Verifier and
session-store identity must be stable across every client-config construction or
resumption silently stops matching, and the two knobs are `TlsConfig.session_ticket`
(`:1085`) and `TlsConfig.ticket_key` (`:1086`). That is a separate requirement
about resumption state, it is not discharged by the `skip_cert_verify` flag, and
it is recorded here as its own item so it is not lost when the flag instruction
is removed.

`keyMatchesCertificate` (`src/quic/tls13.zig:3657`) also parses the certificate
as X.509 and demands `parsed.pub_key_algo == .curveEd25519` at `:3669`. It has
no caller outside its own tests at this revision, so it is deleted with the rest
of the X.509 machinery rather than patched.

## What we give up, and what it costs

**Native multipath.** quic-zig has `paths: [2]NetworkPath`
(`src/quic/connection.zig:608`) with a single `active_path_idx` (`:609`) and RFC
9000 migration; it does not implement `draft-ietf-quic-multipath`, and iroh wants
up to 8 concurrent paths per connection. The maintainer says so in
`SPEC/STATUS.md` and does not list it as in progress.

**The structural fact, which the estimate below did not state.** Those two slots
are an **active/candidate register, not a path set**, and accepting a second
address *is* abandoning the first. `handleMigration`
(`vendor/quic/src/quic/connection.zig:3426`) writes the new address into the
inactive slot at `:3442-3443` and flips `active_path_idx` at `:3452`; the old
slot keeps its counters, unread, until the next migration overwrites it. At the
bridge there is literally one destination per connection: `Conn.drain` stamps
every egress datagram from `conn.peer()` (`src/transport/quic_bridge.zig`),
which is `Connection.peerAddress`
(`vendor/quic/src/quic/connection.zig`) —
`&self.paths[self.active_path_idx].peer_addr`.

So **a peer reachable two ways is two connections**, not one connection with two
paths, and that is not an inference from the array's length alone.
`src/transport/dial.zig` reached it independently from the dial side and tests
it: *"two targets to one peer are two connections, because the core has one
path"* (`:1376`), asserting two live connection ids over one peer.

The mitigation is iroh's own, and it is the reason the design is survivable:
the synthetic-ULA map presents relay and custom paths as RFC 4193 unique local
addresses (`fd15:070a:510b:0000/0001/0003::/64`, fixed port 12345) so that one
connection carries a relay path and N direct paths **without the QUIC stack
knowing**. With two slots ozai holds a relay path and one direct path at a time,
where iroh holds up to eight. A peer behind a hostile NAT may take longer to
reach a direct path, and `MAX_QNT_ADDRESSES` pruning becomes the tuning knob
that matters. **That is the cost this record originally priced — convergence
speed, and a path that is one of two rather than one of eight.** It is real, it
is small, and it is not the whole cost. A peer that *migrates* pays that price
and little else; a peer that *uses both addresses at once* pays something an
order of magnitude larger, in a different unit — see
[Multipath, measured 2026-10-01](#multipath-measured-2026-10-01). The two must
not be described in the same words, and the first version of this record
described only the first.

If that turns out not to be good enough, the follow-up is to extend quic-zig's
path table rather than to reimplement QUIC. It is recorded here so the decision
is revisited on evidence rather than on frustration. **The evidence now
exists**, and it points the same way. The honest size of that follow-up is in
[The follow-up, and its honest size](#the-follow-up-and-its-honest-size), and it
is not one line.

**Fork maintenance.** quic-zig is one small project with no tags, at 57 stars,
last pushed 2026-09-29. The fork has to be rebased when it moves, and the patch
is ours to carry. The patch is now larger than a fork of an untagged
single-maintainer project usually is, which is the honest shape of this risk.
Accepted: the alternative is a C dependency plus a Rust toolchain in the build,
permanently.

**No QUIC v2, no DPLPMTUD on the vendored path.** `SPEC/STATUS.md` marks QUIC v2
(RFC 9369) ✅ Complete. DPLPMTUD is not claimed. Neither blocks an iroh peer.

**A TLS server over TCP, written rather than reused.** Wave 2's relay carrier
is RFC 6455 binary messages over an HTTP upgrade with TLS (`docs/PLAN.md`,
slice A). Upstream's TLS-over-TCP stack was never copied here, so that slice
inherits no server and writes one. It is the one exclusion in `VENDORED.md`
with a bill attached, and the bill is that slice's rather than the transport's.

**The reason this decision gave for the exclusion was too broad, and is
corrected here.** `src/http1` does own sockets, and its socket-owning files are
the real socket exclusions. Upstream's four files of `src/tls` do not. At the
pinned `14b9dc3e`, `src/tls/common.zig:1-3` names itself the helpers of "the
sans-IO TLS 1.3 `tls_server` and `tls_client`", and `src/tls/server.zig:1-8`
says "`Conn` never touches a socket: the caller feeds it the ciphertext it read,
flushes `pendingOutput()` to the peer, and moves plaintext with `read` /
`write`". No `socket`, `bind`, `listen` or `accept` appears in that file. They
were left behind with the protocol layers, and what an eventual port has to
lift is their ambient `../sys.zig` calls — `sys.randomBytes` and
`sys.realtimeSeconds`, through the single import at `server.zig:37` — into
injected entropy and an injected clock. That is port work, not socket work,
and `src/sys.zig` is gone from this module, so the seam those calls sit on does
not exist here either. **No TLS-over-TCP server and no HTTPS server exists in
this repository.** The bill stands and is Wave 2's to pay; nothing here offers
it back.

### Multipath, measured 2026-10-01

**How this was measured.** Driven directly over `Connection` with hand-built
`posix.sockaddr` values, no socket, injected clock and seeded entropy, in the
shape of `vendor/quic/src/quic/lossy_link_test.zig`'s `Pair` (`:339`): client
and server `ConnectionManager`, two addresses A and B on loopback, 10 ms one-way
delay. Every figure below was printed by that harness and repeats identically.
The harness was throwaway and has been deleted. These are measurements of
**this substrate on this harness** — not a general property of RFC 9000
migration, and not a claim about any other stack.

**A peer that migrates once, or a handful of times, is cheap.** Bounded, small,
and paid once per switch:

| case | datagrams | |
|---|---|---|
| idle connection | 2 | one PATH_CHALLENGE, one PATH_RESPONSE, zero retries |
| saturated, 77 KB cwnd, 1 MiB queued | 71 | ~3 RTTs at 20 ms; the surplus is bulk already queued, not machinery — the challenge is exempt from congestion control (`vendor/quic/src/quic/packet_packer.zig:437-440`) |
| NAT rebinding, port only, saturated | 109 | the other branch of `handleMigration` |
| worst case | 8 | 1 + 3 challenge re-sends each way, `PathValidator.MAX_RETRIES = 3` (`connection.zig:52`) |

The convergence concern this record priced is real and it is this size. A peer
behind a hostile NAT pays a few datagrams and a few RTTs to reach a direct path,
and `MAX_QNT_ADDRESSES` pruning is the knob.

**A peer that uses both addresses concurrently is not cheap at all.** Same
400 ms window, same deterministic start, the two addresses alternating every
60 ms:

| | migrations | datagrams | delivered |
|---|---:|---:|---:|
| one address | 0 | 12,147 | 15,167 KiB |
| two, alternating | 8 | 814 | 969 KiB — **6% of the single-address case** |

**It never leaves slow start, because every IP change puts the congestion window
back to 12,000** — a fresh `Cubic.init()` is
`initialWindow(1200)` = 12,000 (`vendor/quic/src/quic/congestion.zig:16`,
`:244`). **It oscillates; it does not converge.** That is a different failure
from slow convergence, and it is the one a deployment that expects a peer to
be reachable two ways actually hits. Two of the ten switches in that run cost
nothing at all, because a switch only counts as a migration when a
non-probing packet from the new address arrives before the peer moves back.

**What a migration throws away, and what it does not.** Discarded on an IP
change: congestion window (77,005 → 12,000), RTT history (`has_measurement`
true → false, `vendor/quic/src/quic/rtt.zig:31`), MTU search (1326 → 1200
`BASE_PLPMTU`, `mtu.zig:5`), ECN validator state, and the pacer budget
(`connection.zig:3461-3468`). **Kept:** `bytes_in_flight` — 72,930 before the
flip and 72,930 after, same turn — and the sent-packet map with its loss
timers. In-flight packets are not dropped, re-pathed or retransmitted. A
port-only change is the better case: it keeps cwnd, MTU and RTT and instead
calls `cc.enterRecoveryForMigration(now)`
(`vendor/quic/src/quic/congestion.zig:387`), so pre-migration losses stop
counting.

**Two results that are benign, recorded so this section does not teach a reader
to fear a thing that is often free.** A second address the peer never speaks
from costs nothing: 400 ms, 12,147 datagrams, 0 migrations, `paths[1]`
untouched, no probe sent. Nothing is learned about it and nothing is spent on
it. And the trigger is narrow — the address only has to send a **non-probing**
frame. A probing-only packet leaves `has_non_probing` false at
`connection.zig:1540` and changes nothing, and `Frame.isProbing`
(`vendor/quic/src/quic/frame.zig:727-732`) covers exactly PADDING,
NEW_CONNECTION_ID, PATH_CHALLENGE and PATH_RESPONSE.

### The follow-up, and its honest size

The remedy is unchanged: **extend quic-zig's path table rather than reimplement
QUIC.** It was recorded so the decision would be revisited on evidence rather
than on frustration, and the evidence now exists. It says extend the table, for
any deployment that expects a peer to *use* both paths rather than choose
between them. [Revisit if](#revisit-if) already names the trigger; the trigger's
remedy is the one this measurement reaches for.

It is not a one-line change and must not be quoted as one. `active_path_idx` is
load-bearing across `connection.zig`, not a field with one reader: it indexes
the active path for received-byte accounting (`:1185`, `:1429`), the
anti-amplification lift (`:1387`), the preferred-address switch
(`:2721-2729`), the connection-ID rewrite (`:1603`) and egress
(`peerAddress`, `:4327-4328`). Widening the array is the mechanical half.
Making those per-path instead of per-active-path is the other half, and it is
the half that decides whether the measurement above is fixable:

- **Congestion, RTT and ECN state would have to become per-path.** Today a
  migration *discards* them (`connection.zig:3461-3468`) precisely because
  there was only one live path to move them to. With N live paths they must be
  retained per path; if they are not, every path change still costs a fresh
  Cubic and the 6% is the ceiling rather than the current state.
- **Bytes-in-flight would have to be attributed per path.** It is one `u64`
  today (`vendor/quic/src/quic/ack_handler.zig:639`) and the sent-packet map
  has no path dimension at all — which is why the total survives a migration
  untouched. That is correct only while one path exists.
- **Path validation becomes a set of validators**, not the single
  `PathValidator` (`connection.zig:52`) the inactive slot currently borrows.
- **`draft-ietf-quic-multipath` itself stays unimplemented.** Widening the
  table is what the follow-up above has always meant; it is a precondition for
  the draft, not a claim to have implemented it.

### The estimate, restated

The first version of this record implied a patch of "two functions and one
flag" against a core of 30,437 lines. Measured, M8 is three phases in this
order:

1. **Deletion** — 7 files, 7,194 lines out, plus a `src/sys.zig` split and a
   `src/lib.zig` cut. Mechanical, but `test_all.zig` and the module root are
   load-bearing for the build and must land in the same commit as the deletion.
2. **Threading** — 60 hidden-input call sites across the two largest files,
   plus deleting the `test_clock` global. The bulk of the work, and the part
   that buys a virtual clock and therefore makes phase 3 testable.
3. **Certificates** — four gated functions, `TlsConfig`, `ClientAuth`, and a
   split of the `skip_cert_verify` bit.

Phase 2 is not optional and not smaller than phase 3. A record that says
"bounded patch" and then bills only the certificate work understates M8 by
roughly half.

### Interop: the one claim that got worse

The matrix in `SPEC/interop-results.md` is dated 2026-09-18 and was run at
quic-zig `4988228`, **not** at the `14b9dc3e` we would vendor. It uses
`martenseemann/quic-go-interop:latest` and `cloudflare/quiche-qns:latest` through
`interop/runner/matrix.sh`.

The eight cases this record names — retry, resumption, zerortt, handshake,
transfer, longrtt, blackhole, ipv6 — do pass in all four directions. But the
matrix totals are not a pass, and the first version of this record called
requirement 3 a flat pass:

| Direction | Pass | Fail | Unsupported |
|---|---:|---:|---:|
| `quic-go<-quic-zig` | 19 | 0 | 3 |
| `quic-zig<-quic-go` | 19 | **1** | 2 |
| `quic-zig<-quiche` | 11 | **7** | 4 |
| `quiche<-quic-zig` | 17 | **2** | 3 |

Ten red cells, seven of them against a conforming peer implementation. Upstream's
own write-up attributes most to the peer or the environment, and the
attributions are specific and plausible — `amplificationlimit` fails because the
runner waits for a Handshake-first datagram the quiche client never sends;
`connectionmigration` and the rebind cases need client-side behaviour quic-go
does not implement. Two are not let off that easily:

- `multiplexing` against quiche is marked **open**: quiche's client completes
  1986 of 1999 requests and times out, and fixing a real `MAX_STREAMS` bug did
  not move the number.
- `handshakeloss` and `handshakecorruption` against quiche are **slow, not
  broken** — 50 sequential handshakes under 30 % loss complete at roughly 2.7 s
  each, and quiche's client gives up. Still red, still our Initial/Handshake
  retransmission being slower off the mark than a peer will wait.

Two consequences for the record. The interop claim is **"passes the cases that
matter for iroh; 10 of 88 cells red, 1 open"**, not "pass". And the evidence
does not pin to the commit we vendor, so M8 must re-run the matrix at our own
SHA before requirement 3 is discharged.

Reproducing that matrix needs `interop/quic-interop-runner`, a git submodule
declared in `.gitmodules` and outside `build.zig.zon`'s `.paths`. It does not
block vendoring — it is simply not in the tarball. It does mean the interop
matrix is reproducible only by initialising the submodule and running
`interop/runner/matrix.sh` with Docker, `quic-network-simulator` and `tshark`.

## Revisit if

- **quic-zig fixes the 0.16 compile error and publishes a tag, or its Ed25519
  raw-SPKI support lands upstream.** Until then "drop the fork and consume the
  dependency directly" is **not available**: as of the pinned SHA the tree does
  not build on the `minimum_zig_version` its own `build.zig.zon` claims. See
  [Upstream does not compile on 0.16.0](#upstream-does-not-compile-on-0160).
- A sans-IO QUIC with per-path egress, Ed25519 certificates and multipath appears
  on 0.16.x. `ericsssan/zquic` is the closest thing seen and only needs 0.16
  support.
- `c4milo/colibri` ships a native TLS and closes the gaps in its Limits section.
- The convergence cost above shows up in measurement, in which case the path
  table is extended before anything else is considered.
- **Threading grows past the two largest files.** Executed: 60 sites, confined to
  `connection.zig`, `tls13.zig`, `connection_manager.zig` and six small files,
  with no design change and `std.Random` passed by value rather than through a
  per-connection object the caller cannot own. The trigger did not fire, and
  the fallback is not re-priced. It re-prices if a *future* change pushes the
  seam into the packet and frame layers: `quiche` is already sans-IO with time
  as a parameter, and the cost of switching is a C boundary rather than a
  rewrite of a 30,000-line core.
- **`std.Io.Evented` absorbs what libxev was doing.** Zig 0.16 already ships it
  at `lib/std/Io.zig:31` — `Uring` on Linux, `Kqueue` on the BSDs, `Dispatch` on
  Apple, and `void` where fibers are unsupported. It is a stdlib event loop with
  no dependency, which is the `libxev`/`link_libc` half of step 1 argued in
  reach anyway. If a future 0.16.x makes it usable across ozai's targets, the
  argument for forking a stack that needs its event loop cut out of it gets
  weaker, and the fallback should be re-priced.
- **A real certificate chain is ever needed.** This is the trigger the old
  `skip_cert_verify` bullet was groping at, and execution answered it: the flag
  was not a flag to bend but the wrong shape, and the fix was to delete the
  walk. So the question is no longer whether the flag resists a split. It is
  whether anything downstream needs X.509 back — an ACME client, a server
  presenting a CA-issued leaf, a WebTransport deployment whose peer brings its
  own authority. iroh's identity model needs none of those, and adding one
  means carrying the parser, the walk and the validity dates into the fork
  again. That is a rewrite wearing a patch's clothing, and it is the point to
  price `quiche`.
- **The 0-RTT item closes badly.** If a stable verifier identity across
  client-config construction turns out to need more than one constructor that
  owns `session_ticket` and `ticket_key`, the resumption design is load-bearing
  in a way the fork should not own. See
  [Still open](#still-open-after-m8).
- **Requirement 3 has to be discharged.** It is discharged against this fork or
  not at all, because upstream's interop runner is a git submodule outside the
  published package. There are two legs and they now stand differently. The
  upstream matrix leg needs that submodule plus a node with Docker and
  `quic-network-simulator`, neither of which is here, and it is **open**. The
  native `iroh = "=1.3.0"` partner leg needs neither and **has run against the
  patched tree in both roles**: exits 0 and 0, exact peer ids, the agreed ALPN
  and all six declared payloads each way, with the typed refusals and a Retry
  receipted against the same partner — and since 2026-10-05 all seven of those
  runs are receipts of one build, `70567c34…`, rather than of two. So the revisit
  trigger is now the matrix alone, and the honest shape of this item is *one leg
  met, one leg unmeasured*.

## Correction of 2026-09-30

A read-only survey of the pinned tree, followed by a line-by-line re-read of
every file cited here, found the record's cost model wrong. The decision stands.
The evidence is in [The plan, at measured size](#the-plan-at-measured-size); what
moved is:

1. **Ingress and egress.** Egress is `pub fn send(self: *Connection, out_buf:
   []u8) !usize` at `src/quic/connection.zig:3128`, an error union rather than
   the `usize` recorded, and it reads the clock itself at `:3129`. The
   `sendAt(out_buf, now: i64)` seam at `:3134` already exists and is the real
   entry point. `RecvAction` has four arms, not three.
2. **Purity, absent from the record entirely.** 60 hidden-input call sites —
   34 clock, 26 CSPRNG — and a mutable `test_clock` global at `src/sys.zig:472`.
   The vendored core does the thing `AGENTS.md` §2 forbids, and phase 2 now
   exists, is the largest item, and runs first.
3. **Ed25519.** Four gated functions, not two: `clientProcessCertificate`
   (`:1754`), `clientProcessCertificateVerify` (`:1875`),
   `serverProcessClientCertificate` (`:2462`),
   `serverProcessClientCertificateVerify` (`:2482`). Plus `TlsConfig` (`:1059`)
   and `ClientAuth` (`:331`). And `verifyCertificateVerifySignature`'s `.ed25519`
   arm is unreachable for a raw SPKI because its `:93` guard demands an
   X.509-derived `pub_key_algo` that only `:1818` and `:1840` ever set.
4. **The `skip_cert_verify = false` instruction is removed.** Its false branch
   is the chain validation, hostname check and CA-bundle verification that
   requirement 2 forbids. Replaced by a split of the bit: chain walking stays
   behind the flag, the CertificateVerify check becomes unconditional on a key
   lifted from the raw SPKI. The 0-RTT concern that shared the step is kept as
   its own item against `session_ticket` and `ticket_key`.
5. **The deletion set is much larger.** `src/event_loop.zig` (5,211 lines), not
   `ecn_socket.zig` (584), is the socket owner, and it opens and binds inside
   its constructors at `:856` and `:892-894`. With `http1/socket.zig`,
   `http1/timers.zig`, `xev_backend.zig`, `http1/e2e_test.zig` and a rewritten
   `test_all.zig`, the set is 7 files and 7,194 lines. `src/sys.zig` splits
   rather than deletes, and the module root `src/lib.zig` has to be cut.
6. **Requirement 3 is downgraded.** Ten of 88 interop cells are red, one
   (`multiplexing` vs quiche) is open upstream, and the matrix was run at
   `4988228` rather than the pinned commit.
7. **Held.** MIT, `minimum_zig_version = "0.16.0"`, version `0.5.0`, zero tags
   — so pinning by SHA is the only option. Sole dependency `endel/libxev`. The
   interop-runner submodule is outside `.paths`, so it does not block vendoring
   but does block reproducing the matrix. `signCertificateVerify`'s `.ed25519`
   arm signs from the raw seed, and the server sends the leaf verbatim without
   parsing it — that part of the first version was right.
8. **One rejected-candidate claim could not be reproduced** and is marked
   unverified: `flushSendBatch` does not exist in `zigstack/zquic` at
   `master`. Its Ed25519 disqualifier was re-checked and is exact.

---

## Execution record of 2026-09-30

M8 executed. This section is what happened, what it cost against what this
record predicted, and what it did not finish. It reopens nothing: the substrate
is quic-zig and the evidence did not say otherwise.

### What was vendored

`endel/quic-zig` at `14b9dc3e5e8429d07e7ed18619c7b4f4baaa3719`, fetched
2026-09-30 against the pinned SHA. Upstream is 74 `.zig` files and 65,164 lines
under `src/`. `vendor/quic/` is **33 `.zig` files and 30,279 lines**, measured
on this date.

The socket-owning layers were **never copied**, which is a different act from
copying them and deleting them. `src/event_loop.zig` (5,211),
`src/quic/ecn_socket.zig` (584), `src/http1/socket.zig` (364),
`src/http1/timers.zig` (194), `src/xev_backend.zig` (31) and
`src/http1/e2e_test.zig` (759) never entered the repository. Neither did `h3`
(7,106 lines), `webtransport` (3,886), `h0` (208), `moq` (5,865), `http1`
(3,818), the second TLS-over-TCP stack in `src/tls` (4,887), or
`src/quic/testdata`, which is three DER chain fixtures. The `endel/libxev`
dependency and the forced `link_libc` went with them: `build.zig.zon`'s
`.dependencies` is empty.

It is declared as its own module at `build.zig:36-40` and compiled by the
`quic-test` step at `build.zig:51-58`, because a vendored tree nothing
references is a vendored tree nobody has proved still builds.

### Upstream does not compile on 0.16.0

`build.zig.zon` pins `minimum_zig_version = "0.16.0"` and the tree does not
build. Upstream `src/sys.zig:513`, inside `randomBytes`, is
`switch (posix.errno(@as(isize, @bitCast(rc))))`: `posix.errno` wants the
`c_int` a syscall returns and `@bitCast` hands it an `isize`. The socket half
above it spells the same call correctly at `:130`, `:172` and `:205`, so this
is one mistyped line rather than a language mismatch — and it is inside the one
function the threading phase deletes anyway.

It is a small finding and it moves the cost model: the revisit trigger "drop the
fork and consume the dependency directly" has nothing to consume. See
[Revisit if](#revisit-if).

### What was deleted, and why

Deleted by never vendoring: the six socket-owning files above.

Deleted after vendoring, each because something else stopped needing it:

| Deleted | Lines | Why |
|---|---:|---|
| `src/quic/qlog.zig` | 411 | qlog wants a clock and an I/O sink; both are the caller's now, and neither is optional |
| `src/tls/test_certs.zig` | 383 | PEM fixtures for the chain walk. Nothing imported them once it was gone. |
| `src/quic/ca_bundle.zig` | — | the trust anchor `verifyPeerChain` walked to |
| the X.509 walk | — | see [below](#the-certificate-patch-is-a-deletion-not-a-split) |
| `Connection.send` | — | read the clock itself at `connection.zig:3129` upstream; `sendAt` at `:3134` already took the timestamp |
| `sys.test_clock` | — | a mutable global that made the library deterministic only under `zig build test`, which is the thing `AGENTS.md` §2 forbids |

**`rsa.zig` stayed, and it should have.** RSA is a legal TLS 1.3
CertificateVerify signature scheme — `client_auth_signature_schemes`
(`tls13.zig:279-283`) offers `rsa_pss_rsae_sha256/384/512` — even when the
certificate is a raw Ed25519 key. Certificate and signature scheme are
different things. Deleting RSA on the reasoning that an Ed25519 identity implies
an Ed25519-only stack would have removed real interop surface for no gain.

### The certificate patch is a deletion, not a split

This record predicted splitting the `skip_cert_verify` bit and leaving chain
walking behind the flag. What shipped deletes the flag, the walk, and everything
only the walk reached: `certificateWellFormed`, `Certificate.parse`,
`verifyHostName`, `verifyPeerChain`, `clientLeafUsageOk`, the extension parsers
and `ChainError`, plus `TlsConfig.skip_cert_verify`, `ClientAuth.ca_bundle` and
`TlsConfig.keylog_file`. The only surviving mention of `certificateWellFormed`
is a test comment at `tls13.zig:6276` explaining why the bounds guard it
provided is no longer needed.

What replaced them:

- **`liftEd25519Spki`** (`tls13.zig:234`) — 44 bytes in, 32 out, by TLV walk,
  failing only with `error.MalformedSubjectPublicKeyInfo` or
  `error.UnsupportedSubjectPublicKeyInfo`. The length is fixed, so the length
  check at `:237` is also the whole bounds check; there is nothing after it that
  can index out of the buffer.
- **`lifted_key_algo`** (`tls13.zig:270`) — one `const` of type
  `Certificate.AlgorithmCategory` set to `.curveEd25519` *by construction*. This
  is what the record identified as the thing that would make
  `verifyCertificateVerifySignature`'s unreachable `.ed25519` arm reachable, and
  it turned out to be a line rather than a patch.
- **`TlsConfig.expect_peer_node_id: ?[32]u8`** (`tls13.zig:1459`), compared with
  `crypto.timing_safe.eql` at `tls13.zig:2794`. Null accepts any key, and the
  doc comment above the field says plainly what that gives up.
- **`ClientAuth.expect_node_id`** (`tls13.zig:476`), the same comparison on the
  server at `tls13.zig:3529`, and `peer_node_id` (`:1890`) as the key the
  CertificateVerify is checked against.
- **Both CertificateVerify checks are now unconditional** — `tls13.zig:2841` and
  `:3561`, guarded by neither a flag nor `leaf_pub_key_len`. That is the "split
  the bit" the record asked for, arrived at by removing the bit.
- **`signCertificateVerify` no longer draws.** Upstream read 32 bytes before it
  knew which scheme it was signing with and handed them to the Ed25519 arm,
  which needs no nonce. `tls13.zig:6232` is a test that counts the draws and
  expects zero for Ed25519 and exactly one for P-256 — a test that merely
  passed would not have noticed the difference.

`cert_hashes` survived deliberately: the WebTransport leaf-fingerprint bargain
needs no chain either, and `tls13.zig:1461` says so.

**The wire contract this section did not ask for, added afterwards.** Deleting
the walk made the *payload* right and left the *wire* wrong: nothing on it said
the `Certificate` body was a `SubjectPublicKeyInfo` rather than an X.509
certificate, so a peer built on rustls — which is what an iroh peer is — had no
way to learn this stack could read one. Upstream negotiated no certificate type
either, so this is the upstream gap rather than something a fork dropped.
RFC 7250 is now implemented in both roles: the `CertificateType` registry, the
offer and selection codecs, the two parsers, and a fail-closed refusal in each
direction. It is a vendor patch, and `vendor/quic/VENDORED.md` §10 carries it in
full with its test anchors, §11 with its state.

Three things about it belong in this record rather than only there. Both offers
are **mandatory** rather than merely supported, because this stack has exactly
one certificate type and a client that does not offer it has nothing in common
with this server. A server that does not ask for a client certificate omits
`client_certificate_type` from EncryptedExtensions, which RFC 7250 §4.2
requires and which would not hold for a project that authenticates both ends.
And **it was unverified against the patched tree when this was first written.**
A real iroh peer had been driven against an unpatched baseline in both
directions and failed both times with `IncorrectCertificateTypeExtension` and
alert 40. That is the failure this patch answers, and on its own it confirmed
nothing. **Both native receipts of 2026-10-04 now close that**: the patched tree
completed a handshake with the real partner in both roles, exits 0 and 0, exact
peer ids, the agreed ALPN and all six declared payloads each way. So the row
above moved from "landed, unverified" to landed and verified against one peer —
one peer, not two. `vendor/quic/VENDORED.md` §10 carries the one captured
datagram, §11 every receipt, and it says plainly what that capture does not give:
nothing past the Initial, and no key material anywhere.

Net effect on the two largest files: `tls13.zig` went 4,866 upstream → 4,809,
and `connection.zig` 6,666 → 6,762. The line counts barely moved because the
deleted walk and the added lift, doc comments and tests are of about the same
size. **Diff size is not a measure of this patch.**

### Time and randomness

The predicted largest phase, and the one the plan's original order omitted. The
60 sites became two parameters:

- `now: i64` — a monotonic instant in nanoseconds that the caller read.
- `random: std.Random` — **by value**, not a pointer. A handshake that held a
  pointer could be driven twice from one generator, and the SipHash lookup key
  `ConnectionManager.init` draws once (`connection_manager.zig:243-255`) belongs
  to whoever created the manager.

Both public entry points changed shape:
`recvDatagram(bytes, from, local, ecn_val, out_buf, now, random)`
(`connection_manager.zig:496`) and `sendAt(out_buf, now, random)`
(`connection.zig:3139`). `Connection.send` was deleted rather than left as a
wrapper, because a wrapper that reads the clock is the thing the milestone
exists to remove.

Nothing in the vendored module reads a clock or a CSPRNG any more: zero hits for
`nanoTimestamp`, `realtimeSeconds`, `realtimeNs`, `randomBytes` or `randomInt`
across all 33 files.

### `src/sys.zig` — deleted, not split

The record predicted that `sys.zig` would split. It did, and then the whole file
went: 864 lines upstream, 115 with only the clock and entropy left, and now
nothing, along with its re-export at `lib.zig`. `lib.zig:10-15` states why in
one paragraph — every caller of the seam is gone, and so is the file.

There is now no file through which the core could reach the operating system,
and a future patch cannot reintroduce one without writing a new file rather than
editing an old one. The "no `link_libc`" claim at `build.zig:27-32` rests on the
file being absent rather than on lazy analysis never reaching it.

### The `now_s` clock base — a divergence

`Tls13Handshake.step(now_s: i64, random: std.Random)` (`tls13.zig:2367`) is
documented immediately above itself as **a second on the caller's clock, not on
the epoch**. The connection supplies a monotonic instant, and the sans-IO
invariant forbids TLS reading one to find out.

Recorded as a divergence because the parameter is spelled `now_s` and sits in a
file that once read `sys.realtimeSeconds`, so a reader who assumes wall-clock
seconds here will eventually be wrong about something. The argument:

- The one value written from it into a ticket is `creation_time`. The server
  seals it at `tls13.zig:3603`
  (`std.mem.writeInt(i64, ticket_plain[32..40], now_s, .big)`), and the ticket
  is sealed with AES-128-GCM under `ticket_key`, so the peer receives opaque
  bytes and cannot read the base.
- It is not read back on the issuing side. A resuming server recovers only the
  PSK; the **client** stamps its own `creation_time` from its own `now_s` when
  it opens the ticket to offer it (`tls13.zig:3917`).
- There are exactly two subtractions of `now_s - creation_time`, and both are
  differences off one clock. The library takes one at `tls13.zig:4306`, for the
  RFC 8446 §4.2.11 obfuscated ticket age. `SessionTicket.isExpired`
  (`:1074-1075`) holds the other and **the library does not call it** — only its
  own tests at `:5447` and `:5451` do. This record previously said the only
  subtraction was inside one client process; it is not, and neither of these is
  a comparison against anything epoch-derived.
- A monotonic base that restarts with the process could only mis-age a ticket
  that outlived the clock that stamped it, and a process cannot outlive its own
  clock.

The rule for anyone who touches this: **nothing may compare `now_s` against an
epoch-derived quantity.**

### Measured cost against predicted cost

| | Predicted | Measured |
|---|---|---|
| Socket layer | 7 files, 7,194 lines | 6 never copied (7,143 lines), and the vendored tree has no `xev`, no `link_libc` and no `c_api`/`fuzz` |
| Clock and CSPRNG | 60 sites | 60 sites, two parameters, both public entry points changed, no design change |
| Certificate work | four functions, `TlsConfig`, `ClientAuth`, a flag split | the entire X.509 walk deleted and the flag gone with it, plus `keylog_file` and `ca_bundle`, which the record never mentioned |
| The seam file | "splits rather than deletes" | split, emptied to 115 lines, then deleted. No seam file remains. |
| Module root | "cut in the same pass" | `lib.zig` 47 → 41 lines, four layers of re-exports gone |
| Interop matrix | re-run at our SHA | **not done** |

The record was wrong in one direction, and it was the expensive one: it billed
the certificate work and not the threading. The 2026-09-30 correction conceded
that; execution says the correction still understated the rest. Deleting the
chain walk turned out to be *cheap* precisely because it was permitted to be a
deletion rather than a flag split — the split this record proposed would have
left the walk present, dead on one path and live on the others, and every one
of those paths a way for `realtimeSeconds` to come back through.

### Still open after M8

Items are kept after they close, each marked where it stands. Item 3 was
closed after M8 and is marked below. Item 4 was added on 2026-09-30, when a
measurement turned item 1 from "untidy" into a trap; item 1's reason was
corrected in the same pass and its conclusion was not. Items 1, 2 and 4 were
re-read on 2026-10-04 against the tree, when the repair item 4 names had landed
and the native partner leg existed; item 6 was added the same day. Line numbers
inside an item that quotes a measurement are the numbers that measurement used.

**1. 0-RTT, and the verifier identity. The bypass is closed; the RFC-compatible
design is Wave 4 and is open.** The M8 requirement was to keep the client's
session ticket and the server's sealing key stable across config construction.
The old `TlsConfig.session_ticket` and `TlsConfig.ticket_key` fields are the
`.client` and `.server` cases of `TlsConfig.resumption`; each role has one value
to retain. That cutover did not acquire a resumed client's authenticated
identity, and the amendment below is the measurement of why. **That half has
since landed**: `serverBuildEncryptedExtensions` (`tls13.zig:3314`) routes on
one value, `request_client_certificate` (`:3324`), instead of on `using_psk`,
and both writers of `.connected` ask `serverIdentityEstablished` (`:3487`),
which refuses a policy in force with no identity. A resumed connection under a
pin therefore asks for the client certificate exactly as a full one does, and a
server that gets none fails with `certificate_required` (`:3495`). See
`vendor/quic/VENDORED.md` §6 for the patch and its four tests.

What remains open is the *shape*, not the hole. TLS 1.3 sends no
CertificateRequest on a PSK handshake (RFC 8446 Appendix E.3), so what landed
is a **recorded RFC 8446 deviation** — a flight a conforming peer reads as a
protocol error — and not an RFC-compatible authenticated resumption. That
replacement is Wave 4. Until it lands, treat **authenticated client-identity
early data** as unimplemented rather than the standalone unauthenticated
PSK/0-RTT path, and treat a session ticket as bearer material rather than as an
identity.

**Amended 2026-09-30: the reason this item gave was the wrong one.** It read
`ClientAuth`'s doc at `tls13.zig:253-259` — "Session tickets are neither issued
nor accepted while a policy is in force" — as why a pinned client identity and
resumption are mutually exclusive here. That sentence points at the ticket
format, and the ticket format is not the obstacle. A ticket carries no client
identity. The layout cited here was a `[64]u8` plaintext; those sizes and line
numbers were the 2026-09-30 measurement, not the current format. The current
`serverSendTicket` writes `psk(32) || creation_time(8) || quic_version(4) ||
alpn_len(1) || alpn`, with an ALPN of at most 32 bytes and a 16-byte tag:
77 plaintext bytes and 93 sealed bytes at most. The ALPN capacity changed in
the contract cutover so a negotiated protocol is recorded whole. None of these
fields carries a client identity, so the structural obstacle below remains;
it is not resolved by that format change.

The block is structural: **TLS 1.3 has one client-identity acquisition path, and
resumption skips it.** `serverProcessClientCertificate` (`:2066`) is the only
place a server learns who the client is. It lifts the SPKI (`:2083`), compares
`auth.expect_node_id` (`:2084-2086`), and is the only writer of `peer_cert`
anywhere in the tree (`:2088`) and the only server-side writer of
`peer_node_id` (`:2089` — the client writes the same field at `:1477`, for the
server's certificate).
Reaching it needs a CertificateRequest, and
`serverBuildEncryptedExtensions` (`:1912`) decides whether to send one by
testing `using_psk` (`:1934`) **before** it tests `client_auth` (`:1936`). A
resumed connection therefore never triggers the CertificateRequest, never runs
that function, and ends the handshake holding no client identity at all. In
this tree a pinned client identity and resumption are mutually exclusive, and
an iroh peer wants both.

It is also not residue of the chain walk M8 deleted. `ClientAuth` (`:260`) is
`expect_node_id` (`:264`) plus a two-valued `Mode` (`:267-272`), and the
judgement is `liftEd25519Spki` (`:188`) over a fixed 44 bytes
(`ed25519_spki_len`, `:144`). There is no X.509 in it and none on the path.
The guard is live code over a live policy.

Removing the guard is a trap rather than a chore, and item 4 is the
measurement.

**Superseded 2026-10-04, as this item's header says.** The structure above is
what the repair had to survive and it is kept as measured, but `serverBuildEncryptedExtensions`
no longer tests `using_psk` at all and `peer_node_id` is no longer written by
one path alone, so the mutual exclusion this paragraph concludes with is gone.
Read it as the pre-repair state.

**2. Interop, and therefore requirement 3. One leg closed, one open.**
The matrix this record relied on was upstream's, run at `4988228` rather than the
pinned commit, and it is **not reproducible from this repository**: upstream's
runner is a git submodule outside `build.zig.zon`'s `.paths`. M8 did not re-run
it, and neither has anything since.

That leg has a second blocker, independent of the first, and it is about the
node rather than the package: **the matrix cannot be run here at all.** Of the
three tools it needs, `tshark` is present and `docker` and
`quic-network-simulator` are both absent. So this is not a runner that could be
wired up locally; it needs a machine that has the simulator's toolchain.
*Closes when* the matrix is run against this tree **on such a node** —
initialise the submodule outside the package, run `interop/runner/matrix.sh`,
and record the result against our SHA. Until then the honest statement is the
one already in this record: ten of 88 cells red upstream, one open, and ours
unmeasured.

**The native leg needs none of that, and it has now run against the patched
tree, in both roles.** Wave 1 built it: `test/rust_partner/` is a partner pinned
to `iroh = "=1.3.0"`, and `test/interop_peer.zig`, `interop_options.zig`,
`interop_runtime.zig` and `interop_transfer.zig` are the other end of one
command-line contract, over a real socket and the real `Bridge`. A build is not
an exchange, so the two are kept apart — the partner compiling
`--release --locked --offline` and its `--help` running established the
contract, not interoperability.

It did not work at first. Against a pinned unpatched baseline — parent
`6ad2f697…`, old Node `39b7cdfd…`, Debug 5/5 exit 0 — driven through a loopback
UDP proxy that copied exact bytes before forwarding them unchanged, **both**
directions failed. The partner exited 1 with
`IncorrectCertificateTypeExtension` and alert 40; this side exited 0 having
closed at `0x128`, after 75 datagrams and 90,000 bytes one way and 2 datagrams
and 1,303 bytes the other. Both receipts are in `vendor/quic/VENDORED.md` §11.
That run discharged nothing by itself — it proved the failure was real and
reachable, which is what made the RFC 7250 patch a repair rather than a guess —
and it said nothing at all about the patched tree.

**The patched tree then spoke to the same partner, and both roles work.** On
2026-10-04, against the locked Rust fixture `748f0fca…` and the immutable
binary `0b95f541…`, two receipts: `evidence/w1-native-listener-after-role-predicate-fix.json`
and `evidence/w1-native-dialer-after-role-predicate-fix.json`. Each is exits 0
and 0, each end authenticated the exact node id it was configured with
(`d04ab232…` as `1111…`, `a09aa5f4…` as `2222…`), both agreed on
`2f6f7a61692f77312d66697874757265` = `/ozai/w1-fixture`, and all **six** declared
payloads crossed and were compared in both directions — bidi 5 B, uni 4 B,
DATAGRAM 4 B, each way. The ozai side reports `0 dropped, 0 foreign, 0 degraded,
0 codepoints lost`, and each run wrote a capture with its own `wire.manifest`.

**Four typed negatives in both roles, from that same partner.** Wrong peer gives
`error.BadCertificate` here and alert 42 there; ALPN mismatch gives
`error.NoApplicationProtocol` here and alert 120 there, with the partner logging
`CONNECTION_CLOSE error_code=0x178`. Receipts
`w1-live-sdk-{listen,dial}-{wrong-peer,alpn-mismatch}.json`, all four exiting 1
on both sides with `payload_proofs_complete: false`. These are RFC 7250 §4.1/§4.2
and RFC 7301 §3.2 read off an independent implementation rather than a fixture.
Retry is receipted too: `w1-live-sdk-listen-retry.json` runs the ozai listener
with `--require-retry` and completes in 0.48 s, exits 0 and 0, all six payloads.

**Which build ran what, recorded from the receipts.** Seven runs, two digests.
Each row's digest is the `binary_sha256` field for `install/bin/ozai-interop-peer`
inside the receipt that row names — not a remembered pairing.

| Receipt | Run | ozai binary | Exit |
|---|---|---|---|
| `w1-native-listener-after-role-predicate-fix.json` | both roles, six payloads | `0b95f54121abc6eb1ce38d8699abf7a410ab3891f5d222c9b46de5e45f1c4e7d` | 0 / 0 |
| `w1-native-dialer-after-role-predicate-fix.json` | both roles, six payloads | `0b95f541…` | 0 / 0 |
| `w1-live-sdk-listen-wrong-peer.json` | wrong peer, listen | `764dbfd837dbe11173cc8b098e11694adaef92a2403c42d65c9fd80d4b1561a2` | 1 / 1 |
| `w1-live-sdk-dial-wrong-peer.json` | wrong peer, dial | `764dbfd8…` | 1 / 1 |
| `w1-live-sdk-listen-alpn-mismatch.json` | ALPN mismatch, listen | `764dbfd8…` | 1 / 1 |
| `w1-live-sdk-dial-alpn-mismatch.json` | ALPN mismatch, dial | `764dbfd8…` | 1 / 1 |
| `w1-live-sdk-listen-retry.json` | `--require-retry`, listen | `764dbfd8…` | 0 / 0 |

So the two both-role exchanges ran `0b95f541…` and the four negatives and the
Retry run ran `764dbfd8…`. **Two distinct binaries, and neither is claimed as
the other**: the negative rows say nothing about the build the six payloads
crossed on, and the six payloads say nothing about the build the refusals came
from. The Rust partner `748f0fca…` is the same fixture in all seven.

**And since 2026-10-05 one build has produced all seven.** The freshly built
`70567c34fdd0f513dde3c21391c50cc74e03757c2304e3f971768aef1c64c399` ran the whole
set against the same locked partner
`748f0fca9dd2fa1b802b382e25f0eb2af6a12cd2ea7613b16ad9e7399ec80b65`, and each of
the seven receipts records both digests in its own `binary_sha256`:

| Receipt | Case | native | This side | Partner | Exit |
|---|---|---|---|---|---|
| `w1-live-final-listen-positive.json` | positive, native listens | listen | 6 of 6 payloads each way, ALPN `2f6f7a61…` = `/ozai/w1-fixture` | 6 of 6 | 0 / 0 |
| `w1-live-final-dial-positive.json` | positive, native dials | dial | 6 of 6 each way, same ALPN | 6 of 6 | 0 / 0 |
| `w1-live-final-listen-retry.json` | `--require-retry`, native listens | listen | 6 of 6, one Retry answered | 6 of 6 | 0 / 0 |
| `w1-live-final-listen-wrong-peer.json` | wrong peer, native listens | listen | `error.BadCertificate` | `the cryptographic handshake failed: error 42` | 1 / 1 |
| `w1-live-final-dial-wrong-peer.json` | wrong peer, native dials | dial | `error.BadCertificate` | `error 42` | 1 / 1 |
| `w1-live-final-listen-alpn-mismatch.json` | ALPN mismatch, native listens | listen | `error.NoApplicationProtocol` | `error 120` | 1 / 1 |
| `w1-live-final-dial-alpn-mismatch.json` | ALPN mismatch, native dials | dial | `error.NoApplicationProtocol` | `error 120`, and the native side reads the peer's `CONNECTION_CLOSE error_code=0x178, frame_type=0x0` | 1 / 1 |

Every positive receipt is `payload_proofs_complete: true` and every refusal is
`false` — a refusal that transferred anything would be a different finding. The
six payloads are bidi 5 B, uni 4 B and DATAGRAM 4 B, each way, each named by a
`verified_*` line on both ends. The native listener's own counters on the
positive run are `10 in, 10 out, 0 replies, 0 degraded, 0 codepoints lost` and
`ingress: 10 processed, 0 dropped, 0 foreign`; the `--require-retry` run is
`11 in, 12 out, 1 replies` with the same zero counters, so the Retry the run
asked for is the reply it counted. On the dial order the native side prints no
counter line and records the peer's clean
`ApplicationClose { error_code: 0, reason: b"" }` instead, so none is quoted for
it.

**The older rows above are kept, not replaced.** A receipt is evidence about the
build in its own `binary_sha256`, so `0b95f541…`, `764dbfd8…` and `70567c34…` are
three separate claims and a reader has to be able to tell which binary produced
which run. `vendor/quic/VENDORED.md` §11 carries the same seven rows with the
per-case detail.

**And one vector is now captured rather than authored.** The Rust client's first
Initial is in the tree: `test/corpus/rust_wire/rust_client_initial.hex`, 1,200
bytes on the wire, `sha256
473b53b1926dce2f9841718684b76792059ab02ba2fd7770f6b53e7315876f7d`, from
`evidence/capture-w1-native-listener-after-role-predicate-fix/datagrams/000000-peer-inbound.bin`.
It is one datagram of one flight, and it is the *Initial*, which is the only
part of a flight whose keys come from the connection id alone (RFC 9001 §5.2).
**It authenticates.** A probe through the vendored core's own derivation —
`packet.parseQuicHeader`, then `PacketNumSpace.setupInitial(dcid, version,
true)`, then `packet.decrypt` — exits 0 with `VERDICT opened, plaintext 1145
bytes / frames=2 crypto_frames=1 first_crypto_offset=0`
(`evidence/w1-probe-captured-rust-initial-authenticity.log`), so its payload
opens under the keys derived from its own connection id and its first CRYPTO
frame begins at offset 0. That is the core's own `decrypt`, not an independent
reimplementation of RFC 9001: a hand-rolled brute force whose associated-data
handling had drifted reported the opposite, and a reimplementation that
disagrees is evidence about the reimplementation.

Nothing past that Initial is readable from this file or from this tree. The `keys` column
of a `wire.manifest` is a label naming which connection id a header carries and
not a secret, and there is no keylog anywhere in the project — `TlsConfig.keylog_file`
was deleted with the X.509 walk and nothing replaced it. **So: one captured
vector, not a corpus.** Every other vector in this record is still written
against a peer this project produced itself.

*Closes when* — the native leg does now, on these two receipts and on the seven
current-build ones above. What is left on requirement 3 is the upstream matrix
leg above, and it is unchanged.
**This is still not a green Wave 1, and it is not a claim that the gate is
red either.** The first-party suite was green on 2026-10-05 —
`zig build test -Doptimize=Debug` and `zig build test -Doptimize=ReleaseSafe` each
reported **28/28 steps succeeded; 790/790 tests passed**, exit 0 in both modes
(`evidence/w1-full-debug-suite-wave1-union-verification.log`,
`evidence/w1-full-release-safe-suite-wave1.log`) — and the vendored core was green
on its own artifact, `zig build quic-test` at **3/3 steps, 560/560**, exit 0.
**Those are two different numbers and are not interchangeable.** Against the
current bytes the **full gate result is pending** (item 9): the required source
lint fixes have landed and no gate group has been run over them, so a pending
group is recorded as pending and not as a failure, and the red lint and static
figures behind older bytes are not carried forward. Two focused legs are green
against the current bytes — the vendored TLS decode at 1/1 and the QUIC
wire-decode corpus at 1/1 — and a focused decode leg is not the fuzz gate. The
zbc disposition ledger is re-merged at 32 source proofs and 60 records,
byte-idempotent on a second emission. Multipath, the standard relay carrier
and RFC-compatible resumption are Waves 3 and 4 and remain unimplemented. A
substrate that talks to iroh is not a project that has passed its gates.

**3. Nothing under `src/` imports `quic`. Closed 2026-09-30, after M8.**
`src/transport/quic_bridge.zig` closed it: it imports `quic` (`:99`), owns a
`ConnectionManager` (`:115`), and turns one datagram in (`recv`, `:555`) and
one out (`Conn.drain`, `:279`) per call. The module was declared and compiled
at `build.zig:36-40` long before, which is why this item was open at M8 and
why declaring a module is not the same as reaching one. M8's last execution
step claimed it and did not finish it; the bridge is the finishing, and it
landed with M9 rather than in M8.

The closure is of *reach*, not of the transport. What the bridge gives is the
accept half: `ConnectionManager` only ever runs a server, so nothing under
`src/` originates a connection, and `Client` — the client half at
`quic_bridge.zig:854`, built on `connectInto` (`:888`) the way
`vendor/quic/src/quic/lossy_link_test.zig` builds one — is reachable only
from the file's own test blocks. There is still no socket: `batch.zig`
models GSO, GRO and ECN as values and returns the values a socket would be
asked for, without one. Those two gaps are what `TODO.md`'s *Next* now names,
and they are invisible from a module list that otherwise looks connected.

**4. Lifting item 1's guard turns a pinned server into one that authenticates
nobody, and the repair that makes it not look broken is what does it. Measured;
the defect it describes is closed, and what replaced it is item 1's remaining
open work.** The measurement below is kept as it was taken and it still reads
true; it is what the repair had to survive.

A measurement, not a proposal. Taken on a throwaway copy of
`vendor/quic/src/quic/tls13.zig` on 2026-09-30, restored byte-exact afterwards,
with both suites green after the restore (456 vendored tests, 399 project
tests). Nothing in the tree was changed.

**How it was measured.** Two guards of the same shape, `client_auth == null`,
gate resumption: the accept guard at `:1795`, which is the only way into
`tryProcessPsk`, and the issue guard at `:2057`, the only way a ticket is sent.
The probe lifted them and drove the vendored loopback harness (`handshake`,
`:3907`, which returns the server's view of the client certificate in
`peer_cert_out` and pumps both ends through `driveLoopback`, `:3436`) across
two connections: one full handshake to take a ticket, then a resumed one
against a server whose `TlsConfig.client_auth` is
`ClientAuth{ .expect_node_id = <32 bytes> }`. It reported `using_psk` and the
state machine's state on both sides, and read `peerCertificate()` and
`peerNodeId()` off the server after the resumed handshake. Neither the harness
nor a pinned `ClientAuth` is new: `tls13.zig:3999` and its four siblings
already drive exactly that shape.

**What came back, first pass: a dead handshake, not a bypass.** With the guard
lifted alone, `using_psk` is true, `serverBuildEncryptedExtensions` skips the
CertificateRequest (`:1934`) — and `serverBuildFinished` (`:2003`) still routes
on `client_auth` alone, at `:2027`, ignoring `using_psk`. The resumed server
waits in `server_wait_client_certificate` for a Certificate the client is not
going to send: `client_wait_certificate` jumps to `client_wait_finished` the
moment `using_psk` is set (`:1179-1183`). The client's `finished` is then
rejected as `error.UnexpectedMessage` at `:2068`. Loud, and fail-closed. Those
two sites disagree about `using_psk`, and the disagreement is the only thing
standing between the lift and a silent bypass.

**Second pass: the bypass.** Making that routing PSK-aware is the natural
reading of `:2027`, and it is what an author fixing the disagreement writes:

    self.state = if (self.client_auth != null and !self.using_psk)
        .server_wait_client_certificate
    else
        .server_wait_client_finished;

**The result: the handshake completes.** `.connected` on both sides, no
Certificate anywhere in it, and the server holding `peer_cert == null` and
`peer_node_id == null` with `expect_node_id` set and never compared. A server
that pinned a node id accepted a peer it never authenticated, and nothing on
the wire or in either state said so. The pin is not weakened and the
comparison is not wrong — it is on a path that did not run.

**The same defect one layer up, in this repository.** The bridge reads the peer
identity as `conn.entry.conn.peerCertificate().?` at
`src/transport/quic_bridge.zig:1076` and `:1115`, and `Connection.peerCertificate`
(`vendor/quic/src/quic/connection.zig:4021`) is optional because the TLS
layer's is: it delegates to `Tls13Handshake.peerCertificate`
(`tls13.zig:1234`), which is `peer_cert` outright, and `peer_cert` is null on
exactly the connection this item is about. Both call sites are inside that
file's test blocks, so the live accept half reaches no `peerCertificate`
call at all today and nothing in `src/` is wrong yet. It is still the same
trap one layer up: this is the idiom the project's own code already uses for
*who is this peer*, and the bridge is built so that identity is the whole
point of the connection — its module doc says the pin a server actually
enforces is `ClientAuth.expect_node_id` (`:80-83`), and `buildTlsConfig`
installs one (`:528`, `:537`). The first unwrap written on that path turns the
upstream null into a panic here. Both shapes are bugs; which one arrives is
the next reader's decision, not this record's to assume.

*Closes when* item 1 closes: a resumed connection under a pinned `ClientAuth`
either carries a verified client identity or fails the handshake, and a test
in this tree says which. Until then, treat the two `client_auth == null`
guards as load-bearing, and do not "fix" `:2027` before the guard above it.

**Where this stands.** Closed, and by a different mechanism than the one this
item was groping at: the routing at `:2027` was never "fixed" in place, because
`serverBuildEncryptedExtensions` now decides the CertificateRequest from
`client_auth` alone and both `.connected` writers go through
`serverIdentityEstablished`, so the question item 1 asks — does a resumed
connection carry a verified identity or fail — has one answer and a test in
`vendor/quic/src/quic/tls13.zig` states it. The two guards this item called
load-bearing are still load-bearing; what changed is that nothing above them
disagrees any more.

**5. A peer that uses both paths concurrently is broken, and this is the
measurement of how. Open.** Added 2026-10-01; full method and numbers in
[Multipath, measured 2026-10-01](#multipath-measured-2026-10-01). Recorded
here as an open item and not left in the cost prose, because there it reads as
an acceptable trade and it is not one.

**What is broken.** One `Connection` holds two `NetworkPath` slots
(`vendor/quic/src/quic/connection.zig:626`) and one `active_path_idx` (`:627`),
and a non-probing packet from a second peer address is a migration, not a
second path (`:1540-1544`). So there is no configuration of this substrate in
which one connection carries two paths. Accepting a second address abandons the
first, and egress has exactly one destination
(`Connection.peerAddress`, `:4327-4328`). The cost prose called this
convergence speed; the measurement says the convergence part is a few
datagrams and the concurrency part is the whole picture.

**The evidence.** Over the same 400 ms window from an identical deterministic
start, one address gives 0 migrations, 12,147 datagrams and 15,167 KiB
delivered; two addresses alternating every 60 ms give 8 migrations, 814
datagrams and 969 KiB — 6% of the single-address case. It oscillates and never
converges, because every IP change discards the congestion window and the RTT
history (`connection.zig:3461-3468`), putting the window back to 12,000.
Measured on `lossy_link_test.zig`'s `Pair` shape with an injected clock,
seeded entropy and no socket; harness deleted. Not a general property of QUIC
migration.

**What works today.** `src/transport/dial.zig` works around it rather than
being broken by it: two dials, two connections, and the caller owns the policy
that says which — asserted by its test *"two targets to one peer are two
connections, because the core has one path"* (`:1376`). That is a correct
workaround for a peer reached over one path at a time. It is not a substitute
for a peer that sends on both, because such a peer migrates every time it
switches and pays a whole congestion window each time it does.

*Closes when* `Connection.paths` holds more than an active slot and a
candidate, `active_path_idx` is gone or no longer the only way a path is named,
and congestion, RTT and ECN state are retained per path rather than reset on
use (`connection.zig:3461-3468`) — with a test in this tree that drives one
connection from two addresses at once and asserts both are carried and neither
restarts slow start. Until then, operate the two-path peer as two peers, each on
one path, and see [the follow-up's scope](#the-follow-up-and-its-honest-size)
before pricing it as a small change.

**6. A server that offers no protocol at all must still refuse. Closed 2026-10-04
with Wave 1, on a wire receipt.** The guard landed, the TLS parent is 9 of 9,
and the refusal has been seen arriving as CRYPTO_ERROR `0x178`.

RFC 7301 §3.2: "In the event that the server supports no protocols that the
client advertises, then the server SHALL respond with a fatal
no_application_protocol alert." An offer list with nothing in it supports none,
so that is the case, and the answer must not be a completed handshake.

The vendored guard was `if (!matched and self.config.alpn.len > 0)`, and the
second half exempted exactly that: a server whose configured list was empty
matched nothing, skipped the refusal, and completed with no protocol selected.
Retiring a node's last configured protocol leaves an offer list in that state,
so the case is reachable from configuration rather than from a hostile peer. It
is now `if (!matched) return error.NoApplicationProtocol`
(`vendor/quic/src/quic/tls13.zig:3123`): the condition is the walk's own result
and the exemption is gone.

**The premise needed its own vendor fix first, and that fix has landed.**
`initClientInto` (`tls13.zig:2124`) and `initServerInto` (`:2239`) construct
into caller-owned storage and write every field by hand, so the struct's own
default for `selected_alpn_len` never ran and a handshake that had selected
nothing sliced `selected_alpn` with a length nothing had set. Both now store
zero (`:2175`, `:2290`). That is a second Wave 1 vendor patch, separate from
the guard and not cosmetic — it was what made the other half of RFC 7301's
rule, a ClientHello naming no protocol, fail for a reason that was not about
protocols. It is carried in `vendor/quic/VENDORED.md` §11 with its rationale.

With it landed, both RFC 7301 vectors pass — the present-offer refusal at
`test/tls_wire/hello.zig:1105` and the absent-extension answer at `:1162`, which
the change deliberately does not touch. A hello carrying no ALPN extension never
reaches the arm that refuses, because nothing was advertised and so nothing is
echoed; that is one behaviour unchanged, not a second obligation left open. The
pre-fix red that motivated the change is kept as the run's own log,
`evidence/w1-empty-alpn-valid-premise-red.log`.

**What this closes, and what it does not.** The unfiltered
`test/tls_wire/hello.zig` parent now runs **exit 0, 9 of 9**, on the 0.16
toolchain as
`zig test --dep quic -Mroot=test/tls_wire/hello.zig -Mquic=vendor/quic/src/lib.zig`,
logged at
`evidence/w1-full-tls-hello-after-driving-to-the-public-wait-verdict.log`.

The four failures an earlier run reported were premise faults in the test
fixture rather than in the stack. `takeHandshakeKeys` stopped on `_continue`,
which is an action the caller is handed and not a loop of its own, so the walk
ended one step early and fed the next message an answer about keys rather than a
verdict on that message. The fixture now drives to the public `wait_for_data`
(`driveUntilWaiting`, `hello.zig:629`), bounded, and refusing a `send_data` or
`complete` as a walk that went past the message under test. **No production
EncryptedExtensions policy changed.** The wrong-peer vector dropped an
incidental state assertion — the premise that bug broke — and still refuses an
actual foreign `SubjectPublicKeyInfo` with `error.BadCertificate`.

Two earlier runs, which are not one. Before the guard, a run of just the two
RFC 7301 vectors exited 1 with one failure — the present-offer refusal red, the
absent-extension half green — and that log is
`evidence/w1-empty-alpn-valid-premise-red.log`; it is the red that motivated this
guard. Later and separately, an unfiltered parent run exited 1 at 5 of 9 with
four premise failures red, logged
`evidence/w1-full-tls-hello-after-empty-offer-root-fix.log`. Neither log is this
tree's current state.

*Closes when* — and it does now, on the wire. The runtime parent
`w1-runtime-handlers-three-real-refusals-accounted.log` exits 0 with 3 of 3 steps
and 5 of 5 tests: three `no_application_protocol` refusals, and one RECEIVED
`CONNECTION_CLOSE` frame carrying **0x178**, between real `Socket` and `Bridge`
peers. `test/runtime_handlers_test.zig:830-831` is the assertion — a close that
is transport (`!refused.application`) with `code == 0x100 + 120`, read off the
peer's `local_err` (`:478-479`) before timers can reap it. The retirement lane is
a different shape: `:745-746` requires an application close with `code == 0`,
and the last-lane peer must never establish while the handler and turn counts
hold (`:786-802`).

**What that closes, and what it is not.** The RFC 7301 §3.2 obligation is
discharged end to end, and this item was reopened only because the earlier close
had asserted a wire code nobody had seen. **Those peers are Zig/Zig, and that is
still what this particular receipt is.** The independent-implementation evidence
is item 2's, and it is separate: the real partner's own alert for this same
refusal is 120, in both roles, on the native run, and
`test/corpus/rust_wire/rust_client_initial.hex` now carries one captured
datagram — the client's first Initial, and nothing past it. The two missed
`Streams` signatures that once blocked this build are fixed, and that is history
rather than a current state.

Every vendor patch this record names is carried in `vendor/quic/VENDORED.md` §11,
which records them as landed. One of them — recorded below, and previously
recorded nowhere — alters **which protocol a successful handshake settles on**
rather than whether it completes, so it carries its own row, its own anchors and
**No Wave 1 overall green is claimed here.** The integrated suite was green as of
2026-10-05 — 790/790 over 28/28 steps, in Debug and in ReleaseSafe — and the
**full gate result against the current bytes is pending**: the required source
lint fixes have landed, no gate group has been run over them, and a pending gate
is recorded as pending rather than as a failed one. The zbc disposition ledger
is no longer outstanding — it is re-merged at 32 source proofs and 60 records,
byte-idempotent on a second emission. Waves 2–4 —
including multipath, the standard relay carrier and RFC-compatible resumption —
remain unimplemented.

**The selection order, and which list decides** — row four of §11's table, where
the base, the anchors, the rationale, the tests and the wire deviation are
carried. The ClientHello ALPN walk
(`vendor/quic/src/quic/tls13.zig:3139-3167`) had its loops swapped: the outer walk
is now `self.config.alpn` — this server's own configured preference order — and
the inner one walks the client's advertised list (`:3156-3167`), taking the first
of ours the peer also named and leaving both with `break :selection` (`:3166`).
The write is unchanged (`:3163-3164` copies the matched name whole into
`selected_alpn`), and so is the refusal below it (`:3178`), which reads the same
`matched` flag either way.

**At the pinned base it was the other way round, and the anchors are upstream's
own lines.** At `14b9dc3e5e8429d07e7ed18619c7b4f4baaa3719` the outer walk is the
peer's — `while (alpn_pos < 2 + list_len and alpn_pos + 1 <= elen)` at upstream
`tls13.zig:2129` — with `for (self.config.alpn) |our_proto|` inside it (`:2134`)
under upstream's comment "Parse client's ALPN list and try to match with our
configured ALPNs" (`:2124`), and upstream's own test said `// The client's order
wins; both sides must agree on it.` at `:3886` while asserting `moqt-17`. **So
the direction is not in doubt: a client offering `["moqt-17", "moqt-18"]` against
a server configured `["moqt-18", "moqt-17"]` now settles on `moqt-18`, where the
base settled on `moqt-17`.** A reader who takes this the other way round builds a
client that expects its own preference to survive.

**RFC 7301 §3.2 is the rationale, and it is the section's own first sentence.**
"It is expected that a server will have a list of protocols that it supports, in
preference order, and will only select a protocol if the client supports it. In
that case, the server SHOULD select the most highly preferred protocol that it
supports and that is also advertised by the client." Where the two lists
disagree, the most highly preferred protocol *the server* supports and the client
also advertises is the server's own first of them. §4 gives the design reason:
"By placing ownership of protocol selection on the server, ALPN facilitates
scenarios in which certificate selection or connection rerouting may be based on
the negotiated protocol."

**The test anchor is the vendored expectation, rewritten in the same pass, and
nothing else in this tree can see the difference.** `tls13.zig:5211`, `loopback
handshake: the server answers with the one ALPN it chose`, keeps upstream's two
lists (`:5222` server, `:5227` client), says "This side's order decides where the
lists disagree" (`:5232-5233`), and asserts `moqt-18` on both ends
(`:5234-5235`). `test/tls_wire/hello.zig:106` offers the single name `ozai` to
both ends, and every peer built by `test/runtime_handlers_test.zig`'s `addPeer`
(`:691`, `:692`, `:754`, `:792`, `:808`, `:834`, `:859`, `:878`, `:967`) and by
`test/relay_wire_test.zig:1127-1134` advertises exactly one protocol, so the
vendored unit test is the only vector in the tree where the two orders disagree.
**No red against the old order was ever witnessed and none is manufactured here:**
the walk and its expectation moved together. The file is now `sha256
`2f6d8be4197d0d8f6cd4412c1db79b807b73115a545bcb6eabb5a37678510e9c`, 7,889 lines —
not `aee3cd4a…` / 7,890, which is the file every 560/560 and 13-of-13 figure in
this record was taken against, so none of those figures covers this swap.

**A later vendored green exists and does not narrow that.** `zig build quic-test`
ran green again against the admission-hook bytes — **3/3 steps succeeded, 560/560
tests passed**, exit 0 (`evidence/w1-quic-test-after-admission-hook.log`). **That
leg carries no `tls13.zig` digest**: it is named by what landed in it, so this
record cannot say which of the four states above it covered and does not claim it
covered this swap. The digest a vendored green is anchored to by name here is
`aee3cd4a…`, and `aee3cd4a…` is not these bytes.

**The wire deviation.** A handshake whose client and server rank a shared
protocol differently now settles on the **server's** configured order rather than
the **client's** advertised order. Where both lists name the same set — every
configuration in this project, since a caller offers what it serves — nothing
moves and no expectation changes. The selection is still the one name echoed in
EncryptedExtensions (`tls13.zig:3381-3382`), so no byte's format, length or
position changes: what moves is which name fills it.

**7. A DATAGRAM at the advertised size never left the queue. Closed 2026-10-04,
red and green observed; the reason it matters is the advertisement.**
`packSinglePacket` measures every write against `effective_max`
(`vendor/quic/src/quic/packet_packer.zig:583`), which is a **plaintext** budget —
`buf.len -| AEAD_TAG_LEN`, the tag already taken off once. The DATAGRAM arm
charged it a second time at `:957`, and that arm is the only writer where the
term *refuses* rather than bounds.

`Connection.maxDatagramPayloadSize` (`vendor/quic/src/quic/connection.zig:4857`)
advertises the ceiling by subtracting that tag exactly once: with a 1200-byte
path MTU and an 8-byte connection id, `1200 − (1 + 8 + 4 + 16) − 3 = 1168`. A
peer sending exactly what it was told reaches `:957` needing `fbs.seek ≤ 13`; a
1-RTT header alone is 9 plus a packet number. With the second charge the
condition is unreachable, the arm breaks, the datagram stays queued and the
advertised maximum does not cross. So this was a transport-parameter promise
this stack did not keep, which is a different class of defect from a slow path.

**The fix is one line and shrinks nothing.** `:957` now reads
`if (fbs.seek + frame_size > effective_max) break;`. The payload ceiling is not
clamped and no advertised number was lowered to match the refusal; the
conservative room guards at `:722`, `:764`, `:832`, `:872`, `:876`, `:910`,
`:914`, the padding guards at `:615`, `:1008`, `:1150` and the peer's
`max_datagram_frame_size` clamp at `connection.zig:4872-4873` are all untouched.
The tree had already stated the invariant the fix restores, at
`packet_packer.zig:2067-2070`.

`PacketPacker: a DATAGRAM at the advertised payload budget crosses the wire`
(`packet_packer.zig:2750`) packs the advertised 1168 with a follower behind it
over two passes and decrypts both to compare — and only a green run reached by
the **filtered** invocation `zig test vendor/quic/src/test_all.zig -lc
--test-filter …` counts: `zig build quic-test -- --test-filter …` does not
forward the filter and reported 560/560 with the test present. Red
(`w1-vendor-datagram-advertised-budget-red-direct.log`, exit 1 at `:2819`) and
green (`…-green.log`, `All 2 tests passed`). Full rationale in
`vendor/quic/VENDORED.md` §12.

**Two caller-side repairs recorded with it, neither a vendor patch.** A
preferred-address oracle in `test/quic_wire/transport_params.zig` copied the
stateless reset token from an offset one past the end of a buffer the line above
had proved complete — `@memcpy(…, value[41 + cid_len ..])`, a length mismatch
that panics in Debug and ReleaseSafe and zeroed the token under elision; now
`value[25 + cid_len ..][0..16]`, red and green in
`w1-preferred-address-oracle-valid-wire-{red,green}.log`. **No fuzz entry ever
reached that line** — the seed's zero-length connection id is refused one line
earlier — so the green fuzz run was never evidence for it. And the ALPN name
bound is now derived once from the core's own selection storage
(`src/transport/quic_config.zig:33`, `comptime`-asserted 32, not RFC 7301's 255)
and enforced before allocation by `validateAlpns` on both `Bridge.create` and
`Dialer.create`. `vendor/quic/VENDORED.md` §13 carries both.

**Companion TLS ALPN and client-auth pin work. Reported by its owner, partly
re-run by the parent, still out of the landed table.** Owned by
`VendorAlpnPinFailClosed`: a zero-length
`ProtocolName` refused in the offer and in the selection, and a pin demanding
identity in every client-auth mode. **The production hunk is in the tree** —
authorised by the parent once the owner's reds were reported — **and its four
regressions exist**, and the owner reports a red and a green on the same test
bytes. `vendor/quic/src/quic/tls13.zig` has moved through four states —
`cd73f07ec01375c5751c726e0aebfaabb1eb809b4dc18b4419db4238f66929e2` (7,792 lines,
pre-hunk) gave 10 passed and 3 failed; `d2c98d0a23707e29801d78caa3bcbe4f59f91e18f832de9ace4d3fb321209c2d`
(7,854, after the hunk) gave all 13 of `test/tls_wire/hello.zig` passing;
`12d5346941a9b512cab144203bc6c1f8e49f9e77495d341aa3c0987f3edb8944` (7,884, after
the `parseCertificateRequest` widening, its vector and the ordering comment)
gave all 13 again; and current `aee3cd4a5290d8278f92aea3d46ba16d2360f70cc154de881dd9d116afcf5e17`
(7,890) gave all 13 a third time. `test/tls_wire/hello.zig`
(`ee454b334a38f99de9418034440ed62534a6ca4d581433b991de07881648ee3a`, 1,556 lines,
13 tests) is **unchanged across all four**, which is the point: the test bytes
were fixed while the core moved under them. **That stability is ending.**
`hello.zig` **has left** `ee454b33…` / 1,556 lines: the two rows held below — the
`:369` `u16` widening and the `:804` `msg[4..]` guard, each with its comment —
landed, owned by `FuzzRootQuotaAndOracleTrap`. **`ee454b33…` describes the bytes
every green above was taken against and no later ones, and is not a digest of the
current file**; `evidence/w1-merge-static-dispositions.log` records the move
(`reviewer read ee454b334a38, now e45344235410`), which is one of the twelve
whole-file digests that stopped the ledger merge. No full digest for the file
that moved is written here, because this record is not where one is computed: the
shortened pair above is the log's own. Every `:369` and `:804` citation in this
record moved with the file.

**Those digests, every line count and the 13-test count were re-read from the
files after each report.** The fourth link is a shape change and nothing more —
`StaticTlsReview` flagged the vector's `undefined`-plus-writes form as exactly
what the use-undefined rule fires on, and it is now a `comptime` literal, a
constant with no unwritten bytes to reason about. The parent has since run the
`hello.zig` parent itself against these bytes, so that row is no longer
single-witness; the landed table in `vendor/quic/VENDORED.md` §11 still does not
list this hunk, and no green is claimed for it here.

**A near miss belongs in the record too.** An edit call in that work deleted the
`required,` member of the vendored `ClientAuth.Mode` enum, and **the compile and
the 13 of 13 were green against the damaged file**. The owner's own post-edit
read caught it and repaired it before anything was recorded. That is not a defect
in the code — the enum is intact — it is a fact about how the evidence was
produced, and a reader of "13/13 green" is entitled to know that the suite had
nothing to say about what went wrong and that reading is what caught it.

**Two rows landed with no run behind them, two landed with no red behind them, and
one that must never be called closed.** Every one moves a digest, so a green
recorded against `aee3cd4a…` describes those bytes and no later ones — which is
why the two `hello.zig` rows must be read as moving the *test* digest too, which
they now have.

| Item | State | Condition |
|---|---|---|
| `parseCertificateRequest`'s `readU16(data) + 2 != data.len` addition on a `u16` | **landed** in `12d5346…`, with its nine-byte vector; vector reshaped in `aee3cd4a…` | **no red exists and none is recorded.** The pre-fix failure was an integer-overflow ABORT rather than a failed tag, and it was never witnessed: fix and vector landed in one authorised pass. The green is real; a red for it would be a fiction |
| the same trap in the oracle at `test/tls_wire/hello.zig:369` | **landed**, with its comment — `FuzzRootQuotaAndOracleTrap` | **`zig build fuzz` has not been re-run since the repair, so there is no green behind it.** Landing the row is what moved the `hello.zig` digest above |
| unguarded `msg[4..]` at `test/tls_wire/hello.zig:804` (`clientHelloBlockAt`) | **landed**, with its comment — same owner | the same two facts: same digest consequence, and the same unrun `zig build fuzz`. **804, not the 722 first reported** — 722 was a pre-hunk line passed on unchecked, so any row citing it was already stale |
| the offer-side refusal's *ordering invariant* | **landed, invariant-documented** | the comment is in the file; the invariant is still not in code |

**The offer-side refusal is landed, its invariant is now documented, and it is
not closed.** The empty-name refusal lives in the pre-pass that reads every
offered entry (`tls13.zig:3118-3133`); the selection walk below it
(`:3135-3155`) does not repeat the check, so "the pre-pass runs first" is what
makes the walk sound — move either and the selection path would accept a
zero-length name. That ordering is now stated in the file, at
`tls13.zig:3142-3148`: the walk does not repeat the refusal, a zero-length
`ProtocolName` is refused before the walk can reach it, including in a list of
nothing but empty entries, which is that rather than the
`no_application_protocol` below. **3148 is the last line of that comment** — 3149
is blank and 3150 opens a different one, about an entry too long for
`selected_alpn`, which is a different rule about a different thing.
`Rfc7250WireSpecReview` raised the gap on its own re-read and asked for exactly
this comment. **Documented is not closed**: the dependency is still carried by
reading order and prose, not by an assertion the compiler or the suite checks.

**Credit for that review's four findings.** Findings 2 (zero-length *selected*
`ProtocolName`) and 3 (`expect_node_id` under `.optional`) belong to this patch.
Finding 1 (a zero-length name in a caller's *configured* list) belongs to the
concurrent `quic_config.validateAlpns` at `src/transport/quic_config.zig:84-91`
called from `quic_bridge.zig:212` and `dial.zig:406`, **not** to this patch,
which touched neither file. Finding 4 (the accept path dispatching on the
`negotiatedAlpn` fallback when nothing was selected) was **open and unowned**
here, narrowed to what `node_accept.zig:141-155` does with an unnegotiated value.
**It is now found, repaired on the accept path, and proved by a consumer
regression.**

**What it was.** The accept path dispatched on `Connection.negotiatedAlpn`, which
answers `config.alpn[0]` whenever the handshake selected nothing
(`vendor/quic/src/quic/tls13.zig:2060-2063`), and whose own note calls that
fallback "not a negotiated protocol and nothing treats it as one"
(`:2057-2059`). On a server that is this node's own first configured protocol, so
a peer advertising no protocol at all would have been handed to whichever handler
that name belongs to, on a protocol it never named.

**The reachability proof, which is what made it a defect rather than a
latent one.** The core's `no_application_protocol` refuses an empty intersection
of an offer that *was* made, and it lives inside the ALPN extension's own parse —
`tls13.zig:3115` is the `if (elen >= 2)` that arms it, `:3178` is the refusal —
so a ClientHello carrying **no** extension never reaches it and the handshake
**completes**. The core states that itself: "the extension is then absent in both
directions, `negotiatedAlpn` answers `""`, and neither end fails"
(`tls13.zig:1433-1435`), and it answers EncryptedExtensions with an empty
selection rather than with whatever length the storage held (`:2304-2310`,
`:3379-3396`). The present-offer guard above was never about this case, and
nothing had closed the other half.

**What was repaired.** `node_accept.zig` asks the handshake rather than the
fallback, through the one canonical method: `Conn.negotiatedAlpn`
(`src/transport/quic_conn.zig:80-107`), which takes only the receiver — no
`Conn` argument, and no private copy left in the node file — reads
`selected_alpn[0..selected_alpn_len]` (written by the selection walk and by
nothing else, `tls13.zig:3163-3164`), and answers null for a zero length.
`runTask` calls it at `node_accept.zig:144` and then refuses **both** causes —
selected a protocol no registration claims, and selected nothing at all — with
the outcome an unroutable connection already got: counted, warned, dropped
without a peer response, no `Event.routed` fed. Nothing was invented for it.

**Which regression proves it.** `test/runtime_handlers_test.zig:882`, `a peer that
negotiates no protocol reaches no handler` — a real `Socket` + `Bridge` +
`Dialer` peer with `alpn_count` emptied after the configuration check has run, so
`buildClientHello` puts a ClientHello with no ALPN extension on the wire. The
half with teeth is the lane: `protocols_refused` 1, `tasks_routed` 0, and
`node_close.laneStats(node, 0)`'s finished and turns both **0**, because
`config.alpn[0]` there is the gossip ALPN and the old dispatch would have driven
the gossip handler. A peer that does negotiate is served afterwards on the same
node, so the refusal is this connection's and not this node's.

**The serve half is a different file, and it has landed too.** `serveAdmit`
compares against `relay_alpn`, so a serving node listing the relay ALPN first
was reading `Connection.negotiatedAlpn` — its own first configured protocol —
against a peer that named none, and spending a client slot and a
`ServerChallenge` on it. It now asks the handshake the way the accept walk does
(`src/node/node_relay_serve.zig:53`, the same `Conn.negotiatedAlpn` at
`src/transport/quic_conn.zig:80-107`), and null is the walk's own skip: no slot,
no stream, nothing written. Its regression
is `test/relay_wire_test.zig:1674`, `a peer that negotiates no protocol spends no
client slot`. **Written, and no result observed for it here** — written is not
run, and run is not observed until the receipt says so.

**The parent has now run these itself, so they are no longer single-witness.**
Against `aee3cd4a…`, `zig build quic-test -j2 --prefix …/install` gives **Build
Summary: 3/3 steps succeeded; 560/560 tests passed**, exit 0, 52.54 s
(`evidence/w1-quic-test-after-tls-hunk.log`). **560 is the whole artifact, not a
filtered subset** — a build-step `--test-filter` does not forward on this tree, so
every filtered claim here is a direct `zig test` line and this one is not.

**The vendored core's green, and what that green is named by.** A second leg gives
**3/3 steps succeeded, 560/560 tests passed**, exit 0 against the admission-hook
bytes (`evidence/w1-quic-test-after-admission-hook.log`, the same summary line).
**That leg carries no `tls13.zig` digest** — it is named by what landed in it — so
the digest a vendored green is anchored to by name in this record is `aee3cd4a…`,
and this record does not guess one for the second leg. Two earlier `quic-test`
runs from the owner's session, against `d2c98d0a…` and `12d5346…`, are **stale and
discounted**; neither describes `aee3cd4a…`, and nothing is claimed for them after
it.

**The first-party figure is a different artifact and is not interchangeable with
560.** `zig build test -Doptimize=Debug` and `-Doptimize=ReleaseSafe` each report
**28/28 steps succeeded; 790/790 tests passed**, exit 0 in both modes, with the
same per-artifact counts in each — unit 678, integration 3, loopback 24,
protocol-loopback 5, blobs-transfer 6, two-process 11, relay-wire 11,
runtime-handlers 6, rust-wire-initial 23, expected-log-verdict 15, coverage 8.
`quic-test` compiles `vendor/quic/src/test_all.zig` and counts 560; `test` runs
this project's own roots and counts 790, carrying `test/vendored_invariants.zig` —
the vendored no-socket, no-clock, no-global-RNG scanner — inside the unit
artifact's 678.

The parent also ran, on its own account rather than as a restatement: the
`hello.zig` parent → **All 13 tests passed**; the §12 datagram regression → **All
2 tests passed**, so that patch's test still holds after everything else moved;
and `test/quic_wire/transport_params.zig` → **1/1 passed**, `RFC 9000 §9.6: a valid
preferred address keeps its id and reset token`, which is §13's oracle.

**Two absences are deliberate and will stay explicit.** No red exists for the
`parseCertificateRequest` vector and none will be manufactured: the pre-fix
failure was an integer-overflow abort rather than a failed expectation, the fix
and the vector landed in one authorised pass, and a red that was never witnessed
would be a fiction — **an explicit absence is worth more to a reader than a
constructed one.** And the offer-side ordering invariant stays **landed,
invariant-documented, not closed**: a comment that says what the ordering
guarantees is worth having, and calling it closed would claim a machine check
that does not exist.

The `u16`-addition rationale now has a third instance, phrased alike on purpose —
`messages.zig:139-142` for an `extensions` block, and `parseCertificateRequest`
for `SignatureScheme supported_signature_algorithms`: RFC 8446 §4.2.3 measures
each against a byte count, so the peer's length is read as a `usize`, because a
peer writing `ff ff` names something longer than any buffer and adding to it in a
`u16` would overflow before the comparison could answer.

**8. The unit artifact's expected-log accounting for two new ALPN-refusal lanes.
Closed 2026-10-05, by the wiring plus a run that fills the row.** These are **not**
the configuration refusals. Item 7's `validateAlpns` returns
`quic_config.AlpnError` — `error.NoAlpn` for an empty list or an empty entry,
`error.AlpnNameTooLong` for an over-long name — at configuration time from
`Bridge.create` and `Dialer.create`, before anything allocates. **They are not
logs and they never reach the expected-log runner**; they are asserted by the
`Dialer.create` and `Bridge.create` refusal regressions on the fixed-buffer
allocator's `end_index`, which is the right place for them.

**What needed the accounting were the two ALPN-withdrawal vectors in
`quic_bridge.zig`**: handshakes that legitimately end in
`no_application_protocol`, one whose offer leaves only a withdrawn protocol and
the other offering a withdrawn one alone. They live in the **unit** artifact, root
`src/unit_test.zig`, which reaches `node_tests` and `node_retirement_tests` by
`refAllDecls`.

**The loopback artifact must not be touched to absorb them, and was not.** It has
its own runner and its own `BadCertificate` / `NoApplicationProtocol` rows
(`build.zig:282-295`); the unit artifact's rows are the unit artifact's rows and
nowhere else, which is per-artifact accounting stated as a rule and kept as one.

**The wiring that was missing is in the tree.** The unit artifact runs through
`build_support.addTestRun` with its own row (`build.zig:228-239`):
`TLS 1.3 handshake error: error.NoApplicationProtocol`, scope `default`,
**`.count = 2`**. One row and not two rows is the correct shape, and the reason is
the runner's own: a command line that names one message twice is refused before
any test runs (`test/expected_log_runner.zig:46-50`), so a count is how an
artifact says the same refusal arrived twice.

**And a run has filled it.** The runner's contract is exact: the count is the
claim and not a ceiling, a refusal arriving once more than the row declares fails
the run, and a row nothing matched fails it as the stale expectation it then is
(`test/expected_log_runner.zig:34-38`, `:52-56`). Both
`zig build test -Doptimize=Debug` and `zig build test -Doptimize=ReleaseSafe`
report the unit artifact green at 678 of 678, exit 0
(`evidence/w1-full-debug-suite-wave1-union-verification.log`,
`evidence/w1-full-release-safe-suite-wave1.log`). **So both lanes ran, both were
refused the way the row says, and the artifact carrying them is green in both
safety modes.** The count that was deliberately not written here before the
artifact ran is now a receipt rather than a claim, which is the only change of
kind this record permits on a number.

**9. The Wave 1 gate itself. Open, and Wave 1.** **No green is claimed here.** One
part of it closed on 2026-10-05: `zig build test -Doptimize=Debug` and
`zig build test -Doptimize=ReleaseSafe` each reported **28/28 steps succeeded;
790/790 tests passed**, exit 0 in both modes
(`evidence/w1-full-debug-suite-wave1-union-verification.log`,
`evidence/w1-full-release-safe-suite-wave1.log`) over the unioned tree, with the
same per-artifact counts in each. Those receipts describe the bytes of that run,
and they are a targeted run rather than a gate result.

**Against the current bytes the full gate result is pending.** The required
source lint fixes have landed and no gate group has been run over them, so a
pending group is recorded here as pending and **not** as a failure. The red lint
and static figures in `evidence/w1-lint-and-static-current-findings.log` belong
to older bytes.

**Two of the three items named when this was written have moved, and one has
not.**

**1. The TLS decode leg is green; the fuzz gate is pending.** The 1/1 failure is
kept: `evidence/resume-w1-tls-focused-before.log` fails at
`test/tls_wire/messages.zig:330` in `certificateTypeShapes`, reached from `check`
and `test/tls_fuzz.zig`, and `evidence/resume-w1-tls-focused-after.log` is 1/1
passing. **The cause recorded here is corrected: it was not the `u16` overflow
in the TLS oracle.** It was the certificate-type oracle table, which carried one
exclusive `shape` column per body and so forced RFC 7250 §3's counted offer and
§4.2's single-value selection into one verdict — `&.{0}` labelled neither when
it is no offer at all and a whole x509 selection, `&.{1,2}` a whole offer with
no selection the one-byte grammar can hold. Both production decoders in
`tls13.zig` were correct and were not changed; the table now carries one column
per role, `offer` and `selection`. The comptime branch quota in the
captured-golden decode is a separate repair and this correction does not touch
it. `evidence/resume-w1-quic-wire-corpus-replay.log` is 1/1 on the QUIC wire
decode under the correct filter; a command that ran zero tests is not evidence.
**A focused decode leg is not the fuzz gate.**

**2. The zbc disposition ledger is re-merged.** It now holds **32 source proofs
and 60 records**, byte-idempotent on a second emission
(`evidence/resume-w1-ledger-idempotence-canonical.log`: `0 old records dropped,
0 new; identical to gate_zbc_dispositions.zig`, both emitted files SHA256
`3fbaa189…`), with the helper suffix the gate calls preserved and both controls
behaving — the conflicting-kind control refuses rather than counting two reads
as a vote, and the current-defect control refuses until repaired source is
re-read. `evidence/w1-merge-static-dispositions.log` and its
`12 problem(s); ledger NOT rewritten` are why `test/tls_wire/hello.zig` is
recorded above as having left `ee454b33…`; that log is now history, because the
ledger describes the current bytes.

**3. The full lint, static and fuzz gate result is pending**, for the reason at
the head of this item. Nothing here reports it as failed, and nothing here
reports it as green either.

So every receipt in items 2, 6 and 7 is still a targeted run rather than a gate
result. *Closes when* the lint, static and fuzz gate groups have been run over
this tree and their receipts are green. Waves 2–4 —
multipath, the standard relay carrier, RFC-compatible resumption — remain
unimplemented and are not what this item is waiting on.
