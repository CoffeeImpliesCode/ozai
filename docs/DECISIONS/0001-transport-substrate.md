# 0001 — Transport substrate

- **Status**: accepted, recorded 2026-09-29. **Corrected 2026-09-30** against a
  measured read of the vendored tree; see
  [Correction of 2026-09-30](#correction-of-2026-09-30). **Executed at M8 on
  2026-09-30**; see
  [Execution record](#execution-record-of-2026-09-30), which names what is
  still open. Item 3 of that list closed after M8; see
  [Still open](#still-open-after-m8).
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
   [Interop](#interop-the-one-claim-that-got-worse).

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

**Fork maintenance.** quic-zig is one small project with no tags, at 57 stars,
last pushed 2026-09-29. The fork has to be rebased when it moves, and the patch
is ours to carry. The patch is now larger than a fork of an untagged
single-maintainer project usually is, which is the honest shape of this risk.
Accepted: the alternative is a C dependency plus a Rust toolchain in the build,
permanently.

**No QUIC v2, no DPLPMTUD on the vendored path.** `SPEC/STATUS.md` marks QUIC v2
(RFC 9369) ✅ Complete. DPLPMTUD is not claimed. Neither blocks an iroh peer.

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
  published package. Until the matrix is run at our SHA the substrate has never
  spoken to an implementation that is not its own test suite.

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
is a test comment at `tls13.zig:4254-4258` explaining why the bounds guard it
provided is no longer needed.

What replaced them:

- **`liftEd25519Spki`** (`tls13.zig:188`) — 44 bytes in, 32 out, by TLV walk,
  failing only with `error.MalformedSubjectPublicKeyInfo` or
  `error.UnsupportedSubjectPublicKeyInfo`. The length is fixed, so the length
  check at `:191` is also the whole bounds check; there is nothing after it that
  can index out of the buffer.
- **`lifted_key_algo`** (`tls13.zig:224`) — one `const` of type
  `Certificate.AlgorithmCategory` set to `.curveEd25519` *by construction*. This
  is what the record identified as the thing that would make
  `verifyCertificateVerifySignature`'s unreachable `.ed25519` arm reachable, and
  it turned out to be a line rather than a patch.
- **`TlsConfig.expect_peer_node_id: ?[32]u8`** (`tls13.zig:730`), compared with
  `crypto.timing_safe.eql` at `tls13.zig:1466`. Null accepts any key, and the
  doc comment at `:726-729` says plainly what that gives up.
- **`ClientAuth.expect_node_id`** (`tls13.zig:264`), the same comparison on the
  server at `tls13.zig:2085`, and `peer_node_id` as the key the
  CertificateVerify is checked against at `tls13.zig:2110`.
- **Both CertificateVerify checks are now unconditional** — `tls13.zig:1513` and
  `:2117`, guarded by neither a flag nor `leaf_pub_key_len`. That is the "split
  the bit" the record asked for, arrived at by removing the bit.
- **`signCertificateVerify` no longer draws.** Upstream read 32 bytes before it
  knew which scheme it was signing with and handed them to the Ed25519 arm,
  which needs no nonce. `tls13.zig:4211` is a test that counts the draws and
  expects zero for Ed25519 and exactly one for P-256 — a test that merely
  passed would not have noticed the difference.

`cert_hashes` survived deliberately: the WebTransport leaf-fingerprint bargain
needs no chain either, and `tls13.zig:731-734` says so.

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

`Tls13Handshake.step(now_s: i64, random: std.Random)` (`tls13.zig:1118`) is
documented at `tls13.zig:1098-1116` as **a second on the caller's clock, not on
the epoch**. The connection supplies a monotonic instant, and the sans-IO
invariant forbids TLS reading one to find out.

Recorded as a divergence because the parameter is spelled `now_s` and sits in a
file that once read `sys.realtimeSeconds`, so a reader who assumes wall-clock
seconds here will eventually be wrong about something. The argument, from
`tls13.zig:1102-1116`:

- The one value written from it is a session ticket's `creation_time`
  (`tls13.zig:2154`), and the ticket is sealed with AES-128-GCM under
  `ticket_key`, so the peer receives opaque bytes and cannot read the base.
- It is not read back on the issuing side. A resuming server recovers only the
  PSK; the **client** stamps its own `creation_time` from its own `now_s` when
  it parses the ticket (`tls13.zig:2404`).
- So the only subtraction is inside one client process — resumption instant
  minus parse instant, `tls13.zig:2666` — and both sides come off one clock.
- A monotonic base that restarts with the process could only mis-age a ticket
  that outlived the clock that stamped it, and a process cannot outlive its own
  clock.

The rule for anyone who touches this: **nothing may compare `now_s` against an
epoch-derived quantity.** `SessionTicket.isExpired(now_s)` (`tls13.zig:574-575`)
is a difference, never a comparison.

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
corrected in the same pass and its conclusion was not.

**1. 0-RTT, and the verifier identity. Open.** `TlsConfig.session_ticket`
(`tls13.zig:736`) and `TlsConfig.ticket_key` (`tls13.zig:737`) must be stable
across every client-config construction, or resumption silently stops matching.
The certificate patch did **not** discharge this and M8 did not touch it.
*Closes when* one client-identity acquisition path exists that resumption does
not skip, one constructor owns both ticket values, and a test resumes against a
server whose ticket key is held constant across two connections and whose pin
is enforced on the second. Until then treat early data as unimplemented.

**Amended 2026-09-30: the reason this item gave was the wrong one.** It read
`ClientAuth`'s doc at `tls13.zig:253-259` — "Session tickets are neither issued
nor accepted while a policy is in force" — as why a pinned client identity and
resumption are mutually exclusive here. That sentence points at the ticket
format, and the ticket format is not the obstacle. A ticket carries no client
identity today and carrying one is mechanical: the plaintext is `[64]u8`
(`:2152`), laid out `psk(32) || creation_time(8) || alpn_len(1) || alpn`
(`:2151`); the sealed form is the same plus a 16-byte tag (`:2164`); and
`serverSendTicket` writes both at `:2152-2175`. Neither size is negotiated with
anything. Do not read this item as a wire-format change.

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

**2. Interop, and therefore requirement 3. Open.** The matrix this record relied
on was upstream's, run at `4988228` rather than the pinned commit, and it is
**not reproducible from this repository**: upstream's runner is a git submodule
outside `build.zig.zon`'s `.paths`. M8 did not re-run it. Requirement 3 is
re-established against this fork or not at all.

There is a second blocker, independent of the first, and it is about the node
rather than the package: **the matrix cannot be run here at all.** Of the
three tools it needs, `tshark` is present and `docker` and
`quic-network-simulator` are both absent. So this is not a case of a runner
that could be wired up locally; it needs a machine that has the simulator's
toolchain.
*Closes when* the matrix is run against this tree **on a node that has
Docker and `quic-network-simulator`** — initialise the submodule outside the
package, run `interop/runner/matrix.sh`, and record the result against our
SHA. Until then the honest statement is the one already in this record: ten of
88 cells red upstream, one open, and ours unmeasured.

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
nobody, and the repair that makes it not look broken is what does it. Open.**

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
