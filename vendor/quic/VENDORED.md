# vendor/quic

The QUIC substrate for M8. Third-party code, vendored, patched, and pinned.

| | |
|---|---|
| Upstream | `endel/quic-zig` |
| Commit | `14b9dc3e5e8429d07e7ed18619c7b4f4baaa3719` |
| Version | `0.5.0` (`build.zig.zon:3`) — the repository publishes no tags, so a commit SHA is the only pin available |
| Licence | MIT — `LICENSE`, byte-identical to upstream's |
| `minimum_zig_version` | `0.16.0` (upstream `build.zig.zon:13`) |
| Vendored | 32 of upstream's 74 `.zig` files under `src/`: 29,776 lines upstream, 30,236 here |
| Written here | `src/test_all.zig` — upstream's test root, rebuilt (43 lines) |
| Not vendored | 42 files, 35,388 lines — see below |
| Patched | 13 files, +2,707 / −2,247; 1 file deleted outright |

Fetched 2026-09-30 with `gh api` against the pinned SHA. No clone is kept in this
repository; `docs/PLAN.md` and `README.md` point at read-only checkouts under
`~/projects` that do not exist on this node, so every byte here was captured
from GitHub primary source and pinned.

Every count below is measured against this tree and against the pinned commit.
A `file:line` names the file it is in. A bare `:NNN` names the **upstream**
file the section is about; where a section mixes the two, the file is spelled.

## What is here, and why only this

The upstream module root welded four layers into one module. One is here.

**The sans-IO core** — `src/quic/`, 29 of upstream's 32 files. This is what
ozai needs and nothing else is.

**The socket-owning layers were never copied** — 5 files, 6,384 lines:

| File | Lines | What it owns |
|---|---:|---|
| `src/event_loop.zig` | 5,211 | opens and binds sockets inside its own `Server.init` (`:2016`, `:2036`) and `Client.init` (`:2660`, `:5101`) |
| `src/quic/ecn_socket.zig` | 584 | ECN-marked socket |
| `src/http1/socket.zig` | 364 | `std.c.accept4` at `:338`, `std.c.send` at `:159` |
| `src/http1/timers.zig` | 194 | bound to `xev.Timer` |
| `src/xev_backend.zig` | 31 | the libxev backend |

`src/c_api.zig` (484) and `src/fuzz.zig` (1,907) went with them: both drive the
stack through the event loop, so neither would exercise the core at all.

Upstream's own `src/test_all.zig` (51 lines) was not copied either. It is
upstream's test root, so it is rewritten rather than deleted, and it must be:
it names `event_loop.zig`, `quic/ecn_socket.zig` and `http1/e2e_test.zig`,
three files that do not exist here.

The `endel/libxev` dependency and the forced `link_libc` went with the sockets
— both were consequences of owning a socket, which ozai has decided it will not
do. `build.zig.zon`'s `.dependencies` is empty.

This ordering is deliberate. A vendoring plan that copies a repository and then
deletes the socket layer leaves a window in which the tree owns a socket, and a
plan that discovers forty files when it expected three is a plan that was
wrong. Deleting by omission means the socket-owning code was never in the
repository to begin with.

**The protocol layers are gone** — 30 files, 24,829 lines: `h3` (6, 7,106),
`webtransport` (3, 3,886), `h0` (1, 208), `moq` (12, 5,865), the five non-socket
files of `http1` (3,260 — the two socket-owning files are counted above), and
three of the four files of the TLS-over-TCP stack in `src/tls` (4,504). HTTP/3
is a protocol ozai does not implement — `docs/PLAN.md:352` says so.

`src/quic/connection_manager.zig` imported `h3`, `h0` and `webtransport` from
library code (`:13`, `:14`, `:15`), not only from tests, so the cut is not free:
three optional fields on `ConnEntry` (`:64`, `:69`, `:70`), their parameters,
the detach record in `removeConnection`, and `destroyProtocols` (`:155`). Those
are removed rather than left as always-null fields.

**`src/sys.zig` is gone entirely.** Upstream's syscall seam (864 lines) held
both halves in one file. The socket half — `socket`, `close`, `bind`, `sendto`,
`recvfrom`, `listen`, `accept`, `getsockname`, `resolveHost`, `sleepNs`, a
`File` type, and `getenv`, which had no caller at all — was cut at vendoring.
The clock and entropy half was cut by the threading patch below, which is what
deleted the file and `lib.zig`'s re-export of it. **There is no syscall seam
file in this module.** Nothing under `vendor/quic/src/` reaches `std.c`,
`std.posix` sockets, the filesystem, or the process environment; the sweep is
zero for every one of them.

**Kept deliberately:**

- `src/quic/lossy_link_test.zig` — upstream's own in-process harness, 398 lines
  upstream and 447 here, the growth being the parameters the threading patch
  introduced. It drives `Connection` directly over hand-built socket addresses
  and opens nothing. It is upstream's own evidence that this core is drivable
  in-process, which is the whole reason the vendoring is viable, and it is the
  test that would notice if a future patch reintroduced a socket.
- **`src/quic/rsa.zig`.** The certificate is a raw Ed25519 key, and RSA is still
  a legal TLS 1.3 CertificateVerify signature scheme:
  `client_auth_signature_schemes` offers `rsa_pss_rsae_sha256/384/512`, and
  `verifyCertificateVerifySignature` still carries three RSA arms
  (`tls13.zig:106-108`). Certificate and signature scheme are different things.
  A reader who "simplifies" by deleting RSA on the reasoning that an Ed25519
  identity implies an Ed25519-only stack would remove real interop surface for
  no gain.

## The patch, as applied

Upstream's core is sans-IO at the packet level — `ConnectionManager.recvDatagram`
takes the bytes, both addresses, the ECN bits and a caller-supplied output
buffer, and returns a four-arm `RecvAction` whose `send_response` arm hands the
caller something to `sendto` itself. The core never opens a socket. That much
was true and is preserved.

Three things were not true, and each is a project requirement rather than a
preference.

### 1. A bare 44-byte Ed25519 SPKI is a valid peer certificate, both directions

Upstream gates the peer certificate behind X.509 in four places —
`clientProcessCertificate`, `clientProcessCertificateVerify`,
`serverProcessClientCertificate` and `serverProcessClientCertificateVerify` —
and the server's `verifyPeerChain` is unconditional and guarded by no flag.
iroh's identity model is a 44-byte DER `SubjectPublicKeyInfo` wrapping the
32-byte node id, presented in both directions, verified by byte comparison
against the id you expected. A stack that insists on parsing X.509 cannot be an
iroh peer.

**The patch is a deletion, not a flag split.** An earlier version of this file
recorded a split: keep `skip_cert_verify` at `true`, lift the key inside the
skip branch, change the guard that consumes it. What shipped removes the bit, so
there is nothing left to guard. That is cheaper and it is why no dead walk is
left behind for a future patch to accidentally revive.

**Deleted — the X.509 walk** (19 named declarations, the `ChainError` error set
at upstream `tls13.zig:471`, and the `X509Extensions` struct at `:283`):
`certificateWellFormed` (`:135`), `tlvsWellFormed`, `tlvChildren`,
`algorithmIdOk`, `nameOk`, `subjectPublicKeyInfoOk`, `extensionsOk`,
`X509Extensions.hasKeyCertSign`, `issuerConstraintsOk` (`:311`),
`parseX509Extensions`, `parseBasicConstraints`, `parseExtendedKeyUsage`,
`parseKeyUsage`, `clientLeafUsageOk` (`:517`), `verifyPeerChain` (`:486`),
`chainError` (`:505`), `certificateAuthorities` (`:371`),
`keyMatchesCertificate` (`:3657`), `parsePemCertChain` (`:3412`).

**Deleted — what only the client-auth CA list reached:**
`buildCertificateRequest` (`:417`) lost its `*const ClientAuth` parameter and is
now `buildCertificateRequest(buf)` (`tls13.zig:297`), `derHeader` (`:400`) went
with it, and `ClientAuth.authorities` (`:338`) and `ClientAuth.ca_bundle`
(`:333`) went with that, along with `max_authorities_len` (`:366`) and
`max_client_chain` (`:553`).

**Deleted — the keylog**, which went with `TlsConfig.keylog_file`: `hexByte`
(`:1094`) and `writeKeylogLine` (`:1099`), and the six call sites that wrote
NSS keylog lines. That field was a `sys.File` — a file handle, which the
no-file-handle rule forbids whatever the certificate argument. `trimLeadingZeros`
(`:3683`) went with them: a test helper that compared a DER key against a
certificate's modulus, which nothing parses any more.

**Deleted — fields:** `TlsConfig.skip_cert_verify` (`:1076`),
`TlsConfig.ca_bundle` (`:1084`), `TlsConfig.keylog_file` (`:1087`).
`Tls13Handshake.leaf_pub_key_buf: [600]u8`, `leaf_pub_key_len: u16` and
`leaf_pub_key_algo` (`:1253-1255`) are replaced by one field,
`peer_node_id: ?[32]u8` (`tls13.zig:863`) — 600 bytes of DER scratch replaced by
33 bytes of identity, on a struct upstream's own comment calls "~52 KB", so the
struct shrinks by well under a kilobyte and the stack frame barely notices.

**Added:**

- `liftEd25519Spki(der) -> [32]u8` (`tls13.zig:188`) — 44 bytes in, 32 out, by
  TLV walk. Fails only with `error.MalformedSubjectPublicKeyInfo` or
  `error.UnsupportedSubjectPublicKeyInfo`. The length is fixed at 44, so the
  length check is the whole bounds check.
- `lifted_key_algo` (`tls13.zig:224`) — one `const` of type
  `Certificate.AlgorithmCategory` set to `.curveEd25519` **by construction**.
  This is what makes `verifyCertificateVerifySignature`'s `.ed25519` arm
  reachable: that arm demanded `pub_key_algo == .curveEd25519`, a tag only ever
  set by X.509 parsing, which is why it was dead for a raw SPKI. Supplying the
  tag lifted out of the certificate itself turned out to be a line rather than a
  patch.
- `TlsConfig.expect_peer_node_id: ?[32]u8` (`tls13.zig:730`), compared with
  `crypto.timing_safe.eql` at `tls13.zig:1466`. Null accepts any key, and the
  doc comment at `:726-729` says plainly what that gives up.
- `ClientAuth.expect_node_id: ?[32]u8` (`tls13.zig:264`), the same comparison on
  the server at `tls13.zig:2084`.

Both CertificateVerify checks are now unconditional (`tls13.zig:1513` and
`:2117`), guarded by neither a flag nor a length. `cert_hashes` survives
deliberately: the WebTransport leaf-fingerprint bargain needs no chain either.

`signCertificateVerify` no longer draws. Upstream read 32 bytes before it knew
which scheme it was signing with and handed them to the Ed25519 arm, which has
no nonce. `tls13.zig:4211` is a test that counts the draws and expects zero for
Ed25519 and exactly one for P-256 — a test that merely passed would not have
noticed the difference.

### 2. Time and entropy are injected

`AGENTS.md` §2 and `docs/ARCHITECTURE.md:37` forbid exactly this: a state
machine that reads a clock cannot be driven by a test.

Upstream read the monotonic or realtime clock at **46** sites and the process
CSPRNG at **39**, counted across the vendored library and excluding `qlog.zig`,
which read the clock once more and is deleted. It also carried a mutable
`test_clock` global, referenced seven times from `lossy_link_test.zig`, behind
`sys.nanoTimestamp`.

Both are now parameters. They are passed by the caller, per call, and never
stored — a handshake holding either could not be driven twice with two
different clocks:

- `now: i64` — a monotonic instant in nanoseconds that the caller read.
- `now_s: i64` — TLS's channel, and **a second on the caller's clock, not on the
  epoch**. Nothing may compare `now_s` against an epoch-derived quantity;
  `SessionTicket.isExpired(now_s)` (`tls13.zig:574`) is a difference, never a
  comparison. The one value written from it is a ticket's `creation_time`, and
  the ticket is sealed with AES-128-GCM under `ticket_key`, so the peer receives
  opaque bytes and cannot read the base.
- `random: std.Random` — **by value**, not a pointer. A handshake holding a
  pointer could be driven twice from one generator, and the SipHash lookup key
  `ConnectionManager.init` draws once belongs to whoever created the manager.

The seam was half-built already, which is why this extended an existing shape
rather than inventing one: upstream already threaded `now: i64` through **44**
parameters of its own. The patch adds 42 more `now`, the 6 `now_s` (upstream had
one, on the `verifyPeerChain` that is now deleted), and all 61 `random`.

Both public entry points changed shape:
`ConnectionManager.recvDatagram(bytes, from, local, ecn_val, out_buf, now,
random)` (`connection_manager.zig:496`) and
`Connection.sendAt(out_buf, now, random)` (`connection.zig:3139`).
`Connection.send(out_buf)` was deleted rather than left as a wrapper, because a
wrapper that reads the clock is the thing the milestone exists to remove.
`nextTimeoutNs` (`connection.zig:4087`) and `sendDatagram`
(`connection.zig:3947`) gained the instant their deadlines and queue timestamps
are measured from; upstream read the clock inside both.

One draw that turned out not to be needed. The RFC 9000 §18.1 greased transport
parameter (upstream `transport_params.zig:231`) still draws, because a peer that
only ever sees one reserved id learns to tolerate that id, and finding that
parser bug is the point of the probe. It is a protocol probe, not a secret, so
it stays a plain draw from the caller's generator and no test asserts on the
value.

### 3. Cut-outs inside files that were vendored

- **`src/quic/qlog.zig`, 411 lines, and its 12 guarded call sites.** Upstream
  kept `Connection.qlog_writer` (`:759`) and `ConnectionConfig.qlog_dir`
  (`:532`), initialised the writer at `:950` and `:4603`, and called
  `packetReceived`, `packetSent`, `packetLost`, `metricsUpdated` and
  `connectionClosed` from 12 `if (self.qlog_writer) |*ql|` blocks, buffering
  frames per packet to do it. Deleted rather than stubbed: qlog wants a clock
  and an I/O sink, and after this patch neither is available inside the core —
  both are the caller's now, and neither is optional.
  `ConnectionConfig.qlog_dir` is gone from the type.
- **`src/tls/test_certs.zig`, 383 lines.** PEM fixtures for the chain walk. Once
  the walk was deleted, `rsa.zig` and `tls13.zig` imported it for tests only,
  and the RSA-2048 key moved verbatim into `rsa.zig` as a fixture where it still
  signs the fixture message. **This file previously listed `test_certs.zig`
  under "kept deliberately". That was wrong, and the tree has overtaken it.**
- **`src/quic/ca_bundle.zig`, 75 lines.** The trust anchor `verifyPeerChain`
  walked to.
- **`src/sys.zig`, 864 lines upstream.** Split at vendoring, emptied by the
  threading patch, then deleted, with `lib.zig`'s re-export.

### 4. Upstream does not compile on 0.16.0

Upstream's `build.zig.zon` pins `minimum_zig_version = "0.16.0"` and the tree
does not build. `src/sys.zig:513`, inside `randomBytes`, is
`switch (posix.errno(@as(isize, @bitCast(rc))))`: `posix.errno` wants the
`c_int` a syscall returns and `@bitCast` hands it an `isize`. The socket half
above it spells the same call correctly, so this is one mistyped line rather
than a language mismatch — and it sits inside the one function the threading
patch deletes anyway.

It is a small finding and it moves the cost model: the revisit trigger "drop the
fork and consume the dependency directly" has nothing to consume. The pinned
revision is not a working 0.16 build, and this fork is not a fork of a working
state.

## Measured cost

| | Predicted | Measured |
|---|---|---|
| Socket layer | 7 files, 7,194 lines | 5 never copied (6,384), plus `c_api.zig` and `fuzz.zig` (2,391) because both drive the stack through the event loop. No `xev`, no `link_libc`. |
| Clock and CSPRNG | 60 sites | 85 reads removed (46 clock, 39 entropy), 109 new parameters (42 `now`, 6 `now_s`, 61 `random`) across 11 files, both public entry points changed, no design change |
| Certificate work | four functions, `TlsConfig`, `ClientAuth`, a flag split | 24 named functions, the `ChainError` set, the `X509Extensions` struct and two `ClientAuth` size constants deleted outright, the flag gone with them, plus `keylog_file` and `ca_bundle`, which this record never mentioned |
| The seam file | "splits rather than deletes" | split, then emptied by the threading patch, then deleted. There is no seam file. |
| Module root | "cut in the same pass" | `lib.zig` 47 → 41 lines, four layers of re-exports gone |
| Interop matrix | re-run at our SHA | **not done** |

The record was wrong in one direction, and it was the expensive one: it billed
the certificate work and not the threading. Deleting the chain walk turned out to
be *cheap* precisely because it was permitted to be a deletion rather than a flag
split — the split would have left the walk present, dead on one path and live on
the others, and every one of those paths a way for `realtimeSeconds` to come back
through.

Per file, against the pinned commit:

| File | +/− | What |
|---|---:|---|
| `src/quic/tls13.zig` | +1,297 / −1,354 | the certificate deletion |
| `src/quic/connection.zig` | +578 / −482 | qlog out, `send` out, time and entropy in |
| `src/quic/connection_manager.zig` | +199 / −197 | the protocol layers out, time and entropy in |
| `src/quic/rsa.zig` | +198 / −45 | `signPss` takes the caller's salt; the RSA fixture moves here |
| `src/quic/lossy_link_test.zig` | +102 / −53 | upstream's harness, adapted to the new signatures |
| `src/quic/packet.zig` | +76 / −28 | entropy into packet numbering |
| `src/quic/ack_handler.zig` | +70 / −8 | entropy into the challenge |
| `src/quic/packet_packer.zig` | +55 / −9 | time and entropy |
| `src/quic/transport_params.zig` | +48 / −14 | `encode` takes the generator, for the grease draw |
| `src/lib.zig` | +29 / −35 | four layers of re-exports gone, `sys` gone |
| `src/quic/stateless_reset.zig` | +29 / −7 | entropy into the reset token |
| `src/quic/quic_lb.zig` | +25 / −13 | entropy into CID generation |
| `src/quic/congestion.zig` | +1 / −2 | one dead `sys` import |

Diff size is not a measure of this patch. `tls13.zig` went 4,866 → 4,809 lines
and `connection.zig` 6,666 → 6,762: the deleted walk and the added lift, doc
comments and tests are of about the same size.

**The next person pricing a fork of this shape should price the threading, not
the certificate work.** Eleven of the thirteen files changed to take a new
parameter, and two of those also cut a subsystem — `connection.zig` gave up
qlog, `tls13.zig` gave up the X.509 walk. The remaining two, `lib.zig` and
`congestion.zig`, changed only to drop a re-export and a dead import. The
original decision record did not anticipate this, and a decision record that
understates its own cost is worse than one that declines.

## Not gated on purpose, and not unchecked

`devenv.nix` runs the house gate as `GATE_EXCLUDE=vendor zig-gate` (`:86`) and
`GATE_EXCLUDE=vendor zig-gate --no-zbc --cov` (`:100`). **`vendor/quic/` is
excluded from `zig fmt`, `ast-check`, `zlint` and `zbc` on purpose.** It is
upstream code carrying its own formatting and its own idioms; reformatting it
would bury the patch under thirty thousand lines of noise, and linting it with
this project's rules would report findings nobody intends to fix.

"Not gated" must never mean "unchecked". Three things stand in for it:

1. **The vendored suite runs.** `zig build quic-test` (`build.zig:56-58`)
   compiles `vendor/quic/src/test_all.zig` and runs the 455 `test` blocks spread
   across 26 of the 29 vendored files. The module is declared and then compiled
   (`build.zig:36-40`) because a vendored tree nothing references is a vendored
   tree nobody has proved still builds.
2. **The no-socket / no-clock / no-global-RNG invariant is enforced by a test**,
   `test/vendor_invariant_test.zig`. It reads every `.zig` under
   `vendor/quic/src/` and fails on the constructs this directory must not
   contain: `std.posix.socket`, `std.c.`, the socket syscalls, `std.fs`,
   `std.process`, `getenv`, `std.time.nanoTimestamp`, `std.time.timestamp`,
   `std.crypto.random.*`, and the `test_clock` global. The sweep is clean today:
   zero hits for every one of them. Note what it does not forbid — mutability.
   `src/quic/ecdsa_p256.zig:34-35` keeps two file-scope `var`s, a precomputed
   Montgomery table and the flag that builds it once. They are a constant, not
   input, and they are upstream's. The rule is about hidden input, and a rule
   that forbade every `var` would have had to reject those.
3. **This file is the reviewable artefact.** The patch is a named list with line
   references, not a diff nobody can read.

## What is still not settled

**1. 0-RTT, and the verifier identity. Open.** `TlsConfig.session_ticket`
(`tls13.zig:736`) and `TlsConfig.ticket_key` (`tls13.zig:737`) must be stable
across every client-config construction, or resumption silently stops matching.
The certificate patch did **not** discharge this and nothing since has touched
it. Treat early data as unimplemented. It closes when one constructor owns both
values and a test resumes against a server whose ticket key is held constant
across two connections.

There is a tension that keeps this open rather than merely untidy: `ClientAuth`'s
doc comment says session tickets are neither issued nor accepted while a
client-auth policy is in force. In this tree a pinned client identity and
resumption are mutually exclusive, and an iroh peer wants both.

**2. Interop, and therefore requirement 3. Open.** The matrix this vendoring
relied on is upstream's, and it is **not reproducible from this repository**:
upstream's interop runner is a git submodule outside the published package. It
was not re-run at our SHA. Requirement 3 is re-established against this fork or
not at all — `interop/runner/matrix.sh`, with Docker, `quic-network-simulator`
and `tshark`. Until then the honest statement is upstream's own: ten of 88 cells
red, one open, and ours unmeasured.

## Rules for editing this directory

- Do not reintroduce a socket, a syscall, or a file handle. That is the
  invariant the vendoring exists to preserve, and it is what the missing 6,384
  lines bought.
- Do not add a clock read, an environment read, a global, or a global RNG. Take
  the instant and the generator as parameters, and pass them down. Upstream
  already did this on 44 signatures; there is no argument left to have.
- Do not put a deleted subsystem back behind a flag. The certificate patch is a
  deletion, and a switch in front of it would leave the walk reachable.
- `vendor/quic/` is upstream code carrying its own history. The patch is a
  short, named list here, not a diff nobody can review. Keep it that way.

### On rebase

The fork is one small project with no tags, so the SHA moves. **Re-read upstream
for each site; do not reapply this file.** These are the anchors, in the pinned
commit's line numbers:

- `src/sys.zig:513` — the 0.16 type error, and the whole file goes away.
- `src/quic/connection.zig:532`, `:759`, `:950`, `:4603` — `qlog_dir`,
  `qlog_writer` and the two writer-construction sites.
- `src/quic/connection.zig:3128` / `:3134` — the `send` / `sendAt` pair; `send`
  deletes, `sendAt` gains a generator.
- `src/quic/connection.zig:3953`, `:4091` — `sendDatagram` and `nextTimeoutNs`,
  which gain the instant.
- `src/quic/connection_manager.zig:13-15`, `:64`, `:69`, `:70`, `:155` — the
  three protocol imports, the three `ConnEntry` fields, `destroyProtocols`.
- `src/quic/tls13.zig:135` through `:553` — the X.509 walk and its error set.
- `src/quic/tls13.zig:417`, `:400`, `:333`, `:338` — the client-auth CA list.
- `src/quic/tls13.zig:1076`, `:1084`, `:1087` — `skip_cert_verify`, `ca_bundle`,
  `keylog_file`.
- `src/quic/tls13.zig:1253-1255` — the three `leaf_pub_key_*` fields.
- `src/quic/tls13.zig:1094`, `:1099` — the keylog writer.
- `src/quic/transport_params.zig:118`, `:231` — `encode` and the grease draw.
- Every function upstream's body read a clock or the CSPRNG in. `grep -n` for
  `nanoTimestamp`, `realtimeSeconds`, `realtimeNs`, `randomBytes`, `randomInt`
  and `crypto.random.` is the shortest way to find the rest.

Then re-run `zig build quic-test` and `zig build fuzz`, and update the table at
the top of this file. The patch is the asset; the SHA is not.

### The test root is the trap

`vendor/quic/src/test_all.zig` must name **every** file that carries test
blocks. Zig analyses a test block only if the compilation reaches it, and
`lib.zig` is nothing but re-exports, so a root that only re-exports discovers
**zero** tests and exits 0. That is a green step proving nothing, and it is the
failure mode the file exists to prevent.

The cost of getting it wrong is silent: a new file with tests is not run until
it is named below, and nothing fails when you forget. Three files —
`aes_gcm_vectors.zig`, `ghash.zig`, `limits.zig` — carry no `test` block and are
correctly absent; the other 26 are named, and the count is checkable with
`grep -c '^test '` per file.