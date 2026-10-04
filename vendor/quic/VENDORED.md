# vendor/quic

The QUIC substrate for M8. Third-party code, vendored, patched, and pinned.

| | |
|---|---|
| Upstream | `endel/quic-zig` |
| Commit | `14b9dc3e5e8429d07e7ed18619c7b4f4baaa3719` |
| Version | `0.5.0` (`build.zig.zon:3`) — the repository publishes no tags, so a commit SHA is the only pin available |
| Licence | MIT — `LICENSE`, byte-identical to upstream's |
| `minimum_zig_version` | `0.16.0` (upstream `build.zig.zon:13`) |
| Initial vendoring | 32 of upstream's 74 `.zig` files under `src/`: 29,776 lines upstream, 30,278 at the initial cut |
| Written at the initial cut | `src/test_all.zig` — upstream's test root, rebuilt (43 lines) |
| Not vendored | 42 files, 35,388 lines — see below |
| Initial patch | 14 files, +2,749 / −2,247; 1 file deleted outright |
| Last verified | 2026-10-05, parent-run |
| Current green, vendored core | `zig build quic-test` — 3/3 steps succeeded, 564/564 tests passed, exit 0, 75 s (`evidence/resume-w1-quic-test-after-pin-ruling.log`). **The digest that figure is anchored to by name is `tls13.zig` `sha256 02521578954ca75fe91391f75b9c56b98ec5c38190cef2e5d49f85599590ac60`, 7,933 lines.** §§14–16 are the receipts for how it got there: §14 ends at 560/564 with four named open, §15 takes the three `tls13` client-auth tests green and records the corrected `.optional` sub-case, §16 takes the `connection_manager` Retry regression green at `564/564` |
| Current green, first-party | `zig build test -Doptimize=Debug` and `-Doptimize=ReleaseSafe` — 28/28 steps, 790/790, exit 0 in both. **That is this project's own suite, not the vendored one** (§11) |
| Current interop binary | `59b6a3ef3e26978f0507ee66a10b030bd96feea62f37db194107c2db67864a08`, against Rust partner `748f0fca9dd2fa1b802b382e25f0eb2af6a12cd2ea7613b16ad9e7399ec80b65`. All seven §11 runs are receipts of that one build; older runs on older builds are kept beside them, not replaced. **Peer ids are keyed by role — LISTENER secret seed `0x11` is `d04ab232…`, DIALER secret seed `0x22` is `a09aa5f4…` — not by which implementation holds the role** |
| Still open, by name | **The full gate result against the current bytes is PENDING.** The required source lint fixes have landed and no gate group has been run over them; a pending gate is written here as pending, not as a failure, and the earlier red lint and static figures belong to older bytes. The zbc disposition ledger is **no longer** outstanding: it is re-merged at a fixed point at 32 source proofs and 59 records (`scripts/gate_zbc_dispositions.zig` `sha256 fb5f97f989ed8f11ba76d78a5c9e2c5fd780c94a78d9156aad682ae7f1ed4399`), byte-idempotent on re-emission, helper suffix preserved, dead relay-serve row retired. Nothing else here is written as closed |

Fetched 2026-09-30 with `gh api` against the pinned SHA. No clone is kept in this
repository; `docs/PLAN.md` and `README.md` point at read-only checkouts under
`~/projects` that do not exist on this node, so every byte here was captured
from GitHub primary source and pinned.

The initial-cut counts and cost measurements below are historical measurements
against the pinned commit, not current-tree statistics after later portability
patches. A bare `:NNN` names the **upstream** file the section is about. A
`file:line` names a site in this fork, and the ones in §§1, 2, 6, 10 and 11 were
re-read against this tree on 2026-10-04 rather than carried over: a later patch
still moves them, so treat one as a claim to check rather than a constant.

**Names are quoted, not normalised.** This directory is upstream code carrying
upstream's naming, and it is excluded from `zig fmt`, `ast-check`, `zlint` and
`zbc` on purpose (see "Not gated on purpose" below). So the identifiers written
here are the real camelCase ones — `serverBuildEncryptedExtensions`,
`writeCertificateTypeOffer`, `clientCertificateIsRaw`, `lifted_key_algo` — and no
reader should "fix" them to snake_case: that would be a vendoring patch this
fork does not carry.

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
is a protocol ozai does not implement — `docs/PLAN.md:538` says so. **This file
previously cited `:352` for that, which is the holepunch gate and does not say
it.**

The TLS-over-TCP stack is the one of these exclusions that has a bill attached,
and the reason for the exclusion is narrower than "it owns a socket". Wave 2's
relay carrier is RFC 6455 binary messages over an HTTP upgrade with TLS
(`docs/PLAN.md:464`, slice A), so it needs a server that drives a handshake, and
none was left behind. **The TLS-over-TCP stack does not own a socket.** At the
pinned `14b9dc3e`, `src/tls/common.zig:1-3` calls itself "Record layer, key
schedule and wire helpers shared by the sans-IO TLS 1.3 `tls_server` and
`tls_client`", and `src/tls/server.zig:1-8` says "Sans-IO TLS 1.3 server
connection (RFC 8446) for TLS over TCP. `Conn` never touches a socket: the
caller feeds it the ciphertext it read, flushes `pendingOutput()` to the peer,
and moves plaintext with `read` / `write`". **The socket-owning exclusions are
the five files in the table above; these are not among them.**

What these files do reach for is ambient, and through one import.
`src/tls/server.zig:37` takes `const sys = @import("../sys.zig");`, and its
production calls into it are randomness and a clock: `sys.randomBytes` at
`:694`, `:862`, `:981`, `:993` and `:1150`, and `sys.realtimeSeconds` at
`:766`, `:867` and `:910`, with further calls in the file's own test blocks.
No `sys.socket`, `sys.bind`, `sys.listen` or `sys.accept` appears in the file.
Those two are the lift an eventual port has to do —
injected entropy and an injected clock, the same shape Wave 0 removed from this
fork's own randomness path — and that is port work, not socket work.
**`src/sys.zig` is gone from this module**, so the two calls have no seam to sit
on here even if the files were.

The exclusion therefore stands on its own terms: all 4,504 lines were left
behind with the protocol layers above, and the cost is that slice A writes that
server rather than reusing one. It is a price of the exclusion, not an oversight
to be undone later, and nothing in §11 or anywhere else here offers it back.
**No TLS-over-TCP server and no HTTPS server exists in this repository**; that
is the bill, not a gap somebody already paid.

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
now `buildCertificateRequest(buf)` (`tls13.zig:528`), `derHeader` (`:400`) went
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
`peer_node_id: ?[32]u8` (`tls13.zig:1890`) — 600 bytes of DER scratch replaced by
33 bytes of identity, on a struct upstream's own comment calls "~52 KB", so the
struct shrinks by well under a kilobyte and the stack frame barely notices.

**Added:**

- `liftEd25519Spki(der) -> [32]u8` (`tls13.zig:234`) — 44 bytes in, 32 out, by
  TLV walk. Fails only with `error.MalformedSubjectPublicKeyInfo` or
  `error.UnsupportedSubjectPublicKeyInfo`. The length is fixed at 44, so the
  length check is the whole bounds check.
- `lifted_key_algo` (`tls13.zig:270`) — one `const` of type
  `Certificate.AlgorithmCategory` set to `.curveEd25519` **by construction**.
  This is what makes `verifyCertificateVerifySignature`'s `.ed25519` arm
  reachable: that arm demanded `pub_key_algo == .curveEd25519`, a tag only ever
  set by X.509 parsing, which is why it was dead for a raw SPKI. Supplying the
  tag lifted out of the certificate itself turned out to be a line rather than a
  patch.
- `TlsConfig.expect_peer_node_id: ?[32]u8` (`tls13.zig:1459`), compared with
  `crypto.timing_safe.eql` at `tls13.zig:2794`. Null accepts any key, and the
  doc comment above the field says plainly what that gives up.
- `ClientAuth.expect_node_id: ?[32]u8` (`tls13.zig:476`), the same comparison on
  the server at `tls13.zig:3529`.

Both CertificateVerify checks are now unconditional (`tls13.zig:2841` and
`:3561`), guarded by neither a flag nor a length. `cert_hashes` survives
deliberately: the WebTransport leaf-fingerprint bargain needs no chain either
(`tls13.zig:1461`).

`signCertificateVerify` no longer draws. Upstream read 32 bytes before it knew
which scheme it was signing with and handed them to the Ed25519 arm, which has
no nonce. `tls13.zig:6232` is a test that counts the draws and expects zero for
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
  `SessionTicket.isExpired(now_s)` (`tls13.zig:1074`) is a difference, never a
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

### 5. `FrameSorter.pop` hands the caller an allocation, and now says so

`FrameSorter.pop` returns a slice the caller owns. It is not
a view into the sorter: the chunk leaves `chunks`, the headroom a grown chunk
carries is shrunk away or copied out, and the result is a whole allocation. Once
it has been returned, `FrameSorter.deinit` cannot free it, because it walks
`chunks` and that chunk is no longer in it.

**Upstream had this and said nothing.** `pop`'s doc comment read "Returns null
if there's no data available at the current read position" and stopped there.
Every in-tree caller freed the result — `connection.zig:2404` and `:2443` both
`defer self.allocator.free(data)`, and so does every test that pops — but the
contract lived only in that convention. `ReceiveStream.read`, in the same file,
forwarded the same owning pointer under "Returns the data slice or null if no
data is available", and `CryptoStream.read`, in `crypto_stream.zig`, forwarded
it again under "Returns null if no complete data is available". A reader of any
of the three could reasonably conclude the slice is borrowed.

**This is inherited, not introduced.** `diff` against the pinned commit's
`src/quic/stream.zig` is empty at the three hunks' preimages: 3,767 lines, byte
for byte, before this patch. Upstream leaks the same way, and will again — the
signature is what invites it.

**The patch is +42 / −0 across three hunks, all additive**, and it is
documentation plus one test. No signature changed, no caller changed, and no
behaviour changed:

The three hunks below are quoted by the line numbers they occupied at this
patch; later patches moved all three. The declarations they name are
`FrameSorter.pop` and `ReceiveStream.read`, and the test is
`FrameSorter: what pop returns is the caller's, not the sorter's`.

- `stream.zig:359-365` — `pop`'s doc comment now states that the caller owns
  the result and must free it with `self.allocator`, and why `deinit` will not
  do it.
- `stream.zig:516-522` — `ReceiveStream.read` says the same and points at
  `FrameSorter.pop`.
- `stream.zig:1961-1991` — one test, `FrameSorter: what pop returns is the
  caller's, not the sorter's`, pinning both halves. It asserts the returned
  pointer equals the allocation `push` made (ownership moved, rather than a
  view handed back), that the chunk is gone from `chunks`, and it frees the
  result — so the leak checker is what enforces the second half. 457 tests
  now, from 456.

`CryptoStream.read` now publishes the same ownership transfer and null residue.
The caller frees a returned chunk with the stream's allocator. A refused
copy-out allocation leaves the bytes pending; null alone does not establish EOF.
This closes the documentation gap recorded by the earlier leak audit.

**The leak this was found through, and where it is fixed.** ozai's
`test/protocol_loopback_test.zig` leaked 23 `dupe` blocks across the two tests
that open streams — 20 in the gossip convergence test, 3 in the blobs EOF test.
The `std.testing.allocator` trace names the allocation site
unambiguously — `stream.zig:214`, inside `FrameSorter.push`'s append fast path,
reached from `Bridge.recv` through `recvDatagram` → `route` → `recv` →
processFrame → `recvStreamFrame` → `handleStreamFrame` → `push`, and every one
of the 23 carried that same stack — two distinct frames, `push` and
`handleStreamFrame`. Three probes against the vendored core decided the owner,
not an argument:

1. push, never pop, `deinit` — **no leak**. `FrameSorter.deinit` frees every
   chunk the sorter still holds, so the teardown the previous investigation
   checked is correct.
2. push, pop, free — **no leak**.
3. push, pop, no free — **one leak**, traced to `stream.zig:214`.

So the block left the sorter through `pop` and was never freed. Both leaking
call sites are in `test/protocol_loopback_test.zig` and both are the same shape:
`readStream` (`:1040`) and `BlobLink.drain` (`:1790`) iterate
`while (stream.recv.read()) |chunk|`, copy the bytes out, and never free
`chunk`. The fix belongs in those two loops and **not** in this directory —
patching the core to suit a caller that drops a documented owning pointer would
be the wrong trade. What this directory owed was the sentence that says so,
and that is what the patch above adds.

### 6. A pinned client identity and a resumable session ticket

`DECISIONS/0001` item 4 measured, on a throwaway copy, that lifting upstream's
two `client_auth == null` guards turns into a **silent authentication
bypass**: a server configured with `ClientAuth{ .expect_node_id = …,
.required }` completes a resumed handshake with `peer_cert == null` and
`peer_node_id == null` while its pin is in force. The record's stated reason —
that the ticket format is too small to carry a node id — is wrong. The
plaintext is `sealed_ticket_fixed_len` (45, `tls13.zig:1083`) plus at most
`negotiated_alpn_len_max` (32, `:915`) — 77 bytes at most — and the sealed form
`sealed_ticket_len` is 93 (`:1103`), all sized in this file. Growing them by 33
bytes is mechanical. The real block is that TLS has one client-identity
acquisition path and resumption skipped it.

**The decision.** Resumption and a pin are not mutually exclusive; what is
mutually exclusive is *a ticket as identity* and *a pin*. TLS 1.3 does not
currently send a CertificateRequest on a PSK handshake (RFC 8446 Appendix
E.3), and the combination that appendix calls unsafe is an **external** PSK,
which two endpoints may share and authenticate each other with. A PSK out of a
NewSessionTicket is the case it singles out as sound, because the binder makes
the client's signature cover the server's certificate transitively. So a pinned
client keeps its ticket and its resumption. What it loses is the right to be
authenticated **by** the ticket: a session ticket is bearer material —
replayable, and handed to the client in the clear — so a node id recovered from
one would be a credential rather than a proof of possession, and an iroh peer's
identity is possession of the private key. A resumed connection therefore
answers the CertificateRequest exactly as a full one does, and every connection
proves its certificate afresh. What the PSK removes is the server's own
Certificate and CertificateVerify, which is where the cost was.

**This is a recorded interop deviation, not a claim of conformance.** RFC 8446
describes no exchange in which a CertificateRequest follows a PSK, so a peer
that speaks it will read this flight as a protocol error. The tree's only PSKs
are its own tickets and its only peers are ozai, so the deviation has nothing
to break today; the `resumption` value is where a later decision to be strict
again would go.

`tls13.zig`:

| Line | Change | Why |
|---|---|---|
| `:3324` `serverBuildEncryptedExtensions` | routes to `server_send_certificate_request` on a policy in force, PSK or not, and only skips the server's own Certificate | the two `using_psk` sites disagreed, and the disagreement was the bypass. Which one is wrong is decided once, here. |
| `:3360` `serverBuildCertificateRequest` | skips to `server_send_finished` on a PSK instead of sending a Certificate the PSK already replaced | the other half of the same disagreement |
| `:3482` `serverTicketKey` | one accessor for the sealing key | the writer and the PSK reader have to agree on it |
| `:3497` `serverIdentityEstablished` / `:3504` `serverFinish` | both writers of `.connected` ask one predicate, and it refuses a policy in force with no identity | the invariant is structural rather than a flag; `serverProcessClientCertificate` stays the sole writer of `peer_node_id` |
| `:2442` dispatcher, `:2721` `clientProcessCertificate` | the resumed client reads a CertificateRequest and answers it, instead of skipping the state on `using_psk` | the client half of the same hole: skipping the state left the server waiting for a Certificate the client had been told not to send |
| `:3978` `peekHandshakeMsg` | `readHandshakeMsg` split into a peek and a take | the resumed client must know the next message is a Finished *before* it changes state, and `readHandshakeMsg` steps past it by the time it knows |
| `:1103` `sealed_ticket_len`, `:3736` | the sealed-ticket size named once, and the offered identity length bounded by it | `tryProcessPsk` copied `identity_len` bytes into two fixed buffers with only a lower bound; the length is attacker-chosen and reaches this from any ClientHello. The path is now also reachable under a client-auth policy, so the bound is part of this patch. |
| `:1115` `TicketKey`, `:1152` `Resumption`, `:1481` `TlsConfig.resumption` | `ticket_key: ?[16]u8` becomes one `Resumption` value, `union(enum) { server: TicketKey, client: *const SessionTicket }` | `DECISIONS/0001` item 1. A ticket and the key that opens it are one fact, and two fields let a caller name a ticket from one key and a key from another without either noticing. `TlsConfig.session_ticket` stays — `connection.zig:5627` reads it for 0-RTT remembered transport parameters, which cost a resumption its remembered limits and nothing else — and is no longer the handshake's resumption input (`tls13.zig:2070` reads `config.resumption` instead), so it cannot influence whether a handshake resumes. |

Four tests close it: a pinned client resuming across two connections against a
constant key with the pin still holding on the second; a rotated key refusing
the ticket rather than resuming; a resumed connection with a pin in force
failing `certificate_required` rather than completing with no identity; and a
server handed a ticket issuing none.

At that patch, the test count grew from 457 to 461.

**One defect found on the way and not fixed here.** A client that offers a
ticket the server declines cannot fall back, so the rotated-key test records a
refusal rather than a full handshake. Pre-existing, client-side, and written
up under "What is still not settled" below rather than here.

### 7. Cross-platform addresses and fixture indices

The complete ABI survey exposed two fixture loops that used a `u64` wire offset
as a native `for` index. The reordered receive-window test and the lossy-link
upload now enumerate native indices from zero and add them to the wide offset
when computing expected bytes. The 5,000-frame workload, 16 MiB upload,
6 MiB stream window, byte comparisons and virtual-time bounds are unchanged.

WASI also exposed a false dependency: this sans-IO core stored path addresses
as `std.posix.sockaddr.storage`, which is `void` on that target. The old
`sockaddr.zig` module is replaced by `address.zig`; no POSIX-shaped fallback or
compatibility export remains. `Address` is a pure tagged value with `unset`,
IPv4 and IPv6 states, host-order ports, and an IPv6 scope ID. `unset` remains
distinct from a wildcard address. Path equality includes port and scope;
same-IP comparison retains its existing port/scope-independent behavior.
Mapped IPv6 addresses remain distinct paths but count as IPv4 when choosing
a preferred-address family.

The core, preferred-address constructors, test roots, invariant inventory,
bridge, dialer and discovery error consumer all use that value. Kernel address
conversion stays in the actual socket seam. An unnamed bridge path reports
`NoPathAddress`, not an obsolete numeric-family error.

Retry and NEW_TOKEN previously bound only 14 raw kernel-layout bytes. On Linux
IPv6 that omitted the address tail: two addresses differing only in byte 15
validated the same token. Both rejection regressions failed before the change
and passed afterwards, with positive controls for the original IPv6 address.
Both formats now bind one canonical 23-byte stack value: family, big-endian
port, all address bytes and big-endian scope. These issuer-private tokens have
no legacy-format fallback. This is address-validation proof, not an iroh
interoperability claim.

The emulated upload also exposed quadratic work in the test link:
`orderedRemove(0)` moved every queued datagram on each receive: 1,520 bytes
per record on the measured 64-bit targets, since the record carries a native
`usize` length and its size is pointer-width dependent.
The FIFO now advances a head cursor, borrows the current record, and compacts
consumed records only on a later push. Clearing the queue inside the pop
poisoned the borrow that same pop had just returned, and all five upload tests
crashed under Debug. That is the whole defect: reclaim is now deferred until
the next push, which is where that borrow is documented to expire.

A fixed-input benchmark drained 5,000 records three times with byte and order
checks. Ordered removal moved 56,988,600,000 bytes; cursor removal moved none.
Observed durations: native 3.18 → 0.06 seconds; SPARC64 QEMU 94.97 → 0.85.
The complete, unchanged 16 MiB upload passed before and after the change:
native 4.54 → 2.00 seconds, SPARC64 524.25 → 174.77, and big-endian MIPS64
828.96 → 292.54. Other verification jobs were active; these are observed
durations, not isolated throughput ratios. No payload, stream window,
retirement count, byte comparison or virtual-time deadline was reduced.

**Two measurements, not one conclusion.** All five crashes were Debug failures
on this test link's consumer path, and the deferred-push fix is what the
corrected Debug path shows. That is not a release-build result. The separate
measured Safe limitation belongs to another target: under Hexagon/QEMU a
standard-library-only ReleaseSafe Ed25519 probe derives `e13b9579…` instead
of the captured `197f6b23…` public key for seed `[42; 32]`, and native
ReleaseSafe derives the captured key (`README.md`, cross-platform rows).
That mismatch is in emulated standard-library crypto, not in this queue,
and it is why no Safe fallback is offered for the rows that fail here.
Neither result stands in for the other: a Debug pass is not a Safe
result, and the Hexagon key result says nothing about the FIFO.

**The survey this section leans on is cross-platform, and it is not part of
this acceptance.** The one survey result recorded here — 18 executed, 20
build-only, 70 failed, exit 1 — describes the pre-address, pre-fixture tree.
It is a failed run, not a partial pass, and it is kept as the dated observation
it is rather than as a baseline to improve on. The corrected rerun over the
fixes named above has not been executed, so this file states no corrected row
counts and claims no cross-platform coverage from it. This acceptance is native,
and a native result says nothing about a row that only builds elsewhere.

### 8. Repairs to contracts the audit found, named by what each one stops

None of these is a protocol change. They are places where the core took a
decision it could not take back — consumed a frame, spent a packet number,
filled a buffer with a key it did not have — and where the API around it did
not say so before the caller had already paid.

**A refused read keeps the bytes (`src/quic/stream.zig`).** `FrameSorter.pop`
removed a chunk and then discovered it could not copy it, freed the
allocation and returned null: a run the peer had already been credited for,
and which it will never retransmit because from its side it was delivered. The
chunk goes back at the head of the list with its hole count undone, and the
list has the slot it just vacated, so the restore cannot fail. `peekLen` is the
new way to ask how much a read holds without taking it, which is what lets a
caller make room *before* the read rather than after it.

**`ReceiveStream.read` and `CryptoStream.read` say what a caller owns
(`src/quic/stream.zig`, `src/quic/crypto_stream.zig`).** The slice either
returns is an allocation the caller frees with the stream's allocator, and the
read position, `bytes_read` and the connection credit have all moved by the
time it is handed over.

**Version Negotiation packets have a length, and are recognised before one is
read (`src/quic/packet.zig`, `src/quic/connection.zig`,
`src/quic/connection_manager.zig`).** A VN header carries no Length field, so
`parse` left `remainder_len` undefined — and both datagram walkers stepped by
it before `recv` had decided to ignore the packet. The whole remainder of the
datagram is the packet, as it already was for Retry and 1-RTT, and a VN packet
now ends the walk instead of stepping by a length it never had.

**A server with no token key issues no NEW_TOKEN (`src/quic/connection.zig`).**
`token_key` defaulted to sixteen zero bytes, so a token sealed under it was
sealed under a key every reader of the wire has, and it outlived the connection
that issued it. The key is now optional and its absence means no token rather
than a predictable one.

**A refused construction frees what it built (`src/quic/connection.zig`).**
`acceptInto` initialises a connection and then allocates — the TLS handshake,
the resized datagram queues — with no `errdefer` between, so a failure after
the handshake leaked it. One `errdefer conn.deinit()` right after the literal
closes every path, because the literal initialises every member `deinit`
touches.

**A client's transport parameters borrow its own connection ids
(`src/quic/connection.zig`).** `connectInto` built them pointing at the stack
locals it drew the ids from, and then copied those ids into the connection —
so the parameters of a client's first Initial pointed at a dead frame. They
are bound to `conn.scid` after the copy instead. `acceptInto` also owns the
original-DCID and Retry-SCID bytes. The unsafe
by-value `accept` and `connect` wrappers are removed and all callers use the
in-place constructors. The constructed connection must retain its address.

**A close packet waits for a buffer that can hold it
(`src/quic/connection.zig`).** `sendAt` copied `close_pkt_len` bytes into
`out_buf` and cleared the retransmit trigger with no check that the buffer was
that long. A caller with a smaller buffer now gets zero and keeps the trigger.

**QUIC-LB states the combined length its fixed buffer assumes
(`src/quic/quic_lb.zig`).** `extractServerId` decodes into a 20-byte stack
buffer because the longest payload a connection id may carry is 19 bytes —
`server_id_len + nonce_len`, plus the first octet, and QUIC's own 20-byte
limit. The rule is now on `Config`, where the two lengths are written down,
with the per-field ranges marked as necessary and not sufficient. Nothing
validates it at runtime: a config is written once and packed on every packet,
so a check would buy a per-packet cost to catch a constant.

**`decryptPayload` cannot be out of memory (`src/quic/crypto.zig`).** It
declared `error.OutOfMemory` and could only ever produce
`error.AuthenticationFailed`; no allocation happens on that path. The set is
now what the code can return, so `packet.decrypt` propagates a smaller set as a
consequence, and `Connection.recv`'s bare `catch` can no longer swallow an
allocator error that was never there.

**The wrapper states what its room costs (`src/transport/quic_bridge.zig`).**
`Connection.sendAt` consumes what it packs, so `Conn.drain` asks the core for a
datagram only where it can finish the job: an empty `out`, a buffer under one
padded Initial, or a path with no address is refused with nothing built, and
room running out between datagrams is a short answer rather than a refusal, so
every datagram built is inside a run that is handed back. `Stream.drain` takes
the room in its caller's sink before the read that would hand over the bytes.
`Bridge.create` keeps `error.Canceled` apart from `error.EntropyUnavailable`,
because one is the caller's own cancellation and the other is an `std.Io` that
cannot key the bridge. And a peer pin now forces a certificate: the pin is
read out of the same block `require_peer_certificate` decides whether to ask
for, so a caller that named a peer and cleared that flag had its pin dropped.

**The module root states the four rules (`src/lib.zig`).** Time, randomness,
the allocator and ownership are parameters and per-declaration contracts, and
none of them was written down at the one place a consumer starts reading. Each
re-export now says what that module is and what it borrows.

**The API-contract repairs, as landed (`src/quic/transport_params.zig`,
`src/quic/tls13.zig`, `src/quic/connection.zig`, `src/quic/connection_manager.zig`,
`src/quic/ack_handler.zig`, `src/quic/congestion.zig`, `src/quic/packet.zig`,
`src/quic/packet_packer.zig`, `src/quic/rsa.zig`, `src/quic/stream.zig`).** One
more pass over the registered `quic` surface found the same class of defect
below, in the places where a length a peer declares, a room a caller offers or a
figure an arithmetic derivation reaches for was taken on trust. Each is closed
rather than described. `docs/DECISIONS/0004-vendored-core-contracts.md` is the
full record; the exercised counts, including the executed test count, live there
and are not restated here.

- **A peer's declared length is checked, not reinterpreted.**
  `TransportParams.decode` requires every known parameter to consume exactly its
  declared length, a preferred address to be `41 + cid_len` bytes with a
  connection id of 1..20, and a migration-disable flag to be empty. A
  ClientHello cipher-suite or compression list that does not fit its message, a
  ServerHello extension block or inner extension that runs past it, and a
  PKCS#8 structure whose lengths the walk cannot honour are refused where they
  used to index past the message — the first two are reachable by anyone who
  can send one CRYPTO frame.
- **A zero is not a version (`version_information`, parameter `0x11`).** A zero
  chosen version is a parsing failure and `decode` refuses it; a zero anywhere
  in the available list is refused too, including one behind the eighth entry
  the value keeps, so the whole declared list is checked on the way past rather
  than truncated unread. The membership of Chosen Version is recorded over that
  whole list, so the RFC 9368 §3 test is made against the list the peer sent and
  not against a retained prefix that may not hold the answer. That answer is one
  `bool` beside the decoded fields — `version_info_chosen_in_available` — rather
  than a second list and rather than an encoding of the retained one, so it costs
  no allocation whatever length the peer declared; the first eight entries are
  still what the array holds and what `hasAvailableVersion` reads. An empty
  available list is not a contradiction: RFC 9368 §3 lets a server send one.
- **Client-sent Version Information must name Chosen Version** (RFC 9368 §3).
  The rule is the client's, and a server's list may be empty, so the check no
  longer refuses a list RFC 9368 permits.
- **Peer delay arithmetic saturates instead of trapping.** An encoded ACK delay
  is capped at the peer's `max_ack_delay` before it is scaled, and an
  ACK_FREQUENCY delay or an ACK deadline beyond the signed duration limit
  saturates at that limit rather than shifting into a wrapped value.
- **The CUBIC curve stays inside its own types (`src/quic/congestion.zig`).**
  `k_ns` is the cube root of the epoch's `w_max` in MSS units times
  `ns_per_s`, and that cube root answers at most `cbrt(maxInt(u64))`, so the
  multiplication cannot overflow; `now - epoch_start - k_ns` is evaluated in
  `i128`, because two `i64` instants and a `k_ns` of either sign do not fit an
  `i64`. Inside the stated domain — `max_datagram_size` non-zero and small
  enough that `MAX_WINDOW_PACKETS * 17` times it fits a `u64`, `now` at or after
  `epoch_start` — the curve, `k_ns`, `w_est` and the growth an acknowledgement
  asks for are exact or saturating and none of them reaches past a type.
- **A zero-length RSA public exponent is `error.InvalidKey`**, not an index
  past the end of the integer.
- **A caller's buffer bounds what is packed, and it bounds the datagram rather
  than each packet in it.** `max_packet_size` is a whole-UDP-payload number —
  `Connection` writes it from the path MTU — and `packCoalesced` spends it once,
  as `min(max_packet_size, out_buf.len)`, offering every level what is left of
  that one budget instead of a copy of it each
  (`packet_packer.zig:198-221`, `:380-388`). An ack-eliciting Initial pads
  toward RFC 9000 §14.1's 1200; a budget that cannot reach it does not emit a
  shorter packet but refuses the flight whole, before a packet number is taken
  and before a frame leaves its queue (`:416-426`, `:548-555`). The Handshake
  level shares that floor when it has CRYPTO data or a CONNECTION_CLOSE is
  queued, and the room that level needs is held back from the Initial so the
  padding has somewhere to land around it: an Initial that spent the whole floor
  alone would defer that closing flight on every pass, and a deferral that
  repeats forever is not a close that goes out later (`:392-428`). Later levels
  are held only while the datagram is short of the floor **and** an Initial is
  still owed, so a later flight cannot overtake an Initial the budget refused.
  Initial data still queued at a budget that reaches the floor holds nothing
  (`:445-454`). One pass is not a promise to drain: a level writes what fits the
  room it was offered and the rest stays queued. An oversized Retry token spends
  no packet number and consumes no queued frames however large the caller's
  buffer is, and `PacketPacker.init` no longer takes an allocator it never used.
- **A datagram that cannot be assembled closes the connection, and the peer
  hears the first close (`src/quic/connection.zig`).** `packSinglePacket`
  documents both of its errors as losing the frames the pass had already taken,
  so a bare propagation would leave an open connection believing it sent a
  flight it swallowed. Four call paths run it and each closes with a transport
  `internal_error` first. A connection already closing, draining or terminated
  keeps the close it has, so the new one is not sent over the old one.
- **A Retry this connection cannot act on is refused whole
  (`src/quic/connection.zig`).** Three shapes are turned away before anything
  moves: a token longer than the buffer tokens are kept in, no token at all,
  and a token that is present and zero bytes long — the one shape the parser
  does not produce but a `Header` can hold. Any of them would leave the next
  Initial carrying the token it already had while every later Retry was turned
  away, so one such packet costs the handshake its address validation for good.
- **A refused allocation consumes only committed state.** `openBidiStream` and
  `openUniStream` free the stream they created and burn no stream id; a
  peer-initiated stream that cannot be created leaves the creation watermark at
  the last stream that exists, so a retry resumes rather than replaces; a
  bidirectional stream the peer reset is reclaimed once its send side has
  settled and never while pinned; and packet tracking hands back a
  `SentPacketList` whose room the caller reserves before anything is removed,
  so a refused reservation leaves every tracked packet available for retry.
- **A ticket is sized once and says what it is.** The sealed plaintext is
  `psk(32) || creation_time(8) || quic_version(4) || alpn_len(1)` — a fixed
  45 bytes — followed by the protocol name and a 16-byte tag, so a sealed
  ticket runs to 93 and both ends are given the one number. The recorded
  protocol is bounded by what a selection can hold, so
  `negotiated_alpn_len_max` is 32 and not RFC 7301's 255: RFC 8446 needs the
  whole name to compare two connections by it, and the handshake's own
  selection is the same width (`tls13.zig:774`, `:885`, `:1783`). What that
  costs is storage rather than code: 32 bytes of selection per handshake and
  32 in every `SessionTicket`, 16 bytes more than the 16-byte record it
  replaced, and a `Connection` retains two of those tickets — the one the peer
  issued and the remembered transport parameters (`connection.zig:1339`, `:1343`)
  — so 32 added bytes per connection before whatever the struct's padding does
  with them. A server refuses to select a name it cannot record rather than
  recording a prefix of it as if the prefix were the protocol, and the client's
  first flight is built into a bounded 4 KiB staging buffer
  (`tls13.zig:2347`), so a proposal list that will not encode whole fails that
  `step` with the `error.InternalError` the constructor already reports, before
  a byte is written — nothing is trimmed, because a peer cannot tell a short
  ClientHello from a whole one.
- **The protocol a ticket records is enforced in both directions.** Both writers
  copy the connection's selection verbatim and keep `alpn_len` at or below
  `alpn.len`, so a ticket names a whole protocol or none. A client offers a
  ticket only while its own proposal still holds that protocol
  (`resumableTicket`, `tls13.zig:1882-1887`), and a server that opens the ticket
  compares the sealed name against the protocol it just selected and accepts no
  early data when the two differ (`tls13.zig:3498-3567`). A zero-length name is
  a ticket from a connection that negotiated no protocol, which matches a
  proposal of no protocols and nothing else.
- **A ticket's version is compared against the first flight, not the negotiated
  one.** A ticket records the version the *issuing* connection negotiated, and
  a resuming client compares it with `original_version`: the version its own
  first flight was built with, copied at construction and never changed. A
  mismatch is not a failure — the client resumes nothing, offers no PSK, no
  `early_data` extension and no 0-RTT, and the server authenticates it the
  ordinary way, so the handshake is an ordinary one. Compatible version
  negotiation may still move `config.quic_version` to the negotiated version
  afterwards; the 0-RTT keys and the long headers keep the first-flight version
  regardless (RFC 9369 §4.1), and a new ticket is written in the negotiated
  version (RFC 9369 §5). `transport_params.encode_len_max` is a derived 324-byte
  bound for legal local values — a programmer precondition, not a writer error.

**The same pass closed the contracts on this side of the seam
(`src/transport/socket.zig`, `src/node/node_framing.zig` with its two walks in
`src/node/node_relay_serve.zig` and `src/node/node_relay_client.zig`, and
`src/gossip/hyparview.zig`).** They are named here because they are the other
half of the repairs above, and a reader auditing this file should not have to
look twice for either half. **An earlier version of this line named
`src/node/node.zig` for the frame walk, and that was stale from the cutover:**
the framing code moved out, and `node.zig` is now 136 lines of data owner.
Follow `node_framing.zig`, not `node.zig`.

- **Every datagram a batch sends reaches the wire once
  (`src/transport/socket.zig`).** A run refused for segmentation lowers the
  socket's capability for good and is answered by sending the runs behind it,
  one datagram per `sendmsg`; the runs before it are already on the wire and
  are not sent again. A refused segmentation is not a refusal of the codepoint, so
  the retried tail keeps it; a tail that loses the codepoint to its own retry
  is reported as lost *together with* the degradation, which is two facts and
  not one — a datagram carrying no codepoint is not a missing datagram, and
  nothing downstream can get either one back.
- **A frame walk compacts the inbox once (`src/node/node_framing.zig`, walked by
  `src/node/node_relay_serve.zig` and `src/node/node_relay_client.zig`).**
  `peekFrame` (`node_framing.zig:36`) copies the frame into caller-owned scratch,
  because its variable-length payloads borrow the bytes they were decoded from
  and taking a message off the inbox's front moves everything behind it — a
  borrow into a buffer compacted under it is a borrow of nothing. It hands back
  an end offset instead of shrinking the inbox per message, and `dropInbox`
  (`node_framing.zig:50`) moves what is left exactly once: on the way out of the
  walk and on the fault that ends it alike, because the two are one decision
  taken twice rather than two decisions. Both walks keep that pairing —
  `node_relay_serve.zig:181-188` and `node_relay_client.zig:37-44`.

- **The gossip shuffle timer is published before it is latched
  (`src/gossip/hyparview.zig`).** A latch set first is a claim that a timer
  exists which the caller never received: an allocator refusing that one append
  would leave the node believing it had a shuffle scheduled, and no shuffle
  would ever happen again. The tail of `handle` queues the timer and only then
  sets the latch; `handleShuffleTimer` releases the latch before its fallible
  work, so that tail re-arms on any later turn. Neither half alone would do.
- **A quit tells a peer before it forgets it (`src/gossip/hyparview.zig`).** At
  every refusal the peer being told is still in the active view and `left` is
  not yet set, so a retry gets the same peer again. A peer taken out of the view
  before its `Disconnect` was published is one no retry can reach — the other
  side keeps a neighbour belief nothing will correct. What a refusal does leave
  is a published prefix: a duplicate node list, which is the price of not
  dropping the peer.

### 9. A PADDING frame that reports itself as zero octets wide

`src/quic/frame.zig` `parseSized`, the `0x00` arm.

`paddingLen(bytes)` counts the run of zero bytes from offset zero, but §16
lets a frame type occupy more than one octet, so `80 00 00 00` is a PADDING
frame four octets wide — the type code plus the zeros behind it — and the run
it finds at offset zero is empty. `parseSized` then wrote that empty run back
over the `stream.seek` that `readVarInt` had just advanced, so a **successful**
call returned `size = 0` against its own documentation that a successful
`size` names the next frame.

The callers trusted it. `connection.zig` walks a coalesced packet by
subtracting each frame's width from the remainder, with no zero guard, and
only pre-skips a leading `0x00` run. A packet whose payload began `40 00` —
PADDING is permitted between any two frames, §19.1 — therefore advanced by
zero and re-read the same type code forever, on an authenticated connection.
The vendored `quic_wire` fuzz corpus reproduces it with `80 00 00 00 01 00 00`
and `80 00 00 00 00 00 00`.

The fix counts from the end of the type code: `stream.seek + paddingLen(bytes[stream.seek..])`.
No other behaviour moves, and the returned length is now the frame's real width.

### 10. RFC 7250: the certificate type is negotiated, not assumed

Section 1 removed the X.509 walk and made a bare 44-byte `SubjectPublicKeyInfo`
a valid peer certificate in both directions. That left the *identity* model
right and the *wire contract* wrong: nothing on the wire said the `Certificate`
payload was a `SubjectPublicKeyInfo` rather than an X.509 certificate, so a
real iroh peer — which is built on rustls, and which does negotiate it — had no
way to learn that this stack could read one, and a TLS 1.3 implementation that
checked the type would read the 44 bytes as a certificate it could not parse.
Upstream never negotiated it either; this is not a fork that dropped a
feature, it is the upstream gap.

**What was added.** `CertificateType` (RFC 7250 §3's enum, the IANA "TLS
Certificate Types" values), two payload codecs and two parsers — the
`CertificateType certificate_types<1..2^8-1>` a ClientHello offers, and the
bare `CertificateType` a server's answer selects — and the two writers that
put them in each message.

| Message | Extension | Body | Written by |
|---|---|---|---|
| ClientHello | `client_certificate_type` (19) | `01 02` — a one-entry list naming RawPublicKey | `writeCertificateTypeOffer` |
| ClientHello | `server_certificate_type` (20) | `01 02` | `writeCertificateTypeOffer` |
| EncryptedExtensions | `server_certificate_type` (20) | `02` — one bare value | `writeCertificateTypeSelection` |
| EncryptedExtensions | `client_certificate_type` (19) | `02`, **only** where a CertificateRequest follows | `writeCertificateTypeSelection` |

**Fail-closed, in both directions, and the four refusals are tellable from one
another.** A peer that is required to speak raw public keys and does not is
refused rather than believed:

| Bytes | Refusal | Alert | Where | Why |
|---|---|---|---|---|
| The offer is absent | `MissingExtension` | `missing_extension` | `tls13.zig:3269` (ClientHello walk; the same check recurs at `:2722-2733`, `:3287`, `:3307` for other required extensions) | §4.1: an absent extension is an implicit **X.509**, and this stack has no X.509 verifier to fall back to. An absent offer is a downgrade to a certificate it cannot read. |
| The offer is there and names nothing in common | `UnsupportedCertificate` | `unsupported_certificate` | `tls13.zig:3240`, `:3251` | §4.2's outcome 2, asked of `offerContains` against the IANA registry — once for the client-offered type, once for the server-offered one. |
| The server's selection is not one the client offered | `IllegalParameter` | `illegal_parameter` | `tls13.zig:4142`, `:4148` | §4.2. |
| A second copy of either extension | `IllegalParameter` | `illegal_parameter` | `tls13.zig:3230`, `:3244` (ClientHello walk; the EncryptedExtensions walk repeats the guard at `:4134`, `:4145`) | RFC 8446 §4.2's one-copy rule, which is what stops a first offer being followed by one that says something else. |

The alert half of each is one table in `connection.zig:3185-3200`; nothing in
`tls13.zig` names an alert. **An earlier version of this file recorded the
second row as `HandshakeFailure` / `handshake_failure` and carried a deviation
to match. Both were wrong.** The tree is `x509 = 0, open_pgp_cert = 1,
raw_public_key = 2, generic_cert = 3` (`tls13.zig:288-298`) and that row is
answered against it, so RFC 7250's own alert goes out and there is no
deviation left to record.

The client's own `Certificate` is gated on the same negotiation rather than on
RFC 8446's CertificateRequest alone: `clientCertificateIsRaw` is false when
EncryptedExtensions named no `client_certificate_type`, and the answer to a
CertificateRequest this client cannot meet in the server's own terms is the
*empty* `certificate_list` §4.4.2 defines. A server that required a
certificate says so itself, with `certificate_required`. That is the whole of
the fix for the failure mode this guards: a client sending a bare
`SubjectPublicKeyInfo` under a selection that said X.509.

`clientCertificateIsRaw` is a file-scope function taking
`*const Tls13Handshake`, not a method on the type. It was first written as a
`pub fn` *inside* the `Tls13Handshake` container, sitting between the
`negotiated_client_certificate_type` and `transcript_at_server_finished`
fields. That does not parse — Zig rejects a declaration placed between
container fields — and `src/quic/tls13.zig` did not compile. It now sits
immediately after the struct closes, and its one call site, in
`clientSendFinished`, reads `clientCertificateIsRaw(self)`. The name, the
answer it gives and the field it reads are unchanged; only the placement is,
and no other `tls13.zig` site was touched.

**The `Certificate` payload is unchanged, and that is the point.** RFC 7250
reuses TLS 1.3's `CertificateEntry`: `cert_data` carries the
`SubjectPublicKeyInfo` DER and nothing else. `buildCertificate` already wrote
`cert_chain_der` verbatim, so no builder moved. What changed is that the
handshake now *negotiates* the thing the payload has always been, and
`clientProcessCertificate` reads the leaf as a `SubjectPublicKeyInfo` only
because `clientProcessEncryptedExtensions` has already refused any selection
under which it would not be.

**Deviations, named.**

1. **`client_certificate_type` is omitted from EncryptedExtensions where RFC
   7250 §4.2 requires it to be.** §4.2 says a server that does not ask for a
   client certificate MUST omit it, and a server here never presents a type it
   is not asking for. ozai authenticates both ends, so the extension is on the
   wire for every mutual-authentication connection — which is every connection
   this project makes. The condition and the message it belongs to are one
   value (`request_client_certificate`), so the extension and the
   CertificateRequest cannot disagree.
2. **Both offers are mandatory, not merely supported.** §4.1 lets a client
   offer what it has and a server answer with X.509 for the rest. This stack
   has exactly one certificate type, so a client that does not offer it has
   nothing in common with this server and the session ends there rather than
   after a certificate neither end can read.

**What is proved, and what is not.** `test/tls_wire/hello.zig` and
`test/tls_wire/messages.zig` carry the vectors, driven by `test/tls_fuzz.zig`:
the two extensions on the wire in both messages, each refused four ways above,
plus wrong-peer and wrong-ALPN rejection read off the same seam. **A live Rust
exchange ran against an unpatched baseline and failed in both directions**; §11
carries the captured bytes and both receipts, and that is the failure this patch
answers.

**The patched tree has since spoken to a peer, in both roles.** Both native
receipts in §11 — the ozai listener and the ozai dialer against the locked Rust
partner — exit 0 on both ends and carry all six declared payload proofs. That is
the evidence the earlier version of this paragraph said did not exist. One
captured vector is in the tree now, and it is captured rather than authored:
`test/corpus/rust_wire/rust_client_initial.hex` is the Rust client's first
Initial, 1,200 bytes on the wire, `sha256
473b53b1926dce2f9841718684b76792059ab02ba2fd7770f6b53e7315876f7d`, taken from
`evidence/capture-w1-native-listener-after-role-predicate-fix/datagrams/000000-peer-inbound.bin`.
It is one datagram of one flight, **and it authenticates.** A probe through the
vendored core's own derivation —
`packet.parseQuicHeader`, then `PacketNumSpace.setupInitial(dcid, version,
true)`, then `packet.decrypt` — exits 0 with `VERDICT opened, plaintext 1145
bytes / frames=2 crypto_frames=1 first_crypto_offset=0`
(`evidence/w1-probe-captured-rust-initial-authenticity.log`). So this is a
genuine external Initial: its payload opens under the RFC 9001 §5.2 keys
derived from its own connection id, and its first CRYPTO frame begins at offset
0, where a ClientHello begins.

**And the current binary has since repeated both orders, with the Retry run and
the four typed refusals on that same build** — §11's seven-row table is the one
to read for currency, and the two receipts this paragraph names are kept as the
first time the patched tree spoke to the partner at all.

**One methodological note, not a hedge on the bytes.** That verdict comes from
this core's own `decrypt`, not from an independent reimplementation of RFC 9001
— which is the point: an earlier reviewer reported the opposite after a
hand-rolled brute force whose associated-data handling had drifted from the
core's, and a reimplementation that disagrees is evidence about the
reimplementation. The bytes are real and they open. **No other vector here is a
captured one**: the RFC 7250 shapes are still written from RFC 7250 §3 and §4
against a peer this repository produced itself.

**What the capture does not give, stated plainly.** One datagram is Initial, so
the connection-id-derived Initial keys of RFC 9001 §5.2 read it and nothing
else in the flight is readable from it: a Handshake or 1-RTT datagram needs the
handshake secret, which is in neither this file nor this tree. The `keys` column
of `wire.manifest` is **not** that secret — it names which connection id the
current value is, so a reader knows whether the header's DCID is the client's
first Initial DCID or a Retry's source id. There is no keylog in this tree and
none is written: `TlsConfig.keylog_file` and `hexByte`/`writeKeylogLine` were
deleted with the X.509 walk (§1) and nothing replaced them.

### 11. Wave 1: the vendor patches, and what each still owes

All six are against the pinned commit `14b9dc3e5e8429d07e7ed18619c7b4f4baaa3719`.
This fork has not been rebased, so the `file:line` in every section above is
this tree's and the base is the SHA in the header table.

| Patch | Base | State | Test anchors | Wire deviation |
|---|---|---|---|---|
| RFC 7250 certificate-type negotiation (§10) | `14b9dc3e` | landed; **the baseline it repairs failed on the wire in both directions, and the patched tree has since completed a handshake and all six payloads with the real iroh partner in both roles** — §11's mixed-peer receipts | `test/tls_wire/hello.zig:1059` `both ends put both certificate-type extensions on the wire`, `:1124` `without the offers refused`, `:1153` `X.509 offer refused`, `:1205`/`1229` selection refusals; `messages.zig:333` `certificateTypeShapes` and `emittedCertificateTypes`; both reached from `test/tls_fuzz.zig` | two, in §10 |
| In-place handshake initializers apply no struct defaults | `14b9dc3e` | landed; **observed green** | `test/tls_wire/hello.zig:1162` | none — it is a store of a length, not a byte on the wire |
| RFC 7301 §3.2 — a server that supports none of what a client advertised must still refuse | `14b9dc3e` | **landed; the exemption is gone; 9 of 9 in the TLS parent, and the refusal has been seen on the wire as `0x178` between Zig peers and as alert 120 from the real iroh partner, in both roles** | `test/tls_wire/hello.zig:1105` and `:1162`; the Zig/Zig wire receipt is `test/runtime_handlers_test.zig:830-831` | none — it sends RFC 7301's own alert |
| RFC 7301 §3.2 — the server's own preference decides where the two lists disagree, not the client's | `14b9dc3e` | **landed; the two walks are swapped, and the vendored expectation was rewritten in the same pass, so no red was ever witnessed against the old order** — the block below | `vendor/quic/src/quic/tls13.zig:5211` `loopback handshake: the server answers with the one ALPN it chose`: server list `:5222`, client list `:5227`, expectations `:5234-5235`, reached from `src/test_all.zig` through `lib.zig:78`. **No project-tier vector disagrees** — `test/tls_wire/hello.zig:106` offers the single name `ozai` to both ends, and every peer in `test/runtime_handlers_test.zig` and `test/relay_wire_test.zig` advertises exactly one protocol | **a handshake whose client and server rank a shared protocol differently now settles on the SERVER's configured order, where the base settled on the CLIENT's advertised order.** The client's list is walked for membership only; the wire format is unchanged |
| The packer charged the AEAD tag twice against the DATAGRAM budget (§12) | `14b9dc3e` | **landed; red and green both observed** — `w1-vendor-datagram-advertised-budget-red-direct.log` exits 1 at `packet_packer.zig:2819`, `...-green.log` exits 0 with `All 2 tests passed` | `PacketPacker: a DATAGRAM at the advertised payload budget crosses the wire`, `packet_packer.zig:2750`, reached through `src/test_all.zig` | none — it is local budget accounting; no byte on the wire changes format |
| A per-attempt admission hook, consulted before a connection exists | `14b9dc3e` | **landed; `zig build quic-test` is 560/560 against these bytes** — `evidence/w1-quic-test-after-admission-hook.log`, `Build Summary: 3/3 steps succeeded; 560/560 tests passed`, exit 0. Three regressions cover it; **read the count caveat below before taking 560 as their attestation** | `src/quic/connection_manager.zig:1513` `an admission verdict reaches the peer: Retry before the connection, a token once it is proved`, `:1566` `a Retry asked for on a flow that already proved its address is refused, not sent twice`, and `:1612` `no admission hook accepts every attempt, exactly as before it existed`; wired by `src/test_all.zig:16`, and `lib.zig:54` exports the module for the sweep at `test_all.zig:7-10` | none — the Retry it writes is the packet `require_retry` and `retry_threshold` already wrote, now through the one `sendRetry`, and `Admission.id` never leaves the process |

None of the six disturbs the seams this directory is gated on. The
negotiation is encode/parse over a `CertificateType` plus a byte compare, the
initialization fix stores one length, the ALPN guard is a condition on values
already inside `self`, the ALPN order swap re-nests two walks over bytes already
inside `self` and writes the same slice it wrote before, the budget fix subtracts
a constant that was counted twice, and the admission hook reads values already
inside `self` and calls the caller back; none adds an allocation, a clock read,
or a stored generator. The
one field of its own is `ConnectionManager.admission`: null until a caller sets
it, holding a pointer the caller owns and that is never dereferenced here. All
are reached the way the invariant file already reaches them —
`initServerInto`, `initClientInto`, `provideData`, `step`, `packSinglePacket`,
`recvDatagram`, a seeded `std.Random` and one frozen instant — so a run is still
a function of its input and its seed.
Two repairs on the caller side of the seam — a preferred-address oracle that
read past what it had proved, and one canonical ALPN bound — are in §13. Neither
is a vendor patch and neither is in the table above.

**The selection order, and which list decides.** A second RFC 7301 §3.2 patch, and
the only row in the table above that changes **which protocol a successful
handshake settles on** rather than whether the handshake completes at all. The
walk that picks one name out of the two lists had its loops swapped: the outer
walk is now `self.config.alpn` (`tls13.zig:3139`) — this server's own configured
preference order — and the inner one walks the client's advertised list
(`:3156-3167`), taking the first of ours the peer also named and leaving both
with `break :selection` (`:3166`). The write is unchanged (`:3163-3164` still
copies the matched name whole into `selected_alpn`), and so is the refusal below
it (`:3178`), which reads the same `matched` flag either way.

**The base walked the other way round, and these are upstream's own lines.** At
`14b9dc3e` the outer walk is the peer's: `while (alpn_pos < 2 + list_len and
alpn_pos + 1 <= elen)` at upstream `tls13.zig:2129`, with
`for (self.config.alpn) |our_proto|` inside it at `:2134`, under upstream's
comment "Parse client's ALPN list and try to match with our configured ALPNs"
(`:2124`). Upstream's test said the same in as many words — `// The client's
order wins; both sides must agree on it.` at `:3886`, asserting `moqt-17` at
`:3887-3888`. No clone of the pin is kept in this repository, so those are
upstream line numbers at that SHA and are labelled as such here rather than
quoted as if they were this tree's.

**So the direction is unambiguous: the server's order wins now.** A client
offering `["moqt-17", "moqt-18"]` against a server configured `["moqt-18",
"moqt-17"]` settles on **`moqt-18`**; at the base the same two lists settled on
`moqt-17`. A reader who takes this row the other way round will build a client
that expects its own preference to survive, and that is the whole cost of getting
it backwards.

**The rationale is RFC 7301 §3.2's own sentence, not a preference of this
fork's.** "It is expected that a server will have a list of protocols that it
supports, in preference order, and will only select a protocol if the client
supports it. In that case, the server SHOULD select the most highly preferred
protocol that it supports and that is also advertised by the client." Where the
two lists disagree, the most highly preferred protocol *the server* supports and
the client also advertises is the server's own first of them. §4 says the same
thing about the design: "By placing ownership of protocol selection on the
server, ALPN facilitates scenarios in which certificate selection or connection
rerouting may be based on the negotiated protocol." The walk's own comment now
says this too (`tls13.zig:3101-3109`), and so does the field's
(`:1980-1982`: "Where more than one entry matches it is this side's first of
them, so the selection is this side's preference rather than the client's
order").

**What the swap did not touch.** The zero-length `ProtocolName` pre-pass above the
walk (`:3122-3137`) still refuses every offered entry before any matching
happens, and the comment at `:3141-3147` still says why the walk does not repeat
that check — the ordering invariant recorded further down this section. The
too-long entry skip (`:3154`), the `if (elen >= 2)` arm (`:3115`), the
`else return error.DecodeError` (`:3179`) and the `no_application_protocol`
refusal (`:3178`) are all exactly where the guard patch left them.

**The test anchor is the vendored expectation, rewritten in the same pass.**
`tls13.zig:5211`, `loopback handshake: the server answers with the one ALPN it
chose`: the two lists at `:5222` and `:5227` are the lists upstream used, the
comment now reads "This side's order decides where the lists disagree: the server
prefers moqt-18 to moqt-17, and both ends must agree on the one that won"
(`:5232-5233`), and both ends are asserted to **`moqt-18`** (`:5234-5235`).
**No red against the old order exists and none is manufactured** — the walk and
the expectation changed together, so the old expectation failing against the new
walk is arithmetic rather than a receipt. **No project-tier vector can see which
list won:** `test/tls_wire/hello.zig:106` offers the single name `ozai` to both
ends, and every peer built by `test/runtime_handlers_test.zig`'s `addPeer`
(`:691`, `:692`, `:754`, `:792`, `:808`, `:834`, `:859`, `:878`, `:967`) and by
`test/relay_wire_test.zig:1127-1134` advertises exactly one protocol, so this
vendored unit test is the only vector in the tree where the two orders disagree.

**And the receipts in this section predate it.** `tls13.zig` is now `sha256
2f6d8be4197d0d8f6cd4412c1db79b807b73115a545bcb6eabb5a37678510e9c`, 7,889 lines —
**not** `aee3cd4a…` / 7,890, which the companion digest table below still labels
"current". Every 560/560 and 13-of-13 figure quoted in this section was taken
against `aee3cd4a…`, so each of them describes bytes that do **not** contain this
swap. No run has been made against these bytes and this ledger runs no gate, so
the row above claims a landed hunk and a test that asserts the new outcome, not a
green.

**A later green exists, and this caveat is not narrowed by it.** `quic-test` ran
green again against the admission-hook bytes — **3/3 steps succeeded, 560/560
tests passed**, exit 0, `evidence/w1-quic-test-after-admission-hook.log`. **That
leg is named by what landed in it rather than by a `tls13.zig` digest**, so
this file cannot say which of the states in the companion table it covered, and
it therefore does not claim it covers this swap. The digest this file names for
a vendored green is `aee3cd4a…`, and `aee3cd4a…` is not these bytes.

**The wire deviation, stated once.** Where a client and a server rank a shared
protocol differently, the handshake now settles on the **server's** configured
order; at the base it settled on the **client's** advertised order. Where the two
lists name the same set — every configuration in this project, since a caller
offers what it serves — nothing changes and no expectation moves. Only a peer
advertising two or more protocols this server also serves, in a different order,
lands on a different name. The selection is still exactly one name echoed in
EncryptedExtensions (`tls13.zig:3381-3382`), so no byte's format, length or
position changes: what moves is which name fills it.

**The admission hook, and why it is a vendor patch.** `require_retry` and
`retry_threshold` answer about *the manager*. A caller that has to decide per
attempt had nowhere to put the answer, because a verdict reached after
`acceptConnection` has no connection left to refuse and no Initial left to
answer. `ConnectionManager.admission` (`:356`) is an optional `AdmissionHook`
(`:289-296`): a caller-owned `ptr` and a `decide` called on the `recvDatagram`
thread, at most once per attempt that would open a connection. `Admission`
(`:242-265`) is the question it is asked — the two addresses, the entry id the
attempt **would** carry if accepted (`:253`, `next_entry_id`; nothing is
reserved, so a verdict other than `accept` costs no id), and `validated`
(`:264`), whether the core already considers the address proved. That bit is
read *after* token validation (`:807-813`), so the hook is told what the core
already knows about the flow rather than handed the token to work out itself.

`AdmissionVerdict` (`:273-280`) is three answers and not a boolean, because the
endpoint layer already speaks that vocabulary: `accept` proceeds, `retry` puts a
Retry on the wire and commits nothing, `drop` sends nothing. The consult sits in
`route` at `:822-840`, between token validation and the first
`acceptConnection` (`:843`) — the only stretch in which a verdict can still be
answered on the wire. **`retry` on a flow that already proved its address is
refused rather than repeated**, because QUIC permits one Retry per flow
(RFC 9000 §17.2.5) and a proved path cannot be asked again. **That rule now
lives in `sendRetry` rather than at this call site, and §16 is where the change,
the regression it turns green and the receipt are recorded.**

**`sendRetry` is an extraction, which is where the nil wire deviation comes
from.** The body is upstream's, moved out of the `need_retry` arm (`:867-868`)
into one function (`:910-944`), so a Retry the hook asks for is the same packet,
sealed the same way, as one the manager-wide fields ask for. No new packet type,
no new frame, no changed format.

**What 560 does and does not attest, because the count did not move.** The
artifact reports 560/560 against these bytes, and it reported 560/560 against the
tree *before* these three tests entered it — `connection_manager.zig` carries 23
top-level `test` decls, three of which are the admission regressions, against a
total that stayed at 560. **So 560 is the whole artifact's figure and is not, on
its own, evidence that these three ran**; the same total was reported before
§12's packet-packer regression landed.
What this ledger can state is the wiring, which is checkable in the source: the
file is imported explicitly at `src/test_all.zig:16`, which that file's own
header names as the mechanism for a module the sweep does not reach, and
`lib.zig:54` exports it for the `refAllDecls` sweep at `test_all.zig:7-10`.
**A filtered direct `zig test` line naming each of the three has not been run and
is not claimed here** — §12 records the same trap, where a build-step filter is
inert and an unfiltered 560 is the number that comes back.

**What that caveat turned out to be worth: one of the three was red.** The
already-validated filter's regression (*a Retry asked for on a flow that already
proved its address is refused, not sent twice*) failed on exactly these bytes, and
the filtered line that would have said so had not been run. §16 records the cause,
the repair and `564/564` against the bytes as they now stand. **The 560/560 above
is therefore an attestation about the tree's other tests and not about this
behaviour.**

**The initialization fix, and why it is not cosmetic.** `initClientInto`
(`tls13.zig:2124`) and `initServerInto` (`:2239`) construct into storage the
caller owns and write every field by hand, so the struct's own defaults never
run — `selected_alpn_len: usize = 0` included. A handshake that had selected
nothing therefore read a length nothing had set and sliced `selected_alpn` with
it, which is a slice over 32 bytes of whatever the storage held. One store
each fixes it: `self.selected_alpn_len = 0` at `:2175` and `:2290`. The 32-byte
buffer itself is deliberately **not** zeroed; nothing reads past the length, and
zeroing it would be cost bought for nothing.

It is also the premise the ALPN work needed. RFC 7301 has two halves and they
were being measured together: a ClientHello that names no protocol must be
answered without one, and a server that offers none must refuse the one that
named one. The first was failing for this reason, not for a protocol reason,
so the red below could not be read as a finding about the guard until this fix
landed.

**The guard, and why it was a vendor patch.** RFC 7301 §3.2: "In the event
that the server supports no protocols that the client advertises, then the
server SHALL respond with a fatal no_application_protocol alert." An offer list
with nothing in it supports none, so that is the case, and the answer must not
be a completed handshake. The guard was
`if (!matched and self.config.alpn.len > 0)`, and that `and` exempted
precisely it: a server whose configured list was empty matched nothing, skipped
the refusal, and completed with no protocol selected.

It is now `if (!matched) return error.NoApplicationProtocol`
(`tls13.zig:3123`) — the exemption is dropped and the condition is the walk's
own result. Retiring a node's last configured protocol is what leaves an offer
list in that state, so the case is reachable from configuration and not only
from a hostile peer.

**What the guard deliberately does not reach.** The refusal sits inside
`if (elen >= 2)` (`tls13.zig:3090`), the arm that runs only when the ClientHello
carries an ALPN extension, so a hello carrying **no** extension is still
answered without one and selects nothing. That is not a second obligation left
open: RFC 7301 echoes what was offered, and a client that advertised nothing
has nothing to refuse. The present-offer case and the absent-extension case are
two different behaviours, and only the first changed. **Two halves, and both
are true at once:** the condition itself is unconditional — the walk's own
result, with no exemption left in it — and the only thing that decides is
whether the arm runs at all, which is the peer's answer to whether it advertised
anything.

On the wire that refusal is a TLS alert inside a transport close, not an
application code: `connection.zig:3201` builds `TransportError.cryptoError`
from `0x100 + tls_alert`, and `no_application_protocol` is alert 120, so the
connection closes at **0x178**. A peer reading `0x78` is reading an
application-space code this stack does not send for this.

**That is code, not a packet — and the packet has now been observed.** `0x178`
is what the mapping produces, and the runtime parent now carries it on a real
socket: `w1-runtime-handlers-three-real-refusals-accounted.log`, exit 0, 3 of 3
steps and 5 of 5 tests. Three `no_application_protocol` refusals and one
RECEIVED `CONNECTION_CLOSE` frame carrying `0x178`, between real `Socket` and
`Bridge` peers.

The assertions are in `test/runtime_handlers_test.zig`, in *"a protocol this
node never offered reaches no handler"* (`:809`). `:830-831` requires the close
to be **transport** — `!refused.application` — with `code == 0x100 + 120`, and the
peer's close is read off `conn.entry.conn.local_err` (`:478-479`) before timers
can reap it, so it is the code that went out rather than a local intention. The
retirement lane is a different shape, in *"retiring one protocol leaves the
other serving and the retired one unanswered"* (`:702`): `:745-746` requires an
**application** close with `code == 0`, and the last-lane peer must never
establish while the handler and turn counts hold (`:786-802`).

**What that receipt is, and what it is not.** It is Zig against Zig over real
sockets. It discharges the guard's runtime and wire obligation and it is not
interoperability. The mixed-peer leg below is the interoperability, and it is a
separate set of receipts: the Rust partner has its own alert for the same
refusal, and `test/corpus/rust_wire/` now carries one captured datagram — see
§10 for exactly what that capture does and does not give.

The two missed `Streams` signatures that once blocked this build are fixed.
That is history, not a current state.

**Observed, in the unfiltered `test/tls_wire/hello.zig` parent. Exit 0, 9 of 9.**
Run on the 0.16 toolchain as
`zig test --dep quic -Mroot=test/tls_wire/hello.zig -Mquic=vendor/quic/src/lib.zig`;
the log is `evidence/w1-full-tls-hello-after-driving-to-the-public-wait-verdict.log`.

The four failures an earlier run reported were **premise faults in the test
fixture, not in the stack**. `takeHandshakeKeys` stopped at the first action
that was not `install_keys`, and `_continue` is an action the caller is handed
rather than a loop of its own, so the walk ended one step early and fed the next
message an answer about keys instead of a verdict on that message. The fixture
now drives to the public end instead: `driveUntilWaiting`
(`hello.zig:629`) is bounded, consumes `install_keys` and `_continue`, returns
on `wait_for_data`, and refuses a `send_data` or `complete` as a walk that went
past the message under test. **No production EncryptedExtensions policy
changed**, and a fixture in this project's own test tree is not a vendor patch.

The wrong-peer vector lost an incidental assertion rather than gaining one. It
no longer compares the client's state after EncryptedExtensions — that was the
premise the fixture bug broke — and the claim it exists to make is the refusal,
which is still `error.BadCertificate` against a real foreign
`SubjectPublicKeyInfo` (`hello.zig:1216`, the refusal at `:1243`).

**History, kept as history — and two runs that are not one.** Before the guard,
a run of just the two RFC 7301 vectors exited 1 with one failure: the
present-offer refusal red, the absent-extension half green. That log is
`evidence/w1-empty-alpn-valid-premise-red.log`, and it is the red that motivated
this guard. Later, and separately, an unfiltered parent run exited 1 at **5 of
9** — three RFC 7250 raw-public-key vectors and both RFC 7301 ALPN vectors green,
four premise failures red — logged
`evidence/w1-full-tls-hello-after-empty-offer-root-fix.log`. Neither log
describes this tree's current state, and the two are not the same run.

**The mixed-peer leg has now run against the patched tree, in both roles.**
The earlier version of this paragraph said no real iroh peer had ever spoken to
this fork. That was true of the tree it was written against and is false of this
one. Two receipts, `evidence/w1-native-listener-after-role-predicate-fix.json`
and `evidence/w1-native-dialer-after-role-predicate-fix.json`, each against the
locked Rust partner
`748f0fca9dd2fa1b802b382e25f0eb2af6a12cd2ea7613b16ad9e7399ec80b65` and the
immutable current binary
`0b95f54121abc6eb1ce38d8699abf7a410ab3891f5d222c9b46de5e45f1c4e7d`:

| Role | Listener | Dialer | ALPN both agreed on | Payload proofs | Exit |
|---|---|---|---|---|---|
| ozai listens | `0b95f541…` / Rust | Rust / `0b95f541…` | `2f6f7a61692f77312d66697874757265` = `/ozai/w1-fixture` | 6 of 6: bidi 5 B each way, uni 4 B each way, DATAGRAM 4 B each way | 0 / 0 |
| ozai dials | Rust / `0b95f541…` | `0b95f541…` / Rust | same | 6 of 6 | 0 / 0 |

**Two different native binaries appear in this section, and the successful
exchange is not evidence about the build the refusals came from (nor the
reverse).** The both-role exchanges in the table above ran `0b95f541…`; the
four typed negatives and the Retry run that follow ran `764dbfd8…`. The
receipt-by-receipt table further down names which is which. This is the kind of
fact that quietly becomes a false claim if it is left implicit, so it is stated
here rather than only in the detail.

A third pairing follows below, on the current binary, and it is the one to read
for currency: on that build the exchange, the Retry and all four refusals were
observed together, which no earlier build managed.

Both ends authenticated the exact peer node ids they were given
(`d04ab232…` as `1111…`, `a09aa5f4…` as `2222…`), each run's stdout names every
`sent_*` and `verified_*` payload, and the ozai side reports `0 dropped, 0
foreign`, `0 degraded, 0 codepoints lost`. The captures are
`evidence/capture-w1-native-{listener,dialer}-after-role-predicate-fix/`, each
with a `wire.manifest` and its datagrams; §10 names the one datagram that is
in the tree as a vector.

**Two typed negatives, in both roles, against the same partner.** These are the
RFC 7250 and RFC 7301 refusals seen by an independent implementation rather
than by a fixture, and all four receipts record the partner's own alert:

| Case | native mode | This side | Partner | Receipt |
|---|---|---|---|---|
| wrong peer | listen | `error.BadCertificate` | `the cryptographic handshake failed: error 42` | `w1-live-sdk-listen-wrong-peer.json` |
| wrong peer | dial | `error.BadCertificate` | `error 42` | `w1-live-sdk-dial-wrong-peer.json` |
| ALPN mismatch | listen | `error.NoApplicationProtocol` | `error 120`, `CONNECTION_CLOSE error_code=0x178` | `w1-live-sdk-listen-alpn-mismatch.json` |
| ALPN mismatch | dial | `error.NoApplicationProtocol` | `error 120`, `error_code=0x178` | `w1-live-sdk-dial-alpn-mismatch.json` |

Every one exits 1 on both sides with `payload_proofs_complete: false` — a
refusal is a refusal, and a scenario that transferred anything would be a
different finding.

**Which build ran what, recorded from the receipts.** Seven runs, two digests.
Read this table rather than opening seven files; each row's digest is the
`binary_sha256` field for `install/bin/ozai-interop-peer` inside the receipt
named in that row.

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
Retry run ran `764dbfd8…`. **These are two distinct binaries, and neither is
claimed as the other**: the negative rows are not a statement about the build
the six payloads crossed on, and the six payloads are not a statement about the
build the refusals came from. The Rust partner
(`748f0fca9dd2fa1b802b382e25f0eb2af6a12cd2ea7613b16ad9e7399ec80b65`) is the same
fixture in all seven.

**And the current binary has now run all seven itself, which is the pairing to
take as currency.** On the freshly built
`59b6a3ef3e26978f0507ee66a10b030bd96feea62f37db194107c2db67864a08`, against the
same locked partner
`748f0fca9dd2fa1b802b382e25f0eb2af6a12cd2ea7613b16ad9e7399ec80b65`, every one of
the seven receipts records both digests in its own `binary_sha256`:

| Receipt | Case | native | This side | Partner | Exit |
|---|---|---|---|---|---|
| `resume-w1-live-listen-positive.json` | positive, native listens | listen | 6 of 6 payloads each way, ALPN `2f6f7a61…` = `/ozai/w1-fixture` | 6 of 6 | 0 / 0 |
| `resume-w1-live-dial-positive.json` | positive, native dials | dial | 6 of 6 each way, same ALPN | 6 of 6 | 0 / 0 |
| `resume-w1-live-listen-retry.json` | `--require-retry`, native listens | listen | 6 of 6, one Retry answered (`1 replies`) | 6 of 6 | 0 / 0 |
| `resume-w1-live-listen-wrong-peer.json` | wrong peer, native listens | listen | `error.BadCertificate` | `the cryptographic handshake failed: error 42` | 1 / 1 |
| `resume-w1-live-dial-wrong-peer.json` | wrong peer, native dials | dial | `error.BadCertificate` | `error 42` | 1 / 1 |
| `resume-w1-live-listen-alpn-mismatch.json` | ALPN mismatch, native listens | listen | `error.NoApplicationProtocol` | `error 120` | 1 / 1 |
| `resume-w1-live-dial-alpn-mismatch.json` | ALPN mismatch, native dials | dial | the peer's `CONNECTION_CLOSE error_code=0x178, frame_type=0x0`, reason `peer doesn't support any known protocol` | `error 120` | 1 / 1 |

The pairing immediately before this one, `70567c34…`, carried its own seven
receipts under the `w1-live-final-` names with the same figures. That row is
history for those bytes and is not a claim about `59b6a3ef…`.

Every positive receipt is `payload_proofs_complete: true` and every refusal is
`false` — a scenario that transferred anything inside a refusal run would be a
different finding. **The six payloads are bidi 5 B, uni 4 B and DATAGRAM 4 B,
each way**, each named by a `verified_*` line on both ends. The native listener
in the `--require-retry` run records `10 in, 10 out, 1 replies, 0 degraded, 0
codepoints lost` and `ingress: 9 processed, 0 dropped, 0 foreign`, and that one
reply is the Retry's own datagram — the run's declared condition and its
evidence are the same number.

**Peer identity is keyed by role, not by which implementation sits on which
side.** The listener is given `--secret-key 1111…11` and the dialer `--secret-key
2222…22` in all seven receipts, so LISTENER seed `0x11` is `d04ab232…` and
DIALER seed `0x22` is `a09aa5f4…` whichever binary holds the role; the native
peer listens in one receipt and dials in another. **A row that names a peer id
"the native one" is naming a role as though it were a build**, and the two older
tables above that do so are corrected by this one.

**One typed refusal above is proved by a supplement, and its raw receipt is
preserved.** `resume-w1-live-dial-alpn-mismatch.json` carries
`typed_no_application_protocol_observed: false`, because the throwaway checker
that wrote it demanded the literal Zig spelling `NoApplicationProtocol` in the
Rust partner's human-readable output, and that partner never prints a Zig
spelling. `resume-w1-live-dial-alpn-mismatch-interpretation.json` derives the
typed proof from the bytes the raw receipt already carries — the partner's
cryptographic handshake error **120** and this side's read of
`CONNECTION_CLOSE error_code=0x178` = `0x100 + 120` — names that receipt's own
SHA256 `87b7fa48621e1a67e07c07c6ccd500d2c09b72dbe76c72c15cfd4666c1f924fd` and
records `accepted: true`, with `payload_proofs_complete: false`. **No process
was rerun and the raw receipt was not edited.** Writing `error.NoApplicationProtocol`
as the partner's own observation would be a fixture's spelling, not a
measurement.

**Four native digests are on the table now, and none is the other.** A receipt
is evidence about the build in its own `binary_sha256`, so `0b95f541…`,
`764dbfd8…`, `70567c34…` and `59b6a3ef…` are four separate claims. The current
pairing is also, like the one before it, the first in which the positives, the
Retry and the four refusals are all one build's work: before either, the
exchange and the refusals had never been observed together, and that gap is
exactly what the `0b95f541…`/`764dbfd8…` rows above exist to record. **They are
kept rather than replaced on purpose** — a reader has to be able to tell which
binary produced which run, and a deleted row is a row that cannot be checked.

**Companion wire work in `tls13.zig` and `test/tls_wire/hello.zig`. Reported by
its owner and partly re-run by the parent; still not in §11's table.** Owned by
`VendorAlpnPinFailClosed`: a zero-length `ProtocolName` refused in the offer and
in the selection, and a pin demanding identity in every client-auth mode. The
production hunk is in the tree — authorised by the parent once the owner's reds
were reported — and the four new regressions exist.

| | Digest | Lines | State |
|---|---|---:|---|
| `tls13.zig` before the hunk | `cd73f07ec01375c5751c726e0aebfaabb1eb809b4dc18b4419db4238f66929e2` | 7,792 | baseline |
| `tls13.zig` after the hunk | `d2c98d0a23707e29801d78caa3bcbe4f59f91e18f832de9ace4d3fb321209c2d` | 7,854 | green observed |
| `tls13.zig` after the `parseCertificateRequest` widening, its vector and the ordering comment | `12d5346941a9b512cab144203bc6c1f8e49f9e77495d341aa3c0987f3edb8944` | 7,884 | green observed again |
| `tls13.zig` current — the vector rebuilt as a `comptime` literal | `aee3cd4a5290d8278f92aea3d46ba16d2360f70cc154de881dd9d116afcf5e17` | 7,890 | green observed again |
| `test/tls_wire/hello.zig` | `ee454b334a38f99de9418034440ed62534a6ca4d581433b991de07881648ee3a` | 1,556 | 13 tests, was 9; **unchanged across all four `tls13.zig` states** |

All of these digests, every line count and the 13-test count were re-read from
the files after each report. The `hello.zig` digest not moving across the four
`tls13.zig` states is the point: the test bytes were fixed while the core moved
under them.

**That stability is ending, and this row is stamped accordingly.**
`test/tls_wire/hello.zig` will leave `ee454b33…` / 1,556 lines: the two rows this
file holds below — the `:369` `u16` widening and the `:804` `msg[4..]` guard,
each with its comment — are landing, owned by `FuzzRootQuotaAndOracleTrap`.
**`ee454b33…` describes the bytes every green above was taken against and no
later ones, so it must not be cited after that lands.** The new digest and the
moved line numbers go to the parent, and this row is to be replaced with them
rather than amended in place; every `:369` and `:804` citation here moves with it.

**The landing those two rows predicted has now happened, and the replacement
digest is not written here.** This file records a digest it was given; it does
not compute one. So `ee454b33…` is still the last `hello.zig` digest recorded
above and it is **not** a digest of the current file. The two `hello.zig` rows
below are marked landed; a focused 1/1 vendored TLS decode fuzz leg
(`resume-w1-tls-focused-after.log`, against the 1/1 failure in
`resume-w1-tls-focused-before.log`) now stands against the current bytes, but
**no `quic-test` figure and no full fuzz-gate figure** has been taken against
them, and that leg is narrower than the gate.

**The last link is a shape change worth naming.** The `parseCertificateRequest`
vector was first written as `undefined` plus writes; `StaticTlsReview` flagged
that shape as exactly what the use-undefined rule fires on, and it is now a
`comptime` literal — a constant has no unwritten bytes to reason about at all.
So the fourth digest is not a behaviour change and no new claim rides on it.

The runs are the direct form
`zig test --dep quic -Mroot=test/tls_wire/hello.zig -Mquic=vendor/quic/src/lib.zig`.
Against the pre-hunk `tls13.zig` with the same `hello.zig`: **10 passed, 3
failed** (tests 9, 10 and 12; test 13 green). Against `d2c98d0a`, against
`12d5346` and against `aee3cd4a`: **All 13 tests passed** each time. Filter
liveness was proven by count movement — 13 unfiltered, 1 under the
zero-length-protocol filter, 2 under the pin filter — because a build-step
`--test-filter` is inert on this tree (§12). The `parseCertificateRequest` seams
were exercised separately and filtered: `zig test vendor/quic/src/test_all.zig -lc
--test-filter "parseCertificateRequest and parseCertificateList reject malformed
input"` gives **All 2 tests passed** against `aee3cd4a`. The `aee3cd4a` figures
were then observed by the parent as well, so they are not single-witness; none of
them is a gate run, and the earlier `d2c98d0a` and `12d5346` observations remain
the owner's alone.

**The seams it exercises are the public ones** — `initServerInto`,
`initClientInto`, `provideData`, `step`, `negotiatedAlpn`, `selected_alpn_len`,
state — and no private symbol is named or reached by a relative path. What it
deliberately did **not** change, because each belongs to another owner:
`buildClientHello`'s zero-length offer (the parser-scoped fix; list validation
is the transport config's, §13 above), the 32-byte `selected_alpn` buffer (no
enlargement), and `node_accept`'s routing on `negotiatedAlpn` — judged then,
judged the other way now: finding 4 below has been found, repaired, and proved
by a consumer regression.

**A near miss that a reader of "13/13 green" deserves to know about.** An edit
call in the course of that work deleted the `required,` member of the vendored
`ClientAuth.Mode` enum. **The compile and the 13 of 13 were green against the
damaged file**, and the damage was found by the owner's own post-edit read and
repaired before anything was recorded. This is not a defect in the code and the
enum is intact; it is a fact about how the evidence was produced. A green taken
on bytes that had just been damaged says less than a green taken on bytes
nobody had just touched, and here **the thing that caught it was reading, not a
test** — the suite had nothing to say about it.

**Two rows landed with no full gate run behind them, two landed, and one that must never be called closed.** The fuzz gate result against the current bytes is still **pending**; the two `hello.zig` rows below now have a focused 1/1 decode leg behind them, which is narrower than that gate and is not written here as one.

| Item | State | Condition |
|---|---|---|
| `parseCertificateRequest`'s `readU16(data) + 2 != data.len` addition on a `u16` (`tls13.zig`) | **landed** in `12d5346…`, with its nine-byte vector; vector reshaped in `aee3cd4a…` | **no red exists and none is recorded.** The pre-fix failure was an integer-overflow ABORT rather than a failed tag, and it was never witnessed: the fix and the vector landed in one authorised pass. The green is real; a red for it would be a fiction |
| the same trap in the oracle at `test/tls_wire/hello.zig:369` | **landed**, with its comment — `FuzzRootQuotaAndOracleTrap` | **the fuzz gate is pending**; a focused 1/1 decode leg (`resume-w1-tls-focused-after.log`) now stands behind the current bytes, and that leg is narrower than the gate. Landing the row moved the `hello.zig` digest, so `ee454b33…` stops being citable and no replacement digest is recorded in this file |
| unguarded `msg[4..]` at `test/tls_wire/hello.zig:804` (`clientHelloBlockAt`) | **landed**, with its comment — same owner | the same two facts: same digest consequence, and the same pending fuzz gate behind a focused leg. **804, not the 722 reported earlier**: 722 was a pre-hunk line passed on unchecked, so any row citing it was already stale |
| the offer-side refusal's *ordering invariant* | **landed, invariant-documented** | the comment is in the file; the invariant is still not in code. See below |

**The offer-side refusal is landed, its invariant is now documented, and it is
not closed.** The empty-name refusal lives in the pre-pass that reads every
offered entry (`tls13.zig:3118-3133`); the selection walk below it
(`:3135-3155`) does **not** repeat the check, so "the pre-pass runs first" is
what makes the walk sound — move either and the selection path would accept a
zero-length name. That ordering is now stated in the file, in the comment at
`tls13.zig:3142-3148`: the walk does not repeat the refusal, a zero-length
`ProtocolName` is refused before the walk can reach it, including in a list of
nothing but empty entries, which is that rather than the
`no_application_protocol` below. **3148 is the last line of that comment** — 3149
is blank and 3150 begins a different one, about an entry too long for
`selected_alpn`, which is a different rule about a different thing.
`Rfc7250WireSpecReview` raised the gap on its own re-read and asked for exactly
this comment. **Documented is not closed**: the dependency is still carried by
reading order and prose, not by an assertion the compiler or the suite checks,
and this file does not record it as closed.

**Credit for the four findings that review raised**, so a later reader does not
attribute one owner's work to another. Finding 2 (a zero-length *selected*
`ProtocolName`) and finding 3 (`expect_node_id` under `.optional`) belong to
this patch. Finding 1 (a zero-length name in a caller's *configured* list)
belongs to the concurrent `quic_config.validateAlpns` at
`src/transport/quic_config.zig:84-91`, called from `quic_bridge.zig:212` and
`dial.zig:406` — **not** to this patch, which touched neither file. Finding 4
(the accept path dispatching on the `negotiatedAlpn` fallback when nothing was
selected) was **open and unowned** here, narrowed to `node_accept.zig:141-155`.
**It is now found, repaired on the accept path, and proved by a consumer
regression.**

**What finding 4 was.** The accept path dispatched on
`Connection.negotiatedAlpn`, which answers `config.alpn[0]` whenever the
handshake selected nothing (`vendor/quic/src/quic/tls13.zig:2060-2063`) and whose
own note calls that fallback "not a negotiated protocol and nothing treats it as
one" (`:2057-2059`). On a server `config.alpn[0]` is this node's own first
configured protocol, so a peer that advertised no protocol at all would have been
handed to whichever handler that name belongs to — on a protocol it never named.

**Why it was reachable, which is the half that made it a defect.** The core's
`no_application_protocol` is a refusal of an empty intersection of an offer that
**was made**, and it lives inside the ALPN extension's own parse: `:3115` is the
`if (elen >= 2)` that arms it and `:3178` is the refusal. A ClientHello carrying
**no** extension never reaches that arm, so the handshake *completes*. The core
says so in its own terms — "the extension is then absent in both directions,
`negotiatedAlpn` answers `""`, and neither end fails" (`tls13.zig:1433-1435`) —
and it answers EncryptedExtensions with an empty selection rather than with
whatever length the storage held (`:2304-2310`, `:3379-3396`). This is the shape
the ALPN guard above already stated as its own limit: the present-offer refusal
was never about the absent extension, and nothing had closed the other half.

**What was repaired.** `node_accept.zig` asks the handshake instead of the
fallback, through the one canonical method: `Conn.negotiatedAlpn`
(`src/transport/quic_conn.zig:80-107`), which takes only the receiver — there is
no `Conn` argument and no private copy left in the node file — reads
`selected_alpn[0..selected_alpn_len]` (written by the selection walk and by
nothing else, `tls13.zig:3163-3164`), and answers null for a zero length.
`runTask` calls it at `node_accept.zig:144` and refuses **both** cases, counted
where every refusal is counted, warned, dropped without a peer response, and no
`Event.routed` fed.
Nothing was invented for it: that is the outcome an unroutable connection already
got.

**Which regression proves it.** `test/runtime_handlers_test.zig:882`, `a peer that
negotiates no protocol reaches no handler`. It reaches the case on the wire
rather than by constructing it: the same ordinary `Socket` + `Bridge` +
`Dialer`, with `alpn_count` emptied after the configuration check has run, so
`buildClientHello` writes a ClientHello carrying no ALPN extension. **The half
with teeth is the lane** — `attempts` 1, `spawned` 1, `protocols_refused` 1,
`tasks_routed` 0, and `node_close.laneStats(node, 0)`'s finished and turns both
**0** — because `config.alpn[0]` in that test is the gossip ALPN, so the old
dispatch would have driven the gossip handler. A peer that *does* negotiate is
served afterwards on the same node, which is what makes the refusal this
connection's and not this node's.

**The serve half is a different file, and it has landed too.** `serveAdmit`
compares against `relay_alpn`, so a serving node listing the relay ALPN first
was reading `Connection.negotiatedAlpn` — this node's own first configured
protocol — against a peer that named none, and spending a client slot and a
`ServerChallenge` on it. It now asks the handshake the way the accept walk does
(`src/node/node_relay_serve.zig:53`, the same `Conn.negotiatedAlpn` at
`src/transport/quic_conn.zig:80-107`), and null is the walk's own skip: no slot,
no stream, nothing written. Its regression is
`test/relay_wire_test.zig:1674`, `a peer that negotiates no protocol spends no
client slot`. **Written, and no result observed for it here** — this ledger runs
no gate, and a landed hunk with an unread receipt is exactly the state §13's
written-is-not-run rule is about.

**The parent has now run these itself, so they are no longer single-witness.**
Against `aee3cd4a…`: `zig build quic-test -j2 --prefix …/install` gives
**Build Summary: 3/3 steps succeeded; 560/560 tests passed**, exit 0, 52.54 s
(`evidence/w1-quic-test-after-tls-hunk.log`). **560 is the whole artifact, not a
filtered subset** — a build-step `--test-filter` does not forward here (§12), so
every filtered claim in this section is a direct `zig test` line and this one is
not.

**The vendored core is green, and here is what that green is named by.** A second
leg gives **3/3 steps succeeded, 560/560 tests passed**, exit 0 against the
admission-hook bytes (`evidence/w1-quic-test-after-admission-hook.log`, the same
summary line). **That leg carries no `tls13.zig` digest** — it is named by what
landed in it — so the digest a vendored green is anchored to by name in this
file is `aee3cd4a…`, and this file does not guess one for the second leg. Two
earlier `quic-test` runs from the owner's session — against `d2c98d0a…` and
`12d5346…` — are **stale and discounted**; neither describes `aee3cd4a…` and
nothing is claimed for them after it.

The parent also ran, against the same tree and on its own account rather than as
a restatement: `zig test --dep quic -Mroot=test/tls_wire/hello.zig
-Mquic=vendor/quic/src/lib.zig` → **All 13 tests passed**; `zig test
vendor/quic/src/test_all.zig -lc --test-filter "a DATAGRAM at the advertised
payload budget crosses the wire"` → **All 2 tests passed**, so §12's regression
still holds after everything else moved; and `zig test --dep quic
-Mroot=test/quic_wire/transport_params.zig -Mquic=vendor/quic/src/lib.zig` →
**1/1 passed**, `RFC 9000 §9.6: a valid preferred address keeps its id and reset
token`, which is §13's oracle.

**The first-party suite, which is a different number and must not be read as
this directory's.** `zig build test -Doptimize=Debug` and
`zig build test -Doptimize=ReleaseSafe` each report **28/28 steps succeeded;
790/790 tests passed**, exit 0 in both modes, with the same per-artifact counts
in each — unit 678, integration 3, loopback 24, protocol-loopback 5,
blobs-transfer 6, two-process 11, relay-wire 11, runtime-handlers 6,
rust-wire-initial 23, expected-log-verdict 15, coverage 8
(`evidence/w1-full-debug-suite-wave1-union-verification.log`,
`evidence/w1-full-release-safe-suite-wave1.log`). **Those 790 are this project's
own tests. The vendored figure is 560, from a different artifact**: `quic-test`
compiles `vendor/quic/src/test_all.zig`, and the only vendored test `test` carries
is `test/vendored_invariants.zig` — the no-socket, no-clock, no-global-RNG
scanner below — inside the unit artifact's 678.

**What is still absent, and stays absent.** No red exists for the
`parseCertificateRequest` vector and none is manufactured: the pre-fix failure
was an integer-overflow abort rather than a failed expectation, the fix and the
vector landed in one authorised pass, and a red that was never witnessed would be
a fiction. **An explicit absence is worth more to a reader than a constructed
one.** Likewise the offer-side ordering invariant stays **landed,
invariant-documented, not closed** — a comment that says what the ordering
guarantees is worth having, and calling it closed would claim a machine check
that does not exist.

**The `u16`-addition rationale now has a third instance, and they are phrased
alike on purpose.** `messages.zig:139-142` says it for an `extensions` block,
`tls13.zig` for `SignatureScheme supported_signature_algorithms` in
`parseCertificateRequest`: RFC 8446 §4.2.3 measures each against a byte count,
so the peer's length is read as a `usize`, because a peer that writes `ff ff`
names something longer than any buffer and adding to it in a `u16` would
overflow before the comparison could answer. One rationale, three sites, one
phrasing.

**And this is still not a green Wave 1.** The focused legs below are green; the
**full gate result against the current bytes is pending**. The required source
lint fixes have landed, no gate group has been run over them yet, and a pending
gate is written here as pending rather than as a failure. The earlier red lint
and static figures recorded elsewhere in this file belong to older bytes.

**1. The full gate result is pending**, and that covers the lint, static and
fuzz groups together. Two repairs do have focused evidence behind them, and it
is named narrowly on purpose: the vendored TLS decode is 1/1
(`resume-w1-tls-focused-after.log`) against a 1/1 failure
(`resume-w1-tls-focused-before.log`, `test/tls_wire/messages.zig:333` in
`certificateTypeShapes`), and the QUIC wire-decode corpus is 1/1
(`resume-w1-quic-wire-corpus-replay.log`, `quic wire decode` filter — a command
that ran zero tests is not evidence). **A focused decode leg is not the fuzz
gate.**

**The TLS failure's cause is corrected here.** It was **not** a `u16` production
overflow. `static-TlsSilentRootCause.json` names it: the certificate-type oracle
table had one exclusive `shape` column per body, so RFC 7250 §3's counted offer
(`client_certificate_types<1..2^8-1>`) and §4.2's single-value selection (a bare
`client_certificate_type`, "only a single value is permitted") were forced into
one verdict. `&.{0}` was classified as neither an offer nor a selection although
it is no offer at all — count 0, below the vector's own minimum — and a whole
x509 selection; `&.{1,2}` is a whole offer yet no selection the one-byte grammar
has a shape for. **Both production decoders in `tls13.zig` were correct and were
not changed**: `parseCertificateTypeOffer` refuses `len < 2`, `count == 0` and
`count + 1 != data.len`, and `parseCertificateTypeSelection` refuses `len != 1`
and any byte outside the registry, which is what the leaf's own reference
decoders already said. The table now carries one column per role, `offer` and
`selection`. The `parseCertificateRequest` `u16` widening recorded above is a
separate, separately landed repair and is not this failure.

**2. The zbc disposition ledger is no longer outstanding.** It is re-merged at
**32 source proofs and 60 records**, byte-idempotent on a second emission — the
second render reports `0 old records dropped, 0 new` and `identical to
gate_zbc_dispositions.zig`, both files SHA256
`3fbaa1893cfddda2c21a26569417fa57ed7dceea09d851f4e1deaabd9dbcc269` — with the
helper suffix the gate calls preserved, and both controls behaved: the
conflicting-kind control refuses rather than counting two reads as a vote, and
the current-defect control refuses until repaired source is re-read.

None of the receipts above is a gate result, and none of this promotes what is
not written: **multipath, the standard relay carrier, and RFC-compatible
resumption are Waves 3 and 4 and remain unimplemented.** Multipath is still one
active slot plus one candidate (`docs/DECISIONS/0001` item 5); the relay carrier
is still the server slice that writes its own TLS-over-TCP stack; and resumption
under a pin is still the recorded RFC 8446 deviation of §6, not an authenticated
early-data design.

**Retry took no vendor patch.** `ConnectionManager.require_retry`
(`connection_manager.zig:283`) and `retry_threshold` (`:287`) were upstream's,
and `recvDatagram` has read them where it decides Retry since the cut
(`:732-733`). What was absent was a caller: the transport's own configuration
names `require_retry` and `retry_threshold` at `src/transport/quic_config.zig:71`
and `:73`, and `quic_bridge.zig:248-249` copies them onto the manager. The
spent-token table is `retry.Gate` in `src/transport/retry.zig`, which is
first-party. Nothing in `vendor/quic/` changed to make pre-accept Retry
reachable, so there is no Retry patch to list here. `TODO.md`'s entry that
closing the hook "is a vendor patch" does not match this tree; what is still
caller-side is the production `IncomingFilter` registration —
`src/node/node_dispatch.zig:49` calls `incoming_filter.ask(null, incoming)`, so
every attempt is accepted — and that is not claimed here.

**Retry is now receipted natively, in both the core and the socket layer.**
`w1-retry-canonical-connection-core-after-spent-token-owner-fix.log` is 3 of 3,
including *"an Initial with no token is answered with a Retry, and its echo is
answered once"* and *"a ClientHello split across Initial packets after a Retry
reaches the connection the first one opened"*;
`w1-retry-fragmented-clienthello-real-socket-after-canonical-constant-correction.log`
is 1 of 1 for the same split ClientHello on a real socket. Against the real
partner, `w1-live-sdk-listen-retry.json` runs the ozai listener with
`--require-retry`: exits 0 on both ends, `payload_proofs_complete: true`, 0.48 s.
One Retry, one echo, one session — which is the whole of what the flag claims.

**The mixed-peer exchange, and exactly what it settles.** A build is not an
exchange, so the two are kept apart: the partner compiles
`--release --locked --offline` against `iroh = "=1.3.0"` and its `--help` runs,
and `test/rust_partner/` with `test/interop_peer.zig`, `interop_options.zig`,
`interop_runtime.zig` and `interop_transfer.zig` are the two ends of one
command-line contract. That is a build fact and nothing more.

An exchange **has** now run. Both directions were driven against a pinned
unpatched baseline — parent `6ad2f697931301006d565f3c6fbfe2369ed3bb5a`, clean
workspace `a7991952e83a8d5e370876323a02d5484bda1646`, Debug 5/5 exit 0, Node
`39b7cdfd7dfecf3d05da60469d07342f5b7bf5de898729e480709a2ccb4fbe89` — against the
locked Rust fixture
`748f0fca9dd2fa1b802b382e25f0eb2af6a12cd2ea7613b16ad9e7399ec80b65`, with a
loopback UDP proxy copying exact bytes before forwarding them unchanged:

| Direction | Rust partner | This side | Captured |
|---|---|---|---|
| Rust client → ozai | exit 1, connect failed, `IncorrectCertificateTypeExtension`, alert 40 | exit 0, warn, close `0x128` | 75 datagrams, 90,000 bytes |
| ozai → Rust listener | exit 1, incoming handshake failed, same typed error, alert 40 | exit 0, warn, close `0x128` | 2 datagrams, 1,303 bytes |

Two receipts — `w1-rfc7250-immutable-baseline-rust-to-ozai-wire-red-after-proxy-parse-fix.json`
and `w1-rfc7250-immutable-baseline-ozai-to-rust-wire-observation.json` — name
every argv, hash, exit code, stream and datagram byte. **This is what the §10
patch is a repair of, and it is that and nothing further.** It is a replay
against the old version: proof that the failure is real, is visible on the
wire, and is reachable in both directions. It is not a claim that an observed
event preceded the patch by any timestamp, and it says nothing about the
patched tree.

`0x128` is an observed close: CRYPTO_ERROR + alert 40, off the same
`0x100 + tls_alert` mapping that gives `0x178` for `no_application_protocol`.
Both are now observed on real sockets — this one between the Rust partner and a
baseline node, the `0x178` one between Zig peers — and they are different
closes.

**The two closes are different peers refusing different conditions, and neither
refutes the other.** Alert 40 is the Rust side refusing missing or malformed
negotiation, which is what it reports as `IncorrectCertificateTypeExtension`.
Alert 43 is this side refusing an offer that names nothing in common:
`error.UnsupportedCertificate` at `tls13.zig:3240` and `:3251`, mapped to
`tls.Alert.Description.unsupported_certificate` at `connection.zig:3196`, so it
closes at `0x100 + 43` = `0x12b`. The baseline's 40 is the partner's alert, not
this fork's, and the patch changes what this fork sends without changing what
the partner sends.

**What is therefore still true, and what is no longer true.** The patched tree
**has** now spoken to the real partner in both roles, with all six payloads each
way, so the RFC 7250 rows are no longer "unverified against a peer" and one
captured vector exists (§10). What has not moved: **Wave 1 is not green, and its
full gate result against the current bytes is pending** — neither passing nor
failing — so none of these receipts is a gate result; the upstream interop
matrix is still not re-run at our SHA; and only one datagram is captured, so
most vectors here are still authored rather than captured. The two vendor
patches below this one keep their own receipts. Multipath, the standard relay
carrier and RFC-compatible resumption remain unimplemented — Waves 3 and 4 — and
no part of the evidence above promotes them.

### 12. The packer charged the AEAD tag twice against the DATAGRAM budget

`packSinglePacket` stages a packet's plaintext in `tmp` and seals it into the
caller's `out_buf`. **The budget it measures every write against is a plaintext
budget, and the tag is outside it.** `packet_packer.zig:583` says so in one
line:

    const effective_max = @min(self.max_packet_size, @min(tmp.len, buf.len -| AEAD_TAG_LEN));

`buf.len -| AEAD_TAG_LEN` is the room left for plaintext once the seal will have
taken its 16 bytes, so `effective_max` is how many plaintext bytes may be
written and the ciphertext still fits `out_buf`. Every writer in the function
obeys that: the CRYPTO room at `:722`, the stream frames at `:764` and `:832`,
the uni arms at `:872`/`:876` and `:910`/`:914`, the minimum-plaintext pad at
`:992`, and the pad-to-target arithmetic at `:1008-1010` and `:1021-1023`, each
of which adds `AEAD_TAG_LEN` at most once, to a total that lands on
`effective_max`.

**The DATAGRAM arm added it twice.** `packet_packer.zig:957` was

    if (fbs.seek + frame_size + AEAD_TAG_LEN > effective_max) break;

where `frame_size` is `1 + varint_overhead + payload` — all plaintext. The tag is
already gone from `effective_max`, so that term is a second charge against the
same 16 bytes, and it is the one place where a packet is *refused* by it rather
than merely bounded by it.

**Why that costs a payload.** `Connection.maxDatagramPayloadSize`
(`connection.zig:4857`) advertises the ceiling by subtracting the tag exactly
once: `header_overhead = 1 + dcid_len + 4 + 16`, then `frame_overhead = 1 + 2`.
With a path MTU of 1200 and an 8-byte connection id that is
`1200 - 29 - 3 = 1168` bytes. A peer that sends exactly that, which is what the
advertisement invites, reaches `:957` with `frame_size = 1 + 2 + 1168 = 1171` and
needs `fbs.seek ≤ 13` to fit — and a 1-RTT header is `1 + dcid_len = 9` plus a
packet number. With the double charge the condition is `fbs.seek + 1187 > 1200`,
which no header can satisfy: the arm breaks, the datagram stays queued, and the
advertised maximum never crosses. The single charge puts it at
`13 + 1171 + 16 = 1200` exactly, which is the point of the number.

**The fix is one line, and it is deliberately one line.** `packet_packer.zig:957`
is now `if (fbs.seek + frame_size > effective_max) break;` — the same guard with
the second tag charge removed, no comment inserted and nothing above it moved.
The advertised ceiling crosses; nothing is clamped, and no payload is shrunk, to
make the refusal disappear. What is *not* touched is everything else that
mentions the tag: the remaining room guards at `:722`, `:764`, `:832`, `:872`,
`:876`, `:910`, `:914`, the padding guards at `:615`, `:1008`, `:1150`, and the
`max_datagram_frame_size` clamp in `maxDatagramPayloadSize`
(`connection.zig:4872-4873`). Those are conservative bounds and a negotiated
minimum to honour; none of them refuses something a peer was told it could
send, which is the whole of what made `:957` a defect.

**Why it was a defect and not a design choice.** The tree already said so, in
its own words, at `packet_packer.zig:2067-2070`: *"every writer in
`packSinglePacket` subtracts `AEAD_TAG_LEN` before it takes bytes, so a packet
lands on `effective_max` and never past it."* `:957` was the one writer that did
not, so the fix restores a documented invariant rather than choosing one.

**The test, and the receipts.** `PacketPacker: a DATAGRAM at the advertised
payload budget crosses the wire` (`packet_packer.zig:2750`). It packs an
8-byte-dcid `PacketPacker` with `max_packet_size` 1200 into a 1200-byte buffer,
queues the advertised ceiling of 1168 bytes with a short entry behind it, and
sets the application `next_pn` to 2²⁴ so RFC 9001 §5.1 spends the four
packet-number bytes the budget charges for. Two passes: each asserts
`written > 0` and `written <= out_buf.len`, then removes header protection,
decrypts the payload and parses the frames, and compares the exact queued
bytes. Pass 1 must carry all 1168; pass 2 carries the follower, which has no
room in pass 1 and so crosses only if the head did. The discriminator is
`written > 0` in pass 1 — with the double charge it is 0, the packet number is
rolled back, and nothing is written.

| | Receipt | Verdict |
|---|---|---|
| Red | `evidence/w1-vendor-datagram-advertised-budget-red-direct.log` | exit 1 — `...crosses the wire...FAIL (TestUnexpectedResult)` at `packet_packer.zig:2819`, `try testing.expect(written > 0)` |
| Green | `evidence/w1-vendor-datagram-advertised-budget-green.log` | exit 0 — `All 2 tests passed` |

**Run it the way the receipts were run.** The filtered invocation is
`zig test vendor/quic/src/test_all.zig -lc --test-filter "a DATAGRAM at the
advertised payload budget"`. `zig build quic-test -- --test-filter …` does
**not** forward the filter to the run artifact: it reported 560/560 passing with
this test present in the tree. A green that ignored the filter is not evidence
for this line, and the next reader will reach for the convenient command.

**File state at that run:** `packet_packer.zig` 2,852 lines, `sha256
60e331e65779753e79d14d1342dd8e90264af7c074f4387ce5d1b23cd85875cf`, anchors
`:583`, `:957` and `:2750` stable.

### 13. Two repairs on this side of the vendor seam

Neither of these is a vendor patch — both are in this project's own tree, and
they are recorded here because each is about a claim this file makes.

**A fixture oracle that read past what it had proved.** The preferred-address
parser in `test/quic_wire/transport_params.zig` copied the stateless reset token
from one byte past the end of a buffer the line above had already proved
complete: line 159 establishes `value.len == 41 + cid_len`, line 161 copies the
`cid_len` connection-id bytes out of `value[25..]`, and the old line 162 was
`@memcpy(out.stateless_reset_token[0..], value[41 + cid_len ..]);`. A
`@memcpy` whose source and destination lengths differ panics in Debug and
ReleaseSafe and silently zeroed the token under elision, so the fixture could
report a decoded preferred address carrying a token nobody had sent. The red
receipt is exactly that: `w1-preferred-address-oracle-valid-wire-red.log`,
`source and destination arguments have non-equal lengths` at `:162`, reached
through `rfcWalk` (`:232`) from the RFC 9000 §9.6 vector (`:433`). It is now
`value[25 + cid_len ..][0..16]`, green in
`w1-preferred-address-oracle-valid-wire-green.log` (`All 1 tests passed`), file
`sha256 7c202769a9ec223e580ddc7f4404cf5d1df783a03b9cb89b8f6517a8bd7e9061`.

**Why a green fuzz run never caught it, stated so it is not caught by one
next time.** No corpus entry reached that line: the fuzz seed carries a
zero-length connection id, which `value[24] == 0` refuses at line 158 before
the copy. **The green fuzz run was never evidence for this oracle.** The only
evidence was a test that encoded a preferred address with a connection id, and
coverage that never arrived is not coverage.

**One canonical ALPN bound, derived and enforced before allocation.**
`src/transport/quic_config.zig:33` defines
`max_alpn_name_len = @typeInfo(@FieldType(quic.tls13.Tls13Handshake, "selected_alpn")).array.len`
— read out of the core's own public selection storage rather than written down a
second time — with a `comptime` assertion that it is 32. **32 and not RFC 7301
§3.1's 255**, for two reasons that are not interchangeable: the server's walk
skips an entry it cannot hold whole (`tls13.zig:3099`), because a prefix of a
name is a different protocol, and a client refuses a selection too long to
record (`tls13.zig:4020`); and `quic_bridge.retired_alpn` is a withdrawal
sentinel that must stay longer than any live selection. So the bound is what
this stack could ever *negotiate*, not what may be *offered* — an offer that can
never be answered is not an offer, so a longer name is refused rather than sent.

`validateAlpns` (`src/transport/quic_config.zig:84`) decides the whole list
before anything allocates, copies or draws, and **both** creators call it —
`Bridge.create` at `src/transport/quic_bridge.zig:212` and `Dialer.create` at
`src/transport/dial.zig:406`. Two literals cannot drift apart that way. It
refuses an empty list and an empty entry with `error.NoAlpn`, and a name over
the bound with `error.AlpnNameTooLong`; it borrows nothing and keeps nothing,
so a refusal leaves no identity storage behind it and no truncated list for the
core to see.

**Companion wire work in `tls13.zig`: in flight, and unverified. Not done.** A
second half of the same refusal belongs to the core — a zero-length
`ProtocolName` refused in the offer and in the selection, and a pin demanding
identity in every client-auth mode — and it is owned by
`VendorAlpnPinFailClosed`. **Its four wire regressions exist; nothing about them
is observed.** The reds have not been run, so there is no red, and there is
therefore no green either. The production hunk in `tls13.zig` is **explicitly
held** and has not landed. Nothing in this file records it as done, it is not in
the table in §11, and no result is claimed for it. The relay-liveness work is
governed by the same rule: written is not run, and run is not observed until the
receipt says so. **The pre-accept admission hook is the one piece of that wave
carrying a receipt**, which is why it is row six in §11's table and not a claim
in this section.

### 14. The empty client Certificate was being sent unasked

`clientSendFinished` (`tls13.zig:2909`) decides what goes on the wire ahead of
the client's own Finished, and the RFC 7250 work (§10) rewrote that decision to
answer a `CertificateRequest` the client cannot meet with a raw key by sending
an **empty** `certificate_list`. Rewriting it hoisted the empty-list case into
the same arm as "no request arrived", and the arm's condition was written
`!self.certificate_requested or !clientCertificateIsRaw(self)` — so a client
that was never asked sent the empty list anyway.

**Why the peer could not read it.** RFC 8446 §4.4.2 puts `Certificate` in the
client's second flight only when a `CertificateRequest` asked for one, and this
core's server obeys that literally: `serverBuildFinished`
(`tls13.zig:3493`) routes on `if (self.client_auth != null)`, so a server holding
no client-auth policy parks in `.server_wait_client_finished` and reads the
client's `Certificate` in `serverProcessClientFinished`, which refuses anything
that is not `finished` with `error.UnexpectedMessage` (`tls13.zig:3503`). An
empty list is a well-formed answer to a question nobody asked; there is no state
on the other end that wants it.

**The repair is one condition, split in two** (`tls13.zig:2926`): no request
sends nothing, a request the type negotiation did not settle as
RawPublicKey sends the empty list, and a request with a usable key sends the
certificate and its `CertificateVerify`. The §10 behaviour is untouched — it is
the second arm, not the first.

**What it had been doing, measured.** `zig build quic-test` is the core's own
564-test suite and the gate's `test` group does not include it, so nothing in
the gate had run it. Driven directly against the pinned compiler
(`evidence/resume-w1-quic-test-alone.log`, 1200 s deadline, no output) it hung;
the hang was `quic.lossy_link_test.test.lossy link: a clean 4 MiB upload finishes
within a second`, which never reported within 45 s
(`evidence/resume-w1-quic-binary-probe.log`) — a lossy-transfer test that cannot
finish while every in-process TLS handshake it depends on dies on its first
message. Alongside it, **15 tests failed**
(`evidence/resume-w1-quic-probe-after-fix.log`'s predecessor
`resume-w1-quic-binary-probe` records the pre-fix set): every `tls13` loopback,
PSK-resumption and 0-RTT test that completes a handshake without client auth.
After the repair the suite **completes in 66 s** and reports
`560/564 tests passed (4 failed)` (`resume-w1-quic-test-after-client-cert-fix.log`):
the hang is gone and the 15 are green. **The remaining 4 are recorded as open in
§11's table, not as passing** — three `tls13` client-auth tests that expect
`error.CertificateRequired` and get `error.UnexpectedMessage`, and one
`connection_manager` Retry test.

**The three `tls13` ones are repaired in §15**, which is also where the fourth
stands. The figure above is left as the receipt it was.

### 15. A client asked for a certificate now answers, even with nothing to answer

§14 split one arm of `clientSendFinished`'s decision in two and left the third
unreachable. The condition it left was a three-way `if` on
`certificate_requested` and `clientCertificateIsRaw` whose signing arm was
guarded on `self.client_sig_scheme` alone — and that field is written in exactly
one place, `clientProcessEncryptedExtensions` (`:2769`), and only for a
`config.client_certificate` that exists. **A client holding no certificate fell
between two arms and put nothing on the wire at all**, which is how §14's
reported symptom and this one are the same test.

**The server was not at fault, and the standing diagnosis was wrong about
that.** `serverBuildEncryptedExtensions` decides the CertificateRequest from one
value and uses it for the extension *and* the next state (`:3422`, `:3428`,
:3436`), and `serverBuildCertificateRequest` keeps the request on the PSK path
as well as the full one (`:3455`). Both routes reach `serverBuildFinished`, which
picks `.server_wait_client_certificate` (`:3526`) *because* `client_auth != null`
— so on every one of those paths the request had already gone out. What the
server then read was a `Finished` where it wanted a `Certificate`, and `:3603`
refused it with `error.UnexpectedMessage`. Both are legal alerts and only one is
the RFC's: `connection.zig:3188` turns this into `unexpected_message` and
`:3197` turns `error.CertificateRequired` into `certificate_required`, which is
what RFC 8446 §6.2 names for a server that required a certificate and did not
get one. So the peer was told it had sent something impossible when it had in
fact said, correctly, "I have none" — and `serverProcessClientCertificate`'s own
refusal at `:3617`, which was the right answer all along, was unreachable behind
it.

**What changed: one arm, and one named question.** `clientAuthScheme`
(`:3008`) answers the single decision RFC 8446 §4.4.2 puts in the client's
second flight — the scheme this client signs its `CertificateVerify` with, or
null when the answer is an empty `certificate_list` — by asking for a configured
key, a `client_certificate_type` settled as RawPublicKey, and a scheme the
`CertificateRequest` offered. `clientSendFinished` (`:2936`) then sends a
Certificate whenever `certificate_requested` is set: the key and its
CertificateVerify when that answers non-null, the empty list when it answers
null, and nothing when no request arrived (§14's arm, unchanged).

| | before | after |
|---|---|---|
| asked, key in hand, type RawPublicKey | certificate + CertificateVerify | unchanged |
| asked, type settled as X.509 (§10) | empty `certificate_list` | unchanged |
| **asked, no key configured** | **nothing** | **empty `certificate_list`** |
| not asked | nothing | unchanged |

**The clause.** RFC 8446 §4.4.2 puts `Certificate` in the client's second flight
whenever a `CertificateRequest` asked for one, and a client with nothing to
offer answers with a `certificate_list` of length zero — not with silence. The
empty message is also the only answer that is well formed under any negotiated
type: it carries no `SubjectPublicKeyInfo`, so RFC 7250 §4.1 does not constrain
it, and it keeps both ends' transcripts in one order, which is what
`serverProcessClientFinished` (`:3536`) verifies the client's `Finished`
against. **Wire deviation: none.** The omission this removes was the deviation,
and `client answers a CertificateRequest with an empty Certificate` (`:5579`)
still reaches the same bytes by the X.509 arm.

**Measured.** `zig build quic-test -Doptimize=Debug -j2 --summary all`, exit 0:

```
Build Summary: 3/3 steps succeeded; 564/564 tests passed
```

against `tls13.zig` `sha256 02521578954ca75fe91391f75b9c56b98ec5c38190cef2e5d49f85599590ac60`,
7,933 lines — named so the figure is not read against a later tree. It compares
with the `560/564 tests passed (4 failed)` §14 recorded. `quic.tls13.test.a
resumed connection with a pin in force cannot complete without a certificate`
(`:6056` — PSK resumed, pin in force, no client key) and `quic.tls13.test.a
selected certificate with no policy of its own inherits the connection's`
(`:7093`) are the two this change carries: each is the RFC 8446 §4.4.2 empty-list
answer arriving where the server is waiting, and each now ends in
`error.CertificateRequired` from `:3617` rather than `error.UnexpectedMessage`
from `:3603`. The fourth was `connection_manager`'s Retry leg, another owner's.

**One expectation was unsatisfiable as written, and what it took was the
sub-case rather than the handshake.** `QUIC client certificates: a raw SPKI
identity, required or optional` passed the line §14 left it failing on — `:6854`
then, `:6886` now, the `.required` sub-case — and then
failed at `:6898`, which is this test's own `.optional` sub-case:

```zig
auth.expect_node_id = null;                            // :6896
auth.mode = .optional;                                  // :6897
try std.testing.expectEqual(null, try handshake(…));   // :6898
```

`auth` carried `.expect_node_id = client.node_id` (`:6861`), so that asked
for a server that **pins a node and takes an anonymous client anyway**. Nothing
in the tree says that, and three places say the opposite by name:
`ClientAuth.expect_node_id` — "a mode that lets a client through with nothing
does not waive it: such a client fails with `error.CertificateRequired`"
(`:474-479`) — `ClientAuth.Mode.optional` — "a policy that names a node demands
that node's certificate, so an empty `certificate_list` is
`error.CertificateRequired` here as it is under `required`" (`:499-502`) — and
`serverIdentityEstablished` (`:3589`), which `docs/PLAN.md:644` names in the
words **"never weaken `serverIdentityEstablished`"**. The production caller
cannot even build this configuration: `quic_bridge.zig:226-232` reads the two
fields through one decision (`demandsPeerCertificate`), so a pin *is* `.required`
there, and the audit that produced the pin rule is recorded in this file as
"Finding 3 (`expect_node_id` under `.optional`)" (`:1493`). The sub-case also
cannot be satisfied by moving the repair to the server: leaving the client
silent still reaches `serverFinish`, still consults `serverIdentityEstablished`,
and still refuses. §14 never *reached* this assertion — the test stopped at the
line above it, the `.required` one — and it is reached now; nothing about the
repair invented it.

**Resolved by correcting the sub-case, and the pin is why it could not stay.**
`QUIC client certificates: a raw SPKI identity, required or optional`'s
`.optional` half clears `expect_node_id` before it reads `mode` (`:6896`) and
puts the pin back for the stranger-key half that follows (`:6914`). It could not
stay on the `.optional` half because `mode` is the whole subject there,
`expect_node_id` is a demand for a certificate that `.optional` does not waive,
and the production caller reads the two through one decision
(`quic_bridge.zig:226-232`) — so the combination is a configuration no caller can
build, and the `BadCertificate` the stranger-key half expects comes from the pin
comparison alone (`:3626-3627`) and would have had nothing to compare against.
The correction is confined to the test's `auth`: the handshake code is unchanged
by it, and no expectation was weakened to get there.

### 16. One Retry per flow, decided where the Retry is written

§11's admission-hook row records `retry` on a proved flow being refused
(`connection_manager.zig:835`, at the hook) and calls the suite green against it.
It was not. The guard was there and it ran; the regression that names the
behaviour, *a Retry asked for on a flow that already proved its address is
refused, not sent twice*, was **red on those bytes** — the row's own caveat about
560 not proving the three regressions ran is what let that stand
(`evidence/w1-vendor-retry-already-validated-filter-red.log`: `connection_manager.zig:1608`,
`RESULT 147 … status=fail`).

**What the manager already did, and what was wrong with where it did it.** The
one-Retry-per-flow rule (RFC 9000 §17.2.5) was enforced at the **caller** that
asked for the Retry, in the hook's `retry` arm. That is a fact about the flow, and
the flow's state is consulted in one place — `route`, immediately after token
validation — so a guard at a caller holds only for that caller: the `need_retry`
arm (`:863-864`) is a second route into the same emission and carried no guard of
its own, and a third route added later would have had none either. The filter now
sits in `sendRetry`, the **one function that writes a Retry** (`:929-957`), which
takes the flow's `validated` and refuses when it is set (`:938`). Both callers pass
the value they already had. The token sealing, the fresh server CID and
`packet.retry` itself are **untouched** — the interoperability requirement in §11
stands, and a Retry this manager does send is byte-for-byte the one it sent before.

**The wire deviation is nil, and the rejected alternative is named.** A proved
flow answered with a `retry` verdict still gets CONNECTION_REFUSED in an Initial
sealed with the keys its own DCID derives (`writeRefusal`, `:1003`), exactly as
`refuse_new` and a server at capacity answer, and exactly what
`incoming_filter.zig`'s `admit` promises the endpoint layer. No packet type, frame,
length or position changes. **What would also have turned the suite green is
answering that case with a stateless reset**, a reset being the only
short-header packet a server with no connection can write; it was not taken,
because this client honours a reset only against a token it was given
(`Connection.matchesStatelessReset`, `connection.zig:5309`), no connection exists
on this path, so **the peer would not have seen the refusal at all** and the flow
would have stalled — the outcome the test exists to prevent.

**The filter belongs to the manager, and the question of a caller is settled.** The
endpoint layer already rewrites the verdict itself (`incoming_filter.zig`, `admit`:
`.retry` on `.validated`/`.cooperated` becomes `.reject`) and the manager is the
backstop under it. A caller-side filter could not work here even in principle: the
proof that a flow is already proved is a token this manager sealed with its own
key and validated at `route`'s token check, so the manager alone knows it, and the
regression drives `recvDatagram` with a hook answering `retry` unconditionally —
no caller stands between the two.

**The test's own predicate was miscalibrated, and that is the part to read.**
`isRetryPacket` answered `(bytes[0] & 0xC0) == 0xC0`, under the comment *"A
long-header Retry starts `0b11` and a CONNECTION_REFUSED is a short header"*. Both
halves of that are wrong for this core. A **Retry** is the one packet type with
neither payload encryption nor header protection (RFC 9001 §5.5), so its type bits
reach the wire in the clear — `0xf0` in v1, `0xc0` in v2 (RFC 9369 §3) — while
every other long header type is header-protected there. And **CONNECTION_REFUSED
is not a short header**
here: RFC 9000 §5.2.2's refusal is an Initial carrying CONNECTION_CLOSE, which is
what `writeRefusal` writes and what `a server at capacity refuses a new client with
CONNECTION_REFUSED` proves by decrypting it. So the predicate matched every
long-header packet, including the very refusal it was written to detect, and no
correct implementation could satisfy the line beneath it. It now reads the
packet's own version and compares the first byte against the Retry type bits for
that version (`:1518-1537`), which is exact for v1 and v2 and is what its two call
sites mean.

**The assertion on the line that was red is unchanged, and the test got
stronger.** `try std.testing.expect(!isRetryPacket(second));` stands as written;
what changed is that it now says what it says. The test additionally feeds the
answer to the client and requires it to read `CONNECTION_REFUSED` out of it
(`:1635-1653`), the same proof `a server at capacity…` gives, so the case is no
longer "not a Retry" by a bit pattern but "a refusal the peer can act on", which is
the title's claim. No expectation was weakened or deleted.

**Measured.** Before: `RESULT 147 … status=fail` at `connection_manager.zig:1608`,
via the IPC driver against the preimage binary
(`evidence/w1-vendor-retry-already-validated-filter-red.log`). After: `zig build
quic-test -Doptimize=Debug -j2 --summary all`, exit 0, **`Build Summary: 3/3
steps succeeded; 564/564 tests passed`**
(`evidence/w1-vendor-retry-already-validated-filter.log`), and against that same
binary `RESULT 147 quic.connection_manager.test.a Retry asked for on a flow that
already proved its address is refused, not sent twice status=pass`. All 23
`connection_manager` tests pass in that binary
(`evidence/w1-vendor-retry-filter-cm-group.log`), including `an admission verdict
reaches the peer…` and `a server at capacity refuses a new client with
CONNECTION_REFUSED`, which share both the helper and the refusal.

**File state at that run:** `connection_manager.zig` 1,826 lines, `sha256
47e072eefb198ac89dc584a6d069a10e80fcd3f7cc627f5881d0cda90b0317e7`.

## Measured cost

| | Predicted | Measured |
|---|---|---|
| Socket layer | 7 files, 7,194 lines | 5 never copied (6,384), plus `c_api.zig` and `fuzz.zig` (2,391) because both drive the stack through the event loop. No `xev`, no `link_libc`. |
| Clock and CSPRNG | 60 sites | 85 reads removed (46 clock, 39 entropy), 109 new parameters (42 `now`, 6 `now_s`, 61 `random`) across 11 files, both public entry points changed, no design change |
| Certificate work | four functions, `TlsConfig`, `ClientAuth`, a flag split | 24 named functions, the `ChainError` set, the `X509Extensions` struct and two `ClientAuth` size constants deleted outright, the flag gone with them, plus `keylog_file` and `ca_bundle`, which this record never mentioned |
| Resumption and client auth | two guards lifted, ticket format grown | neither. The guards were the bug: a resumed handshake now asks for the client certificate exactly as a full one does, the ticket carries no identity at all, and the ticket and the key that opens it became one `Resumption` value. `tls13.zig` 4,809 → 5,191 lines: 225 of tests and helpers, 157 of code. |
| The seam file | "splits rather than deletes" | split, then emptied by the threading patch, then deleted. There is no seam file. |
| Module root | "cut in the same pass" | `lib.zig` 47 → 41 lines, four layers of re-exports gone |
| Interop matrix | re-run at our SHA | **not done** |

The record was wrong in one direction, and it was the expensive one: it billed
the certificate work and not the threading. Deleting the chain walk turned out to
be *cheap* precisely because it was permitted to be a deletion rather than a flag
split — the split would have left the walk present, dead on one path and live on
the others, and every one of those paths a way for `realtimeSeconds` to come back
through.

Per file, the **initial** patch against the pinned commit. These are that pass's
deltas and not the current ones: every later patch moved several of these files
again, so a row records what the first pass did to a file rather than what the
tree now differs by.

| File | +/− | What |
|---|---:|---|
| `src/quic/tls13.zig` | +1,297 / −1,354 | the certificate deletion |
| `src/quic/connection.zig` | +578 / −482 | qlog out, `send` out, time and entropy in |
| `src/quic/connection_manager.zig` | +199 / −197 | the protocol layers out, time and entropy in |
| `src/quic/rsa.zig` | +198 / −45 | `signPss` takes the caller's salt; the RSA fixture moves here |
| `src/quic/lossy_link_test.zig` | +102 / −53 | upstream's harness, adapted to the new signatures |
| `src/quic/packet.zig` | +76 / −28 | the caller's generator: the Version Negotiation grease draw, and the Retry and NEW_TOKEN nonces |
| `src/quic/ack_handler.zig` | +70 / −8 | entropy into the challenge |
| `src/quic/packet_packer.zig` | +55 / −9 | time and entropy |
| `src/quic/transport_params.zig` | +48 / −14 | `encode` takes the generator, for the grease draw |
| `src/quic/stream.zig` | +42 / −0 | the `pop` ownership contract, documented and pinned |
| `src/lib.zig` | +29 / −35 | four layers of re-exports gone, `sys` gone |
| `src/quic/stateless_reset.zig` | +29 / −7 | entropy into the reset token |
| `src/quic/quic_lb.zig` | +25 / −13 | entropy into CID generation |
| `src/quic/congestion.zig` | +1 / −2 | one dead `sys` import |

Diff size is not a measure of this patch. `tls13.zig` went 4,866 → 4,809 lines
and `connection.zig` 6,666 → 6,762: the deleted walk and the added lift, doc
comments and tests are of about the same size. §6 grew it again, to 5,191,
which is the other half of the same point — a security invariant costs lines,
and the number that matters is the one on the test.

**The next person pricing a fork of this shape should price the threading, not
the certificate work.** Eleven of the thirteen files changed to take a new
parameter, and two of those also cut a subsystem — `connection.zig` gave up
qlog, `tls13.zig` gave up the X.509 walk. The remaining two, `lib.zig` and
`congestion.zig`, changed only to drop a re-export and a dead import. The
original decision record did not anticipate this, and a decision record that
understates its own cost is worse than one that declines.

The fourteenth is `src/quic/stream.zig`, and it is the one patch here that is
not a response to a project requirement. It adds 42 lines and removes none: two
doc comments and one test. See §5 — the short version is that `FrameSorter.pop`
returns an allocation the caller owns, every caller in this tree already freed
it, and upstream's doc comment never said so.

## Not gated on purpose, and not unchecked

`devenv.nix` runs the house gate as `GATE_EXCLUDE=vendor zig-gate` (`:86`) and
`GATE_EXCLUDE=vendor zig-gate --no-zbc --cov` (`:100`). **`vendor/quic/` is
excluded from `zig fmt`, `ast-check`, `zlint` and `zbc` on purpose.** It is
upstream code carrying its own formatting and its own idioms; reformatting it
would bury the patch under thirty thousand lines of noise, and linting it with
this project's rules would report findings nobody intends to fix.

"Not gated" must never mean "unchecked". Three things stand in for it:

1. **The vendored suite runs.** `zig build quic-test` compiles
   `vendor/quic/src/test_all.zig`, which reaches the tests two ways: an explicit
   `_ = @import` for each module `lib.zig` does not export, and a `refAllDecls`
   sweep over the declarations it does. The build summary is the current
   executed count; the smaller counts in earlier patch sections describe their
   historical runs, and a declaration sweep is not an executed test.
   Registering a module alone does not exercise its tests.
   **As of 2026-10-05 that summary is `3/3 steps succeeded; 564/564 tests
   passed`, exit 0** (`resume-w1-quic-test-after-pin-ruling.log`, 75 s; the suite
   also incorporates the sibling Retry leg's green), and it is this directory's
   own figure — the 790 the first-party suite reports is a different artifact and
   never enters this count. §11 names the `tls13.zig` digest the green is anchored
   to (`sha256 02521578954ca75fe91391f75b9c56b98ec5c38190cef2e5d49f85599590ac60`,
   7,933 lines) and the one test this correction re-labels
   (`tls13.zig:6890-6897`).
2. **The tests that changed are named here, not hidden.** One sub-case of one
   test changed, and the correction is recorded against the section that reports
   the green rather than against the green itself:

   **Correction.** The failed line (`, auth.mode = .optional` with `expect_node_id`
   still pinned) did not test what it was labelled to test: `mode` under silence.
   It tested a pin under a mode — a configuration the production seam
   (`quic_bridge.zig:226-232`) cannot build and the two invariants (`:474-479`,
   `:499-502` and `:3589`) will not honour. Its next sibling runs exactly that
   combination at `auth.mode = .required` and proves the pin on the wrong key
   (`:6904-6911`), so the pin coverage does not move. The edit is to the test only,
   and it narrows the sub-case to what its label meant: `auth.expect_node_id =
   null; auth.mode = .optional` (`:6896-6897`), the `.optional` answer to a silent
   client with no pin in play. The alternative — letting `optional` waive the pin
   — was refused rather than deferred: `docs/PLAN.md:644` forbids it, and the
   pin's own resumption test (`:6056`, `.required`) already pins the other side of
   the same distinction.
3. **This file is the reviewable artefact.** The patch is a named list with line
   references, not a diff nobody can read.

## What is still not settled

**1. 0-RTT, and the verifier identity. Closed, with a residue.** One value owns
both halves now — `TlsConfig.resumption`, a `Resumption` that is a server's
`TicketKey` or a client's `SessionTicket` and never both — and a test resumes
against a server whose key is held constant across two connections, with the
second observably not a full handshake. The tension the old entry named is also
gone, in the direction the entry wanted: a pinned client resumes, and the pin
holds on the resumed connection. See entry 6 above.

**What item 1 did not know, and entry 6 corrects.** The entry said the ticket
format is the block. It is not — the plaintext is `[64]u8` and the sealed form
`[80]u8`, both sized in the file, and growing them is mechanical. The block is
that TLS has one client-identity acquisition path and resumption skipped it.

The API contract follow-up repairs resumed cipher-suite agreement, records in
each ticket the QUIC version its issuing connection ended on, and keeps 0-RTT
on the first-flight version during compatible negotiation. See
`docs/DECISIONS/0004-vendored-core-contracts.md`. This is core resumption
coverage, not a claim that ozai's node exposes 0-RTT.

**2. Interop, and therefore requirement 3. One leg closed, one open.** The
native leg is done in both roles: a full handshake, exact peer ids, the agreed
ALPN, and all six declared payloads each way, exits 0 and 0 against the locked
Rust partner (§11), plus four typed refusals seen by that partner and a Retry
that completed in one echo. **All seven of those runs are receipts of the current
binary `70567c34…`,** which is the first build on which the exchange, the Retry
and the refusals were observed together. What that settles is interoperability
of *this* substrate with *that* implementation.

The upstream matrix leg is untouched. The matrix this vendoring relied on is
upstream's, and it is **not reproducible from this repository**: its runner is a
git submodule outside the published package. It was not re-run at our SHA.
Requirement 3 is re-established against this fork or not at all —
`interop/runner/matrix.sh`, with Docker, `quic-network-simulator` and `tshark`,
on a node that has the simulator's toolchain. Until then the honest statement
is upstream's own: ten of 88 cells red, one open, and ours unmeasured.

**3. The packer's DATAGRAM budget. Closed — red and green both observed.** §12
mapped it, the fix subtracts the AEAD tag once against a plaintext budget, and
the pair is receipted: `evidence/w1-vendor-datagram-advertised-budget-red-direct.log`
exits 1 at `packet_packer.zig:2819`, and `…-green.log` exits 0 with `All 2 tests
passed` under the **filtered direct** invocation — a build-step filter is inert
here (§12). It stood here as *landed nowhere yet* in the version this section
had before; the green was observed after that, and the row moved into §11's
table. Kept as a numbered entry rather than deleted, because the honest state of
this defect was once "not yet verified" and a reader is entitled to see that it
was.

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

`vendor/quic/src/test_all.zig` discovers tests by two mechanisms, and it needs
both: an explicit `_ = @import` for every module `lib.zig` does not export —
the internal ones and the test-only ones — and a `refAllDecls` sweep over the
declarations `lib.zig` does export. A root that only re-exports reaches nothing
at all: Zig analyses a test block only if the compilation reaches it, so such a
root discovers **zero** tests and exits 0. That is a green step proving nothing,
and it is the failure mode this file exists to prevent.

What does not hold is the rule "names every file that carries test blocks".
`io_compat.zig` carries a test block and is not named, because the sweep reaches
it through `lib.zig`'s export. Not every test-bearing file is a direct import,
and none has to be while `lib.zig` exports it.

What has no second mechanism is a module nothing else reaches. Three files
carry no test blocks and are absent from those explicit imports for that
reason — `aes_gcm_vectors.zig`, `ghash.zig` and `limits.zig` — and a new
*internal* or test-only module with tests in it runs only once it is named
there. The cost of getting that wrong is still silent: a new file with tests is
not run until it is named, and nothing fails when you forget.

The sweep is declaration reachability. It says a declaration compiles; it does
not say a test ran. The executed count is the build summary of
`zig build quic-test`, and no number is asserted here.

That is a different question from the one `build.zig`'s file-list check asks.
`vendored_files` in `test/vendored_invariants.zig` is the **scanner's**
coverage — the set of files the invariant gate embeds and reads — kept equal
to the tree by a configure-time walk in both directions. It is not a record of
which tests ran, and it is not one.