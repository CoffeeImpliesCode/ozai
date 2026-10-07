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

Fetched 2026-09-30 with `gh api` against the pinned SHA. No clone is kept in this
repository; `docs/PLAN.md` and `README.md` point at read-only checkouts under
`~/projects` that do not exist on this node, so every byte here was captured
from GitHub primary source and pinned.

The initial-cut counts and cost measurements below are historical measurements
against the pinned commit, not current-tree statistics after later portability
patches. A `file:line` names the recorded site in this fork; a bare `:NNN` names
the **upstream** file the section is about. Later patches can move fork line numbers.

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
plaintext is `[64]u8` and the sealed form `[80]u8`, both sized in this file, and
growing them by 33 bytes is mechanical. The real block is that TLS has one
client-identity acquisition path and resumption skipped it.

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
| `:2040` `serverBuildEncryptedExtensions` | routes to `server_send_certificate_request` on a policy in force, PSK or not, and only skips the server's own Certificate | the two `using_psk` sites disagreed, and the disagreement was the bypass. Which one is wrong is decided once, here. |
| `:2059` `serverBuildCertificateRequest` | skips to `server_send_finished` on a PSK instead of sending a Certificate the PSK already replaced | the other half of the same disagreement |
| `:2179` `serverTicketKey` | one accessor for the sealing key | the writer and the PSK reader have to agree on it |
| `:2194` `serverIdentityEstablished` / `:2201` `serverFinish` | both writers of `.connected` ask one predicate, and it refuses a policy in force with no identity | the invariant is structural rather than a flag; `serverProcessClientCertificate` stays the sole writer of `peer_node_id` |
| `:1273` dispatcher, `:1501` `clientProcessCertificate` | the resumed client reads a CertificateRequest and answers it, instead of skipping the state on `using_psk` | the client half of the same hole: skipping the state left the server waiting for a Certificate the client had been told not to send |
| `:2603` `peekHandshakeMsg` | `readHandshakeMsg` split into a peek and a take | the resumed client must know the next message is a Finished *before* it changes state, and `readHandshakeMsg` steps past it by the time it knows |
| `:597` `sealed_ticket_len`, `:2424` | the sealed-ticket size named once, and the offered identity length bounded by it | `tryProcessPsk` copied `identity_len` bytes into two fixed buffers with only a lower bound; the length is attacker-chosen and reaches this from any ClientHello. The path is now also reachable under a client-auth policy, so the bound is part of this patch. |
| `:609` `TicketKey`, `:632` `Resumption`, `:827` `TlsConfig.resumption` | `ticket_key: ?[16]u8` becomes one `Resumption` value, `union(enum) { server: TicketKey, client: *const SessionTicket }` | `DECISIONS/0001` item 1. A ticket and the key that opens it are one fact, and two fields let a caller name a ticket from one key and a key from another without either noticing. `TlsConfig.session_ticket` stays — `connection.zig:4671` reads it for 0-RTT remembered transport parameters, which cost a resumption its remembered limits and nothing else — and is no longer the handshake's resumption input, so it cannot influence whether a handshake resumes. |

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
(`src/transport/socket.zig`, `src/node/node.zig`, `src/gossip/hyparview.zig`).**
They are named here because they are the other half of the repairs above, and a
reader auditing this file should not have to look twice for either half.

- **Every datagram a batch sends reaches the wire once
  (`src/transport/socket.zig`).** A run refused for segmentation lowers the
  socket's capability for good and is answered by sending the runs behind it,
  one datagram per `sendmsg`; the runs before it are already on the wire and
  are not sent again. A refused segmentation is not a refusal of the codepoint, so
  the retried tail keeps it; a tail that loses the codepoint to its own retry
  is reported as lost *together with* the degradation, which is two facts and
  not one — a datagram carrying no codepoint is not a missing datagram, and
  nothing downstream can get either one back.
- **A frame walk compacts the inbox once (`src/node/node.zig`).** `peekFrame`
  copies the frame into caller-owned scratch, because its variable-length
  payloads borrow the bytes they were decoded from and taking a message off the
  inbox's front moves everything behind it — a borrow into a buffer compacted
  under it is a borrow of nothing. It hands back an end offset instead of
  shrinking the inbox per message, and `dropInbox` moves what is left exactly
  once: on the way out of the walk and on the fault that ends it alike, because
  the two are one decision taken twice rather than two decisions.
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

### 9. RFC 7250 raw-key certificate-type deviation

The vendored core has no X.509 parser or certificate fallback. Its only peer
identity format is the 44-byte Ed25519 DER `SubjectPublicKeyInfo` containing a
32-byte node id. The RFC 7250 extension patch makes that format explicit in
TLS 1.3, in both certificate directions.

**ClientHello offers.** In `src/quic/tls13.zig`, extension type 19 is
`client_certificate_type` and type 20 is `server_certificate_type`. The
ClientHello writes each extension with the normal `type:u16, length:u16`
header. Each `extension_data` is the one-byte vector length and one-byte type
`[1, 2]` (`:3975-3976`). The parser requires both offers once (`:2843-2932`).
It rejects an empty or malformed vector, repeated values, and an offer without
raw-public-key type 2. Unique extra values are tolerated only when type 2 is
also present. The server still selects type 2.

**EncryptedExtensions selections.** The server writes type 19 and type 20 with
one-byte `extension_data` `[2]` (`:4227-4228`). The client requires each
selection to contain exactly that byte (`:3763-3797`). Missing extensions,
malformed selections, duplicate extensions and non-2 selections fail closed.
TLS 1.3 `CertificateRequest` does not carry these certificate-type extensions.

This is a raw-public-key-only negotiation, not an X.509 fallback. Missing
offers fail with `MissingExtension`. Malformed vector lengths fail with
`DecodeError`. Duplicate offer values or extensions fail with
`IllegalParameter`. An offer without type 2 fails with `HandshakeFailure`.
Selections must be exactly one byte with value 2. The parser may ignore other
unique offered types, but it never selects them.

**SNI capacity suffix.** `buildClientHello` writes into one fixed 4096-byte
buffer. A large SNI and QUIC transport-parameter extension can leave too
little room for the mandatory six-byte `psk_key_exchange_modes` extension.
Before writing it, `buildClientHello` calls `extFits(buf.len, pos, 2)`
(`tls13.zig:4027`). This reserves its four-byte header and two-byte payload.
The `RFC 7250 ClientHello capacity covers the mandatory suffix` regression
returns `InternalError` when the SNI consumes that space. It accepts a name
one byte shorter and emits an exactly 4096-byte ClientHello.

No public TLS API changed. `TlsConfig` and `ClientAuth` are unchanged. The
existing Ed25519 SPKI extraction, node-id pin checks and unconditional
CertificateVerify checks remain in force. The strict Rust peer checks its pin
during TLS. Stock iroh keeps its upstream verifier and resolver unchanged.
The harness compares stock iroh's observed peer SPKI to the expected pin after
the handshake and before application bytes.

The peer manifest pins `iroh` and `noq` to 1.3.0. `Cargo.lock` fixes the
dependency graph, and the proof uses `--locked`.

With the scratch setup in `README.md`, the real-process role proof runs as:

```sh
cargo build --locked --release --manifest-path interop/iroh-peer/Cargo.toml
"$ZIG" build test-rust-interop -Doptimize=Debug \
  -Diroh-peer="$CARGO_TARGET_DIR/release/ozai-iroh-peer"
"$ZIG" build test-rust-interop -Doptimize=ReleaseSafe \
  -Diroh-peer="$CARGO_TARGET_DIR/release/ozai-iroh-peer"
```

The peer's locked Rust contract tests passed 12/12. The process suite passed
5/5 tests over 4/4 steps in both modes. It checks the ALPN contract and four
routes: Zig client to strict `noq`, Zig client to stock iroh, strict `noq`
client to Zig server, and stock iroh client to Zig server. All four negotiated
`ozai` and exchanged the exact 17-byte request and response payloads.
This proves a bounded TLS handshake and stream exchange. It does not close the
upstream matrix or prove mixed blob/gossip/relay protocols, NAT traversal or
0-RTT.

### 10. Native Noq extension wire and lifetime limits

The extension source is Noq 1.3.0 at
`c1f411562e6078852749b8bcf1190523096a107f`.
The vendor implements observed-address role transport parameters and frames.
It also implements native NAT ADD_ADDRESS, REACH_ADDRESS and REMOVE_ADDRESS,
plus native multipath transport parameters and frames.
These are Noq wire extensions, not the standalone Number-Time `src/net/qnt.zig` protocol.

`Node.Config.address_discovery_role` opts into native observed-address negotiation.
Bridge and dial configurations pass that role to the core.
Native candidate admission uses caller-configured physical addresses.
No node consumer turns received observations into learned candidates or published addresses.
The core supports only path IDs 0 and 1 for the connection lifetime.
Retired IDs retain their slots. Eight historical project address pairs do not expand this capacity.

`test/native_observed_upstream_oracle.rs`, `test/native_nat_upstream_oracle.rs`
and `test/native_multipath_upstream_oracle.rs` capture pinned Noq private codec output.
The actual generator captures produced 19-byte observed-address, 43-byte NAT and 24-byte multipath files.
`src/net/native_oracle_test.zig` is the Zig fixture consumer.
The fresh Zig consumer passed 9/9: three actual codec cases and six collectors.
It compares observed-address roles and varint widths, NAT frames and capacity, and ten multipath variants plus the MaxPath TLV.
Captured files prove encoder/decoder bytes, not live mapping learning or a successful NAT round.

Assembly failure and path abandonment have different contracts.
`Connection.sendAt` calls `failAssembly` when packet assembly fails.
It closes with `INTERNAL_ERROR`. The caller must discard the unspecified output buffer.
`Bridge.Conn.drain` returns `CoreRefused` without publishing an egress prefix.
Assembly allocation failure is not a recoverable requeue operation.

On first `PATH_ABANDON`, `Connection.requeueAbandonedPath` moves reliable retransmission obligations to the surviving path.
It retains STREAM bytes and FIN, control obligations, CRYPTO and pending HANDSHAKE_DONE state.
It retires abandoned sent records and recovery deadlines while preserving packet-number history for subsequent ordinary ACKs.
Repeated abandonment does not duplicate that work.
This is a source contract, not a new mixed-peer wire receipt.

The native traversal cancellation model uses sequence and last-local state.
That standalone model does not drive Node cancellation.
Configured candidates, native frame handling and this model have different production boundaries.

Main observed vendored QUIC Debug and ReleaseSafe suites passing 671/671 each (`bg288`).
Current normal-root Debug and ReleaseSafe integration passed 28/28 steps and 2538/2538 tests each (`bg317`).
The consumer regressions cover owned primary/nested key cleanup and the separate native cancellation model.
The model remains standalone. No Node cancellation integration or new mixed-peer proof follows from these passes.
Fresh schema-3 capture, full default gate and live smokes have not run.

### 11. Retry policy before connection allocation

`ConnectionManager` validates Initial tokens before its synchronous policy callback.
The callback receives borrowed metadata, not an allocated connection.
It must not retain CID slices or reenter the manager.
The manager executes accept, Retry, refuse or ignore before `acceptConnection`.
It refuses Retry for an already validated Initial.
Router policy now reaches this real preallocation route.

The live normal-stack Retry socket proof recorded one unvalidated Initial and one validated Initial.
At the Retry response, `allocated_after_retry` was zero.
The validated Initial then established one connection and exchanged the exact application payload.
Wire vectors and token/address-binding regressions are separate codec evidence.
Neither wire vectors alone nor an isolated policy callback proves that socket route.

### 12. Public stream borrows and deferred reclamation

`transport/bridge_conn.Stream` carries its owning `StreamsMap`.
Public handles borrow core streams and must pin them across connection processing.
Otherwise, callers must reacquire each handle by ID after that processing.
`close` ends sending. It does not release the stream.
`unpin` releases the final active borrow and calls `disposeIfSettled`.
A settled stream enters deferred reclamation for the next disposal cycle.
An unacknowledged FIN keeps the stream alive for retransmission.
The existing overflow backstop preserves reclamation if the disposal queue is full.
This prevents a settled, formerly pinned stream from remaining unreachable by garbage collection.

### 13. `Connection.deinit` releases both path-owned packet handlers

`packetHandler()` follows the active `transport_path`; teardown must not use
that selector. It must release the primary `pkt_handler` and, when present,
the separately owned path-1 handler exactly once. Selecting path 1 during
teardown can free the path-1 handler twice while leaving the primary handler's
packet maps allocated.

The regression test leaves each of paths 0 and 1 active in turn, allocates one
in-flight packet in both handlers, and calls `Connection.deinit` under
`std.testing.allocator`. Leak detection and double-free detection cover both
ownership branches.

### 14. Coverage instrumentation avoids Zig 0.16.0's fuzz-runner type error

The six `std.testing.fuzz` calls in `src/quic/frame.zig`,
`src/quic/native_nat.zig`, `src/quic/observed_address.zig` (two calls),
`src/quic/tls13.zig`, and `src/quic/transport_params.zig` now dispatch at
compile time on both `@import("builtin").fuzz` and
`@import("coverage_options").coverage`. The build supplies that options module
to both the imported QUIC module and the separate `test_all.zig` test root; its
`coverage` boolean is the existing `-Dcoverage` value, defaulting to false.
The same option and guard also serve the project's native-NAT fuzz test in
`src/net/native_nat.zig`, through the library and portable-test root modules.

Coverage sets the module's `fuzz` flag to obtain LLVM counters, not to execute
the fuzz runner. Instantiating these calls with that flag triggers Zig compiler
bug [#36326](https://github.com/ziglang/zig/issues/36326):
`lib/compiler/test_runner.zig:566` expects `*const debug.StackTrace` but receives
`*builtin.StackTrace`.

Only when both flags are true does each test directly call its existing
callback once with a local `std.testing.Smith` initialized with `.in = &.{}`.
This replays the empty input deterministically and keeps the callback reachable
for coverage without instantiating `std.testing.fuzz`. Smith's non-null input
selects corpus replay rather than the fuzz runtime, even in an instrumented
module.

Otherwise the original `std.testing.fuzz` calls, callbacks, options, and corpus
replay run unchanged. In particular, without `-Dcoverage=true`,
`zig build test --fuzz` and `zig build quic-test --fuzz` retain libFuzzer
dispatch even though `builtin.fuzz` is true. Deterministic assertions, measured
coverage roots, and dedicated `zig build fuzz` targets are unchanged.

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
2. **The no-socket / no-clock / no-global-RNG invariant is enforced by a test**,
   `test/vendored_invariants.zig`, run as part of every `zig build test`. It
   reads every `.zig` under `vendor/quic/src/` and fails on the constructs this
   directory must not contain: `std.posix.socket`, `std.c.`, the socket
   syscalls, `std.fs`, `std.process`, `getenv`, `std.time.nanoTimestamp`,
   `std.time.timestamp`, `std.crypto.random.*`, and the `test_clock` global.
   `vendored_files` in that file is what makes the read exhaustive:
   `@embedFile` cannot glob, so `build.zig` walks `vendor/quic/src` on every
   configure and fails when the list and the tree disagree in either direction.
   That list is the scanner's coverage — the set of files the gate embeds — and
   nothing here claims it records which tests ran. The sweep is clean today:
   zero hits for every one of them. Note what it does not forbid — mutability.
   `src/quic/ecdsa_p256.zig:37-38` keeps two file-scope `var`s, a precomputed
   Montgomery table and the flag that builds it once. They are a constant, not
   input, and they are upstream's. The rule is about hidden input, and a rule
   that forbade every `var` would have had to reject those.
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

**2. Interop, and therefore requirement 3. Open.** The full matrix this
vendoring relied on is not reproducible from this repository. Its runner is a
git submodule outside the published package, and it has not run at our SHA.
Section 9 records a bounded process/socket proof with strict `noq` 1.3.0 and
stock iroh 1.3.0. The proof covers four TLS role routes and one application
stream in each route. It does not run the matrix or discharge requirement 3.
The matrix still needs `interop/runner/matrix.sh`, Docker,
`quic-network-simulator` and `tshark`. The upstream tally of ten red cells out
of 88 and one open is historical. The full matrix at our SHA remains unmeasured.

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