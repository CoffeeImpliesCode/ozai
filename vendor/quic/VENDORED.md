# Vendored QUIC core

| Field | Value |
|---|---|
| Upstream | [endel/quic-zig](https://github.com/endel/quic-zig) |
| Source commit | `14b9dc3e5e8429d07e7ed18619c7b4f4baaa3719` |
| Upstream package version | `0.5.0` |
| Upstream Zig requirement | `0.16.0` |
| Local Zig requirement | `0.17.0` |
| License | [MIT](LICENSE), retained from upstream |

This directory contains a heavily patched sans-IO core, not an unmodified upstream release.
The source pin identifies its origin. It does not describe the local API or behavior.

## Included scope

The retained QUIC packet, stream, crypto, TLS, congestion, and connection code
consumes caller-supplied input and returns actions.
It does not open sockets, read clocks, access the environment, or own file handles.
Time, entropy, allocators, and buffers enter through explicit parameters.

The upstream event loop, socket backends, C API, fuzz driver, and syscall seam are absent.
HTTP/1, HTTP/3, WebTransport, MoQ, and TLS-over-TCP layers are also absent.
There is no libxev dependency. Protocol fields that only served those layers were removed.
The in-process lossy-link tests remain. RSA remains for TLS CertificateVerify signature schemes.

## Local changes

- Inject timestamps and entropy instead of process-global clock and random calls.
- Remove socket/file dependencies, qlog output, and TLS key logging.
- Use Ed25519 raw public keys instead of X.509 certificate validation.
  A peer identity is a 44-byte DER SubjectPublicKeyInfo with a 32-byte key.
  Malformed keys and mismatched expected identities fail authentication.
- Negotiate RFC 7250 certificate types 19 and 20 explicitly.
  Client offers contain `[1, 2]`. Server selections contain `[2]`.
  Missing, duplicate, malformed, or non-raw-key selections fail closed.
- Preserve client-pin enforcement during locally supported ticket resumption.
  The core can request fresh client authentication after PSK selection.
  This exchange is a local TLS deviation, not an RFC 8446 interoperability guarantee.
- Keep native Noq extension codecs and path policy separate from socket execution.
  Extension provenance is Noq 1.3.0 commit `c1f411562e6078852749b8bcf1190523096a107f`.
- Validate Initial tokens before the synchronous connection-allocation policy callback.
- Return owned stream-read allocations with explicit release duties.
  Refused reads retain the queued bytes. Public stream borrows defer reclamation.
- Release partially constructed connections and both path-owned packet handlers.
  Keep transport-parameter slices tied to connection-owned IDs.
- Recognize Version Negotiation before ordinary packet-length parsing.
  Do not issue NEW_TOKEN without a configured key.
  Retain close-packet retries when an output buffer is too small.
- Make socket-address values independent of host ABI layout.
  Check wire offsets before conversion to native fixture indices.
- Keep connection, frame, packet-packing, congestion, and transport-parameter
  validation explicit at the public boundaries.
- Port array repetition to splats and declaration/field reflection to parallel arrays.
  Optimization tag comparisons use Zig 0.17 names.
  AES fast paths use little-endian targets only.
  GHASH assembly targets x86_64 and aarch64, not aarch64_be.
  Scalar big-endian paths use explicit-endian I/O and need no bitcast change.

## Integration boundaries

The `quic` package module is separate from `ozai`.
The native `ozai` transport supplies sockets, datagram execution, clocks, and entropy.
Node-level authenticated 0-RTT and the complete upstream interoperability matrix remain incomplete.
A core resumption test does not establish either feature.

The configured first-party lint scan excludes this directory.
`zig build quic-test` executes its test root. `zig build invariants` checks source contracts.
`src/test_all.zig` imports non-exported modules and reflects over public module declarations.
Both mechanisms are needed to include tests outside the public exports.

When updating the upstream pin, compare every changed contract against its tests.
Do not replace this fork with the upstream event loop or silently restore hidden I/O.
Retain the binary protocol fixtures and upstream license.
