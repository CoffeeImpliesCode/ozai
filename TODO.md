# TODO

The plan is in [`docs/PLAN.md`](docs/PLAN.md); this is only the near-term
checklist, so that the next agent does not have to re-read the plan to find out
what "next" means.

## Done

- **M1 — identity and addressing.** `src/base/`. 38 tests green in Debug and
  ReleaseSafe, pinned against iroh's published vectors.
- **M7, pure half — the synthetic-ULA construction and its inverse.**
  `src/base/ula.zig`, vector-pinned to iroh `1.3.0`. The allocation of an
  address to a key, and the socket, are still plan.

## Next

- **M2 — wire codecs.** varint plus a postcard-compatible reader and writer.
  Start with `RangeSpec` / `RangeSpecSeq` from iroh-blobs: it is small, it has
  hexdump tests upstream to copy, and it is the algebra everything else in
  M11's transfer path depends on. Fuzz at every decoder boundary.
- **M3 — tickets and discovery records.** `EndpointTicket`, `BlobTicket`, the
  pkarr signed packet. The BEP-0044 signable form and the
  lowercase-after-prefix base32 rule are the two things that will silently
  produce packets nobody accepts.

## Waiting on a predecessor

- **M8 — the QUIC substrate.** Decided, see
  [`DECISIONS/0001-transport-substrate.md`](docs/DECISIONS/0001-transport-substrate.md).
  It sits behind M7, and M2–M7 do not wait on it. What genuinely cannot start is
  M9 and up: anything needing a live peer connection.

## Standing constraints

- Wire compatibility is a golden-vector test, never a comment. A claim with no
  captured bytes attached does not go in.
- The foreign checkouts under `~/projects/github-n0-computer-iroh*` are
  read-only. Never edit them, never commit them, never add agent rules to them.
- `zig-gate` binaries live in `~/.local/bin` and are version-pinned. They are
  not taken from `devenv` `packages`, and `zig` is not either.
