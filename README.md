# ozai

A Zig implementation of the [iroh](https://github.com/n0-computer/iroh) peer-to-peer stack.
Nodes use 32-byte public keys as identities. The stack includes QUIC transport,
relay framing, discovery, gossip, blob transfer, and ticket codecs.

**Status:** experimental. The complete upstream interoperability matrix and
node-level authenticated 0-RTT are not complete. Some protocol models remain
standalone rather than connected to `Node`.

## Requirements

- Zig 0.17.0.
- Linux and libc for the native socket and node drivers.
- Bash, GNU coreutils, and util-linux for the native test scratch helpers.
- Optional: Nix, devenv, and direnv for development tools.
- Optional: Rust and Cargo for the pinned peer in `interop/iroh-peer/`.
- Optional: Python 3, iproute2, nftables, and procps for isolated relay smoke tests.

Pure codecs and state machines do not require libc or network access.
The development shell uses Zig from `PATH` and checks its version.

## Build and test

Tests use standard temporary directories under `.zig-cache/tmp` by default.

```sh
zig build
zig build test
zig build test-portable
zig build quic-test invariants test-gate-policy
```

`zig build` installs the static library and `ozai-node` in `zig-out/`.
`test-portable` covers socket-free protocol and state-machine code.
`quic-test` runs the vendored transport tests. `invariants` checks source contracts.
Repeat the tests with `-Doptimize=safe` to use optimized safety checks.
Foreign node-test children use cross-test's selected executor, including QEMU user runners.

The optional Linux NAT fixture accepts an absolute, canonical, caller-owned evidence
directory. `zig build nat-fixture relay-fixture` builds its supervisor and Zig peer.
The `test-native-interop` step passes arguments after `--`.
Run the installed supervisor without arguments to see its CLI.

## Use

```sh
zig build run-ozai-node-id
zig build run-ozai-node -- --progress --for 30000
```

The first command prints a node identity. The second runs a node for 30 seconds
and prints progress counters. Without `--progress`, it prints its banner and final report.

To consume the package, add an `ozai` dependency to `build.zig.zon`, then import
its registered modules in your `build.zig`:

```zig
const dep = b.dependency("ozai", .{
    .target = target,
    .optimize = optimize,
});
app.root_module.addImport("ozai", dep.module("ozai"));
app.root_module.addImport("quic", dep.module("quic"));
```

Enable `.link_libc = true` on the application module when it uses the native drivers.
Import `quic` only when application code names the transport core's types.
Runtime owners require serialized access and exactly one teardown.
Borrowed values must not outlive their owners. See the type documentation.

The optional `test-rust-interop`, `test-gossip-interop`, `test-blobs-interop`, and
`test-relay-interop` steps accept `-Diroh-peer=/absolute/path/to/ozai-iroh-peer`.
Build that peer with `cargo build --locked --manifest-path interop/iroh-peer/Cargo.toml`.

## Development checks

`direnv allow` loads the optional devenv shell and portable cache defaults.
The strict gate also needs `zig-gate`, ziglint, zlint, Zwanzig, cross-test,
and the coverage tools through `PATH`. Set `ZBC` to the native analyzer's absolute path.
Its default is `$HOME/.local/bin/zbc`.
For the gate or external test scratch, set `GATE_SCRATCH` to a private directory
on a local filesystem, not NFS. An explicit invalid path is rejected.

```sh
export GATE_SCRATCH="${XDG_CACHE_HOME:-$HOME/.cache}/ozai/scratch"
mkdir -p -m 700 "$GATE_SCRATCH"
export ZIG="$(command -v zig)"
export OZAI_COVERAGE_RT=/absolute/path/to/zig-cov-rt.o
zig run scripts/project_gate.zig -- measure
export OZAI_COVERAGE_POLICY=/absolute/path/to/coverage-policy.json
devenv shell -- gate
# Replay the policy's exact measurement without the other checks:
zig run scripts/project_gate.zig -- validate /absolute/path/to/measurement.json
```

`measure` captures instrumented coverage for Debug and ReleaseSafe under
`GATE_SCRATCH`. Keep its manifest, binaries, reports, and raw counters together.
Prepare an external schema-3 JSON policy from the captured cold tuples and counts.
The policy format is `Ledger` in `scripts/coverage_policy.zig`.
Its `measurement` field names the exact manifest path and SHA-256.
It also requires source/compiler identity, scope, modes, exact cold-item decisions,
and per-mode `unmapped_project` and `unowned` counts with reasons.
Do not commit generated coverage records.

`gate` runs configured checks and uninstrumented tests in both safety modes;
`gate-strict` is the same command.
Set `OZAI_COVERAGE_POLICY` to enable retained coverage replay; invalid or stale records fail.
Line hits do not establish branch coverage, protocol interoperability, or production reachability.

## Layout

- `src/`: library, protocol state machines, native drivers, and examples.
- `test/`: protocol, process, socket, and interoperability tests and binary fixtures.
- `vendor/quic/`: patched sans-IO QUIC core with its upstream license.
- `interop/iroh-peer/`: pinned Rust interoperability peer.
- `scripts/`: strict coverage and static-analysis policy.
- [Architecture](docs/ARCHITECTURE.md): layer boundaries and ownership rules.
- [QUIC provenance](vendor/quic/VENDORED.md): upstream pin and local changes.

## License

This repository does not include a root license. Do not assume a license grant
for first-party code. The vendored QUIC code retains its
[MIT license](vendor/quic/LICENSE).
