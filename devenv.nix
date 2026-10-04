{ pkgs, lib, ... }:

# ozai dev environment (house convention, cf. ~/projects/zig-agent-proto,
# ~/projects/topology, ~/projects/wayland).
#
# `packages` deliberately carries no `zig`: on this host `zig` is the anyzig
# shim, which resolves the toolchain by reading `.minimum_zig_version` from
# build.zig.zon. A nixpkgs `zig` here would shadow the shim and build with a
# version the manifest does not describe. The shim also exits 1 with no output
# when it cannot resolve a toolchain, so a bad pin looks like a silent build
# failure; the gate below names a compiler instead of relying on it.
let
  packages = with pkgs; [
    bash
    git
    pkg-config
  ];

  # Zig flocks every global-cache manifest. A build that dies holding one of
  # its manifest locks wedges every later build that wants the same cache, so
  # each project gets its own root under the node-local scratch disk.
  #
  # The anyzig shim resolves its toolchain through this same variable, at
  # `<root>/p/<hash>`. A root without `p` makes the shim re-fetch the tarball
  # from ziglang.org, fail extraction, and exit 1 in silence, so `p` is a
  # symlink to the one shared toolchain store: build caches stay per-project,
  # downloaded toolchains stay shared.
  zigCache = "/tmp/zig-caches/ozai";

  # The *local* cache is the other one, and it is where the 14 GiB went. Zig
  # keys it on a hash of the build graph, so every configuration gets its own
  # tree and nothing is ever compacted. It follows `--cache-dir`, not
  # `ZIG_GLOBAL_CACHE_DIR`, so without this a build writes `.zig-cache` into the
  # project directory — on the NFS export, not on local disk. The same reasoning
  # is why TMPDIR moves. These are the values `.envrc` sets for a direnv shell,
  # repeated here because the gate runs in a devenv shell, where `.envrc` was
  # never evaluated. Nothing here prunes or deletes a cache: `zig build --help`
  # lists the prune flag, and that is the tool for it.
  zigLocalCache = "/tmp/cache/ozai/.zig-cache";
  zigScratch = "/tmp/scratch/ozai";

  # `zig` and the house gate tools live in the user's own bin directory, which a
  # devenv shell's PATH does not carry — it is assembled from the nix store, so
  # both gate scripts exited 127 at `zig version` before checking anything, and
  # `enterShell` could not print the version it promises to print loudly.
  #
  # This is a shell fragment, not an `env` entry, for two reasons: `$PATH` has
  # to be expanded by the shell that runs it (`${PATH}` in a Nix string is a Nix
  # variable and does not exist), and an `env` PATH would be a literal nobody
  # can predict. It is therefore prepended where it is needed — `enterShell`
  # and the gate scripts.
  pinnedToolPath = ''export PATH="$HOME/.local/bin:$PATH"'';

  # The gate is the repository's own driver, not a global wrapper.
  #
  # `zig-gate` is the house wrapper, and it resolves its toolchain through the
  # anyzig shim, which on this host re-downloads the pinned release and exits 1
  # in silence — the recorded audit ran every check by invoking the pinned
  # compiler directly instead. `scripts/gate.zig` takes the compiler as data:
  # `OZAIGATE_ZIG` when the caller named one, otherwise whatever `zig` resolves
  # to here. The driver cross-checks that compiler against
  # `.minimum_zig_version` before it runs anything, and the receipt names and
  # hashes the file it resolved to. Nothing is installed, repaired or replaced
  # to make this work, and no user-wide wrapper is touched.
  #
  # What the driver does not do: `cross-test` is a portability survey over
  # foreign targets driven by `cross-test.profile.sh`, not a native gate, and it
  # stays the separate documented command it already is.
  gatePrelude = ''
    set -eu
    ${pinnedToolPath}
    compiler="${OZAIGATE_ZIG:-$(command -v zig)}"
    export OZAIGATE_ZIG="$compiler"
    # The scratch root the driver builds, caches, prefixes and writes its
    # receipt under. It defaults under `$TMPDIR` — local disk, already the
    # project's — and a caller with its own approved root names it in
    # `OZAIGATE_SCRATCH`. It is a named variable rather than a literal in each
    # script so the two scripts below cannot disagree about where a run wrote.
    scratch="${OZAIGATE_SCRATCH:-$TMPDIR/gate}"
    mkdir -p "$scratch"
    export OZAIGATE_SCRATCH="$scratch"
  '';
in
{
  inherit packages;

  env = {
    ZIG_GLOBAL_CACHE_DIR = zigCache;
    ZIG_LOCAL_CACHE_DIR = zigLocalCache;
    TMPDIR = zigScratch;
    # `TMP` and `TEMP` are the same root under the other two names. The driver
    # refuses to run unless all three are set and safe: a child that falls
    # back to `/tmp` is a child writing to a node-shared volume this project
    # has no business writing to, and the refusal is the whole point.
    TMP = zigScratch;
    TEMP = zigScratch;
    CROSS_JOBS = "8";
    CROSS_BUILD_JOBS = "8";

    LD_LIBRARY_PATH = lib.makeLibraryPath packages;
    INCLUDE_DIRECTORIES = lib.makeIncludePath packages;
  };

  # https://devenv.sh/basics/
  enterShell = ''
    mkdir -p "$ZIG_GLOBAL_CACHE_DIR" "$ZIG_LOCAL_CACHE_DIR" "$TMPDIR"
    ${pinnedToolPath}
    [ -e "$ZIG_GLOBAL_CACHE_DIR/p" ] || ln -s /tmp/zig-global-cache/p "$ZIG_GLOBAL_CACHE_DIR/p"
    echo "zig $(zig version 2>/dev/null || echo '<unresolved: check .minimum_zig_version>')"
  '';

  # https://devenv.sh/scripts/
  #
  # The documented entry point. Every group the driver defines runs unless the
  # arguments name a subset, both safety modes are inside the compile groups,
  # and every output — the install prefix, the build cache, the receipt — lands
  # under the scratch root named above rather than in the working tree. The
  # driver refuses an absent or unsafe `TMPDIR`/`TMP`/`TEMP`/cache variable
  # before it spawns anything, so those five names are set by `env` above rather
  # than left to the compiler's defaults.
  #
  # Required absent tools are recorded `not_available` and fail the run.
  # Optional zwanzig is binding when present; its absence is N/A.
  # Unconfigured zippy and sanitizers are recorded `not_configured`, not PASS.
  scripts.gate.exec = gatePrelude + ''
    exec "$compiler" run scripts/gate.zig -- --scratch "$scratch" "$@"
  '';

  # Every group except `static`, and it is named for exactly that rather than
  # for being stricter: `static` is where `zbc` runs and where its triage binds,
  # so leaving it out is leaving a configured check unrun. `gate` above is the
  # whole thing; this is a design pass in which a static-analysis finding
  # cannot block, not a cheaper gate and not a stricter one.
  #
  # Coverage is *not* part of either script — the driver runs builds, and the
  # instrumented run is still `zig-cov test` with `-Dcoverage-rt`, which is what
  # supplies the runtime object. That command is unchanged, and this script does
  # not re-implement it.
  scripts.gate-design.exec = gatePrelude + ''
    exec "$compiler" run scripts/gate.zig -- --scratch "$scratch" \
      --group compiler --group fmt --group ast --group refdecls \
      --group compile-all --group build --group test --group portable \
      --group fuzz --group lint "$@"
  '';

  # See full reference at https://devenv.sh/reference/options/
}