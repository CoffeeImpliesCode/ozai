{ pkgs, lib, ... }:

# ozai dev environment (house convention, cf. ~/projects/zig-agent-proto,
# ~/projects/topology, ~/projects/wayland).
#
# `packages` deliberately carries no `zig`: on this host `zig` is the anyzig
# shim, which resolves the toolchain by reading `.minimum_zig_version` from
# build.zig.zon. A nixpkgs `zig` here would shadow the shim and build with a
# version the manifest does not describe. The shim also exits 1 with no output
# when it cannot resolve a toolchain, so a bad pin looks like a silent build
# failure; `enterShell` prints the version to make that loud.
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

  # `zig` and `zig-gate` live in the user's own bin directory, which a devenv
  # shell's PATH does not carry — it is assembled from the nix store, so both
  # gate scripts exited 127 at `zig version` before checking anything, and
  # `enterShell` could not print the version it promises to print loudly.
  #
  # This is a shell fragment, not an `env` entry, for two reasons: `$PATH` has
  # to be expanded by the shell that runs it (`${PATH}` in a Nix string is a Nix
  # variable and does not exist), and an `env` PATH would be a literal nobody
  # can predict. It is therefore prepended where it is needed — `enterShell`
  # and the two gate scripts — and `devenv shell -- zig build` still has no
  # `zig`; the build commands belong to a direnv shell, which keeps the PATH
  # the user already had.
  pinnedToolPath = ''export PATH="$HOME/.local/bin:$PATH"'';
in
{
  inherit packages;

  env = {
    ZIG_GLOBAL_CACHE_DIR = zigCache;

    LD_LIBRARY_PATH = lib.makeLibraryPath packages;
    INCLUDE_DIRECTORIES = lib.makeIncludePath packages;
  };

  # https://devenv.sh/basics/
  enterShell = ''
    mkdir -p "$ZIG_GLOBAL_CACHE_DIR"
    ${pinnedToolPath}
    [ -e "$ZIG_GLOBAL_CACHE_DIR/p" ] || ln -s /tmp/zig-global-cache/p "$ZIG_GLOBAL_CACHE_DIR/p"
    echo "zig $(zig version 2>/dev/null || echo '<unresolved: check .minimum_zig_version>')"
  '';

  # https://devenv.sh/scripts/
  #
  # The house gate: `zig-gate`'s sections in order — fmt, build, test,
  # ast-check, ziglint, zlint, zbc, zwanzig, cross-test. The version cross-check
  # above runs first because every later step is meaningless against a
  # toolchain the manifest does not describe. `zbc` is the only advisory
  # section here (`ZBC_STRICT=1` makes it binding) and `cross-test` is the only
  # one that leaves this host, so this gate is as slow as its slowest section.
  #
  # `GATE_EXCLUDE` is the driver's named mechanism for what is not this
  # project's source, and it overrides the built-in default rather than adding
  # to it, so the default's patterns have to be written out here too.
  #
  # `^[.]/vendor/` covers `vendor/quic`, and excluding it is a decision rather
  # than an oversight. It is upstream code carrying its own formatting and its
  # own idioms; reformatting it would bury the patch under thirty thousand
  # lines of noise, and linting it with this project's rules would report
  # findings nobody intends to fix. The patch ozai applies is a named list in
  # `vendor/quic/VENDORED.md`, and that file is the reviewable artefact. The
  # vendored tree is still compiled -- `zig build quic-test` builds it and runs
  # its own tests -- so "not gated" never means "not proved to build".
  #
  # The four cache/output roots are the rest of what is not source. A lint
  # section reads whatever the file list hands it, and a build leaves
  # `.zig-cache/` and `zig-out/` in the tree; reporting build output as a
  # defect is a measurement of build state, not of this repository.
  scripts.gate.exec = ''
    set -eu
    ${pinnedToolPath}
    version="$(zig version)"
    pin="$(sed -n 's/.*\.minimum_zig_version = "\(.*\)".*/\1/p' build.zig.zon)"
    test "$version" = "$pin" || {
      echo "zig $version does not match .minimum_zig_version $pin" >&2
      exit 1
    }
    GATE_EXCLUDE='^[.]/vendor/ /[.]zig-cache/ /zig-out/ /zig-cache/ /zig-global-cache/' zig-gate
  '';

  # The same gate with two changes, and only two. `--no-zbc` drops section 7
  # and nothing else — fmt, build, test, ast-check, ziglint, zlint, zwanzig
  # and cross-test all still run — and `--cov` adds the coverage section on
  # top, advisory until `ZIG_COV_FAIL_UNDER` is set. It is kept separate so a
  # failing zbc advisory never blocks a design pass, and it is not a cheaper
  # gate: only the zbc section is gone.
  scripts.gate-strict.exec = ''
    set -eu
    ${pinnedToolPath}
    version="$(zig version)"
    pin="$(sed -n 's/.*\.minimum_zig_version = "\(.*\)".*/\1/p' build.zig.zon)"
    test "$version" = "$pin" || {
      echo "zig $version does not match .minimum_zig_version $pin" >&2
      exit 1
    }
    GATE_EXCLUDE='^[.]/vendor/ /[.]zig-cache/ /zig-out/ /zig-cache/ /zig-global-cache/' \
      zig-gate --no-zbc --cov
  '';

  # See full reference at https://devenv.sh/reference/options/
}