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
  # The house gate: fmt, build, test, ast-check, ziglint, zlint, zbc. The version
  # cross-check runs first because every later step is meaningless against a
  # toolchain the manifest does not describe.
  scripts.gate.exec = ''
    set -eu
    ${pinnedToolPath}
    version="$(zig version)"
    pin="$(sed -n 's/.*\.minimum_zig_version = "\(.*\)".*/\1/p' build.zig.zon)"
    test "$version" = "$pin" || {
      echo "zig $version does not match .minimum_zig_version $pin" >&2
      exit 1
    }
    zig-gate
  '';

  # A second form for design work: the version cross-check plus coverage, no
  # advisory tooling. Kept separate so a failing zbc advisory never blocks.
  scripts.gate-strict.exec = ''
    set -eu
    ${pinnedToolPath}
    version="$(zig version)"
    pin="$(sed -n 's/.*\.minimum_zig_version = "\(.*\)".*/\1/p' build.zig.zon)"
    test "$version" = "$pin" || {
      echo "zig $version does not match .minimum_zig_version $pin" >&2
      exit 1
    }
    zig-gate --no-zbc --cov
  '';

  # See full reference at https://devenv.sh/reference/options/
}