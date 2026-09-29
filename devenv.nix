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
in
{
  inherit packages;

  env = {
    # Zig flocks every global-cache manifest, so a build that dies holding one
    # of those locks wedges every later build wanting the same global cache.
    # A project-local global cache keeps this project independent of that; the
    # cost is one extra compiler_rt build.
    ZIG_GLOBAL_CACHE_DIR = ".zig-global-cache";

    LD_LIBRARY_PATH = lib.makeLibraryPath packages;
    INCLUDE_DIRECTORIES = lib.makeIncludePath packages;
  };

  # https://devenv.sh/basics/
  enterShell = ''
    echo "zig $(zig version 2>/dev/null || echo '<unresolved: check .minimum_zig_version>')"
  '';

  # https://devenv.sh/scripts/
  #
  # The house gate: fmt, build, test, ast-check, zlint, zbc. The version
  # cross-check runs first because every later step is meaningless against a
  # toolchain the manifest does not describe.
  scripts.gate.exec = ''
    set -eu
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
