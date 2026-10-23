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
    binutils
    llvmPackages.llvm
    coreutils
    util-linux
    gnused
    gawk
    inetutils
  ];


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
  # The installed x86_64 ZBC ELF requires GLIBC_2.36. Invoke its loader
  # explicitly on Nix hosts without /lib64, with libc from the same package.
  zbcRuntime =
    assert pkgs.stdenv.hostPlatform.system == "x86_64-linux";
    assert lib.versionAtLeast pkgs.glibc.version "2.36";
    lib.getLib pkgs.glibc;
in
{
  inherit packages;

  env = {
    LD_LIBRARY_PATH = lib.makeLibraryPath packages;
    INCLUDE_DIRECTORIES = lib.makeIncludePath packages;
    OZAI_ZBC_LOADER = "${zbcRuntime}/lib/ld-linux-x86-64.so.2";
    OZAI_ZBC_LIBRARY_PATH = "${zbcRuntime}/lib";
    ZWANZIG_ARGS = "--max-states-per-point 200";
  };

  # https://devenv.sh/basics/
  enterShell = ''
    ${pinnedToolPath}
    . "$HOME/.local/lib/host-scratch.sh"
    : "''${HOST_SCRATCH_ROOT:?host scratch helper did not select a root}"
    echo "zig $(zig version 2>/dev/null || echo '<unresolved: check .minimum_zig_version>')"
  '';

  # https://devenv.sh/scripts/
  #
  # The house gate: `zig-gate`'s sections in order — fmt, build, test,
  # ast-check, ziglint, zlint, zbc, zwanzig, cross-test. The version cross-check
  # above runs first because every later step is meaningless against a
  # toolchain the manifest does not describe. Every configured check, including
  # zbc, is binding; cross-test is the only check that leaves this host.
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
  # Both entry points run the same project-owned fail-closed policy. Coverage
  # reports, raw counters, executables and command logs remain on host scratch.
  scripts.gate.exec = ''
    set -eu
    ${pinnedToolPath}
    . "$HOME/.local/lib/host-scratch.sh"
    : "''${HOST_SCRATCH_ROOT:?host scratch helper did not select a root}"
    export ZIG="''${ZIG:-$(command -v zig)}"
    export OZAI_COVERAGE_RT="''${OZAI_COVERAGE_RT:-$HOME/tools/zcov/zig-out/lib/zig-cov-rt.o}"
    export ZIG_LOCAL_CACHE_DIR="''${ZIG_LOCAL_CACHE_DIR:-$HOST_SCRATCH_ROOT/scratch/gate-driver-cache}"
    exec "$ZIG" run --cache-dir "$ZIG_LOCAL_CACHE_DIR" scripts/project_gate.zig -- gate
  '';

  scripts.gate-strict.exec = ''
    exec gate "$@"
  '';

  # See full reference at https://devenv.sh/reference/options/
}