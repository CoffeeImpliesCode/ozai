{ pkgs, lib, ... }:
let
  packages = with pkgs; [
    bash
    git
    pkg-config
    binutils
    llvmPackages.llvm
    coreutils
    util-linux
    python3
    iproute2
    nftables
    procps
    gnused
    gawk
    inetutils
  ];
  # Keep Zig from PATH. The pinned nixpkgs does not provide Zig 0.17.0.
  toolSetup = ''
    export ZIG="''${ZIG:-$(command -v zig)}"
    if [ "$("$ZIG" version)" != 0.17.0 ]; then
      echo 'ozai requires Zig 0.17.0 on PATH' >&2
      exit 1
    fi
    export GATE_SCRATCH="''${GATE_SCRATCH:-''${XDG_CACHE_HOME:-$HOME/.cache}/ozai/scratch}"
    mkdir -p -m 700 "$GATE_SCRATCH"
    export ZIG_LOCAL_CACHE_DIR="''${ZIG_LOCAL_CACHE_DIR:-''${XDG_CACHE_HOME:-$HOME/.cache}/ozai/zig-local}"
    mkdir -p "$ZIG_LOCAL_CACHE_DIR"
  '';
  # The optional native ZBC executable can use a matching Nix glibc loader.
  nativeZbc = pkgs.stdenv.hostPlatform.system == "x86_64-linux";
  zbcRuntime = lib.getLib pkgs.glibc;
in
{
  inherit packages;
  env = {
    LD_LIBRARY_PATH = lib.makeLibraryPath packages;
    INCLUDE_DIRECTORIES = lib.makeIncludePath packages;
    ZWANZIG_ARGS = "--max-states-per-point 200";
  } // lib.optionalAttrs nativeZbc {
    OZAI_ZBC_LOADER = "${zbcRuntime}/lib/ld-linux-x86-64.so.2";
    OZAI_ZBC_LIBRARY_PATH = "${zbcRuntime}/lib";
  };

  enterShell = toolSetup;

  scripts.gate.exec = ''
    set -eu
    ${toolSetup}
    exec "$ZIG" run --cache-dir "$ZIG_LOCAL_CACHE_DIR" scripts/project_gate.zig -- gate
  '';

  scripts.gate-strict.exec = ''
    exec gate "$@"
  '';
}
