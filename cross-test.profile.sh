# Full Linux socket/process suite, including matching foreign node artifacts.
# The portable ABI survey is separate: cross-test.portable.profile.sh.
# n32, x32, and full Hexagon socket/node artifacts are excluded here.
# The portable survey keeps these targets visible.
# LoongArch64 covers canonical musl (lp64d) and soft-float (lp64s).
CROSS_BUILD_STEP=test
# Native test rows need the detected host loader on Nix, not a deployment path.
CROSS_BUILD_ARGS=(-Dnative-test-linker=true)
# Keep the 6.3 MB receive-window burst intact. Its isolated GNU AArch64 run
# takes minutes under QEMU; bound parallelism and allow emulated execution.
CROSS_JOBS=2
CROSS_TIMEOUT=900
CROSS_BUILD_TIMEOUT=2700
CROSS_MATRIX=(
    'x86_64-linux-gnu|auto'
    'x86_64-linux-musl|auto'
    'arm-linux-musleabi|auto'
    'arm-linux-musleabihf|auto'
    'thumb-linux-musleabi|auto'
    'thumb-linux-musleabihf|auto'
    'aarch64-linux-musl|auto'
    'loongarch64-linux-musl|auto'
    'loongarch64-linux-muslsf|auto'
    'mipsel-linux-musleabi|auto'
    'mipsel-linux-musleabihf|auto'
    'mips64el-linux-muslabi64|auto'
    'powerpc64le-linux-musl|auto'
    'riscv32-linux-musl|auto'
    'riscv64-linux-musl|auto'
    'x86-linux-musl|auto'
)