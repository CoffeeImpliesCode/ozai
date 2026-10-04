# Full Linux socket/process suite, including matching foreign node artifacts.
# The portable ABI survey is separate: cross-test.portable.profile.sh.
# n32 and x32 are excluded: Zig 0.16's std.os.linux does not compile for those
# pointer/register-width combinations. The complete survey still records them.
# Full Hexagon Debug socket/node artifacts crash the pinned compiler. Its pure
# modules remain executable in the complete survey.
CROSS_BUILD_STEP=test
# Keep the 6.3 MB receive-window burst intact. Its isolated GNU AArch64 run
# takes minutes under QEMU; bound parallelism and allow emulated execution.
CROSS_JOBS=8
CROSS_BUILD_JOBS=8
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
    'loongarch64-linux-muslf32|auto'
    'loongarch64-linux-muslsf|auto'
    'mipsel-linux-musleabi|auto'
    'mipsel-linux-musleabihf|auto'
    'mips64el-linux-muslabi64|auto'
    'powerpc64le-linux-musl|auto'
    'riscv32-linux-musl|auto'
    'riscv64-linux-musl|auto'
    'x86-linux-musl|auto'
)