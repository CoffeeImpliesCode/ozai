# Exercise the full socket/process suite against both Linux x86_64 C libraries.
# Each test uses its matching node artifact; this is not foreign-architecture coverage.
CROSS_BUILD_STEP=test
CROSS_MATRIX=(
    'x86_64-linux-gnu|auto'
    'x86_64-linux-musl|auto'
)