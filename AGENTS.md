# ozai — Agent Rules (Zig, hardcore quality)

Instantiated from `~/projects/zig-AGENTS-template.md`. TigerBeetle-style
discipline (loose), aggressive linting, coverage, verification, and a mandatory
post-implementation reviewer workflow. Zig version is pinned in
`build.zig.zon`; every tool follows it.

- Zig: **0.16.0** (pinned in `build.zig.zon`) · VCS: `jj` (colocated git;
  never raw git except `jj git push`)
- New work starts on a **clean change**; parallel work in
  `jj worktree add <path>`
- Reference material is read-only: `~/projects/github-n0-computer-iroh*`.
  Never edit, commit, or add agent rules to a foreign checkout.
- Read before coding: `zig-tiger-style`, `zig-best-practices`,
  `zig-project`, `zig-linting`, `zig-coverage`, `zig-testing`,
  `verification-before-completion`, `code-review`, `jj-core`,
  `using-git-worktrees`

- `zig build test` prints a `failed command:` block above a **green** summary
  for the loopback artifact, and that is not a failure. `Step.result_failed_command`
  is documented as "may be populated even if the step succeeded" and is filled
  before the child is spawned; the build runner prints it whenever a step wrote
  to stderr. `test/expected_log_runner.zig` prints the one error-level log it
  was told to expect, so its step always writes. **The step table and the exit
  code are the truth** — `9/9 steps succeeded`, exit 0. Add
  `--error-style minimal` to drop the command line around it; nothing suppresses
  the message itself, which is correct, since the message is the evidence.

## 1. Golden rules (loose Tiger Style)

Safety > Performance > Developer Experience.

- **Explicit everything**: allocators as params (never global), explicit
  error sets (no `anyerror` in APIs), explicit control flow. No hidden
  allocations, state, or macros.
- **All errors handled**; never discard with `_ =`. Every `if` asks: does the
  `else` need handling? Assert positive AND negative space at boundaries.
- **Assertions** detect programmer errors: pair them (write + read-back),
  split compound (`assert(a); assert(b);`), assert comptime relationships
  (`comptime assert(@sizeOf(NodeId) == 32);`).
- **Loops have fixed upper bounds**; fail fast. Event loops assert
  non-termination.
- **Small functions**: push `if`s up, `for`s down. Parent owns mutable state;
  helpers compute, don't apply.
- **Naming**: fns `camelCase`, types `PascalCase`, vars `snake_case`; units
  appended (`latency_ms_max`); no abbreviations; options-struct for 2+ same-typed
  args; callbacks last, named `<caller>_callback`.
- **Formatting**: `zig fmt`, 100 cols hard limit, braces on multi-line `if`.
  Division explicit: `@divExact`/`@divFloor`/`div_ceil`.
- **Comments say WHY**; an obviously-true assertion beats a comment.
- **No backwards compatibility**: delete, don't deprecate; no
  aliases/shims/unused params.
- **Zero deps unless justified**; scripts as `scripts/*.zig`, not shell.

## 2. Architecture: extreme-testable by default

Mandatory for new code, default for refactors; reviewers enforce it.

- **`io: std.Io` threaded explicitly** (never global) → deterministic
  simulation (VOPR pattern; marionette on 0.16): deterministic Io swap,
  seed+commit reproducibility, time as data. Logic never reads clock/env/cwd —
  lifted inputs. A `localtime()` failure hid a 4-yearly bug behind 100% line
  coverage in another project; a network stack hides at least as much.
- **Network logic is pure over bytes.** Every state machine takes a decoded
  message and a state value and returns a new state plus an action list. No
  socket handle, no clock read, no allocator. This is the single most important
  rule in this file: an iroh-shaped port has hundreds of branches over wire
  bytes, and none of them may touch the network.
- **State is a parameter, not a capture** (`process(e, &count)`); sequence bugs
  like `(5,4)` after `(5,0)` become visible. Pure fns return new state.
- **Split at the bridges**: dispatch → loop + processor; each step provably
  independent. Prime-path count ≈ cyclomatic complexity — keep low.
- **Allocator injection + fail-N**: failing allocator, fail Nth alloc from 0
  until success — every OOM path exercised. Same for I/O errors (Tripwire-style
  injection proves `errdefer` runs).
- **Errors are values**: explicit error sets + comptime error-set sweeps
  (`inline for` over `@typeInfo(ErrorSet)`) exercise every error path at compile
  time.
- **Comptime exhaustiveness**: `try comptime testFn();` / `inline for` over
  enumerable domains — the strongest coverage substitute Zig has. Wire enums
  are enumerable domains; decode every variant in a comptime sweep.
- **`unreachable` is a claim**: marks impossible cases so coverage is honest;
  every uncovered path answered test/refactor/accept, never "test because
  coverage said so".
- **Determinism is a feature**: seeds injected, no wall-clock in logic,
  `Smith` fuzz at every decoder boundary (wire, postcard, varint), metamorphic
  oracles (ticket encode→decode→encode is a fixed point), mutation checks on
  the suite so coverage means detection.
- **Wire compatibility is a test, not a comment.** Any claim of iroh
  interoperability is a golden-vector test carrying bytes captured from the
  Rust implementation, or it is an unverified claim.

A module that can't be deterministically driven or failure-injected is a
review finding, not a documented limitation.

## 3. Before you start

0. **Clean environment first — never lose work to a revert.** `jj st`:
   dirty change? `jj commit -m "wip: ..."` (checkpoint) or a fresh change.
   Baseline tests must pass before the first edit — a red suite is provably
   yours.
1. Read this file again + `README.md`, `TODO.md`, `docs/PLAN.md`,
   `docs/ARCHITECTURE.md`, and the relevant record under `docs/DECISIONS/`.
   Once per task.
2. Bug fixes: **red-green** — failing test first, prove it fails, then fix.
3. Features: agree test seams up front; vertical slices (test → impl →
   repeat), never horizontal dumps.
4. Non-trivial work: state plan (what/where/how verified) before editing;
   check §2 while planning.

## 4. Quality gates — definition of done

`verification-before-completion`: **no completion claim without fresh
evidence in the same turn.** The house driver is `devenv shell -- gate`
(`zig-gate` behind a version cross-check).

| # | Gate | Evidence |
|---|------|----------|
| 1 | Format | `zig fmt --check .` — zero diffs |
| 2 | Build | `zig build -Doptimize=Debug` + `ReleaseSafe` — exit 0 |
| 3 | Tests | `zig build test` Debug + `ReleaseSafe` — all green, zero leaks (`std.testing.allocator`) |
| 4 | Syntax | `zig ast-check` on every changed `.zig` |
| 5 | Compile-all | `refAllDecls` test in each root — unused decls still type-check |
| 6 | Lint | `zlint` — zero errors on changed files |
| 7 | Coverage | measure changed paths (kcov 0.16 / zcov 0.17-dev); every uncovered path: test, refactor, or accept with a written reason |
| 8 | Static analysis | if configured: zwanzig (path-sensitive) / zippy (memory) — zero new findings |
| 9 | Sanitizers | optional: `-fsanitize-c=full`, `-fsanitize-thread`, valgrind |
| 10 | Fuzz | every decoder: `zig build test --fuzz=<bounded>` — no crashes, inputs replayed |

Density rule: 12/357 paths is noise; 352/357 makes each missing path a
judgment call. Coverage guides, never gates alone.

## 5. Reviewer workflow (MANDATORY after every implementation)

Non-optional for changes >1 file or touching shared code:

1. **Self-gates** (§4) — attach raw output (exit codes, counts), no summaries.
2. **Standards axis**: §1 + §2 + §4 + Fowler smells. Repo rules override
   baseline; smells are judgment calls. **§2 is a standard**: hidden
   inputs/state, non-injectable failure paths, non-deterministic seams =
   findings.
3. **Spec axis**: re-read task/issue — missing requirements, scope creep, wrong
   implementations; quote the spec line per finding.
4. **Spawn a reviewer subagent** (non-trivial diffs): diff range + this
   file + task. Reviewer independently runs gates 1–3, 6–8, re-checks
   both axes; findings per file, hard violations vs judgment calls,
   <400 words.
5. **Fix at root cause**; re-run failed gates.
6. **Report** (shape below).

```
GATES: fmt=PASS build=PASS test=Debug 47/47 ReleaseSafe 47/47 leaks=0
       ast=OK refAllDecls=OK lint=0 coverage=NEW 91% (accepted: …)
REVIEW: Standards: N (worst: …) | Spec: N (worst: …)
FIXED: … | SKIPPED (reason): … | DEBT: (ceiling + trigger)
```

## 6. Tooling (pinned to Zig version)

- **One linter, recorded in repo**: `zlint` config in `zlint.json`. Deeper:
  `zwanzig` (path-sensitive CFG/ZIR) + `zippy` (build-graph memory lints) as
  separate opt-in CI jobs.
- **Coverage**: kcov on the global-cache test binary (0.16); zcov on
  0.17-dev.
- **zls** tracks the pinned Zig version. Suppressions are documented decisions,
  never blanket.
- `zig-gate` binaries live in `~/.local/bin` and are version-pinned; they are
  NOT taken from `devenv` `packages`.

## 7. CI (mirror of the gates)

One job per gate group: `fmt → ast-check → test(Debug) →
test(ReleaseSafe) → lint → coverage (artifact + density comment) →
[fuzz: weekly] → [zwanzig/zippy: nightly]`

## 8. Committing

- Conventional Commits (`type(scope): subject`, ≤50 chars); atomic; tests
  pass in the commit.
- **Checkpoint often** (`jj commit -m "wip: ..."`).
- Verification evidence in the body when a gate drove a follow-up fix.
- Red gate blocks the push, not a workaround.

## 9. AI-slop guard (reviewers and agents self-check)

- **Obvious comments** (restating code, dividers, vague TODOs) — remove; KEEP
  why-comments.
- **Over-defensive code** — checks for guaranteed values, multi-layer duplicate
  validation. KEEP boundary validation; prove redundancy before deleting.
- **Excessive complexity** — nesting >3, god fns (>50 lines), long param lists
  (options struct), clever one-liners.
- **Needless abstraction** — single-use wrappers, speculative indirection,
  one-implementer interfaces.
- **Dead code** — unused decls/imports, debug leftovers (`std.debug.print` in
  non-test code).
- **Duplication** — extract only when intent is shared, not incidental
  similarity.
- **Missing tests** — behavior not locked by a regression test → add the
  narrowest test, don't remove code.
- **Oversized modules** — >250 pure LOC must split by responsibility (never
  `utils.zig`), plan shown first.
- **Performance equivalences** — only when provably equivalent; no hot-path
  micro-opts without a benchmark; unsure → SKIP.

When in doubt: **SKIP, don't guess.** Silent skips forbidden; report `N/A`
explicitly.
