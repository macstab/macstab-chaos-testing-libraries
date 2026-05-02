# Contributing

## Prerequisites

- GCC or Clang (C11)
- GNU Make
- Docker + buildx (for cross-compilation and integration tests)
- Python 3.11+ (for the benchmark driver)
- Linux x86_64 or arm64 recommended; macOS works for unit tests

```bash
make unit          # compile and run all unit tests
make native        # build native .so for the current host
make docker-build  # full cross-build via Docker (glibc + musl, amd64 + arm64)
```

No other installation is required — all cross-compilers run inside Docker.

## Repository layout

| Path | What lives here |
|------|----------------|
| `src/` | Library source — one subdirectory per library (`io`, `net`, `dns`, `time`, `memory`, `process`) |
| `test/unit/` | Unity-based unit tests (fast, no Docker required) |
| `test/runtime/` | Shell integration tests (run via Docker against the built `.so`) |
| `test/proptest/` | Property-based tests |
| `benchmark/` | Harness, kernels, driver, and run scripts |
| `docs/` | Markdown documentation |
| `scripts/` | Build and validation helpers |
| `.github/workflows/` | CI (ci, matrix, bench, codeql, release) |

## Commit conventions

This project uses [Conventional Commits](https://www.conventionalcommits.org/):

| Prefix | Effect |
|--------|--------|
| `feat:` | bumps MINOR version |
| `fix:` / `perf:` | bumps PATCH version |
| `feat!:` / `fix!:` or `BREAKING CHANGE:` footer | bumps MAJOR version |
| `chore:` / `docs:` / `test:` / `refactor:` | no version bump |

## Code style

- C11, `-std=c11 -pedantic -Wall -Wextra -Werror`
- No dynamic allocation in the hot path
- Every public symbol is documented with a Doxygen block
- Run `make unit` before pushing — CI enforces `-Werror`

## Adding a new interception point

1. Add the syscall wrapper in `src/<library>/chaos_<lib>_hooks.c`
2. Implement the scenario evaluation logic — delegate to the shared
   scenario engine in `src/common/`
3. Add a `CHAOS_HOOK` registration entry
4. Write a unit test in `test/unit/test_<lib>.c`
5. Write an integration test in `test/runtime/test_<libc>.sh`
6. Document the new hook in `docs/<LIB>.md`

## Adding a new scenario effect

1. Define the effect enum value in the public header
2. Implement the evaluation function in `src/common/chaos_scenario.c`
3. Add JSON parsing for the new field in `src/common/chaos_config.c`
4. Cover it with a property test in `test/proptest/`

## Benchmark kernels

New benchmark kernels go in `benchmark/kernels/bench_<category>.c`.
Register each kernel with the `CHAOS_BENCH(...)` macro. See
`benchmark/kernels/bench_meta.c` for a minimal example.

Run locally:

```bash
./benchmark/run-bench.sh --smoke            # quick sanity check (~10 s)
./benchmark/run-bench.sh --full --compare   # full sweep with baseline vs LD_PRELOAD
```

For cycle-accurate numbers use a bare-metal Linux host with
`isolcpus` / `nohz_full` and `governor=performance`.

## Pull requests

- One logical change per PR
- Tests required for new hooks, effects, and benchmark kernels
- `make unit` must pass locally before opening a PR
- For breaking API changes, add a `BREAKING CHANGE:` footer to the
  commit message
- Keep PRs focused — reviewers are humans
