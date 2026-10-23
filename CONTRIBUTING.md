# Contributing

A change is ready when `make check` passes: clang-format clean, 100 % line coverage of
every shipped source, and the runtime probes green. This file says how to get there
and where each kind of change goes.

## Prerequisites

| Tool | Needed for |
|---|---|
| C99 compiler (gcc or clang) and GNU Make | everything |
| Linux (amd64 or arm64) | `make native`, `make native-init`, `make unit` (the `chaos-init` tests include Linux headers) |
| `clang-format` | `make fmt-check`, `make fmt` |
| gcov (gcc) | `make coverage` |
| Docker with buildx | runtime probes, `make test-matrix`, `make docker-build-all`, `make ci-local`, `demo/`, `benchmark/` |
| clang with libFuzzer | `make fuzz` |
| Python 3 (standard library only) | `benchmark/driver/chaos_bench_driver.py` |

On macOS, run the CI gates in the Linux CI image (`docker/Dockerfile.ci`):

```bash
make ci-local          # fmt-check, unit, coverage, ASan, UBSan, scan-build
make ci-local-unit     # one gate at a time: ci-local-{fmt,unit,coverage,asan,ubsan,scan}
make ci-local-shell    # interactive shell in that image
```

## Everyday commands

```bash
make unit              # build and run every unit binary (test/unit/)
make native            # build/libchaos-<lib>.so for all six libraries
make native-init       # build/chaos-init (static)
make fmt               # rewrite src/ and test/ to the repository style
make check             # fmt-check + coverage + test: the gate a PR must pass
make test-matrix       # glibc and musl probes on linux/amd64 and linux/arm64
make verify-docs       # run every ```sh verified``` block in docs/*.md
```

`make docker-build-all` builds the release assets into `dist/`: the 24 libraries
(6 × glibc/musl × amd64/arm64) and the static `chaos-init-amd64` / `chaos-init-arm64`. Cross compilers are needed only for `make cross-*` outside Docker.

## Repository layout

| Path | Contents |
|---|---|
| `src/common/` | headers every library includes: qualifiers, status and hits files, vDSO clock, sleep |
| `src/core/`, `src/config/`, `src/effects/`, `src/wrappers/` | `libchaos-io`: runtime state, rule parser and fd cache, effect decisions, wrappers |
| `src/net/`, `src/dns/`, `src/time/`, `src/memory/`, `src/process/` | one directory per library: `*_config.c` (rules, reload), `*_actions.c` (effects), wrappers (`*_hooks.c`, or `chaos_net_socket.c`/`_extra.c`/`_wait.c`, `chaos_dns_lookup.c`) |
| `src/init/` | `chaos-init`, the SECCOMP-mode supervisor |
| `test/unit/` | assert-based unit binaries that `#include` the sources they test |
| `test/support/` | per-library test globals and stub real functions |
| `test/runtime/` | Docker and host probes (`*_probe.c` + `test_*.sh`), coverage and format gates |
| `test/fuzz/` | libFuzzer harnesses, one per rule parser |
| `benchmark/` | harness, kernels, scenarios, run script, A/B driver |
| `demo/` | `docker compose` fault profiles |
| `docs/` | subsystem references |
| `.github/workflows/` | `ci`, `matrix`, `codeql`, `bench`, `release` |

## Code rules

- **C99**, built with `-std=c99 -Wall -Wextra -Werror -pedantic`; the shared objects
  add the size flags listed in the README. `-Werror` makes every warning a build break.
- **No allocation on the call path.** Wrappers may run inside a signal handler and
  must not reach an allocator: tables are static or mapped once with a raw `mmap`
  system call.
- **Fail open.** Any internal failure (unresolved symbol, unreadable rule file,
  endpoint lookup error) forwards the call unchanged. Never turn a library error into
  a fault the rules did not ask for.
- **errno discipline.** A wrapper that does not inject leaves `errno` exactly as the
  real function left it; save and restore it around internal calls
  (`test/runtime/test_errno_glibc.sh` enforces this).
- **No self-interposition.** Internal libc calls run with the thread's reentrancy guard
  raised; control-file I/O uses raw system calls, so another library's rules cannot
  fault it.
- **Documentation.** Every file has a `@file` header (purpose, design, invariants,
  thread and signal safety, fork behaviour, failure behaviour); every function a
  contract-first Doxygen block. Comments state why, not what. 100 columns.

## Adding an interposed function

1. **Wrapper.** Add it to the library's wrapper file, exported with
   `CHAOS_<LIB>_EXPORT`. Resolve the real function in the library's
   `chaos_<lib>_ensure_symbols()` through `dlsym(RTLD_NEXT)`, with a raw-syscall
   fallback where a call can arrive before resolution. Follow the existing sequence:
   guard check → rule match → `LATENCY` → errno → real call → post-call effects.
2. **Operation.** Map it onto an existing operation where its semantics match (as
   `fopen` uses `open` rules); add a new operation to the parser only when no
   existing one fits, and update the effect/operation matrix (`*_effect_allowed()`).
3. **Unit test** in `test/unit/test_chaos_<lib>.c`: injected, passthrough and
   reentrant paths. The coverage gate fails on any unexecuted line.
4. **Runtime probe** in `test/runtime/<lib>_probe.c`, run by
   `test_<lib>_glibc.sh` and `test_<lib>_alpine.sh` (io: the probe inside
   `test_glibc.sh` and `test_alpine.sh`). A glibc-only alias goes into
   `test_variants_glibc.sh`.
5. **SECCOMP mode.** If the function is a system call that `chaos-init` must decide,
   add it to the library's list in `src/init/chaos_init_core.c` and map it in
   `src/init/chaos_init_<lib>.c`.
6. **Docs.** `docs/<LIB>.md` and the library's section of `README.md`.

## Adding an effect

1. **Parser.** Recognise it in `src/<lib>/chaos_<lib>_config.c` (`io`:
   `src/config/chaos_io_config.c`), validate its value, and restrict it to the
   operations it is meaningful for in `*_effect_allowed()`.
2. **Behaviour** in `*_actions.c`; every firing passes through `chaos_policy_fire()`,
   so qualifiers and hit counts work without extra code.
3. **SECCOMP mode.** If seccomp cannot carry it out (it changes data the kernel
   moves, or needs the descriptor), reject it in `chaos_init_<lib>_supported()` behind
   `CHAOS_<LIB>_RULE_SUPPORTED`, so the status file says
   `unsupported in seccomp mode` instead of the rule doing nothing.
4. **Tests.** Parser cases in `test/unit/test_<lib>_config.c`, behaviour in
   `test/unit/test_<lib>_actions.c` (io: `test_config_parse.c`, `test_actions.c`),
   valid and invalid forms in `test/unit/test_config_proptest.c`; run the parser's
   libFuzzer harness (`make fuzz`, `test/fuzz/fuzz_<lib>_config.c`).
5. **Docs.** The effect tables in `README.md` and `docs/<LIB>.md`, and the effect
   taxonomy in `docs/DSL.md`.

## Benchmark kernels

New kernels go in `benchmark/kernels/bench_<category>.c` and register with
`CHAOS_BENCH(category, name, state_t, setup, iter, teardown)`;
`benchmark/kernels/bench_meta.c` is the minimal example. Each measured function needs
`<name>_passthrough`, `<name>_match_no_fire` and `<name>_errno`, two scenario files in
`benchmark/scenarios/`, and a `run_trio` line in `benchmark/run-bench.sh`. Details:
[`benchmark/README.md`](benchmark/README.md).

```bash
./benchmark/run-bench.sh --smoke              # clock_gettime cells only
./benchmark/run-bench.sh --full --compare     # every cell, then the A/B driver
```

Docker numbers are `ADVISORY`. Release-grade numbers need bare-metal Linux with
`isolcpus`, `nohz_full` and the `performance` governor.

## Commits

Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/):
`type(scope): subject`, one logical change per commit. git-cliff (`cliff.toml`) builds
`CHANGELOG.md` from them at release time and drops anything unconventional.

| Type | CHANGELOG group |
|---|---|
| `feat` | Features |
| `fix` | Bug Fixes |
| `perf` | Performance |
| `refactor` | Refactoring |
| `docs` | Documentation |
| `test` | Testing |
| `chore` | Miscellaneous |
| `ci` | CI |
| `build` | Build |

Mark an incompatible change (rule grammar, file paths, status or hits format, exported
symbols) with `!` after the type or a `BREAKING CHANGE:` footer. Releases follow
[`RELEASING.md`](RELEASING.md): a `develop` → `main` pull request gated by the benchmark
check, then a bare semantic-version tag (`1.2.3`) that `.github/workflows/release.yml`
builds, checks and publishes.

## Pull requests

- One logical change per PR, with its tests: a new wrapper, effect or kernel without
  a test does not pass the coverage gate.
- `make check` passes locally (or `make ci-local` on macOS).
- Behaviour changes update the README section and `docs/` page they affect in the same
  PR.
- Keep PRs reviewable: a reviewer reads every line.
