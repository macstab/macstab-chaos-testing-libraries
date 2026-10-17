# Security Policy

Report vulnerabilities privately; every report is read and answered.

## Reporting a vulnerability

**Do not open a public GitHub issue for a security vulnerability.**

Email **info@macstab.com** with the subject prefix `[SECURITY]`. Include what you have:

- affected version(s), library (`libchaos-<lib>` or `chaos-init`), libc and architecture
- reproduction steps, a proof of concept, or a failing test case
- impact: what an attacker gains, and what access they need first
- the name or alias to credit, if you want credit

A short report now is more useful than a polished one later; follow-up questions come
by email.

## What you can expect

| When | What happens |
|---|---|
| Within **72 hours** | Acknowledgement that the report was received |
| Within **7 days** | Initial triage: confirmed, needs more information, or out of scope |
| During investigation | Updates as the picture clarifies, usually weekly |
| At fix-ready | Coordinated release date agreed with you; CVE / GHSA requested where applicable |
| **30 days** after the fix release | Public security advisory; reporter credited unless they asked otherwise |

## Supported versions

Security fixes are backported to:

- the current major version: latest minor, latest patch
- the previous major version, for **6 months** after a new major version is released

Older versions receive no security backports. Releases are listed on the
[releases page](https://github.com/macstab/macstab-chaos-testing-libraries/releases).

## Threat model

The libraries are test tooling. They run inside the target process (LD_PRELOAD mode)
or as its supervisor (SECCOMP mode, `chaos-init`), and they trust their rule files:
whoever can write `/tmp/.chaos-<lib>.conf` decides which faults the target sees. The
rules are read from a fixed path in `/tmp`, which any local user can write; the status
and hits files are created with mode 0666. This is a documented design limit
([`docs/SAFETY.md` §9](docs/SAFETY.md#9-config-file-security)); isolate `/tmp` per
container in shared environments.

## In scope

- **Memory safety** in any library or in `chaos-init`: buffer overflows, out-of-bounds
  reads, use-after-free, double free, reachable through an interposed call, a rule
  file, a status or hits file, or a notified system call.
- **Rule-file parsing** that crashes, hangs or misbehaves on malformed input (the
  parsers are fuzzed: `make fuzz`), or a rule that takes effect beyond what its text
  says.
- **Control-file handling**: following a planted symbolic link when creating a status
  or hits file (they are created `O_EXCL`/`O_NOFOLLOW`), or a write outside
  `/tmp/.chaos-*`.
- **Behaviour without rules**: any change to a program's results, `errno` or file
  descriptors while no rule matches. The libraries must be passthrough when idle.
- **`chaos-init`**: privilege gained by the supervised application (the tracee runs
  with `no_new_privs`), reads of processes `chaos-init` did not start, or a filter that
  lets the tracee escape supervision in a way not documented in
  [`docs/SECCOMP.md`](docs/SECCOMP.md).
- **Build and release integrity**: tampered release artifacts, a mismatch between
  release assets and their `SHA256SUMS`, compromise of the build pipeline.

## Not in scope

- **Faults a configured rule asks for.** A program that crashes because a rule made
  `write` fail is the library doing its job.
- **Writing rule files.** Anyone who can write `/tmp/.chaos-<lib>.conf` controls the
  faults by design (see the threat model above).
- **Control of the process environment.** An attacker who sets `LD_PRELOAD` or chooses
  the container entrypoint already controls the process; neither is a trust boundary.
- **Documented coverage gaps**, such as calls the libraries do not interpose,
  statically linked programs under `LD_PRELOAD`, or io_uring in SECCOMP mode.
- **Third-party code** not vendored by this project; report it upstream.

## Credit

Researchers are credited in the published advisory and in the release notes. To stay
anonymous, say so in the report.

## Thanks

Vulnerability research is unpaid and often thankless work that makes everyone safer.
It is appreciated.
