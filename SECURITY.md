# Security Policy

Thank you for taking the time to look. Coordinated disclosure protects
users; every report is taken seriously.

## Reporting a vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Email **info@macstab.com** with subject prefix `[SECURITY]`.

Include whatever you have:

- Affected version(s)
- Reproduction steps, proof of concept, or a failing test case
- Impact assessment — what an attacker can do with this
- Your name or alias for credit, if you want one

A short clear report beats a polished one that took three weeks. Send
what you have; we'll come back with questions.

## What you can expect

| When | What happens |
|---|---|
| Within **72 hours**       | Acknowledgement that the report was received |
| Within **7 days**         | Initial triage — confirmed, needs more info, or out of scope |
| During investigation      | Updates as the picture clarifies, usually weekly |
| At fix-ready              | Coordinated release date agreed with you; CVE / GHSA requested where applicable |
| **30 days** post-release  | Public security advisory; reporter credited (unless they asked otherwise) |

## Supported versions

Security fixes are backported to:

- The current major version — latest minor + latest patch
- The previous major version, for **6 months** after a new major releases

Older versions receive no security backports. The current supported list
is visible on the
[releases page](https://github.com/macstab/macstab-chaos-testing-libraries/releases).

## In scope

- Memory safety vulnerabilities in the interposer libraries — buffer
  overflows, use-after-free, double-free, format-string bugs reachable
  via the LD_PRELOAD interface
- Vulnerabilities in scenario-file parsing — path traversal, injection
  via untrusted scenario JSON/config
- Build-system or supply-chain issues — compromised artifacts, tampered
  release binaries, unsigned checksums

## Not in scope

- **Bugs that only manifest when chaos scenarios are intentionally
  configured to inject failures.** That is the library doing its job.
  If you can cause unintended behaviour *without* deliberately configuring
  a chaos scenario — that is a security issue and we want to hear about it.
- Issues in third-party libraries not vendored by this project — please
  report those upstream
- Issues that require an attacker to already control the process
  environment — LD_PRELOAD itself is not a trust boundary against a
  hostile process launcher

## Credit

Researchers are credited in the published advisory and in the release
notes. If you would rather stay anonymous, say so in the report — that
wish is honoured.

## Thanks

Vulnerability reporting is unpaid, frequently thankless work that makes
everyone safer. It is appreciated.
