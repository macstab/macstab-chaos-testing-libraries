# Changelog

All notable changes to this project will be documented in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] — 2026-10-25

### Bug Fixes

- **io:** Resolve libc symbols lazily so wrappers survive early constructors ([8be40ec](https://github.com/macstab/macstab-chaos-testing-libraries/commit/8be40ec1b6127f703077ff90e7ba7e6f8e7f4990))
- **io:** Resolve libc symbols lazily so wrappers survive early constructors ([7300ddd](https://github.com/macstab/macstab-chaos-testing-libraries/commit/7300ddd35c77899f5fc7e08a0df8a9842ddefe88))
- **io:** Resolve libc symbols lazily so wrappers survive early constructors ([#28](https://github.com/macstab/macstab-chaos-testing-libraries/issues/28)) ([fe6f523](https://github.com/macstab/macstab-chaos-testing-libraries/commit/fe6f5232a11dc1fecccfe76ff7e5158f237c15ee))
- MPTCP fallback connections under chaos-init; fewer net lookups on non-sockets ([#42](https://github.com/macstab/macstab-chaos-testing-libraries/issues/42)) ([4d4303d](https://github.com/macstab/macstab-chaos-testing-libraries/commit/4d4303d09e83526dca75ad33979dc92c9eda4c73))
- **bench:** Gate only between sweeps on the same CPU model; skip Markdown-only PRs ([94966b3](https://github.com/macstab/macstab-chaos-testing-libraries/commit/94966b3b9c1ef1e50ec3729be3f6a969f78095c1))

### Build

- **release:** Ship chaos-init-amd64 and chaos-init-arm64 ([032770b](https://github.com/macstab/macstab-chaos-testing-libraries/commit/032770bd6cf314b7ed2309bcec1db33a7f4bbef5))
- **changelog:** Make bare x.y.z tags the changelog version boundaries ([6efb3eb](https://github.com/macstab/macstab-chaos-testing-libraries/commit/6efb3eb7a8dbecd922d6edde677930fc37ce8214))

### CI

- A release pipeline with valid benchmarks, a pre-release gate and a runbook ([#41](https://github.com/macstab/macstab-chaos-testing-libraries/issues/41)) ([1952666](https://github.com/macstab/macstab-chaos-testing-libraries/commit/195266656ec41970e25de0b0dc1c76a8cd61ec81))

### Documentation

- Update CHANGELOG for 1.0.1 ([#25](https://github.com/macstab/macstab-chaos-testing-libraries/issues/25)) ([08cbb25](https://github.com/macstab/macstab-chaos-testing-libraries/commit/08cbb252c6e5c5f6b19fb49393fc016550875fa6))
- **bench:** Add 1.0.1-benchmarks.md ([#26](https://github.com/macstab/macstab-chaos-testing-libraries/issues/26)) ([f2fec58](https://github.com/macstab/macstab-chaos-testing-libraries/commit/f2fec5846fada4f85fcb2dc1df38cfe48424dcf5))
- **bench:** Add 1.0.1-benchmarks.md ([#29](https://github.com/macstab/macstab-chaos-testing-libraries/issues/29)) ([e52c280](https://github.com/macstab/macstab-chaos-testing-libraries/commit/e52c2805585aa98018af185a6bd0b12599aa47a6))
- **bench:** Add 1.0.1-benchmarks.md ([#31](https://github.com/macstab/macstab-chaos-testing-libraries/issues/31)) ([54043a2](https://github.com/macstab/macstab-chaos-testing-libraries/commit/54043a2c62f4117941d1724938661f3f0c0b7926))
- Update CHANGELOG for 2.0.0 ([#36](https://github.com/macstab/macstab-chaos-testing-libraries/issues/36)) ([488a464](https://github.com/macstab/macstab-chaos-testing-libraries/commit/488a464b4fd5b67751d23f28486b8de6f555f8af))
- **bench:** Add 2.0.0-benchmarks.md ([#37](https://github.com/macstab/macstab-chaos-testing-libraries/issues/37)) ([b180199](https://github.com/macstab/macstab-chaos-testing-libraries/commit/b1801991b29144f2ecd1cfeb91ef2f656204e3dc))
- Update CHANGELOG for 2.0.0 ([#45](https://github.com/macstab/macstab-chaos-testing-libraries/issues/45)) ([fd37c70](https://github.com/macstab/macstab-chaos-testing-libraries/commit/fd37c70984f5e5cd280c0a0160c89a16e3a8f4df))
- Update CHANGELOG for 2.0.0 ([#47](https://github.com/macstab/macstab-chaos-testing-libraries/issues/47)) ([11322e4](https://github.com/macstab/macstab-chaos-testing-libraries/commit/11322e49577247c15d0b49d6ec3a161ad91d68fd))
- **bench:** Add 2.0.0-benchmarks.md ([#48](https://github.com/macstab/macstab-chaos-testing-libraries/issues/48)) ([0d8a6e0](https://github.com/macstab/macstab-chaos-testing-libraries/commit/0d8a6e09e8fb618a1b9f04dc5672a2d86aca92e3))

### Features

- SECCOMP injection mode (chaos-init), review fixes, full coverage ([#33](https://github.com/macstab/macstab-chaos-testing-libraries/issues/33)) ([c3dde32](https://github.com/macstab/macstab-chaos-testing-libraries/commit/c3dde32e3e8012402e24287ccee7675901584ae5))

### Miscellaneous

- Sync main into develop after 1.0.1 ([#27](https://github.com/macstab/macstab-chaos-testing-libraries/issues/27)) ([2e6599a](https://github.com/macstab/macstab-chaos-testing-libraries/commit/2e6599a723178152cf95e6a2e86ff4ddea40a1b0))
- Sync main into develop after 1.0.1 ([#30](https://github.com/macstab/macstab-chaos-testing-libraries/issues/30)) ([ab2fc5b](https://github.com/macstab/macstab-chaos-testing-libraries/commit/ab2fc5bac78535a6b3ff436eba390454487ec275))
- Sync main into develop ([8327f2a](https://github.com/macstab/macstab-chaos-testing-libraries/commit/8327f2ad345de4a88d39ca5b6da924d920b43bbc))
- Sync main into develop after 2.0.0 ([#38](https://github.com/macstab/macstab-chaos-testing-libraries/issues/38)) ([2dfc449](https://github.com/macstab/macstab-chaos-testing-libraries/commit/2dfc449ad61035b643647578e1da7add8e0fb668))
- Sync main into develop after 2.0.0 ([#39](https://github.com/macstab/macstab-chaos-testing-libraries/issues/39)) ([616e28b](https://github.com/macstab/macstab-chaos-testing-libraries/commit/616e28bcc3776c9d8b325de8316514836c9a7a9b))
- Sync main into develop before 2.0.1 ([#43](https://github.com/macstab/macstab-chaos-testing-libraries/issues/43)) ([1f8b786](https://github.com/macstab/macstab-chaos-testing-libraries/commit/1f8b786dd25b77667ed3767cbf6a4f59fb22d92d))
- Record main as merged for the 2.0.1 release ([0288f90](https://github.com/macstab/macstab-chaos-testing-libraries/commit/0288f90342d9ec3f02962fac5335ae04a2d16261))

### Performance

- Fork children store only the per-process state that changed ([ae03bf4](https://github.com/macstab/macstab-chaos-testing-libraries/commit/ae03bf4569b2e65c44631e555e17881f747086d7))
- **net:** Resolve the second end of a connection only when it could win ([6ca5986](https://github.com/macstab/macstab-chaos-testing-libraries/commit/6ca59861171c8d6e055fa2fe34eb13c667c5082b))
- **io:** Resolve a new descriptor's path at its first rule check, not at open ([88f6407](https://github.com/macstab/macstab-chaos-testing-libraries/commit/88f6407bf116471f484ca2183c37cbe9b31969a8))

### Testing

- **io:** Cover concurrent symbol resolution; document the ordering contract ([d3c47d3](https://github.com/macstab/macstab-chaos-testing-libraries/commit/d3c47d338a3fd68a22b58ea8f9d3a2a354b35865))

## [1.0.1] — 2026-09-28

### Bug Fixes

- Improve changelog PR creation to handle post-release automation edge cases ([4b93329](https://github.com/macstab/macstab-chaos-testing-libraries/commit/4b93329c158b7c8fa0cce37e29b4e75cb802299e))
- **net:** Bound UNIX sun_path scan by address_length ([7140af3](https://github.com/macstab/macstab-chaos-testing-libraries/commit/7140af3e92af0937b8427c7c2f95a31913ed41d7))

### Documentation

- Update CHANGELOG for 1.0.0 ([#20](https://github.com/macstab/macstab-chaos-testing-libraries/issues/20)) ([ba054b4](https://github.com/macstab/macstab-chaos-testing-libraries/commit/ba054b4e5c857cb01093a504ba74add672b4de87))
- **bench:** Add 1.0.0-benchmarks.md ([#21](https://github.com/macstab/macstab-chaos-testing-libraries/issues/21)) ([41e0c2f](https://github.com/macstab/macstab-chaos-testing-libraries/commit/41e0c2f6ce9166f28f0d8b830ab3d9701bdc43f9))
- **demo:** Add runnable per-fault demo profiles ([4162de0](https://github.com/macstab/macstab-chaos-testing-libraries/commit/4162de0d0e7ba1cdc91635ef34b9c14ed479325f))

### Miscellaneous

- Sync main into develop after 1.0.0 ([46eec28](https://github.com/macstab/macstab-chaos-testing-libraries/commit/46eec28679528989cfdddb613cf7c9b646693d3e))
- Add Apache-2.0 LICENSE file ([9513472](https://github.com/macstab/macstab-chaos-testing-libraries/commit/9513472745a16dc8994567faa190c8e41575b0c0))
- Ignore Python bytecode caches ([597f7c7](https://github.com/macstab/macstab-chaos-testing-libraries/commit/597f7c7d388a8c31ee8b329542da2c7ab69880d7))

### Refactoring

- Remove unused `run_trio` function from benchmarking script ([8429118](https://github.com/macstab/macstab-chaos-testing-libraries/commit/8429118b32a57bfe6c8e167a1d91e726ec28a2f8))

## [1.0.0] — 2026-05-03

### Bug Fixes

- **ci:** Fixing the workflow ([#3](https://github.com/macstab/macstab-chaos-testing-libraries/issues/3)) ([4f38268](https://github.com/macstab/macstab-chaos-testing-libraries/commit/4f38268e9e8eedb2ff9ed47037e3bbc01a6363c6))
- Make release workable ([#7](https://github.com/macstab/macstab-chaos-testing-libraries/issues/7)) ([68429c4](https://github.com/macstab/macstab-chaos-testing-libraries/commit/68429c4d65a6a25bf7613f1222e0f73105f64120))
- Correct release ([#8](https://github.com/macstab/macstab-chaos-testing-libraries/issues/8)) ([6b0a232](https://github.com/macstab/macstab-chaos-testing-libraries/commit/6b0a232a341574a14f1aa05f2792bae5daa0bc22))
- Refactor release workflow to improve changelog automation and remove unused bot token checks. ([11646f1](https://github.com/macstab/macstab-chaos-testing-libraries/commit/11646f109d340d0848c4496bcd9988ed99c16e1e))
- Refactor release workflow to improve changelog automation and remove unused bot token checks. ([f58fedb](https://github.com/macstab/macstab-chaos-testing-libraries/commit/f58fedb55671383ffcef1880893552bdc875b736))
- Add release-over-release benchmarking and regression gating to release workflow ([9c72734](https://github.com/macstab/macstab-chaos-testing-libraries/commit/9c72734045f5803ab57a6e959a72a4aebe4af513))
- Scope chaos rules to target-specific patterns to avoid matching harness calls ([7d2f39d](https://github.com/macstab/macstab-chaos-testing-libraries/commit/7d2f39d416504da6f9e5dae6c2de0b4e15740e48))

### CI

- Use semver glob tag trigger without v prefix ([#5](https://github.com/macstab/macstab-chaos-testing-libraries/issues/5)) ([724dd81](https://github.com/macstab/macstab-chaos-testing-libraries/commit/724dd81dd1fa2fd77bc673242ee6a424da146ab9))
- Use semver glob tag trigger without v prefix ([#5](https://github.com/macstab/macstab-chaos-testing-libraries/issues/5)) ([#6](https://github.com/macstab/macstab-chaos-testing-libraries/issues/6)) ([9065d2a](https://github.com/macstab/macstab-chaos-testing-libraries/commit/9065d2ae260b8237ce66fc7dad9999b4300aa336))

### Documentation

- Update CHANGELOG for 1.0.0 ([#9](https://github.com/macstab/macstab-chaos-testing-libraries/issues/9)) ([450b48b](https://github.com/macstab/macstab-chaos-testing-libraries/commit/450b48b6e535a19e293293657e950e3204c2e200))
- Update CHANGELOG for 1.0.0 ([#10](https://github.com/macstab/macstab-chaos-testing-libraries/issues/10)) ([433dd9b](https://github.com/macstab/macstab-chaos-testing-libraries/commit/433dd9b665d87e52bf2215fabebff6aa054b7cb7))
- Update CHANGELOG for 1.0.0 ([#11](https://github.com/macstab/macstab-chaos-testing-libraries/issues/11)) ([ffc58a5](https://github.com/macstab/macstab-chaos-testing-libraries/commit/ffc58a519ceacf651bc143e9f517e4a6859d5ec7))
- Update CHANGELOG for 1.0.0 ([#12](https://github.com/macstab/macstab-chaos-testing-libraries/issues/12)) ([e5bcc75](https://github.com/macstab/macstab-chaos-testing-libraries/commit/e5bcc7502d476d9787bfe44818684a6b06afe31c))
- **bench:** Add 1.0.0-benchmarks.md ([#13](https://github.com/macstab/macstab-chaos-testing-libraries/issues/13)) ([a0278d0](https://github.com/macstab/macstab-chaos-testing-libraries/commit/a0278d0d1fb19d7e9fce70b8a13f737982f34f69))
- Update CHANGELOG for 1.0.0 ([#15](https://github.com/macstab/macstab-chaos-testing-libraries/issues/15)) ([5509824](https://github.com/macstab/macstab-chaos-testing-libraries/commit/5509824a452ee26c3acac71ece3eab4d40a41c38))
- **bench:** Add 1.0.0-benchmarks.md ([#16](https://github.com/macstab/macstab-chaos-testing-libraries/issues/16)) ([3be92ac](https://github.com/macstab/macstab-chaos-testing-libraries/commit/3be92ac243557c412791792db871b6955948870c))
- **bench:** Add 1.0.0-benchmarks.md ([#18](https://github.com/macstab/macstab-chaos-testing-libraries/issues/18)) ([f8e468e](https://github.com/macstab/macstab-chaos-testing-libraries/commit/f8e468e1af13c727c4c76baea092f52cc50c83ad))
- Update CHANGELOG for 1.0.0 ([#19](https://github.com/macstab/macstab-chaos-testing-libraries/issues/19)) ([b135ac5](https://github.com/macstab/macstab-chaos-testing-libraries/commit/b135ac5f18d0b5be6d38b1ca9fd4ae71dd558175))

### Features

- Initial release  ([ecf0e0e](https://github.com/macstab/macstab-chaos-testing-libraries/commit/ecf0e0ea16aae0ce8c94f1f0e04e05bd8484c402))
- Add benchmark matrix generation and upload to release workflow ([ee1b015](https://github.com/macstab/macstab-chaos-testing-libraries/commit/ee1b015ea4fd19a9c1f454d3426787586d569634))
- Add benchmarking matrix with multi-variant support to release workflow ([35a86dd](https://github.com/macstab/macstab-chaos-testing-libraries/commit/35a86dd50a4decc09111589d2817d77f165d0e90))
- Add benchmarking matrix with multi-variant support to release workflow ([9cf2e23](https://github.com/macstab/macstab-chaos-testing-libraries/commit/9cf2e234e9c0007620968725c99cd1e4e0bc62e3))
- Add benchmarking matrix with multi-variant support to release workflow ([3e875b6](https://github.com/macstab/macstab-chaos-testing-libraries/commit/3e875b667ecb2b730c3be90156847a6ad26eb12d))

### Miscellaneous

- Sync main into develop after 1.0.0 ([#14](https://github.com/macstab/macstab-chaos-testing-libraries/issues/14)) ([26b8831](https://github.com/macstab/macstab-chaos-testing-libraries/commit/26b8831d4cbc739aee9bec908603344137d3d7e8))


