# Releasing

How a release of `macstab-chaos-testing-libraries` is cut, verified and, if needed,
repaired. Every step names the command, what it must show, and what to do when it does
not. Follow it top to bottom; do not skip the checks.

A release is the tag `X.Y.Z` (no `v`) on `main`. Pushing it runs
[`release.yml`](.github/workflows/release.yml), which builds, publishes and benchmarks the
release. Before the tag, the same benchmark gate runs on the release pull request
([`bench.yml`](.github/workflows/bench.yml)), so a performance regression is normally
caught there, not after publishing.

Commands assume the repository root, `gh` authenticated with admin rights on the
repository, and `R=macstab/macstab-chaos-testing-libraries`.

---

## 0. One-time setup

Done once per repository; check it before the first release with this procedure.

| What | Where | Why |
|---|---|---|
| Secrets `BOT_GITHUB_TOKEN`, `BOT_USER_NAME`, `BOT_USER_EMAIL` | Settings → Secrets → Actions | `release.yml` opens and admin-merges the changelog, benchmark-matrix and main → develop sync PRs with them; a missing secret fails those steps after the release is published. |
| `main`: required status check **`release-over-release gate`** | Settings → Branches → `main` | Without it a red benchmark gate does not block merging the release PR. |
| `main` and `develop`: allow merge commits | Settings → General → Pull Requests | Release and sync PRs are merged with a merge commit (§3, §7). |

---

## 1. Decide the version

Semantic versioning, judged against the last release that is not a prerelease:

| Bump | When (any one is enough) |
|---|---|
| **major** `X.0.0` | An existing rule file is rejected or selects other calls (grammar, selector or matching semantics); an intercepted function is no longer intercepted; the rule, status or hits file path or format changes; a supported platform is dropped. |
| **minor** `x.Y.0` | New effect, qualifier, intercepted function, library or injection mode; no existing rule file changes meaning. |
| **patch** `x.y.Z` | Bug fixes, performance, documentation, build and CI only. |

Commits marked `!` or with a `BREAKING CHANGE:` footer force a major release.

```sh
git fetch origin --tags
LAST=$(gh release list -R $R --exclude-pre-releases --limit 1 --json tagName --jq '.[0].tagName')
git log --oneline "$LAST"..origin/develop | grep -E '^[0-9a-f]+ [a-z]+(\([^)]*\))?!:' || echo "no breaking commits"
```

---

## 2. Preconditions on `develop`

All must hold; fix before continuing.

```sh
git fetch origin
# main is fully merged into develop (0 = yes). If not: §7.3 first.
git rev-list --count origin/develop..origin/main
# develop is green: ci, matrix and codeql succeeded on its last commit.
gh run list -R $R --branch develop --limit 6 --json workflowName,conclusion,headSha \
  --jq '.[] | "\(.workflowName) \(.conclusion) \(.headSha[0:7])"'
# Nothing intended for this release is still open against develop.
gh pr list -R $R --base develop
```

`make ci-local` (format, unit, 100 % coverage, ASan, UBSan, scan-build) is CI's local
mirror; run it when CI and your checkout disagree.

---

## 3. Release pull request `develop` → `main`

```sh
gh pr create -R $R --base main --head develop \
  --title "feat: <one-line summary of the release>" \
  --body-file <release notes: features, fixes, breaking changes, known limits>
```

- **Title** is a Conventional Commit; for a major release use `feat!:`.
- **Body**: what changed, per feature and fix, the breaking changes (§1) and known limits.
  Users read it as the release description.

Wait for every check. The benchmark check (`bench.yml`) sweeps all four variants 10 times
and takes up to about 2.5 hours:

| Check | Meaning when red |
|---|---|
| `ci`, `matrix`, `codeql` | A defect; fix on `develop` (new PR), this PR updates. |
| `sweep (…)` → *Check benchmark scenarios* | A scenario no longer loads or fires (§8). |
| `release-over-release gate` | A benchmark is slower than the last accepted release by > 15 % **and** > 25 ns, significantly. Open the run's summary and the `gate-reports` artifact (`benchmark-vs-prev-<variant>.md`, rows marked ⚠️). Fix the regression on `develop`; or, if the slowdown is the intended cost of a fix, state that in this PR's body (it becomes the release's known limit) and proceed. |

**Merge with "Create a merge commit"** (never squash or rebase): the merge commit makes
`main` contain `develop`'s history, so the next release PR has no conflicts and
git-cliff sees every Conventional Commit for the changelog.

```sh
gh pr merge <number> -R $R --merge --admin
```

---

## 4. Tag

```sh
git fetch origin
VERSION=X.Y.Z
git tag "$VERSION" origin/main      # the release PR's merge commit
git show --no-patch --oneline "$VERSION"
git push origin "$VERSION"
```

The tag must be bare `X.Y.Z`: `release.yml` triggers on it and git-cliff uses it as the
changelog boundary. Never tag a commit that is not on `main`.

---

## 5. Watch the release workflow

```sh
gh run watch -R $R "$(gh run list -R $R --workflow release.yml --limit 1 --json databaseId --jq '.[0].databaseId')"
```

| Job | Produces | Typical duration |
|---|---|---|
| `build all variants` | 24 libraries, `chaos-init-amd64/arm64`, glibc ≤ 2.17 symbol check, `SHA256SUMS` | 10 min |
| `publish GitHub release` | the release with notes, binaries and `CHANGELOG.md`; changelog PR to `main` | 2 min |
| `bench (<variant>)` × 4 | scenario check, 10-run sweep, envelopes | 60–120 min |
| `bench aggregate, gate, commit` | gate against the last accepted release, `X.Y.Z-benchmarks.md`, all reports attached, matrix PR to `main`, main → develop sync PR | 5 min |

The release is public after `publish GitHub release`; the benchmarks never block it.

---

## 6. Verify the published release

```sh
gh release view "$VERSION" -R $R --json isPrerelease,assets --jq '.isPrerelease, (.assets[].name)'
```

Must list, and `isPrerelease` must be `false`:

- `libchaos-{io,net,dns,time,memory,process}-{glibc,musl}-{amd64,arm64}.so` (24)
- `chaos-init-amd64`, `chaos-init-arm64`
- `SHA256SUMS`, `CHANGELOG.md`
- `bench-envelopes-$VERSION-<variant>.tar.gz` (4), `benchmark-comparison-<variant>.md`,
  `benchmark-vs-prev-<variant>.md`, `gate-summary.md`, `$VERSION-benchmarks.md`

Checksums and a load test of the published files:

```sh
D=$(mktemp -d) && gh release download "$VERSION" -R $R -D "$D" -p '*.so' -p 'chaos-init-*' -p SHA256SUMS
(cd "$D" && sha256sum -c SHA256SUMS)          # every line OK (macOS: shasum -a 256 -c)
docker run --rm -v "$D":/d debian:12 sh -c \
  'echo "/tmp/x:open:EIO:1.0" > /tmp/.chaos-io.conf; touch /tmp/x;
   LD_PRELOAD=/d/libchaos-io-glibc-amd64.so cat /tmp/x; echo "exit=$?"'
# expect "cat: /tmp/x: Input/output error" and exit=1
```

`CHANGELOG.md` must open with a `## [X.Y.Z]` section listing this release's commits; if
it shows `[Unreleased]` or another version's range, see §8.

---

## 7. After the release

### 7.1 Automatic pull requests

`release.yml` opens and admin-merges three pull requests. Confirm each is merged:

```sh
gh pr list -R $R --state all --limit 5 --json number,title,state,baseRefName \
  --jq '.[] | "\(.number) \(.state) ->\(.baseRefName) \(.title)"'
```

- `docs: update CHANGELOG for X.Y.Z` → `main`
- `docs(bench): add X.Y.Z-benchmarks.md` → `main`
- `chore: sync main into develop after X.Y.Z` → `develop`, merged with a **merge commit**

### 7.2 `main` and `develop` in sync

```sh
git fetch origin && git rev-list --count origin/develop..origin/main   # must be 0
```

### 7.3 If the sync pull request did not merge

It conflicts when `develop` changed the same lines as the release's changelog or matrix
commits. Resolve on a branch, keeping `develop`'s code and `main`'s generated files
(`CHANGELOG.md`, `*-benchmarks.md`):

```sh
git switch -c chore/sync-main-into-develop origin/develop
git merge origin/main                       # resolve, then: make ci-local
git push -u origin chore/sync-main-into-develop
gh pr create -R $R --base develop --title "chore: sync main into develop" --body "…"
gh pr merge <number> -R $R --merge --admin  # a merge commit, never a squash
```

### 7.4 Downstream

The Java modules (`macstab/chaos-testing`) vendor the binaries:
`scripts/sync-libchaos.sh X.Y.Z` there downloads them and verifies `SHA256SUMS`.

---

## 8. When something goes wrong

| Symptom | Action |
|---|---|
| A job of `release.yml` failed before `publish GitHub release` | Nothing is published. Fix on `develop`, release PR, then re-tag: `git push origin :refs/tags/X.Y.Z && git tag -f X.Y.Z origin/main && git push origin X.Y.Z`. Only in this case may a tag be moved. |
| A job failed after publishing (infrastructure, timeout) | `gh run rerun <run-id> -R $R --failed`. Never move a published tag. |
| The gate marked the release **prerelease** | The release stays downloadable and is not the gate's baseline. Fix the regression and release a patch. If the slowdown is accepted (the cost of a fix), document it in the release notes, then `gh release edit X.Y.Z -R $R --prerelease=false` so it becomes the baseline. |
| `Check benchmark scenarios` failed | Its log names the benchmark and reason (does not load, fires n of 64, breaks the run). Fix the scenario or kernel; if what the benchmark measures changes, bump its `srev` or `krev` in `benchmark/suite.tsv` (re-baselined once instead of reported as a regression). |
| The gate reports a re-baselined benchmark | Expected for one release after a `krev`/`srev` bump; it is compared again from the next release on. |
| `CHANGELOG.md` has the wrong range | `cliff.toml`'s `tag_pattern` must match the bare tags; regenerate with `git cliff --tag X.Y.Z` and update the release asset with `gh release upload X.Y.Z CHANGELOG.md --clobber`. |
| A defect in a published release | Never delete or move its tag. Release a patch with the fix; mark the defective release prerelease and say why in its notes. |
