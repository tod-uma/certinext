# Releasing

Releases flow through **two separate channels** from a single annotated tag:

1. **GitLab** — `release_job` reads the tag message and creates a GitLab release page.
2. **GitHub / PyPI** — the GitLab→GitHub mirror pushes the tag; GitHub Actions
   builds the wheel, publishes to PyPI, and creates a GitHub release page.

**Both release pages show identical notes**, taken verbatim from the annotated
tag message — neither CI pipeline generates notes on its own.

## TL;DR

```bash
# 1. Bump the version in pyproject.toml (on a branch, via MR) and merge it.
# 2. From an up-to-date clone of main with full history:
git checkout main && git pull
python scripts/make_release_tag.py        # opens an editor with a draft changelog
git push gitlab vX.Y.Z                    # GitLab CI triggers; mirror pushes to GitHub
```

The GitLab→GitHub mirror typically propagates the tag within a few minutes.
GitHub Actions then runs, reads the same tag message, and creates the GitHub
release with identical notes.

## What "correct" means

- **Pre-release** (`vX.Y.Za1`, `vX.Y.Zb1`, `vX.Y.ZrcN`): notes cover changes
  since the *previous tag of any kind* — incremental, just enough to see what's
  new in this build.
- **Stable** (`vX.Y.Z`): notes cover **every change since the previous _stable_
  tag**, including everything that shipped in the intervening alpha/beta/rc
  pre-releases. A stable release's notes are a complete record, not just the
  delta since the last rc.

`make_release_tag.py` picks the right comparison tag automatically.

## The script

```bash
python scripts/make_release_tag.py [VERSION] [--print] [--summarize] [--no-edit] [-f]
```

- **`VERSION`** — optional. Defaults to the version in `pyproject.toml`. The
  `v` prefix is added for you. Pass an explicit version to override.
- **`--print`** — print the generated changelog and exit. Does not create a
  tag. Combine with `--summarize` to preview the polished version.
- **`--summarize`** — polish the changelog into prose release notes (see
  [Polishing with an LLM](#polishing-with-an-llm) below).
- **`--no-edit`** — skip the editor and use the generated changelog as-is.
- **`-f` / `--force`** — replace an existing tag of the same name (for
  re-cutting a release).

By default the script:

1. Reads the version from `pyproject.toml`.
2. Finds the correct previous tag (previous *stable* for a stable release;
   previous tag of any kind otherwise), restricted to ancestors of `HEAD`.
3. Builds a changelog from `git log <previous>..HEAD`, grouped into sections
   (Features, Fixes, CI / Build, …) by conventional-commit type. Each entry
   ends with its short commit SHA, which GitLab auto-links to the commit.
4. Opens the draft in your git editor so you can curate it.
5. Creates the annotated tag with `--cleanup=verbatim` (so Markdown headings
   are preserved).

**Run it from a full clone**, not a shallow one.

## Polishing with an LLM

- **`--summarize` flag.** Pipes the draft through the installed `claude` CLI
  (`claude -p`) for prose release notes. Falls back to the raw draft if
  `claude` is not installed or not logged in.
- **`/release` slash command** (Claude Code users). Uses your
  already-authenticated session. See `.claude/commands/release.md`.

Either way, review the result in the editor before the tag is created.

## GitLab Flavored Markdown

Tag messages are rendered as GLFM on GitLab and as standard Markdown on GitHub.
Both render `##`/`###` headings and bullet lists identically.

- **Commit SHAs auto-link on GitLab.** Bare short SHAs (e.g. `(a1b2c3d)`)
  become commit links on GitLab. On GitHub they appear as plain text.
- **File paths do not auto-link on either platform.** Use explicit links if you
  reference a specific file.

## Doing it by hand

Use `--cleanup=verbatim` — git's default strips `#`-prefixed lines as comments,
silently removing every Markdown heading:

```bash
git tag -a vX.Y.Z --cleanup=verbatim     # opens your editor; write the changelog
git push gitlab vX.Y.Z
```

## How CI uses the tag

**GitLab** (`release_job`): reads the tag message via the Tags API and POSTs it
as the release description.

**GitHub Actions** (`release` job): uses the `gh` CLI to fetch the annotated
tag object from the GitHub API (after the mirror pushes it) and passes the
message as the release body to `softprops/action-gh-release`.

## Two pipelines, different jobs

The two CI systems live in `.gitlab-ci.yml` (primary —
`gitlab.its.maine.edu/sysadmin/python-libs/certinext`) and
`.github/workflows/ci.yml` (the push mirror at `tod-uma/certinext`). They run
**different jobs**, and the GitLab *tag* pipeline runs different jobs than a
GitLab *merge* pipeline — so a green merge does not imply a green tag, and vice
versa.

| Trigger | Jobs |
| --- | --- |
| GitLab merge / branch | `lint`, `typecheck`, `unit-test` (`-m "not integration"`); plus `integration-test` → `tests/test_integration.py` (only on `main`, and only when sandbox creds are set) |
| GitLab tag (`vX.Y.Z`) | `integration-cert-issuance` → `tests/test_sandbox_integration.py`, then `release_build` (GitLab package registry) and `release_job` (GitLab Release page) |
| GitHub Actions (any `refs/tags/v*`) | `lint`, `typecheck`, `test`, then `publish-pypi` (PyPI via OIDC) and `release` (GitHub Release page) |

## PyPI is published by GitHub Actions, not GitLab

The public PyPI upload is the `publish-pypi` job in `.github/workflows/ci.yml`.
It triggers on any `refs/tags/v*` (rc tags included), `needs: [lint, typecheck,
test]`, and uploads to pypi.org over OIDC (`environment: pypi`). Its `test` job
runs `pytest tests/` with **no sandbox credentials**, so every
`@pytest.mark.integration` test **skips** there. That makes the PyPI publish
**independent of GitLab CI and of any CertiNext sandbox outage.**

## When the GitLab tag pipeline goes red but PyPI still publishes

A CertiNext `/domains` outage (the recurring sandbox 422 / empty-content bug)
breaks the GitLab tag pipeline but **not** PyPI:

- `tests/test_sandbox_integration.py` calls `domain.get_list()`, so
  `integration-cert-issuance` **fails** during the outage.
- `release_build` and `release_job` both declare
  `needs: [{job: integration-cert-issuance, optional: true}]`. `optional: true`
  only tolerates the job being **absent**, not **failing** — so when it fails,
  both are **skipped**: no GitLab Release page, no GitLab package upload.
- GitHub Actions is a separate system whose `test` job skips the integration
  suite, so `publish-pypi` and the GitHub Release still succeed.

**Precedent:** `rc6` (2026-06-22) was tagged mid-outage — its GitLab tag
pipeline failed and no GitLab Release was created, yet it still reached public
PyPI. `rc7` (2026-06-24) was tagged after sandbox `/domains` recovered, so
`integration-cert-issuance` passed and the whole tag pipeline went green (GitLab
Release + package + PyPI all published).

**Bottom line:** tagging during a `/domains` outage still ships the package to
PyPI and creates the GitHub Release — you just won't get a GitLab Release page or
GitLab package entry until the outage clears and the tag pipeline is re-run.
