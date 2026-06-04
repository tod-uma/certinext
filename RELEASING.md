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
