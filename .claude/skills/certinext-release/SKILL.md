---
name: certinext-release
description: Cut a release tag for the certinext repo. Use when the user asks to create a version tag, cut a release, or push a release in the certinext repo.
---

Cut a release for certinext. The tag message is the source of truth — GitLab CI reads it verbatim as the release description, and GitHub mirrors it to a GitHub release. Stable tags also trigger PyPI publish via GitHub Actions.

`$ARGUMENTS` may specify the version (e.g. `/release v1.2.0`).

## Steps

1. **Confirm the version and be on main.**
   - Read `version` from `pyproject.toml`. If a version bump is needed and isn't on `main` yet, it must land via MR before tagging — do not tag a version that isn't in `pyproject.toml` on `main`.
   - Check out and pull main with full history:
     ```bash
     git checkout main && git pull
     ```
   - **Confirm `main`'s CI is green before tagging.** The tag points at `HEAD` on `main` (usually a just-merged commit), and certinext's tag pipeline runs *different* jobs than the merge pipeline — the merge runs `integration-test`, while a tag runs `integration-cert-issuance` plus `release_build`/`release_job` — so a red `main` can stay hidden until after you tag. Check the latest `main` pipeline:
     ```bash
     glab ci list   # latest pipeline for `main` should be `success`
     ```
     If it is not `success`, inspect the failing jobs (`glab ci get -p <pipeline-id>`), **list each failing job and why**, then use `AskUserQuestion` to decide whether to tag anyway or stop. A red `main` does not always block *shipping*: a known vendor `/domains` outage reddens the `integration-cert-issuance` tag job too (`tests/test_sandbox_integration.py` calls `domain.get_list()`), which **skips** the GitLab `release_job` and package upload — but PyPI and the GitHub Release still publish, because those run on GitHub Actions independently of GitLab CI. So tagging mid-outage still reaches PyPI; you just lose the GitLab Release page until the outage clears. Make proceeding a deliberate call. See [RELEASING.md](../../../RELEASING.md) for the full GitLab-vs-GitHub-Actions split.

2. **Find the previous tag and determine the new version.**
   ```bash
   git tag --sort=-version:refname | head -5
   git log <prev-tag>..HEAD --oneline
   ```
   Use `$ARGUMENTS` if provided. Otherwise use `AskUserQuestion` — see the `/version-scheme` skill for alpha/beta/rc/stable guidance.

   **Never jump directly from one stable to the next.** Always go through at least one `rcN` first. The only exception is a trivially safe emergency hotfix already proven in production.

3. **Verify documentation is up to date.**
   Review `README.md` against the commits since the previous tag:
   ```bash
   git log <prev-tag>..HEAD --oneline
   ```
   For every user-visible change (new CLI flag, changed behaviour, new feature, changed default), check that the README reflects it. Pay particular attention to:
   - CLI tool sections (new arguments, changed prompts, new workflows)
   - Credential resolution order
   - Python library sections (new properties, new methods, changed return types)

   If the README is missing any changes, **stop**. Create a `docs/` branch, update the README, bump to the next rc, merge it, and tag that version instead. Do not skip this check or defer it to a follow-up PR — the release is the public record.

4. **Draft the release notes.** Write a concise Markdown changelog:
   - Lead with a `## Highlights` section (2–4 sentences of prose on the most important user-facing changes).
   - Follow with grouped detail lists (`## Features`, `## Fixes`, etc.); merge closely related entries and drop noise.
   - Preserve bare commit SHAs in parentheses — GitLab auto-links them.
   - Where you name a specific file, use an explicit blob link at the tag: `[file.py](../../-/blob/vX.Y.Z/path/to/file.py)` — GLFM does not auto-link file paths, but issues `#N`, MRs `!N`, and users `@name` do auto-link.
   - **Stable release gotcha:** for a stable `X.Y.Z` tag, anchor the changelog at the previous *stable* tag (not the last rc/beta/alpha) so the notes cover every change since the last stable release.

   **Output the full message as plain text in the response before any tool call.**

5. **Get approval.** Use `AskUserQuestion` with Yes/No.

6. **Create the annotated tag.**
   Write the approved notes to a temp file, then:
   ```bash
   git tag -a vX.Y.Z --cleanup=verbatim -F <notes-file>
   ```
   - Never use a lightweight tag — CI reads from annotated tags only.
   - `--cleanup=verbatim` is required: git's default strips lines starting with `#`, silently deleting every Markdown heading.
   - To re-cut a tag (e.g. after fixing the notes), add `-f`: `git tag -a vX.Y.Z --cleanup=verbatim -F <notes-file> -f`

7. **Push the tag.** Use `AskUserQuestion` to confirm before pushing. Push to
   the `gitlab` remote — this repo has no `origin` (see the `git-remotes`
   skill); GitHub is a mirror populated by GitLab CI, not pushed to directly.
   ```bash
   git push gitlab vX.Y.Z
   ```

8. **Verify all three destinations:**
   - **GitLab** — `release_job` passes; release at `sysadmin/python-libs/certinext/-/releases` has the correct description.
   - **GitHub Actions** — `publish-pypi` job passes; GitHub release appears with the same description.
   - **PyPI** — stable versions are visible without `--pre`; pre-releases require `pip install --pre certinext` to see.
