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

2. **Find the previous tag and determine the new version.**
   ```bash
   git tag --sort=-version:refname | head -5
   git log <prev-tag>..HEAD --oneline
   ```
   Use `$ARGUMENTS` if provided. Otherwise use `AskUserQuestion` — see the `/version-scheme` skill for alpha/beta/rc/stable guidance.

   **Never jump directly from one stable to the next.** Always go through at least one `rcN` first. The only exception is a trivially safe emergency hotfix already proven in production.

3. **Draft the release notes.** Write a concise Markdown changelog:
   - Lead with a `## Highlights` section (2–4 sentences of prose on the most important user-facing changes).
   - Follow with grouped detail lists (`## Features`, `## Fixes`, etc.); merge closely related entries and drop noise.
   - Preserve bare commit SHAs in parentheses — GitLab auto-links them.
   - Where you name a specific file, use an explicit blob link at the tag: `[file.py](../../-/blob/vX.Y.Z/path/to/file.py)` — GLFM does not auto-link file paths, but issues `#N`, MRs `!N`, and users `@name` do auto-link.
   - **Stable release gotcha:** for a stable `X.Y.Z` tag, anchor the changelog at the previous *stable* tag (not the last rc/beta/alpha) so the notes cover every change since the last stable release.

   **Output the full message as plain text in the response before any tool call.**

4. **Get approval.** Use `AskUserQuestion` with Yes/No.

5. **Create the annotated tag.**
   Write the approved notes to a temp file, then:
   ```bash
   git tag -a vX.Y.Z --cleanup=verbatim -F <notes-file>
   ```
   - Never use a lightweight tag — CI reads from annotated tags only.
   - `--cleanup=verbatim` is required: git's default strips lines starting with `#`, silently deleting every Markdown heading.
   - To re-cut a tag (e.g. after fixing the notes), add `-f`: `git tag -a vX.Y.Z --cleanup=verbatim -F <notes-file> -f`

6. **Push the tag.** Use `AskUserQuestion` to confirm before pushing.
   ```bash
   git push origin vX.Y.Z
   ```

7. **Verify all three destinations:**
   - **GitLab** — `release_job` passes; release at `sysadmin/python-libs/certinext/-/releases` has the correct description.
   - **GitHub Actions** — `publish-pypi` job passes; GitHub release appears with the same description.
   - **PyPI** — stable versions are visible without `--pre`; pre-releases require `pip install --pre certinext` to see.
